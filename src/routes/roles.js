const express = require('express');
const { z } = require('zod');
const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { requirePermission, userHasPermission, getUserPermissions } = require('../middleware/permissions');
const { isOwnerRole, isReservedRoleName } = require('../utils/roleRank');
const { broadcastWorkspaceEvent, sendUserEvent } = require('../socket');
const { logAuthEvent } = require('../services/authAudit');
const {
  PERMISSIONS,
  LEGACY_PERMISSION_ALIASES,
  getTransitivePrerequisites
} = require('../rbac/registry');

const router = express.Router();

const validPermMap = new Map();
PERMISSIONS.forEach((p) => validPermMap.set(p.key, p));

const updateRoleSchema = z.object({
  name: z.string().min(1).optional(),
  permission_keys: z.array(z.string()).optional()
});

// PATCH /api/roles/:id - Edit custom role name and permissions
router.patch('/:id', requireAuth, validate(updateRoleSchema), async (req, res, next) => {
  const roleId = Number(req.params.id);
  const { name, permission_keys } = req.body;

  try {
    const roleRes = await req.db.query('SELECT * FROM roles WHERE id = ?', [roleId]);
    if (roleRes.length === 0) {
      return res.status(404).json({ error: { message: 'Role not found', code: 'NOT_FOUND' } });
    }

    const role = roleRes[0];

    if (!role.is_editable || role.is_system === 1 || isOwnerRole(role)) {
      return res.status(403).json({
        error: { message: 'System role permissions are locked and cannot be edited', code: 'ROLE_NOT_EDITABLE' }
      });
    }

    // Anti-escalation: caller cannot edit their own role
    const userRoleCheck = await req.db.query(
      'SELECT 1 FROM workspace_members WHERE user_id = ? AND role_id = ? LIMIT 1',
      [req.user.id, roleId]
    );
    if (userRoleCheck.length > 0) {
      return res.status(403).json({
        error: { message: 'You cannot edit your own role', code: 'CANNOT_EDIT_OWN_ROLE' }
      });
    }

    const targetWsId = role.workspace_id || req.body.workspace_id || req.headers['x-workspace-id'] ||
      (await req.db.query('SELECT workspace_id FROM workspace_members WHERE user_id = ? LIMIT 1', [req.user.id]))[0]?.workspace_id;

    if (targetWsId) {
      const hasPerm = (await userHasPermission(req.user.id, targetWsId, 'role.edit', req.db)) ||
                      (await userHasPermission(req.user.id, targetWsId, 'workspace.manage_roles', req.db));
      if (!hasPerm) {
        return res.status(403).json({
          error: { message: 'You do not have permission to edit roles', code: 'PERMISSION_DENIED' }
        });
      }
    }

    if (name && name.trim()) {
      const cleanName = name.trim();
      if (isReservedRoleName(cleanName)) {
        return res.status(400).json({
          error: { message: 'Role name is reserved for system roles', code: 'RESERVED_ROLE_NAME' }
        });
      }

      if (targetWsId) {
        const dupCheck = await req.db.query(
          'SELECT id FROM roles WHERE workspace_id = ? AND LOWER(name) = LOWER(?) AND id != ? LIMIT 1',
          [targetWsId, cleanName, roleId]
        );
        if (dupCheck.length > 0) {
          return res.status(400).json({
            error: { message: 'A role with this name already exists in this workspace', code: 'DUPLICATE_ROLE_NAME' }
          });
        }
      }

      await req.db.execute('UPDATE roles SET name = ? WHERE id = ?', [cleanName, roleId]);
    }

    if (Array.isArray(permission_keys)) {
      // Validate unknown and planned keys
      for (const rawKey of permission_keys) {
        const canonical = LEGACY_PERMISSION_ALIASES[rawKey] || rawKey;
        const meta = validPermMap.get(canonical);
        if (!meta) {
          return res.status(400).json({
            error: { message: `Unknown permission key: ${rawKey}`, code: 'UNKNOWN_PERMISSION_KEY' }
          });
        }
        if (meta.planned) {
          return res.status(400).json({
            error: { message: `Planned permission key cannot be assigned: ${rawKey}`, code: 'PLANNED_PERMISSION_KEY' }
          });
        }
      }

      // Auto-include transitive prerequisites as the Role Editor does
      const requestedKeys = new Set(
        permission_keys.map((k) => LEGACY_PERMISSION_ALIASES[k] || k)
      );
      for (const k of Array.from(requestedKeys)) {
        const prereqs = getTransitivePrerequisites(k);
        prereqs.forEach((p) => requestedKeys.add(p));
      }
      const canonicalKeys = Array.from(requestedKeys);

      if (targetWsId) {
        const callerPerms = await getUserPermissions(req.user.id, targetWsId, req.db);
        const callerIsOwner = callerPerms.role?.is_system === 1 && (callerPerms.role?.is_editable === 0 || callerPerms.role?.rank >= 100);
        if (!callerIsOwner) {
          const callerPermSet = new Set(
            callerPerms.permissions.map((k) => LEGACY_PERMISSION_ALIASES[k] || k)
          );
          const unauthorizedPerm = canonicalKeys.find((k) => !callerPermSet.has(k));
          if (unauthorizedPerm) {
            return res.status(403).json({
              error: {
                message: `You cannot grant permissions you do not possess (${unauthorizedPerm})`,
                code: 'PRIVILEGE_ESCALATION_FORBIDDEN'
              }
            });
          }
        }
      }

      // Clear existing role permissions
      await req.db.execute('DELETE FROM role_permissions WHERE role_id = ?', [roleId]);

      if (canonicalKeys.length > 0) {
        const permsRes = await req.db.query(
          'SELECT id, `key` FROM permissions WHERE `key` IN (?)',
          [canonicalKeys]
        );

        for (const p of permsRes) {
          await req.db.execute(
            'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
            [roleId, p.id]
          );
        }
      }
    }

    const updatedRoleRes = await req.db.query(
      `SELECT r.id, r.name, r.is_system, r.is_editable, r.workspace_id,
              GROUP_CONCAT(DISTINCT p.key) as permission_keys_str
       FROM roles r
       LEFT JOIN role_permissions rp ON r.id = rp.role_id
       LEFT JOIN permissions p ON rp.permission_id = p.id
       WHERE r.id = ?
       GROUP BY r.id, r.name, r.is_system, r.is_editable, r.workspace_id`,
      [roleId]
    );

    const updatedRole = updatedRoleRes[0];
    const keys = updatedRole.permission_keys_str ? updatedRole.permission_keys_str.split(',') : [];
    const rolePayload = { ...updatedRole, permission_keys: keys };

    if (targetWsId) {
      broadcastWorkspaceEvent(targetWsId, 'workspace:role_updated', { role: rolePayload }, req.headers['x-origin-id'], req.tenant?.id);
    }

    try {
      const affectedUsers = await req.db.query(
        'SELECT DISTINCT user_id FROM workspace_members WHERE role_id = ? UNION SELECT DISTINCT user_id FROM board_members WHERE role_id = ?',
        [roleId, roleId]
      );
      for (const u of affectedUsers) {
        sendUserEvent(u.user_id, 'user:permissions_updated', {
          roleId,
          workspaceId: targetWsId
        }, req.tenant?.id);
      }
    } catch (sockErr) {
      console.warn('[WARN] Failed to emit user:permissions_updated on role edit:', sockErr.message);
    }

    await logAuthEvent(req.db, {
      userId: req.user.id,
      email: req.user.email,
      eventType: 'role.updated',
      req,
      metadata: {
        workspace_id: targetWsId,
        role_id: roleId,
        role_name: rolePayload.name,
        permission_count: keys.length
      }
    });

    return res.json({ role: rolePayload });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/roles/:id - Delete custom role (blocked if in use by members or is system role)
router.delete('/:id', requireAuth, async (req, res, next) => {
  const roleId = Number(req.params.id);

  try {
    const roleRes = await req.db.query('SELECT * FROM roles WHERE id = ?', [roleId]);
    if (roleRes.length === 0) {
      return res.status(404).json({ error: { message: 'Role not found', code: 'NOT_FOUND' } });
    }

    const role = roleRes[0];

    if (role.is_system === 1 || isOwnerRole(role)) {
      return res.status(400).json({
        error: { message: 'Owner and built-in system roles cannot be deleted', code: 'ROLE_IS_SYSTEM' }
      });
    }

    const targetWsId = role.workspace_id || req.body?.workspace_id || req.headers['x-workspace-id'] ||
      (await req.db.query('SELECT workspace_id FROM workspace_members WHERE user_id = ? LIMIT 1', [req.user.id]))[0]?.workspace_id;
    if (targetWsId) {
      const hasPerm = (await userHasPermission(req.user.id, targetWsId, 'role.delete', req.db)) ||
                      (await userHasPermission(req.user.id, targetWsId, 'workspace.manage_roles', req.db));
      if (!hasPerm) {
        return res.status(403).json({
          error: { message: 'You do not have permission to delete custom roles', code: 'PERMISSION_DENIED' }
        });
      }
    }

    // Check if role is assigned to any workspace members or board members
    const memberCountRes = await req.db.query(
      'SELECT COUNT(*) as count FROM workspace_members WHERE role_id = ?',
      [roleId]
    );
    const count = Number(memberCountRes[0]?.count || 0);

    const boardMemberCountRes = await req.db.query(
      'SELECT COUNT(*) as count FROM board_members WHERE role_id = ?',
      [roleId]
    );
    const boardMemberCount = Number(boardMemberCountRes[0]?.count || 0);

    if (count > 0 || boardMemberCount > 0) {
      return res.status(400).json({
        error: {
          message: `Cannot delete custom role while ${count + boardMemberCount} member assignment(s) exist. Reassign members first.`,
          code: 'ROLE_IN_USE'
        }
      });
    }

    await req.db.execute('DELETE FROM role_permissions WHERE role_id = ?', [roleId]);
    await req.db.execute('DELETE FROM roles WHERE id = ?', [roleId]);

    if (targetWsId) {
      broadcastWorkspaceEvent(targetWsId, 'workspace:role_deleted', { roleId }, req.headers['x-origin-id'], req.tenant?.id);
    }

    await logAuthEvent(req.db, {
      userId: req.user.id,
      email: req.user.email,
      eventType: 'role.deleted',
      req,
      metadata: {
        workspace_id: targetWsId,
        role_id: roleId,
        role_name: role.name
      }
    });

    return res.json({ message: 'Custom role deleted successfully', id: roleId });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

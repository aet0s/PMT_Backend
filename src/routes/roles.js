const express = require('express');
const { z } = require('zod');
const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { requirePermission, userHasPermission, getUserPermissions } = require('../middleware/permissions');
const { isOwnerRole, isReservedRoleName, getRoleRank } = require('../utils/roleRank');
const { broadcastWorkspaceEvent, sendUserEvent } = require('../socket');
const { logAuthEvent } = require('../services/authAudit');
const {
  PERMISSIONS,
  SYSTEM_ROLES,
  LEGACY_PERMISSION_ALIASES,
  getTransitivePrerequisites
} = require('../rbac/registry');

const router = express.Router();

const validPermMap = new Map();
PERMISSIONS.forEach((p) => validPermMap.set(p.key, p));

const LEGACY_KEY_REMAP = {
  'role.assign': 'member.assign_role'
};

const updateRoleSchema = z.object({
  name: z.string().min(1).optional(),
  permission_keys: z.array(z.string()).optional(),
  rank: z.number().int().optional()
});

// PATCH /api/roles/:id - Edit custom role name and permissions
router.patch('/:id', requireAuth, requirePermission('role.edit'), validate(updateRoleSchema), async (req, res, next) => {
  const roleId = Number(req.params.id);
  const { name, permission_keys } = req.body;

  try {
    const roleRes = await req.db.query('SELECT * FROM roles WHERE id = ?', [roleId]);
    if (roleRes.length === 0) {
      return res.status(404).json({ error: { message: 'Role not found', code: 'NOT_FOUND' } });
    }

    const role = roleRes[0];

    if (!role.is_editable || isOwnerRole(role)) {
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
      const hasPerm = await userHasPermission(req.user.id, targetWsId, 'role.edit', req.db);
      if (!hasPerm) {
        return res.status(403).json({
          error: { message: 'You do not have permission to edit roles', code: 'PERMISSION_DENIED' }
        });
      }
    }

    let rolePayload = null;

    await req.db.transaction(async (tx) => {
      if (name && name.trim()) {
        const cleanName = name.trim();
        if (cleanName.toLowerCase() !== role.name.toLowerCase()) {
          if (role.is_system) {
            const err = new Error('System role names cannot be renamed');
            err.status = 400;
            err.code = 'CANNOT_RENAME_SYSTEM_ROLE';
            throw err;
          }
          if (isReservedRoleName(cleanName)) {
            const err = new Error('Role name is reserved for system roles');
            err.status = 400;
            err.code = 'RESERVED_ROLE_NAME';
            throw err;
          }

          if (targetWsId) {
            const dupCheck = await tx.query(
              'SELECT id FROM roles WHERE workspace_id = ? AND LOWER(name) = LOWER(?) AND id != ? LIMIT 1',
              [targetWsId, cleanName, roleId]
            );
            if (dupCheck.length > 0) {
              const err = new Error('A role with this name already exists in this workspace');
              err.status = 400;
              err.code = 'DUPLICATE_ROLE_NAME';
              throw err;
            }
          }

          await tx.execute('UPDATE roles SET name = ? WHERE id = ?', [cleanName, roleId]);
        }
      }

      if (req.body.rank !== undefined) {
        const requestedRank = Number(req.body.rank);
        if (isNaN(requestedRank) || requestedRank < 11 || requestedRank > 79) {
          const err = new Error('Custom role rank must be between 11 and 79');
          err.status = 400;
          err.code = 'INVALID_ROLE_RANK';
          throw err;
        }

        if (targetWsId) {
          const callerPerms = await getUserPermissions(req.user.id, targetWsId, tx);
          const callerIsOwner = isOwnerRole(callerPerms.role);
          const callerRank = getRoleRank(callerPerms.role);
          const currentRoleRank = Number(role.rank || 30);

          if (!callerIsOwner && (callerRank <= currentRoleRank || callerRank <= requestedRank)) {
            const err = new Error('You cannot edit a role with equal or higher rank, nor set a rank equal or higher than your own');
            err.status = 403;
            err.code = 'INSUFFICIENT_ROLE_RANK';
            throw err;
          }
        }

        await tx.execute('UPDATE roles SET rank = ? WHERE id = ?', [requestedRank, roleId]);
        role.rank = requestedRank;
      }

      let canonicalKeys = null;
      if (Array.isArray(permission_keys)) {
        const existingRolePermsRes = await tx.query(
          `SELECT p.id, p.key, p.planned
           FROM role_permissions rp
           JOIN permissions p ON rp.permission_id = p.id
           WHERE rp.role_id = ?`,
          [roleId]
        );
        const existingPlannedKeys = new Set(
          existingRolePermsRes
            .filter((p) => p.planned && validPermMap.has(p.key))
            .map((p) => p.key)
        );

        const activeKeysOnly = [];
        for (const rawKey of permission_keys) {
          const remapped = LEGACY_KEY_REMAP[rawKey] || rawKey;
          const canonical = LEGACY_PERMISSION_ALIASES[remapped] || remapped;
          const meta = validPermMap.get(canonical);
          if (!meta) {
            const err = new Error(`Unknown permission key: ${rawKey}`);
            err.status = 400;
            err.code = 'UNKNOWN_PERMISSION_KEY';
            throw err;
          }
          if (meta.planned) {
            if (!existingPlannedKeys.has(canonical)) {
              const err = new Error(`Cannot add planned permission key: ${rawKey}`);
              err.status = 400;
              err.code = 'CANNOT_ADD_PLANNED_KEY';
              throw err;
            }
            activeKeysOnly.push(canonical);
          } else {
            activeKeysOnly.push(canonical);
          }
        }

        for (const plannedKey of existingPlannedKeys) {
          if (!activeKeysOnly.includes(plannedKey)) {
            activeKeysOnly.push(plannedKey);
          }
        }

        const requestedKeys = new Set(activeKeysOnly);
        for (const k of Array.from(requestedKeys)) {
          const prereqs = getTransitivePrerequisites(k);
          prereqs.forEach((p) => requestedKeys.add(p));
        }
        canonicalKeys = Array.from(requestedKeys);

        if (targetWsId) {
          const callerPerms = await getUserPermissions(req.user.id, targetWsId, tx);
          const callerIsOwner = isOwnerRole(callerPerms.role);
          if (!callerIsOwner) {
            const callerPermSet = new Set(
              callerPerms.permissions.map((k) => LEGACY_PERMISSION_ALIASES[k] || k)
            );
            const unauthorizedPerm = canonicalKeys.find((k) => !callerPermSet.has(k));
            if (unauthorizedPerm) {
              const err = new Error(`You cannot grant permissions you do not possess (${unauthorizedPerm})`);
              err.status = 403;
              err.code = 'PRIVILEGE_ESCALATION_FORBIDDEN';
              throw err;
            }
          }
        }

        await tx.execute('DELETE FROM role_permissions WHERE role_id = ?', [roleId]);

        if (canonicalKeys.length > 0) {
          const permsRes = await tx.query(
            'SELECT id, `key` FROM permissions WHERE `key` IN (?)',
            [canonicalKeys]
          );

          for (const p of permsRes) {
            await tx.execute(
              'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
              [roleId, p.id]
            );
          }
        }
      }

      const updatedRoleRes = await tx.query(
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
      const rawKeys = updatedRole.permission_keys_str ? updatedRole.permission_keys_str.split(',') : [];
      const keys = rawKeys
        .map((k) => LEGACY_KEY_REMAP[k] || LEGACY_PERMISSION_ALIASES[k] || k)
        .filter((k) => validPermMap.has(k) && !validPermMap.get(k).planned);
      rolePayload = { ...updatedRole, permission_keys: Array.from(new Set(keys)) };

      // Atomic Audit Log inside same transaction (Item 2a, Item 2b)
      await logAuthEvent(tx, {
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
    });

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

    return res.json({ role: rolePayload });
  } catch (err) {
    if (err.status && err.status < 500) {
      return res.status(err.status).json({ error: { message: err.message, code: err.code || 'BAD_REQUEST' } });
    }
    next(err);
  }
});

// DELETE /api/roles/:id - Delete custom role (blocked if in use by members or is system role)
router.delete('/:id', requireAuth, requirePermission('role.delete'), async (req, res, next) => {
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
      const hasPerm = await userHasPermission(req.user.id, targetWsId, 'role.delete', req.db);
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


// POST /api/roles/:id/reset-default - Reset role permissions back to system defaults
router.post('/:id/reset-default', requireAuth, requirePermission('role.edit'), async (req, res, next) => {
  const roleId = Number(req.params.id);

  try {
    const roleRes = await req.db.query('SELECT * FROM roles WHERE id = ?', [roleId]);
    if (roleRes.length === 0) {
      return res.status(404).json({ error: { message: 'Role not found', code: 'NOT_FOUND' } });
    }

    const role = roleRes[0];

    if (isOwnerRole(role)) {
      return res.status(403).json({
        error: { message: 'Owner role permissions are locked and cannot be edited', code: 'ROLE_NOT_EDITABLE' }
      });
    }

    const targetWsId = role.workspace_id || req.body?.workspace_id || req.headers['x-workspace-id'] ||
      (await req.db.query('SELECT workspace_id FROM workspace_members WHERE user_id = ? LIMIT 1', [req.user.id]))[0]?.workspace_id;

    if (targetWsId) {
      const callerPerms = await getUserPermissions(req.user.id, targetWsId, req.db);
      const callerIsOwner = isOwnerRole(callerPerms.role);
      if (!callerIsOwner) {
        const userRoleCheck = await req.db.query(
          'SELECT 1 FROM workspace_members WHERE user_id = ? AND role_id = ? LIMIT 1',
          [req.user.id, roleId]
        );
        if (userRoleCheck.length > 0) {
          return res.status(403).json({
            error: { message: 'You cannot reset your own role', code: 'CANNOT_EDIT_OWN_ROLE' }
          });
        }
      }
    }

    // Find default permissions from SYSTEM_ROLES
    let defaultRoleDef = SYSTEM_ROLES[role.name];
    if (!defaultRoleDef) {
      const normalized = String(role.name || '').trim().toLowerCase();
      const matchKey = Object.keys(SYSTEM_ROLES).find((k) => k.toLowerCase() === normalized);
      if (matchKey) {
        defaultRoleDef = SYSTEM_ROLES[matchKey];
      }
    }

    if (!defaultRoleDef) {
      defaultRoleDef = SYSTEM_ROLES['Team Member'];
    }

    const defaultPermKeys = defaultRoleDef?.permissions || [];
    let rolePayload = null;

    await req.db.transaction(async (tx) => {
      await tx.execute('DELETE FROM role_permissions WHERE role_id = ?', [roleId]);

      if (defaultPermKeys.length > 0) {
        const permsRes = await tx.query(
          'SELECT id, `key` FROM permissions WHERE `key` IN (?)',
          [defaultPermKeys]
        );

        for (const p of permsRes) {
          await tx.execute(
            'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
            [roleId, p.id]
          );
        }
      }

      const updatedRoleRes = await tx.query(
        `SELECT r.id, r.name, r.is_system, r.is_editable, r.workspace_id, r.rank,
                GROUP_CONCAT(DISTINCT p.key) as permission_keys_str
         FROM roles r
         LEFT JOIN role_permissions rp ON r.id = rp.role_id
         LEFT JOIN permissions p ON rp.permission_id = p.id
         WHERE r.id = ?
         GROUP BY r.id, r.name, r.is_system, r.is_editable, r.workspace_id, r.rank`,
        [roleId]
      );

      const updatedRole = updatedRoleRes[0];
      const rawKeys = updatedRole.permission_keys_str ? updatedRole.permission_keys_str.split(',') : [];
      const keys = rawKeys.filter((k) => validPermMap.has(k) && !validPermMap.get(k).planned);
      rolePayload = { ...updatedRole, permission_keys: Array.from(new Set(keys)) };

      await logAuthEvent(tx, {
        userId: req.user.id,
        email: req.user.email,
        eventType: 'role.updated',
        req,
        metadata: {
          workspace_id: targetWsId,
          role_id: roleId,
          role_name: rolePayload.name,
          permission_count: keys.length,
          action: 'reset_default'
        }
      });
    });

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
      console.warn('[WARN] Failed to emit user:permissions_updated on role reset:', sockErr.message);
    }

    return res.json({
      role: rolePayload,
      message: `Permissions for "${rolePayload.name}" have been reset to system defaults`
    });
  } catch (err) {
    if (err.status && err.status < 500) {
      return res.status(err.status).json({ error: { message: err.message, code: err.code || 'BAD_REQUEST' } });
    }
    next(err);
  }
});

module.exports = router;

const express = require('express');
const { z } = require('zod');
const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { requirePermission, userHasPermission, getUserPermissions } = require('../middleware/permissions');
const { isOwnerRole } = require('../utils/roleRank');
const { broadcastWorkspaceEvent } = require('../socket');
const { logAuthEvent } = require('../services/authAudit');

const router = express.Router();

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

    if (!role.is_editable || isOwnerRole(role.name)) {
      return res.status(403).json({
        error: { message: 'Owner and Super Admin role permissions are locked and cannot be edited', code: 'ROLE_NOT_EDITABLE' }
      });
    }

    const workspaceId = role.workspace_id;
    if (workspaceId) {
      const hasPerm = (await userHasPermission(req.user.id, workspaceId, 'role.edit', req.db)) ||
                      (await userHasPermission(req.user.id, workspaceId, 'workspace.manage_roles', req.db));
      if (!hasPerm) {
        return res.status(403).json({
          error: { message: 'You do not have permission to edit custom roles', code: 'PERMISSION_DENIED' }
        });
      }
    }

    if (name && name.trim()) {
      await req.db.execute('UPDATE roles SET name = ? WHERE id = ?', [name.trim(), roleId]);
    }

    if (Array.isArray(permission_keys)) {
      if (workspaceId) {
        const callerPerms = await getUserPermissions(req.user.id, workspaceId, req.db);
        if (!isOwnerRole(callerPerms.role?.name)) {
          const callerPermSet = new Set(callerPerms.permissions);
          const unauthorizedPerm = permission_keys.find((k) => !callerPermSet.has(k));
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

      if (permission_keys.length > 0) {
        const permsRes = await req.db.query(
          'SELECT id, `key` FROM permissions WHERE `key` IN (?)',
          [permission_keys]
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

    if (workspaceId) {
      broadcastWorkspaceEvent(workspaceId, 'workspace:role_updated', { role: rolePayload }, req.headers['x-origin-id'], req.tenant?.id);
    }

    await logAuthEvent(req.db, {
      userId: req.user.id,
      email: req.user.email,
      eventType: 'role.updated',
      req,
      metadata: {
        workspace_id: workspaceId,
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

    if (role.is_system || isOwnerRole(role.name)) {
      return res.status(400).json({
        error: { message: 'Owner and built-in system roles cannot be deleted', code: 'ROLE_IS_SYSTEM' }
      });
    }

    const workspaceId = role.workspace_id;
    if (workspaceId) {
      const hasPerm = (await userHasPermission(req.user.id, workspaceId, 'role.delete', req.db)) ||
                      (await userHasPermission(req.user.id, workspaceId, 'workspace.manage_roles', req.db));
      if (!hasPerm) {
        return res.status(403).json({
          error: { message: 'You do not have permission to delete custom roles', code: 'PERMISSION_DENIED' }
        });
      }
    }

    // Check if role is assigned to any workspace members
    const memberCountRes = await req.db.query(
      'SELECT COUNT(*) as count FROM workspace_members WHERE role_id = ?',
      [roleId]
    );
    const count = Number(memberCountRes[0]?.count || 0);

    if (count > 0) {
      return res.status(400).json({
        error: {
          message: `Cannot delete custom role while ${count} member(s) are assigned to it. Reassign members first.`,
          code: 'ROLE_IN_USE'
        }
      });
    }

    await req.db.execute('DELETE FROM roles WHERE id = ?', [roleId]);

    if (workspaceId) {
      broadcastWorkspaceEvent(workspaceId, 'workspace:role_deleted', { roleId }, req.headers['x-origin-id'], req.tenant?.id);
    }

    await logAuthEvent(req.db, {
      userId: req.user.id,
      email: req.user.email,
      eventType: 'role.deleted',
      req,
      metadata: {
        workspace_id: workspaceId,
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

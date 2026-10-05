const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const {
  requirePermission,
  userHasPermission,
  getUserPermissions,
  countSuperAdmins,
  countOwners
} = require('../middleware/permissions');
const { sendUserEvent, disconnectUserSockets, broadcastWorkspaceEvent } = require('../socket');
const { notify } = require('../services/notify');
const { revokeAllSessions } = require('../services/sessionService');
const { logAuthEvent } = require('../services/authAudit');
const { validatePassword, generateCompliantPassword } = require('../utils/passwordPolicy');
const { canResetTarget, isOwnerRole, getRoleRank } = require('../utils/roleRank');

const router = express.Router();

const createWorkspaceSchema = z.object({
  name: z.string().min(1, 'Workspace name is required')
});

const updateWorkspaceSchema = z.object({
  name: z.string().min(1).optional(),
  is_archived: z.boolean().optional(),
  require_2fa_for_admins: z.boolean().optional()
});

const createRoleSchema = z.object({
  name: z.string().min(1, 'Role name is required'),
  permission_keys: z.array(z.string()).default([])
});

const assignRoleSchema = z.object({
  role_id: z.number().int().positive(),
  board_ids: z.array(z.number()).optional()
});

// GET /api/workspaces - List all workspaces user belongs to
router.get('/', requireAuth, async (req, res, next) => {
  try {
    // Check if user has any pending invitations matching their email address and auto-accept
    if (req.user && req.user.email) {
      const pendingRes = await req.db.query(
        `SELECT pi.id, pi.workspace_id, GROUP_CONCAT(ib.board_id) as board_ids_str
         FROM pending_invitations pi
         LEFT JOIN invitation_boards ib ON pi.id = ib.invitation_id
         WHERE pi.email = ? AND pi.status = 'pending'
         GROUP BY pi.id, pi.workspace_id`,
        [req.user.email]
      );

      if (pendingRes.length > 0) {
        const teamMemberRoleRes = await req.db.query(
          "SELECT id FROM roles WHERE is_system = 1 AND name = 'Team Member' AND workspace_id IS NULL"
        );
        const teamMemberRoleId = teamMemberRoleRes[0]?.id;

        for (const inviteRow of pendingRes) {
          const boardIds = inviteRow.board_ids_str ? inviteRow.board_ids_str.split(',').map(Number) : [];

          await req.db.execute(
            `INSERT INTO workspace_members (workspace_id, user_id, role, role_id)
             VALUES (?, ?, 'Team Member', ?)
             ON DUPLICATE KEY UPDATE role_id = VALUES(role_id), role = 'Team Member'`,
            [inviteRow.workspace_id, req.user.id, teamMemberRoleId]
          );

          if (boardIds.length > 0) {
            for (const boardId of boardIds) {
              await req.db.execute(
                "INSERT IGNORE INTO board_members (board_id, user_id, role) VALUES (?, ?, 'member')",
                [boardId, req.user.id]
              );
            }
          } else {
            const allWsBoards = await req.db.query(
              'SELECT id FROM boards WHERE workspace_id = ? AND is_archived = 0',
              [inviteRow.workspace_id]
            );
            for (const b of allWsBoards) {
              await req.db.execute(
                "INSERT IGNORE INTO board_members (board_id, user_id, role) VALUES (?, ?, 'member')",
                [b.id, req.user.id]
              );
            }
          }

          await req.db.execute(
            `UPDATE pending_invitations
             SET status = 'accepted', accepted_at = CURRENT_TIMESTAMP(3), accepted_by_user_id = ?
             WHERE id = ?`,
            [req.user.id, inviteRow.id]
          );
        }
      }
    }

    const wsRes = await req.db.query(
      `SELECT w.id, w.name, w.is_archived, w.created_at, COALESCE(r.name, wm.role, 'Team Member') as role_name, r.id as role_id
       FROM workspaces w
       JOIN workspace_members wm ON w.id = wm.workspace_id
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE wm.user_id = ? AND w.is_archived = 0
       ORDER BY w.id ASC`,
      [req.user.id]
    );
    return res.json({ workspaces: wsRes });
  } catch (err) {
    next(err);
  }
});

// POST /api/workspaces - Create new workspace and assign Super Admin to creator
router.post('/', requireAuth, validate(createWorkspaceSchema), async (req, res, next) => {
  const { name } = req.body;
  try {
    const wsExec = await req.db.execute(
      'INSERT INTO workspaces (name) VALUES (?)',
      [name]
    );
    const workspaceId = wsExec.insertId;
    const [workspace] = await req.db.query('SELECT id, name, created_at FROM workspaces WHERE id = ?', [workspaceId]);

    // Find Owner/Super Admin system role ID
    const ownerRoleRes = await req.db.query(
      "SELECT id, name FROM roles WHERE is_system = 1 AND name IN ('Owner', 'Super Admin') AND workspace_id IS NULL ORDER BY (name = 'Owner') DESC LIMIT 1"
    );
    const ownerRoleId = ownerRoleRes[0]?.id;
    const ownerRoleName = ownerRoleRes[0]?.name || 'Owner';

    await req.db.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)',
      [workspace.id, req.user.id, ownerRoleName, ownerRoleId]
    );

    return res.status(201).json({ workspace: { ...workspace, role: ownerRoleName, role_id: ownerRoleId } });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/workspaces/:id - Update workspace
router.patch('/:id', requireAuth, requirePermission('workspace.edit_settings'), validate(updateWorkspaceSchema), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const { name, is_archived, require_2fa_for_admins } = req.body;

  try {
    const updates = [];
    const values = [];

    if (name !== undefined) {
      updates.push('name = ?');
      values.push(name);
    }
    if (is_archived !== undefined) {
      updates.push('is_archived = ?');
      values.push(is_archived ? 1 : 0);
    }
    if (require_2fa_for_admins !== undefined) {
      updates.push('require_2fa_for_admins = ?');
      values.push(require_2fa_for_admins ? 1 : 0);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: { message: 'No fields to update', code: 'BAD_REQUEST' } });
    }

    values.push(workspaceId);
    const execRes = await req.db.execute(
      `UPDATE workspaces SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    if (execRes.affectedRows === 0) {
      return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
    }

    const [updatedWs] = await req.db.query('SELECT id, name, is_archived, require_2fa_for_admins, created_at FROM workspaces WHERE id = ?', [workspaceId]);
    const wsPayload = { ...updatedWs, require_2fa_for_admins: !!updatedWs.require_2fa_for_admins };
    broadcastWorkspaceEvent(workspaceId, 'workspace:updated', { workspace: wsPayload }, req.headers['x-origin-id'], req.tenant?.id);
    return res.json({ workspace: wsPayload });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/workspaces/:id - Delete workspace
router.delete('/:id', requireAuth, requirePermission('workspace.delete'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);

  try {
    const ws = await req.db.query('SELECT id FROM workspaces WHERE id = ?', [workspaceId]);
    if (ws.length === 0) {
      return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
    }

    await req.db.execute('DELETE FROM workspaces WHERE id = ?', [workspaceId]);
    return res.json({ message: 'Workspace deleted successfully', id: workspaceId });
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/my-permissions - Get user's effective role and permissions
router.get('/:id/my-permissions', requireAuth, async (req, res, next) => {
  const workspaceId = Number(req.params.id);

  try {
    const permData = await getUserPermissions(req.user.id, workspaceId, req.db);
    return res.json(permData);
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/roles - Get all system & custom roles for workspace with member counts
router.get('/:id/roles', requireAuth, async (req, res, next) => {
  const workspaceId = Number(req.params.id);

  try {
    const rolesRes = await req.db.query(
      `SELECT r.id, r.name, r.is_system, r.is_editable, r.workspace_id, r.created_at,
              COUNT(DISTINCT wm.user_id) as member_count,
              GROUP_CONCAT(DISTINCT p.key) as permission_keys_str
       FROM roles r
       LEFT JOIN workspace_members wm ON r.id = wm.role_id AND wm.workspace_id = ?
       LEFT JOIN role_permissions rp ON r.id = rp.role_id
       LEFT JOIN permissions p ON rp.permission_id = p.id
       WHERE r.workspace_id IS NULL OR r.workspace_id = ?
       GROUP BY r.id, r.name, r.is_system, r.is_editable, r.workspace_id, r.created_at
       ORDER BY r.is_system DESC, r.id ASC`,
      [workspaceId, workspaceId]
    );

    // Expand Super Admin role permissions array if null
    const allPermsRes = await req.db.query('SELECT `key` FROM permissions');
    const allPermKeys = allPermsRes.map((p) => p.key);

    const roles = rolesRes.map((r) => {
      const keys = r.permission_keys_str ? r.permission_keys_str.split(',') : [];
      if (r.name === 'Super Admin' || r.name === 'Owner') {
        return { ...r, permission_keys: allPermKeys };
      }
      return { ...r, permission_keys: Array.from(new Set(keys)) };
    });

    return res.json({ roles });
  } catch (err) {
    next(err);
  }
});

// POST /api/workspaces/:id/roles - Create custom role
router.post('/:id/roles', requireAuth, requirePermission('role.create'), validate(createRoleSchema), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const { name, permission_keys } = req.body;

  try {
    // Privilege escalation check: caller cannot grant permissions they do not possess
    const callerPerms = await getUserPermissions(req.user.id, workspaceId, req.db);
    if (!isOwnerRole(callerPerms.role?.name)) {
      const callerPermSet = new Set(callerPerms.permissions);
      const unauthorizedPerm = (permission_keys || []).find((k) => !callerPermSet.has(k));
      if (unauthorizedPerm) {
        return res.status(403).json({
          error: {
            message: `You cannot create a role with permissions you do not possess (${unauthorizedPerm})`,
            code: 'PRIVILEGE_ESCALATION_FORBIDDEN'
          }
        });
      }
    }

    const roleExec = await req.db.execute(
      `INSERT INTO roles (workspace_id, name, is_system, is_editable, created_by_user_id)
       VALUES (?, ?, 0, 1, ?)`,
      [workspaceId, name.trim(), req.user.id]
    );

    const roleId = roleExec.insertId;
    const [role] = await req.db.query(
      'SELECT id, workspace_id, name, is_system, is_editable, created_at FROM roles WHERE id = ?',
      [roleId]
    );

    if (Array.isArray(permission_keys) && permission_keys.length > 0) {
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

    const createdRole = {
      ...role,
      member_count: 0,
      permission_keys: permission_keys || []
    };
    broadcastWorkspaceEvent(workspaceId, 'workspace:role_created', { role: createdRole }, req.headers['x-origin-id'], req.tenant?.id);
    return res.status(201).json({ role: createdRole });
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/members - List members
router.get('/:id/members', requireAuth, async (req, res, next) => {
  const workspaceId = Number(req.params.id);

  try {
    const isMember = await req.db.query(
      'SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
      [workspaceId, req.user.id]
    );
    if (isMember.length === 0) {
      return res.status(403).json({ error: { message: 'Access denied to workspace members', code: 'FORBIDDEN' } });
    }

    const membersRes = await req.db.query(
      `SELECT u.id, u.name, u.email, r.id as role_id, r.name as role_name, r.is_system, r.is_editable
       FROM workspace_members wm
       JOIN users u ON wm.user_id = u.id
       JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ?
       ORDER BY r.is_system DESC, u.name ASC`,
      [workspaceId]
    );

    const boardMembersRes = await req.db.query(
      `SELECT bm.user_id, bm.board_id
       FROM board_members bm
       JOIN boards b ON bm.board_id = b.id
       WHERE b.workspace_id = ?`,
      [workspaceId]
    );

    const userBoardsMap = {};
    boardMembersRes.forEach((row) => {
      if (!userBoardsMap[row.user_id]) userBoardsMap[row.user_id] = [];
      userBoardsMap[row.user_id].push(row.board_id);
    });

    const members = membersRes.map((m) => ({
      id: m.id,
      name: m.name,
      email: m.email,
      role: m.role_name,
      role_id: m.role_id,
      role_details: {
        id: m.role_id,
        name: m.role_name,
        is_system: m.is_system,
        is_editable: m.is_editable
      },
      board_ids: userBoardsMap[m.id] || []
    }));

    return res.json({ members });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/workspaces/:id/members/:userId/role - Reassign member role (Safety Floor Enforced)
router.patch('/:id/members/:userId/role', requireAuth, requirePermission('member.assign_role'), validate(assignRoleSchema), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const targetUserId = Number(req.params.userId);
  const { role_id, board_ids } = req.body;

  try {
    // Anti-escalation Rule 0: Cannot change your own role
    if (Number(req.user.id) === targetUserId) {
      return res.status(403).json({
        error: { message: 'You cannot change your own role', code: 'SELF_ROLE_CHANGE_FORBIDDEN' }
      });
    }

    // 1. Fetch current role of target user
    const targetMemberRes = await req.db.query(
      `SELECT r.id as role_id, r.name as role_name
       FROM workspace_members wm
       JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, targetUserId]
    );

    if (targetMemberRes.length === 0) {
      return res.status(404).json({ error: { message: 'Workspace member not found', code: 'NOT_FOUND' } });
    }

    const currentRoleName = targetMemberRes[0].role_name;

    // 2. Fetch new role details
    const newRoleRes = await req.db.query(
      'SELECT id, name, is_system FROM roles WHERE id = ? AND (workspace_id = ? OR workspace_id IS NULL)',
      [role_id, workspaceId]
    );

    if (newRoleRes.length === 0) {
      return res.status(404).json({ error: { message: 'Role not found', code: 'NOT_FOUND' } });
    }

    const newRole = newRoleRes[0];

    // Fetch caller role & ranks
    const callerMemberRes = await req.db.query(
      `SELECT r.id as role_id, r.name as role_name
       FROM workspace_members wm
       JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, req.user.id]
    );
    const callerRoleName = callerMemberRes[0]?.role_name || 'Team Member';
    const callerRank = getRoleRank(callerRoleName);
    const targetRank = getRoleRank(currentRoleName);
    const newRank = getRoleRank(newRole.name);

    // Anti-escalation Rule 1: Only an Owner may modify another Owner
    if (isOwnerRole(currentRoleName) && !isOwnerRole(callerRoleName)) {
      return res.status(403).json({
        error: {
          message: 'Only an Owner may modify an Owner',
          code: 'ONLY_OWNER_MAY_MODIFY_OWNER'
        }
      });
    }

    // Anti-escalation Rule 2: Cannot demote the last Owner in workspace
    if (isOwnerRole(currentRoleName) && !isOwnerRole(newRole.name)) {
      const ownerCount = await countOwners(workspaceId, req.db);
      if (ownerCount <= 1) {
        return res.status(409).json({
          error: {
            message: 'A workspace must have at least one Owner at all times. You cannot demote the only Owner.',
            code: 'LAST_OWNER_CANNOT_BE_REMOVED'
          }
        });
      }
    }

    // Anti-escalation Rule 3: Cannot change the role of someone with equal or higher rank (unless caller is Owner)
    if (!isOwnerRole(callerRoleName) && callerRank <= targetRank) {
      return res.status(403).json({
        error: {
          message: 'You cannot change the role of a member with equal or higher rank',
          code: 'INSUFFICIENT_ROLE_RANK'
        }
      });
    }

    // Anti-escalation Rule 4: Cannot assign a role with higher rank than caller's own rank
    if (!isOwnerRole(callerRoleName) && newRank > callerRank) {
      return res.status(403).json({
        error: {
          message: 'Cannot assign a role with higher rank than your own',
          code: 'PRIVILEGE_ESCALATION_FORBIDDEN'
        }
      });
    }

    // Anti-escalation Rule 5: Cannot assign a role with permissions caller does not possess
    if (!isOwnerRole(callerRoleName)) {
      const newRolePermsRes = await req.db.query(
        'SELECT p.key FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = ?',
        [newRole.id]
      );
      const newRolePermKeys = newRolePermsRes.map((p) => p.key);
      const callerPerms = await getUserPermissions(req.user.id, workspaceId, req.db);
      const callerPermSet = new Set(callerPerms.permissions);
      const unauthorizedPerm = newRolePermKeys.find((k) => !callerPermSet.has(k));
      if (unauthorizedPerm) {
        return res.status(403).json({
          error: {
            message: `You cannot assign a role containing permissions you do not possess (${unauthorizedPerm})`,
            code: 'PRIVILEGE_ESCALATION_FORBIDDEN'
          }
        });
      }
    }

    // Fetch old member state to detect exact role & board changes
    const oldMemberRes = await req.db.query(
      'SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
      [workspaceId, targetUserId]
    );
    const oldRoleId = oldMemberRes[0]?.role_id;

    const oldBoardsRes = await req.db.query(
      `SELECT board_id FROM board_members WHERE user_id = ? AND board_id IN (SELECT id FROM boards WHERE workspace_id = ?)`,
      [targetUserId, workspaceId]
    );
    const oldBoardIds = oldBoardsRes.map((r) => r.board_id);

    // Update member role_id
    await req.db.execute(
      'UPDATE workspace_members SET role_id = ? WHERE workspace_id = ? AND user_id = ?',
      [role_id, workspaceId, targetUserId]
    );

    // Update board permissions if provided
    if (Array.isArray(board_ids)) {
      const wsBoards = await req.db.query('SELECT id FROM boards WHERE workspace_id = ?', [workspaceId]);
      const validWsBoardIds = wsBoards.map((b) => b.id);

      if (validWsBoardIds.length > 0) {
        if (board_ids.length > 0) {
          await req.db.query(
            `DELETE FROM board_members 
             WHERE user_id = ? AND board_id IN (?) AND board_id NOT IN (?)`,
            [targetUserId, validWsBoardIds, board_ids]
          );
        } else {
          await req.db.query(
            `DELETE FROM board_members 
             WHERE user_id = ? AND board_id IN (?)`,
            [targetUserId, validWsBoardIds]
          );
        }
      }

      for (const bId of board_ids) {
        if (validWsBoardIds.includes(bId)) {
          await req.db.execute(
            `INSERT INTO board_members (board_id, user_id, role)
             VALUES (?, ?, 'member')
             ON DUPLICATE KEY UPDATE role = VALUES(role)`,
            [bId, targetUserId]
          );
        }
      }

      // Notify added/removed board access individually
      const addedBoardIds = board_ids.filter((bId) => !oldBoardIds.includes(bId));
      const removedBoardIds = oldBoardIds.filter((bId) => !board_ids.includes(bId));

      for (const bId of addedBoardIds) {
        const bRes = await req.db.query('SELECT name FROM boards WHERE id = ?', [bId]);
        await notify({
          eventType: 'board.member_added',
          actorUserId: req.user.id,
          targetUserId,
          boardId: bId,
          workspaceId,
          meta: { boardName: bRes[0]?.name || 'Board' }
        });
      }

      for (const bId of removedBoardIds) {
        const bRes = await req.db.query('SELECT name FROM boards WHERE id = ?', [bId]);
        await notify({
          eventType: 'board.member_removed',
          actorUserId: req.user.id,
          targetUserId,
          boardId: bId,
          workspaceId,
          meta: { boardName: bRes[0]?.name || 'Board' }
        });
      }
    }

    sendUserEvent(targetUserId, 'user:permissions_updated', {
      workspaceId,
      targetUserId,
      roleId: role_id,
      boardIds: board_ids
    });

    // Notify role change ONLY IF the role ID actually changed
    if (oldRoleId && Number(oldRoleId) !== Number(role_id)) {
      const wsRes = await req.db.query('SELECT name FROM workspaces WHERE id = ?', [workspaceId]);
      const roleRes = await req.db.query('SELECT name FROM roles WHERE id = ?', [role_id]);
      await notify({
        eventType: 'member.role_changed',
        actorUserId: req.user.id,
        targetUserId,
        workspaceId,
        meta: { roleName: roleRes[0]?.name || 'Member', workspaceName: wsRes[0]?.name || 'Workspace' }
      });
      // Revoke all sessions for target user so old permissions cannot be refreshed
      await revokeAllSessions(req.db, targetUserId, 'ROLE_CHANGE', req);
    }

    broadcastWorkspaceEvent(workspaceId, 'workspace:member_updated', { workspaceId, targetUserId, roleId: role_id }, req.headers['x-origin-id'], req.tenant?.id);
    return res.json({ message: 'Member role and permissions updated successfully' });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/workspaces/:id/members/:userId - Remove member (Safety Floor Enforced)
router.delete('/:id/members/:userId', requireAuth, requirePermission('member.remove'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const targetUserId = Number(req.params.userId);

  try {
    if (Number(req.user.id) === targetUserId) {
      return res.status(403).json({
        error: { message: 'You cannot remove yourself from the workspace. Use leave instead.', code: 'SELF_REMOVAL_FORBIDDEN' }
      });
    }

    const targetMemberRes = await req.db.query(
      `SELECT r.name as role_name FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, targetUserId]
    );

    if (targetMemberRes.length === 0) {
      return res.status(404).json({ error: { message: 'Workspace member not found', code: 'NOT_FOUND' } });
    }

    const callerMemberRes = await req.db.query(
      `SELECT r.name as role_name FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, req.user.id]
    );
    const callerRoleName = callerMemberRes[0]?.role_name || 'Team Member';
    const targetRoleName = targetMemberRes[0]?.role_name || 'Team Member';

    if (isOwnerRole(targetRoleName)) {
      if (!isOwnerRole(callerRoleName)) {
        return res.status(403).json({
          error: { message: 'Only an Owner may remove another Owner', code: 'ONLY_OWNER_MAY_MODIFY_OWNER' }
        });
      }
      const ownerCount = await countOwners(workspaceId, req.db);
      if (ownerCount <= 1) {
        return res.status(409).json({
          error: { message: 'Cannot remove the sole Owner of a workspace.', code: 'LAST_OWNER_CANNOT_BE_REMOVED' }
        });
      }
    } else {
      const callerRank = getRoleRank(callerRoleName);
      const targetRank = getRoleRank(targetRoleName);
      if (!isOwnerRole(callerRoleName) && callerRank <= targetRank) {
        return res.status(403).json({
          error: { message: 'You cannot remove a member with equal or higher rank', code: 'INSUFFICIENT_ROLE_RANK' }
        });
      }
    }

    const wsRes = await req.db.query('SELECT name FROM workspaces WHERE id = ?', [workspaceId]);

    await notify({
      eventType: 'member.removed',
      actorUserId: req.user.id,
      targetUserId,
      workspaceId,
      meta: { workspaceName: wsRes[0]?.name || 'Workspace' }
    });

    await req.db.execute('DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?', [workspaceId, targetUserId]);
    await req.db.execute(
      `DELETE FROM board_members WHERE user_id = ? AND board_id IN (SELECT id FROM boards WHERE workspace_id = ?)`,
      [targetUserId, workspaceId]
    );

    // Revoke all sessions for removed member
    await revokeAllSessions(req.db, targetUserId, 'MEMBER_REMOVED', req);

    broadcastWorkspaceEvent(workspaceId, 'workspace:member_removed', { workspaceId, targetUserId }, req.headers['x-origin-id'], req.tenant?.id);
    return res.json({ message: 'Member removed from workspace' });
  } catch (err) {
    next(err);
  }
});

// POST /api/workspaces/:workspaceId/members/:userId/reset-password
// Sets a temporary password for a member and forces change at next login (must_change_password)
// Item 1: member.reset_password may only be used on a user whose role rank is below caller's; never on yourself; only an Owner may reset an Owner.
router.post('/:workspaceId/members/:userId/reset-password', requireAuth, requirePermission('member.reset_password'), async (req, res, next) => {
  const workspaceId = Number(req.params.workspaceId);
  const targetUserId = Number(req.params.userId);

  try {
    const memberRes = await req.db.query(
      'SELECT u.id, u.email, u.name FROM workspace_members wm JOIN users u ON wm.user_id = u.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [workspaceId, targetUserId]
    );

    if (memberRes.length === 0) {
      return res.status(404).json({ error: { message: 'Workspace member not found', code: 'NOT_FOUND' } });
    }

    const targetUser = memberRes[0];

    // Evaluate caller and target role ranks
    const callerRoleRes = await req.db.query(
      `SELECT wm.role as legacy_role, r.name as role_name
       FROM workspace_members wm
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, req.user.id]
    );
    const callerRole = callerRoleRes[0]?.role_name || callerRoleRes[0]?.legacy_role || 'member';

    const targetRoleRes = await req.db.query(
      `SELECT wm.role as legacy_role, r.name as role_name
       FROM workspace_members wm
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, targetUserId]
    );
    const targetRole = targetRoleRes[0]?.role_name || targetRoleRes[0]?.legacy_role || 'member';

    const authority = canResetTarget(callerRole, targetRole, req.user.id, targetUserId);
    if (!authority.allowed) {
      return res.status(403).json({ error: { message: authority.message, code: authority.code } });
    }

    let temporaryPassword = req.body.temporaryPassword;
    if (temporaryPassword) {
      const validation = validatePassword(temporaryPassword);
      if (!validation.isValid) {
        return res.status(400).json({ error: { message: validation.error, code: 'PASSWORD_TOO_WEAK' } });
      }
    } else {
      temporaryPassword = generateCompliantPassword(14);
    }

    const passwordHash = await bcrypt.hash(temporaryPassword, 12);

    await req.db.execute(
      'UPDATE users SET password_hash = ?, must_change_password = 1, failed_login_attempts = 0, locked_until = NULL WHERE id = ?',
      [passwordHash, targetUserId]
    );

    // Revoke all existing sessions for the target user and disconnect sockets
    await revokeAllSessions(req.db, targetUserId, 'ADMIN_PASSWORD_RESET', req);
    disconnectUserSockets(targetUserId, req.tenant ? req.tenant.id : null, 'ADMIN_PASSWORD_RESET');

    // Record auth audit log (Item 4: temp password NEVER appears in audit log)
    await logAuthEvent(req.db, {
      userId: targetUserId,
      email: targetUser.email,
      eventType: 'PASSWORD_RESET',
      req,
      metadata: { resetBy: req.user.id, workspaceId }
    });

    return res.json({
      message: 'Temporary password set successfully',
      user: { id: targetUser.id, email: targetUser.email, name: targetUser.name },
      temporary_password: temporaryPassword,
      must_change_password: true
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/workspaces/:workspaceId/members/:userId/reset-2fa
// Administratively resets 2FA for a workspace member, revoking sessions and disconnecting sockets
// Item 1: member.reset_2fa with the same rank rules as reset_password
router.post('/:workspaceId/members/:userId/reset-2fa', requireAuth, requirePermission('member.reset_2fa'), async (req, res, next) => {
  const workspaceId = Number(req.params.workspaceId);
  const targetUserId = Number(req.params.userId);

  try {
    const memberRes = await req.db.query(
      'SELECT u.id, u.email, u.name, u.totp_enabled FROM workspace_members wm JOIN users u ON wm.user_id = u.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [workspaceId, targetUserId]
    );

    if (memberRes.length === 0) {
      return res.status(404).json({ error: { message: 'Workspace member not found', code: 'NOT_FOUND' } });
    }

    const targetUser = memberRes[0];

    const callerRoleRes = await req.db.query(
      `SELECT wm.role as legacy_role, r.name as role_name
       FROM workspace_members wm
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, req.user.id]
    );
    const callerRole = callerRoleRes[0]?.role_name || callerRoleRes[0]?.legacy_role || 'member';

    const targetRoleRes = await req.db.query(
      `SELECT wm.role as legacy_role, r.name as role_name
       FROM workspace_members wm
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, targetUserId]
    );
    const targetRole = targetRoleRes[0]?.role_name || targetRoleRes[0]?.legacy_role || 'member';

    const authority = canResetTarget(callerRole, targetRole, req.user.id, targetUserId);
    if (!authority.allowed) {
      return res.status(403).json({ error: { message: authority.message, code: authority.code } });
    }

    await req.db.execute(
      'UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_enrolled_at = NULL, last_totp_code = NULL, last_totp_timestamp = NULL WHERE id = ?',
      [targetUserId]
    );

    await req.db.execute('DELETE FROM recovery_codes WHERE user_id = ?', [targetUserId]);

    // Revoke all sessions and disconnect active sockets
    await revokeAllSessions(req.db, targetUserId, 'ADMIN_2FA_RESET', req);
    disconnectUserSockets(targetUserId, req.tenant ? req.tenant.id : null, 'ADMIN_2FA_RESET');

    // Record auth audit log
    await logAuthEvent(req.db, {
      userId: targetUserId,
      email: targetUser.email,
      eventType: '2FA_RESET',
      req,
      metadata: { resetBy: req.user.id, workspaceId }
    });

    return res.json({
      message: 'Two-factor authentication reset successfully for user',
      user: { id: targetUser.id, email: targetUser.email, name: targetUser.name },
      totp_enabled: false
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

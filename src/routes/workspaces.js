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
const { sanitizePlain } = require('../utils/sanitizer');
const { createInvitationHelper } = require('./invitations');

const router = express.Router();

const createWorkspaceSchema = z.object({
  name: z.string().min(1, 'Workspace name is required').transform((v) => sanitizePlain(v))
});

const updateWorkspaceSchema = z.object({
  name: z.string().min(1).transform((v) => sanitizePlain(v)).optional(),
  is_archived: z.boolean().optional(),
  require_2fa_for_admins: z.boolean().optional()
});

const createRoleSchema = z.object({
  name: z.string().min(1, 'Role name is required').transform((v) => sanitizePlain(v)),
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
        `SELECT pi.id, pi.workspace_id, pi.role_id, GROUP_CONCAT(ib.board_id) as board_ids_str
         FROM pending_invitations pi
         LEFT JOIN invitation_boards ib ON pi.id = ib.invitation_id
         WHERE pi.email = ? AND pi.status = 'pending'
         GROUP BY pi.id, pi.workspace_id, pi.role_id`,
        [req.user.email]
      );

      if (pendingRes.length > 0) {
        const teamMemberRoleRes = await req.db.query(
          "SELECT id, name FROM roles WHERE is_system = 1 AND name = 'Team Member' AND workspace_id IS NULL"
        );
        const defaultRoleId = teamMemberRoleRes[0]?.id;
        const defaultRoleName = teamMemberRoleRes[0]?.name || 'Team Member';

        for (const inviteRow of pendingRes) {
          const boardIds = inviteRow.board_ids_str ? inviteRow.board_ids_str.split(',').map(Number) : [];

          let targetRoleId = inviteRow.role_id;
          let targetRoleName = defaultRoleName;
          if (targetRoleId) {
            const rRes = await req.db.query(
              'SELECT id, name FROM roles WHERE id = ? AND (workspace_id = ? OR workspace_id IS NULL)',
              [targetRoleId, inviteRow.workspace_id]
            );
            if (rRes.length > 0) {
              targetRoleName = rRes[0].name;
            } else {
              targetRoleId = defaultRoleId;
            }
          } else {
            targetRoleId = defaultRoleId;
          }

          await req.db.execute(
            `INSERT INTO workspace_members (workspace_id, user_id, role, role_id)
             VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE role_id = VALUES(role_id), role = VALUES(role)`,
            [inviteRow.workspace_id, req.user.id, targetRoleName, targetRoleId]
          );

          if (boardIds.length > 0) {
            for (const boardId of boardIds) {
              await req.db.execute(
                "INSERT IGNORE INTO board_members (board_id, user_id, role) VALUES (?, ?, 'member')",
                [boardId, req.user.id]
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
  const name = sanitizePlain(req.body.name);
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
      values.push(sanitizePlain(name));
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
       ORDER BY r.is_system DESC,
                FIELD(r.name, 'Owner', 'Super Admin', 'Admin', 'Project Manager', 'Team Member', 'Viewer', 'Guest'),
                r.id ASC`,
      [workspaceId, workspaceId]
    );

    // Expand Super Admin / Owner role permissions array if null
    const allPermsRes = await req.db.query('SELECT `key` FROM permissions');
    const allPermKeys = allPermsRes.map((p) => p.key);

    const seenSystemRoleNames = new Set();
    const roles = [];

    for (const r of rolesRes) {
      if (r.is_system) {
        if (seenSystemRoleNames.has(r.name)) continue;
        seenSystemRoleNames.add(r.name);
      }
      const keys = r.permission_keys_str ? r.permission_keys_str.split(',') : [];
      if (r.name === 'Super Admin' || r.name === 'Owner') {
        roles.push({ ...r, permission_keys: allPermKeys });
      } else {
        roles.push({ ...r, permission_keys: Array.from(new Set(keys)) });
      }
    }

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

    await logAuthEvent(req.db, {
      userId: req.user.id,
      email: req.user.email,
      eventType: 'role.created',
      req,
      metadata: {
        workspace_id: workspaceId,
        role_id: roleId,
        role_name: name.trim(),
        permission_count: (permission_keys || []).length
      }
    });

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

    const wsRes = await req.db.query('SELECT name FROM workspaces WHERE id = ?', [workspaceId]);
    const workspaceName = wsRes[0]?.name || 'Workspace';

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
      `SELECT bm.user_id, bm.board_id, b.name as board_name
       FROM board_members bm
       JOIN boards b ON bm.board_id = b.id
       WHERE b.workspace_id = ? AND b.is_archived = 0`,
      [workspaceId]
    );

    const userBoardsMap = {};
    boardMembersRes.forEach((row) => {
      if (!userBoardsMap[row.user_id]) userBoardsMap[row.user_id] = [];
      userBoardsMap[row.user_id].push({ id: row.board_id, name: row.board_name });
    });

    const roleIds = Array.from(new Set(membersRes.map((m) => m.role_id).filter(Boolean)));
    let rolePermMap = {};
    if (roleIds.length > 0) {
      const rpRes = await req.db.query(
        `SELECT rp.role_id, p.key
         FROM role_permissions rp
         JOIN permissions p ON rp.permission_id = p.id
         WHERE rp.role_id IN (?)`,
        [roleIds]
      );
      rpRes.forEach((row) => {
        if (!rolePermMap[row.role_id]) rolePermMap[row.role_id] = [];
        rolePermMap[row.role_id].push(row.key);
      });
    }

    const allPermsRes = await req.db.query('SELECT `key` FROM permissions');
    const allPermKeys = allPermsRes.map((p) => p.key);

    const members = membersRes.map((m) => {
      const isOwner = isOwnerRole(m.role_name);
      const permissions = isOwner ? allPermKeys : (rolePermMap[m.role_id] || []);
      const userBoards = userBoardsMap[m.id] || [];
      return {
        id: m.id,
        name: m.name,
        email: m.email,
        role: m.role_name,
        role_id: m.role_id,
        is_owner: isOwner,
        workspace_name: workspaceName,
        role_details: {
          id: m.role_id,
          name: m.role_name,
          is_system: m.is_system,
          is_editable: m.is_editable
        },
        permissions,
        permissions_count: permissions.length,
        board_ids: userBoards.map((b) => b.id),
        boards: userBoards
      };
    });

    return res.json({ members, workspace_name: workspaceName });
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

    // Rule: Owner role is locked and cannot be changed
    if (isOwnerRole(currentRoleName)) {
      return res.status(403).json({
        error: {
          message: 'The Owner role is locked and cannot be changed.',
          code: 'OWNER_ROLE_LOCKED'
        }
      });
    }

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

    // Only Owner may assign Owner role
    if (isOwnerRole(newRole.name) && !isOwnerRole(callerRoleName)) {
      return res.status(403).json({
        error: {
          message: 'Only an Owner may assign the Owner role',
          code: 'ONLY_OWNER_MAY_ASSIGN_OWNER'
        }
      });
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
        await notify(
          {
            eventType: 'board.member_added',
            actorUserId: req.user.id,
            targetUserId,
            boardId: bId,
            workspaceId,
            tenantId: req.tenant?.id || null,
            meta: { boardName: bRes[0]?.name || 'Board' }
          },
          req.db
        );
      }

      for (const bId of removedBoardIds) {
        const bRes = await req.db.query('SELECT name FROM boards WHERE id = ?', [bId]);
        await notify(
          {
            eventType: 'board.member_removed',
            actorUserId: req.user.id,
            targetUserId,
            boardId: bId,
            workspaceId,
            tenantId: req.tenant?.id || null,
            meta: { boardName: bRes[0]?.name || 'Board' }
          },
          req.db
        );
      }
    }

    sendUserEvent(targetUserId, 'user:permissions_updated', {
      workspaceId,
      targetUserId,
      roleId: role_id,
      boardIds: board_ids
    }, req.tenant?.id);

    // Notify role change ONLY IF the role ID actually changed
    if (oldRoleId && Number(oldRoleId) !== Number(role_id)) {
      const wsRes = await req.db.query('SELECT name FROM workspaces WHERE id = ?', [workspaceId]);
      const roleRes = await req.db.query('SELECT name FROM roles WHERE id = ?', [role_id]);
      await notify(
        {
          eventType: 'member.role_changed',
          actorUserId: req.user.id,
          targetUserId,
          workspaceId,
          tenantId: req.tenant?.id || null,
          meta: { roleName: roleRes[0]?.name || 'Member', workspaceName: wsRes[0]?.name || 'Workspace' }
        },
        req.db
      );
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
      `SELECT r.name as role_name, u.email as user_email
       FROM workspace_members wm 
       JOIN roles r ON wm.role_id = r.id 
       JOIN users u ON wm.user_id = u.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, targetUserId]
    );

    if (targetMemberRes.length === 0) {
      return res.status(404).json({ error: { message: 'Workspace member not found', code: 'NOT_FOUND' } });
    }

    const targetUserEmail = targetMemberRes[0]?.user_email;

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

    await notify(
      {
        eventType: 'member.removed',
        actorUserId: req.user.id,
        targetUserId,
        workspaceId,
        tenantId: req.tenant?.id || null,
        meta: { workspaceName: wsRes[0]?.name || 'Workspace' }
      },
      req.db
    );

    // Remove from workspace
    await req.db.execute('DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?', [workspaceId, targetUserId]);
    await req.db.execute(
      `DELETE FROM board_members WHERE user_id = ? AND board_id IN (SELECT id FROM boards WHERE workspace_id = ?)`,
      [targetUserId, workspaceId]
    );

    // Delete any pending invitations for this email in this workspace
    if (targetUserEmail) {
      await req.db.execute('DELETE FROM pending_invitations WHERE email = ? AND workspace_id = ?', [targetUserEmail, workspaceId]);
    }

    // Revoke all sessions for removed member
    await revokeAllSessions(req.db, targetUserId, 'MEMBER_REMOVED', req);

    // If the removed member has no other owned workspaces (invited member), clean up user completely from DB
    const ownedOtherWs = await req.db.query(
      `SELECT COUNT(*) as count FROM workspace_members wm 
       JOIN roles r ON wm.role_id = r.id 
       WHERE wm.user_id = ? AND r.name IN ('Owner', 'Super Admin')`,
      [targetUserId]
    );

    if (ownedOtherWs[0]?.count === 0) {
      await req.db.execute('DELETE FROM workspace_members WHERE user_id = ?', [targetUserId]);
      await req.db.execute('DELETE FROM board_members WHERE user_id = ?', [targetUserId]);
      if (targetUserEmail) {
        await req.db.execute('DELETE FROM pending_invitations WHERE email = ?', [targetUserEmail]);
      }
      await req.db.execute('DELETE FROM users WHERE id = ?', [targetUserId]);

      if (req.tenant?.id && targetUserEmail) {
        try {
          const { getMasterDb } = require('../services/tenantPools');
          const masterDb = getMasterDb();
          await masterDb.execute('DELETE FROM tenant_user_directory WHERE email = ? AND tenant_id = ?', [targetUserEmail, req.tenant.id]);
        } catch (e) {}
      }
    }

    broadcastWorkspaceEvent(workspaceId, 'workspace:member_removed', { workspaceId, targetUserId }, req.headers['x-origin-id'], req.tenant?.id);
    return res.json({ message: 'Member removed from workspace and database' });
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

// POST /api/workspaces/:id/members - Add or invite member to workspace
router.post('/:id/members', requireAuth, requirePermission('member.invite'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const { email, user_id, role_id, role } = req.body;

  try {
    const [workspace] = await req.db.query('SELECT * FROM workspaces WHERE id = ?', [workspaceId]);
    if (!workspace) {
      return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
    }

    let targetRoleId = role_id ? Number(role_id) : null;
    let roleName = role || 'Team Member';
    if (!targetRoleId && role) {
      const [rRow] = await req.db.query(
        'SELECT id, name FROM roles WHERE (workspace_id = ? OR workspace_id IS NULL) AND name = ? LIMIT 1',
        [workspaceId, role]
      );
      if (rRow) {
        targetRoleId = rRow.id;
        roleName = rRow.name;
      }
    }
    if (!targetRoleId) {
      const [tmRow] = await req.db.query(
        "SELECT id, name FROM roles WHERE is_system = 1 AND name = 'Team Member' AND workspace_id IS NULL LIMIT 1"
      );
      targetRoleId = tmRow?.id || 2;
      roleName = tmRow?.name || 'Team Member';
    }

    let targetUser = null;
    if (user_id) {
      const [uRow] = await req.db.query('SELECT id, email, name FROM users WHERE id = ?', [Number(user_id)]);
      targetUser = uRow;
    } else if (email) {
      const [uRow] = await req.db.query('SELECT id, email, name FROM users WHERE email = ?', [email.trim().toLowerCase()]);
      targetUser = uRow;
    }

    if (targetUser) {
      const existing = await req.db.query(
        'SELECT * FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
        [workspaceId, targetUser.id]
      );
      if (existing.length > 0) {
        return res.status(409).json({
          error: { message: 'User is already a member of this workspace', code: 'ALREADY_MEMBER' }
        });
      }

      await req.db.execute(
        'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)',
        [workspaceId, targetUser.id, roleName, targetRoleId]
      );

      const wsBoards = await req.db.query('SELECT id FROM boards WHERE workspace_id = ? AND is_archived = 0', [workspaceId]);
      for (const b of wsBoards) {
        await req.db.execute(
          "INSERT IGNORE INTO board_members (board_id, user_id, role) VALUES (?, ?, 'member')",
          [b.id, targetUser.id]
        );
      }

      await notify(
        {
          eventType: 'member.added',
          actorUserId: req.user.id,
          targetUserId: targetUser.id,
          workspaceId,
          tenantId: req.tenant?.id || null,
          meta: { workspaceName: workspace.name }
        },
        req.db
      );

      broadcastWorkspaceEvent(
        workspaceId,
        'workspace:member_added',
        { workspaceId, user: targetUser, role_id: targetRoleId },
        req.headers['x-origin-id'],
        req.tenant?.id
      );

      return res.status(201).json({
        message: 'Member added to workspace successfully',
        member: {
          id: targetUser.id,
          name: targetUser.name,
          email: targetUser.email,
          role: roleName,
          role_id: targetRoleId
        }
      });
    }

    if (email) {
      const result = await createInvitationHelper(req, {
        workspaceId,
        email: email.trim().toLowerCase(),
        roleId: targetRoleId
      });
      return res.status(201).json({
        message: 'Invitation sent to user',
        invitation: result.invitation
      });
    }

    return res.status(400).json({
      error: { message: 'Either email or user_id is required', code: 'BAD_REQUEST' }
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/workspaces/:id/invitations - Send invitation for workspace
router.post('/:id/invitations', requireAuth, requirePermission('member.invite'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const { email, role_id, board_ids } = req.body;
  if (!email) {
    return res.status(400).json({ error: { message: 'Email is required', code: 'BAD_REQUEST' } });
  }
  try {
    const result = await createInvitationHelper(req, {
      workspaceId,
      email: email.trim().toLowerCase(),
      roleId: role_id ? Number(role_id) : undefined,
      boardIds: board_ids
    });
    return res.status(201).json(result);
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/invitations - List pending invitations for workspace
router.get('/:id/invitations', requireAuth, requirePermission('member.view'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  try {
    const invites = await req.db.query(
      `SELECT pi.*, r.name as role_name, u.name as inviter_name
       FROM pending_invitations pi
       LEFT JOIN roles r ON pi.role_id = r.id
       LEFT JOIN users u ON pi.invited_by_user_id = u.id
       WHERE pi.workspace_id = ?
       ORDER BY pi.created_at DESC`,
      [workspaceId]
    );
    return res.json({ invitations: invites });
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/archived - List archived boards and cards for workspace
router.get('/:id/archived', requireAuth, async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  try {
    const wsMember = await req.db.query(
      'SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
      [workspaceId, req.user.id]
    );
    if (wsMember.length === 0) {
      return res.status(403).json({ error: { message: 'Access denied', code: 'FORBIDDEN' } });
    }

    const boards = await req.db.query(
      `SELECT b.*, w.name as workspace_name
       FROM boards b
       JOIN workspaces w ON b.workspace_id = w.id
       WHERE b.workspace_id = ? AND b.is_archived = 1
       ORDER BY b.created_at DESC`,
      [workspaceId]
    );

    const cards = await req.db.query(
      `SELECT c.*, l.name as list_name, b.name as board_name
       FROM cards c
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       WHERE b.workspace_id = ? AND c.is_archived = 1
       ORDER BY c.created_at DESC`,
      [workspaceId]
    );

    return res.json({ boards, cards });
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/activity - Workspace Activity Feed with server-side pagination (20 per page)
router.get('/:id/activity', requireAuth, requirePermission('workspace.view'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(20, Math.max(1, parseInt(req.query.limit, 10) || 20)); // Exactly 20 per page default/max
  const offset = (page - 1) * limit;

  const boardId = req.query.board_id ? Number(req.query.board_id) : null;
  const actionType = req.query.action_type ? String(req.query.action_type).trim() : null;
  const search = req.query.search ? String(req.query.search).trim() : null;

  try {
    const whereConditions = ['b.workspace_id = ?'];
    const queryParams = [workspaceId];

    if (boardId) {
      whereConditions.push('a.board_id = ?');
      queryParams.push(boardId);
    }

    if (actionType && actionType !== 'all') {
      whereConditions.push('a.action_type = ?');
      queryParams.push(actionType);
    }

    if (search) {
      whereConditions.push(
        '(c.title LIKE ? OR u.name LIKE ? OR b.name LIKE ? OR JSON_UNQUOTE(JSON_EXTRACT(a.meta_json, "$.title")) LIKE ? OR JSON_UNQUOTE(JSON_EXTRACT(a.meta_json, "$.card_title")) LIKE ?)'
      );
      const searchWildcard = `%${search}%`;
      queryParams.push(searchWildcard, searchWildcard, searchWildcard, searchWildcard, searchWildcard);
    }

    const whereSql = whereConditions.join(' AND ');

    // 1. Total count query
    const countSql = `
      SELECT COUNT(*) as total
      FROM activity_log a
      JOIN boards b ON a.board_id = b.id
      LEFT JOIN users u ON a.user_id = u.id
      LEFT JOIN cards c ON a.card_id = c.id
      WHERE ${whereSql}
    `;
    const countRes = await req.db.query(countSql, queryParams);
    const total = Number(countRes[0]?.total || 0);
    const totalPages = Math.ceil(total / limit) || 1;

    // 2. Paginated data query
    const selectSql = `
      SELECT
        a.id,
        a.board_id,
        a.card_id,
        a.user_id,
        a.action_type,
        a.meta_json,
        a.created_at,
        u.name as user_name,
        u.email as user_email,
        u.avatar_url as user_avatar,
        b.name as board_name,
        b.background_color as board_background_color,
        c.title as card_title,
        c.list_id as card_list_id
      FROM activity_log a
      JOIN boards b ON a.board_id = b.id
      LEFT JOIN users u ON a.user_id = u.id
      LEFT JOIN cards c ON a.card_id = c.id
      WHERE ${whereSql}
      ORDER BY a.created_at DESC, a.id DESC
      LIMIT ? OFFSET ?
    `;
    const rows = await req.db.query(selectSql, [...queryParams, limit, offset]);

    // 3. Boards in workspace for filtering
    const boardsRes = await req.db.query(
      'SELECT id, name, background_color FROM boards WHERE workspace_id = ? AND is_archived = 0 ORDER BY name ASC',
      [workspaceId]
    );

    // 4. Parse meta_json safely
    const activities = rows.map((row) => {
      let meta = {};
      try {
        if (typeof row.meta_json === 'string') {
          meta = JSON.parse(row.meta_json);
        } else if (typeof row.meta_json === 'object' && row.meta_json !== null) {
          meta = row.meta_json;
        }
      } catch (e) {
        meta = {};
      }

      return {
        id: row.id,
        board_id: row.board_id,
        board_name: row.board_name,
        board_background_color: row.board_background_color,
        card_id: row.card_id,
        card_title: row.card_title || meta.card_title || meta.title || null,
        user_id: row.user_id,
        user_name: row.user_name || 'System',
        user_email: row.user_email,
        user_avatar: row.user_avatar,
        action_type: row.action_type,
        meta,
        created_at: row.created_at
      };
    });

    return res.json({
      activities,
      pagination: {
        page,
        limit,
        total,
        total_pages: totalPages,
        has_more: page < totalPages
      },
      boards: boardsRes
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/reports - Comprehensive workspace analytics & reporting
router.get('/:id/reports', requireAuth, async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const boardId = req.query.board_id && req.query.board_id !== 'all' ? Number(req.query.board_id) : null;
  const timeframe = req.query.timeframe ? String(req.query.timeframe).trim() : 'all';

  try {
    const ws = await req.db.query('SELECT id, name FROM workspaces WHERE id = ?', [workspaceId]);
    if (ws.length === 0) {
      return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
    }

    const memberCheck = await req.db.query(
      'SELECT 1 FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
      [workspaceId, req.user.id]
    );
    if (memberCheck.length === 0) {
      return res.status(403).json({ error: { message: 'Access denied: not a workspace member', code: 'FORBIDDEN' } });
    }

    // 1. Fetch active boards
    const boardsRes = await req.db.query(
      `SELECT id, name, background_color, is_archived, created_at
       FROM boards
       WHERE workspace_id = ? AND is_archived = 0
       ORDER BY name ASC`,
      [workspaceId]
    );

    // Build timeframe conditions
    let timeframeClause = '';
    if (timeframe === '7d') {
      timeframeClause = 'AND c.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)';
    } else if (timeframe === '30d') {
      timeframeClause = 'AND c.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)';
    } else if (timeframe === '90d') {
      timeframeClause = 'AND c.created_at >= DATE_SUB(NOW(), INTERVAL 90 DAY)';
    } else if (timeframe === 'this_month') {
      timeframeClause = 'AND c.created_at >= DATE_FORMAT(NOW(), "%Y-%m-01")';
    }

    const boardParam = [];
    let boardClause = '';
    if (boardId) {
      boardClause = 'AND b.id = ?';
      boardParam.push(boardId);
    }

    // 2. High-level summary metrics
    const summaryRes = await req.db.query(
      `SELECT
        COUNT(DISTINCT c.id) as total_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 1 THEN c.id END) as completed_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 0 AND c.due_date IS NOT NULL AND c.due_date < NOW() THEN c.id END) as overdue_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 0 AND c.due_date IS NOT NULL AND c.due_date >= NOW() AND c.due_date <= DATE_ADD(NOW(), INTERVAL 7 DAY) THEN c.id END) as due_soon_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 0 AND (c.due_date IS NULL OR c.due_date >= NOW()) THEN c.id END) as in_progress_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 0 AND c.due_date IS NULL THEN c.id END) as no_due_date_tasks
       FROM cards c
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       WHERE b.workspace_id = ?
         AND b.is_archived = 0
         AND l.is_archived = 0
         AND c.is_archived = 0
         ${boardClause}
         ${timeframeClause}`,
      [workspaceId, ...boardParam]
    );

    const totalTasks = Number(summaryRes[0]?.total_tasks || 0);
    const completedTasks = Number(summaryRes[0]?.completed_tasks || 0);
    const overdueTasks = Number(summaryRes[0]?.overdue_tasks || 0);
    const dueSoonTasks = Number(summaryRes[0]?.due_soon_tasks || 0);
    const inProgressTasks = Number(summaryRes[0]?.in_progress_tasks || 0);
    const noDueDateTasks = Number(summaryRes[0]?.no_due_date_tasks || 0);

    const completionRate = totalTasks > 0 ? Math.round((completedTasks / totalTasks) * 1000) / 10 : 0;
    const overdueRate = totalTasks > 0 ? Math.round((overdueTasks / totalTasks) * 1000) / 10 : 0;

    // 3. Average cycle time calculation (days between card creation and completion activity, or completion time)
    const cycleRes = await req.db.query(
      `SELECT AVG(TIMESTAMPDIFF(HOUR, c.created_at, a.created_at) / 24.0) as avg_cycle_days
       FROM activity_log a
       JOIN cards c ON a.card_id = c.id
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       WHERE b.workspace_id = ?
         AND a.action_type = 'marked_complete'
         AND b.is_archived = 0
         AND l.is_archived = 0
         AND c.is_archived = 0
         ${boardClause}
         ${timeframeClause}`,
      [workspaceId, ...boardParam]
    );

    let avgCycleDays = cycleRes[0]?.avg_cycle_days != null ? Math.round(Number(cycleRes[0].avg_cycle_days) * 10) / 10 : null;
    if (avgCycleDays === null && completedTasks > 0) {
      // Fallback: age of completed tasks from created_at
      const fallbackCycle = await req.db.query(
        `SELECT AVG(TIMESTAMPDIFF(HOUR, c.created_at, NOW()) / 24.0) as avg_days
         FROM cards c
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE b.workspace_id = ?
           AND c.is_complete = 1
           AND b.is_archived = 0
           AND l.is_archived = 0
           AND c.is_archived = 0
           ${boardClause}
           ${timeframeClause}`,
        [workspaceId, ...boardParam]
      );
      avgCycleDays = fallbackCycle[0]?.avg_days != null ? Math.round(Number(fallbackCycle[0].avg_days) * 10) / 10 : 0;
    } else if (avgCycleDays === null) {
      avgCycleDays = 0;
    }

    // 4. Boards breakdown
    const boardsBreakdownRes = await req.db.query(
      `SELECT
        b.id,
        b.name,
        b.background_color,
        COUNT(DISTINCT bm.user_id) as member_count,
        COUNT(DISTINCT c.id) as total_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 1 THEN c.id END) as completed_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 0 AND c.due_date IS NOT NULL AND c.due_date < NOW() THEN c.id END) as overdue_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 0 AND (c.due_date IS NULL OR c.due_date >= NOW()) THEN c.id END) as in_progress_tasks
       FROM boards b
       LEFT JOIN board_members bm ON b.id = bm.board_id
       LEFT JOIN lists l ON b.id = l.board_id AND l.is_archived = 0
       LEFT JOIN cards c ON l.id = c.list_id AND c.is_archived = 0 ${timeframeClause}
       WHERE b.workspace_id = ? AND b.is_archived = 0
       GROUP BY b.id, b.name, b.background_color
       ORDER BY total_tasks DESC, b.name ASC`,
      [workspaceId]
    );

    const boardsBreakdown = boardsBreakdownRes.map((b) => {
      const bTotal = Number(b.total_tasks || 0);
      const bCompleted = Number(b.completed_tasks || 0);
      const bOverdue = Number(b.overdue_tasks || 0);
      const bInProgress = Number(b.in_progress_tasks || 0);
      return {
        id: b.id,
        name: b.name,
        background_color: b.background_color,
        member_count: Number(b.member_count || 0),
        total_tasks: bTotal,
        completed_tasks: bCompleted,
        overdue_tasks: bOverdue,
        in_progress_tasks: bInProgress,
        completion_rate: bTotal > 0 ? Math.round((bCompleted / bTotal) * 100) : 0
      };
    });

    // 5. Status / Lists breakdown
    const statusBreakdownRes = await req.db.query(
      `SELECT
        l.id as list_id,
        l.name as list_name,
        b.id as board_id,
        b.name as board_name,
        COUNT(DISTINCT c.id) as task_count,
        COUNT(DISTINCT CASE WHEN c.is_complete = 1 THEN c.id END) as completed_count
       FROM lists l
       JOIN boards b ON l.board_id = b.id
       LEFT JOIN cards c ON l.id = c.list_id AND c.is_archived = 0 ${timeframeClause}
       WHERE b.workspace_id = ?
         AND b.is_archived = 0
         AND l.is_archived = 0
         ${boardClause}
       GROUP BY l.id, l.name, b.id, b.name, l.position
       ORDER BY b.name ASC, l.position ASC`,
      [workspaceId, ...boardParam]
    );

    const statusBreakdown = statusBreakdownRes.map((s) => ({
      list_id: s.list_id,
      list_name: s.list_name,
      board_id: s.board_id,
      board_name: s.board_name,
      task_count: Number(s.task_count || 0),
      completed_count: Number(s.completed_count || 0),
      percentage: totalTasks > 0 ? Math.round((Number(s.task_count || 0) / totalTasks) * 100) : 0
    }));

    // 6. Labels breakdown
    const labelsBreakdownRes = await req.db.query(
      `SELECT
        lb.id,
        lb.name,
        lb.color,
        b.name as board_name,
        COUNT(DISTINCT cl.card_id) as task_count
       FROM labels lb
       JOIN boards b ON lb.board_id = b.id
       JOIN card_labels cl ON lb.id = cl.label_id
       JOIN cards c ON cl.card_id = c.id AND c.is_archived = 0 ${timeframeClause}
       JOIN lists l ON c.list_id = l.id AND l.is_archived = 0
       WHERE b.workspace_id = ?
         AND b.is_archived = 0
         ${boardClause}
       GROUP BY lb.id, lb.name, lb.color, b.name
       ORDER BY task_count DESC`,
      [workspaceId, ...boardParam]
    );

    const unlabeledRes = await req.db.query(
      `SELECT COUNT(DISTINCT c.id) as unlabeled_tasks
       FROM cards c
       JOIN lists l ON c.list_id = l.id AND l.is_archived = 0
       JOIN boards b ON l.board_id = b.id AND b.is_archived = 0
       LEFT JOIN card_labels cl ON c.id = cl.card_id
       WHERE b.workspace_id = ?
         AND c.is_archived = 0
         AND cl.label_id IS NULL
         ${boardClause}
         ${timeframeClause}`,
      [workspaceId, ...boardParam]
    );
    const unlabeledCount = Number(unlabeledRes[0]?.unlabeled_tasks || 0);

    // 7. Member workload
    const membersWorkloadRes = await req.db.query(
      `SELECT
        u.id,
        u.name,
        u.email,
        r.name as role_name,
        COUNT(DISTINCT c.id) as assigned_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 1 THEN c.id END) as completed_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 0 AND c.due_date IS NOT NULL AND c.due_date < NOW() THEN c.id END) as overdue_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 0 AND (c.due_date IS NULL OR c.due_date >= NOW()) THEN c.id END) as in_progress_tasks
       FROM workspace_members wm
       JOIN users u ON wm.user_id = u.id
       LEFT JOIN roles r ON wm.role_id = r.id
       LEFT JOIN card_members cm ON u.id = cm.user_id
       LEFT JOIN cards c ON cm.card_id = c.id AND c.is_archived = 0 ${timeframeClause}
       LEFT JOIN lists l ON c.list_id = l.id AND l.is_archived = 0
       LEFT JOIN boards b ON l.board_id = b.id AND b.is_archived = 0 AND b.workspace_id = wm.workspace_id ${boardClause}
       WHERE wm.workspace_id = ?
       GROUP BY u.id, u.name, u.email, r.name
       ORDER BY assigned_tasks DESC, u.name ASC`,
      [workspaceId, ...boardParam]
    );

    const unassignedRes = await req.db.query(
      `SELECT COUNT(DISTINCT c.id) as unassigned_tasks
       FROM cards c
       JOIN lists l ON c.list_id = l.id AND l.is_archived = 0
       JOIN boards b ON l.board_id = b.id AND b.is_archived = 0
       LEFT JOIN card_members cm ON c.id = cm.card_id
       WHERE b.workspace_id = ?
         AND c.is_archived = 0
         AND cm.user_id IS NULL
         ${boardClause}
         ${timeframeClause}`,
      [workspaceId, ...boardParam]
    );
    const unassignedCount = Number(unassignedRes[0]?.unassigned_tasks || 0);

    // Fetch all assigned cards for members in this workspace with board & list info
    const assignedCardsRes = await req.db.query(
      `SELECT
        cm.user_id,
        c.id,
        c.title,
        c.due_date,
        c.is_complete,
        c.created_at,
        l.name as list_name,
        b.id as board_id,
        b.name as board_name,
        CASE WHEN c.is_complete = 0 AND c.due_date IS NOT NULL AND c.due_date < NOW() THEN 1 ELSE 0 END as is_overdue,
        CASE WHEN c.is_complete = 0 AND c.due_date IS NOT NULL AND c.due_date >= NOW() AND c.due_date <= DATE_ADD(NOW(), INTERVAL 7 DAY) THEN 1 ELSE 0 END as is_due_soon
       FROM card_members cm
       JOIN cards c ON cm.card_id = c.id
       JOIN lists l ON c.list_id = l.id AND l.is_archived = 0
       JOIN boards b ON l.board_id = b.id AND b.is_archived = 0
       WHERE b.workspace_id = ?
         AND c.is_archived = 0
         ${boardClause}
         ${timeframeClause}
       ORDER BY c.due_date ASC, c.created_at DESC`,
      [workspaceId, ...boardParam]
    );

    const userTasksMap = {};
    assignedCardsRes.forEach((row) => {
      if (!userTasksMap[row.user_id]) userTasksMap[row.user_id] = [];
      userTasksMap[row.user_id].push({
        id: row.id,
        title: row.title,
        due_date: row.due_date,
        is_complete: Boolean(row.is_complete),
        is_overdue: Boolean(row.is_overdue),
        is_due_soon: Boolean(row.is_due_soon),
        list_name: row.list_name,
        board_id: row.board_id,
        board_name: row.board_name,
        created_at: row.created_at
      });
    });

    const membersWorkload = membersWorkloadRes.map((m) => {
      const assigned = Number(m.assigned_tasks || 0);
      const completed = Number(m.completed_tasks || 0);
      const overdue = Number(m.overdue_tasks || 0);
      const inProgress = Number(m.in_progress_tasks || 0);
      const userTasks = userTasksMap[m.id] || [];

      // Board distribution for this user
      const userBoardsMap = {};
      userTasks.forEach((t) => {
        if (!userBoardsMap[t.board_id]) {
          userBoardsMap[t.board_id] = { id: t.board_id, name: t.board_name, task_count: 0, completed_count: 0 };
        }
        userBoardsMap[t.board_id].task_count++;
        if (t.is_complete) userBoardsMap[t.board_id].completed_count++;
      });
      const userBoards = Object.values(userBoardsMap);
      const dueSoon = userTasks.filter((t) => t.is_due_soon).length;

      return {
        id: m.id,
        name: m.name,
        email: m.email,
        role: m.role_name || 'Member',
        assigned_tasks: assigned,
        completed_tasks: completed,
        overdue_tasks: overdue,
        in_progress_tasks: inProgress,
        due_soon_tasks: dueSoon,
        completion_rate: assigned > 0 ? Math.round((completed / assigned) * 100) : 0,
        boards: userBoards,
        tasks: userTasks
      };
    });

    // 8. Overdue Tasks detailed list
    const overdueTasksRes = await req.db.query(
      `SELECT
        c.id,
        c.title,
        c.due_date,
        l.name as list_name,
        b.id as board_id,
        b.name as board_name,
        TIMESTAMPDIFF(DAY, c.due_date, NOW()) as days_overdue
       FROM cards c
       JOIN lists l ON c.list_id = l.id AND l.is_archived = 0
       JOIN boards b ON l.board_id = b.id AND b.is_archived = 0
       WHERE b.workspace_id = ?
         AND c.is_archived = 0
         AND c.is_complete = 0
         AND c.due_date IS NOT NULL
         AND c.due_date < NOW()
         ${boardClause}
         ${timeframeClause}
       ORDER BY c.due_date ASC
       LIMIT 20`,
      [workspaceId, ...boardParam]
    );

    // Attach assignees for overdue tasks
    const overdueTaskIds = overdueTasksRes.map((t) => t.id);
    let overdueMembersMap = {};
    if (overdueTaskIds.length > 0) {
      const ovmRes = await req.db.query(
        `SELECT cm.card_id, u.id as user_id, u.name, u.email
         FROM card_members cm
         JOIN users u ON cm.user_id = u.id
         WHERE cm.card_id IN (${overdueTaskIds.map(() => '?').join(',')})`,
        overdueTaskIds
      );
      ovmRes.forEach((row) => {
        if (!overdueMembersMap[row.card_id]) overdueMembersMap[row.card_id] = [];
        overdueMembersMap[row.card_id].push({
          id: row.user_id,
          name: row.name,
          email: row.email
        });
      });
    }

    const overdueTasksList = overdueTasksRes.map((t) => ({
      id: t.id,
      title: t.title,
      due_date: t.due_date,
      list_name: t.list_name,
      board_id: t.board_id,
      board_name: t.board_name,
      days_overdue: Math.max(0, Number(t.days_overdue || 0)),
      members: overdueMembersMap[t.id] || []
    }));

    // 9. Daily velocity for past 7 days
    const dailyVelocityRes = await req.db.query(
      `SELECT
        DATE_FORMAT(c.created_at, '%Y-%m-%d') as date_str,
        COUNT(*) as created_count
       FROM cards c
       JOIN lists l ON c.list_id = l.id AND l.is_archived = 0
       JOIN boards b ON l.board_id = b.id AND b.is_archived = 0
       WHERE b.workspace_id = ?
         AND c.is_archived = 0
         AND c.created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
         ${boardClause}
       GROUP BY DATE_FORMAT(c.created_at, '%Y-%m-%d')
       ORDER BY date_str ASC`,
      [workspaceId, ...boardParam]
    );

    const completedVelocityRes = await req.db.query(
      `SELECT
        DATE_FORMAT(a.created_at, '%Y-%m-%d') as date_str,
        COUNT(*) as completed_count
       FROM activity_log a
       JOIN boards b ON a.board_id = b.id AND b.is_archived = 0
       WHERE b.workspace_id = ?
         AND a.action_type = 'marked_complete'
         AND a.created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
         ${boardClause}
       GROUP BY DATE_FORMAT(a.created_at, '%Y-%m-%d')
       ORDER BY date_str ASC`,
      [workspaceId, ...boardParam]
    );

    // Build 7 day calendar map
    const past7Days = [];
    const createdMap = Object.fromEntries(dailyVelocityRes.map((r) => [r.date_str, Number(r.created_count)]));
    const completedMap = Object.fromEntries(completedVelocityRes.map((r) => [r.date_str, Number(r.completed_count)]));

    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const isoDate = d.toISOString().split('T')[0];
      const dayLabel = d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
      past7Days.push({
        date: isoDate,
        label: dayLabel,
        created: createdMap[isoDate] || 0,
        completed: completedMap[isoDate] || 0
      });
    }

    return res.json({
      workspace: {
        id: ws[0].id,
        name: ws[0].name
      },
      summary: {
        total_tasks: totalTasks,
        completed_tasks: completedTasks,
        in_progress_tasks: inProgressTasks,
        overdue_tasks: overdueTasks,
        due_soon_tasks: dueSoonTasks,
        no_due_date_tasks: noDueDateTasks,
        completion_rate: completionRate,
        overdue_rate: overdueRate,
        avg_cycle_days: avgCycleDays,
        total_boards: boardsRes.length,
        total_members: membersWorkload.length,
        unassigned_tasks: unassignedCount
      },
      boards: boardsRes,
      boards_breakdown: boardsBreakdown,
      status_breakdown: statusBreakdown,
      labels_breakdown: {
        labels: labelsBreakdownRes.map((lb) => ({
          id: lb.id,
          name: lb.name,
          color: lb.color,
          board_name: lb.board_name,
          task_count: Number(lb.task_count || 0)
        })),
        unlabeled_tasks: unlabeledCount
      },
      members_workload: membersWorkload,
      overdue_tasks_list: overdueTasksList,
      velocity: past7Days
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

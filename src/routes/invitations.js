const express = require('express');
const crypto = require('crypto');
const { z } = require('zod');
const { getMasterDb, getTenantDb, getDevSingleDb } = require('../services/tenantPools');
const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { notify } = require('../services/notify');
const { userHasPermission } = require('../middleware/permissions');
const { broadcastWorkspaceEvent } = require('../socket');

const { isOwnerRole } = require('../utils/roleRank');

const router = express.Router();

const inviteSchema = z.object({
  email: z.string().email('Invalid email address'),
  workspace_id: z.number({ required_error: 'workspace_id is required' }),
  role_id: z.number().int().positive().optional(),
  board_ids: z.array(z.number()).optional().default([])
});

function normalizeEmail(email) {
  return (email || '').trim().toLowerCase();
}

function signInviteToken(rawToken, tenantSlug = 'default') {
  const hmac = crypto.createHmac('sha256', process.env.JWT_SECRET || 'invitation_secret');
  const sig = hmac.update(`${tenantSlug}:${rawToken}`).digest('hex').slice(0, 16);
  return `${tenantSlug}.${rawToken}.${sig}`;
}

function parseAndVerifyInviteToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length === 3) {
    const [tenantSlug, rawToken, sig] = parts;
    const expectedSig = crypto.createHmac('sha256', process.env.JWT_SECRET || 'invitation_secret')
      .update(`${tenantSlug}:${rawToken}`).digest('hex').slice(0, 16);
    if (sig === expectedSig) {
      return { tenantSlug, rawToken, valid: true };
    }
    return { valid: false };
  }
  if (parts.length === 1) {
    return { tenantSlug: null, rawToken: token, valid: true };
  }
  return { valid: false };
}

async function requireWorkspaceAdmin(workspaceId, userId, dbInstance = null) {
  return await userHasPermission(userId, workspaceId, 'member.invite', dbInstance);
}

// GET /api/invitations/verify?token=... (Public verification for registration page)
router.get('/verify', async (req, res, next) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).json({ error: { message: 'Token is required', code: 'BAD_REQUEST' } });
  }

  const tokenInfo = parseAndVerifyInviteToken(token);
  if (!tokenInfo || !tokenInfo.valid) {
    return res.status(400).json({ error: { message: 'Invalid invitation token signature', code: 'INVALID_SIGNATURE' } });
  }

  try {
    let activeDb = req.db;
    if (!activeDb && tokenInfo.tenantSlug && tokenInfo.tenantSlug !== 'default') {
      const masterDb = getMasterDb();
      const [tenant] = await masterDb.query(
        "SELECT id, db_name FROM tenants WHERE slug = ? AND status != 'deleted'",
        [tokenInfo.tenantSlug]
      );
      if (tenant) {
        activeDb = await getTenantDb(tenant.id);
      }
    }
    if (!activeDb) {
      activeDb = getDevSingleDb();
    }
    const inviteRes = await activeDb.query(
      `SELECT pi.id, pi.email, pi.workspace_id, pi.role_id, pi.status, pi.expires_at, w.name as workspace_name,
              r.name as role_name,
              GROUP_CONCAT(ib.board_id) as board_ids_str
       FROM pending_invitations pi
       JOIN workspaces w ON pi.workspace_id = w.id
       LEFT JOIN roles r ON pi.role_id = r.id
       LEFT JOIN invitation_boards ib ON pi.id = ib.invitation_id
       WHERE pi.token = ?
       GROUP BY pi.id, pi.email, pi.workspace_id, pi.role_id, pi.status, pi.expires_at, w.name, r.name`,
      [token]
    );

    if (inviteRes.length === 0) {
      return res.status(404).json({ error: { message: 'Invitation not found', code: 'NOT_FOUND' } });
    }

    const invite = inviteRes[0];
    if (invite.status !== 'pending') {
      return res.status(410).json({ error: { message: 'Invitation has already been used or revoked', code: 'INVITATION_INVALID' } });
    }

    if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
      return res.status(410).json({ error: { message: 'Invitation link has expired (7 day limit)', code: 'INVITATION_EXPIRED' } });
    }

    const boardIds = invite.board_ids_str ? invite.board_ids_str.split(',').map(Number) : [];

    let boardNames = [];
    if (boardIds.length > 0) {
      const boardsRes = await (req.db || getDevSingleDb()).query(
        'SELECT name FROM boards WHERE id IN (?)',
        [boardIds]
      );
      boardNames = boardsRes.map((b) => b.name);
    }

    return res.json({
      invitation: {
        id: invite.id,
        email: invite.email,
        workspace_id: invite.workspace_id,
        workspace_name: invite.workspace_name,
        role_name: invite.role_name || 'Team Member',
        board_names: boardNames,
        status: invite.status
      }
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/invitations?workspace_id=... (Fetch all invitations for workspace admin)
router.get('/', requireAuth, async (req, res, next) => {
  const { workspace_id } = req.query;
  if (!workspace_id) {
    return res.status(400).json({ error: { message: 'workspace_id is required', code: 'BAD_REQUEST' } });
  }

  try {
    const isAdmin = await requireWorkspaceAdmin(Number(workspace_id), req.user.id, req.db);
    if (!isAdmin) {
      return res.status(403).json({ error: { message: 'Only workspace admins can view invitations', code: 'FORBIDDEN' } });
    }

    const invitesRes = await req.db.query(
      `SELECT pi.id, pi.email, pi.workspace_id, pi.token, pi.role_id, pi.status, pi.created_at, pi.expires_at, pi.accepted_at,
              u.name as invited_by_name,
              r.name as role_name,
              GROUP_CONCAT(ib.board_id) as board_ids_str
       FROM pending_invitations pi
       LEFT JOIN users u ON pi.invited_by_user_id = u.id
       LEFT JOIN roles r ON pi.role_id = r.id
       LEFT JOIN invitation_boards ib ON pi.id = ib.invitation_id
       WHERE pi.workspace_id = ? 
         AND pi.status = 'pending'
         AND NOT EXISTS (
           SELECT 1 FROM workspace_members wm
           JOIN users u2 ON wm.user_id = u2.id
           WHERE wm.workspace_id = pi.workspace_id AND u2.email = pi.email
         )
       GROUP BY pi.id, pi.email, pi.workspace_id, pi.token, pi.role_id, pi.status, pi.created_at, pi.expires_at, pi.accepted_at, u.name, r.name
       ORDER BY pi.created_at DESC`,
      [Number(workspace_id)]
    );

    const allBoardIds = new Set();
    const invites = invitesRes.map((inv) => {
      const bIds = inv.board_ids_str ? inv.board_ids_str.split(',').map(Number) : [];
      bIds.forEach((id) => allBoardIds.add(id));
      return { ...inv, board_ids: bIds };
    });

    const boardMap = {};
    if (allBoardIds.size > 0) {
      const boardsRes = await req.db.query(
        'SELECT id, name FROM boards WHERE id IN (?)',
        [Array.from(allBoardIds)]
      );
      boardsRes.forEach((b) => {
        boardMap[b.id] = b.name;
      });
    }

    const clientBase = (process.env.CLIENT_URL || (process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5173')).replace(/\/$/, '');

    const invitations = invites.map((inv) => ({
      ...inv,
      role_name: inv.role_name || 'Team Member',
      board_names: (inv.board_ids || []).map((id) => boardMap[id]).filter(Boolean),
      invite_url: `${clientBase}/register?invite_token=${inv.token}&email=${encodeURIComponent(inv.email)}`
    }));

    return res.json({ invitations });
  } catch (err) {
    next(err);
  }
});

async function createInvitationHelper({ db, user, tenant, workspaceId, email, roleId, boardIds = [], originId = null }) {
  const normalizedEmail = normalizeEmail(email);

  // Validate boards belong to workspace
  if (boardIds.length > 0) {
    const validBoardsRes = await db.query(
      'SELECT id FROM boards WHERE workspace_id = ? AND id IN (?)',
      [workspaceId, boardIds]
    );
    const validBoardIds = validBoardsRes.map((row) => row.id);
    const invalidBoardIds = boardIds.filter((id) => !validBoardIds.includes(id));
    if (invalidBoardIds.length > 0) {
      const err = new Error('One or more selected boards do not belong to this workspace');
      err.status = 400;
      err.code = 'BAD_REQUEST';
      throw err;
    }
  }

  // Resolve role
  let resolvedRoleId = roleId;
  let resolvedRoleName = 'Team Member';
  if (resolvedRoleId) {
    const roleRes = await db.query(
      'SELECT id, name FROM roles WHERE id = ? AND (workspace_id = ? OR workspace_id IS NULL)',
      [resolvedRoleId, workspaceId]
    );
    if (roleRes.length === 0) {
      const err = new Error('Selected role does not exist');
      err.status = 400;
      err.code = 'BAD_REQUEST';
      throw err;
    }
    if (isOwnerRole(roleRes[0].name)) {
      const err = new Error('Cannot invite a member with Owner role');
      err.status = 403;
      err.code = 'FORBIDDEN';
      throw err;
    }
    resolvedRoleName = roleRes[0].name;
  } else {
    const defaultRoleRes = await db.query(
      "SELECT id, name FROM roles WHERE is_system = 1 AND name = 'Team Member' AND workspace_id IS NULL"
    );
    resolvedRoleId = defaultRoleRes[0]?.id || null;
    resolvedRoleName = defaultRoleRes[0]?.name || 'Team Member';
  }

  const existingUserRes = await db.query(
    'SELECT id, name, email FROM users WHERE email = ?',
    [normalizedEmail]
  );

  let token;
  let invitationId;
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const tenantSlug = tenant?.slug || 'default';
  const rawToken = crypto.randomBytes(20).toString('hex');
  const signedToken = signInviteToken(rawToken, tenantSlug);

  const existingInvite = await db.query(
    "SELECT id, token FROM pending_invitations WHERE email = ? AND workspace_id = ? AND status = 'pending'",
    [normalizedEmail, workspaceId]
  );

  if (existingInvite.length > 0) {
    invitationId = existingInvite[0].id;
    token = signedToken;
    await db.execute(
      'UPDATE pending_invitations SET token = ?, role_id = ?, expires_at = ?, created_at = CURRENT_TIMESTAMP(3) WHERE id = ?',
      [token, resolvedRoleId, expiresAt, invitationId]
    );
    await db.execute('DELETE FROM invitation_boards WHERE invitation_id = ?', [invitationId]);
  } else {
    token = signedToken;
    const insRes = await db.execute(
      `INSERT INTO pending_invitations (email, workspace_id, invited_by_user_id, token, role_id, status, expires_at)
       VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
      [normalizedEmail, workspaceId, user.id, token, resolvedRoleId, expiresAt]
    );
    invitationId = insRes.insertId;
  }

  for (const bId of boardIds) {
    await db.execute(
      'INSERT IGNORE INTO invitation_boards (invitation_id, board_id) VALUES (?, ?)',
      [invitationId, bId]
    );
  }

  const clientBase = (process.env.CLIENT_URL || (process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5173')).replace(/\/$/, '');
  const inviteUrl = `${clientBase}/register?invite_token=${token}&email=${encodeURIComponent(normalizedEmail)}`;

  if (existingUserRes.length === 0) {
    broadcastWorkspaceEvent(workspaceId, 'workspace:invitation_created', {
      invitation: {
        id: invitationId,
        email: normalizedEmail,
        workspace_id: workspaceId,
        role_id: resolvedRoleId,
        role_name: resolvedRoleName,
        board_ids: boardIds,
        token,
        expires_at: expiresAt,
        invite_url: inviteUrl
      }
    }, originId, tenant?.id);
    return {
      status: 202,
      data: {
        requires_registration: true,
        invite_token: token,
        invite_url: inviteUrl,
        role_id: resolvedRoleId,
        role_name: resolvedRoleName,
        message: 'Invitation link generated! Copy and share the registration link below with the user to test signup.'
      }
    };
  }

  const targetUser = existingUserRes[0];

  await db.execute(
    `INSERT INTO workspace_members (workspace_id, user_id, role, role_id)
     VALUES (?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE role_id = VALUES(role_id), role = VALUES(role)`,
    [workspaceId, targetUser.id, resolvedRoleName, resolvedRoleId]
  );

  if (boardIds.length > 0) {
    for (const boardId of boardIds) {
      await db.execute(
        "INSERT IGNORE INTO board_members (board_id, user_id, role) VALUES (?, ?, 'member')",
        [boardId, targetUser.id]
      );
    }
  }

  await db.execute(
    `UPDATE pending_invitations SET status = 'accepted', accepted_at = CURRENT_TIMESTAMP(3), accepted_by_user_id = ? WHERE token = ?`,
    [targetUser.id, token]
  );

  const wsRes = await db.query('SELECT name FROM workspaces WHERE id = ?', [workspaceId]);
  const wsName = wsRes[0]?.name || 'Workspace';

  await notify({
    eventType: 'invite.sent',
    actorUserId: user.id,
    inviteeUserId: targetUser.id,
    workspaceId: workspaceId,
    meta: { workspaceName: wsName }
  });

  await notify({
    eventType: 'invite.accepted',
    actorUserId: targetUser.id,
    workspaceId: workspaceId,
    meta: { workspaceName: wsName }
  });

  const memberPayload = {
    id: targetUser.id,
    name: targetUser.name,
    email: targetUser.email,
    role: resolvedRoleName,
    role_id: resolvedRoleId,
    workspace_id: workspaceId,
    board_ids: boardIds
  };

  broadcastWorkspaceEvent(workspaceId, 'workspace:member_added', { member: memberPayload }, originId, tenant?.id);

  return {
    status: 200,
    data: {
      invite_token: token,
      invite_url: inviteUrl,
      member: memberPayload
    }
  };
}

// POST /api/invitations (Create / Send invitation)
router.post('/', requireAuth, validate(inviteSchema), async (req, res, next) => {
  const { email, workspace_id, role_id, board_ids = [] } = req.body;

  try {
    const isAdmin = await requireWorkspaceAdmin(workspace_id, req.user.id, req.db);
    if (!isAdmin) {
      return res.status(403).json({
        error: { message: 'Only workspace admins can invite others', code: 'FORBIDDEN' }
      });
    }

    const result = await createInvitationHelper({
      db: req.db,
      user: req.user,
      tenant: req.tenant,
      workspaceId: workspace_id,
      email,
      roleId: role_id,
      boardIds: board_ids,
      originId: req.headers['x-origin-id']
    });

    return res.status(result.status).json(result.data);
  } catch (err) {
    next(err);
  }
});

// POST /api/invitations/accept (Accept invitation with token for logged-in user)
router.post('/accept', requireAuth, async (req, res, next) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ error: { message: 'token is required', code: 'BAD_REQUEST' } });
  }

  const tokenInfo = parseAndVerifyInviteToken(token);
  if (!tokenInfo || !tokenInfo.valid) {
    return res.status(400).json({ error: { message: 'Invalid invitation token signature', code: 'INVALID_SIGNATURE' } });
  }

  try {
    const inviteRes = await req.db.query(
      `SELECT pi.id, pi.workspace_id, pi.role_id, pi.status, pi.expires_at, GROUP_CONCAT(ib.board_id) as board_ids_str
       FROM pending_invitations pi
       LEFT JOIN invitation_boards ib ON pi.id = ib.invitation_id
       WHERE pi.token = ?
       GROUP BY pi.id, pi.workspace_id, pi.role_id, pi.status, pi.expires_at`,
      [token]
    );

    if (inviteRes.length === 0) {
      return res.status(404).json({ error: { message: 'Pending invitation not found', code: 'NOT_FOUND' } });
    }

    const invite = inviteRes[0];
    if (invite.status !== 'pending') {
      return res.status(410).json({ error: { message: 'Invitation has already been used or revoked', code: 'INVITATION_INVALID' } });
    }

    if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
      return res.status(410).json({ error: { message: 'Invitation link has expired (7 day limit)', code: 'INVITATION_EXPIRED' } });
    }

    const boardIds = invite.board_ids_str ? invite.board_ids_str.split(',').map(Number) : [];

    let assignedRoleId = invite.role_id;
    let assignedRoleName = 'Team Member';
    if (assignedRoleId) {
      const rRes = await req.db.query('SELECT id, name FROM roles WHERE id = ?', [assignedRoleId]);
      if (rRes.length > 0) {
        assignedRoleName = rRes[0].name;
      } else {
        assignedRoleId = null;
      }
    }
    if (!assignedRoleId) {
      const teamMemberRoleRes = await req.db.query(
        "SELECT id, name FROM roles WHERE is_system = 1 AND name = 'Team Member' AND workspace_id IS NULL"
      );
      assignedRoleId = teamMemberRoleRes[0]?.id;
      assignedRoleName = teamMemberRoleRes[0]?.name || 'Team Member';
    }

    await req.db.execute(
      `INSERT INTO workspace_members (workspace_id, user_id, role, role_id)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE role_id = VALUES(role_id), role = VALUES(role)`,
      [invite.workspace_id, req.user.id, assignedRoleName, assignedRoleId]
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
      [req.user.id, invite.id]
    );

    const wsRes = await req.db.query('SELECT name FROM workspaces WHERE id = ?', [invite.workspace_id]);
    const wsName = wsRes[0]?.name || 'Workspace';

    await notify({
      eventType: 'invite.accepted',
      actorUserId: req.user.id,
      workspaceId: invite.workspace_id,
      meta: { workspaceName: wsName }
    });

    return res.json({
      message: 'Invitation accepted successfully',
      workspace_id: invite.workspace_id
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/invitations/:id/regenerate (Regenerate invitation token & extend expiry)
router.post('/:id/regenerate', requireAuth, async (req, res, next) => {
  const inviteId = Number(req.params.id);

  try {
    const inviteRes = await req.db.query('SELECT * FROM pending_invitations WHERE id = ?', [inviteId]);
    if (inviteRes.length === 0) {
      return res.status(404).json({ error: { message: 'Invitation not found', code: 'NOT_FOUND' } });
    }

    const invite = inviteRes[0];
    const isAdmin = await requireWorkspaceAdmin(invite.workspace_id, req.user.id, req.db);
    if (!isAdmin) {
      return res.status(403).json({ error: { message: 'Only workspace admins can regenerate invitations', code: 'FORBIDDEN' } });
    }

    const tenantSlug = req.tenant?.slug || 'default';
    const rawToken = crypto.randomBytes(20).toString('hex');
    const newToken = signInviteToken(rawToken, tenantSlug);
    const newExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await req.db.execute(
      `UPDATE pending_invitations SET token = ?, expires_at = ?, status = 'pending', created_at = CURRENT_TIMESTAMP(3) WHERE id = ?`,
      [newToken, newExpiresAt, inviteId]
    );

    const clientBase = (process.env.CLIENT_URL || (process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5173')).replace(/\/$/, '');
    const inviteUrl = `${clientBase}/register?invite_token=${newToken}&email=${encodeURIComponent(invite.email)}`;

    broadcastWorkspaceEvent(invite.workspace_id, 'workspace:invitation_created', {
      invitation: {
        id: inviteId,
        email: invite.email,
        workspace_id: invite.workspace_id,
        role_id: invite.role_id,
        token: newToken,
        expires_at: newExpiresAt,
        invite_url: inviteUrl
      }
    }, req.headers['x-origin-id'], req.tenant?.id);

    return res.json({
      message: 'Invitation link regenerated successfully',
      invite_token: newToken,
      invite_url: inviteUrl,
      expires_at: newExpiresAt
    });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/invitations/:id (Revoke pending invitation)
router.delete('/:id', requireAuth, async (req, res, next) => {
  const inviteId = Number(req.params.id);

  try {
    const inviteRes = await req.db.query('SELECT workspace_id FROM pending_invitations WHERE id = ?', [inviteId]);
    if (inviteRes.length === 0) {
      return res.status(404).json({ error: { message: 'Invitation not found', code: 'NOT_FOUND' } });
    }

    const isAdmin = await requireWorkspaceAdmin(inviteRes[0].workspace_id, req.user.id, req.db);
    if (!isAdmin) {
      return res.status(403).json({ error: { message: 'Only workspace admins can revoke invitations', code: 'FORBIDDEN' } });
    }

    await req.db.execute('DELETE FROM pending_invitations WHERE id = ?', [inviteId]);
    broadcastWorkspaceEvent(inviteRes[0].workspace_id, 'workspace:invitation_revoked', { invitationId: inviteId }, req.headers['x-origin-id'], req.tenant?.id);
    return res.json({ message: 'Invitation revoked successfully' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const {
  requirePermission,
  requirePermissionForBody,
  userHasPermission,
  getUserPermissions,
  accessibleBoardIds,
  countSuperAdmins,
  countOwners
} = require('../middleware/permissions');
const { sendUserEvent, disconnectUserSockets, broadcastWorkspaceEvent } = require('../socket');
const { notify } = require('../services/notify');
const { logActivity } = require('../utils/activity');
const { revokeAllSessions } = require('../services/sessionService');
const { logAuthEvent } = require('../services/authAudit');
const { validatePassword, generateCompliantPassword } = require('../utils/passwordPolicy');
const { canResetTarget, isOwnerRole, getRoleRank, isReservedRoleName } = require('../utils/roleRank');
const { syncCompanyOwners } = require('../utils/syncCompanyOwners');
const { sanitizePlain } = require('../utils/sanitizer');
const { createInvitationHelper } = require('./invitations');
const {
  PERMISSIONS,
  LEGACY_PERMISSION_ALIASES,
  getTransitivePrerequisites
} = require('../rbac/registry');
const { evaluatePermission } = require('../rbac/evaluate');

const validPermMap = new Map();
PERMISSIONS.forEach((p) => validPermMap.set(p.key, p));

const multer = require('multer');
const storage = require('../storage');

function detectImageMagicBytes(buffer) {
  if (!buffer || buffer.length < 8) return null;
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return 'image/jpeg';
  if (
    buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47 &&
    buffer[4] === 0x0D && buffer[5] === 0x0A && buffer[6] === 0x1A && buffer[7] === 0x0A
  ) return 'image/png';
  const header6 = buffer.slice(0, 6).toString('ascii');
  if (header6 === 'GIF87a' || header6 === 'GIF89a') return 'image/gif';
  if (
    buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
    buffer.length >= 12 && buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50
  ) return 'image/webp';
  return null;
}

const iconUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/svg+xml'];
    if (!allowed.includes(file.mimetype)) {
      const err = new Error('Invalid file type. Only JPEG, PNG, WebP, GIF, and SVG images are permitted.');
      err.code = 'INVALID_IMAGE_TYPE';
      err.status = 400;
      return cb(err);
    }
    cb(null, true);
  }
});

const router = express.Router();

const createWorkspaceSchema = z.object({
  name: z.string().min(1, 'Workspace name is required').transform((v) => sanitizePlain(v))
});

const updateWorkspaceSchema = z.object({
  name: z.string().min(1).transform((v) => sanitizePlain(v)).optional(),
  description: z.string().transform((v) => sanitizePlain(v)).optional(),
  icon_url: z.string().max(500).nullable().optional(),
  settings: z.any().optional(),
  is_archived: z.boolean().optional(),
  require_2fa_for_admins: z.boolean().optional()
});

const createRoleSchema = z.object({
  name: z.string().min(1, 'Role name is required').transform((v) => sanitizePlain(v)),
  permission_keys: z.array(z.string()).optional().default([]),
  clone_role_id: z.number().int().positive().optional(),
  rank: z.number().int().optional()
});

const assignRoleSchema = z.object({
  role_id: z.number().int().positive(),
  board_ids: z.array(z.number()).optional()
});

// GET /api/workspaces - List all workspaces user belongs to
router.get('/', requireAuth, async (req, res, next) => {
  try {
    // Auto-sync company owners so all active workspaces are immediately available to every Owner
    await syncCompanyOwners(req.db, req.user.id);

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
      `SELECT w.*, COALESCE(r.name, wm.role, 'Team Member') as role_name, r.id as role_id
       FROM workspaces w
       JOIN workspace_members wm ON w.id = wm.workspace_id
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE wm.user_id = ? AND w.is_archived = 0
       ORDER BY w.id ASC`,
      [req.user.id]
    );
    const workspacesWithParsedSettings = wsRes.map((w) => {
      let parsed = w.settings;
      if (typeof parsed === 'string') {
        try { parsed = JSON.parse(parsed); } catch {}
      }
      const iconUrl = w.icon_url || parsed?.icon_url || null;
      return { ...w, icon_url: iconUrl, settings: parsed };
    });
    return res.json({ workspaces: workspacesWithParsedSettings });
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id - Get single workspace details
router.get('/:id', requireAuth, requirePermission('workspace.view'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  try {
    const wsRes = await req.db.query(
      `SELECT w.*, COALESCE(r.name, wm.role, 'Team Member') as role_name, r.id as role_id
       FROM workspaces w
       JOIN workspace_members wm ON w.id = wm.workspace_id
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE w.id = ? AND wm.user_id = ?`,
      [workspaceId, req.user.id]
    );
    if (wsRes.length === 0) {
      return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
    }
    const w = wsRes[0];
    let parsed = w.settings;
    if (typeof parsed === 'string') {
      try { parsed = JSON.parse(parsed); } catch {}
    }
    const iconUrl = w.icon_url || parsed?.icon_url || null;
    return res.json({ workspace: { ...w, icon_url: iconUrl, settings: parsed } });
  } catch (err) {
    next(err);
  }
});

// POST /api/workspaces - Create new workspace and ensure Admin/Owner visibility
router.post('/', requireAuth, validate(createWorkspaceSchema), async (req, res, next) => {
  const name = sanitizePlain(req.body.name);
  try {
    // Check permission to create workspace:
    // User must hold workspace.create in at least one of their workspaces in this tenant, evaluated through evaluate.js.
    const userMemberships = await req.db.query(
      `SELECT wm.workspace_id, wm.role_id, r.is_system, r.is_editable, r.rank, r.name as role_name
       FROM workspace_members wm
       JOIN roles r ON wm.role_id = r.id
       WHERE wm.user_id = ?`,
      [req.user.id]
    );

    let canCreateWorkspace = false;
    for (const m of userMemberships) {
      const permData = await getUserPermissions(req.user.id, m.workspace_id, req.db);
      const evalRes = evaluatePermission({
        key: 'workspace.create',
        workspaceRole: {
          id: m.role_id,
          name: m.role_name,
          rank: m.rank,
          is_system: m.is_system,
          permissions: permData.permissions
        }
      });
      if (evalRes.allowed) {
        canCreateWorkspace = true;
        break;
      }
    }

    const existingWsCount = (await req.db.query('SELECT COUNT(*) as count FROM workspaces'))[0]?.count || 0;
    if (existingWsCount > 0 && !canCreateWorkspace) {
      return res.status(403).json({
        error: { message: 'You do not have permission to create workspaces', code: 'PERMISSION_DENIED' }
      });
    }

    const wsExec = await req.db.execute(
      'INSERT INTO workspaces (name) VALUES (?)',
      [name]
    );
    const workspaceId = wsExec.insertId;
    const [workspace] = await req.db.query('SELECT id, name, created_at FROM workspaces WHERE id = ?', [workspaceId]);

    // Fetch system role IDs
    const sysRoles = await req.db.query(
      "SELECT id, name FROM roles WHERE is_system = 1 AND workspace_id IS NULL"
    );
    const roleIdMap = {};
    sysRoles.forEach((r) => { roleIdMap[r.name] = r.id; });
    const ownerRoleId = roleIdMap['Owner'] || roleIdMap['Super Admin'];
    const adminRoleId = roleIdMap['Admin'];
    const pmRoleId = roleIdMap['Project Manager'];

    // Automatically enrol ALL Company Owners in the new workspace
    const companyOwnersRes = await req.db.query(
      `SELECT DISTINCT wm.user_id
       FROM workspace_members wm
       JOIN roles r ON wm.role_id = r.id
       WHERE (r.is_system = 1 AND (r.is_editable = 0 OR COALESCE(r.rank, 30) >= 100))
          OR wm.role IN ('Owner', 'Super Admin')`
    );
    const ownerUserIds = new Set(companyOwnersRes.map((o) => Number(o.user_id)));
    ownerUserIds.add(Number(req.user.id));

    for (const uid of ownerUserIds) {
      await req.db.execute(
        'INSERT IGNORE INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)',
        [workspaceId, uid, 'Owner', ownerRoleId]
      );
      sendUserEvent(uid, 'workspace:created', { workspace: { ...workspace, role: 'Owner' } }, req.tenant?.id);
      sendUserEvent(uid, 'user:workspaces_updated', { workspaceId }, req.tenant?.id);
    }

    await logAuthEvent(req.db, {
      userId: req.user.id,
      email: req.user.email,
      eventType: 'workspace.created',
      req,
      metadata: { workspace_id: workspaceId, name }
    });

    return res.status(201).json({ workspace: { ...workspace, role: 'Owner', role_id: ownerRoleId } });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/workspaces/:id - Update workspace
router.patch(
  '/:id',
  requireAuth,
  requirePermissionForBody((req) => {
    const { is_archived } = req.body;
    if (is_archived === true) return 'workspace.archive';
    if (is_archived === false) return 'workspace.restore';
    return { any: ['workspace.edit', 'workspace.edit_settings'] };
  }),
  validate(updateWorkspaceSchema),
  async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const { name, description, icon_url, settings, is_archived, require_2fa_for_admins } = req.body;

  try {
    const isArchive = is_archived !== undefined;
    const updates = [];
    const values = [];

    if (name !== undefined) {
      updates.push('name = ?');
      values.push(sanitizePlain(name));
    }
    if (description !== undefined) {
      updates.push('description = ?');
      values.push(sanitizePlain(description));
    }
    if (icon_url !== undefined) {
      updates.push('icon_url = ?');
      values.push(icon_url);
    }
    if (settings !== undefined) {
      updates.push('settings = ?');
      values.push(typeof settings === 'object' && settings !== null ? JSON.stringify(settings) : settings);
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
    let execRes;
    try {
      execRes = await req.db.execute(
        `UPDATE workspaces SET ${updates.join(', ')} WHERE id = ?`,
        values
      );
    } catch (dbErr) {
      // If icon_url column is not yet present on legacy DB schema, fallback gracefully
      if (icon_url !== undefined) {
        const fallbackUpdates = updates.filter(u => u !== 'icon_url = ?');
        const fallbackValues = values.filter((_, idx) => idx !== updates.indexOf('icon_url = ?'));
        if (fallbackUpdates.length > 0) {
          execRes = await req.db.execute(
            `UPDATE workspaces SET ${fallbackUpdates.join(', ')} WHERE id = ?`,
            fallbackValues
          );
        }
      } else {
        throw dbErr;
      }
    }

    if (execRes && execRes.affectedRows === 0) {
      return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
    }

    const [updatedWs] = await req.db.query('SELECT w.* FROM workspaces w WHERE w.id = ?', [workspaceId]);
    let parsedSettings = updatedWs.settings;
    if (typeof parsedSettings === 'string') {
      try { parsedSettings = JSON.parse(parsedSettings); } catch {}
    }
    const finalIconUrl = updatedWs.icon_url || parsedSettings?.icon_url || null;
    const wsPayload = {
      ...updatedWs,
      icon_url: finalIconUrl,
      settings: parsedSettings,
      require_2fa_for_admins: !!updatedWs.require_2fa_for_admins
    };
    broadcastWorkspaceEvent(workspaceId, 'workspace:updated', { workspace: wsPayload }, req.headers['x-origin-id'], req.tenant?.id);

    await logActivity({
      workspaceId,
      userId: req.user.id,
      actionType: isArchive ? (is_archived ? 'workspace_archived' : 'workspace_restored') : 'workspace_updated',
      metaJson: { workspace_name: updatedWs.name, updates: req.body },
      dbInstance: req.db,
      tenantId: req.tenant?.id
    });

    return res.json({ workspace: wsPayload });
  } catch (err) {
    next(err);
  }
});

// POST /api/workspaces/:id/icon - Upload workspace icon
router.post('/:id/icon', requireAuth, requirePermission('workspace.edit'), (req, res, next) => {
  iconUpload.single('icon')(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: { message: 'Image must not exceed 5MB', code: 'FILE_TOO_LARGE' } });
      }
      return res.status(err.status || 400).json({ error: { message: err.message, code: err.code || 'UPLOAD_ERROR' } });
    }

    if (!req.file) {
      return res.status(400).json({ error: { message: 'No image file uploaded', code: 'NO_FILE' } });
    }

    const verifiedMime = detectImageMagicBytes(req.file.buffer);
    if (!verifiedMime && !req.file.mimetype.includes('svg')) {
      return res.status(400).json({
        error: {
          message: 'Invalid file format. Magic bytes do not match a valid JPEG, PNG, WebP, GIF, or SVG image.',
          code: 'INVALID_IMAGE_TYPE'
        }
      });
    }

    const workspaceId = Number(req.params.id);
    try {
      const tenantId = req.tenant ? req.tenant.id : '1';
      const saveRes = await storage.saveWorkspaceIcon(tenantId, workspaceId, req.file);

      // Update icon_url column and settings.icon_url for backwards compatibility
      const [existingWs] = await req.db.query('SELECT settings FROM workspaces WHERE id = ?', [workspaceId]);
      let settingsObj = {};
      if (existingWs?.settings) {
        try {
          settingsObj = typeof existingWs.settings === 'string' ? JSON.parse(existingWs.settings) : existingWs.settings;
        } catch {}
      }
      settingsObj.icon_url = saveRes.file_url;

      try {
        await req.db.execute(
          'UPDATE workspaces SET icon_url = ?, settings = ? WHERE id = ?',
          [saveRes.file_url, JSON.stringify(settingsObj), workspaceId]
        );
      } catch (colErr) {
        // Fallback if icon_url column is pending migration
        await req.db.execute(
          'UPDATE workspaces SET settings = ? WHERE id = ?',
          [JSON.stringify(settingsObj), workspaceId]
        );
      }

      const [updatedWs] = await req.db.query('SELECT w.* FROM workspaces w WHERE w.id = ?', [workspaceId]);
      let parsedSettings = updatedWs.settings;
      if (typeof parsedSettings === 'string') {
        try { parsedSettings = JSON.parse(parsedSettings); } catch {}
      }
      const wsPayload = {
        ...updatedWs,
        icon_url: saveRes.file_url,
        settings: parsedSettings,
        require_2fa_for_admins: !!updatedWs.require_2fa_for_admins
      };

      broadcastWorkspaceEvent(workspaceId, 'workspace:updated', { workspace: wsPayload }, req.headers['x-origin-id'], req.tenant?.id);

      await logActivity({
        workspaceId,
        userId: req.user.id,
        actionType: 'workspace_icon_updated',
        metaJson: { workspace_name: updatedWs.name, icon_url: saveRes.file_url },
        dbInstance: req.db,
        tenantId: req.tenant?.id
      });

      return res.json({
        message: 'Workspace icon uploaded successfully',
        icon_url: saveRes.file_url,
        workspace: wsPayload
      });
    } catch (saveErr) {
      next(saveErr);
    }
  });
});

// DELETE /api/workspaces/:id/icon - Remove workspace icon
router.delete('/:id/icon', requireAuth, requirePermission('workspace.edit'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  try {
    const [existingWs] = await req.db.query('SELECT settings FROM workspaces WHERE id = ?', [workspaceId]);
    let settingsObj = {};
    if (existingWs?.settings) {
      try {
        settingsObj = typeof existingWs.settings === 'string' ? JSON.parse(existingWs.settings) : existingWs.settings;
      } catch {}
    }
    delete settingsObj.icon_url;

    try {
      await req.db.execute(
        'UPDATE workspaces SET icon_url = NULL, settings = ? WHERE id = ?',
        [JSON.stringify(settingsObj), workspaceId]
      );
    } catch (colErr) {
      await req.db.execute(
        'UPDATE workspaces SET settings = ? WHERE id = ?',
        [JSON.stringify(settingsObj), workspaceId]
      );
    }

    const [updatedWs] = await req.db.query('SELECT w.* FROM workspaces w WHERE w.id = ?', [workspaceId]);
    let parsedSettings = updatedWs.settings;
    if (typeof parsedSettings === 'string') {
      try { parsedSettings = JSON.parse(parsedSettings); } catch {}
    }
    const wsPayload = {
      ...updatedWs,
      icon_url: null,
      settings: parsedSettings,
      require_2fa_for_admins: !!updatedWs.require_2fa_for_admins
    };

    broadcastWorkspaceEvent(workspaceId, 'workspace:updated', { workspace: wsPayload }, req.headers['x-origin-id'], req.tenant?.id);

    await logActivity({
      workspaceId,
      userId: req.user.id,
      actionType: 'workspace_icon_removed',
      metaJson: { workspace_name: updatedWs.name },
      dbInstance: req.db,
      tenantId: req.tenant?.id
    });

    return res.json({
      message: 'Workspace icon removed successfully',
      workspace: wsPayload
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/security - Company security settings (Section 6)
router.get('/:id/security', requireAuth, requirePermission('company.manage_security'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  try {
    const [ws] = await req.db.query(
      'SELECT id, require_2fa_for_admins, settings FROM workspaces WHERE id = ?',
      [workspaceId]
    );
    if (!ws) {
      return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
    }
    let parsedSettings = ws.settings;
    if (typeof parsedSettings === 'string') {
      try { parsedSettings = JSON.parse(parsedSettings); } catch {}
    }
    const settings = parsedSettings || {};
    return res.json({
      require_2fa: Boolean(settings.require_2fa || ws.require_2fa_for_admins),
      require_2fa_for_admins: Boolean(ws.require_2fa_for_admins)
    });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/workspaces/:id/security - Update company security settings (Section 6)
router.patch('/:id/security', requireAuth, requirePermission('company.manage_security'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const { require_2fa, require_2fa_for_admins } = req.body;
  try {
    const [ws] = await req.db.query('SELECT id, settings, require_2fa_for_admins FROM workspaces WHERE id = ?', [workspaceId]);
    if (!ws) {
      return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
    }
    let parsedSettings = ws.settings;
    if (typeof parsedSettings === 'string') {
      try { parsedSettings = JSON.parse(parsedSettings); } catch {}
    }
    const settings = parsedSettings || {};
    if (require_2fa !== undefined) {
      settings.require_2fa = Boolean(require_2fa);
    }
    let req2faAdmins = ws.require_2fa_for_admins;
    if (require_2fa_for_admins !== undefined) {
      req2faAdmins = require_2fa_for_admins ? 1 : 0;
    }

    await req.db.execute(
      'UPDATE workspaces SET settings = ?, require_2fa_for_admins = ? WHERE id = ?',
      [JSON.stringify(settings), req2faAdmins, workspaceId]
    );

    return res.json({
      message: 'Security settings updated',
      require_2fa: Boolean(settings.require_2fa),
      require_2fa_for_admins: Boolean(req2faAdmins)
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/workspaces/:id/auto-archive - Auto-archive completed tasks older than N days
router.post('/:id/auto-archive', requireAuth, requirePermission(['task.archive', 'workspace.edit_settings']), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const days = req.body.days !== undefined ? Number(req.body.days) : 7;

  try {
    const canArchive = (await userHasPermission(req.user.id, workspaceId, 'task.archive', req.db)) ||
                       (await userHasPermission(req.user.id, workspaceId, 'workspace.edit', req.db));
    if (!canArchive) {
      return res.status(403).json({ error: { message: 'Permission denied to archive tasks', code: 'PERMISSION_DENIED' } });
    }

    let intervalClause = '';
    const params = [workspaceId];
    if (days > 0) {
      intervalClause = 'AND COALESCE(c.completed_at, c.created_at) < DATE_SUB(NOW(), INTERVAL ? DAY)';
      params.push(days);
    }

    const cardsToArchive = await req.db.query(
      `SELECT c.id, c.title, l.board_id
       FROM cards c
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       WHERE b.workspace_id = ?
         AND (c.is_complete = 1 OR LOWER(l.name) IN ('done', 'completed', 'finished', 'closed', 'archive', 'archived'))
         AND c.is_archived = 0
         ${intervalClause}`,
      params
    );

    if (cardsToArchive.length > 0) {
      const cardIds = cardsToArchive.map((c) => c.id);
      await req.db.query(
        `UPDATE cards SET is_archived = 1 WHERE id IN (${cardIds.map(() => '?').join(',')})`,
        cardIds
      );

      for (const card of cardsToArchive) {
        broadcastWorkspaceEvent(workspaceId, 'card:archived', { cardId: card.id, boardId: card.board_id }, req.headers['x-origin-id'], req.tenant?.id);
      }
    }

    return res.json({
      success: true,
      archived_count: cardsToArchive.length,
      days
    });
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
  const rawProjectId = req.query.board_id || req.query.project_id;
  const projectId = rawProjectId ? Number(rawProjectId) : null;

  try {
    const isMember = await req.db.query(
      'SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
      [workspaceId, req.user.id]
    );
    if (isMember.length === 0) {
      return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
    }

    if (projectId) {
      const bRes = await req.db.query('SELECT workspace_id FROM boards WHERE id = ?', [projectId]);
      if (bRes.length === 0 || Number(bRes[0].workspace_id) !== Number(workspaceId)) {
        return res.status(400).json({ error: { message: 'Board does not belong to workspace', code: 'BOARD_MISMATCH' } });
      }
    }

    const permData = await getUserPermissions(req.user.id, workspaceId, req.db, projectId);
    return res.json(permData);
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/roles - Get all system & custom roles for workspace with member counts
router.get('/:id/roles', requireAuth, requirePermission('role.view'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);

  try {
    const rolesRes = await req.db.query(
      `SELECT r.id, r.name, r.is_system, r.is_editable, r.rank, r.workspace_id, r.created_at,
              COUNT(DISTINCT wm.user_id) as member_count,
              GROUP_CONCAT(DISTINCT p.key) as permission_keys_str
       FROM roles r
       LEFT JOIN workspace_members wm ON r.id = wm.role_id AND wm.workspace_id = ?
       LEFT JOIN role_permissions rp ON r.id = rp.role_id
       LEFT JOIN permissions p ON rp.permission_id = p.id AND p.planned = 0
       WHERE r.workspace_id IS NULL OR r.workspace_id = ?
       GROUP BY r.id, r.name, r.is_system, r.is_editable, r.rank, r.workspace_id, r.created_at
       ORDER BY r.is_system DESC,
                FIELD(r.name, 'Owner', 'Super Admin', 'Admin', 'Project Manager', 'Team Lead', 'Team Member', 'Viewer', 'Auditor', 'Guest'),
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
      if (isOwnerRole(r)) {
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
  const { name, permission_keys, clone_role_id } = req.body;

  try {
    const cleanName = name.trim();
    if (isReservedRoleName(cleanName)) {
      return res.status(400).json({
        error: { message: 'Role name is reserved for system roles', code: 'RESERVED_ROLE_NAME' }
      });
    }

    const dupCheck = await req.db.query(
      'SELECT id FROM roles WHERE workspace_id = ? AND LOWER(name) = LOWER(?) LIMIT 1',
      [workspaceId, cleanName]
    );
    if (dupCheck.length > 0) {
      return res.status(400).json({
        error: { message: 'A role with this name already exists in this workspace', code: 'DUPLICATE_ROLE_NAME' }
      });
    }

    let rawKeys = Array.isArray(permission_keys) ? [...permission_keys] : [];
    if (clone_role_id) {
      const clonePermsRes = await req.db.query(
        `SELECT p.key FROM role_permissions rp
         JOIN permissions p ON rp.permission_id = p.id
         WHERE rp.role_id = ?`,
        [clone_role_id]
      );
      const cloneKeys = clonePermsRes.map((r) => r.key);
      rawKeys = Array.from(new Set([...cloneKeys, ...rawKeys]));
    }

    // Validate unknown and planned keys
    for (const rawKey of rawKeys) {
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

    // Auto-include transitive prerequisites
    const requestedKeys = new Set(
      rawKeys.map((k) => LEGACY_PERMISSION_ALIASES[k] || k)
    );
    for (const k of Array.from(requestedKeys)) {
      const prereqs = getTransitivePrerequisites(k);
      prereqs.forEach((p) => requestedKeys.add(p));
    }
    const canonicalKeys = Array.from(requestedKeys);

    // Privilege escalation check: caller cannot grant permissions they do not possess
    const callerPerms = await getUserPermissions(req.user.id, workspaceId, req.db);
    const callerIsOwner = isOwnerRole(callerPerms.role);
    if (!callerIsOwner) {
      const callerPermSet = new Set(
        callerPerms.permissions.map((k) => LEGACY_PERMISSION_ALIASES[k] || k)
      );
      const unauthorizedPerm = canonicalKeys.find((k) => !callerPermSet.has(k));
      if (unauthorizedPerm) {
        return res.status(403).json({
          error: {
            message: `You cannot create a role with permissions you do not possess (${unauthorizedPerm})`,
            code: 'PRIVILEGE_ESCALATION_FORBIDDEN'
          }
        });
      }
    }

    // Custom role rank rule: rank-capped below 80 and defaulting to 30, but allowed to be set between 11 and 79
    const requestedRank = req.body.rank !== undefined ? Number(req.body.rank) : 30;
    if (isNaN(requestedRank) || requestedRank < 11 || requestedRank > 79) {
      return res.status(400).json({
        error: { message: 'Custom role rank must be between 11 and 79', code: 'INVALID_ROLE_RANK' }
      });
    }

    const callerRank = getRoleRank(callerPerms.role);
    if (!callerIsOwner && callerRank <= requestedRank) {
      return res.status(403).json({
        error: {
          message: 'You cannot create a custom role with equal or higher rank than your own',
          code: 'INSUFFICIENT_ROLE_RANK'
        }
      });
    }

    const roleExec = await req.db.execute(
      `INSERT INTO roles (workspace_id, name, is_system, is_editable, rank, created_by_user_id)
       VALUES (?, ?, 0, 1, ?, ?)`,
      [workspaceId, cleanName, requestedRank, req.user.id]
    );

    const roleId = roleExec.insertId;
    const [role] = await req.db.query(
      'SELECT id, workspace_id, name, is_system, is_editable, rank, created_at FROM roles WHERE id = ?',
      [roleId]
    );

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

    const createdRole = {
      ...role,
      member_count: 0,
      permission_keys: canonicalKeys
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
        role_name: cleanName,
        permission_count: canonicalKeys.length
      }
    });

    return res.status(201).json({ role: createdRole });
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/members - List members
router.get('/:id/members', requireAuth, requirePermission('member.view'), async (req, res, next) => {
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

    let membersRes = await req.db.query(
      `SELECT u.id, u.name, u.email, u.avatar_url, r.id as role_id, r.name as role_name, r.is_system, r.is_editable, r.rank, wm.status
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

    // Section 5.4: Member lists for Guests: Guests only see members of boards they belong to
    const callerRoleRows = await req.db.query(
      'SELECT r.rank FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [workspaceId, req.user.id]
    );
    const callerRank = Number(callerRoleRows[0]?.rank || 30);
    const isGuest = callerRank <= 10;

    if (isGuest) {
      const callerBoards = boardMembersRes.filter((bm) => bm.user_id === req.user.id).map((bm) => bm.board_id);
      const allowedUserIds = new Set(boardMembersRes.filter((bm) => callerBoards.includes(bm.board_id)).map((bm) => bm.user_id));
      allowedUserIds.add(req.user.id);
      membersRes = membersRes.filter((m) => allowedUserIds.has(m.id) && m.status !== 'deactivated');
    } else {
      membersRes = membersRes.filter((m) => m.status !== 'deactivated');
    }

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
      const isOwner = isOwnerRole({ name: m.role_name, is_system: m.is_system, rank: m.rank });
      const permissions = isOwner ? allPermKeys : (rolePermMap[m.role_id] || []);
      const userBoards = userBoardsMap[m.id] || [];
      return {
        id: m.id,
        name: m.name,
        email: m.email,
        avatar_url: m.avatar_url,
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
router.patch('/:id/members/:userId/role', requireAuth, requirePermission(['member.assign_role', 'role.assign']), validate(assignRoleSchema), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const targetUserId = Number(req.params.userId);
  const { role_id, board_ids } = req.body;
  try {
    // 1. Fetch current role of target user
    const targetMemberRes = await req.db.query(
      `SELECT r.id as role_id, r.name as role_name, r.is_system, r.is_editable, COALESCE(r.rank, 30) as rank
       FROM workspace_members wm
       JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, targetUserId]
    );

    if (targetMemberRes.length === 0) {
      return res.status(404).json({ error: { message: 'Workspace member not found', code: 'NOT_FOUND' } });
    }

    const targetRole = targetMemberRes[0];
    const targetIsOwner = isOwnerRole(targetRole);
    const targetRank = getRoleRank(targetRole);

    // Last Owner Protection: Cannot demote the last Owner of the workspace
    if (targetIsOwner) {
      const ownerCount = await countOwners(workspaceId, req.db);
      if (ownerCount <= 1) {
        return res.status(400).json({
          error: {
            message: 'Cannot demote the last Owner of the workspace.',
            code: 'LAST_OWNER_PROTECTION'
          }
        });
      }
    }

    // Anti-escalation Rule 0: Cannot change your own role
    if (Number(req.user.id) === targetUserId) {
      return res.status(403).json({
        error: { message: 'You cannot change your own role', code: 'SELF_ROLE_CHANGE_FORBIDDEN' }
      });
    }

    // Fetch caller role & ranks
    const callerMemberRes = await req.db.query(
      `SELECT r.id as role_id, r.name as role_name, r.is_system, r.is_editable, COALESCE(r.rank, 30) as rank
       FROM workspace_members wm
       JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, req.user.id]
    );
    const callerRole = callerMemberRes[0] || { role_name: 'Team Member', is_system: 0, is_editable: 1, rank: 30 };
    const callerIsOwner = isOwnerRole(callerRole);
    const callerRank = getRoleRank(callerRole);

    // Rule: Owner role is locked and cannot be changed by non-owners
    if (targetIsOwner && !callerIsOwner) {
      return res.status(403).json({
        error: {
          message: 'Only an Owner may modify the Owner role',
          code: 'ONLY_OWNER_MAY_MODIFY_OWNER'
        }
      });
    }

    // 2. Fetch new role details
    const newRoleRes = await req.db.query(
      'SELECT id, name, is_system, is_editable, COALESCE(rank, 30) as rank FROM roles WHERE id = ? AND (workspace_id = ? OR workspace_id IS NULL)',
      [role_id, workspaceId]
    );

    if (newRoleRes.length === 0) {
      return res.status(404).json({ error: { message: 'Role not found', code: 'NOT_FOUND' } });
    }

    const newRole = newRoleRes[0];
    const newRoleIsOwner = isOwnerRole(newRole);
    const newRank = getRoleRank(newRole);

    // Anti-escalation Rule 4: Cannot assign a role with higher or equal rank than caller's own rank
    if (!callerIsOwner && newRank >= callerRank) {
      return res.status(403).json({
        error: {
          message: 'Cannot assign a role with equal or higher rank than your own',
          code: 'PRIVILEGE_ESCALATION_FORBIDDEN'
        }
      });
    }

    // Only Owner may assign Owner role
    if (newRoleIsOwner && !callerIsOwner) {
      return res.status(403).json({
        error: {
          message: 'Only an Owner may assign the Owner role',
          code: 'ONLY_OWNER_MAY_ASSIGN_OWNER'
        }
      });
    }

    // Anti-escalation Rule 3: Cannot change the role of someone with equal or higher rank (unless caller is Owner)
    if (!callerIsOwner && callerRank <= targetRank) {
      return res.status(403).json({
        error: {
          message: 'You cannot change the role of a member with equal or higher rank',
          code: 'INSUFFICIENT_ROLE_RANK'
        }
      });
    }

    // Anti-escalation Rule 5: Cannot assign a role with permissions caller does not possess
    if (!callerIsOwner) {
      const { LEGACY_PERMISSION_ALIASES } = require('../rbac/registry');
      const newRolePermsRes = await req.db.query(
        'SELECT p.key FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = ?',
        [newRole.id]
      );
      const newRolePermKeys = newRolePermsRes.map((p) => LEGACY_PERMISSION_ALIASES[p.key] || p.key);
      const callerPerms = await getUserPermissions(req.user.id, workspaceId, req.db);
      const callerPermSet = new Set(callerPerms.permissions.map((k) => LEGACY_PERMISSION_ALIASES[k] || k));
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

    // Update member role_id and role name
    await req.db.execute(
      'UPDATE workspace_members SET role_id = ?, role = ? WHERE workspace_id = ? AND user_id = ?',
      [role_id, newRole.name, workspaceId, targetUserId]
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
          eventType: 'workspace.member_role_changed',
          actorUserId: req.user.id,
          targetUserId,
          workspaceId,
          tenantId: req.tenant?.id || null,
          meta: { roleName: roleRes[0]?.name || 'Member', workspaceName: wsRes[0]?.name || 'Workspace' }
        },
        req.db
      );
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

    const callerMemberRes = await req.db.query(
      `SELECT wm.role as legacy_role, r.id, r.name as role_name, r.rank, r.is_system, r.is_editable
       FROM workspace_members wm 
       LEFT JOIN roles r ON wm.role_id = r.id 
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, req.user.id]
    );
    const callerRole = callerMemberRes[0]?.id
      ? { name: callerMemberRes[0].role_name, rank: callerMemberRes[0].rank, is_system: callerMemberRes[0].is_system, is_editable: callerMemberRes[0].is_editable }
      : (callerMemberRes[0]?.role_name || callerMemberRes[0]?.legacy_role || 'Team Member');

    const targetMemberRes = await req.db.query(
      `SELECT wm.role as legacy_role, r.id, r.name as role_name, r.rank, r.is_system, r.is_editable, u.email as user_email
       FROM workspace_members wm 
       LEFT JOIN roles r ON wm.role_id = r.id 
       JOIN users u ON wm.user_id = u.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, targetUserId]
    );

    if (targetMemberRes.length === 0) {
      return res.status(404).json({ error: { message: 'Workspace member not found', code: 'NOT_FOUND' } });
    }

    const targetUserEmail = targetMemberRes[0]?.user_email;
    const targetRole = targetMemberRes[0]?.id
      ? { name: targetMemberRes[0].role_name, rank: targetMemberRes[0].rank, is_system: targetMemberRes[0].is_system, is_editable: targetMemberRes[0].is_editable }
      : (targetMemberRes[0]?.role_name || targetMemberRes[0]?.legacy_role || 'Team Member');

    if (isOwnerRole(targetRole)) {
      if (!isOwnerRole(callerRole)) {
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
      const callerRank = getRoleRank(callerRole);
      const targetRank = getRoleRank(targetRole);
      if (!isOwnerRole(callerRole) && callerRank <= targetRank) {
        return res.status(403).json({
          error: { message: 'You cannot remove a member with equal or higher rank', code: 'INSUFFICIENT_ROLE_RANK' }
        });
      }
    }

    const wsRes = await req.db.query('SELECT name FROM workspaces WHERE id = ?', [workspaceId]);

    await notify(
      {
        eventType: 'workspace.member_removed',
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

    // Check remaining workspaces in the tenant for this user
    const remainingWs = await req.db.query(
      'SELECT COUNT(*) as count FROM workspace_members WHERE user_id = ?',
      [targetUserId]
    );
    const hasOtherWorkspaces = (remainingWs[0]?.count || 0) > 0;

    if (!hasOtherWorkspaces) {
      // Revoke all sessions only if member has no other workspaces in tenant
      await revokeAllSessions(req.db, targetUserId, 'MEMBER_REMOVED', req);
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

// POST /api/workspaces/:id/members/:userId/deactivate (Section 6)
router.post('/:id/members/:userId/deactivate', requireAuth, requirePermission('member.deactivate'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const targetUserId = Number(req.params.userId);

  try {
    if (Number(req.user.id) === targetUserId) {
      return res.status(400).json({ error: { message: 'Cannot deactivate yourself', code: 'SELF_DEACTIVATION_FORBIDDEN' } });
    }

    const callerWsRows = await req.db.query(
      'SELECT r.rank FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [workspaceId, req.user.id]
    );
    const callerRank = Number(callerWsRows[0]?.rank || 30);

    const targetWsRows = await req.db.query(
      'SELECT r.rank, r.is_system, r.is_editable, wm.status FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [workspaceId, targetUserId]
    );
    if (targetWsRows.length === 0) {
      return res.status(404).json({ error: { message: 'Member not found in workspace', code: 'NOT_FOUND' } });
    }

    const targetRank = Number(targetWsRows[0]?.rank || 30);
    if (targetRank >= callerRank) {
      return res.status(403).json({ error: { message: 'Cannot deactivate member with equal or higher rank', code: 'FORBIDDEN' } });
    }

    // Last Owner check across all workspaces in tenant where target is an Owner
    const targetOwnerWorkspaces = await req.db.query(
      `SELECT wm.workspace_id, w.name as workspace_name
       FROM workspace_members wm
       JOIN roles r ON wm.role_id = r.id
       JOIN workspaces w ON wm.workspace_id = w.id
       WHERE wm.user_id = ? AND r.is_system = 1 AND (r.is_editable = 0 OR COALESCE(r.rank, 30) >= 100)`,
      [targetUserId]
    );

    for (const ow of targetOwnerWorkspaces) {
      const ownerCount = await countOwners(ow.workspace_id, req.db);
      if (ownerCount <= 1) {
        return res.status(400).json({
          error: {
            message: 'Cannot deactivate the last Owner of the workspace',
            code: 'LAST_OWNER'
          }
        });
      }
    }

    // Company-level offboarding: set status = 'deactivated' in EVERY workspace of tenant
    await req.db.execute(
      "UPDATE workspace_members SET status = 'deactivated' WHERE user_id = ?",
      [targetUserId]
    );

    // Revoke all sessions for deactivated user
    await req.db.execute(
      'UPDATE sessions SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL',
      [targetUserId]
    );

    try {
      const { invalidateSessionCache } = require('../middleware/auth');
      invalidateSessionCache(req.tenant?.id);
    } catch (e) {}

    await logActivity({
      workspaceId,
      userId: req.user.id,
      actionType: 'member_deactivated',
      metaJson: { target_user_id: targetUserId },
      dbInstance: req.db,
      tenantId: req.tenant?.id
    });

    disconnectUserSockets(targetUserId, req.tenant ? req.tenant.id : null, 'MEMBER_DEACTIVATED');
    broadcastWorkspaceEvent(workspaceId, 'workspace:member_deactivated', { workspaceId, targetUserId }, req.headers['x-origin-id'], req.tenant?.id);

    return res.json({ message: 'Member deactivated', user_id: targetUserId, status: 'deactivated' });
  } catch (err) {
    next(err);
  }
});

// POST /api/workspaces/:id/members/:userId/reactivate (Section 6)
router.post('/:id/members/:userId/reactivate', requireAuth, requirePermission('member.deactivate'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const targetUserId = Number(req.params.userId);

  try {
    const callerWsRows = await req.db.query(
      'SELECT r.rank FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [workspaceId, req.user.id]
    );
    const callerRank = Number(callerWsRows[0]?.rank || 30);

    const targetWsRows = await req.db.query(
      'SELECT r.rank, wm.status FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [workspaceId, targetUserId]
    );
    if (targetWsRows.length === 0) {
      return res.status(404).json({ error: { message: 'Member not found in workspace', code: 'NOT_FOUND' } });
    }

    const targetRank = Number(targetWsRows[0]?.rank || 30);
    if (targetRank >= callerRank) {
      return res.status(403).json({ error: { message: 'Cannot reactivate member with equal or higher rank', code: 'FORBIDDEN' } });
    }

    // Company-level reactivation: restores status = 'active' across all workspaces (previous roles preserved)
    await req.db.execute(
      "UPDATE workspace_members SET status = 'active' WHERE user_id = ?",
      [targetUserId]
    );

    await logActivity({
      workspaceId,
      userId: req.user.id,
      actionType: 'member_reactivated',
      metaJson: { target_user_id: targetUserId },
      dbInstance: req.db,
      tenantId: req.tenant?.id
    });

    broadcastWorkspaceEvent(workspaceId, 'workspace:member_reactivated', { workspaceId, targetUserId }, req.headers['x-origin-id'], req.tenant?.id);

    return res.json({ message: 'Member reactivated', user_id: targetUserId, status: 'active' });
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
      `SELECT wm.role as legacy_role, r.id, r.name as role_name, r.rank, r.is_system, r.is_editable
       FROM workspace_members wm
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, req.user.id]
    );
    const callerRole = callerRoleRes[0]?.id
      ? { name: callerRoleRes[0].role_name, rank: callerRoleRes[0].rank, is_system: callerRoleRes[0].is_system, is_editable: callerRoleRes[0].is_editable }
      : (callerRoleRes[0]?.role_name || callerRoleRes[0]?.legacy_role || 'member');

    const targetRoleRes = await req.db.query(
      `SELECT wm.role as legacy_role, r.id, r.name as role_name, r.rank, r.is_system, r.is_editable
       FROM workspace_members wm
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, targetUserId]
    );
    const targetRole = targetRoleRes[0]?.id
      ? { name: targetRoleRes[0].role_name, rank: targetRoleRes[0].rank, is_system: targetRoleRes[0].is_system, is_editable: targetRoleRes[0].is_editable }
      : (targetRoleRes[0]?.role_name || targetRoleRes[0]?.legacy_role || 'member');

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

    const wsRes = await req.db.query('SELECT name FROM workspaces WHERE id = ?', [workspaceId]);
    await notify(
      {
        eventType: 'security.admin_password_reset',
        actorUserId: req.user.id,
        targetUserId,
        workspaceId,
        tenantId: req.tenant?.id || null,
        meta: { workspaceName: wsRes[0]?.name || 'Workspace' }
      },
      req.db
    );

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
      `SELECT wm.role as legacy_role, r.id, r.name as role_name, r.rank, r.is_system, r.is_editable
       FROM workspace_members wm
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, req.user.id]
    );
    const callerRole = callerRoleRes[0]?.id
      ? { name: callerRoleRes[0].role_name, rank: callerRoleRes[0].rank, is_system: callerRoleRes[0].is_system, is_editable: callerRoleRes[0].is_editable }
      : (callerRoleRes[0]?.role_name || callerRoleRes[0]?.legacy_role || 'member');

    const targetRoleRes = await req.db.query(
      `SELECT wm.role as legacy_role, r.id, r.name as role_name, r.rank, r.is_system, r.is_editable
       FROM workspace_members wm
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, targetUserId]
    );
    const targetRole = targetRoleRes[0]?.id
      ? { name: targetRoleRes[0].role_name, rank: targetRoleRes[0].rank, is_system: targetRoleRes[0].is_system, is_editable: targetRoleRes[0].is_editable }
      : (targetRoleRes[0]?.role_name || targetRoleRes[0]?.legacy_role || 'member');

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

    const wsRes = await req.db.query('SELECT name FROM workspaces WHERE id = ?', [workspaceId]);
    await notify(
      {
        eventType: 'security.two_factor_reset',
        actorUserId: req.user.id,
        targetUserId,
        workspaceId,
        tenantId: req.tenant?.id || null,
        meta: { workspaceName: wsRes[0]?.name || 'Workspace' }
      },
      req.db
    );

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
          eventType: 'workspace.member_added',
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
router.get('/:id/archived', requireAuth, requirePermission('archive.view'), async (req, res, next) => {
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
router.get('/:id/activity', requireAuth, requirePermission('activity.view'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(20, Math.max(1, parseInt(req.query.limit, 10) || 20)); // Exactly 20 per page default/max
  const offset = (page - 1) * limit;

  const boardId = req.query.board_id ? Number(req.query.board_id) : null;
  const actionType = req.query.action_type ? String(req.query.action_type).trim() : null;
  const search = req.query.search ? String(req.query.search).trim() : null;

  try {
    const whereConditions = ['(a.workspace_id = ? OR b.workspace_id = ?)'];
    const queryParams = [workspaceId, workspaceId];

    // Section 5.4: Filter activity by accessibleBoardIds
    const allowedBoardIds = await accessibleBoardIds(req.user.id, workspaceId, 'project.view', req.db);
    if (allowedBoardIds.length > 0) {
      whereConditions.push('(a.board_id IS NULL OR a.board_id IN (?))');
      queryParams.push(allowedBoardIds);
    } else {
      whereConditions.push('a.board_id IS NULL');
    }

    if (boardId) {
      whereConditions.push('a.board_id = ?');
      queryParams.push(boardId);
    }

    if (req.query.user_id) {
      whereConditions.push('a.user_id = ?');
      queryParams.push(Number(req.query.user_id));
    }

    if (actionType && actionType !== 'all') {
      whereConditions.push('a.action_type = ?');
      queryParams.push(actionType);
    }

    const category = (req.query.category || '').trim().toLowerCase();
    if (category && category !== 'all') {
      if (category === 'auth') {
        whereConditions.push("(a.action_type LIKE '%login%' OR a.action_type LIKE '%logout%' OR a.action_type LIKE '%password%' OR a.action_type LIKE '%2fa%' OR a.action_type LIKE '%session%')");
      } else if (category === 'tasks' || category === 'cards') {
        whereConditions.push("(a.action_type LIKE '%card%' OR a.action_type LIKE '%task%' OR a.action_type LIKE '%due_date%' OR a.action_type LIKE '%complete%' OR a.action_type LIKE '%checklist%')");
      } else if (category === 'comments') {
        whereConditions.push("(a.action_type LIKE '%comment%')");
      } else if (category === 'members') {
        whereConditions.push("(a.action_type LIKE '%member%' OR a.action_type LIKE '%assign%' OR a.action_type LIKE '%invite%')");
      } else if (category === 'roles') {
        whereConditions.push("(a.action_type LIKE '%role%' OR a.action_type LIKE '%permission%')");
      } else if (category === 'boards') {
        whereConditions.push("(a.action_type LIKE '%board%' OR a.action_type LIKE '%list%' OR a.action_type LIKE '%label%')");
      }
    }

    if (search) {
      whereConditions.push(
        '(c.title LIKE ? OR u.name LIKE ? OR b.name LIKE ? OR a.action_type LIKE ? OR JSON_UNQUOTE(JSON_EXTRACT(a.meta_json, "$.title")) LIKE ? OR JSON_UNQUOTE(JSON_EXTRACT(a.meta_json, "$.card_title")) LIKE ? OR JSON_UNQUOTE(JSON_EXTRACT(a.meta_json, "$.item_text")) LIKE ?)'
      );
      const searchWildcard = `%${search}%`;
      queryParams.push(searchWildcard, searchWildcard, searchWildcard, searchWildcard, searchWildcard, searchWildcard, searchWildcard);
    }

    const whereSql = whereConditions.join(' AND ');

    // 1. Total count query
    const countSql = `
      SELECT COUNT(*) as total
      FROM activity_log a
      LEFT JOIN boards b ON a.board_id = b.id
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
        a.workspace_id,
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
      LEFT JOIN boards b ON a.board_id = b.id
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
router.get('/:id/reports', requireAuth, requirePermission('report.view_project'), async (req, res, next) => {
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

    // Section 5.4: Filter active boards via accessibleBoardIds
    const allowedBoardIds = await accessibleBoardIds(req.user.id, workspaceId, 'project.view', req.db);
    if (allowedBoardIds.length === 0) {
      return res.json({
        workspace: { id: workspaceId, name: ws[0].name },
        boards: [],
        summary: { totalTasks: 0, completedTasks: 0, overdueTasks: 0, dueSoonTasks: 0, completionRate: 0 },
        breakdowns: { byStage: {}, byPriority: {}, byBoard: [] },
        trends: { tasksCreatedOverTime: [], tasksCompletedOverTime: [] }
      });
    }

    if (boardId && !allowedBoardIds.includes(boardId)) {
      return res.status(403).json({ error: { message: 'Access denied: not authorized to view reports for this project', code: 'FORBIDDEN' } });
    }

    const boardsRes = await req.db.query(
      `SELECT id, name, background_color, is_archived, created_at
       FROM boards
       WHERE workspace_id = ? AND is_archived = 0 AND id IN (?)
       ORDER BY name ASC`,
      [workspaceId, boardId ? [boardId] : allowedBoardIds]
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
    } else {
      boardClause = 'AND b.id IN (?)';
      boardParam.push(allowedBoardIds);
    }

    // Helper to categorize task stage by list name and completion flag
    function classifyTaskStage(listName, isComplete) {
      if (isComplete) return 'done';
      const name = (listName || '').toLowerCase().trim();
      if (name.includes('done') || name.includes('complete') || name.includes('finished') || name.includes('closed') || name.includes('resolved')) {
        return 'done';
      }
      if (name.includes('review') || name.includes('qa') || name.includes('test') || name.includes('verify') || name.includes('audit')) {
        return 'review';
      }
      if (name.includes('progress') || name.includes('doing') || name.includes('wip') || name.includes('working') || name.includes('dev') || name.includes('active')) {
        return 'in_progress';
      }
      if (name.includes('todo') || name.includes('to do') || name.includes('to-do') || name.includes('backlog') || name.includes('open') || name.includes('new') || name.includes('ready') || name.includes('pending')) {
        return 'todo';
      }
      return 'in_progress';
    }

    // 2. High-level summary metrics
    const summaryRes = await req.db.query(
      `SELECT
        COUNT(DISTINCT c.id) as total_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 1 OR LOWER(l.name) IN ('done', 'completed', 'complete', 'closed', 'finished') THEN c.id END) as completed_tasks,
        COUNT(DISTINCT CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND c.due_date IS NOT NULL AND c.due_date < NOW() THEN c.id END) as overdue_tasks,
        COUNT(DISTINCT CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND c.due_date IS NOT NULL AND c.due_date >= NOW() AND c.due_date <= DATE_ADD(NOW(), INTERVAL 7 DAY) THEN c.id END) as due_soon_tasks,
        COUNT(DISTINCT CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND (LOWER(l.name) LIKE '%progress%' OR LOWER(l.name) LIKE '%doing%' OR LOWER(l.name) LIKE '%wip%' OR LOWER(l.name) LIKE '%working%' OR LOWER(l.name) LIKE '%active%') THEN c.id END) as in_progress_tasks,
        COUNT(DISTINCT CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND (LOWER(l.name) LIKE '%review%' OR LOWER(l.name) LIKE '%qa%' OR LOWER(l.name) LIKE '%test%') THEN c.id END) as review_tasks,
        COUNT(DISTINCT CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND (LOWER(l.name) LIKE '%todo%' OR LOWER(l.name) LIKE '%to do%' OR LOWER(l.name) LIKE '%to-do%' OR LOWER(l.name) LIKE '%backlog%' OR LOWER(l.name) LIKE '%open%' OR (LOWER(l.name) NOT LIKE '%progress%' AND LOWER(l.name) NOT LIKE '%doing%' AND LOWER(l.name) NOT LIKE '%wip%' AND LOWER(l.name) NOT LIKE '%working%' AND LOWER(l.name) NOT LIKE '%active%' AND LOWER(l.name) NOT LIKE '%review%' AND LOWER(l.name) NOT LIKE '%qa%' AND LOWER(l.name) NOT LIKE '%test%')) THEN c.id END) as todo_tasks,
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
    const todoTasks = Number(summaryRes[0]?.todo_tasks || 0);
    const reviewTasks = Number(summaryRes[0]?.review_tasks || 0);
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
           AND (c.is_complete = 1 OR LOWER(l.name) IN ('done', 'completed', 'complete', 'closed', 'finished'))
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

    // 4. Status / Lists breakdown & Pipeline Cards
    const statusBreakdownRes = await req.db.query(
      `SELECT
        l.id as list_id,
        l.name as list_name,
        l.position as list_position,
        b.id as board_id,
        b.name as board_name,
        COUNT(DISTINCT c.id) as task_count,
        COUNT(DISTINCT CASE WHEN c.is_complete = 1 OR LOWER(l.name) IN ('done', 'completed', 'complete', 'closed', 'finished') THEN c.id END) as completed_count,
        COUNT(DISTINCT CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND c.due_date IS NOT NULL AND c.due_date < NOW() THEN c.id END) as overdue_count
       FROM lists l
       JOIN boards b ON l.board_id = b.id
       LEFT JOIN cards c ON l.id = c.list_id AND c.is_archived = 0
       WHERE b.workspace_id = ?
         AND b.is_archived = 0
         AND l.is_archived = 0
         ${boardClause}
       GROUP BY l.id, l.name, l.position, b.id, b.name
       ORDER BY b.name ASC, l.position ASC`,
      [workspaceId, ...boardParam]
    );

    // Fetch active cards for pipeline visualization with assignees
    const pipelineCardsRes = await req.db.query(
      `SELECT
        c.id,
        c.title,
        c.list_id,
        c.due_date,
        c.is_complete,
        c.position,
        c.created_at,
        l.name as list_name,
        b.id as board_id,
        b.name as board_name,
        CASE WHEN (c.is_complete = 1 OR LOWER(l.name) IN ('done', 'completed', 'complete', 'closed', 'finished')) THEN 1 ELSE 0 END as is_effectively_complete,
        CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND c.due_date IS NOT NULL AND c.due_date < NOW() THEN 1 ELSE 0 END as is_overdue,
        CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND c.due_date IS NOT NULL AND c.due_date >= NOW() AND c.due_date <= DATE_ADD(NOW(), INTERVAL 7 DAY) THEN 1 ELSE 0 END as is_due_soon
       FROM cards c
       JOIN lists l ON c.list_id = l.id AND l.is_archived = 0
       JOIN boards b ON l.board_id = b.id AND b.is_archived = 0
       WHERE b.workspace_id = ?
         AND c.is_archived = 0
         ${boardClause}
       ORDER BY c.position ASC, c.id ASC`,
      [workspaceId, ...boardParam]
    );

    const pipelineCardIds = pipelineCardsRes.map((c) => c.id);
    let cardMembersMap = {};
    if (pipelineCardIds.length > 0) {
      const cmRes = await req.db.query(
        `SELECT cm.card_id, u.id, u.name, u.email, u.avatar_url
         FROM card_members cm
         JOIN users u ON cm.user_id = u.id
         WHERE cm.card_id IN (${pipelineCardIds.map(() => '?').join(',')})`,
        pipelineCardIds
      );
      cmRes.forEach((row) => {
        if (!cardMembersMap[row.card_id]) cardMembersMap[row.card_id] = [];
        cardMembersMap[row.card_id].push({
          id: row.id,
          name: row.name,
          email: row.email,
          avatar_url: row.avatar_url
        });
      });
    }

    const listCardsMap = {};
    pipelineCardsRes.forEach((c) => {
      if (!listCardsMap[c.list_id]) listCardsMap[c.list_id] = [];
      const isDone = Boolean(c.is_effectively_complete);
      listCardsMap[c.list_id].push({
        id: c.id,
        title: c.title,
        due_date: c.due_date,
        is_complete: isDone,
        is_overdue: Boolean(c.is_overdue),
        is_due_soon: Boolean(c.is_due_soon),
        list_id: c.list_id,
        list_name: c.list_name,
        board_id: c.board_id,
        board_name: c.board_name,
        stage: classifyTaskStage(c.list_name, isDone),
        members: cardMembersMap[c.id] || []
      });
    });

    const statusBreakdown = statusBreakdownRes.map((s) => {
      const sStage = classifyTaskStage(s.list_name, false);
      return {
        list_id: s.list_id,
        list_name: s.list_name,
        list_position: s.list_position,
        board_id: s.board_id,
        board_name: s.board_name,
        stage: sStage,
        task_count: Number(s.task_count || 0),
        completed_count: Number(s.completed_count || 0),
        overdue_count: Number(s.overdue_count || 0),
        percentage: totalTasks > 0 ? Math.round((Number(s.task_count || 0) / totalTasks) * 100) : 0,
        cards: listCardsMap[s.list_id] || []
      };
    });

    // Stage breakdown across entire workspace
    const stageBreakdown = {
      todo: 0,
      in_progress: 0,
      review: 0,
      done: 0
    };
    statusBreakdown.forEach((s) => {
      if (s.stage === 'todo') stageBreakdown.todo += s.task_count;
      else if (s.stage === 'review') stageBreakdown.review += s.task_count;
      else if (s.stage === 'done') stageBreakdown.done += s.task_count;
      else stageBreakdown.in_progress += s.task_count;
    });

    // 5. Boards breakdown
    const boardsBreakdownRes = await req.db.query(
      `SELECT
        b.id,
        b.name,
        b.background_color,
        COUNT(DISTINCT bm.user_id) as member_count,
        COUNT(DISTINCT c.id) as total_tasks,
        COUNT(DISTINCT CASE WHEN c.is_complete = 1 OR LOWER(l.name) IN ('done', 'completed', 'complete', 'closed', 'finished') THEN c.id END) as completed_tasks,
        COUNT(DISTINCT CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND c.due_date IS NOT NULL AND c.due_date < NOW() THEN c.id END) as overdue_tasks,
        COUNT(DISTINCT CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND (LOWER(l.name) LIKE '%progress%' OR LOWER(l.name) LIKE '%doing%' OR LOWER(l.name) LIKE '%wip%' OR LOWER(l.name) LIKE '%working%' OR LOWER(l.name) LIKE '%active%') THEN c.id END) as in_progress_tasks,
        COUNT(DISTINCT CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND (LOWER(l.name) LIKE '%todo%' OR LOWER(l.name) LIKE '%to do%' OR LOWER(l.name) LIKE '%to-do%' OR LOWER(l.name) LIKE '%backlog%' OR LOWER(l.name) LIKE '%open%' OR (LOWER(l.name) NOT LIKE '%progress%' AND LOWER(l.name) NOT LIKE '%doing%' AND LOWER(l.name) NOT LIKE '%wip%' AND LOWER(l.name) NOT LIKE '%working%' AND LOWER(l.name) NOT LIKE '%active%' AND LOWER(l.name) NOT LIKE '%review%' AND LOWER(l.name) NOT LIKE '%qa%' AND LOWER(l.name) NOT LIKE '%test%')) THEN c.id END) as todo_tasks
       FROM boards b
       LEFT JOIN board_members bm ON b.id = bm.board_id
       LEFT JOIN lists l ON b.id = l.board_id AND l.is_archived = 0
       LEFT JOIN cards c ON l.id = c.list_id AND c.is_archived = 0 ${timeframeClause}
       WHERE b.workspace_id = ? AND b.is_archived = 0
       GROUP BY b.id, b.name, b.background_color
       ORDER BY total_tasks DESC, b.name ASC`,
      [workspaceId]
    );

    // Group lists by board
    const boardListsMap = {};
    statusBreakdown.forEach((s) => {
      if (!boardListsMap[s.board_id]) boardListsMap[s.board_id] = [];
      boardListsMap[s.board_id].push({
        id: s.list_id,
        name: s.list_name,
        task_count: s.task_count,
        stage: s.stage
      });
    });

    const boardsBreakdown = boardsBreakdownRes.map((b) => {
      const bTotal = Number(b.total_tasks || 0);
      const bCompleted = Number(b.completed_tasks || 0);
      const bOverdue = Number(b.overdue_tasks || 0);
      const bInProgress = Number(b.in_progress_tasks || 0);
      const bTodo = Number(b.todo_tasks || 0);
      return {
        id: b.id,
        name: b.name,
        background_color: b.background_color,
        member_count: Number(b.member_count || 0),
        total_tasks: bTotal,
        completed_tasks: bCompleted,
        overdue_tasks: bOverdue,
        in_progress_tasks: bInProgress,
        todo_tasks: bTodo,
        completion_rate: bTotal > 0 ? Math.round((bCompleted / bTotal) * 100) : 0,
        lists: boardListsMap[b.id] || []
      };
    });

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
        u.avatar_url,
        r.name as role_name,
        COUNT(DISTINCT CASE WHEN b.id IS NOT NULL THEN c.id END) as assigned_tasks,
        COUNT(DISTINCT CASE WHEN b.id IS NOT NULL AND (c.is_complete = 1 OR LOWER(l.name) IN ('done', 'completed', 'complete', 'closed', 'finished')) THEN c.id END) as completed_tasks,
        COUNT(DISTINCT CASE WHEN b.id IS NOT NULL AND (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND c.due_date IS NOT NULL AND c.due_date < NOW() THEN c.id END) as overdue_tasks,
        COUNT(DISTINCT CASE WHEN b.id IS NOT NULL AND (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND (LOWER(l.name) LIKE '%progress%' OR LOWER(l.name) LIKE '%doing%' OR LOWER(l.name) LIKE '%wip%' OR LOWER(l.name) LIKE '%working%' OR LOWER(l.name) LIKE '%active%') THEN c.id END) as in_progress_tasks,
        COUNT(DISTINCT CASE WHEN b.id IS NOT NULL AND (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND (LOWER(l.name) LIKE '%review%' OR LOWER(l.name) LIKE '%qa%' OR LOWER(l.name) LIKE '%test%') THEN c.id END) as review_tasks,
        COUNT(DISTINCT CASE WHEN b.id IS NOT NULL AND (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND (LOWER(l.name) LIKE '%todo%' OR LOWER(l.name) LIKE '%to do%' OR LOWER(l.name) LIKE '%to-do%' OR LOWER(l.name) LIKE '%backlog%' OR LOWER(l.name) LIKE '%open%' OR (LOWER(l.name) NOT LIKE '%progress%' AND LOWER(l.name) NOT LIKE '%doing%' AND LOWER(l.name) NOT LIKE '%wip%' AND LOWER(l.name) NOT LIKE '%working%' AND LOWER(l.name) NOT LIKE '%active%' AND LOWER(l.name) NOT LIKE '%review%' AND LOWER(l.name) NOT LIKE '%qa%' AND LOWER(l.name) NOT LIKE '%test%')) THEN c.id END) as todo_tasks
       FROM workspace_members wm
       JOIN users u ON wm.user_id = u.id
       LEFT JOIN roles r ON wm.role_id = r.id
       LEFT JOIN card_members cm ON u.id = cm.user_id
       LEFT JOIN cards c ON cm.card_id = c.id AND c.is_archived = 0
       LEFT JOIN lists l ON c.list_id = l.id AND l.is_archived = 0
       LEFT JOIN boards b ON l.board_id = b.id AND b.is_archived = 0 AND b.workspace_id = wm.workspace_id ${boardClause}
       WHERE wm.workspace_id = ?
       GROUP BY u.id, u.name, u.email, u.avatar_url, r.name
       ORDER BY assigned_tasks DESC, u.name ASC`,
      [...boardParam, workspaceId]
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
        c.list_id,
        l.name as list_name,
        l.position as list_position,
        b.id as board_id,
        b.name as board_name,
        CASE WHEN (c.is_complete = 1 OR LOWER(l.name) IN ('done', 'completed', 'complete', 'closed', 'finished')) THEN 1 ELSE 0 END as is_effectively_complete,
        CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND c.due_date IS NOT NULL AND c.due_date < NOW() THEN 1 ELSE 0 END as is_overdue,
        CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')) AND c.due_date IS NOT NULL AND c.due_date >= NOW() AND c.due_date <= DATE_ADD(NOW(), INTERVAL 7 DAY) THEN 1 ELSE 0 END as is_due_soon
       FROM card_members cm
       JOIN cards c ON cm.card_id = c.id
       JOIN lists l ON c.list_id = l.id AND l.is_archived = 0
       JOIN boards b ON l.board_id = b.id AND b.is_archived = 0
       WHERE b.workspace_id = ?
         AND c.is_archived = 0
         ${boardClause}
       ORDER BY c.due_date ASC, c.created_at DESC`,
      [workspaceId, ...boardParam]
    );

    const userTasksMap = {};
    assignedCardsRes.forEach((row) => {
      if (!userTasksMap[row.user_id]) userTasksMap[row.user_id] = [];
      const isDone = Boolean(row.is_effectively_complete);
      const isOverdue = Boolean(row.is_overdue);
      const isDueSoon = Boolean(row.is_due_soon);
      const stage = classifyTaskStage(row.list_name, isDone);

      userTasksMap[row.user_id].push({
        id: row.id,
        title: row.title,
        due_date: row.due_date,
        is_complete: isDone,
        is_overdue: isOverdue,
        is_due_soon: isDueSoon,
        list_id: row.list_id,
        list_name: row.list_name,
        stage: stage,
        board_id: row.board_id,
        board_name: row.board_name,
        created_at: row.created_at
      });
    });

    // 7b. Cards Created / Reported by Members (Tracks Tester, QA, and Manager activity)
    const createdCardsRes = await req.db.query(
      `SELECT
        ca.user_id,
        c.id,
        c.title,
        c.due_date,
        c.is_complete,
        c.created_at,
        c.list_id,
        l.name as list_name,
        l.position as list_position,
        b.id as board_id,
        b.name as board_name,
        CASE WHEN (c.is_complete = 1 OR LOWER(l.name) IN ('done', 'completed', 'complete', 'closed', 'finished', 'resolved')) THEN 1 ELSE 0 END as is_effectively_complete,
        CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished', 'resolved')) AND c.due_date IS NOT NULL AND c.due_date < NOW() THEN 1 ELSE 0 END as is_overdue,
        CASE WHEN (c.is_complete = 0 AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished', 'resolved')) AND c.due_date IS NOT NULL AND c.due_date >= NOW() AND c.due_date <= DATE_ADD(NOW(), INTERVAL 7 DAY) THEN 1 ELSE 0 END as is_due_soon
       FROM (
         SELECT user_id, card_id FROM card_assigners
         UNION
         SELECT user_id, card_id FROM activity_log WHERE action_type = 'created_card' AND card_id IS NOT NULL AND user_id IS NOT NULL
       ) ca
       JOIN cards c ON ca.card_id = c.id
       JOIN lists l ON c.list_id = l.id AND l.is_archived = 0
       JOIN boards b ON l.board_id = b.id AND b.is_archived = 0
       WHERE b.workspace_id = ?
         AND c.is_archived = 0
         ${boardClause}
         ${timeframeClause}
       ORDER BY c.created_at DESC`,
      [workspaceId, ...boardParam]
    );

    const userCreatedCardsMap = {};
    createdCardsRes.forEach((row) => {
      if (!userCreatedCardsMap[row.user_id]) userCreatedCardsMap[row.user_id] = [];
      const isDone = Boolean(row.is_effectively_complete);
      const isOverdue = Boolean(row.is_overdue);
      const isDueSoon = Boolean(row.is_due_soon);
      const stage = classifyTaskStage(row.list_name, isDone);

      userCreatedCardsMap[row.user_id].push({
        id: row.id,
        title: row.title,
        due_date: row.due_date,
        is_complete: isDone,
        is_overdue: isOverdue,
        is_due_soon: isDueSoon,
        list_id: row.list_id,
        list_name: row.list_name,
        stage: stage,
        board_id: row.board_id,
        board_name: row.board_name,
        created_at: row.created_at,
        members: cardMembersMap[row.id] || []
      });
    });

    const membersWorkload = membersWorkloadRes.map((m) => {
      const assigned = Number(m.assigned_tasks || 0);
      const completed = Number(m.completed_tasks || 0);
      const overdue = Number(m.overdue_tasks || 0);
      const inProgress = Number(m.in_progress_tasks || 0);
      const todo = Number(m.todo_tasks || 0);
      const review = Number(m.review_tasks || 0);
      const userTasks = userTasksMap[m.id] || [];

      const userCreatedCards = userCreatedCardsMap[m.id] || [];
      const createdTasksCount = userCreatedCards.length;
      const createdCompletedCount = userCreatedCards.filter((t) => t.is_complete).length;
      const createdTodoCount = userCreatedCards.filter((t) => t.stage === 'todo' && !t.is_complete).length;
      const createdInProgressCount = userCreatedCards.filter((t) => (t.stage === 'in_progress' || t.stage === 'review') && !t.is_complete).length;
      const createdOverdueCount = userCreatedCards.filter((t) => t.is_overdue).length;
      const createdResolutionRate = createdTasksCount > 0 ? Math.round((createdCompletedCount / createdTasksCount) * 100) : 0;

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
        avatar_url: m.avatar_url,
        role: m.role_name || 'Member',
        assigned_tasks: assigned,
        todo_tasks: todo,
        in_progress_tasks: inProgress,
        review_tasks: review,
        completed_tasks: completed,
        overdue_tasks: overdue,
        due_soon_tasks: dueSoon,
        completion_rate: assigned > 0 ? Math.round((completed / assigned) * 100) : 0,
        created_tasks: createdTasksCount,
        created_completed_tasks: createdCompletedCount,
        created_todo_tasks: createdTodoCount,
        created_in_progress_tasks: createdInProgressCount,
        created_overdue_tasks: createdOverdueCount,
        created_resolution_rate: createdResolutionRate,
        created_cards: userCreatedCards,
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
         AND LOWER(l.name) NOT IN ('done', 'completed', 'complete', 'closed', 'finished')
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
        todo_tasks: todoTasks,
        in_progress_tasks: inProgressTasks,
        review_tasks: reviewTasks,
        completed_tasks: completedTasks,
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
      stage_breakdown: stageBreakdown,
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

// ============================================================================
// COMPANY MEMBERS DIRECTORY & MANAGEMENT ENDPOINTS
// ============================================================================

// GET /api/workspaces/:id/company-members - Directory of all users, workspaces, boards, and pending invites
router.get('/:id/company-members', requireAuth, requirePermission('member.view'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);

  try {
    const isMember = await req.db.query(
      'SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
      [workspaceId, req.user.id]
    );
    if (isMember.length === 0) {
      return res.status(403).json({ error: { message: 'Access denied to workspace', code: 'FORBIDDEN' } });
    }

    const hasViewPerm = await userHasPermission(req.user.id, workspaceId, 'member.view', req.db);
    if (!hasViewPerm) {
      return res.status(403).json({ error: { message: 'Permission denied: member.view required', code: 'FORBIDDEN' } });
    }

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit, 10) || 20));
    const offset = (page - 1) * limit;
    const search = (req.query.search || '').trim().toLowerCase();
    const filterWsId = req.query.workspace_id && req.query.workspace_id !== 'all' ? Number(req.query.workspace_id) : null;

    let whereClauses = [];
    let countParams = [];
    let queryParams = [];

    if (search) {
      whereClauses.push('(LOWER(u.name) LIKE ? OR LOWER(u.email) LIKE ?)');
      countParams.push(`%${search}%`, `%${search}%`);
      queryParams.push(`%${search}%`, `%${search}%`);
    }

    if (filterWsId) {
      whereClauses.push('EXISTS (SELECT 1 FROM workspace_members wm WHERE wm.workspace_id = ? AND wm.user_id = u.id)');
      countParams.push(filterWsId);
      queryParams.push(filterWsId);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    // 1. Total count of matching users
    const [countRow] = await req.db.query(
      `SELECT COUNT(u.id) as total FROM users u ${whereSql}`,
      countParams
    );
    const total = countRow?.total || 0;
    const totalPages = Math.ceil(total / limit) || 1;

    // 2. Paginated users
    const usersRes = await req.db.query(
      `SELECT u.id, u.name, u.email, u.avatar_url, u.created_at
       FROM users u
       ${whereSql}
       ORDER BY u.name ASC
       LIMIT ? OFFSET ?`,
      [...queryParams, limit, offset]
    );

    const userIds = usersRes.map((u) => u.id);

    // 3. Workspace memberships for paginated users across unarchived workspaces
    const wmRes = userIds.length > 0 ? await req.db.query(
      `SELECT wm.user_id, wm.workspace_id, wm.role as role_name, wm.role_id,
              w.name as workspace_name, r.name as resolved_role_name,
              r.is_system, r.is_editable
       FROM workspace_members wm
       JOIN workspaces w ON wm.workspace_id = w.id
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE w.is_archived = 0 AND wm.user_id IN (?)
       ORDER BY w.name ASC`,
      [userIds]
    ) : [];

    // 4. Board memberships for paginated users across unarchived boards
    const bmRes = userIds.length > 0 ? await req.db.query(
      `SELECT bm.user_id, bm.board_id, bm.role,
              b.name as board_name, b.workspace_id,
              w.name as workspace_name
       FROM board_members bm
       JOIN boards b ON bm.board_id = b.id
       JOIN workspaces w ON b.workspace_id = w.id
       WHERE b.is_archived = 0 AND w.is_archived = 0 AND bm.user_id IN (?)
       ORDER BY b.name ASC`,
      [userIds]
    ) : [];

    // 5. All active workspaces
    const allWorkspaces = await req.db.query(
      'SELECT id, name FROM workspaces WHERE is_archived = 0 ORDER BY name ASC'
    );

    // 6. All active boards
    const allBoards = await req.db.query(
      `SELECT b.id, b.name, b.workspace_id, w.name as workspace_name
       FROM boards b
       JOIN workspaces w ON b.workspace_id = w.id
       WHERE b.is_archived = 0 AND w.is_archived = 0
       ORDER BY b.name ASC`
    );

    // 7. Available roles
    const rolesRes = await req.db.query(
      `SELECT id, name, is_system, is_editable
       FROM roles
       WHERE workspace_id = ? OR workspace_id IS NULL
       ORDER BY is_system DESC, name ASC`,
      [workspaceId]
    );

    // 8. Pending company invitations
    const pendingInvitesRes = await req.db.query(
      `SELECT pi.id, pi.email, pi.workspace_id, pi.token, pi.role_id, pi.status, pi.created_at, pi.expires_at,
              w.name as workspace_name, r.name as role_name,
              GROUP_CONCAT(ib.board_id) as board_ids_str
       FROM pending_invitations pi
       JOIN workspaces w ON pi.workspace_id = w.id
       LEFT JOIN roles r ON pi.role_id = r.id
       LEFT JOIN invitation_boards ib ON pi.id = ib.invitation_id
       WHERE pi.status = 'pending'
       GROUP BY pi.id, pi.email, pi.workspace_id, pi.token, pi.role_id, pi.status, pi.created_at, pi.expires_at, w.name, r.name
       ORDER BY pi.created_at DESC`
    );

    const boardMap = {};
    allBoards.forEach((b) => {
      boardMap[b.id] = b.name;
    });

    const clientBase = (process.env.CLIENT_URL || (process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5173')).replace(/\/$/, '');

    const invitations = pendingInvitesRes.map((inv) => {
      const bIds = inv.board_ids_str ? inv.board_ids_str.split(',').map(Number) : [];
      return {
        ...inv,
        role_name: inv.role_name || 'Team Member',
        board_ids: bIds,
        board_names: bIds.map((id) => boardMap[id]).filter(Boolean),
        invite_url: `${clientBase}/invite?token=${inv.token}&email=${encodeURIComponent(inv.email)}`
      };
    });

    // Build user mapping
    const userWsMap = {};
    wmRes.forEach((row) => {
      if (!userWsMap[row.user_id]) userWsMap[row.user_id] = [];
      userWsMap[row.user_id].push({
        id: row.workspace_id,
        name: row.workspace_name,
        role: row.resolved_role_name || row.role_name || 'Member',
        role_id: row.role_id
      });
    });

    const userBoardsMap = {};
    bmRes.forEach((row) => {
      if (!userBoardsMap[row.user_id]) userBoardsMap[row.user_id] = [];
      userBoardsMap[row.user_id].push({
        id: row.board_id,
        name: row.board_name,
        workspace_id: row.workspace_id,
        workspace_name: row.workspace_name,
        role: row.role
      });
    });

    const members = usersRes.map((u) => {
      const userWorkspaces = userWsMap[u.id] || [];
      const userBoards = userBoardsMap[u.id] || [];

      // Determine primary role across workspaces
      let primaryRole = 'Team Member';
      let isOwner = false;
      if (userWorkspaces.some((w) => isOwnerRole(w.role))) {
        primaryRole = 'Owner';
        isOwner = true;
      } else if (userWorkspaces.some((w) => w.role === 'Admin')) {
        primaryRole = 'Admin';
      } else if (userWorkspaces.length > 0) {
        primaryRole = userWorkspaces[0].role || 'Team Member';
      }

      return {
        id: u.id,
        name: u.name,
        email: u.email,
        avatar_url: u.avatar_url,
        created_at: u.created_at,
        role: primaryRole,
        is_owner: isOwner,
        workspaces: userWorkspaces,
        boards: userBoards
      };
    });

    return res.json({
      members,
      pagination: {
        page,
        limit,
        total,
        totalPages
      },
      workspaces: allWorkspaces,
      boards: allBoards,
      roles: rolesRes,
      invitations
    });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/workspaces/:id/company-members/:userId/role - Change member role across all their workspaces
router.patch('/:id/company-members/:userId/role', requireAuth, requirePermission(['member.assign_role', 'role.assign']), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const targetUserId = Number(req.params.userId);
  const role_id = req.body.role_id !== undefined ? req.body.role_id : req.body.roleId;

  if (!role_id) {
    return res.status(400).json({ error: { message: 'role_id is required', code: 'BAD_REQUEST' } });
  }

  try {
    if (Number(req.user.id) === targetUserId) {
      return res.status(403).json({
        error: { message: 'You cannot change your own role', code: 'SELF_ROLE_CHANGE_FORBIDDEN' }
      });
    }

    const [roleRow] = await req.db.query('SELECT id, name, is_system, is_editable, COALESCE(rank, 30) as rank FROM roles WHERE id = ?', [role_id]);
    if (!roleRow) {
      return res.status(400).json({ error: { message: 'Selected role does not exist', code: 'BAD_REQUEST' } });
    }

    // Caller rank check
    const callerMemberRes = await req.db.query(
      `SELECT r.id, r.name, r.is_system, r.is_editable, COALESCE(r.rank, 30) as rank
       FROM workspace_members wm
       JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND wm.user_id = ?`,
      [workspaceId, req.user.id]
    );
    const callerRole = callerMemberRes[0] || { is_system: 0, is_editable: 1, rank: 30 };
    const callerIsOwner = isOwnerRole(callerRole);
    const callerRank = getRoleRank(callerRole);

    const newRoleRank = getRoleRank(roleRow);
    if (newRoleRank >= callerRank && !callerIsOwner) {
      return res.status(403).json({
        error: {
          message: 'Cannot assign a role at or above your own rank',
          code: 'CANNOT_ASSIGN_ROLE_AT_OR_ABOVE_OWN_RANK'
        }
      });
    }

    // Target current role check
    const targetRoles = await req.db.query(
      `SELECT r.id, r.name as role_name, r.is_system, r.is_editable, COALESCE(r.rank, 30) as rank
       FROM workspace_members wm
       JOIN roles r ON wm.role_id = r.id
       WHERE wm.user_id = ?`,
      [targetUserId]
    );
    const targetIsOwner = targetRoles.some((r) => isOwnerRole(r));
    const newIsOwner = isOwnerRole(roleRow);

    if (targetIsOwner && !callerIsOwner) {
      return res.status(403).json({
        error: { message: 'Only an Owner may modify the Owner role', code: 'ONLY_OWNER_MAY_MODIFY_OWNER' }
      });
    }

    // Safety Floor: Cannot demote the last Owner in the company
    if (targetIsOwner && !newIsOwner) {
      const allOwnerRows = await req.db.query(
        `SELECT DISTINCT wm.user_id
         FROM workspace_members wm
         JOIN roles r ON wm.role_id = r.id
         WHERE r.is_system = 1 AND (r.is_editable = 0 OR COALESCE(r.rank, 30) >= 100)`
      );
      if (allOwnerRows.length <= 1) {
        return res.status(400).json({
          error: { message: 'Cannot demote the last Owner of the organization', code: 'SAFETY_FLOOR_VIOLATION' }
        });
      }
    }

    await req.db.execute(
      'UPDATE workspace_members SET role = ?, role_id = ? WHERE user_id = ?',
      [roleRow.name, roleRow.id, targetUserId]
    );

    if (newIsOwner) {
      await syncCompanyOwners(req.db, targetUserId);
    }

    // Notify user of permission update across workspaces
    sendUserEvent(targetUserId, 'user:permissions_updated', {
      workspaceId,
      targetUserId,
      roleId: roleRow.id,
      companyWide: true
    }, req.tenant?.id);

    return res.json({
      success: true,
      message: `Role updated to ${roleRow.name} successfully`,
      user_id: targetUserId,
      role: roleRow.name,
      role_id: roleRow.id
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/workspaces/:id/company-members/:userId/workspaces - Assign/unassign workspaces for member
router.post('/:id/company-members/:userId/workspaces', requireAuth, requirePermission(['member.invite', 'workspace.update']), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const targetUserId = Number(req.params.userId);
  const workspace_ids = req.body.workspace_ids || req.body.workspaceIds || [];
  const role_id = req.body.role_id !== undefined ? req.body.role_id : req.body.roleId;

  try {
    // Resolve default role for new assignments
    let resolvedRoleId = role_id;
    let resolvedRoleName = 'Team Member';
    if (resolvedRoleId) {
      const [rRow] = await req.db.query('SELECT id, name FROM roles WHERE id = ?', [resolvedRoleId]);
      if (rRow) {
        resolvedRoleId = rRow.id;
        resolvedRoleName = rRow.name;
      }
    } else {
      const [defRow] = await req.db.query("SELECT id, name FROM roles WHERE is_system = 1 AND name = 'Team Member' LIMIT 1");
      if (defRow) {
        resolvedRoleId = defRow.id;
        resolvedRoleName = defRow.name;
      }
    }

    const currentWsRows = await req.db.query(
      `SELECT wm.workspace_id, wm.role, wm.role_id, r.is_system, r.is_editable, COALESCE(r.rank, 30) as rank
       FROM workspace_members wm
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE wm.user_id = ?`,
      [targetUserId]
    );
    const currentWsIds = currentWsRows.map((r) => r.workspace_id);

    const targetSet = new Set(workspace_ids.map(Number));

    // Workspaces to add
    const toAdd = Array.from(targetSet).filter((id) => !currentWsIds.includes(id));
    for (const addWsId of toAdd) {
      await req.db.execute(
        `INSERT INTO workspace_members (workspace_id, user_id, role, role_id)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE role = VALUES(role), role_id = VALUES(role_id)`,
        [addWsId, targetUserId, resolvedRoleName, resolvedRoleId]
      );
    }

    // Workspaces to remove
    const toRemove = currentWsIds.filter((id) => !targetSet.has(id));
    for (const remWsId of toRemove) {
      // Safety Floor: cannot remove if sole owner of that workspace
      const currentMember = currentWsRows.find((r) => r.workspace_id === remWsId);
      const isOwner = isOwnerRole(currentMember);
      if (isOwner) {
        const otherOwners = await req.db.query(
          `SELECT wm.user_id FROM workspace_members wm
           JOIN roles r ON wm.role_id = r.id
           WHERE wm.workspace_id = ? AND r.is_system = 1 AND (r.is_editable = 0 OR COALESCE(r.rank, 30) >= 100) AND wm.user_id != ?`,
          [remWsId, targetUserId]
        );
        if (otherOwners.length === 0) {
          continue; // Skip removing sole owner
        }
      }

      await req.db.execute(
        'DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
        [remWsId, targetUserId]
      );

      // Clean up board memberships in this removed workspace
      await req.db.execute(
        `DELETE bm FROM board_members bm
         JOIN boards b ON bm.board_id = b.id
         WHERE b.workspace_id = ? AND bm.user_id = ?`,
        [remWsId, targetUserId]
      );
    }

    return res.json({ success: true, message: 'Workspace assignments updated successfully' });
  } catch (err) {
    next(err);
  }
});

// POST /api/workspaces/:id/company-members/:userId/boards - Assign/unassign boards for member
router.post('/:id/company-members/:userId/boards', requireAuth, requirePermission(['member.invite', 'project.edit']), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const targetUserId = Number(req.params.userId);
  const board_ids = req.body.board_ids || req.body.boardIds || [];

  try {
    const targetSet = new Set(board_ids.map(Number));

    // Get board parent workspaces to auto-enrol user if needed
    if (board_ids.length > 0) {
      const boardParents = await req.db.query(
        'SELECT id, workspace_id FROM boards WHERE id IN (?)',
        [Array.from(targetSet)]
      );

      const [defaultRole] = await req.db.query(
        "SELECT id, name FROM roles WHERE is_system = 1 AND name = 'Team Member' LIMIT 1"
      );

      for (const b of boardParents) {
        await req.db.execute(
          `INSERT IGNORE INTO workspace_members (workspace_id, user_id, role, role_id)
           VALUES (?, ?, ?, ?)`,
          [b.workspace_id, targetUserId, defaultRole?.name || 'Team Member', defaultRole?.id || null]
        );

        await req.db.execute(
          `INSERT INTO board_members (board_id, user_id, role, role_id)
           VALUES (?, ?, 'member', ?)
           ON DUPLICATE KEY UPDATE role = 'member', role_id = COALESCE(VALUES(role_id), role_id)`,
          [b.id, targetUserId, defaultRole?.id || null]
        );
      }
    }

    // Remove from unselected boards (using req.db.query because mysql2 execute does not expand IN (?) arrays)
    if (board_ids.length > 0) {
      await req.db.query(
        'DELETE FROM board_members WHERE user_id = ? AND board_id NOT IN (?)',
        [targetUserId, Array.from(targetSet)]
      );
    } else {
      await req.db.query(
        'DELETE FROM board_members WHERE user_id = ?',
        [targetUserId]
      );
    }

    try {
      sendUserEvent(targetUserId, 'user:workspaces_updated', {
        workspaceId,
        userId: targetUserId
      }, req.tenant?.id || req.tenantId);
      broadcastWorkspaceEvent(workspaceId, 'workspace:member_updated', {
        workspaceId,
        userId: targetUserId
      }, req.headers?.['x-origin-id'] || null, req.tenant?.id || req.tenantId);
    } catch (sockErr) {
      console.warn('[WARN] Failed to broadcast board member update socket event:', sockErr.message);
    }

    return res.json({ success: true, message: 'Board assignments updated successfully' });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/workspaces/:id/company-members/:userId - Remove member from company
router.delete('/:id/company-members/:userId', requireAuth, requirePermission('member.remove'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const targetUserId = Number(req.params.userId);

  try {
    if (targetUserId === req.user.id) {
      return res.status(400).json({ error: { message: 'You cannot remove yourself from the organization', code: 'CANNOT_REMOVE_SELF' } });
    }

    const [targetUser] = await req.db.query('SELECT id, email, name FROM users WHERE id = ?', [targetUserId]);
    if (!targetUser) {
      return res.status(404).json({ error: { message: 'Member not found', code: 'NOT_FOUND' } });
    }

    const targetUserEmail = targetUser.email ? targetUser.email.trim().toLowerCase() : null;

    // Safety Floor: Cannot remove an Owner
    const targetRoles = await req.db.query(
      `SELECT r.is_system, r.is_editable, COALESCE(r.rank, 30) as rank, r.name
       FROM workspace_members wm
       JOIN roles r ON wm.role_id = r.id
       WHERE wm.user_id = ?`,
      [targetUserId]
    );
    const targetIsOwner = targetRoles.some((r) => isOwnerRole(r));

    if (targetIsOwner) {
      const callerRoles = await req.db.query(
        `SELECT r.is_system, r.is_editable, COALESCE(r.rank, 30) as rank, r.name
         FROM workspace_members wm
         JOIN roles r ON wm.role_id = r.id
         WHERE wm.user_id = ?`,
        [req.user.id]
      );
      const callerIsOwner = callerRoles.some((r) => isOwnerRole(r));
      if (!callerIsOwner) {
        return res.status(403).json({
          error: { message: 'Only an Owner may remove an Owner from the organization', code: 'ONLY_OWNER_MAY_MODIFY_OWNER' }
        });
      }
      return res.status(400).json({
        error: { message: 'Organization owners cannot be removed from company directory', code: 'CANNOT_REMOVE_OWNER' }
      });
    }

    // Revoke all sessions, invalidate session cache, and disconnect user sockets immediately
    await revokeAllSessions(req.db, targetUserId, 'MEMBER_REMOVED', req);

    // Remove from all board and workspace memberships
    await req.db.execute('DELETE FROM board_members WHERE user_id = ?', [targetUserId]);
    await req.db.execute('DELETE FROM workspace_members WHERE user_id = ?', [targetUserId]);

    // Delete any pending invitations for this user's email
    if (targetUserEmail) {
      await req.db.execute('DELETE FROM pending_invitations WHERE LOWER(email) = ?', [targetUserEmail]);
    }

    // Clean up master DB tenant_user_directory if multi-tenant
    if (targetUserEmail) {
      try {
        const { getMasterDb } = require('../services/tenantPools');
        const masterDb = getMasterDb();
        if (req.tenant?.id) {
          await masterDb.execute('DELETE FROM tenant_user_directory WHERE LOWER(email) = ? AND tenant_id = ?', [targetUserEmail, req.tenant.id]);
        }
      } catch (e) {
        console.warn(`[COMPANY_MEMBER_REMOVE] Master directory cleanup failed: ${e.message}`);
      }
    }

    // Delete user record from database (cascades all user relationships)
    await req.db.execute('DELETE FROM users WHERE id = ?', [targetUserId]);

    // Notify & log activity
    try {
      await logActivity({
        workspaceId,
        userId: req.user.id,
        actionType: 'member_removed',
        metaJson: {
          removed_user_id: targetUserId,
          removed_user_name: targetUser.name,
          removed_user_email: targetUser.email,
          scope: 'company'
        },
        dbInstance: req.db,
        tenantId: req.tenant?.id
      });
    } catch (e) {}

    broadcastWorkspaceEvent(workspaceId, 'workspace:member_removed', { workspaceId, targetUserId }, req.headers['x-origin-id'], req.tenant?.id);

    return res.json({ success: true, message: 'Member removed from company successfully', user_id: targetUserId });
  } catch (err) {
    next(err);
  }
});

// Helper function to check if user has company admin/owner status
async function isCompanyAdminOrOwner(userId, db) {
  const rows = await db.query(
    `SELECT r.id
     FROM workspace_members wm
     JOIN roles r ON wm.role_id = r.id
     WHERE wm.user_id = ? AND r.is_system = 1 AND (r.is_editable = 0 OR COALESCE(r.rank, 30) >= 80)
     LIMIT 1`,
    [userId]
  );
  return rows.length > 0;
}

// GET /api/workspaces/:id/audit - View audit logs
router.get('/:id/audit', requireAuth, requirePermission('audit.view'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  try {
    const logs = await req.db.query(
      `SELECT id, user_id, email, event_type, ip_address, user_agent, metadata, created_at
       FROM auth_audit_log
       ORDER BY created_at DESC
       LIMIT ?`,
      [limit]
    );
    return res.json({ logs });
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/audit/export - Export audit logs as CSV
router.get('/:id/audit/export', requireAuth, requirePermission('audit.export'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  try {
    const logs = await req.db.query(
      `SELECT id, user_id, email, event_type, ip_address, user_agent, created_at
       FROM auth_audit_log
       ORDER BY created_at DESC
       LIMIT 5000`
    );
    const header = 'id,user_id,email,event_type,ip_address,user_agent,created_at\n';
    const rows = logs.map(l => `${l.id},${l.user_id || ''},"${l.email || ''}","${l.event_type || ''}","${l.ip_address || ''}","${(l.user_agent || '').replace(/"/g, '""')}","${l.created_at}"`).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="audit-export-ws-${workspaceId}.csv"`);
    return res.send(header + rows);
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/search - Global workspace search
router.get('/:id/search', requireAuth, requirePermission('search.use'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const q = String(req.query.q || '').trim();
  try {
    if (!q) {
      return res.json({ cards: [], boards: [] });
    }

    // Section 5.4: Filter search results by accessibleBoardIds
    const allowedBoardIds = await accessibleBoardIds(req.user.id, workspaceId, 'project.view', req.db);
    if (allowedBoardIds.length === 0) {
      return res.json({ cards: [], boards: [] });
    }

    const cards = await req.db.query(
      `SELECT c.id, c.title, l.board_id, b.name as board_name
       FROM cards c
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       WHERE b.workspace_id = ? AND b.id IN (?) AND (c.title LIKE ? OR c.description LIKE ?)
       LIMIT 50`,
      [workspaceId, allowedBoardIds, `%${q}%`, `%${q}%`]
    );
    const boards = await req.db.query(
      `SELECT id, name FROM boards WHERE workspace_id = ? AND id IN (?) AND name LIKE ? LIMIT 20`,
      [workspaceId, allowedBoardIds, `%${q}%`]
    );
    return res.json({ cards, boards });
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/issues - Server-side paginated & filtered issue list
router.get('/:id/issues', requireAuth, requirePermission('task.view'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);

  try {
    const isMember = await req.db.query(
      'SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
      [workspaceId, req.user.id]
    );
    if (isMember.length === 0) {
      return res.status(403).json({ error: { message: 'Access denied to workspace', code: 'FORBIDDEN' } });
    }

    const hasViewPerm = await userHasPermission(req.user.id, workspaceId, 'task.view', req.db);
    if (!hasViewPerm) {
      return res.status(403).json({ error: { message: 'Permission denied: task.view required', code: 'FORBIDDEN' } });
    }

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit, 10) || 20)); // Exactly 20 per page default
    const offset = (page - 1) * limit;

    const boardId = req.query.board_id && req.query.board_id !== 'all' ? Number(req.query.board_id) : null;
    const search = (req.query.search || '').trim().toLowerCase();
    const listId = req.query.list_id && req.query.list_id !== 'all' ? Number(req.query.list_id) : null;
    const stage = req.query.stage && req.query.stage !== 'all' ? String(req.query.stage).trim().toLowerCase() : null;
    const assigneeId = req.query.assignee_id && req.query.assignee_id !== 'all' ? req.query.assignee_id : null;
    const assignerId = req.query.assigner_id && req.query.assigner_id !== 'all' ? Number(req.query.assigner_id) : null;
    const dueDate = req.query.due_date && req.query.due_date !== 'all' ? String(req.query.due_date).trim().toLowerCase() : null;
    const sort = req.query.sort ? String(req.query.sort).trim().toLowerCase() : 'newest';
    const onlyBugs = req.query.only_bugs !== 'false';

    // Section 5.4: Filter issues by accessibleBoardIds
    const allowedBoardIds = await accessibleBoardIds(req.user.id, workspaceId, 'task.view', req.db);
    if (allowedBoardIds.length === 0) {
      return res.json({ issues: [], total: 0, page, limit, totalPages: 0 });
    }

    // Base conditions: active cards, active lists, active boards in workspace
    const whereConditions = [
      'b.workspace_id = ?',
      'b.is_archived = 0',
      'l.is_archived = 0',
      'c.is_archived = 0',
      'b.id IN (?)'
    ];
    const queryParams = [workspaceId, allowedBoardIds];

    // Filter to only cards that have a label matching 'bug' (case-insensitive)
    if (onlyBugs) {
      whereConditions.push(`EXISTS (
        SELECT 1 
        FROM card_labels cl_bug 
        JOIN labels lbl_bug ON cl_bug.label_id = lbl_bug.id 
        WHERE cl_bug.card_id = c.id 
          AND LOWER(TRIM(lbl_bug.name)) LIKE '%bug%'
      )`);
    }

    if (boardId) {
      whereConditions.push('b.id = ?');
      queryParams.push(boardId);
    }

    const isAdmin = await isCompanyAdminOrOwner(req.user.id, req.db);
    if (!isAdmin) {
      whereConditions.push(
        '(EXISTS (SELECT 1 FROM board_members bm WHERE bm.board_id = b.id AND bm.user_id = ?) OR r.name = "Viewer")'
      );
      queryParams.push(req.user.id);
    }

    if (search) {
      whereConditions.push('(LOWER(c.title) LIKE ? OR LOWER(COALESCE(c.description, "")) LIKE ? OR CAST(c.id AS CHAR) = ?)');
      const wild = `%${search}%`;
      queryParams.push(wild, wild, search);
    }

    if (listId) {
      whereConditions.push('c.list_id = ?');
      queryParams.push(listId);
    }

    if (stage) {
      if (stage === 'done') {
        whereConditions.push('(c.is_complete = 1 OR LOWER(l.name) LIKE "%done%" OR LOWER(l.name) LIKE "%completed%")');
      } else if (stage === 'review') {
        whereConditions.push('(c.is_complete = 0 AND (LOWER(l.name) LIKE "%review%" OR LOWER(l.name) LIKE "%qa%" OR LOWER(l.name) LIKE "%test%"))');
      } else if (stage === 'in_progress') {
        whereConditions.push('(c.is_complete = 0 AND (LOWER(l.name) LIKE "%progress%" OR LOWER(l.name) LIKE "%doing%" OR LOWER(l.name) LIKE "%active%"))');
      } else if (stage === 'todo') {
        whereConditions.push('(c.is_complete = 0 AND (LOWER(l.name) LIKE "%to do%" OR LOWER(l.name) LIKE "%todo%" OR LOWER(l.name) LIKE "%backlog%"))');
      }
    }

    if (assigneeId) {
      if (assigneeId === 'unassigned') {
        whereConditions.push('NOT EXISTS (SELECT 1 FROM card_members cm WHERE cm.card_id = c.id)');
      } else {
        whereConditions.push('EXISTS (SELECT 1 FROM card_members cm WHERE cm.card_id = c.id AND cm.user_id = ?)');
        queryParams.push(Number(assigneeId));
      }
    }

    if (assignerId) {
      whereConditions.push('EXISTS (SELECT 1 FROM card_assigners ca WHERE ca.card_id = c.id AND ca.user_id = ?)');
      queryParams.push(assignerId);
    }

    if (dueDate) {
      if (dueDate === 'overdue') {
        whereConditions.push('(c.is_complete = 0 AND c.due_date IS NOT NULL AND c.due_date < NOW())');
      } else if (dueDate === 'today') {
        whereConditions.push('(c.due_date IS NOT NULL AND DATE(c.due_date) = CURDATE())');
      } else if (dueDate === 'this_week') {
        whereConditions.push('(c.due_date IS NOT NULL AND YEARWEEK(c.due_date, 1) = YEARWEEK(CURDATE(), 1))');
      } else if (dueDate === 'next_week') {
        whereConditions.push('(c.due_date IS NOT NULL AND YEARWEEK(c.due_date, 1) = YEARWEEK(DATE_ADD(CURDATE(), INTERVAL 1 WEEK), 1))');
      } else if (dueDate === 'no_date') {
        whereConditions.push('(c.due_date IS NULL)');
      }
    }

    const whereSql = whereConditions.join(' AND ');

    // 1. Total count query over FULL dataset (never restricted to 20 rows!)
    const countSql = `
      SELECT COUNT(DISTINCT c.id) as total
      FROM cards c
      JOIN lists l ON c.list_id = l.id
      JOIN boards b ON l.board_id = b.id
      JOIN workspace_members wm ON b.workspace_id = wm.workspace_id AND wm.user_id = ?
      LEFT JOIN roles r ON wm.role_id = r.id
      WHERE ${whereSql}
    `;
    const countRes = await req.db.query(countSql, [req.user.id, ...queryParams]);
    const total = Number(countRes[0]?.total || 0);
    const totalPages = Math.ceil(total / limit) || 1;

    // Sorting
    let orderSql = 'c.created_at DESC, c.id DESC';
    if (sort === 'oldest') {
      orderSql = 'c.created_at ASC, c.id ASC';
    } else if (sort === 'due_date_asc') {
      orderSql = 'CASE WHEN c.due_date IS NULL THEN 1 ELSE 0 END, c.due_date ASC, c.id ASC';
    } else if (sort === 'due_date_desc') {
      orderSql = 'CASE WHEN c.due_date IS NULL THEN 1 ELSE 0 END, c.due_date DESC, c.id DESC';
    } else if (sort === 'title_asc') {
      orderSql = 'c.title ASC, c.id ASC';
    } else if (sort === 'title_desc') {
      orderSql = 'c.title DESC, c.id DESC';
    }

    // 2. Paginated data query
    const selectSql = `
      SELECT
        c.id,
        c.list_id,
        c.title,
        c.description,
        c.position,
        c.due_date,
        c.start_date,
        c.is_complete,
        c.is_archived,
        c.created_at,
        l.name as list_name,
        l.board_id,
        b.name as board_name
      FROM cards c
      JOIN lists l ON c.list_id = l.id
      JOIN boards b ON l.board_id = b.id
      JOIN workspace_members wm ON b.workspace_id = wm.workspace_id AND wm.user_id = ?
      LEFT JOIN roles r ON wm.role_id = r.id
      WHERE ${whereSql}
      ORDER BY ${orderSql}
      LIMIT ? OFFSET ?
    `;

    const cardsRes = await req.db.query(selectSql, [req.user.id, ...queryParams, limit, offset]);

    const cardIds = cardsRes.map((c) => c.id);
    const cardAssignersMap = {};
    const cardMembersMap = {};
    const cardLabelsMap = {};

    if (cardIds.length > 0) {
      // Fetch Assigners
      const caRes = await req.db.query(
        `SELECT ca.card_id, u.id, u.name, u.email, u.avatar_url 
         FROM card_assigners ca
         JOIN users u ON ca.user_id = u.id
         WHERE ca.card_id IN (?)
         ORDER BY u.name ASC`,
        [cardIds]
      );
      caRes.forEach((row) => {
        if (!cardAssignersMap[row.card_id]) cardAssignersMap[row.card_id] = [];
        cardAssignersMap[row.card_id].push({ id: row.id, name: row.name, email: row.email, avatar_url: row.avatar_url });
      });

      // Fetch Members / Assignees
      const cmRes = await req.db.query(
        `SELECT cm.card_id, u.id, u.name, u.email, u.avatar_url 
         FROM card_members cm
         JOIN users u ON cm.user_id = u.id
         WHERE cm.card_id IN (?)
         ORDER BY u.name ASC`,
        [cardIds]
      );
      cmRes.forEach((row) => {
        if (!cardMembersMap[row.card_id]) cardMembersMap[row.card_id] = [];
        cardMembersMap[row.card_id].push({ id: row.id, name: row.name, email: row.email, avatar_url: row.avatar_url });
      });

      // Fetch Labels
      const clRes = await req.db.query(
        `SELECT cl.card_id, l.id, l.name, l.color 
         FROM card_labels cl
         JOIN labels l ON cl.label_id = l.id
         WHERE cl.card_id IN (?)`,
        [cardIds]
      );
      clRes.forEach((row) => {
        if (!cardLabelsMap[row.card_id]) cardLabelsMap[row.card_id] = [];
        cardLabelsMap[row.card_id].push({ id: row.id, name: row.name, color: row.color });
      });
    }

    const issues = cardsRes.map((c) => ({
      ...c,
      listName: c.list_name,
      boardName: c.board_name,
      assigners: cardAssignersMap[c.id] || [],
      members: cardMembersMap[c.id] || [],
      assigned_users: cardMembersMap[c.id] || [],
      labels: cardLabelsMap[c.id] || []
    }));

    // Fetch filter options for the frontend (boards, lists, members in this workspace)
    const boards = await req.db.query(
      'SELECT id, name FROM boards WHERE workspace_id = ? AND is_archived = 0 ORDER BY name ASC',
      [workspaceId]
    );

    const lists = await req.db.query(
      `SELECT DISTINCT l.id, l.name, l.board_id
       FROM lists l
       JOIN boards b ON l.board_id = b.id
       WHERE b.workspace_id = ? AND b.is_archived = 0 AND l.is_archived = 0
       ORDER BY l.position ASC, l.name ASC`,
      [workspaceId]
    );

    const members = await req.db.query(
      `SELECT DISTINCT u.id, u.name, u.email, u.avatar_url
       FROM users u
       JOIN workspace_members wm ON u.id = wm.user_id
       WHERE wm.workspace_id = ?
       ORDER BY u.name ASC`,
      [workspaceId]
    );

    return res.json({
      issues,
      pagination: {
        page,
        limit,
        total,
        totalPages
      },
      filterOptions: {
        boards,
        lists,
        members
      }
    });
  } catch (err) {
    next(err);
  }
});

// Helper: compute UTC [startUtc, endUtc) bounds for a date string in a specific IANA timezone
function getUtcRangeForDate(dateStr, timeZone = 'Asia/Kolkata') {
  const [y, m, d] = dateStr.split('-').map(Number);
  const approxUtc = new Date(Date.UTC(y, m - 1, d, 0, 0, 0));
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric', month: 'numeric', day: 'numeric',
    hour: 'numeric', minute: 'numeric', second: 'numeric',
    hour12: false
  });
  const formatParts = (dt) => {
    const parts = formatter.formatToParts(dt);
    const map = {};
    parts.forEach(p => map[p.type] = p.value);
    return {
      year: Number(map.year),
      month: Number(map.month),
      day: Number(map.day),
      hour: Number(map.hour) === 24 ? 0 : Number(map.hour),
      minute: Number(map.minute),
      second: Number(map.second)
    };
  };
  let guess = approxUtc.getTime();
  for (let i = 0; i < 3; i++) {
    const cur = formatParts(new Date(guess));
    const curDateAsUtc = Date.UTC(cur.year, cur.month - 1, cur.day, cur.hour, cur.minute, cur.second);
    const targetDateAsUtc = Date.UTC(y, m - 1, d, 0, 0, 0);
    const diff = targetDateAsUtc - curDateAsUtc;
    guess += diff;
    if (diff === 0) break;
  }
  const startUtc = new Date(guess);
  const endUtc = new Date(guess + 24 * 60 * 60 * 1000);
  return { startUtc, endUtc };
}

// Helper: compute working days between two dates, excluding non-working days and holidays (Bug A & 5 fix)
function getWorkingDaysBetween(startDate, endDate, workingDays = [1, 2, 3, 4, 5], holidays = []) {
  if (!startDate || !endDate) return 1;
  const start = new Date(startDate);
  const end = new Date(endDate);
  if (isNaN(start.getTime()) || isNaN(end.getTime())) return 1;
  if (start > end) return 1;

  const cur = new Date(start);
  cur.setUTCHours(0, 0, 0, 0);
  const target = new Date(end);
  target.setUTCHours(23, 59, 59, 999);

  let count = 0;
  const holidaysSet = new Set(Array.isArray(holidays) ? holidays : []);

  while (cur <= target) {
    const jsDay = cur.getUTCDay(); // 0=Sun..6=Sat
    const isoDay = jsDay === 0 ? 7 : jsDay; // 1=Mon..7=Sun
    const dateStr = cur.toISOString().slice(0, 10);
    if (workingDays.includes(isoDay) && !holidaysSet.has(dateStr)) {
      count++;
    }
    cur.setUTCDate(cur.getUTCDate() + 1);
  }
  return Math.max(1, count);
}

// GET /api/workspaces/:id/daily-tracker - Server-side paginated & filtered daily task tracking (v2)
router.get('/:id/daily-tracker', requireAuth, requirePermission('daily_tracker.view'), async (req, res, next) => {
  const routeWsId = Number(req.params.id);

  try {
    const isMember = await req.db.query(
      'SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
      [routeWsId, req.user.id]
    );
    if (isMember.length === 0) {
      return res.status(403).json({ error: { message: 'Access denied to workspace', code: 'FORBIDDEN' } });
    }

    const hasPerm = await userHasPermission(req.user.id, routeWsId, 'daily_tracker.view', req.db);
    if (!hasPerm) {
      return res.status(403).json({ error: { message: 'Permission denied: daily_tracker.view required', code: 'FORBIDDEN' } });
    }

    // 1. Date parameter: default to today (YYYY-MM-DD)
    const targetDate = req.query.date && /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.date).trim())
      ? String(req.query.date).trim()
      : new Date().toISOString().slice(0, 10);

    // 2. Mode & Pagination: 20 cards per page default
    const mode = req.query.mode ? String(req.query.mode).trim().toLowerCase() : 'created'; // 'created' | 'active' | 'in_progress'
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.max(1, Math.min(100, parseInt(req.query.limit, 10) || 20));
    const offset = (page - 1) * limit;

    // 3. Filters
    const reqWsId = req.query.workspace_id;
    const filterWsId = reqWsId && reqWsId !== 'all' ? Number(reqWsId) : (reqWsId === 'all' ? null : routeWsId);
    const labelId = req.query.label_id && req.query.label_id !== 'all' ? Number(req.query.label_id) : null;
    const boardId = req.query.board_id && req.query.board_id !== 'all' ? Number(req.query.board_id) : null;
    const search = (req.query.search || '').trim().toLowerCase();
    const sort = req.query.sort ? String(req.query.sort).trim().toLowerCase() : 'newest';

    // Workspaces user can access where user holds daily_tracker.view (Bug A fix)
    const userWorkspaces = await req.db.query(
      `SELECT w.id, w.name, w.settings
       FROM workspaces w
       JOIN workspace_members wm ON w.id = wm.workspace_id
       WHERE wm.user_id = ? AND w.is_archived = 0
       ORDER BY w.name ASC`,
      [req.user.id]
    );

    const allowedWorkspaces = [];
    for (const ws of userWorkspaces) {
      const canView = await userHasPermission(req.user.id, ws.id, 'daily_tracker.view', req.db);
      if (canView) {
        allowedWorkspaces.push(ws);
      }
    }
    const allowedWsIds = allowedWorkspaces.map((w) => w.id);

    if (allowedWsIds.length === 0) {
      return res.status(403).json({
        error: { message: 'Permission denied: daily_tracker.view required', code: 'FORBIDDEN' }
      });
    }

    let activeWsIds = [];
    if (filterWsId) {
      if (!allowedWsIds.includes(filterWsId)) {
        return res.status(403).json({
          error: { message: `Permission denied: daily_tracker.view required for workspace ${filterWsId}`, code: 'FORBIDDEN' }
        });
      }
      activeWsIds = [filterWsId];
    } else {
      // workspace_id=all: strictly workspaces where user holds daily_tracker.view
      activeWsIds = allowedWsIds;
    }

    // Compute accessible boards across all active workspaces (Bug A fix)
    let allAllowedBoardIds = [];
    for (const wsId of activeWsIds) {
      const bIds = await accessibleBoardIds(req.user.id, wsId, 'project.view', req.db);
      allAllowedBoardIds = allAllowedBoardIds.concat(bIds);
    }
    allAllowedBoardIds = Array.from(new Set(allAllowedBoardIds));

    // A PM or user on no boards sees zero cards, zero boards and zero labels (Bug A fix)
    if (allAllowedBoardIds.length === 0) {
      return res.json({
        cards: [],
        pagination: { page, limit, total: 0, totalPages: 0 },
        summary: { total: 0, completed: 0, in_progress: 0, completion_rate: 0, date: targetDate, mode },
        filterOptions: { workspaces: allowedWorkspaces, labels: [], boards: [] }
      });
    }

    // Read workspace settings for timezone (Bug G fix)
    const currentWs = userWorkspaces.find((w) => w.id === routeWsId) || userWorkspaces[0];
    let wsSettings = {};
    try {
      wsSettings = typeof currentWs?.settings === 'string' ? JSON.parse(currentWs.settings) : (currentWs?.settings || {});
    } catch {}
    const timezone = wsSettings?.timezone || 'Asia/Kolkata';
    const { startUtc, endUtc } = getUtcRangeForDate(targetDate, timezone);

    const whereConditions = [
      'b.workspace_id IN (?)',
      'b.id IN (?)',
      'b.is_archived = 0',
      'l.is_archived = 0',
      'c.is_archived = 0'
    ];
    const queryParams = [activeWsIds, allAllowedBoardIds];

    if (boardId) {
      if (!allAllowedBoardIds.includes(boardId)) {
        return res.json({
          cards: [],
          pagination: { page, limit, total: 0, totalPages: 0 },
          summary: { total: 0, completed: 0, in_progress: 0, completion_rate: 0, date: targetDate, mode },
          filterOptions: { workspaces: allowedWorkspaces, labels: [], boards: [] }
        });
      }
      whereConditions.push('b.id = ?');
      queryParams.push(boardId);
    }

    if (labelId) {
      whereConditions.push('EXISTS (SELECT 1 FROM card_labels cl WHERE cl.card_id = c.id AND cl.label_id = ?)');
      queryParams.push(labelId);
    }

    if (search) {
      whereConditions.push('(LOWER(c.title) LIKE ? OR LOWER(COALESCE(c.description, "")) LIKE ? OR CAST(c.id AS CHAR) = ?)');
      const wild = `%${search}%`;
      queryParams.push(wild, wild, search);
    }

    if (mode === 'active') {
      whereConditions.push(`(
        (c.created_at >= ? AND c.created_at < ?)
        OR EXISTS (
          SELECT 1 FROM activity_log a
          WHERE a.card_id = c.id
            AND a.created_at >= ? AND a.created_at < ?
            AND a.action_type IN ('checklist_toggled', 'moved_card', 'attachment_uploaded', 'attachment_added', 'marked_complete')
            AND (
              a.action_type != 'checklist_toggled'
              OR JSON_UNQUOTE(JSON_EXTRACT(a.meta_json, '$.is_checked')) IN ('true', '1')
              OR a.meta_json LIKE '%"is_checked":true%'
              OR a.meta_json LIKE '%"is_checked":1%'
            )
        )
        OR EXISTS (
          SELECT 1 FROM comments cm
          WHERE cm.card_id = c.id
            AND cm.created_at >= ? AND cm.created_at < ?
            AND LENGTH(TRIM(cm.body)) >= 20
        )
        OR EXISTS (
          SELECT 1 FROM attachments att
          WHERE att.card_id = c.id
            AND att.created_at >= ? AND att.created_at < ?
        )
        OR EXISTS (
          SELECT 1 FROM check_ins ci
          WHERE ci.card_id = c.id
            AND ci.work_date = ?
        )
      )`);
      queryParams.push(startUtc, endUtc, startUtc, endUtc, startUtc, endUtc, startUtc, endUtc, targetDate);
    } else if (mode === 'in_progress') {
      // Bug D fix: use lists.is_done_list = 0
      whereConditions.push('(c.is_complete = 0 AND l.is_done_list = 0)');
    } else {
      // Bug G fix: range predicates instead of DATE(c.created_at) = ?
      whereConditions.push('(c.created_at >= ? AND c.created_at < ?)');
      queryParams.push(startUtc, endUtc);
    }

    const whereSql = whereConditions.join(' AND ');

    // Bug D fix: use l.is_done_list = 1 for completed
    const summarySql = `
      SELECT
        COUNT(DISTINCT c.id) as total,
        SUM(CASE WHEN c.is_complete = 1 OR l.is_done_list = 1 THEN 1 ELSE 0 END) as completed,
        SUM(CASE WHEN c.is_complete = 0 AND l.is_done_list = 0 THEN 1 ELSE 0 END) as in_progress
      FROM cards c
      JOIN lists l ON c.list_id = l.id
      JOIN boards b ON l.board_id = b.id
      JOIN workspaces w ON b.workspace_id = w.id
      WHERE ${whereSql}
    `;
    const summaryRes = await req.db.query(summarySql, queryParams);
    const total = Number(summaryRes[0]?.total || 0);
    const completed = Number(summaryRes[0]?.completed || 0);
    const in_progress = Number(summaryRes[0]?.in_progress || 0);
    const completion_rate = total > 0 ? Math.round((completed / total) * 100) : 0;
    const totalPages = Math.ceil(total / limit) || 1;

    let orderSql = 'c.created_at DESC, c.id DESC';
    if (sort === 'oldest') {
      orderSql = 'c.created_at ASC, c.id ASC';
    } else if (sort === 'title_asc') {
      orderSql = 'c.title ASC, c.id ASC';
    } else if (sort === 'title_desc') {
      orderSql = 'c.title DESC, c.id DESC';
    }

    const selectSql = `
      SELECT
        c.id,
        c.list_id,
        c.title,
        c.description,
        c.position,
        c.due_date,
        c.start_date,
        c.first_moved_or_assigned_at,
        c.completed_at,
        c.completed_by,
        c.completion_note,
        c.completion_evidence_url,
        c.completion_attachment_id,
        c.is_complete,
        c.is_archived,
        c.created_at,
        c.created_by,
        u_creator.name as created_by_name,
        l.name as list_name,
        l.position as list_position,
        l.is_done_list,
        l.board_id,
        b.name as board_name,
        b.workspace_id,
        w.name as workspace_name
      FROM cards c
      JOIN lists l ON c.list_id = l.id
      JOIN boards b ON l.board_id = b.id
      JOIN workspaces w ON b.workspace_id = w.id
      LEFT JOIN users u_creator ON c.created_by = u_creator.id
      WHERE ${whereSql}
      ORDER BY ${orderSql}
      LIMIT ? OFFSET ?
    `;
    const cardsRes = await req.db.query(selectSql, [...queryParams, limit, offset]);
    const cardIds = cardsRes.map((c) => c.id);

    const cardMembersMap = {};
    const cardAssignersMap = {};
    const cardLabelsMap = {};
    const cardActivitiesMap = {};
    const cardCommentsMap = {};
    const cardAttachmentsMap = {};
    const cardChecklistsMap = {};
    const cardFocusMap = {};
    const cardCheckinsMap = {};

    if (cardIds.length > 0) {
      // 1. Members
      const cmRes = await req.db.query(
        `SELECT cm.card_id, u.id, u.name, u.email, u.avatar_url
         FROM card_members cm
         JOIN users u ON cm.user_id = u.id
         WHERE cm.card_id IN (?)
         ORDER BY u.name ASC`,
        [cardIds]
      );
      cmRes.forEach((row) => {
        if (!cardMembersMap[row.card_id]) cardMembersMap[row.card_id] = [];
        cardMembersMap[row.card_id].push({ id: row.id, name: row.name, email: row.email, avatar_url: row.avatar_url });
      });

      // 2. Assigners
      const caRes = await req.db.query(
        `SELECT ca.card_id, u.id, u.name, u.email, u.avatar_url
         FROM card_assigners ca
         JOIN users u ON ca.user_id = u.id
         WHERE ca.card_id IN (?)
         ORDER BY u.name ASC`,
        [cardIds]
      );
      caRes.forEach((row) => {
        if (!cardAssignersMap[row.card_id]) cardAssignersMap[row.card_id] = [];
        cardAssignersMap[row.card_id].push({ id: row.id, name: row.name, email: row.email, avatar_url: row.avatar_url });
      });

      // 3. Labels
      const clRes = await req.db.query(
        `SELECT cl.card_id, l.id, l.name, l.color
         FROM card_labels cl
         JOIN labels l ON cl.label_id = l.id
         WHERE cl.card_id IN (?)`,
        [cardIds]
      );
      clRes.forEach((row) => {
        if (!cardLabelsMap[row.card_id]) cardLabelsMap[row.card_id] = [];
        cardLabelsMap[row.card_id].push({ id: row.id, name: row.name, color: row.color });
      });

      // 4. Performance Range Query (Bug K): fetch target range activity AND latest event
      const actRes = await req.db.query(
        `SELECT a.id, a.card_id, a.user_id, a.action_type, a.meta_json, a.created_at, u.name as user_name
         FROM activity_log a
         LEFT JOIN users u ON a.user_id = u.id
         WHERE a.card_id IN (?)
           AND (
             (a.created_at >= ? AND a.created_at < ?)
             OR a.id IN (SELECT MAX(id) FROM activity_log WHERE card_id IN (?) GROUP BY card_id)
           )
         ORDER BY a.created_at DESC`,
        [cardIds, startUtc, endUtc, cardIds]
      );
      actRes.forEach((row) => {
        if (!cardActivitiesMap[row.card_id]) cardActivitiesMap[row.card_id] = [];
        cardActivitiesMap[row.card_id].push(row);
      });

      // 5. Comments (Bug K & I): target range + latest
      const commRes = await req.db.query(
        `SELECT co.id, co.card_id, co.user_id, co.body, co.created_at, u.name as user_name
         FROM comments co
         LEFT JOIN users u ON co.user_id = u.id
         WHERE co.card_id IN (?)
           AND (
             (co.created_at >= ? AND co.created_at < ?)
             OR co.id IN (SELECT MAX(id) FROM comments WHERE card_id IN (?) GROUP BY card_id)
           )
         ORDER BY co.created_at DESC`,
        [cardIds, startUtc, endUtc, cardIds]
      );
      commRes.forEach((row) => {
        if (!cardCommentsMap[row.card_id]) cardCommentsMap[row.card_id] = [];
        cardCommentsMap[row.card_id].push(row);
      });

      // 6. Attachments (Bug C): recognize added & uploaded
      const attRes = await req.db.query(
        `SELECT att.id, att.card_id, att.file_name, att.file_size_bytes, att.created_at, u.name as user_name
         FROM attachments att
         LEFT JOIN users u ON att.uploaded_by_user_id = u.id
         WHERE att.card_id IN (?)
         ORDER BY att.created_at DESC`,
        [cardIds]
      );
      attRes.forEach((row) => {
        if (!cardAttachmentsMap[row.card_id]) cardAttachmentsMap[row.card_id] = [];
        cardAttachmentsMap[row.card_id].push(row);
      });

      // 7. Checklists & items with created_by and created_at (Bug B & J)
      const chkRes = await req.db.query(
        `SELECT ci.id, ci.checklist_id, ci.text, ci.is_checked, ci.created_at, ci.created_by, ch.card_id
         FROM checklist_items ci
         JOIN checklists ch ON ci.checklist_id = ch.id
         WHERE ch.card_id IN (?)
         ORDER BY ci.position ASC, ci.id ASC`,
        [cardIds]
      );
      chkRes.forEach((row) => {
        if (!cardChecklistsMap[row.card_id]) cardChecklistsMap[row.card_id] = [];
        cardChecklistsMap[row.card_id].push(row);
      });

      // 8. Card Focus
      const focRes = await req.db.query(
        `SELECT cf.*, u.name as user_name
         FROM card_focus cf
         JOIN users u ON cf.user_id = u.id
         WHERE cf.card_id IN (?) AND cf.ended_at IS NULL`,
        [cardIds]
      );
      focRes.forEach((row) => {
        if (!cardFocusMap[row.card_id]) cardFocusMap[row.card_id] = [];
        cardFocusMap[row.card_id].push(row);
      });

      // 9. Check-ins for targetDate
      const ciRes = await req.db.query(
        `SELECT ci.*, u.name as user_name
         FROM check_ins ci
         JOIN users u ON ci.user_id = u.id
         WHERE ci.card_id IN (?) AND ci.work_date = ?
         ORDER BY ci.id DESC`,
        [cardIds, targetDate]
      );
      ciRes.forEach((row) => {
        if (!cardCheckinsMap[row.card_id]) cardCheckinsMap[row.card_id] = [];
        cardCheckinsMap[row.card_id].push(row);
      });
    }

    const now = new Date();

    const cards = cardsRes.map((c) => {
      const activities = cardActivitiesMap[c.id] || [];
      const comments = cardCommentsMap[c.id] || [];
      const attachments = cardAttachmentsMap[c.id] || [];
      const checklistItems = cardChecklistsMap[c.id] || [];
      const focusList = cardFocusMap[c.id] || [];
      const checkinsToday = cardCheckinsMap[c.id] || [];

      const flags = [];

      // Latest activity calculation
      let latestActivityAt = new Date(c.created_at);
      let latestActivityEvent = 'created';
      let latestActor = c.created_by_name || null;
      let latestMeta = null;

      if (activities.length > 0) {
        const topAct = activities[0];
        const actDate = new Date(topAct.created_at);
        if (actDate > latestActivityAt) {
          latestActivityAt = actDate;
          latestActivityEvent = topAct.action_type;
          latestActor = topAct.user_name;
          latestMeta = topAct.meta_json;
        }
      }

      if (comments.length > 0) {
        const topComm = comments[0];
        const commDate = new Date(topComm.created_at);
        if (commDate > latestActivityAt) {
          latestActivityAt = commDate;
          latestActivityEvent = 'added_comment';
          latestActor = topComm.user_name;
          latestMeta = { body: topComm.body };
        }
      }

      // Bug G: Filter activities in range [startUtc, endUtc)
      const targetDateActivities = activities.filter((a) => {
        const d = new Date(a.created_at);
        return d >= startUtc && d < endUtc;
      });

      const targetDateComments = comments.filter((cm) => {
        const d = new Date(cm.created_at);
        return d >= startUtc && d < endUtc;
      });

      const targetDateAttachments = attachments.filter((att) => {
        const d = new Date(att.created_at);
        return d >= startUtc && d < endUtc;
      });

      // Working days calculation using workspace working_days and holidays settings (Bug 5 fix)
      const currentWs = allowedWorkspaces.find((w) => w.id === routeWsId) || allowedWorkspaces[0];
      let wsSettingsObj = {};
      try {
        wsSettingsObj = typeof currentWs?.settings === 'string' ? JSON.parse(currentWs.settings) : (currentWs?.settings || {});
      } catch {}
      const wsWorkingDays = wsSettingsObj?.working_days || [1, 2, 3, 4, 5];
      const wsHolidays = wsSettingsObj?.holidays || [];

      const startDate = c.first_moved_or_assigned_at ? new Date(c.first_moved_or_assigned_at) : new Date(c.created_at);
      const daysInProgress = getWorkingDaysBetween(startDate, targetDate, wsWorkingDays, wsHolidays);

      // Inactivity & idle warning in working days
      const workingDaysSinceActivity = getWorkingDaysBetween(latestActivityAt, targetDate, wsWorkingDays, wsHolidays);
      if (workingDaysSinceActivity >= 3) {
        if (!flags.includes('inactivity')) flags.push('inactivity');
      } else if (workingDaysSinceActivity >= 2) {
        if (!flags.includes('idle_warning')) flags.push('idle_warning');
      }
      if (daysInProgress >= 14) {
        if (!flags.includes('long_running')) flags.push('long_running');
      }

      // --- ANTI-CHEAT ENGINE ---

      // 1. Checklist anti-cheat (Bug B & 5):
      // Min text 5 chars; untick earns 0; rapid tick within 2m flagged; per-person credit once per item lifetime
      const checklistToggles = targetDateActivities.filter((a) => a.action_type === 'checklist_toggled');
      const itemFinalState = new Map();
      let lastChecklistActor = null;
      let creditedChecklistCount = 0;

      // Bulk ticking check: 8 or more ticks in 60 seconds
      const userTickTimes = checklistToggles
        .filter(a => a.user_id)
        .map(a => new Date(a.created_at).getTime())
        .sort((a, b) => a - b);
      let isBulkTicking = false;
      for (let i = 0; i <= userTickTimes.length - 8; i++) {
        if (userTickTimes[i + 7] - userTickTimes[i] <= 60 * 1000) {
          isBulkTicking = true;
          break;
        }
      }
      if (isBulkTicking) {
        if (!flags.includes('bulk_ticking')) flags.push('bulk_ticking');
      }

      for (const a of checklistToggles) {
        let meta = a.meta_json;
        if (typeof meta === 'string') {
          try { meta = JSON.parse(meta); } catch {}
        }
        const itemId = meta?.item_id ? Number(meta.item_id) : null;
        const itemText = meta?.item_text ? String(meta.item_text).trim() : '';
        const isChecked = meta?.is_checked === true || meta?.is_checked === 1 || String(meta?.is_checked) === 'true';

        // Min 5 chars rule
        if (itemText.length > 0 && itemText.length < 5) {
          continue;
        }

        const chkItem = checklistItems.find((ci) => ci.id === itemId);

        // created_and_ticked: own item ticked within 2 minutes of creation
        if (chkItem && chkItem.created_by && a.user_id && Number(chkItem.created_by) === Number(a.user_id)) {
          const createTime = new Date(chkItem.created_at).getTime();
          const toggleTime = new Date(a.created_at).getTime();
          if (Math.abs(toggleTime - createTime) <= 2 * 60 * 1000) {
            if (!flags.includes('created_and_ticked')) flags.push('created_and_ticked');
            if (!flags.includes('rapid_checklist_tick')) flags.push('rapid_checklist_tick');
            continue; // Not credited
          }
        }

        // Lifetime credit once per item per lifetime
        if (chkItem && chkItem.lifetime_tick_count > 1) {
          continue; // Lifetime credit already used, 0 credit
        }

        const key = itemId ? `id_${itemId}` : `text_${itemText.toLowerCase()}`;
        if (!itemFinalState.has(key)) {
          itemFinalState.set(key, isChecked);
          if (isChecked && !isBulkTicking) {
            creditedChecklistCount++;
            if (!lastChecklistActor && a.user_name) {
              lastChecklistActor = a.user_name;
            }
          }
        }
      }

      // 2. Meaningful Comments (Bug I & 5):
      // >= 20 chars AND >= 4 real words, no repeat within 7 days, max 3 credited per day, flag edited
      let creditedCommentsCount = 0;
      let latestCreditedComment = null;
      const seenCommentHashes = new Set();

      for (const cm of targetDateComments) {
        const bodyText = String(cm.body || '').trim();
        const words = bodyText.split(/\s+/).filter((w) => w.length > 0);

        if (bodyText.length < 20 || words.length < 4) {
          continue;
        }

        const norm = bodyText.toLowerCase().replace(/[^\w]/g, '');
        if (seenCommentHashes.has(norm)) {
          if (!flags.includes('repeat_comment')) flags.push('repeat_comment');
          continue;
        }
        seenCommentHashes.add(norm);

        // Flag edited comment (keep original_length)
        const isEdited = cm.original_length !== null || activities.some((a) => a.action_type === 'edited_comment' && (
          (a.meta_json && typeof a.meta_json === 'object' && Number(a.meta_json.comment_id) === Number(cm.id)) ||
          (typeof a.meta_json === 'string' && a.meta_json.includes(String(cm.id)))
        ));
        if (isEdited) {
          if (!flags.includes('edited_comment')) flags.push('edited_comment');
        }

        if (creditedCommentsCount < 3) {
          creditedCommentsCount++;
          if (!latestCreditedComment) latestCreditedComment = cm;
        }
      }

      // 3. Column Moves (Bug E & 5):
      // Forward move credited once per stage per card using list position; backward moves never credited and flagged
      const movedActs = targetDateActivities.filter((a) => a.action_type === 'moved_card');
      const movedAct = movedActs[0];
      let moveText = null;
      let hasForwardMove = false;

      if (movedAct) {
        let meta = movedAct.meta_json;
        if (typeof meta === 'string') {
          try { meta = JSON.parse(meta); } catch {}
        }
        const toCol = meta?.to || c.list_name || 'column';
        const actor = movedAct.user_name ? ` by ${movedAct.user_name}` : '';
        const fromPos = meta?.from_position ?? null;
        const toPos = meta?.to_position ?? (c.list_position || 0);

        if (fromPos !== null && toPos < fromPos) {
          // Backward moves are never credited and are flagged
          if (!flags.includes('backward_move')) flags.push('backward_move');
          moveText = `⚠️ Backward move to ${toCol}${actor}`;
          hasForwardMove = false;
        } else if (movedActs.length >= 3) {
          if (!flags.includes('ping_pong')) flags.push('ping_pong');
          moveText = `⚠️ Column ping-pong (${movedActs.length} moves in ${toCol})`;
        } else if (c.is_done_list === 1 || c.is_complete === 1) {
          moveText = `🚀 Completed (${toCol})${actor}`;
          hasForwardMove = true;
        } else {
          moveText = `Moved to ${toCol}${actor}`;
          hasForwardMove = true;
        }
      }

      // 4. Instant complete and completed with open checklist flags (Bug 5)
      if (c.is_complete === 1 || c.is_done_list === 1) {
        const compTime = c.completed_at ? new Date(c.completed_at).getTime() : latestActivityAt.getTime();
        const createTime = new Date(c.created_at).getTime();
        if (compTime - createTime <= 10 * 60 * 1000) {
          if (!flags.includes('instant_complete')) flags.push('instant_complete');
        }
        const hasOpenItems = checklistItems.some(ci => !ci.is_checked);
        if (hasOpenItems) {
          if (!flags.includes('completed_with_open_checklist')) flags.push('completed_with_open_checklist');
        }
      }

      // 5. Attachments: link counts 0.5, file counts 1.0 (Bug 8)
      let attScore = 0;
      targetDateAttachments.forEach((att) => {
        attScore += att.file_type === 'link' ? 0.5 : 1.0;
      });
      const hasAttachment = attScore > 0 || targetDateActivities.some(
        (a) => a.action_type === 'attachment_uploaded' || a.action_type === 'attachment_added'
      );
      const attActor = targetDateAttachments[0]?.user_name || null;

      // 5. Card Intake & Empty/Copy Flags (Bug J):
      const isCreatedToday = new Date(c.created_at) >= startUtc && new Date(c.created_at) < endUtc;
      if (isCreatedToday) {
        if (c.title.toLowerCase().startsWith('copy of') || c.title.toLowerCase().includes('(copy)')) {
          if (!flags.includes('copy_card')) flags.push('copy_card');
        }
        const hasDesc = c.description && String(c.description).replace(/<[^>]+>/g, '').trim().length > 0;
        if (!hasDesc && checklistItems.length === 0) {
          if (!flags.includes('empty_card')) flags.push('empty_card');
        }
      }

      // 6. Focus & Check-in Today (New Feature)
      const activeDeepFocus = focusList.find((f) => f.deep_work === 1);
      const todayCheckin = checkinsToday[0] || null;

      // Activity Pill & Genuine Work Evaluation
      let activityPill = null;
      let hasGenuineWork = false;

      if (todayCheckin) {
        const flagSuffix = todayCheckin.flags ? ` [${todayCheckin.flags}]` : '';
        activityPill = `🎯 Check-in (${todayCheckin.progress_pct}% - ${todayCheckin.status}) by ${todayCheckin.user_name}${flagSuffix}`;
        hasGenuineWork = true;
      } else if (creditedChecklistCount > 0 && creditedCommentsCount > 0) {
        const actor = lastChecklistActor ? ` by ${lastChecklistActor}` : '';
        const snippet = latestCreditedComment ? ` • 💬 "${latestCreditedComment.body.trim().slice(0, 30)}..."` : '';
        activityPill = `✓ ${creditedChecklistCount} checklist item(s) done${actor}${snippet}`;
        hasGenuineWork = true;
      } else if (creditedChecklistCount > 0) {
        const actor = lastChecklistActor ? ` by ${lastChecklistActor}` : '';
        activityPill = `✓ ${creditedChecklistCount} checklist item(s) completed${actor}`;
        hasGenuineWork = true;
      } else if (creditedCommentsCount > 0) {
        const author = latestCreditedComment?.user_name ? ` by ${latestCreditedComment.user_name}` : '';
        const snippet = latestCreditedComment.body.trim().slice(0, 45);
        activityPill = `💬 "${snippet}${latestCreditedComment.body.length > 45 ? '...' : ''}"${author}`;
        hasGenuineWork = true;
      } else if (moveText && hasForwardMove) {
        activityPill = moveText;
        hasGenuineWork = true;
      } else if (hasAttachment) {
        activityPill = `📎 File attached${attActor ? ` by ${attActor}` : ''}`;
        hasGenuineWork = true;
      } else if (isCreatedToday) {
        // Bug J fix: Card creation is NEVER genuine work; show as Intake by <user>
        const creatorName = c.created_by_name || 'Someone';
        activityPill = `Intake by ${creatorName}`;
        hasGenuineWork = false;
      } else {
        activityPill = 'Active today';
        hasGenuineWork = false;
      }

      return {
        ...c,
        boardId: c.board_id,
        workspaceId: c.workspace_id,
        listName: c.list_name,
        boardName: c.board_name,
        workspaceName: c.workspace_name,
        members: cardMembersMap[c.id] || [],
        assigned_users: cardMembersMap[c.id] || [],
        assigners: cardAssignersMap[c.id] || [],
        labels: cardLabelsMap[c.id] || [],
        days_in_progress: daysInProgress,
        last_activity_at: latestActivityAt.toISOString(),
        activity_pill: activityPill,
        has_genuine_work: hasGenuineWork,
        flags: Array.from(new Set(flags)),
        verified_checklist_count: creditedChecklistCount,
        comments_count: creditedCommentsCount,
        has_focus: focusList.length > 0,
        is_deep_work: Boolean(activeDeepFocus),
        checkin_today: todayCheckin
      };
    });

    // Filter options restricted to allowed boards only (Bug A fix)
    const labels = await req.db.query(
      `SELECT DISTINCT l.id, l.name, l.color
       FROM labels l
       WHERE l.board_id IN (?)
       ORDER BY l.name ASC`,
      [allAllowedBoardIds]
    );

    const boards = await req.db.query(
      `SELECT id, name, workspace_id
       FROM boards
       WHERE id IN (?) AND is_archived = 0
       ORDER BY name ASC`,
      [allAllowedBoardIds]
    );

    return res.json({
      cards,
      pagination: {
        page,
        limit,
        total,
        totalPages
      },
      summary: {
        total,
        completed,
        in_progress,
        completion_rate,
        date: targetDate,
        mode
      },
      filterOptions: {
        workspaces: allowedWorkspaces,
        labels,
        boards
      }
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/daily-tracker/people - People view with Focus + Check-in states
router.get('/:id/daily-tracker/people', requireAuth, async (req, res, next) => {
  const routeWsId = Number(req.params.id);

  try {
    const isMember = await req.db.query(
      'SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
      [routeWsId, req.user.id]
    );
    if (isMember.length === 0) {
      return res.status(403).json({ error: { message: 'Access denied to workspace', code: 'FORBIDDEN' } });
    }

    const hasViewPeople = await userHasPermission(req.user.id, routeWsId, 'daily_tracker.view_people', req.db);

    const targetDate = req.query.date && /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.date).trim())
      ? String(req.query.date).trim()
      : new Date().toISOString().slice(0, 10);

    const [wsRow] = await req.db.query('SELECT settings FROM workspaces WHERE id = ?', [routeWsId]);
    let wsSettings = {};
    try {
      wsSettings = typeof wsRow?.settings === 'string' ? JSON.parse(wsRow.settings) : (wsRow?.settings || {});
    } catch {}
    const timezone = wsSettings?.timezone || 'Asia/Kolkata';
    const workingDays = wsSettings?.working_days || [1, 2, 3, 4, 5]; // 1=Mon, 7=Sun
    const { startUtc, endUtc } = getUtcRangeForDate(targetDate, timezone);

    // Compute whether targetDate is a working day
    const [y, m, d] = targetDate.split('-').map(Number);
    const targetDtObj = new Date(Date.UTC(y, m - 1, d, 12, 0, 0));
    const jsDay = targetDtObj.getUTCDay();
    const isoDay = jsDay === 0 ? 7 : jsDay;
    const isWorkingDay = workingDays.includes(isoDay);

    // Check cutoff time (default 18:00 workspace timezone)
    const now = new Date();
    const timeFmt = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      hour: 'numeric', minute: 'numeric', hour12: false
    });
    const parts = timeFmt.formatToParts(now);
    const curHour = parseInt(parts.find(p => p.type === 'hour')?.value || '0', 10);
    const curMin = parseInt(parts.find(p => p.type === 'minute')?.value || '0', 10);
    const isPastCutoff = curHour > 18 || (curHour === 18 && curMin >= 0);

    // Query members
    let members = [];
    if (hasViewPeople) {
      members = await req.db.query(
        `SELECT u.id, u.name, u.email, u.avatar_url, r.name as role_name
         FROM workspace_members wm
         JOIN users u ON wm.user_id = u.id
         JOIN roles r ON wm.role_id = r.id
         WHERE wm.workspace_id = ?
         ORDER BY u.name ASC`,
        [routeWsId]
      );
    } else {
      // Regular members see only themselves
      members = await req.db.query(
        `SELECT u.id, u.name, u.email, u.avatar_url, r.name as role_name
         FROM workspace_members wm
         JOIN users u ON wm.user_id = u.id
         JOIN roles r ON wm.role_id = r.id
         WHERE wm.workspace_id = ? AND u.id = ?`,
        [routeWsId, req.user.id]
      );
    }

    if (members.length === 0) {
      return res.json({ date: targetDate, timezone, people: [] });
    }

    const memberIds = members.map((m) => m.id);

    // 1. Leave days (only approved leave suppresses flags; Bug 6 fix)
    const leaveRows = await req.db.query(
      "SELECT user_id, reason FROM leave_days WHERE date = ? AND user_id IN (?) AND status = 'approved'",
      [targetDate, memberIds]
    );
    const leaveMap = {};
    leaveRows.forEach((r) => { leaveMap[r.user_id] = r; });

    // Pending requests & last 30 days leave (Bug 6 fix)
    const pendingLeaveRows = await req.db.query(
      `SELECT ld.id, ld.user_id, ld.date, ld.reason, ld.status, ld.created_at, u.name as user_name
       FROM leave_days ld
       JOIN users u ON ld.user_id = u.id
       WHERE ld.user_id IN (?) AND ld.status = 'pending'
       ORDER BY ld.date ASC`,
      [memberIds]
    );

    const leave30Rows = await req.db.query(
      `SELECT user_id, COUNT(*) as cnt
       FROM leave_days
       WHERE user_id IN (?) AND status = 'approved' AND date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
       GROUP BY user_id`,
      [memberIds]
    );
    const leave30Map = {};
    leave30Rows.forEach((r) => { leave30Map[r.user_id] = Number(r.cnt); });

    // 2. Active Focus cards
    const focusRows = await req.db.query(
      `SELECT cf.*, c.title as card_title, l.board_id
       FROM card_focus cf
       JOIN cards c ON cf.card_id = c.id
       JOIN lists l ON c.list_id = l.id
       WHERE cf.user_id IN (?) AND cf.ended_at IS NULL`,
      [memberIds]
    );
    const focusMap = {};
    focusRows.forEach((f) => {
      if (!focusMap[f.user_id]) focusMap[f.user_id] = [];
      focusMap[f.user_id].push(f);
    });

    // 3. Check-ins for targetDate
    const checkinRows = await req.db.query(
      `SELECT ci.*, c.title as card_title
       FROM check_ins ci
       JOIN cards c ON ci.card_id = c.id
       WHERE ci.user_id IN (?) AND ci.work_date = ?`,
      [memberIds, targetDate]
    );
    const checkinMap = {};
    const checkinIds = checkinRows.map((ci) => ci.id);
    checkinRows.forEach((ci) => {
      if (!checkinMap[ci.user_id]) checkinMap[ci.user_id] = [];
      checkinMap[ci.user_id].push(ci);
    });

    // Reviews for these check-ins
    const reviewMap = {};
    if (checkinIds.length > 0) {
      const revRows = await req.db.query(
        `SELECT r.*, u.name as reviewer_name
         FROM check_in_reviews r
         JOIN users u ON r.reviewer_id = u.id
         WHERE r.check_in_id IN (?)
         ORDER BY r.created_at ASC`,
        [checkinIds]
      );
      revRows.forEach((r) => {
        if (!reviewMap[r.check_in_id]) reviewMap[r.check_in_id] = [];
        reviewMap[r.check_in_id].push(r);
      });
    }

    // 4. Activity events on targetDate
    const actRows = await req.db.query(
      `SELECT a.user_id, a.card_id, a.action_type, a.meta_json, a.created_at
       FROM activity_log a
       WHERE a.user_id IN (?) AND a.created_at >= ? AND a.created_at < ?`,
      [memberIds, startUtc, endUtc]
    );
    const actMap = {};
    actRows.forEach((a) => {
      if (!actMap[a.user_id]) actMap[a.user_id] = [];
      actMap[a.user_id].push(a);
    });

    // 5. Comments on targetDate
    const commRows = await req.db.query(
      `SELECT co.user_id, co.card_id, co.body, co.created_at
       FROM comments co
       WHERE co.user_id IN (?) AND co.created_at >= ? AND co.created_at < ?`,
      [memberIds, startUtc, endUtc]
    );
    const commMap = {};
    commRows.forEach((c) => {
      if (!commMap[c.user_id]) commMap[c.user_id] = [];
      commMap[c.user_id].push(c);
    });

    const people = members.map((m) => {
      const userLeave = leaveMap[m.id];
      const userFocus = focusMap[m.id] || [];
      const userCheckins = checkinMap[m.id] || [];
      const userActs = actMap[m.id] || [];
      const userComms = commMap[m.id] || [];

      const flags = [];
      const checkedItems = [];
      const commentSnippets = [];
      const files = [];
      const checkinTexts = [];
      const unansweredReviews = [];

      for (const a of userActs) {
        if (a.action_type === 'checklist_toggled') {
          let meta = a.meta_json;
          if (typeof meta === 'string') { try { meta = JSON.parse(meta); } catch {} }
          if (meta?.item_text && (meta.is_checked === true || meta.is_checked === 1 || String(meta.is_checked) === 'true')) {
            checkedItems.push(meta.item_text);
          }
        } else if (a.action_type === 'attachment_uploaded' || a.action_type === 'attachment_added') {
          let meta = a.meta_json;
          if (typeof meta === 'string') { try { meta = JSON.parse(meta); } catch {} }
          files.push({ name: meta?.file_name || 'File', url: meta?.file_url || null });
        }
      }

      for (const cm of userComms) {
        if (cm.body && cm.body.trim().length >= 20) {
          commentSnippets.push(cm.body.trim().slice(0, 60));
        }
      }

      for (const ci of userCheckins) {
        checkinTexts.push({
          id: ci.id,
          card_title: ci.card_title,
          did: ci.did,
          next_step: ci.next_step,
          blocker: ci.blocker,
          status: ci.status,
          progress_pct: ci.progress_pct,
          evidence_url: ci.evidence_url
        });
        const revs = reviewMap[ci.id] || [];
        for (const r of revs) {
          if (!r.answered_at && (r.action === 'question' || r.action === 'request_evidence')) {
            unansweredReviews.push({
              id: r.id,
              action: r.action,
              note: r.note,
              reviewer_name: r.reviewer_name
            });
            flags.push(`unanswered_${r.action}`);
          }
        }
      }

      // Determine State
      let state = 'Idle';
      let stateSeverity = 'normal'; // 'normal' | 'amber' | 'red' | 'green'

      if (userLeave) {
        state = 'On leave';
      } else if (userFocus.length > 0) {
        const hasBlockedCheckin = userCheckins.some((ci) => ci.status === 'blocked' || (ci.blocker && ci.blocker.trim()));
        if (hasBlockedCheckin) {
          state = 'Blocked';
          stateSeverity = 'red';
        } else if (userCheckins.length > 0) {
          state = 'Focused-check-in-done';
          stateSeverity = 'green';
        } else {
          // Check-in missing
          if (!isWorkingDay) {
            state = 'Idle';
          } else {
            state = 'Focused-check-in-missing';
            stateSeverity = isPastCutoff ? 'red' : 'amber';
            flags.push('missing_checkin');
          }
        }

        // Deep work review check
        for (const f of userFocus) {
          if (f.deep_work === 1) {
            const daysSinceStarted = Math.max(1, Math.floor((now.getTime() - new Date(f.started_at).getTime()) / (1000 * 60 * 60 * 24)));
            if (f.estimate_days && daysSinceStarted > f.estimate_days) {
              state = 'Needs review';
              stateSeverity = 'amber';
              flags.push('over_estimate');
            } else if (daysSinceStarted > f.check_in_every_days && userCheckins.length === 0 && checkedItems.length === 0) {
              state = 'Needs review';
              stateSeverity = 'amber';
              flags.push('deep_work_stalled');
            }
          }
        }
      } else {
        const hasCreditedWork = checkedItems.length > 0 || commentSnippets.length > 0 || files.length > 0;
        if (hasCreditedWork) {
          state = 'Active';
          stateSeverity = 'green';
        } else {
          state = 'Idle';
          stateSeverity = 'normal';
        }
      }

      return {
        id: m.id,
        name: m.name,
        email: m.email,
        avatar_url: m.avatar_url,
        role: m.role_name,
        state,
        state_severity: stateSeverity,
        has_focus: userFocus.length > 0,
        focus_cards: userFocus.map((f) => ({
          card_id: f.card_id,
          card_title: f.card_title,
          deep_work: f.deep_work === 1,
          started_at: f.started_at,
          estimate_days: f.estimate_days
        })),
        evidence: {
          checked_items: checkedItems,
          comments: commentSnippets,
          files,
          check_ins: checkinTexts,
          unanswered_reviews: unansweredReviews
        },
        leave_days_last_30_days: leave30Map[m.id] || 0,
        flags: Array.from(new Set(flags))
      };
    });

    // Priority sorting: what needs attention first
    const statePriority = {
      'Blocked': 1,
      'Focused-check-in-missing': 2,
      'Needs review': 3,
      'Idle': 4,
      'Focused-check-in-done': 5,
      'Active': 6,
      'On leave': 7
    };
    people.sort((a, b) => {
      const pA = statePriority[a.state] || 99;
      const pB = statePriority[b.state] || 99;
      if (pA !== pB) return pA - pB;
      return a.name.localeCompare(b.name);
    });

    return res.json({
      date: targetDate,
      timezone,
      is_working_day: isWorkingDay,
      cutoff_passed: isPastCutoff,
      pending_requests: pendingLeaveRows,
      people
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/workspaces/:id/leave-days
router.get('/:id/leave-days', requireAuth, requirePermission('leave.request'), async (req, res, next) => {
  const routeWsId = Number(req.params.id);

  try {
    const canApprove = await userHasPermission(req.user.id, routeWsId, 'leave.approve', req.db);
    let whereClause = 'wm.workspace_id = ?';
    const params = [routeWsId];

    if (!canApprove) {
      whereClause += ' AND ld.user_id = ?';
      params.push(req.user.id);
    }

    const leaveRows = await req.db.query(
      `SELECT ld.*, u.name as user_name, u.email as user_email
       FROM leave_days ld
       JOIN users u ON ld.user_id = u.id
       JOIN workspace_members wm ON u.id = wm.user_id
       WHERE ${whereClause}
       ORDER BY ld.date DESC`,
      params
    );

    const pendingRequests = leaveRows.filter(r => r.status === 'pending');

    return res.json({
      leave_days: leaveRows,
      pending_requests: pendingRequests
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/workspaces/:id/leave-days
router.post('/:id/leave-days', requireAuth, requirePermission('leave.request'), async (req, res, next) => {
  const routeWsId = Number(req.params.id);
  const { date, reason, user_id } = req.body;

  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(String(date).trim())) {
    return res.status(400).json({ error: { message: 'Valid date (YYYY-MM-DD) is required', code: 'BAD_REQUEST' } });
  }

  try {
    const canApprove = await userHasPermission(req.user.id, routeWsId, 'leave.approve', req.db);
    let targetUserId = req.user.id;
    if (user_id && Number(user_id) !== Number(req.user.id)) {
      if (!canApprove) {
        return res.status(403).json({ error: { message: 'Only approvers can request leave on behalf of other members', code: 'FORBIDDEN' } });
      }
      targetUserId = Number(user_id);
    }

    // Auto-approve if requester holds leave.approve; otherwise pending
    const status = canApprove ? 'approved' : 'pending';
    const approvedBy = canApprove ? req.user.id : null;
    const approvedAt = canApprove ? new Date() : null;

    const ins = await req.db.execute(
      `INSERT INTO leave_days (user_id, date, reason, status, requested_by, approved_by, approved_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE reason = VALUES(reason), status = VALUES(status), approved_by = VALUES(approved_by), approved_at = VALUES(approved_at)`,
      [targetUserId, date, reason ? sanitizePlain(reason) : null, status, req.user.id, approvedBy, approvedAt]
    );

    const [row] = await req.db.query('SELECT * FROM leave_days WHERE user_id = ? AND date = ?', [targetUserId, date]);

    // Audit log (Bug 6 requirement: every create, approve, delete is audit-logged)
    await req.db.execute(
      `INSERT INTO auth_audit_log (user_id, email, event_type, ip_address, user_agent, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, NOW())`,
      [
        req.user.id,
        req.user.email,
        'leave_day_requested',
        req.ip || '127.0.0.1',
        req.headers['user-agent'] || 'api',
        JSON.stringify({ date, targetUserId, status, reason: reason ? sanitizePlain(reason) : null })
      ]
    );

    return res.status(201).json({ leave_day: row });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/workspaces/:id/leave-days/:leaveId
router.patch('/:id/leave-days/:leaveId', requireAuth, requirePermission('leave.approve'), async (req, res, next) => {
  const routeWsId = Number(req.params.id);
  const leaveId = Number(req.params.leaveId);
  const { action, reason } = req.body; // action: 'approve' | 'reject'

  if (!['approve', 'reject'].includes(action)) {
    return res.status(400).json({ error: { message: "Action must be 'approve' or 'reject'", code: 'BAD_REQUEST' } });
  }

  try {
    const [leave] = await req.db.query('SELECT * FROM leave_days WHERE id = ?', [leaveId]);
    if (!leave) {
      return res.status(404).json({ error: { message: 'Leave request not found', code: 'NOT_FOUND' } });
    }

    // Team Lead check: only approve for members of own boards
    const hasAccessAll = await userHasPermission(req.user.id, routeWsId, 'project.access_all', req.db);
    if (!hasAccessAll) {
      const [sharedBoard] = await req.db.query(
        `SELECT 1 FROM board_members bm1
         JOIN board_members bm2 ON bm1.board_id = bm2.board_id
         JOIN boards b ON bm1.board_id = b.id
         WHERE b.workspace_id = ? AND bm1.user_id = ? AND bm2.user_id = ? LIMIT 1`,
        [routeWsId, req.user.id, leave.user_id]
      );
      if (!sharedBoard) {
        return res.status(403).json({
          error: { message: 'Team Lead can only approve leave for members of their own boards', code: 'FORBIDDEN' }
        });
      }
    }

    const newStatus = action === 'approve' ? 'approved' : 'rejected';
    const rejReason = action === 'reject' && reason ? sanitizePlain(reason) : null;

    await req.db.execute(
      `UPDATE leave_days SET status = ?, approved_by = ?, approved_at = NOW(), rejection_reason = ? WHERE id = ?`,
      [newStatus, req.user.id, rejReason, leaveId]
    );

    const [updated] = await req.db.query('SELECT * FROM leave_days WHERE id = ?', [leaveId]);

    // Audit log (Bug 6 requirement: every create, approve, delete is audit-logged)
    await req.db.execute(
      `INSERT INTO auth_audit_log (user_id, email, event_type, ip_address, user_agent, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, NOW())`,
      [
        req.user.id,
        req.user.email,
        `leave_day_${newStatus}`,
        req.ip || '127.0.0.1',
        req.headers['user-agent'] || 'api',
        JSON.stringify({ leaveId, date: leave.date, targetUserId: leave.user_id, status: newStatus })
      ]
    );

    return res.json({ leave_day: updated });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/workspaces/:id/leave-days/:leaveId
router.delete('/:id/leave-days/:leaveId', requireAuth, requirePermission('leave.request'), async (req, res, next) => {
  const routeWsId = Number(req.params.id);
  const leaveId = Number(req.params.leaveId);

  try {
    const [leave] = await req.db.query('SELECT * FROM leave_days WHERE id = ?', [leaveId]);
    if (!leave) {
      return res.status(404).json({ error: { message: 'Leave request not found', code: 'NOT_FOUND' } });
    }

    const canApprove = await userHasPermission(req.user.id, routeWsId, 'leave.approve', req.db);
    const isOwnerOfRequest = Number(leave.user_id) === Number(req.user.id) || Number(leave.requested_by) === Number(req.user.id);

    if (!canApprove && !isOwnerOfRequest) {
      return res.status(403).json({ error: { message: 'Only author or approver can delete leave request', code: 'FORBIDDEN' } });
    }

    await req.db.execute('DELETE FROM leave_days WHERE id = ?', [leaveId]);

    // Audit log (Bug 6 requirement: every create, approve, delete is audit-logged)
    await req.db.execute(
      `INSERT INTO auth_audit_log (user_id, email, event_type, ip_address, user_agent, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, NOW())`,
      [
        req.user.id,
        req.user.email,
        'leave_day_deleted',
        req.ip || '127.0.0.1',
        req.headers['user-agent'] || 'api',
        JSON.stringify({ leaveId, date: leave.date, targetUserId: leave.user_id })
      ]
    );

    return res.json({ success: true, message: 'Leave request deleted' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

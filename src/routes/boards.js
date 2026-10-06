const express = require('express');
const { z } = require('zod');
const { parseJson } = require('../db/mysql');
const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { requirePermission, userHasPermission } = require('../middleware/permissions');
const { broadcastBoardEvent, sendUserEvent } = require('../socket');
const path = require('path');
const fs = require('fs');
const { queueFileCleanupRetry } = require('../utils/fileCleanupQueue');
const { logAuthEvent } = require('../services/authAudit');
const { notify } = require('../services/notify');
const { sanitizePlain } = require('../utils/sanitizer');

const router = express.Router();

const createBoardSchema = z.object({
  workspace_id: z.number({ required_error: 'workspace_id is required' }),
  name: z.string().min(1, 'Board name is required').transform((v) => sanitizePlain(v)),
  background_color: z.string().optional()
});

const updateBoardSchema = z.object({
  name: z.string().min(1).transform((v) => sanitizePlain(v)).optional(),
  background_color: z.string().optional(),
  is_archived: z.boolean().optional()
});

// GET /api/boards?workspace_id=
router.get('/', requireAuth, async (req, res, next) => {
  const { workspace_id, archived } = req.query;

  try {
    let archivedCondition = 'b.is_archived = 0';
    if (archived === 'true' || archived === '1') {
      archivedCondition = 'b.is_archived = 1';
    } else if (archived === 'all') {
      archivedCondition = '1=1';
    }

    let query = `
      SELECT DISTINCT b.id, b.workspace_id, b.name, b.background_color, b.is_archived, b.created_at, w.name as workspace_name
      FROM boards b
      JOIN workspaces w ON b.workspace_id = w.id
      JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
      LEFT JOIN roles r ON wm.role_id = r.id
      LEFT JOIN board_members bm ON b.id = bm.board_id AND bm.user_id = ?
      WHERE ${archivedCondition} 
        AND w.is_archived = 0
        AND (
          EXISTS (
            SELECT 1 FROM role_permissions rp
            JOIN permissions p ON rp.permission_id = p.id
            WHERE rp.role_id = wm.role_id AND p.key IN ('project.view', 'project.create', 'board.create')
          )
          OR bm.user_id IS NOT NULL
        )
    `;
    const params = [req.user.id, req.user.id];

    if (workspace_id) {
      const wsMember = await req.db.query(
        'SELECT 1 FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
        [Number(workspace_id), req.user.id]
      );
      if (wsMember.length === 0) {
        return res.status(403).json({
          error: { message: 'You must be a member of this workspace to access its boards', code: 'FORBIDDEN' }
        });
      }
      query += ` AND b.workspace_id = ?`;
      params.push(Number(workspace_id));
    }

    query += ` ORDER BY b.id ASC`;

    const boardsRes = await req.db.query(query, params);
    return res.json({ boards: boardsRes });
  } catch (err) {
    next(err);
  }
});

// POST /api/boards
router.post('/', requireAuth, requirePermission('board.create'), validate(createBoardSchema), async (req, res, next) => {
  const { workspace_id, name, background_color = 'bg-gradient-to-br from-indigo-900 via-slate-900 to-purple-950' } = req.body;

  try {
    // Check workspace membership
    const wsMember = await req.db.query(
      `SELECT wm.role
       FROM workspace_members wm
       JOIN workspaces w ON wm.workspace_id = w.id
       WHERE wm.workspace_id = ? AND wm.user_id = ? AND w.is_archived = 0`,
      [workspace_id, req.user.id]
    );
    if (wsMember.length === 0) {
      return res.status(403).json({
        error: { message: 'You must be a member of this workspace to create a board', code: 'FORBIDDEN' }
      });
    }

    const boardExec = await req.db.execute(
      'INSERT INTO boards (workspace_id, name, background_color) VALUES (?, ?, ?)',
      [workspace_id, name, background_color]
    );
    const boardId = boardExec.insertId;
    const [board] = await req.db.query('SELECT * FROM boards WHERE id = ?', [boardId]);

    // Add user as admin board member
    await req.db.execute(
      "INSERT INTO board_members (board_id, user_id, role) VALUES (?, ?, 'admin')",
      [board.id, req.user.id]
    );

    // Create default lists for the new board
    await req.db.execute(
      `INSERT INTO lists (board_id, name, position) VALUES 
       (?, 'To Do', 1000.0),
       (?, 'In Progress', 2000.0),
       (?, 'Done', 3000.0)`,
      [board.id, board.id, board.id]
    );

    // Create default board labels
    await req.db.execute(
      `INSERT INTO labels (board_id, name, color) VALUES 
       (?, 'Feature', '#3b82f6'),
       (?, 'Bug', '#ef4444'),
       (?, 'Design', '#ec4899'),
       (?, 'Backend', '#10b981'),
       (?, 'Urgent', '#f59e0b')`,
      [board.id, board.id, board.id, board.id, board.id]
    );

    return res.status(201).json({ board });
  } catch (err) {
    next(err);
  }
});

// GET /api/boards/:id (Full Nested Fetch)
router.get('/:id', requireAuth, async (req, res, next) => {
  const boardId = Number(req.params.id);

  try {
    // 1. Fetch Board
    const boardRes = await req.db.query(
      `SELECT b.*, w.name as workspace_name 
       FROM boards b
       JOIN workspaces w ON b.workspace_id = w.id
       WHERE b.id = ?`,
      [boardId]
    );
    if (boardRes.length === 0) {
      return res.status(404).json({ error: { message: 'Board not found', code: 'NOT_FOUND' } });
    }
    const board = boardRes[0];

    // Check permission (two-level evaluation: company-level OR project-level)
    const hasViewPerm = await userHasPermission(req.user.id, board.workspace_id, 'project.view', req.db, boardId);
    if (!hasViewPerm) {
      return res.status(403).json({ error: { message: 'Access denied to this board', code: 'FORBIDDEN' } });
    }

    // 2. Fetch Board Members
    const membersRes = await req.db.query(
      `SELECT u.id, u.name, u.email, bm.role
       FROM board_members bm
       JOIN users u ON bm.user_id = u.id
       WHERE bm.board_id = ?
       ORDER BY u.name ASC`,
      [boardId]
    );

    // 3. Fetch Board Labels
    const labelsRes = await req.db.query(
      'SELECT id, name, color FROM labels WHERE board_id = ? ORDER BY id ASC',
      [boardId]
    );

    // 4. Fetch Lists
    const listsRes = await req.db.query(
      `SELECT id, board_id, name, position, is_archived, created_at 
       FROM lists 
       WHERE board_id = ? AND is_archived = 0
       ORDER BY position ASC, id ASC`,
      [boardId]
    );
    const lists = listsRes;
    const listIds = lists.map((l) => l.id);

    let cards = [];
    let cardLabelsMap = {};
    let cardMembersMap = {};
    let cardChecklistsMap = {};
    let cardCommentsMap = {};
    let cardAttachmentsMap = {};

    if (listIds.length > 0) {
      // 5. Fetch Cards
      const cardsRes = await req.db.query(
        `SELECT c.* FROM cards c
         WHERE c.list_id IN (?) AND c.is_archived = 0
         ORDER BY c.position ASC, c.id ASC`,
        [listIds]
      );
      cards = cardsRes;
      const cardIds = cards.map((c) => c.id);

      if (cardIds.length > 0) {
        // Fetch Card Labels
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

        // Fetch Card Members
        const cmRes = await req.db.query(
          `SELECT cm.card_id, u.id, u.name, u.email 
           FROM card_members cm
           JOIN users u ON cm.user_id = u.id
           WHERE cm.card_id IN (?)`,
          [cardIds]
        );
        cmRes.forEach((row) => {
          if (!cardMembersMap[row.card_id]) cardMembersMap[row.card_id] = [];
          cardMembersMap[row.card_id].push({ id: row.id, name: row.name, email: row.email });
        });

        // Fetch Checklists & Items
        const chRes = await req.db.query(
          `SELECT ch.id as checklist_id, ch.card_id, ch.title as checklist_title, ch.position as checklist_pos,
                  ci.id as item_id, ci.text, ci.is_checked, ci.position as item_pos
           FROM checklists ch
           LEFT JOIN checklist_items ci ON ch.id = ci.checklist_id
           WHERE ch.card_id IN (?)
           ORDER BY ch.position ASC, ci.id ASC`,
          [cardIds]
        );

        chRes.forEach((row) => {
          if (!cardChecklistsMap[row.card_id]) cardChecklistsMap[row.card_id] = {};
          if (!cardChecklistsMap[row.card_id][row.checklist_id]) {
            cardChecklistsMap[row.card_id][row.checklist_id] = {
              id: row.checklist_id,
              card_id: row.card_id,
              title: row.checklist_title,
              position: row.checklist_pos,
              items: []
            };
          }
          if (row.item_id) {
            cardChecklistsMap[row.card_id][row.checklist_id].items.push({
              id: row.item_id,
              text: row.text,
              is_checked: row.is_checked,
              position: row.item_pos
            });
          }
        });

        // Fetch Comments
        const comRes = await req.db.query(
          `SELECT com.id, com.card_id, com.user_id, com.body, com.created_at, u.name as author_name
           FROM comments com
           JOIN users u ON com.user_id = u.id
           WHERE com.card_id IN (?)
           ORDER BY com.created_at ASC`,
          [cardIds]
        );
        comRes.forEach((row) => {
          if (!cardCommentsMap[row.card_id]) cardCommentsMap[row.card_id] = [];
          cardCommentsMap[row.card_id].push(row);
        });

        // Fetch Attachments
        const attRes = await req.db.query(
          `SELECT a.*, u.name as uploader_name
           FROM attachments a
           LEFT JOIN users u ON a.uploaded_by_user_id = u.id
           WHERE a.card_id IN (?)
           ORDER BY a.created_at DESC`,
          [cardIds]
        );
        attRes.forEach((row) => {
          if (!cardAttachmentsMap[row.card_id]) cardAttachmentsMap[row.card_id] = [];
          cardAttachmentsMap[row.card_id].push(row);
        });
      }
    }

    // 6. Fetch Activity Log for Board
    const activityRes = await req.db.query(
      `SELECT a.id, a.card_id, a.user_id, a.action_type, a.meta_json, a.created_at, u.name as user_name
       FROM activity_log a
       LEFT JOIN users u ON a.user_id = u.id
       WHERE a.board_id = ?
       ORDER BY a.created_at DESC
       LIMIT 100`,
      [boardId]
    );

    const parsedActivity = activityRes.map((act) => ({
      ...act,
      meta_json: parseJson(act.meta_json)
    }));

    // Assemble nested structure
    const cardsByListId = {};
    cards.forEach((c) => {
      const cardDetail = {
        ...c,
        labels: cardLabelsMap[c.id] || [],
        members: cardMembersMap[c.id] || [],
        checklists: Object.values(cardChecklistsMap[c.id] || {}),
        comments: cardCommentsMap[c.id] || [],
        attachments: cardAttachmentsMap[c.id] || [],
        comments_count: (cardCommentsMap[c.id] || []).length
      };
      if (!cardsByListId[c.list_id]) cardsByListId[c.list_id] = [];
      cardsByListId[c.list_id].push(cardDetail);
    });

    const bmRoleRes = await req.db.query(
      'SELECT role FROM board_members WHERE board_id = ? AND user_id = ?',
      [boardId, req.user.id]
    );
    const userRole = bmRoleRes[0]?.role || 'member';

    const populatedLists = lists.map((l) => ({
      ...l,
      cards: cardsByListId[l.id] || []
    }));

    return res.json({
      board: {
        ...board,
        user_role: userRole,
        members: membersRes,
        labels: labelsRes,
        lists: populatedLists,
        activity: parsedActivity
      }
    });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/boards/:id
router.patch('/:id', requireAuth, requirePermission('board.edit_settings'), validate(updateBoardSchema), async (req, res, next) => {
  const boardId = Number(req.params.id);
  const { name, background_color, is_archived } = req.body;

  try {
    const updates = [];
    const values = [];

    if (name !== undefined) {
      updates.push('name = ?');
      values.push(name);
    }
    if (background_color !== undefined) {
      updates.push('background_color = ?');
      values.push(background_color);
    }
    if (is_archived !== undefined) {
      updates.push('is_archived = ?');
      values.push(is_archived ? 1 : 0);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: { message: 'No fields to update', code: 'BAD_REQUEST' } });
    }

    values.push(boardId);
    const execRes = await req.db.execute(
      `UPDATE boards SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    if (execRes.affectedRows === 0) {
      return res.status(404).json({ error: { message: 'Board not found', code: 'NOT_FOUND' } });
    }

    const [updatedBoard] = await req.db.query('SELECT * FROM boards WHERE id = ?', [boardId]);
    if (is_archived === true && updatedBoard) {
      await notify({
        eventType: 'board.archived',
        actorUserId: req.user.id,
        boardId,
        workspaceId: updatedBoard.workspace_id,
        meta: { boardName: updatedBoard.name }
      });
    }

    return res.json({ board: updatedBoard });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/boards/:id
router.delete('/:id', requireAuth, requirePermission('board.delete'), async (req, res, next) => {
  const boardId = Number(req.params.id);

  // 1. Resolve board and verify existence
  const [board] = await req.db.query('SELECT id, name, workspace_id FROM boards WHERE id = ?', [boardId]);
  if (!board) {
    return res.status(404).json({ error: { message: 'Board not found', code: 'NOT_FOUND' } });
  }

  // 2. Fetch all attachment file paths belonging to this board (excluding external link attachments)
  const attachments = await req.db.query(
    `SELECT a.id, a.file_name, a.file_url, a.file_type FROM attachments a
     JOIN cards c ON a.card_id = c.id
     JOIN lists l ON c.list_id = l.id
     WHERE l.board_id = ? AND a.file_type != 'link'`,
    [boardId]
  );

  // 3. Execute database deletion in a transaction FIRST
  try {
    await req.db.query('START TRANSACTION');

    // Record audit event in tenant database before cascade delete
    await logAuthEvent(req.db, {
      userId: req.user.id,
      email: req.user.email,
      eventType: 'BOARD_DELETED',
      req,
      metadata: { boardId, boardName: board.name, workspaceId: board.workspace_id, filesCount: attachments.length }
    });

    // Execute cascade delete
    await req.db.execute('DELETE FROM boards WHERE id = ?', [boardId]);

    // Commit transaction
    await req.db.query('COMMIT');
  } catch (dbErr) {
    try {
      await req.db.query('ROLLBACK');
    } catch (rbErr) {}
    return next(dbErr);
  }

  // 4. AFTER COMMIT: Remove files from disk (rejecting path traversal)
  const tenantUploadDir = path.resolve(process.env.UPLOADS_DIR || path.join(process.cwd(), 'uploads'));
  for (const att of attachments) {
    if (att.file_url && att.file_type !== 'link') {
      const relativeKey = att.file_url.startsWith('/api/files/')
        ? att.file_url.substring('/api/files/'.length)
        : (att.file_url.startsWith('/uploads/') ? att.file_url.substring('/uploads/'.length) : att.file_url);

      const resolvedPath = path.resolve(tenantUploadDir, relativeKey);
      // Strictly verify path is within tenant upload directory (no directory traversal)
      if (!resolvedPath.startsWith(tenantUploadDir + path.sep) && resolvedPath !== tenantUploadDir) {
        console.error(`[SECURITY] Path traversal rejected during file cleanup for board ${boardId}: '${att.file_url}'`);
        continue;
      }
      try {
        if (fs.existsSync(resolvedPath)) {
          await fs.promises.unlink(resolvedPath);
        }
      } catch (unlinkErr) {
        console.error(`[FILE_CLEANUP] Failed to unlink file ${resolvedPath}:`, unlinkErr.message);
        queueFileCleanupRetry(resolvedPath);
      }
    }
  }

  // 5. Broadcast deletion over socket to other connected users
  broadcastBoardEvent(boardId, 'board:deleted', { boardId }, req.headers['x-origin-id'], req.tenant?.id);

  return res.json({ message: 'Board deleted successfully', boardId });
});

// GET /api/boards/:id/workspace-members (List workspace members and their access status to this board)
router.get('/:id/workspace-members', requireAuth, async (req, res, next) => {
  const boardId = Number(req.params.id);

  try {
    const boardRes = await req.db.query('SELECT id, workspace_id FROM boards WHERE id = ?', [boardId]);
    if (boardRes.length === 0) {
      return res.status(404).json({ error: { message: 'Board not found', code: 'NOT_FOUND' } });
    }
    const workspaceId = boardRes[0].workspace_id;

    const membersRes = await req.db.query(
      `SELECT u.id, u.name, u.email, 
              COALESCE(r.name, wm.role, 'Team Member') as workspace_role,
              bm.role as board_role,
              (EXISTS (SELECT 1 FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = wm.role_id AND p.key IN ('project.view', 'project.create')) OR bm.user_id IS NOT NULL) as has_access,
              (EXISTS (SELECT 1 FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = wm.role_id AND p.key IN ('project.manage_members', 'workspace.edit'))) as is_workspace_admin
       FROM workspace_members wm
       JOIN users u ON wm.user_id = u.id
       LEFT JOIN roles r ON wm.role_id = r.id
       LEFT JOIN board_members bm ON bm.board_id = ? AND bm.user_id = u.id
       WHERE wm.workspace_id = ?
       ORDER BY is_workspace_admin DESC, u.name ASC`,
      [boardId, workspaceId]
    );

    return res.json({ members: membersRes });
  } catch (err) {
    next(err);
  }
});

// POST /api/boards/:id/members (Grant board permission by user_id or email)
router.post('/:id/members', requireAuth, requirePermission('project.manage_members'), async (req, res, next) => {
  const boardId = Number(req.params.id);
  const { email, user_id } = req.body;

  try {
    const boardRes = await req.db.query('SELECT id, workspace_id FROM boards WHERE id = ?', [boardId]);
    if (boardRes.length === 0) {
      return res.status(404).json({ error: { message: 'Board not found', code: 'NOT_FOUND' } });
    }
    const workspaceId = boardRes[0].workspace_id;

    let targetUser;
    if (user_id) {
      const userRes = await req.db.query('SELECT id, name, email FROM users WHERE id = ?', [user_id]);
      if (userRes.length === 0) {
        return res.status(404).json({ error: { message: 'User not found', code: 'NOT_FOUND' } });
      }
      targetUser = userRes[0];
    } else if (email) {
      const userRes = await req.db.query('SELECT id, name, email FROM users WHERE email = ?', [email.trim().toLowerCase()]);
      if (userRes.length === 0) {
        return res.status(404).json({ error: { message: 'User with this email not found', code: 'NOT_FOUND' } });
      }
      targetUser = userRes[0];
    } else {
      return res.status(400).json({ error: { message: 'user_id or email is required', code: 'BAD_REQUEST' } });
    }

    // Ensure target user is member of workspace
    const wsCheck = await req.db.query('SELECT user_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?', [workspaceId, targetUser.id]);
    if (wsCheck.length === 0) {
      const teamMemberRoleRes = await req.db.query(
        "SELECT id FROM roles WHERE is_system = 1 AND name = 'Team Member' AND workspace_id IS NULL"
      );
      const teamMemberRoleId = teamMemberRoleRes[0]?.id;
      await req.db.execute(
        `INSERT IGNORE INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, 'Team Member', ?)`,
        [workspaceId, targetUser.id, teamMemberRoleId]
      );
    }

    await req.db.execute(
      `INSERT IGNORE INTO board_members (board_id, user_id, role) VALUES (?, ?, 'member')`,
      [boardId, targetUser.id]
    );

    sendUserEvent(targetUser.id, 'user:permissions_updated', {
      workspaceId,
      boardId,
      action: 'granted'
    }, req.tenant ? req.tenant.id : null);
    broadcastBoardEvent(boardId, 'board:members_updated', { boardId, userId: targetUser.id, action: 'granted' }, req.tenant ? req.tenant.id : null);

    const bRes = await req.db.query('SELECT name FROM boards WHERE id = ?', [boardId]);
    await notify({
      eventType: 'board.member_added',
      actorUserId: req.user.id,
      targetUserId: targetUser.id,
      boardId,
      workspaceId,
      meta: { boardName: bRes[0]?.name || 'Board' }
    });

    return res.json({ member: { ...targetUser, role: 'member' } });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/boards/:id/members/:userId (Revoke board access)
router.delete('/:id/members/:userId', requireAuth, requirePermission('project.manage_members'), async (req, res, next) => {
  const boardId = Number(req.params.id);
  const targetUserId = Number(req.params.userId);

  try {
    const boardRes = await req.db.query('SELECT name, workspace_id FROM boards WHERE id = ?', [boardId]);
    await req.db.execute('DELETE FROM board_members WHERE board_id = ? AND user_id = ?', [boardId, targetUserId]);

    if (boardRes[0]) {
      sendUserEvent(targetUserId, 'user:permissions_updated', {
        workspaceId: boardRes[0].workspace_id,
        boardId,
        action: 'revoked'
      }, req.tenant ? req.tenant.id : null);
      broadcastBoardEvent(boardId, 'board:members_updated', { boardId, userId: targetUserId, action: 'revoked' }, req.tenant ? req.tenant.id : null);

      await notify({
        eventType: 'board.member_removed',
        actorUserId: req.user.id,
        targetUserId,
        boardId,
        workspaceId: boardRes[0].workspace_id,
        meta: { boardName: boardRes[0].name || 'Board' }
      });
    }

    return res.json({ message: 'Board access revoked successfully' });
  } catch (err) {
    next(err);
  }
});

// GET /api/boards/:id/labels
router.get('/:id/labels', requireAuth, async (req, res, next) => {
  const boardId = Number(req.params.id);
  try {
    const labelsRes = await req.db.query('SELECT * FROM labels WHERE board_id = ? ORDER BY id ASC', [boardId]);
    return res.json({ labels: labelsRes });
  } catch (err) {
    next(err);
  }
});

// POST /api/boards/:id/labels
router.post('/:id/labels', requireAuth, requirePermission('board.edit_settings'), async (req, res, next) => {
  const boardId = Number(req.params.id);
  const { name, color } = req.body;

  if (!name || !color) {
    return res.status(400).json({ error: { message: 'Name and color are required', code: 'BAD_REQUEST' } });
  }

  try {
    const labelExec = await req.db.execute(
      'INSERT INTO labels (board_id, name, color) VALUES (?, ?, ?)',
      [boardId, name, color]
    );
    const [label] = await req.db.query('SELECT * FROM labels WHERE id = ?', [labelExec.insertId]);
    return res.status(201).json({ label });
  } catch (err) {
    next(err);
  }
});

// GET /api/boards/:id/archived - Return archived lists and cards for board
router.get('/:id/archived', requireAuth, async (req, res, next) => {
  const boardId = Number(req.params.id);
  try {
    const [board] = await req.db.query('SELECT * FROM boards WHERE id = ?', [boardId]);
    if (!board) {
      return res.status(404).json({ error: { message: 'Board not found', code: 'NOT_FOUND' } });
    }
    const hasPerm = await userHasPermission(req.user.id, board.workspace_id, 'project.view', req.db, boardId);
    if (!hasPerm) {
      return res.status(403).json({ error: { message: 'Access denied', code: 'FORBIDDEN' } });
    }
    const lists = await req.db.query('SELECT * FROM lists WHERE board_id = ? AND is_archived = 1 ORDER BY position ASC', [boardId]);
    const cards = await req.db.query(
      `SELECT c.*, l.name as list_name FROM cards c
       JOIN lists l ON c.list_id = l.id
       WHERE l.board_id = ? AND c.is_archived = 1 ORDER BY c.created_at DESC`,
      [boardId]
    );
    return res.json({ lists, cards });
  } catch (err) {
    next(err);
  }
});

// POST /api/boards/:id/archive - Archive board
router.post('/:id/archive', requireAuth, requirePermission('board.edit_settings'), async (req, res, next) => {
  const boardId = Number(req.params.id);
  try {
    const [board] = await req.db.query('SELECT * FROM boards WHERE id = ?', [boardId]);
    if (!board) return res.status(404).json({ error: { message: 'Board not found', code: 'NOT_FOUND' } });

    await req.db.execute('UPDATE boards SET is_archived = 1 WHERE id = ?', [boardId]);
    const [updatedBoard] = await req.db.query('SELECT * FROM boards WHERE id = ?', [boardId]);

    await notify({
      eventType: 'board.archived',
      actorUserId: req.user.id,
      boardId,
      workspaceId: board.workspace_id,
      meta: { boardName: board.name }
    });

    return res.json({ message: 'Board archived successfully', board: updatedBoard });
  } catch (err) {
    next(err);
  }
});

// POST /api/boards/:id/restore - Restore archived board
router.post('/:id/restore', requireAuth, requirePermission('board.edit_settings'), async (req, res, next) => {
  const boardId = Number(req.params.id);
  try {
    const [board] = await req.db.query('SELECT * FROM boards WHERE id = ?', [boardId]);
    if (!board) return res.status(404).json({ error: { message: 'Board not found', code: 'NOT_FOUND' } });

    await req.db.execute('UPDATE boards SET is_archived = 0 WHERE id = ?', [boardId]);
    const [updatedBoard] = await req.db.query('SELECT * FROM boards WHERE id = ?', [boardId]);

    return res.json({ message: 'Board restored successfully', board: updatedBoard });
  } catch (err) {
    next(err);
  }
});

// GET /api/boards/:id/attachments - Return attachments for cards on this board
router.get('/:id/attachments', requireAuth, async (req, res, next) => {
  const boardId = Number(req.params.id);
  try {
    const [board] = await req.db.query('SELECT * FROM boards WHERE id = ?', [boardId]);
    if (!board) return res.status(404).json({ error: { message: 'Board not found', code: 'NOT_FOUND' } });
    const hasPerm = await userHasPermission(req.user.id, board.workspace_id, 'project.view', req.db, boardId);
    if (!hasPerm) return res.status(403).json({ error: { message: 'Access denied', code: 'FORBIDDEN' } });

    const attachments = await req.db.query(
      `SELECT a.*, c.title as card_title, u.name as uploader_name FROM attachments a
       JOIN cards c ON a.card_id = c.id
       JOIN lists l ON c.list_id = l.id
       LEFT JOIN users u ON a.uploaded_by_user_id = u.id
       WHERE l.board_id = ? ORDER BY a.created_at DESC`,
      [boardId]
    );
    return res.json({ attachments });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

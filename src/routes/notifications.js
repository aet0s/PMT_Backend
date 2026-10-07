// server/src/routes/notifications.js
// Complete notification REST API with cursor pagination, read-time authorization,
// summary aggregates, mutes, and preferences.

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/permissions');
const { getUserPreferences, updateUserPreferences } = require('../services/notificationPreferences');
const { NOTIFICATION_EVENTS } = require('../services/notificationEvents');

const router = express.Router();

/**
 * Constructs read-time SQL access condition:
 * Ensures user only sees notifications for workspaces and boards they currently have access to.
 * If user was removed from a board or workspace, their old notifications for that board/workspace
 * are automatically excluded from lists and aggregates.
 */
function getReadTimeAccessFilter(userId) {
  const clause = `(
    n.user_id = ?
    AND (
      n.workspace_id IS NULL
      OR EXISTS (
        SELECT 1 FROM workspace_members wm 
        WHERE wm.workspace_id = n.workspace_id AND wm.user_id = ?
      )
    )
    AND (
      n.board_id IS NULL
      OR EXISTS (
        SELECT 1 FROM boards b
        JOIN workspace_members wm ON b.workspace_id = wm.workspace_id AND wm.user_id = ?
        LEFT JOIN roles r ON wm.role_id = r.id
        LEFT JOIN board_members bm ON bm.board_id = b.id AND bm.user_id = ?
        WHERE b.id = n.board_id
          AND (
            r.name IN ('Owner', 'Super Admin', 'Admin')
            OR r.name = 'Viewer'
            OR EXISTS (
              SELECT 1 FROM role_permissions rp
              JOIN permissions p ON rp.permission_id = p.id
              WHERE rp.role_id = wm.role_id AND p.key IN ('workspace.edit_settings', 'workspace.delete', 'project.view')
            )
            OR bm.user_id IS NOT NULL
          )
      )
    )
  )`;
  const params = [userId, userId, userId, userId];
  return { clause, params };
}

// GET /api/notifications (cursor pagination; filters board, workspace, category, unread, mentions)
router.get('/', requireAuth, requirePermission('notification.view_own'), async (req, res, next) => {
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '20', 10)));
  const beforeId = req.query.before_id ? Number(req.query.before_id) : null;
  const boardId = req.query.board_id ? Number(req.query.board_id) : null;
  const workspaceId = req.query.workspace_id ? Number(req.query.workspace_id) : null;
  const category = (req.query.category || '').trim();
  const unreadOnly = req.query.unread === 'true' || req.query.filter === 'unread';
  const mentionsOnly = req.query.mentions === 'true' || req.query.filter === 'mentions';
  const filter = (req.query.filter || 'all').trim().toLowerCase();
  const search = (req.query.search || '').trim();

  try {
    const accessFilter = getReadTimeAccessFilter(req.user.id);
    const whereClauses = [accessFilter.clause];
    const queryParams = [...accessFilter.params];

    if (beforeId) {
      whereClauses.push('n.id < ?');
      queryParams.push(beforeId);
    }

    if (boardId) {
      whereClauses.push('n.board_id = ?');
      queryParams.push(boardId);
    }

    if (workspaceId) {
      whereClauses.push('n.workspace_id = ?');
      queryParams.push(workspaceId);
    }

    if (unreadOnly) {
      whereClauses.push('n.is_read = 0');
    } else if (filter === 'read') {
      whereClauses.push('n.is_read = 1');
    }

    if (mentionsOnly) {
      whereClauses.push("(n.event_type = 'comment.mention' OR n.type = 'mention' OR n.priority = 1)");
    }

    if (category) {
      const matchingEvents = Object.entries(NOTIFICATION_EVENTS)
        .filter(([_, conf]) => conf.category.toLowerCase() === category.toLowerCase())
        .map(([k]) => k);
      if (matchingEvents.length > 0) {
        whereClauses.push('n.event_type IN (?)');
        queryParams.push(matchingEvents);
      }
    }

    if (search) {
      whereClauses.push('(n.message LIKE ? OR u.name LIKE ? OR c.title LIKE ? OR b.name LIKE ?)');
      const sParam = `%${search}%`;
      queryParams.push(sParam, sParam, sParam, sParam);
    }

    const whereSql = whereClauses.join(' AND ');
    const dataQueryParams = [...queryParams, Number(limit) + 1];

    const rows = await req.db.query(
      `SELECT n.id, n.user_id, n.type, n.event_type, n.card_id, n.board_id, n.workspace_id,
              n.actor_user_id, n.message, n.meta, n.priority, n.count, n.is_read, n.created_at,
              u.name as actor_name, c.title as card_title, b.name as board_name, w.name as workspace_name
       FROM notifications n
       LEFT JOIN users u ON n.actor_user_id = u.id
       LEFT JOIN cards c ON n.card_id = c.id
       LEFT JOIN boards b ON n.board_id = b.id
       LEFT JOIN workspaces w ON n.workspace_id = w.id
       WHERE ${whereSql}
       ORDER BY n.id DESC
       LIMIT ?`,
      dataQueryParams
    );

    const hasMore = rows.length > limit;
    const notifications = hasMore ? rows.slice(0, limit) : rows;
    const nextCursor = notifications.length > 0 ? notifications[notifications.length - 1].id : null;

    // Parse meta JSON if present
    for (const notif of notifications) {
      if (notif.meta && typeof notif.meta === 'string') {
        try {
          notif.meta = JSON.parse(notif.meta);
        } catch (e) {}
      }
    }

    // Global unread count for badge
    const [unreadTotalRes] = await req.db.query(
      `SELECT COUNT(*) as count FROM notifications n WHERE ${accessFilter.clause} AND n.is_read = 0`,
      accessFilter.params
    );

    return res.json({
      notifications,
      unread_count: Number(unreadTotalRes?.count || 0),
      has_more: hasMore,
      next_cursor: hasMore ? nextCursor : null
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/notifications/summary ({ unread_total, per_board, per_workspace })
router.get('/summary', requireAuth, requirePermission('notification.view_own'), async (req, res, next) => {
  try {
    const accessFilter = getReadTimeAccessFilter(req.user.id);

    // Total unread
    const [totalRes] = await req.db.query(
      `SELECT COUNT(*) as count FROM notifications n WHERE ${accessFilter.clause} AND n.is_read = 0`,
      accessFilter.params
    );
    const unreadTotal = Number(totalRes?.count || 0);

    // Per-board unread breakdown
    const boardRows = await req.db.query(
      `SELECT n.board_id, COUNT(*) as count
       FROM notifications n
       WHERE ${accessFilter.clause} AND n.is_read = 0 AND n.board_id IS NOT NULL
       GROUP BY n.board_id`,
      accessFilter.params
    );
    const perBoard = {};
    for (const r of boardRows) {
      perBoard[r.board_id] = Number(r.count);
    }

    // Per-workspace unread breakdown
    const wsRows = await req.db.query(
      `SELECT n.workspace_id, COUNT(*) as count
       FROM notifications n
       WHERE ${accessFilter.clause} AND n.is_read = 0 AND n.workspace_id IS NOT NULL
       GROUP BY n.workspace_id`,
      accessFilter.params
    );
    const perWorkspace = {};
    for (const r of wsRows) {
      perWorkspace[r.workspace_id] = Number(r.count);
    }

    return res.json({
      unread_total: unreadTotal,
      per_board: perBoard,
      per_workspace: perWorkspace
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/notifications/unread-count (legacy badge endpoint)
router.get('/unread-count', requireAuth, requirePermission('notification.view_own'), async (req, res, next) => {
  try {
    const accessFilter = getReadTimeAccessFilter(req.user.id);
    const [countRes] = await req.db.query(
      `SELECT COUNT(*) as count FROM notifications n WHERE ${accessFilter.clause} AND n.is_read = 0`,
      accessFilter.params
    );
    return res.json({ unread_count: Number(countRes?.count || 0) });
  } catch (err) {
    next(err);
  }
});

// GET /api/notifications/preferences
router.get('/preferences', requireAuth, requirePermission('notification.view_own'), async (req, res, next) => {
  try {
    const categories = await getUserPreferences(req.user.id, req.db);

    // Fetch user mode (all | only_mine)
    let mode = 'all';
    try {
      const [uSet] = await req.db.query('SELECT mode FROM notification_user_settings WHERE user_id = ?', [req.user.id]);
      if (uSet?.mode) mode = uSet.mode;
    } catch (e) {}

    // Fetch per-workspace all-boards flags
    const workspaceSettings = {};
    try {
      const wsRows = await req.db.query(
        'SELECT workspace_id, notify_all_boards FROM notification_workspace_settings WHERE user_id = ?',
        [req.user.id]
      );
      for (const r of wsRows) {
        workspaceSettings[r.workspace_id] = { notify_all_boards: Boolean(r.notify_all_boards) };
      }
    } catch (e) {}

    return res.json({
      preferences: categories,
      mode,
      workspace_settings: workspaceSettings
    });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/notifications/preferences
router.patch('/preferences', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  const { updates, mode, workspace_id, notify_all_boards } = req.body;
  try {
    if (Array.isArray(updates) && updates.length > 0) {
      await updateUserPreferences(req.user.id, updates, req.db);
    }

    if (mode && ['all', 'only_mine'].includes(mode)) {
      try {
        await req.db.execute(
          `INSERT INTO notification_user_settings (user_id, mode)
           VALUES (?, ?)
           ON DUPLICATE KEY UPDATE mode = VALUES(mode)`,
          [req.user.id, mode]
        );
      } catch (e) {}
    }

    if (workspace_id !== undefined && notify_all_boards !== undefined) {
      try {
        await req.db.execute(
          `INSERT INTO notification_workspace_settings (user_id, workspace_id, notify_all_boards)
           VALUES (?, ?, ?)
           ON DUPLICATE KEY UPDATE notify_all_boards = VALUES(notify_all_boards)`,
          [req.user.id, Number(workspace_id), notify_all_boards ? 1 : 0]
        );
      } catch (e) {}
    }

    const categories = await getUserPreferences(req.user.id, req.db);
    return res.json({ message: 'Notification preferences updated successfully', preferences: categories });
  } catch (err) {
    next(err);
  }
});

// GET /api/notifications/mutes (List active mutes)
router.get('/mutes', requireAuth, requirePermission('notification.view_own'), async (req, res, next) => {
  try {
    const rows = await req.db.query(
      'SELECT board_id, card_id FROM notification_mutes WHERE user_id = ?',
      [req.user.id]
    );
    const boardIds = rows.map((r) => r.board_id).filter(Boolean);
    const cardIds = rows.map((r) => r.card_id).filter(Boolean);

    return res.json({
      muted_boards: boardIds,
      muted_cards: cardIds
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/notifications/mute
router.post('/mute', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  const { board_id, card_id } = req.body;
  if (!board_id && !card_id) {
    return res.status(400).json({ error: { message: 'Must specify board_id or card_id to mute', code: 'BAD_REQUEST' } });
  }

  try {
    await req.db.execute(
      `INSERT IGNORE INTO notification_mutes (user_id, board_id, card_id)
       VALUES (?, ?, ?)`,
      [req.user.id, board_id ? Number(board_id) : null, card_id ? Number(card_id) : null]
    );

    return res.json({ ok: true, message: 'Notifications muted' });
  } catch (err) {
    next(err);
  }
});

// POST /api/notifications/unmute
router.post('/unmute', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  const { board_id, card_id } = req.body;
  if (!board_id && !card_id) {
    return res.status(400).json({ error: { message: 'Must specify board_id or card_id to unmute', code: 'BAD_REQUEST' } });
  }

  try {
    if (board_id) {
      await req.db.execute(
        'DELETE FROM notification_mutes WHERE user_id = ? AND board_id = ?',
        [req.user.id, Number(board_id)]
      );
    }
    if (card_id) {
      await req.db.execute(
        'DELETE FROM notification_mutes WHERE user_id = ? AND card_id = ?',
        [req.user.id, Number(card_id)]
      );
    }

    return res.json({ ok: true, message: 'Notifications unmuted' });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/notifications/:id/read
router.patch('/:id/read', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  const notificationId = Number(req.params.id);

  try {
    await req.db.execute(
      'UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?',
      [notificationId, req.user.id]
    );

    return res.json({ message: 'Notification marked as read' });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/notifications/:id/unread
router.patch('/:id/unread', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  const notificationId = Number(req.params.id);

  try {
    await req.db.execute(
      'UPDATE notifications SET is_read = 0 WHERE id = ? AND user_id = ?',
      [notificationId, req.user.id]
    );

    return res.json({ message: 'Notification marked as unread' });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/notifications/read-all (marks all read, or per-board read)
router.patch('/read-all', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  const boardId = req.body.board_id || req.query.board_id ? Number(req.body.board_id || req.query.board_id) : null;

  try {
    const accessFilter = getReadTimeAccessFilter(req.user.id);
    let sql = `UPDATE notifications n SET n.is_read = 1 WHERE ${accessFilter.clause} AND n.is_read = 0`;
    const params = [...accessFilter.params];

    if (boardId) {
      sql += ' AND n.board_id = ?';
      params.push(boardId);
    }

    await req.db.execute(sql, params);

    return res.json({ message: boardId ? 'Board notifications marked as read' : 'All notifications marked as read' });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/notifications/:id (Delete single notification)
router.delete('/:id', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  const notificationId = Number(req.params.id);

  try {
    await req.db.execute(
      'DELETE FROM notifications WHERE id = ? AND user_id = ?',
      [notificationId, req.user.id]
    );

    return res.json({ message: 'Notification deleted' });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/notifications/clear/read (Clear all read notifications)
router.delete('/clear/read', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  try {
    const accessFilter = getReadTimeAccessFilter(req.user.id);
    const delRes = await req.db.execute(
      `DELETE n FROM notifications n WHERE ${accessFilter.clause} AND n.is_read = 1`,
      accessFilter.params
    );

    return res.json({ message: 'Read notifications cleared', count: delRes.affectedRows });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

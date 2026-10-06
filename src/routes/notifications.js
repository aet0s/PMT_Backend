const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { getUserPreferences, updateUserPreferences } = require('../services/notificationPreferences');

const router = express.Router();

/**
 * Constructs SQL condition and params to ensure user only sees notifications
 * within their authorized workspaces and boards.
 */
function getNotificationAccessFilter(userId) {
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
        SELECT 1 FROM workspace_members wm
        LEFT JOIN roles r ON wm.role_id = r.id
        LEFT JOIN board_members bm ON bm.board_id = n.board_id AND bm.user_id = ?
        WHERE wm.workspace_id = n.workspace_id AND wm.user_id = ?
          AND (
            r.name IN ('Owner', 'Super Admin', 'Admin')
            OR EXISTS (
              SELECT 1 FROM role_permissions rp
              JOIN permissions p ON rp.permission_id = p.id
              WHERE rp.role_id = wm.role_id AND p.key IN ('workspace.edit_settings', 'workspace.delete')
            )
            OR bm.user_id IS NOT NULL
          )
      )
    )
  )`;
  const params = [userId, userId, userId, userId];
  return { clause, params };
}

// GET /api/notifications?page=1&limit=20&filter=all&workspace_id=...
router.get('/', requireAuth, async (req, res, next) => {
  const page = Math.max(1, parseInt(req.query.page || '1', 10));
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '20', 10)));
  const offset = (page - 1) * limit;
  const filter = (req.query.filter || 'all').trim().toLowerCase();
  const search = (req.query.search || '').trim();
  const workspaceId = req.query.workspace_id ? Number(req.query.workspace_id) : null;

  try {
    const accessFilter = getNotificationAccessFilter(req.user.id);
    const whereClauses = [accessFilter.clause];
    const queryParams = [...accessFilter.params];

    if (filter === 'unread') {
      whereClauses.push('n.is_read = 0');
    } else if (filter === 'read') {
      whereClauses.push('n.is_read = 1');
    } else if (filter === 'cards') {
      whereClauses.push("(n.event_type LIKE 'card.%' OR n.type LIKE 'card.%' OR n.type = 'assignment')");
    } else if (filter === 'comments') {
      whereClauses.push("(n.event_type LIKE 'comment.%' OR n.type LIKE 'comment.%' OR n.type = 'mention')");
    } else if (filter === 'checklists') {
      whereClauses.push("(n.event_type LIKE 'checklist.%' OR n.type LIKE 'checklist.%')");
    } else if (filter === 'boards') {
      whereClauses.push("(n.event_type LIKE 'board.%' OR n.type LIKE 'board.%')");
    } else if (filter === 'members') {
      whereClauses.push("(n.event_type LIKE 'member.%' OR n.event_type LIKE 'invite.%' OR n.type = 'invite')");
    } else if (filter === 'attachments') {
      whereClauses.push("(n.event_type LIKE 'attachment.%' OR n.type LIKE 'attachment.%')");
    }

    if (workspaceId) {
      whereClauses.push('n.workspace_id = ?');
      queryParams.push(workspaceId);
    }

    if (search) {
      whereClauses.push('(n.message LIKE ? OR u.name LIKE ? OR c.title LIKE ? OR b.name LIKE ?)');
      const sParam = `%${search}%`;
      queryParams.push(sParam, sParam, sParam, sParam);
    }

    const whereSql = whereClauses.join(' AND ');

    // Query paginated rows
    const dataQueryParams = [...queryParams, Number(limit), Number(offset)];
    const notificationsRes = await req.db.query(
      `SELECT n.id, n.user_id, n.type, n.event_type, n.card_id, n.board_id, n.workspace_id, n.actor_user_id, n.message, n.is_read, n.created_at,
              u.name as actor_name, c.title as card_title, b.name as board_name, w.name as workspace_name
       FROM notifications n
       LEFT JOIN users u ON n.actor_user_id = u.id
       LEFT JOIN cards c ON n.card_id = c.id
       LEFT JOIN boards b ON n.board_id = b.id
       LEFT JOIN workspaces w ON n.workspace_id = w.id
       WHERE ${whereSql}
       ORDER BY n.created_at DESC
       LIMIT ? OFFSET ?`,
      dataQueryParams
    );

    // Total count for current filter
    const totalCountRes = await req.db.query(
      `SELECT COUNT(*) as total
       FROM notifications n
       LEFT JOIN users u ON n.actor_user_id = u.id
       LEFT JOIN cards c ON n.card_id = c.id
       LEFT JOIN boards b ON n.board_id = b.id
       WHERE ${whereSql}`,
      queryParams
    );
    const totalCount = Number(totalCountRes[0]?.total || 0);

    // Global unread count for badge (scoped strictly to authorized notifications)
    const unreadCountRes = await req.db.query(
      `SELECT COUNT(*) as count FROM notifications n WHERE ${accessFilter.clause} AND n.is_read = 0`,
      accessFilter.params
    );

    return res.json({
      notifications: notificationsRes,
      unread_count: Number(unreadCountRes[0]?.count || 0),
      total_count: totalCount,
      page,
      limit,
      has_more: offset + notificationsRes.length < totalCount
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/notifications/unread-count
router.get('/unread-count', requireAuth, async (req, res, next) => {
  try {
    const accessFilter = getNotificationAccessFilter(req.user.id);
    const countRes = await req.db.query(
      `SELECT COUNT(*) as count FROM notifications n WHERE ${accessFilter.clause} AND n.is_read = 0`,
      accessFilter.params
    );

    return res.json({ unread_count: Number(countRes[0]?.count || 0) });
  } catch (err) {
    next(err);
  }
});

// GET /api/notifications/preferences
router.get('/preferences', requireAuth, async (req, res, next) => {
  try {
    const categories = await getUserPreferences(req.user.id, req.db);
    return res.json({ preferences: categories });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/notifications/preferences
router.patch('/preferences', requireAuth, async (req, res, next) => {
  const { updates } = req.body;
  try {
    await updateUserPreferences(req.user.id, updates || [], req.db);
    const updatedCategories = await getUserPreferences(req.user.id, req.db);
    return res.json({ message: 'Notification preferences updated successfully', preferences: updatedCategories });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/notifications/:id/read
router.patch('/:id/read', requireAuth, async (req, res, next) => {
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
router.patch('/:id/unread', requireAuth, async (req, res, next) => {
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

// PATCH /api/notifications/read-all
router.patch('/read-all', requireAuth, async (req, res, next) => {
  try {
    const accessFilter = getNotificationAccessFilter(req.user.id);
    await req.db.execute(
      `UPDATE notifications n SET n.is_read = 1 WHERE ${accessFilter.clause} AND n.is_read = 0`,
      accessFilter.params
    );

    return res.json({ message: 'All notifications marked as read' });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/notifications/:id (Delete single notification)
router.delete('/:id', requireAuth, async (req, res, next) => {
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
router.delete('/clear/read', requireAuth, async (req, res, next) => {
  try {
    const accessFilter = getNotificationAccessFilter(req.user.id);
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

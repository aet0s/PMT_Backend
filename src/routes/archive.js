const express = require('express');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// GET /api/archive
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const workspacesRes = await req.db.query(
      `SELECT w.id, w.name, w.created_at, wm.role
       FROM workspaces w
       JOIN workspace_members wm ON w.id = wm.workspace_id
       WHERE wm.user_id = ? AND w.is_archived = 1
       ORDER BY w.created_at DESC`,
      [req.user.id]
    );

    const boardsRes = await req.db.query(
      `SELECT DISTINCT b.id, b.workspace_id, b.name, b.background_color, b.created_at, w.name as workspace_name, wm.role
       FROM boards b
       JOIN workspaces w ON b.workspace_id = w.id
       JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
       LEFT JOIN board_members bm ON b.id = bm.board_id AND bm.user_id = ?
       WHERE (wm.user_id IS NOT NULL OR bm.user_id IS NOT NULL) AND b.is_archived = 1
       ORDER BY b.created_at DESC`,
      [req.user.id, req.user.id]
    );

    const cardsRes = await req.db.query(
      `SELECT DISTINCT c.id, c.list_id, c.title, c.description, c.due_date, c.start_date, c.is_complete, c.created_at,
              l.name as list_name, b.id as board_id, b.name as board_name,
              w.id as workspace_id, w.name as workspace_name
       FROM cards c
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       JOIN workspaces w ON b.workspace_id = w.id
       JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
       LEFT JOIN board_members bm ON b.id = bm.board_id AND bm.user_id = ?
       WHERE (wm.user_id IS NOT NULL OR bm.user_id IS NOT NULL) AND c.is_archived = 1
       ORDER BY c.created_at DESC`,
      [req.user.id, req.user.id]
    );

    return res.json({
      workspaces: workspacesRes,
      boards: boardsRes,
      cards: cardsRes
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

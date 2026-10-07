// server/src/utils/activity.js
// Centralized activity logging helper for boards and cards

const { getDevSingleDb } = require('../services/tenantPools');
const { broadcastBoardEvent } = require('../socket');
const { parseJson } = require('../db/mysql');

async function logActivity(boardId, cardId, userId, actionType, metaJson = {}, dbInstance = null, tenantId = null) {
  if (!boardId) return;
  const db = dbInstance || getDevSingleDb();
  const effectiveTenantId = tenantId || db?.tenantId || metaJson?.tenantId || null;
  try {
    const result = await db.execute(
      'INSERT INTO activity_log (board_id, card_id, user_id, action_type, meta_json) VALUES (?, ?, ?, ?, ?)',
      [boardId, cardId || null, userId || null, actionType, JSON.stringify(metaJson || {})]
    );

    if (result && result.insertId) {
      const actRes = await db.query(
        `SELECT a.id, a.board_id, a.card_id, a.user_id, a.action_type, a.meta_json, a.created_at,
                u.name as user_name, u.email as user_email,
                c.title as card_title
         FROM activity_log a
         LEFT JOIN users u ON a.user_id = u.id
         LEFT JOIN cards c ON a.card_id = c.id
         WHERE a.id = ?`,
        [result.insertId]
      );

      if (actRes && actRes.length > 0) {
        const parsed = {
          ...actRes[0],
          meta_json: parseJson(actRes[0].meta_json)
        };
        broadcastBoardEvent(boardId, 'board:activity', { activity: parsed }, null, effectiveTenantId);
      }
    }
  } catch (err) {
    console.error('Failed to log activity:', err.message);
  }
}

module.exports = { logActivity };

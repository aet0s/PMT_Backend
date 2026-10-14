// server/src/utils/activity.js
// Centralized comprehensive activity & audit logging helper across all company domains
// (auth, workspaces, boards, cards, checklists, comments, members, roles, etc.)

const { getDevSingleDb } = require('../services/tenantPools');
const { broadcastBoardEvent, broadcastWorkspaceEvent } = require('../socket');
const { parseJson } = require('../db/mysql');

/**
 * Log any system action to the tenant's activity_log.
 * Supports both positional arguments: (boardId, cardId, userId, actionType, metaJson, dbInstance, tenantId)
 * and options object: { boardId, cardId, userId, workspaceId, actionType, metaJson, dbInstance, tenantId }
 */
async function logActivity(boardIdOrOptions, cardIdArg, userIdArg, actionTypeArg, metaJsonArg = {}, dbInstanceArg = null, tenantIdArg = null) {
  let boardId = null;
  let cardId = null;
  let userId = null;
  let workspaceId = null;
  let actionType = null;
  let metaJson = {};
  let dbInstance = null;
  let tenantId = null;

  if (boardIdOrOptions && typeof boardIdOrOptions === 'object' && !('id' in boardIdOrOptions) && boardIdOrOptions.actionType) {
    boardId = boardIdOrOptions.boardId || null;
    cardId = boardIdOrOptions.cardId || null;
    userId = boardIdOrOptions.userId || null;
    workspaceId = boardIdOrOptions.workspaceId || null;
    actionType = boardIdOrOptions.actionType;
    metaJson = boardIdOrOptions.metaJson || {};
    dbInstance = boardIdOrOptions.dbInstance || null;
    tenantId = boardIdOrOptions.tenantId || null;
  } else {
    boardId = boardIdOrOptions || null;
    cardId = cardIdArg || null;
    userId = userIdArg || null;
    actionType = actionTypeArg;
    metaJson = metaJsonArg || {};
    dbInstance = dbInstanceArg || null;
    tenantId = tenantIdArg || null;
  }

  if (!actionType) return;

  const db = dbInstance || getDevSingleDb();
  if (!db) return;

  const effectiveTenantId = tenantId || db?.tenantId || metaJson?.tenantId || null;

  try {
    // If cardId is provided without boardId or workspaceId, resolve them
    if (cardId && (!boardId || !workspaceId)) {
      try {
        const cRes = await db.query(
          `SELECT l.board_id, b.workspace_id 
           FROM cards c
           JOIN lists l ON c.list_id = l.id
           JOIN boards b ON l.board_id = b.id
           WHERE c.id = ?`,
          [cardId]
        );
        if (cRes.length > 0) {
          if (!boardId) boardId = cRes[0].board_id;
          if (!workspaceId) workspaceId = cRes[0].workspace_id;
        }
      } catch (e) {
        // Non-blocking lookup failure
      }
    }

    // If boardId is provided without workspaceId, resolve it
    if (boardId && !workspaceId) {
      try {
        const bRes = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [boardId]);
        if (bRes.length > 0) {
          workspaceId = bRes[0].workspace_id;
        }
      } catch (e) {
        // Non-blocking lookup failure
      }
    }

    // Ensure userId from metaJson if missing
    if (!userId && (metaJson.user_id || metaJson.userId)) {
      userId = metaJson.user_id || metaJson.userId;
    }

    const result = await db.execute(
      `INSERT INTO activity_log (board_id, card_id, user_id, workspace_id, action_type, meta_json)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        boardId ? Number(boardId) : null,
        cardId ? Number(cardId) : null,
        userId ? Number(userId) : null,
        workspaceId ? Number(workspaceId) : null,
        String(actionType).trim(),
        JSON.stringify(metaJson || {})
      ]
    );

    if (result && result.insertId) {
      const actRes = await db.query(
        `SELECT a.id, a.board_id, a.card_id, a.user_id, a.workspace_id, a.action_type, a.meta_json, a.created_at,
                u.name as user_name, u.email as user_email, u.avatar_url as user_avatar_url,
                c.title as card_title,
                b.name as board_name,
                w.name as workspace_name
         FROM activity_log a
         LEFT JOIN users u ON a.user_id = u.id
         LEFT JOIN cards c ON a.card_id = c.id
         LEFT JOIN boards b ON a.board_id = b.id
         LEFT JOIN workspaces w ON a.workspace_id = w.id
         WHERE a.id = ?`,
        [result.insertId]
      );

      if (actRes && actRes.length > 0) {
        const parsed = {
          ...actRes[0],
          meta_json: parseJson(actRes[0].meta_json)
        };

        if (boardId) {
          broadcastBoardEvent(boardId, 'board:activity', { activity: parsed }, null, effectiveTenantId);
        }
        if (workspaceId) {
          broadcastWorkspaceEvent(workspaceId, 'workspace:activity', { activity: parsed }, null, effectiveTenantId);
        }
        return parsed;
      }
    }
  } catch (err) {
    console.error(`[AUDIT_ERROR] Failed to log activity "${actionType}":`, err.message);
  }
}

module.exports = { logActivity };

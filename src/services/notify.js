// server/src/services/notify.js
// Central notification dispatcher function with multi-tenant database outbox support.
const { getDevSingleDb, getTenantDb } = require('./tenantPools');

function isSingleTenantMode() {
  return process.env.DEV_SINGLE_TENANT === '1';
}
const { NOTIFICATION_EVENTS, renderMessage } = require('./notificationEvents');
const { resolveRecipients } = require('./resolveRecipients');
const { isEventEnabledForUser } = require('./notificationPreferences');
const { sendUserNotification } = require('../socket');
const { enqueueOutbox, processOutbox } = require('./notificationOutbox');

/**
 * Direct fallback insertion and real-time delivery
 */
async function insertAndDeliverNotification(userId, eventType, message, meta, ctx, actorName, db, tenantId) {
  try {
    let finalWsId = ctx.workspaceId || null;
    if (!finalWsId && ctx.boardId) {
      try {
        const bRes = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [ctx.boardId]);
        if (bRes[0]?.workspace_id) finalWsId = bRes[0].workspace_id;
      } catch (e) {}
    }

    const metaJson = JSON.stringify({
      ...meta,
      actorName: actorName || 'Someone',
      boardId: ctx.boardId,
      cardId: ctx.cardId,
      workspaceId: finalWsId
    });

    let insertRes;
    try {
      insertRes = await db.execute(
        `INSERT INTO notifications (user_id, type, event_type, card_id, board_id, workspace_id, actor_user_id, message, meta)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          userId,
          eventType,
          eventType,
          ctx.cardId || null,
          ctx.boardId || null,
          finalWsId,
          ctx.actorUserId || null,
          message,
          metaJson
        ]
      );
    } catch (colErr) {
      insertRes = await db.execute(
        `INSERT INTO notifications (user_id, type, event_type, card_id, board_id, workspace_id, actor_user_id, message)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          userId,
          eventType,
          eventType,
          ctx.cardId || null,
          ctx.boardId || null,
          finalWsId,
          ctx.actorUserId || null,
          message
        ]
      );
    }

    const [notification] = await db.query(
      `SELECT id, user_id, type, event_type, card_id, board_id, workspace_id, actor_user_id, message, is_read, created_at
       FROM notifications WHERE id = ?`,
      [insertRes.insertId]
    );

    if (notification) {
      notification.actor_name = actorName || 'Someone';
      notification.meta = meta;
      sendUserNotification(userId, notification, tenantId);
    }
  } catch (err) {
    console.error(`[NOTIFY_DELIVERY_ERROR] Failed to insert/emit notification to user ${userId}:`, err);
  }
}

/**
 * Central Notification Dispatcher Function
 * Every notification-worthy action in the app calls notify(...) post-DB write.
 */
async function notify(
  params = {},
  dbInstance = null
) {
  const {
    eventType,
    actorUserId,
    workspaceId,
    boardId,
    cardId,
    targetUserId,
    inviteeUserId,
    mentionedUserIds,
    meta = {},
    dedupeKey = null
  } = params;

  if (!eventType || !NOTIFICATION_EVENTS[eventType]) {
    console.warn(`Unknown or uncataloged eventType passed to notify: "${eventType}"`);
    return;
  }

  let tenantId = params.tenantId || params.req?.tenant?.id || dbInstance?.tenantId || params.db?.tenantId || null;
  let db = dbInstance || params.db || params.req?.db || null;

  if (isSingleTenantMode() || process.env.DEV_SINGLE_TENANT === '1') {
    if (!db) {
      db = getDevSingleDb();
    }
    if (!tenantId) {
      tenantId = 'single';
    }
  } else {
    // Multi-tenant mode: db and tenantId are strictly REQUIRED
    if (!db && tenantId) {
      try {
        db = await getTenantDb(tenantId);
      } catch (e) {
        db = null;
      }
    }

    if (!db || !tenantId) {
      throw new Error(
        `[NOTIFY_ERROR] Database connection and tenantId are required in multi-tenant mode (got tenantId=${tenantId}, db=${!!db})`
      );
    }
  }

  try {
    // 1. Resolve workspaceId or boardId if missing but cardId/boardId present
    let resolvedBoardId = boardId;
    let resolvedWorkspaceId = workspaceId;

    if (!resolvedBoardId && cardId) {
      const cardRes = await db.query(
        'SELECT l.board_id, b.workspace_id FROM cards c JOIN lists l ON c.list_id = l.id JOIN boards b ON l.board_id = b.id WHERE c.id = ?',
        [cardId]
      );
      if (cardRes[0]) {
        resolvedBoardId = cardRes[0].board_id;
        resolvedWorkspaceId = cardRes[0].workspace_id;
      }
    } else if (!resolvedWorkspaceId && resolvedBoardId) {
      const boardRes = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [resolvedBoardId]);
      if (boardRes[0]) {
        resolvedWorkspaceId = boardRes[0].workspace_id;
      }
    }

    // 2. Enqueue into Outbox table for crash durability & transaction isolation
    try {
      await enqueueOutbox(db, {
        eventType,
        workspaceId: resolvedWorkspaceId ? Number(resolvedWorkspaceId) : null,
        boardId: resolvedBoardId ? Number(resolvedBoardId) : null,
        cardId: cardId ? Number(cardId) : null,
        actorUserId: actorUserId ? Number(actorUserId) : null,
        targetUserId: targetUserId ? Number(targetUserId) : null,
        inviteeUserId: inviteeUserId ? Number(inviteeUserId) : null,
        mentionedUserIds: Array.isArray(mentionedUserIds) ? mentionedUserIds.map(Number) : [],
        meta,
        dedupeKey
      });

      // 3. Trigger immediate outbox processor for low-latency delivery
      await processOutbox(db, tenantId);
    } catch (outboxErr) {
      // Fallback: direct in-memory resolution & delivery
      let actorName = meta.actorName;
      if (!actorName && actorUserId) {
        const actorRes = await db.query('SELECT name FROM users WHERE id = ?', [actorUserId]);
        actorName = actorRes[0]?.name || 'Someone';
      }

      const ctx = {
        workspaceId: resolvedWorkspaceId ? Number(resolvedWorkspaceId) : null,
        boardId: resolvedBoardId ? Number(resolvedBoardId) : null,
        cardId: cardId ? Number(cardId) : null,
        actorUserId: actorUserId ? Number(actorUserId) : null,
        targetUserId: targetUserId ? Number(targetUserId) : null,
        inviteeUserId: inviteeUserId ? Number(inviteeUserId) : null,
        tenantId: tenantId ? Number(tenantId) : null,
        mentionedUserIds: Array.isArray(mentionedUserIds) ? mentionedUserIds.map(Number) : []
      };

      const recipients = await resolveRecipients(eventType, ctx, db);
      for (const recipientId of recipients) {
        if (ctx.actorUserId && Number(recipientId) === Number(ctx.actorUserId)) continue;
        const isEnabled = await isEventEnabledForUser(recipientId, eventType, 'in_app', db);
        if (!isEnabled) continue;
        const message = renderMessage(eventType, meta, actorName);
        await insertAndDeliverNotification(recipientId, eventType, message, meta, ctx, actorName, db, tenantId);
      }
    }
  } catch (err) {
    console.error(`Error in notify dispatcher for event ${eventType}:`, err);
  }
}

module.exports = { notify, insertAndDeliverNotification };

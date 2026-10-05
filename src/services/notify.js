// server/src/services/notify.js
// Central notification dispatcher function with multi-tenant database support.
const { getDevSingleDb, getTenantDb } = require('./tenantPools');
const { NOTIFICATION_EVENTS, renderMessage } = require('./notificationEvents');
const { resolveRecipients } = require('./resolveRecipients');
const { isEventEnabledForUser } = require('./notificationPreferences');
const { enqueueNotification } = require('./notifyBatcher');

/**
 * Central Notification Dispatcher Function
 * Every notification-worthy action in the app calls notify(...) post-DB write.
 */
async function notify(
  {
    eventType,
    actorUserId,
    workspaceId,
    boardId,
    cardId,
    targetUserId,
    inviteeUserId,
    mentionedUserIds,
    tenantId = null,
    meta = {}
  },
  dbInstance = null
) {
  if (!eventType || !NOTIFICATION_EVENTS[eventType]) {
    console.warn(`Unknown or uncataloged eventType passed to notify: "${eventType}"`);
    return;
  }

  let db = dbInstance;
  if (!db) {
    if (tenantId) {
      try {
        db = await getTenantDb(tenantId);
      } catch (e) {
        db = getDevSingleDb();
      }
    } else {
      db = getDevSingleDb();
    }
  }

  try {
    // 1. Resolve actor name if not in meta
    let actorName = meta.actorName;
    if (!actorName && actorUserId) {
      const actorRes = await db.query('SELECT name FROM users WHERE id = ?', [actorUserId]);
      actorName = actorRes[0]?.name || 'Someone';
    }

    // 2. Infer workspaceId or boardId if missing but cardId/boardId present
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

    // 3. Resolve recipients
    const recipients = await resolveRecipients(eventType, ctx, db);

    // 4. Dispatch to each recipient
    for (const recipientId of recipients) {
      // Exclude actor from receiving notification for their own action
      if (ctx.actorUserId && Number(recipientId) === Number(ctx.actorUserId)) {
        continue;
      }

      // Check server-side preference check
      const isEnabled = await isEventEnabledForUser(recipientId, eventType, 'in_app', db);
      if (!isEnabled) {
        continue;
      }

      // Enqueue to batcher/dispatcher
      enqueueNotification(recipientId, eventType, ctx, meta, actorName, db);
    }
  } catch (err) {
    console.error(`Error in notify dispatcher for event ${eventType}:`, err);
  }
}

module.exports = { notify };

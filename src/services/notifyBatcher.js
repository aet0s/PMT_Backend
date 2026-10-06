// server/src/services/notifyBatcher.js
// In-memory debounce batcher for high-frequency notification events.
const { getDevSingleDb } = require('./tenantPools');
const { sendUserNotification } = require('../socket');
const { renderMessage } = require('./notificationEvents');

const DEBOUNCE_MS = 5000; // 5-second window
const pendingBatchMap = new Map();

/**
 * Generates batch key for anti-spam debouncing
 */
function getBatchKey(recipientUserId, cardId, eventType) {
  return `${recipientUserId}:${cardId || 0}:${eventType}`;
}

/**
 * Enqueues a notification into the in-memory anti-spam batcher
 */
function enqueueNotification(recipientUserId, eventType, ctx, meta, actorName, dbInstance = null) {
  const IMMEDIATE_EVENTS = new Set([
    'card.created',
    'card.assigned',
    'card.unassigned',
    'card.moved',
    'card.completed',
    'card.deleted',
    'comment.added',
    'comment.mention',
    'invite.sent',
    'invite.accepted',
    'member.added',
    'member.role_changed',
    'member.removed',
    'board.member_added',
    'board.member_removed',
    'board.archived',
    'attachment.added',
    'label.added'
  ]);
  if (!ctx.cardId || IMMEDIATE_EVENTS.has(eventType)) {
    return flushSingleNotification(recipientUserId, eventType, ctx, meta, actorName, dbInstance);
  }

  const key = getBatchKey(recipientUserId, ctx.cardId, eventType);

  if (pendingBatchMap.has(key)) {
    const batch = pendingBatchMap.get(key);
    batch.count += 1;
    batch.metas.push(meta);
    if (dbInstance) batch.db = dbInstance;

    // Reset debounce timer
    clearTimeout(batch.timer);
    batch.timer = setTimeout(() => flushBatch(key), DEBOUNCE_MS);
  } else {
    const batch = {
      recipientUserId,
      eventType,
      ctx,
      actorName,
      db: dbInstance,
      count: 1,
      metas: [meta],
      timer: setTimeout(() => flushBatch(key), DEBOUNCE_MS)
    };
    pendingBatchMap.set(key, batch);
  }
}

/**
 * Flushes a batched item from memory to DB and emits socket notification
 */
async function flushBatch(key) {
  const batch = pendingBatchMap.get(key);
  if (!batch) return;
  pendingBatchMap.delete(key);

  const { recipientUserId, eventType, ctx, actorName, count, metas, db } = batch;
  const lastMeta = metas[metas.length - 1] || {};

  let message;
  if (count === 1) {
    message = renderMessage(eventType, lastMeta, actorName);
  } else {
    // Consolidated merged message for rapid-fire events
    if (eventType.startsWith('checklist_item')) {
      const checklistTitle = lastMeta.checklistTitle || 'Checklist';
      const cardTitle = lastMeta.cardTitle || 'Card';
      const actionVerb = eventType === 'checklist_item.completed' ? 'completed' : 'reopened';
      message = `${actorName} ${actionVerb} ${count} items in ${checklistTitle} on "${cardTitle}"`;
    } else if (eventType === 'card.moved') {
      const cardTitle = lastMeta.cardTitle || 'Card';
      message = `${actorName} moved "${cardTitle}" ${count} times`;
    } else {
      message = renderMessage(eventType, { ...lastMeta, count }, actorName);
    }
  }

  await insertAndEmitNotification(recipientUserId, eventType, message, ctx, db);
}

/**
 * Flushes a single unbatched notification immediately
 */
async function flushSingleNotification(recipientUserId, eventType, ctx, meta, actorName, dbInstance = null) {
  const message = renderMessage(eventType, meta, actorName);
  await insertAndEmitNotification(recipientUserId, eventType, message, ctx, dbInstance);
}

/**
 * Inserts notification row to DB and emits socket notification:new
 */
async function insertAndEmitNotification(userId, eventType, message, ctx, dbInstance = null) {
  const db = dbInstance || getDevSingleDb();

  try {
    let finalWsId = ctx.workspaceId || null;
    if (!finalWsId && ctx.boardId) {
      try {
        const bRes = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [ctx.boardId]);
        if (bRes[0]?.workspace_id) finalWsId = bRes[0].workspace_id;
      } catch (e) {}
    }

    const insertRes = await db.execute(
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

    const [notification] = await db.query(
      `SELECT id, user_id, type, event_type, card_id, board_id, workspace_id, actor_user_id, message, is_read, created_at
       FROM notifications WHERE id = ?`,
      [insertRes.insertId]
    );

    // Fetch actor name if available
    if (ctx.actorUserId) {
      const actorRes = await db.query('SELECT name FROM users WHERE id = ?', [ctx.actorUserId]);
      notification.actor_name = actorRes[0]?.name || 'Someone';
    }

    sendUserNotification(userId, notification, ctx.tenantId);
    return notification;
  } catch (err) {
    console.error('Error inserting & emitting notification:', err);
    return null;
  }
}

module.exports = {
  enqueueNotification,
  flushSingleNotification
};

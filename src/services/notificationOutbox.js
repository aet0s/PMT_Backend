// server/src/services/notificationOutbox.js
// Idempotent outbox pattern, advisory-locked worker, DB-backed coalescing, and retry mechanism.

const { NOTIFICATION_EVENTS, renderMessage } = require('./notificationEvents');
const { resolveRecipients } = require('./resolveRecipients');
const { sendUserNotification } = require('../socket');

/**
 * Enqueues a notification task into the tenant outbox table
 */
async function enqueueOutbox(db, params = {}) {
  const {
    eventType,
    workspaceId = null,
    boardId = null,
    cardId = null,
    actorUserId = null,
    targetUserId = null,
    inviteeUserId = null,
    mentionedUserIds = [],
    meta = {},
    dedupeKey = null
  } = params;

  const insertQuery = `
    INSERT INTO notification_outbox (
      event_type, workspace_id, board_id, card_id,
      actor_user_id, target_user_id, invitee_user_id,
      mentioned_user_ids, meta, dedupe_key, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
  `;

  try {
    const res = await db.execute(insertQuery, [
      eventType,
      workspaceId,
      boardId,
      cardId,
      actorUserId,
      targetUserId,
      inviteeUserId,
      JSON.stringify(mentionedUserIds || []),
      JSON.stringify(meta || {}),
      dedupeKey || null
    ]);
    return res.insertId;
  } catch (err) {
    if (dedupeKey && err.code === 'ER_DUP_ENTRY') {
      // Deduplicated successfully (e.g. reminder already enqueued for this date)
      return null;
    }
    throw err;
  }
}

/**
 * Computes unread notification counts for a user
 */
async function getUnreadCounts(db, userId, boardId = null) {
  try {
    const [totalRes] = await db.query(
      'SELECT COUNT(*) as unread_total FROM notifications WHERE user_id = ? AND is_read = 0',
      [userId]
    );
    const unreadTotal = Number(totalRes?.unread_total || 0);

    let unreadBoard = 0;
    if (boardId) {
      const [boardRes] = await db.query(
        'SELECT COUNT(*) as unread_board FROM notifications WHERE user_id = ? AND board_id = ? AND is_read = 0',
        [userId, boardId]
      );
      unreadBoard = Number(boardRes?.unread_board || 0);
    }

    return { unreadTotal, unreadBoard };
  } catch (err) {
    return { unreadTotal: 0, unreadBoard: 0 };
  }
}

/**
 * Processes pending outbox rows for a tenant database
 */
async function processOutbox(db, tenantId = 'single') {
  if (!db) return;

  const lockKey = `pm_notif_lock_${tenantId}`;
  let lockAcquired = false;

  try {
    const [lockRes] = await db.query('SELECT GET_LOCK(?, 0) as got_lock', [lockKey]);
    if (!lockRes || Number(lockRes.got_lock) !== 1) {
      // Another worker process is currently processing this tenant
      return;
    }
    lockAcquired = true;

    const rows = await db.query(
      `SELECT * FROM notification_outbox
       WHERE status IN ('pending', 'failed')
         AND (next_retry_at IS NULL OR next_retry_at <= NOW(3))
       ORDER BY id ASC
       LIMIT 50`
    );

    for (const row of rows) {
      await db.execute(
        "UPDATE notification_outbox SET status = 'processing' WHERE id = ?",
        [row.id]
      );

      try {
        const eventConfig = NOTIFICATION_EVENTS[row.event_type];
        if (!eventConfig) {
          await db.execute(
            "UPDATE notification_outbox SET status = 'dead_letter', last_error = 'Unknown eventType' WHERE id = ?",
            [row.id]
          );
          continue;
        }

        const mentionedUserIds = row.mentioned_user_ids ? (typeof row.mentioned_user_ids === 'string' ? JSON.parse(row.mentioned_user_ids) : row.mentioned_user_ids) : [];
        const meta = row.meta ? (typeof row.meta === 'string' ? JSON.parse(row.meta) : row.meta) : {};

        let actorName = meta.actorName || 'Someone';
        if (row.actor_user_id && !meta.actorName) {
          const [actorRow] = await db.query('SELECT name FROM users WHERE id = ?', [row.actor_user_id]);
          if (actorRow) actorName = actorRow.name;
        }

        const ctx = {
          workspaceId: row.workspace_id,
          boardId: row.board_id,
          cardId: row.card_id,
          actorUserId: row.actor_user_id,
          targetUserId: row.target_user_id,
          inviteeUserId: row.invitee_user_id,
          tenantId,
          mentionedUserIds
        };

        const recipients = await resolveRecipients(row.event_type, ctx, db);

        for (const recipientId of recipients) {
          const isPriority =
            Number(recipientId) === Number(row.target_user_id) ||
            mentionedUserIds.includes(Number(recipientId));

          let coalesced = false;

          // 4. DB-backed coalescing: within 60s for high-frequency events on same card & actor
          if (
            eventConfig.coalescingPolicy === 'coalesce_60s' &&
            row.card_id &&
            row.actor_user_id
          ) {
            const recentRows = await db.query(
              `SELECT id, count, meta FROM notifications
               WHERE user_id = ? AND event_type = ? AND card_id = ? AND actor_user_id = ?
                 AND is_read = 0 AND created_at >= NOW(3) - INTERVAL 60 SECOND
               ORDER BY id DESC LIMIT 1`,
              [recipientId, row.event_type, row.card_id, row.actor_user_id]
            );

            if (recentRows.length > 0) {
              const existingNotif = recentRows[0];
              const newCount = Number(existingNotif.count || 1) + 1;
              const mergedMeta = { ...meta, count: newCount };
              const updatedMessage = renderMessage(row.event_type, mergedMeta, actorName);

              await db.execute(
                `UPDATE notifications
                 SET count = ?, message = ?, meta = ?, created_at = NOW(3)
                 WHERE id = ?`,
                [newCount, updatedMessage, JSON.stringify(mergedMeta), existingNotif.id]
              );

              coalesced = true;

              const { unreadTotal, unreadBoard } = await getUnreadCounts(db, recipientId, row.board_id);
              sendUserNotification(
                recipientId,
                {
                  id: existingNotif.id,
                  type: row.event_type,
                  event_type: row.event_type,
                  message: updatedMessage,
                  count: newCount,
                  meta: mergedMeta,
                  board_id: row.board_id,
                  card_id: row.card_id,
                  workspace_id: row.workspace_id,
                  unread_total: unreadTotal,
                  unread_board: unreadBoard
                },
                tenantId
              );
            }
          }

          if (!coalesced) {
            const message = renderMessage(row.event_type, meta, actorName);
            const userDedupeKey = row.dedupe_key ? `${recipientId}:${row.dedupe_key}` : null;

            const insertRes = await db.execute(
              `INSERT INTO notifications (
                user_id, type, event_type, card_id, board_id,
                workspace_id, actor_user_id, message, meta,
                priority, count, dedupe_key
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
              [
                recipientId,
                row.event_type,
                row.event_type,
                row.card_id,
                row.board_id,
                row.workspace_id,
                row.actor_user_id,
                message,
                JSON.stringify(meta),
                isPriority ? 1 : 0,
                userDedupeKey
              ]
            );

            const [createdNotif] = await db.query(
              `SELECT id, user_id, type, event_type, card_id, board_id, workspace_id,
                      actor_user_id, message, meta, is_read, priority, count, created_at
               FROM notifications WHERE id = ?`,
              [insertRes.insertId]
            );

            if (createdNotif) {
              createdNotif.actor_name = actorName;
              createdNotif.meta = meta;
              const { unreadTotal, unreadBoard } = await getUnreadCounts(db, recipientId, row.board_id);
              createdNotif.unread_total = unreadTotal;
              createdNotif.unread_board = unreadBoard;
              sendUserNotification(recipientId, createdNotif, tenantId);
            }
          }
        }

        await db.execute(
          "UPDATE notification_outbox SET status = 'completed', processed_at = NOW(3) WHERE id = ?",
          [row.id]
        );
      } catch (procErr) {
        const nextRetry = Number(row.retry_count || 0) + 1;
        if (nextRetry >= 5) {
          await db.execute(
            "UPDATE notification_outbox SET status = 'dead_letter', retry_count = ?, last_error = ? WHERE id = ?",
            [nextRetry, procErr.message.slice(0, 500), row.id]
          );
        } else {
          const delaySeconds = Math.pow(2, nextRetry) * 2;
          await db.execute(
            `UPDATE notification_outbox
             SET status = 'failed', retry_count = ?, last_error = ?,
                 next_retry_at = NOW(3) + INTERVAL ? SECOND
             WHERE id = ?`,
            [nextRetry, procErr.message.slice(0, 500), delaySeconds, row.id]
          );
        }
      }
    }
  } finally {
    if (lockAcquired) {
      try {
        await db.query('SELECT RELEASE_LOCK(?)', [lockKey]);
      } catch (e) {}
    }
  }
}

/**
 * Retention cleanup job: deletes read notifications older than 30 days
 */
async function cleanOldNotifications(db) {
  if (!db) return 0;
  try {
    const res = await db.execute(
      'DELETE FROM notifications WHERE is_read = 1 AND created_at < NOW(3) - INTERVAL 30 DAY'
    );
    return res.affectedRows || 0;
  } catch (err) {
    console.error('[NOTIF_RETENTION_ERROR] Failed to purge old read notifications:', err);
    return 0;
  }
}

module.exports = {
  enqueueOutbox,
  processOutbox,
  getUnreadCounts,
  cleanOldNotifications
};

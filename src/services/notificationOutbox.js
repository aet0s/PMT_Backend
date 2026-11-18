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

  if (dedupeKey) {
    const existing = await db.query('SELECT id FROM notification_outbox WHERE dedupe_key = ? LIMIT 1', [dedupeKey]);
    if (existing && existing.length > 0) {
      return null;
    }
  }

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
    if (dedupeKey && (err.code === 'ER_DUP_ENTRY' || (err.message && err.message.includes('Duplicate')))) {
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
  let connection = null;

  try {
    // MySQL GET_LOCK() is connection-scoped. If db is a connection pool,
    // calling db.query() immediately returns the connection to the pool.
    // We MUST acquire and hold a dedicated connection throughout outbox processing.
    if (typeof db.getConnection === 'function') {
      connection = await db.getConnection();
    }
    const runner = connection || db;

    const [lockRes] = await runner.query('SELECT GET_LOCK(?, 0) as got_lock', [lockKey]);
    if (!lockRes || Number(lockRes.got_lock) !== 1) {
      // Another worker process is currently processing this tenant
      return;
    }
    lockAcquired = true;

    // Recover only expired processing leases where worker may have crashed or timed out.
    // Never reset an actively processed notification whose lease is still valid.
    await runner.execute(
      `UPDATE notification_outbox
       SET status = 'failed',
           last_error = 'Worker lease timeout: lease expired without completion',
           next_retry_at = NOW(3),
           lease_expires_at = NULL
       WHERE status = 'processing'
         AND lease_expires_at IS NOT NULL
         AND lease_expires_at < NOW(3)`
    ).catch(() => {});

    const rows = await (connection || db).query(
      `SELECT * FROM notification_outbox
       WHERE (status IN ('pending', 'failed')
              OR (status = 'processing' AND lease_expires_at IS NOT NULL AND lease_expires_at < NOW(3)))
         AND (next_retry_at IS NULL OR next_retry_at <= NOW(3))
       ORDER BY id ASC
       LIMIT 50`
    );

    for (const row of rows) {
      // Atomic row claim: sets processing_started_at and lease_expires_at (2-minute lease).
      // Can claim a pending/failed row, or claim a row whose lease has expired.
      const claimRes = await runner.execute(
        `UPDATE notification_outbox
         SET status = 'processing',
             processing_started_at = NOW(3),
             lease_expires_at = NOW(3) + INTERVAL 2 MINUTE
         WHERE id = ?
           AND (
             status IN ('pending', 'failed')
             OR (status = 'processing' AND lease_expires_at IS NOT NULL AND lease_expires_at < NOW(3))
           )`,
        [row.id]
      );
      if (!claimRes || claimRes.affectedRows === 0) {
        continue;
      }

      try {
        const eventConfig = NOTIFICATION_EVENTS[row.event_type];
        if (!eventConfig) {
          await db.execute(
            "UPDATE notification_outbox SET status = 'dead_letter', last_error = 'Unknown eventType' WHERE id = ?",
            [row.id]
          );
          continue;
        }

        if (eventConfig.notifiable === false) {
          await db.execute(
            "UPDATE notification_outbox SET status = 'completed', processed_at = NOW(3) WHERE id = ?",
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

              // Web Push delivery integration through existing outbox pattern
              try {
                const { sendPushNotification } = require('./pushService');
                sendPushNotification(db, {
                  notification: createdNotif,
                  recipientId,
                  eventType: row.event_type,
                  message,
                  meta,
                  ctx,
                  actorName,
                  tenantId
                }).catch(() => {});
              } catch (_) {}
            }
          }
        }

        await runner.execute(
          "UPDATE notification_outbox SET status = 'completed', processed_at = NOW(3), lease_expires_at = NULL WHERE id = ?",
          [row.id]
        );
      } catch (procErr) {
        const nextRetry = Number(row.retry_count || 0) + 1;
        if (nextRetry >= 5) {
          await runner.execute(
            "UPDATE notification_outbox SET status = 'dead_letter', retry_count = ?, last_error = ?, lease_expires_at = NULL WHERE id = ?",
            [nextRetry, procErr.message.slice(0, 500), row.id]
          );
        } else {
          const delaySeconds = Math.pow(2, nextRetry) * 2;
          await runner.execute(
            `UPDATE notification_outbox
             SET status = 'failed', retry_count = ?, last_error = ?,
                 next_retry_at = NOW(3) + INTERVAL ? SECOND,
                 lease_expires_at = NULL
             WHERE id = ?`,
            [nextRetry, procErr.message.slice(0, 500), delaySeconds, row.id]
          );
        }
      }
    }
  } finally {
    const runner = connection || db;
    if (lockAcquired && runner) {
      try {
        await runner.query('SELECT RELEASE_LOCK(?)', [lockKey]);
      } catch (e) {}
    }
    if (connection && typeof connection.release === 'function') {
      try {
        connection.release();
      } catch (e) {}
    }
  }
}

/**
 * Heartbeat/renewal for long-running notification processing lease
 */
async function renewLease(runner, rowId, additionalSeconds = 120) {
  if (!runner || !rowId) return false;
  try {
    const res = await runner.execute(
      `UPDATE notification_outbox
       SET lease_expires_at = NOW(3) + INTERVAL ? SECOND
       WHERE id = ? AND status = 'processing'`,
      [additionalSeconds, rowId]
    );
    return Boolean(res && res.affectedRows > 0);
  } catch (e) {
    return false;
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
  renewLease,
  getUnreadCounts,
  cleanOldNotifications
};

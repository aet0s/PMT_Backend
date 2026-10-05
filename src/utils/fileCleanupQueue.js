// server/src/utils/fileCleanupQueue.js
/**
 * Persistent Database-Backed File Cleanup Retry Queue.
 * Retries unlinking disk files with exponential backoff up to max_attempts (5).
 * Persists queue state in database to ensure restart survival.
 */
const fs = require('fs');
const { getMasterDb, getDevSingleDb } = require('../services/tenantPools');

let retryInterval = null;
let tableEnsured = false;

function getQueueDb() {
  if (process.env.DEV_SINGLE_TENANT === '1') {
    return getDevSingleDb();
  }
  return getMasterDb();
}

async function ensureCleanupTable() {
  if (tableEnsured) return;
  try {
    const db = getQueueDb();
    await db.query(`
      CREATE TABLE IF NOT EXISTS file_cleanup_queue (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tenant_id INT NULL,
        file_path VARCHAR(1024) NOT NULL,
        attempts INT NOT NULL DEFAULT 0,
        max_attempts INT NOT NULL DEFAULT 5,
        next_run_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        status ENUM('pending', 'failed', 'completed') NOT NULL DEFAULT 'pending',
        error_message TEXT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_status_next_run (status, next_run_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
    tableEnsured = true;
  } catch (err) {
    console.error('[FILE_CLEANUP] Failed to ensure file_cleanup_queue table:', err.message);
  }
}

async function queueFileCleanupRetry(filePath, tenantId = null) {
  try {
    await ensureCleanupTable();
    const db = getQueueDb();
    await db.query(
      `INSERT INTO file_cleanup_queue (tenant_id, file_path, attempts, max_attempts, next_run_at, status)
       VALUES (?, ?, 0, 5, NOW(), 'pending')`,
      [tenantId, filePath]
    );
    console.log(`[FILE_CLEANUP] Persisted file to cleanup retry queue: ${filePath}`);
    ensureWorker();
  } catch (err) {
    console.error(`[FILE_CLEANUP] Failed to enqueue file cleanup for ${filePath}:`, err.message);
  }
}

async function processFileCleanupQueue() {
  try {
    await ensureCleanupTable();
    const db = getQueueDb();
    const rows = await db.query(
      `SELECT id, tenant_id, file_path, attempts, max_attempts
       FROM file_cleanup_queue
       WHERE status = 'pending' AND next_run_at <= NOW() AND attempts < max_attempts
       ORDER BY next_run_at ASC
       LIMIT 50`
    );

    if (!rows || rows.length === 0) return;

    for (const item of rows) {
      try {
        if (fs.existsSync(item.file_path)) {
          fs.unlinkSync(item.file_path);
        }
        await db.query(
          `UPDATE file_cleanup_queue SET status = 'completed', updated_at = NOW() WHERE id = ?`,
          [item.id]
        );
        console.log(`[FILE_CLEANUP] Successfully unlinked queued file: ${item.file_path}`);
      } catch (err) {
        const nextAttempts = item.attempts + 1;
        if (nextAttempts >= item.max_attempts) {
          console.error(`[FILE_CLEANUP] Giving up on file ${item.file_path} after ${nextAttempts} attempts:`, err.message);
          await db.query(
            `UPDATE file_cleanup_queue SET status = 'failed', attempts = ?, error_message = ?, updated_at = NOW() WHERE id = ?`,
            [nextAttempts, err.message, item.id]
          );
        } else {
          const delaySeconds = Math.pow(2, nextAttempts);
          await db.query(
            `UPDATE file_cleanup_queue
             SET attempts = ?, error_message = ?, next_run_at = DATE_ADD(NOW(), INTERVAL ? SECOND), updated_at = NOW()
             WHERE id = ?`,
            [nextAttempts, err.message, delaySeconds, item.id]
          );
          console.warn(`[FILE_CLEANUP] Attempt ${nextAttempts} failed for ${item.file_path}: ${err.message}. Retrying in ${delaySeconds}s.`);
        }
      }
    }
  } catch (err) {
    console.error('[FILE_CLEANUP] Queue processing error:', err.message);
  }
}

function startCleanupWorker(intervalMs = 3000) {
  // Process immediately on startup/boot
  processFileCleanupQueue().catch(() => {});
  ensureWorker(intervalMs);
}

function stopCleanupWorker() {
  if (retryInterval) {
    clearInterval(retryInterval);
    retryInterval = null;
  }
}

function ensureWorker(intervalMs = 3000) {
  if (!retryInterval) {
    retryInterval = setInterval(processFileCleanupQueue, intervalMs);
    if (retryInterval.unref) retryInterval.unref();
  }
}

module.exports = {
  queueFileCleanupRetry,
  processFileCleanupQueue,
  startCleanupWorker,
  stopCleanupWorker,
  ensureCleanupTable
};

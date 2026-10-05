// server/src/utils/fileCleanupQueue.js
/**
 * In-memory retry queue for files that fail unlinking after a database transaction commits.
 * Retries unlinking with exponential backoff up to 5 times.
 */
const fs = require('fs');

const retryQueue = [];
let retryInterval = null;

function queueFileCleanupRetry(filePath) {
  retryQueue.push({ filePath, attempts: 0, nextAttempt: Date.now() + 1000 });
  ensureWorker();
}

function processRetryQueue() {
  const now = Date.now();
  for (let i = retryQueue.length - 1; i >= 0; i--) {
    const item = retryQueue[i];
    if (now >= item.nextAttempt) {
      try {
        if (fs.existsSync(item.filePath)) {
          fs.unlinkSync(item.filePath);
        }
        retryQueue.splice(i, 1);
      } catch (err) {
        item.attempts++;
        if (item.attempts >= 5) {
          console.error(`[FILE_CLEANUP] Giving up on file ${item.filePath} after 5 attempts:`, err.message);
          retryQueue.splice(i, 1);
        } else {
          item.nextAttempt = now + Math.pow(2, item.attempts) * 2000;
        }
      }
    }
  }
  if (retryQueue.length === 0 && retryInterval) {
    clearInterval(retryInterval);
    retryInterval = null;
  }
}

function ensureWorker() {
  if (!retryInterval) {
    retryInterval = setInterval(processRetryQueue, 2000);
    if (retryInterval.unref) retryInterval.unref();
  }
}

module.exports = { queueFileCleanupRetry, getRetryQueue: () => retryQueue };

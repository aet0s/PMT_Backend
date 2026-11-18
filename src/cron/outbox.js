// server/src/cron/outbox.js
// Automated background worker for reliable notification outbox delivery,
// stuck processing record recovery, and periodic nonce/rate-limit cleanup.

const { getMasterDb, getTenantDb, getDevSingleDb } = require('../services/tenantPools');
const { processOutbox } = require('../services/notificationOutbox');
const { cleanupExpiredNonces } = require('../secure/replayStore');
const { cleanupExpiredRateLimits } = require('../middleware/rateLimit');

let isRunning = false;
let outboxTimer = null;
let cleanupTimer = null;

async function processAllTenantsOutbox() {
  if (isRunning) return;
  isRunning = true;

  try {
    if (process.env.DEV_SINGLE_TENANT === '1') {
      try {
        const db = getDevSingleDb();
        if (db) {
          await processOutbox(db, 'single');
        }
      } catch (err) {
        console.error('[OUTBOX-CRON] Single tenant sweep error:', err.message);
      }
      return;
    }

    let masterDb;
    try {
      masterDb = getMasterDb();
    } catch (_) {
      return;
    }

    const tenants = await masterDb.query(
      "SELECT id, slug FROM tenants WHERE status = 'active'"
    );

    if (!Array.isArray(tenants)) return;

    for (const tenant of tenants) {
      try {
        const tenantDb = await getTenantDb(tenant.id);
        if (tenantDb) {
          await processOutbox(tenantDb, tenant.id);
        }
      } catch (tenantErr) {
        console.error(`[OUTBOX-CRON] Sweep error for tenant ${tenant.slug}:`, tenantErr.message);
      }
    }
  } catch (err) {
    console.error('[OUTBOX-CRON] Global sweep error:', err.message);
  } finally {
    isRunning = false;
  }
}

async function runPeriodicCleanups() {
  try {
    await cleanupExpiredNonces();
    await cleanupExpiredRateLimits();
  } catch (err) {
    console.error('[CLEANUP-CRON] Periodic cleanup error:', err.message);
  }
}

function initOutboxCron(intervalMs = 15000) {
  if (outboxTimer) clearInterval(outboxTimer);
  if (cleanupTimer) clearInterval(cleanupTimer);

  // Poll outbox every 15 seconds
  outboxTimer = setInterval(processAllTenantsOutbox, intervalMs);
  if (outboxTimer.unref) outboxTimer.unref();

  // Nonce and rate limit cleanup every 5 minutes
  cleanupTimer = setInterval(runPeriodicCleanups, 5 * 60 * 1000);
  if (cleanupTimer.unref) cleanupTimer.unref();

  // Run immediate initial check
  const t1 = setTimeout(processAllTenantsOutbox, 2000);
  if (t1.unref) t1.unref();
  const t2 = setTimeout(runPeriodicCleanups, 5000);
  if (t2.unref) t2.unref();

  console.log('[CRON] Notification outbox background worker & periodic cleanup initialized.');
}

module.exports = {
  processAllTenantsOutbox,
  runPeriodicCleanups,
  initOutboxCron
};

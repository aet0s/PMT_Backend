// server/src/cron/retention.js
// Daily notification retention cleanup job across all tenants.
// Automatically purges read notifications older than 30 days.
const cron = require('node-cron');
const { cleanOldNotifications } = require('../services/notificationOutbox');
const { getMasterDb, getTenantDb, getDevSingleDb } = require('../services/tenantPools');

async function runTenantRetention(db, tenantId = null) {
  if (!db) return 0;
  return await cleanOldNotifications(db);
}

async function processAllTenantsRetention() {
  if (process.env.DEV_SINGLE_TENANT === '1') {
    const singleDb = getDevSingleDb();
    const purged = await runTenantRetention(singleDb);
    return purged;
  }

  let totalPurged = 0;
  try {
    const masterDb = getMasterDb();
    const tenants = await masterDb.query(
      "SELECT id, slug, db_name FROM tenants WHERE status = 'active'"
    );

    const BATCH_SIZE = 5;
    for (let i = 0; i < tenants.length; i += BATCH_SIZE) {
      const batch = tenants.slice(i, i + BATCH_SIZE);
      const results = await Promise.all(
        batch.map(async (tenant) => {
          try {
            const tenantDb = await getTenantDb(tenant.id);
            return await runTenantRetention(tenantDb, tenant.id);
          } catch (tenantErr) {
            console.error(`[RETENTION ERROR] Cleanup failed for tenant ${tenant.slug}:`, tenantErr.message);
            return 0;
          }
        })
      );
      totalPurged += results.reduce((acc, count) => acc + count, 0);
    }
  } catch (err) {
    console.error('[RETENTION ERROR] Error querying active tenants for retention:', err.message);
  }
  return totalPurged;
}

function initRetentionCron() {
  // Run daily at 03:00 AM: '0 3 * * *'
  cron.schedule('0 3 * * *', async () => {
    try {
      const count = await processAllTenantsRetention();
      if (count > 0) {
        console.log(`[RETENTION] Purged ${count} old read notifications across active tenants.`);
      }
    } catch (err) {
      console.error('Error running notification retention cron:', err);
    }
  });

  console.log('Notification retention cron job initialized (daily at 03:00 AM).');
}

module.exports = {
  initRetentionCron,
  processAllTenantsRetention,
  runTenantRetention
};

// server/src/cron/autoArchive.js
// Automated background auto-archive sweep across all tenants and workspaces.
// Automatically archives completed tasks older than the workspace's configured threshold.

const cron = require('node-cron');
const { getMasterDb, getTenantDb, getDevSingleDb } = require('../services/tenantPools');
const { broadcastWorkspaceEvent } = require('../socket');
const auditService = require('../services/audit');

/**
 * Executes the auto-archive sweep for a specific workspace.
 * @param {object} params
 * @param {object} params.db - Active database pool
 * @param {number} params.workspaceId - ID of the workspace
 * @param {number} [params.days=7] - Number of days threshold (0 = immediate)
 * @param {number|null} [params.actorId=null] - User ID if triggered manually, null if system cron
 * @param {string|null} [params.originId=null] - Socket origin ID to prevent echo
 * @param {number|null} [params.tenantId=null] - Tenant ID for socket broadcasting
 * @returns {Promise<{ archived_count: number, card_ids: number[], days: number }>}
 */
async function executeAutoArchiveSweep({ db, workspaceId, days = 7, actorId = null, originId = null, tenantId = null }) {
  if (!db || !workspaceId) return { archived_count: 0, card_ids: [], days };

  const numDays = Math.max(0, Number(days) || 0);
  let intervalClause = '';
  const params = [workspaceId];

  if (numDays > 0) {
    intervalClause = 'AND COALESCE(c.completed_at, c.created_at) < DATE_SUB(NOW(), INTERVAL ? DAY)';
    params.push(numDays);
  }

  const cardsToArchive = await db.query(
    `SELECT c.id, c.title, l.board_id
     FROM cards c
     JOIN lists l ON c.list_id = l.id
     JOIN boards b ON l.board_id = b.id
     WHERE b.workspace_id = ?
       AND (c.is_complete = 1 OR l.is_done_list = 1 OR LOWER(TRIM(l.name)) IN ('done', 'completed', 'finished', 'closed', 'archive', 'archived'))
       AND c.is_archived = 0
       ${intervalClause}`,
    params
  );

  if (!cardsToArchive || cardsToArchive.length === 0) {
    return { archived_count: 0, card_ids: [], days: numDays };
  }

  const cardIds = cardsToArchive.map((c) => c.id);
  await db.query(
    `UPDATE cards SET is_archived = 1 WHERE id IN (${cardIds.map(() => '?').join(',')})`,
    cardIds
  );

  for (const card of cardsToArchive) {
    broadcastWorkspaceEvent(workspaceId, 'card:archived', { cardId: card.id, boardId: card.board_id }, originId, tenantId);
  }

  await auditService.record({
    action: 'workspace.auto_archive',
    category: 'task',
    entityType: 'workspace',
    entityId: workspaceId,
    entityLabel: `Auto-archived ${cardsToArchive.length} completed task(s)`,
    outcome: 'success',
    severity: 'info',
    actorId: actorId || null,
    meta: {
      archivedCount: cardsToArchive.length,
      days: numDays,
      cardIds,
      triggeredBy: actorId ? 'manual' : 'scheduled_cron'
    },
    db
  }).catch(() => { });

  return {
    archived_count: cardsToArchive.length,
    card_ids: cardIds,
    days: numDays
  };
}

/**
 * Runs auto-archive sweep on all workspaces within a given tenant database.
 */
async function processTenantAutoArchive(db, tenantId = null) {
  if (!db) return 0;
  let totalArchived = 0;

  try {
    const workspaces = await db.query('SELECT id, settings FROM workspaces WHERE is_archived = 0');
    for (const ws of workspaces) {
      let settings = {};
      try {
        settings = typeof ws.settings === 'string' ? JSON.parse(ws.settings) : (ws.settings || {});
      } catch {
        settings = {};
      }

      const archiveSetting = settings?.workspace_defaults?.autoArchiveDays ??
                             settings?.project_defaults?.autoArchiveDays ??
                             '7';

      if (archiveSetting === 'never') {
        continue;
      }

      const days = Number(archiveSetting);
      if (isNaN(days) || days < 0) continue;

      const result = await executeAutoArchiveSweep({
        db,
        workspaceId: ws.id,
        days,
        actorId: null,
        originId: null,
        tenantId
      });

      totalArchived += result.archived_count;
    }
  } catch (err) {
    console.error(`[AUTO-ARCHIVE ERROR] Failed to process workspaces for tenant ${tenantId}:`, err.message);
  }

  return totalArchived;
}

/**
 * Iterates through all active tenants and performs the auto-archive sweep.
 */
async function processAllTenantsAutoArchive() {
  if (process.env.DEV_SINGLE_TENANT === '1') {
    const singleDb = getDevSingleDb();
    return await processTenantAutoArchive(singleDb);
  }

  let totalArchived = 0;
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
            return await processTenantAutoArchive(tenantDb, tenant.id);
          } catch (tenantErr) {
            console.error(`[AUTO-ARCHIVE ERROR] Sweep failed for tenant ${tenant.slug}:`, tenantErr.message);
            return 0;
          }
        })
      );
      totalArchived += results.reduce((acc, count) => acc + count, 0);
    }
  } catch (err) {
    console.error('[AUTO-ARCHIVE ERROR] Error querying active tenants:', err.message);
  }

  return totalArchived;
}

/**
 * Initializes the automated auto-archive cron job.
 * Runs hourly at minute 20.
 */
function initAutoArchiveCron() {
  // Schedule every hour at :20 ('20 * * * *')
  cron.schedule('20 * * * *', async () => {
    try {
      const count = await processAllTenantsAutoArchive();
      if (count > 0) {
        console.log(`[AUTO-ARCHIVE] Successfully archived ${count} completed task(s) across active tenants.`);
      }
    } catch (err) {
      console.error('[AUTO-ARCHIVE] Cron execution failed:', err.message);
    }
  });

  console.log('[CRON] Auto-archive scheduled job initialized (hourly at :20).');
}

module.exports = {
  executeAutoArchiveSweep,
  processTenantAutoArchive,
  processAllTenantsAutoArchive,
  initAutoArchiveCron
};

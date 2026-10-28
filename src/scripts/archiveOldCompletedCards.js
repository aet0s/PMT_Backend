// server/src/scripts/archiveOldCompletedCards.js
// CLI script to sweep and archive completed cards older than N days (default: 7) across all tenants.

const { getMasterDb, getTenantDb, getDevSingleDb } = require('../services/tenantPools');
const { executeAutoArchiveSweep } = require('../cron/autoArchive');

async function main() {
  const daysArg = process.argv[2] !== undefined ? Number(process.argv[2]) : 7;
  const days = isNaN(daysArg) ? 7 : Math.max(0, daysArg);

  console.log('================================================================');
  console.log(`   LIVE SWEEP: AUTO-ARCHIVING COMPLETED CARDS OLDER THAN ${days} DAYS`);
  console.log('================================================================\n');

  if (process.env.DEV_SINGLE_TENANT === '1') {
    const singleDb = getDevSingleDb();
    const workspaces = await singleDb.query('SELECT id, name FROM workspaces WHERE is_archived = 0');
    let total = 0;
    for (const ws of workspaces) {
      const res = await executeAutoArchiveSweep({ db: singleDb, workspaceId: ws.id, days });
      if (res.archived_count > 0) {
        console.log(`[DEV_SINGLE] Workspace '${ws.name}' (ID: ${ws.id}): Archived ${res.archived_count} card(s).`);
        total += res.archived_count;
      }
    }
    console.log(`\nCompleted. Total cards archived: ${total}`);
    process.exit(0);
  }

  const masterDb = getMasterDb();
  const tenants = await masterDb.query("SELECT id, slug, db_name FROM tenants WHERE status = 'active'");
  console.log(`Found ${tenants.length} active tenant(s).\n`);

  let grandTotal = 0;

  for (const tenant of tenants) {
    try {
      const tenantDb = await getTenantDb(tenant.id);
      const workspaces = await tenantDb.query('SELECT id, name FROM workspaces WHERE is_archived = 0');
      let tenantArchived = 0;

      for (const ws of workspaces) {
        const res = await executeAutoArchiveSweep({
          db: tenantDb,
          workspaceId: ws.id,
          days,
          actorId: null,
          originId: null,
          tenantId: tenant.id
        });

        if (res.archived_count > 0) {
          console.log(`  ✓ Tenant [${tenant.slug}] - Workspace '${ws.name}' (ID: ${ws.id}): Archived ${res.archived_count} card(s).`);
          tenantArchived += res.archived_count;
        }
      }

      grandTotal += tenantArchived;
      if (tenantArchived > 0) {
        console.log(`Tenant [${tenant.slug}] subtotal: ${tenantArchived} card(s) archived.\n`);
      }
    } catch (err) {
      console.error(`  ✖ Failed processing tenant [${tenant.slug}]:`, err.message);
    }
  }

  console.log('----------------------------------------------------------------');
  console.log(`Sweep completed successfully. Grand total archived: ${grandTotal} card(s).`);
  console.log('================================================================\n');
  process.exit(0);
}

main().catch((err) => {
  console.error('Fatal error during archive sweep:', err);
  process.exit(1);
});

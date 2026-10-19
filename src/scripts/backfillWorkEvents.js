// server/src/scripts/backfillWorkEvents.js
// Idempotent backfill script for Daily Tracker v2 work events and columns.
// Usage: node src/scripts/backfillWorkEvents.js --tenant <slug> (--dry-run | --apply)
// Or via npm: npm run work_events:backfill -- --tenant <slug> (--dry-run | --apply)

require('dotenv').config({ path: require('path').resolve(__dirname, '../../../.env') });
const { getMasterDb, getTenantDb, closeAllTenantPools } = require('../services/tenantPools');

async function main() {
  const args = process.argv.slice(2);
  let tenantSlug = null;
  let isDryRun = false;
  let isApply = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--tenant' && args[i + 1]) {
      tenantSlug = args[i + 1];
      i++;
    } else if (args[i] === '--dry-run') {
      isDryRun = true;
    } else if (args[i] === '--apply') {
      isApply = true;
    }
  }

  if (!tenantSlug) {
    console.error('ERROR: Missing required --tenant <slug> parameter.');
    console.error('Usage: node src/scripts/backfillWorkEvents.js --tenant <slug> (--dry-run | --apply)');
    process.exit(1);
  }

  if ((!isDryRun && !isApply) || (isDryRun && isApply)) {
    console.error('ERROR: You must specify exactly one of --dry-run or --apply.');
    process.exit(1);
  }

  console.log('================================================================');
  console.log(`  WORK EVENTS BACKFILL: Tenant [${tenantSlug}] (Mode: ${isApply ? 'APPLY' : 'DRY-RUN'})`);
  console.log('================================================================\n');

  const masterDb = getMasterDb();
  const [tRows] = await masterDb.query('SELECT * FROM tenants WHERE slug = ?', [tenantSlug]);
  if (!tRows || tRows.length === 0) {
    console.error(`ERROR: Tenant with slug '${tenantSlug}' not found.`);
    process.exit(1);
  }

  const tenant = tRows[0];
  const db = await getTenantDb(tenant.id);

  console.log(`Found tenant: ID ${tenant.id}, DB: ${tenant.db_name}`);

  // 1. Snapshot if applying
  if (isApply) {
    const timestamp = Date.now();
    console.log(`[SNAPSHOT] Creating snapshot table cards_snapshot_${timestamp}...`);
    await db.execute(`CREATE TABLE IF NOT EXISTS cards_snapshot_${timestamp} AS SELECT * FROM cards`);
    console.log(`[SNAPSHOT] Snapshot cards_snapshot_${timestamp} created successfully.`);
  }

  // 2. Backfill lists.is_done_list
  const listsToUpdate = await db.query(
    `SELECT id, name FROM lists
     WHERE is_done_list = 0
       AND (LOWER(name) LIKE '%done%' OR LOWER(name) LIKE '%completed%')
       AND LOWER(name) NOT LIKE '%not done%'`
  );
  console.log(`[LISTS] Found ${listsToUpdate.length} lists to mark as is_done_list = 1.`);

  // 3. Backfill cards.completed_at and completed_by
  const cardsToComplete = await db.query(
    `SELECT c.id, c.title, c.is_complete, l.is_done_list
     FROM cards c
     JOIN lists l ON c.list_id = l.id
     WHERE (c.is_complete = 1 OR l.is_done_list = 1)
       AND (c.completed_at IS NULL OR c.completed_by IS NULL)`
  );
  console.log(`[CARDS] Found ${cardsToComplete.length} completed cards missing completed_at or completed_by.`);

  // 4. Backfill cards.first_moved_or_assigned_at
  const cardsToFirstMoved = await db.query(
    `SELECT id, title, created_at FROM cards WHERE first_moved_or_assigned_at IS NULL`
  );
  console.log(`[CARDS] Found ${cardsToFirstMoved.length} cards missing first_moved_or_assigned_at.`);

  // 5. Backfill checklist_items.created_by
  const itemsToBackfill = await db.query(
    `SELECT id FROM checklist_items WHERE created_by IS NULL`
  );
  console.log(`[CHECKLIST] Found ${itemsToBackfill.length} checklist items missing created_by.`);

  if (isApply) {
    console.log('\n[APPLY] Executing backfill updates...');

    if (listsToUpdate.length > 0) {
      await db.execute(
        `UPDATE lists
         SET is_done_list = 1
         WHERE (LOWER(name) LIKE '%done%' OR LOWER(name) LIKE '%completed%')
           AND LOWER(name) NOT LIKE '%not done%'`
      );
      console.log(`  ✓ Updated ${listsToUpdate.length} lists.`);
    }

    if (cardsToComplete.length > 0) {
      await db.execute(
        `UPDATE cards c
         JOIN lists l ON c.list_id = l.id
         SET c.completed_at = COALESCE(c.completed_at, c.created_at),
             c.completed_by = COALESCE(c.completed_by, c.created_by)
         WHERE (c.is_complete = 1 OR l.is_done_list = 1)
           AND (c.completed_at IS NULL OR c.completed_by IS NULL)`
      );
      console.log(`  ✓ Updated ${cardsToComplete.length} completed cards.`);
    }

    if (cardsToFirstMoved.length > 0) {
      await db.execute(
        `UPDATE cards
         SET first_moved_or_assigned_at = created_at
         WHERE first_moved_or_assigned_at IS NULL`
      );
      console.log(`  ✓ Updated ${cardsToFirstMoved.length} cards with first_moved_or_assigned_at.`);
    }

    if (itemsToBackfill.length > 0) {
      await db.execute(
        `UPDATE checklist_items ci
         JOIN checklists ch ON ci.checklist_id = ch.id
         JOIN cards c ON ch.card_id = c.id
         SET ci.created_by = c.created_by
         WHERE ci.created_by IS NULL`
      );
      console.log(`  ✓ Updated ${itemsToBackfill.length} checklist items with card creator.`);
    }

    console.log('\n🎉 BACKFILL COMPLETED SUCCESSFULLY!');
  } else {
    console.log('\n[DRY-RUN] No database modifications were made.');
  }

  await closeAllTenantPools();
  process.exit(0);
}

main().catch((err) => {
  console.error('FATAL Backfill Error:', err);
  process.exit(1);
});

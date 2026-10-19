#!/usr/bin/env node
// server/src/scripts/backfillDoneLists.js
// Marks existing lists named exactly Done/Completed (case-insensitive) as done lists (is_done_list = 1).
// Supports --dry-run (default) and --apply modes.
// Measures completed card counts before and after to prove they do not drop.

require('dotenv').config();
const { getMasterDb, getTenantDb, closeAllPools } = require('../services/tenantPools');

async function runBackfill() {
  const isApply = process.argv.includes('--apply');
  const isDryRun = !isApply || process.argv.includes('--dry-run');

  console.log('================================================================');
  console.log(`   DONE LISTS BACKFILL (${isDryRun ? 'DRY-RUN MODE' : 'LIVE APPLY MODE'})   `);
  console.log('================================================================\n');

  const masterDb = getMasterDb();
  const [apolloTenant] = await masterDb.query(
    "SELECT id, slug, name, db_name FROM tenants WHERE slug = 'apollo' OR slug = 'apollo_corp' LIMIT 1"
  );

  if (!apolloTenant) {
    console.error('Apollo tenant not found in master registry!');
    process.exit(1);
  }

  console.log(`Target Tenant: ${apolloTenant.name} (Slug: ${apolloTenant.slug}, DB: ${apolloTenant.db_name})\n`);
  const tenantDb = await getTenantDb(apolloTenant.id);

  // 1. Completed count BEFORE
  const [beforeCountRow] = await tenantDb.query(`
    SELECT COUNT(DISTINCT c.id) as count
    FROM cards c
    JOIN lists l ON c.list_id = l.id
    WHERE c.is_archived = 0
      AND (c.is_complete = 1 OR l.is_done_list = 1)
  `);
  const beforeCount = beforeCountRow.count;
  console.log(`[BEFORE] Total completed cards on Apollo: ${beforeCount}`);

  // 2. Identify candidate lists named exactly 'Done' or 'Completed' (case-insensitive)
  const candidateLists = await tenantDb.query(`
    SELECT l.id, l.name, l.board_id, b.name as board_name, l.is_done_list,
           COUNT(c.id) as card_count
    FROM lists l
    JOIN boards b ON l.board_id = b.id
    LEFT JOIN cards c ON l.id = c.list_id AND c.is_archived = 0
    WHERE LOWER(TRIM(l.name)) IN ('done', 'completed')
    GROUP BY l.id, l.name, l.board_id, b.name, l.is_done_list
    ORDER BY l.board_id, l.id
  `);

  console.log(`Found ${candidateLists.length} list(s) named exactly Done/Completed:\n`);
  const listsToMark = [];

  for (const list of candidateLists) {
    const alreadyMarked = list.is_done_list === 1;
    const statusStr = alreadyMarked ? 'ALREADY MARKED (is_done_list = 1)' : 'WILL BE MARKED (is_done_list -> 1)';
    console.log(`  - List #${list.id} "${list.name}" on Board #${list.board_id} ("${list.board_name}"): ${list.card_count} active cards. [${statusStr}]`);
    if (!alreadyMarked) {
      listsToMark.push(list);
    }
  }

  console.log(`\nLists requiring update: ${listsToMark.length}`);

  if (isDryRun) {
    console.log('\n[DRY RUN] No database writes performed. Pass --apply to execute updates.');
    console.log(`[BEFORE] Completed cards: ${beforeCount}`);
    console.log(`[ESTIMATED AFTER] Completed cards will be >= ${beforeCount} (strictly non-decreasing).`);
  } else {
    // 3. Apply updates
    if (listsToMark.length > 0) {
      const ids = listsToMark.map((l) => l.id);
      await tenantDb.query(
        `UPDATE lists SET is_done_list = 1 WHERE id IN (${ids.map(() => '?').join(',')})`,
        ids
      );
      console.log(`\n✓ Successfully marked ${listsToMark.length} list(s) as is_done_list = 1.`);
    }

    // 4. Completed count AFTER
    const [afterCountRow] = await tenantDb.query(`
      SELECT COUNT(DISTINCT c.id) as count
      FROM cards c
      JOIN lists l ON c.list_id = l.id
      WHERE c.is_archived = 0
        AND (c.is_complete = 1 OR l.is_done_list = 1)
    `);
    const afterCount = afterCountRow.count;
    console.log(`\n[AFTER] Total completed cards on Apollo: ${afterCount}`);

    if (afterCount >= beforeCount) {
      console.log(`✓ VERIFIED: Completed counts did not drop (${beforeCount} -> ${afterCount}, change: +${afterCount - beforeCount}).\n`);
    } else {
      console.error(`❌ REGRESSION: Completed counts dropped from ${beforeCount} to ${afterCount}!`);
      process.exit(1);
    }
  }

  await closeAllPools();
}

runBackfill().catch((err) => {
  console.error('Backfill error:', err);
  process.exit(1);
});

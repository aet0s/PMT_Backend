// server/src/scripts/backupAndMigrateDailyTrackerV3.js
// Exports any remaining card_focus rows to server/snapshots/, applies migration 0046
// idempotently across all tenant DBs, and verifies backfill row counts.
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const { getMasterDb, getTenantDb, getDevSingleDb } = require('../services/tenantPools');

async function runOnDb(db, dbName, label, migrationSql) {
  console.log(`\n--- [${label}] ---`);

  // 1. Snapshot card_focus if it exists
  const [tbl] = await db.query(
    `SELECT COUNT(*) AS cnt FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'card_focus'`
  );
  if (Number(tbl?.cnt || 0) > 0) {
    const rows = await db.query('SELECT * FROM card_focus');
    console.log(`card_focus exists with ${rows.length} row(s).`);
    if (rows.length > 0) {
      const snapDir = path.resolve(__dirname, '../../snapshots');
      if (!fs.existsSync(snapDir)) fs.mkdirSync(snapDir, { recursive: true });
      const snapFile = path.join(snapDir, `card_focus_backup_${label.replace(/[^a-zA-Z0-9_-]/g, '_')}_${Date.now()}.json`);
      fs.writeFileSync(snapFile, JSON.stringify({ database: label, count: rows.length, rows }, null, 2));
      console.log(`Backed up card_focus rows to ${snapFile}`);
    }
  } else {
    console.log('card_focus table already absent.');
  }

  // 2. Count check_ins before migration
  const [preCi] = await db.query('SELECT COUNT(*) AS cnt FROM check_ins');
  const [preGroups] = await db.query(
    `SELECT COUNT(*) AS cnt FROM (
       SELECT b.workspace_id, ci.user_id, ci.work_date
       FROM check_ins ci
       JOIN cards c ON ci.card_id = c.id
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       GROUP BY b.workspace_id, ci.user_id, ci.work_date
     ) t`
  );

  // 3. Execute migration 0046 using multipleStatements connection
  const conn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || '',
    database: dbName,
    multipleStatements: true,
    timezone: '+00:00',
    charset: 'utf8mb4'
  });
  try {
    await conn.query(migrationSql);
    const checksum = crypto.createHash('sha256').update(migrationSql, 'utf8').digest('hex');
    await conn.query(
      `INSERT INTO schema_migrations (version, name, checksum, applied_at)
       VALUES ('0046', '0046_daily_tracker_v3_unified_updates.sql', ?, NOW())
       ON DUPLICATE KEY UPDATE checksum = VALUES(checksum)`,
      [checksum]
    );
  } finally {
    await conn.end();
  }

  // 4. Verify post-migration counts
  const [postDu] = await db.query('SELECT COUNT(*) AS cnt FROM daily_updates');
  const [postDui] = await db.query('SELECT COUNT(*) AS cnt FROM daily_update_items');
  const [postFocus] = await db.query(
    `SELECT COUNT(*) AS cnt FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'card_focus'`
  );

  console.log(
    `Verification [${label}]: check_ins=${preCi.cnt}, expected_groups=${preGroups.cnt}, daily_updates=${postDu.cnt}, daily_update_items=${postDui.cnt}, card_focus_exists=${postFocus.cnt}`
  );

  return {
    label,
    check_ins: Number(preCi.cnt),
    expected_groups: Number(preGroups.cnt),
    daily_updates: Number(postDu.cnt),
    daily_update_items: Number(postDui.cnt),
    card_focus_exists: Number(postFocus.cnt)
  };
}

async function main() {
  const migPath = path.resolve(__dirname, '../db/migrations/tenant/0046_daily_tracker_v3_unified_updates.sql');
  const migrationSql = fs.readFileSync(migPath, 'utf8');
  const results = [];

  if (process.env.DEV_SINGLE_TENANT === '1') {
    const db = getDevSingleDb();
    results.push(await runOnDb(db, process.env.MYSQL_DATABASE || 'pm_dev_single', 'dev_single', migrationSql));
  } else {
    try {
      const singleDb = getDevSingleDb();
      results.push(await runOnDb(singleDb, process.env.MYSQL_DATABASE || 'pm_dev_single', 'pm_dev_single', migrationSql));
    } catch (e) {
      console.log('Skipping pm_dev_single:', e.message);
    }

    const masterDb = getMasterDb();
    const tenants = await masterDb.query("SELECT id, slug, db_name FROM tenants WHERE status = 'active'");
    for (const t of tenants) {
      try {
        const tDb = await getTenantDb(t.id);
        results.push(await runOnDb(tDb, t.db_name, `${t.slug} (${t.db_name})`, migrationSql));
      } catch (err) {
        console.error(`Failed on tenant ${t.slug}:`, err.message);
      }
    }
  }

  console.log('\n=== Migration 0046 Summary ===');
  console.table(results);
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

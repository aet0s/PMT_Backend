#!/usr/bin/env node
// server/src/scripts/resetLiveDb.js
// Completely clears all project management databases and initializes a clean pm_master.
// - Drops all tenant databases matching pm_t_*
// - Drops all test databases matching pm_test_*
// - Drops pm_dev_single
// - Recreates pm_master with utf8mb4 collation
// - Applies all migrations to pm_master

require('dotenv').config();
const mysql = require('mysql2/promise');
const { migrateMaster } = require('../db/migrator');
const { closeAllPools } = require('../services/tenantPools');

async function resetLiveDatabase() {
  console.log('\n======================================================');
  console.log('   PMT Database Reset - Clean Slate for Production    ');
  console.log('======================================================\n');

  const host = process.env.MYSQL_HOST || '127.0.0.1';
  const port = Number(process.env.MYSQL_PORT || 3306);
  const user = process.env.MYSQL_USER || 'root';
  const password = process.env.MYSQL_PASSWORD !== undefined ? process.env.MYSQL_PASSWORD : '';
  const masterDbName = process.env.MYSQL_MASTER_DATABASE || 'pm_master';

  console.log(`Connecting to MySQL on ${host}:${port} as ${user}...`);

  const conn = await mysql.createConnection({ host, port, user, password });

  try {
    const [rows] = await conn.query('SHOW DATABASES');
    const allDbs = rows.map((r) => Object.values(r)[0]);

    // 1. Drop all tenant and test databases
    const targetDbs = allDbs.filter(
      (name) => name.startsWith('pm_t_') || name.startsWith('pm_test_') || name === 'pm_dev_single'
    );

    if (targetDbs.length > 0) {
      console.log(`[1/3] Dropping ${targetDbs.length} existing tenant/dev databases:`);
      for (const dbName of targetDbs) {
        console.log(`  - Dropping \`${dbName}\`...`);
        await conn.query(`DROP DATABASE IF EXISTS \`${dbName}\``);
      }
      console.log('  ✓ All tenant/dev databases dropped.\n');
    } else {
      console.log('[1/3] No existing tenant (pm_t_*) databases found to drop.\n');
    }

    // 2. Drop and recreate master database
    console.log(`[2/3] Resetting master database \`${masterDbName}\`...`);
    await conn.query(`DROP DATABASE IF EXISTS \`${masterDbName}\``);
    await conn.query(`CREATE DATABASE \`${masterDbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    console.log(`  ✓ Master database \`${masterDbName}\` created cleanly.\n`);

    // 3. Run master migrations
    console.log(`[3/3] Running master migrations on \`${masterDbName}\`...`);
    await migrateMaster();
    console.log(`  ✓ All master schema migrations applied successfully.\n`);

    console.log('======================================================');
    console.log('✓ SUCCESS: Database server is completely fresh!');
    console.log(`  - Master database: \`${masterDbName}\` is initialized and ready.`);
    console.log('  - All registrations on pmt.solarman.in will now create fresh `pm_t_*` databases.');
    console.log('======================================================\n');
  } catch (err) {
    console.error('\n❌ ERROR resetting database:', err.message);
    process.exit(1);
  } finally {
    await conn.end();
    await closeAllPools();
  }
}

if (require.main === module) {
  resetLiveDatabase()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}

module.exports = { resetLiveDatabase };

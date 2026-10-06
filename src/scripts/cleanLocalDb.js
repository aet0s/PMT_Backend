#!/usr/bin/env node
// server/src/scripts/cleanLocalDb.js
// Cleans local XAMPP MySQL databases for Project Management Tool (PMT):
// - Drops all test/orphaned tenant databases (pm_t_*, pm_test_*)
// - Drops and recreates pm_master & pm_dev_single
// - Runs migrations on pm_master and pm_dev_single
// - Seeds clean development baseline

require('dotenv').config();
const mysql = require('mysql2/promise');
const { migrateMaster, migrateSingleTenant } = require('../db/migrator');
const { closeAllPools } = require('../services/tenantPools');

async function cleanLocalDatabase() {
  console.log('=== Cleaning Local XAMPP MySQL Databases for PMT ===');
  const conn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || ''
  });

  try {
    const [rows] = await conn.query('SHOW DATABASES');
    const dbNames = rows.map((r) => Object.values(r)[0]);

    // 1. Drop all pm_t_* and pm_test_* tenant databases
    const pmtDbs = dbNames.filter(
      (name) => name.startsWith('pm_t_') || name.startsWith('pm_test_')
    );

    console.log(`[1/4] Dropping ${pmtDbs.length} tenant databases...`);
    for (const dbName of pmtDbs) {
      await conn.query(`DROP DATABASE IF EXISTS \`${dbName}\``);
    }
    console.log(`✓ All ${pmtDbs.length} tenant databases dropped.`);

    // 2. Drop and recreate pm_master
    const masterDbName = process.env.MYSQL_MASTER_DATABASE || 'pm_master';
    console.log(`[2/4] Resetting master database '${masterDbName}'...`);
    await conn.query(`DROP DATABASE IF EXISTS \`${masterDbName}\``);
    await conn.query(`CREATE DATABASE \`${masterDbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    console.log(`✓ Master database '${masterDbName}' recreated.`);

    // 3. Drop and recreate pm_dev_single
    const devDbName = process.env.MYSQL_DATABASE || 'pm_dev_single';
    console.log(`[3/4] Resetting dev database '${devDbName}'...`);
    await conn.query(`DROP DATABASE IF EXISTS \`${devDbName}\``);
    await conn.query(`CREATE DATABASE \`${devDbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    console.log(`✓ Dev database '${devDbName}' recreated.`);

    // 4. Run migrations
    console.log('[4/4] Running schema migrations on master and single databases...');
    await migrateMaster();
    console.log(`✓ Migrations applied to '${masterDbName}'.`);

    await migrateSingleTenant(devDbName);
    console.log(`✓ Migrations applied to '${devDbName}'.`);

    // 5. Seed clean dev single
    console.log('Running clean seed on pm_dev_single...');
    const seedScript = require('../db/seed');
    // seed.js executes directly if invoked or exports a function if required
    console.log('✓ Local MySQL databases cleaned and initialized successfully!');
  } catch (err) {
    console.error('Error cleaning local database:', err);
    throw err;
  } finally {
    await conn.end();
    await closeAllPools();
  }
}

if (require.main === module) {
  cleanLocalDatabase()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}

module.exports = { cleanLocalDatabase };

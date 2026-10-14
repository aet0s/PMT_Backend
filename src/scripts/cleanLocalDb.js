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

    // 5. Ensure password_resets table on master
    await conn.query(`
      CREATE TABLE IF NOT EXISTS \`${masterDbName}\`.password_resets (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        otp_code VARCHAR(20) NOT NULL,
        otp_hash VARCHAR(255) NOT NULL,
        reset_token VARCHAR(500) NULL,
        attempts INT NOT NULL DEFAULT 0,
        verified TINYINT(1) NOT NULL DEFAULT 0,
        expires_at DATETIME(3) NOT NULL,
        created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        INDEX idx_pr_email (email),
        INDEX idx_pr_expires (expires_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // 6. Run clean seed on single dev database
    try {
      console.log('Running clean seed on dev database...');
      const { execSync } = require('child_process');
      const path = require('path');
      execSync('node src/db/seed.js', {
        stdio: 'inherit',
        cwd: path.resolve(__dirname, '../../')
      });
    } catch (seedErr) {
      console.warn('[WARN] Seed execution note:', seedErr.message);
    }

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

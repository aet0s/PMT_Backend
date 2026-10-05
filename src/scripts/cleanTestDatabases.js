#!/usr/bin/env node
// server/src/scripts/cleanTestDatabases.js
// Cleans up all orphaned test databases matching pm_test_% or pm_t_test_% or pm_t_parta_%

require('dotenv').config();
const mysql = require('mysql2/promise');
const { getMasterDb, closeAllPools } = require('../services/tenantPools');

async function cleanTestDatabases() {
  console.log('=== Cleaning Up Test Databases ===');
  const conn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || ''
  });

  try {
    const [rows] = await conn.query('SHOW DATABASES');
    const dbNames = rows.map((r) => Object.values(r)[0]);

    const testDbs = dbNames.filter(
      (name) =>
        name.startsWith('pm_test_') ||
        name.startsWith('pm_t_parta_') ||
        name.startsWith('pm_t_test_') ||
        name.startsWith('pm_t_collision_') ||
        name.startsWith('pm_t_conc_')
    );

    console.log(`Found ${testDbs.length} test database(s) to remove:`);
    for (const dbName of testDbs) {
      console.log(`  - Dropping ${dbName}...`);
      await conn.query(`DROP DATABASE IF EXISTS \`${dbName}\``);
    }

    // Clean up master registry
    const masterDb = getMasterDb();
    const testSlugs = ['parta_off_corp', 'parta_on_corp', 'collision_a', 'collision_b', 'conc_tenant', 'fail_tenant'];
    for (const slug of testSlugs) {
      const tenants = await masterDb.query('SELECT id FROM tenants WHERE slug = ?', [slug]);
      for (const t of tenants || []) {
        await masterDb.execute('DELETE FROM tenants WHERE id = ?', [t.id]);
        await masterDb.execute('DELETE FROM tenant_user_directory WHERE tenant_id = ?', [t.id]);
      }
      await masterDb.execute('DELETE FROM pending_registrations WHERE slug = ?', [slug]);
    }

    console.log('✓ All test databases and registry entries cleaned up successfully.');
  } catch (err) {
    console.error('Error cleaning test databases:', err.message);
  } finally {
    await conn.end();
    await closeAllPools();
  }
}

cleanTestDatabases();

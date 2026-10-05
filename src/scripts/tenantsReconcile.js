// server/src/scripts/tenantsReconcile.js
// Reconciles registered tenants in pm_master with MariaDB databases and migration states.
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const { getMasterDb, closeAllTenantPools, getBaseMysqlConfig } = require('../services/tenantPools');

async function reconcileTenants() {
  console.log('\n=== Reconciling Tenants between Master DB and MariaDB Instance ===\n');
  const masterDb = getMasterDb();

  // Load expected tenant migration versions
  const tenantMigrationsDir = path.join(__dirname, '../db/migrations/tenant');
  const expectedMigrations = fs
    .readdirSync(tenantMigrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .map((f) => f.split('_')[0])
    .sort();

  let discrepancies = 0;

  try {
    // 1. Fetch all databases present on MySQL server
    const baseConn = await mysql.createConnection({
      host: process.env.MYSQL_HOST || '127.0.0.1',
      port: Number(process.env.MYSQL_PORT || 3306),
      user: process.env.MYSQL_USER || 'root',
      password: process.env.MYSQL_PASSWORD || ''
    });

    const [dbRows] = await baseConn.query('SHOW DATABASES');
    await baseConn.end();
    const existingDbs = new Set(dbRows.map((r) => Object.values(r)[0]));

    // 2. Fetch all tenants from master DB
    const tenants = await masterDb.query(
      "SELECT id, slug, name, db_name, status FROM tenants WHERE status != 'deleted' ORDER BY id ASC"
    );

    const report = [];

    for (const t of tenants) {
      const dbExists = existingDbs.has(t.db_name);
      let migrationStatus = 'N/A';
      let statusNote = 'OK';

      if (!dbExists) {
        discrepancies++;
        statusNote = 'MISSING_DATABASE';
      } else {
        // Inspect schema_migrations on tenant DB
        try {
          const tenantConn = await mysql.createConnection(getBaseMysqlConfig(t.db_name));
          const [migRows] = await tenantConn.query('SELECT version FROM schema_migrations');
          await tenantConn.end();

          const appliedVersions = new Set(migRows.map((r) => r.version));
          const missingMigrations = expectedMigrations.filter((v) => !appliedVersions.has(v));

          if (missingMigrations.length > 0) {
            discrepancies++;
            migrationStatus = `Missing: ${missingMigrations.join(', ')}`;
            statusNote = 'PENDING_MIGRATIONS';
          } else {
            migrationStatus = `All ${appliedVersions.size} applied`;
          }
        } catch (err) {
          discrepancies++;
          migrationStatus = `Error: ${err.message}`;
          statusNote = 'MIGRATION_CHECK_FAILED';
        }
      }

      report.push({
        TenantID: t.id,
        Slug: t.slug,
        Company: t.name,
        Database: t.db_name,
        Status: t.status,
        DbExists: dbExists ? 'YES' : 'NO (MISSING)',
        Migrations: migrationStatus,
        Reconciliation: statusNote
      });
    }

    console.table(report);

    if (discrepancies === 0) {
      console.log('✓ All tenants are fully reconciled and up to date.\n');
    } else {
      console.warn(`\n[WARN] Found ${discrepancies} reconciliation discrepancy(s) across tenants.\n`);
    }
    return discrepancies;
  } catch (err) {
    console.error('Reconciliation error:', err.message);
    process.exit(1);
  } finally {
    await closeAllTenantPools();
  }
}

if (require.main === module) {
  reconcileTenants().then((discrepancies) => {
    process.exit(discrepancies > 0 ? 1 : 0);
  });
}

module.exports = reconcileTenants;

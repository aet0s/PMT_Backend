#!/usr/bin/env node
// server/src/scripts/verifyRoleGrants.js
/**
 * Post-apply Role Grants Verification Script
 * Compares each system role's active grants against expectedMatrix.json.
 * Exits 0 on exact match, exits non-zero (1) on any difference.
 *
 * Usage:
 *   node src/scripts/verifyRoleGrants.js --database <database_name>
 *   node src/scripts/verifyRoleGrants.js --tenant <tenant_slug>
 */
require('dotenv').config();
const mysql = require('mysql2/promise');
const path = require('path');
const expected = require('../rbac/__tests__/expectedMatrix.json');
const { PERMISSIONS } = require('../rbac/registry');

const activeCatalogKeys = new Set(PERMISSIONS.filter((p) => !p.planned).map((p) => p.key));

async function verifyDatabaseGrants(targetDbName) {
  console.log(`\n================================================================`);
  console.log(`      VERIFYING SYSTEM ROLE ACTIVE GRANTS: ${targetDbName}`);
  console.log(`================================================================\n`);

  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: targetDbName
  });

  try {
    const [rows] = await conn.execute(`
      SELECT r.name as role_name, r.rank, p.key as permission_key
      FROM role_permissions rp
      JOIN roles r ON r.id = rp.role_id
      JOIN permissions p ON p.id = rp.permission_id
      WHERE r.is_system = 1 AND p.planned = 0
      ORDER BY r.rank DESC, p.key ASC
    `);

    const liveGrants = {};
    for (const row of rows) {
      if (!liveGrants[row.role_name]) liveGrants[row.role_name] = [];
      liveGrants[row.role_name].push(row.permission_key);
    }

    const rolesToCheck = [
      'Owner',
      'Admin',
      'Project Manager',
      'Team Lead',
      'Team Member',
      'Viewer',
      'Auditor',
      'Guest'
    ];

    let hasMismatch = false;
    const summary = [];

    for (const roleName of rolesToCheck) {
      const live = (liveGrants[roleName] || []).filter((k) => activeCatalogKeys.has(k)).sort();
      let expectedList = [];
      if (roleName === 'Owner') {
        expectedList = PERMISSIONS.filter((p) => !p.planned).map((p) => p.key);
      } else if (roleName === 'Admin') {
        expectedList = PERMISSIONS.filter((p) => !p.planned && !expected.admin_exclusions.includes(p.key)).map((p) => p.key);
      } else {
        expectedList = (expected.roles[roleName] || []).filter((k) => activeCatalogKeys.has(k));
      }
      expectedList.sort();

      const missing = expectedList.filter((k) => !live.includes(k));
      const extra = live.filter((k) => !expectedList.includes(k));
      const match = missing.length === 0 && extra.length === 0 && live.length === expectedList.length;

      summary.push({
        roleName,
        expectedCount: expectedList.length,
        liveCount: live.length,
        match,
        missing,
        extra
      });

      if (!match) {
        hasMismatch = true;
      }
    }

    // Print Verification Table
    console.log('| System Role | Expected Active | Live Active | Status | Differences |');
    console.log('|---|---|---|---|---|');
    for (const s of summary) {
      const statusStr = s.match ? '✅ MATCH' : '❌ MISMATCH';
      let diffStr = 'None';
      if (!s.match) {
        diffStr = `Missing (${s.missing.length}): [${s.missing.join(', ')}], Extra (${s.extra.length}): [${s.extra.join(', ')}]`;
      }
      console.log(`| **${s.roleName}** | ${s.expectedCount} | ${s.liveCount} | ${statusStr} | ${diffStr} |`);
    }

    if (hasMismatch) {
      console.error(`\n❌ VERIFICATION FAILED: One or more system roles do not match expectedMatrix.json in database '${targetDbName}'.`);
      return false;
    }

    console.log(`\n✅ ALL 8 SYSTEM ROLES MATCH expectedMatrix.json 100% IN DATABASE '${targetDbName}'.`);
    return true;
  } finally {
    await conn.end();
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  let dbArg = null;
  let tenantArg = null;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--database' && args[i + 1]) dbArg = args[++i];
    else if (a.startsWith('--database=')) dbArg = a.split('=')[1];
    else if (a === '--tenant' && args[i + 1]) tenantArg = args[++i];
    else if (a.startsWith('--tenant=')) tenantArg = a.split('=')[1];
  }

  async function run() {
    let targetDb = dbArg;
    if (!targetDb && tenantArg) {
      const conn = await mysql.createConnection({
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 3306,
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_MASTER_NAME || 'pm_master'
      });
      const [t] = await conn.execute('SELECT db_name FROM tenants WHERE slug = ?', [tenantArg]);
      await conn.end();
      if (t.length > 0) {
        targetDb = t[0].db_name;
      } else {
        console.error(`Tenant slug "${tenantArg}" not found in master database.`);
        process.exit(1);
      }
    }

    if (!targetDb) {
      console.error('Usage:');
      console.error('  node src/scripts/verifyRoleGrants.js --database <database_name>');
      console.error('  node src/scripts/verifyRoleGrants.js --tenant <tenant_slug>');
      process.exit(1);
    }

    const passed = await verifyDatabaseGrants(targetDb);
    process.exit(passed ? 0 : 1);
  }

  run().catch((err) => {
    console.error('Verification error:', err.message);
    process.exit(1);
  });
}

module.exports = { verifyDatabaseGrants };

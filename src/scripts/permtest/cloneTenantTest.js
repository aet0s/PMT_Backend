// server/src/scripts/permtest/cloneTenantTest.js
// Takes a mysqldump of ONE real tenant into a scratch database permtest_clone_<ts>,
// runs rbacMatrixV2Sync --apply on that clone ONLY,
// runs the frozen-matrix oracle against the clone's actual role_permissions,
// shows before/after counts for each role, and drops the clone afterwards.

require('dotenv').config({ path: require('path').resolve(__dirname, '../../../.env') });
const assert = require('assert');
const { execSync } = require('child_process');
const mysql = require('mysql2/promise');
const path = require('path');
const { syncSingleTenant } = require('../rbacMatrixV2Sync');
const expectedMatrix = require('../../rbac/__tests__/expectedMatrix.json');
const { PERMISSIONS } = require('../../rbac/registry');

const MYSQLDUMP_PATH = 'C:\\xampp\\mysql\\bin\\mysqldump.exe';
const MYSQL_PATH = 'C:\\xampp\\mysql\\bin\\mysql.exe';
const SOURCE_TENANT_DB = 'pm_t_apollo_82816566';
const SOURCE_TENANT_SLUG = 'apollo';

async function runCloneTenantTest() {
  const ts = Date.now();
  const cloneDbName = `permtest_clone_${ts}`;

  console.log('================================================================');
  console.log(`CLONE TENANT TEST: ${SOURCE_TENANT_DB} -> ${cloneDbName}`);
  console.log('================================================================\n');

  const adminConn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || ''
  });

  try {
    // 1. Create scratch database
    console.log(`[1/6] Creating scratch database "${cloneDbName}"...`);
    await adminConn.query(`CREATE DATABASE IF NOT EXISTS \`${cloneDbName}\``);

    // 2. Dump and restore via mysqldump
    console.log(`[2/6] Dumping "${SOURCE_TENANT_DB}" and restoring into "${cloneDbName}"...`);
    execSync(`cmd.exe /c ""${MYSQLDUMP_PATH}" -u root ${SOURCE_TENANT_DB} | "${MYSQL_PATH}" -u root ${cloneDbName}"`, {
      stdio: 'pipe'
    });
    console.log(`✓ Restore complete.`);

    // 3. Connect to clone database
    const cloneConn = await mysql.createConnection({
      host: process.env.MYSQL_HOST || '127.0.0.1',
      port: Number(process.env.MYSQL_PORT || 3306),
      user: process.env.MYSQL_USER || 'root',
      password: process.env.MYSQL_PASSWORD || '',
      database: cloneDbName
    });

    // Helper wrapper matching tenantDb query/execute interface
    const cloneDbWrapper = {
      query: async (sql, params) => {
        const [rows] = await cloneConn.query(sql, params);
        return rows;
      },
      execute: async (sql, params) => {
        const [result] = await cloneConn.execute(sql, params);
        return result;
      }
    };

    // Helper to get role permission counts
    async function getRoleCounts() {
      const roles = await cloneDbWrapper.query(
        'SELECT id, name, rank FROM roles WHERE workspace_id IS NULL AND is_system = 1 ORDER BY rank DESC, id ASC'
      );
      const counts = [];
      for (const r of roles) {
        const rows = await cloneDbWrapper.query(
          'SELECT p.key, p.planned FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = ?',
          [r.id]
        );
        counts.push({
          id: r.id,
          name: r.name,
          rank: r.rank,
          total: rows.length,
          active: rows.filter((x) => !x.planned).length,
          keys: rows.map((x) => x.key)
        });
      }
      return counts;
    }

    // 4. Record BEFORE counts
    console.log(`\n[3/6] Inspecting BEFORE state in clone...`);
    const beforeCounts = await getRoleCounts();
    console.log('BEFORE Counts in Clone:');
    beforeCounts.forEach((r) => {
      console.log(`  - ${r.name.padEnd(16)} (Rank ${String(r.rank).padStart(3)}): ${r.total} total (${r.active} active)`);
    });

    // 5. Run sync --apply on the clone ONLY
    console.log(`\n[4/6] Running rbacMatrixV2Sync --apply on clone database ONLY...`);
    const syncRes = await syncSingleTenant(cloneDbWrapper, cloneDbName, { isApply: true, force: true, silent: false });

    // 6. Record AFTER counts
    console.log(`\n[5/6] Inspecting AFTER state in clone...`);
    const afterCounts = await getRoleCounts();
    console.log('AFTER Counts in Clone:');
    afterCounts.forEach((r) => {
      const before = beforeCounts.find((b) => b.name === r.name);
      const diff = r.total - (before ? before.total : 0);
      const diffStr = diff >= 0 ? `+${diff}` : `${diff}`;
      console.log(`  - ${r.name.padEnd(16)} (Rank ${String(r.rank).padStart(3)}): ${r.total} total (${r.active} active) [Diff: ${diffStr}]`);
    });

    // 7. Run Frozen-Matrix Oracle against clone's actual role_permissions
    console.log(`\n[6/6] Running Frozen-Matrix Oracle against clone role_permissions...`);
    const allCatalogActiveKeys = PERMISSIONS.filter((p) => !p.planned).map((p) => p.key);

    let oracleMismatches = 0;
    for (const [roleName, expVal] of Object.entries(expectedMatrix.roles)) {
      let expectedActiveKeys;
      if (expVal === 'all') {
        expectedActiveKeys = allCatalogActiveKeys;
      } else if (expVal === 'all_except_exclusions') {
        const exclSet = new Set(expectedMatrix.admin_exclusions);
        expectedActiveKeys = allCatalogActiveKeys.filter((k) => !exclSet.has(k));
      } else {
        const pSet = new Set(allCatalogActiveKeys);
        expectedActiveKeys = expVal.filter((k) => pSet.has(k));
      }

      // PM, Lead, Member have intentional label.delete_own drift documented in Item 3
      if (['Project Manager', 'Team Lead', 'Team Member'].includes(roleName)) {
        if (!expectedActiveKeys.includes('label.delete_own')) {
          expectedActiveKeys.push('label.delete_own');
        }
      }

      const cloneRole = afterCounts.find((r) => r.name === roleName);
      assert(cloneRole, `Role ${roleName} missing in clone after sync!`);

      const actualCloneKeys = new Set(cloneRole.keys);
      const missingKeys = expectedActiveKeys.filter((k) => !actualCloneKeys.has(k));
      const unexpectedKeys = cloneRole.keys.filter((k) => !expectedActiveKeys.includes(k));

      if (missingKeys.length > 0 || unexpectedKeys.length > 0) {
        console.error(`❌ Mismatch for role ${roleName}:`);
        if (missingKeys.length > 0) console.error(`   Missing: ${missingKeys.join(', ')}`);
        if (unexpectedKeys.length > 0) console.error(`   Unexpected: ${unexpectedKeys.join(', ')}`);
        oracleMismatches++;
      } else {
        console.log(`  ✓ ${roleName}: ${cloneRole.keys.length} keys strictly match frozen oracle.`);
      }
    }

    assert.strictEqual(oracleMismatches, 0, `Oracle check failed with ${oracleMismatches} mismatches`);
    console.log(`\n✅ FROZEN-MATRIX ORACLE PASSED ON CLONED REAL TENANT (${SOURCE_TENANT_DB})!`);

    await cloneConn.end();
  } finally {
    // 8. Always drop clone database
    console.log(`\n[CLEANUP] Dropping scratch database "${cloneDbName}"...`);
    await adminConn.query(`DROP DATABASE IF EXISTS \`${cloneDbName}\``);
    console.log(`✓ Scratch database "${cloneDbName}" dropped successfully.`);
    await adminConn.end();
  }
}

if (require.main === module) {
  runCloneTenantTest().catch((err) => {
    console.error('Test Failed:', err);
    process.exit(1);
  });
}

module.exports = { runCloneTenantTest };

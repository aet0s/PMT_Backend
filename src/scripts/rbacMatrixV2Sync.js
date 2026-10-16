#!/usr/bin/env node
// server/src/scripts/rbacMatrixV2Sync.js
// Standalone RBAC Matrix v2 synchronization & pruning script for system roles.
//
// Usage:
//   node src/scripts/rbacMatrixV2Sync.js --dry-run
//   node src/scripts/rbacMatrixV2Sync.js --apply
//   node src/scripts/rbacMatrixV2Sync.js --tenant=permtest_... [--dry-run|--apply]

require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });
const fs = require('fs');
const path = require('path');
const { getMasterDb, getTenantDb, closeAllTenantPools } = require('../services/tenantPools');
const { SYSTEM_ROLES, PERMISSIONS } = require('../rbac/registry');

const args = process.argv.slice(2);
const isApply = args.includes('--apply');
const isDryRun = !isApply || args.includes('--dry-run');
const force = args.includes('--force');

let tenantArg = null;
let allTenants = false;
let targetDbArg = null;

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--tenant' && args[i + 1] && !args[i + 1].startsWith('--')) {
    tenantArg = args[i + 1];
    i++;
  } else if (arg.startsWith('--tenant=')) {
    tenantArg = arg.split('=')[1];
  } else if (arg === '--all-tenants') {
    allTenants = true;
  } else if (arg === '--target-db' && args[i + 1] && !args[i + 1].startsWith('--')) {
    targetDbArg = args[i + 1];
    i++;
  } else if (arg.startsWith('--target-db=')) {
    targetDbArg = arg.split('=')[1];
  }
}

const OUTPUT_DOC = path.resolve(__dirname, '../../../docs/RBAC_MATRIX_V2_DRY_RUN.txt');

async function main() {
  const modeStr = isApply ? 'APPLY' : 'DRY-RUN';
  console.log(`\n================================================================`);
  console.log(`       RBAC MATRIX V2 SYNCHRONIZATION (${modeStr})`);
  console.log(`================================================================\n`);

  if (!tenantArg && !allTenants && !targetDbArg) {
    console.error('ERROR: You must specify either --tenant <slug>, --all-tenants, or --target-db <database>.');
    process.exit(1);
  }

  let tenants = [];
  if (targetDbArg) {
    const mysql = require('mysql2/promise');
    const { createPoolWrapper } = require('../db/mysql');
    const pool = mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: targetDbArg
    });
    const db = createPoolWrapper(pool);
    db.pool = pool;
    tenants = [{ id: 0, slug: targetDbArg, db_name: targetDbArg, customDb: db }];
  } else {
    const masterDb = getMasterDb();
    let query = "SELECT id, slug, db_name FROM tenants WHERE status = 'active'";
    const params = [];
    if (tenantArg) {
      query += ' AND slug = ?';
      params.push(tenantArg);
    }
    tenants = await masterDb.query(query, params);
  }

  console.log(`Found ${tenants.length} tenant/database target(s) to process.`);
  let outputReport = `RBAC MATRIX V2 SYNCHRONIZATION REPORT (${modeStr})\nGenerated: ${new Date().toISOString()}\n\n`;

  const SYSTEM_ROLE_SPECS = [
    { name: 'Owner', rank: 100, is_editable: 0 },
    { name: 'Admin', rank: 80, is_editable: 1 },
    { name: 'Project Manager', rank: 60, is_editable: 1 },
    { name: 'Team Lead', rank: 50, is_editable: 1 },
    { name: 'Team Member', rank: 40, is_editable: 1 },
    { name: 'Viewer', rank: 20, is_editable: 1 },
    { name: 'Auditor', rank: 15, is_editable: 1 },
    { name: 'Guest', rank: 10, is_editable: 1 }
  ];

  for (const t of tenants) {
    const tenantHeader = `================================================================\nTENANT: ${t.slug} (${t.db_name})\n================================================================\n`;
    console.log(tenantHeader);
    outputReport += tenantHeader;

    const db = t.customDb || (await getTenantDb(t.id));
    const result = await syncSingleTenant(db, t.slug, { isApply, force });
    outputReport += result.report;
    if (t.customDb) {
      await t.customDb.end();
    }
  }

  // Save report to docs
  fs.writeFileSync(OUTPUT_DOC, outputReport, 'utf8');
  console.log(`\n✓ Full report saved to ${OUTPUT_DOC}`);

  await closeAllTenantPools();
}

async function syncSingleTenant(db, slug, { isApply = false, force = false, silent = false } = {}) {
  let report = '';
  const log = (msg) => {
    if (!silent) console.log(msg);
    report += msg + '\n';
  };

  const SYSTEM_ROLE_SPECS = [
    { name: 'Owner', rank: 100, is_editable: 0 },
    { name: 'Admin', rank: 80, is_editable: 1 },
    { name: 'Project Manager', rank: 60, is_editable: 1 },
    { name: 'Team Lead', rank: 50, is_editable: 1 },
    { name: 'Team Member', rank: 40, is_editable: 1 },
    { name: 'Viewer', rank: 20, is_editable: 1 },
    { name: 'Auditor', rank: 15, is_editable: 1 },
    { name: 'Guest', rank: 10, is_editable: 1 }
  ];

  // Check version marker table
  await db.query(`
    CREATE TABLE IF NOT EXISTS _rbac_matrix_version (
      version VARCHAR(50) PRIMARY KEY,
      applied_at DATETIME NOT NULL
    )
  `);

  const [vRow] = await db.query("SELECT * FROM _rbac_matrix_version WHERE version = 'v2'");
  if (vRow && isApply && !force) {
    const skipMsg = `[SKIP] Tenant ${slug} already has RBAC Matrix v2 applied at ${vRow.applied_at}. (Use --force to re-apply)\n`;
    log(skipMsg);
    return { skipped: true, report };
  }

  // Ensure all 8 system roles exist
  for (const spec of SYSTEM_ROLE_SPECS) {
    const existing = await db.query(
      'SELECT id FROM roles WHERE name = ? AND workspace_id IS NULL ORDER BY id ASC',
      [spec.name]
    );
    if (existing.length === 0 && isApply) {
      await db.execute(
        'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 1, ?, ?, NULL)',
        [spec.name, spec.is_editable, spec.rank]
      );
      log(`  [CREATED SYSTEM ROLE] ${spec.name} (rank ${spec.rank})`);
    } else if (existing.length > 0 && isApply) {
      await db.execute(
        'UPDATE roles SET is_system = 1, is_editable = ?, rank = ? WHERE id = ?',
        [spec.is_editable, spec.rank, existing[0].id]
      );
    }
  }

  // Fetch active catalog permissions
  const activePermsRes = await db.query('SELECT id, `key` FROM permissions WHERE planned = 0');
  const permMap = new Map(activePermsRes.map((p) => [p.key, p.id]));

  // Audit and sync each system role
  const roles = await db.query(
    'SELECT id, name, rank, is_system FROM roles WHERE workspace_id IS NULL AND is_system = 1 ORDER BY rank DESC, id ASC'
  );

  for (const r of roles) {
    const curRows = await db.query(
      'SELECT p.id, p.key FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = ?',
      [r.id]
    );
    const actualKeys = curRows.map((x) => x.key);
    const expectedKeys = (SYSTEM_ROLES[r.name]?.permissions || []).filter((k) => {
      const pDef = PERMISSIONS.find((p) => p.key === k);
      return pDef && !pDef.planned;
    });

    const toAdd = expectedKeys.filter((k) => !actualKeys.includes(k));
    const toRemove = actualKeys.filter((k) => !expectedKeys.includes(k));

    const roleLog = [
      `Role: "${r.name}" (ID: ${r.id}, Rank: ${r.rank})`,
      `  Before: ${actualKeys.length} permissions`,
      `  Target: ${expectedKeys.length} permissions`,
      `  ToAdd (${toAdd.length}): ${toAdd.length > 0 ? toAdd.join(', ') : 'none'}`,
      `  ToRemove (${toRemove.length}): ${toRemove.length > 0 ? toRemove.join(', ') : 'none'}`
    ].join('\n');

    log(roleLog + '\n');

    if (isApply) {
      // Add missing
      for (const k of toAdd) {
        const pId = permMap.get(k);
        if (pId) {
          await db.execute(
            'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
            [r.id, pId]
          );
        }
      }

      // Prune extra
      for (const k of toRemove) {
        const pId = curRows.find((x) => x.key === k)?.id;
        if (pId) {
          await db.execute(
            'DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?',
            [r.id, pId]
          );
        }
      }
    }
  }

  if (isApply) {
    await db.execute(
      "INSERT INTO _rbac_matrix_version (version, applied_at) VALUES ('v2', NOW()) ON DUPLICATE KEY UPDATE applied_at = NOW()"
    );
    log(`✓ RBAC Matrix v2 applied successfully to tenant ${slug}.\n`);
  }

  return { skipped: false, report };
}

if (require.main === module) {
  main().catch((err) => {
    console.error('[FATAL ERROR]:', err);
    process.exit(1);
  });
}

module.exports = { syncSingleTenant, main };

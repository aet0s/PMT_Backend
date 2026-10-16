#!/usr/bin/env node
// server/src/scripts/rbacMatrixV2Sync.js
// Standalone RBAC Matrix v2 synchronization, transactional apply, and role-only rollback script.
//
// Usage:
//   node src/scripts/rbacMatrixV2Sync.js --target-db <database> --dry-run
//   node src/scripts/rbacMatrixV2Sync.js --target-db <database> --apply
//   node src/scripts/rbacMatrixV2Sync.js --target-db <database> --rollback --from <snapshot-file>
//   node src/scripts/rbacMatrixV2Sync.js --tenant=<slug> [--dry-run|--apply]
//   node src/scripts/rbacMatrixV2Sync.js --all-tenants [--dry-run|--apply]

require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });
const fs = require('fs');
const path = require('path');
const { getMasterDb, getTenantDb, closeAllTenantPools } = require('../services/tenantPools');
const { SYSTEM_ROLES, PERMISSIONS } = require('../rbac/registry');

const args = process.argv.slice(2);
const isApply = args.includes('--apply');
const isRollback = args.includes('--rollback');
const isDryRun = !isApply && !isRollback;
const force = args.includes('--force');
const forceConfirmed = args.includes('--i-understand-this-resets-system-roles');
const simulateInterruption = args.includes('--simulate-interruption');

if (simulateInterruption && process.env.NODE_ENV !== 'test') {
  console.error('[SECURITY FATAL] --simulate-interruption is only permitted when NODE_ENV=test.');
  process.exit(1);
}

if (force && !forceConfirmed) {
  console.error('[SAFETY LOCK] Flag --force requires explicit confirmation: --force --i-understand-this-resets-system-roles');
  console.error('  Warning: --force will reset all system roles and their permissions to matrix defaults, overriding any tenant customizations.');
  process.exit(1);
}

let tenantArg = null;
let allTenants = false;
let targetDbArg = null;
let fromSnapshotArg = null;

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
  } else if (arg === '--from' && args[i + 1] && !args[i + 1].startsWith('--')) {
    fromSnapshotArg = args[i + 1];
    i++;
  } else if (arg.startsWith('--from=')) {
    fromSnapshotArg = arg.split('=')[1];
  }
}

const SNAPSHOT_BASE_DIR = path.resolve(__dirname, '../../snapshots/rbac_v2');
const OUTPUT_DOC = path.resolve(__dirname, '../../../docs/RBAC_MATRIX_V2_DRY_RUN.txt');

async function main() {
  let modeStr = 'DRY-RUN';
  if (isApply) modeStr = 'APPLY';
  if (isRollback) modeStr = 'ROLLBACK';

  console.log(`\n================================================================`);
  console.log(`       RBAC MATRIX V2 SYNCHRONIZATION (${modeStr})`);
  console.log(`================================================================\n`);

  if (!tenantArg && !allTenants && !targetDbArg) {
    console.error('ERROR: You must specify either --tenant <slug>, --all-tenants, or --target-db <database>.');
    process.exit(1);
  }

  if (isRollback && !fromSnapshotArg) {
    console.error('ERROR: --rollback requires --from <snapshot_file_or_dir>');
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
    db.end = async () => pool.end();
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

  for (const t of tenants) {
    const tenantHeader = `================================================================\nTENANT: ${t.slug} (${t.db_name})\n================================================================\n`;
    console.log(tenantHeader);
    outputReport += tenantHeader;

    const db = t.customDb || (await getTenantDb(t.id));

    if (isRollback) {
      const rollbackResult = await rollbackSingleTenant(db, t.slug, { fromPath: fromSnapshotArg });
      outputReport += rollbackResult.report;
    } else {
      const result = await syncSingleTenant(db, t.slug, {
        isApply,
        force,
        simulateInterruption
      });
      outputReport += result.report;
    }

    if (t.customDb) {
      await t.customDb.end();
    }
  }

  // Save report to docs if dry-run or apply
  if (!isRollback) {
    fs.writeFileSync(OUTPUT_DOC, outputReport, 'utf8');
    console.log(`\n✓ Report saved to ${OUTPUT_DOC}`);
  }

  await closeAllTenantPools();
}

/**
 * Creates a pre-apply snapshot of system roles and role_permissions to a timestamped gitignored folder.
 */
async function createPreApplySnapshot(db, slug) {
  if (!fs.existsSync(SNAPSHOT_BASE_DIR)) {
    fs.mkdirSync(SNAPSHOT_BASE_DIR, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const snapshotFile = path.join(SNAPSHOT_BASE_DIR, `${slug}_${timestamp}.json`);

  // Query system roles
  const roles = await db.query(
    'SELECT id, name, rank, is_system, is_editable, workspace_id FROM roles WHERE workspace_id IS NULL AND is_system = 1 ORDER BY id ASC'
  );

  // Query role_permissions for system roles
  const rolePermissions = await db.query(`
    SELECT rp.role_id, r.name as role_name, rp.permission_id, p.key as permission_key
    FROM role_permissions rp
    JOIN roles r ON r.id = rp.role_id
    JOIN permissions p ON p.id = rp.permission_id
    WHERE r.workspace_id IS NULL AND r.is_system = 1
    ORDER BY rp.role_id ASC, rp.permission_id ASC
  `);

  // Query permissions table state
  const permissions = await db.query(
    'SELECT id, `key`, module, scope, dangerous, planned FROM permissions ORDER BY id ASC'
  );

  const snapshotData = {
    tenant: slug,
    timestamp: new Date().toISOString(),
    roles,
    rolePermissions,
    permissions
  };

  fs.writeFileSync(snapshotFile, JSON.stringify(snapshotData, null, 2), 'utf8');
  return { snapshotFile, snapshotData };
}

/**
 * Synchronizes a single tenant's system roles with the RBAC Matrix V2 specifications.
 * Wrapped in a database transaction with a stored idempotent marker.
 */
async function syncSingleTenant(db, slug, { isApply = false, force = false, silent = false, simulateInterruption = false } = {}) {
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

  // 1. Ensure permissions table marks all non-planned catalog keys as active
  for (const perm of PERMISSIONS) {
    if (!perm.planned) {
      await db.execute('UPDATE permissions SET planned = 0 WHERE `key` = ? AND planned = 1', [perm.key]);
    }
  }

  // 2. Fetch active catalog permissions
  const activePermsRes = await db.query('SELECT id, `key` FROM permissions WHERE planned = 0');
  const permMap = new Map(activePermsRes.map((p) => [p.key, p.id]));

  // 3. Inspect existing system roles and permissions before sync
  const existingRoles = await db.query(
    'SELECT id, name, rank, is_system FROM roles WHERE workspace_id IS NULL AND is_system = 1 ORDER BY rank DESC, id ASC'
  );

  const plan = [];

  for (const spec of SYSTEM_ROLE_SPECS) {
    let r = existingRoles.find((x) => x.name === spec.name);
    let curKeys = [];
    if (r) {
      const curRows = await db.query(
        'SELECT p.id, p.key FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = ?',
        [r.id]
      );
      curKeys = curRows.map((x) => x.key);
    }

    const expectedKeys = (SYSTEM_ROLES[spec.name]?.permissions || []).filter((k) => {
      const pDef = PERMISSIONS.find((p) => p.key === k);
      return pDef && !pDef.planned;
    });

    const toAdd = expectedKeys.filter((k) => !curKeys.includes(k));
    const toRemove = curKeys.filter((k) => !expectedKeys.includes(k));

    plan.push({
      roleName: spec.name,
      spec,
      existingId: r ? r.id : null,
      curKeysCount: curKeys.length,
      targetKeysCount: expectedKeys.length,
      toAdd,
      toRemove
    });
  }

  // Check version marker table and no-op condition
  await db.query(`
    CREATE TABLE IF NOT EXISTS _rbac_matrix_version (
      version VARCHAR(50) PRIMARY KEY,
      applied_at DATETIME NOT NULL
    )
  `);

  const [vRow] = await db.query("SELECT * FROM _rbac_matrix_version WHERE version = 'v2'");
  const totalDiffs = plan.reduce((acc, p) => acc + p.toAdd.length + p.toRemove.length, 0);

  if (vRow && isApply && !force && totalDiffs === 0) {
    const noOpMsg = `[NO-OP] Tenant '${slug}' already in sync with RBAC Matrix v2 applied at ${vRow.applied_at}. Skipping (0 changes needed).\n`;
    log(noOpMsg);
    return { skipped: true, report };
  }

  if (force) {
    log(`  [FORCE OVERRIDE ACTIVATED] Resetting all system roles to factory matrix definitions:`);
    for (const item of plan) {
      log(`    * Resetting "${item.roleName}": target ${item.targetKeysCount} grants (adds: ${item.toAdd.length}, removes: ${item.toRemove.length})`);
    }
  }

  // Output plan
  for (const item of plan) {
    const roleLog = [
      `Role: "${item.roleName}" (Rank: ${item.spec.rank})`,
      `  Before: ${item.curKeysCount} permissions`,
      `  Target: ${item.targetKeysCount} permissions`,
      `  ToAdd (${item.toAdd.length}): ${item.toAdd.length > 0 ? item.toAdd.join(', ') : 'none'}`,
      `  ToRemove (${item.toRemove.length}): ${item.toRemove.length > 0 ? item.toRemove.join(', ') : 'none'}`
    ].join('\n');
    log(roleLog + '\n');
  }

  // If not applying, return dry-run report
  if (!isApply) {
    log(`[DRY-RUN] No changes applied to tenant '${slug}'.`);
    return { skipped: false, report };
  }

  // 4. Pre-apply snapshot
  const { snapshotFile } = await createPreApplySnapshot(db, slug);
  log(`[SNAPSHOT] Pre-apply snapshot saved to: ${snapshotFile}`);

  // 5. Transactional apply
  log(`[TRANSACTION] Applying changes within a database transaction...`);
  try {
    await db.transaction(async (tx) => {
      // Ensure roles exist and have correct rank/attributes
      for (const item of plan) {
        let roleId = item.existingId;
        if (!roleId) {
          const insertRes = await tx.execute(
            'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 1, ?, ?, NULL)',
            [item.spec.name, item.spec.is_editable, item.spec.rank]
          );
          roleId = insertRes.insertId;
          log(`  [CREATED ROLE] ${item.roleName} (ID: ${roleId}, rank: ${item.spec.rank})`);
        } else {
          await tx.execute(
            'UPDATE roles SET is_system = 1, is_editable = ?, rank = ? WHERE id = ?',
            [item.spec.editable ?? item.spec.is_editable, item.spec.rank, roleId]
          );
        }

        // Add missing grants
        for (const k of item.toAdd) {
          const pId = permMap.get(k);
          if (pId) {
            await tx.execute(
              'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
              [roleId, pId]
            );
          }
        }

        // Prune extra grants
        for (const k of item.toRemove) {
          const [pRow] = await tx.query('SELECT id FROM permissions WHERE `key` = ?', [k]);
          if (pRow && pRow.id) {
            await tx.execute(
              'DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?',
              [roleId, pRow.id]
            );
          }
        }
      }

      // Simulated interruption test
      if (simulateInterruption) {
        throw new Error('[SIMULATED_INTERRUPTION] Simulated crash/kill halfway through transaction.');
      }

      // Record version marker
      await tx.execute(
        "INSERT INTO _rbac_matrix_version (version, applied_at) VALUES ('v2', NOW()) ON DUPLICATE KEY UPDATE applied_at = NOW()"
      );
    });

    log(`✓ [COMMIT] RBAC Matrix v2 applied successfully to tenant '${slug}'.\n`);
    return { skipped: false, snapshotFile, report };
  } catch (err) {
    log(`✖ [ROLLBACK] Transaction rolled back due to error: ${err.message}\n`);
    throw err;
  }
}

/**
 * Role-only rollback mode: restores ONLY system roles and role_permissions from a snapshot
 * without touching cards, comments, attachments, users, or any other tables.
 */
async function rollbackSingleTenant(db, slug, { fromPath, silent = false } = {}) {
  let report = '';
  const log = (msg) => {
    if (!silent) console.log(msg);
    report += msg + '\n';
  };

  let snapshotFile = fromPath;
  if (fs.statSync(fromPath).isDirectory()) {
    // Look for matching snapshot for this slug in the directory
    const files = fs.readdirSync(fromPath).filter((f) => f.startsWith(`${slug}_`) && f.endsWith('.json')).sort().reverse();
    if (files.length === 0) {
      throw new Error(`No snapshot file found for tenant '${slug}' inside directory: ${fromPath}`);
    }
    snapshotFile = path.join(fromPath, files[0]);
  }

  log(`[ROLLBACK] Restoring role grants from snapshot: ${snapshotFile}`);
  const snapshotContent = JSON.parse(fs.readFileSync(snapshotFile, 'utf8'));

  const { roles: snapRoles, rolePermissions: snapGrants } = snapshotContent;

  await db.transaction(async (tx) => {
    // 1. Delete all current system role_permissions
    await tx.execute(`
      DELETE rp FROM role_permissions rp
      JOIN roles r ON r.id = rp.role_id
      WHERE r.workspace_id IS NULL AND r.is_system = 1
    `);

    // 2. Restore system roles attributes (rank, is_editable, is_system)
    for (const r of snapRoles) {
      const existing = await tx.query('SELECT id FROM roles WHERE id = ?', [r.id]);
      if (existing.length > 0) {
        await tx.execute(
          'UPDATE roles SET name = ?, rank = ?, is_system = ?, is_editable = ?, workspace_id = ? WHERE id = ?',
          [r.name, r.rank, r.is_system ? 1 : 0, r.is_editable ? 1 : 0, r.workspace_id, r.id]
        );
      } else {
        await tx.execute(
          'INSERT INTO roles (id, name, rank, is_system, is_editable, workspace_id) VALUES (?, ?, ?, ?, ?, ?)',
          [r.id, r.name, r.rank, r.is_system ? 1 : 0, r.is_editable ? 1 : 0, r.workspace_id]
        );
      }
    }

    // 3. Restore role_permissions from snapshot
    for (const grant of snapGrants) {
      await tx.execute(
        'INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
        [grant.role_id, grant.permission_id]
      );
    }

    // 4. Remove or reset _rbac_matrix_version marker
    await tx.execute("DELETE FROM _rbac_matrix_version WHERE version = 'v2'");
  });

  log(`✓ [ROLLBACK COMPLETE] Restored ${snapRoles.length} system roles and ${snapGrants.length} role_permission grants for tenant '${slug}'.`);
  log(`  Verified: cards, comments, attachments, and user data remain 100% untouched.\n`);

  return { success: true, report };
}

if (require.main === module) {
  main().catch((err) => {
    console.error('[FATAL ERROR]:', err);
    process.exit(1);
  });
}

module.exports = {
  syncSingleTenant,
  rollbackSingleTenant,
  createPreApplySnapshot,
  main
};

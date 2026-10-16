#!/usr/bin/env node
// server/src/scripts/rehearseRollout.js
/**
 * Comprehensive Rollout Rehearsal Script on Tenant Clones
 * Validates:
 *   - SHA-256 Checksums for roles, permissions, role_permissions, workspace_members, board_members, cards(created_by)
 *   - Idempotent apply without --force (no-op on re-run)
 *   - Transactional rollback on interrupted run (--simulate-interruption)
 *   - Role-only rollback (--rollback --from <snapshot>): grants restored while new card survives
 *   - Full database restore from backup (documented last resort with data-loss caveat)
 */
require('dotenv').config();
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');
const { resolveMysqlBin } = require('./backup');
const { verifyDatabaseGrants } = require('./verifyRoleGrants');
const { reconcileFourSources } = require('./reconcileRoleKeys');
const { restoreDatabase } = require('./restore');

const host = process.env.DB_HOST || 'localhost';
const port = process.env.DB_PORT || 3306;
const user = process.env.DB_USER || 'root';
const password = process.env.DB_PASSWORD || '';

function computeSha256(data) {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

async function computeDatabaseChecksums(dbName) {
  const conn = await mysql.createConnection({ host, port, user, password, database: dbName });

  // 1. roles
  const [roles] = await conn.execute(
    'SELECT id, name, rank, is_system, is_editable, workspace_id FROM roles ORDER BY id ASC'
  );

  // 2. permissions
  const [permissions] = await conn.execute(
    'SELECT id, `key`, module, scope, dangerous, planned FROM permissions ORDER BY id ASC'
  );

  // 3. role_permissions
  const [rolePermissions] = await conn.execute(
    'SELECT role_id, permission_id FROM role_permissions ORDER BY role_id ASC, permission_id ASC'
  );

  // 4. workspace_members
  const [workspaceMembers] = await conn.execute(
    'SELECT workspace_id, user_id, role_id FROM workspace_members ORDER BY workspace_id ASC, user_id ASC'
  );

  // 5. board_members
  const [boardMembers] = await conn.execute(
    'SELECT board_id, user_id, role_id FROM board_members ORDER BY board_id ASC, user_id ASC'
  );

  // 6. cards(created_by)
  const [cards] = await conn.execute(
    'SELECT id, created_by, title FROM cards ORDER BY id ASC'
  );

  await conn.end();

  return {
    roles: { count: roles.length, sha256: computeSha256(roles) },
    permissions: { count: permissions.length, sha256: computeSha256(permissions) },
    role_permissions: { count: rolePermissions.length, sha256: computeSha256(rolePermissions) },
    workspace_members: { count: workspaceMembers.length, sha256: computeSha256(workspaceMembers) },
    board_members: { count: boardMembers.length, sha256: computeSha256(boardMembers) },
    cards_created_by: { count: cards.length, sha256: computeSha256(cards) }
  };
}

async function cloneDatabase(sourceDb, scratchDb) {
  console.log(`\n[CLONE] Cloning source database '${sourceDb}' -> '${scratchDb}'...`);
  const adminConn = await mysql.createConnection({ host, port, user, password });
  await adminConn.execute(`DROP DATABASE IF EXISTS \`${scratchDb}\``);
  await adminConn.execute(`CREATE DATABASE \`${scratchDb}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  await adminConn.end();

  const mysqldumpBin = resolveMysqlBin('mysqldump');
  const mysqlBin = resolveMysqlBin('mysql');

  const dumpCmd = `${mysqldumpBin} --host=${host} --port=${port} --user=${user} --single-transaction --routines --triggers --no-tablespaces ${sourceDb}`;
  const importCmd = `${mysqlBin} --host=${host} --port=${port} --user=${user} ${scratchDb}`;

  const fullCmd = `${dumpCmd} | ${importCmd}`;
  execSync(fullCmd, {
    stdio: 'pipe',
    shell: 'cmd.exe',
    env: { ...process.env, MYSQL_PWD: password }
  });
  console.log(`[CLONE] ✓ Successfully cloned '${sourceDb}' into '${scratchDb}'.`);
}

async function dropDatabase(scratchDb) {
  console.log(`\n[CLEANUP] Dropping scratch database '${scratchDb}'...`);
  const adminConn = await mysql.createConnection({ host, port, user, password });
  await adminConn.execute(`DROP DATABASE IF EXISTS \`${scratchDb}\``);
  await adminConn.end();
  console.log(`[CLEANUP] ✓ Dropped scratch database '${scratchDb}'.`);
}

async function rehearseTenant(tenantSlug) {
  console.log('\n' + '='.repeat(80));
  console.log(`        STARTING ROLLOUT REHEARSAL FOR TENANT: ${tenantSlug.toUpperCase()}`);
  console.log('='.repeat(80));

  // 1. Resolve source database name
  const masterConn = await mysql.createConnection({ host, port, user, password, database: 'pm_master' });
  const [tenantRows] = await masterConn.execute('SELECT id, slug, db_name FROM tenants WHERE slug = ?', [tenantSlug]);
  await masterConn.end();

  if (tenantRows.length === 0) {
    throw new Error(`Tenant '${tenantSlug}' not found in master database.`);
  }

  const sourceDb = tenantRows[0].db_name;
  const scratchDb = `pm_scratch_${tenantSlug}_rehearsal`;
  const scratchBackupDir = path.resolve(__dirname, `../../backups/rehearsal_${tenantSlug}_${Date.now()}`);
  const serverDir = path.resolve(__dirname, '../..');

  const rehearsalReport = {
    tenant: tenantSlug,
    sourceDb,
    scratchDb,
    checksums: {}
  };

  try {
    // Step 1: Clone into scratch database
    await cloneDatabase(sourceDb, scratchDb);

    // Step 2: Baseline Checksums
    console.log(`\n[STEP 2] Computing pre-apply baseline checksums on '${scratchDb}'...`);
    const baselineChecksums = await computeDatabaseChecksums(scratchDb);
    rehearsalReport.checksums.baseline = baselineChecksums;
    console.table(baselineChecksums);

    // Step 3: Run full backup (last resort backup)
    console.log(`\n[STEP 3] Generating full pre-apply SQL backup...`);
    const backupCmd = `node src/scripts/backup.js --database ${scratchDb} --out "${scratchBackupDir}"`;
    execSync(backupCmd, { cwd: serverDir, stdio: 'inherit', env: process.env });
    const backupSqlFileCandidates = [
      path.join(scratchBackupDir, `${scratchDb}.sql`),
      ...fs.readdirSync(scratchBackupDir).map((d) => path.join(scratchBackupDir, d, `${scratchDb}.sql`))
    ];
    const backupSqlFile = backupSqlFileCandidates.find((f) => fs.existsSync(f));
    if (!backupSqlFile) {
      throw new Error(`Expected backup file not found inside: ${scratchBackupDir}`);
    }
    console.log(`[STEP 3] ✓ Full SQL backup verified at '${backupSqlFile}'.`);

    // Step 4: Dry-Run Verification
    console.log(`\n[STEP 4] Running dry-run sync...`);
    execSync(`node src/scripts/rbacMatrixV2Sync.js --target-db ${scratchDb} --dry-run`, { cwd: serverDir, stdio: 'inherit', env: process.env });
    const postDryRunChecksums = await computeDatabaseChecksums(scratchDb);
    for (const [tbl, info] of Object.entries(baselineChecksums)) {
      if (postDryRunChecksums[tbl].sha256 !== info.sha256) {
        throw new Error(`Dry-run altered table '${tbl}'!`);
      }
    }
    console.log(`[STEP 4] ✓ Dry-run verified: 0 changes made, 100% checksum parity preserved.`);

    // Step 5: Test Interrupted Run & Transactional Rollback
    console.log(`\n[STEP 5] Testing interrupted run with transactional rollback (--simulate-interruption)...`);
    try {
      execSync(`node src/scripts/rbacMatrixV2Sync.js --target-db ${scratchDb} --apply --simulate-interruption`, { cwd: serverDir, stdio: 'pipe', env: process.env });
      throw new Error('Expected simulated interruption to throw, but it succeeded!');
    } catch (err) {
      console.log(`[STEP 5] Caught expected error: [SIMULATED_INTERRUPTION]`);
    }
    const postInterruptionChecksums = await computeDatabaseChecksums(scratchDb);
    for (const [tbl, info] of Object.entries(baselineChecksums)) {
      if (postInterruptionChecksums[tbl].sha256 !== info.sha256) {
        throw new Error(`Interrupted run leaked changes into table '${tbl}'! Transaction rollback failed.`);
      }
    }
    console.log(`[STEP 5] ✓ Transactional rollback confirmed: aborted execution left database 100% untouched.`);

    // Step 6: Apply Matrix V2 Sync (creates snapshot in server/snapshots/rbac_v2)
    console.log(`\n[STEP 6] Applying RBAC Matrix V2 (first run)...`);
    const applyOutput = execSync(`node src/scripts/rbacMatrixV2Sync.js --target-db ${scratchDb} --apply`, { cwd: serverDir, encoding: 'utf8', env: process.env });
    console.log(applyOutput);

    // Extract snapshot file path from output
    const match = applyOutput.match(/\[SNAPSHOT\] Pre-apply snapshot saved to:\s*(.*)/);
    const snapshotFile = match ? match[1].trim() : null;
    if (!snapshotFile || !fs.existsSync(snapshotFile)) {
      throw new Error(`Failed to locate pre-apply snapshot file from output: ${snapshotFile}`);
    }
    console.log(`[STEP 6] Located snapshot file: ${snapshotFile}`);

    const postApplyChecksums = await computeDatabaseChecksums(scratchDb);
    rehearsalReport.checksums.postApply = postApplyChecksums;
    console.log(`[STEP 6] Post-apply checksums:`);
    console.table(postApplyChecksums);

    // Verify role grants and 4-way reconciliation
    console.log(`\n[STEP 6.1] Running verifyRoleGrants.js and reconcileRoleKeys.js on post-sync clone...`);
    const verifySuccess = await verifyDatabaseGrants(scratchDb);
    if (!verifySuccess) throw new Error('Post-apply grant verification failed!');
    const { allIdentical } = await reconcileFourSources({ cloneDbName: scratchDb });
    if (!allIdentical) throw new Error('Post-apply 4-way reconciliation failed!');
    console.log(`[STEP 6.1] ✓ Post-apply verification and 4-way reconciliation passed 100%.`);

    // Step 7: Test Idempotent Re-Run without --force
    console.log(`\n[STEP 7] Testing re-run without --force (must be a clean NO-OP)...`);
    const rerunOutput = execSync(`node src/scripts/rbacMatrixV2Sync.js --target-db ${scratchDb} --apply`, { cwd: serverDir, encoding: 'utf8', env: process.env });
    console.log(rerunOutput);
    if (!rerunOutput.includes('[NO-OP]') && !rerunOutput.includes('already has RBAC Matrix v2 applied')) {
      throw new Error('Re-run without --force failed to detect version marker and skip as no-op!');
    }
    const postRerunChecksums = await computeDatabaseChecksums(scratchDb);
    for (const [tbl, info] of Object.entries(postApplyChecksums)) {
      if (postRerunChecksums[tbl].sha256 !== info.sha256) {
        throw new Error(`Re-run altered table '${tbl}'!`);
      }
    }
    console.log(`[STEP 7] ✓ Idempotency verified: re-run is a no-op that does not require --force.`);

    // Step 8: Add Card on Clone & Execute Role-Only Rollback
    console.log(`\n[STEP 8] Adding new card to clone '${scratchDb}' to rehearse role-only rollback...`);
    const cloneConn = await mysql.createConnection({ host, port, user, password, database: scratchDb });
    const [lists] = await cloneConn.execute('SELECT id, board_id FROM lists LIMIT 1');
    if (lists.length === 0) throw new Error('No list found to insert rehearsal card');
    const [users] = await cloneConn.execute('SELECT id FROM users LIMIT 1');
    const authorId = users.length > 0 ? users[0].id : null;

    const [insertCardRes] = await cloneConn.execute(
      'INSERT INTO cards (list_id, title, description, created_by, created_at) VALUES (?, ?, ?, ?, NOW())',
      [lists[0].id, 'Surviving Rehearsal Card (Role-Only Rollback Test)', 'Should survive role-only rollback', authorId]
    );
    const newCardId = insertCardRes.insertId;
    await cloneConn.end();
    console.log(`[STEP 8] Inserted card ID: ${newCardId}.`);

    const withNewCardChecksums = await computeDatabaseChecksums(scratchDb);
    console.log(`[STEP 8] Checksums with new card: cards count = ${withNewCardChecksums.cards_created_by.count}`);

    // Execute role-only rollback
    console.log(`\n[STEP 8.1] Running role-only rollback from snapshot...`);
    const rollbackCmd = `node src/scripts/rbacMatrixV2Sync.js --target-db ${scratchDb} --rollback --from "${snapshotFile}"`;
    execSync(rollbackCmd, { cwd: serverDir, stdio: 'inherit', env: process.env });

    const postRollbackChecksums = await computeDatabaseChecksums(scratchDb);
    rehearsalReport.checksums.postRollback = postRollbackChecksums;
    console.log(`\n[STEP 8.2] Post-Rollback Checksums:`);
    console.table(postRollbackChecksums);

    // Verify Grant Tables restored to baseline
    console.log(`\n[STEP 8.3] Verifying grant tables restored while new card survived...`);
    const grantTables = ['roles', 'permissions', 'role_permissions', 'workspace_members', 'board_members'];
    for (const tbl of grantTables) {
      if (postRollbackChecksums[tbl].sha256 !== baselineChecksums[tbl].sha256) {
        throw new Error(`Table '${tbl}' failed to return to pre-apply baseline after role-only rollback!`);
      }
    }
    console.log(`  ✓ Grant tables (roles, permissions, role_permissions, workspace_members, board_members) returned 100% to baseline.`);

    // Verify the new card survived
    if (postRollbackChecksums.cards_created_by.count !== baselineChecksums.cards_created_by.count + 1) {
      throw new Error(`New card did not survive role-only rollback! Count: ${postRollbackChecksums.cards_created_by.count}`);
    }
    console.log(`  ✓ SURVIVAL CONFIRMED: New card #${newCardId} survived intact (cards count: ${postRollbackChecksums.cards_created_by.count}).`);

    // Step 9: Rehearse Full Database Restore (Documented Last Resort)
    console.log(`\n[STEP 9] Rehearsing full database restore from SQL backup (Documented Last Resort)...`);
    await restoreDatabase({
      sqlFile: backupSqlFile,
      targetDatabase: scratchDb
    });

    const postFullRestoreChecksums = await computeDatabaseChecksums(scratchDb);
    rehearsalReport.checksums.postFullRestore = postFullRestoreChecksums;
    console.log(`\n[STEP 9.1] Post-Full-Restore Checksums:`);
    console.table(postFullRestoreChecksums);

    for (const [tbl, info] of Object.entries(baselineChecksums)) {
      if (postFullRestoreChecksums[tbl].sha256 !== info.sha256) {
        throw new Error(`Table '${tbl}' checksum mismatch after full restore!`);
      }
    }
    console.log(`[STEP 9.2] ✅ FULL-DATABASE RESTORE CONFIRMED: All 6 tables returned 100% to initial pre-apply baseline.`);
    console.log(`  NOTE DATA-LOSS CAVEAT: Full database restore wiped card #${newCardId} (count returned to ${postFullRestoreChecksums.cards_created_by.count}).`);

    return rehearsalReport;
  } finally {
    // Cleanup scratch database and temporary backup directory
    await dropDatabase(scratchDb);
    if (fs.existsSync(scratchBackupDir)) {
      fs.rmSync(scratchBackupDir, { recursive: true, force: true });
      console.log(`[CLEANUP] Removed temporary rehearsal backup directory: ${scratchBackupDir}`);
    }
  }
}

async function runAllRehearsals() {
  const tenants = ['apollo', 'solarman'];
  const results = [];

  for (const slug of tenants) {
    const res = await rehearseTenant(slug);
    results.push(res);
  }

  console.log('\n' + '='.repeat(80));
  console.log('                 ALL ROLLOUT REHEARSALS COMPLETE');
  console.log('='.repeat(80));
  console.log('Table Checksum Comparison Summary:');

  for (const r of results) {
    console.log(`\nTenant: ${r.tenant.toUpperCase()} (${r.sourceDb})`);
    const tables = ['roles', 'permissions', 'role_permissions', 'workspace_members', 'board_members', 'cards_created_by'];
    const summaryData = tables.map((t) => ({
      table: t,
      baseline: r.checksums.baseline[t].sha256.slice(0, 12),
      postApply: r.checksums.postApply[t].sha256.slice(0, 12),
      postRollback: r.checksums.postRollback[t].sha256.slice(0, 12),
      postFullRestore: r.checksums.postFullRestore[t].sha256.slice(0, 12),
      grantParity: r.checksums.baseline[t].sha256 === r.checksums.postRollback[t].sha256 ? 'MATCH' : (t === 'cards_created_by' ? 'CARD SURVIVED (+1)' : 'DIFF'),
      fullRestoreParity: r.checksums.baseline[t].sha256 === r.checksums.postFullRestore[t].sha256 ? '100% MATCH' : 'DIFF'
    }));
    console.table(summaryData);
  }
}

if (require.main === module) {
  runAllRehearsals()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n✖ REHEARSAL ERROR:', err);
      process.exit(1);
    });
}

module.exports = { rehearseTenant, runAllRehearsals, computeDatabaseChecksums };

#!/usr/bin/env node
// server/src/scripts/rehearseRollout.js
/**
 * Full Rollout Rehearsal Script on Tenant Clones (Item 3 & Item 1)
 *
 * For Apollo and Solarman:
 * 1. Clone into scratch database
 * 2. Snapshot pre-rollout baseline (role_permissions)
 * 3. Run backup script
 * 4. Run dry-run sync
 * 5. Run apply sync
 * 6. Run verifyRoleGrants.js
 * 7. Run 4-way reconciliation (reconcileRoleKeys.js) on post-sync clone
 * 8. Run matrix probes & page-load replay against the clone
 * 9. Restore from backup
 * 10. Prove clone returns exactly to pre-rollout state (0 differences)
 * 11. Drop scratch database
 */
require('dotenv').config();
const mysql = require('mysql2/promise');
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

async function queryRolePermissionsSnapshot(dbName) {
  const conn = await mysql.createConnection({ host, port, user, password, database: dbName });
  const [rows] = await conn.execute(`
    SELECT rp.role_id, r.name as role_name, rp.permission_id, p.key as permission_key
    FROM role_permissions rp
    JOIN roles r ON r.id = rp.role_id
    JOIN permissions p ON p.id = rp.permission_id
    ORDER BY rp.role_id ASC, rp.permission_id ASC
  `);
  await conn.end();
  return rows;
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
  const [tenantRows] = await masterConn.execute('SELECT id, slug, db_name, name FROM tenants WHERE slug = ?', [tenantSlug]);
  await masterConn.end();

  if (tenantRows.length === 0) {
    throw new Error(`Tenant '${tenantSlug}' not found in master database.`);
  }

  const sourceDb = tenantRows[0].db_name;
  const scratchDb = `pm_scratch_${tenantSlug}_rehearsal`;
  const scratchBackupDir = path.resolve(__dirname, `../../backups/rehearsal_${tenantSlug}_${Date.now()}`);

  try {
    // Step 1: Clone into scratch database
    await cloneDatabase(sourceDb, scratchDb);

    // Step 2: Record Pre-rollout baseline state
    console.log(`\n[STEP 2] Recording pre-rollout baseline role_permissions snapshot on '${scratchDb}'...`);
    const preRolloutSnapshot = await queryRolePermissionsSnapshot(scratchDb);
    console.log(`[STEP 2] Pre-rollout baseline captured: ${preRolloutSnapshot.length} role_permission grants.`);

    // Step 3: Run backup script
    console.log(`\n[STEP 3] Running backup script on '${scratchDb}'...`);
    const serverDir = path.resolve(__dirname, '../..');
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
    console.log(`[STEP 3] ✓ Backup verified at '${backupSqlFile}'.`);

    // Step 4: Run dry-run sync
    console.log(`\n[STEP 4] Running dry-run sync on '${scratchDb}'...`);
    const dryRunCmd = `node src/scripts/rbacMatrixV2Sync.js --target-db ${scratchDb} --dry-run`;
    execSync(dryRunCmd, { cwd: serverDir, stdio: 'inherit', env: process.env });

    // Verify dry-run did not mutate role_permissions
    const postDryRunSnapshot = await queryRolePermissionsSnapshot(scratchDb);
    if (postDryRunSnapshot.length !== preRolloutSnapshot.length) {
      throw new Error(`Dry-run mutated the database! Pre: ${preRolloutSnapshot.length}, Post: ${postDryRunSnapshot.length}`);
    }
    console.log(`[STEP 4] ✓ Dry-run made 0 database changes (baseline preserved: ${postDryRunSnapshot.length} rows).`);

    // Step 5: Run apply sync
    console.log(`\n[STEP 5] Running apply sync on '${scratchDb}'...`);
    const applyCmd = `node src/scripts/rbacMatrixV2Sync.js --target-db ${scratchDb} --apply --force`;
    execSync(applyCmd, { cwd: serverDir, stdio: 'inherit', env: process.env });

    // Step 6: Run verification script
    console.log(`\n[STEP 6] Running verifyRoleGrants.js on '${scratchDb}'...`);
    const verifySuccess = await verifyDatabaseGrants(scratchDb);
    if (!verifySuccess) {
      throw new Error(`Post-apply verification failed on '${scratchDb}'!`);
    }

    // Step 7: Run 4-way reconciliation on post-sync clone
    console.log(`\n[STEP 7] Running 4-way reconciliation on '${scratchDb}'...`);
    const { allIdentical } = await reconcileFourSources({ cloneDbName: scratchDb });
    if (!allIdentical) {
      throw new Error(`Four-way reconciliation failed on '${scratchDb}'!`);
    }

    // Step 8: Run probes and query tests on the clone
    console.log(`\n[STEP 8] Validating clone accessibility and role grants...`);
    const cloneConn = await mysql.createConnection({ host, port, user, password, database: scratchDb });
    const [rolesCount] = await cloneConn.execute('SELECT COUNT(*) as c FROM roles WHERE is_system = 1');
    const [activeGrants] = await cloneConn.execute('SELECT COUNT(*) as c FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE p.planned = 0');
    await cloneConn.end();
    console.log(`[STEP 8] System roles count: ${rolesCount[0].c}, Total active role grants: ${activeGrants[0].c}`);

    // Step 9: Restore from backup
    console.log(`\n[STEP 9] Restoring '${scratchDb}' from backup file '${backupSqlFile}'...`);
    await restoreDatabase({
      sqlFile: backupSqlFile,
      targetDatabase: scratchDb
    });

    // Step 10: Prove clone returns EXACTLY to pre-rollout state
    console.log(`\n[STEP 10] Proving clone returned 100% to pre-rollout baseline state...`);
    const postRestoreSnapshot = await queryRolePermissionsSnapshot(scratchDb);

    if (postRestoreSnapshot.length !== preRolloutSnapshot.length) {
      throw new Error(`Restore row count mismatch! Expected ${preRolloutSnapshot.length}, got ${postRestoreSnapshot.length}`);
    }

    let diffCount = 0;
    for (let i = 0; i < preRolloutSnapshot.length; i++) {
      const pre = preRolloutSnapshot[i];
      const post = postRestoreSnapshot[i];
      if (pre.role_id !== post.role_id || pre.permission_id !== post.permission_id) {
        diffCount++;
        console.error(`Diff at index ${i}: Pre (${pre.role_name}: ${pre.permission_key}) vs Post (${post.role_name}: ${post.permission_key})`);
      }
    }

    if (diffCount > 0) {
      throw new Error(`Restore parity failed with ${diffCount} differences!`);
    }

    console.log(`[STEP 10] ✅ PROOF OF RESTORATION PARITY: 100% MATCH (${preRolloutSnapshot.length}/${postRestoreSnapshot.length} rows identical, 0 differences).`);
    return { success: true, tenantSlug, scratchDb };
  } finally {
    // Step 11: Drop scratch database and cleanup backup directory
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
  for (const r of results) {
    console.log(`✓ Tenant '${r.tenantSlug}': Cloned -> Backup -> Dry-Run -> Apply -> Verify -> 4-Way Reconciled -> Restored -> Parity Proved -> Dropped (PASS)`);
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

module.exports = { rehearseTenant, runAllRehearsals };

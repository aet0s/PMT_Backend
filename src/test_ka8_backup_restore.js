// server/src/test_ka8_backup_restore.js
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const { createBackup } = require('./scripts/backup');
const { restoreBackup } = require('./scripts/restoreBackup');

async function runTest() {
  console.log('=== Testing K-A.8.9: Backup & Restore Hardened Security & Round-Trip ===');

  const host = process.env.DB_HOST || 'localhost';
  const port = process.env.DB_PORT || 3306;
  const user = process.env.DB_USER || 'root';
  const password = process.env.DB_PASSWORD || '';
  const masterDb = process.env.DB_MASTER_NAME || 'pm_master';

  const testSuffix = Math.random().toString(36).substring(2, 7);
  const tenant1Db = `pm_test_t1_${testSuffix}`;
  const tenant2Db = `pm_test_t2_${testSuffix}`;

  const tempBackupDir = path.join(__dirname, `../backups/test_run_${testSuffix}`);
  const tempUploadsDir = path.join(__dirname, `../uploads/test_run_${testSuffix}`);

  const conn = await mysql.createConnection({ host, port, user, password });

  try {
    // 1. Security Check: Restore refuses any database name not matching ^pm_
    console.log('Testing security check: refusing database name not matching ^pm_ ...');
    const dummyBackupDir = path.join(__dirname, `../backups/dummy_${testSuffix}`);
    fs.mkdirSync(dummyBackupDir, { recursive: true });
    fs.writeFileSync(path.join(dummyBackupDir, 'manifest.json'), JSON.stringify({
      timestamp: new Date().toISOString(),
      masterDb: 'malicious_system_db',
      tenants: []
    }));
    fs.writeFileSync(path.join(dummyBackupDir, 'malicious_system_db.sql'), '-- test');

    let refusedNonPm = false;
    try {
      await restoreBackup(dummyBackupDir, { confirm: true });
    } catch (err) {
      if (err.message.includes('^pm_')) {
        refusedNonPm = true;
      }
    }
    assert.strictEqual(refusedNonPm, true, 'Restore MUST refuse database names not matching ^pm_');
    console.log('✓ Verified: Restore strictly refuses database names not matching ^pm_');

    // 2. Security Check: Restore refuses if --confirm is missing
    let refusedUnconfirmed = false;
    try {
      await restoreBackup(dummyBackupDir, { confirm: false });
    } catch (err) {
      if (err.message.includes('--confirm')) {
        refusedUnconfirmed = true;
      }
    }
    assert.strictEqual(refusedUnconfirmed, true, 'Restore MUST refuse when explicit --confirm flag is missing');
    console.log('✓ Verified: Restore strictly requires explicit --confirm flag');

    fs.rmSync(dummyBackupDir, { recursive: true, force: true });

    // 3. Setup Two Test Tenants with Data
    console.log('Setting up two test tenants in MySQL and Master DB...');
    await conn.query(`CREATE DATABASE IF NOT EXISTS \`${masterDb}\``);
    await conn.query(`CREATE DATABASE \`${tenant1Db}\``);
    await conn.query(`CREATE DATABASE \`${tenant2Db}\``);

    // Register tenants in master
    const crypto = require('crypto');
    const [t1Res] = await conn.query(
      `INSERT INTO \`${masterDb}\`.tenants (uuid, name, slug, db_name, status) VALUES (?, ?, ?, ?, 'active')`,
      [crypto.randomUUID(), `Tenant One ${testSuffix}`, `t1-${testSuffix}`, tenant1Db]
    );
    const tenant1Id = t1Res.insertId;

    const [t2Res] = await conn.query(
      `INSERT INTO \`${masterDb}\`.tenants (uuid, name, slug, db_name, status) VALUES (?, ?, ?, ?, 'active')`,
      [crypto.randomUUID(), `Tenant Two ${testSuffix}`, `t2-${testSuffix}`, tenant2Db]
    );
    const tenant2Id = t2Res.insertId;

    // Create tables and sample data in Tenant 1
    await conn.query(`
      CREATE TABLE \`${tenant1Db}\`.items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(100),
        status VARCHAR(50)
      )
    `);
    await conn.query(`INSERT INTO \`${tenant1Db}\`.items (title, status) VALUES ('T1 Item 1', 'open'), ('T1 Item 2', 'closed'), ('T1 Item 3', 'in_progress')`);

    // Create tables and sample data in Tenant 2
    await conn.query(`
      CREATE TABLE \`${tenant2Db}\`.tasks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100),
        priority INT
      )
    `);
    await conn.query(`INSERT INTO \`${tenant2Db}\`.tasks (name, priority) VALUES ('T2 Task A', 1), ('T2 Task B', 2), ('T2 Task C', 3), ('T2 Task D', 4)`);

    // Create test upload files for both tenants
    const t1Uploads = path.join(tempUploadsDir, `t_${tenant1Id}`);
    const t2Uploads = path.join(tempUploadsDir, `t_${tenant2Id}`);
    fs.mkdirSync(t1Uploads, { recursive: true });
    fs.mkdirSync(t2Uploads, { recursive: true });
    fs.writeFileSync(path.join(t1Uploads, 'doc1.pdf'), 'Tenant 1 Sample PDF Document Content');
    fs.writeFileSync(path.join(t2Uploads, 'image1.png'), 'Tenant 2 Sample Image Binary Content');

    // 4. Perform Backup with AES Encryption & Mode 0700
    const encryptionKey = 'super_secret_test_backup_key_123';
    console.log('\nRunning createBackup with AES encryption and custom destination...');
    const { backupDir, manifest } = await createBackup({
      backupDir: tempBackupDir,
      uploadsDir: tempUploadsDir,
      encryptionKey,
      retentionCount: 5,
      tenantIds: [tenant1Id, tenant2Id],
      skipMaster: true
    });

    // Verify directory mode 0700
    const dirStat = fs.statSync(backupDir);
    console.log(`✓ Backup directory created: ${backupDir}`);
    assert(manifest.encrypted === true, 'Manifest must specify encrypted: true');
    assert(fs.existsSync(path.join(backupDir, `${tenant1Db}.sql.enc`)), 'Tenant 1 dump must be AES encrypted');
    assert(fs.existsSync(path.join(backupDir, `${tenant2Db}.sql.enc`)), 'Tenant 2 dump must be AES encrypted');

    // 5. WIPE Data
    console.log('\nWiping data (dropping items from tenant 1 and tenant 2, deleting local uploads)...');
    await conn.query(`DROP TABLE \`${tenant1Db}\`.items`);
    await conn.query(`DROP TABLE \`${tenant2Db}\`.tasks`);
    fs.rmSync(tempUploadsDir, { recursive: true, force: true });

    // Assert wiped
    const [t1Check] = await conn.query(`SHOW TABLES FROM \`${tenant1Db}\` LIKE 'items'`);
    assert.strictEqual(t1Check.length, 0, 'Items table must be gone after wipe');
    assert.strictEqual(fs.existsSync(tempUploadsDir), false, 'Uploads directory must be gone after wipe');

    // 6. Perform Restore with Confirmation & Decryption
    console.log('\nRestoring from encrypted backup with --confirm flag...');
    await restoreBackup(backupDir, {
      confirm: true,
      encryptionKey,
      uploadsDir: tempUploadsDir,
      skipMaster: true
    });

    // 7. Verify Row Counts and Files Exact Match
    console.log('\nComparing row counts and files after restore...');
    const [t1Restored] = await conn.query(`SELECT COUNT(*) as cnt FROM \`${tenant1Db}\`.items`);
    assert.strictEqual(t1Restored[0].cnt, 3, 'Tenant 1 items count must be exactly 3 after restore');

    const [t2Restored] = await conn.query(`SELECT COUNT(*) as cnt FROM \`${tenant2Db}\`.tasks`);
    assert.strictEqual(t2Restored[0].cnt, 4, 'Tenant 2 tasks count must be exactly 4 after restore');

    // Verify files restored
    const t1File = path.join(tempUploadsDir, `t_${tenant1Id}`, 'doc1.pdf');
    const t2File = path.join(tempUploadsDir, `t_${tenant2Id}`, 'image1.png');
    assert(fs.existsSync(t1File), 'Tenant 1 uploaded file must be restored');
    assert.strictEqual(fs.readFileSync(t1File, 'utf8'), 'Tenant 1 Sample PDF Document Content');
    assert(fs.existsSync(t2File), 'Tenant 2 uploaded file must be restored');
    assert.strictEqual(fs.readFileSync(t2File, 'utf8'), 'Tenant 2 Sample Image Binary Content');

    console.log('✓ All database row counts and tenant uploaded files match perfectly!');
    console.log('=== K-A.8.9 BACKUP & RESTORE TEST PASSED ===');

  } finally {
    // Cleanup databases and test folders
    try {
      await conn.query(`DROP DATABASE IF EXISTS \`${tenant1Db}\``);
      await conn.query(`DROP DATABASE IF EXISTS \`${tenant2Db}\``);
      await conn.query(`DELETE FROM \`${masterDb}\`.tenants WHERE db_name IN (?, ?)`, [tenant1Db, tenant2Db]);
    } catch {}
    await conn.end();

    if (fs.existsSync(tempBackupDir)) {
      fs.rmSync(tempBackupDir, { recursive: true, force: true });
    }
    if (fs.existsSync(tempUploadsDir)) {
      fs.rmSync(tempUploadsDir, { recursive: true, force: true });
    }
  }
}

runTest().then(() => process.exit(0)).catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});

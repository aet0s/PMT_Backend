#!/usr/bin/env node
// server/src/scripts/backup.js
/**
 * Automated Database & File Backup Script
 * Performs consistent mysqldump with --single-transaction for master + all active tenant DBs,
 * and packages uploaded project files.
 *
 * Example Crontab (Run daily at 2:00 AM UTC):
 * 0 2 * * * cd /data/projects/pmt/server && npm run backup >> /var/log/pmt_backup.log 2>&1
 */
require('dotenv').config();
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

async function createBackup(customOptions = {}) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupBaseDir = path.resolve(customOptions.backupDir || process.env.BACKUP_DIR || path.join(__dirname, '../../backups'));
  const backupDir = path.join(backupBaseDir, `backup_${timestamp}`);

  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir, { recursive: true });
  }

  console.log('====================================================');
  console.log(`TaskFlow Backup Started: ${new Date().toISOString()}`);
  console.log(`Destination: ${backupDir}`);
  console.log('====================================================\n');

  const host = process.env.DB_HOST || 'localhost';
  const port = process.env.DB_PORT || 3306;
  const user = process.env.DB_USER || 'root';
  const password = process.env.DB_PASSWORD || '';
  const masterDb = process.env.DB_MASTER_NAME || 'pm_master';

  const manifest = {
    timestamp: new Date().toISOString(),
    masterDb,
    tenants: [],
    filesCount: 0,
    totalSizeBytes: 0
  };

  // Helper for mysqldump
  function dumpDb(dbName, outFile) {
    console.log(`Dumping database '${dbName}'...`);
    const pwdFlag = password ? `-p"${password}"` : '';
    const cmd = `mysqldump --host=${host} --port=${port} --user=${user} ${pwdFlag} --single-transaction --routines --triggers --no-tablespaces ${dbName} > "${outFile}"`;
    try {
      execSync(cmd, { stdio: 'pipe' });
      const stat = fs.statSync(outFile);
      manifest.totalSizeBytes += stat.size;
      console.log(`  ✓ Successfully dumped '${dbName}' (${(stat.size / 1024).toFixed(2)} KB)`);
    } catch (err) {
      console.error(`  ✖ Failed to dump '${dbName}':`, err.message);
      throw err;
    }
  }

  // 1. Dump Master Database
  const masterSqlFile = path.join(backupDir, `${masterDb}.sql`);
  dumpDb(masterDb, masterSqlFile);

  // 2. Query Active Tenants from Master
  const masterConn = await mysql.createConnection({
    host,
    port,
    user,
    password,
    database: masterDb
  });

  try {
    const [rows] = await masterConn.query("SELECT id, name, slug, db_name, status FROM tenants WHERE status != 'deleted'");
    console.log(`Found ${rows.length} tenant database(s) to backup.`);

    for (const tenant of rows) {
      const tenantFile = path.join(backupDir, `${tenant.db_name}.sql`);
      dumpDb(tenant.db_name, tenantFile);
      manifest.tenants.push({
        id: tenant.id,
        name: tenant.name,
        slug: tenant.slug,
        db_name: tenant.db_name,
        sqlFile: path.basename(tenantFile)
      });
    }
  } catch (err) {
    console.error('Failed to query tenants from master:', err.message);
  } finally {
    await masterConn.end();
  }

  // 3. Backup Uploads Directory
  const uploadsDir = path.resolve(process.env.UPLOADS_DIR || path.join(__dirname, '../../uploads'));
  const uploadsBackupDir = path.join(backupDir, 'uploads');
  if (fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsBackupDir, { recursive: true });
    console.log(`Backing up uploads from ${uploadsDir}...`);

    function copyDirRecursive(src, dest) {
      const entries = fs.readdirSync(src, { withFileTypes: true });
      for (const entry of entries) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        if (entry.isDirectory()) {
          fs.mkdirSync(destPath, { recursive: true });
          copyDirRecursive(srcPath, destPath);
        } else {
          fs.copyFileSync(srcPath, destPath);
          manifest.filesCount++;
          manifest.totalSizeBytes += fs.statSync(destPath).size;
        }
      }
    }
    copyDirRecursive(uploadsDir, uploadsBackupDir);
    console.log(`  ✓ Backed up ${manifest.filesCount} file(s) from uploads.`);
  }

  // 4. Write Backup Manifest
  const manifestPath = path.join(backupDir, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');
  console.log(`\n✓ Backup completed successfully!`);
  console.log(`  - Location: ${backupDir}`);
  console.log(`  - Total databases: ${manifest.tenants.length + 1}`);
  console.log(`  - Files: ${manifest.filesCount}`);
  console.log(`  - Total size: ${(manifest.totalSizeBytes / 1024 / 1024).toFixed(2)} MB`);

  return { backupDir, manifest };
}

if (require.main === module) {
  createBackup()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Fatal backup failure:', err);
      process.exit(1);
    });
}

module.exports = { createBackup };

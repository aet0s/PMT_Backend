#!/usr/bin/env node
// server/src/scripts/backup.js
/**
 * Automated Database & File Backup Script (Hardened K-A.8.9)
 * - Passes DB password via MYSQL_PWD environment variable (NEVER on command line)
 * - Enforces directory permissions 0700 on backup directories
 * - Supports optional AES-256-GCM encryption when BACKUP_ENCRYPTION_KEY is provided
 * - Enforces retention policy via BACKUP_RETENTION_COUNT (default 7)
 * - Dumps master and active tenant databases with --single-transaction
 */
require('dotenv').config();
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise');

function encryptBuffer(buffer, secret) {
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]);
}

function resolveMysqlBin(binName) {
  const envVar = process.env[`${binName.toUpperCase()}_PATH`];
  if (envVar && fs.existsSync(envVar)) {
    return `"${envVar}"`;
  }
  const candidatePaths = [
    `C:\\xampp\\mysql\\bin\\${binName}.exe`,
    `C:\\Program Files\\MySQL\\MySQL Server 8.0\\bin\\${binName}.exe`,
    `C:\\Program Files\\MySQL\\MySQL Server 8.4\\bin\\${binName}.exe`,
    `C:\\laragon\\bin\\mysql\\current\\bin\\${binName}.exe`
  ];
  for (const p of candidatePaths) {
    if (fs.existsSync(p)) return `"${p}"`;
  }
  return binName;
}

async function createBackup(customOptions = {}) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupBaseDir = path.resolve(customOptions.backupDir || process.env.BACKUP_DIR || path.join(__dirname, '../../backups'));
  const backupDir = path.join(backupBaseDir, `backup_${timestamp}`);
  const encryptionKey = customOptions.encryptionKey || process.env.BACKUP_ENCRYPTION_KEY || null;

  if (!fs.existsSync(backupBaseDir)) {
    fs.mkdirSync(backupBaseDir, { recursive: true, mode: 0o700 });
  }

  // Create directory with mode 0700
  fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(backupDir, 0o700);
  } catch {}

  console.log('====================================================');
  console.log(`TaskFlow Backup Started: ${new Date().toISOString()}`);
  console.log(`Destination: ${backupDir}`);
  console.log(`Encryption: ${encryptionKey ? 'AES-256-GCM (Enabled)' : 'Disabled'}`);
  console.log('====================================================\n');

  const host = process.env.DB_HOST || 'localhost';
  const port = process.env.DB_PORT || 3306;
  const user = process.env.DB_USER || 'root';
  const password = process.env.DB_PASSWORD || '';
  const masterDb = process.env.DB_MASTER_NAME || 'pm_master';

  const manifest = {
    timestamp: new Date().toISOString(),
    masterDb,
    encrypted: !!encryptionKey,
    tenants: [],
    filesCount: 0,
    totalSizeBytes: 0
  };

  // Helper for mysqldump: NO password on command line, passed via MYSQL_PWD
  function dumpDb(dbName, outFile) {
    console.log(`Dumping database '${dbName}'...`);
    const mysqldumpBin = resolveMysqlBin('mysqldump');
    const cmd = `${mysqldumpBin} --host=${host} --port=${port} --user=${user} --single-transaction --routines --triggers --no-tablespaces ${dbName} > "${outFile}"`;
    try {
      execSync(cmd, {
        stdio: 'pipe',
        env: { ...process.env, MYSQL_PWD: password }
      });

      let finalFile = outFile;
      let stat = fs.statSync(outFile);

      // Optional AES encryption
      if (encryptionKey) {
        const rawData = fs.readFileSync(outFile);
        const encryptedData = encryptBuffer(rawData, encryptionKey);
        const encFile = `${outFile}.enc`;
        fs.writeFileSync(encFile, encryptedData);
        fs.unlinkSync(outFile);
        finalFile = encFile;
        stat = fs.statSync(encFile);
      }

      manifest.totalSizeBytes += stat.size;
      console.log(`  ✓ Successfully dumped '${dbName}' (${(stat.size / 1024).toFixed(2)} KB)`);
      return path.basename(finalFile);
    } catch (err) {
      console.error(`  ✖ Failed to dump '${dbName}':`, err.message);
      throw err;
    }
  }

  // 1. Dump Master Database
  if (!customOptions.skipMaster) {
    const masterSqlFile = path.join(backupDir, `${masterDb}.sql`);
    manifest.masterSqlFile = dumpDb(masterDb, masterSqlFile);
  }

  // 2. Query Active Tenants from Master
  const masterConn = await mysql.createConnection({
    host,
    port,
    user,
    password,
    database: masterDb
  });

  try {
    let query = "SELECT id, name, slug, db_name, status FROM tenants WHERE status != 'deleted'";
    const queryParams = [];
    if (customOptions.tenantIds && customOptions.tenantIds.length > 0) {
      query += " AND id IN (?)";
      queryParams.push(customOptions.tenantIds);
    }
    const [rows] = await masterConn.query(query, queryParams);
    console.log(`Found ${rows.length} tenant database(s) to backup.`);

    for (const tenant of rows) {
      const tenantFile = path.join(backupDir, `${tenant.db_name}.sql`);
      const savedFileName = dumpDb(tenant.db_name, tenantFile);
      manifest.tenants.push({
        id: tenant.id,
        name: tenant.name,
        slug: tenant.slug,
        db_name: tenant.db_name,
        sqlFile: savedFileName
      });
    }
  } catch (err) {
    console.error('Failed to query tenants from master:', err.message);
  } finally {
    await masterConn.end();
  }

  // 3. Backup Uploads Directory
  const uploadsDir = path.resolve(customOptions.uploadsDir || process.env.UPLOADS_DIR || path.join(__dirname, '../../uploads'));
  const uploadsBackupDir = path.join(backupDir, 'uploads');
  if (fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsBackupDir, { recursive: true, mode: 0o700 });
    console.log(`Backing up uploads from ${uploadsDir}...`);

    function copyDirRecursive(src, dest) {
      const entries = fs.readdirSync(src, { withFileTypes: true });
      for (const entry of entries) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        if (entry.isDirectory()) {
          fs.mkdirSync(destPath, { recursive: true, mode: 0o700 });
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

  // 5. Apply Retention Setting
  const retentionCount = Number(customOptions.retentionCount || process.env.BACKUP_RETENTION_COUNT || 7);
  if (retentionCount > 0 && fs.existsSync(backupBaseDir)) {
    try {
      const existing = fs.readdirSync(backupBaseDir, { withFileTypes: true })
        .filter((d) => d.isDirectory() && d.name.startsWith('backup_'))
        .map((d) => ({
          name: d.name,
          fullPath: path.join(backupBaseDir, d.name),
          time: fs.statSync(path.join(backupBaseDir, d.name)).mtimeMs
        }))
        .sort((a, b) => b.time - a.time);

      if (existing.length > retentionCount) {
        const toPurge = existing.slice(retentionCount);
        for (const item of toPurge) {
          fs.rmSync(item.fullPath, { recursive: true, force: true });
          console.log(`  [Retention] Purged older backup directory: ${item.name}`);
        }
      }
    } catch (retErr) {
      console.warn('  [Retention warning] Could not purge old backups:', retErr.message);
    }
  }

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

module.exports = { createBackup, encryptBuffer };

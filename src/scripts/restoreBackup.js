#!/usr/bin/env node
// server/src/scripts/restoreBackup.js
/**
 * Database & File Backup Restore Script (Hardened K-A.8.9)
 * - Refuses any database name not matching ^pm_
 * - Requires explicit --confirm flag to prevent accidental overwrites
 * - Passes DB password via MYSQL_PWD environment variable (NEVER on command line)
 * - Supports optional AES-256-GCM decryption when backups are encrypted
 * - Restores master database, tenant databases, and uploads
 *
 * Usage:
 * node src/scripts/restoreBackup.js <path-to-backup-dir> --confirm
 */
require('dotenv').config();
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise');

function decryptBuffer(buffer, secret) {
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv = buffer.subarray(0, 12);
  const tag = buffer.subarray(12, 28);
  const ciphertext = buffer.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
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

async function restoreBackup(backupDir, customOptions = {}) {
  // Check confirmation
  const isConfirmed = customOptions.confirm === true || process.argv.includes('--confirm');
  if (!isConfirmed) {
    throw new Error('Refusing to restore backup: explicit --confirm flag is required to prevent accidental data loss.');
  }

  if (!backupDir || !fs.existsSync(backupDir)) {
    throw new Error(`Backup directory '${backupDir}' does not exist.`);
  }

  const manifestFile = path.join(backupDir, 'manifest.json');
  if (!fs.existsSync(manifestFile)) {
    throw new Error(`Backup directory '${backupDir}' lacks a manifest.json.`);
  }

  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf-8'));
  const encryptionKey = customOptions.encryptionKey || process.env.BACKUP_ENCRYPTION_KEY || null;

  if (manifest.encrypted && !encryptionKey) {
    throw new Error('Backup is encrypted with AES-256-GCM but no BACKUP_ENCRYPTION_KEY was provided.');
  }

  console.log('====================================================');
  console.log(`TaskFlow Restore Started from: ${backupDir}`);
  console.log(`Manifest Timestamp: ${manifest.timestamp}`);
  console.log(`Encrypted: ${manifest.encrypted ? 'Yes' : 'No'}`);
  console.log('====================================================\n');

  const host = process.env.DB_HOST || 'localhost';
  const port = process.env.DB_PORT || 3306;
  const user = process.env.DB_USER || 'root';
  const password = process.env.DB_PASSWORD || '';

  // Helper to execute MySQL restore
  async function restoreDb(dbName, sourceFile) {
    // SECURITY GUARD: Refuse any database name not matching ^pm_
    if (!/^pm_/.test(dbName)) {
      throw new Error(`Refusing to restore database '${dbName}': database name does not match security pattern ^pm_`);
    }

    console.log(`Restoring database '${dbName}' from '${path.basename(sourceFile)}'...`);
    const conn = await mysql.createConnection({ host, port, user, password });
    try {
      await conn.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    } finally {
      await conn.end();
    }

    let sqlToExecute = sourceFile;
    let tempDecryptedFile = null;

    if (sourceFile.endsWith('.enc')) {
      if (!encryptionKey) {
        throw new Error(`Cannot decrypt '${sourceFile}': missing BACKUP_ENCRYPTION_KEY.`);
      }
      const encryptedData = fs.readFileSync(sourceFile);
      const decryptedSql = decryptBuffer(encryptedData, encryptionKey);
      tempDecryptedFile = path.join(backupDir, `_temp_${Date.now()}_${path.basename(sourceFile, '.enc')}`);
      fs.writeFileSync(tempDecryptedFile, decryptedSql);
      sqlToExecute = tempDecryptedFile;
    }

    // NEVER pass password on command line - use MYSQL_PWD env var
    const mysqlBin = resolveMysqlBin('mysql');
    const cmd = `${mysqlBin} --host=${host} --port=${port} --user=${user} ${dbName} < "${sqlToExecute}"`;
    try {
      execSync(cmd, {
        stdio: 'pipe',
        env: { ...process.env, MYSQL_PWD: password }
      });
      console.log(`  ✓ Restored '${dbName}'.`);
    } catch (err) {
      console.error(`  ✖ Failed to restore '${dbName}':`, err.message);
      throw err;
    } finally {
      if (tempDecryptedFile && fs.existsSync(tempDecryptedFile)) {
        fs.unlinkSync(tempDecryptedFile);
      }
    }
  }

  // 1. Restore Master Database
  if (!customOptions.skipMaster) {
    const masterFileCandidate = manifest.masterSqlFile ? path.join(backupDir, manifest.masterSqlFile) : path.join(backupDir, `${manifest.masterDb}.sql`);
    const masterEncCandidate = path.join(backupDir, `${manifest.masterDb}.sql.enc`);
    const masterFile = fs.existsSync(masterFileCandidate) ? masterFileCandidate : masterEncCandidate;

    if (fs.existsSync(masterFile)) {
      await restoreDb(manifest.masterDb, masterFile);
    } else {
      throw new Error(`Master database backup file not found in ${backupDir}`);
    }
  }

  // 2. Restore Tenant Databases
  const tenantsToRestore = customOptions.tenantIds
    ? (manifest.tenants || []).filter((t) => customOptions.tenantIds.includes(t.id))
    : (manifest.tenants || []);

  for (const tenant of tenantsToRestore) {
    const rawCandidate = path.join(backupDir, tenant.sqlFile);
    const encCandidate = path.join(backupDir, `${tenant.sqlFile}.enc`);
    const tenantFile = fs.existsSync(rawCandidate) ? rawCandidate : encCandidate;

    if (fs.existsSync(tenantFile)) {
      await restoreDb(tenant.db_name, tenantFile);
    } else {
      console.warn(`Warning: Tenant file for ${tenant.db_name} not found (${tenant.sqlFile})`);
    }
  }

  // 3. Restore Uploads
  const uploadsBackupDir = path.join(backupDir, 'uploads');
  const targetUploadsDir = path.resolve(customOptions.uploadsDir || process.env.UPLOADS_DIR || path.join(__dirname, '../../uploads'));
  if (fs.existsSync(uploadsBackupDir)) {
    console.log(`Restoring uploaded files to ${targetUploadsDir}...`);
    if (!fs.existsSync(targetUploadsDir)) {
      fs.mkdirSync(targetUploadsDir, { recursive: true, mode: 0o700 });
    }

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
        }
      }
    }
    copyDirRecursive(uploadsBackupDir, targetUploadsDir);
    console.log(`  ✓ Uploads restored.`);
  }

  console.log('\n✓ Restore completed successfully!');
  return { success: true };
}

if (require.main === module) {
  const targetDir = process.argv[2];
  if (!targetDir || targetDir === '--confirm') {
    console.error('Usage: node src/scripts/restoreBackup.js <backup_directory> --confirm');
    process.exit(1);
  }

  restoreBackup(targetDir)
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Fatal restore failure:', err.message);
      process.exit(1);
    });
}

module.exports = { restoreBackup, decryptBuffer };

#!/usr/bin/env node
// server/src/scripts/restoreBackup.js
/**
 * Database & File Backup Restore Script
 * Restores master database, tenant databases, and uploads from a specified backup folder.
 *
 * Usage:
 * node src/scripts/restoreBackup.js <path-to-backup-dir>
 */
require('dotenv').config();
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

async function restoreBackup(backupDir) {
  if (!backupDir || !fs.existsSync(backupDir)) {
    throw new Error(`Backup directory '${backupDir}' does not exist.`);
  }

  const manifestFile = path.join(backupDir, 'manifest.json');
  if (!fs.existsSync(manifestFile)) {
    throw new Error(`Backup directory '${backupDir}' lacks a manifest.json.`);
  }

  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf-8'));
  console.log('====================================================');
  console.log(`TaskFlow Restore Started from: ${backupDir}`);
  console.log(`Manifest Timestamp: ${manifest.timestamp}`);
  console.log('====================================================\n');

  const host = process.env.DB_HOST || 'localhost';
  const port = process.env.DB_PORT || 3306;
  const user = process.env.DB_USER || 'root';
  const password = process.env.DB_PASSWORD || '';

  // Helper to execute MySQL restore
  async function restoreDb(dbName, sqlFile) {
    console.log(`Restoring database '${dbName}' from '${path.basename(sqlFile)}'...`);
    const conn = await mysql.createConnection({ host, port, user, password });
    try {
      await conn.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    } finally {
      await conn.end();
    }

    const pwdFlag = password ? `-p"${password}"` : '';
    const cmd = `mysql --host=${host} --port=${port} --user=${user} ${pwdFlag} ${dbName} < "${sqlFile}"`;
    try {
      execSync(cmd, { stdio: 'pipe' });
      console.log(`  ✓ Restored '${dbName}'.`);
    } catch (err) {
      console.error(`  ✖ Failed to restore '${dbName}':`, err.message);
      throw err;
    }
  }

  // 1. Restore Master Database
  const masterFile = path.join(backupDir, `${manifest.masterDb}.sql`);
  if (fs.existsSync(masterFile)) {
    await restoreDb(manifest.masterDb, masterFile);
  }

  // 2. Restore Tenant Databases
  for (const tenant of manifest.tenants || []) {
    const tenantFile = path.join(backupDir, tenant.sqlFile);
    if (fs.existsSync(tenantFile)) {
      await restoreDb(tenant.db_name, tenantFile);
    }
  }

  // 3. Restore Uploads
  const uploadsBackupDir = path.join(backupDir, 'uploads');
  const targetUploadsDir = path.resolve(process.env.UPLOADS_DIR || path.join(__dirname, '../../uploads'));
  if (fs.existsSync(uploadsBackupDir)) {
    console.log(`Restoring uploaded files to ${targetUploadsDir}...`);
    if (!fs.existsSync(targetUploadsDir)) {
      fs.mkdirSync(targetUploadsDir, { recursive: true });
    }

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
  if (!targetDir) {
    console.error('Usage: node src/scripts/restoreBackup.js <backup_directory>');
    process.exit(1);
  }

  restoreBackup(targetDir)
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Fatal restore failure:', err);
      process.exit(1);
    });
}

module.exports = { restoreBackup };

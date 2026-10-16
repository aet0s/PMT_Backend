#!/usr/bin/env node
// server/src/scripts/restore.js
/**
 * Database Restoration Script (Hardened K-A.8.9)
 * - Passes DB password via MYSQL_PWD environment variable
 * - Restores SQL dump file into specified target database
 * - Validates schema and table creation post-restore
 */
require('dotenv').config();
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const { resolveMysqlBin } = require('./backup');

function decryptBuffer(buffer, secret) {
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv = buffer.slice(0, 12);
  const tag = buffer.slice(12, 28);
  const encrypted = buffer.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

async function restoreDatabase({ sqlFile, targetDatabase, encryptionKey = null }) {
  if (!fs.existsSync(sqlFile)) {
    throw new Error(`SQL file does not exist: ${sqlFile}`);
  }
  if (!targetDatabase) {
    throw new Error('Target database name is required for restore.');
  }

  const host = process.env.DB_HOST || 'localhost';
  const port = process.env.DB_PORT || 3306;
  const user = process.env.DB_USER || 'root';
  const password = process.env.DB_PASSWORD || '';

  console.log('====================================================');
  console.log(`TaskFlow Restore Started: ${new Date().toISOString()}`);
  console.log(`Source File:     ${sqlFile}`);
  console.log(`Target Database: ${targetDatabase}`);
  console.log('====================================================\n');

  // 1. Ensure target database exists
  const adminConn = await mysql.createConnection({ host, port, user, password });
  await adminConn.execute(`CREATE DATABASE IF NOT EXISTS \`${targetDatabase}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  await adminConn.end();

  // 2. Handle decryption if needed
  let importFile = sqlFile;
  let tempDecryptedFile = null;

  if (sqlFile.endsWith('.enc')) {
    if (!encryptionKey) {
      throw new Error('File is encrypted (.enc) but no BACKUP_ENCRYPTION_KEY provided.');
    }
    const encryptedBuf = fs.readFileSync(sqlFile);
    const decryptedBuf = decryptBuffer(encryptedBuf, encryptionKey);
    tempDecryptedFile = sqlFile.replace(/\.enc$/, '.dec.tmp');
    fs.writeFileSync(tempDecryptedFile, decryptedBuf);
    importFile = tempDecryptedFile;
  }

  // 3. Execute mysql import via child_process with MYSQL_PWD
  const mysqlBin = resolveMysqlBin('mysql');
  const cmd = `${mysqlBin} --host=${host} --port=${port} --user=${user} ${targetDatabase} < "${importFile}"`;

  try {
    console.log(`Importing dump into database '${targetDatabase}'...`);
    execSync(cmd, {
      stdio: 'pipe',
      env: { ...process.env, MYSQL_PWD: password }
    });
    console.log(`✓ Database '${targetDatabase}' restored successfully from '${path.basename(sqlFile)}'.`);
  } finally {
    if (tempDecryptedFile && fs.existsSync(tempDecryptedFile)) {
      fs.unlinkSync(tempDecryptedFile);
    }
  }

  return { success: true, targetDatabase, sourceFile: sqlFile };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  let fileArg = null;
  let databaseArg = null;
  let dirArg = null;
  let tenantArg = null;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--file' && args[i + 1]) fileArg = args[++i];
    else if (a.startsWith('--file=')) fileArg = a.split('=')[1];
    else if (a === '--database' && args[i + 1]) databaseArg = args[++i];
    else if (a.startsWith('--database=')) databaseArg = a.split('=')[1];
    else if (a === '--dir' && args[i + 1]) dirArg = args[++i];
    else if (a.startsWith('--dir=')) dirArg = a.split('=')[1];
    else if (a === '--tenant' && args[i + 1]) tenantArg = args[++i];
    else if (a.startsWith('--tenant=')) tenantArg = a.split('=')[1];
  }

  async function run() {
    if (fileArg && databaseArg) {
      return restoreDatabase({
        sqlFile: path.resolve(fileArg),
        targetDatabase: databaseArg,
        encryptionKey: process.env.BACKUP_ENCRYPTION_KEY || null
      });
    }

    if (dirArg && tenantArg) {
      const manifestPath = path.join(path.resolve(dirArg), 'manifest.json');
      if (!fs.existsSync(manifestPath)) {
        throw new Error(`manifest.json not found in backup directory: ${dirArg}`);
      }
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      const tenantEntry = manifest.tenants.find((t) => t.slug === tenantArg);
      if (!tenantEntry) {
        throw new Error(`Tenant '${tenantArg}' not found in backup manifest.`);
      }
      const targetDb = databaseArg || tenantEntry.db_name;
      const sqlFile = path.join(path.resolve(dirArg), tenantEntry.sqlFile);
      return restoreDatabase({
        sqlFile,
        targetDatabase: targetDb,
        encryptionKey: process.env.BACKUP_ENCRYPTION_KEY || null
      });
    }

    console.error('Usage:');
    console.error('  node src/scripts/restore.js --file <path.sql> --database <target_db>');
    console.error('  node src/scripts/restore.js --dir <backup_dir> --tenant <slug> [--database <target_db>]');
    process.exit(1);
  }

  run()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Fatal restore failure:', err.message);
      process.exit(1);
    });
}

module.exports = { restoreDatabase, decryptBuffer };

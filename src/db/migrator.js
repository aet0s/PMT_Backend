// server/src/db/migrator.js
// Forward-only migration engine for master and tenant databases.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
require('dotenv').config();

function getDbConfig(database) {
  return {
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || '',
    database,
    multipleStatements: true,
    timezone: '+00:00',
    charset: 'utf8mb4'
  };
}

async function ensureDatabase(dbName) {
  if (!dbName || !/^[a-zA-Z0-9_]+$/.test(dbName)) {
    throw new Error(`Invalid database name '${dbName}'. Only alphanumeric characters and underscores are allowed.`);
  }

  try {
    const conn = await mysql.createConnection({
      host: process.env.MYSQL_HOST || '127.0.0.1',
      port: Number(process.env.MYSQL_PORT || 3306),
      user: process.env.MYSQL_USER || 'root',
      password: process.env.MYSQL_PASSWORD !== undefined ? process.env.MYSQL_PASSWORD : ''
    });

    try {
      await conn.query(
        `CREATE DATABASE IF NOT EXISTS \`${dbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`
      );
    } catch (createErr) {
      // In shared hosting or managed environments without global CREATE DATABASE privilege,
      // log warning and continue as the database may already have been created.
      console.warn(`[WARN] ensureDatabase could not run CREATE DATABASE for '${dbName}' (might already exist):`, createErr.message);
    } finally {
      await conn.end();
    }
  } catch (connErr) {
    // If connecting without a specific database is disallowed by the server, proceed directly to connecting to dbName
    console.warn(`[WARN] ensureDatabase could not connect to MySQL server root:`, connErr.message);
  }
}

async function runMigrationsOnDb(dbName, migrationType) {
  await ensureDatabase(dbName);

  const conn = await mysql.createConnection(getDbConfig(dbName));
  try {
    await conn.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version VARCHAR(50) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        checksum VARCHAR(64) NOT NULL,
        applied_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    const dir = path.join(__dirname, 'migrations', migrationType);
    if (!fs.existsSync(dir)) return [];

    const files = fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
    const [appliedRows] = await conn.query('SELECT version, checksum FROM schema_migrations');
    const appliedMap = new Map(appliedRows.map((r) => [r.version, r.checksum]));

    const appliedThisRun = [];

    for (const file of files) {
      const version = file.split('_')[0];
      const filePath = path.join(dir, file);
      const sqlContent = fs.readFileSync(filePath, 'utf8');
      const checksum = crypto.createHash('sha256').update(sqlContent, 'utf8').digest('hex');

      if (appliedMap.has(version)) {
        if (appliedMap.get(version) !== checksum) {
          console.warn(`[WARN] Migration ${file} on ${dbName} checksum changed from applied version!`);
        }
        continue;
      }

      console.log(`[MIGRATE] Applying ${migrationType}/${file} on ${dbName}...`);
      await conn.query(sqlContent);
      await conn.execute(
        'INSERT INTO schema_migrations (version, name, checksum) VALUES (?, ?, ?)',
        [version, file, checksum]
      );
      appliedThisRun.push(file);
      console.log(`[MIGRATE] Successfully applied ${file}`);
    }

    return appliedThisRun;
  } finally {
    await conn.end();
  }
}

async function migrateMaster() {
  const masterDb = process.env.MYSQL_MASTER_DATABASE || 'pm_master';
  console.log(`=== Running Master Migrations on ${masterDb} ===`);
  const applied = await runMigrationsOnDb(masterDb, 'master');
  console.log(`Applied ${applied.length} master migration(s).`);
  return applied;
}

async function migrateSingleTenant(dbName) {
  console.log(`=== Running Tenant Migrations on ${dbName} ===`);
  const applied = await runMigrationsOnDb(dbName, 'tenant');
  console.log(`Applied ${applied.length} tenant migration(s) on ${dbName}.`);
  return applied;
}

async function migrateTenants() {
  const masterDb = process.env.MYSQL_MASTER_DATABASE || 'pm_master';
  await ensureDatabase(masterDb);

  const conn = await mysql.createConnection(getDbConfig(masterDb));
  try {
    const [tables] = await conn.query("SHOW TABLES LIKE 'tenants'");
    if (tables.length === 0) {
      console.log('No tenants table found in master database. Migrating single dev DB...');
      return await migrateSingleTenant(process.env.MYSQL_DATABASE || 'pm_dev_single');
    }

    const [tenants] = await conn.query("SELECT id, db_name, name FROM tenants WHERE status = 'active'");
    if (tenants.length === 0) {
      console.log('No active tenants found. Migrating single dev DB...');
      return await migrateSingleTenant(process.env.MYSQL_DATABASE || 'pm_dev_single');
    }

    for (const tenant of tenants) {
      await migrateSingleTenant(tenant.db_name);
    }
  } finally {
    await conn.end();
  }
}

async function dbStatus() {
  const masterDb = process.env.MYSQL_MASTER_DATABASE || 'pm_master';
  const singleDb = process.env.MYSQL_DATABASE || 'pm_dev_single';

  console.log('=== Database Migration Status ===');

  const checkStatus = async (dbName, type) => {
    try {
      const conn = await mysql.createConnection(getDbConfig(dbName));
      const [rows] = await conn.query('SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC');
      await conn.end();
      console.log(`Database: ${dbName} (${type})`);
      console.table(rows);
    } catch (err) {
      console.log(`Database: ${dbName} (not reachable / not migrated: ${err.message})`);
    }
  };

  await checkStatus(masterDb, 'master');
  await checkStatus(singleDb, 'tenant/dev_single');
}

// CLI entrypoint
if (require.main === module) {
  const cmd = process.argv[2];
  (async () => {
    if (cmd === 'master') {
      await migrateMaster();
    } else if (cmd === 'tenants') {
      await migrateTenants();
    } else if (cmd === 'single') {
      const dbName = process.argv[3] || process.env.MYSQL_DATABASE || 'pm_dev_single';
      await migrateSingleTenant(dbName);
    } else if (cmd === 'status') {
      await dbStatus();
    } else {
      console.log('Usage: node migrator.js [master|tenants|single|status]');
    }
    process.exit(0);
  })().catch((err) => {
    console.error('Migration failed:', err);
    process.exit(1);
  });
}

module.exports = {
  migrateMaster,
  migrateTenants,
  migrateSingleTenant,
  runMigrationsOnDb,
  ensureDatabase,
  dbStatus,
  getDbConfig
};

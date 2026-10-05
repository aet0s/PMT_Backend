// server/src/db/index.js
// Default database connection for single-tenant dev and migration compatibility.
const { createPool } = require('./mysql');
const migrator = require('./migrator');
require('dotenv').config();

const pool = createPool({
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD !== undefined ? process.env.MYSQL_PASSWORD : '',
  database: process.env.MYSQL_DATABASE || 'pm_dev_single'
});

async function ensureRuntimeSchema() {
  const dbName = process.env.MYSQL_DATABASE || 'pm_dev_single';
  const results = { master: [], tenant: [] };

  // If in multi-tenant mode, ensure master schema is migrated
  if (process.env.DEV_SINGLE_TENANT !== '1') {
    try {
      results.master = await migrator.migrateMaster();
    } catch (err) {
      console.warn('[DB] Master migration warning during startup:', err.message);
    }
  }

  // Always ensure single/tenant database has migrations applied
  try {
    results.tenant = await migrator.migrateSingleTenant(dbName);
  } catch (err) {
    console.warn('[DB] Single-tenant migration warning during startup:', err.message);
  }

  return results;
}

module.exports = {
  pool,
  query: (text, params) => pool.query(text, params),
  execute: (text, params) => pool.execute(text, params),
  transaction: (callback) => pool.transaction(callback),
  ensureRuntimeSchema
};

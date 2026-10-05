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
  // Real migrations replace runtime DDL mutations.
  // In single-tenant dev mode, ensure pm_dev_single has migrations applied.
  const dbName = process.env.MYSQL_DATABASE || 'pm_dev_single';
  await migrator.migrateSingleTenant(dbName);
}

module.exports = {
  pool,
  query: (text, params) => pool.query(text, params),
  execute: (text, params) => pool.execute(text, params),
  transaction: (callback) => pool.transaction(callback),
  ensureRuntimeSchema
};

// server/src/db/mysql.js
// Production-ready MySQL/MariaDB database wrapper with pooling, transactions, and boolean mapping.
const mysql = require('mysql2/promise');

const BOOLEAN_COLUMNS = new Set([
  'is_archived',
  'is_complete',
  'is_system',
  'is_editable',
  'is_read',
  'is_enabled',
  'has_access',
  'is_workspace_admin',
  'is_checked',
  'must_change_password'
]);

function mapRowBooleans(row) {
  if (!row || typeof row !== 'object') return row;
  const mapped = Array.isArray(row) ? [...row] : { ...row };
  for (const key of Object.keys(mapped)) {
    if (BOOLEAN_COLUMNS.has(key) || key.startsWith('is_') || key.startsWith('has_')) {
      if (mapped[key] !== null && mapped[key] !== undefined) {
        mapped[key] = Boolean(mapped[key]);
      }
    }
  }
  return mapped;
}

function mapBooleans(result) {
  if (!result) return result;
  if (Array.isArray(result)) {
    return result.map(mapRowBooleans);
  }
  return mapRowBooleans(result);
}

function parseJson(val) {
  if (val === null || val === undefined) return null;
  if (typeof val === 'object') return val;
  try {
    return JSON.parse(val);
  } catch (e) {
    return val;
  }
}

function createPoolWrapper(pool) {
  return {
    rawPool: pool,

    async query(sql, params = []) {
      const [rawRows] = await pool.query(sql, params);
      const rows = mapBooleans(rawRows);
      if (Array.isArray(rows)) {
        Object.defineProperty(rows, 'rows', {
          value: rows,
          enumerable: false,
          writable: true,
          configurable: true
        });
        Object.defineProperty(rows, 'rowCount', {
          value: rows.length,
          enumerable: false,
          writable: true,
          configurable: true
        });
      }
      return rows;
    },

    async execute(sql, params = []) {
      const [result] = await pool.execute(sql, params);
      return {
        insertId: result && result.insertId !== undefined ? Number(result.insertId) : null,
        affectedRows: result && result.affectedRows !== undefined ? Number(result.affectedRows) : 0,
        raw: result
      };
    },

    async transaction(callback) {
      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        const tx = {
          conn,
          async query(sql, params = []) {
            const [rawRows] = await conn.query(sql, params);
            const rows = mapBooleans(rawRows);
            if (Array.isArray(rows)) {
              Object.defineProperty(rows, 'rows', {
                value: rows,
                enumerable: false,
                writable: true,
                configurable: true
              });
              Object.defineProperty(rows, 'rowCount', {
                value: rows.length,
                enumerable: false,
                writable: true,
                configurable: true
              });
            }
            return rows;
          },
          async execute(sql, params = []) {
            const [result] = await conn.execute(sql, params);
            return {
              insertId: result && result.insertId !== undefined ? Number(result.insertId) : null,
              affectedRows: result && result.affectedRows !== undefined ? Number(result.affectedRows) : 0,
              raw: result
            };
          }
        };
        const result = await callback(tx);
        await conn.commit();
        return result;
      } catch (err) {
        await conn.rollback();
        throw err;
      } finally {
        conn.release();
      }
    },

    async end() {
      await pool.end();
    }
  };
}

function createPool(config = {}) {
  const pool = mysql.createPool({
    host: config.host || process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(config.port || process.env.MYSQL_PORT || 3306),
    user: config.user || process.env.MYSQL_USER || 'root',
    password: config.password !== undefined ? config.password : (process.env.MYSQL_PASSWORD || ''),
    database: config.database || process.env.MYSQL_DATABASE || 'pm_dev_single',
    waitForConnections: true,
    connectionLimit: config.connectionLimit || 10,
    queueLimit: 0,
    timezone: '+00:00',
    dateStrings: false,
    supportBigNumbers: true,
    bigNumberStrings: false,
    decimalNumbers: true,
    charset: 'utf8mb4',
    namedPlaceholders: false
  });

  return createPoolWrapper(pool);
}

module.exports = {
  createPool,
  createPoolWrapper,
  mapBooleans,
  parseJson
};

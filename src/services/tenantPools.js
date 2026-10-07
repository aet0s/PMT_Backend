// server/src/services/tenantPools.js
// Dynamic multi-tenant connection pool manager with LRU caching, idle eviction, and master DB integration.
const mysql = require('mysql2/promise');
const { createPoolWrapper } = require('../db/mysql');
require('dotenv').config();

const TENANT_POOL_LIMIT = Number(process.env.TENANT_POOL_LIMIT || 5);
const MAX_OPEN_TENANT_POOLS = Number(process.env.MAX_OPEN_TENANT_POOLS || 50);
const POOL_IDLE_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

let masterDbWrapper = null;
let devSingleWrapper = null;

// Map: tenantId -> { wrapper, rawPool, lastAccessed: number, dbName: string }
const tenantPoolCache = new Map();

function getBaseMysqlConfig(database) {
  return {
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || '',
    database,
    waitForConnections: true,
    connectionLimit: TENANT_POOL_LIMIT,
    queueLimit: 0,
    timezone: '+00:00',
    charset: 'utf8mb4'
  };
}

function getMasterDb() {
  if (!masterDbWrapper) {
    const masterDbName = process.env.MYSQL_MASTER_DATABASE || 'pm_master';
    const pool = mysql.createPool({
      ...getBaseMysqlConfig(masterDbName),
      connectionLimit: Number(process.env.MYSQL_POOL_LIMIT || 10)
    });
    masterDbWrapper = createPoolWrapper(pool);
  }
  return masterDbWrapper;
}

function getDevSingleDb() {
  if (!devSingleWrapper) {
    const dbName = process.env.MYSQL_DATABASE || 'pm_dev_single';
    const pool = mysql.createPool({
      ...getBaseMysqlConfig(dbName),
      connectionLimit: Number(process.env.MYSQL_POOL_LIMIT || 10)
    });
    devSingleWrapper = createPoolWrapper(pool);
  }
  return devSingleWrapper;
}

async function evictOldestPoolIfNeeded() {
  if (tenantPoolCache.size < MAX_OPEN_TENANT_POOLS) return;

  let oldestKey = null;
  let oldestTime = Infinity;

  for (const [key, entry] of tenantPoolCache.entries()) {
    if (entry.lastAccessed < oldestTime) {
      oldestTime = entry.lastAccessed;
      oldestKey = key;
    }
  }

  if (oldestKey !== null) {
    await evictTenantPool(oldestKey);
  }
}

async function evictTenantPool(tenantId) {
  const entry = tenantPoolCache.get(Number(tenantId));
  if (entry) {
    tenantPoolCache.delete(Number(tenantId));
    try {
      await entry.rawPool.end();
    } catch (err) {
      console.warn(`[WARN] Error closing tenant pool ${tenantId}:`, err.message);
    }
  }
}

function getTenantDbByName(dbName) {
  // Look in cache by dbName
  for (const entry of tenantPoolCache.values()) {
    if (entry.dbName === dbName) {
      entry.lastAccessed = Date.now();
      return entry.wrapper;
    }
  }

  const rawPool = mysql.createPool(getBaseMysqlConfig(dbName));
  const wrapper = createPoolWrapper(rawPool);
  return wrapper;
}

async function getTenantDb(tenantId) {
  if (process.env.DEV_SINGLE_TENANT === '1') {
    return getDevSingleDb();
  }
  const tid = Number(tenantId);
  const now = Date.now();

  const cached = tenantPoolCache.get(tid);
  if (cached) {
    cached.lastAccessed = now;
    return cached.wrapper;
  }

  // Query master DB for tenant database name
  const masterDb = getMasterDb();
  const [tenant] = await masterDb.query(
    "SELECT id, slug, db_name, status FROM tenants WHERE id = ? AND status IN ('active', 'provisioning')",
    [tid]
  );

  if (!tenant) {
    throw new Error(`Tenant not found or inactive (ID: ${tenantId})`);
  }

  await evictOldestPoolIfNeeded();

  const rawPool = mysql.createPool(getBaseMysqlConfig(tenant.db_name));
  const wrapper = createPoolWrapper(rawPool);
  wrapper.tenantId = tid;

  tenantPoolCache.set(tid, {
    wrapper,
    rawPool,
    lastAccessed: now,
    dbName: tenant.db_name
  });

  return wrapper;
}

async function getTenantDbBySlug(slug) {
  const masterDb = getMasterDb();
  const [tenant] = await masterDb.query(
    "SELECT id FROM tenants WHERE slug = ? AND status IN ('active', 'provisioning')",
    [slug.trim().toLowerCase()]
  );
  if (!tenant) {
    throw new Error(`Tenant not found for slug "${slug}"`);
  }
  return await getTenantDb(tenant.id);
}

// Periodic cleanup of idle pools
setInterval(async () => {
  const now = Date.now();
  for (const [tid, entry] of tenantPoolCache.entries()) {
    if (now - entry.lastAccessed > POOL_IDLE_TIMEOUT_MS) {
      await evictTenantPool(tid);
    }
  }
}, 60 * 1000).unref();

async function closeAllTenantPools() {
  for (const [tid, entry] of tenantPoolCache.entries()) {
    try {
      await entry.rawPool.end();
    } catch (e) {
      // ignore
    }
  }
  tenantPoolCache.clear();

  if (masterDbWrapper) {
    try {
      await masterDbWrapper.rawPool.end();
    } catch (e) {}
    masterDbWrapper = null;
  }

  if (devSingleWrapper) {
    try {
      await devSingleWrapper.rawPool.end();
    } catch (e) {}
    devSingleWrapper = null;
  }
}

module.exports = {
  getMasterDb,
  getTenantDb,
  getTenantDbBySlug,
  getTenantDbByName,
  getDevSingleDb,
  evictTenantPool,
  closeAllTenantPools,
  closeAllPools: closeAllTenantPools,
  getBaseMysqlConfig,
  tenantPoolCache
};

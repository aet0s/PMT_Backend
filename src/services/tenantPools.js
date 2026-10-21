// server/src/services/tenantPools.js
// Dynamic multi-tenant connection pool manager with LRU caching, idle eviction, and master DB integration.
const mysql = require('mysql2/promise');
const { createPoolWrapper } = require('../db/mysql');
require('dotenv').config();

const TENANT_POOL_LIMIT = Math.max(15, Number(process.env.TENANT_POOL_LIMIT || 15));
const MAX_OPEN_TENANT_POOLS = Number(process.env.MAX_OPEN_TENANT_POOLS || 50);
const POOL_IDLE_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

let masterDbWrapper = null;
let devSingleWrapper = null;

// Map: tenantId -> { wrapper, rawPool, lastAccessed: number, dbName: string }
const tenantPoolCache = new Map();

// In-memory tenant metadata cache (5 minutes TTL) to eliminate master DB queries on every request
const tenantMetadataCache = new Map();
const TENANT_METADATA_TTL_MS = 5 * 60 * 1000;

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
    timezone: process.env.MYSQL_TIMEZONE || 'local',
    dateStrings: true,
    charset: 'utf8mb4',
    enableKeepAlive: true,
    keepAliveInitialDelay: 10000,
    idleTimeout: 30000,
    maxIdle: Math.min(10, TENANT_POOL_LIMIT),
    connectTimeout: 10000
  };
}

function attachPoolErrorHandler(pool, label) {
  if (pool && typeof pool.on === 'function') {
    pool.on('error', (err) => {
      console.warn(`[WARN] MySQL pool error (${label}):`, err?.code || err?.message);
    });
  }
}

function getMasterDb() {
  if (!masterDbWrapper) {
    const masterDbName = process.env.MYSQL_MASTER_DATABASE || 'pm_master';
    const pool = mysql.createPool({
      ...getBaseMysqlConfig(masterDbName),
      connectionLimit: Math.max(15, Number(process.env.MYSQL_POOL_LIMIT || 15))
    });
    attachPoolErrorHandler(pool, 'masterDb');
    masterDbWrapper = createPoolWrapper(pool);
  }
  return masterDbWrapper;
}

function getDevSingleDb() {
  if (!devSingleWrapper) {
    const dbName = process.env.MYSQL_DATABASE || 'pm_dev_single';
    const pool = mysql.createPool({
      ...getBaseMysqlConfig(dbName),
      connectionLimit: Math.max(15, Number(process.env.MYSQL_POOL_LIMIT || 15))
    });
    attachPoolErrorHandler(pool, 'devSingleDb');
    devSingleWrapper = createPoolWrapper(pool);
  }
  return devSingleWrapper;
}

async function getTenantMetadata(tenantId) {
  if (!tenantId) return null;
  const tid = Number(tenantId);
  const now = Date.now();
  const cached = tenantMetadataCache.get(tid);
  if (cached && (now - cached.cachedAt < TENANT_METADATA_TTL_MS)) {
    return cached.tenant;
  }

  const masterDb = getMasterDb();
  const [tenant] = await masterDb.query(
    'SELECT id, slug, name, db_name, status FROM tenants WHERE id = ?',
    [tid]
  );
  if (tenant) {
    tenantMetadataCache.set(tid, { tenant, cachedAt: now });
  }
  return tenant || null;
}

function invalidateTenantMetadata(tenantId = null) {
  if (tenantId) {
    tenantMetadataCache.delete(Number(tenantId));
  } else {
    tenantMetadataCache.clear();
  }
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
  attachPoolErrorHandler(rawPool, `db:${dbName}`);
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

  // Retrieve tenant metadata from in-memory cache / master DB
  const tenant = await getTenantMetadata(tid);

  if (!tenant || (tenant.status !== 'active' && tenant.status !== 'provisioning')) {
    throw new Error(`Tenant not found or inactive (ID: ${tenantId})`);
  }

  await evictOldestPoolIfNeeded();

  const rawPool = mysql.createPool(getBaseMysqlConfig(tenant.db_name));
  attachPoolErrorHandler(rawPool, `tenant:${tid}`);
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
  getTenantMetadata,
  invalidateTenantMetadata,
  evictTenantPool,
  closeAllTenantPools,
  closeAllPools: closeAllTenantPools,
  getBaseMysqlConfig,
  tenantPoolCache
};

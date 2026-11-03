// server/src/secure/idempotencyStore.js
// Persistent idempotency storage to ensure retry safety on state mutations.

const crypto = require('crypto');
const { getMasterDb, getDevSingleDb } = require('../services/tenantPools');

function getIdempotencyDb() {
  try {
    if (process.env.DEV_SINGLE_TENANT === '1') {
      return getDevSingleDb();
    }
    return getMasterDb();
  } catch {
    return null;
  }
}

function computePayloadHash(data) {
  const serialized = typeof data === 'string' ? data : JSON.stringify(data ?? {});
  return crypto.createHash('sha256').update(serialized).digest('hex');
}

async function getStoredIdempotency(dbOverride, idempotencyKey) {
  if (!idempotencyKey) return null;
  const db = dbOverride || getIdempotencyDb();
  if (!db || typeof db.query !== 'function') return null;

  try {
    const rows = await db.query(
      `SELECT idempotency_key, user_id, tenant_id, operation, request_hash, status_code, response_body
       FROM api_idempotency
       WHERE idempotency_key = ?`,
      [idempotencyKey]
    );

    if (rows && rows.length > 0) {
      const rec = rows[0];
      return {
        key: rec.idempotency_key,
        userId: rec.user_id,
        tenantId: rec.tenant_id,
        operation: rec.operation,
        requestHash: rec.request_hash,
        statusCode: rec.status_code,
        response: JSON.parse(rec.response_body)
      };
    }
  } catch (err) {
    console.warn('[IDEMPOTENCY] Query failed:', err.message);
  }
  return null;
}

async function storeIdempotency(dbOverride, {
  idempotencyKey,
  userId = null,
  tenantId = null,
  operation,
  data,
  statusCode,
  response
}) {
  if (!idempotencyKey) return;
  const db = dbOverride || getIdempotencyDb();
  if (!db || typeof db.query !== 'function') return;

  try {
    const requestHash = computePayloadHash(data);
    const bodyStr = JSON.stringify(response ?? {});

    await db.query(
      `INSERT INTO api_idempotency (idempotency_key, user_id, tenant_id, operation, request_hash, status_code, response_body, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE status_code = VALUES(status_code), response_body = VALUES(response_body)`,
      [idempotencyKey, userId, tenantId, operation, requestHash, statusCode, bodyStr]
    );
  } catch (err) {
    console.warn('[IDEMPOTENCY] Store failed:', err.message);
  }
}

module.exports = {
  computePayloadHash,
  getStoredIdempotency,
  storeIdempotency
};


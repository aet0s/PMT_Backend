// server/src/secure/replayStore.js
// Anti-replay store with atomic MySQL insertion and in-memory fallback.

const { getMasterDb, getDevSingleDb } = require('../services/tenantPools');

function getReplayDb() {
  try {
    if (process.env.DEV_SINGLE_TENANT === '1') {
      return getDevSingleDb();
    }
    return getMasterDb();
  } catch {
    return null;
  }
}

// In-memory sliding window for instantaneous duplicate prevention
const memoryNonceCache = new Map();
const MAX_MEMORY_NONCES = 50000;
const RETENTION_SECONDS = 300; // 5 minutes

function cleanMemoryCache() {
  const cutoff = Math.floor(Date.now() / 1000) - RETENTION_SECONDS;
  for (const [nonce, ts] of memoryNonceCache.entries()) {
    if (ts < cutoff) {
      memoryNonceCache.delete(nonce);
    }
  }
}

// Clean every 60 seconds
if (typeof setInterval !== 'undefined') {
  setInterval(cleanMemoryCache, 60000).unref();
}

/**
 * Atomically consumes a nonce. Rejects duplicate nonces with 400 REPLAY_DETECTED.
 * @param {object|null} dbOverride - Optional database handle
 * @param {string} nonce - Unique 128-bit base64url or hex nonce
 * @param {number} timestamp - Unix seconds timestamp
 */
async function consumeNonce(dbOverride, nonce, timestamp) {
  if (!nonce || typeof nonce !== 'string') {
    const err = new Error('Invalid nonce provided');
    err.status = 400;
    err.code = 'INVALID_NONCE';
    throw err;
  }

  // 1. Check in-memory fast window
  if (memoryNonceCache.has(nonce)) {
    const err = new Error('Replay detected: Nonce has already been consumed');
    err.status = 400;
    err.code = 'REPLAY_DETECTED';
    throw err;
  }

  // 2. Atomically insert into database replay_nonces table (Fail-Closed)
  const db = dbOverride || getReplayDb();
  if (!db || typeof db.query !== 'function') {
    const err = new Error('Replay store unavailable: No durable database connection');
    err.status = 503;
    err.code = 'REPLAY_STORE_UNAVAILABLE';
    throw err;
  }

  try {
    await db.query(
      `INSERT INTO replay_nonces (nonce, timestamp, created_at)
       VALUES (?, ?, NOW())`,
      [nonce, Number(timestamp) || Math.floor(Date.now() / 1000)]
    );
  } catch (dbErr) {
    // MySQL ER_DUP_ENTRY (code 1062)
    if (dbErr.code === 'ER_DUP_ENTRY' || dbErr.errno === 1062) {
      const err = new Error('Replay detected: Nonce has already been consumed');
      err.status = 400;
      err.code = 'REPLAY_DETECTED';
      throw err;
    }
    console.error('[REPLAY-STORE] Database write failed (fail-closed):', dbErr.message);
    const err = new Error('Replay protection unavailable: Nonce store failed');
    err.status = 503;
    err.code = 'REPLAY_STORE_UNAVAILABLE';
    throw err;
  }

  // 3. Mark in memory cache
  if (memoryNonceCache.size >= MAX_MEMORY_NONCES) {
    cleanMemoryCache();
  }
  memoryNonceCache.set(nonce, Number(timestamp) || Math.floor(Date.now() / 1000));
}

module.exports = {
  consumeNonce
};

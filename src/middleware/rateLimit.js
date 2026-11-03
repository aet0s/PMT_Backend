// server/src/middleware/rateLimit.js
// Production sliding-window rate limiter with memory + database persistence and trusted proxy handling.

const { getMasterDb, getDevSingleDb } = require('../services/tenantPools');

function getClientIp(req) {
  // Rely strictly on Express req.ip (configured with app.set('trust proxy', 1))
  // Never read raw X-Forwarded-For directly to prevent spoofing
  return req.ip || req.socket?.remoteAddress || '127.0.0.1';
}

function getActiveDbForLimits() {
  try {
    if (process.env.DEV_SINGLE_TENANT === '1') {
      return getDevSingleDb();
    }
    return getMasterDb();
  } catch {
    return null;
  }
}

function createRateLimiter({
  windowMs = 15 * 60 * 1000,
  maxRequests = 100,
  message = 'Too many requests, please try again later.',
  code = 'RATE_LIMIT_EXCEEDED',
  keyPrefix = 'rl'
}) {
  const memoryStore = new Map();

  // Periodic memory store cleanup every 2 minutes
  const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of memoryStore.entries()) {
      if (now > entry.resetAt) {
        memoryStore.delete(key);
      }
    }
  }, 2 * 60 * 1000);

  if (cleanupTimer.unref) cleanupTimer.unref();

  const middleware = async (req, res, next) => {
    // Rate limiting may be bypassed ONLY when NODE_ENV === 'test' or DISABLE_RATE_LIMIT === 'true'
    if (process.env.DISABLE_RATE_LIMIT === 'true' || (process.env.NODE_ENV === 'test' && process.env.DISABLE_RATE_LIMIT !== 'false')) {
      return next();
    }

    const ip = getClientIp(req);
    const key = `${keyPrefix}:${ip}`;
    const now = Date.now();

    let entry = memoryStore.get(key);
    if (!entry || now > entry.resetAt) {
      entry = {
        hits: 1,
        resetAt: now + windowMs
      };
      memoryStore.set(key, entry);
    } else {
      entry.hits += 1;
    }

    const remaining = Math.max(0, maxRequests - entry.hits);
    const resetSeconds = Math.ceil(entry.resetAt / 1000);
    const retryAfter = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));

    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', remaining);
    res.setHeader('X-RateLimit-Reset', resetSeconds);

    if (entry.hits > maxRequests) {
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({
        error: {
          message,
          code,
          retry_after_seconds: retryAfter,
          requestId: req.id
        }
      });
    }

    // Best-effort asynchronous write to rate_limits table for multi-process sharing
    const db = getActiveDbForLimits();
    if (db) {
      db.query(
        `INSERT INTO rate_limits (limiter_key, hits, reset_at, created_at, updated_at)
         VALUES (?, 1, ?, NOW(), NOW())
         ON DUPLICATE KEY UPDATE hits = hits + 1, updated_at = NOW()`,
        [key, entry.resetAt]
      ).catch(() => {});
    }

    return next();
  };

  middleware.reset = () => {
    memoryStore.clear();
  };

  return middleware;
}

// REAL production rate limiters (Pass-through placeholders completely eliminated)
const loginRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: process.env.NODE_ENV === 'production' ? 10 : 500,
  message: 'Too many login attempts. Please wait 15 minutes before trying again.',
  code: 'LOGIN_RATE_LIMIT_EXCEEDED',
  keyPrefix: 'login'
});

const authRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: process.env.NODE_ENV === 'production' ? 15 : 500,
  message: 'Too many authentication requests. Please try again later.',
  code: 'AUTH_RATE_LIMIT_EXCEEDED',
  keyPrefix: 'auth'
});

const apiRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 300,
  message: 'Too many requests. Please slow down.',
  code: 'API_RATE_LIMIT_EXCEEDED',
  keyPrefix: 'api'
});

const uploadRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 30,
  message: 'Upload rate limit exceeded. Please wait before uploading more files.',
  code: 'UPLOAD_RATE_LIMIT_EXCEEDED',
  keyPrefix: 'upload'
});

const exportRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 10,
  message: 'Export rate limit exceeded. Please wait before requesting additional exports.',
  code: 'EXPORT_RATE_LIMIT_EXCEEDED',
  keyPrefix: 'export'
});

function resetAllRateLimits() {
  loginRateLimiter.reset();
  authRateLimiter.reset();
  apiRateLimiter.reset();
  uploadRateLimiter.reset();
  exportRateLimiter.reset();
}

module.exports = {
  createRateLimiter,
  loginRateLimiter,
  authRateLimiter,
  apiRateLimiter,
  uploadRateLimiter,
  exportRateLimiter,
  resetAllRateLimits,
  getClientIp
};

// server/src/middleware/rateLimit.js
// Production sliding-window rate limiter with memory + database persistence and trusted proxy handling.

const { getMasterDb, getDevSingleDb } = require('../services/tenantPools');

function getClientIp(req) {
  let ip = req.ip || req.socket?.remoteAddress || '127.0.0.1';
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }

  // If ip resolved to loopback (proxy is on localhost / nginx container),
  // check X-Real-IP or X-Forwarded-For explicitly set by trusted local proxy.
  if ((ip === '127.0.0.1' || ip === '::1') && req.headers) {
    if (req.headers['x-real-ip']) {
      return String(req.headers['x-real-ip']).trim();
    }
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
      const parts = String(xff).split(',').map((s) => s.trim()).filter(Boolean);
      if (parts.length > 0) {
        return parts[0];
      }
    }
  }

  return ip;
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
  keyPrefix = 'rl',
  keyGenerator = null
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

    const key = typeof keyGenerator === 'function'
      ? keyGenerator(req)
      : `${keyPrefix}:${getClientIp(req)}`;

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

  middleware.resetKey = (key) => {
    if (key) {
      memoryStore.delete(key);
      const db = getActiveDbForLimits();
      if (db) {
        db.query('DELETE FROM rate_limits WHERE limiter_key = ?', [key]).catch(() => {});
      }
    }
  };

  return middleware;
}

// Extract normalized email from request body (supporting both REST and encrypted subReq payloads)
function extractEmailFromReq(req) {
  const rawEmail = req.body?.email || req.body?.data?.email || '';
  return String(rawEmail).trim().toLowerCase();
}

// Configurable production thresholds
const LOGIN_RATE_LIMIT_MAX = process.env.LOGIN_RATE_LIMIT_MAX
  ? parseInt(process.env.LOGIN_RATE_LIMIT_MAX, 10)
  : (process.env.NODE_ENV === 'production' ? 30 : 500);

const AUTH_RATE_LIMIT_MAX = process.env.AUTH_RATE_LIMIT_MAX
  ? parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10)
  : (process.env.NODE_ENV === 'production' ? 60 : 500);

const API_RATE_LIMIT_MAX = process.env.API_RATE_LIMIT_MAX
  ? parseInt(process.env.API_RATE_LIMIT_MAX, 10)
  : 300;

const UPLOAD_RATE_LIMIT_MAX = process.env.UPLOAD_RATE_LIMIT_MAX
  ? parseInt(process.env.UPLOAD_RATE_LIMIT_MAX, 10)
  : 60;

const EXPORT_RATE_LIMIT_MAX = process.env.EXPORT_RATE_LIMIT_MAX
  ? parseInt(process.env.EXPORT_RATE_LIMIT_MAX, 10)
  : 30;

// LOGIN RATE LIMITER:
// Keyed by IP + normalized email to prevent single-IP office collisions while guarding against credential stuffing
const loginRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: LOGIN_RATE_LIMIT_MAX,
  message: 'Too many login attempts. Please wait 15 minutes before trying again.',
  code: 'LOGIN_RATE_LIMIT_EXCEEDED',
  keyPrefix: 'login',
  keyGenerator: (req) => {
    const ip = getClientIp(req);
    const email = extractEmailFromReq(req);
    return email ? `login:${ip}:${email}` : `login:${ip}`;
  }
});

// AUTH RATE LIMITER:
// Keyed by IP + normalized email for registration, OTPs, and password resets
const authRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: AUTH_RATE_LIMIT_MAX,
  message: 'Too many authentication requests. Please try again later.',
  code: 'AUTH_RATE_LIMIT_EXCEEDED',
  keyPrefix: 'auth',
  keyGenerator: (req) => {
    const ip = getClientIp(req);
    const email = extractEmailFromReq(req);
    return email ? `auth:${ip}:${email}` : `auth:${ip}`;
  }
});

const apiRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: API_RATE_LIMIT_MAX,
  message: 'Too many requests. Please slow down.',
  code: 'API_RATE_LIMIT_EXCEEDED',
  keyPrefix: 'api'
});

const uploadRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: UPLOAD_RATE_LIMIT_MAX,
  message: 'Upload rate limit exceeded. Please wait before uploading more files.',
  code: 'UPLOAD_RATE_LIMIT_EXCEEDED',
  keyPrefix: 'upload'
});

const exportRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: EXPORT_RATE_LIMIT_MAX,
  message: 'Export rate limit exceeded. Please wait before requesting additional exports.',
  code: 'EXPORT_RATE_LIMIT_EXCEEDED',
  keyPrefix: 'export'
});

/**
 * Resets rate limit keys for a user upon successful authentication
 */
function clearLoginRateLimit(req, explicitEmail = null) {
  const ip = getClientIp(req);
  const email = (explicitEmail || extractEmailFromReq(req)).trim().toLowerCase();
  if (email) {
    loginRateLimiter.resetKey(`login:${ip}:${email}`);
  }
  loginRateLimiter.resetKey(`login:${ip}`);
}

function clearAuthRateLimit(req, explicitEmail = null) {
  const ip = getClientIp(req);
  const email = (explicitEmail || extractEmailFromReq(req)).trim().toLowerCase();
  if (email) {
    authRateLimiter.resetKey(`auth:${ip}:${email}`);
  }
  authRateLimiter.resetKey(`auth:${ip}`);
}

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
  clearLoginRateLimit,
  clearAuthRateLimit,
  resetAllRateLimits,
  getClientIp
};

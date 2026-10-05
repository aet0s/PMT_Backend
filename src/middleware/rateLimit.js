// server/src/middleware/rateLimit.js
// In-memory sliding window rate limiter keyed by IP address.

const ipBuckets = new Map();

function getClientIp(req) {
  // Rely strictly on Express req.ip (configured with app.set('trust proxy', ...))
  // Never read raw X-Forwarded-For headers directly from req.headers to prevent spoofing
  return req.ip || '127.0.0.1';
}

function createRateLimiter({
  windowMs = 15 * 60 * 1000,
  maxRequests = 100,
  message = 'Too many requests from this IP, please try again later.',
  code = 'RATE_LIMIT_EXCEEDED'
}) {
  const limiterStore = new Map();

  // Periodically clean up stale records every 5 minutes
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [ip, timestamps] of limiterStore.entries()) {
      const valid = timestamps.filter((t) => now - t < windowMs);
      if (valid.length === 0) {
        limiterStore.delete(ip);
      } else {
        limiterStore.set(ip, valid);
      }
    }
  }, 5 * 60 * 1000);

  if (cleanupInterval.unref) cleanupInterval.unref();

  const middleware = (req, res, next) => {
    // Rate limiting may only be bypassed when NODE_ENV=test and DISABLE_RATE_LIMIT is explicitly true
    if (process.env.NODE_ENV === 'test' && process.env.DISABLE_RATE_LIMIT === 'true') {
      return next();
    }

    const ip = getClientIp(req);
    const now = Date.now();
    const timestamps = (limiterStore.get(ip) || []).filter((t) => now - t < windowMs);

    if (timestamps.length >= maxRequests) {
      const oldest = timestamps[0];
      const retryAfterSeconds = Math.ceil((oldest + windowMs - now) / 1000);
      res.setHeader('Retry-After', retryAfterSeconds);
      res.setHeader('X-RateLimit-Limit', maxRequests);
      res.setHeader('X-RateLimit-Remaining', 0);
      res.setHeader('X-RateLimit-Reset', Math.ceil((oldest + windowMs) / 1000));

      return res.status(429).json({
        error: {
          message,
          code,
          retry_after_seconds: retryAfterSeconds
        }
      });
    }

    timestamps.push(now);
    limiterStore.set(ip, timestamps);

    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - timestamps.length));
    next();
  };

  middleware.reset = () => {
    limiterStore.clear();
  };

  return middleware;
}

const authRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 120,
  message: 'Too many authentication attempts from this IP. Please try again later.'
});

const loginRateLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000, // 10 minutes
  maxRequests: 30,
  message: 'Too many login attempts from this IP. Please try again in a few minutes.',
  code: 'LOGIN_RATE_LIMIT_EXCEEDED'
});

function resetAllRateLimits() {
  authRateLimiter.reset();
  loginRateLimiter.reset();
}

module.exports = {
  createRateLimiter,
  authRateLimiter,
  loginRateLimiter,
  resetAllRateLimits,
  getClientIp
};

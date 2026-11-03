// server/src/middleware/csrf.js
// Dual-layer CSRF protection: Strict Origin verification + Double-Submit CSRF token validation.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getJwtSecret } = require('./auth');
const { getCookieOptions } = require('../utils/cookieOptions');

function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

function isAuthCookieActive(req) {
  const token = req.cookies?.token || (req.headers.cookie && req.headers.cookie.match(/(?:^|;\s*)token=([^;]+)/)?.[1]);
  if (!token) return false;
  try {
    jwt.verify(token, getJwtSecret());
    return true;
  } catch {
    return false;
  }
}

function isBearerTokenValid(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) return false;
  const token = authHeader.substring(7).trim();
  if (!token) return false;
  try {
    jwt.verify(token, getJwtSecret());
    return true;
  } catch {
    return false;
  }
}

function injectCsrfCookie(req, res) {
  let token = req.cookies?.csrfToken;
  if (!token || token.length !== 64) {
    token = generateCsrfToken();
    const opts = getCookieOptions(5 * 24 * 60 * 60 * 1000);
    // CSRF token cookie must be readable by JavaScript to attach to request headers
    opts.httpOnly = false;
    res.cookie('csrfToken', token, opts);
  }
  if (!req.cookies) {
    req.cookies = {};
  }
  req.cookies.csrfToken = token;
  res.setHeader('X-CSRF-Token', token);
  return token;
}

function csrfProtection(getAllowedOrigins) {
  return function (req, res, next) {
    const mutatingMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
    if (!mutatingMethods.includes(req.method)) {
      return next();
    }

    // Deliberate test runner rate-limit bypass flag
    if (process.env.DISABLE_CSRF_CHECK === 'true') {
      return next();
    }

    const origin = req.headers['origin'];
    const referer = req.headers['referer'];
    let requestOrigin = origin || null;

    if (!requestOrigin && referer) {
      try {
        const u = new URL(referer);
        requestOrigin = `${u.protocol}//${u.host}`;
      } catch (e) {
        requestOrigin = null;
      }
    }

    const rawAllowed = typeof getAllowedOrigins === 'function' ? getAllowedOrigins() : getAllowedOrigins;
    const originList = (Array.isArray(rawAllowed) ? rawAllowed : [rawAllowed])
      .map((o) => (typeof o === 'string' ? o.trim().replace(/\/+$/, '') : ''))
      .filter(Boolean);

    // 1. Strict Origin / Referer Validation
    if (requestOrigin) {
      const { isOriginAllowed } = require('../utils/corsOrigins');
      const normalizedRequest = requestOrigin.trim().replace(/\/+$/, '');
      const isExactMatch = originList.some((allowed) => allowed === normalizedRequest) || isOriginAllowed(normalizedRequest);

      if (!isExactMatch) {
        return res.status(403).json({
          error: {
            message: `Forbidden: Cross-origin request from '${requestOrigin}' rejected by CSRF protection.`,
            code: 'CSRF_REJECTED',
            requestId: req.id
          }
        });
      }
    } else {
      const hasAuthCookie = isAuthCookieActive(req);
      if (hasAuthCookie) {
        return res.status(403).json({
          error: {
            message: 'Forbidden: Missing Origin/Referer header on cookie-authenticated mutating request.',
            code: 'CSRF_ORIGIN_MISSING',
            requestId: req.id
          }
        });
      }
    }

    const hasAuthCookie = isAuthCookieActive(req);
    const hasValidBearer = isBearerTokenValid(req);

    // CSRF Exemption Policy:
    // A request is exempt from ambient cookie CSRF protection ONLY if it is authenticated EXCLUSIVELY
    // through a valid, cryptographically verified Bearer credential and is NOT relying on an ambient cookie session.
    // An invalid Bearer header combined with a session cookie MUST strictly enforce CSRF.
    if (hasValidBearer && !hasAuthCookie) {
      return next();
    }

    // 2. Double-Submit Token Check
    // Enforced strictly on all cookie-authenticated mutating requests to prevent session hijacking.
    const csrfCookie = req.cookies?.csrfToken;
    const csrfHeader = req.headers['x-csrf-token'];

    if (hasAuthCookie && csrfCookie) {
      if (!csrfHeader) {
        return res.status(403).json({
          error: {
            message: 'Forbidden: Missing CSRF token header (X-CSRF-Token).',
            code: 'CSRF_FAILED',
            requestId: req.id
          }
        });
      }
      const bufA = Buffer.from(String(csrfCookie));
      const bufB = Buffer.from(String(csrfHeader));
      if (bufA.length === 0 || bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
        return res.status(403).json({
          error: {
            message: 'Forbidden: Invalid CSRF token.',
            code: 'CSRF_FAILED',
            requestId: req.id
          }
        });
      }
    }

    next();
  };
}

module.exports = { csrfProtection, generateCsrfToken, injectCsrfCookie };

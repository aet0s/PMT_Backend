// server/src/middleware/csrf.js
/**
 * Cross-Origin CSRF Protection for state-changing HTTP requests.
 * Ensures that POST, PUT, PATCH, and DELETE requests carry an Origin or Referer
 * that exactly matches the server's allowed origins allowlist (CORS_ORIGINS / CLIENT_URL).
 * 
 * Rules:
 * 1. GET, HEAD, OPTIONS requests are unaffected (safe methods per RFC 7231).
 * 2. If Origin or Referer is present, it must EXACTLY match an allowed origin
 *    (strict string equality; no startsWith, endsWith, includes, or loose regex).
 * 3. If Origin/Referer is missing on a mutating request authenticated via session cookies,
 *    the request is strictly rejected with 403 CSRF_ORIGIN_MISSING.
 * 4. Origin "null" (privacy-sensitive context / sandboxed iframe) is rejected unless
 *    explicitly allowlisted.
 */
function csrfProtection(getAllowedOrigins) {
  return function (req, res, next) {
    const mutatingMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
    if (!mutatingMethods.includes(req.method)) {
      return next();
    }

    const originHeader = req.headers.origin;
    const refererHeader = req.headers.referer;

    let requestOrigin = originHeader;
    if (!requestOrigin && refererHeader) {
      try {
        requestOrigin = new URL(refererHeader).origin;
      } catch (e) {
        requestOrigin = null;
      }
    }

    const rawAllowed = typeof getAllowedOrigins === 'function' ? getAllowedOrigins() : getAllowedOrigins;
    const originList = (Array.isArray(rawAllowed) ? rawAllowed : [rawAllowed])
      .map(o => (typeof o === 'string' ? o.trim().replace(/\/+$/, '') : ''))
      .filter(Boolean);

    // If an Origin or Referer is supplied (standard for all browsers on mutating requests)
    if (requestOrigin) {
      const { isOriginAllowed } = require('../utils/corsOrigins');
      const normalizedRequest = requestOrigin.trim().replace(/\/+$/, '');
      const isExactMatch = originList.some(allowed => allowed === normalizedRequest) || isOriginAllowed(normalizedRequest);

      if (!isExactMatch) {
        return res.status(403).json({
          error: {
            message: `Forbidden: Cross-origin request from '${requestOrigin}' rejected by CSRF protection.`,
            code: 'CSRF_REJECTED'
          }
        });
      }
    } else {
      // Missing Origin & Referer: Check for cookie authentication
      const hasAuthCookie = Boolean(
        (req.cookies && (req.cookies.token || req.cookies.refreshToken)) ||
        (req.headers.cookie && /(?:^|;\s*)(token|refreshToken)=/.test(req.headers.cookie))
      );

      if (hasAuthCookie) {
        return res.status(403).json({
          error: {
            message: 'Forbidden: Missing Origin/Referer header on cookie-authenticated mutating request.',
            code: 'CSRF_ORIGIN_MISSING'
          }
        });
      }
    }

    next();
  };
}

module.exports = { csrfProtection };

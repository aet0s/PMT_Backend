// server/src/middleware/csrf.js
/**
 * Cross-Origin CSRF Protection for state-changing HTTP requests.
 * Ensures that POST, PUT, PATCH, and DELETE requests carry an Origin or Referer
 * that matches the server's allowed origins allowlist (CORS_ORIGINS / CLIENT_URL).
 */
function csrfProtection(getAllowedOrigins) {
  return function (req, res, next) {
    const mutatingMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
    if (!mutatingMethods.includes(req.method)) {
      return next();
    }

    // Skip public migrations/webhooks if needed, but apply to all /api/
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

    const allowedOrigins = typeof getAllowedOrigins === 'function' ? getAllowedOrigins() : getAllowedOrigins;

    // If an Origin or Referer is supplied (standard for all browsers on mutating cross-site requests)
    if (requestOrigin) {
      if (!allowedOrigins.includes(requestOrigin)) {
        return res.status(403).json({
          error: {
            message: `Forbidden: Cross-origin request from '${requestOrigin}' rejected by CSRF protection.`,
            code: 'CSRF_REJECTED'
          }
        });
      }
    } else if (process.env.NODE_ENV === 'production' && req.cookies && (req.cookies.token || req.cookies.refreshToken)) {
      // In production, if session cookies are present on a mutating request, Origin or Referer MUST be present
      return res.status(403).json({
        error: {
          message: 'Forbidden: Missing Origin/Referer header on authenticated mutating request.',
          code: 'CSRF_ORIGIN_MISSING'
        }
      });
    }

    next();
  };
}

module.exports = { csrfProtection };

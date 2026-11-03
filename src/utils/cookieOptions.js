// server/src/utils/cookieOptions.js
/**
 * Resolves cookie configuration for session and auth tokens.
 *
 * SameSite Architecture:
 * - Default: SameSite=Lax. In a cross-subdomain setup (e.g. pmt.solarman.in frontend
 *   and pmtmgmt.solarman.in backend), both hosts share the same registrable domain ('solarman.in').
 *   Browsers classify them as Same-Site, meaning SameSite=Lax cookies are sent on top-level
 *   and same-site subresource requests with credentials: 'include'.
 * - SameSite=None: ONLY required if the frontend and backend are hosted on completely different
 *   registrable domains (e.g. app.com and api.io). Must be explicitly set via COOKIE_SAME_SITE=none.
 *
 * Path Policy:
 * - Refresh tokens MUST use path: '/' (or a path that covers '/api/secure') so that
 *   the refresh cookie is sent to the encrypted POST /api/secure gateway endpoint
 *   when executing the auth.refresh operation. A path of '/api/auth' is strictly avoided.
 */
function getCookieOptions(maxAgeMs, env = process.env) {
  const isProd = env.NODE_ENV === 'production';
  const rawSameSite = (env.COOKIE_SAME_SITE || 'lax').toLowerCase();
  const sameSite = ['lax', 'strict', 'none'].includes(rawSameSite) ? rawSameSite : 'lax';

  const secure = env.COOKIE_SECURE !== undefined
    ? env.COOKIE_SECURE === 'true'
    : isProd;

  // Path must encompass /api/secure for the encrypted POST-only gateway
  const path = env.COOKIE_PATH || '/';

  const opts = {
    httpOnly: true,
    secure,
    sameSite,
    path,
    maxAge: maxAgeMs
  };

  if (env.COOKIE_DOMAIN) {
    opts.domain = env.COOKIE_DOMAIN;
  }

  return opts;
}

function getSessionCookieOptions(maxAgeMs, env = process.env) {
  return getCookieOptions(maxAgeMs, env);
}

function getRefreshCookieOptions(maxAgeMs, env = process.env) {
  // Refresh cookie must be valid for /api/secure
  const opts = getCookieOptions(maxAgeMs, env);
  opts.path = env.REFRESH_COOKIE_PATH || '/';
  return opts;
}

function getClearCookieOptions(env = process.env) {
  const opts = getCookieOptions(0, env);
  delete opts.maxAge;
  return opts;
}

module.exports = {
  getCookieOptions,
  getSessionCookieOptions,
  getRefreshCookieOptions,
  getClearCookieOptions
};


// server/src/middleware/auth.js
// Multi-tenant JWT authentication middleware attaching req.user, req.tenant, and req.db.
const jwt = require('jsonwebtoken');
const { getTenantDb, getDevSingleDb, getMasterDb } = require('../services/tenantPools');
const { isTokenBlacklisted } = require('../utils/tokenBlacklist');

function getJwtSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('FATAL: JWT_SECRET environment variable is missing in production.');
    }
    throw new Error('JWT_SECRET environment variable is not defined.');
  }
  if (process.env.NODE_ENV === 'production' && secret.length < 32) {
    throw new Error('FATAL: JWT_SECRET is too weak for production (minimum 32 characters required).');
  }
  return secret;
}

function extractToken(req) {
  if (req.cookies && req.cookies.token) {
    return req.cookies.token;
  }
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7).trim();
  }
  return null;
}

// In-memory cache for active session status (max 5 seconds TTL)
const sessionCache = new Map();

async function checkSessionActive(db, tenantId, sessionId) {
  if (!sessionId) return { active: true };
  const effectiveTenant = tenantId ? String(tenantId) : (process.env.DEV_SINGLE_TENANT === '1' ? 'single' : 'unknown');
  const cacheKey = `t:${effectiveTenant}:sess:${sessionId}`;
  const now = Date.now();
  const cached = sessionCache.get(cacheKey);

  if (cached && (now - cached.cachedAt) < 5000) {
    if (!cached.active) {
      return { active: false, code: 'SESSION_REVOKED', message: 'Session has been revoked. Please log in again.' };
    }
    if (cached.expiresAt && new Date(cached.expiresAt).getTime() < now) {
      return { active: false, code: 'SESSION_EXPIRED', message: 'Session has expired. Please log in again.' };
    }
    return { active: true };
  }

  const sessRows = await db.query(
    'SELECT revoked_at, expires_at FROM sessions WHERE id = ?',
    [sessionId]
  );

  if (sessRows.length === 0) {
    sessionCache.set(cacheKey, { active: false, cachedAt: now });
    return { active: false, code: 'SESSION_REVOKED', message: 'Session has been revoked. Please log in again.' };
  }

  const sess = sessRows[0];
  const isRevoked = !!sess.revoked_at;
  const isExpired = new Date(sess.expires_at).getTime() < now;
  const active = !isRevoked && !isExpired;

  sessionCache.set(cacheKey, {
    active,
    expiresAt: sess.expires_at,
    cachedAt: now
  });

  if (isRevoked) {
    return { active: false, code: 'SESSION_REVOKED', message: 'Session has been revoked. Please log in again.' };
  }
  if (isExpired) {
    return { active: false, code: 'SESSION_EXPIRED', message: 'Session has expired. Please log in again.' };
  }

  return { active: true };
}

function invalidateSessionCache(tenantId = null, sessionId = null) {
  if (sessionId) {
    const effectiveTenant = tenantId ? String(tenantId) : (process.env.DEV_SINGLE_TENANT === '1' ? 'single' : 'unknown');
    sessionCache.delete(`t:${effectiveTenant}:sess:${sessionId}`);
  } else if (tenantId) {
    const prefix = `t:${tenantId}:sess:`;
    for (const key of sessionCache.keys()) {
      if (key.startsWith(prefix)) {
        sessionCache.delete(key);
      }
    }
  } else {
    sessionCache.clear();
  }
}

const requireAuth = async (req, res, next) => {
  const token = extractToken(req);

  if (!token) {
    return res.status(401).json({
      error: { message: 'Authentication token missing', code: 'UNAUTHORIZED' }
    });
  }

  if (isTokenBlacklisted(token)) {
    return res.status(401).json({
      error: { message: 'Session has been revoked upon logout. Please log in again.', code: 'SESSION_REVOKED' }
    });
  }

  try {
    const payload = jwt.verify(token, getJwtSecret());
    const userId = Number(payload.sub || payload.userId);
    const tenantId = payload.tid ? Number(payload.tid) : (payload.tenantId ? Number(payload.tenantId) : null);

    const sessionId = payload.sid || null;

    req.user = {
      id: userId,
      email: payload.email,
      name: payload.name,
      tenantId,
      sessionId
    };

    if (tenantId) {
      const masterDb = getMasterDb();
      const [tenant] = await masterDb.query(
        'SELECT id, slug, name, db_name, status FROM tenants WHERE id = ?',
        [tenantId]
      );

      if (!tenant) {
        return res.status(401).json({
          error: { message: 'Tenant company no longer exists', code: 'TENANT_NOT_FOUND' }
        });
      }

      if (tenant.status !== 'active' && tenant.status !== 'provisioning') {
        return res.status(403).json({
          error: { message: `Company is currently ${tenant.status}`, code: 'TENANT_INACTIVE' }
        });
      }

      req.tenant = tenant;
      req.db = await getTenantDb(tenantId);
      req.db.tenantId = tenant.id;
    } else {
      // Single-tenant or development fallback
      req.tenant = {
        id: 1,
        slug: 'dev',
        name: 'Dev Company',
        db_name: process.env.MYSQL_DATABASE || 'pm_dev_single',
        status: 'active'
      };
      req.db = getDevSingleDb();
      req.db.tenantId = 1;
    }

    const userRes = await req.db.query(
      'SELECT id, name, email, must_change_password, locked_until, totp_enabled FROM users WHERE id = ?',
      [userId]
    );
    if (userRes.length === 0) {
      return res.status(401).json({
        error: { message: 'User account no longer exists in this organization', code: 'USER_NOT_FOUND' }
      });
    }

    const dbUser = userRes[0];
    if (dbUser.locked_until && new Date(dbUser.locked_until) > new Date()) {
      return res.status(423).json({
        error: { message: 'Account is temporarily locked due to multiple failed login attempts', code: 'ACCOUNT_LOCKED' }
      });
    }

    req.user.mustChangePassword = !!dbUser.must_change_password;
    req.user.totpEnabled = !!dbUser.totp_enabled;

    // Item 4: must_change_password enforcement in middleware
    // While true, every route except change-password, logout, and me returns 403 PASSWORD_CHANGE_REQUIRED
    if (dbUser.must_change_password) {
      const url = req.originalUrl || req.url || '';
      const isExempt = (
        ((req.method === 'PUT' || req.method === 'POST') && (url.includes('/auth/password') || url.includes('/change-password'))) ||
        (req.method === 'POST' && (url.endsWith('/api/auth/logout') || url.endsWith('/api/auth/logout-all'))) ||
        (req.method === 'GET' && (url.endsWith('/api/auth/me') || url.includes('/auth/me')))
      );

      if (!isExempt) {
        return res.status(403).json({
          error: {
            message: 'Password change required before accessing this resource. Please change your temporary password.',
            code: 'PASSWORD_CHANGE_REQUIRED'
          }
        });
      }
    }

    // Item 3: Session active check on every request with max 5s in-memory cache
    if (sessionId) {
      const sessionStatus = await checkSessionActive(req.db, req.tenant?.id, sessionId);
      if (!sessionStatus.active) {
        return res.status(401).json({
          error: { message: sessionStatus.message, code: sessionStatus.code }
        });
      }
    }

    next();
  } catch (err) {
    return res.status(401).json({
      error: { message: 'Invalid or expired token', code: 'UNAUTHORIZED' }
    });
  }
};

/**
 * Optional tenant resolution middleware for unauthenticated routes
 * (e.g. invitation link verification by tenant header or slug)
 */
const resolveOptionalTenant = async (req, res, next) => {
  try {
    const tenantId = req.headers['x-tenant-id'] || req.query.tenant_id;
    const tenantSlug = req.headers['x-tenant-slug'] || req.query.tenant_slug;

    if (tenantId) {
      req.db = await getTenantDb(Number(tenantId));
    } else if (tenantSlug) {
      const masterDb = getMasterDb();
      const [t] = await masterDb.query(
        'SELECT id, slug, db_name, status FROM tenants WHERE slug = ?',
        [String(tenantSlug).trim().toLowerCase()]
      );
      if (t) {
        req.tenant = t;
        req.db = await getTenantDb(t.id);
      }
    } else if (process.env.DEV_SINGLE_TENANT === '1') {
      req.db = getDevSingleDb();
    }
  } catch (e) {
    // optional, proceed without req.db
  }
  next();
};

module.exports = {
  requireAuth,
  getJwtSecret,
  extractToken,
  resolveOptionalTenant,
  checkSessionActive,
  invalidateSessionCache
};

// server/src/services/sessionService.js
// Access JWT (15-min) and rotating refresh token management with reuse detection.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getJwtSecret } = require('../middleware/auth');
const { getClientIp } = require('../middleware/rateLimit');
const { logAuthEvent } = require('./authAudit');

const ACCESS_TOKEN_EXPIRY = '5d'; // 5 days max
const REFRESH_TOKEN_DAYS = 5; // 5 days absolute ceiling

function parseDeviceInfo(userAgent) {
  if (!userAgent) return 'Unknown Device';
  let browser = 'Unknown Browser';
  let os = 'Unknown OS';

  if (/windows/i.test(userAgent)) os = 'Windows';
  else if (/macintosh|mac os x/i.test(userAgent)) os = 'macOS';
  else if (/linux/i.test(userAgent)) os = 'Linux';
  else if (/android/i.test(userAgent)) os = 'Android';
  else if (/iphone|ipad|ipod/i.test(userAgent)) os = 'iOS';

  if (/edg/i.test(userAgent)) browser = 'Edge';
  else if (/chrome|crios/i.test(userAgent)) browser = 'Chrome';
  else if (/firefox|fxios/i.test(userAgent)) browser = 'Firefox';
  else if (/safari/i.test(userAgent)) browser = 'Safari';

  return `${browser} on ${os}`;
}

function hashToken(rawToken) {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

function generateAccessToken(user, tenantId = null, sessionId = null, expiresInSeconds = null, extraClaims = {}) {
  const payload = {
    sub: user.id,
    userId: user.id,
    email: user.email,
    name: user.name,
    sid: sessionId,
    ...extraClaims
  };
  if (tenantId) {
    payload.tid = Number(tenantId);
    payload.tenantId = Number(tenantId);
  }
  const expiresIn = (expiresInSeconds && expiresInSeconds > 0) ? expiresInSeconds : (5 * 24 * 60 * 60);
  return jwt.sign(payload, getJwtSecret(), { expiresIn });
}

async function createSession(db, user, req, options = {}) {
  const sessionId = crypto.randomUUID();
  const familyId = options.familyId || crypto.randomUUID();
  const tenantId = options.tenantId || req?.tenant?.id || null;
  const randomHex = crypto.randomBytes(32).toString('hex');
  const rawRefreshToken = tenantId ? `${tenantId}.${randomHex}` : randomHex;
  const tokenHash = hashToken(rawRefreshToken);

  const ipAddress = req ? getClientIp(req) : '127.0.0.1';
  const userAgent = req ? (req.headers['user-agent'] || 'Unknown') : 'Unknown';
  const deviceInfo = parseDeviceInfo(userAgent);

  const expiresAt = options.expiresAt || new Date(Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000);
  const remainingSeconds = Math.max(60, Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000));

  await db.execute(
    `INSERT INTO sessions 
     (id, user_id, refresh_token_hash, family_id, device_info, ip_address, user_agent, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP(3))`,
    [sessionId, user.id, tokenHash, familyId, deviceInfo, ipAddress, userAgent.substring(0, 500), expiresAt]
  );

  const extraClaims = options.two_fa_required ? { two_fa_required: true } : {};
  const accessToken = generateAccessToken(user, options.tenantId || null, sessionId, remainingSeconds, extraClaims);

  // Notify if user has previous sessions (new device/session login)
  try {
    const prevSessions = await db.query(
      'SELECT id FROM sessions WHERE user_id = ? AND id != ? LIMIT 1',
      [user.id, sessionId]
    );
    if (prevSessions.length > 0) {
      const { logAuthEvent } = require('./authAudit');
      await logAuthEvent(db, {
        userId: user.id,
        email: user.email,
        eventType: 'NEW_DEVICE_SESSION',
        metadata: { deviceInfo, ipAddress }
      });
      const { notify } = require('./notify');
      await notify({
        db,
        tenantId,
        eventType: 'security.new_device_session',
        actorId: user.id,
        targetUserId: user.id,
        data: { deviceInfo, ipAddress }
      });
    }
  } catch (notifErr) {
    // Non-blocking
  }

  return {
    sessionId,
    familyId,
    accessToken,
    refreshToken: rawRefreshToken,
    expiresIn: remainingSeconds, // Capped to 5-day ceiling
    expiresAt
  };
}

async function rotateSession(db, rawRefreshToken, req, tenantId = null) {
  if (!rawRefreshToken || typeof rawRefreshToken !== 'string') {
    const error = new Error('Refresh token is required');
    error.status = 400;
    error.code = 'INVALID_REFRESH_TOKEN';
    throw error;
  }

  const tokenHash = hashToken(rawRefreshToken);

  const [session] = await db.query(
    'SELECT *, TIMESTAMPDIFF(SECOND, revoked_at, CURRENT_TIMESTAMP(3)) as revoked_elapsed_sec FROM sessions WHERE refresh_token_hash = ?',
    [tokenHash]
  );

  if (!session) {
    const error = new Error('Invalid or non-existent refresh token');
    error.status = 401;
    error.code = 'INVALID_REFRESH_TOKEN';
    throw error;
  }

  // Family 5-day maximum lifetime ceiling check (user can stay logged in for at most 5 days from initial login)
  const [famFirst] = await db.query(
    'SELECT MIN(created_at) as first_created_at FROM sessions WHERE family_id = ?',
    [session.family_id]
  );
  const familyCreatedAt = famFirst?.first_created_at ? new Date(famFirst.first_created_at) : new Date(session.created_at);
  const maxFamilyExpiresAt = new Date(familyCreatedAt.getTime() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000);

  if (Date.now() >= maxFamilyExpiresAt.getTime()) {
    // 5-day limit reached: revoke family and require full relogin
    await db.execute(
      'UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP(3) WHERE family_id = ? AND revoked_at IS NULL',
      [session.family_id]
    );

    const error = new Error('Session has reached its 5-day maximum duration. Please sign in again.');
    error.status = 401;
    error.code = 'SESSION_MAX_LIFETIME_EXCEEDED';
    throw error;
  }

  // Reuse Detection & 20-Second Rotation Race Grace Window (Item 2)
  if (session.revoked_at) {
    const elapsedSec = (session.revoked_elapsed_sec !== null && session.revoked_elapsed_sec !== undefined)
      ? Number(session.revoked_elapsed_sec)
      : (Date.now() - new Date(session.revoked_at).getTime()) / 1000;

    // Grace window only applies if the family still has active (unrevoked) sessions
    const [activeInFamily] = await db.query(
      'SELECT COUNT(*) as count FROM sessions WHERE family_id = ? AND revoked_at IS NULL',
      [session.family_id]
    );

    if (activeInFamily && activeInFamily.count > 0 && elapsedSec <= 20) {
      // Within 20-second rotation race grace window:
      // Return a fresh valid pair for the same family, DO NOT revoke.
      const [user] = await db.query(
        'SELECT id, name, email, must_change_password, locked_until FROM users WHERE id = ?',
        [session.user_id]
      );
      if (!user) {
        const error = new Error('User associated with session not found');
        error.status = 401;
        error.code = 'USER_NOT_FOUND';
        throw error;
      }
      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        const error = new Error('User account is temporarily locked');
        error.status = 423;
        error.code = 'ACCOUNT_LOCKED';
        throw error;
      }

      const newSession = await createSession(db, user, req, {
        familyId: session.family_id,
        tenantId,
        expiresAt: maxFamilyExpiresAt
      });

      return {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          must_change_password: !!user.must_change_password
        },
        ...newSession
      };
    }

    // Reuse after the grace window (> 20s): revoke the entire family!
    await db.execute(
      'UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP(3) WHERE family_id = ? AND revoked_at IS NULL',
      [session.family_id]
    );

    try {
      const { invalidateSessionCache } = require('../middleware/auth');
      invalidateSessionCache(tenantId);
      const { disconnectUserSockets } = require('../socket');
      disconnectUserSockets(session.user_id, tenantId, 'TOKEN_REUSE_DETECTED');
    } catch (e) {}

    await logAuthEvent(db, {
      userId: session.user_id,
      eventType: 'TOKEN_REUSE_DETECTED',
      req,
      metadata: { familyId: session.family_id, attemptedSessionId: session.id, elapsedSec }
    });

    const error = new Error('Token reuse detected. All sessions in this chain have been revoked for your security.');
    error.status = 401;
    error.code = 'TOKEN_REUSED';
    throw error;
  }

  // Check expiration
  if (new Date(session.expires_at) < new Date()) {
    const error = new Error('Refresh token has expired. Please sign in again.');
    error.status = 401;
    error.code = 'REFRESH_TOKEN_EXPIRED';
    throw error;
  }

  // Check user status
  const [user] = await db.query(
    'SELECT id, name, email, must_change_password, locked_until FROM users WHERE id = ?',
    [session.user_id]
  );

  if (!user) {
    const error = new Error('User associated with session not found');
    error.status = 401;
    error.code = 'USER_NOT_FOUND';
    throw error;
  }

  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    const error = new Error('User account is temporarily locked');
    error.status = 423;
    error.code = 'ACCOUNT_LOCKED';
    throw error;
  }

  // Check if user is deactivated across all workspaces in tenant
  const memberRows = await db.query('SELECT status FROM workspace_members WHERE user_id = ?', [user.id]);
  if (memberRows && memberRows.length > 0 && memberRows.every(r => r.status === 'deactivated')) {
    const error = new Error('Your account has been deactivated. Please contact your workspace administrator.');
    error.status = 403;
    error.code = 'ACCOUNT_DEACTIVATED';
    throw error;
  }

  // Revoke the old session
  await db.execute(
    'UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP(3) WHERE id = ?',
    [session.id]
  );

  // Issue new session in the same family (capped to 5-day ceiling)
  const requires2fa = await checkUserRequires2Fa(db, user.id, user.totp_enabled);
  const newSession = await createSession(db, user, req, {
    familyId: session.family_id,
    tenantId,
    expiresAt: maxFamilyExpiresAt,
    two_fa_required: requires2fa
  });

  await logAuthEvent(db, {
    userId: user.id,
    email: user.email,
    eventType: 'TOKEN_REFRESH_SUCCESS',
    req,
    metadata: { sessionId: newSession.sessionId, previousSessionId: session.id }
  });

  return {
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      must_change_password: !!user.must_change_password
    },
    ...newSession
  };
}

async function listSessions(db, userId, currentSessionId = null) {
  const rows = await db.query(
    `SELECT id, device_info, ip_address, user_agent, created_at, updated_at, expires_at
     FROM sessions
     WHERE user_id = ? AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP(3)
     ORDER BY created_at DESC`,
    [userId]
  );

  return rows.map((row) => ({
    id: row.id,
    device_info: row.device_info,
    ip_address: row.ip_address,
    created_at: row.created_at,
    expires_at: row.expires_at,
    is_current: currentSessionId ? row.id === currentSessionId : false
  }));
}

async function revokeSession(db, userId, sessionId, req = null) {
  await db.execute(
    'UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP(3) WHERE id = ? AND user_id = ?',
    [sessionId, userId]
  );

  try {
    const { invalidateSessionCache } = require('../middleware/auth');
    invalidateSessionCache(req?.tenant?.id || null, sessionId);
  } catch (e) {}

  await logAuthEvent(db, {
    userId,
    eventType: 'SESSION_REVOKED',
    req,
    metadata: { sessionId }
  });
}

async function revokeAllSessions(db, userId, reason = 'LOGOUT_ALL', req = null) {
  await db.execute(
    'UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP(3) WHERE user_id = ? AND revoked_at IS NULL',
    [userId]
  );

  try {
    const { invalidateSessionCache } = require('../middleware/auth');
    invalidateSessionCache(req?.tenant?.id || null);
    const { disconnectUserSockets } = require('../socket');
    disconnectUserSockets(userId, req?.tenant?.id || null, reason);
  } catch (e) {}

  await logAuthEvent(db, {
    userId,
    eventType: reason,
    req
  });
}

async function revokeAllExceptCurrent(db, userId, currentSessionId, req = null) {
  if (currentSessionId) {
    await db.execute(
      'UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP(3) WHERE user_id = ? AND id != ? AND revoked_at IS NULL',
      [userId, currentSessionId]
    );
  } else {
    await revokeAllSessions(db, userId, 'LOGOUT_OTHER_SESSIONS', req);
  }

  try {
    const { invalidateSessionCache } = require('../middleware/auth');
    invalidateSessionCache(req?.tenant?.id || null);
  } catch (e) {}

  await logAuthEvent(db, {
    userId,
    eventType: 'LOGOUT_OTHER_SESSIONS',
    req,
    metadata: { keptSessionId: currentSessionId }
  });
}

async function checkUserRequires2Fa(db, userId, totpEnabled) {
  if (totpEnabled) return false;
  try {
    const wsRows = await db.query(
      `SELECT w.settings, w.require_2fa_for_admins, r.rank
       FROM workspace_members wm
       JOIN workspaces w ON wm.workspace_id = w.id
       JOIN roles r ON wm.role_id = r.id
       WHERE wm.user_id = ? AND wm.status = 'active'`,
      [userId]
    );
    for (const row of wsRows) {
      let settings = row.settings;
      if (typeof settings === 'string') {
        try { settings = JSON.parse(settings); } catch (e) { settings = {}; }
      }
      if (settings?.require_2fa) return true;
      if (row.require_2fa_for_admins && Number(row.rank || 0) >= 50) return true;
    }
  } catch (e) {}
  return false;
}

module.exports = {
  createSession,
  rotateSession,
  listSessions,
  revokeSession,
  revokeAllSessions,
  revokeAllExceptCurrent,
  generateAccessToken,
  parseDeviceInfo,
  checkUserRequires2Fa
};

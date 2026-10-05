// server/src/routes/auth.js
// Multi-tenant authentication with rotating sessions, TOTP 2FA, lockout protection, and audit logging.
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const { requireAuth, getJwtSecret } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { getMasterDb, getTenantDb, getDevSingleDb } = require('../services/tenantPools');
const { provisionTenant, slugify } = require('../services/tenantProvisioner');
const { EmailProvider } = require('../services/providers');
const { validatePassword, generateCompliantPassword } = require('../utils/passwordPolicy');
const { authRateLimiter, loginRateLimiter } = require('../middleware/rateLimit');
const { logAuthEvent } = require('../services/authAudit');
const { userHasPermission } = require('../middleware/permissions');
const {
  createSession,
  rotateSession,
  listSessions,
  revokeSession,
  revokeAllSessions,
  revokeAllExceptCurrent
} = require('../services/sessionService');
const {
  generateTotpSetup,
  verifyTotpCode,
  generateRecoveryCodes,
  verifyRecoveryCode,
  disableTwoFactor
} = require('../services/twoFactorService');
const { encryptSecret, decryptSecret } = require('../utils/cryptoVault');

const router = express.Router();

// Apply auth rate limiter to all auth endpoints
router.use(authRateLimiter);

const BCRYPT_ROUNDS = 12;

// In-memory single-use and rate-limit tracking for 2FA login challenges
const usedChallengeTokens = new Set();
const challengeFailedAttempts = new Map();

// Reserved company slugs that cannot be registered
const RESERVED_SLUGS = new Set([
  'admin', 'administrator', 'api', 'app', 'assets', 'auth', 'billing', 'config',
  'dashboard', 'dev', 'docs', 'help', 'internal', 'login', 'mail', 'master',
  'pmt', 'portal', 'private', 'public', 'register', 'root', 'secure', 'settings',
  'setup', 'static', 'status', 'support', 'system', 'tenant', 'test', 'user', 'www'
]);

// Registration abuse prevention: per-IP tracking and provisioning concurrency
const registrationIpTracker = new Map();
let activeTenantProvisionings = 0;

function checkRegistrationIpLimit(ip) {
  const windowMs = 60 * 60 * 1000; // 1 hour
  const max = Number(process.env.REGISTRATION_RATE_LIMIT_PER_HOUR || 3);
  const now = Date.now();
  const timestamps = (registrationIpTracker.get(ip) || []).filter((t) => now - t < windowMs);
  if (timestamps.length >= max) {
    return false;
  }
  timestamps.push(now);
  registrationIpTracker.set(ip, timestamps);
  return true;
}

function resetRegistrationLimitsForTest() {
  registrationIpTracker.clear();
  activeTenantProvisionings = 0;
}

// Dummy bcrypt hash for constant-time simulated comparisons when email does not exist
const DUMMY_HASH = '$2b$12$e8r0.sA8uU1qR09rVpGqf.rT7a7b8c9d0e1f2g3h4i5j6k7l8m9n0';

const registerCompanySchema = z.object({
  companyName: z.string().optional(),
  company_name: z.string().optional(),
  slug: z.string().optional(),
  name: z.string().optional(),
  admin_name: z.string().optional(),
  email: z.string().email('Invalid email address').optional(),
  admin_email: z.string().email('Invalid email address').optional(),
  password: z.string().optional(),
  admin_password: z.string().optional(),
  phone: z.string().optional()
}).refine((data) => (data.companyName || data.company_name) && (data.name || data.admin_name) && (data.email || data.admin_email) && (data.password || data.admin_password), {
  message: 'Company name, admin name, email, and password are required.'
});

const verifyRegistrationSchema = z.object({
  verification_id: z.number().int().positive('verification_id is required'),
  otp: z.string().min(6).max(6, 'OTP must be 6 digits')
});

const registerUserSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
  invite_token: z.string().optional()
});

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
  tenant_slug: z.string().optional()
});

const verifyLogin2FaSchema = z.object({
  temp_token: z.string().min(1, 'temp_token is required'),
  code: z.string().min(1, 'Authentication code or recovery code is required')
});

const confirm2FaSchema = z.object({
  secret: z.string().min(16, 'TOTP secret is required'),
  token: z.string().min(6, 'TOTP token is required')
});

const disable2FaSchema = z.object({
  password: z.string().min(1, 'Password is required'),
  token: z.string().optional()
});

const updateProfileSchema = z.object({
  name: z.string().min(1, 'Name is required').optional(),
  email: z.string().email('Invalid email address').optional(),
  timezone: z.string().max(100).optional(),
  locale: z.string().max(20).optional(),
  avatar_url: z.string().max(500).nullable().optional()
});

function normalizeEmail(email) {
  return (email || '').trim().toLowerCase();
}

const { getCookieOptions, getClearCookieOptions } = require('../utils/cookieOptions');

const COOKIE_OPTIONS = getCookieOptions(15 * 60 * 1000); // 15 minutes
const REFRESH_COOKIE_OPTIONS = getCookieOptions(30 * 24 * 60 * 60 * 1000); // 30 days

// -------------------------------------------------------------
// POST /api/auth/register-company
// Step 1: Validates company & admin password policy; provisions or OTP
// -------------------------------------------------------------
router.post('/register-company', validate(registerCompanySchema), async (req, res, next) => {
  const registrationEnabled = process.env.REGISTRATION_ENABLED !== 'false' && process.env.REGISTRATION_ENABLED !== '0';
  if (!registrationEnabled) {
    return res.status(403).json({
      error: { message: 'Company registration is currently disabled.', code: 'REGISTRATION_DISABLED' }
    });
  }

  const companyName = req.body.companyName || req.body.company_name;
  const name = req.body.name || req.body.admin_name;
  const email = req.body.email || req.body.admin_email;
  const password = req.body.password || req.body.admin_password;
  const { slug, phone } = req.body;

  // 1. IP rate limiting (configurable, default 3 per hour)
  const clientIp = req.ip || '127.0.0.1';
  if (!checkRegistrationIpLimit(clientIp)) {
    return res.status(429).json({
      error: {
        message: 'Too many registration requests from this IP address. Please try again later.',
        code: 'REGISTRATION_RATE_LIMIT_EXCEEDED'
      }
    });
  }

  // 2. Validate Password Policy (min 10 chars, mixed classes)
  const passwordCheck = validatePassword(password);
  if (!passwordCheck.isValid) {
    return res.status(400).json({
      error: { message: passwordCheck.error, code: 'PASSWORD_TOO_WEAK' }
    });
  }

  const normalizedEmail = normalizeEmail(email);
  const normalizedSlug = slugify(slug || companyName);

  // 3. Format validation for slug and email
  const slugRegex = /^[a-z0-9](?:[a-z0-9-_]{1,61}[a-z0-9])?$/;
  if (!slugRegex.test(normalizedSlug) || normalizedSlug.length < 3) {
    return res.status(400).json({
      error: {
        message: 'Company URL / slug must be between 3 and 63 lowercase alphanumeric characters, underscores, and hyphens, and cannot start or end with a hyphen or underscore.',
        code: 'INVALID_SLUG_FORMAT'
      }
    });
  }

  // 4. Reserved slug check
  if (RESERVED_SLUGS.has(normalizedSlug)) {
    return res.status(400).json({
      error: {
        message: `Company URL / slug "${normalizedSlug}" is reserved for system use.`,
        code: 'SLUG_RESERVED'
      }
    });
  }

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(normalizedEmail)) {
    return res.status(400).json({
      error: { message: 'Invalid email address format.', code: 'INVALID_EMAIL_FORMAT' }
    });
  }

  // 5. Artificial CPU Cost: Compute bcrypt hash upfront BEFORE any database operations
  // This imposes computational work (cost 12) on callers, preventing unauthenticated callers from spamming cheap DB queries
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  // 6. Concurrency limit on active provisioning jobs (max 2 at a time)
  const maxConcurrency = Number(process.env.MAX_CONCURRENT_PROVISIONINGS || 2);
  if (activeTenantProvisionings >= maxConcurrency) {
    return res.status(429).json({
      error: {
        message: 'Server is currently busy provisioning new accounts. Please retry in a few moments.',
        code: 'PROVISIONING_BUSY'
      }
    });
  }

  const masterDb = getMasterDb();

  try {
    // 7. Global daily cap on new tenants (configurable, default 20)
    const dailyCap = Number(process.env.REGISTRATION_DAILY_CAP || 20);
    const capRows = await masterDb.query(
      "SELECT COUNT(*) as count FROM tenants WHERE created_at >= NOW() - INTERVAL 1 DAY"
    );
    const recentTenantsCount = capRows && capRows[0] ? Number(capRows[0].count) : 0;
    if (recentTenantsCount >= dailyCap) {
      return res.status(429).json({
        error: {
          message: 'Daily company registration limit reached. Please contact support.',
          code: 'DAILY_REGISTRATION_CAP_REACHED'
        }
      });
    }

    // Check slug availability in master tenants (Item 8: deleted slug stays reserved for 30 days)
    const existingTenant = await masterDb.query(
      "SELECT id, slug, status, deleted_at, updated_at FROM tenants WHERE slug = ?",
      [normalizedSlug]
    );
    if (existingTenant.length > 0) {
      const t = existingTenant[0];
      if (t.status !== 'deleted') {
        return res.status(409).json({
          error: { message: `Company URL / slug "${normalizedSlug}" is already taken.`, code: 'SLUG_CONFLICT' }
        });
      }
      const delTime = t.deleted_at ? new Date(t.deleted_at).getTime() : new Date(t.updated_at).getTime();
      const daysSinceDeletion = (Date.now() - delTime) / (1000 * 60 * 60 * 24);
      if (daysSinceDeletion < 30) {
        return res.status(409).json({
          error: {
            message: `Company URL / slug "${normalizedSlug}" is reserved for 30 days following deletion.`,
            code: 'SLUG_RESERVED'
          }
        });
      }
    }

    // Check email uniqueness in master directory
    const existingUser = await masterDb.query(
      'SELECT id FROM tenant_user_directory WHERE email = ?',
      [normalizedEmail]
    );
    if (existingUser.length > 0) {
      return res.status(409).json({
        error: { message: `Email "${normalizedEmail}" is already registered.`, code: 'EMAIL_CONFLICT' }
      });
    }

    const verificationMode = (process.env.VERIFICATION_MODE || 'off').toLowerCase();

    // If verification mode is OFF (default), provision immediately without OTP
    if (verificationMode !== 'on') {
      activeTenantProvisionings++;
      let provisionResult;
      try {
        provisionResult = await provisionTenant({
          companyName: companyName.trim(),
          slug: normalizedSlug,
          ownerEmail: normalizedEmail,
          ownerPasswordHash: passwordHash,
          ownerName: name.trim(),
          phone: phone || null
        });
      } finally {
        activeTenantProvisionings--;
      }

      const { tenant, owner, workspace } = provisionResult;
      const tenantDb = await getTenantDb(tenant.id);

      // Create session with rotating refresh token and 15-min JWT
      const session = await createSession(tenantDb, owner, req, { tenantId: tenant.id });
      res.cookie('token', session.accessToken, COOKIE_OPTIONS);
      res.cookie('refreshToken', session.refreshToken, REFRESH_COOKIE_OPTIONS);

      await logAuthEvent(tenantDb, {
        userId: owner.id,
        email: owner.email,
        eventType: 'COMPANY_REGISTERED',
        req,
        metadata: { company: tenant.name, slug: tenant.slug }
      });

      return res.status(201).json({
        message: 'Company registered and provisioned successfully',
        tenant,
        user: owner,
        initial_workspace_id: workspace.id,
        token: session.accessToken,
        refreshToken: session.refreshToken,
        expiresIn: session.expiresIn
      });
    }

    // Verification mode is ON: Keep existing OTP & pending registration flow
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = await bcrypt.hash(otp, BCRYPT_ROUNDS);

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    const insRes = await masterDb.execute(
      `INSERT INTO pending_registrations 
       (email, phone, company_name, slug, admin_name, password_hash, email_otp_hash, attempts, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
      [normalizedEmail, phone || null, companyName.trim(), normalizedSlug, name.trim(), passwordHash, otpHash, expiresAt]
    );

    const verificationId = insRes.insertId;
    await EmailProvider.sendOtp(normalizedEmail, otp, { companyName, slug: normalizedSlug });

    return res.status(200).json({
      message: 'Verification code sent to your email',
      verification_id: verificationId,
      email: normalizedEmail,
      slug: normalizedSlug,
      dev_otp: process.env.NODE_ENV !== 'production' ? otp : undefined
    });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// POST /api/auth/verify-registration (Preserved for VERIFICATION_MODE=on)
// -------------------------------------------------------------
router.post('/verify-registration', validate(verifyRegistrationSchema), async (req, res, next) => {
  const { verification_id, otp } = req.body;
  const masterDb = getMasterDb();

  try {
    const regRes = await masterDb.query(
      'SELECT * FROM pending_registrations WHERE id = ?',
      [verification_id]
    );

    if (regRes.length === 0) {
      return res.status(404).json({
        error: { message: 'Pending registration not found. Please start registration again.', code: 'NOT_FOUND' }
      });
    }

    const reg = regRes[0];

    if (new Date(reg.expires_at) < new Date()) {
      await masterDb.execute('DELETE FROM pending_registrations WHERE id = ?', [verification_id]);
      return res.status(400).json({
        error: { message: 'Verification code has expired. Please register again.', code: 'OTP_EXPIRED' }
      });
    }

    if (reg.attempts >= 5) {
      await masterDb.execute('DELETE FROM pending_registrations WHERE id = ?', [verification_id]);
      return res.status(429).json({
        error: { message: 'Too many failed verification attempts. Please register again.', code: 'TOO_MANY_ATTEMPTS' }
      });
    }

    const isOtpValid = await bcrypt.compare(otp, reg.email_otp_hash);
    if (!isOtpValid) {
      await masterDb.execute(
        'UPDATE pending_registrations SET attempts = attempts + 1 WHERE id = ?',
        [verification_id]
      );
      const remaining = 5 - (reg.attempts + 1);
      return res.status(400).json({
        error: { message: `Invalid verification code. ${remaining} attempts remaining.`, code: 'INVALID_OTP' }
      });
    }

    const provisionResult = await provisionTenant({
      companyName: reg.company_name,
      slug: reg.slug,
      ownerEmail: reg.email,
      ownerPasswordHash: reg.password_hash,
      ownerName: reg.admin_name,
      phone: reg.phone
    });

    await masterDb.execute('DELETE FROM pending_registrations WHERE id = ?', [verification_id]);

    const { tenant, owner, workspace } = provisionResult;
    const tenantDb = await getTenantDb(tenant.id);
    const session = await createSession(tenantDb, owner, req, { tenantId: tenant.id });

    res.cookie('token', session.accessToken, COOKIE_OPTIONS);
    res.cookie('refreshToken', session.refreshToken, REFRESH_COOKIE_OPTIONS);

    return res.status(201).json({
      message: 'Company provisioned successfully',
      tenant,
      user: owner,
      initial_workspace_id: workspace.id,
      token: session.accessToken,
      refreshToken: session.refreshToken,
      expiresIn: session.expiresIn
    });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// POST /api/auth/register
// User registration (e.g. from invitation link or dev)
// -------------------------------------------------------------
router.post('/register', validate(registerUserSchema), async (req, res, next) => {
  const { name, email, password, invite_token: inviteToken } = req.body;

  // Validate Password Policy
  const passwordCheck = validatePassword(password);
  if (!passwordCheck.isValid) {
    return res.status(400).json({
      error: { message: passwordCheck.error, code: 'PASSWORD_TOO_WEAK' }
    });
  }

  const normalizedEmail = normalizeEmail(email);
  let activeDb = req.db;
  if (!activeDb && inviteToken) {
    const parts = inviteToken.split('.');
    if (parts.length === 3 && parts[0] !== 'default') {
      const masterDb = getMasterDb();
      const [tenant] = await masterDb.query(
        "SELECT id, db_name, slug FROM tenants WHERE slug = ? AND status != 'deleted'",
        [parts[0]]
      );
      if (tenant) {
        activeDb = await getTenantDb(tenant.id);
        req.tenant = tenant;
      }
    }
  }
  if (!activeDb) {
    activeDb = getDevSingleDb();
  }

  try {
    const existing = await activeDb.query('SELECT id FROM users WHERE email = ?', [normalizedEmail]);
    if (existing.length > 0) {
      return res.status(400).json({
        error: { message: 'Email is already registered', code: 'EMAIL_IN_USE' }
      });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const userRes = await activeDb.execute(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      [name, normalizedEmail, passwordHash]
    );
    const userId = userRes.insertId;
    const [user] = await activeDb.query('SELECT id, name, email, created_at FROM users WHERE id = ?', [userId]);

    let createdWorkspaceId = null;
    let createdBoardId = null;
    let invite = null;

    if (inviteToken) {
      const inviteRes = await activeDb.query(
        `SELECT pi.id, pi.workspace_id, pi.status, pi.expires_at, GROUP_CONCAT(ib.board_id) as board_ids_str
         FROM pending_invitations pi
         LEFT JOIN invitation_boards ib ON pi.id = ib.invitation_id
         WHERE pi.token = ?
         GROUP BY pi.id, pi.workspace_id, pi.status, pi.expires_at`,
        [inviteToken]
      );
      if (inviteRes.length === 0) {
        return res.status(404).json({ error: { message: 'Invitation not found', code: 'NOT_FOUND' } });
      }
      const foundInvite = inviteRes[0];
      if (foundInvite.status !== 'pending') {
        return res.status(410).json({ error: { message: 'Invitation has already been used or revoked', code: 'INVITATION_INVALID' } });
      }
      if (foundInvite.expires_at && new Date(foundInvite.expires_at) < new Date()) {
        return res.status(410).json({ error: { message: 'Invitation link has expired (7 day limit)', code: 'INVITATION_EXPIRED' } });
      }
      invite = {
        ...foundInvite,
        board_ids: foundInvite.board_ids_str ? foundInvite.board_ids_str.split(',').map(Number) : []
      };
    }

    if (!invite) {
      const emailInviteRes = await activeDb.query(
        `SELECT pi.id, pi.workspace_id, pi.status, pi.expires_at, GROUP_CONCAT(ib.board_id) as board_ids_str
         FROM pending_invitations pi
         LEFT JOIN invitation_boards ib ON pi.id = ib.invitation_id
         WHERE pi.email = ? AND pi.status = 'pending'
           AND (pi.expires_at IS NULL OR pi.expires_at > CURRENT_TIMESTAMP(3))
         GROUP BY pi.id, pi.workspace_id, pi.status, pi.expires_at
         ORDER BY pi.created_at DESC LIMIT 1`,
        [normalizedEmail]
      );
      if (emailInviteRes.length > 0) {
        invite = {
          ...emailInviteRes[0],
          board_ids: emailInviteRes[0].board_ids_str ? emailInviteRes[0].board_ids_str.split(',').map(Number) : []
        };
      }
    }

    if (invite) {
      const teamMemberRoleRes = await activeDb.query(
        "SELECT id FROM roles WHERE is_system = 1 AND name = 'Team Member' AND workspace_id IS NULL"
      );
      const teamMemberRoleId = teamMemberRoleRes[0]?.id;

      await activeDb.execute(
        `INSERT INTO workspace_members (workspace_id, user_id, role, role_id)
         VALUES (?, ?, 'Team Member', ?)
         ON DUPLICATE KEY UPDATE role_id = VALUES(role_id), role = 'Team Member'`,
        [invite.workspace_id, user.id, teamMemberRoleId]
      );

      if (invite.board_ids && invite.board_ids.length > 0) {
        for (const boardId of invite.board_ids) {
          await activeDb.execute(
            "INSERT IGNORE INTO board_members (board_id, user_id, role) VALUES (?, ?, 'member')",
            [boardId, user.id]
          );
        }
        createdBoardId = invite.board_ids[0];
      } else {
        const allWsBoards = await activeDb.query(
          'SELECT id FROM boards WHERE workspace_id = ? AND is_archived = 0 ORDER BY id ASC',
          [invite.workspace_id]
        );
        for (const b of allWsBoards) {
          await activeDb.execute(
            "INSERT IGNORE INTO board_members (board_id, user_id, role) VALUES (?, ?, 'member')",
            [b.id, user.id]
          );
        }
        createdBoardId = allWsBoards[0]?.id || null;
      }

      await activeDb.execute(
        `UPDATE pending_invitations
         SET status = 'accepted', accepted_at = CURRENT_TIMESTAMP(3), accepted_by_user_id = ?
         WHERE id = ?`,
        [user.id, invite.id]
      );

      createdWorkspaceId = invite.workspace_id;
    } else {
      const wsRes = await activeDb.execute(
        'INSERT INTO workspaces (name) VALUES (?)',
        [`${name}'s Workspace`]
      );
      createdWorkspaceId = wsRes.insertId;

      const ownerRoleRes = await activeDb.query(
        "SELECT id, name FROM roles WHERE is_system = 1 AND name IN ('Owner', 'Super Admin') AND workspace_id IS NULL ORDER BY (name = 'Owner') DESC LIMIT 1"
      );
      const ownerRoleId = ownerRoleRes[0]?.id;
      const ownerRoleName = ownerRoleRes[0]?.name || 'Owner';

      await activeDb.execute(
        'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)',
        [createdWorkspaceId, user.id, ownerRoleName, ownerRoleId]
      );

      const boardRes = await activeDb.execute(
        "INSERT INTO boards (workspace_id, name, background_color) VALUES (?, 'Getting Started', 'bg-gradient-to-br from-indigo-900 via-slate-900 to-purple-950')",
        [createdWorkspaceId]
      );
      createdBoardId = boardRes.insertId;

      await activeDb.execute(
        "INSERT INTO board_members (board_id, user_id, role) VALUES (?, ?, 'admin')",
        [createdBoardId, user.id]
      );

      await activeDb.execute(
        `INSERT INTO lists (board_id, name, position) VALUES 
         (?, 'To Do', 1000.0),
         (?, 'In Progress', 2000.0),
         (?, 'Done', 3000.0)`,
        [createdBoardId, createdBoardId, createdBoardId]
      );
    }

    const tenantId = req.tenant?.id || null;
    if (tenantId) {
      const masterDb = getMasterDb();
      await masterDb.execute(
        'INSERT IGNORE INTO tenant_user_directory (email, tenant_id) VALUES (?, ?)',
        [normalizedEmail, tenantId]
      );
    }

    const session = await createSession(activeDb, user, req, { tenantId });
    res.cookie('token', session.accessToken, COOKIE_OPTIONS);
    res.cookie('refreshToken', session.refreshToken, REFRESH_COOKIE_OPTIONS);

    await logAuthEvent(activeDb, {
      userId: user.id,
      email: user.email,
      eventType: 'USER_REGISTERED',
      req
    });

    return res.status(201).json({
      user,
      initial_workspace_id: createdWorkspaceId,
      initial_board_id: createdBoardId,
      token: session.accessToken,
      refreshToken: session.refreshToken,
      expiresIn: session.expiresIn
    });
  } catch (err) {
    next(err);
  }
});

// Helper for login attempt verification and lockout calculation
// Item 7: Identical responses and timing for unknown email, wrong password, and locked account
async function handleUserLoginVerification(db, user, password, req, tenant = null) {
  // 1. Check if user account is currently locked out
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    const remainingMs = new Date(user.locked_until) - new Date();
    const remainingMinutes = Math.ceil(remainingMs / 60000);

    // Constant-time simulated password compare to avoid timing side-channels
    await bcrypt.compare(password, user.password_hash || DUMMY_HASH);

    await logAuthEvent(db, {
      userId: user.id,
      email: user.email,
      eventType: 'ACCOUNT_LOCKED_ATTEMPT',
      req,
      metadata: { remainingMinutes }
    });

    const error = new Error('Invalid email or password');
    error.status = 401;
    error.code = 'INVALID_CREDENTIALS';
    error.isLocked = true;
    error.remainingMinutes = remainingMinutes;
    throw error;
  }

  // 2. Check password match
  const isMatch = await bcrypt.compare(password, user.password_hash);
  if (!isMatch) {
    const failedAttempts = (user.failed_login_attempts || 0) + 1;

    if (failedAttempts >= 5) {
      // 5 failed attempts -> 15 min exponential lockout
      const lockoutCount = (user.lockout_count || 0) + 1;
      const durationMinutes = 15 * Math.pow(2, lockoutCount - 1);
      const lockedUntil = new Date(Date.now() + durationMinutes * 60 * 1000);

      await db.execute(
        'UPDATE users SET failed_login_attempts = 0, lockout_count = ?, locked_until = ? WHERE id = ?',
        [lockoutCount, lockedUntil, user.id]
      );

      await logAuthEvent(db, {
        userId: user.id,
        email: user.email,
        eventType: 'ACCOUNT_LOCKED',
        req,
        metadata: { durationMinutes, lockoutCount }
      });

      const error = new Error('Invalid email or password');
      error.status = 401;
      error.code = 'INVALID_CREDENTIALS';
      error.isLocked = true;
      error.durationMinutes = durationMinutes;
      throw error;
    }

    // Increment failed attempts
    await db.execute(
      'UPDATE users SET failed_login_attempts = ? WHERE id = ?',
      [failedAttempts, user.id]
    );

    await logAuthEvent(db, {
      userId: user.id,
      email: user.email,
      eventType: 'LOGIN_FAILURE',
      req,
      metadata: { failedAttempts, remainingAttempts: 5 - failedAttempts }
    });

    const error = new Error('Invalid email or password');
    error.status = 401;
    error.code = 'INVALID_CREDENTIALS';
    error.remainingAttempts = 5 - failedAttempts;
    throw error;
  }

  // 3. Password matched! Reset lockout state
  await db.execute(
    'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, lockout_count = 0 WHERE id = ?',
    [user.id]
  );

  // 4. Check if TOTP 2FA is enabled for this user
  if (user.totp_enabled) {
    // Generate short-lived (5 min) temporary 2FA verification token
    const tempToken = jwt.sign(
      {
        sub: user.id,
        userId: user.id,
        email: user.email,
        tenantId: tenant ? tenant.id : null,
        purpose: '2fa_login',
        jti: crypto.randomUUID()
      },
      getJwtSecret(),
      { expiresIn: '5m' }
    );

    await logAuthEvent(db, {
      userId: user.id,
      email: user.email,
      eventType: '2FA_CHALLENGE_ISSUED',
      req
    });

    return {
      requires_2fa: true,
      temp_token: tempToken
    };
  }

  // 5. Normal login: Create session, rotating refresh token, 15-min JWT
  const session = await createSession(db, user, req, { tenantId: tenant?.id || null });

  await logAuthEvent(db, {
    userId: user.id,
    email: user.email,
    eventType: 'LOGIN_SUCCESS',
    req,
    metadata: { sessionId: session.sessionId }
  });

  return {
    requires_2fa: false,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      avatar_url: user.avatar_url || null,
      timezone: user.timezone || 'UTC',
      locale: user.locale || 'en',
      created_at: user.created_at,
      must_change_password: !!user.must_change_password,
      totp_enabled: !!user.totp_enabled
    },
    tenant: tenant || null,
    token: session.accessToken,
    refreshToken: session.refreshToken,
    expiresIn: session.expiresIn,
    session_id: session.sessionId
  };
}

// -------------------------------------------------------------
// POST /api/auth/login
// Supports multi-tenant lookup, company picker, lockout, and TOTP 2FA
// -------------------------------------------------------------
router.post('/login', loginRateLimiter, validate(loginSchema), async (req, res, next) => {
  const { email, password, tenant_slug } = req.body;
  const normalizedEmail = normalizeEmail(email);

  try {
    // 1. Single dev mode or explicit dev slug
    if (process.env.DEV_SINGLE_TENANT === '1' && !tenant_slug) {
      const devDb = getDevSingleDb();
      const userRes = await devDb.query('SELECT * FROM users WHERE email = ?', [normalizedEmail]);
      if (userRes.length === 0) {
        await bcrypt.compare(password, DUMMY_HASH);
        return res.status(401).json({ error: { message: 'Invalid email or password', code: 'INVALID_CREDENTIALS' } });
      }

      const loginResult = await handleUserLoginVerification(devDb, userRes[0], password, req, null);
      if (loginResult.token) {
        res.cookie('token', loginResult.token, COOKIE_OPTIONS);
        res.cookie('refreshToken', loginResult.refreshToken, REFRESH_COOKIE_OPTIONS);
      }
      return res.json(loginResult);
    }

    const masterDb = getMasterDb();

    // 2. Specific tenant slug provided
    if (tenant_slug) {
      const cleanSlug = slugify(tenant_slug);
      const [tenant] = await masterDb.query(
        "SELECT id, slug, name, db_name, status FROM tenants WHERE slug = ? AND status != 'deleted'",
        [cleanSlug]
      );

      if (!tenant) {
        await bcrypt.compare(password, DUMMY_HASH);
        return res.status(404).json({ error: { message: `Company "${cleanSlug}" not found`, code: 'TENANT_NOT_FOUND' } });
      }

      if (tenant.status !== 'active') {
        return res.status(403).json({ error: { message: `Company account is ${tenant.status}`, code: 'TENANT_INACTIVE' } });
      }

      const tenantDb = await getTenantDb(tenant.id);
      const userRes = await tenantDb.query('SELECT * FROM users WHERE email = ?', [normalizedEmail]);
      if (userRes.length === 0) {
        await bcrypt.compare(password, DUMMY_HASH);
        return res.status(401).json({ error: { message: 'Invalid email or password', code: 'INVALID_CREDENTIALS' } });
      }

      const loginResult = await handleUserLoginVerification(tenantDb, userRes[0], password, req, tenant);
      if (loginResult.token) {
        res.cookie('token', loginResult.token, COOKIE_OPTIONS);
        res.cookie('refreshToken', loginResult.refreshToken, REFRESH_COOKIE_OPTIONS);
      }
      return res.json(loginResult);
    }

    // 3. No tenant slug provided: Query global tenant_user_directory
    const matchingTenants = await masterDb.query(
      `SELECT t.id, t.slug, t.name, t.db_name, t.status
       FROM tenant_user_directory tud
       JOIN tenants t ON tud.tenant_id = t.id
       WHERE tud.email = ? AND t.status = 'active'`,
      [normalizedEmail]
    );

    if (matchingTenants.length === 0) {
      // Fallback: check dev single db
      const devDb = getDevSingleDb();
      const devUser = await devDb.query('SELECT * FROM users WHERE email = ?', [normalizedEmail]);
      if (devUser.length > 0) {
        const loginResult = await handleUserLoginVerification(devDb, devUser[0], password, req, null);
        if (loginResult.token) {
          res.cookie('token', loginResult.token, COOKIE_OPTIONS);
          res.cookie('refreshToken', loginResult.refreshToken, REFRESH_COOKIE_OPTIONS);
        }
        return res.json(loginResult);
      }

      return res.status(401).json({ error: { message: 'Invalid email or password', code: 'INVALID_CREDENTIALS' } });
    }

    if (matchingTenants.length === 1) {
      // Exactly one company: automatically authenticate into it
      const targetTenant = matchingTenants[0];
      const tenantDb = await getTenantDb(targetTenant.id);
      const userRes = await tenantDb.query('SELECT * FROM users WHERE email = ?', [normalizedEmail]);
      if (userRes.length === 0) {
        return res.status(401).json({ error: { message: 'Invalid email or password', code: 'INVALID_CREDENTIALS' } });
      }

      const loginResult = await handleUserLoginVerification(tenantDb, userRes[0], password, req, targetTenant);
      if (loginResult.token) {
        res.cookie('token', loginResult.token, COOKIE_OPTIONS);
        res.cookie('refreshToken', loginResult.refreshToken, REFRESH_COOKIE_OPTIONS);
      }
      return res.json(loginResult);
    }

    // Multiple companies: return company selector
    return res.json({
      requires_company_selection: true,
      companies: matchingTenants.map((t) => ({ id: t.id, slug: t.slug, name: t.name }))
    });
  } catch (err) {
    if (err.status) {
      return res.status(err.status).json({
        error: {
          message: err.message,
          code: err.code || 'AUTH_ERROR',
          remaining_minutes: err.remainingMinutes,
          remaining_attempts: err.remainingAttempts
        }
      });
    }
    next(err);
  }
});

// -------------------------------------------------------------
// POST /api/auth/2fa/verify-login
// Step 2 of login when TOTP 2FA is active
// -------------------------------------------------------------
router.post('/2fa/verify-login', validate(verifyLogin2FaSchema), async (req, res, next) => {
  const { temp_token: tempToken, code } = req.body;

  try {
    let payload;
    try {
      payload = jwt.verify(tempToken, getJwtSecret());
    } catch (e) {
      return res.status(401).json({
        error: { message: '2FA login challenge has expired or is invalid. Please sign in again.', code: 'CHALLENGE_EXPIRED' }
      });
    }

    if (payload.purpose !== '2fa_login') {
      return res.status(400).json({
        error: { message: 'Invalid token purpose', code: 'INVALID_TOKEN' }
      });
    }

    // Item 5: Challenge token is single-use
    if (usedChallengeTokens.has(tempToken)) {
      return res.status(401).json({
        error: { message: '2FA login challenge has already been used or invalidated. Please sign in again.', code: 'CHALLENGE_ALREADY_USED' }
      });
    }

    const userId = Number(payload.sub || payload.userId);
    const tenantId = payload.tenantId ? Number(payload.tenantId) : null;

    let db;
    let tenant = null;

    if (tenantId) {
      const masterDb = getMasterDb();
      const [t] = await masterDb.query('SELECT id, slug, name, db_name, status FROM tenants WHERE id = ?', [tenantId]);
      if (!t || t.status !== 'active') {
        return res.status(403).json({ error: { message: 'Tenant company inactive or deleted', code: 'TENANT_INACTIVE' } });
      }
      tenant = t;
      db = await getTenantDb(tenantId);
    } else {
      db = getDevSingleDb();
    }

    const userRes = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
    if (userRes.length === 0) {
      return res.status(404).json({ error: { message: 'User not found', code: 'NOT_FOUND' } });
    }

    const user = userRes[0];

    // Check account lockout
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(423).json({
        error: { message: 'Account is temporarily locked. Please try again later.', code: 'ACCOUNT_LOCKED' }
      });
    }

    // Decrypt TOTP secret at rest (Item 5)
    const plainSecret = decryptSecret(user.totp_secret);
    let is2FaValid = verifyTotpCode(code, plainSecret);
    let isRecoveryCode = false;
    const currentWindow = Math.floor(Date.now() / 30000);

    // Item 5: Reject a TOTP code already used in its time window (anti-replay)
    if (is2FaValid) {
      if (user.last_totp_code === String(code).trim() && Number(user.last_totp_timestamp) === currentWindow) {
        return res.status(400).json({
          error: { message: 'This TOTP code has already been used in the current time window. Please wait for the next code.', code: 'TOTP_CODE_ALREADY_USED' }
        });
      }
    } else {
      // If TOTP failed, try recovery code
      isRecoveryCode = await verifyRecoveryCode(db, user.id, code);
      if (isRecoveryCode) {
        is2FaValid = true;
      }
    }

    // Item 5: Rate limit and lock second step (5 wrong codes -> challenge invalid, counts toward account lockout)
    if (!is2FaValid) {
      const challengeFails = (challengeFailedAttempts.get(tempToken) || 0) + 1;
      challengeFailedAttempts.set(tempToken, challengeFails);

      const userFails = (user.failed_login_attempts || 0) + 1;

      if (challengeFails >= 5 || userFails >= 5) {
        usedChallengeTokens.add(tempToken);
        challengeFailedAttempts.delete(tempToken);

        const lockoutCount = (user.lockout_count || 0) + 1;
        const durationMinutes = 15 * Math.pow(2, lockoutCount - 1);
        const lockedUntil = new Date(Date.now() + durationMinutes * 60 * 1000);

        await db.execute(
          'UPDATE users SET failed_login_attempts = 0, lockout_count = ?, locked_until = ? WHERE id = ?',
          [lockoutCount, lockedUntil, user.id]
        );

        await logAuthEvent(db, {
          userId: user.id,
          email: user.email,
          eventType: 'ACCOUNT_LOCKED',
          req,
          metadata: { durationMinutes, lockoutCount, reason: '2FA_BRUTE_FORCE' }
        });

        return res.status(423).json({
          error: {
            message: `Maximum 2FA verification attempts exceeded. Challenge invalidated and account locked for ${durationMinutes} minutes.`,
            code: 'ACCOUNT_LOCKED',
            durationMinutes
          }
        });
      }

      await db.execute('UPDATE users SET failed_login_attempts = ? WHERE id = ?', [userFails, user.id]);

      await logAuthEvent(db, {
        userId: user.id,
        email: user.email,
        eventType: '2FA_LOGIN_FAILED',
        req,
        metadata: { challengeFails, userFails }
      });

      return res.status(400).json({
        error: { message: 'Invalid authentication or recovery code', code: 'INVALID_2FA_CODE' }
      });
    }

    // Code verified! Invalidate challenge token (single-use)
    usedChallengeTokens.add(tempToken);
    challengeFailedAttempts.delete(tempToken);

    if (!isRecoveryCode) {
      await db.execute(
        'UPDATE users SET last_totp_code = ?, last_totp_timestamp = ?, failed_login_attempts = 0, locked_until = NULL, lockout_count = 0 WHERE id = ?',
        [String(code).trim(), currentWindow, user.id]
      );
    } else {
      await db.execute(
        'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, lockout_count = 0 WHERE id = ?',
        [user.id]
      );
    }

    // Code verified! Create session
    const session = await createSession(db, user, req, { tenantId });
    res.cookie('token', session.accessToken, COOKIE_OPTIONS);
    res.cookie('refreshToken', session.refreshToken, REFRESH_COOKIE_OPTIONS);

    await logAuthEvent(db, {
      userId: user.id,
      email: user.email,
      eventType: isRecoveryCode ? '2FA_RECOVERY_CODE_LOGIN_SUCCESS' : '2FA_LOGIN_SUCCESS',
      req,
      metadata: { sessionId: session.sessionId, usedRecoveryCode: isRecoveryCode }
    });

    return res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar_url: user.avatar_url || null,
        timezone: user.timezone || 'UTC',
        locale: user.locale || 'en',
        created_at: user.created_at,
        must_change_password: !!user.must_change_password,
        totp_enabled: true
      },
      tenant,
      token: session.accessToken,
      refreshToken: session.refreshToken,
      expiresIn: session.expiresIn,
      session_id: session.sessionId,
      used_recovery_code: isRecoveryCode
    });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// POST /api/auth/refresh
// Rotating Refresh Token with Reuse Detection
// -------------------------------------------------------------
router.post('/refresh', async (req, res, next) => {
  const refreshToken = req.body.refreshToken || (req.cookies && req.cookies.refreshToken);
  if (!refreshToken) {
    return res.status(400).json({
      error: { message: 'Refresh token is required', code: 'MISSING_REFRESH_TOKEN' }
    });
  }

  // To find tenant DB from refresh token hash:
  // If req.tenant/req.db is available from header or context, use it.
  // Otherwise search across active tenant databases or check session table.
  let activeDb = req.db;
  let tenantId = req.tenant?.id || null;

  try {
    if (!activeDb) {
      // Find which tenant database holds this session
      const crypto = require('crypto');
      const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

      // 1. O(1) direct lookup if token contains tenantId prefix
      if (refreshToken.includes('.')) {
        const potentialTid = Number(refreshToken.split('.')[0]);
        if (potentialTid) {
          try {
            const tDb = await getTenantDb(potentialTid);
            const [sess] = await tDb.query('SELECT id FROM sessions WHERE refresh_token_hash = ?', [tokenHash]);
            if (sess) {
              activeDb = tDb;
              tenantId = potentialTid;
            }
          } catch (e) {}
        }
      }

      // 2. Fallback lookup across active tenants if prefix not present
      if (!activeDb) {
        const masterDb = getMasterDb();
        const activeTenants = await masterDb.query(
          "SELECT id, slug, name, db_name FROM tenants WHERE status = 'active'"
        );

        for (const t of activeTenants) {
          try {
            const tDb = await getTenantDb(t.id);
            const [sess] = await tDb.query('SELECT id FROM sessions WHERE refresh_token_hash = ?', [tokenHash]);
            if (sess) {
              activeDb = tDb;
              tenantId = t.id;
              break;
            }
          } catch (e) {
            // continue checking other tenants
          }
        }
      }

      if (!activeDb) {
        const devDb = getDevSingleDb();
        const [devSess] = await devDb.query('SELECT id FROM sessions WHERE refresh_token_hash = ?', [tokenHash]);
        if (devSess) {
          activeDb = devDb;
        }
      }
    }

    if (!activeDb) {
      return res.status(401).json({
        error: { message: 'Invalid or expired session token', code: 'INVALID_REFRESH_TOKEN' }
      });
    }

    const rotationResult = await rotateSession(activeDb, refreshToken, req, tenantId);

    res.cookie('token', rotationResult.accessToken, COOKIE_OPTIONS);
    res.cookie('refreshToken', rotationResult.refreshToken, REFRESH_COOKIE_OPTIONS);

    return res.json({
      user: rotationResult.user,
      token: rotationResult.accessToken,
      refreshToken: rotationResult.refreshToken,
      expiresIn: rotationResult.expiresIn,
      session_id: rotationResult.sessionId
    });
  } catch (err) {
    if (err.status) {
      return res.status(err.status).json({
        error: { message: err.message, code: err.code || 'UNAUTHORIZED' }
      });
    }
    next(err);
  }
});

// -------------------------------------------------------------
// GET /api/auth/sessions
// List active sessions for authenticated user
// -------------------------------------------------------------
router.get('/sessions', requireAuth, async (req, res, next) => {
  try {
    const sessions = await listSessions(req.db, req.user.id, req.user.sessionId);
    return res.json({ sessions });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// DELETE /api/auth/sessions/:id
// Revoke a specific active session
// -------------------------------------------------------------
router.delete('/sessions/:id', requireAuth, async (req, res, next) => {
  const targetSessionId = req.params.id;
  try {
    const sessionRes = await req.db.query('SELECT user_id FROM sessions WHERE id = ?', [targetSessionId]);
    if (sessionRes.length === 0) {
      return res.status(404).json({ error: { message: 'Session not found', code: 'NOT_FOUND' } });
    }

    const sessionOwnerId = sessionRes[0].user_id;
    if (sessionOwnerId !== req.user.id) {
      // Find workspaceId to check session.revoke_others
      let wsId = req.workspaceId;
      if (!wsId) {
        const wsRes = await req.db.query(
          'SELECT workspace_id FROM workspace_members WHERE user_id = ? LIMIT 1',
          [req.user.id]
        );
        wsId = wsRes[0]?.workspace_id;
      }

      const hasPerm = wsId ? await userHasPermission(req.user.id, wsId, 'session.revoke_others', req.db) : false;
      if (!hasPerm) {
        return res.status(403).json({
          error: { message: 'You do not have permission to revoke other users sessions', code: 'PERMISSION_DENIED' }
        });
      }
    }

    await revokeSession(req.db, sessionOwnerId, targetSessionId, req);
    return res.json({ message: 'Session revoked successfully', session_id: targetSessionId });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// POST /api/auth/sessions/revoke-others
// Revoke all other sessions except current
// -------------------------------------------------------------
router.post('/sessions/revoke-others', requireAuth, async (req, res, next) => {
  try {
    await revokeAllExceptCurrent(req.db, req.user.id, req.user.sessionId, req);
    return res.json({ message: 'All other sessions have been revoked' });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// POST /api/auth/logout
// Revoke current session & clear cookies
// -------------------------------------------------------------
router.post('/logout', requireAuth, async (req, res, next) => {
  try {
    if (req.user?.sessionId) {
      await revokeSession(req.db, req.user.id, req.user.sessionId, req);
    }
    const { maxAge, ...clearOptions } = COOKIE_OPTIONS;
    res.clearCookie('token', clearOptions);
    res.clearCookie('refreshToken', clearOptions);
    return res.json({ message: 'Logged out successfully' });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// POST /api/auth/logout-all
// Log out everywhere (revoke all sessions)
// -------------------------------------------------------------
router.post('/logout-all', requireAuth, async (req, res, next) => {
  try {
    await revokeAllSessions(req.db, req.user.id, 'LOGOUT_ALL', req);
    const { maxAge, ...clearOptions } = COOKIE_OPTIONS;
    res.clearCookie('token', clearOptions);
    res.clearCookie('refreshToken', clearOptions);
    return res.json({ message: 'Logged out from all devices successfully' });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// TOTP 2FA Endpoints
// -------------------------------------------------------------

// POST /api/auth/2fa/generate & /api/auth/2fa/setup - Generate secret and QR code for setup
const handle2FaGenerate = async (req, res, next) => {
  try {
    const tenantName = req.tenant?.name || 'ProjectMgmt';
    const setupData = await generateTotpSetup(req.user, tenantName);

    return res.json({
      secret: setupData.secret,
      otpauth_url: setupData.otpauth_url,
      qr_code: setupData.qr_code
    });
  } catch (err) {
    next(err);
  }
};

router.post('/2fa/generate', requireAuth, handle2FaGenerate);
router.post('/2fa/setup', requireAuth, handle2FaGenerate);

// POST /api/auth/2fa/confirm - Verify code, enable TOTP, issue 10 recovery codes
router.post('/2fa/confirm', requireAuth, validate(confirm2FaSchema), async (req, res, next) => {
  const { secret, token } = req.body;

  try {
    const isValid = verifyTotpCode(token, secret);
    if (!isValid) {
      return res.status(400).json({
        error: { message: 'Invalid 6-digit verification code. Please check your authenticator app and try again.', code: 'INVALID_2FA_CODE' }
      });
    }

    // Save AES-256-GCM encrypted TOTP secret and enable 2FA on user (Item 5)
    const encryptedSecret = encryptSecret(secret);
    await req.db.execute(
      'UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_enrolled_at = CURRENT_TIMESTAMP(3) WHERE id = ?',
      [encryptedSecret, req.user.id]
    );

    // Generate 10 single-use recovery codes
    const recoveryCodes = await generateRecoveryCodes(req.db, req.user.id);

    await logAuthEvent(req.db, {
      userId: req.user.id,
      email: req.user.email,
      eventType: '2FA_ENROLLED',
      req
    });

    return res.json({
      message: 'Two-factor authentication enabled successfully',
      totp_enabled: true,
      recovery_codes: recoveryCodes
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/2fa/disable - Disable 2FA with password confirmation
router.post('/2fa/disable', requireAuth, validate(disable2FaSchema), async (req, res, next) => {
  const { password, token } = req.body;

  try {
    const [user] = await req.db.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!user) {
      return res.status(404).json({ error: { message: 'User not found', code: 'NOT_FOUND' } });
    }

    // Verify password
    const isPasswordMatch = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordMatch) {
      return res.status(400).json({
        error: { message: 'Incorrect password', code: 'INVALID_CREDENTIALS' }
      });
    }

    // If token provided, verify TOTP with decrypted secret
    if (token && user.totp_secret) {
      const plainSecret = decryptSecret(user.totp_secret);
      const isTokenValid = verifyTotpCode(token, plainSecret);
      if (!isTokenValid) {
        return res.status(400).json({
          error: { message: 'Invalid authenticator code', code: 'INVALID_2FA_CODE' }
        });
      }
    }

    await disableTwoFactor(req.db, req.user.id);

    await logAuthEvent(req.db, {
      userId: req.user.id,
      email: req.user.email,
      eventType: '2FA_DISABLED',
      req
    });

    return res.json({
      message: 'Two-factor authentication disabled successfully',
      totp_enabled: false
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/auth/2fa/status - Get 2FA enrollment status
router.get('/2fa/status', requireAuth, async (req, res, next) => {
  try {
    const [user] = await req.db.query(
      'SELECT totp_enabled, totp_enrolled_at FROM users WHERE id = ?',
      [req.user.id]
    );

    return res.json({
      totp_enabled: !!user?.totp_enabled,
      totp_enrolled_at: user?.totp_enrolled_at || null
    });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// GET /api/auth/activity
// Current user's recent security and auth events (paginated)
// -------------------------------------------------------------
router.get('/activity', requireAuth, async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const offset = (page - 1) * limit;

    let rows = [];
    let total = 0;

    if (req.db) {
      const countRes = await req.db.query(
        'SELECT COUNT(*) as total FROM auth_audit_log WHERE user_id = ? OR email = ?',
        [req.user.id, req.user.email]
      );
      total = Number(countRes[0]?.total || 0);

      rows = await req.db.query(
        `SELECT id, event_type, ip_address, user_agent, metadata, created_at
         FROM auth_audit_log
         WHERE user_id = ? OR email = ?
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?`,
        [req.user.id, req.user.email, limit, offset]
      );
    }

    const events = rows.map((r) => {
      let meta = null;
      try {
        if (r.metadata) meta = typeof r.metadata === 'string' ? JSON.parse(r.metadata) : r.metadata;
      } catch (e) {
        meta = null;
      }
      return {
        id: r.id,
        action: r.event_type ? r.event_type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : 'Security Event',
        event_type: r.event_type,
        ip: r.ip_address || '127.0.0.1',
        user_agent: r.user_agent || null,
        metadata: meta,
        created_at: r.created_at ? new Date(r.created_at).toISOString() : new Date().toISOString()
      };
    });

    return res.json({
      events,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit) || 1
      }
    });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// GET /api/auth/me
// -------------------------------------------------------------
router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const userRes = await req.db.query(
      'SELECT id, name, email, avatar_url, timezone, locale, must_change_password, totp_enabled, created_at FROM users WHERE id = ?',
      [req.user.id]
    );
    if (userRes.length === 0) {
      return res.status(404).json({ error: { message: 'User not found', code: 'NOT_FOUND' } });
    }
    const user = userRes[0];
    return res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar_url: user.avatar_url || null,
        timezone: user.timezone || 'UTC',
        locale: user.locale || 'en',
        must_change_password: !!user.must_change_password,
        totp_enabled: !!user.totp_enabled,
        created_at: user.created_at
      },
      tenant: req.tenant || null
    });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// PUT /api/auth/profile
// Update user profile (name, email, timezone, locale, avatar_url)
// -------------------------------------------------------------
router.put('/profile', requireAuth, validate(updateProfileSchema), async (req, res, next) => {
  const { name, email, timezone, locale, avatar_url } = req.body;
  const updates = [];
  const values = [];

  try {
    if (name !== undefined) {
      if (!name.trim()) {
        return res.status(400).json({ error: { message: 'Name cannot be empty', code: 'INVALID_INPUT' } });
      }
      updates.push('name = ?');
      values.push(name.trim());
    }

    if (email !== undefined) {
      const normalizedEmail = normalizeEmail(email);
      const existing = await req.db.query('SELECT id FROM users WHERE email = ? AND id != ?', [normalizedEmail, req.user.id]);
      if (existing.length > 0) {
        return res.status(400).json({ error: { message: 'Email is already in use by another account', code: 'EMAIL_IN_USE' } });
      }
      updates.push('email = ?');
      values.push(normalizedEmail);
    }

    if (timezone !== undefined) {
      updates.push('timezone = ?');
      values.push(timezone.trim() || 'UTC');
    }

    if (locale !== undefined) {
      updates.push('locale = ?');
      values.push(locale.trim() || 'en');
    }

    if (avatar_url !== undefined) {
      updates.push('avatar_url = ?');
      values.push(avatar_url);
    }

    if (updates.length > 0) {
      values.push(req.user.id);
      await req.db.execute(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, values);
    }

    const [updatedUser] = await req.db.query(
      'SELECT id, name, email, avatar_url, timezone, locale, must_change_password, totp_enabled, created_at FROM users WHERE id = ?',
      [req.user.id]
    );

    return res.json({
      message: 'Profile updated successfully',
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        avatar_url: updatedUser.avatar_url || null,
        timezone: updatedUser.timezone || 'UTC',
        locale: updatedUser.locale || 'en',
        must_change_password: !!updatedUser.must_change_password,
        totp_enabled: !!updatedUser.totp_enabled,
        created_at: updatedUser.created_at
      }
    });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// PUT/POST /api/auth/password & /api/auth/change-password
// Change password (enforcing password policy, cost 12, revoking all sessions)
// -------------------------------------------------------------
const handlePasswordChange = async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;

  // Validate password policy
  const passwordCheck = validatePassword(newPassword);
  if (!passwordCheck.isValid) {
    return res.status(400).json({
      error: { message: passwordCheck.error, code: 'PASSWORD_TOO_WEAK' }
    });
  }

  try {
    const userRes = await req.db.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (userRes.length === 0) {
      return res.status(404).json({ error: { message: 'User not found', code: 'NOT_FOUND' } });
    }

    const user = userRes[0];
    if (user.must_change_password) {
      if (currentPassword) {
        const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isMatch) {
          return res.status(400).json({ error: { message: 'Current temporary password is incorrect', code: 'INVALID_CREDENTIALS' } });
        }
      }
    } else {
      if (!currentPassword) {
        return res.status(400).json({ error: { message: 'Current password is required', code: 'INVALID_INPUT' } });
      }
      const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
      if (!isMatch) {
        return res.status(400).json({ error: { message: 'Current password is incorrect', code: 'INVALID_CREDENTIALS' } });
      }
    }

    const newHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    await req.db.execute(
      'UPDATE users SET password_hash = ?, must_change_password = 0, failed_login_attempts = 0, locked_until = NULL WHERE id = ?',
      [newHash, req.user.id]
    );

    // Revoke all sessions for this user (they must log in with new password or use new session)
    await revokeAllSessions(req.db, req.user.id, 'PASSWORD_CHANGE', req);

    await logAuthEvent(req.db, {
      userId: req.user.id,
      email: req.user.email,
      eventType: 'PASSWORD_CHANGE',
      req
    });

    return res.json({
      message: 'Password changed successfully. All active sessions have been revoked for your security.',
      must_change_password: false
    });
  } catch (err) {
    next(err);
  }
};

router.put('/password', requireAuth, handlePasswordChange);
router.post('/password', requireAuth, handlePasswordChange);
router.post('/change-password', requireAuth, handlePasswordChange);

router.resetRegistrationLimitsForTest = resetRegistrationLimitsForTest;
router.RESERVED_SLUGS = RESERVED_SLUGS;

module.exports = router;

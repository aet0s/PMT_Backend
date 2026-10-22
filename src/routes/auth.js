// server/src/routes/auth.js
// Multi-tenant authentication with rotating sessions, TOTP 2FA, lockout protection, and audit logging.
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const { requireAuth, getJwtSecret, extractToken } = require('../middleware/auth');
const { blacklistToken } = require('../utils/tokenBlacklist');
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
  revokeAllExceptCurrent,
  checkUserRequires2Fa
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
  verification_token: z.string().optional(),
  invite_token: z.string().optional(),
  token: z.string().optional(),
  company_name: z.string().optional(),
  companyName: z.string().optional(),
  slug: z.string().optional(),
  phone: z.string().optional()
});

const sendOtpSchema = z.object({
  email: z.string().email('Invalid email address')
});

const verifyOtpSchema = z.object({
  email: z.string().email('Invalid email address'),
  otp: z.union([z.string(), z.number()]).transform((v) => String(v).trim().replace(/\D/g, '')).refine((v) => v.length === 6, {
    message: 'OTP must be 6 digits'
  })
});

const resetPasswordWithOtpSchema = z.object({
  email: z.string().email('Invalid email address'),
  reset_token: z.string().min(1, 'Reset token is required'),
  new_password: z.string().min(1, 'New password is required')
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
  token: z.string().min(6).optional(),
  code: z.string().min(6).optional()
}).refine(data => data.token || data.code, { message: 'TOTP token or code is required' });

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

// In-memory OTP stores with expiration & attempt limits
const registrationOtps = new Map();
const passwordResetOtps = new Map();

function generateOtp() {
  return Math.floor(100000 + crypto.randomInt(0, 900000)).toString();
}

function createVerificationToken(email, purpose) {
  return jwt.sign(
    { email: normalizeEmail(email), purpose, jti: crypto.randomUUID() },
    getJwtSecret(),
    { expiresIn: '15m' }
  );
}

function verifyTokenPayload(token, expectedPurpose, expectedEmail) {
  try {
    const payload = jwt.verify(token, getJwtSecret());
    if (payload.purpose !== expectedPurpose) return false;
    if (expectedEmail && normalizeEmail(payload.email) !== normalizeEmail(expectedEmail)) return false;
    return payload;
  } catch (err) {
    return false;
  }
}

const { getCookieOptions, getClearCookieOptions } = require('../utils/cookieOptions');

const COOKIE_OPTIONS = getCookieOptions(5 * 24 * 60 * 60 * 1000); // 5 days
const REFRESH_COOKIE_OPTIONS = getCookieOptions(5 * 24 * 60 * 60 * 1000); // 5 days

/**
 * Robustly checks if an email is registered anywhere in the system
 * (master directory, tenant owner emails, dev single db, and active tenant databases).
 */
async function isEmailAlreadyRegistered(email) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) return false;

  const masterDb = getMasterDb();

  // 1. Check master tenant_user_directory (fast indexed lookup)
  try {
    const inDir = await masterDb.query(
      'SELECT id FROM tenant_user_directory WHERE LOWER(email) = ? LIMIT 1',
      [normalizedEmail]
    );
    if (inDir && inDir.length > 0) return true;
  } catch (err) {
    console.warn('[EMAIL_CHECK] Error querying tenant_user_directory:', err.message);
  }

  // 2. Check master tenants table (owner_email)
  try {
    const inTenants = await masterDb.query(
      "SELECT id FROM tenants WHERE LOWER(owner_email) = ? AND status != 'deleted' LIMIT 1",
      [normalizedEmail]
    );
    if (inTenants && inTenants.length > 0) return true;
  } catch (err) {
    console.warn('[EMAIL_CHECK] Error querying tenants owner_email:', err.message);
  }

  // 3. Check single dev database users table
  try {
    const devDb = getDevSingleDb();
    const inDev = await devDb.query(
      'SELECT id FROM users WHERE LOWER(email) = ? LIMIT 1',
      [normalizedEmail]
    );
    if (inDev && inDev.length > 0) return true;
  } catch (err) {}

  // 4. Scan active tenant databases
  try {
    const activeTenants = await masterDb.query(
      "SELECT id FROM tenants WHERE status = 'active'"
    );
    for (const t of activeTenants) {
      try {
        const tDb = await getTenantDb(t.id);
        const inTenant = await tDb.query(
          'SELECT id FROM users WHERE LOWER(email) = ? LIMIT 1',
          [normalizedEmail]
        );
        if (inTenant && inTenant.length > 0) {
          // Self-heal: ensure global directory has this mapping
          await masterDb.execute(
            'INSERT IGNORE INTO tenant_user_directory (email, tenant_id) VALUES (?, ?)',
            [normalizedEmail, t.id]
          );
          return true;
        }
      } catch (tErr) {}
    }
  } catch (err) {}

  return false;
}

// -------------------------------------------------------------
// GET /api/auth/check-email?email=...
// Fast pre-check to verify if an email is already registered
// -------------------------------------------------------------
router.get('/check-email', async (req, res, next) => {
  const { email } = req.query;
  if (!email) {
    return res.status(400).json({ error: { message: 'Email query parameter is required', code: 'BAD_REQUEST' } });
  }
  try {
    const exists = await isEmailAlreadyRegistered(email);
    return res.json({ email: normalizeEmail(email), registered: exists });
  } catch (err) {
    next(err);
  }
});

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
    // 7. Global daily cap on new tenants (configurable, default 20, 10000 in test mode)
    const dailyCap = Number(process.env.REGISTRATION_DAILY_CAP || (process.env.NODE_ENV === 'test' ? 10000 : 20));
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

    // Check email uniqueness across master directory and all tenant databases
    const emailExists = await isEmailAlreadyRegistered(normalizedEmail);
    if (emailExists) {
      return res.status(409).json({
        error: { message: 'This email address is already registered to an existing member. Each member must have a unique email address.', code: 'EMAIL_CONFLICT' }
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
// POST /api/auth/register/send-otp
// Step 1: Validates email, sends 6-digit OTP via EmailProvider
// -------------------------------------------------------------
router.post('/register/send-otp', validate(sendOtpSchema), async (req, res, next) => {
  const { email } = req.body;
  const normalizedEmail = normalizeEmail(email);

  try {
    // Check if email already exists before generating or sending OTP
    const emailExists = await isEmailAlreadyRegistered(normalizedEmail);
    if (emailExists) {
      return res.status(409).json({
        error: { message: 'An account with this email address already exists. Please sign in.', code: 'EMAIL_IN_USE' }
      });
    }

    // Rate limiting: 30-second cooldown between requests
    const existingEntry = registrationOtps.get(normalizedEmail);
    if (existingEntry && existingEntry.sentAt && (Date.now() - existingEntry.sentAt < 30 * 1000)) {
      return res.status(429).json({
        error: { message: 'Please wait 30 seconds before requesting another code.', code: 'RATE_LIMITED' }
      });
    }

    const otp = generateOtp();
    const otpHash = await bcrypt.hash(otp, 10);
    const expiresAt = Date.now() + 10 * 60 * 1000;

    registrationOtps.set(normalizedEmail, {
      otpHash,
      attempts: 0,
      expiresAt,
      sentAt: Date.now(),
      verified: false
    });

    await EmailProvider.sendOtp(normalizedEmail, otp, { purpose: 'registration' });

    return res.json({
      message: 'A 6-digit verification code has been sent to your email address.',
      email: normalizedEmail,
      expiresInMinutes: 10,
      dev_otp: process.env.NODE_ENV !== 'production' ? otp : undefined
    });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// POST /api/auth/register/verify-otp
// Step 2: Validates OTP and issues a verification token for password setup
// -------------------------------------------------------------
router.post('/register/verify-otp', validate(verifyOtpSchema), async (req, res, next) => {
  const { email, otp } = req.body;
  const normalizedEmail = normalizeEmail(email);

  const entry = registrationOtps.get(normalizedEmail);
  if (!entry) {
    return res.status(400).json({
      error: { message: 'No active verification session found for this email. Please request a new code.', code: 'OTP_NOT_FOUND' }
    });
  }

  if (Date.now() > entry.expiresAt) {
    registrationOtps.delete(normalizedEmail);
    return res.status(400).json({
      error: { message: 'Verification code has expired. Please request a new code.', code: 'OTP_EXPIRED' }
    });
  }

  if (entry.attempts >= 5) {
    registrationOtps.delete(normalizedEmail);
    return res.status(429).json({
      error: { message: 'Too many invalid attempts. Please request a new verification code.', code: 'TOO_MANY_ATTEMPTS' }
    });
  }

  const isValid = await bcrypt.compare(otp, entry.otpHash);
  if (!isValid) {
    entry.attempts += 1;
    const remaining = 5 - entry.attempts;
    return res.status(400).json({
      error: { message: `Invalid verification code. ${remaining} attempt(s) remaining.`, code: 'INVALID_OTP' }
    });
  }

  const verificationToken = createVerificationToken(normalizedEmail, 'registration_verified');
  entry.verified = true;
  entry.verificationToken = verificationToken;

  return res.json({
    message: 'Email address verified successfully.',
    verified: true,
    verification_token: verificationToken
  });
});

// -------------------------------------------------------------
// POST /api/auth/register
// User registration (e.g. from invitation link or dev)
// -------------------------------------------------------------
router.post('/register', validate(registerUserSchema), async (req, res, next) => {
  const { name, email, password, verification_token: verificationToken, company_name, companyName, slug, phone } = req.body;
  const inviteToken = req.body.invite_token || req.body.token;

  // Validate Password Policy
  const passwordCheck = validatePassword(password);
  if (!passwordCheck.isValid) {
    return res.status(400).json({
      error: { message: passwordCheck.error, code: 'PASSWORD_TOO_WEAK' }
    });
  }

  const normalizedEmail = normalizeEmail(email);

  // Enforce email verification for self-registration when token is supplied or VERIFICATION_MODE is enabled
  // For invited members, clicking the email invitation link already proves email ownership, so OTP is bypassed.
  const verificationMode = (process.env.VERIFICATION_MODE || 'off').toLowerCase();
  const isEnforced = verificationMode === 'on' || verificationMode === 'otp';

  if (!inviteToken) {
    if (verificationToken) {
      const regEntry = registrationOtps.get(normalizedEmail);
      const tokenValid = verifyTokenPayload(verificationToken, 'registration_verified', normalizedEmail);
      const entryValid = regEntry && regEntry.verified && (Date.now() < regEntry.expiresAt + 15 * 60 * 1000);

      if (!tokenValid && !entryValid) {
        return res.status(400).json({
          error: { message: 'Invalid or expired verification session. Please verify your email again.', code: 'EMAIL_NOT_VERIFIED' }
        });
      }
    } else if (isEnforced) {
      const regEntry = registrationOtps.get(normalizedEmail);
      const entryValid = regEntry && regEntry.verified && (Date.now() < regEntry.expiresAt + 15 * 60 * 1000);

      if (!entryValid) {
        return res.status(400).json({
          error: { message: 'Please verify your email with the 6-digit verification code first.', code: 'EMAIL_NOT_VERIFIED' }
        });
      }
    }
  }

  try {
    // When multi-tenant mode is active (DEV_SINGLE_TENANT !== '1') and registration is not via invite:
    // Automatically provision a dedicated tenant database with pm_t_ prefix!
    if (!inviteToken && process.env.DEV_SINGLE_TENANT !== '1') {
      const registrationEnabled = process.env.REGISTRATION_ENABLED !== 'false' && process.env.REGISTRATION_ENABLED !== '0';
      if (!registrationEnabled) {
        return res.status(403).json({
          error: { message: 'Registration is currently disabled.', code: 'REGISTRATION_DISABLED' }
        });
      }

      const clientIp = req.ip || '127.0.0.1';
      if (!checkRegistrationIpLimit(clientIp)) {
        return res.status(429).json({
          error: {
            message: 'Too many registration requests from this IP address. Please try again later.',
            code: 'REGISTRATION_RATE_LIMIT_EXCEEDED'
          }
        });
      }

      const emailExists = await isEmailAlreadyRegistered(normalizedEmail);
      if (emailExists) {
        return res.status(409).json({
          error: { message: 'This email address is already registered to an existing member. Each member must have a unique email address.', code: 'EMAIL_CONFLICT' }
        });
      }

      const masterDb = getMasterDb();

      const orgName = (company_name || companyName || `${name.trim()}'s Team`).trim();
      let baseSlug = slugify(slug || orgName);
      let candidateSlug = baseSlug;
      let attempts = 0;
      while (attempts < 5) {
        const existingSlug = await masterDb.query(
          'SELECT id FROM tenants WHERE slug = ?',
          [candidateSlug]
        );
        if (existingSlug.length === 0 && !RESERVED_SLUGS.has(candidateSlug)) break;
        candidateSlug = `${baseSlug}_${crypto.randomBytes(2).toString('hex')}`;
        attempts++;
      }

      const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

      activeTenantProvisionings++;
      let provisionResult;
      try {
        provisionResult = await provisionTenant({
          companyName: orgName,
          slug: candidateSlug,
          ownerEmail: normalizedEmail,
          ownerPasswordHash: passwordHash,
          ownerName: name.trim(),
          phone: phone || null
        });
      } finally {
        activeTenantProvisionings--;
      }

      const { tenant, owner, workspace, board } = provisionResult;
      const tenantDb = await getTenantDb(tenant.id);
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
        message: 'Registration successful',
        tenant,
        user: {
          id: owner.id,
          name: owner.name,
          email: owner.email,
          created_at: owner.created_at
        },
        initial_workspace_id: workspace.id,
        initial_board_id: board ? board.id : null,
        token: session.accessToken,
        refreshToken: session.refreshToken,
        expiresIn: session.expiresIn
      });
    }

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
    const existing = await activeDb.query('SELECT id FROM users WHERE email = ?', [normalizedEmail]);
    if (existing.length > 0) {
      return res.status(400).json({
        error: { message: 'This email address is already registered to an existing member. Each member must have a unique email address.', code: 'EMAIL_IN_USE' }
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
        `SELECT pi.id, pi.workspace_id, pi.role_id, pi.status, pi.expires_at, GROUP_CONCAT(ib.board_id) as board_ids_str
         FROM pending_invitations pi
         LEFT JOIN invitation_boards ib ON pi.id = ib.invitation_id
         WHERE pi.token = ?
         GROUP BY pi.id, pi.workspace_id, pi.role_id, pi.status, pi.expires_at`,
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
        `SELECT pi.id, pi.workspace_id, pi.role_id, pi.status, pi.expires_at, GROUP_CONCAT(ib.board_id) as board_ids_str
         FROM pending_invitations pi
         LEFT JOIN invitation_boards ib ON pi.id = ib.invitation_id
         WHERE pi.email = ? AND pi.status = 'pending'
           AND (pi.expires_at IS NULL OR pi.expires_at > CURRENT_TIMESTAMP(3))
         GROUP BY pi.id, pi.workspace_id, pi.role_id, pi.status, pi.expires_at
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
      let assignedRoleId = invite.role_id;
      let assignedRoleName = 'Team Member';
      if (assignedRoleId) {
        const roleCheck = await activeDb.query(
          'SELECT id, name FROM roles WHERE id = ? AND (workspace_id = ? OR workspace_id IS NULL)',
          [assignedRoleId, invite.workspace_id]
        );
        if (roleCheck.length > 0) {
          assignedRoleName = roleCheck[0].name;
        } else {
          assignedRoleId = null;
        }
      }
      if (!assignedRoleId) {
        const teamMemberRoleRes = await activeDb.query(
          "SELECT id, name FROM roles WHERE is_system = 1 AND name = 'Team Member' AND workspace_id IS NULL"
        );
        assignedRoleId = teamMemberRoleRes[0]?.id;
        assignedRoleName = teamMemberRoleRes[0]?.name || 'Team Member';
      }

      await activeDb.execute(
        `INSERT INTO workspace_members (workspace_id, user_id, role, role_id)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE role_id = VALUES(role_id), role = VALUES(role)`,
        [invite.workspace_id, user.id, assignedRoleName, assignedRoleId]
      );

      if (invite.board_ids && invite.board_ids.length > 0) {
        for (const boardId of invite.board_ids) {
          await activeDb.execute(
            `INSERT INTO board_members (board_id, user_id, role, role_id)
             VALUES (?, ?, 'member', ?)
             ON DUPLICATE KEY UPDATE role = 'member', role_id = COALESCE(VALUES(role_id), role_id)`,
            [boardId, user.id, assignedRoleId]
          );
        }
        createdBoardId = invite.board_ids[0];
      } else {
        createdBoardId = null;
      }

      await activeDb.execute(
        `UPDATE pending_invitations
         SET status = 'accepted', accepted_at = CURRENT_TIMESTAMP(3), accepted_by_user_id = ?
         WHERE id = ?`,
        [user.id, invite.id]
      );

      createdWorkspaceId = invite.workspace_id;
    } else {
      const rawCompany = (company_name || companyName || name || 'Company').trim();
      const cleanCompany = rawCompany.replace(/\s+Workspace$/i, '');
      const workspaceName = cleanCompany.endsWith("'s") ? `${cleanCompany} Workspace` : `${cleanCompany}'s Workspace`;

      const wsRes = await activeDb.execute(
        'INSERT INTO workspaces (name) VALUES (?)',
        [workspaceName]
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
        `INSERT INTO lists (board_id, name, position, wip_limit_enabled) VALUES 
         (?, 'To Do', 1000.0, 1),
         (?, 'In Progress', 2000.0, 1),
         (?, 'Review', 3000.0, 1),
         (?, 'Done', 4000.0, 0)`,
        [createdBoardId, createdBoardId, createdBoardId, createdBoardId]
      );

      await activeDb.execute(
        `INSERT INTO labels (board_id, name, color) VALUES 
         (?, 'Feature', '#3b82f6'),
         (?, 'Bug', '#ef4444'),
         (?, 'Design', '#ec4899'),
         (?, 'Backend', '#10b981'),
         (?, 'Frontend', '#8b5cf6'),
         (?, 'Urgent', '#f59e0b')`,
        [createdBoardId, createdBoardId, createdBoardId, createdBoardId, createdBoardId, createdBoardId]
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

  // Check if user is deactivated across all workspaces in tenant
  const memberRows = await db.query('SELECT status FROM workspace_members WHERE user_id = ?', [user.id]);
  if (memberRows && memberRows.length > 0 && memberRows.every(r => r.status === 'deactivated')) {
    const error = new Error('Your account has been deactivated. Please contact your workspace administrator.');
    error.status = 403;
    error.code = 'ACCOUNT_DEACTIVATED';
    throw error;
  }

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
  const requires2fa = await checkUserRequires2Fa(db, user.id, user.totp_enabled);
  const session = await createSession(db, user, req, { tenantId: tenant?.id || null, two_fa_required: requires2fa });

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
router.post('/login', validate(loginSchema), async (req, res, next) => {
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
      if (process.env.DEV_SINGLE_TENANT === '1') {
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
      }

      await bcrypt.compare(password, DUMMY_HASH);
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
// Database-persisted Password Reset Helpers
// -------------------------------------------------------------
async function getPasswordResetDb() {
  if (process.env.DEV_SINGLE_TENANT === '1') {
    return getDevSingleDb();
  }
  return getMasterDb();
}

async function ensurePasswordResetsTable() {
  try {
    const db = await getPasswordResetDb();
    await db.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        otp_code VARCHAR(20) NOT NULL,
        otp_hash VARCHAR(255) NOT NULL,
        reset_token VARCHAR(500) NULL,
        attempts INT NOT NULL DEFAULT 0,
        verified TINYINT(1) NOT NULL DEFAULT 0,
        expires_at DATETIME(3) NOT NULL,
        created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        INDEX idx_pr_email (email),
        INDEX idx_pr_expires (expires_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
  } catch (err) {
    console.warn('[PASSWORD_RESETS_INIT] Notice ensuring table:', err.message);
  }
}

// -------------------------------------------------------------
// POST /api/auth/forgot-password/send-otp
// Step 1: Initiates password reset by sending 6-digit OTP to user email
// -------------------------------------------------------------
router.post('/forgot-password/send-otp', validate(sendOtpSchema), async (req, res, next) => {
  const { email } = req.body;
  const normalizedEmail = normalizeEmail(email);

  try {
    let userFound = false;

    // Check directory and databases for user existence
    try {
      const masterDb = getMasterDb();
      const existing = await masterDb.query(
        'SELECT id FROM tenant_user_directory WHERE LOWER(email) = ? LIMIT 1',
        [normalizedEmail]
      );
      if (existing && existing.length > 0) userFound = true;
    } catch {}

    if (!userFound) {
      try {
        const devDb = getDevSingleDb();
        const existing = await devDb.query('SELECT id, name FROM users WHERE LOWER(email) = ? LIMIT 1', [normalizedEmail]);
        if (existing && existing.length > 0) userFound = true;
      } catch {}
    }

    // Fallback: If not found in directory or devDb, search active tenant databases and auto-heal directory
    if (!userFound) {
      try {
        const masterDb = getMasterDb();
        const activeTenants = await masterDb.query("SELECT id, db_name FROM tenants WHERE status = 'active'");
        for (const t of activeTenants) {
          try {
            const tenantDb = await getTenantDb(t.id);
            const users = await tenantDb.query('SELECT id, name FROM users WHERE LOWER(email) = ? LIMIT 1', [normalizedEmail]);
            if (users && users.length > 0) {
              userFound = true;
              // Auto-heal directory so future lookups succeed instantly
              await masterDb.execute('INSERT IGNORE INTO tenant_user_directory (email, tenant_id) VALUES (?, ?)', [normalizedEmail, t.id]);
              break;
            }
          } catch {}
        }
      } catch (dirErr) {
        console.warn('[FORGOT_PASSWORD_DIRECTORY_FALLBACK_WARN]', dirErr.message);
      }
    }

    // Rate limit check: 30-second cooldown between requests
    const existingEntry = passwordResetOtps.get(normalizedEmail);
    if (existingEntry && existingEntry.sentAt && (Date.now() - existingEntry.sentAt < 30 * 1000)) {
      return res.status(429).json({
        error: { message: 'Please wait 30 seconds before requesting another code.', code: 'RATE_LIMITED' }
      });
    }

    if (userFound) {
      const otp = generateOtp();
      const otpHash = await bcrypt.hash(otp, 10);
      const expiresAtMs = Date.now() + 10 * 60 * 1000;
      const expiresAtDate = new Date(expiresAtMs);

      passwordResetOtps.set(normalizedEmail, {
        otp,
        otpHash,
        attempts: 0,
        expiresAt: expiresAtMs,
        sentAt: Date.now(),
        verified: false
      });

      // Persist in MySQL so server reboots do not discard active OTP
      try {
        const prDb = await getPasswordResetDb();
        await ensurePasswordResetsTable();
        await prDb.execute('DELETE FROM password_resets WHERE email = ?', [normalizedEmail]);
        await prDb.execute(
          'INSERT INTO password_resets (email, otp_code, otp_hash, expires_at) VALUES (?, ?, ?, ?)',
          [normalizedEmail, otp, otpHash, expiresAtDate]
        );
      } catch (dbErr) {
        console.warn('[PASSWORD_RESET_DB_SAVE_WARN]', dbErr.message);
      }

      await EmailProvider.sendOtp(normalizedEmail, otp, { purpose: 'password_reset' });

      return res.json({
        message: 'A 6-digit reset code has been sent to your email address.',
        email: normalizedEmail,
        expiresInMinutes: 10,
        dev_otp: process.env.NODE_ENV !== 'production' ? otp : undefined
      });
    } else {
      // Security: Do not reveal whether user email exists in database
      return res.json({
        message: 'If an account exists with this email address, a 6-digit reset code has been sent.',
        email: normalizedEmail,
        expiresInMinutes: 10
      });
    }
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// POST /api/auth/forgot-password/verify-otp
// Step 2: Validates reset OTP and issues temporary password reset token
// -------------------------------------------------------------
router.post('/forgot-password/verify-otp', validate(verifyOtpSchema), async (req, res, next) => {
  const { email, otp } = req.body;
  const normalizedEmail = normalizeEmail(email);
  const cleanOtp = String(otp || '').trim().replace(/\D/g, '');

  let entry = passwordResetOtps.get(normalizedEmail);
  let dbRow = null;

  try {
    const prDb = await getPasswordResetDb();
    await ensurePasswordResetsTable();
    const rows = await prDb.query(
      'SELECT id, otp_code, otp_hash, attempts, verified, expires_at FROM password_resets WHERE email = ? ORDER BY id DESC LIMIT 1',
      [normalizedEmail]
    );
    if (rows && rows.length > 0) {
      dbRow = rows[0];
    }
  } catch (dbErr) {
    console.warn('[PASSWORD_RESET_DB_LOAD_WARN]', dbErr.message);
  }

  // Restore memory entry from database if server restarted
  if (!entry && dbRow) {
    entry = {
      otp: dbRow.otp_code,
      otpHash: dbRow.otp_hash,
      attempts: dbRow.attempts,
      expiresAt: new Date(dbRow.expires_at).getTime(),
      verified: !!dbRow.verified
    };
    passwordResetOtps.set(normalizedEmail, entry);
  }

  if (!entry && !dbRow) {
    return res.status(400).json({
      error: { message: 'No reset request found for this email or the code has expired. Please request a new code.', code: 'OTP_NOT_FOUND' }
    });
  }

  const effectiveExpiresAt = entry?.expiresAt || (dbRow ? new Date(dbRow.expires_at).getTime() : 0);
  if (Date.now() > effectiveExpiresAt) {
    passwordResetOtps.delete(normalizedEmail);
    try {
      const prDb = await getPasswordResetDb();
      await prDb.execute('DELETE FROM password_resets WHERE email = ?', [normalizedEmail]);
    } catch {}
    return res.status(400).json({
      error: { message: 'Reset code has expired. Please request a new code.', code: 'OTP_EXPIRED' }
    });
  }

  const currentAttempts = Math.max(entry?.attempts || 0, dbRow?.attempts || 0);
  if (currentAttempts >= 5) {
    passwordResetOtps.delete(normalizedEmail);
    try {
      const prDb = await getPasswordResetDb();
      await prDb.execute('DELETE FROM password_resets WHERE email = ?', [normalizedEmail]);
    } catch {}
    return res.status(429).json({
      error: { message: 'Too many invalid attempts. Please request a new reset code.', code: 'TOO_MANY_ATTEMPTS' }
    });
  }

  const expectedCode = entry?.otp || dbRow?.otp_code;
  const expectedHash = entry?.otpHash || dbRow?.otp_hash;
  const isDirectMatch = expectedCode && cleanOtp === expectedCode;
  const isBcryptMatch = expectedHash ? await bcrypt.compare(cleanOtp, expectedHash) : false;
  const isValid = isDirectMatch || isBcryptMatch;

  if (!isValid) {
    const newAttempts = currentAttempts + 1;
    if (entry) entry.attempts = newAttempts;
    try {
      const prDb = await getPasswordResetDb();
      await prDb.execute('UPDATE password_resets SET attempts = attempts + 1 WHERE email = ?', [normalizedEmail]);
    } catch {}
    const remaining = Math.max(0, 5 - newAttempts);
    return res.status(400).json({
      error: { message: `Invalid reset code. ${remaining} attempt(s) remaining.`, code: 'INVALID_OTP' }
    });
  }

  const resetToken = createVerificationToken(normalizedEmail, 'password_reset_verified');
  if (entry) {
    entry.verified = true;
    entry.resetToken = resetToken;
  }

  try {
    const prDb = await getPasswordResetDb();
    await prDb.execute(
      'UPDATE password_resets SET verified = 1, reset_token = ? WHERE email = ?',
      [resetToken, normalizedEmail]
    );
  } catch {}

  return res.json({
    message: 'Reset code verified successfully.',
    verified: true,
    reset_token: resetToken
  });
});

// -------------------------------------------------------------
// POST /api/auth/forgot-password/verify-token
// Validates whether a reset token is valid and unexpired
// -------------------------------------------------------------
router.post('/forgot-password/verify-token', async (req, res) => {
  const { token, email } = req.body;
  if (!token) {
    return res.status(400).json({
      error: { message: 'Reset token is required.', code: 'MISSING_RESET_TOKEN' }
    });
  }
  const payload = verifyTokenPayload(token, 'password_reset_verified', email);
  let dbValid = false;
  if (email) {
    try {
      const prDb = await getPasswordResetDb();
      const rows = await prDb.query(
        'SELECT id FROM password_resets WHERE email = ? AND reset_token = ? AND verified = 1 AND expires_at > CURRENT_TIMESTAMP(3)',
        [normalizeEmail(email), token]
      );
      if (rows && rows.length > 0) dbValid = true;
    } catch {}
  }
  if (!payload && !dbValid) {
    return res.status(400).json({
      error: { message: 'Password reset token is invalid or has expired. Please request a new link.', code: 'INVALID_RESET_TOKEN' }
    });
  }
  return res.json({
    valid: true,
    email: payload?.email || email,
    message: 'Reset token is valid.'
  });
});

// -------------------------------------------------------------
// POST /api/auth/forgot-password/reset
// Step 3: Resets password using verified token and enforces strong password policy
// -------------------------------------------------------------
router.post('/forgot-password/reset', validate(resetPasswordWithOtpSchema), async (req, res, next) => {
  const { email, reset_token, new_password } = req.body;
  const normalizedEmail = normalizeEmail(email);

  // Validate reset token
  const tokenValid = verifyTokenPayload(reset_token, 'password_reset_verified', normalizedEmail);
  const entry = passwordResetOtps.get(normalizedEmail);
  const entryValid = entry && entry.verified && (Date.now() < entry.expiresAt + 15 * 60 * 1000);
  let dbValid = false;
  try {
    const prDb = await getPasswordResetDb();
    const rows = await prDb.query(
      'SELECT id FROM password_resets WHERE email = ? AND reset_token = ? AND verified = 1',
      [normalizedEmail, reset_token]
    );
    if (rows && rows.length > 0) dbValid = true;
  } catch {}

  if (!tokenValid && !entryValid && !dbValid) {
    return res.status(400).json({
      error: { message: 'Invalid or expired password reset session. Please request a new code.', code: 'INVALID_RESET_TOKEN' }
    });
  }

  // Validate Password Policy
  const passwordCheck = validatePassword(new_password);
  if (!passwordCheck.isValid) {
    return res.status(400).json({
      error: { message: passwordCheck.error, code: 'PASSWORD_TOO_WEAK' }
    });
  }

  try {
    const passwordHash = await bcrypt.hash(new_password, BCRYPT_ROUNDS);

    if (process.env.DEV_SINGLE_TENANT === '1') {
      const devDb = getDevSingleDb();
      const userRes = await devDb.query('SELECT * FROM users WHERE email = ?', [normalizedEmail]);
      if (userRes.length === 0) {
        return res.status(404).json({ error: { message: 'User account not found', code: 'USER_NOT_FOUND' } });
      }
      const user = userRes[0];
      await devDb.execute(
        'UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL, lockout_count = 0 WHERE id = ?',
        [passwordHash, user.id]
      );
      await revokeAllSessions(devDb, user.id, 'PASSWORD_RESET', req);
      await logAuthEvent(devDb, {
        userId: user.id,
        email: user.email,
        eventType: 'PASSWORD_RESET',
        req
      });
    } else {
      const masterDb = getMasterDb();
      const usersInDir = await masterDb.query(
        'SELECT id, tenant_id FROM tenant_user_directory WHERE LOWER(email) = ?',
        [normalizedEmail]
      );
      if (usersInDir.length === 0) {
        // Fallback: check active tenants directly
        const activeTenants = await masterDb.query("SELECT id, db_name FROM tenants WHERE status = 'active'");
        for (const t of activeTenants) {
          try {
            const tenantDb = await getTenantDb(t.id);
            const [u] = await tenantDb.query('SELECT id FROM users WHERE LOWER(email) = ? LIMIT 1', [normalizedEmail]);
            if (u) {
              usersInDir.push({ id: null, tenant_id: t.id });
              await masterDb.execute('INSERT IGNORE INTO tenant_user_directory (email, tenant_id) VALUES (?, ?)', [normalizedEmail, t.id]);
            }
          } catch {}
        }
      }
      if (usersInDir.length === 0) {
        return res.status(404).json({ error: { message: 'User account not found', code: 'USER_NOT_FOUND' } });
      }
      for (const row of usersInDir) {
        if (row.tenant_id) {
          try {
            const tenantDb = await getTenantDb(row.tenant_id);
            const [u] = await tenantDb.query('SELECT id FROM users WHERE email = ?', [normalizedEmail]);
            if (u) {
              await tenantDb.execute(
                'UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL, lockout_count = 0 WHERE id = ?',
                [passwordHash, u.id]
              );
              await revokeAllSessions(tenantDb, u.id, 'PASSWORD_RESET', req);
            }
          } catch (tErr) {
            console.error('Failed updating tenant password during reset:', tErr.message);
          }
        }
      }
    }

    passwordResetOtps.delete(normalizedEmail);
    try {
      const prDb = await getPasswordResetDb();
      await prDb.execute('DELETE FROM password_resets WHERE email = ?', [normalizedEmail]);
    } catch {}

    return res.json({
      message: 'Password reset successfully. You can now log in with your new password.'
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

    const cookieMaxAge = (rotationResult.expiresIn && rotationResult.expiresIn > 0)
      ? rotationResult.expiresIn * 1000
      : (5 * 24 * 60 * 60 * 1000);

    res.cookie('token', rotationResult.accessToken, { ...COOKIE_OPTIONS, maxAge: cookieMaxAge });
    res.cookie('refreshToken', rotationResult.refreshToken, { ...REFRESH_COOKIE_OPTIONS, maxAge: cookieMaxAge });

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
    let wsId = req.workspaceId;
    if (!wsId) {
      const wsRes = await req.db.query(
        'SELECT workspace_id FROM workspace_members WHERE user_id = ? LIMIT 1',
        [req.user.id]
      );
      wsId = wsRes[0]?.workspace_id;
    }
    if (wsId) {
      const hasPerm = await userHasPermission(req.user.id, wsId, 'session.view_own', req.db);
      if (!hasPerm) {
        return res.status(403).json({
          error: { message: 'You do not have permission to view sessions', code: 'PERMISSION_DENIED' }
        });
      }
    }
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
    if (sessionOwnerId === req.user.id) {
      let wsId = req.workspaceId;
      if (!wsId) {
        const wsRes = await req.db.query(
          'SELECT workspace_id FROM workspace_members WHERE user_id = ? LIMIT 1',
          [req.user.id]
        );
        wsId = wsRes[0]?.workspace_id;
      }
      if (wsId) {
        const hasPerm = await userHasPermission(req.user.id, wsId, 'session.revoke_own', req.db);
        if (!hasPerm) {
          return res.status(403).json({
            error: { message: 'You do not have permission to revoke sessions', code: 'PERMISSION_DENIED' }
          });
        }
      }
    } else {
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

      // Rank check: a user cannot revoke the sessions of someone of equal or higher rank
      const callerRoleRows = await req.db.query(
        `SELECT MAX(COALESCE(r.rank, 30)) as max_rank, MAX(r.is_system) as max_sys 
         FROM workspace_members wm 
         JOIN roles r ON wm.role_id = r.id 
         WHERE wm.user_id = ?`,
        [req.user.id]
      );
      const targetRoleRows = await req.db.query(
        `SELECT MAX(COALESCE(r.rank, 30)) as max_rank, MAX(r.is_system) as max_sys 
         FROM workspace_members wm 
         JOIN roles r ON wm.role_id = r.id 
         WHERE wm.user_id = ?`,
        [sessionOwnerId]
      );
      const callerRank = Number(callerRoleRows[0]?.max_rank || 30);
      const targetRank = Number(targetRoleRows[0]?.max_rank || 30);

      if (callerRank <= targetRank) {
        return res.status(403).json({
          error: {
            message: 'You cannot revoke the session of a user with equal or higher rank',
            code: 'INSUFFICIENT_ROLE_RANK'
          }
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
    let wsId = req.workspaceId;
    if (!wsId) {
      const wsRes = await req.db.query(
        'SELECT workspace_id FROM workspace_members WHERE user_id = ? LIMIT 1',
        [req.user.id]
      );
      wsId = wsRes[0]?.workspace_id;
    }
    if (wsId) {
      const hasPerm = await userHasPermission(req.user.id, wsId, 'session.revoke_own', req.db);
      if (!hasPerm) {
        return res.status(403).json({
          error: { message: 'You do not have permission to revoke sessions', code: 'PERMISSION_DENIED' }
        });
      }
    }
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
    const token = extractToken(req);
    if (token) {
      blacklistToken(token);
    }
    if (req.user?.sessionId) {
      await revokeSession(req.db, req.user.id, req.user.sessionId, req);
    } else if (req.user?.id) {
      await revokeAllSessions(req.db, req.user.id, 'LOGOUT', req);
    }
    const clearOptions = getClearCookieOptions();
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
    const token = extractToken(req);
    if (token) {
      blacklistToken(token);
    }
    await revokeAllSessions(req.db, req.user.id, 'LOGOUT_ALL', req);
    const clearOptions = getClearCookieOptions();
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

const handle2FaConfirm = async (req, res, next) => {
  const secret = req.body.secret;
  const token = req.body.token || req.body.code;

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
};

router.post('/2fa/confirm', requireAuth, validate(confirm2FaSchema), handle2FaConfirm);
router.post('/2fa/verify', requireAuth, validate(confirm2FaSchema), handle2FaConfirm);

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
// Security and auth events (workspace-wide for admins, personal for members)
// -------------------------------------------------------------
router.get('/activity', requireAuth, async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20)); // Exactly 20 per page default
    const offset = (page - 1) * limit;
    const workspaceId = req.query.workspace_id ? Number(req.query.workspace_id) : null;
    const boardId = req.query.board_id ? Number(req.query.board_id) : null;
    const targetUserId = req.query.user_id ? Number(req.query.user_id) : null;
    const search = (req.query.search || '').trim().toLowerCase();
    const category = (req.query.category || '').trim().toLowerCase();
    const actionType = (req.query.action_type || '').trim().toLowerCase();

    let rows = [];
    let total = 0;

    if (req.db) {
      // Determine if caller has permission to view all workspace security & activity audit records
      let canViewAll = false;
      if (workspaceId) {
        canViewAll = await userHasPermission(req.user.id, workspaceId, 'audit.view', req.db);
        if (!canViewAll) {
          canViewAll = await userHasPermission(req.user.id, workspaceId, 'activity.view', req.db);
        }
        if (!canViewAll) {
          canViewAll = await userHasPermission(req.user.id, workspaceId, 'company.manage_security', req.db);
        }
      }

      if (!canViewAll) {
        // Check if user is an Owner or Super Admin or Admin in any active workspace
        const adminCheck = await req.db.query(
          `SELECT 1 FROM workspace_members wm
           JOIN roles r ON wm.role_id = r.id
           WHERE wm.user_id = ? AND r.is_system = 1 AND (COALESCE(r.rank, 30) >= 80 OR r.is_editable = 0)
           LIMIT 1`,
          [req.user.id]
        );
        canViewAll = adminCheck.length > 0;
      }

      const whereClauses = [];
      const queryParams = [];

      // Non-admins can only see their own activities
      if (!canViewAll) {
        whereClauses.push('(a.user_id = ? OR LOWER(COALESCE(u.email, \'\')) = ?)');
        queryParams.push(req.user.id, (req.user.email || '').toLowerCase());
      } else if (targetUserId) {
        // Filter by specific user (member-wise audit)
        whereClauses.push('a.user_id = ?');
        queryParams.push(targetUserId);
      }

      if (boardId) {
        whereClauses.push('a.board_id = ?');
        queryParams.push(boardId);
      }

      if (workspaceId) {
        whereClauses.push('(a.workspace_id = ? OR b.workspace_id = ?)');
        queryParams.push(workspaceId, workspaceId);
      }

      if (actionType && actionType !== 'all') {
        whereClauses.push('a.action_type = ?');
        queryParams.push(actionType);
      }

      if (category && category !== 'all') {
        if (category === 'auth') {
          whereClauses.push("(a.action_type LIKE '%login%' OR a.action_type LIKE '%logout%' OR a.action_type LIKE '%password%' OR a.action_type LIKE '%2fa%' OR a.action_type LIKE '%session%')");
        } else if (category === 'tasks' || category === 'cards') {
          whereClauses.push("(a.action_type LIKE '%card%' OR a.action_type LIKE '%task%' OR a.action_type LIKE '%due_date%' OR a.action_type LIKE '%complete%' OR a.action_type LIKE '%checklist%')");
        } else if (category === 'comments') {
          whereClauses.push("(a.action_type LIKE '%comment%')");
        } else if (category === 'members') {
          whereClauses.push("(a.action_type LIKE '%member%' OR a.action_type LIKE '%assign%' OR a.action_type LIKE '%invite%')");
        } else if (category === 'roles') {
          whereClauses.push("(a.action_type LIKE '%role%' OR a.action_type LIKE '%permission%')");
        } else if (category === 'boards') {
          whereClauses.push("(a.action_type LIKE '%board%' OR a.action_type LIKE '%list%' OR a.action_type LIKE '%label%')");
        } else if (category === 'workspace') {
          whereClauses.push("(a.action_type LIKE '%workspace%')");
        }
      }

      if (search) {
        whereClauses.push(
          '(LOWER(a.action_type) LIKE ? OR LOWER(COALESCE(u.name, \'\')) LIKE ? OR LOWER(COALESCE(u.email, \'\')) LIKE ? OR LOWER(COALESCE(c.title, \'\')) LIKE ? OR LOWER(COALESCE(b.name, \'\')) LIKE ? OR LOWER(COALESCE(w.name, \'\')) LIKE ? OR LOWER(COALESCE(a.meta_json, \'\')) LIKE ?)'
        );
        const searchPattern = `%${search}%`;
        queryParams.push(searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern);
      }

      const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

      const countRes = await req.db.query(
        `SELECT COUNT(*) as total
         FROM activity_log a
         LEFT JOIN users u ON a.user_id = u.id
         LEFT JOIN cards c ON a.card_id = c.id
         LEFT JOIN boards b ON a.board_id = b.id
         LEFT JOIN workspaces w ON a.workspace_id = w.id
         ${whereSql}`,
        queryParams
      );
      total = Number(countRes[0]?.total || 0);

      rows = await req.db.query(
        `SELECT a.id, a.board_id, a.card_id, a.user_id, a.workspace_id, a.action_type,
                a.meta_json, a.created_at,
                u.name as user_name, u.email as user_email, u.avatar_url as user_avatar,
                c.title as card_title,
                b.name as board_name,
                w.name as workspace_name
         FROM activity_log a
         LEFT JOIN users u ON a.user_id = u.id
         LEFT JOIN cards c ON a.card_id = c.id
         LEFT JOIN boards b ON a.board_id = b.id
         LEFT JOIN workspaces w ON a.workspace_id = w.id
         ${whereSql}
         ORDER BY a.created_at DESC, a.id DESC
         LIMIT ? OFFSET ?`,
        [...queryParams, limit, offset]
      );
    }

    const events = rows.map((r) => {
      let meta = {};
      try {
        if (r.meta_json) {
          meta = typeof r.meta_json === 'string' ? JSON.parse(r.meta_json) : r.meta_json;
        }
      } catch (e) {
        meta = {};
      }

      const cardTitle = r.card_title || meta.card_title || meta.title || null;
      const boardName = r.board_name || meta.board_name || meta.boardName || null;
      const userName = r.user_name || meta.user_name || 'System';
      const atLower = String(r.action_type || '').toLowerCase();

      // Human-readable summary details
      let detailsSummary = '';
      if (atLower === 'user_login' || atLower === 'login_success') {
        detailsSummary = meta.method ? `Logged in via ${meta.method}` : 'Logged in to account';
      } else if (atLower === 'user_logout' || atLower === 'logout') {
        detailsSummary = 'Logged out of session';
      } else if (atLower === 'token_refresh_success') {
        detailsSummary = 'Security session token refreshed';
      } else if (atLower === 'login_failed') {
        detailsSummary = `Failed login attempt${meta.reason ? `: ${meta.reason}` : ''}`;
      } else if (atLower === 'password_changed') {
        detailsSummary = 'Changed account password';
      } else if (atLower === '2fa_enabled') {
        detailsSummary = 'Enabled two-factor authentication (2FA)';
      } else if (atLower === '2fa_disabled') {
        detailsSummary = 'Disabled two-factor authentication (2FA)';
      } else if (atLower === 'profile_updated') {
        detailsSummary = 'Updated account profile details';
      } else if (atLower === 'session_revoked') {
        detailsSummary = 'Revoked active session';
      } else if (atLower === 'created_card' || atLower === 'card_created') {
        detailsSummary = `Created task "${cardTitle || 'Card'}"${boardName ? ` in "${boardName}"` : ''}`;
      } else if (atLower === 'card_renamed') {
        detailsSummary = `Renamed task to "${cardTitle || meta.new_title || 'Card'}"`;
      } else if (atLower === 'card_description_updated') {
        detailsSummary = `Updated description for task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'card_cover_changed') {
        detailsSummary = `Changed cover for task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'moved_card' || atLower === 'card_moved') {
        detailsSummary = `Moved task "${cardTitle || 'Card'}"${meta.from && meta.to ? ` from "${meta.from}" to "${meta.to}"` : ''}`;
      } else if (atLower === 'marked_complete' || atLower === 'completed_card') {
        detailsSummary = `Completed task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'marked_incomplete') {
        detailsSummary = `Reopened task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'due_date_changed') {
        detailsSummary = meta.due_date ? `Set due date on "${cardTitle || 'Card'}" to ${meta.due_date}` : `Removed due date from "${cardTitle || 'Card'}"`;
      } else if (atLower === 'card_archived') {
        detailsSummary = `Archived task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'card_restored') {
        detailsSummary = `Restored task "${cardTitle || 'Card'}" from archive`;
      } else if (atLower === 'card_deleted' || atLower === 'deleted_card') {
        detailsSummary = `Deleted task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'added_comment' || atLower === 'comment_added') {
        detailsSummary = `Added a comment on task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'edited_comment') {
        detailsSummary = `Edited comment on task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'deleted_comment') {
        detailsSummary = `Deleted comment from task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'checklist_added') {
        detailsSummary = `Added checklist "${meta.checklist_title || 'Checklist'}" to task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'checklist_removed') {
        detailsSummary = `Removed checklist "${meta.checklist_title || 'Checklist'}" from task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'checklist_item_added') {
        detailsSummary = `Added checklist item "${meta.item_text || ''}" on "${cardTitle || 'Card'}"`;
      } else if (atLower === 'checklist_toggled') {
        detailsSummary = `${meta.is_checked ? 'Checked' : 'Unchecked'} checklist item "${meta.item_text || ''}" on "${cardTitle || 'Card'}"`;
      } else if (atLower === 'checklist_item_edited') {
        detailsSummary = `Edited checklist item "${meta.item_text || ''}" on "${cardTitle || 'Card'}"`;
      } else if (atLower === 'checklist_item_deleted') {
        detailsSummary = `Deleted checklist item "${meta.item_text || ''}" from "${cardTitle || 'Card'}"`;
      } else if (atLower === 'label_added') {
        detailsSummary = `Added label "${meta.label_name || 'Label'}" to task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'label_removed') {
        detailsSummary = `Removed label "${meta.label_name || 'Label'}" from task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'member_added') {
        detailsSummary = `Assigned "${meta.member_name || 'user'}" to task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'member_removed') {
        detailsSummary = `Unassigned "${meta.member_name || 'user'}" from task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'attachment_added') {
        detailsSummary = `Added attachment "${meta.file_name || 'file'}" to task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'attachment_removed') {
        detailsSummary = `Removed attachment "${meta.file_name || 'file'}" from task "${cardTitle || 'Card'}"`;
      } else if (atLower === 'board_created') {
        detailsSummary = `Created board "${boardName || 'Board'}"`;
      } else if (atLower === 'board_renamed') {
        detailsSummary = `Renamed board to "${meta.board_name || boardName || 'Board'}"`;
      } else if (atLower === 'board_archived') {
        detailsSummary = `Archived board "${boardName || 'Board'}"`;
      } else if (atLower === 'board_restored') {
        detailsSummary = `Restored board "${boardName || 'Board'}"`;
      } else if (atLower === 'board_deleted') {
        detailsSummary = `Deleted board "${meta.board_name || boardName || 'Board'}"`;
      } else if (atLower === 'board_member_added') {
        detailsSummary = `Added "${meta.member_name || 'member'}" to board "${boardName || 'Board'}"`;
      } else if (atLower === 'board_member_removed') {
        detailsSummary = `Removed member from board "${boardName || 'Board'}"`;
      } else if (atLower === 'list_created') {
        detailsSummary = `Created list "${meta.list_name || 'List'}"${boardName ? ` in "${boardName}"` : ''}`;
      } else if (atLower === 'list_renamed') {
        detailsSummary = `Renamed list to "${meta.list_name || 'List'}"`;
      } else if (atLower === 'list_archived') {
        detailsSummary = `Archived list "${meta.list_name || 'List'}"`;
      } else if (atLower === 'list_reordered') {
        detailsSummary = `Reordered list "${meta.list_name || 'List'}"`;
      } else if (atLower === 'list_deleted') {
        detailsSummary = `Deleted list "${meta.list_name || 'List'}"`;
      } else if (atLower.includes('workspace')) {
        detailsSummary = `${atLower.replace(/_/g, ' ')} "${r.workspace_name || meta.workspace_name || 'workspace'}"`;
      } else if (atLower.includes('role')) {
        detailsSummary = `${atLower.replace(/_/g, ' ')} "${meta.role_name || meta.name || 'role'}"`;
      } else {
        detailsSummary = `${atLower.replace(/_/g, ' ')}${cardTitle ? ` on "${cardTitle}"` : ''}${boardName ? ` in "${boardName}"` : ''}`;
      }

      return {
        id: r.id,
        event: r.action_type,
        event_type: r.action_type,
        action: r.action_type ? r.action_type.replace(/[._]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : 'Activity',
        action_type: r.action_type,
        board_id: r.board_id,
        board_name: boardName,
        card_id: r.card_id,
        card_title: cardTitle,
        workspace_id: r.workspace_id,
        workspace_name: r.workspace_name,
        user_id: r.user_id,
        user_name: userName,
        user_email: r.user_email || meta.email || null,
        user_avatar: r.user_avatar || null,
        ip: meta.ip_address || meta.ip || '127.0.0.1',
        user_agent: meta.user_agent || null,
        metadata: meta,
        details: detailsSummary,
        created_at: r.created_at ? new Date(r.created_at).toISOString() : new Date().toISOString()
      };
    });

    return res.json({
      events,
      logs: events,
      activities: events,
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

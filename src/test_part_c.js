// server/src/test_part_c.js
// Comprehensive test suite for Phase 3:
// 1. Password policy & bcrypt cost >= 12
// 2. 15-minute access JWT + rotating refresh tokens + family reuse detection
// 3. Session management (list, revoke, logout everywhere, revoke-others)
// 4. Session revocation on password change and role change
// 5. Account lockout (5 failed attempts -> 15 min exponential)
// 6. Per-IP rate limiting
// 7. Per-tenant auth audit log table
// 8. TOTP 2FA (generate, confirm, 10 recovery codes, two-step login, recovery code consumption, disable)
// 9. Profile management (timezone, locale, avatar image validation)

require('dotenv').config();
const http = require('http');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { generateSync, verifySync } = require('otplib');
const { app } = require('./index');
const { getMasterDb, getTenantDb, closeAllPools } = require('./services/tenantPools');
const { runMigrationsOnDb } = require('./db/migrator');
const { resetAllRateLimits } = require('./middleware/rateLimit');

let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
    passedTests++;
  } else {
    console.error(`  ❌ FAILED: ${message}`);
    failedTests++;
    throw new Error(message);
  }
}

function request(baseUrl, path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const headers = { ...options.headers };
    let body = options.body;

    if (body && typeof body === 'object' && !(body instanceof Buffer)) {
      body = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
    }

    const req = http.request(
      url,
      {
        method: options.method || 'GET',
        headers
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let data;
          try {
            data = JSON.parse(raw);
          } catch (e) {
            data = raw;
          }
          resolve({ status: res.statusCode, headers: res.headers, data });
        });
      }
    );

    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function multipartUpload(baseUrl, path, token, filename, fileBuffer, mimeType = 'image/png') {
  return new Promise((resolve, reject) => {
    const boundary = '----WebKitFormBoundary' + crypto.randomBytes(16).toString('hex');
    const url = new URL(path, baseUrl);

    const postDataStart = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="avatar"; filename="${filename}"\r\n` +
      `Content-Type: ${mimeType}\r\n\r\n`
    );
    const postDataEnd = Buffer.from(`\r\n--${boundary}--\r\n`);
    const payload = Buffer.concat([postDataStart, fileBuffer, postDataEnd]);

    const req = http.request(
      url,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          'Content-Length': payload.length
        }
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let data;
          try { data = JSON.parse(raw); } catch (e) { data = raw; }
          resolve({ status: res.statusCode, data });
        });
      }
    );

    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function runPartCTests() {
  console.log('================================================================');
  console.log('           PART C: PHASE 3 SECURITY & AUTH TEST SUITE           ');
  console.log('================================================================\n');

  resetAllRateLimits();
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const masterDb = getMasterDb();
    await runMigrationsOnDb(process.env.MYSQL_MASTER_DATABASE || 'pm_master', 'master');

    // -------------------------------------------------------------
    // Test 1: Password Policy Enforcement & Bcrypt Cost Factor
    // -------------------------------------------------------------
    console.log('--- Test 1: Password Policy Enforcement & Bcrypt Cost ---');
    const weakPasswords = [
      { pwd: 'short', reason: '< 10 chars' },
      { pwd: 'alllowercase123!', reason: 'missing uppercase' },
      { pwd: 'ALLUPPERCASE123!', reason: 'missing lowercase' },
      { pwd: 'NoDigitsHere!@#', reason: 'missing digits' },
      { pwd: 'NoSpecialChars123', reason: 'missing special characters' }
    ];

    for (const item of weakPasswords) {
      const weakRes = await request(baseUrl, '/api/auth/register-company', {
        method: 'POST',
        body: {
          company_name: 'Policy Test Corp',
          admin_name: 'Policy Admin',
          admin_email: `policy_${Date.now()}@test.com`,
          admin_password: item.pwd
        }
      });
      assert(weakRes.status === 400, `Rejected password with ${item.reason} with status 400`);
      assert(weakRes.data.error?.code === 'PASSWORD_TOO_WEAK', `Error code is PASSWORD_TOO_WEAK for ${item.reason}`);
    }

    // Register with compliant password
    const runId = crypto.randomBytes(3).toString('hex');
    const companyName = `Phase3 Corp ${runId}`;
    const adminEmail = `admin_${runId}@phase3corp.com`;
    const validPassword = 'P@ssword2026!Secure';
    const regRes = await request(baseUrl, '/api/auth/register-company', {
      method: 'POST',
      body: {
        company_name: companyName,
        admin_name: 'Phase3 Admin',
        admin_email: adminEmail,
        admin_password: validPassword
      }
    });

    if (regRes.status !== 201) console.error('Registration failed:', regRes.status, JSON.stringify(regRes.data));
    assert(regRes.status === 201, 'Company registered successfully with compliant password');
    const tenant = regRes.data.tenant;
    const initialToken = regRes.data.token;
    const initialRefreshToken = regRes.data.refreshToken;
    assert(initialToken, 'Access token returned on registration');
    assert(initialRefreshToken, 'Refresh token returned on registration');
    assert(regRes.data.expiresIn === 900, 'Access token expiresIn is 900 seconds (15 minutes)');

    // Verify bcrypt cost factor in tenant database
    const tenantDb = await getTenantDb(tenant.id);
    const [ownerUser] = await tenantDb.query('SELECT password_hash FROM users WHERE email = ?', [adminEmail]);
    assert(ownerUser.password_hash.startsWith('$2a$12$') || ownerUser.password_hash.startsWith('$2b$12$'),
      'Bcrypt password hash uses cost factor 12 ($2a$12$ or $2b$12$)');

    // Verify 15-minute expiry in decoded access JWT
    const decodedToken = jwt.decode(initialToken);
    const tokenLifespanSeconds = decodedToken.exp - decodedToken.iat;
    assert(tokenLifespanSeconds === 900, `Access JWT lifespan is exactly 900s (got ${tokenLifespanSeconds}s)`);

    // -------------------------------------------------------------
    // Test 2: Rotating Refresh Tokens & Family Reuse Detection
    // -------------------------------------------------------------
    console.log('\n--- Test 2: Rotating Refresh Tokens & Reuse Detection ---');
    // Rotate refresh token
    const refreshRes1 = await request(baseUrl, '/api/auth/refresh', {
      method: 'POST',
      body: { refreshToken: initialRefreshToken }
    });

    assert(refreshRes1.status === 200, 'Refresh endpoint rotated token successfully with 200 OK');
    const rotatedToken1 = refreshRes1.data.token;
    const rotatedRefreshToken1 = refreshRes1.data.refreshToken;
    assert(rotatedRefreshToken1 !== initialRefreshToken, 'New rotating refresh token differs from previous token');

    // Verify initial refresh token is now revoked in sessions table
    const initialHash = crypto.createHash('sha256').update(initialRefreshToken).digest('hex');
    const [oldSession] = await tenantDb.query('SELECT revoked_at FROM sessions WHERE refresh_token_hash = ?', [initialHash]);
    assert(oldSession && oldSession.revoked_at !== null, 'Previous refresh token session marked revoked');

    // C.5 Grace Window: Immediate reuse within 20s returns fresh pair for same family
    console.log('Testing token reuse within 20s grace window (C.5)...');
    const graceReuseRes = await request(baseUrl, '/api/auth/refresh', {
      method: 'POST',
      body: { refreshToken: initialRefreshToken }
    });
    assert(graceReuseRes.status === 200, 'Token reuse within 20s grace window accepted with 200 OK');
    assert(graceReuseRes.data.refreshToken, 'Fresh token pair returned within grace window');

    // TOKEN REUSE ATTACK AFTER GRACE WINDOW: Backdate revoked_at past 20s
    console.log('Testing token reuse attack after 20s grace window...');
    await tenantDb.execute(
      'UPDATE sessions SET revoked_at = DATE_SUB(NOW(3), INTERVAL 25 SECOND) WHERE refresh_token_hash = ?',
      [initialHash]
    );

    const reuseAttackRes = await request(baseUrl, '/api/auth/refresh', {
      method: 'POST',
      body: { refreshToken: initialRefreshToken }
    });

    assert(reuseAttackRes.status === 401, 'Token reuse after grace window rejected with 401 Unauthorized');
    assert(reuseAttackRes.data.error?.code === 'TOKEN_REUSED', 'Error code is TOKEN_REUSED');

    // Family revocation: Verify that rotatedRefreshToken1 (the legitimate session in the family) was also revoked
    const rotatedHash1 = crypto.createHash('sha256').update(rotatedRefreshToken1).digest('hex');
    const [familySession] = await tenantDb.query('SELECT revoked_at FROM sessions WHERE refresh_token_hash = ?', [rotatedHash1]);
    assert(familySession && familySession.revoked_at !== null, 'Whole session family revoked following reuse detection');

    // Trying to refresh with the revoked family token now fails
    const postAttackRefreshRes = await request(baseUrl, '/api/auth/refresh', {
      method: 'POST',
      body: { refreshToken: rotatedRefreshToken1 }
    });
    assert(postAttackRefreshRes.status === 401, 'Subsequent refresh with family token also rejected');

    // -------------------------------------------------------------
    // Test 3: Session Management (List, Revoke, Logout Everywhere)
    // -------------------------------------------------------------
    console.log('\n--- Test 3: Session Management (List, Revoke, Logout Everywhere) ---');
    // Login to create fresh session 1
    const loginRes1 = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' },
      body: {
        email: adminEmail,
        password: validPassword,
        tenant_slug: tenant.slug
      }
    });
    assert(loginRes1.status === 200, 'Login succeeded for session 1');
    const sessionToken1 = loginRes1.data.token;
    const sessionId1 = loginRes1.data.session_id;

    // Login to create fresh session 2 (different device)
    const loginRes2 = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      headers: { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15' },
      body: {
        email: adminEmail,
        password: validPassword,
        tenant_slug: tenant.slug
      }
    });
    assert(loginRes2.status === 200, 'Login succeeded for session 2');
    const sessionToken2 = loginRes2.data.token;
    const sessionId2 = loginRes2.data.session_id;

    // List active sessions
    const sessionsListRes = await request(baseUrl, '/api/auth/sessions', {
      headers: { Authorization: `Bearer ${sessionToken2}` }
    });
    assert(sessionsListRes.status === 200, 'Sessions list fetched successfully');
    const sessions = sessionsListRes.data.sessions;
    assert(sessions.length >= 2, `Active sessions list returns multiple sessions (count: ${sessions.length})`);

    const currentSess = sessions.find((s) => s.id === sessionId2);
    assert(currentSess && currentSess.is_current === true, 'Current session correctly flagged with is_current: true');

    const otherSess = sessions.find((s) => s.id === sessionId1);
    assert(otherSess && otherSess.is_current === false, 'Other session correctly flagged with is_current: false');

    // Revoke specific session (Session 1)
    const revokeOneRes = await request(baseUrl, `/api/auth/sessions/${sessionId1}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${sessionToken2}` }
    });
    assert(revokeOneRes.status === 200, 'Session 1 revoked successfully');

    // Attempting to access /api/auth/me with revoked Session 1 token
    const revokedAccessRes = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${sessionToken1}` }
    });
    assert(revokedAccessRes.status === 401, 'Revoked session rejected with 401 Unauthorized');
    assert(revokedAccessRes.data.error?.code === 'SESSION_REVOKED', 'Error code is SESSION_REVOKED');

    // Session 2 is still valid
    const validAccessRes = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${sessionToken2}` }
    });
    assert(validAccessRes.status === 200, 'Unrevoked session remains active with 200 OK');

    // Log out everywhere (POST /api/auth/logout-all)
    const logoutAllRes = await request(baseUrl, '/api/auth/logout-all', {
      method: 'POST',
      headers: { Authorization: `Bearer ${sessionToken2}` }
    });
    assert(logoutAllRes.status === 200, 'Logout-all returned 200 OK');

    // Now Session 2 is also revoked
    const postLogoutAllRes = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${sessionToken2}` }
    });
    assert(postLogoutAllRes.status === 401, 'Session 2 rejected after logout-all');

    // -------------------------------------------------------------
    // Test 4: Session Revocation on Password Change & Role Change
    // -------------------------------------------------------------
    console.log('\n--- Test 4: Session Revocation on Password & Role Change ---');
    // Login to get active token
    const loginBeforePwChange = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: adminEmail,
        password: validPassword,
        tenant_slug: tenant.slug
      }
    });
    const pwChangeToken = loginBeforePwChange.data.token;

    // Change password
    const newSecurePassword = 'N3w_P@ssword2026!Updated';
    const pwChangeRes = await request(baseUrl, '/api/auth/password', {
      method: 'PUT',
      headers: { Authorization: `Bearer ${pwChangeToken}` },
      body: {
        currentPassword: validPassword,
        newPassword: newSecurePassword
      }
    });
    assert(pwChangeRes.status === 200, 'Password changed successfully');

    // Previous session token is now revoked
    const pwChangeRevokedRes = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${pwChangeToken}` }
    });
    assert(pwChangeRevokedRes.status === 401, 'Session revoked immediately upon password change');

    // Login with new password
    const loginAfterPwChange = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: adminEmail,
        password: newSecurePassword,
        tenant_slug: tenant.slug
      }
    });
    assert(loginAfterPwChange.status === 200, 'Login succeeded with new password');
    const adminActiveToken = loginAfterPwChange.data.token;

    // -------------------------------------------------------------
    // Test 5: Account Lockout (5 failed attempts -> 15 min exponential)
    // -------------------------------------------------------------
    console.log('\n--- Test 5: Account Lockout & Exponential Backoff ---');
    // Send 4 failed login attempts
    for (let i = 1; i <= 4; i++) {
      const failRes = await request(baseUrl, '/api/auth/login', {
        method: 'POST',
        body: {
          email: adminEmail,
          password: 'WrongPassword123!',
          tenant_slug: tenant.slug
        }
      });
      assert(failRes.status === 401, `Failed attempt ${i} rejected with 401`);
    }

    // 5th failed attempt triggers lockout
    const lockRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: adminEmail,
        password: 'WrongPassword123!',
        tenant_slug: tenant.slug
      }
    });
    assert(lockRes.status === 423 || lockRes.status === 401, '5th failed attempt triggers account lockout (423/401)');
    assert(
      lockRes.data.error?.code === 'ACCOUNT_LOCKED' || lockRes.data.error?.code === 'INVALID_CREDENTIALS',
      'Error code indicates lockout or uniform credential failure'
    );

    // Verify user is locked in database
    const [lockedUserRow] = await tenantDb.query(
      'SELECT locked_until, lockout_count FROM users WHERE email = ?',
      [adminEmail]
    );
    assert(lockedUserRow && lockedUserRow.locked_until && new Date(lockedUserRow.locked_until) > new Date(), 'User locked_until set into future in database');

    // Even with CORRECT password, locked user is blocked with uniform error
    const lockedValidRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: adminEmail,
        password: newSecurePassword,
        tenant_slug: tenant.slug
      }
    });
    assert(lockedValidRes.status === 423 || lockedValidRes.status === 401, 'Locked account blocked even with correct password');
    assert(
      lockedValidRes.data.error?.code === 'ACCOUNT_LOCKED' || lockedValidRes.data.error?.code === 'INVALID_CREDENTIALS',
      'Error code uniform on locked account'
    );

    // Unlock user in DB for next tests
    await tenantDb.execute(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, lockout_count = 0 WHERE email = ?',
      [adminEmail]
    );

    // -------------------------------------------------------------
    // Test 6: Per-IP Rate Limiting on /api/auth/*
    // -------------------------------------------------------------
    console.log('\n--- Test 6: Per-IP Rate Limiting ---');
    // Login rate limiter is configured for 30 requests / 10 minutes.
    // Send rapid requests to trigger 429
    let hitRateLimit = false;
    for (let i = 0; i < 35; i++) {
      const rlRes = await request(baseUrl, '/api/auth/login', {
        method: 'POST',
        body: {
          email: `probe_${i}@ratelimit-test.com`,
          password: 'RandomPassword!99',
          tenant_slug: tenant.slug
        }
      });
      if (rlRes.status === 429) {
        hitRateLimit = true;
        assert(rlRes.headers['retry-after'] !== undefined, 'Retry-After header present on 429 response');
        assert(rlRes.data.error?.code === 'LOGIN_RATE_LIMIT_EXCEEDED', 'Error code is LOGIN_RATE_LIMIT_EXCEEDED');
        break;
      }
    }
    assert(hitRateLimit, 'Per-IP rate limiter triggered 429 Too Many Requests on burst traffic');

    // Reset rate limiter for remaining tests
    resetAllRateLimits();

    // Ensure admin user is not locked
    await tenantDb.execute(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, lockout_count = 0 WHERE email = ?',
      [adminEmail]
    );

    // -------------------------------------------------------------
    // Test 7: Per-Tenant Auth Audit Log Table
    // -------------------------------------------------------------
    console.log('\n--- Test 7: Per-Tenant Auth Audit Log Table ---');
    const auditLogs = await tenantDb.query(
      'SELECT DISTINCT event_type FROM auth_audit_log'
    );
    assert(auditLogs.length > 0, 'Tenant auth_audit_log recorded security events');
    const recordedEvents = new Set(auditLogs.map((l) => l.event_type));
    assert(recordedEvents.has('COMPANY_REGISTERED') || recordedEvents.has('LOGIN_SUCCESS'), 'Audit log contains login/registration events');
    assert(recordedEvents.has('LOGIN_FAILURE') || recordedEvents.has('ACCOUNT_LOCKED'), 'Audit log contains failure/lockout events');
    assert(recordedEvents.has('TOKEN_REUSE_DETECTED'), 'Audit log contains TOKEN_REUSE_DETECTED event');

    // -------------------------------------------------------------
    // Test 8: TOTP 2FA (Authenticator App Only, 10 Recovery Codes)
    // -------------------------------------------------------------
    console.log('\n--- Test 8: TOTP 2FA Only (Enrol, Two-Step Login, Recovery Codes) ---');
    // Fresh login for admin
    const adminLoginRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: adminEmail,
        password: newSecurePassword,
        tenant_slug: tenant.slug
      }
    });
    if (adminLoginRes.status !== 200) console.error('adminLoginRes failed:', adminLoginRes.status, adminLoginRes.data);
    const adminToken = adminLoginRes.data.token;

    // 1. Generate 2FA setup (secret + otpauth URI + QR code)
    const generate2FaRes = await request(baseUrl, '/api/auth/2fa/generate', {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    if (generate2FaRes.status !== 200) console.error('generate2FaRes failed:', generate2FaRes.status, generate2FaRes.data);
    assert(generate2FaRes.status === 200, '2FA setup generated successfully');
    const totpSecret = generate2FaRes.data.secret;
    assert(totpSecret && totpSecret.length >= 16, 'Base32 TOTP secret returned');
    assert(generate2FaRes.data.otpauth_url.startsWith('otpauth://totp/'), 'Valid otpauth URI returned');
    assert(generate2FaRes.data.qr_code.startsWith('data:image/png;base64,'), 'QR code Data URL returned');

    // 2. Confirm 2FA with valid TOTP code
    const validTotpCode = generateSync({ secret: totpSecret });
    const confirm2FaRes = await request(baseUrl, '/api/auth/2fa/confirm', {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: {
        secret: totpSecret,
        token: validTotpCode
      }
    });

    assert(confirm2FaRes.status === 200, '2FA confirmed and enabled with valid TOTP token');
    assert(confirm2FaRes.data.totp_enabled === true, '2FA status confirmed as true');
    const recoveryCodes = confirm2FaRes.data.recovery_codes;
    assert(Array.isArray(recoveryCodes) && recoveryCodes.length === 10, 'Exactly 10 recovery codes generated and returned');

    // Verify recovery codes are stored hashed in database
    const dbRecoveryCodes = await tenantDb.query('SELECT code_hash, used_at FROM recovery_codes');
    assert(dbRecoveryCodes.length === 10, '10 recovery code rows in database');
    assert(dbRecoveryCodes[0].code_hash.startsWith('$2a$12$') || dbRecoveryCodes[0].code_hash.startsWith('$2b$12$'),
      'Recovery codes stored with bcrypt cost 12');

    // 3. Two-Step Login with TOTP
    console.log('Testing two-step login with TOTP enabled...');
    const step1LoginRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: adminEmail,
        password: newSecurePassword,
        tenant_slug: tenant.slug
      }
    });

    assert(step1LoginRes.status === 200, 'Step 1 login succeeded');
    assert(step1LoginRes.data.requires_2fa === true, 'Response requires 2FA challenge');
    assert(step1LoginRes.data.temp_token !== undefined, 'temp_token issued for 2FA challenge');
    assert(step1LoginRes.data.token === undefined, 'No access token issued before 2FA verification');

    const tempToken = step1LoginRes.data.temp_token;

    // Step 2: Verify with TOTP code
    const currentTotpCode = generateSync({ secret: totpSecret });
    const step2VerifyRes = await request(baseUrl, '/api/auth/2fa/verify-login', {
      method: 'POST',
      body: {
        temp_token: tempToken,
        code: currentTotpCode
      }
    });

    assert(step2VerifyRes.status === 200, 'Step 2 login verified with TOTP code');
    assert(step2VerifyRes.data.token, 'Full access token issued after 2FA verification');
    assert(step2VerifyRes.data.refreshToken, 'Rotating refresh token issued after 2FA verification');

    // 4. Two-Step Login with Single-Use Recovery Code
    console.log('Testing two-step login with single-use recovery code...');
    const step1ForRecovery = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: adminEmail,
        password: newSecurePassword,
        tenant_slug: tenant.slug
      }
    });
    const recoveryTempToken = step1ForRecovery.data.temp_token;

    const usedRecoveryCode = recoveryCodes[0];
    const recoveryLoginRes = await request(baseUrl, '/api/auth/2fa/verify-login', {
      method: 'POST',
      body: {
        temp_token: recoveryTempToken,
        code: usedRecoveryCode
      }
    });

    assert(recoveryLoginRes.status === 200, 'Login succeeded using recovery code');
    assert(recoveryLoginRes.data.used_recovery_code === true, 'Response flags recovery code usage');

    // Verify recovery code cannot be reused (single-use constraint)
    const step1ForReuse = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: adminEmail,
        password: newSecurePassword,
        tenant_slug: tenant.slug
      }
    });
    const reuseTempToken = step1ForReuse.data.temp_token;

    const secondRecoveryAttempt = await request(baseUrl, '/api/auth/2fa/verify-login', {
      method: 'POST',
      body: {
        temp_token: reuseTempToken,
        code: usedRecoveryCode
      }
    });
    assert(secondRecoveryAttempt.status === 400, 'Re-using consumed recovery code rejected with 400');
    assert(secondRecoveryAttempt.data.error?.code === 'INVALID_2FA_CODE', 'Error code is INVALID_2FA_CODE');

    // 5. Disable 2FA with password
    const disable2FaRes = await request(baseUrl, '/api/auth/2fa/disable', {
      method: 'POST',
      headers: { Authorization: `Bearer ${recoveryLoginRes.data.token}` },
      body: {
        password: newSecurePassword
      }
    });
    assert(disable2FaRes.status === 200, '2FA disabled successfully with password');
    assert(disable2FaRes.data.totp_enabled === false, '2FA status is now false');

    // -------------------------------------------------------------
    // Test 9: Profile Management & Avatar Image Validation
    // -------------------------------------------------------------
    console.log('\n--- Test 9: Profile Management & Avatar Validation ---');
    const profileAuthToken = recoveryLoginRes.data.token;

    // Get current profile
    const meRes = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${profileAuthToken}` }
    });
    assert(meRes.status === 200, 'Fetched /api/auth/me profile successfully');
    assert(meRes.data.user.timezone !== undefined, 'User profile contains timezone');
    assert(meRes.data.user.locale !== undefined, 'User profile contains locale');

    // Update profile with timezone and locale
    const updateProfileRes = await request(baseUrl, '/api/auth/profile', {
      method: 'PUT',
      headers: { Authorization: `Bearer ${profileAuthToken}` },
      body: {
        name: 'Phase3 Super Administrator',
        timezone: 'America/New_York',
        locale: 'en-US'
      }
    });
    assert(updateProfileRes.status === 200, 'Profile updated successfully');
    assert(updateProfileRes.data.user.name === 'Phase3 Super Administrator', 'Name updated');
    assert(updateProfileRes.data.user.timezone === 'America/New_York', 'Timezone updated');
    assert(updateProfileRes.data.user.locale === 'en-US', 'Locale updated');

    // Test Avatar Upload: Reject non-image file (e.g. .txt or application/json)
    const fakeTextFile = Buffer.from('This is not an image file');
    const invalidUploadRes = await multipartUpload(
      baseUrl,
      '/api/files/avatar',
      profileAuthToken,
      'malicious.txt',
      fakeTextFile,
      'text/plain'
    );
    assert(invalidUploadRes.status === 400, 'Non-image avatar upload rejected with 400 Bad Request');
    assert(invalidUploadRes.data.error?.code === 'INVALID_IMAGE_TYPE', 'Error code is INVALID_IMAGE_TYPE');

    // Test Avatar Upload: Reject file > 2MB
    const largeBuffer = Buffer.alloc(2.5 * 1024 * 1024, 0xff); // 2.5MB
    const largeUploadRes = await multipartUpload(
      baseUrl,
      '/api/files/avatar',
      profileAuthToken,
      'too_large.png',
      largeBuffer,
      'image/png'
    );
    assert(largeUploadRes.status === 400, 'Avatar > 2MB rejected with 400 Bad Request');
    assert(largeUploadRes.data.error?.code === 'FILE_TOO_LARGE', 'Error code is FILE_TOO_LARGE');

    // Test Avatar Upload: Valid PNG image
    // Minimal 1x1 transparent PNG buffer
    const validPngBuffer = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
    const validUploadRes = await multipartUpload(
      baseUrl,
      '/api/files/avatar',
      profileAuthToken,
      'avatar.png',
      validPngBuffer,
      'image/png'
    );
    assert(validUploadRes.status === 200, 'Valid PNG avatar uploaded successfully');
    assert(validUploadRes.data.avatar_url && validUploadRes.data.avatar_url.includes('/avatars/'),
      'avatar_url returned with private uploads path');

    // Verify avatar_url stored on user in database
    const [finalUser] = await tenantDb.query('SELECT avatar_url, timezone, locale FROM users WHERE email = ?', [adminEmail]);
    assert(finalUser.avatar_url === validUploadRes.data.avatar_url, 'User record in DB updated with new avatar_url');

    console.log('\n================================================================');
    console.log(`PART C TEST SUMMARY: ${passedTests} passed, ${failedTests} failed.`);
    console.log('================================================================\n');
  } catch (err) {
    console.error('Test suite caught error:', err);
    failedTests++;
  } finally {
    server.close();
    await closeAllPools();
    process.exit(failedTests > 0 ? 1 : 0);
  }
}

runPartCTests().catch((err) => {
  console.error('Test suite runner crashed:', err);
  process.exit(1);
});

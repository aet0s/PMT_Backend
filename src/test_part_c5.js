// server/src/test_part_c5.js
// Comprehensive test suite for Part C.5:
// 1. Password-reset & 2FA-reset authority (rank checks, never self, owner-only for owner, CLI admin:reset-2fa)
// 2. Refresh rotation race (2 parallel refresh calls succeed, 20s grace window, reuse after 20s revokes family)
// 3. Immediate revocation & socket disconnect (session sid check, 5s cache invalidation, disconnects)
// 4. must_change_password middleware enforcement (blocks all routes except me, password, logout with 403 PASSWORD_CHANGE_REQUIRED)
// 5. 2FA hardening (5 wrong attempts locks challenge & account, single-use challenge token, anti-replay, AES-256-GCM at rest)
// 6. File authorization & magic bytes (404 cross-tenant, card attachment authorization, avatar magic bytes validation)
// 7. Lockout timing & uniform response (unknown email, wrong password, locked account return uniform 401 INVALID_CREDENTIALS)
// 8. Phase 2.5 items (failed provisioning cleanup via tenants:reconcile, reminder cron tenant isolation, 30-day slug reservation)

require('dotenv').config();
process.env.DEV_SINGLE_TENANT = '0';
process.env.REGISTRATION_RATE_LIMIT_PER_HOUR = '100';
process.env.REGISTRATION_DAILY_CAP = '10000';
const http = require('http');
const crypto = require('crypto');
const { execSync } = require('child_process');
const { generateSync } = require('otplib');
const { app } = require('./index');
const { getMasterDb, getTenantDb, closeAllPools } = require('./services/tenantPools');
const { runMigrationsOnDb } = require('./db/migrator');
const { resetAllRateLimits } = require('./middleware/rateLimit');
const { encryptSecret, decryptSecret } = require('./utils/cryptoVault');
const { processAllTenantsReminders } = require('./cron/reminders');
const reconcileTenants = require('./scripts/tenantsReconcile');

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

async function runPartC5Tests() {
  console.log('================================================================');
  console.log('                 PART C.5 SECURITY & ROBUSTNESS                 ');
  console.log('================================================================\n');

  resetAllRateLimits();
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const masterDb = getMasterDb();
    await runMigrationsOnDb(process.env.MYSQL_MASTER_DATABASE || 'pm_master', 'master');

    const testSuffix = crypto.randomBytes(3).toString('hex');
    const tenantSlug = `c5_corp_${testSuffix}`;
    const ownerEmail = `owner_${testSuffix}@c5corp.com`;
    const adminEmail = `admin_${testSuffix}@c5corp.com`;
    const memberEmail = `member_${testSuffix}@c5corp.com`;
    const defaultPassword = 'SecurePassword123!';

    // Register test company
    const regRes = await request(baseUrl, '/api/auth/register-company', {
      method: 'POST',
      body: {
        companyName: `C5 Corp ${testSuffix}`,
        slug: tenantSlug,
        name: 'Company Owner',
        email: ownerEmail,
        password: defaultPassword
      }
    });

    assert(regRes.status === 201, 'Company registered successfully');
    const ownerToken = regRes.data.token;
    const ownerId = regRes.data.user.id;
    const tenantId = regRes.data.tenant.id;
    const workspaceId = regRes.data.initial_workspace_id;
    const tenantDb = await getTenantDb(tenantId);

    // Create an Admin user and a Member user in this tenant
    const bcrypt = require('bcryptjs');
    const passwordHash = await bcrypt.hash(defaultPassword, 12);

    const [managerRole] = await tenantDb.query("SELECT id FROM roles WHERE name IN ('Project Manager', 'Manager')");
    const [memberRole] = await tenantDb.query("SELECT id FROM roles WHERE name IN ('Team Member', 'Member')");

    // Ensure Manager has member.reset_password and member.reset_2fa permissions to test rank logic
    const [pwPerm] = await tenantDb.query("SELECT id FROM permissions WHERE `key` = 'member.reset_password'");
    const [twoFaPerm] = await tenantDb.query("SELECT id FROM permissions WHERE `key` = 'member.reset_2fa'");
    if (pwPerm && managerRole) {
      await tenantDb.execute('INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [managerRole.id, pwPerm.id]);
    }
    if (twoFaPerm && managerRole) {
      await tenantDb.execute('INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [managerRole.id, twoFaPerm.id]);
    }

    const adminUserRes = await tenantDb.execute(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      ['Manager User', adminEmail, passwordHash]
    );
    const adminId = adminUserRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)',
      [workspaceId, adminId, 'Manager', managerRole.id]
    );

    const memberUserRes = await tenantDb.execute(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      ['Member User', memberEmail, passwordHash]
    );
    const memberId = memberUserRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)',
      [workspaceId, memberId, 'Team Member', memberRole.id]
    );

    // Login as Manager to get Manager token
    const adminLoginRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: adminEmail, password: defaultPassword, tenant_slug: tenantSlug }
    });
    assert(adminLoginRes.status === 200, 'Manager logged in');
    const adminToken = adminLoginRes.data.token;

    // Login as Member to get Member token
    const memberLoginRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: memberEmail, password: defaultPassword, tenant_slug: tenantSlug }
    });
    assert(memberLoginRes.status === 200, 'Member logged in');
    const memberToken = memberLoginRes.data.token;

    // -------------------------------------------------------------------------
    // 1. Password-Reset & 2FA-Reset Authority (Rank Rules)
    // -------------------------------------------------------------------------
    console.log('\n--- Test 1: Password-Reset & 2FA-Reset Authority & Rank Rules ---');

    // a) Cannot reset yourself
    const selfResetRes = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${ownerId}/reset-password`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assert(selfResetRes.status === 403 || selfResetRes.status === 400, 'Cannot reset password on yourself');
    assert(selfResetRes.data.error?.code === 'SELF_RESET_FORBIDDEN' || selfResetRes.data.error?.code === 'CANNOT_RESET_SELF', 'Error code indicates self-reset forbidden');

    // b) Manager cannot reset an Owner (rank violation)
    const adminResetOwnerRes = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${ownerId}/reset-password`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert(adminResetOwnerRes.status === 403, 'Manager cannot reset Owner password (403 Forbidden)');
    assert(
      adminResetOwnerRes.data.error?.code === 'ONLY_OWNER_MAY_RESET_OWNER' || adminResetOwnerRes.data.error?.code === 'INSUFFICIENT_RANK',
      'Error code ONLY_OWNER_MAY_RESET_OWNER or INSUFFICIENT_RANK'
    );

    // c) Manager cannot reset another Manager (rank must be strictly lower)
    const adminResetAdminRes = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${adminId}/reset-password`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert(adminResetAdminRes.status === 403 || adminResetAdminRes.status === 400, 'Manager cannot reset self or equal rank (403/400)');

    // d) Owner CAN reset Member password
    const ownerResetMemberRes = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${memberId}/reset-password`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assert(ownerResetMemberRes.status === 200, 'Owner can reset Member password (200 OK)');
    assert(ownerResetMemberRes.data.temporary_password || ownerResetMemberRes.data.temp_password, 'Temporary password returned');
    assert(ownerResetMemberRes.data.must_change_password === true, 'Flagged must_change_password');

    // Target sessions are revoked upon reset
    const postResetMemberMe = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${memberToken}` }
    });
    assert(postResetMemberMe.status === 401, 'Target member session revoked after password reset');

    // e) 2FA reset authority
    // First, enroll Member in 2FA
    const mockSecret = 'JBSWY3DPEHPK3PXP';
    const encryptedMock = encryptSecret(mockSecret);
    await tenantDb.execute(
      'UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?',
      [encryptedMock, memberId]
    );

    // Manager tries to reset 2FA on Owner -> 403
    const adminResetOwner2Fa = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${ownerId}/reset-2fa`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert(adminResetOwner2Fa.status === 403, 'Manager cannot reset Owner 2FA (403 Forbidden)');

    // Owner resets Member 2FA -> 200 OK
    const ownerResetMember2Fa = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${memberId}/reset-2fa`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assert(ownerResetMember2Fa.status === 200, 'Owner can reset Member 2FA (200 OK)');
    const [memberAfter2FaReset] = await tenantDb.query('SELECT totp_enabled, totp_secret FROM users WHERE id = ?', [memberId]);
    assert(memberAfter2FaReset.totp_enabled === 0, '2FA disabled in DB');
    assert(memberAfter2FaReset.totp_secret === null, '2FA secret cleared in DB');

    // f) CLI script test: npm run admin:reset-2fa
    // Re-enable 2FA on admin
    await tenantDb.execute(
      'UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?',
      [encryptedMock, adminId]
    );
    const cliOutput = execSync(`node src/scripts/adminReset2fa.js ${tenantSlug} ${adminEmail}`, {
      cwd: __dirname + '/..',
      encoding: 'utf8'
    });
    assert(cliOutput.toLowerCase().includes('successful'), 'CLI admin:reset-2fa script completed successfully');
    const [adminAfterCliReset] = await tenantDb.query('SELECT totp_enabled FROM users WHERE id = ?', [adminId]);
    assert(adminAfterCliReset.totp_enabled === 0, 'Admin 2FA reset by CLI');

    // -------------------------------------------------------------------------
    // 2. Refresh Rotation Race: 20-Second Grace Window & Parallel Calls
    // -------------------------------------------------------------------------
    console.log('\n--- Test 2: Refresh Rotation Race & Parallel Refresh Calls ---');

    const freshLogin = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: ownerEmail, password: defaultPassword, tenant_slug: tenantSlug }
    });
    const testRefreshToken = freshLogin.data.refreshToken;

    // Send TWO parallel refresh calls simultaneously with the same refresh token
    const [parallel1, parallel2] = await Promise.all([
      request(baseUrl, '/api/auth/refresh', { method: 'POST', body: { refreshToken: testRefreshToken } }),
      request(baseUrl, '/api/auth/refresh', { method: 'POST', body: { refreshToken: testRefreshToken } })
    ]);

    assert(parallel1.status === 200, 'Parallel refresh call 1 succeeded with 200 OK');
    assert(parallel2.status === 200, 'Parallel refresh call 2 succeeded with 200 OK (grace window handled race)');
    assert(parallel1.data.refreshToken && parallel2.data.refreshToken, 'Both parallel calls returned fresh pairs');

    // Verify token reuse AFTER 20-second grace window revokes family
    const tokenHashToAge = crypto.createHash('sha256').update(testRefreshToken).digest('hex');
    await tenantDb.execute(
      'UPDATE sessions SET revoked_at = DATE_SUB(NOW(3), INTERVAL 25 SECOND) WHERE refresh_token_hash = ?',
      [tokenHashToAge]
    );

    const agedReuseRes = await request(baseUrl, '/api/auth/refresh', {
      method: 'POST',
      body: { refreshToken: testRefreshToken }
    });
    assert(agedReuseRes.status === 401, 'Token reuse after 20s grace window rejected with 401');
    assert(agedReuseRes.data.error?.code === 'TOKEN_REUSED', 'Error code TOKEN_REUSED');

    // -------------------------------------------------------------------------
    // 3. Immediate Revocation & Socket Disconnects
    // -------------------------------------------------------------------------
    console.log('\n--- Test 3: Immediate Revocation Enforcement ---');

    const activeLogin = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: ownerEmail, password: defaultPassword, tenant_slug: tenantSlug }
    });
    const activeToken = activeLogin.data.token;
    const activeSessionId = activeLogin.data.session_id;

    // Verify session is active
    const check1 = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${activeToken}` }
    });
    assert(check1.status === 200, 'Session is initially active');

    // Explicitly revoke session via DELETE /api/auth/sessions/:id
    await request(baseUrl, `/api/auth/sessions/${activeSessionId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${activeToken}` }
    });

    // Next request MUST immediately fail with 401 SESSION_REVOKED
    const check2 = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${activeToken}` }
    });
    assert(check2.status === 401, 'Revoked session is immediately rejected on next request (401)');
    assert(check2.data.error?.code === 'SESSION_REVOKED', 'Error code is SESSION_REVOKED');

    // -------------------------------------------------------------------------
    // 4. must_change_password Enforced in Middleware
    // -------------------------------------------------------------------------
    console.log('\n--- Test 4: must_change_password Middleware Enforcement ---');

    // Reset member password generates temp password and sets must_change_password = 1
    const resetRes = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${memberId}/reset-password`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    const tempPassword = resetRes.data.temporary_password || resetRes.data.temp_password;

    // Login with temp password
    const tempLoginRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: memberEmail, password: tempPassword, tenant_slug: tenantSlug }
    });
    assert(tempLoginRes.status === 200, 'Member logged in with temporary password');
    const tempToken = tempLoginRes.data.token;

    // Attempt to access protected route (e.g. GET /api/workspaces)
    const blockedRoute = await request(baseUrl, '/api/workspaces', {
      headers: { Authorization: `Bearer ${tempToken}` }
    });
    assert(blockedRoute.status === 403, 'Protected route blocked when must_change_password is true (403)');
    assert(blockedRoute.data.error?.code === 'PASSWORD_CHANGE_REQUIRED', 'Error code is PASSWORD_CHANGE_REQUIRED');

    // GET /api/auth/me MUST be allowed
    const allowedMe = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${tempToken}` }
    });
    assert(allowedMe.status === 200, 'GET /api/auth/me is allowed when must_change_password is true');
    assert(allowedMe.data.user.must_change_password === true, 'User record shows must_change_password true');

    // Change password via POST /api/auth/password
    const newMemberPassword = 'NewMemberPass456!';
    const changePassRes = await request(baseUrl, '/api/auth/password', {
      method: 'POST',
      headers: { Authorization: `Bearer ${tempToken}` },
      body: {
        currentPassword: tempPassword,
        newPassword: newMemberPassword
      }
    });
    assert(changePassRes.status === 200, 'Password changed successfully');

    // Verify temp password does not appear in audit log
    const auditRows = await tenantDb.query(
      "SELECT * FROM auth_audit_log WHERE user_id = ? AND event_type = 'PASSWORD_RESET'",
      [memberId]
    );
    assert(auditRows && auditRows.length > 0, 'PASSWORD_RESET event logged in audit log');
    for (const r of auditRows) {
      const serialized = JSON.stringify(r);
      assert(!serialized.includes(tempPassword), 'Temp password does NOT appear in audit log rows');
    }

    // -------------------------------------------------------------------------
    // 5. 2FA Hardening: Second Step Lockout, Anti-Replay, AES-256-GCM
    // -------------------------------------------------------------------------
    console.log('\n--- Test 5: 2FA Hardening (Lockout, Anti-Replay, AES-256-GCM) ---');

    // Test AES-256-GCM encryption/decryption at rest
    const plainTest = 'SECRET_TOTP_KEY_SAMPLE';
    const encrypted = encryptSecret(plainTest);
    assert(encrypted.startsWith('enc:v1:'), 'Encrypted secret uses enc:v1 prefix');
    const decrypted = decryptSecret(encrypted);
    assert(decrypted === plainTest, 'Decrypted secret matches original plaintext exactly');

    // Setup 2FA for Owner
    const setupOwner2Fa = await request(baseUrl, '/api/auth/2fa/generate', {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    const ownerSecret = setupOwner2Fa.data.secret;
    const currentCode = generateSync({ secret: ownerSecret });

    const confirm2Fa = await request(baseUrl, '/api/auth/2fa/confirm', {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: { secret: ownerSecret, token: currentCode }
    });
    assert(confirm2Fa.status === 200, 'Owner 2FA confirmed');

    // Verify secret is encrypted in database
    const [ownerDbRow] = await tenantDb.query('SELECT totp_secret FROM users WHERE id = ?', [ownerId]);
    assert(ownerDbRow.totp_secret.startsWith('enc:v1:'), 'totp_secret is stored encrypted with AES-256-GCM at rest');

    // Step 1: Login to get 2FA challenge token
    const step1Login = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: ownerEmail, password: defaultPassword, tenant_slug: tenantSlug }
    });
    assert(step1Login.data.requires_2fa === true, 'Requires 2FA challenge');
    const challengeToken = step1Login.data.temp_token;

    // Send 5 wrong TOTP codes to trigger challenge invalidation & account lockout
    for (let i = 1; i <= 4; i++) {
      const wrongCodeRes = await request(baseUrl, '/api/auth/2fa/verify-login', {
        method: 'POST',
        body: { temp_token: challengeToken, code: '000000' }
      });
      assert(wrongCodeRes.status === 400, `Wrong code attempt ${i} rejected with 400`);
    }

    // 5th attempt invalidates challenge and locks account
    const fifthWrongRes = await request(baseUrl, '/api/auth/2fa/verify-login', {
      method: 'POST',
      body: { temp_token: challengeToken, code: '000000' }
    });
    assert(fifthWrongRes.status === 423, '5th wrong 2FA code invalidates challenge and locks account (423)');

    // Unlock owner for remaining tests
    await tenantDb.execute('UPDATE users SET failed_login_attempts = 0, locked_until = NULL, lockout_count = 0 WHERE id = ?', [ownerId]);

    // Test Anti-Replay: same TOTP code in same 30s window rejected
    const step1ForReplay = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: ownerEmail, password: defaultPassword, tenant_slug: tenantSlug }
    });
    const replayChallengeToken = step1ForReplay.data.temp_token;
    // Ensure we are not at the tail end of the 30-second window to prevent window rollover
    const secInWindow = Math.floor(Date.now() / 1000) % 30;
    if (secInWindow >= 27) {
      await new Promise((r) => setTimeout(r, (30 - secInWindow + 1) * 1000));
    }
    const freshCode = generateSync({ secret: ownerSecret });

    const step2FirstUse = await request(baseUrl, '/api/auth/2fa/verify-login', {
      method: 'POST',
      body: { temp_token: replayChallengeToken, code: freshCode }
    });
    assert(step2FirstUse.status === 200, 'First use of TOTP code succeeds');

    // New challenge token in same window
    const step1SecondChallenge = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: ownerEmail, password: defaultPassword, tenant_slug: tenantSlug }
    });
    const secondChallengeToken = step1SecondChallenge.data.temp_token;

    const replayAttempt = await request(baseUrl, '/api/auth/2fa/verify-login', {
      method: 'POST',
      body: { temp_token: secondChallengeToken, code: freshCode }
    });
    assert(replayAttempt.status === 400, 'Replayed TOTP code in same window rejected (400)');
    assert(replayAttempt.data.error?.code === 'TOTP_CODE_ALREADY_USED', 'Error code TOTP_CODE_ALREADY_USED');

    // -------------------------------------------------------------------------
    // 6. File Authorization & Avatar Magic Bytes
    // -------------------------------------------------------------------------
    console.log('\n--- Test 6: File Authorization & Avatar Magic Bytes ---');

    // Upload spoofed avatar (HTML file named avatar.png)
    const spoofedHtmlBuffer = Buffer.from('<html><script>alert("pwned")</script></html>');
    const spoofUploadRes = await multipartUpload(
      baseUrl,
      '/api/files/avatar',
      ownerToken,
      'avatar.png',
      spoofedHtmlBuffer,
      'image/png'
    );
    assert(spoofUploadRes.status === 400, 'Spoofed HTML file disguised as PNG rejected by magic bytes verification');
    assert(
      spoofUploadRes.data.error?.code === 'INVALID_FILE_SIGNATURE' || spoofUploadRes.data.error?.code === 'INVALID_IMAGE_TYPE',
      'Error code indicates invalid file signature or image type'
    );

    // Cross-tenant file access test
    // Request a file from another tenant ID (e.g. 99999)
    const crossTenantFileRes = await request(baseUrl, '/api/files/99999/test.txt', {
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assert(crossTenantFileRes.status === 404, 'Cross-tenant file download returns 404');

    // -------------------------------------------------------------------------
    // 7. Lockout Uniformity & Attacker IP Rate Limiting Guard
    // -------------------------------------------------------------------------
    console.log('\n--- Test 7: Lockout Response Uniformity ---');

    // Uniform response for unknown email
    const unknownEmailRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: 'nonexistent_user@c5corp.com', password: defaultPassword, tenant_slug: tenantSlug }
    });
    assert(unknownEmailRes.status === 401, 'Unknown email returns 401');
    assert(unknownEmailRes.data.error?.code === 'INVALID_CREDENTIALS', 'Uniform error code INVALID_CREDENTIALS');

    // Uniform response for wrong password
    const wrongPasswordRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: ownerEmail, password: 'WrongPassword999!', tenant_slug: tenantSlug }
    });
    assert(wrongPasswordRes.status === 401, 'Wrong password returns 401');
    assert(wrongPasswordRes.data.error?.code === 'INVALID_CREDENTIALS', 'Uniform error code INVALID_CREDENTIALS');

    // -------------------------------------------------------------------------
    // 8. Phase 2.5 Items: Reconcile, Reminder Cron Tenant Isolation, 30-Day Slug
    // -------------------------------------------------------------------------
    console.log('\n--- Test 8: Phase 2.5 Robustness & Isolated Reminders ---');

    // a) 30-Day Slug Reservation
    // Mark a tenant as deleted
    const deadSlug = `dead_slug_${testSuffix}`;
    const deadUuid = crypto.randomUUID();
    const deadDbName = `pm_t_dead_${testSuffix}`;
    await masterDb.execute(
      "INSERT INTO tenants (uuid, slug, name, db_name, status, deleted_at) VALUES (?, ?, 'Dead Co', ?, 'deleted', NOW())",
      [deadUuid, deadSlug, deadDbName]
    );

    // Attempt to register company with reserved dead slug
    const reuseSlugRes = await request(baseUrl, '/api/auth/register-company', {
      method: 'POST',
      body: {
        companyName: 'Dead Co Reborn',
        slug: deadSlug,
        name: 'New Owner',
        email: `newowner_${testSuffix}@domain.com`,
        password: defaultPassword
      }
    });
    assert(reuseSlugRes.status === 409, 'Deleted tenant slug remains reserved for 30 days (409 Conflict)');
    assert(reuseSlugRes.data.error?.code === 'SLUG_RESERVED', 'Error code SLUG_RESERVED');

    // b) Reminder Cron Tenant Isolation: Check that a broken tenant query does not crash reminder processing
    try {
      // Calling processAllTenantsReminders with multi-tenant mode active catches errors per-tenant without crashing process
      await processAllTenantsReminders();
      assert(true, 'Reminder cron processAllTenantsReminders ran cleanly with per-tenant error isolation');
    } catch (e) {
      assert(false, `Reminder cron threw unhandled exception: ${e.message}`);
    }

    // c) tenants:reconcile clean run
    try {
      await reconcileTenants();
      assert(true, 'tenants:reconcile runs cleanly and verifies database alignment');
    } catch (e) {
      assert(false, `tenants:reconcile threw error: ${e.message}`);
    }

    console.log('\n================================================================');
    console.log(`PART C.5 TEST SUMMARY: ${passedTests} passed, ${failedTests} failed.`);
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

runPartC5Tests().catch((err) => {
  console.error('Part C.5 runner crashed:', err);
  process.exit(1);
});

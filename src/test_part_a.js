// server/src/test_part_a.js
// Comprehensive test suite for Part A requirements:
// 1. VERIFICATION_MODE=off (immediate provisioning) & VERIFICATION_MODE=on (OTP flow)
// 2. REGISTRATION_ENABLED=false flag
// 3. Slug and email conflict checks
// 4. In-app password reset with member.reset_password & must_change_password enforcement
// 5. CLI admin:reset-password script execution
// 6. Signed, tenant-scoped, 7-day expiring, single-use, revocable invitations
// 7. Notification preferences with email channel hidden

require('dotenv').config();
const http = require('http');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { execSync } = require('child_process');
const path = require('path');

const { getMasterDb, getTenantDb, closeAllPools } = require('./services/tenantPools');
const { dropTenantDatabase } = require('./services/tenantProvisioner');
const { EmailProvider } = require('./services/providers');
const migrator = require('./db/migrator');

const authRouter = require('./routes/auth');
const workspacesRouter = require('./routes/workspaces');
const invitationsRouter = require('./routes/invitations');
const notificationsRouter = require('./routes/notifications');

let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
  if (!condition) {
    console.error(`  ❌ FAILED: ${message}`);
    failedTests++;
    throw new Error(message);
  } else {
    console.log(`  ✓ ${message}`);
    passedTests++;
  }
}

async function request(baseUrl, path, options = {}) {
  const url = `${baseUrl}${path}`;
  const headers = { ...(options.headers || {}) };
  let body = options.body;

  if (body && typeof body === 'object' && !(body instanceof Buffer)) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }

  const res = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body
  });

  const contentType = res.headers.get('content-type') || '';
  let data;
  if (contentType.includes('application/json')) {
    data = await res.json();
  } else {
    data = await res.text();
  }

  return { status: res.status, headers: res.headers, data };
}

async function runPartATests() {
  console.log('================================================================');
  console.log('                 PART A VERIFICATION & AUTH TESTS               ');
  console.log('================================================================\n');

  await migrator.migrateMaster();

  const app = express();
  app.use(cors({ origin: true, credentials: true }));
  app.use(cookieParser());
  app.use(express.json());

  app.use('/api/auth', authRouter);
  app.use('/api/workspaces', workspacesRouter);
  app.use('/api/invitations', invitationsRouter);
  app.use('/api/notifications', notificationsRouter);

  app.use((err, req, res, next) => {
    const status = err.status || 400;
    res.status(status).json({ error: { message: err.message, code: err.code || 'BAD_REQUEST' } });
  });

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const masterDb = getMasterDb();

  try {
    // Cleanup any existing test tenants
    const testSlugs = ['parta_off_corp', 'parta_on_corp'];
    for (const slug of testSlugs) {
      const existing = await masterDb.query(
        'SELECT id, db_name FROM tenants WHERE slug = ?',
        [slug]
      );
      for (const t of existing) {
        try {
          await dropTenantDatabase(t.db_name);
        } catch (e) {}
        await masterDb.execute('DELETE FROM tenants WHERE id = ?', [t.id]);
        await masterDb.execute('DELETE FROM tenant_user_directory WHERE tenant_id = ?', [t.id]);
      }
      await masterDb.execute('DELETE FROM pending_registrations WHERE slug = ?', [slug]);
    }

    // -------------------------------------------------------------
    // Test 1: REGISTRATION_ENABLED=false blocks registration
    // -------------------------------------------------------------
    console.log('--- Test 1: REGISTRATION_ENABLED Flag ---');
    process.env.REGISTRATION_ENABLED = 'false';

    const disabledRegRes = await request(baseUrl, '/api/auth/register-company', {
      method: 'POST',
      body: {
        company_name: 'Part A Blocked Corp',
        slug: 'parta_blocked',
        admin_name: 'Alice Blocked',
        admin_email: 'alice@blocked.com',
        admin_password: 'Password123!'
      }
    });

    assert(disabledRegRes.status === 403, 'Registration returns 403 when REGISTRATION_ENABLED=false');
    assert(disabledRegRes.data.error?.code === 'REGISTRATION_DISABLED', 'Error code is REGISTRATION_DISABLED');

    // Restore registration
    process.env.REGISTRATION_ENABLED = 'true';

    // -------------------------------------------------------------
    // Test 2: VERIFICATION_MODE=off (Immediate Provisioning)
    // -------------------------------------------------------------
    console.log('\n--- Test 2: VERIFICATION_MODE=off (Default Immediate Provisioning) ---');
    process.env.VERIFICATION_MODE = 'off';

    const directRegRes = await request(baseUrl, '/api/auth/register-company', {
      method: 'POST',
      body: {
        company_name: 'Part A Off Corp',
        slug: 'parta_off_corp',
        admin_name: 'Alice Direct',
        admin_email: 'alice@parta-off.com',
        admin_password: 'Password123!'
      }
    });

    assert(directRegRes.status === 201, 'Returns 201 Created immediately without OTP');
    assert(directRegRes.data.tenant && directRegRes.data.tenant.slug === 'parta_off_corp', 'Tenant created and returned in payload');
    assert(directRegRes.data.user && directRegRes.data.user.email === 'alice@parta-off.com', 'Owner user returned');
    assert(directRegRes.data.token, 'Owner JWT token returned immediately');
    const ownerToken = directRegRes.data.token;
    const tenantOffId = directRegRes.data.tenant.id;
    const workspaceOffId = directRegRes.data.initial_workspace_id;

    // Verify owner can access their workspace immediately
    const meRes = await request(baseUrl, '/api/auth/me', {
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assert(meRes.status === 200, 'Owner authenticated successfully with returned token');
    assert(meRes.data.user.email === 'alice@parta-off.com', 'Authenticated user matches registered owner');

    // -------------------------------------------------------------
    // Test 3: Uniqueness Conflicts (Slug and Email)
    // -------------------------------------------------------------
    console.log('\n--- Test 3: Slug & Email Uniqueness Checks ---');
    const dupSlugRes = await request(baseUrl, '/api/auth/register-company', {
      method: 'POST',
      body: {
        company_name: 'Duplicate Slug Corp',
        slug: 'parta_off_corp',
        admin_name: 'Bob Duplicate',
        admin_email: 'bob@other.com',
        admin_password: 'Password123!'
      }
    });
    assert(dupSlugRes.status === 409, 'Duplicate slug rejected with 409 Conflict');
    assert(dupSlugRes.data.error?.code === 'SLUG_CONFLICT', 'Error code is SLUG_CONFLICT');

    const dupEmailRes = await request(baseUrl, '/api/auth/register-company', {
      method: 'POST',
      body: {
        company_name: 'Different Slug Corp',
        slug: 'different_slug_corp',
        admin_name: 'Alice Impersonator',
        admin_email: 'alice@parta-off.com',
        admin_password: 'Password123!'
      }
    });
    assert(dupEmailRes.status === 409, 'Duplicate registered email rejected with 409 Conflict');
    assert(dupEmailRes.data.error?.code === 'EMAIL_CONFLICT', 'Error code is EMAIL_CONFLICT');

    // -------------------------------------------------------------
    // Test 4: VERIFICATION_MODE=on (OTP & Pending Registration Flow)
    // -------------------------------------------------------------
    console.log('\n--- Test 4: VERIFICATION_MODE=on (OTP Flow) ---');
    process.env.VERIFICATION_MODE = 'on';
    EmailProvider.clearHistory();

    const otpRegRes = await request(baseUrl, '/api/auth/register-company', {
      method: 'POST',
      body: {
        company_name: 'Part A On Corp',
        slug: 'parta_on_corp',
        admin_name: 'Charlie On',
        admin_email: 'charlie@parta-on.com',
        admin_password: 'Password123!'
      }
    });

    assert(otpRegRes.status === 200, 'Returns 200 with pending verification');
    assert(otpRegRes.data.verification_id, 'Verification ID returned');
    assert(otpRegRes.data.token === undefined, 'No auth token returned before OTP verification');

    const lastMsg = EmailProvider.getLastMessage('charlie@parta-on.com');
    assert(lastMsg && lastMsg.otp, 'OTP captured by EmailProvider');

    const verifyOtpRes = await request(baseUrl, '/api/auth/verify-registration', {
      method: 'POST',
      body: {
        verification_id: otpRegRes.data.verification_id,
        otp: lastMsg.otp
      }
    });
    assert(verifyOtpRes.status === 201, 'Valid OTP verified and tenant provisioned with 201 Created');
    assert(verifyOtpRes.data.token, 'Auth token returned after OTP verification');

    // Reset VERIFICATION_MODE back to default "off"
    process.env.VERIFICATION_MODE = 'off';

    // -------------------------------------------------------------
    // Test 5: In-App Password Reset with member.reset_password
    // -------------------------------------------------------------
    console.log('\n--- Test 5: In-App Member Password Reset (Zero-Email) ---');

    // Seed a team member in tenantOffId
    const tenantOffDb = await getTenantDb(tenantOffId);
    const bcrypt = require('bcryptjs');
    const memberPassHash = await bcrypt.hash('MemberInitialPass123!', 10);
    const insMember = await tenantOffDb.execute(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      ['Dave Member', 'dave@parta-off.com', memberPassHash]
    );
    const memberUserId = insMember.insertId;

    const teamMemberRoleRes = await tenantOffDb.query(
      "SELECT id FROM roles WHERE is_system = 1 AND name = 'Team Member' AND workspace_id IS NULL"
    );
    await tenantOffDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)',
      [workspaceOffId, memberUserId, 'Team Member', teamMemberRoleRes[0]?.id]
    );

    // Initial login of member
    const memberLoginRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: 'dave@parta-off.com',
        password: 'MemberInitialPass123!',
        tenant_slug: 'parta_off_corp'
      }
    });
    assert(memberLoginRes.status === 200, 'Member logged in successfully');
    assert(memberLoginRes.data.user.must_change_password === false, 'must_change_password is initially false');

    // Owner (has Super Admin role with member.reset_password) resets member's password
    const resetRes = await request(baseUrl, `/api/workspaces/${workspaceOffId}/members/${memberUserId}/reset-password`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: {}
    });
    assert(resetRes.status === 200, 'Owner successfully reset member password');
    assert(resetRes.data.temporary_password, 'Temporary password returned to admin');
    assert(resetRes.data.must_change_password === true, 'must_change_password set to true');
    const tempPassword = resetRes.data.temporary_password;

    // Member logs in with temporary password
    const tempLoginRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: 'dave@parta-off.com',
        password: tempPassword,
        tenant_slug: 'parta_off_corp'
      }
    });
    assert(tempLoginRes.status === 200, 'Member logged in with temporary password');
    assert(tempLoginRes.data.user.must_change_password === true, 'Response requires must_change_password: true');
    const memberToken = tempLoginRes.data.token;

    // Member changes password
    const changePassRes = await request(baseUrl, '/api/auth/password', {
      method: 'PUT',
      headers: { Authorization: `Bearer ${memberToken}` },
      body: {
        currentPassword: tempPassword,
        newPassword: 'MyNewSecurePassword456!'
      }
    });
    assert(changePassRes.status === 200, 'Member successfully changed password');
    assert(changePassRes.data.must_change_password === false, 'must_change_password cleared to false');

    // Member logs in with new password
    const newLoginRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: 'dave@parta-off.com',
        password: 'MyNewSecurePassword456!',
        tenant_slug: 'parta_off_corp'
      }
    });
    assert(newLoginRes.status === 200, 'Member logged in with new password');
    assert(newLoginRes.data.user.must_change_password === false, 'must_change_password is now false');

    // Member without permission attempting to reset someone else's password gets 403
    const unauthorizedResetRes = await request(baseUrl, `/api/workspaces/${workspaceOffId}/members/${memberUserId}/reset-password`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${newLoginRes.data.token}` },
      body: {}
    });
    assert(unauthorizedResetRes.status === 403, 'Member without permission is blocked with 403 Forbidden');

    // -------------------------------------------------------------
    // Test 6: CLI Script admin:reset-password
    // -------------------------------------------------------------
    console.log('\n--- Test 6: CLI Script admin:reset-password ---');
    const scriptPath = path.join(__dirname, 'scripts', 'adminResetPassword.js');
    const cmd = `node "${scriptPath}" parta_off_corp dave@parta-off.com`;
    const cliOutput = execSync(cmd, { encoding: 'utf8' });
    assert(cliOutput.includes('ADMIN PASSWORD RESET SUCCESS'), 'CLI script succeeded');
    const tempMatch = cliOutput.match(/Temporary Password:\s*(\S+)/);
    assert(tempMatch && tempMatch[1], 'Temporary password extracted from CLI output');
    const cliTempPassword = tempMatch[1];

    // Verify member can log in with CLI-generated temporary password and has must_change_password=true
    const cliTempLoginRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: 'dave@parta-off.com',
        password: cliTempPassword,
        tenant_slug: 'parta_off_corp'
      }
    });
    assert(cliTempLoginRes.status === 200, 'Member logged in with CLI-generated temporary password');
    assert(cliTempLoginRes.data.user.must_change_password === true, 'CLI reset enforces must_change_password');

    // -------------------------------------------------------------
    // Test 7: Invitations (Signed, Expiring, Single-Use, Revocable)
    // -------------------------------------------------------------
    console.log('\n--- Test 7: Signed, Expiring, Single-Use, Revocable Invitations ---');

    // 1. Generate invitation link
    const inviteRes = await request(baseUrl, '/api/invitations', {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: {
        email: 'newuser@parta-off.com',
        workspace_id: workspaceOffId
      }
    });
    assert(inviteRes.status === 202, 'Invitation link created with 202 Accepted');
    assert(inviteRes.data.invite_token, 'Signed invite token returned');
    const inviteToken = inviteRes.data.invite_token;
    assert(inviteToken.includes('.'), 'Token has HMAC signature appended');

    // 2. Public verification of invitation link
    const verifyInviteRes = await request(baseUrl, `/api/invitations/verify?token=${encodeURIComponent(inviteToken)}`);
    assert(verifyInviteRes.status === 200, 'Valid signed invitation verified');
    assert(verifyInviteRes.data.invitation.email === 'newuser@parta-off.com', 'Verified invitation has correct email');

    // 3. Tampered token signature fails
    const tamperedToken = `${inviteToken.split('.')[0]}.tampered_sig_12345`;
    const tamperedVerifyRes = await request(baseUrl, `/api/invitations/verify?token=${encodeURIComponent(tamperedToken)}`);
    assert(tamperedVerifyRes.status === 400, 'Tampered signature rejected with 400 Bad Request');

    // 4. Revocation of invitation
    const listInvitesRes = await request(baseUrl, `/api/invitations?workspace_id=${workspaceOffId}`, {
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    const invId = listInvitesRes.data.invitations[0]?.id;
    assert(invId, 'Found pending invitation ID in workspace');

    const revokeRes = await request(baseUrl, `/api/invitations/${invId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assert(revokeRes.status === 200, 'Invitation revoked successfully');

    const verifyRevokedRes = await request(baseUrl, `/api/invitations/verify?token=${encodeURIComponent(inviteToken)}`);
    assert(verifyRevokedRes.status === 404 || verifyRevokedRes.status === 410, 'Revoked invitation rejected with 404/410');

    // 5. Expiration check: create an expired invitation directly in DB
    const crypto = require('crypto');
    const rawExpired = crypto.randomBytes(20).toString('hex');
    const hmac = crypto.createHmac('sha256', process.env.JWT_SECRET || 'invitation_secret');
    const sigExpired = hmac.update(`parta_off_corp:${rawExpired}`).digest('hex').slice(0, 16);
    const expiredToken = `parta_off_corp.${rawExpired}.${sigExpired}`;
    const pastDate = new Date(Date.now() - 1000 * 60 * 60 * 24); // 1 day ago

    await tenantOffDb.execute(
      `INSERT INTO pending_invitations (email, workspace_id, invited_by_user_id, token, status, expires_at)
       VALUES (?, ?, 1, ?, 'pending', ?)`,
      ['expired@parta-off.com', workspaceOffId, expiredToken, pastDate]
    );

    const expiredVerifyRes = await request(baseUrl, `/api/invitations/verify?token=${encodeURIComponent(expiredToken)}`);
    assert(expiredVerifyRes.status === 410, 'Expired invitation rejected with 410 Gone');
    assert(expiredVerifyRes.data.error?.code === 'INVITATION_EXPIRED', 'Error code is INVITATION_EXPIRED');

    // 6. Single-use check: register with a new invitation
    const freshInviteRes = await request(baseUrl, '/api/invitations', {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: {
        email: 'singleuse@parta-off.com',
        workspace_id: workspaceOffId
      }
    });
    const singleUseToken = freshInviteRes.data.invite_token;

    const regWithInviteRes = await request(baseUrl, '/api/auth/register', {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` }, // sets tenant context
      body: {
        name: 'Single Use User',
        email: 'singleuse@parta-off.com',
        password: 'Password123!',
        invite_token: singleUseToken
      }
    });
    assert(regWithInviteRes.status === 201, 'User registered successfully using invitation link');

    // Reusing the token must fail (single-use)
    const reuseVerifyRes = await request(baseUrl, `/api/invitations/verify?token=${encodeURIComponent(singleUseToken)}`);
    assert(reuseVerifyRes.status === 410, 'Re-verifying used invitation returns 410 Gone (single use)');

    // -------------------------------------------------------------
    // Test 8: Notification Preferences: Email Channel Hidden
    // -------------------------------------------------------------
    console.log('\n--- Test 8: Notification Preferences (Email Channel Hidden) ---');
    const prefsRes = await request(baseUrl, '/api/notifications/preferences', {
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    assert(prefsRes.status === 200, 'Notification preferences fetched successfully');
    const categories = prefsRes.data.preferences || {};
    let foundEmail = false;
    for (const group of Object.values(categories)) {
      for (const item of group) {
        if (item.email !== undefined) foundEmail = true;
      }
    }
    assert(!foundEmail, 'Email channel is completely hidden from notification preferences');

    console.log('\n================================================================');
    console.log(`PART A TEST SUMMARY: ${passedTests} passed, ${failedTests} failed.`);
    console.log('================================================================\n');
  } finally {
    server.close();
    await closeAllPools();
    process.exit(failedTests > 0 ? 1 : 0);
  }
}

runPartATests().catch((err) => {
  console.error('Test suite runner crashed:', err);
  process.exit(1);
});

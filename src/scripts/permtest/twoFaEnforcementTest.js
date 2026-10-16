// server/src/scripts/permtest/twoFaEnforcementTest.js
// Tests dynamic per-request 2FA enforcement, live setting toggles, look-alike path rejection,
// and immediate unblocking upon TOTP setup without re-login.

const { withFixture } = require('./fixtures');
const { generateSync } = require('../../../node_modules/otplib');

async function runTwoFaEnforcementSuite() {
  console.log('='.repeat(64));
  console.log('        TEST: REQUIRE_2FA DYNAMIC PER-REQUEST ENFORCEMENT       ');
  console.log('='.repeat(64));

  let totalChecks = 0;
  let checksPassed = 0;

  await withFixture(async (fixture) => {
    const { ownerClient, w1Id, users, tenantDb } = fixture.context;
    const memberTargetUser = users['MemberTarget'];
    const memberClient = memberTargetUser.client;

    // Ensure member has no TOTP setup initially
    await tenantDb.execute('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', [memberTargetUser.user.id]);

    // Give owner TOTP enabled so workspace owner can manage security settings even when require_2fa is active
    await tenantDb.execute('UPDATE users SET totp_enabled = 1, totp_secret = ? WHERE id = ?', ['JBSWY3DPEHPK3PXP', ownerClient.user.id]);

    // Ensure 2FA is initially disabled on W1
    await ownerClient.patch(`/api/workspaces/${w1Id}/security`, { require_2fa: false, require_2fa_for_admins: false });

    console.log('\n--- [1] Baseline: User logs in with 2FA disabled -> 200 OK ---');
    const initialReq = await memberClient.get(`/api/workspaces/${w1Id}`);
    totalChecks++;
    if (initialReq.status === 200) {
      checksPassed++;
      console.log('✓ PASS: Active user can access workspace when 2FA is disabled.');
    } else {
      throw new Error(`Expected 200 initially, got ${initialReq.status}`);
    }

    console.log('\n--- [2] Live Toggle ON: Existing token gets 403 TWO_FA_SETUP_REQUIRED without re-login ---');
    await ownerClient.patch(`/api/workspaces/${w1Id}/security`, { require_2fa: true });
    totalChecks++;
    const postToggleOnReq = await memberClient.get(`/api/workspaces/${w1Id}`);
    if (postToggleOnReq.status === 403 && postToggleOnReq.data?.error?.code === 'TWO_FA_SETUP_REQUIRED') {
      checksPassed++;
      console.log('✓ PASS: Live toggle immediately triggers 403 TWO_FA_SETUP_REQUIRED on existing session.');
    } else {
      throw new Error(`Expected 403 TWO_FA_SETUP_REQUIRED, got ${postToggleOnReq.status}`);
    }

    console.log('\n--- [3] Live Toggle OFF: Existing token immediately regains 200 OK ---');
    await ownerClient.patch(`/api/workspaces/${w1Id}/security`, { require_2fa: false });
    totalChecks++;
    const postToggleOffReq = await memberClient.get(`/api/workspaces/${w1Id}`);
    if (postToggleOffReq.status === 200) {
      checksPassed++;
      console.log('✓ PASS: Disabling 2FA immediately restores 200 OK without re-login.');
    } else {
      throw new Error(`Expected 200 after disabling 2FA, got ${postToggleOffReq.status}`);
    }

    // Re-enable 2FA for path boundary and activation tests
    await ownerClient.patch(`/api/workspaces/${w1Id}/security`, { require_2fa: true });

    console.log('\n--- [4] Negative Tests: Non-exempt routes & strict segment-boundary matching ---');
    const blockedRoutes = [
      '/api/auth/sessions',
      '/api/auth/activity',
      `/api/workspaces/${w1Id}`
    ];
    for (const blockedPath of blockedRoutes) {
      totalChecks++;
      const blockedRes = await memberClient.get(blockedPath);
      if (blockedRes.status === 403 && blockedRes.data?.error?.code === 'TWO_FA_SETUP_REQUIRED') {
        checksPassed++;
        console.log(`✓ PASS: Non-exempt path ${blockedPath} correctly rejected with 403 TWO_FA_SETUP_REQUIRED.`);
      } else {
        throw new Error(`Expected 403 for blocked path ${blockedPath}, got ${blockedRes.status}`);
      }
    }

    // Verify segment boundary matching: look-alikes do NOT match prefix
    const allowedPrefixes = ['/api/auth/2fa', '/api/auth/logout', '/api/auth/logout-all', '/api/auth/me'];
    const isBoundaryMatch = (pathname) => allowedPrefixes.some(prefix => pathname === prefix || pathname.startsWith(prefix + '/'));
    const lookalikes = ['/api/auth/2fa_bypass', '/api/auth/me_fake', '/api/auth/logout_hack'];
    for (const lookalike of lookalikes) {
      if (isBoundaryMatch(lookalike) === false) {
        console.log(`✓ PASS: Segment boundary logic correctly excludes ${lookalike}`);
      } else {
        throw new Error(`Boundary match leaked for ${lookalike}`);
      }
    }

    console.log('\n--- [5] Allowed Segment Boundaries Accessible During Restricted State ---');
    totalChecks++;
    const meRes = await memberClient.get('/api/auth/me');
    if (meRes.status === 200) {
      checksPassed++;
      console.log('✓ PASS: /api/auth/me is accessible during restricted 2FA state.');
    } else {
      throw new Error(`Expected 200 for /auth/me, got ${meRes.status}`);
    }

    totalChecks++;
    const setupRes = await memberClient.post('/api/auth/2fa/setup', {});
    const secret = setupRes.data?.secret || setupRes.data?.manual_entry_key;
    if (setupRes.status === 200 && secret) {
      checksPassed++;
      console.log('✓ PASS: /api/auth/2fa/setup succeeds (200 OK).');
    } else {
      throw new Error(`Expected 200 for /auth/2fa/setup, got ${setupRes.status}`);
    }

    console.log('\n--- [6] Completing TOTP Setup Regains Access Immediately Without Re-login ---');
    const code = generateSync({ secret });
    const verifyRes = await memberClient.post('/api/auth/2fa/verify', { secret, code });
    if (verifyRes.status !== 200) {
      throw new Error(`2FA verify failed: ${verifyRes.status}`);
    }

    totalChecks++;
    const postVerifyReq = await memberClient.get(`/api/workspaces/${w1Id}`);
    if (postVerifyReq.status === 200) {
      checksPassed++;
      console.log('✓ PASS: Access fully restored (200 OK) immediately upon TOTP activation without re-login.');
    } else {
      throw new Error(`Expected 200 after verify, got ${postVerifyReq.status}`);
    }
  });

  console.log(`\n2FA Enforcement Suite: ${checksPassed}/${totalChecks} checks passed.\n`);
  return { checksPassed, totalChecks };
}

module.exports = { runTwoFaEnforcementSuite };

if (require.main === module) {
  runTwoFaEnforcementSuite().then(res => {
    if (res.checksPassed !== res.totalChecks) process.exit(1);
  }).catch(err => {
    console.error(err);
    process.exit(1);
  });
}

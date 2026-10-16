// server/src/scripts/permtest/deactivationTest.js
// Comprehensive test suite for company-level deactivation, member removal, and session handling.

const { withFixture } = require('./fixtures');
const { PermtestClient } = require('./client');

async function runDeactivationSuite() {
  console.log('='.repeat(64));
  console.log('        TEST: COMPANY-LEVEL DEACTIVATION & OFFBOARDING          ');
  console.log('='.repeat(64));

  await withFixture(async (fixture) => {
    const { ownerClient, w1Id, w2Id, users, tenantDb } = fixture.context;
    const memberClient = users['Team Member'].client;
    const memberTargetUser = users['MemberTarget'];
    const memberTargetClient = memberTargetUser.client;
    const memberTargetId = memberTargetUser.user.id;
    const ownerId = ownerClient.user.id;

    console.log('\n--- [1] Multi-Workspace Setup for Target User ---');
    // Add memberTarget to W2 as well
    const teamMemberRole = (await tenantDb.query("SELECT id FROM roles WHERE name = 'Team Member' AND workspace_id IS NULL"))[0];
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role_id, status) VALUES (?, ?, ?, ?)',
      [w2Id, memberTargetId, teamMemberRole.id, 'active']
    );

    // Verify user is active in both W1 and W2
    const initMemberships = await tenantDb.query(
      'SELECT workspace_id, status FROM workspace_members WHERE user_id = ?',
      [memberTargetId]
    );
    if (initMemberships.length !== 2 || !initMemberships.every(m => m.status === 'active')) {
      throw new Error(`Expected 2 active memberships, got: ${JSON.stringify(initMemberships)}`);
    }
    console.log('✓ PASS: Target user actively belongs to both Workspace 1 and Workspace 2.');

    console.log('\n--- [2] Self-Deactivation Guard ---');
    const selfDeact = await ownerClient.post(`/api/workspaces/${w1Id}/members/${ownerId}/deactivate`, {});
    if (selfDeact.status !== 400 || selfDeact.data?.error?.code !== 'SELF_DEACTIVATION_FORBIDDEN') {
      throw new Error(`Self-deactivation guard failed: expected 400 SELF_DEACTIVATION_FORBIDDEN, got ${selfDeact.status}`);
    }
    console.log('✓ PASS: Self-deactivation strictly rejected with 400 SELF_DEACTIVATION_FORBIDDEN.');

    console.log('\n--- [3] Rank Rule Guard ---');
    // Admin (rank 80, has member.deactivate) attempting to deactivate Owner (rank 100)
    const adminClient = users['Admin'].client;
    const rankDeact = await adminClient.post(`/api/workspaces/${w1Id}/members/${ownerId}/deactivate`, {});
    if (rankDeact.status !== 403 || rankDeact.data?.error?.code !== 'FORBIDDEN') {
      throw new Error(`Rank rule failed: expected 403 FORBIDDEN, got ${rankDeact.status} ${JSON.stringify(rankDeact.data)}`);
    }
    console.log('✓ PASS: Equal or higher rank deactivation strictly rejected with 403 FORBIDDEN.');

    console.log('\n--- [4] Last-Owner Protection Guard ---');
    // Attempting to deactivate Owner when Owner is sole owner of W1
    // We already tested self-deactivation, now let's promote memberTarget to Owner in W2, and try deactivating them
    const ownerRole = (await tenantDb.query("SELECT id FROM roles WHERE name = 'Owner' AND workspace_id IS NULL"))[0];
    // Remove real owner from W2 so memberTarget is the ONLY owner in W2
    await tenantDb.execute('DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?', [w2Id, ownerId]);
    await tenantDb.execute('UPDATE workspace_members SET role_id = ? WHERE workspace_id = ? AND user_id = ?', [ownerRole.id, w2Id, memberTargetId]);

    // Now attempt to deactivate memberTarget from W1: they are last owner in W2!
    const lastOwnerDeact = await ownerClient.post(`/api/workspaces/${w1Id}/members/${memberTargetId}/deactivate`, {});
    if (lastOwnerDeact.status !== 400 || lastOwnerDeact.data?.error?.code !== 'LAST_OWNER') {
      throw new Error(`Last-Owner guard failed: expected 400 LAST_OWNER, got ${lastOwnerDeact.status} ${JSON.stringify(lastOwnerDeact.data)}`);
    }
    console.log('✓ PASS: Deactivating last Owner of any workspace blocked with 400 LAST_OWNER.');

    // Restore W2 owner and demote memberTarget back to Team Member
    await tenantDb.execute('INSERT INTO workspace_members (workspace_id, user_id, role_id, status) VALUES (?, ?, ?, ?)', [w2Id, ownerId, ownerRole.id, 'active']);
    await tenantDb.execute('UPDATE workspace_members SET role_id = ? WHERE workspace_id = ? AND user_id = ?', [teamMemberRole.id, w2Id, memberTargetId]);

    console.log('\n--- [5] Company-Level Deactivation Execution ---');
    // Ensure memberTarget has an active session
    const preLogin = await memberTargetClient.post('/api/auth/login', {
      email: memberTargetUser.email,
      password: memberTargetUser.password
    });
    if (preLogin.status !== 200) {
      throw new Error(`Target pre-login failed with ${preLogin.status}`);
    }
    const targetToken = preLogin.data.token;
    const targetRefreshToken = preLogin.data.refreshToken;

    // Owner deactivates memberTarget
    const deactRes = await ownerClient.post(`/api/workspaces/${w1Id}/members/${memberTargetId}/deactivate`, {});
    if (deactRes.status !== 200 || deactRes.data.status !== 'deactivated') {
      throw new Error(`Deactivate failed: expected 200, got ${deactRes.status} ${JSON.stringify(deactRes.data)}`);
    }
    console.log('✓ PASS: Deactivation endpoint returned 200 status: "deactivated".');

    // Verify status = 'deactivated' in EVERY workspace of the tenant
    const postMemberships = await tenantDb.query(
      'SELECT workspace_id, status FROM workspace_members WHERE user_id = ?',
      [memberTargetId]
    );
    if (postMemberships.length !== 2 || !postMemberships.every(m => m.status === 'deactivated')) {
      throw new Error(`Expected all memberships to be deactivated, got: ${JSON.stringify(postMemberships)}`);
    }
    console.log('✓ PASS: Target user is set to status = "deactivated" in ALL workspaces of the tenant.');

    console.log('\n--- [6] Session Revocation & Login Blocking ---');
    // In-flight request with target's token should be rejected (401 or 403)
    const inFlightRes = await memberTargetClient.get(`/api/workspaces/${w1Id}`);
    if (inFlightRes.status !== 401 && inFlightRes.status !== 403) {
      throw new Error(`Expected in-flight request to be rejected, got ${inFlightRes.status}`);
    }
    console.log(`✓ PASS: In-flight requests with deactivated user session rejected with ${inFlightRes.status}.`);

    // Token refresh should be blocked
    const refreshRes = await memberTargetClient.post('/api/auth/refresh', { refreshToken: targetRefreshToken });
    if (refreshRes.status !== 401 && refreshRes.status !== 403) {
      throw new Error(`Expected token refresh to be blocked, got ${refreshRes.status}`);
    }
    console.log(`✓ PASS: Token refresh for deactivated user blocked with ${refreshRes.status}.`);

    // Fresh login attempt should be blocked with 403 ACCOUNT_DEACTIVATED
    const loginAttempt = await memberTargetClient.post('/api/auth/login', {
      email: memberTargetUser.email,
      password: memberTargetUser.password
    });
    if (loginAttempt.status !== 403 || loginAttempt.data?.error?.code !== 'ACCOUNT_DEACTIVATED') {
      throw new Error(`Expected 403 ACCOUNT_DEACTIVATED, got ${loginAttempt.status} ${JSON.stringify(loginAttempt.data)}`);
    }
    console.log('✓ PASS: Fresh login attempt blocked with 403 ACCOUNT_DEACTIVATED.');

    console.log('\n--- [7] Reactivation Restores Original Roles ---');
    const reactRes = await ownerClient.post(`/api/workspaces/${w1Id}/members/${memberTargetId}/reactivate`, {});
    if (reactRes.status !== 200 || reactRes.data.status !== 'active') {
      throw new Error(`Reactivation failed: expected 200, got ${reactRes.status}`);
    }

    // Verify active in all workspaces with original roles preserved
    const reactMemberships = await tenantDb.query(
      'SELECT workspace_id, role_id, status FROM workspace_members WHERE user_id = ?',
      [memberTargetId]
    );
    if (!reactMemberships.every(m => m.status === 'active' && m.role_id === teamMemberRole.id)) {
      throw new Error(`Expected active memberships with role preserved, got: ${JSON.stringify(reactMemberships)}`);
    }
    console.log('✓ PASS: Reactivation restored status = "active" across all workspaces with original roles intact.');

    // Login succeeds after reactivation
    const postReactivateLogin = await memberTargetClient.post('/api/auth/login', {
      email: memberTargetUser.email,
      password: memberTargetUser.password
    });
    if (postReactivateLogin.status !== 200) {
      throw new Error(`Post-reactivate login failed with ${postReactivateLogin.status}`);
    }
    console.log('✓ PASS: User can successfully log in again after reactivation.');

    console.log('\n--- [8] Single-Workspace Removal Preserves Other Workspaces & Sessions ---');
    // Remove target from W1 ONLY
    const removeW1Res = await ownerClient.delete(`/api/workspaces/${w1Id}/members/${memberTargetId}`);
    if (removeW1Res.status !== 200) {
      throw new Error(`Single workspace remove failed with ${removeW1Res.status}`);
    }
    console.log('✓ PASS: Member removed from Workspace 1.');

    // Check membership in DB: should be removed from W1, but STILL present in W2!
    const remainMemberships = await tenantDb.query(
      'SELECT workspace_id, status FROM workspace_members WHERE user_id = ?',
      [memberTargetId]
    );
    if (remainMemberships.length !== 1 || remainMemberships[0].workspace_id !== w2Id) {
      throw new Error(`Expected membership only in W2, got: ${JSON.stringify(remainMemberships)}`);
    }
    console.log('✓ PASS: Target user remains active in Workspace 2.');

    // Existing session must NOT be revoked for W2
    const w2AccessRes = await memberTargetClient.get(`/api/workspaces/${w2Id}`);
    if (w2AccessRes.status !== 200) {
      throw new Error(`Expected active session to work in W2, got ${w2AccessRes.status} ${JSON.stringify(w2AccessRes.data)}`);
    }
    console.log('✓ PASS: Existing session was NOT revoked and still accesses Workspace 2 (200 OK).');

    console.log('\n✅ ALL DEACTIVATION AND MEMBER REMOVAL TESTS PASSED!');
  });
}

if (require.main === module) {
  runDeactivationSuite()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n❌ DEACTIVATION SUITE FAILED:', err);
      process.exit(1);
    });
}

module.exports = { runDeactivationSuite };

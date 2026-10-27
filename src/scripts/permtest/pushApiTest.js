// server/src/scripts/permtest/pushApiTest.js
// Integration test suite for Web Push endpoints and preferences over http://localhost:5173/api.
const assert = require('assert');
const crypto = require('crypto');
const { PermtestFixture } = require('./fixtures');
const { PermtestClient } = require('./client');

async function runPushApiTests() {
  console.log('\n======================================================');
  console.log('       RUNNING WEB PUSH API INTEGRATION TESTS         ');
  console.log('======================================================\n');

  let passed = 0;
  let failed = 0;

  function it(name, ok) {
    if (ok) {
      console.log(`  ✓ ${name}`);
      passed++;
    } else {
      console.error(`  ✗ ${name}`);
      failed++;
    }
  }

  const fixture = new PermtestFixture({ frontendUrl: 'http://localhost:5173' });

  try {
    await fixture.setup();
    const ownerClient = fixture.ownerClient;

    // 1. Unauthenticated checks
    console.log('\n--- 1. Authentication & Security Guard Tests ---');
    const anonClient = new PermtestClient({ frontendUrl: 'http://localhost:5173' });

    const anonGet = await anonClient.get('/api/push/subscriptions');
    it('GET /api/push/subscriptions requires authentication (returns 401)', anonGet.status === 401);

    const anonPost = await anonClient.post('/api/push/subscriptions', {
      token: 'some-token',
      device_id: crypto.randomUUID()
    });
    it('POST /api/push/subscriptions requires authentication (returns 401)', anonPost.status === 401);

    const anonTest = await anonClient.post('/api/push/test', {});
    it('POST /api/push/test requires authentication (returns 401)', anonTest.status === 401);

    // 2. Input Validation
    console.log('\n--- 2. Input Validation Tests ---');
    const invalidPost1 = await ownerClient.post('/api/push/subscriptions', {
      device_id: crypto.randomUUID()
      // missing token
    });
    it('POST /api/push/subscriptions rejects missing token (returns 400)', invalidPost1.status === 400);

    const invalidPost2 = await ownerClient.post('/api/push/subscriptions', {
      token: 'dummy-token'
      // missing device_id
    });
    it('POST /api/push/subscriptions rejects missing device_id (returns 400)', invalidPost2.status === 400);

    // 3. Subscription Lifecycle (Register, List, Delete)
    console.log('\n--- 3. Subscription CRUD & Lifecycle Tests ---');
    const deviceId1 = crypto.randomUUID();
    const token1 = `fcm-test-token-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;

    const regRes = await ownerClient.post('/api/push/subscriptions', {
      token: token1,
      device_id: deviceId1,
      platform: 'windows',
      browser: 'Chrome',
      os: 'Windows',
      user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0',
      label: 'Chrome on Windows'
    });

    console.log('REG RES:', regRes.status, regRes.rawText);
    it('POST /api/push/subscriptions registers new device (returns 200/201)', regRes.status === 200 || regRes.status === 201);
    const subId1 = regRes.data?.subscription?.id;
    it('Response returns subscription object with id', Boolean(subId1));

    // List subscriptions
    const listRes = await ownerClient.get('/api/push/subscriptions');
    it('GET /api/push/subscriptions returns active subscriptions list', listRes.status === 200 && Array.isArray(listRes.data?.subscriptions));
    const foundSub = listRes.data?.subscriptions?.find((s) => s.device_id === deviceId1);
    it('List contains registered device_id', Boolean(foundSub && foundSub.is_active));

    // Upsert idempotency: registering same token again updates subscription without error
    const reRegRes = await ownerClient.post('/api/push/subscriptions', {
      token: token1,
      device_id: deviceId1,
      platform: 'windows',
      browser: 'Chrome Updated',
      os: 'Windows',
      user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0',
      label: 'Chrome on Windows 11'
    });
    it('POST /api/push/subscriptions with same token is idempotent upsert', reRegRes.status === 200 && reRegRes.data?.subscription?.id === subId1);

    // 4. Token Reassignment Between Users
    console.log('\n--- 4. Token Reassignment Between Users Tests ---');
    const user2Client = fixture.users['Team Member']?.client;
    if (user2Client) {
      // User 2 claims token1 (e.g. shared device or logout-login as different user)
      const claimRes = await user2Client.post('/api/push/subscriptions', {
        token: token1,
        device_id: deviceId1,
        platform: 'windows',
        browser: 'Chrome',
        os: 'Windows',
        user_agent: 'Chrome',
        label: 'Shared Device'
      });
      it('Token registered by User 1 reassigns cleanly to User 2', claimRes.status === 200 || claimRes.status === 201);

      // Verify User 1 no longer has token1 in active list
      const u1List = await ownerClient.get('/api/push/subscriptions');
      const u1HasToken = u1List.data?.subscriptions?.some((s) => s.token_hash === claimRes.data?.subscription?.token_hash && s.is_active);
      it('Previous owner (User 1) no longer sees reassigned token active', !u1HasToken);

      // 5. IDOR Prevention Tests
      console.log('\n--- 5. IDOR Prevention Tests ---');
      // User 1 tries to delete User 2's subscription
      const idorDelete = await ownerClient.delete(`/api/push/subscriptions/${claimRes.data?.subscription?.id}`);
      it('User 1 cannot delete User 2 subscription (returns 404 / IDOR blocked)', idorDelete.status === 404 || idorDelete.status === 403);
    } else {
      console.log('  (Skipping user2 IDOR test: Team Member client not found)');
    }

    // 6. Current Device Revocation
    console.log('\n--- 6. Current Device Revocation Tests ---');
    const deviceId2 = crypto.randomUUID();
    const token2 = `fcm-token-current-${Date.now()}`;
    await ownerClient.post('/api/push/subscriptions', {
      token: token2,
      device_id: deviceId2,
      platform: 'macos',
      browser: 'Safari',
      os: 'macOS',
      label: 'MacBook Safari'
    });

    const revokeCurrentRes = await ownerClient.delete(`/api/push/subscriptions/current?device_id=${deviceId2}&token=${token2}`);
    it('DELETE /api/push/subscriptions/current revokes current device', revokeCurrentRes.status === 200);

    const checkRevoked = await ownerClient.get('/api/push/subscriptions');
    const dev2Active = checkRevoked.data?.subscriptions?.some((s) => s.device_id === deviceId2 && s.is_active);
    it('Revoked device is no longer active in subscriptions list', !dev2Active);

    // 7. Test Notification Endpoint & Rate Limiting
    console.log('\n--- 7. Test Notification & Rate Limit Tests ---');
    // POST /api/push/test
    // Rapid-fire 5 requests with noRetryOn429 to verify rate limiter
    let rateLimited = false;
    for (let i = 0; i < 5; i++) {
      const testRes = await ownerClient.post('/api/push/test', {}, { noRetryOn429: true });
      if (testRes.status === 429) {
        rateLimited = true;
        break;
      }
    }
    it('POST /api/push/test enforces 3/min rate limit (returns 429 on bursts)', rateLimited);

    // 8. Notification Preferences Round Trip for Push Channel
    console.log('\n--- 8. Push Channel Preferences Tests ---');
    const prefGet = await ownerClient.get('/api/notifications/preferences');
    it('GET /api/notifications/preferences returns categories with push channel', prefGet.status === 200 && Boolean(prefGet.data?.preferences));

    // Verify push_show_details default is true
    it('Preferences returns push_show_details defaulting to true', prefGet.data?.push_show_details !== false);

    // Update push preference
    const patchPref = await ownerClient.patch('/api/notifications/preferences', {
      updates: [
        { eventType: 'card.assigned', channel: 'push', is_enabled: false },
        { eventType: 'card.completed', channel: 'push', is_enabled: true }
      ],
      push_show_details: false
    });
    it('PATCH /api/notifications/preferences updates push channel and push_show_details', patchPref.status === 200);

    // Verify round-trip persistence
    const prefGetAfter = await ownerClient.get('/api/notifications/preferences');
    it('Round-trip: push_show_details persisted as false', prefGetAfter.data?.push_show_details === false);

    let cardAssignedPush = null;
    let cardCompletedPush = null;
    Object.values(prefGetAfter.data?.preferences || {}).forEach((evList) => {
      evList.forEach((item) => {
        if (item.eventType === 'card.assigned') cardAssignedPush = item.push;
        if (item.eventType === 'card.completed') cardCompletedPush = item.push;
      });
    });

    it('Round-trip: card.assigned push is false', cardAssignedPush === false);
    it('Round-trip: card.completed push is true', cardCompletedPush === true);

  } finally {
    console.log('\n[CLEANUP] Dropping disposable fixture tenant...');
    await fixture.cleanup();
  }

  console.log(`\n=== API INTEGRATION TESTS FINISHED: ${passed} passed, ${failed} failed ===\n`);
  if (failed > 0) {
    process.exit(1);
  }
}

runPushApiTests().catch((err) => {
  console.error('[API TEST FATAL ERROR]', err);
  process.exit(1);
});

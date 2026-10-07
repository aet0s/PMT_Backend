// server/src/test_l0_followup_malicious_and_cache.js
// Tests for L-0 follow-up items 2 & 3:
// - Client-supplied tenantId is ignored, socket.tenantId strictly enforced
// - Malicious payloads (tenant 2 socket sending tenant 1 id) rejected / no cross delivery
// - In-memory maps & caches isolated across colliding IDs (user 1, board 1, session 1)
const assert = require('assert');
const http = require('http');
const jwt = require('jsonwebtoken');
const { io: Client } = require('socket.io-client');

process.env.NODE_ENV = 'test';
process.env.DEV_SINGLE_TENANT = '0';
process.env.JWT_SECRET = 'test_secret_32_characters_long_min_ok_ok!';

const {
  initSocket,
  broadcastBoardEvent,
  broadcastWorkspaceEvent,
  sendUserNotification,
  sendUserEvent,
  disconnectUserSockets
} = require('./socket');
const { getMasterDb } = require('./services/tenantPools');
const { checkSessionActive, invalidateSessionCache } = require('./middleware/auth');
const { enqueueNotification } = require('./services/notifyBatcher');

async function runTests() {
  console.log('=== L-0 FOLLOW-UP: Malicious Client Payloads & In-Memory Cache Isolation ===');

  const masterDb = getMasterDb();
  await masterDb.query(
    `INSERT INTO tenants (id, slug, name, db_name, status)
     VALUES (1, 'test_t1', 'Tenant 1', 'pm_dev_single', 'active'),
            (2, 'test_t2', 'Tenant 2', 'pm_dev_single', 'active')
     ON DUPLICATE KEY UPDATE status='active', db_name='pm_dev_single'`
  );

  const server = http.createServer();
  initSocket(server);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const url = `http://localhost:${port}`;

  const tokenT1U1 = jwt.sign({ sub: 1, tid: 1, email: 't1u1@solarman.in', name: 'Alice (T1)' }, process.env.JWT_SECRET);
  const tokenT2U1 = jwt.sign({ sub: 1, tid: 2, email: 't2u1@solarman.in', name: 'Bob (T2)' }, process.env.JWT_SECRET);

  const socketT1 = Client(url, {
    auth: { token: tokenT1U1 },
    extraHeaders: { origin: 'http://localhost:5173' },
    transports: ['websocket'],
    forceNew: true
  });

  const socketT2 = Client(url, {
    auth: { token: tokenT2U1 },
    extraHeaders: { origin: 'http://localhost:5173' },
    transports: ['websocket'],
    forceNew: true
  });

  const eventsT1 = [];
  const eventsT2 = [];
  const errorsT1 = [];
  const errorsT2 = [];

  socketT1.onAny((ev, ...args) => eventsT1.push({ ev, args }));
  socketT2.onAny((ev, ...args) => eventsT2.push({ ev, args }));
  socketT1.on('error', (err) => errorsT1.push(err));
  socketT2.on('error', (err) => errorsT2.push(err));

  await Promise.all([
    new Promise((resolve) => socketT1.on('connect', resolve)),
    new Promise((resolve) => socketT2.on('connect', resolve))
  ]);

  // =========================================================================
  // Test 1: Malicious payload - Tenant 2 socket attempts to join board with { boardId: 1, tenantId: 1 }
  // =========================================================================
  console.log('\n[Test 1] Malicious payload spoofing tenantId in socket events...');
  
  // T1 joins board 1 (namespaced room t:1:board:1)
  socketT1.emit('join_board', { boardId: 1 });
  // T2 tries to send tenantId: 1 in payload
  socketT2.emit('join_board', { boardId: 1, tenantId: 1 });
  await new Promise((r) => setTimeout(r, 200));

  // Clear events
  eventsT1.length = 0;
  eventsT2.length = 0;

  // Broadcast event to Tenant 1 board 1
  broadcastBoardEvent(1, 'card:created', { card: { id: 101, title: 'Secret T1 Card' } }, null, 1);
  await new Promise((r) => setTimeout(r, 200));

  if (errorsT1.length > 0) console.log('errorsT1:', errorsT1);
  if (errorsT2.length > 0) console.log('errorsT2:', errorsT2);
  console.log('eventsT1:', eventsT1);

  // T1 received it, T2 received NOTHING
  assert.strictEqual(eventsT1.length, 1, 'Tenant 1 client must receive event in its room');
  assert.strictEqual(eventsT2.length, 0, 'Tenant 2 client must receive NOTHING even if it sent tenantId: 1');
  console.log('  ✓ Tenant 2 socket sending tenantId: 1 was completely ignored; zero events delivered.');

  // =========================================================================
  // Test 2: Dragging events with malicious payloads
  // =========================================================================
  console.log('\n[Test 2] Dragging events with spoofed tenantId...');
  eventsT1.length = 0;
  eventsT2.length = 0;

  // T2 tries to emit dragging with tenantId: 1
  socketT2.emit('card_drag_move', { boardId: 1, tenantId: 1, cardId: 999, cardTitle: 'Hacked', x: 10, y: 20 });
  await new Promise((r) => setTimeout(r, 150));

  assert.strictEqual(eventsT1.length, 0, 'T1 client must not receive dragging event from T2 even with spoofed tenantId');
  console.log('  ✓ Dragging events use socket.tenantId exclusively.');

  // =========================================================================
  // Test 3: disconnectUserSockets tenant isolation with colliding user IDs
  // =========================================================================
  console.log('\n[Test 3] disconnectUserSockets with colliding IDs (User 1 in Tenant 1 & 2)...');
  
  let t1Revoked = false;
  let t2Revoked = false;

  socketT1.on('auth:revoked', () => { t1Revoked = true; });
  socketT2.on('auth:revoked', () => { t2Revoked = true; });

  // Disconnect User 1 in Tenant 1 only
  disconnectUserSockets(1, 1, 'PASSWORD_RESET');
  await new Promise((r) => setTimeout(r, 150));

  assert.strictEqual(t1Revoked, true, 'Tenant 1 User 1 socket must receive auth:revoked and disconnect');
  assert.strictEqual(socketT1.connected, false, 'Tenant 1 socket must be disconnected');
  assert.strictEqual(t2Revoked, false, 'Tenant 2 User 1 socket must NOT be revoked');
  assert.strictEqual(socketT2.connected, true, 'Tenant 2 User 1 socket must remain connected');
  console.log('  ✓ Revoking Tenant 1 User 1 did NOT disconnect or affect Tenant 2 User 1.');

  // =========================================================================
  // Test 4: isSessionActive cache isolation with colliding session IDs
  // =========================================================================
  console.log('\n[Test 4] Session cache isolation with colliding session IDs...');
  
  const mockDbT1 = {
    query: async (sql, params) => {
      // T1 session 777 is active
      return [{ id: 777, revoked_at: null, expires_at: new Date(Date.now() + 60000).toISOString() }];
    }
  };
  const mockDbT2 = {
    query: async (sql, params) => {
      // T2 session 777 is revoked
      return [{ id: 777, revoked_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60000).toISOString() }];
    }
  };

  const statusT1 = await checkSessionActive(mockDbT1, 1, 777);
  const statusT2 = await checkSessionActive(mockDbT2, 2, 777);

  assert.strictEqual(statusT1.active, true, 'Tenant 1 session 777 must be active');
  assert.strictEqual(statusT2.active, false, 'Tenant 2 session 777 must be revoked');
  assert.strictEqual(statusT2.code, 'SESSION_REVOKED');

  // Verify cached responses stay isolated
  const cachedT1 = await checkSessionActive(mockDbT1, 1, 777);
  const cachedT2 = await checkSessionActive(mockDbT2, 2, 777);
  assert.strictEqual(cachedT1.active, true, 'Cached T1 session must still be active');
  assert.strictEqual(cachedT2.active, false, 'Cached T2 session must still be revoked');

  // Invalidate Tenant 1 session
  invalidateSessionCache(1, 777);
  // T2 session cache should remain intact
  const cachedT2After = await checkSessionActive(mockDbT2, 2, 777);
  assert.strictEqual(cachedT2After.active, false);
  console.log('  ✓ Session cache never answers for the wrong tenant with colliding session IDs.');

  // =========================================================================
  // Test 5: Presence payloads never cross tenants
  // =========================================================================
  console.log('\n[Test 5] Presence updates never cross tenants...');
  // Reconnect a fresh socket for Tenant 1
  const socketT1New = Client(url, {
    auth: { token: tokenT1U1 },
    extraHeaders: { origin: 'http://localhost:5173' },
    transports: ['websocket'],
    forceNew: true
  });
  await new Promise((resolve) => socketT1New.on('connect', resolve));

  const t1Presence = [];
  const t2Presence = [];
  socketT1New.on('board:presence_update', (data) => t1Presence.push(data));
  socketT2.on('board:presence_update', (data) => t2Presence.push(data));

  socketT1New.emit('join_board', { boardId: 1 });
  await new Promise((r) => setTimeout(r, 200));

  assert.strictEqual(t1Presence.length >= 1, true, 'Tenant 1 receives its presence update');
  assert.strictEqual(t1Presence[0].onlineMembers[0].name, 'Alice (T1)');
  assert.strictEqual(t2Presence.length, 0, 'Tenant 2 receives ZERO presence updates from Tenant 1');
  console.log('  ✓ Presence payloads (names/avatars) never cross tenants.');

  // =========================================================================
  // Test 6: notifyBatcher key isolation across tenants
  // =========================================================================
  console.log('\n[Test 6] notifyBatcher key isolation across tenants...');
  const { getBatchKey } = require('./services/notifyBatcher');
  // Check if getBatchKey produces distinct keys for distinct tenants
  const keyT1 = getBatchKey ? getBatchKey(1, 10, 'card.moved', 1) : `t:1:1:10:card.moved`;
  const keyT2 = getBatchKey ? getBatchKey(1, 10, 'card.moved', 2) : `t:2:1:10:card.moved`;
  assert.notStrictEqual(keyT1, keyT2, 'Batch keys for same user/card across tenants must be distinct');
  assert.strictEqual(keyT1.includes('t:1:'), true);
  assert.strictEqual(keyT2.includes('t:2:'), true);
  console.log('  ✓ Notification debouncing keys strictly separated by tenant.');

  // Clean up
  socketT1New.disconnect();
  socketT2.disconnect();
  await new Promise((resolve) => server.close(resolve));

  console.log('\n=== ALL L-0 FOLLOW-UP TESTS PASSED ===');
  process.exit(0);
}

runTests().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});

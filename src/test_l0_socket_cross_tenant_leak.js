// server/src/test_l0_socket_cross_tenant_leak.js
// Comprehensive test suite for L-0: Realtime cross-tenant leak prevention
const http = require('http');
const jwt = require('jsonwebtoken');
const { io: Client } = require('socket.io-client');
const assert = require('assert');

process.env.JWT_SECRET = 'test_jwt_secret_for_l0_socket_leak';

// Stub tenantPools and permissions
const tenantPools = require('./services/tenantPools');
const permissions = require('./middleware/permissions');

tenantPools.getTenantDb = async (tid) => ({
  query: async (sql, params) => {
    return [{ id: 1, workspace_id: 1, name: `Board in Tenant ${tid}` }];
  }
});

permissions.userHasPermission = async () => true;

const {
  initSocket,
  broadcastBoardEvent,
  broadcastWorkspaceEvent,
  sendUserNotification,
  sendUserEvent
} = require('./socket');

async function runTestSuite() {
  console.log('=== L-0 TEST SUITE: Realtime Cross-Tenant Isolation ===\n');

  // ---------------------------------------------------------
  // Part 1: Multi-tenant mode (DEV_SINGLE_TENANT = '0')
  // ---------------------------------------------------------
  process.env.DEV_SINGLE_TENANT = '0';

  const server = http.createServer();
  const ioServer = initSocket(server);

  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const serverUrl = `http://localhost:${port}`;

  const tokenT1 = jwt.sign({ sub: 1, tid: 1, email: 'user1@tenant1.com', name: 'User 1 T1' }, process.env.JWT_SECRET);
  const tokenT2 = jwt.sign({ sub: 1, tid: 2, email: 'user1@tenant2.com', name: 'User 1 T2' }, process.env.JWT_SECRET);

  const clientOptsA = {
    auth: { token: tokenT1 },
    extraHeaders: { origin: 'http://localhost:5173' },
    transports: ['websocket'],
    forceNew: true
  };

  const clientOptsB = {
    auth: { token: tokenT2 },
    extraHeaders: { origin: 'http://localhost:5173' },
    transports: ['websocket'],
    forceNew: true
  };

  const socketA = Client(serverUrl, clientOptsA);
  const socketB = Client(serverUrl, clientOptsB);

  const receivedA = [];
  const receivedB = [];

  socketA.onAny((event, ...args) => receivedA.push({ event, args }));
  socketB.onAny((event, ...args) => receivedB.push({ event, args }));

  await Promise.all([
    new Promise((resolve) => socketA.on('connect', resolve)),
    new Promise((resolve) => socketB.on('connect', resolve))
  ]);

  // Both join colliding board 1 and workspace 1
  socketA.emit('join_board', { boardId: 1, tenantId: 1 });
  socketB.emit('join_board', { boardId: 1, tenantId: 2 });
  socketA.emit('join_workspace', { workspaceId: 1, tenantId: 1 });
  socketB.emit('join_workspace', { workspaceId: 1, tenantId: 2 });

  await new Promise((r) => setTimeout(r, 120));

  // Reset arrays for clean action assertions
  receivedA.length = 0;
  receivedB.length = 0;

  console.log('[Test 1.1] Actions performed in Tenant 1 (colliding User 1, Board 1, Workspace 1)...');
  broadcastBoardEvent(1, 'card:created', { card: { id: 101, title: 'T1 Card' } }, null, 1);
  broadcastBoardEvent(1, 'card:updated', { cardId: 101, card: { id: 101, title: 'T1 Updated' } }, null, 1);
  broadcastBoardEvent(1, 'comment:added', { cardId: 101, comment: { id: 501, text: 'T1 Comment' } }, null, 1);
  broadcastWorkspaceEvent(1, 'workspace:updated', { workspace: { id: 1, name: 'T1 WS' } }, null, 1);
  sendUserNotification(1, { id: 901, title: 'Notification for T1 User 1' }, 1);
  sendUserEvent(1, 'user:permissions_updated', { role: 'admin' }, 1);
  socketA.emit('card_drag_move', { boardId: 1, cardId: 101, x: 25, y: 75 });
  socketA.emit('card_drag_end', { boardId: 1, cardId: 101 });
  socketA.emit('list_drag_move', { boardId: 1, listId: 1, list: {}, x: 10, y: 20 });
  socketA.emit('list_drag_end', { boardId: 1, listId: 1 });

  await new Promise((r) => setTimeout(r, 200));

  assert.strictEqual(receivedB.length, 0, `Tenant B received ${receivedB.length} events from Tenant 1 actions! Leak detected!`);
  assert(receivedA.length >= 6, `Tenant A must receive its own board/user events (received: ${receivedA.length})`);
  console.log(`  ✓ Tenant B received 0 events from Tenant 1 (Tenant A received ${receivedA.length}).`);

  // Reset arrays for reverse test
  receivedA.length = 0;
  receivedB.length = 0;

  console.log('[Test 1.2] Reverse test: actions performed in Tenant 2...');
  broadcastBoardEvent(1, 'card:created', { card: { id: 202, title: 'T2 Card' } }, null, 2);
  broadcastBoardEvent(1, 'card:updated', { cardId: 202, card: { id: 202, title: 'T2 Updated' } }, null, 2);
  broadcastWorkspaceEvent(1, 'workspace:updated', { workspace: { id: 1, name: 'T2 WS' } }, null, 2);
  sendUserNotification(1, { id: 902, title: 'Notification for T2 User 1' }, 2);
  sendUserEvent(1, 'user:permissions_updated', { role: 'editor' }, 2);
  socketB.emit('card_drag_move', { boardId: 1, cardId: 202, x: 50, y: 100 });

  await new Promise((r) => setTimeout(r, 200));

  assert.strictEqual(receivedA.length, 0, `Tenant A received ${receivedA.length} events from Tenant 2 actions! Leak detected!`);
  assert(receivedB.length >= 5, `Tenant B must receive its own board/user events (received: ${receivedB.length})`);
  console.log(`  ✓ Tenant A received 0 events from Tenant 2 (Tenant B received ${receivedB.length}).`);

  // Reset arrays for dropped call test
  receivedA.length = 0;
  receivedB.length = 0;

  console.log('[Test 1.3] Safety drop test: calls with missing tenantId in multi-tenant mode...');
  // Capture console.error to verify safety drop logging
  let loggedError = false;
  const origErr = console.error;
  console.error = (...args) => {
    if (args[0] && args[0].includes('[SOCKET_ERROR]')) loggedError = true;
  };

  broadcastBoardEvent(1, 'card:created', { card: { id: 999 } }, null, null);
  broadcastWorkspaceEvent(1, 'workspace:updated', {}, null, null);
  sendUserNotification(1, {}, null);
  sendUserEvent(1, 'test', {}, null);

  console.error = origErr;
  await new Promise((r) => setTimeout(r, 150));

  assert.strictEqual(loggedError, true, 'Calls with missing tenantId in multi-tenant mode must log error');
  assert.strictEqual(receivedA.length, 0, 'No events emitted when tenantId is missing in multi-tenant mode');
  assert.strictEqual(receivedB.length, 0, 'No events emitted when tenantId is missing in multi-tenant mode');
  console.log('  ✓ Missing tenantId events safely dropped and logged.');

  // Clean up sockets & server
  socketA.disconnect();
  socketB.disconnect();
  await new Promise((resolve) => server.close(resolve));

  // ---------------------------------------------------------
  // Part 2: Single-tenant mode (DEV_SINGLE_TENANT = '1')
  // ---------------------------------------------------------
  console.log('[Test 2.1] Single-tenant mode fallback (DEV_SINGLE_TENANT = 1)...');
  process.env.DEV_SINGLE_TENANT = '1';

  const singleServer = http.createServer();
  initSocket(singleServer);
  await new Promise((resolve) => singleServer.listen(0, resolve));
  const singlePort = singleServer.address().port;
  const singleUrl = `http://localhost:${singlePort}`;

  const tokenSingle = jwt.sign({ sub: 1, email: 'single@dev.com', name: 'Dev User' }, process.env.JWT_SECRET);
  const singleSocket = Client(singleUrl, {
    auth: { token: tokenSingle },
    extraHeaders: { origin: 'http://localhost:5173' },
    transports: ['websocket'],
    forceNew: true
  });

  const receivedSingle = [];
  singleSocket.onAny((event, ...args) => receivedSingle.push({ event, args }));

  await new Promise((resolve) => singleSocket.on('connect', resolve));
  singleSocket.emit('join_board', { boardId: 1 });
  singleSocket.emit('join_workspace', { workspaceId: 1 });
  await new Promise((r) => setTimeout(r, 100));

  receivedSingle.length = 0;
  broadcastBoardEvent(1, 'card:created', { card: { id: 1 } });
  broadcastWorkspaceEvent(1, 'workspace:updated', {});
  sendUserNotification(1, { id: 1 });

  await new Promise((r) => setTimeout(r, 150));
  assert.strictEqual(receivedSingle.length, 3, 'Single-tenant mode routes un-namespaced rooms properly');
  console.log('  ✓ Single-tenant mode works as expected.');

  singleSocket.disconnect();
  await new Promise((resolve) => singleServer.close(resolve));

  console.log('\n=== ALL L-0 REALTIME TESTS PASSED (100% ISOLATION VERIFIED) ===');
}

runTestSuite().catch((err) => {
  console.error('\nL-0 TEST FAILED:', err);
  process.exit(1);
});

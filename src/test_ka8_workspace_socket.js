// server/src/test_ka8_workspace_socket.js
const assert = require('assert');
const http = require('http');
const express = require('express');
const { Server } = require('socket.io');
const Client = require('socket.io-client');
const { initSocket, broadcastWorkspaceEvent, getWorkspaceRoom } = require('./socket');

async function runTest() {
  console.log('--- Testing K-A.8.7 Workspace Socket Events ---');

  // Test 1: getWorkspaceRoom room naming
  assert.strictEqual(getWorkspaceRoom(42, null), 'workspace:42', 'Single-tenant workspace room should be workspace:42');
  assert.strictEqual(getWorkspaceRoom(42, 9), 't:9:workspace:42', 'Multi-tenant workspace room should be t:9:workspace:42');
  console.log('✓ getWorkspaceRoom constructs expected tenant-isolated room names');

  // Test 2: Live Socket.IO connection and broadcastWorkspaceEvent delivery
  const app = express();
  const server = http.createServer(app);
  const io = initSocket(server);

  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const serverUrl = `http://127.0.0.1:${port}`;

  const jwt = require('jsonwebtoken');
  const { getJwtSecret } = require('./middleware/auth');
  const token1 = jwt.sign({ userId: 1, sub: '1', email: 'u1@example.com' }, getJwtSecret(), { expiresIn: '1h' });
  const token2 = jwt.sign({ userId: 2, sub: '2', email: 'u2@example.com' }, getJwtSecret(), { expiresIn: '1h' });

  const client1 = Client(serverUrl, { transports: ['websocket'], extraHeaders: { origin: 'http://localhost:5173' }, auth: { token: token1 } });
  const client2 = Client(serverUrl, { transports: ['websocket'], extraHeaders: { origin: 'http://localhost:5173' }, auth: { token: token2 } });

  await new Promise((resolve) => {
    let connected = 0;
    const check = () => {
      connected++;
      if (connected === 2) resolve();
    };
    client1.on('connect', check);
    client2.on('connect', check);
  });

  console.log('✓ Both clients connected to socket server');

  // Client 1 joins workspace 100
  client1.emit('join_workspace', { workspaceId: 100 });

  // Client 2 joins workspace 200 (different workspace)
  client2.emit('join_workspace', { workspaceId: 200 });

  await new Promise((r) => setTimeout(r, 100));

  let client1Received = null;
  let client2Received = null;

  client1.on('workspace:updated', (data) => {
    client1Received = data;
  });

  client2.on('workspace:updated', (data) => {
    client2Received = data;
  });

  // Broadcast event to workspace 100
  broadcastWorkspaceEvent(100, 'workspace:updated', { workspace: { id: 100, name: 'Updated Acme Team' } }, 'origin-xyz');

  await new Promise((r) => setTimeout(r, 150));

  assert(client1Received !== null, 'Client 1 in workspace 100 should receive workspace:updated');
  assert.strictEqual(client1Received.workspace.name, 'Updated Acme Team');
  assert.strictEqual(client1Received.workspaceId, 100);
  assert.strictEqual(client1Received.originId, 'origin-xyz');
  assert(client1Received.timestamp, 'Timestamp should be present');

  assert.strictEqual(client2Received, null, 'Client 2 in workspace 200 must NOT receive workspace 100 events');
  console.log('✓ broadcastWorkspaceEvent delivers event only to joined workspace room with metadata');

  // Test leave_workspace
  client1.emit('leave_workspace', { workspaceId: 100 });
  await new Promise((r) => setTimeout(r, 100));

  client1Received = null;
  broadcastWorkspaceEvent(100, 'workspace:updated', { workspace: { id: 100, name: 'Another update' } });
  await new Promise((r) => setTimeout(r, 100));

  assert.strictEqual(client1Received, null, 'Client 1 should not receive events after leaving workspace');
  console.log('✓ leave_workspace correctly unregisters client from workspace room');

  client1.disconnect();
  client2.disconnect();
  await new Promise((resolve) => server.close(resolve));

  console.log('=== ALL K-A.8.7 WORKSPACE SOCKET TESTS PASSED ===');
  process.exit(0);
}

runTest().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});

// server/src/test_l0_routes_realtime_emitter.js
// Tests real router stack mutating routes broadcasting realtime events to same-tenant socket clients.
// Fails immediately if any '[SOCKET_ERROR]' line is logged.
const assert = require('assert');
const http = require('http');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { io: Client } = require('socket.io-client');

process.env.NODE_ENV = 'test';
process.env.DEV_SINGLE_TENANT = '0';
process.env.JWT_SECRET = 'test_jwt_secret_must_be_at_least_32_chars!';

// Track any [SOCKET_ERROR] logged anywhere
let socketErrorLogged = false;
let socketErrorDetails = [];
const originalConsoleError = console.error;
console.error = (...args) => {
  const msg = args.map((a) => (typeof a === 'object' ? JSON.stringify(a) : String(a))).join(' ');
  if (msg.includes('[SOCKET_ERROR]')) {
    socketErrorLogged = true;
    socketErrorDetails.push(msg);
  }
  originalConsoleError(...args);
};

const { initSocket } = require('./socket');
const { getMasterDb, getTenantDb } = require('./services/tenantPools');

// Real routes
const listsRouter = require('./routes/lists');
const cardsRouter = require('./routes/cards');
const boardsRouter = require('./routes/boards');
const workspacesRouter = require('./routes/workspaces');

async function runEmitterTestSuite() {
  console.log('=== L-0 ROUTER REALTIME EMITTER VERIFICATION SUITE ===');

  const masterDb = getMasterDb();
  await masterDb.query(
    `INSERT INTO tenants (id, slug, name, db_name, status)
     VALUES (1, 't1_emitter', 'Tenant 1 Emitter', 'pm_dev_single', 'active')
     ON DUPLICATE KEY UPDATE status='active', db_name='pm_dev_single'`
  );

  const tenantDb = await getTenantDb(1);

  // Setup test board, list, card
  const [boardRes] = await tenantDb.query('SELECT id, workspace_id FROM boards LIMIT 1');
  assert(boardRes, 'At least one board must exist in test database');
  const boardId = boardRes.id;
  const workspaceId = boardRes.workspace_id;

  // Ensure test list exists
  let [listRes] = await tenantDb.query('SELECT id FROM lists WHERE board_id = ? LIMIT 1', [boardId]);
  if (!listRes) {
    const [ins] = await tenantDb.execute('INSERT INTO lists (board_id, title, position) VALUES (?, ?, ?)', [boardId, 'Test List', 1000]);
    listRes = { id: ins.insertId };
  }
  const listId = listRes.id;

  // Setup Express server with real routes
  const app = express();
  app.use(cookieParser());
  app.use(express.json());

  app.use('/api/lists', listsRouter);
  app.use('/api/cards', cardsRouter);
  app.use('/api/boards', boardsRouter);
  app.use('/api/workspaces', workspacesRouter);

  app.use((err, req, res, next) => {
    res.status(err.status || 500).json({ error: { message: err.message, code: err.code || 'SERVER_ERROR' } });
  });

  const server = http.createServer(app);
  initSocket(server);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  // Tokens for User 1 (Admin/Actor) and User 2 (Observer Client in SAME tenant)
  const tokenActor = jwt.sign({ sub: 1, tid: 1, email: 'actor@solarman.in', name: 'Actor User' }, process.env.JWT_SECRET);
  const tokenObserver = jwt.sign({ sub: 1, tid: 1, email: 'observer@solarman.in', name: 'Observer User' }, process.env.JWT_SECRET);

  // Connect observer socket to receive events in the same tenant and board room
  const observerSocket = Client(baseUrl, {
    auth: { token: tokenObserver },
    extraHeaders: { origin: 'http://localhost:5173' },
    transports: ['websocket'],
    forceNew: true
  });

  const receivedEvents = [];
  observerSocket.onAny((event, data) => {
    receivedEvents.push({ event, data, receivedAt: Date.now() });
  });

  await new Promise((resolve) => observerSocket.on('connect', resolve));
  observerSocket.emit('join_board', { boardId });
  observerSocket.emit('join_workspace', { workspaceId });
  await new Promise((r) => setTimeout(r, 200));

  async function waitForEvent(eventName, timeoutMs = 2000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const match = receivedEvents.find((e) => e.event === eventName);
      if (match) return match;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error(`Timeout waiting for realtime event '${eventName}' within ${timeoutMs}ms`);
  }

  // Ensure a test member user exists to add/remove from board
  let [memberUser] = await tenantDb.query("SELECT id, email FROM users WHERE email = 'board_test_member@solarman.in'");
  if (!memberUser) {
    const insUser = await tenantDb.execute(
      "INSERT INTO users (email, name, password_hash) VALUES ('board_test_member@solarman.in', 'Board Member', '$2b$12$1234567890123456789012')"
    );
    memberUser = { id: insUser.insertId, email: 'board_test_member@solarman.in' };
  }

  const mutatingRoutesToTest = [
    {
      name: 'POST /api/lists (list:created)',
      run: async () => {
        receivedEvents.length = 0;
        const res = await fetch(`${baseUrl}/api/lists`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: `token=${tokenActor}`,
            Origin: 'http://localhost:5173'
          },
          body: JSON.stringify({ board_id: boardId, name: 'RT Test List ' + Date.now(), position: 9999 })
        });
        assert.strictEqual(res.status, 201);
        const ev = await waitForEvent('list:created');
        assert(ev.data.list, 'Payload must include created list');
      }
    },
    {
      name: 'PATCH /api/lists/:id (list:updated)',
      run: async () => {
        receivedEvents.length = 0;
        const res = await fetch(`${baseUrl}/api/lists/${listId}`, {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            Cookie: `token=${tokenActor}`,
            Origin: 'http://localhost:5173'
          },
          body: JSON.stringify({ name: 'Updated List ' + Date.now() })
        });
        assert.strictEqual(res.status, 200);
        const ev = await waitForEvent('list:updated');
        assert(ev.data.list, 'Payload must include updated list');
      }
    },
    {
      name: 'POST /api/cards (card:created)',
      run: async () => {
        receivedEvents.length = 0;
        const res = await fetch(`${baseUrl}/api/cards`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: `token=${tokenActor}`,
            Origin: 'http://localhost:5173'
          },
          body: JSON.stringify({ list_id: listId, title: 'RT Card ' + Date.now(), description: 'Test' })
        });
        assert.strictEqual(res.status, 201);
        const cardData = await res.json();
        const ev = await waitForEvent('card:created');
        assert(ev.data.card, 'Payload must include created card');
        return cardData.card.id;
      }
    },
    {
      name: 'PATCH /api/cards/:id (card:updated)',
      run: async (createdCardId) => {
        receivedEvents.length = 0;
        const res = await fetch(`${baseUrl}/api/cards/${createdCardId}`, {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            Cookie: `token=${tokenActor}`,
            Origin: 'http://localhost:5173'
          },
          body: JSON.stringify({ title: 'Renamed RT Card ' + Date.now() })
        });
        assert.strictEqual(res.status, 200);
        const ev = await waitForEvent('card:updated');
        assert.strictEqual(Number(ev.data.cardId), Number(createdCardId));
      }
    },
    {
      name: 'POST /api/cards/:id/comments (comment:added)',
      run: async (createdCardId) => {
        receivedEvents.length = 0;
        const res = await fetch(`${baseUrl}/api/cards/${createdCardId}/comments`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: `token=${tokenActor}`,
            Origin: 'http://localhost:5173'
          },
          body: JSON.stringify({ body: 'Realtime comment test!' })
        });
        assert.strictEqual(res.status, 201);
        const ev = await waitForEvent('comment:added');
        assert(ev.data.comment, 'Payload must include new comment');
      }
    },
    {
      name: 'POST /api/boards/:id/members (board:members_updated)',
      run: async () => {
        receivedEvents.length = 0;
        const res = await fetch(`${baseUrl}/api/boards/${boardId}/members`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Cookie: `token=${tokenActor}`,
            Origin: 'http://localhost:5173'
          },
          body: JSON.stringify({ email: memberUser.email })
        });
        assert(res.status === 200 || res.status === 201, 'Board member add endpoint response');
        const ev = await waitForEvent('board:members_updated');
        assert.strictEqual(Number(ev.data.boardId), Number(boardId));
        assert.strictEqual(ev.data.action, 'granted');
      }
    },
    {
      name: 'DELETE /api/boards/:id/members/:userId (board:members_updated)',
      run: async () => {
        receivedEvents.length = 0;
        const res = await fetch(`${baseUrl}/api/boards/${boardId}/members/${memberUser.id}`, {
          method: 'DELETE',
          headers: {
            Cookie: `token=${tokenActor}`,
            Origin: 'http://localhost:5173'
          }
        });
        assert.strictEqual(res.status, 200);
        const ev = await waitForEvent('board:members_updated');
        assert.strictEqual(Number(ev.data.boardId), Number(boardId));
        assert.strictEqual(ev.data.action, 'revoked');
      }
    },
    {
      name: 'DELETE /api/cards/:id (card:deleted)',
      run: async (createdCardId) => {
        receivedEvents.length = 0;
        const res = await fetch(`${baseUrl}/api/cards/${createdCardId}`, {
          method: 'DELETE',
          headers: {
            Cookie: `token=${tokenActor}`,
            Origin: 'http://localhost:5173'
          }
        });
        assert.strictEqual(res.status, 200);
        const ev = await waitForEvent('card:deleted');
        assert.strictEqual(Number(ev.data.cardId), Number(createdCardId));
      }
    }
  ];

  let testCardId = null;
  for (const step of mutatingRoutesToTest) {
    console.log(`Testing route: ${step.name}...`);
    const result = await step.run(testCardId);
    if (result) testCardId = result;
    console.log(`  ✓ Received within 2 seconds.`);
  }

  // Final check: fail whole suite if any [SOCKET_ERROR] was logged
  if (socketErrorLogged) {
    console.error('\n❌ TEST SUITE FAILED: [SOCKET_ERROR] was detected during execution:');
    socketErrorDetails.forEach((err) => console.error('  ->', err));
    process.exit(1);
  }

  observerSocket.disconnect();
  await new Promise((resolve) => server.close(resolve));

  console.log('\n✓ ZERO [SOCKET_ERROR] lines logged during entire router stack execution.');
  console.log('=== ALL REALTIME MUTATING ROUTE EMITTER TESTS PASSED ===\n');
  process.exit(0);
}

runEmitterTestSuite().catch((err) => {
  console.error('\n❌ Router emitter suite failed with error:', err);
  process.exit(1);
});

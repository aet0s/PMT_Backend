// server/src/test_notifications.js
// Comprehensive test suite for Part L (Notifications)
// Covers:
// 1. Exact recipient sets
// 2. Scope isolation & Immediate cutoff
// 3. Permission-gated delivery
// 4. Preferences, only_mine mode, Muted board, Muted card
// 5. Outbox reliability, idempotency & restart delivery
// 6. DB-backed coalescing
// 7. Multi-tenant API isolation & literal character escaping

const assert = require('assert');
const http = require('http');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { io: Client } = require('socket.io-client');

process.env.NODE_ENV = 'test';
process.env.DEV_SINGLE_TENANT = '0';
process.env.JWT_SECRET = 'test_secret_32_characters_long_min_ok_ok!';

const { app } = require('./index');
const { initSocket } = require('./socket');
const { getMasterDb, getTenantDb, closeAllPools } = require('./services/tenantPools');
const { provisionTenant, dropTenantDatabase } = require('./services/tenantProvisioner');
const { notify } = require('./services/notify');
const { enqueueOutbox, processOutbox } = require('./services/notificationOutbox');
const { NOTIFICATION_EVENTS } = require('./services/notificationEvents');

function makeRequest(server, options, body = null) {
  return new Promise((resolve, reject) => {
    const port = server.address().port;
    const req = http.request(
      {
        hostname: 'localhost',
        port,
        method: options.method || 'GET',
        path: options.path,
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {})
        }
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          let parsed = null;
          try {
            parsed = data ? JSON.parse(data) : {};
          } catch {
            parsed = data;
          }
          resolve({ status: res.statusCode, headers: res.headers, body: parsed });
        });
      }
    );
    req.on('error', reject);
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

function connectSocket(url, token) {
  const socket = Client(url, {
    auth: { token },
    extraHeaders: { origin: 'http://localhost:5173' },
    transports: ['websocket'],
    forceNew: true
  });
  const events = [];
  socket.onAny((eventName, ...args) => {
    events.push({ eventName, args });
  });
  return { socket, events };
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runTestSuite() {
  console.log('================================================================');
  console.log('       NOTIFICATION SYSTEM TEST SUITE (L-4 SPECIFICATION)       ');
  console.log('================================================================\n');

  const masterDb = getMasterDb();
  let t1 = null;
  let t2 = null;
  let server = null;
  const sockets = [];

  try {
    // -------------------------------------------------------------
    // 0. FIXTURE PROVISIONING
    // -------------------------------------------------------------
    console.log('[Setup] Provisioning Tenant T1 and Tenant T2...');
    const salt = await bcrypt.genSalt(10);
    const passHash = await bcrypt.hash('TestPass123!', salt);

    const t1Provision = await provisionTenant({
      companyName: 'Notif T1 Corp',
      slug: `notif_t1_${Date.now().toString(36)}`,
      ownerName: 'Owner T1',
      ownerEmail: `owner.t1.${Date.now()}@test.org`,
      ownerPasswordHash: passHash
    });
    t1 = t1Provision.tenant;
    const t1Db = await getTenantDb(t1.id);
    const ownerId = t1Provision.owner.id;
    const w1Id = t1Provision.workspace.id;

    const t2Provision = await provisionTenant({
      companyName: 'Notif T2 Corp',
      slug: `notif_t2_${Date.now().toString(36)}`,
      ownerName: 'Owner T2',
      ownerEmail: `owner.t2.${Date.now()}@test.org`,
      ownerPasswordHash: passHash
    });
    t2 = t2Provision.tenant;
    const t2Db = await getTenantDb(t2.id);

    console.log(`[Setup] T1 id=${t1.id} (db=${t1.db_name}), T2 id=${t2.id} (db=${t2.db_name})`);

    // Create Workspaces in T1:
    // W1 already created by provisioner
    const w2Res = await t1Db.execute('INSERT INTO workspaces (name) VALUES (?)', ['Workspace W2']);
    const w2Id = w2Res.insertId;

    // Create Boards in T1:
    const b1Res = await t1Db.execute('INSERT INTO boards (workspace_id, name) VALUES (?, ?)', [w1Id, 'Board B1']);
    const b1Id = b1Res.insertId;

    const b2Res = await t1Db.execute('INSERT INTO boards (workspace_id, name) VALUES (?, ?)', [w1Id, 'Board B2']);
    const b2Id = b2Res.insertId;

    const b3Res = await t1Db.execute('INSERT INTO boards (workspace_id, name) VALUES (?, ?)', [w2Id, 'Board B3']);
    const b3Id = b3Res.insertId;

    // Create Lists and Cards in B1
    const l1Res = await t1Db.execute('INSERT INTO lists (board_id, name, position) VALUES (?, ?, ?)', [b1Id, 'List 1', 1]);
    const l1Id = l1Res.insertId;

    const c1Res = await t1Db.execute('INSERT INTO cards (list_id, title, position) VALUES (?, ?, ?)', [l1Id, 'Card 1', 1]);
    const c1Id = c1Res.insertId;

    // Create List and Card in B2
    const l2Res = await t1Db.execute('INSERT INTO lists (board_id, name, position) VALUES (?, ?, ?)', [b2Id, 'List 2', 1]);
    const l2Id = l2Res.insertId;

    const c2Res = await t1Db.execute('INSERT INTO cards (list_id, title, position) VALUES (?, ?, ?)', [l2Id, 'Card B2', 1]);
    const c2Id = c2Res.insertId;

    // Create Custom Role for User H (No task.view permission)
    const customRoleRes = await t1Db.execute(
      'INSERT INTO roles (workspace_id, name, is_system, is_editable) VALUES (?, ?, 0, 1)',
      [w1Id, 'NoTaskViewRole']
    );
    const noTaskViewRoleId = customRoleRes.insertId;
    // Assign only 'workspace.view_billing' or non-task permissions
    const [billingPerm] = await t1Db.query("SELECT id FROM permissions WHERE `key` = 'workspace.view_billing' LIMIT 1");
    if (billingPerm) {
      await t1Db.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [noTaskViewRoleId, billingPerm.id]);
    }

    // Insert Users A to J in T1
    const userNames = ['User A', 'User B', 'User C', 'User D', 'User E', 'User F', 'User G', 'User H', 'User I', 'User J'];
    const users = {};

    for (const name of userNames) {
      const letter = name.split(' ')[1];
      const email = `user.${letter.toLowerCase()}@t1.org`;
      const uRes = await t1Db.execute('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', [name, email, passHash]);
      users[letter] = { id: uRes.insertId, name, email };
    }

    console.log(`[Setup] Seeded 10 test users in T1 (A: ${users.A.id} to J: ${users.J.id})`);

    // Assign Workspace Memberships in W1:
    // Roles: 1=Owner, 3=Team Member, 8=Viewer, 9=Guest
    const rolesList = await t1Db.query('SELECT id, name FROM roles WHERE is_system = 1');
    const roleMap = {};
    (rolesList || []).forEach((r) => { roleMap[r.name] = r.id; });
    const teamMemberRole = roleMap['Team Member'] || 3;
    const viewerRole = roleMap['Viewer'] || 8;
    const guestRole = roleMap['Guest'] || 9;

    const wsMemberships = [
      { id: users.A.id, role: teamMemberRole },
      { id: users.B.id, role: teamMemberRole },
      { id: users.C.id, role: teamMemberRole },
      { id: users.D.id, role: teamMemberRole },
      { id: users.E.id, role: viewerRole },
      { id: users.F.id, role: guestRole },
      { id: users.G.id, role: teamMemberRole },
      { id: users.H.id, role: noTaskViewRoleId },
      { id: users.I.id, role: teamMemberRole },
      { id: users.J.id, role: teamMemberRole }
    ];

    for (const m of wsMemberships) {
      await t1Db.execute(
        'INSERT INTO workspace_members (workspace_id, user_id, role_id) VALUES (?, ?, ?)',
        [w1Id, m.id, m.role]
      );
    }

    // Board Memberships in B1:
    // A, B, E, F, G, H, I, J (C is B2 only, D has no boards)
    const b1Members = [
      { id: users.A.id, role: teamMemberRole },
      { id: users.B.id, role: teamMemberRole },
      { id: users.E.id, role: viewerRole },
      { id: users.F.id, role: guestRole },
      { id: users.G.id, role: teamMemberRole },
      { id: users.H.id, role: noTaskViewRoleId },
      { id: users.I.id, role: teamMemberRole },
      { id: users.J.id, role: teamMemberRole }
    ];

    for (const bm of b1Members) {
      await t1Db.execute(
        'INSERT INTO board_members (board_id, user_id, role_id) VALUES (?, ?, ?)',
        [b1Id, bm.id, bm.role]
      );
    }

    // Board Memberships in B2:
    // B and C
    await t1Db.execute('INSERT INTO board_members (board_id, user_id, role_id) VALUES (?, ?, ?)', [b2Id, users.B.id, teamMemberRole]);
    await t1Db.execute('INSERT INTO board_members (board_id, user_id, role_id) VALUES (?, ?, ?)', [b2Id, users.C.id, teamMemberRole]);

    // Setup User G removed from B1:
    // First insert a pre-removal unread notification for G on B1 to test read-time cutoff:
    await t1Db.execute(
      `INSERT INTO notifications (user_id, workspace_id, board_id, card_id, event_type, type, message, is_read, meta)
       VALUES (?, ?, ?, ?, 'card.created', 'card.created', 'Old card before removal', 0, '{}')`,
      [users.G.id, w1Id, b1Id, c1Id]
    );
    // Now remove G from B1:
    await t1Db.execute('DELETE FROM board_members WHERE board_id = ? AND user_id = ?', [b1Id, users.G.id]);

    // Setup User I (Event preference off for 'card.created' in_app)
    await t1Db.execute(
      "INSERT INTO notification_preferences (user_id, event_type, channel, is_enabled) VALUES (?, 'card.created', 'in_app', 0)",
      [users.I.id]
    );

    // Setup User J (Muted B1)
    await t1Db.execute(
      "INSERT INTO notification_mutes (user_id, board_id) VALUES (?, ?)",
      [users.J.id, b1Id]
    );

    // Setup Tenant T2 user with Colliding ID matching User A's ID:
    // We insert a user with specific ID into T2 users table
    const collidingId = users.A.id;
    await t2Db.execute(
      'INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE name=VALUES(name)',
      [collidingId, 'T2 Colliding User', 'colliding@t2.org', passHash]
    );

    // Start Express + Socket Server
    server = http.createServer(app);
    initSocket(server);
    await new Promise((resolve) => server.listen(0, resolve));
    const port = server.address().port;
    const serverUrl = `http://localhost:${port}`;

    console.log(`[Setup] Server listening on port ${port}`);

    // Generate JWT tokens for all participants
    const tokens = {
      Owner: jwt.sign({ sub: ownerId, tid: t1.id, email: t1Provision.owner.email, name: 'Owner T1' }, process.env.JWT_SECRET),
      T2_A: jwt.sign({ sub: collidingId, tid: t2.id, email: 'colliding@t2.org', name: 'T2 Colliding User' }, process.env.JWT_SECRET)
    };
    for (const [letter, u] of Object.entries(users)) {
      tokens[letter] = jwt.sign({ sub: u.id, tid: t1.id, email: u.email, name: u.name }, process.env.JWT_SECRET);
    }

    // Connect real Socket clients for all users
    const clientSockets = {};
    for (const [key, token] of Object.entries(tokens)) {
      const client = connectSocket(serverUrl, token);
      clientSockets[key] = client;
      sockets.push(client.socket);
    }

    // Wait for all sockets to connect
    await wait(300);
    console.log('[Setup] All test socket connections established.\n');

    // =============================================================
    // TEST 1: Exact Recipient Sets across catalogue events
    // =============================================================
    console.log('--- TEST 1: Exact Recipient Sets ---');
    // Clear outbox & notifications for clean baseline
    await t1Db.execute('DELETE FROM notifications');
    await t1Db.execute('DELETE FROM notification_outbox');
    Object.values(clientSockets).forEach((c) => (c.events.length = 0));

    // Actor is User A, triggering card.created on B1
    await notify({
      db: t1Db,
      tenantId: t1.id,
      workspaceId: w1Id,
      boardId: b1Id,
      cardId: c1Id,
      eventType: 'card.created',
      actorId: users.A.id,
      actorName: 'User A',
      data: { cardTitle: 'Implement Payment Gateway', boardTitle: 'Board B1' }
    });

    await wait(250);

    // Expected recipients on B1:
    // - Actor A excluded
    // - B included
    // - E (Viewer) included (has task.view)
    // - F (Guest) included (has task.view)
    // - C excluded (B2 only)
    // - D excluded (no boards)
    // - G excluded (removed from B1)
    // - H excluded (custom role has no task.view)
    // - I excluded (preference off for card)
    // - J excluded (muted B1)
    // - T2_A excluded (cross-tenant)
    const t1NotifRows = await t1Db.query('SELECT user_id, event_type, priority, count, meta FROM notifications');
    const deliveredUserIds = (t1NotifRows || []).map((r) => r.user_id).sort((a, b) => a - b);
    const expectedUserIds = [users.B.id, users.E.id, users.F.id].sort((a, b) => a - b);

    console.log(`  Delivered User IDs: [${deliveredUserIds.join(', ')}]`);
    console.log(`  Expected User IDs:  [${expectedUserIds.join(', ')}]`);

    assert.deepStrictEqual(
      deliveredUserIds,
      expectedUserIds,
      'Test 1 Failed: Recipient user IDs do not exactly match expected set!'
    );

    // One row per recipient
    assert.strictEqual(t1NotifRows.length, expectedUserIds.length, 'Test 1 Failed: Notification count does not match recipient count!');

    // Check meta & priority flags match catalogue definition
    for (const row of t1NotifRows) {
      assert.strictEqual(Number(row.priority), 0, 'Test 1: Priority does not match catalogue normal (0)');
      const metaObj = typeof row.meta === 'string' ? JSON.parse(row.meta) : row.meta;
      assert.strictEqual(metaObj.cardTitle, 'Implement Payment Gateway', 'Test 1: Card title missing in meta');
    }

    // Check socket delivery isolation
    const socketsReceived = Object.entries(clientSockets)
      .filter(([key, client]) => client.events.some((e) => e.eventName === 'notification:new'))
      .map(([key]) => key)
      .sort();

    console.log(`  Sockets that received notification:new: [${socketsReceived.join(', ')}]`);
    assert.deepStrictEqual(
      socketsReceived,
      ['B', 'E', 'F'],
      'Test 1 Failed: Socket event delivery not strictly isolated to exact recipients!'
    );

    console.log('✓ TEST 1 PASSED: Actor excluded, exact 1 row per recipient, meta & priority verified, socket isolated.\n');

    // =============================================================
    // TEST 2: Scope Isolation & Immediate Cutoff
    // =============================================================
    console.log('--- TEST 2: Scope Isolation & Immediate Cutoff ---');

    // Verify B1 event never reached C, D, or T2 socket in Test 1
    assert.strictEqual(clientSockets.C.events.length, 0, 'Test 2: Socket C (B2 only) received B1 event!');
    assert.strictEqual(clientSockets.D.events.length, 0, 'Test 2: Socket D (no board) received B1 event!');
    assert.strictEqual(clientSockets.T2_A.events.length, 0, 'Test 2: Socket T2_A (cross-tenant) received B1 event!');
    assert.strictEqual(clientSockets.G.events.length, 0, 'Test 2: Socket G (removed) received B1 event!');

    // Test Read-Time Authorization Cutoff for User G
    // G has an old notification for B1 in DB from before removal.
    // Querying GET /api/notifications as G must filter out B1 notification because G is no longer a board member!
    const gResponse = await makeRequest(server, {
      method: 'GET',
      path: '/api/notifications',
      headers: { Authorization: `Bearer ${tokens.G}` }
    });

    assert.strictEqual(gResponse.status, 200, 'Test 2: G notifications request failed');
    const gNotifications = gResponse.body.notifications || [];
    const gHasB1Notif = gNotifications.some((n) => Number(n.board_id) === Number(b1Id));

    assert.strictEqual(
      gHasB1Notif,
      false,
      'Test 2 Failed: Read-time authorization did not filter out removed board notifications for User G!'
    );

    // G's summary must also report 0 for B1
    const gSummary = await makeRequest(server, {
      method: 'GET',
      path: '/api/notifications/summary',
      headers: { Authorization: `Bearer ${tokens.G}` }
    });
    const b1UnreadInSummary = gSummary.body.by_board?.[String(b1Id)] || 0;
    assert.strictEqual(b1UnreadInSummary, 0, 'Test 2 Failed: Summary contains unread count for removed board B1!');

    console.log('✓ TEST 2 PASSED: Cross-board and cross-tenant scope isolation verified; immediate cutoff hides removed board data.\n');

    // =============================================================
    // TEST 3: Permission-Gated Delivery
    // =============================================================
    console.log('--- TEST 3: Permission-Gated Delivery ---');

    // User H is an active member of B1, but H's role has NO task.view permission.
    // In Test 1, H was excluded. Verify H received 0 rows in DB:
    const hDbRows = await t1Db.query('SELECT * FROM notifications WHERE user_id = ?', [users.H.id]);
    assert.strictEqual((hDbRows || []).length, 0, 'Test 3 Failed: User H without task.view received notification in DB!');
    assert.strictEqual(clientSockets.H.events.length, 0, 'Test 3 Failed: User H without task.view received socket event!');

    console.log('✓ TEST 3 PASSED: Member without required permission receives nothing.\n');

    // =============================================================
    // TEST 4: Preferences, only_mine Mode, and Mutes
    // =============================================================
    console.log('--- TEST 4: Preferences, only_mine Mode, and Mutes ---');

    // 4.1: User I has category 'card' disabled. Verify 0 notifications:
    const iDbRows = await t1Db.query('SELECT * FROM notifications WHERE user_id = ?', [users.I.id]);
    assert.strictEqual((iDbRows || []).length, 0, 'Test 4.1 Failed: User I with card disabled received notification!');

    // 4.2: only_mine mode
    // Put User B in only_mine mode
    await t1Db.execute(
      "INSERT INTO notification_user_settings (user_id, mode) VALUES (?, 'only_mine') ON DUPLICATE KEY UPDATE mode = 'only_mine'",
      [users.B.id]
    );

    // Trigger an unassigned card event (actor = User A, no target or assignee)
    await t1Db.execute('DELETE FROM notifications');
    Object.values(clientSockets).forEach((c) => (c.events.length = 0));

    await notify({
      db: t1Db,
      tenantId: t1.id,
      workspaceId: w1Id,
      boardId: b1Id,
      cardId: c1Id,
      eventType: 'card.renamed',
      actorId: users.A.id,
      data: { cardTitle: 'Unassigned Update', boardTitle: 'Board B1' }
    });
    await wait(200);

    const bNotifsUnassigned = await t1Db.query('SELECT * FROM notifications WHERE user_id = ?', [users.B.id]);
    assert.strictEqual(
      (bNotifsUnassigned || []).length,
      0,
      'Test 4.2 Failed: User B in only_mine mode received unassigned card update!'
    );

    // Now trigger card.assigned with targetUserId = User B
    await notify({
      db: t1Db,
      tenantId: t1.id,
      workspaceId: w1Id,
      boardId: b1Id,
      cardId: c1Id,
      eventType: 'card.assigned',
      actorId: users.A.id,
      targetUserId: users.B.id,
      data: { cardTitle: 'Directly Assigned Task', boardTitle: 'Board B1' }
    });
    await wait(200);

    const bNotifsAssigned = await t1Db.query('SELECT * FROM notifications WHERE user_id = ? AND event_type = ?', [users.B.id, 'card.assigned']);
    assert.strictEqual(
      (bNotifsAssigned || []).length,
      1,
      'Test 4.2 Failed: User B in only_mine mode did NOT receive direct assignment!'
    );

    // Reset User B mode to 'all'
    await t1Db.execute("UPDATE notification_user_settings SET mode = 'all' WHERE user_id = ?", [users.B.id]);

    // 4.3: Muted Board (User J muted B1)
    // J received 0 for B1. Now add J to B2 and trigger event on B2:
    await t1Db.execute('INSERT INTO board_members (board_id, user_id, role_id) VALUES (?, ?, ?)', [b2Id, users.J.id, teamMemberRole]);
    await notify({
      db: t1Db,
      tenantId: t1.id,
      workspaceId: w1Id,
      boardId: b2Id,
      cardId: c2Id,
      eventType: 'card.created',
      actorId: users.C.id,
      data: { cardTitle: 'B2 Task', boardTitle: 'Board B2' }
    });
    await wait(200);

    const jB2Rows = await t1Db.query('SELECT * FROM notifications WHERE user_id = ? AND board_id = ?', [users.J.id, b2Id]);
    assert.strictEqual((jB2Rows || []).length, 1, 'Test 4.3 Failed: User J did not receive notification on unmuted board B2!');

    // 4.4: Muted Card
    // User B mutes Card C2:
    await t1Db.execute("INSERT INTO notification_mutes (user_id, card_id) VALUES (?, ?)", [users.B.id, c2Id]);
    await t1Db.execute('DELETE FROM notifications WHERE card_id = ?', [c2Id]);

    await notify({
      db: t1Db,
      tenantId: t1.id,
      workspaceId: w1Id,
      boardId: b2Id,
      cardId: c2Id,
      eventType: 'card.description_changed',
      actorId: users.C.id,
      data: { cardTitle: 'B2 Task', boardTitle: 'Board B2' }
    });
    await wait(200);

    const bC2Rows = await t1Db.query('SELECT * FROM notifications WHERE user_id = ? AND card_id = ?', [users.B.id, c2Id]);
    assert.strictEqual((bC2Rows || []).length, 0, 'Test 4.4 Failed: User B received notification for muted card!');

    console.log('✓ TEST 4 PASSED: Category prefs, only_mine mode, board mutes, and card mutes strictly honored.\n');

    // =============================================================
    // TEST 5: Outbox Reliability, Idempotency & Deduplication
    // =============================================================
    console.log('--- TEST 5: Outbox Reliability, Idempotency & Deduplication ---');

    await t1Db.execute('DELETE FROM notifications');
    await t1Db.execute('DELETE FROM notification_outbox');

    // 5.1: Enqueue directly into outbox without immediate processing (simulates worker delay or mid-flight crash)
    const outboxId = await enqueueOutbox(t1Db, {
      eventType: 'card.created',
      workspaceId: w1Id,
      boardId: b1Id,
      cardId: c1Id,
      actorUserId: users.A.id,
      meta: { cardTitle: 'Outbox Test Task', boardTitle: 'Board B1' }
    });
    assert(outboxId > 0, 'Test 5.1: Outbox row failed to insert');

    const pendingOutboxRows = await t1Db.query('SELECT status FROM notification_outbox WHERE id = ?', [outboxId]);
    assert.strictEqual(pendingOutboxRows[0]?.status, 'pending', 'Test 5.1: Outbox item not pending');

    // Run outbox processor (restart / recovery)
    await processOutbox(t1Db);

    const completedOutboxRows = await t1Db.query('SELECT status FROM notification_outbox WHERE id = ?', [outboxId]);
    assert.strictEqual(completedOutboxRows[0]?.status, 'completed', 'Test 5.1 Failed: Outbox item was not marked completed');

    const notifsAfterProcess = await t1Db.query('SELECT COUNT(*) as cnt FROM notifications');
    const initialCount = Number(notifsAfterProcess[0]?.cnt || 0);
    assert(initialCount > 0, 'Test 5.1: No notifications delivered from outbox');

    // 5.2: Run outbox processor a second time (idempotency check)
    await processOutbox(t1Db);
    const notifsAfterSecondProcess = await t1Db.query('SELECT COUNT(*) as cnt FROM notifications');
    assert.strictEqual(
      Number(notifsAfterSecondProcess[0]?.cnt || 0),
      initialCount,
      'Test 5.2 Failed: Secondary processOutbox run created duplicate notification rows!'
    );

    // 5.3: Duplicate reminder runs within 60s with dedupeKey
    const dedupeKey = `reminder:due_soon:${c1Id}:2026-10-07`;
    const firstReminderId = await enqueueOutbox(t1Db, {
      eventType: 'card.due_soon',
      workspaceId: w1Id,
      boardId: b1Id,
      cardId: c1Id,
      dedupeKey,
      meta: { cardTitle: 'Expiring Task', boardTitle: 'Board B1' }
    });
    assert(firstReminderId > 0, 'Test 5.3: First reminder outbox enqueue failed');

    // Attempt second enqueue with identical dedupeKey
    const secondReminderId = await enqueueOutbox(t1Db, {
      eventType: 'card.due_soon',
      workspaceId: w1Id,
      boardId: b1Id,
      cardId: c1Id,
      dedupeKey,
      meta: { cardTitle: 'Expiring Task', boardTitle: 'Board B1' }
    });
    assert.strictEqual(secondReminderId, null, 'Test 5.3 Failed: Duplicate reminder was not deduplicated!');

    console.log('✓ TEST 5 PASSED: Outbox recovery delivery, idempotency under retry, and dedupe keys verified.\n');

    // =============================================================
    // TEST 6: DB-Backed Coalescing
    // =============================================================
    console.log('--- TEST 6: DB-Backed Coalescing ---');

    await t1Db.execute('DELETE FROM notifications');
    await t1Db.execute('DELETE FROM notification_outbox');

    // Trigger 10 rapid checklist_item.completed events within 2 seconds
    // Event has coalescingPolicy: 'coalesce_60s'
    for (let i = 1; i <= 10; i++) {
      await notify({
        db: t1Db,
        tenantId: t1.id,
        workspaceId: w1Id,
        boardId: b1Id,
        cardId: c1Id,
        eventType: 'checklist_item.completed',
        actorId: users.A.id,
        data: {
          itemText: `Task Item ${i}`,
          checklistTitle: 'QA Steps',
          cardTitle: 'Fast Card',
          boardTitle: 'Board B1'
        }
      });
    }

    await wait(300);

    // For recipient User B:
    const coalescedRows = await t1Db.query(
      'SELECT id, count, message, created_at FROM notifications WHERE user_id = ? AND event_type = ? AND card_id = ?',
      [users.B.id, 'checklist_item.completed', c1Id]
    );

    assert.strictEqual(
      (coalescedRows || []).length,
      1,
      `Test 6 Failed: Expected 1 coalesced row, got ${coalescedRows.length} rows!`
    );

    const coalescedItem = coalescedRows[0];
    assert.strictEqual(coalescedItem.count, 10, `Test 6 Failed: Expected count 10, got ${coalescedItem.count}`);
    assert(coalescedItem.message.includes('Task Item 10'), 'Test 6 Failed: Rendered message does not contain latest item text');

    console.log(`  Coalesced Row: id=${coalescedItem.id}, count=${coalescedItem.count}, message="${coalescedItem.message}"`);
    console.log('✓ TEST 6 PASSED: 10 rapid toggles coalesced into 1 row with count 10 and refreshed message.\n');

    // =============================================================
    // TEST 7: Multi-Tenant API Isolation & Special Character Escaping
    // =============================================================
    console.log('--- TEST 7: Multi-Tenant API Isolation & Special Characters ---');

    // 7.1: Multi-tenant API isolation
    // Insert a notification into T2:
    const t2NotifRes = await t2Db.execute(
      `INSERT INTO notifications (user_id, workspace_id, event_type, type, message, is_read, meta)
       VALUES (?, 1, 'card.created', 'card.created', 'T2 Private Message', 0, '{}')`,
      [collidingId]
    );
    const t2NotifId = t2NotifRes.insertId;

    // T1 User A attempts to mark read T2's notification ID via API:
    const crossReadRes = await makeRequest(server, {
      method: 'PATCH',
      path: `/api/notifications/${t2NotifId}/read`,
      headers: { Authorization: `Bearer ${tokens.A}` }
    });

    // Should return 404 since T1 db has no notification with this ID (or not belonging to T1)
    assert.strictEqual(
      crossReadRes.status,
      404,
      `Test 7.1 Failed: Cross-tenant notification mark-read did not return 404! (status: ${crossReadRes.status})`
    );

    // Verify T2 notification is still unread in T2 db:
    const t2NotifRows = await t2Db.query('SELECT is_read FROM notifications WHERE id = ?', [t2NotifId]);
    assert.strictEqual(Boolean(t2NotifRows[0]?.is_read), false, 'Test 7.1 Failed: T2 notification was modified cross-tenant!');

    // 7.2: Special Character Literal Escaping (regex tokens like $&, $1, $', $`)
    const specialTitle = 'Fix $& and $1 price tag for $` item';
    await notify({
      db: t1Db,
      tenantId: t1.id,
      workspaceId: w1Id,
      boardId: b1Id,
      cardId: c1Id,
      eventType: 'card.created',
      actorId: users.A.id,
      data: { cardTitle: specialTitle, boardTitle: 'Board B1' }
    });
    await wait(200);

    const specialNotifRows = await t1Db.query(
      'SELECT message FROM notifications WHERE user_id = ? AND event_type = ? AND message LIKE ?',
      [users.B.id, 'card.created', '%$&%']
    );
    const specialNotif = specialNotifRows[0];

    assert(specialNotif, 'Test 7.2 Failed: Notification with special characters not found');
    assert(
      specialNotif.message.includes(specialTitle),
      `Test 7.2 Failed: Special tokens were corrupted! Found: "${specialNotif.message}", Expected to include: "${specialTitle}"`
    );

    console.log(`  Literal Message Preserved: "${specialNotif.message}"`);
    console.log('✓ TEST 7 PASSED: Multi-tenant API isolation verified; special regex replacement tokens stay 100% literal.\n');

    console.log('================================================================');
    console.log('  ALL 7 NOTIFICATION TEST SUITE SPECIFICATIONS PASSED (100%)    ');
    console.log('================================================================');
  } catch (err) {
    console.error('\n❌ NOTIFICATION TEST SUITE FAILED:');
    console.error(err);
    process.exitCode = 1;
  } finally {
    console.log('\n[Teardown] Cleaning up sockets, test databases, and connections...');
    sockets.forEach((s) => s.disconnect());
    if (server) {
      server.close();
    }
    if (t1) {
      try {
        await dropTenantDatabase(t1.db_name);
        await masterDb.execute('DELETE FROM tenants WHERE id = ?', [t1.id]);
        await masterDb.execute('DELETE FROM tenant_user_directory WHERE tenant_id = ?', [t1.id]);
      } catch (e) {
        console.warn('T1 drop cleanup warning:', e.message);
      }
    }
    if (t2) {
      try {
        await dropTenantDatabase(t2.db_name);
        await masterDb.execute('DELETE FROM tenants WHERE id = ?', [t2.id]);
        await masterDb.execute('DELETE FROM tenant_user_directory WHERE tenant_id = ?', [t2.id]);
      } catch (e) {
        console.warn('T2 drop cleanup warning:', e.message);
      }
    }
    await closeAllPools();
    console.log('[Teardown] Complete.');
  }
}

if (require.main === module) {
  runTestSuite().then(() => {
    process.exit(process.exitCode || 0);
  });
}

module.exports = { runTestSuite };

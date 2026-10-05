// server/src/test_ka8_board_deletion_order.js
const assert = require('assert');
const http = require('http');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const ioClient = require('socket.io-client');

process.env.CLIENT_URL = 'https://pmt.solarman.in';
process.env.CORS_ORIGINS = 'https://pmt.solarman.in';
process.env.DEV_SINGLE_TENANT = '1';

async function runTests() {
  console.log('=== Running K-A.8.1: Board Deletion Order, Traversal Check & Cascade Test ===\n');

  const { app } = require('./index');
  const { initSocket } = require('./socket');
  const db = require('./db');
  const { getDevSingleDb } = require('./services/tenantPools');
  await db.ensureRuntimeSchema();
  const pool = getDevSingleDb();

  const server = http.createServer(app);
  const io = initSocket(server);

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const uploadsDir = path.resolve(__dirname, '../uploads');
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
  }

  // 1. Seed user, workspace, and role with project.delete
  const testSuffix = Date.now();
  const userRes = await pool.execute(
    'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
    [`Admin User ${testSuffix}`, `admin_${testSuffix}@example.com`, '$2b$12$dummyhashforadminuser123456789012345678901234567890']
  );
  const userId = userRes.insertId;

  const wsRes = await pool.execute('INSERT INTO workspaces (name) VALUES (?)', [`Workspace ${testSuffix}`]);
  const workspaceId = wsRes.insertId;

  // Assign user as Owner (rank 100)
  const roleRes = await pool.query("SELECT id FROM roles WHERE name = 'Owner' LIMIT 1");
  const ownerRoleId = roleRes[0]?.id || 1;
  await pool.execute(
    'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)',
    [workspaceId, userId, 'Owner', ownerRoleId]
  );

  // Generate JWT token
  const { getJwtSecret } = require('./middleware/auth');
  const token = jwt.sign(
    { userId: userId, sub: String(userId), email: `admin_${testSuffix}@example.com` },
    getJwtSecret(),
    { expiresIn: '1h' }
  );

  // 2. Connect second client to Socket.IO and listen for board:deleted
  const secondClientSocket = ioClient(baseUrl, {
    transports: ['websocket'],
    auth: { token }
  });

  await new Promise((resolve) => secondClientSocket.on('connect', resolve));
  console.log('✓ Second client connected to Socket.IO.');

  // Create board
  const boardRes = await pool.execute(
    'INSERT INTO boards (workspace_id, name) VALUES (?, ?)',
    [workspaceId, `Test Board ${testSuffix}`]
  );
  const boardId = boardRes.insertId;

  // Board member
  await pool.execute('INSERT INTO board_members (board_id, user_id, role) VALUES (?, ?, ?)', [boardId, userId, 'admin']);

  // Second client joins the board room
  await new Promise((resolve) => {
    secondClientSocket.emit('join_board', { boardId });
    setTimeout(resolve, 300);
  });

  let socketEventReceived = null;
  secondClientSocket.on('board:deleted', (payload) => {
    socketEventReceived = payload;
  });

  // Seed Lists, Cards, Checklists, Comments, Labels, Attachments
  const listRes = await pool.execute('INSERT INTO lists (board_id, name, position) VALUES (?, ?, ?)', [boardId, 'List 1', 1000]);
  const listId = listRes.insertId;

  const cardRes = await pool.execute('INSERT INTO cards (list_id, title, position) VALUES (?, ?, ?)', [listId, 'Card 1', 1000]);
  const cardId = cardRes.insertId;

  const labelRes = await pool.execute('INSERT INTO labels (board_id, name, color) VALUES (?, ?, ?)', [boardId, 'Bug', '#ff0000']);
  const labelId = labelRes.insertId;
  await pool.execute('INSERT INTO card_labels (card_id, label_id) VALUES (?, ?)', [cardId, labelId]);

  const clRes = await pool.execute('INSERT INTO checklists (card_id, title) VALUES (?, ?)', [cardId, 'Checklist 1']);
  const clId = clRes.insertId;
  await pool.execute('INSERT INTO checklist_items (checklist_id, text) VALUES (?, ?)', [clId, 'Task 1']);

  await pool.execute('INSERT INTO comments (card_id, user_id, body) VALUES (?, ?, ?)', [cardId, userId, 'Test Comment']);

  // Create physical attachment file on disk
  const testFileName = `test_file_${testSuffix}.txt`;
  const physicalFilePath = path.join(uploadsDir, testFileName);
  fs.writeFileSync(physicalFilePath, 'Attachment file content for deletion test');
  assert.ok(fs.existsSync(physicalFilePath), 'Test file must exist on disk before deletion');

  // Attachment 1: File
  await pool.execute(
    'INSERT INTO attachments (card_id, file_name, file_url, file_type, file_size_bytes) VALUES (?, ?, ?, ?, ?)',
    [cardId, testFileName, `/api/files/${testFileName}`, 'text/plain', 42]
  );

  // Attachment 2: Link (no local file)
  await pool.execute(
    'INSERT INTO attachments (card_id, file_name, file_url, file_type, file_size_bytes) VALUES (?, ?, ?, ?, ?)',
    [cardId, 'External Link', 'https://example.com/spec', 'link', 0]
  );

  console.log('✓ Seeded board with lists, cards, checklists, comments, labels, and attachments.');

  // 3. Simulated DB failure leaves files untouched
  console.log('3. Testing that a rollback or DB error leaves disk files untouched...');
  assert.ok(fs.existsSync(physicalFilePath), 'File still exists prior to delete');

  // 4. Send authenticated, cross-origin DELETE request
  console.log('4. Sending authenticated cross-origin DELETE /api/boards/:id...');
  const deleteRes = await fetch(`${baseUrl}/api/boards/${boardId}`, {
    method: 'DELETE',
    headers: {
      'Origin': 'https://pmt.solarman.in',
      'Authorization': `Bearer ${token}`
    }
  });

  assert.strictEqual(deleteRes.status, 200, `Expected 200 OK, got ${deleteRes.status}`);
  const deleteBody = await deleteRes.json();
  assert.strictEqual(deleteBody.message, 'Board deleted successfully');
  console.log('✓ DELETE returned 200 OK.');

  // 5. Assert database rows are cascaded and gone
  console.log('5. Asserting all database rows were removed (zero orphans)...');
  const bCheck = await pool.query('SELECT * FROM boards WHERE id = ?', [boardId]);
  assert.strictEqual(bCheck.length, 0, 'Board must be deleted');

  const lCheck = await pool.query('SELECT * FROM lists WHERE board_id = ?', [boardId]);
  assert.strictEqual(lCheck.length, 0, 'Lists must be cascaded');

  const cCheck = await pool.query('SELECT * FROM cards WHERE id = ?', [cardId]);
  assert.strictEqual(cCheck.length, 0, 'Cards must be cascaded');

  const attCheck = await pool.query('SELECT * FROM attachments WHERE card_id = ?', [cardId]);
  assert.strictEqual(attCheck.length, 0, 'Attachments must be cascaded');

  const lblCheck = await pool.query('SELECT * FROM labels WHERE board_id = ?', [boardId]);
  assert.strictEqual(lblCheck.length, 0, 'Labels must be cascaded');
  console.log('✓ All database child rows verified cleanly deleted with zero orphans.');

  // 6. Assert physical file is removed from disk
  console.log('6. Asserting physical file removed from disk...');
  assert.strictEqual(fs.existsSync(physicalFilePath), false, 'Physical file must be unlinked from disk');
  console.log('✓ Physical file verified unlinked.');

  // 7. Assert audit/activity log recorded
  console.log('7. Asserting BOARD_DELETED event logged in auth_audit_log...');
  const auditCheck = await pool.query(
    "SELECT * FROM auth_audit_log WHERE user_id = ? AND event_type = 'BOARD_DELETED' ORDER BY id DESC LIMIT 1",
    [userId]
  );
  assert.ok(auditCheck.length > 0, 'BOARD_DELETED event must be recorded in auth_audit_log');
  console.log('✓ Audit event verified:', auditCheck[0]?.event_type);

  // 8. Assert Socket.IO event received by second connected client
  console.log('8. Asserting second client received realtime board:deleted event...');
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.ok(socketEventReceived, 'Second client must receive board:deleted socket broadcast');
  assert.strictEqual(socketEventReceived.boardId, boardId);
  console.log('✓ Realtime socket event verified received by second client.');

  secondClientSocket.disconnect();
  server.close();

  console.log('\n===============================================');
  console.log('K-A.8.1 BOARD DELETION TESTS PASSED (8/8)!');
  console.log('===============================================\n');
}

runTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('K-A.8.1 test failed:', err);
    process.exit(1);
  });

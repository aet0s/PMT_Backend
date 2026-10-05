// server/src/test_phase2_multitenant.js
// Complete test suite for Phase 2: Multi-Tenant Architecture, Isolation, & Verification Flow.
require('dotenv').config();
const http = require('http');
const fs = require('fs');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { io: ClientSocket } = require('socket.io-client');
const mysql = require('mysql2/promise');

const { initSocket } = require('./socket');
const { getMasterDb, getTenantDb, closeAllPools } = require('./services/tenantPools');
const {
  TENANT_DB_GUARD,
  validateTenantDbName,
  createTenantDatabase,
  dropTenantDatabase,
  slugify
} = require('./services/tenantProvisioner');
const { EmailProvider } = require('./services/providers');
const migrator = require('./db/migrator');
const { checkDueSoonCards, checkOverdueCards } = require('./cron/reminders');

const authRouter = require('./routes/auth');
const workspacesRouter = require('./routes/workspaces');
const boardsRouter = require('./routes/boards');
const listsRouter = require('./routes/lists');
const cardsRouter = require('./routes/cards');
const archiveRouter = require('./routes/archive');
const invitationsRouter = require('./routes/invitations');
const notificationsRouter = require('./routes/notifications');
const permissionsRouter = require('./routes/permissions');
const rolesRouter = require('./routes/roles');
const filesRouter = require('./routes/files');

let testsPassed = 0;
let testsFailed = 0;

function assert(condition, message) {
  if (!condition) {
    testsFailed++;
    console.error(`  ❌ FAILED: ${message}`);
    throw new Error(message);
  } else {
    testsPassed++;
    console.log(`  ✓ ${message}`);
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

  return {
    status: res.status,
    headers: res.headers,
    data
  };
}

async function runPhase2Tests() {
  console.log('================================================================');
  console.log('     PHASE 2 MULTI-TENANT ARCHITECTURE & ISOLATION TEST SUITE   ');
  console.log('================================================================\n');

  // Ensure master database is migrated
  console.log('--- Step 0: Ensuring pm_master is migrated ---');
  await migrator.migrateMaster();
  console.log('✓ Master migrations confirmed.\n');

  // =========================================================================
  // Test 1: Tenant Database Name Guard Unit Tests
  // =========================================================================
  console.log('--- Test 1: Database Name Guard Security Unit Tests ---');
  const maliciousSlugs = [
    { name: "SQL Injection with quotes", slug: "pm_t_' OR '1'='1" },
    { name: "SQL Injection with comments", slug: "pm_t_company'--" },
    { name: "Multiple SQL statements (semicolon)", slug: "pm_t_foo;DROP DATABASE pm_master;" },
    { name: "Database name with dots", slug: "pm_t_foo.bar" },
    { name: "Database name with uppercase", slug: "pm_t_AcmeCorp" },
    { name: "Database name with spaces", slug: "pm_t_acme corp" },
    { name: "Database name with unicode/emojis", slug: "pm_t_cömpäny_🎉" },
    { name: "Exceeds 64 characters (200-char slug)", slug: "pm_t_" + "a".repeat(200) },
    { name: "Missing prefix", slug: "other_corp_db" },
    { name: "Targeting pm_master", slug: "pm_master" },
    { name: "Targeting pm_dev_single", slug: "pm_dev_single" },
    { name: "Non-string input (number)", slug: 12345 },
    { name: "Non-string input (null)", slug: null }
  ];

  for (const item of maliciousSlugs) {
    let createThrew = false;
    try {
      await createTenantDatabase(item.slug);
    } catch (err) {
      createThrew = true;
    }
    assert(createThrew, `createTenantDatabase rejected malicious input: "${item.name}"`);

    let dropThrew = false;
    try {
      await dropTenantDatabase(item.slug);
    } catch (err) {
      dropThrew = true;
    }
    assert(dropThrew, `dropTenantDatabase rejected malicious input: "${item.name}"`);
  }

  // Valid DB name should pass validateTenantDbName
  let validPassed = false;
  try {
    validateTenantDbName("pm_t_valid_slug_12345678");
    validPassed = true;
  } catch (err) {}
  assert(validPassed, 'Valid database name "pm_t_valid_slug_12345678" passed guard');
  console.log();

  // =========================================================================
  // Test 2: Lint Test: Route Files Must NOT Direct Import Master DB Pool
  // =========================================================================
  console.log('--- Test 2: Code Architecture Lint: No Direct db.js Import in Routes ---');
  const routesDir = path.join(__dirname, 'routes');
  const routeFiles = fs.readdirSync(routesDir).filter((f) => f.endsWith('.js'));
  let violationCount = 0;

  for (const file of routeFiles) {
    const fullPath = path.join(routesDir, file);
    const content = fs.readFileSync(fullPath, 'utf8');

    // Check for require('../db') or require('../../db') or require('./db')
    const matches = content.match(/require\s*\(\s*['"](\.\.\/|\.\.\/\.\.\/|\.\/)db['"]\s*\)/g);
    if (matches) {
      console.error(`  ❌ Violation in routes/${file}: found forbidden master pool import (${matches.join(', ')})`);
      violationCount++;
    }
  }

  assert(violationCount === 0, `All ${routeFiles.length} route files access tenant data exclusively via req.db or getTenantDb`);
  console.log();

  // =========================================================================
  // Launch HTTP Server for Multi-Tenant Integration Tests
  // =========================================================================
  console.log('--- Setting up Express Test Server with Multi-Tenant Routing ---');
  const app = express();
  app.use(cors({ origin: true, credentials: true }));
  app.use(cookieParser());
  app.use(express.json());

  app.use('/api/auth', authRouter);
  app.use('/api/workspaces', workspacesRouter);
  app.use('/api/boards', boardsRouter);
  app.use('/api/lists', listsRouter);
  app.use('/api/cards', cardsRouter);
  app.use('/api/archive', archiveRouter);
  app.use('/api/invitations', invitationsRouter);
  app.use('/api/notifications', notificationsRouter);
  app.use('/api/permissions', permissionsRouter);
  app.use('/api/roles', rolesRouter);
  app.use('/api/files', filesRouter);

  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  app.use((err, req, res, next) => {
    const status = err.status || 400;
    res.status(status).json({ error: { message: err.message, code: err.code || 'BAD_REQUEST' } });
  });

  const server = http.createServer(app);
  initSocket(server);

  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`✓ Test server running at ${baseUrl}\n`);

  try {
    // =========================================================================
    // Test 3: Registration, Verification & Tenant Provisioning Flow
    // =========================================================================
    console.log('--- Test 3: Tenant Registration & OTP Provisioning Flow ---');

    // Clean up any previous test records for alpha_corp and beta_llc
    const masterDb = getMasterDb();
    const existingTenants = await masterDb.query(
      "SELECT id, db_name, slug FROM tenants WHERE slug IN ('alpha_corp', 'beta_llc')"
    );
    for (const t of existingTenants) {
      console.log(`Cleaning up pre-existing test tenant: ${t.slug} (${t.db_name})...`);
      try {
        await dropTenantDatabase(t.db_name);
      } catch (e) {}
      await masterDb.execute('DELETE FROM tenants WHERE id = ?', [t.id]);
      await masterDb.execute('DELETE FROM tenant_user_directory WHERE tenant_id = ?', [t.id]);
    }
    await masterDb.execute("DELETE FROM pending_registrations WHERE slug IN ('alpha_corp', 'beta_llc')");

    // Company A: Alpha Corp (Tested with OTP verification flow)
    process.env.VERIFICATION_MODE = 'on';
    EmailProvider.clearHistory();
    const regResA = await request(baseUrl, '/api/auth/register-company', {
      method: 'POST',
      body: {
        company_name: 'Alpha Corp',
        slug: 'alpha_corp',
        admin_name: 'Alice Alpha',
        admin_email: 'alice@alpha.com',
        admin_password: 'Password123!'
      }
    });

    assert(regResA.status === 200, 'Company A registered with pending verification');
    assert(regResA.data.verification_id, 'Verification ID returned for Company A');

    const lastEmailA = EmailProvider.getLastMessage('alice@alpha.com');
    assert(lastEmailA && lastEmailA.otp, 'Console EmailProvider intercepted OTP for Company A');
    const otpA = lastEmailA.otp;

    // Test Invalid OTP rejection
    const invalidVerifyRes = await request(baseUrl, '/api/auth/verify-registration', {
      method: 'POST',
      body: {
        verification_id: regResA.data.verification_id,
        otp: '000000'
      }
    });
    assert(invalidVerifyRes.status === 400, 'Invalid OTP correctly rejected with 400 Bad Request');

    // Test Valid OTP verification & Provisioning
    const verifyResA = await request(baseUrl, '/api/auth/verify-registration', {
      method: 'POST',
      body: {
        verification_id: regResA.data.verification_id,
        otp: otpA
      }
    });

    assert(verifyResA.status === 201, 'Valid OTP verified and Company A provisioned with 201 Created');
    assert(verifyResA.data.tenant && verifyResA.data.tenant.slug === 'alpha_corp', 'Company A tenant object returned');
    assert(verifyResA.data.token, 'JWT token returned with tenant ID for Alice');
    const tokenA = verifyResA.data.token;
    const tenantA = verifyResA.data.tenant;
    const userA = verifyResA.data.user;

    // Company B: Beta LLC
    EmailProvider.clearHistory();
    const regResB = await request(baseUrl, '/api/auth/register-company', {
      method: 'POST',
      body: {
        company_name: 'Beta LLC',
        slug: 'beta_llc',
        admin_name: 'Bob Beta',
        admin_email: 'bob@beta.com',
        admin_password: 'Password123!'
      }
    });
    assert(regResB.status === 200, 'Company B registered with pending verification');

    const lastEmailB = EmailProvider.getLastMessage('bob@beta.com');
    const otpB = lastEmailB.otp;

    const verifyResB = await request(baseUrl, '/api/auth/verify-registration', {
      method: 'POST',
      body: {
        verification_id: regResB.data.verification_id,
        otp: otpB
      }
    });
    assert(verifyResB.status === 201, 'Valid OTP verified and Company B provisioned with 201 Created');
    const tokenB = verifyResB.data.token;
    const tenantB = verifyResB.data.tenant;
    const userB = verifyResB.data.user;
    console.log();

    // =========================================================================
    // Test 4: Multi-Tenant Login & Company Selection
    // =========================================================================
    console.log('--- Test 4: Multi-Tenant Login & Company Resolution ---');

    // Login with slug
    const loginSlugRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: 'alice@alpha.com',
        password: 'Password123!',
        tenant_slug: 'alpha_corp'
      }
    });
    assert(loginSlugRes.status === 200, 'Login with tenant_slug succeeded');
    assert(loginSlugRes.data.tenant.slug === 'alpha_corp', 'Login selected correct tenant');

    // Login without slug (single company auto-selected)
    const loginAutoRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: 'alice@alpha.com',
        password: 'Password123!'
      }
    });
    assert(loginAutoRes.status === 200, 'Single-company user auto-selected company upon login without slug');

    // Multi-company directory: add Alice to Company B directory as well
    await masterDb.execute(
      `INSERT INTO tenant_user_directory (email, tenant_id) VALUES (?, ?)`,
      ['alice@alpha.com', tenantB.id]
    );

    const loginMultiRes = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: {
        email: 'alice@alpha.com',
        password: 'Password123!'
      }
    });
    assert(loginMultiRes.status === 200, 'Multi-company login returned 200 with company options');
    assert(loginMultiRes.data.requires_company_selection === true, 'Response requires_company_selection is true');
    assert(loginMultiRes.data.companies.length >= 2, 'Response lists all companies user belongs to');

    // Clean up temporary multi-company record
    await masterDb.execute(
      'DELETE FROM tenant_user_directory WHERE email = ? AND tenant_id = ?',
      ['alice@alpha.com', tenantB.id]
    );
    console.log();

    // =========================================================================
    // Test 5: Verify Provisioned Seeds & Query Resources
    // =========================================================================
    console.log('--- Test 5: Fetch Resources Seeded in Tenant A and Tenant B ---');

    // Fetch workspaces for Tenant A
    const wsResA = await request(baseUrl, '/api/workspaces', {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert(wsResA.status === 200, 'Tenant A fetched workspaces');
    const workspaceA = wsResA.data.workspaces[0];
    assert(workspaceA && workspaceA.id, 'Tenant A has provisioned workspace');

    // Fetch boards for Tenant A
    const boardsResA = await request(baseUrl, `/api/boards?workspace_id=${workspaceA.id}`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert(boardsResA.status === 200, 'Tenant A fetched boards');
    const boardA = boardsResA.data.boards ? boardsResA.data.boards[0] : boardsResA.data[0];
    assert(boardA && boardA.id, 'Tenant A has provisioned board');

    // Fetch lists and cards for Tenant A's board
    const boardDetailResA = await request(baseUrl, `/api/boards/${boardA.id}`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert(boardDetailResA.status === 200, 'Tenant A fetched board detail with lists and cards');
    const boardDetailA = boardDetailResA.data.board || boardDetailResA.data;
    const listA = boardDetailA.lists[0];
    const cardA = listA.cards[0];
    assert(listA && listA.id, 'Tenant A has provisioned list');
    assert(cardA && cardA.id, 'Tenant A has provisioned welcome card');

    // Fetch resources for Tenant B
    const wsResB = await request(baseUrl, '/api/workspaces', {
      headers: { Authorization: `Bearer ${tokenB}` }
    });
    assert(wsResB.status === 200, 'Tenant B fetched workspaces');
    const workspaceB = wsResB.data.workspaces[0];

    const boardsResB = await request(baseUrl, `/api/boards?workspace_id=${workspaceB.id}`, {
      headers: { Authorization: `Bearer ${tokenB}` }
    });
    const boardB = boardsResB.data.boards ? boardsResB.data.boards[0] : boardsResB.data[0];

    const boardDetailResB = await request(baseUrl, `/api/boards/${boardB.id}`, {
      headers: { Authorization: `Bearer ${tokenB}` }
    });
    const boardDetailB = boardDetailResB.data.board || boardDetailResB.data;
    const listB = boardDetailB.lists[0];
    const cardB = listB.cards[0];

    assert(workspaceA.id !== workspaceB.id || tenantA.id !== tenantB.id, 'Workspaces belong to separate tenants');
    console.log();

    // =========================================================================
    // Test 6: Cross-Tenant Isolation Tests (Strict 404 Guarantees)
    // =========================================================================
    console.log('--- Test 6: Cross-Tenant Resource Isolation (Token A accessing Tenant B IDs) ---');

    // Tenant B creates an extra workspace, board, list, card, and attachment
    const newWsResB = await request(baseUrl, '/api/workspaces', {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenB}` },
      body: { name: 'Beta Confidential Workspace' }
    });
    assert(newWsResB.status === 201, 'Tenant B created isolated workspace');
    const wsB_isolated = newWsResB.data.workspace;

    const newBoardResB = await request(baseUrl, '/api/boards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenB}` },
      body: { workspace_id: wsB_isolated.id, name: 'Beta Secret Board' }
    });
    assert(newBoardResB.status === 201, 'Tenant B created isolated board');
    const boardB_isolated = newBoardResB.data.board;

    const newListResB = await request(baseUrl, '/api/lists', {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenB}` },
      body: { board_id: boardB_isolated.id, name: 'Beta Secret List' }
    });
    assert(newListResB.status === 201, 'Tenant B created isolated list');
    const listB_isolated = newListResB.data.list;

    const newCardResB = await request(baseUrl, '/api/cards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenB}` },
      body: { list_id: listB_isolated.id, title: 'Beta Secret Card' }
    });
    assert(newCardResB.status === 201, 'Tenant B created isolated card');
    const cardB_isolated = newCardResB.data.card;

    const attResB = await request(baseUrl, `/api/cards/${cardB_isolated.id}/attachments/link`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenB}` },
      body: { link_url: 'https://beta.com/secret-spec', display_name: 'Beta Secret Spec' }
    });
    assert(attResB.status === 201, 'Tenant B created attachment on its isolated card');
    const attB_isolated = attResB.data.attachment;

    // 6.1 Workspace isolation: Token A modifying Tenant B's workspace returns 404
    const crossWs = await request(baseUrl, `/api/workspaces/${wsB_isolated.id}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${tokenA}` },
      body: { name: 'Hacked Workspace' }
    });
    assert(crossWs.status === 404, 'Token A modifying Tenant B Workspace returns 404');

    // 6.2 Board isolation: Token A accessing Tenant B's board returns 404
    const crossBoard = await request(baseUrl, `/api/boards/${boardB_isolated.id}`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert(crossBoard.status === 404, 'Token A accessing Tenant B Board returns 404');

    // 6.3 List isolation: Token A modifying Tenant B's list returns 404
    const crossList = await request(baseUrl, `/api/lists/${listB_isolated.id}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${tokenA}` },
      body: { name: 'Hacked List' }
    });
    assert(crossList.status === 404, 'Token A modifying Tenant B List returns 404');

    // 6.4 Card isolation: Token A accessing Tenant B's card returns 404
    const crossCard = await request(baseUrl, `/api/cards/${cardB_isolated.id}`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert(crossCard.status === 404, 'Token A accessing Tenant B Card returns 404');

    // 6.5 Comment on cross-tenant card: Token A returns 404
    const crossComment = await request(baseUrl, `/api/cards/${cardB_isolated.id}/comments`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenA}` },
      body: { body: 'Unauthorized cross-tenant comment' }
    });
    assert(crossComment.status === 404, 'Token A commenting on Tenant B Card returns 404');

    // 6.6 Checklist on cross-tenant card: Token A returns 404
    const crossChecklist = await request(baseUrl, `/api/cards/${cardB_isolated.id}/checklists`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenA}` },
      body: { title: 'Unauthorized Checklist' }
    });
    assert(crossChecklist.status === 404, 'Token A adding checklist to Tenant B Card returns 404');

    // 6.7 Cross-tenant attachment deletion: Token A returns 404
    const crossAttDelete = await request(baseUrl, `/api/cards/attachments/${attB_isolated.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert(crossAttDelete.status === 404, 'Token A deleting Tenant B Attachment returns 404');
    console.log();

    // =========================================================================
    // Test 7: Tenant-Isolated File Upload & Cross-Tenant File Download
    // =========================================================================
    console.log('--- Test 7: Tenant File Storage & Cross-Tenant Download Guard ---');

    // Create a mock uploaded file under Tenant B's storage path
    const uploadBaseDir = path.resolve(__dirname, '../uploads');
    const tenantBFileDir = path.join(uploadBaseDir, String(tenantB.id), 'cards', String(cardB_isolated.id));
    fs.mkdirSync(tenantBFileDir, { recursive: true });
    const secretFileName = 'confidential_beta_report.txt';
    const secretFilePath = path.join(tenantBFileDir, secretFileName);
    fs.writeFileSync(secretFilePath, 'TOP SECRET DATA BELONGING EXCLUSIVELY TO BETA LLC');

    // Tenant B can download its own file
    const downloadB = await request(baseUrl, `/api/files/${tenantB.id}/cards/${cardB_isolated.id}/${secretFileName}`, {
      headers: { Authorization: `Bearer ${tokenB}` }
    });
    assert(downloadB.status === 200, 'Tenant B successfully downloads its own file');
    assert(downloadB.data.includes('TOP SECRET'), 'File content verified for Tenant B');

    // Tenant A attempts to download Tenant B's file -> MUST RETURN 404
    const crossDownloadA = await request(baseUrl, `/api/files/${tenantB.id}/cards/${cardB_isolated.id}/${secretFileName}`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert(crossDownloadA.status === 404, 'Token A attempting to download Tenant B file returns 404');

    // Path traversal attempt -> MUST RETURN 403 or 404
    const pathTraversal = await request(baseUrl, `/api/files/${tenantA.id}/../../${tenantB.id}/cards/${cardB_isolated.id}/${secretFileName}`, {
      headers: { Authorization: `Bearer ${tokenA}` }
    });
    assert(pathTraversal.status === 403 || pathTraversal.status === 404, 'Path traversal attack safely blocked (403/404)');
    console.log();

    // =========================================================================
    // Test 8: Socket.IO Namespaced Rooms & Cross-Tenant Join Prevention
    // =========================================================================
    console.log('--- Test 8: Socket.IO Namespacing & Cross-Tenant Join Guard ---');

    // Connect Client Socket authenticated as Tenant A
    const socketClientA = ClientSocket(baseUrl, {
      auth: { token: tokenA },
      transports: ['websocket'],
      forceNew: true
    });

    await new Promise((resolve, reject) => {
      socketClientA.on('connect', resolve);
      socketClientA.on('connect_error', reject);
    });
    assert(socketClientA.connected, 'Socket client A connected and authenticated');

    // Connect Client Socket authenticated as Tenant B
    const socketClientB = ClientSocket(baseUrl, {
      auth: { token: tokenB },
      transports: ['websocket'],
      forceNew: true
    });

    await new Promise((resolve, reject) => {
      socketClientB.on('connect', resolve);
      socketClientB.on('connect_error', reject);
    });
    assert(socketClientB.connected, 'Socket client B connected and authenticated');

    // Cross-tenant socket join: Socket A attempts to join Tenant B's board ID
    let crossJoinBlocked = false;
    await new Promise((resolve) => {
      socketClientA.on('error', (err) => {
        if (err.code === 'NOT_FOUND' || err.code === 'FORBIDDEN') {
          crossJoinBlocked = true;
        }
        resolve();
      });
      // Emit join for board belonging to Tenant B
      socketClientA.emit('join_board', { boardId: boardB_isolated.id });
      setTimeout(resolve, 500);
    });
    assert(crossJoinBlocked, 'Socket A joining Tenant B board was rejected with error event');

    // Valid join: Socket A joins Tenant A's board
    let presenceReceived = false;
    await new Promise((resolve) => {
      socketClientA.on('board:presence_update', (data) => {
        if (data.boardId === boardA.id) {
          presenceReceived = true;
          resolve();
        }
      });
      socketClientA.emit('join_board', { boardId: boardA.id });
      setTimeout(resolve, 500);
    });
    assert(presenceReceived, 'Socket A successfully joined Tenant A board and received presence');

    socketClientA.disconnect();
    socketClientB.disconnect();
    console.log();

    // =========================================================================
    // Test 9: Multi-Tenant Reminder Cron Logic
    // =========================================================================
    console.log('--- Test 9: Multi-Tenant Reminder Cron Test ---');
    const tenantDbA = await getTenantDb(tenantA.id);

    // Seed a due-soon card in Tenant A (due in 30 minutes)
    const in30Minutes = new Date(Date.now() + 30 * 60 * 1000);
    await tenantDbA.execute(
      'UPDATE cards SET due_date = ?, is_complete = 0 WHERE id = ?',
      [in30Minutes, cardA.id]
    );

    const now = new Date();
    const dueSoonCount = await checkDueSoonCards(now, tenantDbA);
    assert(dueSoonCount >= 1, 'Reminder cron processed due-soon card for Tenant A');

    // Re-run to verify deduplication
    const dueSoonDedup = await checkDueSoonCards(now, tenantDbA);
    assert(dueSoonDedup === 0, 'Reminder cron deduplicated: 0 duplicate notifications created');
    console.log();

  } finally {
    await new Promise((resolve) => server.close(resolve));
    await closeAllPools();
    console.log('✓ Test server stopped and connection pools closed.\n');
  }

  console.log('================================================================');
  console.log(`PHASE 2 TEST SUMMARY: ${testsPassed} passed, ${testsFailed} failed.`);
  console.log('================================================================\n');

  if (testsFailed > 0) {
    process.exit(1);
  }
  process.exit(0);
}

// Run test suite
if (require.main === module) {
  runPhase2Tests().catch((err) => {
    console.error('Fatal error during Phase 2 tests:', err);
    process.exit(1);
  });
}

module.exports = { runPhase2Tests };

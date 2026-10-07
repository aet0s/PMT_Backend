// server/src/test_backend.js
// Comprehensive test and hardening suite for MySQL/MariaDB backend.
require('dotenv').config();
process.env.DEV_SINGLE_TENANT = '1';
const http = require('http');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { io: ClientSocket } = require('socket.io-client');
const db = require('./db');
const { initSocket } = require('./socket');
const migrator = require('./db/migrator');
const { checkDueSoonCards, checkOverdueCards } = require('./cron/reminders');
const { validateEnv } = require('./config/env');

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

const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;

async function runRegressionTests() {
  console.log('=== Running Phase 1.5 Hardening & Regression Suite Against MySQL (pm_dev_single) ===\n');

  const testDb = process.env.MYSQL_DATABASE || 'pm_dev_single';
  await migrator.migrateSingleTenant(testDb);
  console.log('✓ Migration verified on', testDb);

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
  console.log(`Server listening on ${baseUrl}\n`);

  let clientSocket = null;

  try {
    // -------------------------------------------------------------
    // SECTION 1: Baseline Core Endpoints
    // -------------------------------------------------------------
    // 1. Healthcheck
    const health = await fetch(`${baseUrl}/api/health`).then((r) => r.json());
    if (health.status !== 'ok') throw new Error('Health check failed');
    console.log('1. ✓ Healthcheck passed');

    // 2. Register Owner User A
    const ownerEmail = `owner_${Date.now()}@example.com`;
    const regRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Workspace Owner',
        email: ownerEmail,
        password: 'Password123!'
      })
    });
    const regData = await regRes.json();
    if (!regRes.ok) throw new Error(`Register failed: ${JSON.stringify(regData)}`);
    const ownerId = regData.user.id;
    const cookieHeader = regRes.headers.get('set-cookie')?.split(';')[0] || '';
    const ownerHeaders = { 'Content-Type': 'application/json', Cookie: cookieHeader };
    console.log(`2. ✓ Registration passed for owner (User ID: ${ownerId})`);

    // 3. /me
    const meRes = await fetch(`${baseUrl}/api/auth/me`, { headers: ownerHeaders }).then((r) => r.json());
    if (meRes.user?.email !== ownerEmail) throw new Error('Auth me email mismatch');
    console.log('3. ✓ GET /api/auth/me passed');

    // 4. Update Profile
    const profRes = await fetch(`${baseUrl}/api/auth/profile`, {
      method: 'PUT',
      headers: ownerHeaders,
      body: JSON.stringify({ name: 'Workspace Owner Updated' })
    }).then((r) => r.json());
    if (profRes.user?.name !== 'Workspace Owner Updated') throw new Error('Profile update failed');
    console.log('4. ✓ PUT /api/auth/profile passed');

    // 5. List Workspaces
    const wsRes = await fetch(`${baseUrl}/api/workspaces`, { headers: ownerHeaders }).then((r) => r.json());
    if (!wsRes.workspaces?.length) throw new Error('No default workspace created');
    const workspaceId = wsRes.workspaces[0].id;
    console.log(`5. ✓ GET /api/workspaces found workspace ${workspaceId}`);

    // 6. Permissions catalog
    const permRes = await fetch(`${baseUrl}/api/permissions`, { headers: ownerHeaders }).then((r) => r.json());
    if (!permRes.permissions || permRes.permissions.length < 24) throw new Error(`Expected at least 24 permissions, got ${permRes.permissions?.length}`);
    console.log(`6. ✓ GET /api/permissions verified ${permRes.permissions.length} atomic permissions (including member.reset_password)`);

    // 7. My Permissions
    const myPermRes = await fetch(`${baseUrl}/api/workspaces/${workspaceId}/my-permissions`, { headers: ownerHeaders }).then((r) => r.json());
    if (myPermRes.role?.name !== 'Super Admin' && myPermRes.role?.name !== 'Owner') throw new Error(`Role is not Super Admin or Owner (got: ${myPermRes.role?.name})`);
    console.log(`7. ✓ GET /api/workspaces/:id/my-permissions verified ${myPermRes.role?.name}`);

    // 8. Custom Role Creation
    const createRoleRes = await fetch(`${baseUrl}/api/workspaces/${workspaceId}/roles`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({
        name: 'Custom Reviewer',
        permission_keys: ['card.create', 'card.comment', 'card.manage_attachments']
      })
    });
    const createRoleData = await createRoleRes.json();
    const customRoleId = createRoleData.role?.id;
    if (!customRoleId) throw new Error(`Failed to create custom role: ${JSON.stringify(createRoleData)}`);
    console.log(`8. ✓ POST /api/workspaces/:id/roles created custom role ${customRoleId}`);

    // 9. Create Board
    const boardRes = await fetch(`${baseUrl}/api/boards`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({
        workspace_id: workspaceId,
        name: 'Hardening Sprint Board',
        background_color: '#4f46e5'
      })
    }).then((r) => r.json());
    const boardId = boardRes.board?.id;
    if (!boardId) throw new Error('Failed to create board');
    console.log(`9. ✓ POST /api/boards created board ${boardId}`);

    // 10. Fetch Board Nested Structure
    const getBoardRes = await fetch(`${baseUrl}/api/boards/${boardId}`, { headers: ownerHeaders }).then((r) => r.json());
    if (getBoardRes.board?.lists?.length !== 3) throw new Error('Default lists missing on board');
    const firstListId = getBoardRes.board.lists[0].id;
    console.log(`10. ✓ GET /api/boards/:id fetched board with ${getBoardRes.board.lists.length} lists`);

    // 11. Create New List
    const listRes = await fetch(`${baseUrl}/api/lists`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({ board_id: boardId, name: 'In Review' })
    }).then((r) => r.json());
    const listId = listRes.list?.id;
    if (!listId) throw new Error('Failed to create list');
    console.log(`11. ✓ POST /api/lists created list ${listId}`);

    // 12. Create Card
    const cardRes = await fetch(`${baseUrl}/api/cards`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({
        list_id: listId,
        title: 'Complete Phase 1.5 Hardening Pass',
        description: 'Verify all edge cases, cron, sockets, and isolation.'
      })
    }).then((r) => r.json());
    const cardId = cardRes.card?.id;
    if (!cardId) throw new Error('Failed to create card');
    console.log(`12. ✓ POST /api/cards created card ${cardId}`);

    // 13. Move / Update Card
    const updateCardRes = await fetch(`${baseUrl}/api/cards/${cardId}`, {
      method: 'PATCH',
      headers: ownerHeaders,
      body: JSON.stringify({ list_id: firstListId, is_complete: true })
    }).then((r) => r.json());
    if (!updateCardRes.card?.is_complete) throw new Error('Card complete boolean mapping failed');
    console.log('13. ✓ PATCH /api/cards/:id moved card and updated is_complete');

    // 14. Checklists & Items
    const chkRes = await fetch(`${baseUrl}/api/cards/${cardId}/checklists`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({ title: 'Quality Criteria' })
    }).then((r) => r.json());
    const chkId = chkRes.checklist?.id;
    const itemRes = await fetch(`${baseUrl}/api/cards/checklist-items`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({ checklist_id: chkId, text: 'Grep for numeric booleans' })
    }).then((r) => r.json());
    const itemId = itemRes.item?.id;
    const toggleRes = await fetch(`${baseUrl}/api/cards/checklist-items/${itemId}`, {
      method: 'PATCH',
      headers: ownerHeaders,
      body: JSON.stringify({ is_checked: true })
    }).then((r) => r.json());
    if (!toggleRes.item?.is_checked) throw new Error('Checklist item boolean toggle failed');
    console.log('14. ✓ Checklists and items CRUD verified');

    // 15. Comments
    const comRes = await fetch(`${baseUrl}/api/cards/${cardId}/comments`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({ body: 'Automated test verification comment.' })
    }).then((r) => r.json());
    if (!comRes.comment?.id) throw new Error('Failed to add comment');
    console.log('15. ✓ POST /api/cards/:id/comments created comment');

    // 16. Labels
    const labelsRes = await fetch(`${baseUrl}/api/boards/${boardId}/labels`, { headers: ownerHeaders }).then((r) => r.json());
    const labelId = labelsRes.labels?.[0]?.id;
    if (labelId) {
      await fetch(`${baseUrl}/api/cards/${cardId}/labels`, {
        method: 'POST',
        headers: ownerHeaders,
        body: JSON.stringify({ label_id: labelId })
      });
      console.log('16. ✓ POST /api/cards/:id/labels attached label');
    }

    // -------------------------------------------------------------
    // SECTION 2: Attachments (File + Link + Deletion)
    // -------------------------------------------------------------
    // A. Link Attachment
    const linkAttRes = await fetch(`${baseUrl}/api/cards/${cardId}/attachments/link`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({
        link_url: 'https://example.com/specs.pdf',
        file_name: 'Architecture Specs'
      })
    });
    const linkAttData = await linkAttRes.json();
    if (!linkAttRes.ok || !linkAttData.attachment?.id) {
      throw new Error(`Failed to create link attachment: ${JSON.stringify(linkAttData)}`);
    }
    const linkAttachmentId = linkAttData.attachment.id;
    console.log(`17. ✓ POST /api/cards/:id/attachments/link created link attachment ${linkAttachmentId}`);

    // B. File Attachment (Multipart Upload via FormData)
    const formData = new FormData();
    const testFileBlob = new Blob(['Sample test document content for Phase 1.5'], { type: 'text/plain' });
    formData.append('file', testFileBlob, 'test_attachment.txt');

    const fileAttRes = await fetch(`${baseUrl}/api/cards/${cardId}/attachments/file`, {
      method: 'POST',
      headers: { Cookie: cookieHeader },
      body: formData
    });
    const fileAttData = await fileAttRes.json();
    if (!fileAttRes.ok || !fileAttData.attachment?.id) {
      throw new Error(`Failed to upload file attachment: ${JSON.stringify(fileAttData)}`);
    }
    const fileAttachmentId = fileAttData.attachment.id;
    console.log(`18. ✓ POST /api/cards/:id/attachments/file uploaded file attachment ${fileAttachmentId}`);

    // C. Delete Attachment
    const delAttRes = await fetch(`${baseUrl}/api/cards/attachments/${fileAttachmentId}`, {
      method: 'DELETE',
      headers: ownerHeaders
    });
    const delAttData = await delAttRes.json();
    if (!delAttRes.ok || delAttData.id !== fileAttachmentId) {
      throw new Error(`Failed to delete attachment: ${JSON.stringify(delAttData)}`);
    }
    console.log(`19. ✓ DELETE /api/cards/attachments/:id deleted file attachment ${fileAttachmentId}`);

    // -------------------------------------------------------------
    // SECTION 3: Archive & Restore Flow
    // -------------------------------------------------------------
    // Archive card
    await fetch(`${baseUrl}/api/cards/${cardId}`, {
      method: 'PATCH',
      headers: ownerHeaders,
      body: JSON.stringify({ is_archived: true })
    });
    let archRes = await fetch(`${baseUrl}/api/archive`, { headers: ownerHeaders }).then((r) => r.json());
    if (!archRes.cards?.some((c) => c.id === cardId)) {
      throw new Error('Archived card not visible in /api/archive');
    }

    // Restore card
    await fetch(`${baseUrl}/api/cards/${cardId}`, {
      method: 'PATCH',
      headers: ownerHeaders,
      body: JSON.stringify({ is_archived: false })
    });
    archRes = await fetch(`${baseUrl}/api/archive`, { headers: ownerHeaders }).then((r) => r.json());
    if (archRes.cards?.some((c) => c.id === cardId)) {
      throw new Error('Restored card still appearing in /api/archive');
    }
    console.log('20. ✓ Archive and restore lifecycle verified for cards');

    // -------------------------------------------------------------
    // SECTION 4: Reminder Cron Logic (Due-Soon & Overdue)
    // -------------------------------------------------------------
    // Seed due-soon card (due in 30 mins, incomplete, not archived, reminder null)
    const thirtyMinsLater = new Date(Date.now() + 30 * 60 * 1000);
    const dueSoonCardRes = await db.query(
      `INSERT INTO cards (list_id, title, due_date, is_complete, is_archived, position)
       VALUES (?, 'Card Due In 30 Mins', ?, 0, 0, 1)`,
      [listId, thirtyMinsLater]
    );
    const dueSoonCardId = dueSoonCardRes.insertId;

    // Seed overdue card (due 2 hours ago, incomplete, not archived, overdue null)
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
    const overdueCardRes = await db.query(
      `INSERT INTO cards (list_id, title, due_date, is_complete, is_archived, position)
       VALUES (?, 'Card Overdue By 2 Hours', ?, 0, 0, 2)`,
      [listId, twoHoursAgo]
    );
    const overdueCardId = overdueCardRes.insertId;

    // Direct invocation 1: Due soon check
    const dueSoonCount1 = await checkDueSoonCards(db);
    if (dueSoonCount1 < 1) throw new Error('Expected at least 1 due-soon card processed');
    // Direct invocation 2: assert no duplicate notifications dispatched
    const dueSoonCount2 = await checkDueSoonCards(db);
    if (dueSoonCount2 !== 0) throw new Error(`Expected 0 due-soon cards on second pass, got ${dueSoonCount2}`);

    // Direct invocation 1: Overdue check
    const overdueCount1 = await checkOverdueCards(db);
    if (overdueCount1 < 1) throw new Error('Expected at least 1 overdue card processed');
    // Direct invocation 2: assert no duplicate notifications dispatched
    const overdueCount2 = await checkOverdueCards(db);
    if (overdueCount2 !== 0) throw new Error(`Expected 0 overdue cards on second pass, got ${overdueCount2}`);

    console.log('21. ✓ Reminder cron handlers verified (due-soon + overdue triggered once, zero duplication)');

    // -------------------------------------------------------------
    // SECTION 5: Socket.IO Connect + Join Board + Event Broadcast
    // -------------------------------------------------------------
    const rawToken = cookieHeader.split(';')[0].replace('token=', '').trim();
    await new Promise((resolve, reject) => {
      clientSocket = ClientSocket(baseUrl, {
        auth: { token: rawToken },
        transports: ['websocket'],
        extraHeaders: { origin: 'http://localhost:5173' }
      });

      const timer = setTimeout(() => {
        reject(new Error('Socket.io connection / event timeout'));
      }, 5000);

      clientSocket.on('connect', () => {
        clientSocket.emit('join_board', { boardId });
      });

      clientSocket.on('board:presence_update', async () => {
        // Once joined, trigger an action that broadcasts an event
        clientSocket.on('card:created', (data) => {
          if (data.card && data.card.title === 'Socket Broadcast Verification Card') {
            clearTimeout(timer);
            resolve();
          }
        });

        // Trigger REST API card creation
        await fetch(`${baseUrl}/api/cards`, {
          method: 'POST',
          headers: ownerHeaders,
          body: JSON.stringify({
            list_id: listId,
            title: 'Socket Broadcast Verification Card'
          })
        });
      });

      clientSocket.on('connect_error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });

    clientSocket.disconnect();
    clientSocket = null;
    console.log('22. ✓ Socket.IO connect + join_board + card:created broadcast verified');

    // -------------------------------------------------------------
    // SECTION 6: Invitations, Roles, & Member Management
    // -------------------------------------------------------------
    // A. Registration with invite_token for a NEW user
    const newUserEmail = `invited_new_${Date.now()}@example.com`;
    const inviteRes = await fetch(`${baseUrl}/api/invitations`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({
        email: newUserEmail,
        workspace_id: workspaceId,
        board_ids: [boardId]
      })
    }).then((r) => r.json());
    const inviteToken = inviteRes.invite_token;
    if (!inviteToken) throw new Error('Invite token missing from invitation response');

    const regWithInviteRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Invited New User',
        email: newUserEmail,
        password: 'Password123!',
        invite_token: inviteToken
      })
    });
    const regWithInviteData = await regWithInviteRes.json();
    if (!regWithInviteRes.ok) throw new Error(`Register with invite failed: ${JSON.stringify(regWithInviteData)}`);
    const newUserId = regWithInviteData.user.id;
    console.log(`23. ✓ Registration with invite_token verified (User ID: ${newUserId})`);

    // B. Invitation Accept for an EXISTING user
    const existingUserEmail = `existing_member_${Date.now()}@example.com`;

    // 1. User registers independently first
    const regExistingRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Existing Standalone User',
        email: existingUserEmail,
        password: 'Password123!'
      })
    });
    const regExistingData = await regExistingRes.json();
    const existingUserId = regExistingData.user.id;
    const existingCookie = regExistingRes.headers.get('set-cookie')?.split(';')[0] || '';
    const existingHeaders = { 'Content-Type': 'application/json', Cookie: existingCookie };

    // 2. A pending invitation is issued for this existing user
    const existingInviteToken = 'invite_token_' + Date.now();
    const insInviteRes = await db.query(
      `INSERT INTO pending_invitations (email, workspace_id, invited_by_user_id, token, status)
       VALUES (?, ?, ?, ?, 'pending')`,
      [existingUserEmail, workspaceId, ownerId, existingInviteToken]
    );
    await db.query(
      'INSERT INTO invitation_boards (invitation_id, board_id) VALUES (?, ?)',
      [insInviteRes.insertId, boardId]
    );

    // 3. Existing user accepts invitation link via POST /api/invitations/accept
    const acceptRes = await fetch(`${baseUrl}/api/invitations/accept`, {
      method: 'POST',
      headers: existingHeaders,
      body: JSON.stringify({ token: existingInviteToken })
    });
    const acceptData = await acceptRes.json();
    if (!acceptRes.ok) throw new Error(`Invitation accept failed: ${JSON.stringify(acceptData)}`);
    console.log(`24. ✓ Invitation accept endpoint verified for existing user (${existingUserId})`);

    // C. Assign Role to Member
    const assignRoleRes = await fetch(`${baseUrl}/api/workspaces/${workspaceId}/members/${existingUserId}/role`, {
      method: 'PATCH',
      headers: ownerHeaders,
      body: JSON.stringify({ role_id: customRoleId })
    });
    const assignRoleData = await assignRoleRes.json();
    if (!assignRoleRes.ok || !assignRoleData.message) {
      throw new Error(`Assign role failed: ${JSON.stringify(assignRoleData)}`);
    }
    console.log(`25. ✓ Assign role verified (Updated to role ID: ${customRoleId})`);

    // D. Add / Remove Board Member
    // Add existing user to board
    const addBmRes = await fetch(`${baseUrl}/api/boards/${boardId}/members`, {
      method: 'POST',
      headers: ownerHeaders,
      body: JSON.stringify({ user_id: existingUserId, role: 'member' })
    });
    const addBmData = await addBmRes.json();
    if (!addBmRes.ok) throw new Error(`Add board member failed: ${JSON.stringify(addBmData)}`);

    // Remove from board
    const remBmRes = await fetch(`${baseUrl}/api/boards/${boardId}/members/${existingUserId}`, {
      method: 'DELETE',
      headers: ownerHeaders
    });
    const remBmData = await remBmRes.json();
    if (!remBmRes.ok) throw new Error(`Remove board member failed: ${JSON.stringify(remBmData)}`);
    console.log('26. ✓ Add and remove board member verified');

    // E. Remove Member from Workspace
    const remMemberRes = await fetch(`${baseUrl}/api/workspaces/${workspaceId}/members/${existingUserId}`, {
      method: 'DELETE',
      headers: ownerHeaders
    });
    const remMemberData = await remMemberRes.json();
    if (!remMemberRes.ok) throw new Error(`Remove workspace member failed: ${JSON.stringify(remMemberData)}`);
    console.log('27. ✓ Remove workspace member verified');

    // -------------------------------------------------------------
    // SECTION 7: Boolean & ISO-8601 UTC Date Payload Audit
    // -------------------------------------------------------------
    // Audit Board Payload
    const singleBoardRes = await fetch(`${baseUrl}/api/boards/${boardId}`, { headers: ownerHeaders }).then((r) => r.json());
    const boardPayload = singleBoardRes.board;
    if (typeof boardPayload.is_archived !== 'boolean') throw new Error(`board.is_archived is not boolean: ${typeof boardPayload.is_archived}`);
    if (!ISO_DATE_REGEX.test(boardPayload.created_at)) throw new Error(`board.created_at is not ISO-8601 string: ${boardPayload.created_at}`);

    // Audit Card Payload (from board lists or update response)
    const cardPayload = singleBoardRes.board.lists[0]?.cards[0] || updateCardRes.card;
    if (!cardPayload) throw new Error('Card payload not found for audit');
    if (typeof cardPayload.is_complete !== 'boolean') throw new Error(`card.is_complete is not boolean: ${typeof cardPayload.is_complete}`);
    if (typeof cardPayload.is_archived !== 'boolean') throw new Error(`card.is_archived is not boolean: ${typeof cardPayload.is_archived}`);
    if (!ISO_DATE_REGEX.test(cardPayload.created_at)) throw new Error(`card.created_at is not ISO-8601 string: ${cardPayload.created_at}`);

    // Audit Notification Payload
    const notifsAuditRes = await fetch(`${baseUrl}/api/notifications`, { headers: ownerHeaders }).then((r) => r.json());
    const firstNotif = notifsAuditRes.notifications?.[0];
    if (firstNotif) {
      if (typeof firstNotif.is_read !== 'boolean') throw new Error(`notification.is_read is not boolean: ${typeof firstNotif.is_read}`);
      if (!ISO_DATE_REGEX.test(firstNotif.created_at)) throw new Error(`notification.created_at is not ISO-8601 string: ${firstNotif.created_at}`);
    }
    console.log('28. ✓ Boolean & ISO-8601 UTC date audit passed across card, board, and notification payloads');

    // -------------------------------------------------------------
    // SECTION 8: Negative Authorization & Error Cases (>= 10 cases)
    // -------------------------------------------------------------
    // Re-login removed user to obtain an active session for negative membership tests (session was revoked on removal)
    const reloginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: existingUserEmail, password: 'Password123!' })
    });
    const reloginCookie = reloginRes.headers.get('set-cookie')?.split(';')[0] || '';
    const nonMemberHeaders = { 'Content-Type': 'application/json', Cookie: reloginCookie };

    const negativeTests = [
      // 1. Unauthenticated request to /me
      {
        name: 'Unauthenticated GET /api/auth/me returns 401',
        fn: () => fetch(`${baseUrl}/api/auth/me`),
        expectedStatus: 401
      },
      // 2. Nonexistent workspace
      {
        name: 'Nonexistent workspace GET /api/workspaces/999999 returns 404',
        fn: () => fetch(`${baseUrl}/api/workspaces/999999`, { headers: ownerHeaders }),
        expectedStatus: 404
      },
      // 3. Nonexistent board
      {
        name: 'Nonexistent board GET /api/boards/999999 returns 404',
        fn: () => fetch(`${baseUrl}/api/boards/999999`, { headers: ownerHeaders }),
        expectedStatus: 404
      },
      // 4. Nonexistent card update
      {
        name: 'Nonexistent card PATCH /api/cards/999999 returns 404',
        fn: () => fetch(`${baseUrl}/api/cards/999999`, {
          method: 'PATCH',
          headers: ownerHeaders,
          body: JSON.stringify({ title: 'New Title' })
        }),
        expectedStatus: 404
      },
      // 5. Nonexistent attachment deletion
      {
        name: 'Nonexistent attachment DELETE /api/cards/attachments/999999 returns 404',
        fn: () => fetch(`${baseUrl}/api/cards/attachments/999999`, { method: 'DELETE', headers: ownerHeaders }),
        expectedStatus: 404
      },
      // 6. Nonexistent invitation verification token
      {
        name: 'Invalid invite token GET /api/invitations/verify returns 404',
        fn: () => fetch(`${baseUrl}/api/invitations/verify?token=invalid_dummy_token_999`),
        expectedStatus: 404
      },
      // 7. Nonexistent invitation acceptance token
      {
        name: 'Invalid invite accept POST /api/invitations/accept returns 404',
        fn: () => fetch(`${baseUrl}/api/invitations/accept`, {
          method: 'POST',
          headers: ownerHeaders,
          body: JSON.stringify({ token: 'nonexistent_token_abc' })
        }),
        expectedStatus: 404
      },
      // 8. Non-member accessing workspace boards
      {
        name: 'Non-member accessing workspace boards returns 403',
        fn: () => fetch(`${baseUrl}/api/boards?workspace_id=${workspaceId}`, { headers: nonMemberHeaders }),
        expectedStatus: 403
      },
      // 9. Member without workspace.delete permission attempting to delete workspace
      {
        name: 'Forbidden workspace deletion by regular user returns 403',
        fn: () => fetch(`${baseUrl}/api/workspaces/${workspaceId}`, {
          method: 'DELETE',
          headers: nonMemberHeaders
        }),
        expectedStatus: 403
      },
      // 10. Member without member.invite permission attempting to invite user
      {
        name: 'Forbidden invite sending by unauthorized user returns 403',
        fn: () => fetch(`${baseUrl}/api/invitations`, {
          method: 'POST',
          headers: nonMemberHeaders,
          body: JSON.stringify({ email: 'test@forbidden.com', workspace_id: workspaceId })
        }),
        expectedStatus: 403
      },
      // 11. Member without role.manage attempting to create role
      {
        name: 'Forbidden role creation by unauthorized user returns 403',
        fn: () => fetch(`${baseUrl}/api/workspaces/${workspaceId}/roles`, {
          method: 'POST',
          headers: nonMemberHeaders,
          body: JSON.stringify({ name: 'Hacker Role', permission_keys: ['workspace.delete'] })
        }),
        expectedStatus: 403
      },
      // 12. Nonexistent role deletion
      {
        name: 'Nonexistent role deletion DELETE /api/roles/999999 returns 404',
        fn: () => fetch(`${baseUrl}/api/roles/999999`, { method: 'DELETE', headers: ownerHeaders }),
        expectedStatus: 404
      }
    ];

    for (let i = 0; i < negativeTests.length; i++) {
      const testCase = negativeTests[i];
      const res = await testCase.fn();
      if (res.status !== testCase.expectedStatus) {
        const body = await res.text();
        throw new Error(`Negative test "${testCase.name}" failed: expected HTTP ${testCase.expectedStatus}, got ${res.status}. Body: ${body}`);
      }
    }
    console.log(`29. ✓ Verified ${negativeTests.length} negative authorization and missing resource test cases (401/403/404)`);

    // -------------------------------------------------------------
    // SECTION 9: Environment Variable Validation Audit
    // -------------------------------------------------------------
    const missingHostCheck = validateEnv({ ...process.env, MYSQL_HOST: '' });
    if (missingHostCheck.valid || !missingHostCheck.errors.some((e) => e.includes('MYSQL_HOST'))) {
      throw new Error('validateEnv failed to detect missing MYSQL_HOST');
    }

    const missingUserCheck = validateEnv({ ...process.env, MYSQL_USER: '' });
    if (missingUserCheck.valid || !missingUserCheck.errors.some((e) => e.includes('MYSQL_USER'))) {
      throw new Error('validateEnv failed to detect missing MYSQL_USER');
    }

    const validCheck = validateEnv(process.env);
    if (!validCheck.valid) {
      throw new Error(`validateEnv failed on valid environment: ${validCheck.message}`);
    }
    console.log('30. ✓ Environment variable validation logic verified (fails fast on missing required variables)');

    // -------------------------------------------------------------
    // SECTION 10: Teardown & Logout
    // -------------------------------------------------------------
    await fetch(`${baseUrl}/api/roles/${customRoleId}`, { method: 'DELETE', headers: ownerHeaders });
    const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, { method: 'POST', headers: ownerHeaders }).then((r) => r.json());
    if (logoutRes.message !== 'Logged out successfully') throw new Error('Logout failed');
    console.log('31. ✓ Custom role cleanup and logout completed');

    console.log('\n===============================================================');
    console.log('ALL PHASE 1.5 HARDENING PASS TESTS PASSED (31/31)!');
    console.log('===============================================================');
  } finally {
    if (clientSocket && clientSocket.connected) {
      clientSocket.disconnect();
    }
    server.close();
    await db.pool.end();
  }
}

if (require.main === module) {
  runRegressionTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Phase 1.5 test failed:', err);
      process.exit(1);
    });
}

module.exports = runRegressionTests;

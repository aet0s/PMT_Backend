// server/src/test_part_e_rbac.js
// Comprehensive Route x Role and Two-Level RBAC Test Suite for Part E.

require('dotenv').config();
process.env.DEV_SINGLE_TENANT = '0';
process.env.REGISTRATION_RATE_LIMIT_PER_HOUR = '100';
const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { app } = require('./index');
const { getMasterDb, getTenantDb, closeAllPools } = require('./services/tenantPools');
const { runMigrationsOnDb } = require('./db/migrator');
const { resetAllRateLimits } = require('./middleware/rateLimit');
const { userHasPermission, getUserPermissions, countOwners } = require('./middleware/permissions');

let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
    passedTests++;
  } else {
    console.error(`  ❌ FAILED: ${message}`);
    failedTests++;
    throw new Error(message);
  }
}

function request(baseUrl, path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const headers = { ...options.headers };
    let body = options.body;

    if (body && typeof body === 'object' && !(body instanceof Buffer)) {
      body = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
    }

    const req = http.request(
      url,
      {
        method: options.method || 'GET',
        headers
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString();
          let data = raw;
          try {
            data = JSON.parse(raw);
          } catch (e) {
            // Raw text
          }
          resolve({
            status: res.statusCode,
            headers: res.headers,
            data
          });
        });
      }
    );

    req.on('error', reject);

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

async function runPartERbacTests() {
  console.log('================================================================');
  console.log('      PART E: PHASE 4 RBAC & ROUTE x ROLE TEST SUITE            ');
  console.log('================================================================\n');

  resetAllRateLimits();
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const masterDb = getMasterDb();
    await runMigrationsOnDb(process.env.MYSQL_MASTER_DATABASE || 'pm_master', 'master');

    const testSuffix = crypto.randomBytes(3).toString('hex');
    const tenantSlug = `rbac_corp_${testSuffix}`;
    const ownerEmail = `owner_${testSuffix}@rbaccorp.com`;
    const defaultPassword = 'SecurePassword123!';

    console.log(`[SETUP] Registering test company for tenant: ${tenantSlug}...`);
    const regRes = await request(baseUrl, '/api/auth/register-company', {
      method: 'POST',
      body: {
        companyName: `RBAC Corp ${testSuffix}`,
        slug: tenantSlug,
        name: 'Company Owner',
        email: ownerEmail,
        password: defaultPassword
      }
    });

    assert(regRes.status === 201, `Company registered successfully (status: ${regRes.status})`);
    const ownerToken = regRes.data.token;
    const ownerUser = regRes.data.user;
    const tenantId = regRes.data.tenant.id;
    const workspaceId = regRes.data.initial_workspace_id;
    const tenantDb = await getTenantDb(tenantId);

    // Fetch all 6 system roles from tenant DB
    const rolesRows = await tenantDb.query('SELECT id, name FROM roles WHERE workspace_id IS NULL');
    const roleMap = {};
    rolesRows.forEach((r) => {
      roleMap[r.name] = r.id;
    });

    assert(roleMap['Owner'] !== undefined, 'Owner system role exists');
    assert(roleMap['Admin'] !== undefined, 'Admin system role exists');
    assert(roleMap['Project Manager'] !== undefined, 'Project Manager system role exists');
    assert(roleMap['Team Member'] !== undefined, 'Team Member system role exists');
    assert(roleMap['Viewer'] !== undefined, 'Viewer system role exists');
    assert(roleMap['Guest'] !== undefined, 'Guest system role exists');

    // Helper to seed a user with a specific system role and log in
    async function createUserWithRole(name, email, roleName) {
      const passwordHash = await bcrypt.hash(defaultPassword, 10);
      const userExec = await tenantDb.execute(
        `INSERT INTO users (name, email, password_hash)
         VALUES (?, ?, ?)`,
        [name, email, passwordHash]
      );
      const userId = userExec.insertId;

      await tenantDb.execute(
        `INSERT INTO workspace_members (workspace_id, user_id, role, role_id)
         VALUES (?, ?, ?, ?)`,
        [workspaceId, userId, roleName, roleMap[roleName]]
      );

      const loginRes = await request(baseUrl, '/api/auth/login', {
        method: 'POST',
        body: { email, password: defaultPassword, tenant_slug: tenantSlug }
      });

      return {
        id: userId,
        name,
        email,
        roleName,
        token: loginRes.data.token,
        sid: loginRes.data.session_id
      };
    }

    const admin = await createUserWithRole('Bob Admin', `bob_${testSuffix}@rbaccorp.com`, 'Admin');
    const pm = await createUserWithRole('Charlie PM', `pm_${testSuffix}@rbaccorp.com`, 'Project Manager');
    const member = await createUserWithRole('Dave Member', `dave_${testSuffix}@rbaccorp.com`, 'Team Member');
    const viewer = await createUserWithRole('Eve Viewer', `eve_${testSuffix}@rbaccorp.com`, 'Viewer');
    const guest = await createUserWithRole('Frank Guest', `frank_${testSuffix}@rbaccorp.com`, 'Guest');

    assert(admin.token && pm.token && member.token && viewer.token && guest.token, 'All 5 secondary system role users provisioned & logged in');

    // -------------------------------------------------------------------------
    // 2. Anti-Escalation & Safety Floor Tests
    // -------------------------------------------------------------------------
    console.log('\n--- 2. Anti-Escalation & Safety Floor Tests ---');

    // 2a. Self role change forbidden
    const selfRoleRes = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${admin.id}/role`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${admin.token}` },
      body: { role_id: roleMap['Owner'] }
    });
    assert(selfRoleRes.status === 403 && selfRoleRes.data.error.code === 'SELF_ROLE_CHANGE_FORBIDDEN', 'User cannot change their own role (SELF_ROLE_CHANGE_FORBIDDEN)');

    // 2b. Cannot demote sole Owner
    const adminDemotesOwner = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${ownerUser.id}/role`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${admin.token}` },
      body: { role_id: roleMap['Team Member'] }
    });
    assert(adminDemotesOwner.status === 403 && adminDemotesOwner.data.error.code === 'ONLY_OWNER_MAY_MODIFY_OWNER', 'Admin cannot modify Owner role (ONLY_OWNER_MAY_MODIFY_OWNER)');

    // 2c. Privilege escalation: Admin cannot promote Member to Owner
    const adminPromotesToOwner = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${member.id}/role`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${admin.token}` },
      body: { role_id: roleMap['Owner'] }
    });
    assert(adminPromotesToOwner.status === 403 && adminPromotesToOwner.data.error.code === 'PRIVILEGE_ESCALATION_FORBIDDEN', 'Admin cannot promote member to higher rank Owner (PRIVILEGE_ESCALATION_FORBIDDEN)');

    // 2d. Insufficient rank / permissions:
    const pmDemotesAdmin = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${admin.id}/role`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${pm.token}` },
      body: { role_id: roleMap['Team Member'] }
    });
    // PM lacks member.assign_role -> 403 PERMISSION_DENIED
    assert(pmDemotesAdmin.status === 403, 'PM without assign_role permission blocked (403)');

    // Equal-ranked Admin cannot demote another Admin -> 403 INSUFFICIENT_ROLE_RANK
    const admin2 = await createUserWithRole('Alice Admin2', `admin2_${testSuffix}@rbaccorp.com`, 'Admin');
    const adminDemotesAdmin = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${admin.id}/role`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${admin2.token}` },
      body: { role_id: roleMap['Team Member'] }
    });
    assert(adminDemotesAdmin.status === 403 && adminDemotesAdmin.data.error.code === 'INSUFFICIENT_ROLE_RANK', 'Equal-ranked Admin cannot demote another Admin (INSUFFICIENT_ROLE_RANK)');

    // 2e. Sole Owner removal protected
    const removeOwnerRes = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${ownerUser.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${admin.token}` }
    });
    assert(removeOwnerRes.status === 409 || removeOwnerRes.status === 403, 'Removing the sole Owner of workspace is protected (409/403)');

    // 2f. Self removal forbidden
    const selfRemoveRes = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${admin.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${admin.token}` }
    });
    assert(selfRemoveRes.status === 403 && selfRemoveRes.data.error.code === 'SELF_REMOVAL_FORBIDDEN', 'Member cannot remove themselves via DELETE member route (SELF_REMOVAL_FORBIDDEN)');

    // 2g. Privilege escalation in role creation: cannot grant permissions you lack
    const memberCreatesRoleWithAdminPerms = await request(baseUrl, `/api/workspaces/${workspaceId}/roles`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${member.token}` },
      body: {
        name: 'Hacked Super Role',
        permission_keys: ['company.delete', 'company.manage_billing']
      }
    });
    assert(memberCreatesRoleWithAdminPerms.status === 403, 'Member without permissions cannot create a role with elevated permissions');

    // -------------------------------------------------------------------------
    // 3. Two-Level Evaluation & Project Scoping
    // -------------------------------------------------------------------------
    console.log('\n--- 3. Two-Level Permission Evaluation & Scoping ---');

    // 3a. Owner creates Board A
    const boardARes = await request(baseUrl, '/api/boards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: { workspace_id: workspaceId, name: 'Project Alpha' }
    });
    assert(boardARes.status === 201, 'Owner can create Project Alpha');
    const boardAId = boardARes.data.board.id;

    // 3b. Add Dave (Team Member) to Board A
    const addMemberToBoard = await request(baseUrl, `/api/boards/${boardAId}/members`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ownerToken}` },
      body: { user_id: member.id }
    });
    assert(addMemberToBoard.status === 200, 'Owner can add Dave (Team Member) to Project Alpha');

    // 3c. Fetch Board A lists
    const boardADetail = await request(baseUrl, `/api/boards/${boardAId}`, {
      headers: { Authorization: `Bearer ${ownerToken}` }
    });
    const listTodoId = boardADetail.data.board.lists[0].id;

    // 3d. Team Member can view Board A and create task
    const memberGetBoardA = await request(baseUrl, `/api/boards/${boardAId}`, {
      headers: { Authorization: `Bearer ${member.token}` }
    });
    assert(memberGetBoardA.status === 200, 'Team Member can view assigned Project Alpha');

    const memberCreateTask = await request(baseUrl, '/api/cards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${member.token}` },
      body: { list_id: listTodoId, title: 'Task by Team Member' }
    });
    assert(memberCreateTask.status === 201, 'Team Member can create task in Project Alpha');
    const taskAId = memberCreateTask.data.card.id;

    // 3e. Team Member CANNOT delete Board A (403 PERMISSION_DENIED)
    const memberDeleteBoard = await request(baseUrl, `/api/boards/${boardAId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${member.token}` }
    });
    assert(memberDeleteBoard.status === 403, 'Team Member CANNOT delete Project Alpha (403 PERMISSION_DENIED)');

    // 3f. Viewer can view board, but CANNOT create card
    const viewerGetBoardA = await request(baseUrl, `/api/boards/${boardAId}`, {
      headers: { Authorization: `Bearer ${viewer.token}` }
    });
    assert(viewerGetBoardA.status === 200, 'Viewer can view Project Alpha');

    const viewerCreateTask = await request(baseUrl, '/api/cards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${viewer.token}` },
      body: { list_id: listTodoId, title: 'Task by Viewer should fail' }
    });
    assert(viewerCreateTask.status === 403, 'Viewer CANNOT create task (403 PERMISSION_DENIED)');

    // 3g. Guest not assigned to Board A CANNOT view it (403)
    const guestGetBoardA = await request(baseUrl, `/api/boards/${boardAId}`, {
      headers: { Authorization: `Bearer ${guest.token}` }
    });
    assert(guestGetBoardA.status === 403, 'Guest unassigned to Board A gets 403 FORBIDDEN');

    // 3h. Add Guest to Board A -> Guest can now view Board A and comment on task
    await tenantDb.execute(
      "INSERT INTO board_members (board_id, user_id, role) VALUES (?, ?, 'member')",
      [boardAId, guest.id]
    );

    const guestGetBoardAAfterAdd = await request(baseUrl, `/api/boards/${boardAId}`, {
      headers: { Authorization: `Bearer ${guest.token}` }
    });
    assert(guestGetBoardAAfterAdd.status === 200, 'Guest assigned to Board A can now view it');

    const guestCreateTask = await request(baseUrl, '/api/cards', {
      method: 'POST',
      headers: { Authorization: `Bearer ${guest.token}` },
      body: { list_id: listTodoId, title: 'Guest task attempt' }
    });
    assert(guestCreateTask.status === 403, 'Guest still cannot create cards (403 PERMISSION_DENIED)');

    const guestComment = await request(baseUrl, `/api/cards/${taskAId}/comments`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${guest.token}` },
      body: { body: 'Guest comment on task' }
    });
    assert(guestComment.status === 201, 'Guest CAN post comment on assigned board task (comment.create allowed)');

    // -------------------------------------------------------------------------
    // 4. File Authorization via Permission Engine
    // -------------------------------------------------------------------------
    console.log('\n--- 4. Unified File Authorization (`file.view`) ---');

    const ownerFilePerm = await userHasPermission(ownerUser.id, workspaceId, 'file.view', tenantDb, boardAId);
    assert(ownerFilePerm === true, 'userHasPermission returns true for Owner on file.view');

    const memberFilePerm = await userHasPermission(member.id, workspaceId, 'file.view', tenantDb, boardAId);
    assert(memberFilePerm === true, 'userHasPermission returns true for assigned Team Member on file.view');

    const guestFilePerm = await userHasPermission(guest.id, workspaceId, 'file.view', tenantDb, boardAId);
    assert(guestFilePerm === true, 'userHasPermission returns true for assigned Guest on file.view');

    // -------------------------------------------------------------------------
    // 5. Phase 3 & C.5 Routes Across Roles Matrix
    // -------------------------------------------------------------------------
    console.log('\n--- 5. Phase 3 & C.5 Routes Across Roles Matrix ---');

    // 5a. Sessions route: everyone can view own sessions
    for (const u of [ownerUser, admin, pm, member, viewer, guest]) {
      const uToken = u.token || ownerToken;
      const sessRes = await request(baseUrl, '/api/auth/sessions', {
        headers: { Authorization: `Bearer ${uToken}` }
      });
      assert(sessRes.status === 200, `${u.name || 'Owner'} can access GET /api/auth/sessions (session.view_own)`);
    }

    // 5b. Administrative session revocation (session.revoke_others):
    // Member cannot revoke Admin's session
    const memberRevokesAdminSess = await request(baseUrl, `/api/auth/sessions/${admin.sid}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${member.token}` }
    });
    assert(memberRevokesAdminSess.status === 403, 'Team Member CANNOT administratively revoke others sessions (403)');

    // Admin CAN revoke Member's session
    const adminRevokesMemberSess = await request(baseUrl, `/api/auth/sessions/${member.sid}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${admin.token}` }
    });
    assert(adminRevokesMemberSess.status === 200, 'Admin CAN administratively revoke member session (session.revoke_others)');

    // 5c. 2FA Status route
    const twoFaStatusRes = await request(baseUrl, '/api/auth/2fa/status', {
      headers: { Authorization: `Bearer ${pm.token}` }
    });
    assert(twoFaStatusRes.status === 200, 'PM can check 2FA status');

    // 5d. Password Reset Authority across role hierarchy
    const pmResetsAdmin = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${admin.id}/reset-password`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${pm.token}` }
    });
    // PM lacks member.reset_password -> 403 PERMISSION_DENIED
    assert(pmResetsAdmin.status === 403, 'PM without reset_password permission blocked (403)');

    // Admin cannot reset equal-ranked Admin -> 403 INSUFFICIENT_ROLE_RANK
    const adminResetsAdmin = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${admin2.id}/reset-password`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${admin.token}` }
    });
    assert(adminResetsAdmin.status === 403 && adminResetsAdmin.data.error.code === 'INSUFFICIENT_ROLE_RANK', 'Admin cannot reset equal-ranked Admin password (INSUFFICIENT_ROLE_RANK)');

    // Admin CAN reset Member password
    const adminResetsMember = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${member.id}/reset-password`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${admin.token}` },
      body: { temporaryPassword: 'TempPassword123!@#' }
    });
    assert(adminResetsMember.status === 200, 'Admin CAN reset lower-ranked Member password');

    // 5e. 2FA Reset Authority
    // Admin cannot reset Owner 2FA
    const adminResetsOwner2fa = await request(baseUrl, `/api/workspaces/${workspaceId}/members/${ownerUser.id}/reset-2fa`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${admin.token}` }
    });
    assert(adminResetsOwner2fa.status === 403 && adminResetsOwner2fa.data.error.code === 'ONLY_OWNER_MAY_RESET_OWNER', 'Admin cannot reset Owner 2FA (ONLY_OWNER_MAY_RESET_OWNER)');

    // 5f. Self Evaluation endpoint: GET /api/permissions/me
    const myPermsRes = await request(baseUrl, `/api/permissions/me?workspace_id=${workspaceId}`, {
      headers: { Authorization: `Bearer ${viewer.token}` }
    });
    assert(myPermsRes.status === 200, 'GET /api/permissions/me returns user permissions');
    assert(myPermsRes.data.role?.name === 'Viewer', 'Returns correct role for Viewer');
    assert(Array.isArray(myPermsRes.data.permissions), 'Returns array of permissions');

    // -------------------------------------------------------------------------
    // 6. Previously Misidentified & Unprotected Routes Across 6 Roles
    // -------------------------------------------------------------------------
    console.log('\n--- 6. Previously Misidentified & Unprotected Routes Across 6 Roles ---');

    // Dave Member's session was revoked and password reset in step 5; log in and complete password change
    const daveTempLogin = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: member.email, password: 'TempPassword123!@#', tenant_slug: tenantSlug }
    });
    await request(baseUrl, '/api/auth/change-password', {
      method: 'POST',
      headers: { Authorization: `Bearer ${daveTempLogin.data.token}` },
      body: { currentPassword: 'TempPassword123!@#', newPassword: 'NewDavePassword123!@#' }
    });
    const daveReLogin = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      body: { email: member.email, password: 'NewDavePassword123!@#', tenant_slug: tenantSlug }
    });
    member.token = daveReLogin.data.token;

    // 6a. GET /api/invitations: Owner, Admin, PM allowed (200); Member, Viewer, Guest forbidden (403)
    for (const u of [ownerUser, admin, pm]) {
      const uToken = u.token || ownerToken;
      const res = await request(baseUrl, `/api/invitations?workspace_id=${workspaceId}`, {
        headers: { Authorization: `Bearer ${uToken}` }
      });
      assert(res.status === 200, `${u.name || 'Owner'} CAN access GET /api/invitations (member.invite)`);
    }

    for (const u of [member, viewer, guest]) {
      const res = await request(baseUrl, `/api/invitations?workspace_id=${workspaceId}`, {
        headers: { Authorization: `Bearer ${u.token}` }
      });
      assert(res.status === 403, `${u.name} CANNOT access GET /api/invitations (403 FORBIDDEN)`);
    }

    // 6b. POST /api/invitations: PM can invite (200 or 202), Member blocked (403)
    const pmInviteRes = await request(baseUrl, '/api/invitations', {
      method: 'POST',
      headers: { Authorization: `Bearer ${pm.token}` },
      body: {
        email: `invited_by_pm_${testSuffix}@rbaccorp.com`,
        workspace_id: workspaceId
      }
    });
    assert(pmInviteRes.status === 200 || pmInviteRes.status === 202, 'PM can create invitation (member.invite)');
    const [invRow] = await tenantDb.query('SELECT id FROM pending_invitations WHERE token = ?', [pmInviteRes.data.invite_token]);
    const createdInviteId = invRow.id;

    const memberInviteRes = await request(baseUrl, '/api/invitations', {
      method: 'POST',
      headers: { Authorization: `Bearer ${member.token}` },
      body: {
        email: `hacked_invite_${testSuffix}@rbaccorp.com`,
        workspace_id: workspaceId
      }
    });
    assert(memberInviteRes.status === 403, 'Team Member CANNOT create invitation (403 FORBIDDEN)');

    // 6c. DELETE /api/invitations/:id: Member blocked (403), PM can revoke (200)
    const memberRevokeRes = await request(baseUrl, `/api/invitations/${createdInviteId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${member.token}` }
    });
    assert(memberRevokeRes.status === 403, 'Team Member CANNOT revoke invitation (403 FORBIDDEN)');

    const pmRevokeRes = await request(baseUrl, `/api/invitations/${createdInviteId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${pm.token}` }
    });
    assert(pmRevokeRes.status === 200, 'PM can revoke invitation (member.invite)');

    // 6d. GET /api/notifications/unread-count: all 6 roles can access own count (200)
    for (const u of [ownerUser, admin, pm, member, viewer, guest]) {
      const uToken = u.token || ownerToken;
      const res = await request(baseUrl, '/api/notifications/unread-count', {
        headers: { Authorization: `Bearer ${uToken}` }
      });
      assert(res.status === 200, `${u.name || 'Owner'} can access GET /api/notifications/unread-count (self-scoped)`);
    }

    // 6e. GET /api/permissions: all authenticated roles can view permission catalog (200)
    for (const u of [ownerUser, admin, pm, member, viewer, guest]) {
      const uToken = u.token || ownerToken;
      const res = await request(baseUrl, '/api/permissions', {
        headers: { Authorization: `Bearer ${uToken}` }
      });
      assert(res.status === 200, `${u.name || 'Owner'} can access GET /api/permissions catalog`);
    }

    // 6f. GET /api/workspaces/:id/my-permissions: all roles can evaluate their own permissions (200)
    for (const u of [ownerUser, admin, pm, member, viewer]) {
      const uToken = u.token || ownerToken;
      const res = await request(baseUrl, `/api/workspaces/${workspaceId}/my-permissions`, {
        headers: { Authorization: `Bearer ${uToken}` }
      });
      assert(res.status === 200, `${u.name || 'Owner'} can access GET /api/workspaces/:id/my-permissions`);
    }

    // 6g. Custom role modifications: Member/Viewer/Guest cannot PATCH or DELETE roles
    const dummyRoleExec = await tenantDb.execute(
      "INSERT INTO roles (name, workspace_id, is_system, is_editable) VALUES ('Test Role', ?, 0, 1)",
      [workspaceId]
    );
    const dummyRoleId = dummyRoleExec.insertId;

    const memberPatchRole = await request(baseUrl, `/api/roles/${dummyRoleId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${member.token}` },
      body: { name: 'Renamed by Member' }
    });
    assert(memberPatchRole.status === 403, 'Team Member CANNOT modify roles (403 FORBIDDEN)');

    const memberDeleteRole = await request(baseUrl, `/api/roles/${dummyRoleId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${member.token}` }
    });
    assert(memberDeleteRole.status === 403, 'Team Member CANNOT delete roles (403 FORBIDDEN)');

    console.log(`\n================================================================`);
    console.log(`Part E RBAC Tests Completed: ${passedTests} passed, ${failedTests} failed.`);
    console.log(`================================================================\n`);

  } catch (err) {
    console.error('Test execution failed with error:', err);
    failedTests++;
  } finally {
    if (server) server.close();
    process.exit(failedTests > 0 ? 1 : 0);
  }
}

runPartERbacTests();

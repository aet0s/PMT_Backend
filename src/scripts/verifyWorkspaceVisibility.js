const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });
require('dotenv').config();
process.env.DEV_SINGLE_TENANT = '0';
process.env.REGISTRATION_RATE_LIMIT_PER_HOUR = '500';
process.env.REGISTRATION_DAILY_CAP = '10000';

const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const assert = require('assert');

const { app } = require('../index');
const { getTenantDb, closeAllPools } = require('../services/tenantPools');

let server;
let baseUrl;

function request(urlPath, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, baseUrl);
    const headers = { ...options.headers };
    let body = options.body;

    if (body && typeof body === 'object' && !(body instanceof Buffer)) {
      body = JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(body);
    }

    const req = http.request(
      url,
      {
        method: options.method || 'GET',
        headers
      },
      (res) => {
        let rawData = '';
        res.on('data', (chunk) => {
          rawData += chunk;
        });
        res.on('end', () => {
          let parsedData = null;
          if (rawData) {
            try {
              parsedData = JSON.parse(rawData);
            } catch (e) {
              parsedData = rawData;
            }
          }
          resolve({
            status: res.statusCode,
            headers: res.headers,
            data: parsedData
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

async function runTest() {
  console.log('================================================================');
  console.log('   VERIFY WORKSPACE VISIBILITY FOR ADMIN / OWNER WHEN PM CREATES  ');
  console.log('================================================================\n');

  await new Promise((resolve) => {
    server = app.listen(0, () => {
      const port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });

  const testSuffix = crypto.randomBytes(3).toString('hex');
  const tenantSlug = `wsvis_${testSuffix}`;
  const defaultPassword = 'SecurePassword123!';

  console.log(`[1] Registering company: ${tenantSlug}...`);
  const regRes = await request('/api/auth/register-company', {
    method: 'POST',
    body: {
      companyName: `Visibility Corp ${testSuffix}`,
      slug: tenantSlug,
      name: 'Corporate Owner',
      email: `owner_${testSuffix}@example.com`,
      password: defaultPassword
    }
  });

  assert.strictEqual(regRes.status, 201, 'Company registration succeeded');
  const ownerToken = regRes.data.token;
  const tenantId = regRes.data.tenant.id;
  const initialWorkspaceId = regRes.data.initial_workspace_id;
  const tenantDb = await getTenantDb(tenantId);

  const rolesRows = await tenantDb.query('SELECT id, name FROM roles WHERE workspace_id IS NULL');
  const roleMap = {};
  rolesRows.forEach((r) => { roleMap[r.name] = r.id; });

  async function createMember(name, email, roleName) {
    const passwordHash = await bcrypt.hash(defaultPassword, 10);
    const userExec = await tenantDb.execute(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      [name, email, passwordHash]
    );
    const userId = userExec.insertId;
    const roleId = roleMap[roleName];

    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)',
      [initialWorkspaceId, userId, roleName, roleId]
    );

    const loginRes = await request('/api/auth/login', {
      method: 'POST',
      body: { email, password: defaultPassword, tenant_slug: tenantSlug }
    });

    return {
      id: userId,
      name,
      email,
      token: loginRes.data.token,
      roleName,
      roleId
    };
  }

  console.log('[2] Creating Admin, Project Manager, and Team Member...');
  const adminMember = await createMember('Admin Alice', `admin_${testSuffix}@example.com`, 'Admin');
  const pmMember = await createMember('PM Bob', `pm_${testSuffix}@example.com`, 'Project Manager');
  const teamMember = await createMember('Dev Dave', `dev_${testSuffix}@example.com`, 'Team Member');

  console.log('[3] Verifying Team Member cannot create workspace (returns 403)...');
  const unauthWsRes = await request('/api/workspaces', {
    method: 'POST',
    headers: { Authorization: `Bearer ${teamMember.token}` },
    body: { name: 'Unauthorized Workspace' }
  });
  console.log(`    Team Member POST /api/workspaces returned: ${unauthWsRes.status}`);
  assert.strictEqual(unauthWsRes.status, 403, 'Team Member without permission is forbidden from creating workspace');

  console.log('[4] Admin grants workspace.create permission to Project Manager role...');
  const rolesRes = await request(`/api/workspaces/${initialWorkspaceId}/roles`, {
    headers: { Authorization: `Bearer ${adminMember.token}` }
  });
  const pmRoleObj = rolesRes.data.roles.find((r) => r.name === 'Project Manager');
  const updatedPmPerms = Array.from(new Set([...(pmRoleObj.permission_keys || []), 'workspace.create']));

  const patchRoleRes = await request(`/api/roles/${pmRoleObj.id}`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${adminMember.token}` },
    body: {
      name: 'Project Manager',
      permission_keys: updatedPmPerms,
      workspace_id: initialWorkspaceId
    }
  });
  assert.strictEqual(patchRoleRes.status, 200, 'Admin successfully granted workspace.create to Project Manager');

  console.log('[5] Project Manager creates a new workspace: "Sprint Alpha Engineering Workspace"...');
  const createWsRes = await request('/api/workspaces', {
    method: 'POST',
    headers: { Authorization: `Bearer ${pmMember.token}` },
    body: { name: 'Sprint Alpha Engineering Workspace' }
  });
  console.log(`    Project Manager POST /api/workspaces returned: ${createWsRes.status}`);
  assert.strictEqual(createWsRes.status, 201, 'Project Manager successfully created new workspace');
  const newWorkspace = createWsRes.data.workspace;
  console.log(`    Created Workspace ID: ${newWorkspace.id}, Name: "${newWorkspace.name}"`);

  console.log('\n[6] VERIFYING WORKSPACE VISIBILITY FOR OWNER...');
  const ownerWsRes = await request('/api/workspaces', {
    headers: { Authorization: `Bearer ${ownerToken}` }
  });
  assert.strictEqual(ownerWsRes.status, 200, 'Owner can fetch workspaces');
  const ownerWorkspaces = ownerWsRes.data.workspaces || [];
  console.log(`    Owner sees ${ownerWorkspaces.length} workspaces:`, ownerWorkspaces.map(w => `${w.id}: ${w.name} (${w.role_name})`));
  const ownerHasNewWs = ownerWorkspaces.some((w) => w.id === newWorkspace.id);
  assert(ownerHasNewWs, 'Newly created workspace MUST be visible to Company Owner in GET /api/workspaces');

  const ownerPermsInNewWs = await request(`/api/workspaces/${newWorkspace.id}/my-permissions`, {
    headers: { Authorization: `Bearer ${ownerToken}` }
  });
  assert.strictEqual(ownerPermsInNewWs.status, 200, 'Owner can access new workspace permissions');
  assert.strictEqual(ownerPermsInNewWs.data.role.name, 'Owner', 'Owner has Owner role in new workspace');
  console.log('    ✓ Owner has full Owner role & visibility in the new workspace!');

  console.log('\n[7] VERIFYING WORKSPACE VISIBILITY FOR ADMIN...');
  const adminWsRes = await request('/api/workspaces', {
    headers: { Authorization: `Bearer ${adminMember.token}` }
  });
  assert.strictEqual(adminWsRes.status, 200, 'Admin can fetch workspaces');
  const adminWorkspaces = adminWsRes.data.workspaces || [];
  console.log(`    Admin sees ${adminWorkspaces.length} workspaces:`, adminWorkspaces.map(w => `${w.id}: ${w.name} (${w.role_name})`));
  const adminHasNewWs = adminWorkspaces.some((w) => w.id === newWorkspace.id);
  assert(adminHasNewWs, 'Newly created workspace MUST be visible to Company Admin in GET /api/workspaces');

  const adminPermsInNewWs = await request(`/api/workspaces/${newWorkspace.id}/my-permissions`, {
    headers: { Authorization: `Bearer ${adminMember.token}` }
  });
  assert.strictEqual(adminPermsInNewWs.status, 200, 'Admin can access new workspace permissions');
  assert.strictEqual(adminPermsInNewWs.data.role.name, 'Admin', 'Admin has Admin role in new workspace');
  console.log('    ✓ Admin has full Admin role & visibility in the new workspace!');

  console.log('\n[8] VERIFYING WORKSPACE VISIBILITY FOR PROJECT MANAGER (CREATOR)...');
  const pmWsRes = await request('/api/workspaces', {
    headers: { Authorization: `Bearer ${pmMember.token}` }
  });
  assert.strictEqual(pmWsRes.status, 200, 'PM can fetch workspaces');
  const pmWorkspaces = pmWsRes.data.workspaces || [];
  console.log(`    PM sees ${pmWorkspaces.length} workspaces:`, pmWorkspaces.map(w => `${w.id}: ${w.name} (${w.role_name})`));
  const pmHasNewWs = pmWorkspaces.some((w) => w.id === newWorkspace.id);
  assert(pmHasNewWs, 'Newly created workspace MUST be visible to Project Manager in GET /api/workspaces');

  const pmPermsInNewWs = await request(`/api/workspaces/${newWorkspace.id}/my-permissions`, {
    headers: { Authorization: `Bearer ${pmMember.token}` }
  });
  assert.strictEqual(pmPermsInNewWs.status, 200, 'PM can access new workspace permissions');
  console.log(`    ✓ Project Manager role in new workspace: ${pmPermsInNewWs.data.role.name}`);

  console.log('\n[9] VERIFYING OWNER AND ADMIN CAN MANAGE BOARDS IN NEW WORKSPACE...');
  const ownerBoardRes = await request('/api/boards', {
    method: 'POST',
    headers: { Authorization: `Bearer ${ownerToken}` },
    body: { workspace_id: newWorkspace.id, name: 'Executive Overview Board' }
  });
  assert.strictEqual(ownerBoardRes.status, 201, 'Owner can create board in newly created workspace');
  console.log('    ✓ Owner successfully created board in new workspace!');

  const adminBoardRes = await request('/api/boards', {
    method: 'POST',
    headers: { Authorization: `Bearer ${adminMember.token}` },
    body: { workspace_id: newWorkspace.id, name: 'Admin Ops Board' }
  });
  assert.strictEqual(adminBoardRes.status, 201, 'Admin can create board in newly created workspace');
  console.log('    ✓ Admin successfully created board in new workspace!');

  console.log('\n================================================================');
  console.log('   ALL 9 WORKSPACE VISIBILITY TESTS PASSED (100%)');
  console.log('================================================================');

  await closeAllPools();
  server.close();
  process.exit(0);
}

runTest().catch(async (err) => {
  console.error('Test execution failed:', err);
  if (server) server.close();
  await closeAllPools();
  process.exit(1);
});

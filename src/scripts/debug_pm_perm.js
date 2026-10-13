// server/src/scripts/debug_pm_perm.js
const http = require('http');
const { app } = require('../index');
const { getTenantDb, closeAllPools } = require('../services/tenantPools');
const { userHasPermission } = require('../middleware/permissions');
const bcrypt = require('bcryptjs');

async function testPerm() {
  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  function req(path, opts = {}) {
    return new Promise((resolve, reject) => {
      const url = new URL(path, baseUrl);
      const headers = { ...opts.headers };
      let body = opts.body;
      if (body) {
        body = JSON.stringify(body);
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = Buffer.byteLength(body);
      }
      const r = http.request(url, { method: opts.method || 'GET', headers }, (res) => {
        let b = '';
        res.on('data', (c) => (b += c));
        res.on('end', () => resolve({ status: res.statusCode, data: JSON.parse(b || '{}') }));
      });
      r.on('error', reject);
      if (body) r.write(body);
      r.end();
    });
  }

  const reg = await req('/api/auth/register-company', {
    method: 'POST',
    body: { companyName: 'Check Corp', slug: 'chk_' + Date.now(), name: 'Own', email: 'o' + Date.now() + '@c.com', password: 'Password123!' }
  });
  const tDb = await getTenantDb(reg.data.tenant.id);
  const wsId = reg.data.initial_workspace_id;
  const ownerToken = reg.data.token;

  const roles = await tDb.query('SELECT id, name FROM roles WHERE workspace_id IS NULL');
  const pmRole = roles.find((r) => r.name === 'Project Manager');
  const adminRole = roles.find((r) => r.name === 'Admin');

  // Create Admin
  const hash = await bcrypt.hash('Password123!', 10);
  const admEmail = 'adm' + Date.now() + '@c.com';
  const u1 = await tDb.execute('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', ['Admin', admEmail, hash]);
  await tDb.execute('INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)', [wsId, u1.insertId, 'Admin', adminRole.id]);
  const admLogin = await req('/api/auth/login', { method: 'POST', body: { email: admEmail, password: 'Password123!', tenant_slug: reg.data.tenant.slug } });

  // Create PM
  const pmEmail = 'pm' + Date.now() + '@c.com';
  const u2 = await tDb.execute('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', ['PM', pmEmail, hash]);
  await tDb.execute('INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)', [wsId, u2.insertId, 'Project Manager', pmRole.id]);
  const pmLogin = await req('/api/auth/login', { method: 'POST', body: { email: pmEmail, password: 'Password123!', tenant_slug: reg.data.tenant.slug } });

  // Create Board
  const bRes = await req('/api/boards', { method: 'POST', headers: { Authorization: 'Bearer ' + ownerToken }, body: { workspace_id: wsId, name: 'B1' } });
  const boardId = bRes.data.board.id;
  await req('/api/boards/' + boardId + '/members', { method: 'POST', headers: { Authorization: 'Bearer ' + ownerToken }, body: { user_id: u2.insertId } });

  // Create card
  const cRes = await req('/api/cards', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + ownerToken },
    body: { list_id: (await tDb.query('INSERT INTO lists (board_id, name, position) VALUES (?, ?, ?)', [boardId, 'Col', 1000])).insertId, title: 'C1', position: 1000 }
  });
  const cardId = cRes.data.card.id;

  // Check card delete before revoke
  const del1 = await req('/api/cards/' + cardId, { method: 'DELETE', headers: { Authorization: 'Bearer ' + pmLogin.data.token } });
  console.log('1. PM delete card before revoke status:', del1.status);

  // Admin revokes task.delete
  const pmPermsRes = await req('/api/workspaces/' + wsId + '/roles', { headers: { Authorization: 'Bearer ' + admLogin.data.token } });
  const fetchedPmRole = pmPermsRes.data.roles.find((r) => r.name === 'Project Manager');
  const newKeys = fetchedPmRole.permission_keys.filter((k) => k !== 'task.delete' && k !== 'card.delete');

  const updateRes = await req('/api/roles/' + pmRole.id, {
    method: 'PATCH',
    headers: { Authorization: 'Bearer ' + admLogin.data.token },
    body: { name: 'Project Manager', permission_keys: newKeys, workspace_id: wsId }
  });
  console.log('2. Admin update PM role status:', updateRes.status);

  // Create another card
  const c2Res = await req('/api/cards', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + ownerToken },
    body: { list_id: (await tDb.query('SELECT id FROM lists WHERE board_id = ? LIMIT 1', [boardId]))[0].id, title: 'C2', position: 1000 }
  });
  const card2Id = c2Res.data.card.id;

  // Check card delete after revoke
  const del2 = await req('/api/cards/' + card2Id, { method: 'DELETE', headers: { Authorization: 'Bearer ' + pmLogin.data.token } });
  console.log('3. PM delete card after revoke status:', del2.status, del2.data);

  if (hasAfterRevoke) {
    const wsRows = await tDb.query(
      'SELECT r.id as role_id, r.name as role_name, r.is_system, p.key as permission_key FROM workspace_members wm JOIN roles r ON wm.role_id = r.id LEFT JOIN role_permissions rp ON r.id = rp.role_id LEFT JOIN permissions p ON rp.permission_id = p.id WHERE wm.workspace_id = ? AND wm.user_id = ? AND p.key LIKE ?',
      [wsId, u2.insertId, '%delete%']
    );
    console.log('wsRows with delete:', wsRows);

    const bmRows = await tDb.query(
      'SELECT bm.role_id, r.name as role_name, r.is_system, p.key as permission_key FROM board_members bm LEFT JOIN roles r ON bm.role_id = r.id LEFT JOIN role_permissions rp ON r.id = rp.role_id LEFT JOIN permissions p ON rp.permission_id = p.id WHERE bm.board_id = ? AND bm.user_id = ?',
      [boardId, u2.insertId]
    );
    console.log('bmRows:', bmRows);
  }

  await closeAllPools();
  server.close();
  process.exit(0);
}

testPerm();

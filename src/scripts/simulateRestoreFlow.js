// server/src/scripts/simulateRestoreFlow.js
const BASE_URL = 'http://localhost:5000';

async function simulate(email, password, wsIdToRestore) {
  console.log(`\n================ SIMULATING AS ${email} FOR WS ${wsIdToRestore} ================`);
  const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const { token, user } = await loginRes.json();
  console.log(`✓ Logged in as ${user.email}`);

  // Browser on mount calls:
  // 1. GET /api/workspaces
  console.log('1. Calling GET /api/workspaces...');
  const wsRes = await fetch(`${BASE_URL}/api/workspaces`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  console.log('   Status:', wsRes.status);
  const wsData = await wsRes.json();
  const activeWs = wsData.workspaces?.filter(w => !w.is_archived) || [];
  console.log('   Active workspaces count:', activeWs.length);

  // 2. GET /api/workspaces/:id/my-permissions
  const currentWsId = activeWs[0]?.id || wsIdToRestore;
  console.log(`2. Calling GET /api/workspaces/${currentWsId}/my-permissions...`);
  const permRes = await fetch(`${BASE_URL}/api/workspaces/${currentWsId}/my-permissions`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  console.log('   Status:', permRes.status);

  // 3. User navigates to Archive: GET /api/archive
  console.log('3. Calling GET /api/archive without workspace_id...');
  const archRes1 = await fetch(`${BASE_URL}/api/archive`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  console.log('   GET /api/archive status:', archRes1.status);
  const archText1 = await archRes1.text();
  console.log('   GET /api/archive body:', archText1.slice(0, 150));

  console.log(`4. Calling GET /api/archive?workspace_id=${currentWsId}...`);
  const archRes2 = await fetch(`${BASE_URL}/api/archive?workspace_id=${currentWsId}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  console.log('   GET /api/archive?workspace_id status:', archRes2.status);

  // 5. User clicks Restore: PATCH /api/workspaces/:id { is_archived: false }
  console.log(`5. Clicking Restore: PATCH /api/workspaces/${wsIdToRestore} { is_archived: false }...`);
  const restRes = await fetch(`${BASE_URL}/api/workspaces/${wsIdToRestore}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify({ is_archived: false })
  });
  console.log('   PATCH /api/workspaces/:id status:', restRes.status);
  const restText = await restRes.text();
  console.log('   PATCH /api/workspaces/:id body:', restText);
}

async function run() {
  // First, let's archive Workspace 2 so it is definitely archived
  const rootLogin = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'owner@demo.com', password: 'Password123!' })
  });
  const { token } = await rootLogin.json();
  await fetch(`${BASE_URL}/api/workspaces/2`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ is_archived: true })
  });

  await simulate('owner@demo.com', 'Password123!', 2);
  await simulate('owner@demo.com', 'Password123!', 3);
}

run().catch(console.error);

// server/src/scripts/permtest/workspaceCreationRoles.js
// Regression test suite for Workspace Creation Role & Permission Escalation Prevention.
// Verifies that:
// 1. Non-company-owners never escalate to Owner.
// 2. Canonical system roles retain their exact corresponding system role without escalating.
// 3. Custom roles DO NOT map to Team Member, PM, or Admin purely by numeric rank.
// 4. Custom roles receive a destination workspace-scoped role containing ONLY safe, transferable permissions.
// 5. Transitive prerequisites are strictly enforced; broken prerequisites fail closed (UNSAFE_CUSTOM_ROLE_MAPPING).
// 6. Dangerous and company-wide permissions are stripped and never leak across workspace boundaries.
// 7. Multiple authorizing memberships resolve deterministically via least privilege (lowest rank).
// 8. Custom roles with rank < 10 fail closed with NO_VALID_WORKSPACE_CREATOR_ROLE.
// 9. Existing memberships are unaffected, and catalog sync preserves correct mappings.

const { PermtestFixture } = require('./fixtures');
const { PermtestClient } = require('./client');
const { syncSingleTenant } = require('../rbacMatrixV2Sync');
const { closeAllTenantPools } = require('../../services/tenantPools');
const { getUserPermissions } = require('../../middleware/permissions');
const jwt = require('jsonwebtoken');

async function runWorkspaceCreationRoleSuite(fixture) {
  const { users, tenantDb, context, slug } = fixture;
  const results = [];

  function record(id, title, passed, details, evidence = null) {
    results.push({ id, title, passed, details, evidence });
    const status = passed ? '✅ PASS' : '❌ FAIL';
    console.log(`[${id}] ${status}: ${title}`);
    if (!passed) {
      console.log(`    Expected: ${details?.expected}`);
      console.log(`    Actual:   ${details?.actual}`);
      if (evidence) {
        console.log(`    Evidence: ${JSON.stringify(evidence).slice(0, 200)}...`);
      }
    }
  }

  console.log('\n================================================================');
  console.log('   WORKSPACE CREATION ROLE ESCALATION PREVENTION TEST SUITE     ');
  console.log('================================================================\n');

  // Fetch canonical system roles
  const sysRoles = await tenantDb.query(
    'SELECT id, name, rank FROM roles WHERE is_system = 1 AND workspace_id IS NULL ORDER BY rank DESC'
  );
  const sysRoleMap = {};
  sysRoles.forEach((r) => { sysRoleMap[r.name] = r; });

  const [permRow] = await tenantDb.query("SELECT id FROM permissions WHERE `key` = 'workspace.create'");
  const wsCreatePermId = permRow?.id;
  if (!wsCreatePermId) {
    throw new Error('[TEST SETUP] workspace.create permission not found in permissions table');
  }

  const w1Id = context.w1Id;
  const w2Id = context.w2Id;

  // Helper to create an authenticated client for a new user
  function createTestClient(userId, email, name = 'Test User') {
    const client = new PermtestClient({ frontendUrl: fixture.frontendUrl });
    const token = jwt.sign(
      { sub: userId, userId, email, name, tid: fixture.tenant.id, tenantId: fixture.tenant.id },
      process.env.JWT_SECRET || 'test-jwt-secret-for-permtest-hardening-phase',
      { expiresIn: '2h' }
    );
    client.token = token;
    client.user = { id: userId, email, name };
    return client;
  }

  // --------------------------------------------------------------------------
  // TEST 1: Owner creates workspace -> receives Owner (rank 100)
  // --------------------------------------------------------------------------
  try {
    const ownerClient = users['Owner'].client;
    const wsName = `Ws_CreatedBy_Owner_${Date.now()}`;
    const res = await ownerClient.post('/api/workspaces', { name: wsName });

    const wsData = res.data?.workspace || res.data;
    const [dbMember] = await tenantDb.query(
      'SELECT wm.role, wm.role_id, r.rank FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [wsData?.id, ownerClient.user.id]
    );

    const passed = res.status === 201 &&
      wsData?.role === 'Owner' &&
      dbMember?.role === 'Owner' &&
      Number(dbMember?.rank) === 100;

    record(
      'WCR-1.1',
      'Verified Company Owner creates workspace and receives Owner (rank 100)',
      passed,
      {
        expected: 'HTTP 201, role=Owner, rank=100',
        actual: `HTTP ${res.status}, role=${wsData?.role}, dbRole=${dbMember?.role}, rank=${dbMember?.rank}`
      },
      wsData
    );
  } catch (err) {
    record('WCR-1.1', 'Company Owner workspace creation', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 2: Admin creates workspace -> receives Admin (rank 80, NOT Owner)
  // --------------------------------------------------------------------------
  try {
    const adminClient = users['Admin'].client;
    const wsName = `Ws_CreatedBy_Admin_${Date.now()}`;
    const res = await adminClient.post('/api/workspaces', { name: wsName });

    const wsData = res.data?.workspace || res.data;
    const [dbMember] = await tenantDb.query(
      'SELECT wm.role, wm.role_id, r.rank FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [wsData?.id, adminClient.user.id]
    );

    const passed = res.status === 201 &&
      wsData?.role === 'Admin' &&
      dbMember?.role === 'Admin' &&
      Number(dbMember?.rank) === 80 &&
      dbMember?.role !== 'Owner';

    record(
      'WCR-1.2',
      'Admin creates workspace and receives canonical Admin (rank 80, NOT Owner)',
      passed,
      {
        expected: 'HTTP 201, role=Admin, rank=80, role!=Owner',
        actual: `HTTP ${res.status}, role=${wsData?.role}, dbRole=${dbMember?.role}, rank=${dbMember?.rank}`
      },
      wsData
    );
  } catch (err) {
    record('WCR-1.2', 'Admin workspace creation', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 3: Project Manager with workspace.create -> receives Project Manager (rank 60, NOT Owner, NOT Admin)
  // --------------------------------------------------------------------------
  try {
    const pmClient = users['Project Manager'].client;

    // A. Without workspace.create -> MUST get 403
    const denyRes = await pmClient.post('/api/workspaces', { name: `Ws_PM_Deny_${Date.now()}` });
    const isDeniedWithoutPerm = denyRes.status === 403;

    // B. Grant workspace.create to Project Manager system role
    const pmRoleId = sysRoleMap['Project Manager']?.id;
    await tenantDb.execute(
      'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
      [pmRoleId, wsCreatePermId]
    );

    // C. With workspace.create -> MUST get 201, role=Project Manager (NOT Owner)
    const wsName = `Ws_CreatedBy_PM_${Date.now()}`;
    const allowRes = await pmClient.post('/api/workspaces', { name: wsName });
    const wsData = allowRes.data?.workspace || allowRes.data;

    const [dbMember] = await tenantDb.query(
      'SELECT wm.role, wm.role_id, r.rank FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [wsData?.id, pmClient.user.id]
    );

    const passed = isDeniedWithoutPerm &&
      allowRes.status === 201 &&
      wsData?.role === 'Project Manager' &&
      dbMember?.role === 'Project Manager' &&
      Number(dbMember?.rank) === 60 &&
      dbMember?.role !== 'Owner';

    record(
      'WCR-1.3',
      'Project Manager receives Project Manager (rank 60, NOT Owner) when authorized',
      passed,
      {
        expected: 'Denied without perm (403), allowed with perm (201), role=Project Manager, rank=60',
        actual: `denyStatus=${denyRes.status}, allowStatus=${allowRes.status}, role=${wsData?.role}, rank=${dbMember?.rank}`
      },
      wsData
    );
  } catch (err) {
    record('WCR-1.3', 'Project Manager workspace creation', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 4: Team Lead with workspace.create -> receives Team Lead (rank 50, NOT PM, NOT Owner)
  // --------------------------------------------------------------------------
  try {
    const tlClient = users['Team Lead'].client;
    const tlRoleId = sysRoleMap['Team Lead']?.id;

    await tenantDb.execute(
      'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
      [tlRoleId, wsCreatePermId]
    );

    const wsName = `Ws_CreatedBy_TL_${Date.now()}`;
    const res = await tlClient.post('/api/workspaces', { name: wsName });
    const wsData = res.data?.workspace || res.data;

    const [dbMember] = await tenantDb.query(
      'SELECT wm.role, wm.role_id, r.rank FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [wsData?.id, tlClient.user.id]
    );

    const passed = res.status === 201 &&
      wsData?.role === 'Team Lead' &&
      dbMember?.role === 'Team Lead' &&
      Number(dbMember?.rank) === 50 &&
      dbMember?.role !== 'Project Manager' &&
      dbMember?.role !== 'Owner';

    record(
      'WCR-1.4',
      'Team Lead receives Team Lead (rank 50, NOT PM, NOT Owner) when authorized',
      passed,
      {
        expected: 'HTTP 201, role=Team Lead, rank=50, role!=PM, role!=Owner',
        actual: `HTTP ${res.status}, role=${wsData?.role}, dbRole=${dbMember?.role}, rank=${dbMember?.rank}`
      },
      wsData
    );
  } catch (err) {
    record('WCR-1.4', 'Team Lead workspace creation', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 5: Team Member with workspace.create -> receives Team Member (rank 40, NOT PM!)
  // --------------------------------------------------------------------------
  try {
    const tmClient = users['Team Member'].client;
    const tmRoleId = sysRoleMap['Team Member']?.id;

    await tenantDb.execute(
      'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
      [tmRoleId, wsCreatePermId]
    );

    const wsName = `Ws_CreatedBy_TM_${Date.now()}`;
    const res = await tmClient.post('/api/workspaces', { name: wsName });
    const wsData = res.data?.workspace || res.data;

    const [dbMember] = await tenantDb.query(
      'SELECT wm.role, wm.role_id, r.rank FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [wsData?.id, tmClient.user.id]
    );

    const passed = res.status === 201 &&
      wsData?.role === 'Team Member' &&
      dbMember?.role === 'Team Member' &&
      Number(dbMember?.rank) === 40 &&
      dbMember?.role !== 'Project Manager' &&
      dbMember?.role !== 'Owner';

    record(
      'WCR-1.5',
      'Team Member with workspace.create MUST receive Team Member (rank 40, NOT Project Manager!)',
      passed,
      {
        expected: 'HTTP 201, role=Team Member, rank=40, role!=Project Manager, role!=Owner',
        actual: `HTTP ${res.status}, role=${wsData?.role}, dbRole=${dbMember?.role}, rank=${dbMember?.rank}`
      },
      wsData
    );
  } catch (err) {
    record('WCR-1.5', 'Team Member workspace creation', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 6: Viewer with workspace.create -> receives Viewer (rank 20, NOT PM!)
  // --------------------------------------------------------------------------
  try {
    const viewerClient = users['Viewer'].client;
    const viewerRoleId = sysRoleMap['Viewer']?.id;

    await tenantDb.execute(
      'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
      [viewerRoleId, wsCreatePermId]
    );

    const wsName = `Ws_CreatedBy_Viewer_${Date.now()}`;
    const res = await viewerClient.post('/api/workspaces', { name: wsName });
    const wsData = res.data?.workspace || res.data;

    const [dbMember] = await tenantDb.query(
      'SELECT wm.role, wm.role_id, r.rank FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [wsData?.id, viewerClient.user.id]
    );

    const passed = res.status === 201 &&
      wsData?.role === 'Viewer' &&
      dbMember?.role === 'Viewer' &&
      Number(dbMember?.rank) === 20 &&
      dbMember?.role !== 'Project Manager' &&
      dbMember?.role !== 'Owner';

    record(
      'WCR-1.6',
      'Viewer with workspace.create MUST receive Viewer (rank 20, NOT Project Manager!)',
      passed,
      {
        expected: 'HTTP 201, role=Viewer, rank=20, role!=Project Manager, role!=Owner',
        actual: `HTTP ${res.status}, role=${wsData?.role}, dbRole=${dbMember?.role}, rank=${dbMember?.rank}`
      },
      wsData
    );
  } catch (err) {
    record('WCR-1.6', 'Viewer workspace creation', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 7: Auditor with workspace.create -> receives Auditor (rank 15, NOT PM, NOT Owner)
  // --------------------------------------------------------------------------
  try {
    const auditorClient = users['Auditor'].client;
    const auditorRoleId = sysRoleMap['Auditor']?.id;

    await tenantDb.execute(
      'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
      [auditorRoleId, wsCreatePermId]
    );

    const wsName = `Ws_CreatedBy_Auditor_${Date.now()}`;
    const res = await auditorClient.post('/api/workspaces', { name: wsName });
    const wsData = res.data?.workspace || res.data;

    const [dbMember] = await tenantDb.query(
      'SELECT wm.role, wm.role_id, r.rank FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [wsData?.id, auditorClient.user.id]
    );

    const passed = res.status === 201 &&
      wsData?.role === 'Auditor' &&
      dbMember?.role === 'Auditor' &&
      Number(dbMember?.rank) === 15 &&
      dbMember?.role !== 'Project Manager' &&
      dbMember?.role !== 'Owner';

    record(
      'WCR-1.7',
      'Auditor receives Auditor (rank 15, NOT PM, NOT Owner) when authorized',
      passed,
      {
        expected: 'HTTP 201, role=Auditor, rank=15, role!=PM, role!=Owner',
        actual: `HTTP ${res.status}, role=${wsData?.role}, dbRole=${dbMember?.role}, rank=${dbMember?.rank}`
      },
      wsData
    );
  } catch (err) {
    record('WCR-1.7', 'Auditor workspace creation', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 8: Guest with workspace.create -> receives Guest (rank 10, NOT PM, NOT Owner)
  // --------------------------------------------------------------------------
  try {
    const guestClient = users['Guest'].client;
    const guestRoleId = sysRoleMap['Guest']?.id;

    await tenantDb.execute(
      'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
      [guestRoleId, wsCreatePermId]
    );

    const wsName = `Ws_CreatedBy_Guest_${Date.now()}`;
    const res = await guestClient.post('/api/workspaces', { name: wsName });
    const wsData = res.data?.workspace || res.data;

    const [dbMember] = await tenantDb.query(
      'SELECT wm.role, wm.role_id, r.rank FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [wsData?.id, guestClient.user.id]
    );

    const passed = res.status === 201 &&
      wsData?.role === 'Guest' &&
      dbMember?.role === 'Guest' &&
      Number(dbMember?.rank) === 10 &&
      dbMember?.role !== 'Project Manager' &&
      dbMember?.role !== 'Owner';

    record(
      'WCR-1.8',
      'Guest receives Guest (rank 10, NOT PM, NOT Owner) when authorized',
      passed,
      {
        expected: 'HTTP 201, role=Guest, rank=10, role!=PM, role!=Owner',
        actual: `HTTP ${res.status}, role=${wsData?.role}, dbRole=${dbMember?.role}, rank=${dbMember?.rank}`
      },
      wsData
    );
  } catch (err) {
    record('WCR-1.8', 'Guest workspace creation', false, { expected: 'HTTP 201', actual: err.message });
  }

  // ==========================================================================
  // CUSTOM ROLE TEST CASES (PREVENTING PERMISSION ESCALATION)
  // ==========================================================================

  // --------------------------------------------------------------------------
  // TEST 9: Custom role with workspace.create and NO task permissions
  // --------------------------------------------------------------------------
  try {
    // Create custom role in W1 with rank 45 and ZERO task permissions
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 45, ?)',
      [`CustomNoTasks_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    // Grant workspace.create and workspace.view, member.view (NO task permissions)
    const pKeys = ['workspace.create', 'workspace.view', 'member.view'];
    const pRows = await tenantDb.query(
      `SELECT id FROM permissions WHERE \`key\` IN ('workspace.create', 'workspace.view', 'member.view')`
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `notasks_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "No Tasks User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomNoTasks", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'No Tasks User');
    const wsName = `Ws_NoTasks_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    // Query effective permissions in new workspace
    const effPerms = await getUserPermissions(uId, newWs.id, tenantDb);
    const permsArray = Array.from(effPerms.permissions || []);

    const hasAnyTaskPerm = permsArray.some((k) => k.startsWith('task.'));
    const [destRoleRow] = await tenantDb.query('SELECT * FROM roles WHERE id = ?', [newWs.role_id]);

    const passed = res.status === 201 &&
      destRoleRow.workspace_id === newWs.id &&
      !destRoleRow.is_system &&
      !hasAnyTaskPerm &&
      permsArray.includes('workspace.view');

    record(
      'WCR-2.1',
      'Custom role with workspace.create and NO task permissions receives destination role with zero task permissions (NOT Team Member)',
      passed,
      {
        expected: 'HTTP 201, hasAnyTaskPerm=false, is_system=0, role_workspace_id=newWs.id',
        actual: `HTTP ${res.status}, hasAnyTaskPerm=${hasAnyTaskPerm}, is_system=${destRoleRow?.is_system}, permsCount=${permsArray.length}`
      },
      { perms: permsArray }
    );
  } catch (err) {
    record('WCR-2.1', 'Custom role no task permissions test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 10: Custom role with workspace.create and restricted subset of collaboration permissions
  // --------------------------------------------------------------------------
  try {
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 45, ?)',
      [`CustomCollab_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    // Permissions: workspace.create, workspace.view, project.view, task.view, comment.view, comment.create
    const allowedKeys = ['workspace.create', 'workspace.view', 'project.view', 'task.view', 'comment.view', 'comment.create'];
    const pRows = await tenantDb.query(
      `SELECT id, \`key\` FROM permissions WHERE \`key\` IN (${allowedKeys.map(() => '?').join(',')})`,
      allowedKeys
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `collab_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "Collab User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomCollab", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'Collab User');
    const wsName = `Ws_Collab_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    const effPerms = await getUserPermissions(uId, newWs.id, tenantDb);
    const permsSet = new Set(effPerms.permissions || []);

    // Must have collaboration permissions
    const hasCollab = permsSet.has('comment.create') && permsSet.has('task.view');
    // Must NOT have mutation permissions that were never granted
    const hasUnwantedMutations = permsSet.has('task.create') || permsSet.has('task.edit') || permsSet.has('list.create') || permsSet.has('project.create');

    const passed = res.status === 201 && hasCollab && !hasUnwantedMutations;

    record(
      'WCR-2.2',
      'Custom role with restricted collaboration permissions transfers ONLY those permissions without task/list/project creation grants',
      passed,
      {
        expected: 'HTTP 201, hasCollab=true, hasUnwantedMutations=false',
        actual: `HTTP ${res.status}, hasCollab=${hasCollab}, hasUnwantedMutations=${hasUnwantedMutations}`
      },
      Array.from(permsSet)
    );
  } catch (err) {
    record('WCR-2.2', 'Custom role restricted collaboration permissions test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 11: Custom role with higher numerical rank (rank 75) but fewer permissions than Team Member
  // --------------------------------------------------------------------------
  try {
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 75, ?)',
      [`CustomRank75_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    // Grant ONLY workspace.create, workspace.view, project.view, task.view
    const allowedKeys = ['workspace.create', 'workspace.view', 'project.view', 'task.view'];
    const pRows = await tenantDb.query(
      `SELECT id FROM permissions WHERE \`key\` IN (${allowedKeys.map(() => '?').join(',')})`,
      allowedKeys
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `rank75_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "Rank 75 User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomRank75", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'Rank 75 User');
    const wsName = `Ws_Rank75_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    const [destRole] = await tenantDb.query('SELECT * FROM roles WHERE id = ?', [newWs.role_id]);
    const effPerms = await getUserPermissions(uId, newWs.id, tenantDb);
    const permsSet = new Set(effPerms.permissions || []);

    // Rank is 75 (delegation constraint), but permissions are strictly restricted (no task.create, task.edit, comment.create)
    const hasTaskEdit = permsSet.has('task.edit') || permsSet.has('task.create') || permsSet.has('comment.create');
    const passed = res.status === 201 &&
      Number(destRole.rank) === 75 &&
      !hasTaskEdit &&
      permsSet.has('task.view');

    record(
      'WCR-2.3',
      'Custom role with high rank (75) but minimal permissions retains rank 75 WITHOUT gaining Team Member or PM permissions',
      passed,
      {
        expected: 'HTTP 201, destRank=75, hasTaskEdit=false',
        actual: `HTTP ${res.status}, destRank=${destRole?.rank}, hasTaskEdit=${hasTaskEdit}, permsCount=${permsSet.size}`
      },
      Array.from(permsSet)
    );
  } catch (err) {
    record('WCR-2.3', 'High rank fewer permissions test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 12: Custom role with permissions scoped to a different workspace
  // --------------------------------------------------------------------------
  try {
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 45, ?)',
      [`CustomScopedW1_${Date.now()}`, w1Id]
    );
    const sourceRoleId = crRes.insertId;

    const pRows = await tenantDb.query(
      `SELECT id FROM permissions WHERE \`key\` IN ('workspace.create', 'workspace.view', 'project.view')`
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [sourceRoleId, pr.id]);
    }

    const email = `scopedw1_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "Scoped W1 User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomScopedW1", ?)',
      [w1Id, uId, sourceRoleId]
    );

    const client = createTestClient(uId, email, 'Scoped W1 User');
    const wsName = `Ws_NewScope_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    const [destRole] = await tenantDb.query('SELECT * FROM roles WHERE id = ?', [newWs.role_id]);
    const [w1Member] = await tenantDb.query('SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?', [w1Id, uId]);

    // Destination role must be a new role belonging to newWs.id, NOT sourceRoleId from W1
    const passed = res.status === 201 &&
      destRole.id !== sourceRoleId &&
      destRole.workspace_id === newWs.id &&
      w1Member.role_id === sourceRoleId;

    record(
      'WCR-2.4',
      'Custom role ID from source workspace is NEVER reused; destination workspace receives freshly scoped role',
      passed,
      {
        expected: 'HTTP 201, destRole.id != sourceRoleId, destRole.workspace_id == newWs.id',
        actual: `HTTP ${res.status}, destRoleId=${destRole?.id}, sourceRoleId=${sourceRoleId}, destWsId=${destRole?.workspace_id}`
      },
      destRole
    );
  } catch (err) {
    record('WCR-2.4', 'Cross-workspace role scoping test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 13: Custom role containing dangerous or company-wide permissions
  // --------------------------------------------------------------------------
  try {
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 65, ?)',
      [`CustomDangerous_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    // Grant dangerous/company permissions along with workspace.create & workspace.view
    const mixKeys = [
      'workspace.create',
      'workspace.view',
      'company.manage_security',
      'member.deactivate',
      'member.reset_password',
      'role.edit',
      'workspace.delete'
    ];
    const pRows = await tenantDb.query(
      `SELECT id FROM permissions WHERE \`key\` IN (${mixKeys.map(() => '?').join(',')})`,
      mixKeys
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `dangerous_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "Dangerous User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomDangerous", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'Dangerous User');
    const wsName = `Ws_StrippedDangerous_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    const effPerms = await getUserPermissions(uId, newWs.id, tenantDb);
    const permsSet = new Set(effPerms.permissions || []);

    // Dangerous and company permissions must NOT have been transferred
    const hasCompanySecurity = permsSet.has('company.manage_security');
    const hasMemberDeactivate = permsSet.has('member.deactivate');
    const hasRoleEdit = permsSet.has('role.edit');
    const hasWorkspaceDelete = permsSet.has('workspace.delete');

    const passed = res.status === 201 &&
      !hasCompanySecurity &&
      !hasMemberDeactivate &&
      !hasRoleEdit &&
      !hasWorkspaceDelete &&
      permsSet.has('workspace.view');

    record(
      'WCR-2.5',
      'Dangerous and company-wide permissions are stripped and NEVER transferred to the newly created workspace',
      passed,
      {
        expected: 'HTTP 201, zero dangerous/company keys transferred, workspace.view preserved',
        actual: `HTTP ${res.status}, hasCompanySecurity=${hasCompanySecurity}, hasRoleEdit=${hasRoleEdit}, hasWsDelete=${hasWorkspaceDelete}`
      },
      Array.from(permsSet)
    );
  } catch (err) {
    record('WCR-2.5', 'Dangerous and company-wide permission stripping test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 14: Custom role whose permissions cannot be represented safely (broken prerequisites)
  // --------------------------------------------------------------------------
  try {
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 45, ?)',
      [`CustomBrokenPrereqs_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    // Grant workspace.create and task.edit WITHOUT granting task.view or project.view
    const brokenKeys = ['workspace.create', 'workspace.view', 'task.edit'];
    const pRows = await tenantDb.query(
      `SELECT id FROM permissions WHERE \`key\` IN ('workspace.create', 'workspace.view', 'task.edit')`
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `broken_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "Broken User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomBrokenPrereqs", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'Broken User');
    const wsName = `Ws_ShouldFailPrereq_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });

    const passed = res.status === 403 && res.data?.error?.code === 'UNSAFE_CUSTOM_ROLE_MAPPING';

    record(
      'WCR-2.6',
      'Custom role with broken prerequisites (task.edit without task.view/project.view) fails closed with 403 UNSAFE_CUSTOM_ROLE_MAPPING',
      passed,
      {
        expected: 'HTTP 403 Forbidden with UNSAFE_CUSTOM_ROLE_MAPPING',
        actual: `HTTP ${res.status} (${res.data?.error?.code || 'Allowed'})`
      },
      res.data
    );
  } catch (err) {
    record('WCR-2.6', 'Broken prerequisites fail closed test', false, { expected: 'HTTP 403', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 15: Custom role with rank below Guest (rank 5 < 10)
  // --------------------------------------------------------------------------
  try {
    const lowRoleRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 5, ?)',
      [`LowRank5_${Date.now()}`, w1Id]
    );
    const lowRoleId = lowRoleRes.insertId;

    await tenantDb.execute(
      'INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
      [lowRoleId, wsCreatePermId]
    );

    const lowUserEmail = `lowrank5_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "placeholder_hash", "Low Rank User")',
      [lowUserEmail]
    );
    const lowUserId = uRes.insertId;

    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "LowRank5", ?)',
      [w1Id, lowUserId, lowRoleId]
    );

    const lowClient = createTestClient(lowUserId, lowUserEmail, 'Low Rank User');
    const res = await lowClient.post('/api/workspaces', { name: `Ws_LowRank_${Date.now()}` });
    const passed = res.status === 403 && res.data?.error?.code === 'NO_VALID_WORKSPACE_CREATOR_ROLE';

    record(
      'WCR-2.7',
      'Unmappable low-rank role (rank 5 < 10) fails closed with 403 NO_VALID_WORKSPACE_CREATOR_ROLE',
      passed,
      {
        expected: 'HTTP 403 Forbidden with NO_VALID_WORKSPACE_CREATOR_ROLE',
        actual: `HTTP ${res.status} (${res.data?.error?.code || 'Allowed'})`
      },
      res.data
    );
  } catch (err) {
    record('WCR-2.7', 'Unmappable role fail closed test', false, { expected: 'HTTP 403', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 16: User with multiple memberships and mixture of built-in and custom roles
  // --------------------------------------------------------------------------
  try {
    const multiUserEmail = `multimix_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "placeholder_hash", "Multi Mix User")',
      [multiUserEmail]
    );
    const multiUserId = uRes.insertId;

    // 1. Guest in W1 (rank 10, NO workspace.create)
    const guestRoleId = sysRoleMap['Guest']?.id;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "Guest", ?)',
      [w1Id, multiUserId, guestRoleId]
    );

    // 2. Custom restricted role in W2 (rank 45, WITH workspace.create and comment.view ONLY)
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 45, ?)',
      [`CustomMixW2_${Date.now()}`, w2Id]
    );
    const crW2Id = crRes.insertId;
    const pRows = await tenantDb.query(
      `SELECT id FROM permissions WHERE \`key\` IN ('workspace.create', 'workspace.view', 'project.view', 'task.view', 'comment.view')`
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crW2Id, pr.id]);
    }
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomMixW2", ?)',
      [w2Id, multiUserId, crW2Id]
    );

    // 3. Admin in a third workspace W3 (rank 80, WITH workspace.create)
    const w3Res = await tenantDb.execute('INSERT INTO workspaces (name) VALUES (?)', [`W3_Admin_${Date.now()}`]);
    const w3Id = w3Res.insertId;
    const adminRoleId = sysRoleMap['Admin']?.id;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "Admin", ?)',
      [w3Id, multiUserId, adminRoleId]
    );

    const client = createTestClient(multiUserId, multiUserEmail, 'Multi Mix User');
    const wsName = `Ws_MultiMix_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    // Authorizing memberships are W2 (rank 45) and W3 (rank 80).
    // Least privilege resolves to W2 (rank 45, CustomMixW2).
    // The creator receives destination role with W2's permissions, NOT Admin permissions!
    const effPerms = await getUserPermissions(multiUserId, newWs.id, tenantDb);
    const permsSet = new Set(effPerms.permissions || []);

    const hasAdminPowers = permsSet.has('member.invite') || permsSet.has('role.view') || permsSet.has('workspace.edit');
    const hasW2Perms = permsSet.has('comment.view') && permsSet.has('task.view');

    // Existing memberships in W1, W2, W3 must be unchanged
    const [w1Check] = await tenantDb.query('SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?', [w1Id, multiUserId]);
    const [w2Check] = await tenantDb.query('SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?', [w2Id, multiUserId]);
    const [w3Check] = await tenantDb.query('SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?', [w3Id, multiUserId]);

    const passed = res.status === 201 &&
      hasW2Perms &&
      !hasAdminPowers &&
      w1Check?.role_id === guestRoleId &&
      w2Check?.role_id === crW2Id &&
      w3Check?.role_id === adminRoleId;

    record(
      'WCR-2.8',
      'User with mixture of built-in and custom roles across workspaces resolves via least privilege without leaking higher role powers',
      passed,
      {
        expected: 'HTTP 201, hasW2Perms=true, hasAdminPowers=false, memberships unchanged',
        actual: `HTTP ${res.status}, hasW2Perms=${hasW2Perms}, hasAdminPowers=${hasAdminPowers}`
      },
      Array.from(permsSet)
    );
  } catch (err) {
    record('WCR-2.8', 'Mixed memberships least privilege test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST 17: Catalog synchronization and persistence verification
  // --------------------------------------------------------------------------
  try {
    // Run full catalog synchronization on fixture tenant database
    await syncSingleTenant(tenantDb, slug, { isApply: true, force: true, silent: true });

    // Verify company_owners contains only the verified Company Owner
    const companyOwners = await tenantDb.query('SELECT user_id FROM company_owners');
    const ownerIds = companyOwners.map((o) => Number(o.user_id));
    const onlyAuthoritativeOwner = ownerIds.length === 1 && ownerIds[0] === Number(users['Owner'].user.id);

    // Verify no non-owner user has role='Owner' in any workspace
    const rogueOwners = await tenantDb.query(
      'SELECT wm.workspace_id, wm.user_id, wm.role FROM workspace_members wm WHERE wm.role = "Owner" AND wm.user_id != ?',
      [users['Owner'].user.id]
    );

    const passed = onlyAuthoritativeOwner && rogueOwners.length === 0;

    record(
      'WCR-2.9',
      'Catalog synchronization preserves authoritative ownership and zero rogue Owners exist across all workspaces',
      passed,
      {
        expected: 'onlyAuthoritativeOwner=true, rogueOwners=0',
        actual: `onlyAuthoritativeOwner=${onlyAuthoritativeOwner}, rogueOwnersCount=${rogueOwners.length}`
      },
      { ownerIds, rogueOwners }
    );
  } catch (err) {
    record('WCR-2.9', 'Catalog sync persistence test', false, { expected: 'Zero rogue owners', actual: err.message });
  }

  // ==========================================================================
  // ADVERSARIAL REGRESSION TESTS: CUSTOM PERMISSION SCOPE & RANK ENFORCEMENT
  // ==========================================================================

  // --------------------------------------------------------------------------
  // TEST WCR-3.1: Custom role with workspace.create and member.view
  // --------------------------------------------------------------------------
  try {
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 45, ?)',
      [`CustomMemberView_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    const pRows = await tenantDb.query(
      `SELECT id FROM permissions WHERE \`key\` IN ('workspace.create', 'workspace.view', 'member.view')`
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `memview_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "Member View User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomMemberView", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'Member View User');
    const wsName = `Ws_MemView_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    const effPerms = await getUserPermissions(uId, newWs.id, tenantDb);
    const permsSet = new Set(effPerms.permissions || []);

    // member.view must be stripped (not transferable to custom role)
    const hasMemberView = permsSet.has('member.view');
    const hasWsView = permsSet.has('workspace.view');

    // Real API verification: attempt to access global member directory
    const globalMembersRes = await client.get(`/api/workspaces/${newWs.id}/company-members`);

    const passed = res.status === 201 &&
      hasWsView &&
      !hasMemberView &&
      globalMembersRes.status === 403;

    record(
      'WCR-3.1',
      'Custom role with workspace.create and member.view strips member.view and blocks global member directory access (403)',
      passed,
      {
        expected: 'HTTP 201, hasMemberView=false, globalMembers=403',
        actual: `HTTP ${res.status}, hasMemberView=${hasMemberView}, globalMembers=${globalMembersRes.status}`
      },
      Array.from(permsSet)
    );
  } catch (err) {
    record('WCR-3.1', 'Custom role member.view test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST WCR-3.2: Custom role with workspace.create and member.invite
  // --------------------------------------------------------------------------
  try {
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 45, ?)',
      [`CustomMemberInvite_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    const pRows = await tenantDb.query(
      `SELECT id FROM permissions WHERE \`key\` IN ('workspace.create', 'workspace.view', 'member.view', 'member.invite')`
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `meminvite_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "Member Invite User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomMemberInvite", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'Member Invite User');
    const wsName = `Ws_MemInvite_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    const effPerms = await getUserPermissions(uId, newWs.id, tenantDb);
    const permsSet = new Set(effPerms.permissions || []);

    const hasMemberInvite = permsSet.has('member.invite');

    // Real API verification: attempt to send invitation in new workspace
    const inviteRes = await client.post(`/api/workspaces/${newWs.id}/invitations`, {
      email: `unauth_invitee_${Date.now()}@permtest.local`,
      role: 'Team Member'
    });

    const passed = res.status === 201 &&
      !hasMemberInvite &&
      inviteRes.status === 403;

    record(
      'WCR-3.2',
      'Custom role with workspace.create and member.invite strips member.invite and rejects invitation attempts (403)',
      passed,
      {
        expected: 'HTTP 201, hasMemberInvite=false, inviteRes=403',
        actual: `HTTP ${res.status}, hasMemberInvite=${hasMemberInvite}, inviteRes=${inviteRes.status}`
      },
      Array.from(permsSet)
    );
  } catch (err) {
    record('WCR-3.2', 'Custom role member.invite test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST WCR-3.3: Custom role with role.view or attempted role-administration capabilities
  // --------------------------------------------------------------------------
  try {
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 50, ?)',
      [`CustomRoleAdmin_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    const pRows = await tenantDb.query(
      `SELECT id FROM permissions WHERE \`key\` IN ('workspace.create', 'workspace.view', 'role.view', 'role.create', 'role.edit', 'role.delete')`
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `roleadmin_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "Role Admin User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomRoleAdmin", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'Role Admin User');
    const wsName = `Ws_RoleAdmin_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    const effPerms = await getUserPermissions(uId, newWs.id, tenantDb);
    const permsSet = new Set(effPerms.permissions || []);

    const hasAnyRolePerm = Array.from(permsSet).some((k) => k.startsWith('role.'));

    // Real API verification: attempt to create custom role and edit role
    const createRoleRes = await client.post(`/api/workspaces/${newWs.id}/roles`, {
      name: 'RogueCustomRole',
      rank: 30,
      permission_keys: ['task.view']
    });
    const editRoleRes = await client.patch(`/api/roles/${crId}`, {
      name: 'HackedCustomRole'
    });

    const passed = res.status === 201 &&
      !hasAnyRolePerm &&
      createRoleRes.status === 403 &&
      editRoleRes.status === 403;

    record(
      'WCR-3.3',
      'Custom role with role administration perms strips all role.* grants and rejects role creation/modification (403)',
      passed,
      {
        expected: 'HTTP 201, hasAnyRolePerm=false, createRole=403, editRole=403',
        actual: `HTTP ${res.status}, hasAnyRolePerm=${hasAnyRolePerm}, createRole=${createRoleRes.status}, editRole=${editRoleRes.status}`
      },
      Array.from(permsSet)
    );
  } catch (err) {
    record('WCR-3.3', 'Custom role role-administration test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST WCR-3.4: Custom role containing project.create and other broad-scope permissions
  // --------------------------------------------------------------------------
  try {
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 45, ?)',
      [`CustomProjectCreate_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    const pRows = await tenantDb.query(
      `SELECT id FROM permissions WHERE \`key\` IN ('workspace.create', 'workspace.view', 'project.create', 'workspace.edit', 'workspace.delete', 'project.access_all')`
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `projcreate_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "Project Create User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomProjectCreate", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'Project Create User');
    const wsName = `Ws_ProjCreate_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    const effPerms = await getUserPermissions(uId, newWs.id, tenantDb);
    const permsSet = new Set(effPerms.permissions || []);

    const hasProjectCreate = permsSet.has('project.create');
    const hasWorkspaceEdit = permsSet.has('workspace.edit');
    const hasWorkspaceDelete = permsSet.has('workspace.delete');
    const hasAccessAll = permsSet.has('project.access_all');

    // Real API: Creator can create project inside authorized scope (newWs)
    const createAuthorizedRes = await client.post('/api/boards', {
      workspace_id: newWs.id,
      name: 'Authorized Board'
    });

    // Real API: Creator cannot create project in unauthorized scope (W2 where they have no membership)
    const createUnauthorizedRes = await client.post('/api/boards', {
      workspace_id: context.w2Id,
      name: 'Unauthorized Board in W2'
    });

    // Real API: Creator cannot delete workspace
    const deleteWsRes = await client.delete(`/api/workspaces/${newWs.id}`);

    const passed = res.status === 201 &&
      hasProjectCreate &&
      !hasWorkspaceEdit &&
      !hasWorkspaceDelete &&
      !hasAccessAll &&
      createAuthorizedRes.status === 201 &&
      [403, 404].includes(createUnauthorizedRes.status) &&
      deleteWsRes.status === 403;

    record(
      'WCR-3.4',
      'Custom role with project.create transfers board creation in authorized scope only; strips broad administrative grants (delete/edit/access_all)',
      passed,
      {
        expected: 'HTTP 201, hasProjCreate=true, broadStripped=true, authBoard=201, unauthBoard=403/404, deleteWs=403',
        actual: `HTTP ${res.status}, hasProjCreate=${hasProjectCreate}, wsEdit=${hasWorkspaceEdit}, wsDel=${hasWorkspaceDelete}, accAll=${hasAccessAll}, authBoard=${createAuthorizedRes.status}, unauthBoard=${createUnauthorizedRes.status}, deleteWs=${deleteWsRes.status}`
      },
      Array.from(permsSet)
    );
  } catch (err) {
    record('WCR-3.4', 'Custom role project.create broad-scope test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST WCR-3.5: Custom role containing every available company-scoped permission not marked dangerous
  // --------------------------------------------------------------------------
  try {
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 60, ?)',
      [`CustomAllCompanyNonDangerous_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    // Fetch all permissions with scope='company' and dangerous=0 and planned=0, plus prerequisite project.view
    const companyPermRows = await tenantDb.query(
      `SELECT id, \`key\` FROM permissions WHERE (scope = 'company' AND dangerous = 0 AND planned = 0) OR \`key\` = 'project.view'`
    );
    for (const pr of companyPermRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `allcomp_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "All Company Non-Dangerous User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomAllCompanyNonDangerous", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'All Company Non-Dangerous User');
    const wsName = `Ws_AllComp_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    const effPerms = await getUserPermissions(uId, newWs.id, tenantDb);
    const permsSet = new Set(effPerms.permissions || []);

    // Administrative permissions MUST NOT transfer even if scope='company' and dangerous=false
    const hasMemberView = permsSet.has('member.view');
    const hasMemberInvite = permsSet.has('member.invite');
    const hasRoleView = permsSet.has('role.view');
    const hasWsEdit = permsSet.has('workspace.edit');
    const hasWsArchive = permsSet.has('workspace.archive');
    const hasDailyTrackerPeople = permsSet.has('daily_tracker.view_people');
    const hasLeaveApprove = permsSet.has('leave.approve');

    // Safe collaboration & self permissions SHOULD transfer
    const hasWsView = permsSet.has('workspace.view');
    const hasProjCreate = permsSet.has('project.create');
    const hasActivityView = permsSet.has('activity.view');
    const hasSearch = permsSet.has('search.use');

    // Real API checks:
    const editWsRes = await client.patch(`/api/workspaces/${newWs.id}`, { name: 'RenamedWorkspace' });
    const inviteRes = await client.post(`/api/workspaces/${newWs.id}/invitations`, { email: 'i@permtest.local' });
    const globalMembersRes = await client.get(`/api/workspaces/${newWs.id}/company-members`);

    const passed = res.status === 201 &&
      hasWsView &&
      hasProjCreate &&
      hasActivityView &&
      hasSearch &&
      !hasMemberView &&
      !hasMemberInvite &&
      !hasRoleView &&
      !hasWsEdit &&
      !hasWsArchive &&
      !hasDailyTrackerPeople &&
      !hasLeaveApprove &&
      editWsRes.status === 403 &&
      inviteRes.status === 403 &&
      globalMembersRes.status === 403;

    record(
      'WCR-3.5',
      'Custom role with all non-dangerous company-scoped perms filters administrative grants and preserves only safe collaboration perms',
      passed,
      {
        expected: 'HTTP 201, safePerms=true, adminPerms=false, editWs=403, invite=403, companyMembers=403',
        actual: `HTTP ${res.status}, hasWsView=${hasWsView}, hasMemberView=${hasMemberView}, hasRoleView=${hasRoleView}, hasWsEdit=${hasWsEdit}, editWs=${editWsRes.status}, invite=${inviteRes.status}, companyMembers=${globalMembersRes.status}`
      },
      Array.from(permsSet)
    );
  } catch (err) {
    record('WCR-3.5', 'Custom role all company non-dangerous test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST WCR-3.6: Custom role attempting to transfer cross-workspace authority
  // --------------------------------------------------------------------------
  try {
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 45, ?)',
      [`CustomCrossAuth_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    const pRows = await tenantDb.query(
      `SELECT id FROM permissions WHERE \`key\` IN ('workspace.create', 'workspace.view', 'project.view', 'list.create', 'task.view', 'task.edit')`
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `crossauth_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "Cross Auth User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomCrossAuth", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'Cross Auth User');
    const wsName = `Ws_CrossAuth_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    // Real API: Attempt to access or mutate Board C in Workspace 2 (context.boardCId)
    const boardCId = context.boardCId;
    const accessCrossBoardRes = await client.get(`/api/boards/${boardCId}`);
    const mutateCrossListRes = await client.post('/api/lists', {
      board_id: boardCId,
      name: 'RogueCrossList'
    });

    const passed = res.status === 201 &&
      (accessCrossBoardRes.status === 403 || accessCrossBoardRes.status === 404) &&
      (mutateCrossListRes.status === 403 || mutateCrossListRes.status === 404);

    record(
      'WCR-3.6',
      'Custom role creating workspace cannot transfer or exercise authority across unrelated workspaces or foreign boards',
      passed,
      {
        expected: 'HTTP 201, crossBoardAccess=403/404, crossListMutation=403/404',
        actual: `HTTP ${res.status}, crossBoardAccess=${accessCrossBoardRes.status}, crossListMutation=${mutateCrossListRes.status}`
      },
      { crossBoardStatus: accessCrossBoardRes.status, crossListStatus: mutateCrossListRes.status }
    );
  } catch (err) {
    record('WCR-3.6', 'Cross workspace authority test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST WCR-3.7: Custom role with rank 80 or higher that is not a verified company Owner
  // --------------------------------------------------------------------------
  try {
    // Manually insert an anomalous custom role with rank 85 in W1
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 85, ?)',
      [`CustomHighRank_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    const pRows = await tenantDb.query(
      `SELECT id FROM permissions WHERE \`key\` IN ('workspace.create', 'workspace.view')`
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `highrank_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "High Rank User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomHighRank", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'High Rank User');
    const wsName = `Ws_HighRank_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    const [destRole] = await tenantDb.query('SELECT * FROM roles WHERE id = ?', [newWs.role_id]);
    const [dbMember] = await tenantDb.query(
      'SELECT wm.*, r.rank FROM workspace_members wm JOIN roles r ON wm.role_id = r.id WHERE wm.workspace_id = ? AND wm.user_id = ?',
      [newWs.id, uId]
    );

    // Destination rank must be strictly capped at 79 (below Admin rank 80)
    const passed = res.status === 201 &&
      Number(destRole.rank) === 79 &&
      Number(dbMember.rank) === 79 &&
      !destRole.is_system &&
      destRole.workspace_id === newWs.id;

    record(
      'WCR-3.7',
      'Custom role with rank >= 80 is strictly capped below Admin rank 80 (destRank = 79) and retains non-system workspace scope',
      passed,
      {
        expected: 'HTTP 201, destRank=79, is_system=false, workspace_id=newWs.id',
        actual: `HTTP ${res.status}, destRank=${destRole?.rank}, memberRank=${dbMember?.rank}, is_system=${destRole?.is_system}`
      },
      destRole
    );
  } catch (err) {
    record('WCR-3.7', 'Custom role rank 80+ cap test', false, { expected: 'HTTP 201', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // TEST WCR-3.8: Valid custom role containing only approved, safely transferable collaboration permissions
  // --------------------------------------------------------------------------
  try {
    const crRes = await tenantDb.execute(
      'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 0, 1, 45, ?)',
      [`CustomValidCollab_${Date.now()}`, w1Id]
    );
    const crId = crRes.insertId;

    const validCollabKeys = [
      'workspace.create',
      'workspace.view',
      'project.view',
      'project.create',
      'list.create',
      'task.view',
      'task.create',
      'task.edit',
      'comment.view',
      'comment.create',
      'attachment.view',
      'attachment.upload'
    ];
    const pRows = await tenantDb.query(
      `SELECT id, \`key\` FROM permissions WHERE \`key\` IN (${validCollabKeys.map(() => '?').join(',')})`,
      validCollabKeys
    );
    for (const pr of pRows) {
      await tenantDb.execute('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)', [crId, pr.id]);
    }

    const email = `validcollab_${Date.now()}@permtest.local`;
    const uRes = await tenantDb.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?, "hash", "Valid Collab User")',
      [email]
    );
    const uId = uRes.insertId;
    await tenantDb.execute(
      'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, "CustomValidCollab", ?)',
      [w1Id, uId, crId]
    );

    const client = createTestClient(uId, email, 'Valid Collab User');
    const wsName = `Ws_ValidCollab_${Date.now()}`;
    const res = await client.post('/api/workspaces', { name: wsName });
    const newWs = res.data?.workspace || res.data;

    const effPerms = await getUserPermissions(uId, newWs.id, tenantDb);
    const permsSet = new Set(effPerms.permissions || []);

    // Real API requests verifying all transferable capabilities work:
    // 1. Create board
    const boardRes = await client.post('/api/boards', { workspace_id: newWs.id, name: 'Collab Board' });
    const boardId = boardRes.data?.board?.id || boardRes.data?.id;

    // 2. Create list on board
    const listRes = await client.post('/api/lists', { board_id: boardId, name: 'Collab List' });
    const listId = listRes.data?.list?.id || listRes.data?.id;

    // 3. Create card on list
    const cardRes = await client.post('/api/cards', { list_id: listId, title: 'Collab Task' });
    const cardId = cardRes.data?.card?.id || cardRes.data?.id;

    // 4. Create comment on card
    const commentRes = await client.post(`/api/cards/${cardId}/comments`, { body: 'Legitimate collaboration comment' });

    // 5. Verify no administrative powers leaked
    const hasRolePerm = permsSet.has('role.view') || permsSet.has('role.edit');
    const hasMemberAdmin = permsSet.has('member.invite') || permsSet.has('member.assign_role');
    const hasWsAdmin = permsSet.has('workspace.edit') || permsSet.has('workspace.delete');

    const passed = res.status === 201 &&
      boardRes.status === 201 &&
      listRes.status === 201 &&
      cardRes.status === 201 &&
      commentRes.status === 201 &&
      !hasRolePerm &&
      !hasMemberAdmin &&
      !hasWsAdmin;

    record(
      'WCR-3.8',
      'Valid custom role with approved collaboration permissions executes full board/task/comment collaboration without administrative escalation',
      passed,
      {
        expected: 'HTTP 201 for ws, board, list, card, comment; adminPerms=false',
        actual: `ws=${res.status}, board=${boardRes.status}, list=${listRes.status}, card=${cardRes.status}, comment=${commentRes.status}, rolePerm=${hasRolePerm}, memAdmin=${hasMemberAdmin}`
      },
      Array.from(permsSet)
    );
  } catch (err) {
    record('WCR-3.8', 'Valid custom role collaboration test', false, { expected: 'HTTP 201', actual: err.message });
  }

  console.log('\n================================================================');
  const failCount = results.filter((r) => !r.passed).length;
  const passCount = results.filter((r) => r.passed).length;
  console.log(`TOTAL: ${results.length} | PASSED: ${passCount} | FAILED: ${failCount}`);
  console.log('================================================================\n');

  return {
    total: results.length,
    passed: passCount,
    failed: failCount,
    results
  };
}

module.exports = { runWorkspaceCreationRoleSuite };

if (require.main === module) {
  (async () => {
    const frontendUrl = process.env.PERMTEST_FRONTEND_URL || 'http://localhost:5173';
    const fixture = new PermtestFixture({ frontendUrl });
    try {
      await fixture.setup();
      const outcome = await runWorkspaceCreationRoleSuite(fixture);
      if (outcome.failed > 0) {
        console.error(`❌ ${outcome.failed} test(s) failed in workspace creation role suite!`);
        process.exit(1);
      } else {
        console.log('✅ ALL WORKSPACE CREATION ROLE ESCALATION TESTS PASSED!');
        process.exit(0);
      }
    } finally {
      await fixture.cleanup();
      await closeAllTenantPools();
    }
  })().catch((err) => {
    console.error('FATAL TEST ERROR:', err);
    process.exit(1);
  });
}

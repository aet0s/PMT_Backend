// server/src/scripts/permtest/regressions.js
// Regression test definitions for Section 1 issues (REG-1.1 through REG-1.11).
// Red-Green contract: Every test is designed to FAIL on the current codebase (Phase A)
// and PASS only when the corresponding fix is applied in Phase B through Phase E.

const fs = require('fs');
const path = require('path');
const { PROBES } = require('./operations');
const { PERMISSIONS, LEGACY_PERMISSION_ALIASES } = require('../../rbac/registry');

async function runRegressionTests(fixture) {
  const { users, context, tenantDb } = fixture;
  const results = [];

  function record(id, title, passed, details, evidence = null) {
    results.push({
      id,
      title,
      passed,
      details,
      evidence
    });
    const status = passed ? '✅ PASS' : '❌ FAIL (RED)';
    console.log(`[${id}] ${status}: ${title}`);
    if (!passed) {
      console.log(`    Expected: ${details.expected}`);
      console.log(`    Actual:   ${details.actual}`);
      if (evidence) {
        console.log(`    Evidence: ${JSON.stringify(evidence).slice(0, 200)}...`);
      }
    }
  }

  console.log('\n================================================================');
  console.log('       RUNNING REGRESSION SUITE (REG-1.1 to REG-1.11)           ');
  console.log('================================================================\n');

  // --------------------------------------------------------------------------
  // REG-1.1: Cross-board access via membership gate
  // --------------------------------------------------------------------------
  try {
    const memberClient = users['Team Member'].client;
    // Team member is on Board A only. Calling POST /api/lists on Board B
    const res = await memberClient.post('/api/lists', {
      board_id: context.boardBId,
      name: `Hacked_List_${Date.now()}`
    });

    // We EXPECT 403 or 404 (Access Denied). If it returned 200 or 201, cross-board security hole exists!
    const isDenied = res.status === 403 || res.status === 404;
    record(
      'REG-1.1',
      'Team Member without Board B membership MUST NOT create list on Board B (Cross-board isolation)',
      isDenied,
      {
        expected: 'HTTP 403/404 Access Denied',
        actual: `HTTP ${res.status} (${res.data?.error?.message || 'List created successfully on Board B'})`
      },
      res.data
    );
  } catch (err) {
    record('REG-1.1', 'Cross-board access test', false, { expected: 'HTTP 403/404', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.2: Viewer can read sensitive data (audit logs)
  // --------------------------------------------------------------------------
  try {
    const viewerClient = users['Viewer'].client;
    const res = await viewerClient.get(`/api/workspaces/${context.w1Id}/audit`);

    // We EXPECT 403. If 200, Viewer is over-granted sensitive audit.view!
    const isDenied = res.status === 403;
    record(
      'REG-1.2',
      'Viewer role MUST NOT have access to workspace audit logs (audit.view)',
      isDenied,
      {
        expected: 'HTTP 403 Forbidden',
        actual: `HTTP ${res.status} (${res.status === 200 ? 'Audit log leaked to Viewer' : res.data?.error?.message})`
      },
      res.data
    );
  } catch (err) {
    record('REG-1.2', 'Viewer audit access test', false, { expected: 'HTTP 403', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.3: Project Manager is over-granted (password reset / member management)
  // --------------------------------------------------------------------------
  try {
    const pmClient = users['Project Manager'].client;
    const targetUserId = users['Viewer'].user?.id;
    const res = await pmClient.post(`/api/workspaces/${context.w1Id}/members/${targetUserId}/reset-password`, {
      new_password: 'HackedPassword123!@#'
    });

    // PM should NOT have member.reset_password (must be 403)
    const isDenied = res.status === 403;
    record(
      'REG-1.3',
      'Project Manager MUST NOT have administrative permission to reset other members passwords',
      isDenied,
      {
        expected: 'HTTP 403 Forbidden',
        actual: `HTTP ${res.status} (${res.status === 200 ? 'Password reset allowed for PM' : res.data?.error?.message})`
      },
      res.data
    );
  } catch (err) {
    record('REG-1.3', 'PM password reset test', false, { expected: 'HTTP 403', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.4: Role-name branching in the engine
  // --------------------------------------------------------------------------
  try {
    // Check if permissions.js or boards.js uses hardcoded role names for authorization
    const permCode = fs.readFileSync(path.resolve(__dirname, '../../middleware/permissions.js'), 'utf8');
    const boardCode = fs.readFileSync(path.resolve(__dirname, '../../routes/boards.js'), 'utf8');

    const hasHardcodedRoleNames =
      permCode.includes("['Owner', 'Super Admin', 'Admin'].includes(roleName)") ||
      permCode.includes("roleName === 'Viewer'") ||
      boardCode.includes("['owner', 'super admin', 'admin', 'project manager', 'manager'].includes(normalizedRole)");

    record(
      'REG-1.4',
      'Authorization engine MUST NOT branch on role name strings (pure permission project.access_all required)',
      !hasHardcodedRoleNames,
      {
        expected: 'Zero role name branching in middleware/permissions.js and routes',
        actual: hasHardcodedRoleNames ? 'Found hardcoded string comparisons on Owner, Admin, Viewer, Project Manager' : 'Pure permissions used'
      }
    );
  } catch (err) {
    record('REG-1.4', 'Role name branching check', false, { expected: 'No role name branching', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.5: Wrong / inconsistent matrix for Team Member
  // --------------------------------------------------------------------------
  try {
    const memberClient = users['Team Member'].client;

    // Target matrix for Team Member:
    // - list.create -> MUST be 403 (only Team Lead and above manage lists)
    // - list.edit -> MUST be 403
    // - archive.view -> MUST be 200
    // - member.view -> MUST be 200
    const listCreateRes = await memberClient.post('/api/lists', {
      board_id: context.boardAId,
      name: `Member_List_${Date.now()}`
    });
    const listEditRes = await memberClient.patch(`/api/lists/${context.list1Id}`, {
      name: `Renamed_by_Member_${Date.now()}`
    });
    const archiveRes = await memberClient.get(`/api/archive?workspace_id=${context.w1Id}`);
    const memberRes = await memberClient.get(`/api/workspaces/${context.w1Id}/members`);

    const listCreateDenied = listCreateRes.status === 403;
    const listEditDenied = listEditRes.status === 403;
    const archiveAllowed = archiveRes.status === 200;
    const memberAllowed = memberRes.status === 200;

    const passed = listCreateDenied && listEditDenied && archiveAllowed && memberAllowed;
    record(
      'REG-1.5',
      'Team Member must have target matrix permissions: 403 on list.create/list.edit, 200 on archive.view/member.view',
      passed,
      {
        expected: 'list.create (403), list.edit (403), archive.view (200), member.view (200)',
        actual: `list.create (${listCreateRes.status}), list.edit (${listEditRes.status}), archive.view (${archiveRes.status}), member.view (${memberRes.status})`
      }
    );
  } catch (err) {
    record('REG-1.5', 'Team Member matrix consistency test', false, { expected: 'Target matrix satisfied', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.6: Planned permissions leaking into role editor catalog
  // --------------------------------------------------------------------------
  try {
    const ownerClient = users['Owner'].client;
    const permCatalogRes = await ownerClient.get('/api/permissions');
    const returnedPerms = Array.isArray(permCatalogRes.data)
      ? permCatalogRes.data
      : (permCatalogRes.data?.permissions || []);

    const returnedKeys = new Set(returnedPerms.map((p) => p.key));
    const plannedRegistryKeys = PERMISSIONS.filter((p) => p.planned).map((p) => p.key);
    const leakedPlannedKeys = plannedRegistryKeys.filter((k) => returnedKeys.has(k));

    const passed = leakedPlannedKeys.length === 0;

    record(
      'REG-1.6',
      'Catalog endpoint for role editor MUST HIDE all planned: true permissions',
      passed,
      {
        expected: '0 planned permissions exposed in /api/permissions',
        actual: `${leakedPlannedKeys.length} planned permissions exposed in /api/permissions (e.g. ${leakedPlannedKeys.slice(0, 5).join(', ')})`
      }
    );
  } catch (err) {
    record('REG-1.6', 'Planned permissions check', false, { expected: '0 planned', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.7: Duplicate / overlapping keys in registry
  // --------------------------------------------------------------------------
  try {
    const allKeys = new Set(PERMISSIONS.map((p) => p.key));
    const duplicatePairs = [
      ['role.assign', 'member.assign_role'],
      ['project.view_dashboard', 'dashboard.view_project'],
      ['company.manage_billing', 'billing.manage'],
      ['task.import', 'import_export.import'],
      ['task.export', 'import_export.export']
    ];

    const existingDuplicates = duplicatePairs.filter(([k1, k2]) => allKeys.has(k1) && allKeys.has(k2));
    const passed = existingDuplicates.length === 0;

    record(
      'REG-1.7',
      'Catalog MUST eliminate duplicate and overlapping permission keys',
      passed,
      {
        expected: '0 duplicate key pairs in registry.js',
        actual: `${existingDuplicates.length} duplicate pairs still present: ${existingDuplicates.map(([a, b]) => `${a} vs ${b}`).join(', ')}`
      }
    );
  } catch (err) {
    record('REG-1.7', 'Duplicate keys check', false, { expected: '0 duplicates', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.8: Legacy aliases layer present and client uses legacy keys
  // --------------------------------------------------------------------------
  try {
    const hasLegacyAliases = typeof LEGACY_PERMISSION_ALIASES !== 'undefined' && Object.keys(LEGACY_PERMISSION_ALIASES).length > 0;

    record(
      'REG-1.8',
      'Legacy aliases (LEGACY_PERMISSION_ALIASES) must be eliminated after client migration',
      !hasLegacyAliases,
      {
        expected: 'LEGACY_PERMISSION_ALIASES deleted from registry.js',
        actual: hasLegacyAliases ? `${Object.keys(LEGACY_PERMISSION_ALIASES).length} legacy aliases still active in server` : 'Clean'
      }
    );
  } catch (err) {
    record('REG-1.8', 'Legacy aliases check', false, { expected: 'Aliases eliminated', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.9: No "own vs any" rules for tasks (cards.created_by missing)
  // --------------------------------------------------------------------------
  try {
    const colRows = await tenantDb.query(
      `SELECT COLUMN_NAME FROM information_schema.COLUMNS 
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'cards' AND COLUMN_NAME = 'created_by'`,
      [context.tenantDbName]
    );

    const hasCreatedBy = colRows.length > 0;
    record(
      'REG-1.9',
      'Table "cards" must have created_by column to enforce task.delete_own vs task.delete',
      hasCreatedBy,
      {
        expected: 'cards.created_by BIGINT UNSIGNED NULL exists',
        actual: hasCreatedBy ? 'Column exists' : 'Column created_by MISSING from cards table'
      }
    );
  } catch (err) {
    record('REG-1.9', 'Cards created_by column check', false, { expected: 'Column exists', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.10: Several routes use only requireAuth and decide inline without requirePermission
  // --------------------------------------------------------------------------
  try {
    const cardsRouteCode = fs.readFileSync(path.resolve(__dirname, '../../routes/cards.js'), 'utf8');
    const boardsRouteCode = fs.readFileSync(path.resolve(__dirname, '../../routes/boards.js'), 'utf8');

    const boardsPatchHasMiddleware = /router\.patch\('\/:id',\s*requireAuth,\s*requirePermission/.test(boardsRouteCode);
    const cardsPatchHasMiddleware = /router\.patch\('\/:id',\s*requireAuth,\s*requirePermission/.test(cardsRouteCode);

    const passed = boardsPatchHasMiddleware && cardsPatchHasMiddleware;
    record(
      'REG-1.10',
      'Critical mutation routes (PATCH /api/boards/:id, PATCH /api/cards/:id) must use declarative permission middleware',
      passed,
      {
        expected: 'Declarative requirePermission middleware on PATCH /api/boards/:id and PATCH /api/cards/:id',
        actual: `boards.js: ${boardsPatchHasMiddleware ? 'Protected' : 'Missing declarative middleware'}, cards.js: ${cardsPatchHasMiddleware ? 'Protected' : 'Missing declarative middleware'}`
      }
    );
  } catch (err) {
    record('REG-1.10', 'Declarative route middleware check', false, { expected: 'Protected', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.11: Board membership auto-grants project.view, task.view, view.view
  // --------------------------------------------------------------------------
  try {
    const permCode = fs.readFileSync(path.resolve(__dirname, '../../middleware/permissions.js'), 'utf8');

    const hasImplicitViewGrants =
      permCode.includes("['project.view', 'task.view', 'view.view'].some") &&
      permCode.includes("permsSet.add('project.view')");

    record(
      'REG-1.11',
      'Direct board membership MUST NOT auto-grant permissions (Deny by default rule)',
      !hasImplicitViewGrants,
      {
        expected: 'No auto-granting of project.view, task.view, view.view solely on board membership',
        actual: hasImplicitViewGrants ? 'userHasPermission & getUserPermissions auto-grant view permissions to all board members' : 'Clean (roles only)'
      }
    );
  } catch (err) {
    record('REG-1.11', 'Implicit grants check', false, { expected: 'Deny by default', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.12: Client-supplied workspace_id in query/body skips board gate
  // --------------------------------------------------------------------------
  // REG-1.12: Board-membership bypass prevention via workspace_id query/body
  // Table-driven grid: 7 real resource routes x (params, query workspace_id, body workspace_id)
  // Every cell includes a POSITIVE CONTROL executed by an authorized user returning 2xx.
  // --------------------------------------------------------------------------
  try {
    const memberClient = users['Team Member'].client;
    const ownerClient = users['Owner'].client;

    const r12Grid = [];
    let allR12Passed = true;

    // 1. Board: GET /api/boards/:id/labels
    {
      const deniedP = await memberClient.get(`/api/boards/${context.boardBId}/labels`);
      const ctrlP = await ownerClient.get(`/api/boards/${context.boardBId}/labels`);

      const deniedQ = await memberClient.get(`/api/boards/${context.boardBId}/labels?workspace_id=${context.w1Id}`);
      const ctrlQ = await ownerClient.get(`/api/boards/${context.boardBId}/labels?workspace_id=${context.w1Id}`);

      const deniedB = await memberClient.post(`/api/boards/${context.boardBId}/labels`, { name: 'denied_lbl', color: '#ff0000', workspace_id: context.w1Id });
      const ctrlB = await ownerClient.post(`/api/boards/${context.boardBId}/labels`, { name: `ctrl_lbl_${Date.now()}`, color: '#00ff00', workspace_id: context.w1Id });

      const pOk = [403, 404].includes(deniedP.status) && ctrlP.status === 200;
      const qOk = [403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [403, 404].includes(deniedB.status) && (ctrlB.status === 200 || ctrlB.status === 201);
      const passed = pOk && qOk && bOk;
      if (!passed) allR12Passed = false;

      r12Grid.push({
        resource: 'board (GET /api/boards/:id/labels)',
        params: { denied: deniedP.status, control: ctrlP.status },
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        passed
      });
    }

    // 2. List: DELETE /api/lists/:id
    {
      // Cell 1: params
      const l1 = await ownerClient.post('/api/lists', { board_id: context.boardBId, name: 'temp_l1' });
      const l1Id = l1.data?.list?.id || l1.data?.id;
      const deniedP = await memberClient.delete(`/api/lists/${l1Id}`);
      const ctrlP = await ownerClient.delete(`/api/lists/${l1Id}`);

      // Cell 2: query
      const l2 = await ownerClient.post('/api/lists', { board_id: context.boardBId, name: 'temp_l2' });
      const l2Id = l2.data?.list?.id || l2.data?.id;
      const deniedQ = await memberClient.delete(`/api/lists/${l2Id}?workspace_id=${context.w1Id}`);
      const ctrlQ = await ownerClient.delete(`/api/lists/${l2Id}?workspace_id=${context.w1Id}`);

      // Cell 3: body
      const l3 = await ownerClient.post('/api/lists', { board_id: context.boardBId, name: 'temp_l3' });
      const l3Id = l3.data?.list?.id || l3.data?.id;
      const deniedB = await memberClient.delete(`/api/lists/${l3Id}`, { workspace_id: context.w1Id });
      const ctrlB = await ownerClient.delete(`/api/lists/${l3Id}`, { workspace_id: context.w1Id });

      const pOk = [403, 404].includes(deniedP.status) && ctrlP.status === 200;
      const qOk = [403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [403, 404].includes(deniedB.status) && ctrlB.status === 200;
      const passed = pOk && qOk && bOk;
      if (!passed) allR12Passed = false;

      r12Grid.push({
        resource: 'list (DELETE /api/lists/:id)',
        params: { denied: deniedP.status, control: ctrlP.status },
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        passed
      });
    }

    // 3. Card: PATCH /api/cards/:id
    {
      const deniedP = await memberClient.patch(`/api/cards/${context.cardBId}`, { title: 'hacked_p' });
      const ctrlP = await ownerClient.patch(`/api/cards/${context.cardBId}`, { title: 'card_b_ok_p' });

      const deniedQ = await memberClient.patch(`/api/cards/${context.cardBId}?workspace_id=${context.w1Id}`, { title: 'hacked_q' });
      const ctrlQ = await ownerClient.patch(`/api/cards/${context.cardBId}?workspace_id=${context.w1Id}`, { title: 'card_b_ok_q' });

      const deniedB = await memberClient.patch(`/api/cards/${context.cardBId}`, { title: 'hacked_b', workspace_id: context.w1Id });
      const ctrlB = await ownerClient.patch(`/api/cards/${context.cardBId}`, { title: 'card_b_ok_b', workspace_id: context.w1Id });

      const pOk = [403, 404].includes(deniedP.status) && ctrlP.status === 200;
      const qOk = [403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [403, 404].includes(deniedB.status) && ctrlB.status === 200;
      const passed = pOk && qOk && bOk;
      if (!passed) allR12Passed = false;

      r12Grid.push({
        resource: 'card (PATCH /api/cards/:id)',
        params: { denied: deniedP.status, control: ctrlP.status },
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        passed
      });
    }

    // 4. Checklist: DELETE /api/cards/checklists/:id
    {
      const c1 = await ownerClient.post(`/api/cards/${context.cardBId}/checklists`, { title: 'chk_1' });
      const c1Id = c1.data?.checklist?.id || c1.data?.id;
      const deniedP = await memberClient.delete(`/api/cards/checklists/${c1Id}`);
      const ctrlP = await ownerClient.delete(`/api/cards/checklists/${c1Id}`);

      const c2 = await ownerClient.post(`/api/cards/${context.cardBId}/checklists`, { title: 'chk_2' });
      const c2Id = c2.data?.checklist?.id || c2.data?.id;
      const deniedQ = await memberClient.delete(`/api/cards/checklists/${c2Id}?workspace_id=${context.w1Id}`);
      const ctrlQ = await ownerClient.delete(`/api/cards/checklists/${c2Id}?workspace_id=${context.w1Id}`);

      const c3 = await ownerClient.post(`/api/cards/${context.cardBId}/checklists`, { title: 'chk_3' });
      const c3Id = c3.data?.checklist?.id || c3.data?.id;
      const deniedB = await memberClient.delete(`/api/cards/checklists/${c3Id}`, { workspace_id: context.w1Id });
      const ctrlB = await ownerClient.delete(`/api/cards/checklists/${c3Id}`, { workspace_id: context.w1Id });

      const pOk = [403, 404].includes(deniedP.status) && ctrlP.status === 200;
      const qOk = [403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [403, 404].includes(deniedB.status) && ctrlB.status === 200;
      const passed = pOk && qOk && bOk;
      if (!passed) allR12Passed = false;

      r12Grid.push({
        resource: 'checklist (DELETE /api/cards/checklists/:id)',
        params: { denied: deniedP.status, control: ctrlP.status },
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        passed
      });
    }

    // 5. Checklist Item: PATCH /api/cards/checklist-items/:id
    {
      const deniedP = await memberClient.patch(`/api/cards/checklist-items/${context.checklistItemBId}`, { text: 'item_hacked_p' });
      const ctrlP = await ownerClient.patch(`/api/cards/checklist-items/${context.checklistItemBId}`, { text: 'item_ok_p' });

      const deniedQ = await memberClient.patch(`/api/cards/checklist-items/${context.checklistItemBId}?workspace_id=${context.w1Id}`, { text: 'item_hacked_q' });
      const ctrlQ = await ownerClient.patch(`/api/cards/checklist-items/${context.checklistItemBId}?workspace_id=${context.w1Id}`, { text: 'item_ok_q' });

      const deniedB = await memberClient.patch(`/api/cards/checklist-items/${context.checklistItemBId}`, { text: 'item_hacked_b', workspace_id: context.w1Id });
      const ctrlB = await ownerClient.patch(`/api/cards/checklist-items/${context.checklistItemBId}`, { text: 'item_ok_b', workspace_id: context.w1Id });

      const pOk = [403, 404].includes(deniedP.status) && ctrlP.status === 200;
      const qOk = [403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [403, 404].includes(deniedB.status) && ctrlB.status === 200;
      const passed = pOk && qOk && bOk;
      if (!passed) allR12Passed = false;

      r12Grid.push({
        resource: 'checklist item (PATCH /api/cards/checklist-items/:id)',
        params: { denied: deniedP.status, control: ctrlP.status },
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        passed
      });
    }

    // 6. Comment: PATCH /api/cards/comments/:id
    {
      const deniedP = await memberClient.patch(`/api/cards/comments/${context.commentBId}`, { body: 'cmt_hacked_p' });
      const ctrlP = await ownerClient.patch(`/api/cards/comments/${context.commentBId}`, { body: 'cmt_ok_p' });

      const deniedQ = await memberClient.patch(`/api/cards/comments/${context.commentBId}?workspace_id=${context.w1Id}`, { body: 'cmt_hacked_q' });
      const ctrlQ = await ownerClient.patch(`/api/cards/comments/${context.commentBId}?workspace_id=${context.w1Id}`, { body: 'cmt_ok_q' });

      const deniedB = await memberClient.patch(`/api/cards/comments/${context.commentBId}`, { body: 'cmt_hacked_b', workspace_id: context.w1Id });
      const ctrlB = await ownerClient.patch(`/api/cards/comments/${context.commentBId}`, { body: 'cmt_ok_b', workspace_id: context.w1Id });

      const pOk = [403, 404].includes(deniedP.status) && ctrlP.status === 200;
      const qOk = [403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [403, 404].includes(deniedB.status) && ctrlB.status === 200;
      const passed = pOk && qOk && bOk;
      if (!passed) allR12Passed = false;

      r12Grid.push({
        resource: 'comment (PATCH /api/cards/comments/:id)',
        params: { denied: deniedP.status, control: ctrlP.status },
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        passed
      });
    }

    // 7. Attachment: DELETE /api/cards/attachments/:id
    {
      const a1 = await ownerClient.post(`/api/cards/${context.cardBId}/attachments/link`, { link_url: 'https://example.com/a1', display_name: 'a1' });
      const a1Id = a1.data?.attachment?.id || a1.data?.id;
      const deniedP = await memberClient.delete(`/api/cards/attachments/${a1Id}`);
      const ctrlP = await ownerClient.delete(`/api/cards/attachments/${a1Id}`);

      const a2 = await ownerClient.post(`/api/cards/${context.cardBId}/attachments/link`, { link_url: 'https://example.com/a2', display_name: 'a2' });
      const a2Id = a2.data?.attachment?.id || a2.data?.id;
      const deniedQ = await memberClient.delete(`/api/cards/attachments/${a2Id}?workspace_id=${context.w1Id}`);
      const ctrlQ = await ownerClient.delete(`/api/cards/attachments/${a2Id}?workspace_id=${context.w1Id}`);

      const a3 = await ownerClient.post(`/api/cards/${context.cardBId}/attachments/link`, { link_url: 'https://example.com/a3', display_name: 'a3' });
      const a3Id = a3.data?.attachment?.id || a3.data?.id;
      const deniedB = await memberClient.delete(`/api/cards/attachments/${a3Id}`, { workspace_id: context.w1Id });
      const ctrlB = await ownerClient.delete(`/api/cards/attachments/${a3Id}`, { workspace_id: context.w1Id });

      const pOk = [403, 404].includes(deniedP.status) && ctrlP.status === 200;
      const qOk = [403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [403, 404].includes(deniedB.status) && ctrlB.status === 200;
      const passed = pOk && qOk && bOk;
      if (!passed) allR12Passed = false;

      r12Grid.push({
        resource: 'attachment (DELETE /api/cards/attachments/:id)',
        params: { denied: deniedP.status, control: ctrlP.status },
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        passed
      });
    }

    console.log('\n[REG-1.12 TABLE-DRIVEN GRID (DENIED ACTOR vs POSITIVE CONTROL)]');
    for (const row of r12Grid) {
      console.log(`  ${row.resource.padEnd(46)} | params: ${row.params.denied}/${row.params.control} | query: ${row.query.denied}/${row.query.control} | body: ${row.body.denied}/${row.body.control} -> ${row.passed ? 'PASS' : 'FAIL'}`);
    }

    record(
      'REG-1.12',
      'Supplying workspace_id in query/body MUST NOT bypass board-membership gate on Board B (7 resource grid with positive controls)',
      allR12Passed,
      {
        expected: 'Denied actor returns 403, Positive control returns 2xx across all 7 real routes',
        actual: allR12Passed ? 'All 7 resource types strictly DENIED for non-member, CONTROL returned 200' : 'Bypass or control failure detected'
      },
      { grid: r12Grid }
    );
  } catch (err) {
    record('REG-1.12', 'Workspace ID query/body bypass test (table-driven)', false, { expected: '403 Denied / 200 Control', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.13: Cross-workspace resource spoofing (Admin in W1 targeting W2 resource with workspace_id=W1)
  // Table-driven grid: 7 real resource routes x (query workspace_id, body workspace_id, mismatched board_id)
  // Every cell includes a POSITIVE CONTROL executed by authorized W2 Owner returning 2xx.
  // --------------------------------------------------------------------------
  try {
    const adminClient = users['Admin'].client;
    const ownerClient = users['Owner'].client;

    const r13Grid = [];
    let allR13Passed = true;

    // 1. Board: GET /api/boards/:id/labels
    {
      const deniedQ = await adminClient.get(`/api/boards/${context.boardCId}/labels?workspace_id=${context.w1Id}`);
      const ctrlQ = await ownerClient.get(`/api/boards/${context.boardCId}/labels`);

      const deniedB = await adminClient.post(`/api/boards/${context.boardCId}/labels`, { workspace_id: context.w1Id, name: 'lbl_x', color: '#ff0000' });
      const ctrlB = await ownerClient.post(`/api/boards/${context.boardCId}/labels`, { name: `lbl_c_ctrl_${Date.now()}`, color: '#00ff00' });

      const deniedM = await adminClient.get(`/api/boards/${context.boardCId}/labels?board_id=${context.boardAId}`);
      const ctrlM = await ownerClient.get(`/api/boards/${context.boardCId}/labels`);

      const qOk = [400, 403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [400, 403, 404].includes(deniedB.status) && (ctrlB.status === 200 || ctrlB.status === 201);
      const mOk = [400, 403, 404].includes(deniedM.status) && ctrlM.status === 200;
      const passed = qOk && bOk && mOk;
      if (!passed) allR13Passed = false;

      r13Grid.push({
        resource: 'board (GET /api/boards/:id/labels)',
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        mismatched: { denied: deniedM.status, control: ctrlM.status },
        passed
      });
    }

    // 2. List: DELETE /api/lists/:id
    {
      const l1 = await ownerClient.post('/api/lists', { board_id: context.boardCId, name: 'w2_temp_l1' });
      const l1Id = l1.data?.list?.id || l1.data?.id;
      const deniedQ = await adminClient.delete(`/api/lists/${l1Id}?workspace_id=${context.w1Id}`);
      const ctrlQ = await ownerClient.delete(`/api/lists/${l1Id}`);

      const l2 = await ownerClient.post('/api/lists', { board_id: context.boardCId, name: 'w2_temp_l2' });
      const l2Id = l2.data?.list?.id || l2.data?.id;
      const deniedB = await adminClient.delete(`/api/lists/${l2Id}`, { workspace_id: context.w1Id });
      const ctrlB = await ownerClient.delete(`/api/lists/${l2Id}`);

      const l3 = await ownerClient.post('/api/lists', { board_id: context.boardCId, name: 'w2_temp_l3' });
      const l3Id = l3.data?.list?.id || l3.data?.id;
      const deniedM = await adminClient.post('/api/cards', { list_id: l3Id, board_id: context.boardAId, title: 'card_mismatch' });
      const ctrlM = await ownerClient.delete(`/api/lists/${l3Id}`);

      const qOk = [400, 403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [400, 403, 404].includes(deniedB.status) && ctrlB.status === 200;
      const mOk = [400, 403, 404].includes(deniedM.status) && ctrlM.status === 200;
      const passed = qOk && bOk && mOk;
      if (!passed) allR13Passed = false;

      r13Grid.push({
        resource: 'list (DELETE /api/lists/:id)',
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        mismatched: { denied: deniedM.status, control: ctrlM.status },
        passed
      });
    }

    // 3. Card: PATCH /api/cards/:id
    {
      const deniedQ = await adminClient.patch(`/api/cards/${context.cardW2Id}?workspace_id=${context.w1Id}`, { title: 'w2_hack_q' });
      const ctrlQ = await ownerClient.patch(`/api/cards/${context.cardW2Id}`, { title: 'card_w2_ok_q' });

      const deniedB = await adminClient.patch(`/api/cards/${context.cardW2Id}`, { title: 'w2_hack_b', workspace_id: context.w1Id });
      const ctrlB = await ownerClient.patch(`/api/cards/${context.cardW2Id}`, { title: 'card_w2_ok_b', workspace_id: context.w2Id });

      const deniedM = await adminClient.patch(`/api/cards/${context.cardW2Id}`, { title: 'w2_hack_m', board_id: context.boardAId });
      const ctrlM = await ownerClient.patch(`/api/cards/${context.cardW2Id}`, { title: 'card_w2_ok_m' });

      const qOk = [400, 403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [400, 403, 404].includes(deniedB.status) && ctrlB.status === 200;
      const mOk = [400, 403, 404].includes(deniedM.status) && ctrlM.status === 200;
      const passed = qOk && bOk && mOk;
      if (!passed) allR13Passed = false;

      r13Grid.push({
        resource: 'card (PATCH /api/cards/:id)',
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        mismatched: { denied: deniedM.status, control: ctrlM.status },
        passed
      });
    }

    // 4. Checklist: DELETE /api/cards/checklists/:id
    {
      const c1 = await ownerClient.post(`/api/cards/${context.cardW2Id}/checklists`, { title: 'chk_w2_1' });
      const c1Id = c1.data?.checklist?.id || c1.data?.id;
      const deniedQ = await adminClient.delete(`/api/cards/checklists/${c1Id}?workspace_id=${context.w1Id}`);
      const ctrlQ = await ownerClient.delete(`/api/cards/checklists/${c1Id}`);

      const c2 = await ownerClient.post(`/api/cards/${context.cardW2Id}/checklists`, { title: 'chk_w2_2' });
      const c2Id = c2.data?.checklist?.id || c2.data?.id;
      const deniedB = await adminClient.delete(`/api/cards/checklists/${c2Id}`, { workspace_id: context.w1Id });
      const ctrlB = await ownerClient.delete(`/api/cards/checklists/${c2Id}`);

      const c3 = await ownerClient.post(`/api/cards/${context.cardW2Id}/checklists`, { title: 'chk_w2_3' });
      const c3Id = c3.data?.checklist?.id || c3.data?.id;
      const deniedM = await adminClient.post('/api/cards/checklist-items', { checklist_id: c3Id, board_id: context.boardAId, text: 'item_mismatch' });
      const ctrlM = await ownerClient.delete(`/api/cards/checklists/${c3Id}`);

      const qOk = [400, 403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [400, 403, 404].includes(deniedB.status) && ctrlB.status === 200;
      const mOk = [400, 403, 404].includes(deniedM.status) && ctrlM.status === 200;
      const passed = qOk && bOk && mOk;
      if (!passed) allR13Passed = false;

      r13Grid.push({
        resource: 'checklist (DELETE /api/cards/checklists/:id)',
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        mismatched: { denied: deniedM.status, control: ctrlM.status },
        passed
      });
    }

    // 5. Checklist Item: PATCH /api/cards/checklist-items/:id
    {
      const deniedQ = await adminClient.patch(`/api/cards/checklist-items/${context.checklistItemW2Id}?workspace_id=${context.w1Id}`, { text: 'item_w2_hack_q' });
      const ctrlQ = await ownerClient.patch(`/api/cards/checklist-items/${context.checklistItemW2Id}`, { text: 'item_w2_ok_q' });

      const deniedB = await adminClient.patch(`/api/cards/checklist-items/${context.checklistItemW2Id}`, { text: 'item_w2_hack_b', workspace_id: context.w1Id });
      const ctrlB = await ownerClient.patch(`/api/cards/checklist-items/${context.checklistItemW2Id}`, { text: 'item_w2_ok_b', workspace_id: context.w2Id });

      const deniedM = await adminClient.patch(`/api/cards/checklist-items/${context.checklistItemW2Id}`, { text: 'item_w2_hack_m', board_id: context.boardAId });
      const ctrlM = await ownerClient.patch(`/api/cards/checklist-items/${context.checklistItemW2Id}`, { text: 'item_w2_ok_m' });

      const qOk = [400, 403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [400, 403, 404].includes(deniedB.status) && ctrlB.status === 200;
      const mOk = [400, 403, 404].includes(deniedM.status) && ctrlM.status === 200;
      const passed = qOk && bOk && mOk;
      if (!passed) allR13Passed = false;

      r13Grid.push({
        resource: 'checklist item (PATCH /api/cards/checklist-items/:id)',
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        mismatched: { denied: deniedM.status, control: ctrlM.status },
        passed
      });
    }

    // 6. Comment: PATCH /api/cards/comments/:id
    {
      const deniedQ = await adminClient.patch(`/api/cards/comments/${context.commentW2Id}?workspace_id=${context.w1Id}`, { body: 'cmt_w2_hack_q' });
      const ctrlQ = await ownerClient.patch(`/api/cards/comments/${context.commentW2Id}`, { body: 'cmt_w2_ok_q' });

      const deniedB = await adminClient.patch(`/api/cards/comments/${context.commentW2Id}`, { body: 'cmt_w2_hack_b', workspace_id: context.w1Id });
      const ctrlB = await ownerClient.patch(`/api/cards/comments/${context.commentW2Id}`, { body: 'cmt_w2_ok_b', workspace_id: context.w2Id });

      const deniedM = await adminClient.post(`/api/cards/${context.cardW2Id}/comments`, { body: 'cmt_mismatch', board_id: context.boardAId });
      const ctrlM = await ownerClient.patch(`/api/cards/comments/${context.commentW2Id}`, { body: 'cmt_w2_ok_m' });

      const qOk = [400, 403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [400, 403, 404].includes(deniedB.status) && ctrlB.status === 200;
      const mOk = [400, 403, 404].includes(deniedM.status) && ctrlM.status === 200;
      const passed = qOk && bOk && mOk;
      if (!passed) allR13Passed = false;

      r13Grid.push({
        resource: 'comment (PATCH /api/cards/comments/:id)',
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        mismatched: { denied: deniedM.status, control: ctrlM.status },
        passed
      });
    }

    // 7. Attachment: DELETE /api/cards/attachments/:id
    {
      const a1 = await ownerClient.post(`/api/cards/${context.cardW2Id}/attachments/link`, { link_url: 'https://example.com/w2_a1', display_name: 'a1' });
      const a1Id = a1.data?.attachment?.id || a1.data?.id;
      const deniedQ = await adminClient.delete(`/api/cards/attachments/${a1Id}?workspace_id=${context.w1Id}`);
      const ctrlQ = await ownerClient.delete(`/api/cards/attachments/${a1Id}`);

      const a2 = await ownerClient.post(`/api/cards/${context.cardW2Id}/attachments/link`, { link_url: 'https://example.com/w2_a2', display_name: 'a2' });
      const a2Id = a2.data?.attachment?.id || a2.data?.id;
      const deniedB = await adminClient.delete(`/api/cards/attachments/${a2Id}`, { workspace_id: context.w1Id });
      const ctrlB = await ownerClient.delete(`/api/cards/attachments/${a2Id}`);

      const a3 = await ownerClient.post(`/api/cards/${context.cardW2Id}/attachments/link`, { link_url: 'https://example.com/w2_a3', display_name: 'a3' });
      const a3Id = a3.data?.attachment?.id || a3.data?.id;
      const deniedM = await adminClient.post(`/api/cards/${context.cardW2Id}/attachments/link`, { link_url: 'https://example.com/bad', board_id: context.boardAId });
      const ctrlM = await ownerClient.delete(`/api/cards/attachments/${a3Id}`);

      const qOk = [400, 403, 404].includes(deniedQ.status) && ctrlQ.status === 200;
      const bOk = [400, 403, 404].includes(deniedB.status) && ctrlB.status === 200;
      const mOk = [400, 403, 404].includes(deniedM.status) && ctrlM.status === 200;
      const passed = qOk && bOk && mOk;
      if (!passed) allR13Passed = false;

      r13Grid.push({
        resource: 'attachment (DELETE /api/cards/attachments/:id)',
        query: { denied: deniedQ.status, control: ctrlQ.status },
        body: { denied: deniedB.status, control: ctrlB.status },
        mismatched: { denied: deniedM.status, control: ctrlM.status },
        passed
      });
    }

    console.log('\n[REG-1.13 TABLE-DRIVEN GRID (DENIED ACTOR vs POSITIVE CONTROL)]');
    for (const row of r13Grid) {
      console.log(`  ${row.resource.padEnd(46)} | query: ${row.query.denied}/${row.query.control} | body: ${row.body.denied}/${row.body.control} | mismatched: ${row.mismatched.denied}/${row.mismatched.control} -> ${row.passed ? 'PASS' : 'FAIL'}`);
    }

    record(
      'REG-1.13',
      'Admin of W1 sending workspace_id=W1 targeting W2 resource MUST BE DENIED (Hierarchy derivation, 7 resource grid with positive controls)',
      allR13Passed,
      {
        expected: 'Cross-workspace mismatches rejected (400/403/404), Control returned 200 across all 7 real routes',
        actual: allR13Passed ? 'All 7 resource types rejected cross-workspace spoofing, CONTROL returned 200' : 'Hierarchy spoofing or control failure'
      },
      { grid: r13Grid }
    );
  } catch (err) {
    record('REG-1.13', 'Cross-workspace mismatch test (table-driven)', false, { expected: 'Denied / Control 200', actual: err.message });
  }

  // --------------------------------------------------------------------------
  // REG-1.14: Fresh Team Member without workspace.create gets 403 on POST /api/workspaces
  // --------------------------------------------------------------------------
  try {
    const memberClient = users['Team Member'].client;
    const res = await memberClient.post('/api/workspaces', {
      name: `Forbidden_Workspace_${Date.now()}`
    });

    const isDenied = res.status === 403;
    record(
      'REG-1.14',
      'Fresh Team Member without workspace.create MUST get HTTP 403 on POST /api/workspaces',
      isDenied,
      {
        expected: 'HTTP 403 Forbidden',
        actual: `HTTP ${res.status} (${res.data?.error?.code || 'Allowed'})`
      },
      res.data
    );
  } catch (err) {
    record('REG-1.14', 'Fresh Team Member workspace.create test', false, { expected: 'HTTP 403', actual: err.message });
  }

  console.log('\n================================================================');
  const failCount = results.filter((r) => !r.passed).length;
  const passCount = results.filter((r) => r.passed).length;
  console.log(`TOTAL: ${results.length} | PASSED: ${passCount} | FAILED (RED): ${failCount}`);
  console.log('================================================================\n');

  return {
    total: results.length,
    passed: passCount,
    failed: failCount,
    results
  };
}

module.exports = { runRegressionTests };

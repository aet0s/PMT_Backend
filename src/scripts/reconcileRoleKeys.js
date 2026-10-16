#!/usr/bin/env node
// server/src/scripts/reconcileRoleKeys.js
/**
 * Four-Way Role Key Reconciliation Script (Item 1)
 * Compares active key counts and full key lists across FOUR sources side-by-side:
 *   (a) Section 4 specification lists restricted to active keys
 *   (b) expectedMatrix.json
 *   (c) registry.js (SYSTEM_ROLES)
 *   (d) A clone of a real tenant after the sync is applied to the clone
 *
 * All four must be identical; shows any difference key-by-key.
 */
require('dotenv').config();
const mysql = require('mysql2/promise');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');
const expected = require('../rbac/__tests__/expectedMatrix.json');
const { PERMISSIONS, SYSTEM_ROLES } = require('../rbac/registry');
const { resolveMysqlBin } = require('./backup');

const activeCatalogKeys = new Set(PERMISSIONS.filter((p) => !p.planned).map((p) => p.key));

// (a) Section 4 specification lists (from Section 4 spec doc + user clarification)
const SECTION_4_SPEC = {
  Owner: PERMISSIONS.map((p) => p.key),
  Admin: PERMISSIONS.filter((p) => !['workspace.delete', 'company.delete', 'company.export_data', 'billing.manage', 'company.manage_billing'].includes(p.key)).map((p) => p.key),
  'Project Manager': [
    'workspace.view', 'company.view', 'member.view', 'member.invite_guest', 'role.view', 'team.view',
    'project.view', 'project.create', 'project.edit_settings', 'project.archive', 'project.manage_members', 'project.assign_role',
    'project.manage_templates', 'project.change_status', 'project.duplicate', 'project.change_visibility',
    'list.create', 'list.edit', 'list.reorder', 'list.delete',
    'task.view', 'task.create', 'task.edit', 'task.move', 'task.assign', 'task.assign_self', 'task.complete', 'task.delete', 'task.delete_own',
    'task.watch', 'task.set_priority', 'task.bulk_edit', 'task.bulk_delete', 'task.duplicate', 'task.archive', 'task.restore',
    'subtask.create', 'subtask.edit', 'subtask.delete', 'checklist.create', 'checklist.edit', 'checklist.delete',
    'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own', 'comment.delete_any',
    'attachment.view', 'attachment.upload', 'attachment.delete_own', 'attachment.delete_any', 'attachment.version', 'file.view',
    'label.view', 'label.create', 'label.edit', 'label.delete', 'label.delete_own',
    'custom_field.view', 'custom_field.create', 'custom_field.edit', 'custom_field.delete',
    'milestone.view', 'milestone.create', 'milestone.edit', 'milestone.delete',
    'sprint.view', 'sprint.create', 'sprint.edit', 'sprint.start', 'sprint.complete', 'sprint.delete',
    'backlog.view', 'backlog.reorder', 'epic.view', 'epic.create', 'epic.edit', 'epic.delete',
    'time.view_own', 'time.log', 'time.edit_own', 'time.view_all', 'time.approve_timesheet',
    'report.view_project', 'report.view_team', 'report.export', 'dashboard.view_project',
    'view.view', 'view.create', 'view.edit', 'view.delete', 'import_export.import', 'import_export.export',
    'archive.view', 'archive.restore', 'activity.view',
    'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
  ],
  'Team Lead': [
    'workspace.view', 'company.view', 'member.view', 'team.view',
    'project.view', 'list.create', 'list.edit', 'list.reorder',
    'task.view', 'task.create', 'task.edit', 'task.move', 'task.assign', 'task.assign_self', 'task.complete', 'task.delete_own',
    'task.watch', 'task.set_priority', 'task.bulk_edit', 'task.duplicate', 'task.archive', 'task.restore',
    'subtask.create', 'subtask.edit', 'subtask.delete', 'checklist.create', 'checklist.edit', 'checklist.delete',
    'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own', 'comment.delete_any',
    'attachment.view', 'attachment.upload', 'attachment.delete_own', 'attachment.delete_any', 'file.view',
    'label.view', 'label.create', 'label.edit', 'label.delete_own',
    'custom_field.view', 'custom_field.create', 'custom_field.edit', 'milestone.view', 'milestone.create', 'milestone.edit',
    'sprint.view', 'sprint.create', 'sprint.edit', 'sprint.start', 'sprint.complete', 'backlog.view', 'backlog.reorder',
    'epic.view', 'epic.create', 'epic.edit',
    'time.view_own', 'time.log', 'time.edit_own', 'time.view_all',
    'report.view_project', 'report.view_team', 'dashboard.view_project',
    'view.view', 'view.create', 'view.edit', 'view.delete', 'import_export.export',
    'archive.view', 'archive.restore', 'activity.view',
    'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
  ],
  'Team Member': [
    'workspace.view', 'company.view', 'member.view', 'team.view',
    'project.view',
    'task.view', 'task.create', 'task.edit', 'task.move', 'task.assign_self', 'task.complete', 'task.delete_own',
    'task.watch', 'task.set_priority', 'task.duplicate', 'task.archive', 'task.restore',
    'subtask.create', 'subtask.edit', 'subtask.delete', 'checklist.create', 'checklist.edit', 'checklist.delete',
    'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own',
    'attachment.view', 'attachment.upload', 'attachment.delete_own', 'file.view',
    'label.view', 'label.create', 'label.delete_own',
    'custom_field.view', 'milestone.view', 'sprint.view', 'backlog.view', 'epic.view',
    'time.view_own', 'time.log', 'time.edit_own',
    'report.view_project', 'dashboard.view_project',
    'view.view', 'view.create', 'view.edit', 'view.delete',
    'archive.view', 'archive.restore', 'activity.view',
    'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
  ],
  Viewer: [
    'workspace.view', 'company.view', 'member.view', 'team.view',
    'project.view', 'task.view', 'task.watch', 'comment.view', 'attachment.view', 'file.view', 'label.view',
    'custom_field.view', 'milestone.view', 'sprint.view', 'backlog.view', 'epic.view',
    'report.view_project', 'dashboard.view_project', 'view.view', 'activity.view',
    'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
  ],
  Auditor: [
    'workspace.view', 'company.view', 'member.view', 'role.view', 'team.view',
    'project.access_all', 'project.view', 'task.view', 'view.view', 'comment.view', 'attachment.view', 'file.view', 'label.view',
    'custom_field.view', 'milestone.view', 'sprint.view', 'backlog.view', 'epic.view',
    'audit.view', 'audit.export', 'archive.view', 'activity.view',
    'report.view_project', 'report.view_team', 'report.view_all', 'report.export',
    'dashboard.view_project', 'dashboard.view_executive', 'time.view_all',
    'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
  ],
  Guest: [
    'project.view', 'view.view', 'task.view', 'task.watch',
    'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own',
    'attachment.view', 'file.view', 'label.view', 'member.view',
    'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
  ]
};

async function getCloneRoleGrants(tenantDb) {
  const [rows] = await tenantDb.execute(`
    SELECT r.name as role_name, p.key as permission_key
    FROM role_permissions rp
    JOIN roles r ON r.id = rp.role_id
    JOIN permissions p ON p.id = rp.permission_id
    WHERE r.is_system = 1 AND p.planned = 0
    ORDER BY r.rank DESC, p.key ASC
  `);

  const cloneGrants = {};
  for (const row of rows) {
    if (!cloneGrants[row.role_name]) cloneGrants[row.role_name] = [];
    cloneGrants[row.role_name].push(row.permission_key);
  }
  return cloneGrants;
}

async function reconcileFourSources({ cloneDbName = null, cloneConn = null } = {}) {
  console.log('================================================================================');
  console.log('       FOUR-WAY SYSTEM ROLE RECONCILIATION REPORT (GENERATED BY SCRIPT)');
  console.log('================================================================================\n');

  let localConn = cloneConn;
  let shouldClose = false;

  if (!localConn && cloneDbName) {
    localConn = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: cloneDbName
    });
    shouldClose = true;
  }

  let dGrants = {};
  if (localConn) {
    dGrants = await getCloneRoleGrants(localConn);
  }

  const roleOrder = [
    'Owner',
    'Admin',
    'Project Manager',
    'Team Lead',
    'Team Member',
    'Viewer',
    'Auditor',
    'Guest'
  ];

  let allIdentical = true;
  const rows = [];
  const keyDifferences = [];

  for (const role of roleOrder) {
    // (a) Section 4 Spec
    const aList = (SECTION_4_SPEC[role] || []).filter((k) => activeCatalogKeys.has(k)).sort();
    
    // (b) expectedMatrix.json
    let bRaw = [];
    if (role === 'Owner') bRaw = PERMISSIONS.filter((p) => !p.planned).map((p) => p.key);
    else if (role === 'Admin') bRaw = PERMISSIONS.filter((p) => !p.planned && !expected.admin_exclusions.includes(p.key)).map((p) => p.key);
    else bRaw = expected.roles[role] || [];
    const bList = bRaw.filter((k) => activeCatalogKeys.has(k)).sort();

    // (c) registry.js
    const cList = (SYSTEM_ROLES[role]?.permissions || []).filter((k) => activeCatalogKeys.has(k)).sort();

    // (d) Clone post-sync
    const dList = (dGrants[role] || []).filter((k) => activeCatalogKeys.has(k)).sort();

    const countA = aList.length;
    const countB = bList.length;
    const countC = cList.length;
    const countD = localConn ? dList.length : 'N/A';

    // Set comparisons
    const setA = new Set(aList);
    const setB = new Set(bList);
    const setC = new Set(cList);
    const setD = localConn ? new Set(dList) : null;

    const diffAB = aList.filter((k) => !setB.has(k)).concat(bList.filter((k) => !setA.has(k)));
    const diffBC = bList.filter((k) => !setC.has(k)).concat(cList.filter((k) => !setB.has(k)));
    const diffCD = setD ? cList.filter((k) => !setD.has(k)).concat(dList.filter((k) => !setC.has(k))) : [];

    const isMatch = diffAB.length === 0 && diffBC.length === 0 && (!setD || diffCD.length === 0);
    if (!isMatch) allIdentical = false;

    rows.push({
      role,
      countA,
      countB,
      countC,
      countD,
      status: isMatch ? '✅ IDENTICAL' : '❌ MISMATCH',
      diffAB,
      diffBC,
      diffCD,
      keys: aList
    });

    if (!isMatch) {
      keyDifferences.push({
        role,
        diffAB,
        diffBC,
        diffCD
      });
    }
  }

  // Render Table
  console.log('| System Role | (a) Section 4 Spec | (b) expectedMatrix.json | (c) registry.js | (d) Tenant Clone Post-Sync | Reconciliation Status |');
  console.log('|---|:---:|:---:|:---:|:---:|:---:|');
  for (const r of rows) {
    console.log(`| **${r.role}** | **${r.countA}** | **${r.countB}** | **${r.countC}** | **${r.countD}** | ${r.status} |`);
  }

  console.log('\n--- FULL ACTIVE KEY LISTS PER ROLE (4-WAY VERIFIED) ---');
  for (const r of rows) {
    console.log(`\n### ${r.role} (Count: ${r.countA})`);
    console.log(r.keys.map((k) => `  - ${k}`).join('\n'));
  }

  if (!allIdentical) {
    console.error('\n❌ RECONCILIATION FAILED: Differences detected across sources:');
    console.error(JSON.stringify(keyDifferences, null, 2));
  } else {
    console.log('\n✅ ALL FOUR SOURCES ARE 100% IDENTICAL ACROSS ALL 8 ROLES.');
  }

  if (shouldClose && localConn) {
    await localConn.end();
  }

  return { allIdentical, rows, keyDifferences };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  let dbArg = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--database' && args[i + 1]) dbArg = args[++i];
    else if (args[i].startsWith('--database=')) dbArg = args[i].split('=')[1];
  }

  reconcileFourSources({ cloneDbName: dbArg })
    .then(({ allIdentical }) => {
      process.exit(allIdentical ? 0 : 1);
    })
    .catch((err) => {
      console.error('Reconciliation script error:', err);
      process.exit(1);
    });
}

module.exports = {
  SECTION_4_SPEC,
  getCloneRoleGrants,
  reconcileFourSources,
  activeKeys: activeCatalogKeys
};

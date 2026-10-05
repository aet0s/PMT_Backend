// server/src/scripts/generatePermissionMatrixDoc.js
const fs = require('fs');
const path = require('path');
const { PERMISSIONS, SYSTEM_ROLES } = require('../rbac/registry');

function generateMatrixMarkdown() {
  const roleNames = ['Owner', 'Admin', 'Project Manager', 'Team Member', 'Viewer', 'Guest'];
  
  let md = `# Role & Permission Matrix (RBAC)

This document is automatically generated from \`server/src/rbac/registry.js\` and defines the single source of truth for all system roles and permissions.

---

## 1. System Roles Overview

| Role | Rank | System/Immutable | Description |
| :--- | :---: | :---: | :--- |
| **Owner** | 100 | Immutable | Complete control over company data, billing, security, and workspaces. |
| **Admin** | 80 | System | Full workspace administrative control except company deletion and billing. |
| **Project Manager** | 60 | System | Full project and task lifecycle management, reporting, and invitations. |
| **Team Member** | 40 | System | Active contributor: create/edit/move tasks, comments, time tracking. |
| **Viewer** | 20 | System | Read-only access across assigned projects and workspaces. |
| **Guest** | 10 | System | Scoped access strictly to explicitly shared projects with view/comment capability. |

---

## 2. Complete Permissions Matrix

| Module | Permission Key | Scope | Dangerous | Owner | Admin | PM | Member | Viewer | Guest |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
`;

  // Sort permissions by module then key
  const sorted = [...PERMISSIONS].sort((a, b) => {
    if (a.module !== b.module) return a.module.localeCompare(b.module);
    return a.key.localeCompare(b.key);
  });

  for (const perm of sorted) {
    const ownerHas = SYSTEM_ROLES['Owner'].permissions.includes(perm.key) ? '✅' : '❌';
    const adminHas = SYSTEM_ROLES['Admin'].permissions.includes(perm.key) ? '✅' : '❌';
    const pmHas = SYSTEM_ROLES['Project Manager'].permissions.includes(perm.key) ? '✅' : '❌';
    const memberHas = SYSTEM_ROLES['Team Member'].permissions.includes(perm.key) ? '✅' : '❌';
    const viewerHas = SYSTEM_ROLES['Viewer'].permissions.includes(perm.key) ? '✅' : '❌';
    const guestHas = SYSTEM_ROLES['Guest'].permissions.includes(perm.key) ? '✅' : '❌';
    const dangerousStr = perm.dangerous ? '⚠️ Yes' : 'No';

    md += `| \`${perm.module}\` | \`${perm.key}\` | ${perm.scope} | ${dangerousStr} | ${ownerHas} | ${adminHas} | ${pmHas} | ${memberHas} | ${viewerHas} | ${guestHas} |\n`;
  }

  md += `\n---\n*Last regenerated: ${new Date().toISOString()}*\n`;
  return md;
}

const targetPath = path.resolve(__dirname, '../../../docs/PERMISSION_MATRIX.md');
fs.writeFileSync(targetPath, generateMatrixMarkdown(), 'utf-8');
console.log('Generated:', targetPath);

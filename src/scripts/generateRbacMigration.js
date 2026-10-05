// server/src/scripts/generateRbacMigration.js
const fs = require('fs');
const path = require('path');
const { PERMISSIONS, SYSTEM_ROLES } = require('../rbac/registry');

function generateSql() {
  let sql = `-- Migration: 0005_phase4_rbac_system_roles_permissions.sql
-- Seed complete Phase 4 RBAC catalog, 6 system roles, and role_permissions matrix.

-- 1. Extend permissions schema if needed
ALTER TABLE permissions 
  ADD COLUMN IF NOT EXISTS module VARCHAR(50) NOT NULL DEFAULT 'general',
  ADD COLUMN IF NOT EXISTS scope ENUM('company', 'project') NOT NULL DEFAULT 'project',
  ADD COLUMN IF NOT EXISTS dangerous TINYINT(1) NOT NULL DEFAULT 0;

-- 2. Insert or update all catalog permissions
`;

  // Insert permissions in chunks
  const permValues = PERMISSIONS.map((p) => {
    const key = p.key.replace(/'/g, "''");
    const module = p.module.replace(/'/g, "''");
    const label = p.label.replace(/'/g, "''");
    const desc = p.description.replace(/'/g, "''");
    const scope = p.scope;
    const dangerous = p.dangerous ? 1 : 0;
    return `('${key}', '${module}', '${desc}', '${module}', '${scope}', ${dangerous})`;
  }).join(',\n  ');

  sql += `INSERT INTO permissions (\`key\`, category, description, module, scope, dangerous) VALUES
  ${permValues}
ON DUPLICATE KEY UPDATE 
  category = VALUES(category),
  description = VALUES(description),
  module = VALUES(module),
  scope = VALUES(scope),
  dangerous = VALUES(dangerous);

-- 3. Ensure 6 system roles exist
INSERT IGNORE INTO roles (name, is_system, is_editable, workspace_id) VALUES
  ('Owner', 1, 0, NULL),
  ('Admin', 1, 1, NULL),
  ('Project Manager', 1, 1, NULL),
  ('Team Member', 1, 1, NULL),
  ('Viewer', 1, 1, NULL),
  ('Guest', 1, 1, NULL);

-- Legacy role migration: align existing Super Admin and Manager
UPDATE roles SET name = 'Owner', is_editable = 0 WHERE name = 'Super Admin' AND is_system = 1 AND workspace_id IS NULL;
UPDATE roles SET name = 'Project Manager' WHERE name = 'Manager' AND is_system = 1 AND workspace_id IS NULL;

-- 4. Seed role permissions for all 6 system roles
`;

  for (const [roleName, roleDef] of Object.entries(SYSTEM_ROLES)) {
    const permKeysList = roleDef.permissions.map((k) => `'${k}'`).join(', ');
    sql += `
-- Grant permissions for system role: ${roleName}
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r 
CROSS JOIN permissions p
WHERE r.name = '${roleName}' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.\`key\` IN (${permKeysList});
`;
  }

  sql += `
-- 5. Add role_id to board_members for project-level role assignment if not exists
ALTER TABLE board_members
  ADD COLUMN IF NOT EXISTS role_id BIGINT UNSIGNED NULL;
`;

  return sql;
}

const targetPath = path.resolve(__dirname, '../db/migrations/tenant/0005_phase4_rbac_system_roles_permissions.sql');
fs.writeFileSync(targetPath, generateSql(), 'utf-8');
console.log('Generated:', targetPath);

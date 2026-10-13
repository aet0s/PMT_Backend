// server/src/rbac/exportClientPermissions.js
// Exports the canonical RBAC registry and alias maps to client/src/rbac/permissions.json

const fs = require('fs');
const path = require('path');
const {
  PERMISSIONS,
  SYSTEM_ROLES,
  LEGACY_PERMISSION_ALIASES,
  PREREQUISITE_PERMISSIONS
} = require('./registry');

function exportClientPermissions() {
  const clientDir = path.resolve(__dirname, '../../../client/src/rbac');
  if (!fs.existsSync(clientDir)) {
    fs.mkdirSync(clientDir, { recursive: true });
  }

  const exportData = {
    generatedAt: new Date().toISOString(),
    totalPermissions: PERMISSIONS.length,
    permissions: PERMISSIONS,
    aliases: LEGACY_PERMISSION_ALIASES,
    prerequisites: PREREQUISITE_PERMISSIONS,
    systemRoles: SYSTEM_ROLES
  };

  const outputPath = path.join(clientDir, 'permissions.json');
  fs.writeFileSync(outputPath, JSON.stringify(exportData, null, 2), 'utf8');
  console.log(`[RBAC EXPORT] Successfully exported ${PERMISSIONS.length} permissions to ${outputPath}`);
}

if (require.main === module) {
  exportClientPermissions();
}

module.exports = { exportClientPermissions };

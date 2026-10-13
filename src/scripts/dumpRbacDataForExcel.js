// server/src/scripts/dumpRbacDataForExcel.js
const fs = require('fs');
const path = require('path');
const { PERMISSIONS, SYSTEM_ROLES, LEGACY_PERMISSION_ALIASES } = require('../rbac/registry');

const data = {
  permissions: PERMISSIONS,
  systemRoles: SYSTEM_ROLES,
  legacyAliases: LEGACY_PERMISSION_ALIASES
};

const outPath = path.join(__dirname, 'rbac_catalog_dump.json');
fs.writeFileSync(outPath, JSON.stringify(data, null, 2), 'utf8');
console.log(`Exported catalog data to ${outPath}`);

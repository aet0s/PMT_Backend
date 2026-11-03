const fs = require('fs');
const path = require('path');
const { registry, getAllOperationNames } = require('../secure/registry');

const opNames = getAllOperationNames().sort();
const inventory = [];

for (const name of opNames) {
  const op = registry.get(name);
  
  // Extract schema details
  let schemaKeys = [];
  if (op.schema && op.schema.shape) {
    schemaKeys = Object.keys(op.schema.shape);
  } else if (op.schema && typeof op.schema.describe === 'function') {
    try {
      const desc = op.schema.describe();
      schemaKeys = desc.shape ? Object.keys(desc.shape) : [];
    } catch (e) {
      schemaKeys = ['custom_zod'];
    }
  }

  // Determine category
  const [domain] = name.split('.');

  inventory.push({
    name,
    domain,
    requireAuth: op.requireAuth !== false,
    permission: op.permission || '(object-level / internal)',
    schemaFields: schemaKeys.length > 0 ? schemaKeys : ['(passthrough / empty)'],
    tenantScope: op.tenantScope || 'tenant',
    isPublic: op.requireAuth === false
  });
}

console.log(`Processed ${inventory.length} operations.`);
fs.writeFileSync(path.resolve(__dirname, 'operations_inventory.json'), JSON.stringify(inventory, null, 2));


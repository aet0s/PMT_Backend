const fs = require('fs');
const path = require('path');
const { getAllOperationNames, registry } = require('../secure/registry');
const { mapUrlToOperation } = require('../secure/operationMapper');

const routesDir = path.resolve(__dirname, '../routes');
const files = fs.readdirSync(routesDir).filter(f => f.endsWith('.js'));
const allRoutes = [];

for (const file of files) {
  const content = fs.readFileSync(path.join(routesDir, file), 'utf8');
  const baseName = file.replace('.js', '');
  const basePrefix = '/api/' + (baseName === 'index' ? '' : baseName);
  
  const regex = /router\.(get|post|patch|put|delete)\(\s*['"]([^'"]+)['"]/gi;
  let match;
  while ((match = regex.exec(content)) !== null) {
    const method = match[1].toUpperCase();
    const subpath = match[2];
    const fullPath = subpath === '/' ? basePrefix : (basePrefix + (subpath.startsWith('/') ? '' : '/') + subpath);
    allRoutes.push({ file, method, subpath, fullPath });
  }
}

console.log(`Total controller routes found: ${allRoutes.length}`);

// Compare with registered operations
const opNames = getAllOperationNames();
console.log(`Total registered operations in registry: ${opNames.length}`);

fs.writeFileSync(path.resolve(__dirname, 'route_inventory.json'), JSON.stringify({ routes: allRoutes, count: allRoutes.length }, null, 2));


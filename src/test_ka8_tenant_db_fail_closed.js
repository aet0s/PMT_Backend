// server/src/test_ka8_tenant_db_fail_closed.js
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { getActiveDb, userHasPermission, getUserPermissions, countOwners } = require('./middleware/permissions');

async function runTests() {
  console.log('--- Testing K-A.8.6: Fail Closed on Tenant Database Selection ---');

  // PART 1: Runtime tests outside single-tenant mode
  const originalDevSingle = process.env.DEV_SINGLE_TENANT;
  const originalNodeEnv = process.env.NODE_ENV;

  try {
    process.env.DEV_SINGLE_TENANT = '0';
    process.env.NODE_ENV = 'production';

    // 1. getActiveDb(null) must throw
    assert.throws(
      () => getActiveDb(null),
      /Tenant database instance is required/i,
      'getActiveDb(null) must throw when DEV_SINGLE_TENANT is not 1'
    );
    console.log('✓ Pass: getActiveDb(null) throws outside single-tenant mode');

    // 2. getActiveDb({}) must throw
    assert.throws(
      () => getActiveDb({}),
      /Tenant database instance is required/i,
      'getActiveDb({}) must throw when req.db is missing'
    );
    console.log('✓ Pass: getActiveDb({}) throws when req.db is missing');

    // 3. userHasPermission without db must throw
    await assert.rejects(
      async () => await userHasPermission(1, 1, 'project.view'),
      /Tenant database instance is required/i,
      'userHasPermission without db must throw outside single-tenant mode'
    );
    console.log('✓ Pass: userHasPermission without db throws outside single-tenant mode');

    // 4. getUserPermissions without db must throw
    await assert.rejects(
      async () => await getUserPermissions(1, 1),
      /Tenant database instance is required/i,
      'getUserPermissions without db must throw outside single-tenant mode'
    );
    console.log('✓ Pass: getUserPermissions without db throws outside single-tenant mode');

    // 5. countOwners without db must throw
    await assert.rejects(
      async () => await countOwners(1),
      /Tenant database instance is required/i,
      'countOwners without db must throw outside single-tenant mode'
    );
    console.log('✓ Pass: countOwners without db throws outside single-tenant mode');

    // 6. When DEV_SINGLE_TENANT === '1', getActiveDb returns a dev single db without throwing
    process.env.DEV_SINGLE_TENANT = '1';
    process.env.NODE_ENV = 'development';
    const singleDb = getActiveDb(null);
    assert.ok(singleDb && typeof singleDb.query === 'function', 'Must return single db in dev mode');
    console.log('✓ Pass: getActiveDb(null) returns single-tenant dev DB when DEV_SINGLE_TENANT === 1');
  } finally {
    process.env.DEV_SINGLE_TENANT = originalDevSingle;
    process.env.NODE_ENV = originalNodeEnv;
  }

  // PART 2: Source code static scan across server/src
  console.log('\nScanning server/src for calls omitting db argument...');
  const srcDir = path.resolve(__dirname);
  const filesToScan = [];

  function walk(dir) {
    for (const item of fs.readdirSync(dir)) {
      const fullPath = path.join(dir, item);
      if (item === 'node_modules' || item.startsWith('test_')) continue;
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        walk(fullPath);
      } else if (item.endsWith('.js')) {
        filesToScan.push(fullPath);
      }
    }
  }
  walk(srcDir);

  const violations = [];

  for (const file of filesToScan) {
    const code = fs.readFileSync(file, 'utf8');
    const relPath = path.relative(path.resolve(__dirname, '..'), file);

    // Skip definition files or audit scripts
    if (relPath.includes('middleware/permissions.js') || relPath.includes('scripts/rbacAudit.js') || relPath.includes('rbac/routePermissions.js')) {
      continue;
    }

    // Check userHasPermission(a, b, c) without 4th argument
    // Regex matches userHasPermission(arg1, arg2, arg3) where arg3 is last
    const userPermRegex = /userHasPermission\s*\(\s*([^,\n\)]+)\s*,\s*([^,\n\)]+)\s*,\s*([^,\n\)]+)\s*\)/g;
    let match;
    while ((match = userPermRegex.exec(code)) !== null) {
      violations.push(`${relPath}: userHasPermission called with only 3 arguments: ${match[0]}`);
    }

    // Check getUserPermissions(a, b) without 3rd argument
    const getUserPermRegex = /getUserPermissions\s*\(\s*([^,\n\)]+)\s*,\s*([^,\n\)]+)\s*\)/g;
    while ((match = getUserPermRegex.exec(code)) !== null) {
      violations.push(`${relPath}: getUserPermissions called with only 2 arguments: ${match[0]}`);
    }

    // Check countOwners(a) without 2nd argument
    const countOwnersRegex = /countOwners\s*\(\s*([^,\n\)]+)\s*\)/g;
    while ((match = countOwnersRegex.exec(code)) !== null) {
      violations.push(`${relPath}: countOwners called with only 1 argument: ${match[0]}`);
    }
  }

  if (violations.length > 0) {
    console.error('Found permission helper calls omitting db argument:');
    violations.forEach(v => console.error(`  - ${v}`));
    throw new Error(`Permission helper scan failed with ${violations.length} violation(s).`);
  }

  console.log(`✓ Pass: Scanned ${filesToScan.length} files. Zero calls omitting db argument.`);
  console.log('\nAll K-A.8.6 tenant fail-closed assertions passed successfully!');
}

runTests().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});

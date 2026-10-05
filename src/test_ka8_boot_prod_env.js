// server/src/test_ka8_boot_prod_env.js
const assert = require('assert');
const { spawnSync } = require('child_process');
const path = require('path');
const { checkProdEnv } = require('./scripts/checkProdEnv');

function runTest() {
  console.log('=== Testing K-A.8.11: check:prod-env On Boot & Fail-Fast ===\n');

  // 1. Test unit verification of checkProdEnv
  console.log('1. Testing checkProdEnv catches missing/insecure parameters...');
  const incompleteEnv = {
    NODE_ENV: 'production',
    DB_USER: 'root', // Forbidden in prod
    DEV_SINGLE_TENANT: '1' // Forbidden in prod
  };

  const { errors } = checkProdEnv(incompleteEnv);
  assert(errors.length > 0, 'checkProdEnv must report multiple errors on incomplete production env');
  const userErr = errors.find((e) => e.includes('DB_USER'));
  const devSingleErr = errors.find((e) => e.includes('DEV_SINGLE_TENANT'));
  assert(userErr, 'Must identify DB_USER cannot be root');
  assert(devSingleErr, 'Must identify DEV_SINGLE_TENANT must not be enabled');
  console.log(`✓ checkProdEnv caught ${errors.length} errors as expected.`);

  // 2. Test server/src/index.js execution fail-fast in subprocess when NODE_ENV=production
  console.log('\n2. Testing server boot fails fast in production mode when env is incomplete...');
  const serverPath = path.join(__dirname, 'index.js');
  const child = spawnSync(process.execPath, [serverPath], {
    env: {
      ...process.env,
      NODE_ENV: 'production',
      TOTP_ENC_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      CLIENT_URL: 'https://pmt.solarman.in',
      JWT_SECRET: '012345678901234567890123456789012',
      DB_USER: 'root', // Forbidden in production
      DEV_SINGLE_TENANT: '1' // Forbidden in production
    },
    encoding: 'utf8'
  });

  assert.strictEqual(child.status, 1, 'Server process must exit with code 1 on incomplete production environment');
  const combinedOutput = (child.stdout || '') + (child.stderr || '');
  assert(combinedOutput.includes('PRODUCTION BOOT ABORTED'), 'Output must indicate boot aborted due to check:prod-env failure');
  assert(combinedOutput.includes('DB_USER cannot be \'root\' in production'), 'Output must list DB_USER root violation');
  assert(combinedOutput.includes('DEV_SINGLE_TENANT must NOT be enabled in production'), 'Output must list DEV_SINGLE_TENANT violation');
  console.log('✓ Verified: server/src/index.js aborts immediately with code 1 and outputs errors on boot when NODE_ENV=production.');

  console.log('\n=== K-A.8.11 CHECK PROD ENV ON BOOT TEST PASSED ===\n');
}

runTest();

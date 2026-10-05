// server/src/test_ka_prod_env.js
const assert = require('assert');
const { checkProdEnv } = require('./scripts/checkProdEnv');

function runTests() {
  console.log('=== Running K-A.7: Production Environment Hardening Tests ===\n');

  // Test 1: Insecure dev environment fails all security checks
  console.log('1. Testing rejection of default/development environment...');
  const badEnv = {
    NODE_ENV: 'development',
    DISABLE_RATE_LIMIT: 'true',
    DEV_SINGLE_TENANT: 'true',
    DB_USER: 'root',
    JWT_SECRET: 'dev_secret',
    JWT_REFRESH_SECRET: 'short',
    SESSION_SECRET: 'default_secret',
    INVITATION_SECRET: 'secret',
    TOTP_ENC_KEY: 'not-a-hex-key',
    CLIENT_URL: 'http://localhost:5173',
    CORS_ORIGINS: 'http://localhost:5173',
    REGISTRATION_ENABLED: 'true',
    VERIFICATION_MODE: 'off'
  };

  const badResult = checkProdEnv(badEnv);
  assert.ok(badResult.errors.length >= 8, `Expected at least 8 errors, got ${badResult.errors.length}`);
  console.log(`✓ Caught ${badResult.errors.length} expected errors on insecure configuration.`);

  // Test 2: Secure production environment passes all checks
  console.log('2. Testing validation of fully hardened production environment...');
  const goodEnv = {
    NODE_ENV: 'production',
    DISABLE_RATE_LIMIT: 'false',
    DEV_SINGLE_TENANT: 'false',
    DB_USER: 'pmt_app_user',
    JWT_SECRET: 'f89ab928d28a9b74c2e684073b98453472094892c902384a7192837492834719',
    JWT_REFRESH_SECRET: 'c129481928bcde91823749182739481273918273918273918273918273918273',
    SESSION_SECRET: 'e192837192837192837192837192837192837192837192837192837192837192',
    INVITATION_SECRET: 'a918273918273918273918273918273918273918273918273918273918273918',
    TOTP_ENC_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    CLIENT_URL: 'https://pmt.solarman.in',
    CORS_ORIGINS: 'https://pmt.solarman.in',
    REGISTRATION_ENABLED: 'true',
    VERIFICATION_MODE: 'off',
    ALLOW_OPEN_REGISTRATION: 'true',
    BACKUP_JOB_CONFIGURED: 'true'
  };

  const goodResult = checkProdEnv(goodEnv);
  assert.strictEqual(goodResult.errors.length, 0, `Expected 0 errors, got: ${JSON.stringify(goodResult.errors)}`);
  assert.ok(goodResult.warnings.length > 0, 'Expected security warning for open registration');
  console.log('✓ Hardened production configuration passed with 0 errors and proper warning.');

  console.log('\n===============================================');
  console.log('K-A.7 PRODUCTION HARDENING TESTS PASSED!');
  console.log('===============================================\n');
}

runTests();

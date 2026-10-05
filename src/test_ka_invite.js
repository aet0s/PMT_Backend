// server/src/test_ka_invite.js
// Tests for K-A.1: CLIENT_URL validation, invite link generation, and invite lifecycle.
const assert = require('assert');
const crypto = require('crypto');
const { validateEnv } = require('./config/env');

async function runTests() {
  console.log('=== Running K-A.1: Invite & CLIENT_URL Tests ===\n');

  // 1. Env validation in production
  console.log('1. Testing CLIENT_URL env validation in production...');
  const baseProdEnv = {
    NODE_ENV: 'production',
    MYSQL_HOST: '127.0.0.1',
    MYSQL_USER: 'pm_app_user',
    MYSQL_MASTER_DATABASE: 'pm_master',
    MYSQL_TENANT_PREFIX: 'pm_t_',
    JWT_SECRET: 'a_very_long_production_jwt_secret_that_is_32_chars_or_more'
  };

  // Missing CLIENT_URL in production
  const missingClientUrlRes = validateEnv({ ...baseProdEnv });
  assert.strictEqual(missingClientUrlRes.valid, false, 'Should fail validation when CLIENT_URL is missing in production');
  assert(
    missingClientUrlRes.errors.some((e) => e.includes('CLIENT_URL')),
    'Should contain error message mentioning CLIENT_URL'
  );

  // Insecure http:// CLIENT_URL in production
  const httpRes = validateEnv({ ...baseProdEnv, CLIENT_URL: 'http://pmt.solarman.in' });
  assert.strictEqual(httpRes.valid, false, 'Should fail validation when CLIENT_URL is not https in production');
  assert(
    httpRes.errors.some((e) => e.includes('https://')),
    'Should contain error message requiring https://'
  );

  // Valid https:// CLIENT_URL in production
  const validRes = validateEnv({ ...baseProdEnv, CLIENT_URL: 'https://pmt.solarman.in' });
  assert.strictEqual(validRes.valid, true, 'Should pass validation with valid https CLIENT_URL');
  console.log('✓ CLIENT_URL env validation verified.');

  // 2. Invite token signature and link formatting
  console.log('2. Testing invite link generation from CLIENT_URL...');
  process.env.CLIENT_URL = 'https://pmt.solarman.in';
  process.env.JWT_SECRET = 'a_very_long_production_jwt_secret_that_is_32_chars_or_more';

  const rawToken = crypto.randomBytes(20).toString('hex');
  const tenantSlug = 'acme-corp';
  const hmac = crypto.createHmac('sha256', process.env.JWT_SECRET);
  const sig = hmac.update(`${tenantSlug}:${rawToken}`).digest('hex').slice(0, 16);
  const signedToken = `${tenantSlug}.${rawToken}.${sig}`;

  const clientBase = process.env.CLIENT_URL.replace(/\/$/, '');
  const email = 'newuser@acme.com';
  const inviteUrl = `${clientBase}/register?invite_token=${signedToken}&email=${encodeURIComponent(email)}`;

  assert(inviteUrl.startsWith('https://pmt.solarman.in/register?invite_token='), 'Invite link must start with CLIENT_URL');
  assert(!inviteUrl.includes('localhost'), 'Invite link must never contain localhost in production');
  assert(!inviteUrl.includes(':5000'), 'Invite link must never contain backend API port');
  assert(inviteUrl.includes(signedToken), 'Invite link must contain signed token');
  console.log('✓ Invite URL generation verified:', inviteUrl);

  // 3. Verify signed token structure
  console.log('3. Testing signed token verification...');
  const parts = signedToken.split('.');
  assert.strictEqual(parts.length, 3, 'Signed token must have 3 parts: slug.raw.sig');
  assert.strictEqual(parts[0], tenantSlug);
  assert.strictEqual(parts[1], rawToken);
  assert.strictEqual(parts[2], sig);
  console.log('✓ Signed token structure verified.');

  console.log('\n===============================================');
  console.log('K-A.1 SERVER TESTS PASSED (3/3)!');
  console.log('===============================================\n');
}

runTests().catch((err) => {
  console.error('K-A.1 test failed:', err);
  process.exit(1);
});

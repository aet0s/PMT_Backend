// server/src/test_ka8_cookies.js
const assert = require('assert');
const { getCookieOptions, getClearCookieOptions } = require('./utils/cookieOptions');

function runTests() {
  console.log('=== Running K-A.8.3: Cookie Attributes in Cross-Subdomain and Cross-Site Modes ===\n');

  // Mode 1: Production Cross-Subdomain Default (SameSite=Lax)
  console.log('1. Testing default production cross-subdomain configuration (SameSite=Lax)...');
  const prodEnv = {
    NODE_ENV: 'production',
    COOKIE_DOMAIN: '.solarman.in'
  };
  const defaultOpts = getCookieOptions(900000, prodEnv);
  assert.strictEqual(defaultOpts.sameSite, 'lax', 'Default SameSite must be lax for same-site cross-subdomain topology');
  assert.strictEqual(defaultOpts.secure, true, 'Secure must be true in production');
  assert.strictEqual(defaultOpts.httpOnly, true, 'HttpOnly must be true');
  assert.strictEqual(defaultOpts.domain, '.solarman.in', 'Domain should match COOKIE_DOMAIN');
  assert.strictEqual(defaultOpts.path, '/', 'Path must be /');
  assert.strictEqual(defaultOpts.maxAge, 900000);
  console.log('✓ Mode 1 passed: Default cross-subdomain produces SameSite=Lax, Secure=true, Domain=.solarman.in.');

  // Mode 2: Explicit Cross-Site Configuration (SameSite=None)
  console.log('2. Testing explicit cross-site configuration (COOKIE_SAME_SITE=none)...');
  const crossSiteEnv = {
    NODE_ENV: 'production',
    COOKIE_SAME_SITE: 'none'
  };
  const noneOpts = getCookieOptions(900000, crossSiteEnv);
  assert.strictEqual(noneOpts.sameSite, 'none', 'SameSite must be none when explicitly configured');
  assert.strictEqual(noneOpts.secure, true, 'Secure must be true when SameSite=none');
  console.log('✓ Mode 2 passed: Explicit COOKIE_SAME_SITE=none produces SameSite=none, Secure=true.');

  // Mode 3: Local Dev Mode (SameSite=Lax, Secure=false)
  console.log('3. Testing development configuration...');
  const devEnv = {
    NODE_ENV: 'development'
  };
  const devOpts = getCookieOptions(900000, devEnv);
  assert.strictEqual(devOpts.sameSite, 'lax');
  assert.strictEqual(devOpts.secure, false, 'Secure should be false in local development without HTTPS');
  console.log('✓ Mode 3 passed: Development produces SameSite=Lax, Secure=false.');

  // Mode 4: Clear Cookie Options
  console.log('4. Testing clear cookie options...');
  const clearOpts = getClearCookieOptions(prodEnv);
  assert.strictEqual(clearOpts.maxAge, undefined, 'maxAge must be omitted in clear cookie options');
  assert.strictEqual(clearOpts.domain, '.solarman.in');
  assert.strictEqual(clearOpts.path, '/');
  console.log('✓ Mode 4 passed: Clear cookie preserves path and domain without maxAge.');

  console.log('\n===============================================');
  console.log('K-A.8.3 COOKIE TESTS PASSED (4/4)!');
  console.log('===============================================\n');
}

runTests();

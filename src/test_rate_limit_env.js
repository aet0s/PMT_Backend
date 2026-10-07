// server/src/test_rate_limit_env.js
// Tests rate limiter environment restrictions and boot refusal in production.

const { spawn } = require('child_process');
const path = require('path');
const http = require('http');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
    failed++;
  }
}

async function testProductionBootRefusal() {
  console.log('\n--- 1. Production Boot Refusal when DISABLE_RATE_LIMIT=true ---');
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(__dirname, 'index.js')], {
      env: {
        ...process.env,
        NODE_ENV: 'production',
        DISABLE_RATE_LIMIT: 'true',
        PORT: '5099'
      }
    });

    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.stdout.on('data', (d) => { stderr += d.toString(); });

    child.on('exit', (code) => {
      assert(code === 1, `Server exits with code 1 in production when DISABLE_RATE_LIMIT is set (got ${code})`);
      assert(
        stderr.includes('DISABLE_RATE_LIMIT is strictly prohibited') || stderr.includes('Server boot refused'),
        'Prints fatal error message refusing boot'
      );
      resolve();
    });
  });
}

function testMiddlewareBypassLogic() {
  console.log('\n--- 2. Rate Limiting Middleware Environment Scoping ---');
  // Re-require rateLimit with different envs
  const { createRateLimiter } = require('./middleware/rateLimit');

  // Test Case A: NODE_ENV=development with DISABLE_RATE_LIMIT=true -> NOT bypassed
  {
    process.env.NODE_ENV = 'development';
    process.env.DISABLE_RATE_LIMIT = 'true';
    const limiter = createRateLimiter({ maxRequests: 2, windowMs: 60000 });
    let passedCount = 0;
    let blockedCount = 0;

    const fakeReq = { headers: {}, ip: '10.0.0.1' };
    const fakeRes = {
      status: (code) => ({
        json: () => { if (code === 429) blockedCount++; }
      }),
      setHeader: () => {}
    };

    limiter(fakeReq, fakeRes, () => passedCount++);
    limiter(fakeReq, fakeRes, () => passedCount++);
    limiter(fakeReq, fakeRes, () => passedCount++);

    assert(passedCount === 2, `In development, max 2 requests pass before limiter blocks (passed: ${passedCount})`);
    assert(blockedCount === 1, `In development, 3rd request is blocked with 429 even if DISABLE_RATE_LIMIT=true`);
  }

  // Test Case B: NODE_ENV=test with DISABLE_RATE_LIMIT=true -> BYPASSED
  {
    process.env.NODE_ENV = 'test';
    process.env.DISABLE_RATE_LIMIT = 'true';
    const limiter = createRateLimiter({ maxRequests: 2, windowMs: 60000 });
    let passedCount = 0;
    let blockedCount = 0;

    const fakeReq = { headers: {}, ip: '10.0.0.2' };
    const fakeRes = {
      status: (code) => ({
        json: () => { if (code === 429) blockedCount++; }
      }),
      setHeader: () => {}
    };

    limiter(fakeReq, fakeRes, () => passedCount++);
    limiter(fakeReq, fakeRes, () => passedCount++);
    limiter(fakeReq, fakeRes, () => passedCount++);
    limiter(fakeReq, fakeRes, () => passedCount++);

    assert(passedCount === 4, `In test mode with DISABLE_RATE_LIMIT=true, all requests pass (passed: ${passedCount})`);
    assert(blockedCount === 0, `In test mode with DISABLE_RATE_LIMIT=true, zero requests blocked`);
  }

  // Test Case C: NODE_ENV=test without DISABLE_RATE_LIMIT -> RATE LIMIT APPLIES
  {
    process.env.NODE_ENV = 'test';
    delete process.env.DISABLE_RATE_LIMIT;
    const limiter = createRateLimiter({ maxRequests: 2, windowMs: 60000 });
    let passedCount = 0;
    let blockedCount = 0;

    const fakeReq = { headers: {}, ip: '10.0.0.3' };
    const fakeRes = {
      status: (code) => ({
        json: () => { if (code === 429) blockedCount++; }
      }),
      setHeader: () => {}
    };

    limiter(fakeReq, fakeRes, () => passedCount++);
    limiter(fakeReq, fakeRes, () => passedCount++);
    limiter(fakeReq, fakeRes, () => passedCount++);

    assert(passedCount === 2, `In test mode without DISABLE_RATE_LIMIT, rate limit applies normally (passed: ${passedCount})`);
    assert(blockedCount === 1, `In test mode without DISABLE_RATE_LIMIT, request over limit is blocked with 429`);
  }
}

async function run() {
  console.log('================================================================');
  console.log('       TEST SUITE: RATE LIMIT ENVIRONMENT & SAFETY GUARD        ');
  console.log('================================================================');

  await testProductionBootRefusal();
  testMiddlewareBypassLogic();

  console.log('\n================================================================');
  console.log(`RATE LIMIT ENV TESTS: ${passed} passed, ${failed} failed.`);
  console.log('================================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});

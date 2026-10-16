// server/src/scripts/permtest/runRegressions.js
// Runner for Phase A Red tests (REG-1.1 through REG-1.11).

const { PermtestClient } = require('./client');
const { PermtestFixture } = require('./fixtures');
const { runRegressionTests } = require('./regressions');
const { runGenericSpoofTest } = require('./genericSpoofTest');
const { closeAllTenantPools } = require('../../services/tenantPools');

async function main() {
  const frontendUrl = process.env.PERMTEST_FRONTEND_URL || 'http://localhost:5173';
  const client = new PermtestClient({ frontendUrl });

  // 1. Verify frontend and Vite dev proxy preflight
  await client.preflightCheck();

  // 2. Setup disposable fixture
  const fixture = new PermtestFixture({ frontendUrl });
  let outcome = null;
  let spoofOutcome = null;

  try {
    await fixture.setup();
    outcome = await runRegressionTests(fixture);
    spoofOutcome = await runGenericSpoofTest(fixture);
  } finally {
    // 3. Ensure test tenant cleanup
    await fixture.cleanup();
    await closeAllTenantPools();
  }

  // In Phase A, we EXPECT failures (Red tests proving all issues exist)
  if (outcome && outcome.failed > 0) {
    console.log(`\n[PHASE A RED RESULT] Successfully confirmed ${outcome.failed} regression test failures on current code.`);
    process.exit(0);
  } else {
    console.log('\n[NOTICE] All tests passed? In Phase A, regression tests were expected to fail on existing code.');
    process.exit(0);
  }
}

main().catch((err) => {
  console.error('\n[FATAL RUNNER ERROR]:', err);
  process.exit(1);
});

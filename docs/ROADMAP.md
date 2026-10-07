# Project Roadmap & Test Strategy

## Deferred Testing

The following test suites and infrastructure tasks are deferred per scope prioritization (focusing on Part L Notifications and Part M Permission Matrix & Enforcement):

1. **L-0.2 Follow-ups (Items 1-5)**:
   - Root-level unified `test:everything` runner script.
   - Exhaustive full emitter coverage harness across all mutation pathways.
   - Cache audit table verification harness.
   - Production dropped-event metric counter and telemetry hook.
   - Two-tenant browser end-to-end isolation tests.

2. **Playwright Notification E2E**:
   - Multi-browser cross-tenant UI notification delivery tests.

3. **Performance Testing**:
   - High-concurrency socket load and bulk notification delivery benchmarks.

4. **K-B Test Suites**:
   - Ancillary regression test suites from earlier phases.

5. **CI / Continuous Integration Automation**:
   - GitHub Actions pipeline optimizations and containerized runners.

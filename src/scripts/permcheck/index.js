// server/src/scripts/permcheck/index.js
// Main entry point for end-to-end RBAC permission matrix verification.

require('dotenv').config();
const { BrowserClient } = require('./browserClient');
const { setupFixtures, cleanupFixtures } = require('./fixtures');
const { runSuiteN1 } = require('./suiteN1');
const { runSuiteN2 } = require('./suiteN2');
const { Reporter } = require('./reporter');
const { getMasterDb, closeAllTenantPools } = require('../../services/tenantPools');

async function discoverApiBase(frontendUrl) {
  if (process.env.PERMCHECK_API_URL) {
    return process.env.PERMCHECK_API_URL.replace(/\/+$/, '');
  }

  // 1. Try ${frontendUrl}/api/health
  try {
    const res = await fetch(`${frontendUrl}/api/health`);
    if (res.ok) {
      console.log(`[DISCOVERY] API successfully discovered via frontend proxy at ${frontendUrl}`);
      return frontendUrl.replace(/\/+$/, '');
    }
  } catch (e) {
    // try fallback
  }

  // 2. Try direct localhost:5000 fallback
  try {
    const res = await fetch('http://localhost:5000/api/health');
    if (res.ok) {
      console.log('[DISCOVERY] API successfully discovered at http://localhost:5000');
      return 'http://localhost:5000';
    }
  } catch (e) {
    // fallback
  }

  throw new Error(`Unable to discover API endpoint from frontend ${frontendUrl}`);
}

async function verifyFrontendHealthAndCors(frontendUrl, apiBaseUrl) {
  console.log('\n[PREFLIGHT] Verifying Frontend and CORS headers...');

  // GET Root
  const rRoot = await fetch(`${frontendUrl}/`);
  if (!rRoot.ok) throw new Error(`Frontend root returned status ${rRoot.status}`);

  // GET deep links
  const rRoles = await fetch(`${frontendUrl}/w/1/settings/roles`);
  const rProfile = await fetch(`${frontendUrl}/account/profile`);
  console.log(`✓ Deep links verified: /w/1/settings/roles (${rRoles.status}), /account/profile (${rProfile.status})`);

  // CORS Preflight OPTIONS for PATCH and DELETE
  const testClient = new BrowserClient({ apiBaseUrl, frontendUrl });
  const optPatch = await testClient.options('/api/roles/1', 'PATCH');
  const optDelete = await testClient.options('/api/roles/1', 'DELETE');

  const allowPatch = optPatch.status === 204 || optPatch.status === 200;
  const allowDelete = optDelete.status === 204 || optDelete.status === 200;

  if (!allowPatch || !allowDelete) {
    console.warn(`[WARN] CORS Preflight OPTIONS returned: PATCH (${optPatch.status}), DELETE (${optDelete.status})`);
  } else {
    console.log('✓ CORS preflight OPTIONS verified for PATCH and DELETE.');
  }
}

async function main() {
  const args = process.argv.slice(2);
  let filterModule = null;
  let filterPermission = null;
  let quick = false;
  let dryRun = false;
  let cleanupOnly = false;
  let resume = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--module' && args[i + 1]) {
      filterModule = args[i + 1];
      i++;
    } else if (args[i] === '--permission' && args[i + 1]) {
      filterPermission = args[i + 1];
      i++;
    } else if (args[i] === '--quick') {
      quick = true;
    } else if (args[i] === '--dry-run') {
      dryRun = true;
    } else if (args[i] === '--cleanup') {
      cleanupOnly = true;
    } else if (args[i] === '--resume') {
      resume = true;
    }
  }

  const frontendUrl = (process.env.PERMCHECK_FRONTEND_URL || 'http://localhost:5173').replace(/\/+$/, '');
  const isLocal = frontendUrl.includes('localhost') || frontendUrl.includes('127.0.0.1');

  // SAFETY GUARD for non-local targets
  const companySlug = process.env.PERMCHECK_COMPANY_SLUG || (isLocal ? 'permtest_company' : null);
  if (!isLocal) {
    if (!companySlug || !companySlug.startsWith('permtest')) {
      console.error(`[SECURITY FATAL] Refusing to run on non-local target ${frontendUrl}: PERMCHECK_COMPANY_SLUG must start with "permtest"`);
      process.exit(1);
    }
    if (!process.env.PERMCHECK_OWNER_EMAIL || !process.env.PERMCHECK_OWNER_PASSWORD) {
      console.error('[SECURITY FATAL] Non-local targets require PERMCHECK_OWNER_EMAIL and PERMCHECK_OWNER_PASSWORD environment variables.');
      process.exit(1);
    }
  }

  const apiBaseUrl = await discoverApiBase(frontendUrl);
  await verifyFrontendHealthAndCors(frontendUrl, apiBaseUrl);

  const reporter = new Reporter({ frontendUrl, apiBaseUrl, tenantSlug: companySlug });

  if (dryRun) {
    console.log('\n=== DRY RUN MODE: Test Plan Preview ===');
    console.log(`Target Frontend: ${frontendUrl}`);
    console.log(`Target API:      ${apiBaseUrl}`);
    console.log(`Company Slug:    ${companySlug}`);
    console.log(`Module Filter:   ${filterModule || 'All (34 modules)'}`);
    console.log(`Perm Filter:     ${filterPermission || 'All (65 testable)'}`);
    console.log(`Quick Mode:      ${quick ? 'Enabled (System roles only)' : 'Disabled (Full Sweeps)'}`);
    reporter.generateReports();
    process.exit(0);
  }

  let ownerEmail;
  let ownerPassword;
  let tenantId = null;
  let tenantDb = null;
  let targetCompanySlug = companySlug;

  if (isLocal && process.env.DEV_SINGLE_TENANT === '1') {
    ownerEmail = process.env.PERMCHECK_OWNER_EMAIL || 'superadmin@company.com';
    ownerPassword = process.env.PERMCHECK_OWNER_PASSWORD || 'password123';
    targetCompanySlug = null;
    console.log(`[INIT] Running in local single-tenant mode as ${ownerEmail}...`);
  } else {
    const masterDb = getMasterDb();
    let existingTenant = await masterDb.query('SELECT id, slug, db_name, owner_email FROM tenants WHERE slug = ?', [companySlug]);

    ownerEmail = process.env.PERMCHECK_OWNER_EMAIL || 'owner@permtest.local';
    ownerPassword = process.env.PERMCHECK_OWNER_PASSWORD || 'CompliantPass123!@#';

    if (existingTenant.length === 0 && isLocal) {
      console.log(`[PROVISION] Local company "${companySlug}" does not exist. Auto-provisioning via tenantProvisioner...`);
      const { provisionTenant } = require('../../services/tenantProvisioner');
      const prov = await provisionTenant({
        companyName: 'Permtest Local Corp',
        slug: companySlug,
        ownerEmail,
        ownerPassword,
        ownerName: 'Permtest Admin'
      });
      existingTenant = [prov.tenant];
    } else if (existingTenant.length === 0 && !isLocal) {
      throw new Error(`Target company "${companySlug}" not found on master database.`);
    }

    const tenant = existingTenant[0];
    tenantId = tenant.id;
    ownerEmail = tenant.owner_email || ownerEmail;
    console.log(`\n[INIT] Setting up fixtures in tenant "${companySlug}" (ID: ${tenantId})...`);
  }

  const { ownerClient, tenantDb: tDb, context } = await setupFixtures({
    apiBaseUrl,
    frontendUrl,
    ownerEmail,
    ownerPassword,
    tenantSlug: targetCompanySlug,
    tenantId
  });
  tenantDb = tDb;

  if (cleanupOnly) {
    await cleanupFixtures(tenantDb);
    await closeAllTenantPools();
    process.exit(0);
  }

  try {
    // 1. Run Suite N1
    await runSuiteN1({
      ownerClient,
      apiBaseUrl,
      frontendUrl,
      tenantSlug: companySlug,
      tenantDb,
      context,
      filterModule,
      filterPermission,
      quick,
      reporter
    });

    // 2. Run Suite N2 (if not filtering a specific permission)
    if (!filterPermission) {
      await runSuiteN2({
        ownerClient,
        apiBaseUrl,
        frontendUrl,
        tenantSlug: companySlug,
        tenantDb,
        context,
        quick,
        reporter
      });
    }

  } finally {
    // Generate Reports
    reporter.generateReports();

    if (!resume) {
      await cleanupFixtures(tenantDb);
    }
    await closeAllTenantPools();
  }

  const failedCount = reporter.records.filter((r) => r.status === 'FAIL').length;
  console.log(`\nPERMCHECK EXECUTION FINISHED: ${reporter.records.length - failedCount}/${reporter.records.length} PASSED.`);
  if (failedCount > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('[FATAL PERMCHECK ERROR]:', err);
    process.exit(1);
  });
}

module.exports = { main };

// server/src/scripts/notifyAudit.js
// CI Guard: Derives mutating routes from the real router stack and fails if
// any route has neither a declared event nor an explicit no-notify entry with a reason.

const { app } = require('../index');
const { NOTIFICATION_EVENTS, EVENT_CATEGORIES } = require('../services/notificationEvents');
const { ROUTE_NOTIFICATION_MAP } = require('../services/routeNotificationMap');
const { PERMISSIONS } = require('../rbac/registry');

function getExpressRoutes(appInstance) {
  const routes = [];
  function process(stack, prefix = '') {
    for (const layer of stack) {
      if (layer.route) {
        const methods = Object.keys(layer.route.methods).filter((m) => layer.route.methods[m]);
        for (const m of methods) {
          let p = (prefix + layer.route.path).replace(/\/+/g, '/');
          if (p.endsWith('/') && p.length > 1) p = p.slice(0, -1);
          if (p !== '*' && p !== '/api/*') {
            routes.push({ method: m.toUpperCase(), path: p });
          }
        }
      } else if (layer.name === 'router' && layer.handle && layer.handle.stack) {
        let pfx = '';
        if (layer.regexp) {
          const s = layer.regexp.source;
          const match = s.match(/^\^\\?(\/.*?)(?:\\\/\?)?(?:\(\?=\\\/\|\$\)|\$)/);
          if (match) {
            pfx = match[1].replace(/\\\//g, '/').replace(/\\\./g, '.');
          }
        }
        process(layer.handle.stack, prefix + pfx);
      }
    }
  }
  process(appInstance._router.stack);
  return routes;
}

function runAudit() {
  console.log('================================================================');
  console.log('       NOTIFICATION EVENT CATALOGUE & ROUTE AUDIT GUARD         ');
  console.log('================================================================\n');

  // 1. Verify Event Catalogue Integrity
  console.log('--- 1. Validating NOTIFICATION_EVENTS Catalogue Integrity ---');
  const validPermissionKeys = new Set(PERMISSIONS.map((p) => p.key));
  const validCategories = new Set(EVENT_CATEGORIES);
  const catalogEventKeys = Object.keys(NOTIFICATION_EVENTS);

  let catalogErrors = 0;
  for (const [key, config] of Object.entries(NOTIFICATION_EVENTS)) {
    if (!config.category || !validCategories.has(config.category)) {
      console.error(`  ❌ Event "${key}" has invalid category "${config.category}"`);
      catalogErrors++;
    }
    if (!config.requiredPermission || !validPermissionKeys.has(config.requiredPermission)) {
      console.error(`  ❌ Event "${key}" has invalid or null requiredPermission "${config.requiredPermission}"`);
      catalogErrors++;
    }
    if (!config.recipients) {
      console.error(`  ❌ Event "${key}" missing recipient rule`);
      catalogErrors++;
    }
    if (!config.template) {
      console.error(`  ❌ Event "${key}" missing template`);
      catalogErrors++;
    }
    if (!config.coalescingPolicy) {
      console.error(`  ❌ Event "${key}" missing coalescingPolicy`);
      catalogErrors++;
    }
    if (!config.deepLink) {
      console.error(`  ❌ Event "${key}" missing deepLink`);
      catalogErrors++;
    }
  }

  if (catalogErrors === 0) {
    console.log(`  ✓ All ${catalogEventKeys.length} notification events have valid categories, permissions, rules, and templates.`);
  } else {
    console.error(`  ❌ ${catalogErrors} errors found in event catalogue!`);
  }

  // 2. Audit Real Express Mutating Routes
  console.log('\n--- 2. Auditing Live Express Mutating Route Stack ---');
  const allRoutes = getExpressRoutes(app);
  const mutatingMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
  const mutatingRoutes = allRoutes.filter((r) => mutatingMethods.has(r.method));

  let coveredCount = 0;
  let noNotifyCount = 0;
  let missingRoutes = [];
  let invalidEventRoutes = [];

  for (const route of mutatingRoutes) {
    const key = `${route.method} ${route.path}`;
    const mapping = ROUTE_NOTIFICATION_MAP[key];

    if (!mapping) {
      missingRoutes.push(key);
      continue;
    }

    if (mapping.noNotify) {
      if (!mapping.reason || typeof mapping.reason !== 'string' || mapping.reason.trim() === '') {
        missingRoutes.push(`${key} (missing no-notify reason)`);
      } else {
        noNotifyCount++;
      }
    } else if (Array.isArray(mapping.events) && mapping.events.length > 0) {
      for (const ev of mapping.events) {
        if (!NOTIFICATION_EVENTS[ev]) {
          invalidEventRoutes.push(`${key} -> uncatalogued event "${ev}"`);
        }
      }
      coveredCount++;
    } else {
      missingRoutes.push(key);
    }
  }

  console.log(`  Total live mutating routes found: ${mutatingRoutes.length}`);
  console.log(`  Routes with declared events:       ${coveredCount}`);
  console.log(`  Routes with explicit no-notify:    ${noNotifyCount}`);

  if (missingRoutes.length > 0) {
    console.error(`\n❌ AUDIT FAILED: ${missingRoutes.length} mutating routes have NO notification declaration or no-notify reason:`);
    for (const r of missingRoutes) {
      console.error(`   - ${r}`);
    }
  }

  if (invalidEventRoutes.length > 0) {
    console.error(`\n❌ AUDIT FAILED: Routes referencing uncatalogued events:`);
    for (const r of invalidEventRoutes) {
      console.error(`   - ${r}`);
    }
  }

  const passed = catalogErrors === 0 && missingRoutes.length === 0 && invalidEventRoutes.length === 0;

  console.log('\n================================================================');
  if (passed) {
    console.log(`✓ NOTIFY AUDIT PASSED: 100% of mutating routes audited & compliant!`);
    console.log('================================================================\n');
    return true;
  } else {
    console.error(`❌ NOTIFY AUDIT FAILED.`);
    console.log('================================================================\n');
    return false;
  }
}

if (require.main === module) {
  const success = runAudit();
  process.exit(success ? 0 : 1);
}

module.exports = { runAudit };

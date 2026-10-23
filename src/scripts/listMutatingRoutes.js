// server/src/scripts/listMutatingRoutes.js
const { app } = require('../index');
const { AUDIT_EVENT_CATALOGUE } = require('../services/auditEvents');
const { ROUTE_AUDIT_MAP } = require('../services/routeAuditMap');

function getExpressMutatingRoutes(appInstance) {
  const routes = [];
  function process(stack, prefix = '') {
    for (const layer of stack) {
      if (layer.route) {
        const methods = Object.keys(layer.route.methods).filter((m) => layer.route.methods[m]);
        for (const m of methods) {
          if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(m.toUpperCase())) {
            let p = (prefix + layer.route.path).replace(/\/+/g, '/');
            if (p.endsWith('/') && p.length > 1) p = p.slice(0, -1);
            if (p !== '*' && p !== '/api/*') {
              routes.push({ method: m.toUpperCase(), path: p });
            }
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

const mutatingRoutes = getExpressMutatingRoutes(app);
const catalogueEventCount = Object.keys(AUDIT_EVENT_CATALOGUE).length;

let auditedCount = 0;
let exemptionCount = 0;

const rows = mutatingRoutes.map((r, i) => {
  const key = `${r.method} ${r.path}`;
  const mapEntry = ROUTE_AUDIT_MAP[key];
  if (!mapEntry) {
    return { index: i + 1, route: key, status: 'MISSING', details: 'NOT MAPPED' };
  }
  if (mapEntry.exemption) {
    exemptionCount++;
    return { index: i + 1, route: key, status: 'EXEMPT', details: mapEntry.reason };
  }
  auditedCount++;
  return { index: i + 1, route: key, status: 'AUDITED', details: (mapEntry.auditEvents || []).join(', ') };
});

console.log('================================================================================');
console.log('              COMPLETE RECONCILED MUTATING ROUTE AUDIT LIST                    ');
console.log('================================================================================');
console.log(`Catalogue Event Count: ${catalogueEventCount}`);
console.log(`Live Mutating Routes:  ${mutatingRoutes.length}`);
console.log(`Audited Routes:        ${auditedCount}`);
console.log(`Exempt Routes:         ${exemptionCount}`);
console.log('--------------------------------------------------------------------------------');
console.log(JSON.stringify({ catalogueEventCount, totalMutating: mutatingRoutes.length, auditedCount, exemptionCount, rows }, null, 2));

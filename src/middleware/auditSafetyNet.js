// server/src/middleware/auditSafetyNet.js
// Runtime safety net: for any mutating request finishing 2xx without an explicit audit event,
// records a generic 'api.mutation' audit event with route details and increments the fallback counter.

const auditService = require('../services/audit');
const { getAuditContext } = require('../utils/auditContext');

function auditSafetyNetMiddleware(req, res, next) {
  const mutatingMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
  if (!mutatingMethods.includes(req.method)) {
    return next();
  }

  res.on('finish', async () => {
    try {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        if (!res.locals._auditRecorded) {
          auditService.incrementSafetyNetCount();
          const routePattern = req.route?.path ? `${req.baseUrl || ''}${req.route.path}` : req.path;
          const entityIds = { ...req.params };
          const db = req.db;
          if (db) {
            await auditService.record({
              action: 'api.mutation',
              category: 'system',
              entityType: 'api',
              entityId: entityIds.id ? Number(entityIds.id) : null,
              entityLabel: `${req.method} ${routePattern}`,
              outcome: 'success',
              severity: 'info',
              meta: {
                method: req.method,
                route: routePattern,
                status: res.statusCode,
                params: entityIds
              },
              db
            }).catch((e) => console.warn('[WARN] Safety net audit recording failed:', e.message));
          }
        }
      }
    } catch (err) {
      console.warn('[WARN] Safety net error:', err.message);
    }
  });

  next();
}

module.exports = { auditSafetyNetMiddleware };

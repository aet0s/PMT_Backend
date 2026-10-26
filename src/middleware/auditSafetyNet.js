// server/src/middleware/auditSafetyNet.js
// Runtime safety net: for any mutating request finishing 2xx without an explicit audit event,
// records a generic 'api.mutation' audit event with route details and increments the fallback counter.

const auditService = require('../services/audit');
const { getAuditContext } = require('../utils/auditContext');

// Routine background sweeps, polling checks, or personal notification read status
// that should not pollute the tamper-proof security audit log with generic api.mutation fallbacks
const IGNORED_SAFETY_NET_ROUTES = [
  /\/api\/workspaces\/[^/]+\/auto-archive$/,
  /\/api\/notifications\/[^/]+\/read$/,
  /\/api\/notifications\/[^/]+\/unread$/,
  /\/api\/notifications\/read-all$/
];

function auditSafetyNetMiddleware(req, res, next) {
  const mutatingMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
  if (!mutatingMethods.includes(req.method)) {
    return next();
  }

  res.on('finish', async () => {
    try {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        if (!res.locals._auditRecorded) {
          const routePattern = req.route?.path ? `${req.baseUrl || ''}${req.route.path}` : (req.originalUrl || req.path);

          // Check if this route is a routine background task or notification toggle that should be skipped
          const shouldSkip = IGNORED_SAFETY_NET_ROUTES.some((pattern) =>
            pattern.test(routePattern) || pattern.test(req.originalUrl || '') || pattern.test(req.path || '')
          );
          if (shouldSkip) {
            return;
          }

          auditService.incrementSafetyNetCount();
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
              actorId: req.user?.id,
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

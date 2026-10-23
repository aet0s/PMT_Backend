// server/src/utils/auditContext.js
// Request-scoped AsyncLocalStorage context for comprehensive audit logging.
const { AsyncLocalStorage } = require('async_hooks');
const crypto = require('crypto');
const { getClientIp } = require('../middleware/rateLimit');

const auditStorage = new AsyncLocalStorage();

function auditContextMiddleware(req, res, next) {
  const requestId = req.headers['x-request-id'] || req.id || crypto.randomUUID();
  const sessionId = req.user?.sessionId || req.cookies?.sessionId || null;
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || null;

  let workspaceId = null;
  if (req.params?.id && (req.baseUrl?.includes('workspace') || req.path?.includes('workspace'))) {
    workspaceId = Number(req.params.id) || null;
  } else if (req.params?.workspaceId) {
    workspaceId = Number(req.params.workspaceId) || null;
  } else if (req.body?.workspace_id) {
    workspaceId = Number(req.body.workspace_id) || null;
  } else if (req.query?.workspace_id) {
    workspaceId = Number(req.query.workspace_id) || null;
  }

  const initialStore = {
    req,
    res,
    requestId,
    sessionId,
    ip,
    userAgent,
    workspaceId,
    actor: req.user || null,
    actorUserId: req.user?.id || null,
    actorType: req.user ? 'user' : 'api',
    actorName: req.user?.name || null,
    actorEmail: req.user?.email || null,
    actorRole: req.user?.role || null,
    auditRecorded: false
  };

  auditStorage.run(initialStore, () => {
    next();
  });
}

function getAuditContext() {
  return auditStorage.getStore() || null;
}

function setAuditContext(updates = {}) {
  const store = auditStorage.getStore();
  if (store) {
    Object.assign(store, updates);
  }
}

module.exports = {
  auditStorage,
  auditContextMiddleware,
  getAuditContext,
  setAuditContext
};

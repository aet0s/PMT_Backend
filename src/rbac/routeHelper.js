// server/src/rbac/routeHelper.js
// Declarative route helper registering auth, permissions, zod validation, and metadata.

const { requireAuth } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { requirePermission } = require('../middleware/permissions');
const { ROUTE_REGISTRY } = require('./routeRegistry');

/**
 * Declares a route on an Express router with unified auth, permissions, and validation.
 * @param {express.Router} router 
 * @param {object} spec 
 * @param {string} spec.method 'get' | 'post' | 'put' | 'patch' | 'delete'
 * @param {string} spec.path route path
 * @param {string} [spec.permission] required permission key
 * @param {string} [spec.publicReason] reason if public or unpermissioned
 * @param {string} [spec.scope] 'company' | 'project'
 * @param {object} [spec.schema] zod validation schema
 * @param {function|function[]} spec.handler route handler or middleware array
 */
function declareRoute(router, spec) {
  const method = spec.method.toLowerCase();
  const rawPath = spec.path;
  const permission = spec.permission || null;
  const publicReason = spec.publicReason || null;
  const scope = spec.scope || (permission?.startsWith('project.') || permission?.startsWith('task.') ? 'project' : 'company');

  // Register in memory map
  const fullKey = `${method.toUpperCase()} ${rawPath}`;
  ROUTE_REGISTRY.set(fullKey, {
    method: method.toUpperCase(),
    path: rawPath,
    permission,
    publicReason,
    scope
  });

  const middlewares = [];

  // If permissioned, require authentication and permission check
  if (permission) {
    middlewares.push(requireAuth);
    middlewares.push(requirePermission(permission));
  } else if (!publicReason) {
    // If no publicReason provided, enforce requireAuth by default
    middlewares.push(requireAuth);
  }

  // Add validation if schema provided
  if (spec.schema) {
    middlewares.push(validate(spec.schema));
  }

  // Append handlers
  if (Array.isArray(spec.handler)) {
    middlewares.push(...spec.handler);
  } else if (typeof spec.handler === 'function') {
    middlewares.push(spec.handler);
  }

  router[method](rawPath, ...middlewares);
}

module.exports = {
  declareRoute,
  route: declareRoute
};

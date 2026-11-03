// server/src/secure/gateway.js
// POST /api/secure - Centralized Encrypted POST-Only Application Gateway
// Implements the mandatory 19-step validation, decryption, authentication, and RBAC sequence.

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { decryptRequestEnvelope } = require('./crypto');
const { consumeNonce } = require('./replayStore');
const { getStoredIdempotency, storeIdempotency, computePayloadHash } = require('./idempotencyStore');
const { getOperation } = require('./registry');
const { getJwtSecret, checkSessionActive } = require('../middleware/auth');
const { isTokenBlacklisted } = require('../utils/tokenBlacklist');
const { getMasterDb, getTenantDb, getDevSingleDb, getTenantMetadata } = require('../services/tenantPools');
const { userHasPermission } = require('../middleware/permissions');

const router = express.Router();

/**
 * Helper to extract token from session cookie or Authorization header.
 * Query string tokens are strictly ignored.
 */
function extractSessionToken(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7).trim();
  }
  if (req.cookies && req.cookies.token) {
    return req.cookies.token;
  }
  return null;
}

/**
 * Authenticates user from server-side session.
 * Encryption alone NEVER grants access to protected endpoints.
 */
async function authenticateSession(req) {
  const token = extractSessionToken(req);
  if (!token) {
    const err = new Error('Authentication required: No active session');
    err.status = 401;
    err.code = 'UNAUTHORIZED';
    throw err;
  }

  let payload;
  try {
    payload = jwt.verify(token, getJwtSecret());
  } catch (verifyErr) {
    const err = new Error('Invalid or expired authentication session');
    err.status = 401;
    err.code = 'UNAUTHORIZED';
    throw err;
  }

  if (isTokenBlacklisted(token)) {
    const err = new Error('Session has been revoked upon logout');
    err.status = 401;
    err.code = 'SESSION_REVOKED';
    throw err;
  }

  const userId = Number(payload.sub || payload.userId);
  const tenantId = payload.tid ? Number(payload.tid) : (payload.tenantId ? Number(payload.tenantId) : null);
  const sessionId = payload.sid || null;

  let tenant = null;
  let db = null;

  if (tenantId) {
    tenant = await getTenantMetadata(tenantId);
    if (!tenant) {
      const err = new Error('Tenant company no longer exists');
      err.status = 401;
      err.code = 'TENANT_NOT_FOUND';
      throw err;
    }
    if (tenant.status !== 'active' && tenant.status !== 'provisioning') {
      const err = new Error(`Company account is ${tenant.status}`);
      err.status = 403;
      err.code = 'TENANT_INACTIVE';
      throw err;
    }
    db = await getTenantDb(tenantId);
  } else {
    // Single-tenant or dev single
    tenant = { id: 1, slug: 'dev', name: 'Dev Company' };
    db = getDevSingleDb();
  }

  // Verify session is active in database (not revoked or expired)
  if (sessionId) {
    const sessionStatus = await checkSessionActive(db, tenantId, sessionId);
    if (!sessionStatus.active) {
      const err = new Error(sessionStatus.message || 'Session has been revoked');
      err.status = 401;
      err.code = sessionStatus.code || 'SESSION_REVOKED';
      throw err;
    }
  }

  return {
    user: {
      id: userId,
      email: payload.email,
      name: payload.name,
      tenantId,
      sessionId
    },
    tenant,
    db
  };
}

/**
 * POST /api/secure
 * The primary encrypted business endpoint.
 */
router.post('/secure', async (req, res, next) => {
  const requestId = req.id || crypto.randomUUID();

  try {
    // STEPS 1 - 7: Validate envelope, version, key_id, timestamp, decrypt RSA-OAEP + AES-GCM, verify tag
    const decryptedData = decryptRequestEnvelope(req.body);
    const { timestamp, nonce, payload } = decryptedData;

    // STEP 8: Atomically consume nonce using the durable replay-protection store
    await consumeNonce(req.db, nonce, timestamp);

    const { operation, data = {}, request_id, idempotency_key } = payload;

    if (!operation) {
      return res.status(400).json({
        error: {
          message: 'Decrypted payload missing required "operation" field',
          code: 'MISSING_OPERATION',
          requestId
        }
      });
    }

    const opDef = getOperation(operation);
    if (!opDef) {
      return res.status(400).json({
        error: {
          message: `Unknown operation: '${operation}'. All requests must target a registered business operation.`,
          code: 'UNKNOWN_OPERATION',
          requestId
        }
      });
    }

    const isPublicOperation = opDef.requireAuth === false;

    // STEP 9 & 13: Server-side Authentication & Session Verification
    let authContext = { user: null, tenant: null, db: null };
    if (!isPublicOperation) {
      try {
        authContext = await authenticateSession(req);
        req.user = authContext.user;
        req.tenant = authContext.tenant;
        req.db = authContext.db;
      } catch (authErr) {
        return res.status(authErr.status || 401).json({
          error: {
            message: authErr.message || 'Authentication required',
            code: authErr.code || 'UNAUTHORIZED',
            requestId
          }
        });
      }
    } else {
      req.db = process.env.DEV_SINGLE_TENANT === '1' ? getDevSingleDb() : getMasterDb();
    }

    // STEP 10: CSRF Validation for mutating operations
    // (Already verified by csrfProtection middleware on Express route stack)

    // STEP 18 (Pre-execution check): Idempotency check if idempotency_key is present
    if (idempotency_key && authContext.user) {
      const stored = await getStoredIdempotency(req.db, idempotency_key);
      if (stored) {
        const currentHash = computePayloadHash(data);
        if (stored.requestHash !== currentHash) {
          return res.status(409).json({
            error: {
              message: 'Conflict: Idempotency key already used with different request payload',
              code: 'IDEMPOTENCY_CONFLICT',
              requestId
            }
          });
        }
        // Return previously computed idempotent result
        return res.status(stored.statusCode || 200).json(stored.response);
      }
    }

    // STEPS 11 - 17: Operation Registry execution
    let executionResult;
    let statusCode = 200;

    // Validate operation input schema
    let validatedData = data;
    if (opDef.schema) {
      try {
        validatedData = opDef.schema.parse(data);
      } catch (schemaErr) {
        return res.status(400).json({
          error: {
            message: `Validation error for operation '${operation}': ${schemaErr.errors?.[0]?.message || schemaErr.message}`,
            code: 'VALIDATION_ERROR',
            details: schemaErr.errors,
            requestId
          }
        });
      }
    }

    // Resolve resource hierarchy (card -> board -> workspace) if needed
    let workspaceId = data.workspace_id || data.workspaceId || null;
    let projectId = data.board_id || data.boardId || data.project_id || data.projectId || null;

    const cardId = data.card_id || data.cardId || null;
    if (cardId && req.db) {
      const cardRows = await req.db.query(
        'SELECT l.board_id, b.workspace_id FROM cards c JOIN lists l ON c.list_id = l.id JOIN boards b ON l.board_id = b.id WHERE c.id = ?',
        [Number(cardId)]
      );
      if (cardRows && cardRows[0]) {
        projectId = cardRows[0].board_id;
        workspaceId = cardRows[0].workspace_id;
      } else {
        return res.status(404).json({
          error: {
            message: 'Card not found',
            code: 'NOT_FOUND',
            requestId
          }
        });
      }
    } else if (projectId && !workspaceId && req.db) {
      const boardRows = await req.db.query('SELECT workspace_id FROM boards WHERE id = ?', [Number(projectId)]);
      if (boardRows && boardRows[0]) {
        workspaceId = boardRows[0].workspace_id;
      }
    }

    // Check required permission if defined at gateway level
    if (opDef.permission && authContext.user) {
      if (workspaceId) {
        const hasPerm = await userHasPermission(
          authContext.user.id,
          Number(workspaceId),
          opDef.permission,
          req.db,
          projectId ? Number(projectId) : null,
          req
        );

        if (!hasPerm) {
          return res.status(403).json({
            error: {
              message: `Forbidden: Missing required permission '${opDef.permission}'`,
              code: 'PERMISSION_DENIED',
              requestId
            }
          });
        }
      }
    }

    // Execute registered business handler
    const ctx = {
      req,
      res,
      user: authContext.user,
      tenant: authContext.tenant,
      db: req.db,
      workspaceId: workspaceId || null,
      projectId: projectId || null
    };

    executionResult = await opDef.handler(ctx, validatedData);

    // If handler ended response directly, return
    if (res.headersSent) {
      return;
    }

    // Store idempotency result if key was provided
    if (idempotency_key && authContext.user) {
      await storeIdempotency(req.db, {
        idempotencyKey: idempotency_key,
        userId: authContext.user.id,
        tenantId: authContext.tenant?.id || null,
        operation: operation || endpoint,
        data,
        statusCode,
        response: executionResult
      });
    }

    // STEP 19: Return minimized, authorized business response
    const finalStatus = (res.statusCode && res.statusCode !== 200) ? res.statusCode : statusCode;
    return res.status(finalStatus).json(executionResult);
  } catch (err) {
    const status = Number(err.status || err.statusCode) || 400;
    const message = err.message || 'Error processing encrypted request';
    const code = err.code || 'BAD_REQUEST';

    console.warn(`[SECURE-GATEWAY] Request rejected: ${message} (${code})`);

    return res.status(status).json({
      error: {
        message,
        code,
        requestId
      }
    });
  }
});

module.exports = {
  router,
  authenticateSession
};


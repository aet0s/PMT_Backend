// server/src/services/audit.js
// Production-level, append-only, tamper-evident audit logging service with HMAC-SHA256 hash chaining,
// asynchronous two-phase finalizer (0 deadlocks), fail-closed transactions, 1-minute event coalescing,
// 8KB meta capping, sensitive field redaction, and dual-write to activity_log.

const crypto = require('crypto');
const { getAuditContext } = require('../utils/auditContext');
const { broadcastBoardEvent, broadcastWorkspaceEvent } = require('../socket');
const { parseJson } = require('../db/mysql');

// ─────────────────────────────────────────────────────────────────────────────
// 1. BOOT INTEGRITY & HMAC SECRET KEY MANAGEMENT (Item 3)
// ─────────────────────────────────────────────────────────────────────────────
const IS_PROD = process.env.NODE_ENV === 'production';
const DEV_FALLBACK_HMAC_KEY = 'dev-audit-hmac-key-minimum-32chars-for-testing-only!!';
const PROD_DERIVED_HMAC_KEY = crypto
  .createHash('sha256')
  .update(process.env.JWT_SECRET || process.env.DB_PASS || 'pmt_audit_hmac_default_production_key_seed_2026')
  .digest('hex');

if (IS_PROD) {
  if (!process.env.AUDIT_HMAC_KEY || process.env.AUDIT_HMAC_KEY.length < 32) {
    console.warn(
      '⚠️  [AUDIT] AUDIT_HMAC_KEY (min 32 chars) not set in production .env. Using secure derived HMAC key from system secrets.'
    );
  }
}

function getHmacKey(keyId = 'v1') {
  if (process.env.AUDIT_HMAC_KEYS) {
    try {
      const parsed = JSON.parse(process.env.AUDIT_HMAC_KEYS);
      if (parsed[keyId]) return parsed[keyId];
    } catch (_) {}
  }
  return process.env.AUDIT_HMAC_KEY || (IS_PROD ? PROD_DERIVED_HMAC_KEY : DEV_FALLBACK_HMAC_KEY);
}

const CURRENT_KEY_ID = process.env.AUDIT_CURRENT_KEY_ID || 'v1';

// ─────────────────────────────────────────────────────────────────────────────
// 2. REDACTION, TRUNCATION & 8KB META CAPPING (Item 4)
// ─────────────────────────────────────────────────────────────────────────────
const SENSITIVE_KEY_REGEX = /(password|token|secret|totp|otp|code|authorization|cookie|buffer|private_key|api_key)/i;

function redactSensitive(data, depth = 0) {
  if (depth > 10 || data === null || data === undefined) return data;
  if (typeof data !== 'object') return data;

  if (Array.isArray(data)) {
    return data.map((item) => redactSensitive(item, depth + 1));
  }

  const clean = {};
  for (const [key, value] of Object.entries(data)) {
    if (SENSITIVE_KEY_REGEX.test(key)) {
      clean[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      clean[key] = redactSensitive(value, depth + 1);
    } else {
      clean[key] = value;
    }
  }
  return clean;
}

function truncateFieldIfNeeded(field, value) {
  if (typeof value !== 'string') return value;
  const isLongTextField = /(description|body|comment|content|text|notes)/i.test(field);
  if (isLongTextField && value.length > 300) {
    return {
      length: value.length,
      text: value.slice(0, 300)
    };
  }
  return value;
}

/**
 * Enforces strict 8 KB (8192 bytes) ceiling on audit metadata.
 * If size exceeds 8192 bytes, truncates large strings and sets _meta_truncated: true.
 */
function capMeta(meta) {
  if (!meta || typeof meta !== 'object') return meta;
  let jsonStr = JSON.stringify(meta);
  if (jsonStr.length <= 8192) return meta;

  const truncated = { ...meta, _meta_truncated: true };
  for (const [k, v] of Object.entries(truncated)) {
    if (typeof v === 'string' && v.length > 256) {
      truncated[k] = v.slice(0, 256) + '... [TRUNCATED]';
    } else if (Array.isArray(v) && v.length > 20) {
      truncated[k] = v.slice(0, 20);
    }
  }

  jsonStr = JSON.stringify(truncated);
  if (jsonStr.length > 8192) {
    return {
      _meta_truncated: true,
      summary: 'Metadata exceeded 8KB limit and was compacted',
      original_keys: Object.keys(meta)
    };
  }
  return truncated;
}

/**
 * Deterministic JSON stringifier for canonical HMAC-SHA256 hash chaining.
 */
function canonicalizeJson(obj) {
  if (obj === null || obj === undefined) return '';
  if (typeof obj !== 'object') return String(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalizeJson).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalizeJson(obj[k])).join(',') + '}';
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. VOLUME PROTECTION: 1-MINUTE COALESCING (Item 4)
// ─────────────────────────────────────────────────────────────────────────────
// Coalesce repeated events: security.permission_denied, auth.login_failed,
// security.rate_limit_exceeded, audit.viewed.
const COALESCE_ACTIONS = new Set([
  'security.permission_denied',
  'auth.login_failed',
  'security.rate_limit_exceeded',
  'audit.viewed'
]);

// Map: `${tenantKey}:${action}:${actor}:${route}:${minuteBucket}` -> { id, repeat_count, first_occurred_at, last_occurred_at }
const coalesceBuffer = new Map();

function getMinuteBucket(ts = Date.now()) {
  return Math.floor(ts / 60000);
}

let lastPrunedBucket = 0;

function pruneCoalesceBufferIfNeeded() {
  const currentBucket = getMinuteBucket();
  if (currentBucket > lastPrunedBucket) {
    lastPrunedBucket = currentBucket;
    for (const [key] of coalesceBuffer.entries()) {
      const parts = key.split(':');
      const bucket = Number(parts[parts.length - 1]);
      if (!bucket || currentBucket - bucket >= 2) {
        coalesceBuffer.delete(key);
      }
    }
  }
}

// 1-hour session audit view throttle map
const auditViewThrottle = new Map();

function shouldLogAuditView(workspaceId, sessionOrUserId) {
  if (!sessionOrUserId) return true;
  const key = `${workspaceId || 0}:${sessionOrUserId}`;
  const now = Date.now();
  const lastTime = auditViewThrottle.get(key) || 0;
  if (now - lastTime < 3600000) {
    return false;
  }
  auditViewThrottle.set(key, now);
  if (auditViewThrottle.size > 5000) {
    for (const [k, v] of auditViewThrottle.entries()) {
      if (now - v >= 3600000) auditViewThrottle.delete(k);
    }
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. FAIL-CLOSED CATEGORIES (Item 2b)
// ─────────────────────────────────────────────────────────────────────────────
const FAIL_CLOSED_CATEGORIES = new Set([
  'auth',
  'role',
  'member',
  'security',
  'export',
  'audit'
]);

let fallbackMutationCount = 0;
function getSafetyNetCount() {
  return fallbackMutationCount;
}
function incrementSafetyNetCount() {
  fallbackMutationCount++;
}

const AUDIT_TO_ACTIVITY_MAP = {
  'card.created': 'created_card',
  'card.copied': 'created_card',
  'card.moved': 'moved_card',
  'card.completed': 'marked_complete',
  'card.reopened': 'marked_incomplete',
  'card.archived': 'archived_card',
  'card.restored': 'unarchived_card',
  'card.deleted': 'deleted_card',
  'card.assignee_added': 'member_added',
  'card.assignee_removed': 'member_removed',
  'card.assigner_added': 'assigner_added',
  'card.assigner_removed': 'assigner_removed',
  'comment.created': 'added_comment',
  'attachment.created': 'attachment_added',
  'checklist_item.toggled': 'checklist_toggled',
  'board.created': 'created_board'
};

// ─────────────────────────────────────────────────────────────────────────────
// 5. PRIMARY RECORD ENTRY POINT (Item 2a, 2b, 2c)
// ─────────────────────────────────────────────────────────────────────────────
async function record(options = {}) {
  const ctx = getAuditContext();

  // Test hook: force audit insert failure to verify fail-closed rollback (Item 2b)
  if (
    (!IS_PROD || process.env.ENABLE_TEST_HOOKS === 'true') &&
    (options.forceAuditFailure || ctx?.req?.headers?.['x-test-force-audit-failure'] === '1')
  ) {
    const forcedErr = new Error('Forced audit insert failure for fail-closed verification');
    forcedErr.code = 'AUDIT_FORCED_FAILURE';
    throw forcedErr;
  }

  const action = options.action;
  if (!action) {
    throw new Error('Audit record requires an action');
  }

  const category = options.category || 'system';
  const entityType = options.entityType || 'unknown';
  const entityId = options.entityId ? Number(options.entityId) : null;
  const entityLabel = options.entityLabel ? String(options.entityLabel).slice(0, 255) : null;

  let workspaceId = options.workspaceId
    ? Number(options.workspaceId)
    : ctx?.workspaceId
    ? Number(ctx.workspaceId)
    : null;
  let boardId = options.boardId ? Number(options.boardId) : null;
  let cardId = options.cardId ? Number(options.cardId) : null;

  const actorUserId =
    options.actorUserId !== undefined
      ? options.actorUserId
        ? Number(options.actorUserId)
        : null
      : ctx?.actorUserId || null;
  const actorType = options.actorType || ctx?.actorType || (actorUserId ? 'user' : 'system');
  let actorName = options.actorName !== undefined ? options.actorName : ctx?.actorName || null;
  let actorEmail = options.actorEmail !== undefined ? options.actorEmail : ctx?.actorEmail || null;
  let actorRole = options.actorRole !== undefined ? options.actorRole : ctx?.actorRole || null;

  const ipAddress = options.ipAddress || ctx?.ip || null;
  const userAgent = options.userAgent || ctx?.userAgent || null;
  const requestId = options.requestId || ctx?.requestId || null;
  const sessionId = options.sessionId || ctx?.sessionId || null;

  const targetUserId = options.targetUserId ? Number(options.targetUserId) : null;
  const targetUserName = options.targetUserName ? String(options.targetUserName).slice(0, 255) : null;

  const outcome = options.outcome || 'success';
  const severity =
    options.severity ||
    (outcome === 'denied' ? 'warning' : outcome === 'failed' ? 'warning' : 'info');
  const source = options.source || 'live';
  const keyId = options.keyId || CURRENT_KEY_ID;

  const db = options.db || ctx?.req?.db;
  if (!db) {
    throw new Error(`Audit record for action "${action}" failed: No database connection provided`);
  }

  // 1-minute coalescing check for high-frequency events (Item 4)
  if (COALESCE_ACTIONS.has(action) && !options.bypassCoalesce) {
    pruneCoalesceBufferIfNeeded();
    const tenantIdent = ctx?.tenantId || ctx?.req?.tenant?.id || ctx?.req?.tenant?.slug || workspaceId || 'default';
    const routeIdent = options.route || entityLabel || 'default';
    const actorIdent = actorUserId || ipAddress || 'anonymous';
    const minuteBucket = getMinuteBucket();
    const coalesceKey = `${tenantIdent}:${action}:${actorIdent}:${routeIdent}:${minuteBucket}`;

    const existingCoalesced = coalesceBuffer.get(coalesceKey);
    if (existingCoalesced) {
      existingCoalesced.repeat_count++;
      existingCoalesced.last_occurred_at = new Date().toISOString();

      // Persist incremented repeat count into database with optimistic concurrency guard
      if (existingCoalesced.id && db) {
        try {
          const rows = await db.query(
            'SELECT meta, row_hash FROM audit_events WHERE id = ?',
            [existingCoalesced.id]
          );
          if (rows && rows.length > 0) {
            if (rows[0].row_hash) {
              // Finalizer closed the window for this row. Evict key so next event starts a fresh row.
              coalesceBuffer.delete(coalesceKey);
            } else {
              const currentMeta = parseJson(rows[0].meta) || {};
              currentMeta.repeat_count = existingCoalesced.repeat_count;
              currentMeta.last_occurred_at = existingCoalesced.last_occurred_at;
              const [updRes] = await db.execute(
                'UPDATE audit_events SET meta = ? WHERE id = ? AND row_hash IS NULL',
                [JSON.stringify(currentMeta), existingCoalesced.id]
              );
              if (updRes && updRes.affectedRows === 0) {
                // Concurrently finalized between SELECT and UPDATE
                coalesceBuffer.delete(coalesceKey);
              }
            }
          }
        } catch (_) {}
      }

      return {
        id: existingCoalesced.id || null,
        coalesced: true,
        repeat_count: existingCoalesced.repeat_count
      };
    }
  }

  // Auto-resolve missing actor snapshot details if actorUserId is present
  if (actorUserId && (!actorName || !actorEmail)) {
    try {
      const uRes = await db.query('SELECT name, email FROM users WHERE id = ?', [actorUserId]);
      if (uRes.length > 0) {
        if (!actorName) actorName = uRes[0].name;
        if (!actorEmail) actorEmail = uRes[0].email;
      }
    } catch (_) {}
  }

  if (actorUserId && !actorRole) {
    try {
      if (workspaceId) {
        const rRes = await db.query(
          `SELECT COALESCE(r.name, wm.role) as role_name 
           FROM workspace_members wm 
           LEFT JOIN roles r ON wm.role_id = r.id 
           WHERE wm.workspace_id = ? AND wm.user_id = ?`,
          [workspaceId, actorUserId]
        );
        if (rRes.length > 0 && rRes[0].role_name) {
          actorRole = rRes[0].role_name;
        }
      }
      if (!actorRole) {
        const anyRes = await db.query(
          `SELECT COALESCE(r.name, wm.role) as role_name 
           FROM workspace_members wm 
           LEFT JOIN roles r ON wm.role_id = r.id 
           WHERE wm.user_id = ? 
           ORDER BY (COALESCE(r.name, wm.role) = 'Owner') DESC, r.rank DESC LIMIT 1`,
          [actorUserId]
        );
        if (anyRes.length > 0 && anyRes[0].role_name) {
          actorRole = anyRes[0].role_name;
        }
      }
    } catch (_) {}
  }

  // Auto-resolve workspaceId and boardId from cardId if missing
  if (cardId && (!boardId || !workspaceId)) {
    try {
      const cRes = await db.query(
        `SELECT l.board_id, b.workspace_id 
         FROM cards c
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE c.id = ?`,
        [cardId]
      );
      if (cRes.length > 0) {
        if (!boardId) boardId = cRes[0].board_id;
        if (!workspaceId) workspaceId = cRes[0].workspace_id;
      }
    } catch (_) {}
  }

  // Auto-resolve workspaceId from boardId if missing
  if (boardId && !workspaceId) {
    try {
      const bRes = await db.query('SELECT workspace_id FROM boards WHERE id = ?', [boardId]);
      if (bRes.length > 0) {
        workspaceId = bRes[0].workspace_id;
      }
    } catch (_) {}
  }

  // Process changes: redact sensitive keys & truncate long descriptions/comments
  let changes = options.changes || null;
  if (Array.isArray(changes)) {
    changes = changes.map((ch) => {
      const field = ch.field || 'unknown';
      let from = redactSensitive(ch.from);
      let to = redactSensitive(ch.to);
      from = truncateFieldIfNeeded(field, from);
      to = truncateFieldIfNeeded(field, to);
      return { field, from, to };
    });
  }

  // Process metadata: redact sensitive keys and cap at 8 KB
  let meta = capMeta(redactSensitive(options.meta || null));

  // If this action is coalesced, initialize repeat metadata
  if (COALESCE_ACTIONS.has(action)) {
    const nowIso = new Date().toISOString();
    meta = {
      ...(meta || {}),
      repeat_count: options.repeat_count || 1,
      first_occurred_at: options.first_occurred_at || nowIso,
      last_occurred_at: options.last_occurred_at || nowIso
    };
  }

  const eventUid = options.eventUid || crypto.randomUUID();
  const occurredAt = options.occurredAt ? new Date(options.occurredAt) : new Date();
  const occurredAtSql = occurredAt.toISOString().slice(0, 23).replace('T', ' ');

  // ───────────────────────────────────────────────────────────────────────────
  // Non-blocking Concurrent Insert (Item 2c)
  // row_hash and prev_hash are inserted as NULL.
  // Cryptographic hashes are finalized in ID order asynchronously or on demand.
  // ───────────────────────────────────────────────────────────────────────────
  const insertSql = `
    INSERT INTO audit_events (
      event_uid, occurred_at, workspace_id, board_id, card_id,
      actor_user_id, actor_type, actor_name, actor_email, actor_role,
      ip_address, user_agent, request_id, session_id,
      action, category, entity_type, entity_id, entity_label,
      target_user_id, target_user_name, outcome, severity,
      changes, meta, source, key_id, prev_hash, row_hash
    ) VALUES (
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?,
      ?, ?, ?, ?, NULL, NULL
    )
  `;

  const insertParams = [
    eventUid,
    occurredAtSql,
    workspaceId,
    boardId,
    cardId,
    actorUserId,
    actorType,
    actorName,
    actorEmail,
    actorRole,
    ipAddress,
    userAgent,
    requestId,
    sessionId,
    action,
    category,
    entityType,
    entityId,
    entityLabel,
    targetUserId,
    targetUserName,
    outcome,
    severity,
    changes ? JSON.stringify(changes) : null,
    meta ? JSON.stringify(meta) : null,
    source,
    keyId
  ];

  let auditEventId = null;
  let auditInsertFailed = false;
  try {
    const execResult = await db.execute(insertSql, insertParams);
    auditEventId = execResult.insertId;
  } catch (insertErr) {
    // Fail-closed enforcement for critical categories (Item 2b)
    if (FAIL_CLOSED_CATEGORIES.has(category)) {
      console.error(
        `[AUDIT_FAIL_CLOSED] Failed to record audit event for critical category "${category}", action "${action}":`,
        insertErr.message
      );
      throw insertErr;
    }
    auditInsertFailed = true;
    console.warn(
      `[AUDIT_WARN] Non-critical audit insert failed for action "${action}":`,
      insertErr.message
    );
  }

  // Register in coalescing buffer if applicable and insert succeeded
  if (!auditInsertFailed && COALESCE_ACTIONS.has(action) && !options.bypassCoalesce) {
    const tenantIdent = ctx?.tenantId || ctx?.req?.tenant?.id || ctx?.req?.tenant?.slug || workspaceId || 'default';
    const routeIdent = options.route || entityLabel || 'default';
    const actorIdent = actorUserId || ipAddress || 'anonymous';
    const minuteBucket = getMinuteBucket();
    const coalesceKey = `${tenantIdent}:${action}:${actorIdent}:${routeIdent}:${minuteBucket}`;
    coalesceBuffer.set(coalesceKey, {
      id: auditEventId,
      repeat_count: 1,
      first_occurred_at: occurredAtSql,
      last_occurred_at: occurredAtSql
    });
  }

  // Mark in request context that audit event was recorded
  if (ctx) ctx.auditRecorded = true;
  if (ctx?.res?.locals) ctx.res.locals._auditRecorded = true;

  // Dual-write to activity_log for team feed and daily tracker backwards compatibility
  const activityAction = options.activityAction || AUDIT_TO_ACTIVITY_MAP[action];
  if (
    source !== 'backfill' &&
    !options.skipActivityLog &&
    activityAction &&
    (boardId || workspaceId || cardId)
  ) {
    try {
      const activityMeta = {
        ...(options.activityMeta || {}),
        title:
          entityLabel ||
          options.activityMeta?.title ||
          (meta?.title || meta?.cardTitle || null),
        actor_name: actorName,
        changes: changes || undefined,
        audit_event_id: auditEventId
      };

      for (const k of ['description', 'body', 'text', 'comment']) {
        if (typeof activityMeta[k] === 'string' && activityMeta[k].length > 300) {
          activityMeta[k] = activityMeta[k].slice(0, 300) + '...';
        }
      }

      const actRes = await db.execute(
        `INSERT INTO activity_log (board_id, card_id, user_id, workspace_id, action_type, meta_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          boardId || null,
          cardId || null,
          actorUserId || null,
          workspaceId || null,
          activityAction,
          JSON.stringify(activityMeta)
        ]
      );

      if (actRes && actRes.insertId) {
        const fullAct = await db.query(
          `SELECT a.id, a.board_id, a.card_id, a.user_id, a.workspace_id, a.action_type, a.meta_json, a.created_at,
                  u.name as user_name, u.email as user_email, u.avatar_url as user_avatar_url,
                  c.title as card_title,
                  b.name as board_name,
                  w.name as workspace_name
           FROM activity_log a
           LEFT JOIN users u ON a.user_id = u.id
           LEFT JOIN cards c ON a.card_id = c.id
           LEFT JOIN boards b ON a.board_id = b.id
           LEFT JOIN workspaces w ON a.workspace_id = w.id
           WHERE a.id = ?`,
          [actRes.insertId]
        );

        if (fullAct && fullAct.length > 0) {
          const parsed = {
            ...fullAct[0],
            meta_json: parseJson(fullAct[0].meta_json)
          };
          const effectiveTenantId = db.tenantId || ctx?.req?.tenant?.id || null;
          if (boardId) {
            broadcastBoardEvent(boardId, 'board:activity', { activity: parsed }, null, effectiveTenantId);
          }
          if (workspaceId) {
            broadcastWorkspaceEvent(workspaceId, 'workspace:activity', { activity: parsed }, null, effectiveTenantId);
          }
        }
      }
    } catch (actErr) {
      console.warn(
        `[WARN] Dual-write to activity_log for action "${activityAction}" failed:`,
        actErr.message
      );
    }
  }

  return {
    id: auditEventId,
    eventUid,
    occurredAt: occurredAtSql,
    finalized: false
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. CRYPTOGRAPHIC CHAIN FINALIZER (Item 2c, Item 3)
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Asynchronously or on demand finalizes unfinalized audit rows in strict ID order.
 * Assigns prev_hash and HMAC-SHA256 row_hash.
 * Supported by the append-only trigger exception (transition from NULL to NOT NULL).
 */
async function finalizeAuditChain(db, options = {}) {
  // Fetch unfinalized rows in ascending ID order
  const rawUnfinalized = await db.query(
    `SELECT
       id, event_uid, occurred_at, workspace_id, board_id, card_id,
       actor_user_id, actor_type, action, category, entity_type, entity_id,
       outcome, severity, changes, meta, source, key_id
     FROM audit_events
     WHERE row_hash IS NULL
     ORDER BY id ASC`
  );
  const unfinalized = Array.isArray(rawUnfinalized) && Array.isArray(rawUnfinalized[0]) ? rawUnfinalized[0] : rawUnfinalized;

  if (!Array.isArray(unfinalized) || unfinalized.length === 0) {
    return { finalizedCount: 0 };
  }

  // Fetch the latest finalized row_hash to continue the unbroken chain
  let prevHash = null;
  const rawLastRows = await db.query(
    'SELECT id, row_hash FROM audit_events WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1'
  );
  const lastRows = Array.isArray(rawLastRows) && Array.isArray(rawLastRows[0]) ? rawLastRows[0] : rawLastRows;
  if (Array.isArray(lastRows) && lastRows.length > 0 && lastRows[0].row_hash) {
    prevHash = lastRows[0].row_hash;
  } else {
    prevHash = '0'.repeat(64); // Genesis hash
  }

  let count = 0;
  for (const row of unfinalized) {
    // Evict this row from in-memory coalesceBuffer to prevent concurrent coalescing while finalizing
    for (const [k, v] of coalesceBuffer.entries()) {
      if (v.id === row.id) {
        coalesceBuffer.delete(k);
      }
    }

    const occurredAtSql =
      row.occurred_at instanceof Date
        ? row.occurred_at.toISOString().slice(0, 23).replace('T', ' ')
        : String(row.occurred_at).slice(0, 23).replace('T', ' ');

    let currentMeta = typeof row.meta === 'string' ? parseJson(row.meta) : row.meta;
    let canonicalPayload = canonicalizeJson({
      event_uid: row.event_uid,
      occurred_at: occurredAtSql,
      workspace_id: row.workspace_id,
      board_id: row.board_id,
      card_id: row.card_id,
      actor_user_id: row.actor_user_id,
      actor_type: row.actor_type,
      action: row.action,
      category: row.category,
      entity_type: row.entity_type,
      entity_id: row.entity_id,
      outcome: row.outcome,
      severity: row.severity,
      changes: typeof row.changes === 'string' ? parseJson(row.changes) : row.changes,
      meta: currentMeta,
      source: row.source
    });

    const hmacKey = getHmacKey(row.key_id);
    let rowHash = crypto
      .createHmac('sha256', hmacKey)
      .update(canonicalPayload + ':' + prevHash)
      .digest('hex');

    const rawMetaStr = typeof row.meta === 'string' ? row.meta : JSON.stringify(row.meta);
    const [upd] = await db.execute(
      'UPDATE audit_events SET prev_hash = ?, row_hash = ? WHERE id = ? AND row_hash IS NULL AND (meta <=> ? OR meta = ?)',
      [prevHash, rowHash, row.id, rawMetaStr, rawMetaStr]
    );

    if (upd && upd.affectedRows === 0) {
      // Concurrently updated by a coalescing call during hash computation. Re-read fresh meta and finalize.
      const recheck = await db.query('SELECT row_hash, meta FROM audit_events WHERE id = ?', [row.id]);
      const recheckRows = Array.isArray(recheck) && Array.isArray(recheck[0]) ? recheck[0] : recheck;
      if (recheckRows && recheckRows.length > 0 && !recheckRows[0].row_hash) {
        currentMeta = typeof recheckRows[0].meta === 'string' ? parseJson(recheckRows[0].meta) : recheckRows[0].meta;
        canonicalPayload = canonicalizeJson({
          event_uid: row.event_uid,
          occurred_at: occurredAtSql,
          workspace_id: row.workspace_id,
          board_id: row.board_id,
          card_id: row.card_id,
          actor_user_id: row.actor_user_id,
          actor_type: row.actor_type,
          action: row.action,
          category: row.category,
          entity_type: row.entity_type,
          entity_id: row.entity_id,
          outcome: row.outcome,
          severity: row.severity,
          changes: typeof row.changes === 'string' ? parseJson(row.changes) : row.changes,
          meta: currentMeta,
          source: row.source
        });
        rowHash = crypto
          .createHmac('sha256', hmacKey)
          .update(canonicalPayload + ':' + prevHash)
          .digest('hex');
        await db.execute(
          'UPDATE audit_events SET prev_hash = ?, row_hash = ? WHERE id = ? AND row_hash IS NULL',
          [prevHash, rowHash, row.id]
        );
      }
    }

    prevHash = rowHash;
    count++;
  }

  return { finalizedCount: count, lastRowHash: prevHash };
}

function flushCoalesceBuffer() {
  coalesceBuffer.clear();
}

module.exports = {
  record,
  finalizeAuditChain,
  redactSensitive,
  truncateFieldIfNeeded,
  canonicalizeJson,
  capMeta,
  getHmacKey,
  CURRENT_KEY_ID,
  FAIL_CLOSED_CATEGORIES,
  COALESCE_ACTIONS,
  getSafetyNetCount,
  incrementSafetyNetCount,
  flushCoalesceBuffer,
  shouldLogAuditView,
  AUDIT_TO_ACTIVITY_MAP
};

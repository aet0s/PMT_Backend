// server/src/routes/auditEventsController.js
// Workspace-scoped compliance audit log endpoints:
// Keyset pagination, faceted dropdown data, CSV/JSON export with formula injection safety,
// cryptographic hash-chain verification, and timezone-aware date range filtering.

const crypto = require('crypto');
const { requireAuth } = require('../middleware/auth');
const { requirePermission, accessibleBoardIds, userHasPermission } = require('../middleware/permissions');
const { parseJson } = require('../db/mysql');
const auditService = require('../services/audit');

/**
 * Parses date range strings in the given timezone (default Asia/Kolkata)
 * and returns UTC SQL datetime strings (both ends inclusive).
 */
function parseDateRangeToUtc(fromStr, toStr, timeZone = 'Asia/Kolkata') {
  let fromUtc = null;
  let toUtc = null;
  const tzOffset = timeZone === 'Asia/Kolkata' ? '+05:30' : 'Z';

  if (fromStr) {
    const cleanFrom = String(fromStr).trim();
    const fromTimeStr = cleanFrom.length <= 10 && /^\d{4}-\d{2}-\d{2}$/.test(cleanFrom)
      ? `${cleanFrom}T00:00:00.000${tzOffset}`
      : cleanFrom;
    try {
      const d = new Date(fromTimeStr);
      if (!isNaN(d.getTime())) {
        fromUtc = d.toISOString().slice(0, 23).replace('T', ' ');
      }
    } catch (_) {}
  }

  if (toStr) {
    const cleanTo = String(toStr).trim();
    const toTimeStr = cleanTo.length <= 10 && /^\d{4}-\d{2}-\d{2}$/.test(cleanTo)
      ? `${cleanTo}T23:59:59.999${tzOffset}`
      : cleanTo;
    try {
      const d = new Date(toTimeStr);
      if (!isNaN(d.getTime())) {
        toUtc = d.toISOString().slice(0, 23).replace('T', ' ');
      }
    } catch (_) {}
  }

  return { fromUtc, toUtc };
}

/**
 * Sanitizes CSV cell to prevent formula injection (=, +, -, @, tab, CR).
 */
function sanitizeCsvCell(val) {
  if (val === null || val === undefined) return '""';
  let str = typeof val === 'object' ? JSON.stringify(val) : String(val);
  if (/^[=+\-@\t\r]/.test(str)) {
    str = "'" + str;
  }
  return '"' + str.replace(/"/g, '""') + '"';
}

function encodeCursor(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64');
}

function decodeCursor(str) {
  try {
    return JSON.parse(Buffer.from(str, 'base64').toString('utf8'));
  } catch (_) {
    return null;
  }
}

/**
 * Helper to build common WHERE clause and query parameters for audit query.
 */
async function buildAuditFilter(req, workspaceId) {
  const wsRows = await req.db.query('SELECT settings FROM workspaces WHERE id = ?', [workspaceId]);
  const wsSettings = wsRows[0]?.settings ? parseJson(wsRows[0].settings) : {};
  const wsTimezone = wsSettings?.timezone || 'Asia/Kolkata';

  const whereConditions = ['a.workspace_id = ?'];
  const queryParams = [workspaceId];

  // RBAC Board-level scoping: check project.access_all
  const hasAccessAll = await userHasPermission(req.user.id, workspaceId, 'project.access_all', req.db);
  if (!hasAccessAll) {
    const allowedBoardIds = await accessibleBoardIds(req.user.id, workspaceId, 'project.view', req.db);
    if (allowedBoardIds.length > 0) {
      whereConditions.push('(a.board_id IS NULL OR a.board_id IN (?))');
      queryParams.push(allowedBoardIds);
    } else {
      whereConditions.push('a.board_id IS NULL');
    }
  }

  // Date range
  const { fromUtc, toUtc } = parseDateRangeToUtc(req.query.from, req.query.to, wsTimezone);
  if (fromUtc) {
    whereConditions.push('a.occurred_at >= ?');
    queryParams.push(fromUtc);
  }
  if (toUtc) {
    whereConditions.push('a.occurred_at <= ?');
    queryParams.push(toUtc);
  }

  // Actor IDs (multi-select)
  if (req.query.actor_id) {
    const raw = Array.isArray(req.query.actor_id) ? req.query.actor_id : String(req.query.actor_id).split(',');
    const ids = raw.map((x) => x.trim()).filter(Boolean);
    if (ids.includes('system')) {
      const numericIds = ids.filter((x) => x !== 'system').map(Number).filter((n) => !isNaN(n));
      if (numericIds.length > 0) {
        whereConditions.push('(a.actor_type = "system" OR a.actor_user_id IN (?))');
        queryParams.push(numericIds);
      } else {
        whereConditions.push('a.actor_type = "system"');
      }
    } else {
      const numericIds = ids.map(Number).filter((n) => !isNaN(n));
      if (numericIds.length > 0) {
        whereConditions.push('a.actor_user_id IN (?)');
        queryParams.push(numericIds);
      }
    }
  }

  // Actor Role
  if (req.query.actor_role && req.query.actor_role !== 'all') {
    whereConditions.push('a.actor_role = ?');
    queryParams.push(String(req.query.actor_role).trim());
  }

  // Categories (multi-select)
  if (req.query.category && req.query.category !== 'all') {
    const cats = (Array.isArray(req.query.category) ? req.query.category : String(req.query.category).split(','))
      .map((c) => c.trim().toLowerCase())
      .filter(Boolean);
    if (cats.length > 0) {
      whereConditions.push('a.category IN (?)');
      queryParams.push(cats);
    }
  }

  // Actions (multi-select)
  if (req.query.action && req.query.action !== 'all') {
    const acts = (Array.isArray(req.query.action) ? req.query.action : String(req.query.action).split(','))
      .map((a) => a.trim())
      .filter(Boolean);
    if (acts.length > 0) {
      whereConditions.push('a.action IN (?)');
      queryParams.push(acts);
    }
  }

  // Entity Type & Entity ID
  if (req.query.entity_type && req.query.entity_type !== 'all') {
    whereConditions.push('a.entity_type = ?');
    queryParams.push(String(req.query.entity_type).trim());
  }
  if (req.query.entity_id) {
    whereConditions.push('a.entity_id = ?');
    queryParams.push(Number(req.query.entity_id));
  }

  // Board IDs (multi-select)
  if (req.query.board_id && req.query.board_id !== 'all') {
    const bRaw = Array.isArray(req.query.board_id) ? req.query.board_id : String(req.query.board_id).split(',');
    const bIds = bRaw.map(Number).filter((n) => !isNaN(n));
    if (bIds.length > 0) {
      whereConditions.push('a.board_id IN (?)');
      queryParams.push(bIds);
    }
  }

  // Card ID
  if (req.query.card_id) {
    whereConditions.push('a.card_id = ?');
    queryParams.push(Number(req.query.card_id));
  }

  // Target User ID
  if (req.query.target_user_id) {
    whereConditions.push('a.target_user_id = ?');
    queryParams.push(Number(req.query.target_user_id));
  }

  // Outcome
  if (req.query.outcome && req.query.outcome !== 'all') {
    whereConditions.push('a.outcome = ?');
    queryParams.push(String(req.query.outcome).trim());
  }

  // Severity
  if (req.query.severity && req.query.severity !== 'all') {
    whereConditions.push('a.severity = ?');
    queryParams.push(String(req.query.severity).trim());
  }

  // IP Address
  if (req.query.ip) {
    whereConditions.push('a.ip_address = ?');
    queryParams.push(String(req.query.ip).trim());
  }

  // Free-text Search (across actor name/email, entity label, action, changes, meta)
  if (req.query.q) {
    const searchWildcard = `%${String(req.query.q).trim()}%`;
    whereConditions.push(
      '(a.actor_name LIKE ? OR a.actor_email LIKE ? OR a.entity_label LIKE ? OR a.action LIKE ? OR CAST(a.changes AS CHAR) LIKE ? OR CAST(a.meta AS CHAR) LIKE ?)'
    );
    queryParams.push(searchWildcard, searchWildcard, searchWildcard, searchWildcard, searchWildcard, searchWildcard);
  }

  return {
    whereSql: whereConditions.join(' AND '),
    queryParams,
    wsTimezone
  };
}

/**
 * GET /api/workspaces/:id/audit-events
 */
async function getAuditEvents(req, res, next) {
  const workspaceId = Number(req.params.id);
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const sortDir = String(req.query.sort || 'desc').toLowerCase() === 'asc' ? 'ASC' : 'DESC';

  try {
    const { whereSql, queryParams, wsTimezone } = await buildAuditFilter(req, workspaceId);

    // Keyset pagination cursor
    let cursorClause = '';
    const cursorParams = [];
    if (req.query.cursor) {
      const decoded = decodeCursor(req.query.cursor);
      if (decoded && decoded.occurred_at && decoded.id) {
        if (sortDir === 'DESC') {
          cursorClause = ' AND (a.occurred_at < ? OR (a.occurred_at = ? AND a.id < ?))';
        } else {
          cursorClause = ' AND (a.occurred_at > ? OR (a.occurred_at = ? AND a.id > ?))';
        }
        cursorParams.push(decoded.occurred_at, decoded.occurred_at, Number(decoded.id));
      }
    }

    // 1. Total count query
    const countSql = `SELECT COUNT(*) as total FROM audit_events a WHERE ${whereSql}`;
    const [countRow] = await req.db.query(countSql, queryParams);
    const total = Number(countRow?.total || 0);

    // 2. Paginated rows query
    const selectSql = `
      SELECT
        a.id, a.event_uid, a.occurred_at, a.workspace_id, a.board_id, a.card_id,
        a.actor_user_id, a.actor_type, a.actor_name, a.actor_email, a.actor_role,
        a.ip_address, a.user_agent, a.request_id, a.session_id,
        a.action, a.category, a.entity_type, a.entity_id, a.entity_label,
        a.target_user_id, a.target_user_name, a.outcome, a.severity,
        a.changes, a.meta, a.source, a.prev_hash, a.row_hash
      FROM audit_events a
      WHERE ${whereSql} ${cursorClause}
      ORDER BY a.occurred_at ${sortDir}, a.id ${sortDir}
      LIMIT ?
    `;

    const rows = await req.db.query(selectSql, [...queryParams, ...cursorParams, limit]);

    // Format events
    const events = rows.map((r) => ({
      ...r,
      changes: parseJson(r.changes),
      meta: parseJson(r.meta)
    }));

    // Calculate next cursor
    let nextCursor = null;
    if (rows.length === limit) {
      const last = rows[rows.length - 1];
      nextCursor = encodeCursor({
        occurred_at: last.occurred_at instanceof Date ? last.occurred_at.toISOString().slice(0, 23).replace('T', ' ') : last.occurred_at,
        id: last.id
      });
    }

    // Throttled audit view access recording (at most once per session per hour)
    const sessionOrUserId = req.user?.sessionId || req.user?.id;
    if (typeof auditService.shouldLogAuditView === 'function' && auditService.shouldLogAuditView(workspaceId, sessionOrUserId)) {
      auditService.record({
        action: 'audit.page_viewed',
        category: 'audit',
        entityType: 'audit',
        entityId: workspaceId,
        entityLabel: `Workspace #${workspaceId} Audit Log`,
        workspaceId,
        outcome: 'success',
        severity: 'info',
        meta: {
          filters: req.query
        },
        db: req.db
      }).catch(() => {});
    }

    return res.json({
      events,
      pagination: {
        total,
        limit,
        count: events.length,
        has_more: Boolean(nextCursor),
        next_cursor: nextCursor
      },
      timezone: wsTimezone
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/workspaces/:id/audit-events/:eventId
 */
async function getAuditEventById(req, res, next) {
  const workspaceId = Number(req.params.id);
  const eventId = Number(req.params.eventId);

  try {
    const rows = await req.db.query(
      `SELECT * FROM audit_events WHERE id = ? AND workspace_id = ?`,
      [eventId, workspaceId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: { message: 'Audit event not found', code: 'NOT_FOUND' } });
    }

    const event = {
      ...rows[0],
      changes: parseJson(rows[0].changes),
      meta: parseJson(rows[0].meta)
    };

    return res.json({ event });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/workspaces/:id/audit-events/facets
 */
async function getAuditEventFacets(req, res, next) {
  const workspaceId = Number(req.params.id);

  try {
    // 1. Actors (including deactivated members and system)
    const actorsRows = await req.db.query(
      `SELECT DISTINCT
         u.id, u.name, u.email, u.avatar_url,
         COALESCE(r.name, wm.role) as role,
         (wm.status = 'deactivated') as is_deactivated
       FROM workspace_members wm
       JOIN users u ON wm.user_id = u.id
       LEFT JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ?
       ORDER BY u.name ASC`,
      [workspaceId]
    );

    const actors = [
      { id: 'system', name: 'System', role: 'System', is_deactivated: false },
      ...actorsRows.map((a) => ({
        id: a.id,
        name: a.name,
        email: a.email,
        avatar_url: a.avatar_url,
        role: a.role,
        is_deactivated: Boolean(a.is_deactivated)
      }))
    ];

    // 2. Categories with counts
    const catCounts = await req.db.query(
      `SELECT category, COUNT(*) as count FROM audit_events WHERE workspace_id = ? GROUP BY category ORDER BY count DESC`,
      [workspaceId]
    );

    // 3. Actions with counts
    const actionCounts = await req.db.query(
      `SELECT action, category, COUNT(*) as count FROM audit_events WHERE workspace_id = ? GROUP BY action, category ORDER BY count DESC`,
      [workspaceId]
    );

    // 4. Accessible boards
    const hasAccessAll = await userHasPermission(req.user.id, workspaceId, 'project.access_all', req.db);
    let boardsSql = 'SELECT id, name FROM boards WHERE workspace_id = ? AND is_archived = 0';
    const bParams = [workspaceId];
    if (!hasAccessAll) {
      const allowedBoardIds = await accessibleBoardIds(req.user.id, workspaceId, 'project.view', req.db);
      if (allowedBoardIds.length > 0) {
        boardsSql += ' AND id IN (?)';
        bParams.push(allowedBoardIds);
      } else {
        boardsSql += ' AND 1=0';
      }
    }
    boardsSql += ' ORDER BY name ASC';
    const boards = await req.db.query(boardsSql, bParams);

    return res.json({
      actors,
      categories: catCounts,
      actions: actionCounts,
      boards
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/workspaces/:id/audit-events/export?format=csv|json
 */
async function exportAuditEvents(req, res, next) {
  const workspaceId = Number(req.params.id);
  const format = String(req.query.format || 'csv').toLowerCase();

  try {
    const { whereSql, queryParams, wsTimezone } = await buildAuditFilter(req, workspaceId);

    // Enforce export limit of 50,000 rows (Item 6)
    const countSql = `SELECT COUNT(*) as total FROM audit_events a WHERE ${whereSql}`;
    const countRes = await req.db.query(countSql, queryParams);
    const totalMatching = Number(countRes[0]?.total || 0);

    if (totalMatching > 50000) {
      return res.status(400).json({
        error: {
          message: `Export query matches ${totalMatching.toLocaleString()} records, exceeding the maximum allowed limit of 50,000. Please narrow your date range or apply filters before exporting.`,
          code: 'EXPORT_LIMIT_EXCEEDED',
          total: totalMatching,
          limit: 50000
        }
      });
    }

    const selectSql = `
      SELECT
        a.id, a.event_uid, a.occurred_at, a.actor_user_id, a.actor_name, a.actor_email, a.actor_role,
        a.action, a.category, a.entity_type, a.entity_id, a.entity_label,
        a.target_user_id, a.target_user_name, a.outcome, a.severity,
        a.ip_address, a.user_agent, a.request_id, a.session_id,
        a.changes, a.meta, a.row_hash
      FROM audit_events a
      WHERE ${whereSql}
      ORDER BY a.occurred_at DESC, a.id DESC
      LIMIT 50000
    `;

    const rows = await req.db.query(selectSql, queryParams);

    // Log the export audit event
    await auditService.record({
      action: 'audit.exported',
      category: 'export',
      entityType: 'audit',
      entityId: workspaceId,
      entityLabel: `Workspace #${workspaceId} Audit Export (${format.toUpperCase()})`,
      workspaceId,
      outcome: 'success',
      severity: 'notice',
      meta: {
        format,
        row_count: rows.length,
        filters: req.query
      },
      db: req.db
    }).catch(() => {});

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="audit-export-ws-${workspaceId}.json"`);
      const parsedRows = rows.map((r) => ({
        ...r,
        changes: parseJson(r.changes),
        meta: parseJson(r.meta)
      }));
      return res.json({
        workspace_id: workspaceId,
        exported_at: new Date().toISOString(),
        row_count: rows.length,
        filters: req.query,
        events: parsedRows
      });
    }

    // CSV format with header block listing active filters & formula-injection protection
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="audit-export-ws-${workspaceId}.csv"`);

    const filterSummaryLines = [
      `# TASKFLOW AUDIT LOG EXPORT`,
      `# Workspace ID: ${workspaceId}`,
      `# Exported At: ${new Date().toISOString()} (UTC)`,
      `# Workspace Timezone: ${wsTimezone}`,
      `# Total Records: ${rows.length}`,
      `# Applied Filters: ${JSON.stringify(req.query)}`,
      `# -------------------------------------------------------------`
    ].join('\n') + '\n';

    const csvHeaders = [
      'id', 'event_uid', 'occurred_at', 'actor_name', 'actor_email', 'actor_role',
      'action', 'category', 'entity_type', 'entity_id', 'entity_label',
      'target_user_name', 'outcome', 'severity', 'ip_address', 'request_id', 'session_id', 'row_hash'
    ];

    const headerLine = csvHeaders.join(',') + '\n';
    const csvRows = rows.map((r) => {
      return [
        r.id,
        sanitizeCsvCell(r.event_uid),
        sanitizeCsvCell(r.occurred_at),
        sanitizeCsvCell(r.actor_name),
        sanitizeCsvCell(r.actor_email),
        sanitizeCsvCell(r.actor_role),
        sanitizeCsvCell(r.action),
        sanitizeCsvCell(r.category),
        sanitizeCsvCell(r.entity_type),
        r.entity_id || '',
        sanitizeCsvCell(r.entity_label),
        sanitizeCsvCell(r.target_user_name),
        sanitizeCsvCell(r.outcome),
        sanitizeCsvCell(r.severity),
        sanitizeCsvCell(r.ip_address),
        sanitizeCsvCell(r.request_id),
        sanitizeCsvCell(r.session_id),
        sanitizeCsvCell(r.row_hash)
      ].join(',');
    }).join('\n');

    return res.send(filterSummaryLines + headerLine + csvRows);
  } catch (err) {
    next(err);
  }
}

const fs = require('fs');
const path = require('path');

/**
 * POST /api/workspaces/:id/audit-events/verify
 * Cryptographic HMAC-SHA256 hash-chain integrity verification.
 * Verifies finalized rows, reports pending unfinalized rows, compares against external anchor,
 * and reports append-only trigger status.
 */
async function verifyAuditIntegrity(req, res, next) {
  const workspaceId = Number(req.params.id);

  try {
    // Always finalize pending rows in chain before verifying integrity
    await auditService.finalizeAuditChain(req.db);

    const rows = await req.db.query(
      `SELECT
         id, event_uid, occurred_at, workspace_id, board_id, card_id,
         actor_user_id, actor_type, action, category, entity_type, entity_id,
         outcome, severity, changes, meta, source, key_id, prev_hash, row_hash
       FROM audit_events
       ORDER BY id ASC`
    );

    const finalizedRows = [];
    const pendingRows = [];

    for (const r of rows) {
      if (r.row_hash === null || r.row_hash === undefined) {
        pendingRows.push(r);
      } else {
        finalizedRows.push(r);
      }
    }

    let prevHash = '0'.repeat(64);
    let verifiedCount = 0;
    let brokenEventId = null;
    let failureReason = null;

    for (const r of finalizedRows) {
      // 1. Check prev_hash matches chain
      if (r.prev_hash !== prevHash) {
        brokenEventId = r.id;
        failureReason = `Broken prev_hash chain link at event #${r.id}. Expected ${prevHash}, got ${r.prev_hash}`;
        break;
      }

      // 2. Canonical serialization
      const occurredAtSql = r.occurred_at instanceof Date
        ? r.occurred_at.toISOString().slice(0, 23).replace('T', ' ')
        : String(r.occurred_at).slice(0, 23).replace('T', ' ');

      const canonicalPayload = auditService.canonicalizeJson({
        event_uid: r.event_uid,
        occurred_at: occurredAtSql,
        workspace_id: r.workspace_id,
        board_id: r.board_id,
        card_id: r.card_id,
        actor_user_id: r.actor_user_id,
        actor_type: r.actor_type,
        action: r.action,
        category: r.category,
        entity_type: r.entity_type,
        entity_id: r.entity_id,
        outcome: r.outcome,
        severity: r.severity,
        changes: parseJson(r.changes),
        meta: parseJson(r.meta),
        source: r.source
      });

      // 3. Recompute HMAC-SHA256 with key for row's key_id
      const hmacKey = auditService.getHmacKey(r.key_id);
      const expectedHash = crypto
        .createHmac('sha256', hmacKey)
        .update(canonicalPayload + ':' + prevHash)
        .digest('hex');

      if (r.row_hash !== expectedHash) {
        brokenEventId = r.id;
        failureReason = `Cryptographic row_hash mismatch at event #${r.id}. Hash has been modified or corrupted.`;
        break;
      }

      prevHash = r.row_hash;
      verifiedCount++;
    }

    const isValid = brokenEventId === null;

    // Check Trigger Status (Item 5)
    let triggersInstalled = false;
    let triggerStatus = 'warning';
    let triggerWarning = null;
    try {
      const statusRows = await req.db.query(
        "SELECT setting_value FROM audit_system_status WHERE setting_key = 'append_only_triggers'"
      );
      if (statusRows.length > 0 && statusRows[0].setting_value.includes('installed: active')) {
        triggersInstalled = true;
        triggerStatus = 'active';
      } else {
        triggerWarning = statusRows[0]?.setting_value || 'Append-only triggers not installed on database';
      }
    } catch (_) {
      triggerWarning = 'audit_system_status table not accessible';
    }

    // Check Anchor Status (Item 3)
    let anchorMatch = null;
    let anchorStatus = 'none';
    let anchorWarning = null;
    let lastAnchor = null;

    const tenantSlug = req.tenant?.slug || 'apollo';
    const anchorFilePath = path.resolve(__dirname, '../../anchors', `${tenantSlug}-anchor.json`);
    if (fs.existsSync(anchorFilePath)) {
      try {
        lastAnchor = JSON.parse(fs.readFileSync(anchorFilePath, 'utf8'));
        if (lastAnchor && lastAnchor.last_event_id) {
          const anchoredRow = finalizedRows.find((r) => r.id === lastAnchor.last_event_id);
          if (!anchoredRow) {
            anchorMatch = false;
            anchorStatus = 'mismatch';
            anchorWarning = `Anchor mismatch: Event #${lastAnchor.last_event_id} recorded in anchor was not found in audit chain`;
          } else if (anchoredRow.row_hash !== lastAnchor.last_row_hash) {
            anchorMatch = false;
            anchorStatus = 'mismatch';
            anchorWarning = `Anchor mismatch: Event #${lastAnchor.last_event_id} hash ${anchoredRow.row_hash} does not match anchored hash ${lastAnchor.last_row_hash}`;
          } else {
            anchorMatch = true;
            anchorStatus = 'matched';
          }
        }
      } catch (ancErr) {
        anchorWarning = `Could not read anchor file: ${ancErr.message}`;
      }
    }

    // Log the verification attempt
    await auditService.record({
      action: 'audit.verified',
      category: 'audit',
      entityType: 'audit',
      entityId: workspaceId,
      entityLabel: `Audit Integrity Check (${isValid ? 'Passed' : 'Failed'})`,
      workspaceId,
      outcome: isValid ? 'success' : 'failed',
      severity: isValid ? 'info' : 'critical',
      meta: {
        valid: isValid,
        verified_rows: verifiedCount,
        pending_rows: pendingRows.length,
        broken_event_id: brokenEventId,
        failure_reason: failureReason,
        triggers_installed: triggersInstalled,
        anchor_match: anchorMatch
      },
      db: req.db
    }).catch(() => {});

    return res.json({
      valid: isValid,
      verified: isValid,
      verified_rows: verifiedCount,
      pending_rows: pendingRows.length,
      event_count: verifiedCount + pendingRows.length,
      broken_event_id: brokenEventId,
      failing_event_id: brokenEventId,
      triggers_installed: triggersInstalled,
      trigger_status: triggerStatus,
      trigger_warning: triggerWarning,
      anchor_match: anchorMatch,
      anchor_status: anchorStatus,
      anchor_warning: anchorWarning,
      last_anchor: lastAnchor,
      message: isValid
        ? `Cryptographic hash chain intact. Verified ${verifiedCount} audit events (${pendingRows.length} pending finalization).`
        : failureReason
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getAuditEvents,
  getAuditEventById,
  getAuditEventFacets,
  exportAuditEvents,
  verifyAuditIntegrity,
  parseDateRangeToUtc,
  sanitizeCsvCell
};

// server/src/services/authAudit.js
// Per-tenant audit logger for authentication and security events.

const { getClientIp } = require('../middleware/rateLimit');
const auditService = require('./audit');

async function logAuthEvent(db, {
  userId = null,
  email = null,
  eventType,
  req = null,
  metadata = null,
  outcome = null,
  severity = null
}) {
  if (!db || !eventType) return;

  try {
    const ipAddress = req ? getClientIp(req) : null;
    const userAgent = req ? (req.headers['user-agent'] || null) : null;
    const metaObj = { ...(metadata || {}), email: email || null, ip_address: ipAddress, user_agent: userAgent };
    const metaJson = JSON.stringify(metaObj);

    await db.execute(
      `INSERT INTO auth_audit_log (user_id, email, event_type, ip_address, user_agent, metadata)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [userId ? Number(userId) : null, email || null, eventType, ipAddress, userAgent, metaJson]
    );

    const evLower = String(eventType).toLowerCase();
    const isFailure = evLower.includes('fail') || evLower.includes('lockout');
    const computedOutcome = outcome || (isFailure ? 'failed' : 'success');
    const computedSeverity = severity || (isFailure ? 'warning' : 'info');

    let dotAction = eventType;
    if (eventType === 'LOGIN_SUCCESS') dotAction = 'auth.login_success';
    else if (eventType === 'LOGIN_FAILURE') dotAction = 'auth.login_failed';
    else if (eventType === 'ACCOUNT_LOCKED') dotAction = 'auth.lockout';
    else if (eventType === 'ACCOUNT_LOCKED_ATTEMPT') dotAction = 'auth.lockout';
    else if (eventType === 'LOGOUT') dotAction = 'auth.logout';
    else if (eventType === 'PASSWORD_CHANGED') dotAction = 'auth.password_changed';
    else if (eventType === 'TWO_FA_ENABLED') dotAction = 'auth.two_fa_enabled';
    else if (eventType === 'TWO_FA_DISABLED') dotAction = 'auth.two_fa_disabled';
    else if (eventType === 'TWO_FA_RESET') dotAction = 'auth.two_fa_reset';
    else if (!dotAction.startsWith('auth.')) dotAction = `auth.${evLower}`;

    // Mirror to audit_events and activity_log via unified audit service
    await auditService.record({
      action: dotAction,
      category: 'auth',
      entityType: 'user',
      entityId: userId ? Number(userId) : null,
      entityLabel: email || (metadata?.name || null),
      actorUserId: userId ? Number(userId) : null,
      actorEmail: email || null,
      ipAddress,
      userAgent,
      outcome: computedOutcome,
      severity: computedSeverity,
      meta: metaObj,
      activityAction: eventType,
      activityMeta: metaObj,
      db
    });
  } catch (err) {
    console.error(`[AUDIT_ERROR] Failed to record auth audit event "${eventType}":`, err.message);
    throw err;
  }
}

module.exports = {
  logAuthEvent
};

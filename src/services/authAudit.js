// server/src/services/authAudit.js
// Per-tenant audit logger for authentication and security events.

const { getClientIp } = require('../middleware/rateLimit');

async function logAuthEvent(db, {
  userId = null,
  email = null,
  eventType,
  req = null,
  metadata = null
}) {
  if (!db || !eventType) return;

  try {
    const ipAddress = req ? getClientIp(req) : null;
    const userAgent = req ? (req.headers['user-agent'] || null) : null;
    const metaJson = metadata ? JSON.stringify(metadata) : null;

    await db.execute(
      `INSERT INTO auth_audit_log (user_id, email, event_type, ip_address, user_agent, metadata)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [userId ? Number(userId) : null, email || null, eventType, ipAddress, userAgent, metaJson]
    );
  } catch (err) {
    console.error(`[AUDIT_ERROR] Failed to record auth audit event "${eventType}":`, err.message);
  }
}

module.exports = {
  logAuthEvent
};

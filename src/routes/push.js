// server/src/routes/push.js
// REST endpoints for Web Push notification device subscriptions and tests.

const express = require('express');
const crypto = require('crypto');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/permissions');
const { sendTestNotification, isPushEnabled } = require('../services/pushService');
const { record: recordAudit } = require('../services/audit');

const router = express.Router();

// Rate limiter for test push notifications: max 3 requests per minute per user
const testRateLimitMap = new Map();

function checkTestRateLimit(userId) {
  const now = Date.now();
  const windowMs = 60000;
  const maxRequests = 3;
  const uId = Number(userId);

  const timestamps = (testRateLimitMap.get(uId) || []).filter((t) => now - t < windowMs);
  if (timestamps.length >= maxRequests) {
    return false;
  }
  timestamps.push(now);
  testRateLimitMap.set(uId, timestamps);
  return true;
}

// POST /api/push/subscriptions
// Upsert by token_hash: if token belongs to another user it moves to the caller.
router.post('/subscriptions', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  const { device_id, token, platform, browser, os, user_agent, label } = req.body;

  if (!device_id || typeof device_id !== 'string' || !device_id.trim()) {
    return res.status(400).json({ error: { message: 'device_id is required', code: 'BAD_REQUEST' } });
  }

  if (!token || typeof token !== 'string' || !token.trim()) {
    return res.status(400).json({ error: { message: 'FCM push registration token is required', code: 'BAD_REQUEST' } });
  }

  const effectiveDeviceId = device_id.trim();
  const tokenHash = crypto.createHash('sha256').update(token.trim()).digest('hex');

  try {
    const insertQuery = `
      INSERT INTO push_subscriptions (
        user_id, device_id, token, token_hash, platform, browser, os, user_agent, label,
        is_active, last_seen_at, failure_count
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?,
        1, NOW(3), 0
      )
      ON DUPLICATE KEY UPDATE
        id = LAST_INSERT_ID(id),
        user_id = VALUES(user_id),
        device_id = VALUES(device_id),
        token = VALUES(token),
        platform = VALUES(platform),
        browser = VALUES(browser),
        os = VALUES(os),
        user_agent = VALUES(user_agent),
        label = VALUES(label),
        is_active = 1,
        revoked_at = NULL,
        last_seen_at = NOW(3),
        failure_count = 0
    `;

    const result = await req.db.execute(insertQuery, [
      req.user.id,
      effectiveDeviceId,
      token.trim(),
      tokenHash,
      platform || null,
      browser || null,
      os || null,
      (user_agent || req.headers['user-agent'] || '').slice(0, 500),
      label || null
    ]);

    let subId = result.insertId;
    if (!subId) {
      const existing = await req.db.query('SELECT id FROM push_subscriptions WHERE token_hash = ? LIMIT 1', [tokenHash]);
      if (existing && existing.length > 0) subId = existing[0].id;
    }

    // Record audit event
    try {
      await recordAudit({
        db: req.db,
        action: 'push.subscription_created',
        category: 'settings',
        entityType: 'push_subscription',
        entityId: subId || null,
        entityLabel: label || browser || 'Web Browser',
        actorUserId: req.user.id,
        meta: {
          device_id: effectiveDeviceId,
          browser,
          os,
          platform
        }
      });
    } catch (_) {}

    const subObj = {
      id: subId,
      device_id: effectiveDeviceId,
      token_hash: tokenHash,
      platform,
      browser,
      os,
      label,
      is_active: true
    };

    const isNew = result.affectedRows === 1;
    return res.status(isNew ? 201 : 200).json({
      message: isNew ? 'Push subscription registered successfully' : 'Push subscription updated successfully',
      subscription: subObj,
      device: subObj
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/push/subscriptions (List my active devices)
router.get('/subscriptions', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  try {
    const rows = await req.db.query(
      `SELECT id, device_id, platform, browser, os, user_agent, label, created_at, last_seen_at, last_success_at, is_active
       FROM push_subscriptions
       WHERE user_id = ? AND is_active = 1
       ORDER BY last_seen_at DESC`,
      [req.user.id]
    );

    return res.json({
      subscriptions: rows,
      devices: rows,
      push_configured: isPushEnabled()
    });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/push/subscriptions/current (Revoke current device subscription on logout)
router.delete('/subscriptions/current', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  const deviceId = req.query.device_id || req.body?.device_id || null;
  const token = req.query.token || req.body?.token || null;
  const tokenHash = token ? crypto.createHash('sha256').update(token).digest('hex') : (req.query.token_hash || req.body?.token_hash || null);

  if (!deviceId && !tokenHash) {
    return res.status(400).json({ error: { message: 'device_id or token is required to revoke current device', code: 'BAD_REQUEST' } });
  }

  try {
    let result;
    if (tokenHash) {
      result = await req.db.execute(
        `UPDATE push_subscriptions
         SET is_active = 0, revoked_at = NOW(3)
         WHERE token_hash = ? AND user_id = ?`,
        [tokenHash, req.user.id]
      );
    } else {
      result = await req.db.execute(
        `UPDATE push_subscriptions
         SET is_active = 0, revoked_at = NOW(3)
         WHERE device_id = ? AND user_id = ?`,
        [deviceId, req.user.id]
      );
    }

    try {
      await recordAudit({
        db: req.db,
        action: 'push.subscription_revoked',
        category: 'settings',
        entityType: 'push_subscription',
        entityLabel: 'Current Device',
        actorUserId: req.user.id,
        meta: { device_id: deviceId }
      });
    } catch (_) {}

    return res.json({ message: 'Current device subscription revoked successfully', revoked: result.affectedRows > 0 });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/push/subscriptions/:id (Revoke specific device)
router.delete('/subscriptions/:id', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  const subscriptionId = Number(req.params.id);

  try {
    // IDOR check: subscription MUST belong to caller
    const rows = await req.db.query(
      'SELECT id, device_id, browser, os FROM push_subscriptions WHERE id = ? AND user_id = ?',
      [subscriptionId, req.user.id]
    );

    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: { message: 'Device subscription not found', code: 'NOT_FOUND' } });
    }

    await req.db.execute(
      `UPDATE push_subscriptions
       SET is_active = 0, revoked_at = NOW(3)
       WHERE id = ? AND user_id = ?`,
      [subscriptionId, req.user.id]
    );

    try {
      await recordAudit({
        db: req.db,
        action: 'push.subscription_revoked',
        category: 'settings',
        entityType: 'push_subscription',
        entityId: subscriptionId,
        entityLabel: rows[0].browser || 'Device',
        actorUserId: req.user.id,
        meta: { device_id: rows[0].device_id }
      });
    } catch (_) {}

    return res.json({ message: 'Device subscription revoked successfully' });
  } catch (err) {
    next(err);
  }
});

// POST /api/push/test (Send test notification to caller's devices; 3/min limit)
router.post('/test', requireAuth, requirePermission('notification.manage_own'), async (req, res, next) => {
  if (!checkTestRateLimit(req.user.id)) {
    return res.status(429).json({
      error: {
        message: 'Too many test requests. Maximum 3 test notifications per minute allowed.',
        code: 'RATE_LIMIT_EXCEEDED'
      }
    });
  }

  try {
    const outcome = await sendTestNotification(req.db, req.user.id);

    try {
      await recordAudit({
        db: req.db,
        action: 'push.test_sent',
        category: 'settings',
        entityType: 'push_subscription',
        actorUserId: req.user.id,
        meta: { sentCount: outcome.sent }
      });
    } catch (_) {}

    return res.json({
      message: outcome.sent > 0 ? 'Test notification sent successfully' : (outcome.message || 'No active device received test notification'),
      sent: outcome.sent
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

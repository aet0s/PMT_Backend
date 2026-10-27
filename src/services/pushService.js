// server/src/services/pushService.js
// Firebase Cloud Messaging (FCM HTTP v1 API) Web Push delivery service.
// Supports lazy single initialization, token masking, suppression on user active,
// burst coalescing, hourly rate limits, backoff retries, and lifecycle token deactivation.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { NOTIFICATION_EVENTS } = require('./notificationEvents');
const { isEventEnabledForUser } = require('./notificationPreferences');
const { isUserActive } = require('../socket');

let firebaseAdminInstance = null;
let isInitialized = false;
let initFailed = false;

// Metrics counters (at info level, zero personal data)
const metrics = {
  sent: 0,
  failed: 0,
  skipped: {
    disabled: 0,
    user_active: 0,
    preference_disabled: 0,
    coalesced_burst: 0,
    hourly_cap_exceeded: 0,
    no_active_subscriptions: 0
  },
  tokensInvalidated: 0
};

// Burst coalescing cache: `${userId}:${cardId}` -> { count, firstAt, lastAt }
const burstCache = new Map();

// Hourly push counter cache: userId -> Array of timestamps
const hourlyPushCache = new Map();

function maskToken(token) {
  if (!token || typeof token !== 'string') return '***';
  return token.length > 10 ? `${token.slice(0, 6)}...${token.slice(-4)}` : '***';
}

function isPushConfigured() {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const hasPath = !!(process.env.FIREBASE_SERVICE_ACCOUNT_KEY_PATH || process.env.FIREBASE_SERVICE_ACCOUNT_PATH);
  const hasB64 = !!(process.env.FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 || process.env.FIREBASE_SERVICE_ACCOUNT_JSON_B64);
  return Boolean(projectId && (hasPath || hasB64));
}

function isPushEnabled() {
  const flag = process.env.PUSH_ENABLED;
  const isFlagOn = flag === 'true' || flag === '1';
  return isFlagOn && isPushConfigured();
}

/**
 * Lazy single initialization of Firebase Admin SDK
 */
function getFirebaseAdmin() {
  if (!isPushEnabled()) {
    return null;
  }
  if (isInitialized) {
    return firebaseAdminInstance;
  }
  if (initFailed) {
    return null;
  }

  try {
    const admin = require('firebase-admin');
    let serviceAccount = null;

    const b64Val = process.env.FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 || process.env.FIREBASE_SERVICE_ACCOUNT_JSON_B64;
    const pathVal = process.env.FIREBASE_SERVICE_ACCOUNT_KEY_PATH || process.env.FIREBASE_SERVICE_ACCOUNT_PATH;

    if (b64Val) {
      try {
        const decoded = Buffer.from(b64Val, 'base64').toString('utf8');
        serviceAccount = JSON.parse(decoded);
      } catch (decodeErr) {
        console.error('[PUSH] Failed to parse base64 service account JSON:', decodeErr.message);
        initFailed = true;
        return null;
      }
    } else if (pathVal) {
      const saPath = path.resolve(pathVal);
      if (fs.existsSync(saPath)) {
        try {
          const raw = fs.readFileSync(saPath, 'utf8');
          serviceAccount = JSON.parse(raw);
        } catch (readErr) {
          console.error(`[PUSH] Failed to read service account file at ${saPath}:`, readErr.message);
          initFailed = true;
          return null;
        }
      } else {
        console.error(`[PUSH] Service account file not found at ${saPath}`);
        initFailed = true;
        return null;
      }
    }

    if (!serviceAccount) {
      initFailed = true;
      return null;
    }

    let adminApp;
    let certFn;
    try {
      const appMod = require('firebase-admin/app');
      const apps = appMod.getApps ? appMod.getApps() : [];
      if (apps.length > 0) {
        firebaseAdminInstance = apps[0];
        isInitialized = true;
        return firebaseAdminInstance;
      }
      certFn = appMod.cert;
      adminApp = appMod.initializeApp;
    } catch {
      const legacyAdmin = require('firebase-admin');
      if (legacyAdmin.apps && legacyAdmin.apps.length > 0) {
        firebaseAdminInstance = legacyAdmin.apps[0];
        isInitialized = true;
        return firebaseAdminInstance;
      }
      certFn = legacyAdmin.cert || (legacyAdmin.credential && legacyAdmin.credential.cert);
      adminApp = legacyAdmin.initializeApp;
    }

    firebaseAdminInstance = adminApp({
      credential: certFn ? certFn(serviceAccount) : undefined,
      projectId: process.env.FIREBASE_PROJECT_ID || serviceAccount.project_id
    });

    isInitialized = true;
    console.log('[PUSH] Firebase Admin successfully initialized for project:', process.env.FIREBASE_PROJECT_ID || serviceAccount.project_id);
    return firebaseAdminInstance;
  } catch (err) {
    console.error('[PUSH] Failed to initialize Firebase Admin:', err.message);
    initFailed = true;
    return null;
  }
}

/**
 * Maps eventType to readable summary title
 */
function getEventSummaryTitle(eventType) {
  const titleMap = {
    'card.assigned': 'Task Assigned',
    'card.unassigned': 'Task Unassigned',
    'comment.mention': 'Mentioned in Comment',
    'comment.added': 'New Comment',
    'card.due_soon': 'Task Due Soon',
    'card.overdue': 'Task Overdue',
    'checkin.due': 'Daily Check-in Reminder',
    'card.submitted_for_review': 'Review Requested',
    'card.changes_requested': 'Changes Requested',
    'board.member_added': 'Added to Board',
    'board.member_removed': 'Removed from Board',
    'board.created': 'New Board Created',
    'board.archived': 'Board Archived',
    'board.deleted': 'Board Deleted',
    'workspace.member_added': 'Added to Workspace',
    'workspace.member_removed': 'Removed from Workspace',
    'workspace.member_role_changed': 'Role Updated',
    'card.completed': 'Task Completed',
    'card.archived': 'Task Archived',
    'card.deleted': 'Task Deleted'
  };
  return titleMap[eventType] || 'TaskFlow Notification';
}

/**
 * Builds FCM Web Push payload with privacy, TTL, tag, and deep links
 */
function buildPushPayload({ notification = {}, eventType, message, meta = {}, ctx = {}, pushShowDetails = true, showDetails }) {
  const notifId = notification?.id ? String(notification.id) : '';
  const cardId = ctx.cardId || meta.cardId || notification?.card_id || notification?.cardId || null;
  const boardId = ctx.boardId || meta.boardId || notification?.board_id || notification?.boardId || null;
  const workspaceId = ctx.workspaceId || meta.workspaceId || notification?.workspace_id || notification?.workspaceId || null;

  // 1. Deep link URL
  let targetUrl = '/';
  if (workspaceId && boardId) {
    targetUrl = `/w/${workspaceId}/b/${boardId}${cardId ? `?card=${cardId}` : ''}`;
  } else if (boardId) {
    targetUrl = `/b/${boardId}${cardId ? `?card=${cardId}` : ''}`;
  } else if (workspaceId) {
    targetUrl = `/w/${workspaceId}`;
  }

  // 2. Title & Body with pushShowDetails privacy enforcement
  const detailsEnabled = showDetails !== undefined ? Boolean(showDetails) : pushShowDetails !== false;
  let title = 'Task Flow Update';
  let body = 'You have a new update in Task Flow';

  if (detailsEnabled) {
    title = getEventSummaryTitle(eventType);
    const rawBody = message || notification?.message || 'You have a new update';
    // Truncate body to maximum 120 characters
    body = rawBody.length > 120 ? `${rawBody.slice(0, 117)}...` : rawBody;
  }

  // 3. TTL calculation (4h for due_soon/overdue; 24h default)
  let ttlSeconds = 86400; // 24 hours
  if (eventType === 'card.due_soon' || eventType === 'card.overdue') {
    ttlSeconds = 14400; // 4 hours
  }

  // 4. Tag for collapsing per card and event type
  const tag = cardId ? `card-${cardId}-${eventType}` : `board-${boardId || 'gen'}-${eventType}`;

  return {
    notification: {
      title,
      body
    },
    data: {
      url: targetUrl,
      notification_id: notifId,
      event_type: String(eventType || '')
    },
    webpush: {
      headers: {
        TTL: String(ttlSeconds),
        Urgency: eventType === 'comment.mention' || eventType === 'card.assigned' ? 'high' : 'normal'
      },
      notification: {
        title,
        body,
        icon: '/icons/icon-192.png',
        badge: '/icons/icon-192.png',
        tag,
        data: {
          url: targetUrl,
          notification_id: notifId,
          event_type: String(eventType || '')
        }
      },
      fcm_options: {
        link: targetUrl
      }
    }
  };
}

/**
 * Checks and updates hourly rate limit (max 20 per hour; mentions & assignments exempt)
 */
function checkHourlyRateLimit(userId, eventType) {
  // Mentions and assignments are exempt from hourly push cap
  if (eventType === 'comment.mention' || eventType === 'card.assigned' || eventType === 'card.unassigned') {
    return true;
  }

  const cap = Number(process.env.PUSH_HOURLY_CAP || 20);
  const now = Date.now();
  const oneHourAgo = now - 3600000;

  const timestamps = (hourlyPushCache.get(Number(userId)) || []).filter((ts) => ts > oneHourAgo);
  if (timestamps.length >= cap) {
    return false;
  }

  timestamps.push(now);
  hourlyPushCache.set(Number(userId), timestamps);
  return true;
}

/**
 * Checks burst coalescing: at most 1 push per user per card per 60s
 * Returns { shouldSend: boolean, coalescedMessage?: string }
 */
function checkBurstCoalescing(userId, cardId, defaultMessage) {
  if (!cardId) return { shouldSend: true };

  const key = `${userId}:${cardId}`;
  const now = Date.now();
  const existing = burstCache.get(key);

  if (existing && now - existing.lastAt < 60000) {
    existing.count++;
    existing.lastAt = now;
    return {
      shouldSend: false,
      coalescedMessage: `${existing.count} new updates on card`
    };
  }

  burstCache.set(key, { count: 1, firstAt: now, lastAt: now });
  return { shouldSend: true };
}

function calculateNextBackoff(retryCount) {
  const schedule = [60, 300, 1800, 1800, 1800];
  if (retryCount >= 5) return null;
  return schedule[retryCount] || 1800;
}

/**
 * Sends a single FCM message to a subscription token with error handling & backoff
 */
async function sendToSubscription(db, subscription, payload, notificationId = null) {
  if (!subscription || subscription.is_active === 0 || subscription.is_active === false) {
    return { success: false, skipped: true, reason: 'inactive_subscription' };
  }

  const admin = getFirebaseAdmin();
  if (!admin) {
    return { success: false, reason: 'admin_unavailable' };
  }

  const token = subscription.token;
  const message = {
    token,
    notification: payload.notification,
    data: payload.data,
    webpush: payload.webpush
  };

  try {
    let messaging;
    try {
      const { getMessaging } = require('firebase-admin/messaging');
      messaging = getMessaging(admin);
    } catch {
      messaging = typeof admin.messaging === 'function' ? admin.messaging() : admin.messaging;
    }
    await messaging.send(message);

    metrics.sent++;
    // Update subscription success metrics
    await db.execute(
      `UPDATE push_subscriptions
       SET last_seen_at = NOW(3), last_success_at = NOW(3), failure_count = 0, last_error_code = NULL
       WHERE id = ?`,
      [subscription.id]
    );

    // Record delivery
    await db.execute(
      `INSERT INTO push_deliveries (notification_id, subscription_id, status, sent_at)
       VALUES (?, ?, 'sent', NOW(3))`,
      [notificationId || null, subscription.id]
    );

    return { success: true };
  } catch (err) {
    metrics.failed++;
    const errorCode = err.code || err.message || 'UNKNOWN_ERROR';
    console.warn(`[PUSH_ERROR] Delivery failed for subscription ${subscription.id} (token ${maskToken(token)}):`, errorCode);

    // Unregistered / invalid token handling: mark token inactive
    const isUnregistered =
      errorCode === 'messaging/registration-token-not-registered' ||
      errorCode === 'messaging/invalid-registration-token' ||
      errorCode === 'UNREGISTERED' ||
      errorCode === 'NOT_FOUND' ||
      errorCode === 'INVALID_ARGUMENT';

    if (isUnregistered) {
      metrics.tokensInvalidated++;
      await db.execute(
        `UPDATE push_subscriptions
         SET is_active = 0, revoked_at = NOW(3), last_error_at = NOW(3), last_error_code = ?
         WHERE id = ?`,
        [String(errorCode).slice(0, 100), subscription.id]
      );

      await db.execute(
        `INSERT INTO push_deliveries (notification_id, subscription_id, status, reason, error_code, sent_at)
         VALUES (?, ?, 'failed', 'token_unregistered', ?, NOW(3))`,
        [notificationId || null, subscription.id, String(errorCode).slice(0, 100)]
      );

      return { success: false, unregistered: true, errorCode };
    }

    // Transient error handling
    await db.execute(
      `UPDATE push_subscriptions
       SET failure_count = failure_count + 1, last_error_at = NOW(3), last_error_code = ?
       WHERE id = ?`,
      [String(errorCode).slice(0, 100), subscription.id]
    );

    await db.execute(
      `INSERT INTO push_deliveries (notification_id, subscription_id, status, reason, error_code, sent_at)
       VALUES (?, ?, 'failed', 'delivery_error', ?, NOW(3))`,
      [notificationId || null, subscription.id, String(errorCode).slice(0, 100)]
    );

    return { success: false, retryable: true, errorCode };
  }
}

/**
 * Main push delivery dispatcher: checks user active status, preferences, coalescing,
 * caps, and delivers to all active devices.
 */
async function sendPushNotification(db, { notification, recipientId, eventType, message, meta = {}, ctx = {}, actorName = 'Someone', tenantId = 'single' }) {
  if (!db || !recipientId) return { skipped: true };

  // 1. Silent fallback if push is disabled or unconfigured
  if (!isPushEnabled()) {
    metrics.skipped.disabled++;
    return { skipped: true, reason: 'push_disabled' };
  }

  // 2. Active User Suppression: clients send visibility heartbeat; if active in last 60s, skip push
  if (isUserActive(recipientId, 60)) {
    metrics.skipped.user_active++;
    try {
      await db.execute(
        `INSERT INTO push_deliveries (notification_id, subscription_id, status, reason, sent_at)
         SELECT ?, id, 'skipped', 'user_active', NOW(3)
         FROM push_subscriptions WHERE user_id = ? AND is_active = 1 LIMIT 1`,
        [notification?.id || null, recipientId]
      );
    } catch (_) {}
    return { skipped: true, reason: 'user_active' };
  }

  // 3. User push preference check
  const isEnabled = await isEventEnabledForUser(recipientId, eventType, 'push', db);
  if (!isEnabled) {
    metrics.skipped.preference_disabled++;
    return { skipped: true, reason: 'preference_disabled' };
  }

  // 4. Burst coalescing check
  const cardId = ctx.cardId || meta.cardId || null;
  const burstCheck = checkBurstCoalescing(recipientId, cardId, message);
  let effectiveMessage = message;
  if (!burstCheck.shouldSend) {
    metrics.skipped.coalesced_burst++;
    try {
      await db.execute(
        `INSERT INTO push_deliveries (notification_id, subscription_id, status, reason, sent_at)
         SELECT ?, id, 'skipped', 'coalesced_burst', NOW(3)
         FROM push_subscriptions WHERE user_id = ? AND is_active = 1 LIMIT 1`,
        [notification?.id || null, recipientId]
      );
    } catch (_) {}
    return { skipped: true, reason: 'coalesced_burst' };
  }

  // 5. Hourly cap check (20/hr; mentions & assignments exempt)
  if (!checkHourlyRateLimit(recipientId, eventType)) {
    metrics.skipped.hourly_cap_exceeded++;
    try {
      await db.execute(
        `INSERT INTO push_deliveries (notification_id, subscription_id, status, reason, sent_at)
         SELECT ?, id, 'skipped', 'hourly_cap_exceeded', NOW(3)
         FROM push_subscriptions WHERE user_id = ? AND is_active = 1 LIMIT 1`,
        [notification?.id || null, recipientId]
      );
    } catch (_) {}
    return { skipped: true, reason: 'hourly_cap_exceeded' };
  }

  // 6. Fetch user push subscriptions
  const subscriptions = await db.query(
    'SELECT * FROM push_subscriptions WHERE user_id = ? AND is_active = 1',
    [recipientId]
  );

  if (!subscriptions || subscriptions.length === 0) {
    metrics.skipped.no_active_subscriptions++;
    return { skipped: true, reason: 'no_active_subscriptions' };
  }

  // 7. Check user setting: push_show_details
  let pushShowDetails = true;
  try {
    const [uSet] = await db.query('SELECT push_show_details FROM notification_user_settings WHERE user_id = ?', [recipientId]);
    if (uSet && uSet.push_show_details !== null && uSet.push_show_details !== undefined) {
      pushShowDetails = Boolean(uSet.push_show_details);
    }
  } catch (_) {}

  // 8. Build payload
  const payload = buildPushPayload({
    notification,
    eventType,
    message: effectiveMessage,
    meta,
    ctx,
    pushShowDetails
  });

  // 9. Dispatch to each subscription
  const results = [];
  for (const sub of subscriptions) {
    // Deduplication check on notification_id + subscription_id
    if (notification?.id) {
      const existing = await db.query(
        'SELECT id FROM push_deliveries WHERE notification_id = ? AND subscription_id = ? AND status = "sent" LIMIT 1',
        [notification.id, sub.id]
      );
      if (existing && existing.length > 0) {
        continue;
      }
    }

    const res = await sendToSubscription(db, sub, payload, notification?.id);
    results.push(res);
  }

  return { dispatched: true, results };
}

/**
 * Sends a direct test notification to a specific user's devices
 */
async function sendTestNotification(db, userId) {
  if (!isPushEnabled()) {
    throw new Error('Push notifications are disabled or not configured');
  }

  const subscriptions = await db.query(
    'SELECT * FROM push_subscriptions WHERE user_id = ? AND is_active = 1',
    [userId]
  );

  if (!subscriptions || subscriptions.length === 0) {
    return { sent: 0, message: 'No active device subscriptions found for this user' };
  }

  const payload = {
    notification: {
      title: 'Test Notification',
      body: 'Push notifications are working properly on this device!'
    },
    data: {
      url: '/',
      notification_id: 'test',
      event_type: 'push.test'
    },
    webpush: {
      headers: {
        TTL: '300',
        Urgency: 'high'
      },
      notification: {
        title: 'Test Notification',
        body: 'Push notifications are working properly on this device!',
        icon: '/icons/icon-192.png',
        badge: '/icons/icon-192.png',
        tag: 'push-test-notification',
        data: {
          url: '/'
        }
      },
      fcm_options: {
        link: '/'
      }
    }
  };

  let sent = 0;
  for (const sub of subscriptions) {
    const res = await sendToSubscription(db, sub, payload, null);
    if (res.success) sent++;
  }

  return { sent, total: subscriptions.length };
}

/**
 * Deactivates all subscriptions for a user (on logout-all, password reset, deactivation, removal)
 */
async function deactivateUserSubscriptions(db, userId, reason = 'REVOKED') {
  if (!db || !userId) return;
  try {
    await db.execute(
      `UPDATE push_subscriptions
       SET is_active = 0, revoked_at = NOW(3), last_error_code = ?
       WHERE user_id = ? AND is_active = 1`,
      [reason.slice(0, 100), userId]
    );
  } catch (err) {
    console.error(`[PUSH] Failed to deactivate subscriptions for user ${userId}:`, err.message);
  }
}

/**
 * Cleanup job: deletes deliveries older than 14 days and subscriptions unseen for 60 days
 */
async function cleanOldPushData(db) {
  if (!db) return { deliveriesPurged: 0, tokensPurged: 0 };
  let deliveriesPurged = 0;
  let tokensPurged = 0;

  try {
    const delRes = await db.execute(
      'DELETE FROM push_deliveries WHERE sent_at < NOW(3) - INTERVAL 14 DAY'
    );
    deliveriesPurged = delRes.affectedRows || 0;
  } catch (e) {
    console.warn('[PUSH_CLEANUP] Failed to purge old deliveries:', e.message);
  }

  try {
    const tokRes = await db.execute(
      'DELETE FROM push_subscriptions WHERE last_seen_at < NOW(3) - INTERVAL 60 DAY'
    );
    tokensPurged = tokRes.affectedRows || 0;
  } catch (e) {
    console.warn('[PUSH_CLEANUP] Failed to purge stale tokens:', e.message);
  }

  return { deliveriesPurged, tokensPurged };
}

function getMetrics() {
  return { ...metrics };
}

module.exports = {
  isPushConfigured,
  isPushEnabled,
  getFirebaseAdmin,
  initFirebaseAdmin: getFirebaseAdmin,
  maskToken,
  buildPushPayload,
  buildWebpushPayload: buildPushPayload,
  sendPushNotification,
  sendTestNotification,
  sendToSubscription,
  deactivateUserSubscriptions,
  cleanOldPushData,
  calculateNextBackoff,
  getMetrics,
  checkHourlyRateLimit,
  checkBurstCoalescing
};

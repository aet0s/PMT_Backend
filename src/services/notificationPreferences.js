// server/src/services/notificationPreferences.js
// Manages and queries user notification preferences per category and channel.
const { getDevSingleDb } = require('./tenantPools');
const { NOTIFICATION_EVENTS, EVENT_CATEGORIES } = require('./notificationEvents');

const PUSH_DEFAULT_ON_EVENTS = new Set([
  'card.assigned',
  'card.unassigned',
  'comment.mention',
  'comment.added',
  'card.due_soon',
  'card.overdue',
  'checkin.due',
  'card.submitted_for_review',
  'card.changes_requested',
  'board.member_added',
  'workspace.member_added',
  'workspace.member_removed',
  'workspace.member_role_changed'
]);

/**
 * Default fallback rules if user hasn't explicitly set a preference
 */
function getDefaultPreference(eventType, channel = 'in_app') {
  if (channel === 'in_app') {
    return true; // All in-app notifications enabled by default
  }

  if (channel === 'push') {
    return PUSH_DEFAULT_ON_EVENTS.has(eventType);
  }

  // Email channel defaults: only invites and overdue cards default to true
  if (channel === 'email') {
    return ['invite.sent', 'card.overdue'].includes(eventType);
  }

  return false;
}

/**
 * Checks if a specific event & channel is enabled for a user
 */
async function isEventEnabledForUser(userId, eventType, channel = 'in_app', dbInstance = null) {
  if (!userId || !eventType) return false;
  // Email channel is completely disabled (no email service exists)
  if (channel === 'email') return false;

  const db = dbInstance || getDevSingleDb();

  try {
    const res = await db.query(
      `SELECT is_enabled FROM notification_preferences
       WHERE user_id = ? AND event_type = ? AND channel = ?`,
      [userId, eventType, channel]
    );

    if (res.length > 0) {
      return Boolean(res[0].is_enabled);
    }

    return getDefaultPreference(eventType, channel);
  } catch (err) {
    console.error('Error checking notification preference:', err);
    return getDefaultPreference(eventType, channel);
  }
}

/**
 * Fetches all notification preferences for a user, grouped by category.
 * Hides email channel entirely per scope requirement.
 */
async function getUserPreferences(userId, dbInstance = null) {
  if (!userId) return {};
  const db = dbInstance || getDevSingleDb();

  try {
    const prefsRes = await db.query(
      "SELECT event_type, channel, is_enabled FROM notification_preferences WHERE user_id = ? AND channel != 'email'",
      [userId]
    );

    const userPrefMap = {};
    prefsRes.forEach((row) => {
      if (!userPrefMap[row.event_type]) userPrefMap[row.event_type] = {};
      userPrefMap[row.event_type][row.channel] = Boolean(row.is_enabled);
    });

    const categoryGroups = {};
    EVENT_CATEGORIES.forEach((cat) => {
      categoryGroups[cat] = [];
    });

    Object.entries(NOTIFICATION_EVENTS).forEach(([key, config]) => {
      if (config.notifiable === false) return;
      const cat = config.category || 'Cards';
      if (!categoryGroups[cat]) categoryGroups[cat] = [];

      const inAppVal =
        userPrefMap[key]?.in_app !== undefined
          ? userPrefMap[key].in_app
          : getDefaultPreference(key, 'in_app');

      const pushVal =
        userPrefMap[key]?.push !== undefined
          ? userPrefMap[key].push
          : getDefaultPreference(key, 'push');

      categoryGroups[cat].push({
        eventType: key,
        template: config.template,
        in_app: inAppVal,
        push: pushVal
      });
    });

    return categoryGroups;
  } catch (err) {
    console.error('Error fetching user preferences:', err);
    return {};
  }
}

/**
 * Updates batch preferences for a user
 */
async function updateUserPreferences(userId, updates = [], dbInstance = null) {
  if (!userId || !Array.isArray(updates) || updates.length === 0) return true;
  const db = dbInstance || getDevSingleDb();

  try {
    for (const update of updates) {
      const { eventType, channel, is_enabled } = update;
      if (!eventType || !channel || channel === 'email') continue;
      if (channel !== 'in_app' && channel !== 'push') continue;

      await db.execute(
        `INSERT INTO notification_preferences (user_id, event_type, channel, is_enabled)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE is_enabled = VALUES(is_enabled)`,
        [userId, eventType, channel, is_enabled ? 1 : 0]
      );
    }
    return true;
  } catch (err) {
    console.error('Error updating notification preferences:', err);
    throw err;
  }
}

module.exports = {
  isEventEnabledForUser,
  getUserPreferences,
  updateUserPreferences,
  getDefaultPreference,
  PUSH_DEFAULT_ON_EVENTS
};

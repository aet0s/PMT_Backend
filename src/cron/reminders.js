// server/src/cron/reminders.js
// Multi-tenant due-date reminder and overdue notification cron job.
const cron = require('node-cron');
const { notify } = require('../services/notify');
const { sendPushNotification } = require('../services/pushService');
const {
  getWorkspaceCalendarConfig,
  getWorkspaceNowParts,
  isWorkingDayDate,
  isLongTaskCovered
} = require('../services/dailyTrackerService');
const { getMasterDb, getTenantDb, getDevSingleDb } = require('../services/tenantPools');

async function checkDueSoonCards(firstArg = null, secondArg = null, thirdArg = null) {
  let activeDb = null;
  let tenantId = null;
  let now = new Date();

  if (firstArg instanceof Date) {
    now = firstArg;
    activeDb = secondArg || getDevSingleDb();
    tenantId = thirdArg || null;
  } else {
    activeDb = firstArg || getDevSingleDb();
    tenantId = secondArg || null;
  }

  const oneHourLater = new Date(now.getTime() + 60 * 60 * 1000);

  const dueSoonRes = await activeDb.query(
    `SELECT c.id, c.title, c.due_date, l.board_id
     FROM cards c
     JOIN lists l ON c.list_id = l.id
     WHERE c.due_date IS NOT NULL
       AND c.is_complete = 0
       AND c.is_archived = 0
       AND c.due_reminder_sent_at IS NULL
       AND c.due_date > ?
       AND c.due_date <= ?`,
    [now, oneHourLater]
  );

  for (const card of dueSoonRes) {
    const due = new Date(card.due_date);
    const timeStr = due.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    await notify(
      {
        eventType: 'card.due_soon',
        actorUserId: null,
        boardId: card.board_id,
        cardId: card.id,
        tenantId,
        dedupeKey: `card_due_soon_${card.id}_${card.due_date}`,
        meta: { cardTitle: card.title, relativeDueTime: `soon (${timeStr})` }
      },
      activeDb
    );

    await activeDb.execute(
      'UPDATE cards SET due_reminder_sent_at = CURRENT_TIMESTAMP(3) WHERE id = ?',
      [card.id]
    );
  }

  return dueSoonRes.length;
}

async function checkOverdueCards(firstArg = null, secondArg = null, thirdArg = null) {
  let activeDb = null;
  let tenantId = null;
  let now = new Date();

  if (firstArg instanceof Date) {
    now = firstArg;
    activeDb = secondArg || getDevSingleDb();
    tenantId = thirdArg || null;
  } else {
    activeDb = firstArg || getDevSingleDb();
    tenantId = secondArg || null;
  }

  const overdueRes = await activeDb.query(
    `SELECT c.id, c.title, c.due_date, l.board_id
     FROM cards c
     JOIN lists l ON c.list_id = l.id
     WHERE c.due_date IS NOT NULL
       AND c.is_complete = 0
       AND c.is_archived = 0
       AND c.overdue_notified_at IS NULL
       AND c.due_date < ?`,
    [now]
  );

  for (const card of overdueRes) {
    await notify(
      {
        eventType: 'card.overdue',
        actorUserId: null,
        boardId: card.board_id,
        cardId: card.id,
        tenantId,
        dedupeKey: `card_overdue_${card.id}_${card.due_date}`,
        meta: { cardTitle: card.title }
      },
      activeDb
    );

    await activeDb.execute(
      'UPDATE cards SET overdue_notified_at = CURRENT_TIMESTAMP(3) WHERE id = ?',
      [card.id]
    );
  }

  return overdueRes.length;
}

function calculateWorkingDaysOpen(startDate, endDate = new Date(), workingDays = [1, 2, 3, 4, 5], holidays = []) {
  if (!startDate) return 0;
  const start = new Date(startDate);
  const end = new Date(endDate);
  if (isNaN(start.getTime()) || isNaN(end.getTime()) || start >= end) return 0;

  const holidaysSet = new Set(Array.isArray(holidays) ? holidays : []);
  let count = 0;
  const cur = new Date(start);
  cur.setUTCHours(0, 0, 0, 0);
  cur.setUTCDate(cur.getUTCDate() + 1);

  const target = new Date(end);
  target.setUTCHours(0, 0, 0, 0);

  while (cur <= target) {
    const jsDay = cur.getUTCDay();
    const isoDay = jsDay === 0 ? 7 : jsDay;
    const dateStr = cur.toISOString().slice(0, 10);
    if (workingDays.includes(isoDay) && !holidaysSet.has(dateStr)) {
      count++;
    }
    cur.setUTCDate(cur.getUTCDate() + 1);
  }
  return count;
}

function getWorkingDaysUntilDue(dueDate, fromDate = new Date(), workingDays = [1, 2, 3, 4, 5], holidays = []) {
  if (!dueDate) return 0;
  const target = new Date(dueDate);
  const cur = new Date(fromDate);
  if (isNaN(target.getTime()) || isNaN(cur.getTime()) || target <= cur) return 0;

  cur.setUTCHours(0, 0, 0, 0);
  cur.setUTCDate(cur.getUTCDate() + 1);
  target.setUTCHours(0, 0, 0, 0);

  const holidaysSet = new Set(Array.isArray(holidays) ? holidays : []);
  let count = 0;
  while (cur <= target) {
    const jsDay = cur.getUTCDay();
    const isoDay = jsDay === 0 ? 7 : jsDay;
    const dateStr = cur.toISOString().slice(0, 10);
    if (workingDays.includes(isoDay) && !holidaysSet.has(dateStr)) {
      count++;
    }
    cur.setUTCDate(cur.getUTCDate() + 1);
  }
  return count;
}

async function checkDailyCheckinReminders(firstArg = null, secondArg = null, thirdArg = null) {
  let activeDb = null;
  let tenantId = null;
  let now = new Date();

  if (firstArg instanceof Date) {
    now = firstArg;
    activeDb = secondArg || getDevSingleDb();
    tenantId = thirdArg || null;
  } else {
    activeDb = firstArg || getDevSingleDb();
    tenantId = secondArg || null;
    if (thirdArg instanceof Date) now = thirdArg;
  }

  let cardRows = [];
  try {
    cardRows = await activeDb.query(
      `SELECT c.id, c.title, c.created_at, c.first_moved_or_assigned_at, c.due_date,
              cm.user_id, cm.created_at AS assigned_at, l.board_id, b.name as board_name, b.workspace_id,
              w.settings as settings_json,
              clt.is_long_task, clt.expected_finish_date, clt.last_noted_at
       FROM cards c
       JOIN card_members cm ON c.id = cm.card_id
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       JOIN workspaces w ON b.workspace_id = w.id
       LEFT JOIN card_long_tasks clt ON clt.card_id = c.id AND clt.user_id = cm.user_id
       WHERE (l.is_done_list = 0 OR l.is_done_list IS NULL)
         AND LOWER(TRIM(l.name)) NOT IN ('done', 'completed', 'complete', 'closed', 'finished', 'resolved', 'archive', 'archived')
         AND (c.is_complete = 0 OR c.is_complete IS NULL)
         AND (c.is_archived = 0 OR c.is_archived IS NULL)
         AND (l.is_archived = 0 OR l.is_archived IS NULL)
         AND (b.is_archived = 0 OR b.is_archived IS NULL)
       ORDER BY COALESCE(c.first_moved_or_assigned_at, c.created_at) ASC, c.id ASC`
    );
  } catch (err) {
    return 0;
  }

  if (cardRows.length === 0) return 0;

  // Group by workspace_id + user_id
  const groups = new Map();
  for (const row of cardRows) {
    const key = `${row.workspace_id}:${row.user_id}`;
    if (!groups.has(key)) {
      groups.set(key, { workspaceId: row.workspace_id, userId: row.user_id, settingsJson: row.settings_json, cards: [] });
    }
    groups.get(key).cards.push(row);
  }

  const recentCutoffMs = now.getTime() - 3 * 60 * 60 * 1000; // Suppress cards assigned in last 3 hours
  let remindedCount = 0;

  for (const grp of groups.values()) {
    const { workspaceId, userId, settingsJson, cards } = grp;
    const { timezone, workingDays, holidays, cutoffTime } = getWorkspaceCalendarConfig(settingsJson);
    const { dateStr, hour, minute } = getWorkspaceNowParts(timezone, now);

    // 1. Suppress on non-working days & holidays
    if (!isWorkingDayDate(dateStr, workingDays, holidays)) continue;

    // 2. Must be at or past workspace end-of-day cutoff
    const [cutH, cutM] = cutoffTime.split(':').map(Number);
    const pastCutoff = (hour > cutH) || (hour === cutH && minute >= (cutM || 0));
    if (!pastCutoff) continue;

    // 3. Filter out recently assigned cards and long-task covered cards
    const eligibleCards = cards.filter((c) => {
      const assignedTime = new Date(c.assigned_at || c.first_moved_or_assigned_at || c.created_at).getTime();
      if (assignedTime > recentCutoffMs) return false;
      if (isLongTaskCovered(c, dateStr, workingDays, holidays)) return false;
      return true;
    });
    if (eligibleCards.length === 0) continue;

    // 4. Suppress if user is on approved leave today
    const [leave] = await activeDb.query(
      "SELECT id FROM leave_days WHERE user_id = ? AND date = ? AND status = 'approved'",
      [userId, dateStr]
    );
    if (leave) continue;

    // 5. Suppress if user snoozed today on server
    const [snooze] = await activeDb.query(
      'SELECT id FROM daily_tracker_snoozes WHERE workspace_id = ? AND user_id = ? AND snoozed_date = ?',
      [workspaceId, userId, dateStr]
    );
    if (snooze) continue;

    // 6. Suppress if user already submitted daily_update today (or legacy check-in)
    const [existingUpdate] = await activeDb.query(
      'SELECT id FROM daily_updates WHERE workspace_id = ? AND user_id = ? AND work_date = ?',
      [workspaceId, userId, dateStr]
    );
    if (existingUpdate) continue;

    const [legacyCheckin] = await activeDb.query(
      'SELECT id FROM check_ins WHERE user_id = ? AND work_date = ?',
      [userId, dateStr]
    );
    if (legacyCheckin) continue;

    // 7. Atomic idempotency check (at most 1 web push per user per workspace per day, NO bell notification)
    const dedupeKey = `daily_push_${workspaceId}_${userId}_${dateStr}`;
    const [existingOutbox] = await activeDb.query(
      `SELECT id FROM notification_outbox WHERE dedupe_key = ? LIMIT 1`,
      [dedupeKey]
    );
    if (existingOutbox) continue;

    try {
      await activeDb.execute(
        `INSERT INTO notification_outbox (event_type, target_user_id, dedupe_key, payload, status, created_at, updated_at)
         VALUES ('checkin.due', ?, ?, ?, 'completed', NOW(3), NOW(3))`,
        [userId, dedupeKey, JSON.stringify({ workspaceId, workDate: dateStr, cardCount: eligibleCards.length })]
      );
    } catch {
      // Duplicate key under concurrent cron instance -> already handled
      continue;
    }

    // Send web push ONLY (never insert into notifications bell table)
    try {
      await sendPushNotification(activeDb, {
        notification: null,
        recipientId: userId,
        eventType: 'checkin.due',
        message: `Quick 30-second daily update for your ${eligibleCards.length} active task(s)`,
        meta: { workspaceId, workDate: dateStr, cardCount: eligibleCards.length },
        tenantId: tenantId || 'single'
      });
    } catch (pushErr) {
      // Non-fatal if push not configured
    }

    remindedCount++;
  }

  return remindedCount;
}

async function processAllTenantsReminders() {
  if (process.env.DEV_SINGLE_TENANT === '1') {
    const singleDb = getDevSingleDb();
    await checkDueSoonCards(singleDb);
    await checkOverdueCards(singleDb);
    await checkDailyCheckinReminders(singleDb);
    return;
  }

  try {
    const masterDb = getMasterDb();
    const tenants = await masterDb.query(
      "SELECT id, slug, db_name FROM tenants WHERE status = 'active'"
    );

    // Process tenants with bounded concurrency (batch of 5)
    const BATCH_SIZE = 5;
    for (let i = 0; i < tenants.length; i += BATCH_SIZE) {
      const batch = tenants.slice(i, i + BATCH_SIZE);
      await Promise.all(
        batch.map(async (tenant) => {
          try {
            const tenantDb = await getTenantDb(tenant.id);
            await checkDueSoonCards(tenantDb, tenant.id);
            await checkOverdueCards(tenantDb, tenant.id);
            await checkDailyCheckinReminders(tenantDb, tenant.id);
          } catch (tenantErr) {
            console.error(`[CRON ERROR] Reminder processing failed for tenant ${tenant.slug}:`, tenantErr.message);
          }
        })
      );
    }
  } catch (err) {
    console.error('[CRON ERROR] Error querying active tenants:', err.message);
  }
}

function initReminderCron() {
  // Run every 5 minutes: '*/5 * * * *'
  cron.schedule('*/5 * * * *', async () => {
    try {
      await processAllTenantsReminders();
    } catch (err) {
      console.error('Error running due date reminder cron:', err);
    }
  });

  console.log('Due date reminder cron job initialized across all active tenants.');
}

module.exports = {
  initReminderCron,
  checkDueSoonCards,
  checkOverdueCards,
  checkDailyCheckinReminders,
  processAllTenantsReminders
};


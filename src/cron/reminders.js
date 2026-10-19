// server/src/cron/reminders.js
// Multi-tenant due-date reminder and overdue notification cron job.
const cron = require('node-cron');
const { notify } = require('../services/notify');
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

  // Get open assigned cards with board and workspace info
  let cardRows = [];
  try {
    cardRows = await activeDb.query(
      `SELECT c.id, c.title, c.created_at, c.first_moved_or_assigned_at, c.due_date,
              cm.user_id, l.board_id, b.name as board_name, b.workspace_id,
              w.settings as settings_json
       FROM cards c
       JOIN card_members cm ON c.id = cm.card_id
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       JOIN workspaces w ON b.workspace_id = w.id
       WHERE (l.is_done_list = 0 OR l.is_done_list IS NULL)
         AND c.is_complete = 0
         AND c.is_archived = 0
       ORDER BY COALESCE(c.first_moved_or_assigned_at, c.created_at) ASC, c.id ASC`
    );
  } catch (err) {
    return 0;
  }

  if (cardRows.length === 0) return 0;

  // Track members already reminded this run
  const remindedMembers = new Set();
  let remindedCount = 0;

  for (const card of cardRows) {
    if (remindedMembers.has(card.user_id)) continue;

    let settings = {};
    if (card.settings_json) {
      try {
        settings = typeof card.settings_json === 'string' ? JSON.parse(card.settings_json) : card.settings_json;
      } catch {}
    }

    const tz = settings.timezone || 'Asia/Kolkata';
    const workingDays = settings.working_days || [1, 2, 3, 4, 5]; // Mon-Fri
    const holidays = Array.isArray(settings.holidays) ? settings.holidays : [];
    const cutoffStr = settings.cutoff_time || '17:00'; // Default 17:00 Asia/Kolkata
    const [cutoffHour, cutoffMinute] = cutoffStr.split(':').map(Number);

    // Get current date and time in workspace timezone
    let dateStr, hour, minute, isoDay;
    try {
      const formatter = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' });
      dateStr = formatter.format(now); // YYYY-MM-DD
      const timeFormatter = new Intl.DateTimeFormat('en-US', { timeZone: tz, hour: 'numeric', minute: 'numeric', hour12: false });
      const parts = timeFormatter.formatToParts(now);
      hour = Number(parts.find(p => p.type === 'hour')?.value || 0);
      minute = Number(parts.find(p => p.type === 'minute')?.value || 0);

      const dayFormatter = new Intl.DateTimeFormat('en-US', { timeZone: tz, weekday: 'short' });
      const dayShort = dayFormatter.format(now);
      const dayMap = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 };
      isoDay = dayMap[dayShort] ?? 1;
    } catch {
      dateStr = now.toISOString().slice(0, 10);
      hour = now.getUTCHours();
      minute = now.getUTCMinutes();
      const jsDay = now.getUTCDay();
      isoDay = jsDay === 0 ? 7 : jsDay;
    }

    // Must be a working day
    if (!workingDays.includes(isoDay)) continue;

    // Check holidays
    if (holidays.includes(dateStr)) continue;

    // Check if card needs an update:
    // (has been open for at least 1 working day since first assignment or first move, OR its due date is 2 or more working days away)
    const startRef = card.first_moved_or_assigned_at || card.created_at;
    const daysOpen = calculateWorkingDaysOpen(startRef, dateStr, workingDays, holidays);
    const daysUntilDue = card.due_date ? getWorkingDaysUntilDue(card.due_date, dateStr, workingDays, holidays) : 0;
    const needsUpdate = (daysOpen >= 1 || daysUntilDue >= 2);
    if (!needsUpdate) continue;

    // Check if user is on approved leave today
    const [leave] = await activeDb.query(
      "SELECT id FROM leave_days WHERE user_id = ? AND date = ? AND status = 'approved'",
      [card.user_id, dateStr]
    );
    if (leave) continue;

    // Must be at or past cutoff time
    const pastCutoff = (hour > cutoffHour) || (hour === cutoffHour && minute >= (cutoffMinute || 0));
    if (!pastCutoff) continue;

    // Check if member already checked in today on ANY card
    const [checkin] = await activeDb.query(
      'SELECT id FROM check_ins WHERE user_id = ? AND work_date = ?',
      [card.user_id, dateStr]
    );
    if (checkin) continue;

    // Check if reminder was already sent or enqueued today for this member
    const dedupeKey = `checkin_due_${card.user_id}_${dateStr}`;
    const [existingNotif] = await activeDb.query(
      `SELECT id FROM notifications 
       WHERE user_id = ? 
         AND (type = 'checkin.due' OR event_type = 'checkin.due') 
         AND (DATE(created_at) = ? OR (meta IS NOT NULL AND meta LIKE ?))`,
      [card.user_id, dateStr, `%"workDate":"${dateStr}"%`]
    );
    const [existingOutbox] = await activeDb.query(
      `SELECT id FROM notification_outbox 
       WHERE (target_user_id = ? OR dedupe_key = ?) 
         AND event_type = 'checkin.due' 
         AND (dedupe_key LIKE ? OR status IN ('pending', 'processing', 'completed'))`,
      [card.user_id, dedupeKey, `%_${dateStr}%`]
    );
    if (existingNotif || existingOutbox) {
      remindedMembers.add(card.user_id);
      continue;
    }

    // Send single personal notification (no sound, notifiable)
    await notify(
      {
        eventType: 'checkin.due',
        actorUserId: null,
        targetUserId: card.user_id,
        boardId: card.board_id,
        cardId: card.id,
        tenantId,
        dedupeKey,
        meta: {
          cardTitle: card.title,
          cardId: card.id,
          boardName: card.board_name,
          workDate: dateStr
        }
      },
      activeDb
    );

    remindedMembers.add(card.user_id);
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


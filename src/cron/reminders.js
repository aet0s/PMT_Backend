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

  // Get active focus cards with card and board info
  let focusRows = [];
  try {
    focusRows = await activeDb.query(
      `SELECT cf.id, cf.card_id, cf.user_id, c.title, l.board_id, b.name as board_name, b.workspace_id,
              w.settings as settings_json
       FROM card_focus cf
       JOIN cards c ON cf.card_id = c.id
       JOIN lists l ON c.list_id = l.id
       JOIN boards b ON l.board_id = b.id
       JOIN workspaces w ON b.workspace_id = w.id
       WHERE cf.ended_at IS NULL
         AND c.is_complete = 0
         AND c.is_archived = 0`
    );
  } catch (err) {
    // If card_focus does not exist on this DB, ignore
    return 0;
  }

  if (focusRows.length === 0) return 0;

  // Track members already reminded this run
  const remindedMembers = new Set();
  let remindedCount = 0;

  for (const focus of focusRows) {
    if (remindedMembers.has(focus.user_id)) continue;

    let settings = {};
    if (focus.settings_json) {
      try {
        settings = typeof focus.settings_json === 'string' ? JSON.parse(focus.settings_json) : focus.settings_json;
      } catch {}
    }

    const tz = settings.timezone || 'Asia/Kolkata';
    const workingDays = settings.working_days || [1, 2, 3, 4, 5]; // Mon-Fri
    const cutoffStr = settings.cutoff_time || '18:00'; // 18:00
    const [cutoffHour, cutoffMinute] = cutoffStr.split(':').map(Number);

    // Get current date and time in workspace timezone
    let dateStr, hour, minute, dayOfWeek;
    try {
      const formatter = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' });
      dateStr = formatter.format(now); // YYYY-MM-DD
      const timeFormatter = new Intl.DateTimeFormat('en-US', { timeZone: tz, hour: 'numeric', minute: 'numeric', hour12: false });
      const parts = timeFormatter.formatToParts(now);
      hour = Number(parts.find(p => p.type === 'hour')?.value || 0);
      minute = Number(parts.find(p => p.type === 'minute')?.value || 0);

      const dayFormatter = new Intl.DateTimeFormat('en-US', { timeZone: tz, weekday: 'short' });
      const dayShort = dayFormatter.format(now);
      const dayMap = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 0 };
      dayOfWeek = dayMap[dayShort] ?? 1;
    } catch {
      dateStr = now.toISOString().slice(0, 10);
      hour = now.getUTCHours();
      minute = now.getUTCMinutes();
      dayOfWeek = now.getUTCDay();
    }

    // Must be a working day
    if (!workingDays.includes(dayOfWeek)) continue;

    // Check holidays
    const holidays = Array.isArray(settings.holidays) ? settings.holidays : [];
    if (holidays.includes(dateStr)) continue;

    // Check if user is on approved leave today
    const [leave] = await activeDb.query(
      "SELECT id FROM leave_days WHERE user_id = ? AND date = ? AND status = 'approved'",
      [focus.user_id, dateStr]
    );
    if (leave) continue;

    // Must be at or past cutoff time
    const pastCutoff = (hour > cutoffHour) || (hour === cutoffHour && minute >= (cutoffMinute || 0));
    if (!pastCutoff) continue;

    // Check if member already checked in today on ANY card or this card
    const [checkin] = await activeDb.query(
      'SELECT id FROM check_ins WHERE user_id = ? AND work_date = ?',
      [focus.user_id, dateStr]
    );
    if (checkin) continue;

    // Check if reminder was already sent today for this member
    const dedupeKey = `checkin_due_${focus.user_id}_${dateStr}`;
    const [existingNotif] = await activeDb.query(
      `SELECT id FROM notifications WHERE user_id = ? AND (type = 'checkin.due' OR event_type = 'checkin.due') AND DATE(created_at) = ?`,
      [focus.user_id, dateStr]
    );
    if (existingNotif) {
      remindedMembers.add(focus.user_id);
      continue;
    }

    // Send single personal notification (no sound, notifiable)
    await notify(
      {
        eventType: 'checkin.due',
        actorUserId: null,
        targetUserId: focus.user_id,
        boardId: focus.board_id,
        cardId: focus.card_id,
        tenantId,
        dedupeKey,
        meta: {
          cardTitle: focus.title,
          cardId: focus.card_id,
          boardName: focus.board_name,
          workDate: dateStr
        }
      },
      activeDb
    );

    remindedMembers.add(focus.user_id);
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


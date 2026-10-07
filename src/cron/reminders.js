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

async function processAllTenantsReminders() {
  if (process.env.DEV_SINGLE_TENANT === '1') {
    const singleDb = getDevSingleDb();
    await checkDueSoonCards(singleDb);
    await checkOverdueCards(singleDb);
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
  processAllTenantsReminders
};

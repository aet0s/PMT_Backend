#!/usr/bin/env node
// server/src/scripts/notificationsCleanup.js
// Cleans up historical notifications and pending outbox rows of non-main event types.
// Usage: npm run notifications:cleanup -- --tenant <slug> [--dry-run|--apply]

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { getMasterDb, getDevSingleDb, getTenantDbByName, closeAllPools } = require('../services/tenantPools');

const MAIN_EVENT_TYPES = [
  'workspace.member_added',
  'workspace.member_removed',
  'workspace.member_role_changed',
  'board.created',
  'board.member_added',
  'board.member_removed',
  'board.archived',
  'board.deleted',
  'card.assigned',
  'card.unassigned',
  'card.completed',
  'card.archived',
  'card.deleted',
  'comment.mention',
  'comment.added',
  'card.due_soon',
  'card.overdue'
];

async function runCleanup() {
  const args = process.argv.slice(2);
  let tenantSlug = null;
  let isApply = false;
  let isDryRun = true;
  let restoreSnapshotPath = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--tenant' && args[i + 1]) {
      tenantSlug = args[i + 1];
      i++;
    } else if (args[i] === '--apply') {
      isApply = true;
      isDryRun = false;
    } else if (args[i] === '--dry-run') {
      isDryRun = true;
      isApply = false;
    } else if (args[i] === '--restore-snapshot' && args[i + 1]) {
      restoreSnapshotPath = args[i + 1];
      i++;
    } else if (args[i].startsWith('--restore-snapshot=')) {
      restoreSnapshotPath = args[i].split('=')[1];
    }
  }

  if (!tenantSlug && !restoreSnapshotPath) {
    console.error('❌ Error: --tenant <slug> or --restore-snapshot <path> is strictly required.');
    console.log('Usage: npm run notifications:cleanup -- --tenant <slug> [--dry-run | --apply]');
    console.log('       npm run notifications:cleanup -- --restore-snapshot <path> [--tenant <slug>]');
    process.exit(1);
  }

  if (restoreSnapshotPath && !tenantSlug) {
    try {
      const snap = JSON.parse(fs.readFileSync(path.resolve(restoreSnapshotPath), 'utf8'));
      tenantSlug = snap.tenant;
    } catch (_) {}
  }

  console.log('================================================================');
  console.log(`       NOTIFICATION HISTORICAL CLEANUP: tenant "${tenantSlug || 'unknown'}"   `);
  console.log(`       Mode: ${restoreSnapshotPath ? 'RESTORE-SNAPSHOT' : (isApply ? 'APPLY (DESTRUCTIVE)' : 'DRY-RUN (REPORT ONLY)')} `);
  console.log('================================================================\n');

  let db = null;
  let dbName = null;

  try {
    // Resolve tenant database
    if (process.env.DEV_SINGLE_TENANT === '1' && tenantSlug === 'dev') {
      db = getDevSingleDb();
      dbName = process.env.MYSQL_DATABASE || 'pm_dev_single';
    } else {
      const masterDb = getMasterDb();
      const [tenant] = await masterDb.query(
        "SELECT id, slug, db_name, status FROM tenants WHERE slug = ? OR id = ?",
        [tenantSlug, isNaN(Number(tenantSlug)) ? -1 : Number(tenantSlug)]
      );

      if (!tenant) {
        if (tenantSlug === 'single' || tenantSlug === 'dev') {
          db = getDevSingleDb();
          dbName = process.env.MYSQL_DATABASE || 'pm_dev_single';
        } else {
          console.error(`❌ Tenant "${tenantSlug}" was not found in master database.`);
          process.exit(1);
        }
      } else {
        dbName = tenant.db_name;
        db = getTenantDbByName(dbName);
      }
    }

    console.log(`Connected to tenant database: ${dbName}`);

    if (restoreSnapshotPath) {
      console.log(`--- Restoring Snapshot from ${restoreSnapshotPath} ---`);
      const snap = JSON.parse(fs.readFileSync(path.resolve(restoreSnapshotPath), 'utf8'));
      const notifs = snap.notifications || [];
      const outbox = snap.outbox || [];
      let restoredNotifs = 0;
      let restoredOutbox = 0;

      for (const n of notifs) {
        const keys = Object.keys(n);
        const placeholders = keys.map(() => '?').join(', ');
        const values = keys.map(k => n[k]);
        await db.execute(
          `INSERT IGNORE INTO notifications (${keys.map(k => `\`${k}\``).join(', ')}) VALUES (${placeholders})`,
          values
        );
        restoredNotifs++;
      }

      for (const o of outbox) {
        const keys = Object.keys(o);
        const placeholders = keys.map(() => '?').join(', ');
        const values = keys.map(k => o[k]);
        await db.execute(
          `INSERT IGNORE INTO notification_outbox (${keys.map(k => `\`${k}\``).join(', ')}) VALUES (${placeholders})`,
          values
        );
        restoredOutbox++;
      }

      console.log(`✓ Restored ${restoredNotifs} notification rows.`);
      console.log(`✓ Restored ${restoredOutbox} outbox rows.`);
      console.log('✓ Snapshot successfully restored.');
      return;
    }

    // Query counts of non-main notifications
    const notifCounts = await db.query(
      `SELECT event_type, COUNT(*) as count
       FROM notifications
       WHERE event_type NOT IN (?)
       GROUP BY event_type
       ORDER BY count DESC`,
      [MAIN_EVENT_TYPES]
    );

    // Query counts of non-main pending outbox rows
    const outboxCounts = await db.query(
      `SELECT event_type, COUNT(*) as count
       FROM notification_outbox
       WHERE status = 'pending' AND event_type NOT IN (?)
       GROUP BY event_type
       ORDER BY count DESC`,
      [MAIN_EVENT_TYPES]
    );

    const breakdown = {};
    let totalNotifs = 0;
    let totalOutbox = 0;

    for (const r of notifCounts) {
      if (!breakdown[r.event_type]) breakdown[r.event_type] = { notifs: 0, outbox: 0 };
      breakdown[r.event_type].notifs = Number(r.count);
      totalNotifs += Number(r.count);
    }

    for (const r of outboxCounts) {
      if (!breakdown[r.event_type]) breakdown[r.event_type] = { notifs: 0, outbox: 0 };
      breakdown[r.event_type].outbox = Number(r.count);
      totalOutbox += Number(r.count);
    }

    const eventList = Object.keys(breakdown).sort();

    console.log('\n--- Breakdown of Historical Non-Main Rows ---');
    if (eventList.length === 0) {
      console.log('✓ Clean state: No non-main notification or pending outbox rows found. (Idempotent 0-op)\n');
    } else {
      console.log('----------------------------------------------------------------------');
      console.log('| Event Type                               | Notifications | Outbox  |');
      console.log('----------------------------------------------------------------------');
      for (const ev of eventList) {
        const nStr = String(breakdown[ev].notifs).padStart(13);
        const oStr = String(breakdown[ev].outbox).padStart(7);
        console.log(`| ${ev.padEnd(40)} | ${nStr} | ${oStr} |`);
      }
      console.log('----------------------------------------------------------------------');
      console.log(`| TOTAL                                    | ${String(totalNotifs).padStart(13)} | ${String(totalOutbox).padStart(7)} |`);
      console.log('----------------------------------------------------------------------\n');
    }

    if (isApply && (totalNotifs > 0 || totalOutbox > 0)) {
      // 1. Take JSON Snapshot before delete
      console.log('--- Taking Pre-Apply JSON Snapshot ---');
      const notifsToDelete = await db.query(
        'SELECT * FROM notifications WHERE event_type NOT IN (?)',
        [MAIN_EVENT_TYPES]
      );
      const outboxToDelete = await db.query(
        "SELECT * FROM notification_outbox WHERE status = 'pending' AND event_type NOT IN (?)",
        [MAIN_EVENT_TYPES]
      );

      const snapshot = {
        tenant: tenantSlug,
        dbName,
        timestamp: new Date().toISOString(),
        totalNotifications: notifsToDelete.length,
        totalOutbox: outboxToDelete.length,
        notifications: notifsToDelete,
        outbox: outboxToDelete
      };

      const snapshotFilename = `cleanup-snapshot-${tenantSlug}-${Date.now()}.json`;
      const snapshotPath = path.join(process.cwd(), snapshotFilename);
      fs.writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2), 'utf8');
      console.log(`✓ Pre-apply snapshot saved: ${snapshotFilename}`);

      // 2. Perform deletion
      console.log('\n--- Applying Deletion ---');
      const delNotifRes = await db.execute(
        'DELETE FROM notifications WHERE event_type NOT IN (?)',
        [MAIN_EVENT_TYPES]
      );
      const delOutboxRes = await db.execute(
        "DELETE FROM notification_outbox WHERE status = 'pending' AND event_type NOT IN (?)",
        [MAIN_EVENT_TYPES]
      );

      console.log(`✓ Deleted ${delNotifRes.affectedRows || 0} notification rows.`);
      console.log(`✓ Deleted ${delOutboxRes.affectedRows || 0} pending outbox rows.`);
      console.log('✓ Cleanup successfully applied.');
    } else if (isDryRun) {
      console.log(`[DRY-RUN] No rows were modified. Run with --apply to delete ${totalNotifs} notifications and ${totalOutbox} outbox rows.`);
    }

    console.log('\n================================================================');
  } catch (err) {
    console.error('❌ Error during cleanup:', err);
    process.exit(1);
  } finally {
    if (require.main === module) {
      await closeAllPools();
    }
  }
}

if (require.main === module) {
  runCleanup();
}

module.exports = { runCleanup, MAIN_EVENT_TYPES };

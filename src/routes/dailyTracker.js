// server/src/routes/dailyTracker.js
// Daily Tracker v3 API: unified daily updates, server-side snooze, one-click leave today,
// fixed 5-state people view with filters, 7-day timeline drawer, and CSV export.

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { requirePermission, userHasPermission } = require('../middleware/permissions');
const { createRateLimiter } = require('../middleware/rateLimit');
const { sanitizePlain } = require('../utils/sanitizer');
const auditService = require('../services/audit');
const {
  STATE_CODES,
  STATE_META,
  computeMemberDailyState,
  getWorkspaceCalendarConfig,
  getWorkspaceNowParts,
  isWorkingDayDate,
  addDaysToDateStr,
  getLastNWorkingDays,
  calculateWorkingDaysOpen,
  getWorkingDaysUntilDue,
  getUtcRangeForDate,
  computeUpdateHash,
  computeSilentFlags,
  isLongTaskCovered
} = require('../services/dailyTrackerService');

const router = express.Router();

const trackerWriteLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 60,
  keyPrefix: 'dt_write',
  keyGenerator: (req) => `dt_write:${req.user?.id || req.ip}`,
  message: 'Too many daily tracker updates. Please wait a moment and try again.'
});

const MAX_NOTE_LEN = 500;
const RECENTLY_ASSIGNED_HOURS = 3;

function sanitizeCsvCell(val) {
  let str = String(val === null || val === undefined ? '' : val);
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

async function getWorkspaceSettings(db, workspaceId) {
  const [ws] = await db.query('SELECT id, name, settings FROM workspaces WHERE id = ?', [workspaceId]);
  return ws || null;
}

async function ensureWorkspaceMember(db, workspaceId, userId) {
  const [row] = await db.query(
    'SELECT role_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
    [workspaceId, userId]
  );
  return Boolean(row);
}

/**
 * Helper to fetch active assigned cards for a user in a workspace
 */
async function getUserActiveCards(db, workspaceId, userId) {
  return await db.query(
    `SELECT c.id, c.title, c.created_at, c.created_by, c.first_moved_or_assigned_at, c.due_date, c.list_id,
            l.name AS list_name, l.board_id, b.name AS board_title,
            cm.created_at AS assigned_at,
            clt.is_long_task, clt.expected_finish_date, clt.last_noted_at
     FROM cards c
     JOIN card_members cm ON c.id = cm.card_id
     JOIN lists l ON c.list_id = l.id
     JOIN boards b ON l.board_id = b.id
     LEFT JOIN card_long_tasks clt ON clt.card_id = c.id AND clt.user_id = cm.user_id
     WHERE b.workspace_id = ?
       AND cm.user_id = ?
       AND (c.is_complete = 0 OR c.is_complete IS NULL)
       AND (c.is_archived = 0 OR c.is_archived IS NULL)
       AND (l.is_archived = 0 OR l.is_archived IS NULL)
       AND (b.is_archived = 0 OR b.is_archived IS NULL)
       AND (l.is_done_list = 0 OR l.is_done_list IS NULL)
       AND LOWER(TRIM(l.name)) NOT IN ('done', 'completed', 'complete', 'closed', 'finished', 'resolved', 'archive', 'archived')
     ORDER BY COALESCE(c.first_moved_or_assigned_at, c.created_at) ASC, c.id ASC`,
    [workspaceId, userId]
  );
}

async function loadDailyUpdateWithItems(db, updateRow) {
  if (!updateRow) return null;
  const items = await db.query(
    `SELECT dui.*, c.title AS card_title, b.id AS board_id, b.name AS board_title
     FROM daily_update_items dui
     JOIN cards c ON dui.card_id = c.id
     JOIN lists l ON c.list_id = l.id
     JOIN boards b ON l.board_id = b.id
     WHERE dui.daily_update_id = ?
     ORDER BY dui.id ASC`,
    [updateRow.id]
  );
  const reviews = await db.query(
    `SELECT r.*, u.name AS reviewer_name, u.avatar_url AS reviewer_avatar
     FROM check_in_reviews r
     JOIN users u ON r.reviewer_id = u.id
     WHERE r.daily_update_id = ?
     ORDER BY r.created_at ASC`,
    [updateRow.id]
  );
  let parsedHistory = [];
  if (updateRow.edit_history) {
    try {
      parsedHistory = typeof updateRow.edit_history === 'string'
        ? JSON.parse(updateRow.edit_history)
        : updateRow.edit_history;
    } catch { parsedHistory = []; }
  }
  let parsedFlags = [];
  if (updateRow.flags) {
    try {
      parsedFlags = typeof updateRow.flags === 'string' ? JSON.parse(updateRow.flags) : updateRow.flags;
    } catch { parsedFlags = []; }
  }
  return {
    ...updateRow,
    work_date: typeof updateRow.work_date === 'string'
      ? updateRow.work_date.slice(0, 10)
      : new Date(updateRow.work_date).toISOString().slice(0, 10),
    edit_history: parsedHistory,
    flags: parsedFlags,
    items,
    reviews
  };
}

// ---------------------------------------------------------------------------
// 1. GET /api/workspaces/:id/daily-update/today
// ---------------------------------------------------------------------------
router.get('/:id/daily-update/today', requireAuth, requirePermission('checkin.create'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  if (!workspaceId || workspaceId <= 0) {
    return res.status(400).json({ error: { message: 'Invalid workspace ID', code: 'BAD_REQUEST' } });
  }

  try {
    const isMember = await ensureWorkspaceMember(req.db, workspaceId, req.user.id);
    if (!isMember) {
      return res.status(403).json({ error: { message: 'Access denied to workspace', code: 'FORBIDDEN' } });
    }

    const ws = await getWorkspaceSettings(req.db, workspaceId);
    if (!ws) {
      return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
    }

    const { timezone, workingDays, holidays, cutoffTime } = getWorkspaceCalendarConfig(ws.settings);
    const now = new Date();
    const { dateStr: todayStr, hour, minute } = getWorkspaceNowParts(timezone, now);
    const isWorkingDay = isWorkingDayDate(todayStr, workingDays, holidays);
    const [cutH, cutM] = cutoffTime.split(':').map(Number);
    const isPastCutoff = hour > cutH || (hour === cutH && minute >= (cutM || 0));

    // Previous working day for "Same as yesterday"
    const prevWorkingDays = getLastNWorkingDays(addDaysToDateStr(todayStr, -1), 1, workingDays, holidays);
    const yesterdayStr = prevWorkingDays[0] || addDaysToDateStr(todayStr, -1);

    // Check leave today
    const [leaveToday] = await req.db.query(
      "SELECT id, status, reason FROM leave_days WHERE user_id = ? AND date = ? AND status = 'approved'",
      [req.user.id, todayStr]
    );

    // Check server-side snooze today
    const [snoozeRow] = await req.db.query(
      'SELECT id, snoozed_until_date FROM daily_tracker_snoozes WHERE workspace_id = ? AND user_id = ? AND snoozed_date = ?',
      [workspaceId, req.user.id, todayStr]
    );

    // Active cards
    const rawCards = await getUserActiveCards(req.db, workspaceId, req.user.id);
    const recentCutoffMs = now.getTime() - RECENTLY_ASSIGNED_HOURS * 60 * 60 * 1000;

    const cards = rawCards.map((c) => {
      const assignedTime = new Date(c.assigned_at || c.first_moved_or_assigned_at || c.created_at).getTime();
      const recentlyAssigned = assignedTime > recentCutoffMs;
      const longTaskCovered = isLongTaskCovered(c, todayStr, workingDays, holidays);
      return {
        id: c.id,
        title: c.title,
        board_id: c.board_id,
        board_title: c.board_title,
        list_name: c.list_name,
        due_date: c.due_date,
        is_long_task: Boolean(c.is_long_task),
        expected_finish_date: c.expected_finish_date
          ? (typeof c.expected_finish_date === 'string' ? c.expected_finish_date.slice(0, 10) : new Date(c.expected_finish_date).toISOString().slice(0, 10))
          : null,
        last_noted_at: c.last_noted_at
          ? (typeof c.last_noted_at === 'string' ? c.last_noted_at.slice(0, 10) : new Date(c.last_noted_at).toISOString().slice(0, 10))
          : null,
        long_task_covered: longTaskCovered,
        recently_assigned: recentlyAssigned
      };
    });

    // Today's update & yesterday's update
    const [todayRow] = await req.db.query(
      'SELECT * FROM daily_updates WHERE workspace_id = ? AND user_id = ? AND work_date = ?',
      [workspaceId, req.user.id, todayStr]
    );
    const todayUpdate = await loadDailyUpdateWithItems(req.db, todayRow);

    const [yesterdayRow] = await req.db.query(
      `SELECT * FROM daily_updates
       WHERE workspace_id = ? AND user_id = ? AND work_date < ?
       ORDER BY work_date DESC LIMIT 1`,
      [workspaceId, req.user.id, todayStr]
    );
    const yesterdayUpdate = await loadDailyUpdateWithItems(req.db, yesterdayRow);

    // Pending unanswered reviewer questions/evidence requests for this user in this workspace
    const pendingReviews = await req.db.query(
      `SELECT r.id, r.daily_update_id, r.check_in_id, r.action, r.note, r.created_at,
              u.name AS reviewer_name, du.work_date
       FROM check_in_reviews r
       JOIN users u ON r.reviewer_id = u.id
       JOIN daily_updates du ON r.daily_update_id = du.id
       WHERE du.workspace_id = ? AND du.user_id = ?
         AND r.answered_at IS NULL
         AND r.action IN ('question', 'request_evidence')
       ORDER BY r.created_at DESC
       LIMIT 10`,
      [workspaceId, req.user.id]
    );

    const cardsNeedingReminder = cards.filter((c) => !c.recently_assigned && !c.long_task_covered);
    const shouldRemindBanner = Boolean(
      isWorkingDay &&
      !leaveToday &&
      !snoozeRow &&
      !todayUpdate &&
      cardsNeedingReminder.length > 0 &&
      isPastCutoff
    );

    const showSidebarBadge = Boolean(
      isWorkingDay &&
      !leaveToday &&
      !snoozeRow &&
      !todayUpdate &&
      cardsNeedingReminder.length > 0
    );

    return res.json({
      date: todayStr,
      yesterday_date: yesterdayStr,
      timezone,
      cutoff_time: cutoffTime,
      is_working_day: isWorkingDay,
      cutoff_passed: isPastCutoff,
      on_leave_today: Boolean(leaveToday),
      leave_reason: leaveToday?.reason || null,
      is_snoozed: Boolean(snoozeRow),
      should_remind_banner: shouldRemindBanner,
      show_sidebar_badge: showSidebarBadge,
      cards,
      today_update: todayUpdate,
      yesterday_update: yesterdayUpdate,
      pending_reviews: pendingReviews
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// 2. GET /api/workspaces/:id/checkins/pending (v3 calm reminder compatibility)
// ---------------------------------------------------------------------------
router.get('/:id/checkins/pending', requireAuth, requirePermission('checkin.create'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  if (!workspaceId || workspaceId <= 0) {
    return res.status(400).json({ error: { message: 'Invalid workspace ID', code: 'BAD_REQUEST' } });
  }
  try {
    const isMember = await ensureWorkspaceMember(req.db, workspaceId, req.user.id);
    if (!isMember) {
      return res.status(403).json({ error: { message: 'Access denied to workspace', code: 'FORBIDDEN' } });
    }
    const ws = await getWorkspaceSettings(req.db, workspaceId);
    if (!ws) {
      return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
    }
    const { timezone, workingDays, holidays, cutoffTime } = getWorkspaceCalendarConfig(ws.settings);
    const now = new Date();
    const { dateStr: todayStr, hour, minute } = getWorkspaceNowParts(timezone, now);
    const isWorkingDay = isWorkingDayDate(todayStr, workingDays, holidays);
    const [cutH, cutM] = cutoffTime.split(':').map(Number);
    const isPastCutoff = hour > cutH || (hour === cutH && minute >= (cutM || 0));

    const [leaveToday] = await req.db.query(
      "SELECT id FROM leave_days WHERE user_id = ? AND date = ? AND status = 'approved'",
      [req.user.id, todayStr]
    );
    const [snoozeRow] = await req.db.query(
      'SELECT id FROM daily_tracker_snoozes WHERE workspace_id = ? AND user_id = ? AND snoozed_date = ?',
      [workspaceId, req.user.id, todayStr]
    );
    const [todayUpdate] = await req.db.query(
      'SELECT id FROM daily_updates WHERE workspace_id = ? AND user_id = ? AND work_date = ?',
      [workspaceId, req.user.id, todayStr]
    );

    let pendingCards = [];
    if (isWorkingDay && !leaveToday && !snoozeRow && !todayUpdate) {
      const rawCards = await getUserActiveCards(req.db, workspaceId, req.user.id);
      const recentCutoffMs = now.getTime() - RECENTLY_ASSIGNED_HOURS * 60 * 60 * 1000;
      pendingCards = rawCards
        .filter((c) => {
          const assignedTime = new Date(c.assigned_at || c.first_moved_or_assigned_at || c.created_at).getTime();
          if (assignedTime > recentCutoffMs) return false;
          if (isLongTaskCovered(c, todayStr, workingDays, holidays)) return false;
          return true;
        })
        .slice(0, 5)
        .map((c) => ({
          id: c.id,
          title: c.title,
          board_id: c.board_id,
          board_title: c.board_title,
          list_name: c.list_name
        }));
    }

    return res.json({
      date: todayStr,
      timezone,
      cutoff_time: cutoffTime,
      cutoff_passed: isPastCutoff,
      is_working_day: isWorkingDay,
      on_leave_today: Boolean(leaveToday),
      is_snoozed: Boolean(snoozeRow),
      has_updated_today: Boolean(todayUpdate),
      should_remind_banner: Boolean(isWorkingDay && isPastCutoff && !leaveToday && !snoozeRow && !todayUpdate && pendingCards.length > 0),
      show_sidebar_badge: Boolean(isWorkingDay && !leaveToday && !snoozeRow && !todayUpdate && pendingCards.length > 0),
      cards: pendingCards
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// 3. POST /api/workspaces/:id/daily-update (Submit or upsert today's update)
// ---------------------------------------------------------------------------
router.post('/:id/daily-update', requireAuth, requirePermission('checkin.create'), trackerWriteLimiter, async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  if (!workspaceId || workspaceId <= 0) {
    return res.status(400).json({ error: { message: 'Invalid workspace ID', code: 'BAD_REQUEST' } });
  }

  try {
    const isMember = await ensureWorkspaceMember(req.db, workspaceId, req.user.id);
    if (!isMember) {
      return res.status(403).json({ error: { message: 'Access denied to workspace', code: 'FORBIDDEN' } });
    }

    const ws = await getWorkspaceSettings(req.db, workspaceId);
    if (!ws) {
      return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
    }

    const { timezone } = getWorkspaceCalendarConfig(ws.settings);
    const { dateStr: todayStr } = getWorkspaceNowParts(timezone, new Date());

    if (req.body.work_date && String(req.body.work_date).trim() !== todayStr) {
      return res.status(400).json({
        error: { message: 'Daily updates cannot be back-dated. Server workspace date is required.', code: 'CHECKIN_BACKDATING_PROHIBITED' }
      });
    }

    const rawItems = Array.isArray(req.body.items) ? req.body.items : [];
    const summaryNoteRaw = req.body.summary_note ? sanitizePlain(String(req.body.summary_note).trim()) : null;
    if (summaryNoteRaw && summaryNoteRaw.length > MAX_NOTE_LEN) {
      return res.status(400).json({
        error: { message: `Summary note cannot exceed ${MAX_NOTE_LEN} characters.`, code: 'NOTE_TOO_LONG' }
      });
    }

    if (rawItems.length === 0 && !summaryNoteRaw) {
      return res.status(400).json({
        error: { message: 'Please include at least one task status or a brief note.', code: 'EMPTY_DAILY_UPDATE' }
      });
    }

    const validStatuses = ['working', 'done_today', 'blocked'];
    const sanitizedItems = [];
    for (const item of rawItems) {
      const cardId = Number(item.card_id);
      if (!cardId || cardId <= 0) {
        return res.status(400).json({ error: { message: 'Invalid card_id in items.', code: 'BAD_REQUEST' } });
      }
      const status = validStatuses.includes(item.status) ? item.status : 'working';
      const note = item.note ? sanitizePlain(String(item.note).trim()) : null;
      if (note && note.length > MAX_NOTE_LEN) {
        return res.status(400).json({
          error: { message: `Task note cannot exceed ${MAX_NOTE_LEN} characters.`, code: 'NOTE_TOO_LONG' }
        });
      }
      if (status === 'blocked' && (!note || note.length === 0)) {
        return res.status(400).json({
          error: { message: 'Please add a short note explaining what is blocking you.', code: 'BLOCKER_NOTE_REQUIRED' }
        });
      }

      // Verify card belongs to workspace and user is assigned
      const [assigned] = await req.db.query(
        `SELECT c.id FROM cards c
         JOIN card_members cm ON c.id = cm.card_id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE c.id = ? AND b.workspace_id = ? AND cm.user_id = ?`,
        [cardId, workspaceId, req.user.id]
      );
      if (!assigned) {
        return res.status(403).json({
          error: { message: `You can only update cards assigned to you in this workspace (card #${cardId}).`, code: 'FORBIDDEN' }
        });
      }

      const evidenceUrl = item.evidence_url ? String(item.evidence_url).trim().slice(0, 1000) : null;
      const isLongTask = Boolean(item.is_long_task);
      const expectedFinishDate = isLongTask && item.expected_finish_date && /^\d{4}-\d{2}-\d{2}$/.test(String(item.expected_finish_date).trim())
        ? String(item.expected_finish_date).trim()
        : null;

      sanitizedItems.push({
        card_id: cardId,
        status,
        note,
        evidence_url: evidenceUrl,
        is_long_task: isLongTask ? 1 : 0,
        expected_finish_date: expectedFinishDate
      });
    }

    const overallStatus = sanitizedItems.some((i) => i.status === 'blocked') ? 'blocked' : 'on_track';

    // Check yesterday's items for silent anti-cheat flags
    const [yesterdayRow] = await req.db.query(
      `SELECT id FROM daily_updates
       WHERE workspace_id = ? AND user_id = ? AND work_date < ?
       ORDER BY work_date DESC LIMIT 1`,
      [workspaceId, req.user.id, todayStr]
    );
    let yesterdayItems = [];
    if (yesterdayRow) {
      yesterdayItems = await req.db.query(
        'SELECT card_id, status, note FROM daily_update_items WHERE daily_update_id = ?',
        [yesterdayRow.id]
      );
    }

    // Check existing update today (handles double-submit & two-device edit)
    const [existing] = await req.db.query(
      'SELECT * FROM daily_updates WHERE workspace_id = ? AND user_id = ? AND work_date = ?',
      [workspaceId, req.user.id, todayStr]
    );

    if (existing && req.body.expected_version !== undefined && Number(req.body.expected_version) !== Number(existing.version)) {
      return res.status(409).json({
        error: {
          message: 'This daily update was modified on another tab or device. Please refresh to load the latest version.',
          code: 'CONFLICT_VERSION_MISMATCH',
          current_version: existing.version
        }
      });
    }

    let dailyUpdateId;
    let isEdit = false;

    if (existing) {
      isEdit = true;
      dailyUpdateId = existing.id;
      const prevItems = await req.db.query('SELECT card_id, status, note FROM daily_update_items WHERE daily_update_id = ?', [dailyUpdateId]);
      let history = [];
      try {
        history = existing.edit_history
          ? (typeof existing.edit_history === 'string' ? JSON.parse(existing.edit_history) : existing.edit_history)
          : [];
      } catch { history = []; }
      history.push({
        edited_at: new Date().toISOString(),
        previous_status: existing.status,
        previous_summary_note: existing.summary_note,
        previous_items: prevItems
      });

      const flags = computeSilentFlags({
        items: sanitizedItems,
        yesterdayItems,
        dailyUpdate: { edited_at: new Date() }
      });

      await req.db.execute(
        `UPDATE daily_updates
         SET status = ?, summary_note = ?, edit_history = ?, flags = ?, version = version + 1, edited_at = NOW()
         WHERE id = ?`,
        [overallStatus, summaryNoteRaw, JSON.stringify(history), JSON.stringify(flags), dailyUpdateId]
      );
    } else {
      const originalHash = computeUpdateHash(sanitizedItems, summaryNoteRaw);
      const flags = computeSilentFlags({ items: sanitizedItems, yesterdayItems });
      const ins = await req.db.execute(
        `INSERT INTO daily_updates (workspace_id, user_id, work_date, status, summary_note, original_text_hash, flags, version, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1, NOW())`,
        [workspaceId, req.user.id, todayStr, overallStatus, summaryNoteRaw, originalHash, JSON.stringify(flags)]
      );
      dailyUpdateId = ins.insertId;
    }

    // Upsert items & long-task preferences
    for (const item of sanitizedItems) {
      await req.db.execute(
        `INSERT INTO daily_update_items (daily_update_id, card_id, status, note, evidence_url, is_long_task, expected_finish_date, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
         ON DUPLICATE KEY UPDATE
           status = VALUES(status),
           note = VALUES(note),
           evidence_url = VALUES(evidence_url),
           is_long_task = VALUES(is_long_task),
           expected_finish_date = VALUES(expected_finish_date),
           updated_at = NOW()`,
        [dailyUpdateId, item.card_id, item.status, item.note, item.evidence_url, item.is_long_task, item.expected_finish_date]
      );

      if (item.is_long_task) {
        await req.db.execute(
          `INSERT INTO card_long_tasks (card_id, user_id, is_long_task, expected_finish_date, last_noted_at)
           VALUES (?, ?, 1, ?, ?)
           ON DUPLICATE KEY UPDATE
             is_long_task = 1,
             expected_finish_date = VALUES(expected_finish_date),
             last_noted_at = IF(? IS NOT NULL AND ? != '', ?, COALESCE(last_noted_at, ?))`,
          [item.card_id, req.user.id, item.expected_finish_date, todayStr, item.note, item.note, todayStr, todayStr]
        );
      } else {
        await req.db.execute(
          'UPDATE card_long_tasks SET is_long_task = 0 WHERE card_id = ? AND user_id = ?',
          [item.card_id, req.user.id]
        );
      }
    }

    const [savedRow] = await req.db.query('SELECT * FROM daily_updates WHERE id = ?', [dailyUpdateId]);
    const dailyUpdate = await loadDailyUpdateWithItems(req.db, savedRow);

    await auditService.record(req.db, {
      userId: req.user.id,
      workspaceId,
      category: 'checkin',
      action: isEdit ? 'checkin.updated' : 'checkin.created',
      entityType: 'daily_update',
      entityId: dailyUpdateId,
      meta: {
        work_date: todayStr,
        status: overallStatus,
        items_count: sanitizedItems.length,
        version: dailyUpdate.version
      },
      req
    });

    return res.status(isEdit ? 200 : 201).json({ daily_update: dailyUpdate });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// 4. PATCH /api/workspaces/:id/daily-update/:updateId (Edit until end of day)
// ---------------------------------------------------------------------------
router.patch('/:id/daily-update/:updateId', requireAuth, requirePermission('checkin.create'), trackerWriteLimiter, async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const updateId = Number(req.params.updateId);
  if (!workspaceId || !updateId) {
    return res.status(400).json({ error: { message: 'Invalid workspace or update ID', code: 'BAD_REQUEST' } });
  }

  try {
    const [existing] = await req.db.query(
      'SELECT * FROM daily_updates WHERE id = ? AND workspace_id = ?',
      [updateId, workspaceId]
    );
    if (!existing) {
      return res.status(404).json({ error: { message: 'Daily update not found', code: 'NOT_FOUND' } });
    }
    if (Number(existing.user_id) !== Number(req.user.id)) {
      return res.status(403).json({ error: { message: 'Only the author can edit this daily update.', code: 'FORBIDDEN' } });
    }

    const ws = await getWorkspaceSettings(req.db, workspaceId);
    const { timezone } = getWorkspaceCalendarConfig(ws?.settings);
    const { dateStr: todayStr } = getWorkspaceNowParts(timezone, new Date());
    const workDateStr = typeof existing.work_date === 'string'
      ? existing.work_date.slice(0, 10)
      : new Date(existing.work_date).toISOString().slice(0, 10);

    // End-of-day rule in workspace timezone
    if (workDateStr !== todayStr) {
      return res.status(400).json({
        error: {
          message: 'Daily updates can only be edited until the end of the day in the workspace timezone.',
          code: 'EDIT_WINDOW_EXPIRED'
        }
      });
    }

    if (req.body.expected_version !== undefined && Number(req.body.expected_version) !== Number(existing.version)) {
      return res.status(409).json({
        error: {
          message: 'This daily update was modified on another tab or device. Please refresh to load the latest version.',
          code: 'CONFLICT_VERSION_MISMATCH',
          current_version: existing.version
        }
      });
    }

    // Reuse the same validation logic by delegating to items validation
    const rawItems = Array.isArray(req.body.items) ? req.body.items : [];
    const summaryNoteRaw = req.body.summary_note !== undefined
      ? (req.body.summary_note ? sanitizePlain(String(req.body.summary_note).trim()) : null)
      : existing.summary_note;
    if (summaryNoteRaw && summaryNoteRaw.length > MAX_NOTE_LEN) {
      return res.status(400).json({
        error: { message: `Summary note cannot exceed ${MAX_NOTE_LEN} characters.`, code: 'NOTE_TOO_LONG' }
      });
    }

    const validStatuses = ['working', 'done_today', 'blocked'];
    const sanitizedItems = [];
    for (const item of rawItems) {
      const cardId = Number(item.card_id);
      if (!cardId || cardId <= 0) {
        return res.status(400).json({ error: { message: 'Invalid card_id in items.', code: 'BAD_REQUEST' } });
      }
      const status = validStatuses.includes(item.status) ? item.status : 'working';
      const note = item.note ? sanitizePlain(String(item.note).trim()) : null;
      if (note && note.length > MAX_NOTE_LEN) {
        return res.status(400).json({
          error: { message: `Task note cannot exceed ${MAX_NOTE_LEN} characters.`, code: 'NOTE_TOO_LONG' }
        });
      }
      if (status === 'blocked' && (!note || note.length === 0)) {
        return res.status(400).json({
          error: { message: 'Please add a short note explaining what is blocking you.', code: 'BLOCKER_NOTE_REQUIRED' }
        });
      }
      const [assigned] = await req.db.query(
        `SELECT c.id FROM cards c
         JOIN card_members cm ON c.id = cm.card_id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE c.id = ? AND b.workspace_id = ? AND cm.user_id = ?`,
        [cardId, workspaceId, req.user.id]
      );
      if (!assigned) {
        return res.status(403).json({
          error: { message: `You can only update cards assigned to you in this workspace (card #${cardId}).`, code: 'FORBIDDEN' }
        });
      }
      const isLongTask = Boolean(item.is_long_task);
      const expectedFinishDate = isLongTask && item.expected_finish_date && /^\d{4}-\d{2}-\d{2}$/.test(String(item.expected_finish_date).trim())
        ? String(item.expected_finish_date).trim()
        : null;
      sanitizedItems.push({
        card_id: cardId,
        status,
        note,
        evidence_url: item.evidence_url ? String(item.evidence_url).trim().slice(0, 1000) : null,
        is_long_task: isLongTask ? 1 : 0,
        expected_finish_date: expectedFinishDate
      });
    }

    const prevItems = await req.db.query('SELECT card_id, status, note FROM daily_update_items WHERE daily_update_id = ?', [updateId]);
    let history = [];
    try {
      history = existing.edit_history
        ? (typeof existing.edit_history === 'string' ? JSON.parse(existing.edit_history) : existing.edit_history)
        : [];
    } catch { history = []; }
    history.push({
      edited_at: new Date().toISOString(),
      previous_status: existing.status,
      previous_summary_note: existing.summary_note,
      previous_items: prevItems
    });

    const overallStatus = sanitizedItems.length > 0
      ? (sanitizedItems.some((i) => i.status === 'blocked') ? 'blocked' : 'on_track')
      : existing.status;

    const [yesterdayRow] = await req.db.query(
      `SELECT id FROM daily_updates
       WHERE workspace_id = ? AND user_id = ? AND work_date < ?
       ORDER BY work_date DESC LIMIT 1`,
      [workspaceId, req.user.id, todayStr]
    );
    const yesterdayItems = yesterdayRow
      ? await req.db.query('SELECT card_id, status, note FROM daily_update_items WHERE daily_update_id = ?', [yesterdayRow.id])
      : [];

    const flags = computeSilentFlags({
      items: sanitizedItems,
      yesterdayItems,
      dailyUpdate: { edited_at: new Date() }
    });

    await req.db.execute(
      `UPDATE daily_updates
       SET status = ?, summary_note = ?, edit_history = ?, flags = ?, version = version + 1, edited_at = NOW()
       WHERE id = ?`,
      [overallStatus, summaryNoteRaw, JSON.stringify(history), JSON.stringify(flags), updateId]
    );

    for (const item of sanitizedItems) {
      await req.db.execute(
        `INSERT INTO daily_update_items (daily_update_id, card_id, status, note, evidence_url, is_long_task, expected_finish_date, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
         ON DUPLICATE KEY UPDATE
           status = VALUES(status),
           note = VALUES(note),
           evidence_url = VALUES(evidence_url),
           is_long_task = VALUES(is_long_task),
           expected_finish_date = VALUES(expected_finish_date),
           updated_at = NOW()`,
        [updateId, item.card_id, item.status, item.note, item.evidence_url, item.is_long_task, item.expected_finish_date]
      );
      if (item.is_long_task) {
        await req.db.execute(
          `INSERT INTO card_long_tasks (card_id, user_id, is_long_task, expected_finish_date, last_noted_at)
           VALUES (?, ?, 1, ?, ?)
           ON DUPLICATE KEY UPDATE
             is_long_task = 1,
             expected_finish_date = VALUES(expected_finish_date),
             last_noted_at = IF(? IS NOT NULL AND ? != '', ?, COALESCE(last_noted_at, ?))`,
          [item.card_id, req.user.id, item.expected_finish_date, todayStr, item.note, item.note, todayStr, todayStr]
        );
      } else {
        await req.db.execute(
          'UPDATE card_long_tasks SET is_long_task = 0 WHERE card_id = ? AND user_id = ?',
          [item.card_id, req.user.id]
        );
      }
    }

    const [savedRow] = await req.db.query('SELECT * FROM daily_updates WHERE id = ?', [updateId]);
    const dailyUpdate = await loadDailyUpdateWithItems(req.db, savedRow);

    await auditService.record(req.db, {
      userId: req.user.id,
      workspaceId,
      category: 'checkin',
      action: 'checkin.updated',
      entityType: 'daily_update',
      entityId: updateId,
      meta: {
        work_date: todayStr,
        status: overallStatus,
        items_count: sanitizedItems.length,
        version: dailyUpdate.version
      },
      req
    });

    return res.json({ daily_update: dailyUpdate });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// 5. POST /api/workspaces/:id/daily-tracker/snooze (Server-side snooze until tomorrow)
// ---------------------------------------------------------------------------
router.post('/:id/daily-tracker/snooze', requireAuth, requirePermission('checkin.create'), trackerWriteLimiter, async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  if (!workspaceId || workspaceId <= 0) {
    return res.status(400).json({ error: { message: 'Invalid workspace ID', code: 'BAD_REQUEST' } });
  }
  try {
    const isMember = await ensureWorkspaceMember(req.db, workspaceId, req.user.id);
    if (!isMember) {
      return res.status(403).json({ error: { message: 'Access denied to workspace', code: 'FORBIDDEN' } });
    }
    const ws = await getWorkspaceSettings(req.db, workspaceId);
    const { timezone } = getWorkspaceCalendarConfig(ws?.settings);
    const { dateStr: todayStr } = getWorkspaceNowParts(timezone, new Date());
    const untilStr = addDaysToDateStr(todayStr, 1);

    await req.db.execute(
      `INSERT INTO daily_tracker_snoozes (workspace_id, user_id, snoozed_date, snoozed_until_date, created_at)
       VALUES (?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE snoozed_until_date = VALUES(snoozed_until_date)`,
      [workspaceId, req.user.id, todayStr, untilStr]
    );

    await auditService.record(req.db, {
      userId: req.user.id,
      workspaceId,
      category: 'checkin',
      action: 'checkin.updated',
      entityType: 'daily_tracker_snooze',
      entityId: req.user.id,
      meta: { action: 'snooze_until_tomorrow', snoozed_date: todayStr, snoozed_until_date: untilStr },
      req
    });

    return res.json({ success: true, snoozed_date: todayStr, snoozed_until_date: untilStr });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// 6. POST /api/workspaces/:id/daily-tracker/leave-today (One-click "I'm on leave today")
// ---------------------------------------------------------------------------
router.post('/:id/daily-tracker/leave-today', requireAuth, requirePermission('leave.request'), trackerWriteLimiter, async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  if (!workspaceId || workspaceId <= 0) {
    return res.status(400).json({ error: { message: 'Invalid workspace ID', code: 'BAD_REQUEST' } });
  }
  try {
    const isMember = await ensureWorkspaceMember(req.db, workspaceId, req.user.id);
    if (!isMember) {
      return res.status(403).json({ error: { message: 'Access denied to workspace', code: 'FORBIDDEN' } });
    }
    const ws = await getWorkspaceSettings(req.db, workspaceId);
    const { timezone } = getWorkspaceCalendarConfig(ws?.settings);
    const { dateStr: todayStr } = getWorkspaceNowParts(timezone, new Date());
    const reason = req.body.reason ? sanitizePlain(String(req.body.reason).trim()).slice(0, 200) : 'On leave today';

    await req.db.execute(
      `INSERT INTO leave_days (user_id, date, reason, status, requested_by, approved_by, approved_at, created_at)
       VALUES (?, ?, ?, 'approved', ?, ?, NOW(), NOW())
       ON DUPLICATE KEY UPDATE reason = VALUES(reason), status = 'approved', approved_by = VALUES(approved_by), approved_at = NOW()`,
      [req.user.id, todayStr, reason, req.user.id, req.user.id]
    );

    const [row] = await req.db.query('SELECT * FROM leave_days WHERE user_id = ? AND date = ?', [req.user.id, todayStr]);

    await auditService.record(req.db, {
      userId: req.user.id,
      workspaceId,
      category: 'leave',
      action: 'leave.requested',
      entityType: 'leave_day',
      entityId: row?.id || req.user.id,
      meta: { date: todayStr, self_declared_today: true, status: 'approved', reason },
      req
    });

    return res.status(201).json({ leave_day: row, date: todayStr });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// Shared People Computation (used by /people and /people/export)
// ---------------------------------------------------------------------------
async function computePeopleViewData(db, { workspaceId, userId, query = {} }) {
  const ws = await getWorkspaceSettings(db, workspaceId);
  if (!ws) {
    const err = new Error('Workspace not found');
    err.status = 404;
    throw err;
  }

  const { timezone, workingDays, holidays, cutoffTime } = getWorkspaceCalendarConfig(ws.settings);
  const now = new Date();
  const { dateStr: todayStr, hour, minute } = getWorkspaceNowParts(timezone, now);
  const [cutH, cutM] = cutoffTime.split(':').map(Number);
  const isPastCutoff = hour > cutH || (hour === cutH && minute >= (cutM || 0));

  const targetDate = query.date && /^\d{4}-\d{2}-\d{2}$/.test(String(query.date).trim())
    ? String(query.date).trim()
    : todayStr;
  const startDate = query.start_date && /^\d{4}-\d{2}-\d{2}$/.test(String(query.start_date).trim())
    ? String(query.start_date).trim()
    : targetDate;
  const endDate = query.end_date && /^\d{4}-\d{2}-\d{2}$/.test(String(query.end_date).trim())
    ? String(query.end_date).trim()
    : targetDate;

  const isWorkingDay = isWorkingDayDate(targetDate, workingDays, holidays);
  const { startUtc, endUtc } = getUtcRangeForDate(targetDate, timezone);

  // Determine workspace filter (default to route workspaceId, or 'all' if user has project.access_all)
  const filterWsId = query.workspace_id && query.workspace_id !== 'all' ? Number(query.workspace_id) : workspaceId;
  const filterBoardId = query.board_id && query.board_id !== 'all' ? Number(query.board_id) : null;
  const filterMemberId = query.member_id && query.member_id !== 'all' ? Number(query.member_id) : null;
  const filterRole = query.role && query.role !== 'all' ? String(query.role).trim().toLowerCase() : null;
  const filterState = query.state && query.state !== 'all' ? String(query.state).trim() : null;
  const searchStr = query.search ? String(query.search).trim().toLowerCase() : '';

  // Check if user is restricted to boards they belong to (e.g., Team Lead vs Owner/Admin/PM with project.access_all)
  const hasAccessAll = await userHasPermission(userId, filterWsId, 'project.access_all', db);
  let allowedBoardIds = null;
  if (!hasAccessAll) {
    const myBoards = await db.query(
      `SELECT b.id FROM boards b
       JOIN board_members bm ON b.id = bm.board_id
       WHERE b.workspace_id = ? AND bm.user_id = ? AND (b.is_archived = 0 OR b.is_archived IS NULL)`,
      [filterWsId, userId]
    );
    allowedBoardIds = myBoards.map((b) => b.id);
  }

  const allBoards = await db.query(
    `SELECT id, name FROM boards WHERE workspace_id = ? AND (is_archived = 0 OR is_archived IS NULL) ORDER BY name ASC`,
    [filterWsId]
  );

  let members = await db.query(
    `SELECT u.id, u.name, u.email, u.avatar_url, r.name AS role_name
     FROM workspace_members wm
     JOIN users u ON wm.user_id = u.id
     JOIN roles r ON wm.role_id = r.id
     WHERE wm.workspace_id = ?
     ORDER BY u.name ASC`,
    [filterWsId]
  );

  // Filter members by allowed boards if Team Lead doesn't have project.access_all
  if (allowedBoardIds !== null) {
    if (allowedBoardIds.length === 0) {
      members = [];
    } else {
      const bmRows = await db.query(
        'SELECT DISTINCT user_id FROM board_members WHERE board_id IN (?)',
        [allowedBoardIds]
      );
      const allowedUserSet = new Set(bmRows.map((r) => Number(r.user_id)));
      allowedUserSet.add(Number(userId));
      members = members.filter((m) => allowedUserSet.has(Number(m.id)));
    }
  }

  // Distinct roles for filter dropdown
  const distinctRoles = Array.from(new Set(members.map((m) => m.role_name).filter(Boolean))).sort();

  if (members.length === 0) {
    return {
      date: targetDate,
      start_date: startDate,
      end_date: endDate,
      timezone,
      is_working_day: isWorkingDay,
      cutoff_passed: isPastCutoff,
      cutoff_time: cutoffTime,
      state_meta: STATE_META,
      counts: { all: 0, on_track: 0, blocked: 0, not_updated: 0, on_leave: 0, no_tasks: 0 },
      pending_requests: [],
      filter_options: { boards: allBoards, roles: distinctRoles },
      people: []
    };
  }

  const memberIds = members.map((m) => m.id);

  // Leave days on targetDate
  const leaveRows = await db.query(
    "SELECT user_id, reason FROM leave_days WHERE date = ? AND user_id IN (?) AND status = 'approved'",
    [targetDate, memberIds]
  );
  const leaveMap = {};
  leaveRows.forEach((r) => { leaveMap[r.user_id] = r; });

  const pendingLeaveRows = await db.query(
    `SELECT ld.id, ld.user_id, ld.date, ld.reason, ld.status, ld.created_at, u.name AS user_name
     FROM leave_days ld
     JOIN users u ON ld.user_id = u.id
     WHERE ld.user_id IN (?) AND ld.status = 'pending'
     ORDER BY ld.date ASC`,
    [memberIds]
  );

  // Open cards assigned to members
  let openCardsQuery = `
    SELECT c.id, c.title, c.created_at, c.created_by, c.first_moved_or_assigned_at, c.due_date, c.list_id,
           l.board_id, b.name AS board_title, cm.user_id,
           clt.is_long_task, clt.expected_finish_date, clt.last_noted_at
    FROM cards c
    JOIN card_members cm ON c.id = cm.card_id
    JOIN lists l ON c.list_id = l.id
    JOIN boards b ON l.board_id = b.id
    LEFT JOIN card_long_tasks clt ON clt.card_id = c.id AND clt.user_id = cm.user_id
    WHERE b.workspace_id = ?
      AND cm.user_id IN (?)
      AND (c.is_complete = 0 OR c.is_complete IS NULL)
      AND (c.is_archived = 0 OR c.is_archived IS NULL)
      AND (l.is_archived = 0 OR l.is_archived IS NULL)
      AND (b.is_archived = 0 OR b.is_archived IS NULL)
      AND (l.is_done_list = 0 OR l.is_done_list IS NULL)
      AND LOWER(TRIM(l.name)) NOT IN ('done', 'completed', 'complete', 'closed', 'finished', 'resolved', 'archive', 'archived')`;
  const openCardsParams = [filterWsId, memberIds];
  if (filterBoardId) {
    openCardsQuery += ' AND b.id = ?';
    openCardsParams.push(filterBoardId);
  }
  openCardsQuery += ' ORDER BY COALESCE(c.first_moved_or_assigned_at, c.created_at) ASC, c.id ASC';
  const openCardRows = await db.query(openCardsQuery, openCardsParams);
  const openCardsMap = {};
  openCardRows.forEach((c) => {
    if (!openCardsMap[c.user_id]) openCardsMap[c.user_id] = [];
    openCardsMap[c.user_id].push(c);
  });

  // Completed cards on targetDate
  const completedCardRows = await db.query(
    `SELECT c.id, c.title, c.created_by, c.completed_at, c.completed_by, c.first_moved_or_assigned_at, c.created_at,
            c.completion_note, c.completion_evidence_url
     FROM cards c
     JOIN lists l ON c.list_id = l.id
     JOIN boards b ON l.board_id = b.id
     WHERE b.workspace_id = ?
       AND c.completed_by IN (?)
       AND c.completed_at >= ? AND c.completed_at < ?`,
    [filterWsId, memberIds, startUtc, endUtc]
  );
  const completedCardsMap = {};
  completedCardRows.forEach((c) => {
    if (!completedCardsMap[c.completed_by]) completedCardsMap[c.completed_by] = [];
    completedCardsMap[c.completed_by].push(c);
  });

  // Daily updates on targetDate
  const duRows = await db.query(
    'SELECT * FROM daily_updates WHERE workspace_id = ? AND user_id IN (?) AND work_date = ?',
    [filterWsId, memberIds, targetDate]
  );
  const duMap = {};
  const duIds = duRows.map((d) => d.id);
  duRows.forEach((d) => { duMap[d.user_id] = d; });

  const duiMap = {};
  const reviewMap = {};
  if (duIds.length > 0) {
    const duiRows = await db.query(
      `SELECT dui.*, c.title AS card_title
       FROM daily_update_items dui
       JOIN cards c ON dui.card_id = c.id
       WHERE dui.daily_update_id IN (?)
       ORDER BY dui.id ASC`,
      [duIds]
    );
    duiRows.forEach((it) => {
      if (!duiMap[it.daily_update_id]) duiMap[it.daily_update_id] = [];
      duiMap[it.daily_update_id].push(it);
    });
    const revRows = await db.query(
      `SELECT r.*, u.name AS reviewer_name
       FROM check_in_reviews r
       JOIN users u ON r.reviewer_id = u.id
       WHERE r.daily_update_id IN (?)
       ORDER BY r.created_at ASC`,
      [duIds]
    );
    revRows.forEach((r) => {
      if (!reviewMap[r.daily_update_id]) reviewMap[r.daily_update_id] = [];
      reviewMap[r.daily_update_id].push(r);
    });
  }

  // Activity signals on targetDate (card moved/completed, checklist tick, attachment, comment, time logged)
  const actRows = await db.query(
    `SELECT a.user_id, a.card_id, a.action_type, a.meta_json, a.created_at
     FROM activity_log a
     WHERE a.user_id IN (?) AND a.created_at >= ? AND a.created_at < ?`,
    [memberIds, startUtc, endUtc]
  );
  const actMap = {};
  actRows.forEach((a) => {
    if (!actMap[a.user_id]) actMap[a.user_id] = [];
    actMap[a.user_id].push(a);
  });

  const commRows = await db.query(
    `SELECT co.user_id, co.card_id, co.body, co.created_at
     FROM comments co
     WHERE co.user_id IN (?) AND co.created_at >= ? AND co.created_at < ?`,
    [memberIds, startUtc, endUtc]
  );
  const commMap = {};
  commRows.forEach((c) => {
    if (!commMap[c.user_id]) commMap[c.user_id] = [];
    commMap[c.user_id].push(c);
  });

  // Weekly summary (last 7 working days ending at endDate)
  const weekDays = getLastNWorkingDays(endDate, 7, workingDays, holidays);
  const weekStart = weekDays[weekDays.length - 1] || endDate;
  const weekUpdates = await db.query(
    `SELECT user_id, work_date, status FROM daily_updates
     WHERE workspace_id = ? AND user_id IN (?) AND work_date >= ? AND work_date <= ?`,
    [filterWsId, memberIds, weekStart, endDate]
  );
  const weekLeaves = await db.query(
    `SELECT user_id, date FROM leave_days
     WHERE user_id IN (?) AND status = 'approved' AND date >= ? AND date <= ?`,
    [memberIds, weekStart, endDate]
  );
  const weekUpdateByUser = {};
  weekUpdates.forEach((u) => {
    const wd = typeof u.work_date === 'string' ? u.work_date.slice(0, 10) : new Date(u.work_date).toISOString().slice(0, 10);
    if (!weekUpdateByUser[u.user_id]) weekUpdateByUser[u.user_id] = new Map();
    weekUpdateByUser[u.user_id].set(wd, u.status);
  });
  const weekLeaveByUser = {};
  weekLeaves.forEach((l) => {
    const ld = typeof l.date === 'string' ? l.date.slice(0, 10) : new Date(l.date).toISOString().slice(0, 10);
    if (!weekLeaveByUser[l.user_id]) weekLeaveByUser[l.user_id] = new Set();
    weekLeaveByUser[l.user_id].add(ld);
  });

  let people = members.map((m) => {
    const userLeave = leaveMap[m.id];
    const userOpenCards = openCardsMap[m.id] || [];
    const userCompletedCards = completedCardsMap[m.id] || [];
    const userDu = duMap[m.id] || null;
    const userItems = userDu ? (duiMap[userDu.id] || []) : [];
    const userReviews = userDu ? (reviewMap[userDu.id] || []) : [];
    const userActs = actMap[m.id] || [];
    const userComms = commMap[m.id] || [];

    const checkedItems = [];
    const commentSnippets = [];
    const files = [];
    const movedCards = [];

    for (const a of userActs) {
      let meta = a.meta_json;
      if (typeof meta === 'string') { try { meta = JSON.parse(meta); } catch { meta = {}; } }
      meta = meta || {};
      if (a.action_type === 'checklist_toggled' && (meta.is_checked === true || meta.is_checked === 1 || String(meta.is_checked) === 'true')) {
        checkedItems.push(meta.item_text || 'Checklist item');
      } else if (a.action_type === 'attachment_uploaded' || a.action_type === 'attachment_added') {
        files.push({ name: meta.file_name || 'File', url: meta.file_url || null });
      } else if (a.action_type === 'moved_card') {
        movedCards.push({ card_id: a.card_id, from: meta.from, to: meta.to });
      }
    }
    for (const cm of userComms) {
      if (cm.body && cm.body.trim().length > 0) {
        commentSnippets.push(cm.body.trim().slice(0, 80));
      }
    }

    // Exclude trivial self-created cards completed within 3 minutes with no other signals
    const realCompletedCards = userCompletedCards.filter((c) => {
      const isSelfCreated = Number(c.created_by) === Number(m.id);
      const startRef = new Date(c.first_moved_or_assigned_at || c.created_at).getTime();
      const endRef = new Date(c.completed_at).getTime();
      const rapid = (endRef - startRef) / (1000 * 60) <= 3;
      return !(isSelfCreated && rapid && checkedItems.length === 0 && files.length === 0 && commentSnippets.length === 0);
    });

    const hasWorkSignal =
      checkedItems.length > 0 ||
      commentSnippets.length > 0 ||
      files.length > 0 ||
      movedCards.length > 0 ||
      realCompletedCards.length > 0;

    const hasBlockedItem = userItems.some((it) => it.status === 'blocked') || userDu?.status === 'blocked';
    const allCardsLongTaskCovered = userOpenCards.length > 0 && userOpenCards.every((c) => isLongTaskCovered(c, targetDate, workingDays, holidays));

    const state = computeMemberDailyState({
      onLeave: Boolean(userLeave),
      activeCardsCount: userOpenCards.length,
      hasBlockedItem,
      hasDailyUpdate: Boolean(userDu),
      hasWorkSignal,
      allCardsLongTaskCovered
    });

    const meta = STATE_META[state];
    let silentFlags = [];
    if (userDu?.flags) {
      try {
        silentFlags = typeof userDu.flags === 'string' ? JSON.parse(userDu.flags) : userDu.flags;
      } catch { silentFlags = []; }
    }
    const rapidFlags = computeSilentFlags({ completedCards: userCompletedCards, activities: userActs });
    const allFlags = Array.from(new Set([...(Array.isArray(silentFlags) ? silentFlags : []), ...rapidFlags]));

    // Weekly summary
    const uWeekMap = weekUpdateByUser[m.id] || new Map();
    const uLeaveSet = weekLeaveByUser[m.id] || new Set();
    let daysUpdated = 0;
    let daysBlocked = 0;
    let daysOnLeave = 0;
    for (const wd of weekDays) {
      if (uLeaveSet.has(wd)) {
        daysOnLeave++;
      } else if (uWeekMap.has(wd)) {
        daysUpdated++;
        if (uWeekMap.get(wd) === 'blocked') daysBlocked++;
      }
    }

    return {
      id: m.id,
      name: m.name,
      email: m.email,
      avatar_url: m.avatar_url,
      role: m.role_name,
      state,
      state_label: meta.label,
      state_color: meta.color,
      state_icon: meta.icon,
      state_tooltip: meta.tooltip,
      open_cards_count: userOpenCards.length,
      open_cards: userOpenCards.map((c) => ({
        id: c.id,
        card_id: c.id,
        title: c.title,
        board_id: c.board_id,
        board_title: c.board_title,
        due_date: c.due_date,
        is_long_task: Boolean(c.is_long_task),
        expected_finish_date: c.expected_finish_date,
        long_task_covered: isLongTaskCovered(c, targetDate, workingDays, holidays)
      })),
      daily_update: userDu ? {
        id: userDu.id,
        work_date: targetDate,
        status: userDu.status,
        summary_note: userDu.summary_note,
        edited_at: userDu.edited_at,
        created_at: userDu.created_at,
        items: userItems,
        reviews: userReviews
      } : null,
      evidence: {
        checked_items: checkedItems,
        comments: commentSnippets,
        files,
        moved_cards: movedCards,
        completed_cards: userCompletedCards.map((c) => ({
          id: c.id,
          card_id: c.id,
          title: c.title,
          completed_at: c.completed_at,
          completion_note: c.completion_note,
          completion_evidence_url: c.completion_evidence_url
        }))
      },
      weekly_summary: {
        working_days: weekDays.length,
        days_updated: daysUpdated,
        days_blocked: daysBlocked,
        days_on_leave: daysOnLeave
      },
      silent_flags: allFlags,
      leave_reason: userLeave?.reason || null
    };
  });

  // Counts before state filter (after board/member/role/search filters)
  if (filterMemberId) {
    people = people.filter((p) => Number(p.id) === filterMemberId);
  }
  if (filterRole) {
    people = people.filter((p) => String(p.role || '').toLowerCase() === filterRole);
  }
  if (searchStr) {
    people = people.filter((p) =>
      String(p.name || '').toLowerCase().includes(searchStr) ||
      String(p.email || '').toLowerCase().includes(searchStr)
    );
  }

  const counts = {
    all: people.length,
    on_track: people.filter((p) => p.state === STATE_CODES.ON_TRACK).length,
    blocked: people.filter((p) => p.state === STATE_CODES.BLOCKED).length,
    not_updated: people.filter((p) => p.state === STATE_CODES.NOT_UPDATED).length,
    on_leave: people.filter((p) => p.state === STATE_CODES.ON_LEAVE).length,
    no_tasks: people.filter((p) => p.state === STATE_CODES.NO_TASKS).length
  };

  if (filterState && Object.values(STATE_CODES).includes(filterState)) {
    people = people.filter((p) => p.state === filterState);
  }

  // Problem-first sort: blocked -> not_updated -> on_track -> no_tasks -> on_leave
  people.sort((a, b) => {
    const pA = STATE_META[a.state]?.priority || 99;
    const pB = STATE_META[b.state]?.priority || 99;
    if (pA !== pB) return pA - pB;
    return a.name.localeCompare(b.name);
  });

  return {
    date: targetDate,
    start_date: startDate,
    end_date: endDate,
    timezone,
    is_working_day: isWorkingDay,
    cutoff_passed: isPastCutoff,
    cutoff_time: cutoffTime,
    state_meta: STATE_META,
    counts,
    pending_requests: pendingLeaveRows,
    filter_options: { boards: allBoards, roles: distinctRoles },
    people
  };
}

// ---------------------------------------------------------------------------
// 7. GET /api/workspaces/:id/daily-tracker/people
// ---------------------------------------------------------------------------
router.get('/:id/daily-tracker/people', requireAuth, requirePermission('daily_tracker.view_people'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  if (!workspaceId || workspaceId <= 0) {
    return res.status(400).json({ error: { message: 'Invalid workspace ID', code: 'BAD_REQUEST' } });
  }
  try {
    const isMember = await ensureWorkspaceMember(req.db, workspaceId, req.user.id);
    if (!isMember) {
      return res.status(403).json({ error: { message: 'Access denied to workspace', code: 'FORBIDDEN' } });
    }
    const data = await computePeopleViewData(req.db, {
      workspaceId,
      userId: req.user.id,
      query: req.query
    });
    return res.json(data);
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// 8. GET /api/workspaces/:id/daily-tracker/people/export (CSV export)
// ---------------------------------------------------------------------------
router.get('/:id/daily-tracker/people/export', requireAuth, requirePermission('daily_tracker.view_people'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  if (!workspaceId || workspaceId <= 0) {
    return res.status(400).json({ error: { message: 'Invalid workspace ID', code: 'BAD_REQUEST' } });
  }
  try {
    const isMember = await ensureWorkspaceMember(req.db, workspaceId, req.user.id);
    if (!isMember) {
      return res.status(403).json({ error: { message: 'Access denied to workspace', code: 'FORBIDDEN' } });
    }
    const data = await computePeopleViewData(req.db, {
      workspaceId,
      userId: req.user.id,
      query: req.query
    });

    const headers = [
      'Date',
      'Name',
      'Email',
      'Role',
      'State Code',
      'State Label',
      'Open Tasks',
      'Update Status',
      'Summary / Task Notes',
      '7-Day Updated',
      '7-Day Blocked',
      '7-Day On Leave',
      'Silent Flags'
    ];
    const rows = [headers.map(sanitizeCsvCell).join(',')];

    for (const p of data.people) {
      const itemNotes = (p.daily_update?.items || [])
        .map((it) => `${it.card_title} [${it.status}]${it.note ? `: ${it.note}` : ''}`)
        .join(' | ');
      const notesCombined = [p.daily_update?.summary_note, itemNotes].filter(Boolean).join(' — ');
      rows.push([
        data.date,
        p.name,
        p.email,
        p.role,
        p.state,
        p.state_label,
        p.open_cards_count,
        p.daily_update ? p.daily_update.status : 'none',
        notesCombined,
        p.weekly_summary.days_updated,
        p.weekly_summary.days_blocked,
        p.weekly_summary.days_on_leave,
        (p.silent_flags || []).join('; ')
      ].map(sanitizeCsvCell).join(','));
    }

    const csv = rows.join('\r\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="daily-tracker-people-${data.date}.csv"`);
    return res.send(csv);
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// 9. GET /api/workspaces/:id/daily-tracker/people/:userId/timeline (7 working days)
// ---------------------------------------------------------------------------
router.get('/:id/daily-tracker/people/:userId/timeline', requireAuth, requirePermission('daily_tracker.view_people'), async (req, res, next) => {
  const workspaceId = Number(req.params.id);
  const targetUserId = Number(req.params.userId);
  if (!workspaceId || !targetUserId) {
    return res.status(400).json({ error: { message: 'Invalid workspace or user ID', code: 'BAD_REQUEST' } });
  }
  try {
    const isMember = await ensureWorkspaceMember(req.db, workspaceId, req.user.id);
    if (!isMember) {
      return res.status(403).json({ error: { message: 'Access denied to workspace', code: 'FORBIDDEN' } });
    }
    const [targetMember] = await req.db.query(
      `SELECT u.id, u.name, u.email, u.avatar_url, r.name AS role_name
       FROM workspace_members wm
       JOIN users u ON wm.user_id = u.id
       JOIN roles r ON wm.role_id = r.id
       WHERE wm.workspace_id = ? AND u.id = ?`,
      [workspaceId, targetUserId]
    );
    if (!targetMember) {
      return res.status(404).json({ error: { message: 'Member not found in workspace', code: 'NOT_FOUND' } });
    }

    const ws = await getWorkspaceSettings(req.db, workspaceId);
    const { timezone, workingDays, holidays } = getWorkspaceCalendarConfig(ws?.settings);
    const { dateStr: todayStr } = getWorkspaceNowParts(timezone, new Date());
    const endDate = req.query.date && /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.date).trim())
      ? String(req.query.date).trim()
      : todayStr;

    const days = getLastNWorkingDays(endDate, 7, workingDays, holidays);
    const startDate = days[days.length - 1] || endDate;

    const duRows = await req.db.query(
      'SELECT * FROM daily_updates WHERE workspace_id = ? AND user_id = ? AND work_date >= ? AND work_date <= ? ORDER BY work_date DESC',
      [workspaceId, targetUserId, startDate, endDate]
    );
    const duByDate = {};
    for (const row of duRows) {
      const wd = typeof row.work_date === 'string' ? row.work_date.slice(0, 10) : new Date(row.work_date).toISOString().slice(0, 10);
      duByDate[wd] = await loadDailyUpdateWithItems(req.db, row);
    }

    const leaveRows = await dbQuerySafe(
      req.db,
      "SELECT date, reason FROM leave_days WHERE user_id = ? AND status = 'approved' AND date >= ? AND date <= ?",
      [targetUserId, startDate, endDate]
    );
    const leaveByDate = {};
    leaveRows.forEach((l) => {
      const ld = typeof l.date === 'string' ? l.date.slice(0, 10) : new Date(l.date).toISOString().slice(0, 10);
      leaveByDate[ld] = l.reason || 'On leave';
    });

    const timeline = [];
    for (const dayStr of days) {
      const { startUtc, endUtc } = getUtcRangeForDate(dayStr, timezone);
      const acts = await req.db.query(
        `SELECT a.card_id, a.action_type, a.meta_json, a.created_at, c.title AS card_title
         FROM activity_log a
         LEFT JOIN cards c ON a.card_id = c.id
         WHERE a.user_id = ? AND a.created_at >= ? AND a.created_at < ?
           AND a.action_type IN ('moved_card', 'marked_complete', 'checklist_toggled', 'attachment_uploaded', 'comment_added')
         ORDER BY a.created_at DESC
         LIMIT 20`,
        [targetUserId, startUtc, endUtc]
      );
      const du = duByDate[dayStr] || null;
      const onLeave = Boolean(leaveByDate[dayStr]);
      const hasBlocked = du ? (du.status === 'blocked' || (du.items || []).some((i) => i.status === 'blocked')) : false;
      const state = computeMemberDailyState({
        onLeave,
        activeCardsCount: 1,
        hasBlockedItem: hasBlocked,
        hasDailyUpdate: Boolean(du),
        hasWorkSignal: acts.length > 0
      });
      timeline.push({
        date: dayStr,
        state,
        state_label: STATE_META[state].label,
        state_color: STATE_META[state].color,
        leave_reason: leaveByDate[dayStr] || null,
        daily_update: du,
        activities: acts.map((a) => {
          let meta = a.meta_json;
          if (typeof meta === 'string') { try { meta = JSON.parse(meta); } catch { meta = {}; } }
          return { action_type: a.action_type, card_id: a.card_id, card_title: a.card_title, meta, created_at: a.created_at };
        })
      });
    }

    return res.json({
      member: targetMember,
      timezone,
      days: timeline
    });
  } catch (err) {
    next(err);
  }
});

async function dbQuerySafe(db, sql, params) {
  try {
    return await db.query(sql, params);
  } catch {
    return [];
  }
}

module.exports = router;
module.exports.computePeopleViewData = computePeopleViewData;

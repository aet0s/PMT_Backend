// server/src/services/dailyTrackerService.js
// Shared Daily Tracker v3 service: workspace timezone/calendar helpers,
// authoritative 5-state rule table, silent anti-cheat flag detection, and audit helpers.

const crypto = require('crypto');

const STATE_CODES = {
  ON_TRACK: 'on_track',
  BLOCKED: 'blocked',
  NOT_UPDATED: 'not_updated',
  ON_LEAVE: 'on_leave',
  NO_TASKS: 'no_tasks'
};

/**
 * Written Rule Table for Member Daily State (evaluated strictly in priority order):
 *  Priority 1: onLeave === true -> 'on_leave'
 *    Leave (approved) beats everything.
 *  Priority 2: activeCardsCount === 0 && !hasDailyUpdate && !hasBlockedItem -> 'no_tasks'
 *    No active cards assigned and no update/blocker submitted.
 *  Priority 3: hasBlockedItem === true -> 'blocked'
 *    Any item in today's daily update (or legacy check-in) is marked 'blocked'.
 *  Priority 4: hasDailyUpdate === true || hasWorkSignal === true || allCardsLongTaskCovered === true -> 'on_track'
 *    Member submitted a daily update, OR produced a real work signal today,
 *    OR all active cards are marked as long tasks within their 2-3 working-day note cadence.
 *  Priority 5: Otherwise -> 'not_updated'
 *    Has active cards that need an update and no update/signal recorded yet.
 */
const STATE_META = {
  on_track: {
    code: 'on_track',
    label: 'On track',
    color: 'emerald',
    icon: 'check-circle',
    tooltip: 'Updated today or showed real work activity.',
    priority: 3
  },
  blocked: {
    code: 'blocked',
    label: 'Blocked / Needs help',
    color: 'red',
    icon: 'alert-circle',
    tooltip: 'Reported a blocker on one or more tasks and needs help.',
    priority: 1
  },
  not_updated: {
    code: 'not_updated',
    label: 'Not updated yet',
    color: 'amber',
    icon: 'clock',
    tooltip: 'Has active tasks and has not submitted today\'s update yet.',
    priority: 2
  },
  on_leave: {
    code: 'on_leave',
    label: 'On leave',
    color: 'purple',
    icon: 'coffee',
    tooltip: 'On approved leave for this day.',
    priority: 5
  },
  no_tasks: {
    code: 'no_tasks',
    label: 'No tasks assigned',
    color: 'slate',
    icon: 'minus-circle',
    tooltip: 'No active tasks assigned in this workspace.',
    priority: 4
  }
};

function computeMemberDailyState({
  onLeave = false,
  activeCardsCount = 0,
  hasBlockedItem = false,
  hasDailyUpdate = false,
  hasWorkSignal = false,
  allCardsLongTaskCovered = false
}) {
  if (onLeave) return STATE_CODES.ON_LEAVE;
  if (activeCardsCount === 0 && !hasDailyUpdate && !hasBlockedItem) return STATE_CODES.NO_TASKS;
  if (hasBlockedItem) return STATE_CODES.BLOCKED;
  if (hasDailyUpdate || hasWorkSignal || allCardsLongTaskCovered) return STATE_CODES.ON_TRACK;
  return STATE_CODES.NOT_UPDATED;
}

function getWorkspaceCalendarConfig(wsSettingsRaw) {
  let wsSettings = {};
  if (wsSettingsRaw) {
    try {
      wsSettings = typeof wsSettingsRaw === 'string' ? JSON.parse(wsSettingsRaw) : wsSettingsRaw;
    } catch {
      wsSettings = {};
    }
  }
  const timezone = wsSettings?.timezone || 'Asia/Kolkata';
  const workingDays = Array.isArray(wsSettings?.working_days) && wsSettings.working_days.length > 0
    ? wsSettings.working_days.map(Number)
    : [1, 2, 3, 4, 5];
  const holidays = Array.isArray(wsSettings?.holidays) ? wsSettings.holidays : [];
  const cutoffTime = wsSettings?.cutoff_time || '17:00';
  return { timezone, workingDays, holidays, cutoffTime };
}

function getWorkspaceNowParts(timezone = 'Asia/Kolkata', now = new Date()) {
  let dateStr, hour, minute, isoDay;
  try {
    const dateFmt = new Intl.DateTimeFormat('en-CA', {
      timeZone: timezone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    });
    dateStr = dateFmt.format(now);

    const timeFmt = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      hour: 'numeric',
      minute: 'numeric',
      hour12: false
    });
    const parts = timeFmt.formatToParts(now);
    const rawHour = Number(parts.find((p) => p.type === 'hour')?.value || 0);
    hour = rawHour === 24 ? 0 : rawHour;
    minute = Number(parts.find((p) => p.type === 'minute')?.value || 0);

    const dayFmt = new Intl.DateTimeFormat('en-US', { timeZone: timezone, weekday: 'short' });
    const dayShort = dayFmt.format(now);
    const dayMap = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 };
    isoDay = dayMap[dayShort] ?? 1;
  } catch {
    dateStr = now.toISOString().slice(0, 10);
    hour = now.getUTCHours();
    minute = now.getUTCMinutes();
    const jsDay = now.getUTCDay();
    isoDay = jsDay === 0 ? 7 : jsDay;
  }
  return { dateStr, hour, minute, isoDay };
}

function isWorkingDayDate(dateStr, workingDays = [1, 2, 3, 4, 5], holidays = []) {
  if (!dateStr || !/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return false;
  if (holidays.includes(dateStr)) return false;
  const [y, m, d] = dateStr.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d, 12, 0, 0));
  const jsDay = dt.getUTCDay();
  const isoDay = jsDay === 0 ? 7 : jsDay;
  return workingDays.includes(isoDay);
}

function addDaysToDateStr(dateStr, deltaDays) {
  const [y, m, d] = dateStr.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d + deltaDays, 12, 0, 0));
  return dt.toISOString().slice(0, 10);
}

function getLastNWorkingDays(endDateStr, n = 7, workingDays = [1, 2, 3, 4, 5], holidays = []) {
  const result = [];
  let cursor = endDateStr;
  let guard = 0;
  while (result.length < n && guard < 60) {
    if (isWorkingDayDate(cursor, workingDays, holidays)) {
      result.push(cursor);
    }
    cursor = addDaysToDateStr(cursor, -1);
    guard++;
  }
  return result;
}

function calculateWorkingDaysOpen(startDate, endDate = new Date(), workingDays = [1, 2, 3, 4, 5], holidays = []) {
  if (!startDate) return 0;
  const start = new Date(startDate);
  const end = typeof endDate === 'string' ? new Date(`${endDate}T23:59:59Z`) : new Date(endDate);
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
  const cur = typeof fromDate === 'string' ? new Date(`${fromDate}T00:00:00Z`) : new Date(fromDate);
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

function getUtcRangeForDate(dateStr, timeZone = 'Asia/Kolkata') {
  const [y, m, d] = dateStr.split('-').map(Number);
  const approxUtc = new Date(Date.UTC(y, m - 1, d, 0, 0, 0));
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric',
    hour12: false
  });
  const formatParts = (dt) => {
    const parts = formatter.formatToParts(dt);
    const map = {};
    parts.forEach((p) => { map[p.type] = p.value; });
    return {
      year: Number(map.year),
      month: Number(map.month),
      day: Number(map.day),
      hour: Number(map.hour) === 24 ? 0 : Number(map.hour),
      minute: Number(map.minute),
      second: Number(map.second)
    };
  };
  let guess = approxUtc.getTime();
  for (let i = 0; i < 3; i++) {
    const cur = formatParts(new Date(guess));
    const curDateAsUtc = Date.UTC(cur.year, cur.month - 1, cur.day, cur.hour, cur.minute, cur.second);
    const targetAsUtc = Date.UTC(y, m - 1, d, 0, 0, 0);
    guess += (targetAsUtc - curDateAsUtc);
  }
  const startUtc = new Date(guess);
  const endUtc = new Date(guess + 24 * 60 * 60 * 1000);
  return { startUtc, endUtc };
}

function tokenizeNote(str) {
  return new Set(
    String(str || '')
      .toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter((w) => w.length >= 2)
  );
}

function notesAreSimilar(a, b) {
  const s1 = String(a || '').trim().toLowerCase();
  const s2 = String(b || '').trim().toLowerCase();
  if (!s1 || !s2) return false;
  if (s1 === s2) return true;
  const t1 = tokenizeNote(s1);
  const t2 = tokenizeNote(s2);
  if (t1.size === 0 || t2.size === 0) return false;
  let inter = 0;
  for (const t of t1) if (t2.has(t)) inter++;
  const union = new Set([...t1, ...t2]).size;
  return union > 0 && (inter / union) >= 0.85;
}

function computeUpdateHash(items = [], summaryNote = '') {
  const normalized = items
    .slice()
    .sort((a, b) => Number(a.card_id) - Number(b.card_id))
    .map((it) => `${it.card_id}:${it.status}:${String(it.note || '').trim()}`)
    .join('|');
  return crypto.createHash('sha256').update(`${normalized}||${String(summaryNote || '').trim()}`).digest('hex');
}

/**
 * Computes silent anti-cheat flags for a member's daily update (visible ONLY to daily_tracker.view_people).
 */
function computeSilentFlags({ items = [], yesterdayItems = [], completedCards = [], dailyUpdate = null, activities = [] }) {
  const flags = new Set();

  // 1. Same note as yesterday
  for (const item of items) {
    const note = String(item.note || '').trim();
    if (!note) continue;
    const prev = yesterdayItems.find((y) => Number(y.card_id) === Number(item.card_id));
    if (prev && notesAreSimilar(note, prev.note)) {
      flags.add('same_note_as_yesterday');
      break;
    }
  }

  // 2. Identical notes across multiple cards in the same update
  const nonEmptyNotes = items.map((i) => String(i.note || '').trim().toLowerCase()).filter(Boolean);
  if (nonEmptyNotes.length >= 2 && new Set(nonEmptyNotes).size < nonEmptyNotes.length) {
    flags.add('identical_notes_across_cards');
  }

  // 3. Marked done within minutes of starting
  const rapidDone = completedCards.some((c) => {
    const startRef = new Date(c.first_moved_or_assigned_at || c.created_at).getTime();
    const endRef = new Date(c.completed_at).getTime();
    const diffMin = (endRef - startRef) / (1000 * 60);
    return diffMin >= 0 && diffMin <= 3;
  }) || activities.some((a) => a.action_type === 'rapid_complete');
  if (rapidDone) flags.add('marked_done_within_minutes');

  // 4. Edited after submit
  if (dailyUpdate?.edited_at) {
    flags.add('edited_after_submit');
  }

  return Array.from(flags);
}

/**
 * Checks if a card is covered by the 2-3 working-day long-task cadence.
 * Returns true if the card is marked as a long task and was noted within the last 3 working days.
 */
function isLongTaskCovered(longTaskRow, targetDateStr, workingDays, holidays) {
  if (!longTaskRow || !longTaskRow.is_long_task) return false;
  if (!longTaskRow.last_noted_at) return false;
  const lastNotedStr = typeof longTaskRow.last_noted_at === 'string'
    ? longTaskRow.last_noted_at.slice(0, 10)
    : new Date(longTaskRow.last_noted_at).toISOString().slice(0, 10);
  if (lastNotedStr === targetDateStr) return true;
  const workingDaysSince = calculateWorkingDaysOpen(lastNotedStr, targetDateStr, workingDays, holidays);
  return workingDaysSince <= 2; // 2 working days grace -> note required every 3rd working day
}

module.exports = {
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
  notesAreSimilar,
  computeUpdateHash,
  computeSilentFlags,
  isLongTaskCovered
};

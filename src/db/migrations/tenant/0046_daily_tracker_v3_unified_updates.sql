-- Migration: 0046_daily_tracker_v3_unified_updates.sql
-- Description: Daily Tracker v3 unified daily updates per user per workspace per day,
--              long-task cadence tracking, server-side snoozes, check_in_reviews support
--              for daily_updates, backfill from check_ins, and safe drop of card_focus.

SET @dbname = DATABASE();

-- 1. Create daily_updates table (one row per workspace + user + work_date)
CREATE TABLE IF NOT EXISTS daily_updates (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  workspace_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  work_date DATE NOT NULL,
  status ENUM('on_track', 'blocked') NOT NULL DEFAULT 'on_track',
  summary_note VARCHAR(500) NULL,
  original_text_hash VARCHAR(64) NULL,
  edit_history JSON NULL,
  flags JSON NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  edited_at DATETIME(3) NULL,
  UNIQUE KEY uk_daily_updates_ws_user_date (workspace_id, user_id, work_date),
  INDEX idx_daily_updates_user_date (user_id, work_date),
  INDEX idx_daily_updates_ws_date (workspace_id, work_date),
  CONSTRAINT fk_du_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  CONSTRAINT fk_du_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Create daily_update_items table (per-card status + optional note within a daily update)
CREATE TABLE IF NOT EXISTS daily_update_items (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  daily_update_id BIGINT UNSIGNED NOT NULL,
  card_id BIGINT UNSIGNED NOT NULL,
  status ENUM('working', 'done_today', 'blocked') NOT NULL DEFAULT 'working',
  note VARCHAR(500) NULL,
  evidence_url VARCHAR(1000) NULL,
  is_long_task TINYINT(1) NOT NULL DEFAULT 0,
  expected_finish_date DATE NULL,
  flags JSON NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NULL,
  UNIQUE KEY uk_daily_update_items_update_card (daily_update_id, card_id),
  INDEX idx_daily_update_items_card (card_id),
  CONSTRAINT fk_dui_update FOREIGN KEY (daily_update_id) REFERENCES daily_updates(id) ON DELETE CASCADE,
  CONSTRAINT fk_dui_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Create card_long_tasks table (tracks long-task toggle & 2-3 working-day cadence)
CREATE TABLE IF NOT EXISTS card_long_tasks (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  card_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  is_long_task TINYINT(1) NOT NULL DEFAULT 1,
  expected_finish_date DATE NULL,
  last_noted_at DATE NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  UNIQUE KEY uk_card_long_tasks_card_user (card_id, user_id),
  INDEX idx_card_long_tasks_user (user_id),
  CONSTRAINT fk_clt_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE,
  CONSTRAINT fk_clt_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Create daily_tracker_snoozes table (server-side per-user snooze until tomorrow)
CREATE TABLE IF NOT EXISTS daily_tracker_snoozes (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  workspace_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  snoozed_date DATE NOT NULL,
  snoozed_until_date DATE NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uk_dts_ws_user_date (workspace_id, user_id, snoozed_date),
  INDEX idx_dts_user_until (user_id, snoozed_until_date),
  CONSTRAINT fk_dts_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  CONSTRAINT fk_dts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Enhance check_in_reviews to support daily_update_id and inline answer_note
SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'check_in_reviews' AND COLUMN_NAME = 'daily_update_id'
);
SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE check_in_reviews MODIFY COLUMN check_in_id BIGINT UNSIGNED NULL, ADD COLUMN daily_update_id BIGINT UNSIGNED NULL AFTER check_in_id, ADD COLUMN answer_note TEXT NULL AFTER note, ADD INDEX idx_cir_daily_update (daily_update_id);',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 6. Backfill existing check_ins into daily_updates + daily_update_items (idempotent)
-- 6a. Insert parent daily_updates rows
INSERT IGNORE INTO daily_updates (workspace_id, user_id, work_date, status, summary_note, original_text_hash, flags, created_at, edited_at)
SELECT
  b.workspace_id,
  ci.user_id,
  ci.work_date,
  IF(SUM(IF(ci.status IN ('blocked', 'need_help') OR (ci.blocker IS NOT NULL AND TRIM(ci.blocker) != ''), 1, 0)) > 0, 'blocked', 'on_track') AS status,
  LEFT(GROUP_CONCAT(NULLIF(TRIM(ci.did), '') ORDER BY ci.id ASC SEPARATOR ' | '), 500) AS summary_note,
  SHA2(GROUP_CONCAT(CONCAT(ci.card_id, ':', COALESCE(ci.original_text_hash, '')) ORDER BY ci.card_id ASC SEPARATOR '|'), 256) AS original_text_hash,
  JSON_ARRAY('migrated_from_check_ins') AS flags,
  MIN(ci.created_at) AS created_at,
  MAX(ci.edited_at) AS edited_at
FROM check_ins ci
JOIN cards c ON ci.card_id = c.id
JOIN lists l ON c.list_id = l.id
JOIN boards b ON l.board_id = b.id
GROUP BY b.workspace_id, ci.user_id, ci.work_date;

-- 6b. Insert child daily_update_items rows
INSERT IGNORE INTO daily_update_items (daily_update_id, card_id, status, note, evidence_url, flags, created_at, updated_at)
SELECT
  du.id,
  ci.card_id,
  CASE
    WHEN ci.status IN ('blocked', 'need_help') OR (ci.blocker IS NOT NULL AND TRIM(ci.blocker) != '') THEN 'blocked'
    WHEN ci.progress_pct = 100 THEN 'done_today'
    ELSE 'working'
  END AS status,
  LEFT(
    CASE
      WHEN ci.blocker IS NOT NULL AND TRIM(ci.blocker) != '' THEN TRIM(ci.blocker)
      ELSE TRIM(ci.did)
    END,
    500
  ) AS note,
  ci.evidence_url,
  ci.flags,
  ci.created_at,
  ci.edited_at
FROM check_ins ci
JOIN cards c ON ci.card_id = c.id
JOIN lists l ON c.list_id = l.id
JOIN boards b ON l.board_id = b.id
JOIN daily_updates du ON du.workspace_id = b.workspace_id AND du.user_id = ci.user_id AND du.work_date = ci.work_date;

-- 7. Safely drop obsolete card_focus table (nothing may depend on it)
DROP TABLE IF EXISTS card_focus;

-- Migration: 0026_daily_tracker_v2_focus_checkins_done_lists.sql
-- Description: Focus + Check-in model tables, done list indicator, and card tracking columns

SET @dbname = DATABASE();

-- 1. Add is_done_list column to lists table
SET @col_exists = (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = 'lists'
    AND COLUMN_NAME = 'is_done_list'
);

SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE lists ADD COLUMN is_done_list TINYINT(1) NOT NULL DEFAULT 0;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- Backfill is_done_list for existing lists with done or completed in their name
UPDATE lists
SET is_done_list = 1
WHERE (LOWER(name) LIKE '%done%' OR LOWER(name) LIKE '%completed%');

-- 2. Add completed_by column to cards table
SET @col_exists = (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = 'cards'
    AND COLUMN_NAME = 'completed_by'
);

SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE cards ADD COLUMN completed_by BIGINT UNSIGNED NULL;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 3. Add first_moved_or_assigned_at column to cards table
SET @col_exists = (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = 'cards'
    AND COLUMN_NAME = 'first_moved_or_assigned_at'
);

SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE cards ADD COLUMN first_moved_or_assigned_at DATETIME(3) NULL;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- Backfill first_moved_or_assigned_at with created_at for cards where it is NULL
UPDATE cards
SET first_moved_or_assigned_at = created_at
WHERE first_moved_or_assigned_at IS NULL;

-- 4. Create card_focus table
CREATE TABLE IF NOT EXISTS card_focus (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  card_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  started_at DATETIME(3) NOT NULL,
  ended_at DATETIME(3) NULL,
  deep_work TINYINT(1) NOT NULL DEFAULT 0,
  deep_work_set_by BIGINT UNSIGNED NULL,
  check_in_every_days INT NOT NULL DEFAULT 1,
  estimate_days INT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_card_focus_active (user_id, ended_at),
  INDEX idx_card_focus_card (card_id),
  CONSTRAINT fk_card_focus_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE,
  CONSTRAINT fk_card_focus_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Create check_ins table
CREATE TABLE IF NOT EXISTS check_ins (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  card_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  work_date DATE NOT NULL,
  did TEXT NOT NULL,
  next_step TEXT NOT NULL,
  blocker TEXT NULL,
  status ENUM('on_track','blocked','need_help') NOT NULL DEFAULT 'on_track',
  progress_pct TINYINT NOT NULL DEFAULT 0,
  evidence_url VARCHAR(1000) NULL,
  attachment_id BIGINT UNSIGNED NULL,
  original_text_hash VARCHAR(64) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  edited_at DATETIME(3) NULL,
  UNIQUE KEY uk_card_user_date (card_id, user_id, work_date),
  INDEX idx_check_ins_user_date (user_id, work_date),
  INDEX idx_check_ins_card (card_id),
  CONSTRAINT fk_check_ins_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE,
  CONSTRAINT fk_check_ins_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Create check_in_reviews table
CREATE TABLE IF NOT EXISTS check_in_reviews (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  check_in_id BIGINT UNSIGNED NOT NULL,
  reviewer_id BIGINT UNSIGNED NOT NULL,
  action ENUM('ack','question','request_evidence') NOT NULL,
  note TEXT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  answered_at DATETIME(3) NULL,
  INDEX idx_check_in_reviews_checkin (check_in_id),
  INDEX idx_check_in_reviews_reviewer (reviewer_id),
  CONSTRAINT fk_check_in_reviews_checkin FOREIGN KEY (check_in_id) REFERENCES check_ins(id) ON DELETE CASCADE,
  CONSTRAINT fk_check_in_reviews_reviewer FOREIGN KEY (reviewer_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Create leave_days table
CREATE TABLE IF NOT EXISTS leave_days (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  date DATE NOT NULL,
  reason TEXT NULL,
  approved_by BIGINT UNSIGNED NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uk_user_date (user_id, date),
  INDEX idx_leave_days_date (date),
  CONSTRAINT fk_leave_days_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. Add created_at and created_by to checklist_items table
SET @col_exists = (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = 'checklist_items'
    AND COLUMN_NAME = 'created_at'
);

SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE checklist_items ADD COLUMN created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), ADD COLUMN created_by BIGINT UNSIGNED NULL;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 9. Add completion fields to cards table
SET @col_exists = (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = 'cards'
    AND COLUMN_NAME = 'completion_note'
);

SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE cards ADD COLUMN completion_note TEXT NULL, ADD COLUMN completion_evidence_url VARCHAR(1000) NULL, ADD COLUMN completion_attachment_id BIGINT UNSIGNED NULL;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;


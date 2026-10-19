-- Migration: 0027_daily_tracker_v2_enhancements.sql
-- Description: Workspace default timezone, leave days approval workflow, check-in original fields,
--              checklist lifetime tracking, attachment checksums, and performance indexes.

SET @dbname = DATABASE();

-- 1. Default workspace timezone to Asia/Kolkata where missing
UPDATE workspaces
SET settings = JSON_SET(COALESCE(settings, '{}'), '$.timezone', 'Asia/Kolkata')
WHERE settings IS NULL OR JSON_UNQUOTE(JSON_EXTRACT(settings, '$.timezone')) IS NULL OR JSON_UNQUOTE(JSON_EXTRACT(settings, '$.timezone')) = '';

-- 2. Enhance leave_days table: add status, requested_by, approved_at, rejection_reason
SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'leave_days' AND COLUMN_NAME = 'status'
);
SET @stmt = IF(
  @col_exists = 0,
  "ALTER TABLE leave_days ADD COLUMN status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'approved';",
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'leave_days' AND COLUMN_NAME = 'requested_by'
);
SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE leave_days ADD COLUMN requested_by BIGINT UNSIGNED NULL;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'leave_days' AND COLUMN_NAME = 'approved_at'
);
SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE leave_days ADD COLUMN approved_at DATETIME(3) NULL;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'leave_days' AND COLUMN_NAME = 'rejection_reason'
);
SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE leave_days ADD COLUMN rejection_reason VARCHAR(500) NULL;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 3. Enhance check_ins table: add original_did, original_next_step, flags
SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'check_ins' AND COLUMN_NAME = 'original_did'
);
SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE check_ins ADD COLUMN original_did TEXT NULL, ADD COLUMN original_next_step TEXT NULL, ADD COLUMN flags JSON NULL;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 4. Enhance checklist_items table: add ticked_at, ticked_by, lifetime_tick_count
SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'checklist_items' AND COLUMN_NAME = 'lifetime_tick_count'
);
SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE checklist_items ADD COLUMN ticked_at DATETIME(3) NULL, ADD COLUMN ticked_by BIGINT UNSIGNED NULL, ADD COLUMN lifetime_tick_count INT NOT NULL DEFAULT 0;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- Backfill initial lifetime_tick_count = 1 for currently checked items
UPDATE checklist_items
SET lifetime_tick_count = 1
WHERE is_checked = 1 AND lifetime_tick_count = 0;

-- 5. Enhance comments table: add original_length
SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'comments' AND COLUMN_NAME = 'original_length'
);
SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE comments ADD COLUMN original_length INT NULL;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 6. Enhance attachments table: add checksum
SET @col_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'attachments' AND COLUMN_NAME = 'checksum'
);
SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE attachments ADD COLUMN checksum VARCHAR(64) NULL;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 7. Performance Indexes on MariaDB
-- 7a. activity_log (card_id, created_at)
SET @idx_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'activity_log' AND INDEX_NAME = 'idx_act_card_created'
);
SET @stmt = IF(
  @idx_exists = 0,
  'ALTER TABLE activity_log ADD INDEX idx_act_card_created (card_id, created_at);',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 7b. activity_log (created_at, action_type)
SET @idx_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'activity_log' AND INDEX_NAME = 'idx_act_created_action'
);
SET @stmt = IF(
  @idx_exists = 0,
  'ALTER TABLE activity_log ADD INDEX idx_act_created_action (created_at, action_type);',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 7c. cards (created_at)
SET @idx_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'cards' AND INDEX_NAME = 'idx_cards_created_at'
);
SET @stmt = IF(
  @idx_exists = 0,
  'ALTER TABLE cards ADD INDEX idx_cards_created_at (created_at);',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 7d. cards (first_moved_or_assigned_at)
SET @idx_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'cards' AND INDEX_NAME = 'idx_cards_first_moved'
);
SET @stmt = IF(
  @idx_exists = 0,
  'ALTER TABLE cards ADD INDEX idx_cards_first_moved (first_moved_or_assigned_at);',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 7e. lists (board_id, is_done_list)
SET @idx_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'lists' AND INDEX_NAME = 'idx_lists_board_done'
);
SET @stmt = IF(
  @idx_exists = 0,
  'ALTER TABLE lists ADD INDEX idx_lists_board_done (board_id, is_done_list);',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 7f. leave_days (user_id, date, status)
SET @idx_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'leave_days' AND INDEX_NAME = 'idx_leave_days_user_date_status'
);
SET @stmt = IF(
  @idx_exists = 0,
  'ALTER TABLE leave_days ADD INDEX idx_leave_days_user_date_status (user_id, date, status);',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 7g. attachments (card_id, checksum)
SET @idx_exists = (
  SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = 'attachments' AND INDEX_NAME = 'idx_attachments_card_checksum'
);
SET @stmt = IF(
  @idx_exists = 0,
  'ALTER TABLE attachments ADD INDEX idx_attachments_card_checksum (card_id, checksum);',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

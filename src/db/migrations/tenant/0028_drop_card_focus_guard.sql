-- Migration: 0028_drop_card_focus_guard.sql
-- Description: Drop card_focus table only if unused (guarded), otherwise leave unused for Daily Tracker v3 simplification

SET @dbname = DATABASE();

SET @table_exists = (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.TABLES
  WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = 'card_focus'
);

SET @row_count = 0;

-- Check row count if table exists
SET @stmt = IF(
  @table_exists > 0,
  'SELECT COUNT(*) INTO @row_count FROM card_focus;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- Drop card_focus only if table exists and has 0 rows
SET @stmt = IF(
  @table_exists > 0 AND @row_count = 0,
  'DROP TABLE IF EXISTS card_focus;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

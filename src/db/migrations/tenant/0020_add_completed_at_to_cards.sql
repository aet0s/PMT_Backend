-- Migration: 0020_add_completed_at_to_cards.sql
-- Description: Adds completed_at column to cards table for accurate completed task auto-archival

SET @dbname = DATABASE();

-- 1. Add completed_at column to cards table
SET @col_exists = (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = 'cards'
    AND COLUMN_NAME = 'completed_at'
);

SET @stmt = IF(
  @col_exists = 0,
  'ALTER TABLE cards ADD COLUMN completed_at DATETIME(3) NULL AFTER is_complete;',
  'SELECT 1;'
);
PREPARE stmt_exec FROM @stmt;
EXECUTE stmt_exec;
DEALLOCATE PREPARE stmt_exec;

-- 2. Retroactively set completed_at for existing completed cards to their created_at date
UPDATE cards 
SET completed_at = created_at 
WHERE is_complete = 1 AND completed_at IS NULL;

-- 3. Add index on (is_complete, completed_at, is_archived) if not exists
SET @idx_exists = (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = @dbname
    AND TABLE_NAME = 'cards'
    AND INDEX_NAME = 'idx_cards_completed_archival'
);

SET @stmt_idx = IF(
  @idx_exists = 0,
  'CREATE INDEX idx_cards_completed_archival ON cards (is_complete, completed_at, is_archived);',
  'SELECT 1;'
);
PREPARE stmt_idx_exec FROM @stmt_idx;
EXECUTE stmt_idx_exec;
DEALLOCATE PREPARE stmt_idx_exec;

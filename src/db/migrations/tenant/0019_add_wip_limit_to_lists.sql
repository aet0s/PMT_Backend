-- Migration: 0019_add_wip_limit_to_lists.sql
-- Add wip_limit_enabled and wip_limit columns to lists table to support column-level WIP constraints

SET @col_wip_enabled_exists = 0;
SELECT COUNT(*) INTO @col_wip_enabled_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'lists' AND COLUMN_NAME = 'wip_limit_enabled';
SET @stmt_wip_enabled = IF(@col_wip_enabled_exists = 0, 'ALTER TABLE lists ADD COLUMN wip_limit_enabled TINYINT(1) NOT NULL DEFAULT 1 AFTER is_archived;', 'SELECT 1;');
PREPARE stmt1 FROM @stmt_wip_enabled;
EXECUTE stmt1;
DEALLOCATE PREPARE stmt1;

SET @col_wip_limit_exists = 0;
SELECT COUNT(*) INTO @col_wip_limit_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'lists' AND COLUMN_NAME = 'wip_limit';
SET @stmt_wip_limit = IF(@col_wip_limit_exists = 0, 'ALTER TABLE lists ADD COLUMN wip_limit INT NULL DEFAULT NULL AFTER wip_limit_enabled;', 'SELECT 1;');
PREPARE stmt2 FROM @stmt_wip_limit;
EXECUTE stmt2;
DEALLOCATE PREPARE stmt2;

-- Retroactively set wip_limit_enabled = 0 for all existing "Done" or completed columns across all boards
UPDATE lists
SET wip_limit_enabled = 0
WHERE LOWER(TRIM(name)) IN ('done', 'completed', 'finished', 'closed', 'archive', 'archived', 'released', 'shipped')
   OR LOWER(TRIM(name)) LIKE 'done%'
   OR LOWER(TRIM(name)) LIKE '%completed%';

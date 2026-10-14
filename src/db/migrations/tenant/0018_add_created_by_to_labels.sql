-- Migration: 0018_add_created_by_to_labels.sql
-- Add created_by_user_id and is_custom columns to labels table to support custom label deletion rules

SET @col_created_by_exists = 0;
SELECT COUNT(*) INTO @col_created_by_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'labels' AND COLUMN_NAME = 'created_by_user_id';
SET @stmt_created_by = IF(@col_created_by_exists = 0, 'ALTER TABLE labels ADD COLUMN created_by_user_id BIGINT UNSIGNED NULL AFTER color;', 'SELECT 1;');
PREPARE stmt1 FROM @stmt_created_by;
EXECUTE stmt1;
DEALLOCATE PREPARE stmt1;

SET @col_is_custom_exists = 0;
SELECT COUNT(*) INTO @col_is_custom_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'labels' AND COLUMN_NAME = 'is_custom';
SET @stmt_is_custom = IF(@col_is_custom_exists = 0, 'ALTER TABLE labels ADD COLUMN is_custom TINYINT(1) NOT NULL DEFAULT 1 AFTER created_by_user_id;', 'SELECT 1;');
PREPARE stmt2 FROM @stmt_is_custom;
EXECUTE stmt2;
DEALLOCATE PREPARE stmt2;

-- Mark standard preset labels as is_custom = 0 if they don't have a specific creator
UPDATE labels
SET is_custom = 0
WHERE name IN ('Feature', 'Bug', 'Design', 'Backend', 'Frontend', 'Urgent')
  AND created_by_user_id IS NULL;

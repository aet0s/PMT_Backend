-- Migration: 0012_add_description_and_settings_to_workspaces.sql
-- Add description and settings columns to workspaces table

SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'workspaces' AND COLUMN_NAME = 'description';
SET @stmt = IF(@col_exists = 0, 'ALTER TABLE workspaces ADD COLUMN description TEXT NULL;', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists2 = 0;
SELECT COUNT(*) INTO @col_exists2 FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'workspaces' AND COLUMN_NAME = 'settings';
SET @stmt2 = IF(@col_exists2 = 0, 'ALTER TABLE workspaces ADD COLUMN settings JSON NULL;', 'SELECT 1;');
PREPARE stmt2 FROM @stmt2;
EXECUTE stmt2;
DEALLOCATE PREPARE stmt2;

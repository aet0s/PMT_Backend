-- Migration: 0025_add_icon_url_to_workspaces.sql
-- Add icon_url column to workspaces table

SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'workspaces' AND COLUMN_NAME = 'icon_url';
SET @stmt = IF(@col_exists = 0, 'ALTER TABLE workspaces ADD COLUMN icon_url VARCHAR(500) NULL AFTER description;', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Migration: 0014_add_planned_and_label_to_permissions.sql
-- Add planned and label columns to permissions table if not present

SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions' AND COLUMN_NAME = 'planned';
SET @stmt = IF(@col_exists = 0, 'ALTER TABLE permissions ADD COLUMN planned TINYINT(1) NOT NULL DEFAULT 0 AFTER dangerous;', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists2 = 0;
SELECT COUNT(*) INTO @col_exists2 FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'permissions' AND COLUMN_NAME = 'label';
SET @stmt2 = IF(@col_exists2 = 0, 'ALTER TABLE permissions ADD COLUMN label VARCHAR(100) NULL AFTER description;', 'SELECT 1;');
PREPARE stmt2 FROM @stmt2;
EXECUTE stmt2;
DEALLOCATE PREPARE stmt2;

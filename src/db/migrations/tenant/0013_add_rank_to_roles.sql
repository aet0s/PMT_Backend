-- Migration: 0013_add_rank_to_roles.sql
-- Add rank column to roles table and populate system role ranks

SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'roles' AND COLUMN_NAME = 'rank';
SET @stmt = IF(@col_exists = 0, 'ALTER TABLE roles ADD COLUMN rank INT NOT NULL DEFAULT 30 AFTER is_editable;', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

UPDATE roles SET rank = 100 WHERE is_system = 1 AND LOWER(TRIM(name)) IN ('owner', 'super admin');
UPDATE roles SET rank = 80 WHERE is_system = 1 AND LOWER(TRIM(name)) = 'admin';
UPDATE roles SET rank = 60 WHERE is_system = 1 AND LOWER(TRIM(name)) IN ('project manager', 'manager');
UPDATE roles SET rank = 40 WHERE is_system = 1 AND LOWER(TRIM(name)) IN ('team member', 'member');
UPDATE roles SET rank = 20 WHERE is_system = 1 AND LOWER(TRIM(name)) = 'viewer';
UPDATE roles SET rank = 10 WHERE is_system = 1 AND LOWER(TRIM(name)) = 'guest';

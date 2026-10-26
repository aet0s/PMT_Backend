-- Migration: 0033_card_members_assigned_by.sql
-- Track who assigned each member to enforce card ownership and assignment integrity

SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'card_members' AND COLUMN_NAME = 'assigned_by_user_id';

SET @stmt = IF(@col_exists = 0, 'ALTER TABLE card_members ADD COLUMN assigned_by_user_id BIGINT UNSIGNED NULL AFTER user_id;', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Backfill existing card_members from card_assigners
UPDATE card_members cm
JOIN (
  SELECT card_id, MIN(user_id) as first_assigner_id
  FROM card_assigners
  GROUP BY card_id
) ca ON cm.card_id = ca.card_id
SET cm.assigned_by_user_id = ca.first_assigner_id
WHERE cm.assigned_by_user_id IS NULL;

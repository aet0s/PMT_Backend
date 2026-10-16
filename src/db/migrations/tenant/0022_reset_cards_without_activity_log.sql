-- Migration: 0022_reset_cards_without_activity_log.sql
-- Description: Ensures cards without an explicit 'created_card' activity_log event strictly have created_by = NULL.

UPDATE cards c
LEFT JOIN (
  SELECT card_id
  FROM activity_log
  WHERE card_id IS NOT NULL AND action_type = 'created_card'
  GROUP BY card_id
) act ON c.id = act.card_id
SET c.created_by = NULL
WHERE c.created_by IS NOT NULL AND act.card_id IS NULL;

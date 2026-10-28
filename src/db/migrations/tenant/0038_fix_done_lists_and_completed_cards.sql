-- 0038_fix_done_lists_and_completed_cards.sql
-- Ensure all lists named 'Done' or completed variants have is_done_list = 1,
-- and sync completion status on cards residing in those lists.

UPDATE lists 
SET is_done_list = 1 
WHERE is_done_list = 0 
  AND LOWER(TRIM(name)) IN ('done', 'completed', 'finished', 'closed', 'archive', 'archived');

UPDATE cards c
JOIN lists l ON c.list_id = l.id
SET c.is_complete = 1,
    c.completed_at = COALESCE(c.completed_at, c.created_at)
WHERE l.is_done_list = 1 
  AND c.is_complete = 0;

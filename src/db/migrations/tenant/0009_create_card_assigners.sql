-- 0009_create_card_assigners.sql
-- Many-to-many relationship tracking card assigners (creators and additional assigners)

CREATE TABLE IF NOT EXISTS card_assigners (
  card_id BIGINT UNSIGNED NOT NULL,
  user_id BIGINT UNSIGNED NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (card_id, user_id),
  CONSTRAINT fk_ca_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE,
  CONSTRAINT fk_ca_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_ca_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Backfill creators of existing cards from activity_log if available
INSERT IGNORE INTO card_assigners (card_id, user_id)
SELECT card_id, user_id 
FROM activity_log 
WHERE action_type = 'created_card' AND card_id IS NOT NULL AND user_id IS NOT NULL;

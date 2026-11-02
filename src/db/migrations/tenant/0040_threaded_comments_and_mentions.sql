-- Migration: 0039_threaded_comments_and_mentions.sql
-- Threaded Card Comments, Hierarchical Root/Parent references, and Board-Scoped Mentions

-- 1. Add parent_comment_id to comments
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'comments' AND COLUMN_NAME = 'parent_comment_id';

SET @stmt = IF(@col_exists = 0, 'ALTER TABLE comments ADD COLUMN parent_comment_id BIGINT UNSIGNED NULL AFTER user_id;', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 2. Add root_comment_id to comments
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'comments' AND COLUMN_NAME = 'root_comment_id';

SET @stmt = IF(@col_exists = 0, 'ALTER TABLE comments ADD COLUMN root_comment_id BIGINT UNSIGNED NULL AFTER parent_comment_id;', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 3. Add updated_at to comments
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'comments' AND COLUMN_NAME = 'updated_at';

SET @stmt = IF(@col_exists = 0, 'ALTER TABLE comments ADD COLUMN updated_at DATETIME(3) NULL AFTER created_at;', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 4. Add deleted_at to comments (soft-delete support)
SET @col_exists = 0;
SELECT COUNT(*) INTO @col_exists FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'comments' AND COLUMN_NAME = 'deleted_at';

SET @stmt = IF(@col_exists = 0, 'ALTER TABLE comments ADD COLUMN deleted_at DATETIME(3) NULL AFTER updated_at;', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 5. Add indexes on comments
SET @idx_exists = 0;
SELECT COUNT(*) INTO @idx_exists FROM INFORMATION_SCHEMA.STATISTICS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'comments' AND INDEX_NAME = 'idx_comments_parent_comment_id';

SET @stmt = IF(@idx_exists = 0, 'ALTER TABLE comments ADD INDEX idx_comments_parent_comment_id (parent_comment_id);', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @idx_exists = 0;
SELECT COUNT(*) INTO @idx_exists FROM INFORMATION_SCHEMA.STATISTICS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'comments' AND INDEX_NAME = 'idx_comments_root_comment_id';

SET @stmt = IF(@idx_exists = 0, 'ALTER TABLE comments ADD INDEX idx_comments_root_comment_id (root_comment_id);', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @idx_exists = 0;
SELECT COUNT(*) INTO @idx_exists FROM INFORMATION_SCHEMA.STATISTICS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'comments' AND INDEX_NAME = 'idx_comments_card_root';

SET @stmt = IF(@idx_exists = 0, 'ALTER TABLE comments ADD INDEX idx_comments_card_root (card_id, root_comment_id);', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 6. Add Foreign Keys on comments
SET @fk_exists = 0;
SELECT COUNT(*) INTO @fk_exists FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'comments' AND CONSTRAINT_NAME = 'fk_comments_parent';

SET @stmt = IF(@fk_exists = 0, 'ALTER TABLE comments ADD CONSTRAINT fk_comments_parent FOREIGN KEY (parent_comment_id) REFERENCES comments(id) ON DELETE CASCADE;', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @fk_exists = 0;
SELECT COUNT(*) INTO @fk_exists FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'comments' AND CONSTRAINT_NAME = 'fk_comments_root';

SET @stmt = IF(@fk_exists = 0, 'ALTER TABLE comments ADD CONSTRAINT fk_comments_root FOREIGN KEY (root_comment_id) REFERENCES comments(id) ON DELETE CASCADE;', 'SELECT 1;');
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 7. Create comment_mentions table
CREATE TABLE IF NOT EXISTS comment_mentions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  comment_id BIGINT UNSIGNED NOT NULL,
  mentioned_user_id BIGINT UNSIGNED NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_comment_mentions_comment FOREIGN KEY (comment_id) REFERENCES comments(id) ON DELETE CASCADE,
  CONSTRAINT fk_comment_mentions_user FOREIGN KEY (mentioned_user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_comment_mentions_comment_id (comment_id),
  INDEX idx_comment_mentions_user_id (mentioned_user_id),
  UNIQUE KEY uq_comment_user_mention (comment_id, mentioned_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


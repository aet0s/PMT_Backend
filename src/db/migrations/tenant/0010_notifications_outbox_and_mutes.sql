-- Tenant Migration 0010: Notifications Outbox, Mutes, Settings, and Card/Board ON DELETE SET NULL

-- 1. Update foreign keys on notifications table to ON DELETE SET NULL so notifications survive deletions
ALTER TABLE notifications DROP FOREIGN KEY IF EXISTS fk_notif_card;
ALTER TABLE notifications DROP FOREIGN KEY IF EXISTS fk_notif_board;

ALTER TABLE notifications ADD CONSTRAINT fk_notif_card FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE SET NULL;
ALTER TABLE notifications ADD CONSTRAINT fk_notif_board FOREIGN KEY (board_id) REFERENCES boards(id) ON DELETE SET NULL;

-- 2. Add columns to notifications table
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS meta JSON NULL;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS priority TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS count INT NOT NULL DEFAULT 1;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS group_key VARCHAR(255) NULL;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS dedupe_key VARCHAR(255) NULL;

-- 3. Add indexes to notifications table
ALTER TABLE notifications ADD INDEX IF NOT EXISTS idx_notif_user_created (user_id, created_at);
ALTER TABLE notifications ADD INDEX IF NOT EXISTS idx_notif_user_board_read (user_id, board_id, is_read);
ALTER TABLE notifications ADD UNIQUE INDEX IF NOT EXISTS uk_notif_user_dedupe (user_id, dedupe_key);

-- 4. Create Notification Outbox table
CREATE TABLE IF NOT EXISTS notification_outbox (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(100) NOT NULL,
  workspace_id BIGINT UNSIGNED NULL,
  board_id BIGINT UNSIGNED NULL,
  card_id BIGINT UNSIGNED NULL,
  actor_user_id BIGINT UNSIGNED NULL,
  target_user_id BIGINT UNSIGNED NULL,
  invitee_user_id BIGINT UNSIGNED NULL,
  mentioned_user_ids JSON NULL,
  meta JSON NULL,
  dedupe_key VARCHAR(255) NULL,
  status ENUM('pending', 'processing', 'completed', 'failed', 'dead_letter') NOT NULL DEFAULT 'pending',
  retry_count INT NOT NULL DEFAULT 0,
  last_error TEXT NULL,
  next_retry_at DATETIME(3) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  processed_at DATETIME(3) NULL,
  INDEX idx_outbox_status_retry (status, next_retry_at, created_at),
  INDEX idx_outbox_dedupe (dedupe_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Create Notification Mutes table
CREATE TABLE IF NOT EXISTS notification_mutes (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  board_id BIGINT UNSIGNED NULL,
  card_id BIGINT UNSIGNED NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uk_mute_user_board (user_id, board_id),
  UNIQUE KEY uk_mute_user_card (user_id, card_id),
  CONSTRAINT fk_nm_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Create Notification User Settings table (mode: all | only_mine, play_sound: 0 by default)
CREATE TABLE IF NOT EXISTS notification_user_settings (
  user_id BIGINT UNSIGNED PRIMARY KEY,
  mode ENUM('all', 'only_mine') NOT NULL DEFAULT 'all',
  play_sound TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_nus_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE notification_user_settings ADD COLUMN IF NOT EXISTS play_sound TINYINT(1) NOT NULL DEFAULT 0;

-- 7. Create Notification Workspace Settings table (notify_all_boards flag)
CREATE TABLE IF NOT EXISTS notification_workspace_settings (
  user_id BIGINT UNSIGNED NOT NULL,
  workspace_id BIGINT UNSIGNED NOT NULL,
  notify_all_boards TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (user_id, workspace_id),
  CONSTRAINT fk_nws_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_nws_ws FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

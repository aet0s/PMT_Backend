-- Tenant Migration 0034: Web Push Notifications Subscriptions, Deliveries, and User Setting
-- Guarded DDL for MariaDB 10.4+ and MySQL 8

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  device_id VARCHAR(64) NOT NULL,
  token TEXT NOT NULL,
  token_hash CHAR(64) NOT NULL,
  platform VARCHAR(64) NULL,
  browser VARCHAR(64) NULL,
  os VARCHAR(64) NULL,
  user_agent VARCHAR(500) NULL,
  label VARCHAR(100) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  last_seen_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  last_success_at DATETIME(3) NULL,
  last_error_at DATETIME(3) NULL,
  last_error_code VARCHAR(100) NULL,
  failure_count INT UNSIGNED NOT NULL DEFAULT 0,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  revoked_at DATETIME(3) NULL,
  UNIQUE KEY uk_push_sub_token_hash (token_hash),
  INDEX idx_push_sub_user_active (user_id, is_active),
  INDEX idx_push_sub_device (device_id),
  CONSTRAINT fk_push_sub_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS push_deliveries (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  notification_id BIGINT UNSIGNED NULL,
  subscription_id BIGINT UNSIGNED NOT NULL,
  status ENUM('sent', 'failed', 'skipped') NOT NULL,
  reason VARCHAR(255) NULL,
  error_code VARCHAR(100) NULL,
  sent_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_push_deliv_notif (notification_id),
  INDEX idx_push_deliv_sub (subscription_id),
  INDEX idx_push_deliv_sent_at (sent_at),
  CONSTRAINT fk_push_deliv_sub FOREIGN KEY (subscription_id) REFERENCES push_subscriptions(id) ON DELETE CASCADE,
  CONSTRAINT fk_push_deliv_notif FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE notification_user_settings ADD COLUMN IF NOT EXISTS push_show_details TINYINT(1) NOT NULL DEFAULT 1;

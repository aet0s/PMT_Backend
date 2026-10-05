-- Migration: 0003_phase3_auth_sessions_2fa
-- Adds account lockout, 2FA/TOTP fields, avatar/timezone/locale, sessions, recovery codes, and auth audit log.

ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until DATETIME(3) NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS lockout_count INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(255) NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enrolled_at DATETIME(3) NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(500) NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone VARCHAR(100) NOT NULL DEFAULT 'UTC';
ALTER TABLE users ADD COLUMN IF NOT EXISTS locale VARCHAR(20) NOT NULL DEFAULT 'en';

ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS require_2fa_for_admins TINYINT(1) NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS sessions (
  id VARCHAR(36) PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  refresh_token_hash VARCHAR(64) NOT NULL,
  family_id VARCHAR(36) NOT NULL,
  device_info VARCHAR(255) NULL,
  ip_address VARCHAR(45) NULL,
  user_agent VARCHAR(500) NULL,
  expires_at DATETIME(3) NOT NULL,
  revoked_at DATETIME(3) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_sessions_user_active (user_id, revoked_at),
  INDEX idx_sessions_family (family_id),
  INDEX idx_sessions_token_hash (refresh_token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS recovery_codes (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  code_hash VARCHAR(255) NOT NULL,
  used_at DATETIME(3) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  CONSTRAINT fk_rc_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_rc_user_unused (user_id, used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS auth_audit_log (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT UNSIGNED NULL,
  email VARCHAR(255) NULL,
  event_type VARCHAR(64) NOT NULL,
  ip_address VARCHAR(45) NULL,
  user_agent VARCHAR(500) NULL,
  metadata JSON NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_aal_user (user_id),
  INDEX idx_aal_event (event_type),
  INDEX idx_aal_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

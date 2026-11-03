-- Tenant Database Migration 0041: Security Tables for Encrypted Gateway, Replay Protection, Idempotency & Rate Limiting (Single-tenant / Tenant scope)

CREATE TABLE IF NOT EXISTS replay_nonces (
  nonce VARCHAR(128) NOT NULL PRIMARY KEY,
  timestamp BIGINT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_nonce_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS api_idempotency (
  idempotency_key VARCHAR(128) NOT NULL PRIMARY KEY,
  user_id INT NULL,
  tenant_id INT NULL,
  operation VARCHAR(128) NOT NULL,
  request_hash VARCHAR(64) NOT NULL,
  status_code INT NOT NULL,
  response_body MEDIUMTEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_idempotency_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rate_limits (
  limiter_key VARCHAR(191) NOT NULL PRIMARY KEY,
  hits INT NOT NULL DEFAULT 1,
  reset_at BIGINT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_rate_limits_reset (reset_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


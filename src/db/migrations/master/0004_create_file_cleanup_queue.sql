-- Migration: 0004_create_file_cleanup_queue
-- Table for asynchronous and retryable file unlink jobs across tenants.

CREATE TABLE IF NOT EXISTS file_cleanup_queue (
  id INT AUTO_INCREMENT PRIMARY KEY,
  tenant_id INT NULL,
  file_path VARCHAR(1024) NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 5,
  next_run_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status ENUM('pending', 'failed', 'completed') NOT NULL DEFAULT 'pending',
  error_message TEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_status_next_run (status, next_run_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

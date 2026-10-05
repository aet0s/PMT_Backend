-- Migration: 0003_add_deleted_at_to_tenants.sql
-- Adds deleted_at timestamp to tenants table for 30-day slug reservation

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS deleted_at DATETIME(3) NULL AFTER suspended_at;

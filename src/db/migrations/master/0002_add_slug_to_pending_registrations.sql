-- Migration: 0002_add_slug_to_pending_registrations
ALTER TABLE pending_registrations ADD COLUMN slug VARCHAR(100) NULL AFTER company_name;

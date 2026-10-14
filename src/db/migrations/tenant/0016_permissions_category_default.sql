-- Migration: 0016_permissions_category_default
-- Make category column nullable on permissions table so strict SQL mode allows inserts without category
ALTER TABLE permissions MODIFY COLUMN category VARCHAR(100) NULL DEFAULT NULL;

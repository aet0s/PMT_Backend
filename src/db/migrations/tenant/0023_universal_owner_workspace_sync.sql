-- Migration: 0023_universal_owner_workspace_sync.sql
-- Description: Universal Owner Policy: Enrolls all Company Owners as Owner in all active workspaces.

INSERT INTO workspace_members (workspace_id, user_id, role, role_id)
SELECT 
  w.id AS workspace_id,
  owners.user_id,
  r_owner.name AS role,
  r_owner.id AS role_id
FROM workspaces w
CROSS JOIN (
  SELECT DISTINCT wm.user_id
  FROM workspace_members wm
  JOIN roles r ON wm.role_id = r.id
  WHERE (r.is_system = 1 AND (r.is_editable = 0 OR COALESCE(r.rank, 30) >= 100))
     OR wm.role IN ('Owner', 'Super Admin')
) owners
JOIN roles r_owner ON r_owner.is_system = 1 
  AND (r_owner.name = 'Owner' OR r_owner.name = 'Super Admin') 
  AND r_owner.workspace_id IS NULL
WHERE w.is_archived = 0
ON DUPLICATE KEY UPDATE 
  role = VALUES(role), 
  role_id = VALUES(role_id);

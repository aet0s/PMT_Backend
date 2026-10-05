-- Migration: 0005_phase4_rbac_system_roles_permissions.sql
-- Seed complete Phase 4 RBAC catalog, 6 system roles, and role_permissions matrix.

-- 1. Extend permissions schema if needed
ALTER TABLE permissions 
  ADD COLUMN IF NOT EXISTS module VARCHAR(50) NOT NULL DEFAULT 'general',
  ADD COLUMN IF NOT EXISTS scope ENUM('company', 'project') NOT NULL DEFAULT 'project',
  ADD COLUMN IF NOT EXISTS dangerous TINYINT(1) NOT NULL DEFAULT 0;

-- 2. Insert or update all catalog permissions
INSERT INTO permissions (`key`, category, description, module, scope, dangerous) VALUES
  ('company.view', 'company', 'View company profile and details', 'company', 'company', 0),
  ('company.edit_settings', 'company', 'Modify company preferences and profile', 'company', 'company', 1),
  ('company.manage_security', 'company', 'Configure 2FA requirements and authentication policies', 'company', 'company', 1),
  ('company.manage_billing', 'company', 'Access and modify subscriptions and billing', 'company', 'company', 1),
  ('company.delete', 'company', 'Permanently delete company and all tenant databases', 'company', 'company', 1),
  ('company.export_data', 'company', 'Generate and download full tenant database export', 'company', 'company', 1),
  ('workspace.view', 'workspace', 'View workspace information and dashboard', 'workspace', 'company', 0),
  ('workspace.create', 'workspace', 'Create new workspaces', 'workspace', 'company', 0),
  ('workspace.edit', 'workspace', 'Edit workspace name and settings', 'workspace', 'company', 0),
  ('workspace.delete', 'workspace', 'Delete entire workspace and all child boards', 'workspace', 'company', 1),
  ('workspace.archive', 'workspace', 'Archive or restore workspaces', 'workspace', 'company', 0),
  ('team.view', 'team', 'View teams and department memberships', 'team', 'company', 0),
  ('team.create', 'team', 'Create departments and teams', 'team', 'company', 0),
  ('team.edit', 'team', 'Modify team details', 'team', 'company', 0),
  ('team.delete', 'team', 'Delete teams', 'team', 'company', 1),
  ('team.manage_members', 'team', 'Assign or remove members from teams', 'team', 'company', 0),
  ('member.view', 'member', 'View workspace member directory', 'member', 'company', 0),
  ('member.invite', 'member', 'Generate and send invitation links', 'member', 'company', 0),
  ('member.remove', 'member', 'Remove members from workspace', 'member', 'company', 1),
  ('member.assign_role', 'member', 'Change roles of workspace members', 'member', 'company', 1),
  ('member.deactivate', 'member', 'Temporarily deactivate member accounts', 'member', 'company', 1),
  ('member.reset_password', 'member', 'Set temporary password for lower-ranked members', 'member', 'company', 1),
  ('member.reset_2fa', 'member', 'Reset two-factor authentication for lower-ranked members', 'member', 'company', 1),
  ('role.view', 'role', 'View permissions and role catalogs', 'role', 'company', 0),
  ('role.create', 'role', 'Create new custom workspace roles', 'role', 'company', 1),
  ('role.edit', 'role', 'Modify permissions for custom roles', 'role', 'company', 1),
  ('role.delete', 'role', 'Delete custom roles not in use', 'role', 'company', 1),
  ('role.assign', 'role', 'Assign roles to workspace members', 'role', 'company', 1),
  ('project.view', 'project', 'Access and view project boards', 'project', 'project', 0),
  ('project.create', 'project', 'Create new project boards', 'project', 'company', 0),
  ('project.edit_settings', 'project', 'Rename, recolor, and configure board settings', 'project', 'project', 0),
  ('project.delete', 'project', 'Permanently delete project board', 'project', 'project', 1),
  ('project.archive', 'project', 'Archive or restore project boards', 'project', 'project', 0),
  ('project.manage_members', 'project', 'Add or remove members from specific projects', 'project', 'project', 0),
  ('project.manage_templates', 'project', 'Save or apply board templates', 'project', 'project', 0),
  ('project.change_status', 'project', 'Update project health and lifecycle status', 'project', 'project', 0),
  ('project.view_dashboard', 'project', 'View analytics and burndown metrics', 'project', 'project', 0),
  ('view.view', 'view', 'Access Kanban, list, and table views', 'view', 'project', 0),
  ('view.create', 'view', 'Save custom filtered views', 'view', 'project', 0),
  ('view.edit', 'view', 'Modify saved views', 'view', 'project', 0),
  ('view.delete', 'view', 'Delete saved views', 'view', 'project', 0),
  ('list.create', 'list', 'Add new columns to project boards', 'list', 'project', 0),
  ('list.edit', 'list', 'Rename columns and adjust WIP limits', 'list', 'project', 0),
  ('list.reorder', 'list', 'Drag and reorder column positions', 'list', 'project', 0),
  ('list.delete', 'list', 'Delete columns and contained cards', 'list', 'project', 1),
  ('task.view', 'task', 'View card details and discussions', 'task', 'project', 0),
  ('task.create', 'task', 'Add new cards to project lists', 'task', 'project', 0),
  ('task.edit', 'task', 'Update card title, description, dates, labels', 'task', 'project', 0),
  ('task.move', 'task', 'Drag and reorder cards within or across lists', 'task', 'project', 0),
  ('task.delete', 'task', 'Permanently remove cards', 'task', 'project', 1),
  ('task.assign', 'task', 'Assign or unassign members on cards', 'task', 'project', 0),
  ('task.watch', 'task', 'Subscribe to card notifications', 'task', 'project', 0),
  ('task.set_priority', 'task', 'Change task priority level', 'task', 'project', 0),
  ('task.bulk_edit', 'task', 'Batch update multiple cards', 'task', 'project', 0),
  ('task.bulk_delete', 'task', 'Batch delete multiple cards', 'task', 'project', 1),
  ('task.import', 'task', 'Import tasks from CSV/Excel', 'task', 'project', 0),
  ('task.export', 'task', 'Export tasks to CSV/Excel', 'task', 'project', 0),
  ('task.duplicate', 'task', 'Clone card with checklist and labels', 'task', 'project', 0),
  ('task.archive', 'task', 'Archive cards without deleting', 'task', 'project', 0),
  ('task.restore', 'task', 'Restore archived cards', 'task', 'project', 0),
  ('subtask.create', 'subtask', 'Add subtasks to cards', 'subtask', 'project', 0),
  ('subtask.edit', 'subtask', 'Update and complete subtasks', 'subtask', 'project', 0),
  ('subtask.delete', 'subtask', 'Delete subtasks from cards', 'subtask', 'project', 0),
  ('checklist.create', 'checklist', 'Add checklists to cards', 'checklist', 'project', 0),
  ('checklist.edit', 'checklist', 'Check/uncheck and modify checklist items', 'checklist', 'project', 0),
  ('checklist.delete', 'checklist', 'Delete entire checklists', 'checklist', 'project', 0),
  ('comment.view', 'comment', 'Read card discussions', 'comment', 'project', 0),
  ('comment.create', 'comment', 'Post new comments and replies', 'comment', 'project', 0),
  ('comment.edit_own', 'comment', 'Edit comments written by self', 'comment', 'project', 0),
  ('comment.delete_own', 'comment', 'Remove comments written by self', 'comment', 'project', 0),
  ('comment.delete_any', 'comment', 'Moderate discussion by deleting any comment', 'comment', 'project', 1),
  ('attachment.view', 'attachment', 'View and preview file attachments', 'attachment', 'project', 0),
  ('attachment.upload', 'attachment', 'Upload files and links to cards', 'attachment', 'project', 0),
  ('attachment.delete_own', 'attachment', 'Delete files uploaded by self', 'attachment', 'project', 0),
  ('attachment.delete_any', 'attachment', 'Delete any attached files', 'attachment', 'project', 1),
  ('attachment.version', 'attachment', 'Upload and restore attachment versions', 'attachment', 'project', 0),
  ('file.view', 'file', 'Download authorized tenant files and attachments', 'file', 'project', 0),
  ('file.delete', 'file', 'Delete files from tenant storage', 'file', 'project', 1),
  ('session.view_own', 'session', 'List active devices and login sessions', 'session', 'company', 0),
  ('session.revoke_own', 'session', 'Log out active sessions for self', 'session', 'company', 0),
  ('session.revoke_others', 'session', 'Administratively revoke active sessions of members', 'session', 'company', 1),
  ('label.view', 'label', 'View board labels', 'label', 'project', 0),
  ('label.create', 'label', 'Create new colored labels', 'label', 'project', 0),
  ('label.edit', 'label', 'Modify label title and color', 'label', 'project', 0),
  ('label.delete', 'label', 'Delete board labels', 'label', 'project', 0),
  ('custom_field.view', 'custom_field', 'View custom attributes on cards', 'custom_field', 'project', 0),
  ('custom_field.create', 'custom_field', 'Define new custom field schemas', 'custom_field', 'project', 0),
  ('custom_field.edit', 'custom_field', 'Edit custom field values and definitions', 'custom_field', 'project', 0),
  ('custom_field.delete', 'custom_field', 'Delete custom fields', 'custom_field', 'project', 1),
  ('milestone.view', 'milestone', 'View milestones and target dates', 'milestone', 'project', 0),
  ('milestone.create', 'milestone', 'Create project milestones', 'milestone', 'project', 0),
  ('milestone.edit', 'milestone', 'Update milestone progress', 'milestone', 'project', 0),
  ('milestone.delete', 'milestone', 'Remove milestones', 'milestone', 'project', 0),
  ('sprint.view', 'sprint', 'View sprints and burndown charts', 'sprint', 'project', 0),
  ('sprint.create', 'sprint', 'Create new sprint iterations', 'sprint', 'project', 0),
  ('sprint.edit', 'sprint', 'Update sprint goals and duration', 'sprint', 'project', 0),
  ('sprint.start', 'sprint', 'Activate planning sprint', 'sprint', 'project', 0),
  ('sprint.complete', 'sprint', 'Close active sprint and carry over tasks', 'sprint', 'project', 0),
  ('sprint.delete', 'sprint', 'Delete sprints', 'sprint', 'project', 1),
  ('backlog.view', 'backlog', 'View unassigned backlog tasks', 'backlog', 'project', 0),
  ('backlog.reorder', 'backlog', 'Prioritize backlog items', 'backlog', 'project', 0),
  ('epic.view', 'epic', 'View epic groupings and roll-up metrics', 'epic', 'project', 0),
  ('epic.create', 'epic', 'Create high-level epics', 'epic', 'project', 0),
  ('epic.edit', 'epic', 'Modify epics', 'epic', 'project', 0),
  ('epic.delete', 'epic', 'Delete epics', 'epic', 'project', 0),
  ('time.view_own', 'time', 'View personal logged time entries', 'time', 'project', 0),
  ('time.log', 'time', 'Start timer or enter time spent on tasks', 'time', 'project', 0),
  ('time.edit_own', 'time', 'Edit personal time log entries', 'time', 'project', 0),
  ('time.view_all', 'time', 'View team timesheets and logged hours', 'time', 'project', 0),
  ('time.edit_all', 'time', 'Adjust logged hours for team members', 'time', 'project', 1),
  ('time.approve_timesheet', 'time', 'Approve or reject weekly timesheet submissions', 'time', 'company', 1),
  ('report.view_project', 'report', 'View task velocity and project progress', 'report', 'project', 0),
  ('report.view_team', 'report', 'View team workload and allocations', 'report', 'company', 0),
  ('report.view_all', 'report', 'Access cross-project organization reports', 'report', 'company', 0),
  ('report.export', 'report', 'Download PDF and CSV reports', 'report', 'company', 0),
  ('report.create_custom', 'report', 'Build and save custom report configurations', 'report', 'company', 0),
  ('dashboard.view_project', 'dashboard', 'View project KPIs and task status overview', 'dashboard', 'project', 0),
  ('dashboard.view_executive', 'dashboard', 'View organization-wide health roll-up', 'dashboard', 'company', 0),
  ('notification.view_own', 'notification', 'Read in-app notifications', 'notification', 'company', 0),
  ('notification.manage_own', 'notification', 'Configure personal alert preferences', 'notification', 'company', 0),
  ('audit.view', 'audit', 'Inspect security and data mutation logs', 'audit', 'company', 1),
  ('audit.export', 'audit', 'Download CSV of compliance audit logs', 'audit', 'company', 1),
  ('activity.view', 'activity', 'View card and board event stream', 'activity', 'project', 0),
  ('api_key.view', 'api_key', 'List created developer API keys', 'api_key', 'company', 0),
  ('api_key.create', 'api_key', 'Generate API tokens with scoped permissions', 'api_key', 'company', 1),
  ('api_key.revoke', 'api_key', 'Invalidate API tokens', 'api_key', 'company', 1),
  ('webhook.view', 'webhook', 'Inspect outgoing webhook endpoints', 'webhook', 'project', 0),
  ('webhook.create', 'webhook', 'Configure outgoing event webhooks', 'webhook', 'project', 1),
  ('webhook.edit', 'webhook', 'Modify webhook URLs and event triggers', 'webhook', 'project', 1),
  ('webhook.delete', 'webhook', 'Remove webhooks', 'webhook', 'project', 1),
  ('integration.view', 'integration', 'View connected external services', 'integration', 'company', 0),
  ('integration.manage', 'integration', 'Connect or disconnect third-party integrations', 'integration', 'company', 1),
  ('import_export.import', 'import_export', 'Upload bulk data files into projects', 'import_export', 'project', 0),
  ('import_export.export', 'import_export', 'Download workspace and project exports', 'import_export', 'project', 0),
  ('archive.view', 'archive', 'View archived workspaces, boards, and cards', 'archive', 'company', 0),
  ('archive.restore', 'archive', 'Restore archived resources to active state', 'archive', 'company', 0),
  ('archive.permanent_delete', 'archive', 'Permanently purge archived items from database', 'archive', 'company', 1),
  ('search.use', 'search', 'Execute full-text global search', 'search', 'company', 0),
  ('billing.view', 'billing', 'View plan and subscription invoices', 'billing', 'company', 0),
  ('billing.manage', 'billing', 'Upgrade, downgrade, or cancel plans', 'billing', 'company', 1)
ON DUPLICATE KEY UPDATE 
  category = VALUES(category),
  description = VALUES(description),
  module = VALUES(module),
  scope = VALUES(scope),
  dangerous = VALUES(dangerous);

-- 3. Ensure 6 system roles exist
INSERT IGNORE INTO roles (name, is_system, is_editable, workspace_id) VALUES
  ('Owner', 1, 0, NULL),
  ('Admin', 1, 1, NULL),
  ('Project Manager', 1, 1, NULL),
  ('Team Member', 1, 1, NULL),
  ('Viewer', 1, 1, NULL),
  ('Guest', 1, 1, NULL);

-- Legacy role migration: align existing Super Admin and Manager
UPDATE roles SET name = 'Owner', is_editable = 0 WHERE name = 'Super Admin' AND is_system = 1 AND workspace_id IS NULL;
UPDATE roles SET name = 'Project Manager' WHERE name = 'Manager' AND is_system = 1 AND workspace_id IS NULL;

-- 4. Seed role permissions for all 6 system roles

-- Grant permissions for system role: Owner
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r 
CROSS JOIN permissions p
WHERE r.name = 'Owner' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` IN ('company.view', 'company.edit_settings', 'company.manage_security', 'company.manage_billing', 'company.delete', 'company.export_data', 'workspace.view', 'workspace.create', 'workspace.edit', 'workspace.delete', 'workspace.archive', 'team.view', 'team.create', 'team.edit', 'team.delete', 'team.manage_members', 'member.view', 'member.invite', 'member.remove', 'member.assign_role', 'member.deactivate', 'member.reset_password', 'member.reset_2fa', 'role.view', 'role.create', 'role.edit', 'role.delete', 'role.assign', 'project.view', 'project.create', 'project.edit_settings', 'project.delete', 'project.archive', 'project.manage_members', 'project.manage_templates', 'project.change_status', 'project.view_dashboard', 'view.view', 'view.create', 'view.edit', 'view.delete', 'list.create', 'list.edit', 'list.reorder', 'list.delete', 'task.view', 'task.create', 'task.edit', 'task.move', 'task.delete', 'task.assign', 'task.watch', 'task.set_priority', 'task.bulk_edit', 'task.bulk_delete', 'task.import', 'task.export', 'task.duplicate', 'task.archive', 'task.restore', 'subtask.create', 'subtask.edit', 'subtask.delete', 'checklist.create', 'checklist.edit', 'checklist.delete', 'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own', 'comment.delete_any', 'attachment.view', 'attachment.upload', 'attachment.delete_own', 'attachment.delete_any', 'attachment.version', 'file.view', 'file.delete', 'session.view_own', 'session.revoke_own', 'session.revoke_others', 'label.view', 'label.create', 'label.edit', 'label.delete', 'custom_field.view', 'custom_field.create', 'custom_field.edit', 'custom_field.delete', 'milestone.view', 'milestone.create', 'milestone.edit', 'milestone.delete', 'sprint.view', 'sprint.create', 'sprint.edit', 'sprint.start', 'sprint.complete', 'sprint.delete', 'backlog.view', 'backlog.reorder', 'epic.view', 'epic.create', 'epic.edit', 'epic.delete', 'time.view_own', 'time.log', 'time.edit_own', 'time.view_all', 'time.edit_all', 'time.approve_timesheet', 'report.view_project', 'report.view_team', 'report.view_all', 'report.export', 'report.create_custom', 'dashboard.view_project', 'dashboard.view_executive', 'notification.view_own', 'notification.manage_own', 'audit.view', 'audit.export', 'activity.view', 'api_key.view', 'api_key.create', 'api_key.revoke', 'webhook.view', 'webhook.create', 'webhook.edit', 'webhook.delete', 'integration.view', 'integration.manage', 'import_export.import', 'import_export.export', 'archive.view', 'archive.restore', 'archive.permanent_delete', 'search.use', 'billing.view', 'billing.manage');

-- Grant permissions for system role: Admin
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r 
CROSS JOIN permissions p
WHERE r.name = 'Admin' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` IN ('company.view', 'company.edit_settings', 'company.manage_security', 'company.export_data', 'workspace.view', 'workspace.create', 'workspace.edit', 'workspace.delete', 'workspace.archive', 'team.view', 'team.create', 'team.edit', 'team.delete', 'team.manage_members', 'member.view', 'member.invite', 'member.remove', 'member.assign_role', 'member.deactivate', 'member.reset_password', 'member.reset_2fa', 'role.view', 'role.create', 'role.edit', 'role.delete', 'role.assign', 'project.view', 'project.create', 'project.edit_settings', 'project.delete', 'project.archive', 'project.manage_members', 'project.manage_templates', 'project.change_status', 'project.view_dashboard', 'view.view', 'view.create', 'view.edit', 'view.delete', 'list.create', 'list.edit', 'list.reorder', 'list.delete', 'task.view', 'task.create', 'task.edit', 'task.move', 'task.delete', 'task.assign', 'task.watch', 'task.set_priority', 'task.bulk_edit', 'task.bulk_delete', 'task.import', 'task.export', 'task.duplicate', 'task.archive', 'task.restore', 'subtask.create', 'subtask.edit', 'subtask.delete', 'checklist.create', 'checklist.edit', 'checklist.delete', 'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own', 'comment.delete_any', 'attachment.view', 'attachment.upload', 'attachment.delete_own', 'attachment.delete_any', 'attachment.version', 'file.view', 'file.delete', 'session.view_own', 'session.revoke_own', 'session.revoke_others', 'label.view', 'label.create', 'label.edit', 'label.delete', 'custom_field.view', 'custom_field.create', 'custom_field.edit', 'custom_field.delete', 'milestone.view', 'milestone.create', 'milestone.edit', 'milestone.delete', 'sprint.view', 'sprint.create', 'sprint.edit', 'sprint.start', 'sprint.complete', 'sprint.delete', 'backlog.view', 'backlog.reorder', 'epic.view', 'epic.create', 'epic.edit', 'epic.delete', 'time.view_own', 'time.log', 'time.edit_own', 'time.view_all', 'time.edit_all', 'time.approve_timesheet', 'report.view_project', 'report.view_team', 'report.view_all', 'report.export', 'report.create_custom', 'dashboard.view_project', 'dashboard.view_executive', 'notification.view_own', 'notification.manage_own', 'audit.view', 'audit.export', 'activity.view', 'api_key.view', 'api_key.create', 'api_key.revoke', 'webhook.view', 'webhook.create', 'webhook.edit', 'webhook.delete', 'integration.view', 'integration.manage', 'import_export.import', 'import_export.export', 'archive.view', 'archive.restore', 'archive.permanent_delete', 'search.use', 'billing.view');

-- Grant permissions for system role: Project Manager
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r 
CROSS JOIN permissions p
WHERE r.name = 'Project Manager' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` IN ('team.view', 'member.view', 'member.invite', 'project.view', 'project.create', 'project.edit_settings', 'project.delete', 'project.archive', 'project.manage_members', 'project.manage_templates', 'project.change_status', 'project.view_dashboard', 'view.view', 'view.create', 'view.edit', 'view.delete', 'list.create', 'list.edit', 'list.reorder', 'list.delete', 'task.view', 'task.create', 'task.edit', 'task.move', 'task.delete', 'task.assign', 'task.watch', 'task.set_priority', 'task.bulk_edit', 'task.bulk_delete', 'task.import', 'task.export', 'task.duplicate', 'task.archive', 'task.restore', 'subtask.create', 'subtask.edit', 'subtask.delete', 'checklist.create', 'checklist.edit', 'checklist.delete', 'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own', 'comment.delete_any', 'attachment.view', 'attachment.upload', 'attachment.delete_own', 'attachment.delete_any', 'attachment.version', 'file.view', 'file.delete', 'session.view_own', 'session.revoke_own', 'session.revoke_others', 'label.view', 'label.create', 'label.edit', 'label.delete', 'custom_field.view', 'custom_field.create', 'custom_field.edit', 'custom_field.delete', 'milestone.view', 'milestone.create', 'milestone.edit', 'milestone.delete', 'sprint.view', 'sprint.create', 'sprint.edit', 'sprint.start', 'sprint.complete', 'sprint.delete', 'backlog.view', 'backlog.reorder', 'epic.view', 'epic.create', 'epic.edit', 'epic.delete', 'time.view_own', 'time.log', 'time.edit_own', 'time.view_all', 'time.edit_all', 'time.approve_timesheet', 'report.view_project', 'report.view_team', 'report.view_all', 'report.export', 'report.create_custom', 'dashboard.view_project', 'dashboard.view_executive', 'notification.view_own', 'notification.manage_own', 'activity.view', 'webhook.view', 'webhook.create', 'webhook.edit', 'webhook.delete', 'import_export.import', 'import_export.export', 'archive.view', 'archive.restore', 'archive.permanent_delete', 'search.use');

-- Grant permissions for system role: Team Member
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r 
CROSS JOIN permissions p
WHERE r.name = 'Team Member' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` IN ('project.view', 'view.view', 'list.create', 'task.view', 'task.create', 'task.edit', 'task.move', 'task.assign', 'task.watch', 'subtask.create', 'subtask.edit', 'checklist.create', 'checklist.edit', 'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own', 'attachment.view', 'attachment.upload', 'attachment.delete_own', 'file.view', 'session.view_own', 'session.revoke_own', 'label.view', 'label.create', 'custom_field.view', 'milestone.view', 'sprint.view', 'backlog.view', 'epic.view', 'time.view_own', 'time.log', 'time.edit_own', 'report.view_project', 'dashboard.view_project', 'notification.view_own', 'notification.manage_own', 'activity.view', 'search.use');

-- Grant permissions for system role: Viewer
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r 
CROSS JOIN permissions p
WHERE r.name = 'Viewer' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` IN ('company.view', 'workspace.view', 'team.view', 'member.view', 'role.view', 'project.view', 'view.view', 'task.view', 'comment.view', 'attachment.view', 'file.view', 'session.view_own', 'session.revoke_own', 'label.view', 'custom_field.view', 'milestone.view', 'sprint.view', 'backlog.view', 'epic.view', 'notification.view_own', 'notification.manage_own', 'audit.view', 'activity.view', 'api_key.view', 'webhook.view', 'integration.view', 'archive.view', 'search.use', 'billing.view');

-- Grant permissions for system role: Guest
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r 
CROSS JOIN permissions p
WHERE r.name = 'Guest' AND r.is_system = 1 AND r.workspace_id IS NULL
  AND p.`key` IN ('project.view', 'view.view', 'task.view', 'comment.view', 'comment.create', 'attachment.view', 'file.view', 'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use');

-- 5. Add role_id to board_members for project-level role assignment if not exists
ALTER TABLE board_members
  ADD COLUMN IF NOT EXISTS role_id BIGINT UNSIGNED NULL;

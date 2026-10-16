// server/src/rbac/registry.js
// Single source of truth for all system permissions, roles, and the RBAC matrix.

/**
 * Scope definitions:
 * - 'company': Company/workspace wide capability
 * - 'project': Project/board scoped capability
 */

const PERMISSIONS = [
  // --- Company ---
  { key: 'company.view', module: 'company', label: 'View Company Info', description: 'View company profile and details', scope: 'company', dangerous: false, planned: true },
  { key: 'company.edit_settings', module: 'company', label: 'Edit Company Settings', description: 'Modify company preferences and profile', scope: 'company', dangerous: true, planned: true },
  { key: 'company.manage_security', module: 'company', label: 'Manage Security Policies', description: 'Configure 2FA requirements and authentication policies', scope: 'company', dangerous: true },
  { key: 'company.delete', module: 'company', label: 'Delete Company', description: 'Permanently delete company and all tenant databases', scope: 'company', dangerous: true, planned: true },
  { key: 'company.export_data', module: 'company', label: 'Export Company Data', description: 'Generate and download full tenant database export', scope: 'company', dangerous: true, planned: true },

  // --- Workspace ---
  { key: 'workspace.view', module: 'workspace', label: 'View Workspace', description: 'View workspace information and dashboard', scope: 'company', dangerous: false },
  { key: 'workspace.create', module: 'workspace', label: 'Create Workspace', description: 'Create new workspaces', scope: 'company', dangerous: false },
  { key: 'workspace.edit', module: 'workspace', label: 'Edit Workspace', description: 'Edit workspace name and settings', scope: 'company', dangerous: false },
  { key: 'workspace.delete', module: 'workspace', label: 'Delete Workspace', description: 'Delete entire workspace and all child boards', scope: 'company', dangerous: true },
  { key: 'workspace.archive', module: 'workspace', label: 'Archive Workspace', description: 'Archive or restore workspaces', scope: 'company', dangerous: false },

  // --- Team ---
  { key: 'team.view', module: 'team', label: 'View Teams', description: 'View teams and department memberships', scope: 'company', dangerous: false, planned: true },
  { key: 'team.create', module: 'team', label: 'Create Team', description: 'Create departments and teams', scope: 'company', dangerous: false, planned: true },
  { key: 'team.edit', module: 'team', label: 'Edit Team', description: 'Modify team details', scope: 'company', dangerous: false, planned: true },
  { key: 'team.delete', module: 'team', label: 'Delete Team', description: 'Delete teams', scope: 'company', dangerous: true, planned: true },
  { key: 'team.manage_members', module: 'team', label: 'Manage Team Members', description: 'Assign or remove members from teams', scope: 'company', dangerous: false, planned: true },

  // --- Member ---
  { key: 'member.view', module: 'member', label: 'View Members', description: 'View workspace member directory', scope: 'company', dangerous: false },
  { key: 'member.invite', module: 'member', label: 'Invite Members', description: 'Generate and send invitation links', scope: 'company', dangerous: false },
  { key: 'member.invite_guest', module: 'member', label: 'Invite Guest Members', description: 'Invite external collaborators to specific boards', scope: 'company', dangerous: false },
  { key: 'member.remove', module: 'member', label: 'Remove Members', description: 'Remove members from workspace', scope: 'company', dangerous: true },
  { key: 'member.assign_role', module: 'member', label: 'Assign Roles', description: 'Change roles of workspace members', scope: 'company', dangerous: true },
  { key: 'member.deactivate', module: 'member', label: 'Deactivate Members', description: 'Temporarily deactivate member accounts', scope: 'company', dangerous: true },
  { key: 'member.reset_password', module: 'member', label: 'Reset Password', description: 'Set temporary password for lower-ranked members', scope: 'company', dangerous: true },
  { key: 'member.reset_2fa', module: 'member', label: 'Reset 2FA', description: 'Reset two-factor authentication for lower-ranked members', scope: 'company', dangerous: true },

  // --- Role ---
  { key: 'role.view', module: 'role', label: 'View Roles', description: 'View permissions and role catalogs', scope: 'company', dangerous: false },
  { key: 'role.create', module: 'role', label: 'Create Custom Roles', description: 'Create new custom workspace roles', scope: 'company', dangerous: true },
  { key: 'role.edit', module: 'role', label: 'Edit Custom Roles', description: 'Modify permissions for custom roles', scope: 'company', dangerous: true },
  { key: 'role.delete', module: 'role', label: 'Delete Custom Roles', description: 'Delete custom roles not in use', scope: 'company', dangerous: true },

  // --- Project (Boards) ---
  { key: 'project.access_all', module: 'project', label: 'Access All Projects', description: 'Permissions apply across all workspace boards without explicit board membership', scope: 'company', dangerous: true },
  { key: 'project.view', module: 'project', label: 'View Project', description: 'Access and view project boards', scope: 'project', dangerous: false },
  { key: 'project.create', module: 'project', label: 'Create Project', description: 'Create new project boards', scope: 'company', dangerous: false },
  { key: 'project.edit_settings', module: 'project', label: 'Edit Project Settings', description: 'Rename, recolor, and configure board settings', scope: 'project', dangerous: false },
  { key: 'project.delete', module: 'project', label: 'Delete Project', description: 'Permanently delete project board', scope: 'project', dangerous: true },
  { key: 'project.archive', module: 'project', label: 'Archive Project', description: 'Archive or restore project boards', scope: 'project', dangerous: false },
  { key: 'project.manage_members', module: 'project', label: 'Manage Project Members', description: 'Add or remove members from specific projects', scope: 'project', dangerous: false },
  { key: 'project.assign_role', module: 'project', label: 'Assign Project Roles', description: 'Assign or modify board-level member roles', scope: 'project', dangerous: true },
  { key: 'project.manage_templates', module: 'project', label: 'Manage Templates', description: 'Save or apply board templates', scope: 'project', dangerous: false, planned: true },
  { key: 'project.change_status', module: 'project', label: 'Change Project Status', description: 'Update project health and lifecycle status', scope: 'project', dangerous: false, planned: true },
  { key: 'project.duplicate', module: 'project', label: 'Duplicate Project', description: 'Clone project board and structure', scope: 'project', dangerous: false, planned: true },
  { key: 'project.change_visibility', module: 'project', label: 'Change Project Visibility', description: 'Toggle board public or private visibility', scope: 'project', dangerous: false, planned: true },

  // --- View ---
  { key: 'view.view', module: 'view', label: 'View Saved Views', description: 'Access Kanban, list, and table views', scope: 'project', dangerous: false, planned: true },
  { key: 'view.create', module: 'view', label: 'Create Saved Views', description: 'Save custom filtered views', scope: 'project', dangerous: false, planned: true },
  { key: 'view.edit', module: 'view', label: 'Edit Saved Views', description: 'Modify saved views', scope: 'project', dangerous: false, planned: true },
  { key: 'view.delete', module: 'view', label: 'Delete Saved Views', description: 'Delete saved views', scope: 'project', dangerous: false, planned: true },

  // --- List ---
  { key: 'list.create', module: 'list', label: 'Create Lists', description: 'Add new columns to project boards', scope: 'project', dangerous: false },
  { key: 'list.edit', module: 'list', label: 'Edit Lists', description: 'Rename columns and adjust WIP limits', scope: 'project', dangerous: false },
  { key: 'list.reorder', module: 'list', label: 'Reorder Lists', description: 'Drag and reorder column positions', scope: 'project', dangerous: false },
  { key: 'list.delete', module: 'list', label: 'Delete Lists', description: 'Delete columns and contained cards', scope: 'project', dangerous: true },

  // --- Task (Cards) ---
  { key: 'task.view', module: 'task', label: 'View Tasks', description: 'View card details and discussions', scope: 'project', dangerous: false },
  { key: 'task.create', module: 'task', label: 'Create Tasks', description: 'Add new cards to project lists', scope: 'project', dangerous: false },
  { key: 'task.edit', module: 'task', label: 'Edit Tasks', description: 'Update card title, description, dates, labels', scope: 'project', dangerous: false },
  { key: 'task.move', module: 'task', label: 'Move Tasks', description: 'Drag and reorder cards within or across lists', scope: 'project', dangerous: false },
  { key: 'task.assign', module: 'task', label: 'Assign Tasks', description: 'Assign or unassign members on cards', scope: 'project', dangerous: false },
  { key: 'task.assign_self', module: 'task', label: 'Assign Self to Tasks', description: 'Assign or unassign yourself on cards', scope: 'project', dangerous: false },
  { key: 'task.complete', module: 'task', label: 'Complete Tasks', description: 'Mark tasks done or reopen completed tasks', scope: 'project', dangerous: false },
  { key: 'task.delete', module: 'task', label: 'Delete Tasks', description: 'Permanently remove cards', scope: 'project', dangerous: true },
  { key: 'task.delete_own', module: 'task', label: 'Delete Own Tasks', description: 'Delete cards created by yourself', scope: 'project', dangerous: true },
  { key: 'task.watch', module: 'task', label: 'Watch Tasks', description: 'Subscribe to card notifications', scope: 'project', dangerous: false, planned: true },
  { key: 'task.set_priority', module: 'task', label: 'Set Priority', description: 'Change task priority level', scope: 'project', dangerous: false, planned: true },
  { key: 'task.bulk_edit', module: 'task', label: 'Bulk Edit Tasks', description: 'Batch update multiple cards', scope: 'project', dangerous: false, planned: true },
  { key: 'task.bulk_delete', module: 'task', label: 'Bulk Delete Tasks', description: 'Batch delete multiple cards', scope: 'project', dangerous: true, planned: true },
  { key: 'task.duplicate', module: 'task', label: 'Duplicate Tasks', description: 'Clone card with checklist and labels', scope: 'project', dangerous: false },
  { key: 'task.archive', module: 'task', label: 'Archive Tasks', description: 'Archive cards without deleting', scope: 'project', dangerous: false },
  { key: 'task.restore', module: 'task', label: 'Restore Tasks', description: 'Restore archived cards', scope: 'project', dangerous: false },

  // --- Subtask ---
  { key: 'subtask.create', module: 'subtask', label: 'Create Subtasks', description: 'Add subtasks to cards', scope: 'project', dangerous: false, planned: true },
  { key: 'subtask.edit', module: 'subtask', label: 'Edit Subtasks', description: 'Update and complete subtasks', scope: 'project', dangerous: false, planned: true },
  { key: 'subtask.delete', module: 'subtask', label: 'Delete Subtasks', description: 'Delete subtasks from cards', scope: 'project', dangerous: false, planned: true },

  // --- Checklist ---
  { key: 'checklist.create', module: 'checklist', label: 'Create Checklists', description: 'Add checklists to cards', scope: 'project', dangerous: false },
  { key: 'checklist.edit', module: 'checklist', label: 'Edit Checklists', description: 'Check/uncheck and modify checklist items', scope: 'project', dangerous: false },
  { key: 'checklist.delete', module: 'checklist', label: 'Delete Checklists', description: 'Delete entire checklists', scope: 'project', dangerous: false },

  // --- Comment ---
  { key: 'comment.view', module: 'comment', label: 'View Comments', description: 'Read card discussions', scope: 'project', dangerous: false },
  { key: 'comment.create', module: 'comment', label: 'Add Comments', description: 'Post new comments and replies', scope: 'project', dangerous: false },
  { key: 'comment.edit_own', module: 'comment', label: 'Edit Own Comments', description: 'Edit comments written by self', scope: 'project', dangerous: false },
  { key: 'comment.delete_own', module: 'comment', label: 'Delete Own Comments', description: 'Remove comments written by self', scope: 'project', dangerous: false },
  { key: 'comment.delete_any', module: 'comment', label: 'Delete Any Comment', description: 'Moderate discussion by deleting any comment', scope: 'project', dangerous: true },

  // --- Attachment ---
  { key: 'attachment.view', module: 'attachment', label: 'View Attachments', description: 'View and preview file attachments', scope: 'project', dangerous: false },
  { key: 'attachment.upload', module: 'attachment', label: 'Upload Attachments', description: 'Upload files and links to cards', scope: 'project', dangerous: false },
  { key: 'attachment.delete_own', module: 'attachment', label: 'Delete Own Attachments', description: 'Delete files uploaded by self', scope: 'project', dangerous: false },
  { key: 'attachment.delete_any', module: 'attachment', label: 'Delete Any Attachment', description: 'Delete any attached files', scope: 'project', dangerous: true },
  { key: 'attachment.version', module: 'attachment', label: 'Manage Versions', description: 'Upload and restore attachment versions', scope: 'project', dangerous: false, planned: true },

  // --- File ---
  { key: 'file.view', module: 'file', label: 'Download Files', description: 'Download authorized tenant files and attachments', scope: 'project', dangerous: false },
  { key: 'file.delete', module: 'file', label: 'Delete Files', description: 'Delete files from tenant storage', scope: 'project', dangerous: true },

  // --- Session ---
  { key: 'session.view_own', module: 'session', label: 'View Own Sessions', description: 'List active devices and login sessions', scope: 'company', dangerous: false },
  { key: 'session.revoke_own', module: 'session', label: 'Revoke Own Sessions', description: 'Log out active sessions for self', scope: 'company', dangerous: false },
  { key: 'session.revoke_others', module: 'session', label: 'Revoke Others Sessions', description: 'Administratively revoke active sessions of members', scope: 'company', dangerous: true },

  // --- Label ---
  { key: 'label.view', module: 'label', label: 'View Labels', description: 'View board labels', scope: 'project', dangerous: false },
  { key: 'label.create', module: 'label', label: 'Create Labels', description: 'Create new colored labels', scope: 'project', dangerous: false },
  { key: 'label.edit', module: 'label', label: 'Edit Labels', description: 'Modify label title and color', scope: 'project', dangerous: false },
  { key: 'label.delete', module: 'label', label: 'Delete Labels', description: 'Delete board labels', scope: 'project', dangerous: false },
  { key: 'label.delete_own', module: 'label', label: 'Delete Own Labels', description: 'Delete custom labels created by yourself', scope: 'project', dangerous: false },

  // --- Custom Field ---
  { key: 'custom_field.view', module: 'custom_field', label: 'View Custom Fields', description: 'View custom attributes on cards', scope: 'project', dangerous: false, planned: true },
  { key: 'custom_field.create', module: 'custom_field', label: 'Create Custom Fields', description: 'Define new custom field schemas', scope: 'project', dangerous: false, planned: true },
  { key: 'custom_field.edit', module: 'custom_field', label: 'Edit Custom Fields', description: 'Edit custom field values and definitions', scope: 'project', dangerous: false, planned: true },
  { key: 'custom_field.delete', module: 'custom_field', label: 'Delete Custom Fields', description: 'Delete custom fields', scope: 'project', dangerous: true, planned: true },

  // --- Milestone ---
  { key: 'milestone.view', module: 'milestone', label: 'View Milestones', description: 'View milestones and target dates', scope: 'project', dangerous: false, planned: true },
  { key: 'milestone.create', module: 'milestone', label: 'Create Milestones', description: 'Create project milestones', scope: 'project', dangerous: false, planned: true },
  { key: 'milestone.edit', module: 'milestone', label: 'Edit Milestones', description: 'Update milestone progress', scope: 'project', dangerous: false, planned: true },
  { key: 'milestone.delete', module: 'milestone', label: 'Delete Milestones', description: 'Remove milestones', scope: 'project', dangerous: false, planned: true },

  // --- Sprint ---
  { key: 'sprint.view', module: 'sprint', label: 'View Sprints', description: 'View sprints and burndown charts', scope: 'project', dangerous: false, planned: true },
  { key: 'sprint.create', module: 'sprint', label: 'Create Sprints', description: 'Create new sprint iterations', scope: 'project', dangerous: false, planned: true },
  { key: 'sprint.edit', module: 'sprint', label: 'Edit Sprints', description: 'Update sprint goals and duration', scope: 'project', dangerous: false, planned: true },
  { key: 'sprint.start', module: 'sprint', label: 'Start Sprints', description: 'Activate planning sprint', scope: 'project', dangerous: false, planned: true },
  { key: 'sprint.complete', module: 'sprint', label: 'Complete Sprints', description: 'Close active sprint and carry over tasks', scope: 'project', dangerous: false, planned: true },
  { key: 'sprint.delete', module: 'sprint', label: 'Delete Sprints', description: 'Delete sprints', scope: 'project', dangerous: true, planned: true },

  // --- Backlog ---
  { key: 'backlog.view', module: 'backlog', label: 'View Backlog', description: 'View unassigned backlog tasks', scope: 'project', dangerous: false, planned: true },
  { key: 'backlog.reorder', module: 'backlog', label: 'Reorder Backlog', description: 'Prioritize backlog items', scope: 'project', dangerous: false, planned: true },

  // --- Epic ---
  { key: 'epic.view', module: 'epic', label: 'View Epics', description: 'View epic groupings and roll-up metrics', scope: 'project', dangerous: false, planned: true },
  { key: 'epic.create', module: 'epic', label: 'Create Epics', description: 'Create high-level epics', scope: 'project', dangerous: false, planned: true },
  { key: 'epic.edit', module: 'epic', label: 'Edit Epics', description: 'Modify epics', scope: 'project', dangerous: false, planned: true },
  { key: 'epic.delete', module: 'epic', label: 'Delete Epics', description: 'Delete epics', scope: 'project', dangerous: false, planned: true },

  // --- Time ---
  { key: 'time.view_own', module: 'time', label: 'View Own Time', description: 'View personal logged time entries', scope: 'project', dangerous: false, planned: true },
  { key: 'time.log', module: 'time', label: 'Log Time', description: 'Start timer or enter time spent on tasks', scope: 'project', dangerous: false, planned: true },
  { key: 'time.edit_own', module: 'time', label: 'Edit Own Time', description: 'Edit personal time log entries', scope: 'project', dangerous: false, planned: true },
  { key: 'time.view_all', module: 'time', label: 'View All Time', description: 'View team timesheets and logged hours', scope: 'project', dangerous: false, planned: true },
  { key: 'time.edit_all', module: 'time', label: 'Edit All Time', description: 'Adjust logged hours for team members', scope: 'project', dangerous: true, planned: true },
  { key: 'time.approve_timesheet', module: 'time', label: 'Approve Timesheets', description: 'Approve or reject weekly timesheet submissions', scope: 'company', dangerous: true, planned: true },

  // --- Report ---
  { key: 'report.view_project', module: 'report', label: 'View Project Reports', description: 'View task velocity and project progress', scope: 'project', dangerous: false },
  { key: 'report.view_team', module: 'report', label: 'View Team Reports', description: 'View team workload and allocations', scope: 'company', dangerous: false, planned: true },
  { key: 'report.view_all', module: 'report', label: 'View All Reports', description: 'Access cross-project organization reports', scope: 'company', dangerous: false, planned: true },
  { key: 'report.export', module: 'report', label: 'Export Reports', description: 'Download PDF and CSV reports', scope: 'company', dangerous: false, planned: true },
  { key: 'report.create_custom', module: 'report', label: 'Create Custom Reports', description: 'Build and save custom report configurations', scope: 'company', dangerous: false, planned: true },

  // --- Dashboard ---
  { key: 'dashboard.view_project', module: 'dashboard', label: 'View Project Dashboard', description: 'View project KPIs and task status overview', scope: 'project', dangerous: false, planned: true },
  { key: 'dashboard.view_executive', module: 'dashboard', label: 'View Executive Dashboard', description: 'View organization-wide health roll-up', scope: 'company', dangerous: false, planned: true },

  // --- Notification ---
  { key: 'notification.view_own', module: 'notification', label: 'View Notifications', description: 'Read in-app notifications', scope: 'company', dangerous: false },
  { key: 'notification.manage_own', module: 'notification', label: 'Manage Notifications', description: 'Configure personal alert preferences', scope: 'company', dangerous: false },

  // --- Audit ---
  { key: 'audit.view', module: 'audit', label: 'View Audit Log', description: 'Inspect security and data mutation logs', scope: 'company', dangerous: true },
  { key: 'audit.export', module: 'audit', label: 'Export Audit Log', description: 'Download CSV of compliance audit logs', scope: 'company', dangerous: true },

  // --- Activity ---
  { key: 'activity.view', module: 'activity', label: 'View Activity Feed', description: 'View card and board event stream', scope: 'company', dangerous: false },

  // --- API Key ---
  { key: 'api_key.view', module: 'api_key', label: 'View API Keys', description: 'List created developer API keys', scope: 'company', dangerous: false, planned: true },
  { key: 'api_key.create', module: 'api_key', label: 'Create API Keys', description: 'Generate API tokens with scoped permissions', scope: 'company', dangerous: true, planned: true },
  { key: 'api_key.revoke', module: 'api_key', label: 'Revoke API Keys', description: 'Invalidate API tokens', scope: 'company', dangerous: true, planned: true },

  // --- Webhook ---
  { key: 'webhook.view', module: 'webhook', label: 'View Webhooks', description: 'Inspect outgoing webhook endpoints', scope: 'project', dangerous: false, planned: true },
  { key: 'webhook.create', module: 'webhook', label: 'Create Webhooks', description: 'Configure outgoing event webhooks', scope: 'project', dangerous: true, planned: true },
  { key: 'webhook.edit', module: 'webhook', label: 'Edit Webhooks', description: 'Modify webhook URLs and event triggers', scope: 'project', dangerous: true, planned: true },
  { key: 'webhook.delete', module: 'webhook', label: 'Delete Webhooks', description: 'Remove webhooks', scope: 'project', dangerous: true, planned: true },

  // --- Integration ---
  { key: 'integration.view', module: 'integration', label: 'View Integrations', description: 'View connected external services', scope: 'company', dangerous: false, planned: true },
  { key: 'integration.manage', module: 'integration', label: 'Manage Integrations', description: 'Connect or disconnect third-party integrations', scope: 'company', dangerous: true, planned: true },

  // --- Import / Export ---
  { key: 'import_export.import', module: 'import_export', label: 'Import Data', description: 'Upload bulk data files into projects', scope: 'project', dangerous: false, planned: true },
  { key: 'import_export.export', module: 'import_export', label: 'Export Data', description: 'Download workspace and project exports', scope: 'project', dangerous: false, planned: true },

  // --- Archive ---
  { key: 'archive.view', module: 'archive', label: 'View Archive', description: 'View archived workspaces, boards, and cards', scope: 'company', dangerous: false },
  { key: 'archive.restore', module: 'archive', label: 'Restore from Archive', description: 'Restore archived resources to active state', scope: 'project', dangerous: false },
  { key: 'archive.permanent_delete', module: 'archive', label: 'Permanent Delete', description: 'Permanently purge archived items from database', scope: 'company', dangerous: true },

  // --- Search ---
  { key: 'search.use', module: 'search', label: 'Search App', description: 'Execute full-text global search', scope: 'company', dangerous: false },

  // --- Billing ---
  { key: 'billing.view', module: 'billing', label: 'View Billing', description: 'View plan and subscription invoices', scope: 'company', dangerous: false, planned: true },
  { key: 'billing.manage', module: 'billing', label: 'Manage Subscriptions', description: 'Upgrade, downgrade, or cancel plans', scope: 'company', dangerous: true, planned: true }
];

/**
 * 8 System Roles (source of truth per Section 4)
 */
const SYSTEM_ROLES = {
  Owner: {
    name: 'Owner',
    aliases: ['Super Admin'],
    rank: 100,
    is_system: 1,
    is_editable: 0,
    description: 'Full administrative control over all company data, members, and billing. Immutable.',
    permissions: PERMISSIONS.map((p) => p.key) // All permissions
  },
  Admin: {
    name: 'Admin',
    aliases: [],
    rank: 80,
    is_system: 1,
    is_editable: 1,
    description: 'Company-wide administrator. All permissions except company deletion, billing, and ownership transfer.',
    permissions: PERMISSIONS.filter(
      (p) => !['workspace.delete', 'company.delete', 'company.export_data', 'billing.manage', 'company.manage_billing'].includes(p.key)
    ).map((p) => p.key)
  },
  'Project Manager': {
    name: 'Project Manager',
    aliases: ['Manager'],
    rank: 60,
    is_system: 1,
    is_editable: 1,
    description: 'Manages projects, tasks, workflows, and team members. Cannot manage company settings or security.',
    permissions: [
      'workspace.view', 'company.view', 'member.view', 'member.invite_guest', 'role.view', 'team.view',
      'project.view', 'project.create', 'project.edit_settings', 'project.archive', 'project.manage_members', 'project.assign_role',
      'project.manage_templates', 'project.change_status', 'project.duplicate', 'project.change_visibility',
      'list.create', 'list.edit', 'list.reorder', 'list.delete',
      'task.view', 'task.create', 'task.edit', 'task.move', 'task.assign', 'task.assign_self', 'task.complete', 'task.delete',
      'task.watch', 'task.set_priority', 'task.bulk_edit', 'task.bulk_delete', 'task.duplicate', 'task.archive', 'task.restore',
      'subtask.create', 'subtask.edit', 'subtask.delete', 'checklist.create', 'checklist.edit', 'checklist.delete',
      'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own', 'comment.delete_any',
      'attachment.view', 'attachment.upload', 'attachment.delete_own', 'attachment.delete_any', 'attachment.version', 'file.view',
      'label.view', 'label.create', 'label.edit', 'label.delete', 'label.delete_own',
      'custom_field.view', 'custom_field.create', 'custom_field.edit', 'custom_field.delete',
      'milestone.view', 'milestone.create', 'milestone.edit', 'milestone.delete',
      'sprint.view', 'sprint.create', 'sprint.edit', 'sprint.start', 'sprint.complete', 'sprint.delete',
      'backlog.view', 'backlog.reorder', 'epic.view', 'epic.create', 'epic.edit', 'epic.delete',
      'time.view_own', 'time.log', 'time.edit_own', 'time.view_all', 'time.approve_timesheet',
      'report.view_project', 'report.view_team', 'report.export', 'dashboard.view_project',
      'view.view', 'view.create', 'view.edit', 'view.delete', 'import_export.import', 'import_export.export',
      'archive.view', 'archive.restore', 'activity.view',
      'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
    ]
  },
  'Team Lead': {
    name: 'Team Lead',
    aliases: ['Lead'],
    rank: 50,
    is_system: 1,
    is_editable: 1,
    description: 'Leads project execution and list management, reviews team progress and assigns tasks.',
    permissions: [
      'workspace.view', 'company.view', 'member.view', 'team.view',
      'project.view', 'list.create', 'list.edit', 'list.reorder',
      'task.view', 'task.create', 'task.edit', 'task.move', 'task.assign', 'task.assign_self', 'task.complete', 'task.delete_own',
      'task.watch', 'task.set_priority', 'task.bulk_edit', 'task.duplicate', 'task.archive', 'task.restore',
      'subtask.create', 'subtask.edit', 'subtask.delete', 'checklist.create', 'checklist.edit', 'checklist.delete',
      'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own', 'comment.delete_any',
      'attachment.view', 'attachment.upload', 'attachment.delete_own', 'attachment.delete_any', 'file.view',
      'label.view', 'label.create', 'label.edit', 'label.delete_own',
      'custom_field.view', 'custom_field.create', 'custom_field.edit', 'milestone.view', 'milestone.create', 'milestone.edit',
      'sprint.view', 'sprint.create', 'sprint.edit', 'sprint.start', 'sprint.complete', 'backlog.view', 'backlog.reorder',
      'epic.view', 'epic.create', 'epic.edit',
      'time.view_own', 'time.log', 'time.edit_own', 'time.view_all',
      'report.view_project', 'report.view_team', 'dashboard.view_project',
      'view.view', 'view.create', 'view.edit', 'view.delete', 'import_export.export',
      'archive.view', 'archive.restore', 'activity.view',
      'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
    ]
  },
  'Team Member': {
    name: 'Team Member',
    aliases: ['Member'],
    rank: 40,
    is_system: 1,
    is_editable: 1,
    description: 'Collaborates on assigned projects, creates and moves tasks, and logs time.',
    permissions: [
      'workspace.view', 'company.view', 'member.view', 'team.view',
      'project.view',
      'task.view', 'task.create', 'task.edit', 'task.move', 'task.assign_self', 'task.complete', 'task.delete_own',
      'task.watch', 'task.set_priority', 'task.duplicate', 'task.archive', 'task.restore',
      'subtask.create', 'subtask.edit', 'subtask.delete', 'checklist.create', 'checklist.edit', 'checklist.delete',
      'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own',
      'attachment.view', 'attachment.upload', 'attachment.delete_own', 'file.view',
      'label.view', 'label.create', 'label.delete_own',
      'custom_field.view', 'milestone.view', 'sprint.view', 'backlog.view', 'epic.view',
      'time.view_own', 'time.log', 'time.edit_own',
      'report.view_project', 'dashboard.view_project',
      'view.view', 'view.create', 'view.edit', 'view.delete',
      'archive.view', 'archive.restore', 'activity.view',
      'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
    ]
  },
  Viewer: {
    name: 'Viewer',
    aliases: [],
    rank: 20,
    is_system: 1,
    is_editable: 1,
    description: 'Read-only access to projects and tasks. Cannot modify or create resources.',
    permissions: [
      'workspace.view', 'company.view', 'member.view', 'team.view',
      'project.view', 'task.view', 'task.watch', 'comment.view', 'attachment.view', 'file.view', 'label.view',
      'custom_field.view', 'milestone.view', 'sprint.view', 'backlog.view', 'epic.view',
      'report.view_project', 'dashboard.view_project', 'view.view', 'activity.view',
      'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
    ]
  },
  Auditor: {
    name: 'Auditor',
    aliases: [],
    rank: 15,
    is_system: 1,
    is_editable: 1,
    description: 'Read-only compliance and auditing role across all workspace projects and reports.',
    permissions: [
      'workspace.view', 'company.view', 'member.view', 'role.view', 'team.view',
      'project.access_all', 'project.view', 'task.view', 'view.view', 'comment.view', 'attachment.view', 'file.view', 'label.view',
      'custom_field.view', 'milestone.view', 'sprint.view', 'backlog.view', 'epic.view',
      'audit.view', 'audit.export', 'archive.view', 'activity.view',
      'report.view_project', 'report.view_team', 'report.view_all', 'report.export',
      'dashboard.view_project', 'dashboard.view_executive', 'time.view_all',
      'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
    ]
  },
  Guest: {
    name: 'Guest',
    aliases: [],
    rank: 10,
    is_system: 1,
    is_editable: 1,
    description: 'Restricted external collaborator. Access only to explicitly shared projects with view and comment rights.',
    permissions: [
      'project.view', 'view.view', 'task.view', 'task.watch',
      'comment.view', 'comment.create', 'comment.edit_own', 'comment.delete_own',
      'attachment.view', 'file.view', 'label.view', 'member.view',
      'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own', 'search.use'
    ]
  }
};

/**
 * Legacy permission key mapping eliminated for Section 7 / Phase E
 */
const LEGACY_PERMISSION_ALIASES = {};

// Reverse map
const REVERSE_ALIASES = {};
for (const [oldKey, newKey] of Object.entries(LEGACY_PERMISSION_ALIASES)) {
  if (!REVERSE_ALIASES[newKey]) REVERSE_ALIASES[newKey] = [];
  REVERSE_ALIASES[newKey].push(oldKey);
}

/**
 * Get equivalent permission keys (including aliases)
 */
function expandPermissionKeys(permissionKey) {
  const keys = new Set([permissionKey]);
  if (LEGACY_PERMISSION_ALIASES[permissionKey]) {
    keys.add(LEGACY_PERMISSION_ALIASES[permissionKey]);
  }
  if (REVERSE_ALIASES[permissionKey]) {
    for (const k of REVERSE_ALIASES[permissionKey]) {
      keys.add(k);
    }
  }
  return Array.from(keys);
}

/**
 * Prerequisite dependency rules for RBAC permissions.
 * Any permission mapping to an array of prerequisite permissions requires those prerequisites
 * to be held in order to be exercised or granted in a custom role.
 */
const PREREQUISITE_PERMISSIONS = {
  // Task operations
  'task.create': ['task.view', 'project.view'],
  'task.edit': ['task.view', 'project.view'],
  'task.move': ['task.view', 'project.view'],
  'task.delete': ['task.view', 'project.view'],
  'task.delete_own': ['task.view', 'project.view'],
  'task.assign': ['task.view', 'project.view'],
  'task.assign_self': ['task.view', 'project.view'],
  'task.complete': ['task.view', 'project.view'],
  'task.duplicate': ['task.create', 'task.view', 'project.view'],
  'task.archive': ['task.view', 'project.view'],
  'task.restore': ['task.view', 'project.view'],
  'task.view': ['project.view'],

  // Checklist operations
  'checklist.create': ['task.view', 'project.view'],
  'checklist.edit': ['task.view', 'project.view'],
  'checklist.delete': ['task.view', 'project.view'],

  // Comment operations
  'comment.view': ['task.view', 'project.view'],
  'comment.create': ['comment.view', 'task.view', 'project.view'],
  'comment.edit_own': ['comment.view', 'task.view', 'project.view'],
  'comment.delete_own': ['comment.view', 'task.view', 'project.view'],
  'comment.delete_any': ['comment.view', 'task.view', 'project.view'],

  // Attachment operations
  'attachment.view': ['task.view', 'project.view'],
  'attachment.upload': ['attachment.view', 'task.view', 'project.view'],
  'attachment.delete_own': ['attachment.view', 'task.view', 'project.view'],
  'attachment.delete_any': ['attachment.view', 'task.view', 'project.view'],

  // File operations
  'file.view': ['project.view'],
  'file.delete': ['file.view', 'project.view'],

  // List operations
  'list.create': ['project.view'],
  'list.edit': ['project.view'],
  'list.reorder': ['project.view'],
  'list.delete': ['project.view'],

  // Label operations
  'label.view': ['project.view'],
  'label.create': ['label.view', 'project.view'],
  'label.edit': ['label.view', 'project.view'],
  'label.delete': ['label.view', 'project.view'],
  'label.delete_own': ['label.view', 'project.view'],

  // Activity
  'activity.view': ['project.view'],

  // Role operations
  'role.view': ['workspace.view'],
  'role.create': ['role.view', 'workspace.view'],
  'role.edit': ['role.view', 'workspace.view'],
  'role.delete': ['role.view', 'workspace.view'],
  'role.assign': ['role.view', 'workspace.view'],

  // Member operations
  'member.view': ['workspace.view'],
  'member.invite': ['member.view', 'workspace.view'],
  'member.invite_guest': ['member.view', 'workspace.view', 'project.manage_members'],
  'member.remove': ['member.view', 'workspace.view'],
  'member.assign_role': ['member.view', 'workspace.view'],
  'member.reset_password': ['member.view', 'workspace.view'],
  'member.reset_2fa': ['member.view', 'workspace.view'],

  // Project operations
  'project.access_all': ['project.view'],
  'project.edit_settings': ['project.view'],
  'project.delete': ['project.view'],
  'project.archive': ['project.view'],
  'project.manage_members': ['project.view'],
  'project.assign_role': ['project.view'],

  // Report operations
  'report.view_project': ['project.view'],

  // Workspace operations
  'workspace.edit': ['workspace.view'],
  'workspace.delete': ['workspace.view'],
  'workspace.archive': ['workspace.view'],

  // Audit
  'audit.view': ['workspace.view'],
  'audit.export': ['audit.view', 'workspace.view'],

  // Archive
  'archive.restore': ['archive.view', 'workspace.view', 'project.view'],
  'archive.permanent_delete': ['archive.view', 'workspace.view', 'project.view']
};

function getPrerequisites(permissionKey) {
  return PREREQUISITE_PERMISSIONS[permissionKey] || [];
}

function getTransitivePrerequisites(permissionKey) {
  const result = new Set();
  const queue = [...(PREREQUISITE_PERMISSIONS[permissionKey] || [])];
  while (queue.length > 0) {
    const item = queue.shift();
    if (!result.has(item)) {
      result.add(item);
      if (PREREQUISITE_PERMISSIONS[item]) {
        queue.push(...PREREQUISITE_PERMISSIONS[item]);
      }
    }
  }
  return Array.from(result);
}

module.exports = {
  PERMISSIONS,
  SYSTEM_ROLES,
  LEGACY_PERMISSION_ALIASES,
  PREREQUISITE_PERMISSIONS,
  expandPermissionKeys,
  getPrerequisites,
  getTransitivePrerequisites
};

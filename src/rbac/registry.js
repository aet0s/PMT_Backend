// server/src/rbac/registry.js
// Single source of truth for all system permissions, roles, and the RBAC matrix.

/**
 * Scope definitions:
 * - 'company': Company/workspace wide capability
 * - 'project': Project/board scoped capability
 */

const PERMISSIONS = [
  // --- Company ---
  { key: 'company.view', module: 'company', label: 'View Company Info', description: 'View company profile and details', scope: 'company', dangerous: false },
  { key: 'company.edit_settings', module: 'company', label: 'Edit Company Settings', description: 'Modify company preferences and profile', scope: 'company', dangerous: true },
  { key: 'company.manage_security', module: 'company', label: 'Manage Security Policies', description: 'Configure 2FA requirements and authentication policies', scope: 'company', dangerous: true },
  { key: 'company.manage_billing', module: 'company', label: 'Manage Billing', description: 'Access and modify subscriptions and billing', scope: 'company', dangerous: true },
  { key: 'company.delete', module: 'company', label: 'Delete Company', description: 'Permanently delete company and all tenant databases', scope: 'company', dangerous: true },
  { key: 'company.export_data', module: 'company', label: 'Export Company Data', description: 'Generate and download full tenant database export', scope: 'company', dangerous: true },

  // --- Workspace ---
  { key: 'workspace.view', module: 'workspace', label: 'View Workspace', description: 'View workspace information and dashboard', scope: 'company', dangerous: false },
  { key: 'workspace.create', module: 'workspace', label: 'Create Workspace', description: 'Create new workspaces', scope: 'company', dangerous: false },
  { key: 'workspace.edit', module: 'workspace', label: 'Edit Workspace', description: 'Edit workspace name and settings', scope: 'company', dangerous: false },
  { key: 'workspace.delete', module: 'workspace', label: 'Delete Workspace', description: 'Delete entire workspace and all child boards', scope: 'company', dangerous: true },
  { key: 'workspace.archive', module: 'workspace', label: 'Archive Workspace', description: 'Archive or restore workspaces', scope: 'company', dangerous: false },

  // --- Team ---
  { key: 'team.view', module: 'team', label: 'View Teams', description: 'View teams and department memberships', scope: 'company', dangerous: false },
  { key: 'team.create', module: 'team', label: 'Create Team', description: 'Create departments and teams', scope: 'company', dangerous: false },
  { key: 'team.edit', module: 'team', label: 'Edit Team', description: 'Modify team details', scope: 'company', dangerous: false },
  { key: 'team.delete', module: 'team', label: 'Delete Team', description: 'Delete teams', scope: 'company', dangerous: true },
  { key: 'team.manage_members', module: 'team', label: 'Manage Team Members', description: 'Assign or remove members from teams', scope: 'company', dangerous: false },

  // --- Member ---
  { key: 'member.view', module: 'member', label: 'View Members', description: 'View workspace member directory', scope: 'company', dangerous: false },
  { key: 'member.invite', module: 'member', label: 'Invite Members', description: 'Generate and send invitation links', scope: 'company', dangerous: false },
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
  { key: 'role.assign', module: 'role', label: 'Assign Roles to Users', description: 'Assign roles to workspace members', scope: 'company', dangerous: true },

  // --- Project (Boards) ---
  { key: 'project.view', module: 'project', label: 'View Project', description: 'Access and view project boards', scope: 'project', dangerous: false },
  { key: 'project.create', module: 'project', label: 'Create Project', description: 'Create new project boards', scope: 'company', dangerous: false },
  { key: 'project.edit_settings', module: 'project', label: 'Edit Project Settings', description: 'Rename, recolor, and configure board settings', scope: 'project', dangerous: false },
  { key: 'project.delete', module: 'project', label: 'Delete Project', description: 'Permanently delete project board', scope: 'project', dangerous: true },
  { key: 'project.archive', module: 'project', label: 'Archive Project', description: 'Archive or restore project boards', scope: 'project', dangerous: false },
  { key: 'project.manage_members', module: 'project', label: 'Manage Project Members', description: 'Add or remove members from specific projects', scope: 'project', dangerous: false },
  { key: 'project.manage_templates', module: 'project', label: 'Manage Templates', description: 'Save or apply board templates', scope: 'project', dangerous: false },
  { key: 'project.change_status', module: 'project', label: 'Change Project Status', description: 'Update project health and lifecycle status', scope: 'project', dangerous: false },
  { key: 'project.view_dashboard', module: 'project', label: 'View Project Dashboard', description: 'View analytics and burndown metrics', scope: 'project', dangerous: false },

  // --- View ---
  { key: 'view.view', module: 'view', label: 'View Saved Views', description: 'Access Kanban, list, and table views', scope: 'project', dangerous: false },
  { key: 'view.create', module: 'view', label: 'Create Saved Views', description: 'Save custom filtered views', scope: 'project', dangerous: false },
  { key: 'view.edit', module: 'view', label: 'Edit Saved Views', description: 'Modify saved views', scope: 'project', dangerous: false },
  { key: 'view.delete', module: 'view', label: 'Delete Saved Views', description: 'Delete saved views', scope: 'project', dangerous: false },

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
  { key: 'task.delete', module: 'task', label: 'Delete Tasks', description: 'Permanently remove cards', scope: 'project', dangerous: true },
  { key: 'task.assign', module: 'task', label: 'Assign Tasks', description: 'Assign or unassign members on cards', scope: 'project', dangerous: false },
  { key: 'task.watch', module: 'task', label: 'Watch Tasks', description: 'Subscribe to card notifications', scope: 'project', dangerous: false },
  { key: 'task.set_priority', module: 'task', label: 'Set Priority', description: 'Change task priority level', scope: 'project', dangerous: false },
  { key: 'task.bulk_edit', module: 'task', label: 'Bulk Edit Tasks', description: 'Batch update multiple cards', scope: 'project', dangerous: false },
  { key: 'task.bulk_delete', module: 'task', label: 'Bulk Delete Tasks', description: 'Batch delete multiple cards', scope: 'project', dangerous: true },
  { key: 'task.import', module: 'task', label: 'Import Tasks', description: 'Import tasks from CSV/Excel', scope: 'project', dangerous: false },
  { key: 'task.export', module: 'task', label: 'Export Tasks', description: 'Export tasks to CSV/Excel', scope: 'project', dangerous: false },
  { key: 'task.duplicate', module: 'task', label: 'Duplicate Tasks', description: 'Clone card with checklist and labels', scope: 'project', dangerous: false },
  { key: 'task.archive', module: 'task', label: 'Archive Tasks', description: 'Archive cards without deleting', scope: 'project', dangerous: false },
  { key: 'task.restore', module: 'task', label: 'Restore Tasks', description: 'Restore archived cards', scope: 'project', dangerous: false },

  // --- Subtask ---
  { key: 'subtask.create', module: 'subtask', label: 'Create Subtasks', description: 'Add subtasks to cards', scope: 'project', dangerous: false },
  { key: 'subtask.edit', module: 'subtask', label: 'Edit Subtasks', description: 'Update and complete subtasks', scope: 'project', dangerous: false },
  { key: 'subtask.delete', module: 'subtask', label: 'Delete Subtasks', description: 'Delete subtasks from cards', scope: 'project', dangerous: false },

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
  { key: 'attachment.version', module: 'attachment', label: 'Manage Versions', description: 'Upload and restore attachment versions', scope: 'project', dangerous: false },

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

  // --- Custom Field ---
  { key: 'custom_field.view', module: 'custom_field', label: 'View Custom Fields', description: 'View custom attributes on cards', scope: 'project', dangerous: false },
  { key: 'custom_field.create', module: 'custom_field', label: 'Create Custom Fields', description: 'Define new custom field schemas', scope: 'project', dangerous: false },
  { key: 'custom_field.edit', module: 'custom_field', label: 'Edit Custom Fields', description: 'Edit custom field values and definitions', scope: 'project', dangerous: false },
  { key: 'custom_field.delete', module: 'custom_field', label: 'Delete Custom Fields', description: 'Delete custom fields', scope: 'project', dangerous: true },

  // --- Milestone ---
  { key: 'milestone.view', module: 'milestone', label: 'View Milestones', description: 'View milestones and target dates', scope: 'project', dangerous: false },
  { key: 'milestone.create', module: 'milestone', label: 'Create Milestones', description: 'Create project milestones', scope: 'project', dangerous: false },
  { key: 'milestone.edit', module: 'milestone', label: 'Edit Milestones', description: 'Update milestone progress', scope: 'project', dangerous: false },
  { key: 'milestone.delete', module: 'milestone', label: 'Delete Milestones', description: 'Remove milestones', scope: 'project', dangerous: false },

  // --- Sprint ---
  { key: 'sprint.view', module: 'sprint', label: 'View Sprints', description: 'View sprints and burndown charts', scope: 'project', dangerous: false },
  { key: 'sprint.create', module: 'sprint', label: 'Create Sprints', description: 'Create new sprint iterations', scope: 'project', dangerous: false },
  { key: 'sprint.edit', module: 'sprint', label: 'Edit Sprints', description: 'Update sprint goals and duration', scope: 'project', dangerous: false },
  { key: 'sprint.start', module: 'sprint', label: 'Start Sprints', description: 'Activate planning sprint', scope: 'project', dangerous: false },
  { key: 'sprint.complete', module: 'sprint', label: 'Complete Sprints', description: 'Close active sprint and carry over tasks', scope: 'project', dangerous: false },
  { key: 'sprint.delete', module: 'sprint', label: 'Delete Sprints', description: 'Delete sprints', scope: 'project', dangerous: true },

  // --- Backlog ---
  { key: 'backlog.view', module: 'backlog', label: 'View Backlog', description: 'View unassigned backlog tasks', scope: 'project', dangerous: false },
  { key: 'backlog.reorder', module: 'backlog', label: 'Reorder Backlog', description: 'Prioritize backlog items', scope: 'project', dangerous: false },

  // --- Epic ---
  { key: 'epic.view', module: 'epic', label: 'View Epics', description: 'View epic groupings and roll-up metrics', scope: 'project', dangerous: false },
  { key: 'epic.create', module: 'epic', label: 'Create Epics', description: 'Create high-level epics', scope: 'project', dangerous: false },
  { key: 'epic.edit', module: 'epic', label: 'Edit Epics', description: 'Modify epics', scope: 'project', dangerous: false },
  { key: 'epic.delete', module: 'epic', label: 'Delete Epics', description: 'Delete epics', scope: 'project', dangerous: false },

  // --- Time ---
  { key: 'time.view_own', module: 'time', label: 'View Own Time', description: 'View personal logged time entries', scope: 'project', dangerous: false },
  { key: 'time.log', module: 'time', label: 'Log Time', description: 'Start timer or enter time spent on tasks', scope: 'project', dangerous: false },
  { key: 'time.edit_own', module: 'time', label: 'Edit Own Time', description: 'Edit personal time log entries', scope: 'project', dangerous: false },
  { key: 'time.view_all', module: 'time', label: 'View All Time', description: 'View team timesheets and logged hours', scope: 'project', dangerous: false },
  { key: 'time.edit_all', module: 'time', label: 'Edit All Time', description: 'Adjust logged hours for team members', scope: 'project', dangerous: true },
  { key: 'time.approve_timesheet', module: 'time', label: 'Approve Timesheets', description: 'Approve or reject weekly timesheet submissions', scope: 'company', dangerous: true },

  // --- Report ---
  { key: 'report.view_project', module: 'report', label: 'View Project Reports', description: 'View task velocity and project progress', scope: 'project', dangerous: false },
  { key: 'report.view_team', module: 'report', label: 'View Team Reports', description: 'View team workload and allocations', scope: 'company', dangerous: false },
  { key: 'report.view_all', module: 'report', label: 'View All Reports', description: 'Access cross-project organization reports', scope: 'company', dangerous: false },
  { key: 'report.export', module: 'report', label: 'Export Reports', description: 'Download PDF and CSV reports', scope: 'company', dangerous: false },
  { key: 'report.create_custom', module: 'report', label: 'Create Custom Reports', description: 'Build and save custom report configurations', scope: 'company', dangerous: false },

  // --- Dashboard ---
  { key: 'dashboard.view_project', module: 'dashboard', label: 'View Project Dashboard', description: 'View project KPIs and task status overview', scope: 'project', dangerous: false },
  { key: 'dashboard.view_executive', module: 'dashboard', label: 'View Executive Dashboard', description: 'View organization-wide health roll-up', scope: 'company', dangerous: false },

  // --- Notification ---
  { key: 'notification.view_own', module: 'notification', label: 'View Notifications', description: 'Read in-app notifications', scope: 'company', dangerous: false },
  { key: 'notification.manage_own', module: 'notification', label: 'Manage Notifications', description: 'Configure personal alert preferences', scope: 'company', dangerous: false },

  // --- Audit ---
  { key: 'audit.view', module: 'audit', label: 'View Audit Log', description: 'Inspect security and data mutation logs', scope: 'company', dangerous: true },
  { key: 'audit.export', module: 'audit', label: 'Export Audit Log', description: 'Download CSV of compliance audit logs', scope: 'company', dangerous: true },

  // --- Activity ---
  { key: 'activity.view', module: 'activity', label: 'View Activity Feed', description: 'View card and board event stream', scope: 'project', dangerous: false },

  // --- API Key ---
  { key: 'api_key.view', module: 'api_key', label: 'View API Keys', description: 'List created developer API keys', scope: 'company', dangerous: false },
  { key: 'api_key.create', module: 'api_key', label: 'Create API Keys', description: 'Generate API tokens with scoped permissions', scope: 'company', dangerous: true },
  { key: 'api_key.revoke', module: 'api_key', label: 'Revoke API Keys', description: 'Invalidate API tokens', scope: 'company', dangerous: true },

  // --- Webhook ---
  { key: 'webhook.view', module: 'webhook', label: 'View Webhooks', description: 'Inspect outgoing webhook endpoints', scope: 'project', dangerous: false },
  { key: 'webhook.create', module: 'webhook', label: 'Create Webhooks', description: 'Configure outgoing event webhooks', scope: 'project', dangerous: true },
  { key: 'webhook.edit', module: 'webhook', label: 'Edit Webhooks', description: 'Modify webhook URLs and event triggers', scope: 'project', dangerous: true },
  { key: 'webhook.delete', module: 'webhook', label: 'Delete Webhooks', description: 'Remove webhooks', scope: 'project', dangerous: true },

  // --- Integration ---
  { key: 'integration.view', module: 'integration', label: 'View Integrations', description: 'View connected external services', scope: 'company', dangerous: false },
  { key: 'integration.manage', module: 'integration', label: 'Manage Integrations', description: 'Connect or disconnect third-party integrations', scope: 'company', dangerous: true },

  // --- Import / Export ---
  { key: 'import_export.import', module: 'import_export', label: 'Import Data', description: 'Upload bulk data files into projects', scope: 'project', dangerous: false },
  { key: 'import_export.export', module: 'import_export', label: 'Export Data', description: 'Download workspace and project exports', scope: 'project', dangerous: false },

  // --- Archive ---
  { key: 'archive.view', module: 'archive', label: 'View Archive', description: 'View archived workspaces, boards, and cards', scope: 'company', dangerous: false },
  { key: 'archive.restore', module: 'archive', label: 'Restore from Archive', description: 'Restore archived resources to active state', scope: 'company', dangerous: false },
  { key: 'archive.permanent_delete', module: 'archive', label: 'Permanent Delete', description: 'Permanently purge archived items from database', scope: 'company', dangerous: true },

  // --- Search ---
  { key: 'search.use', module: 'search', label: 'Search App', description: 'Execute full-text global search', scope: 'company', dangerous: false },

  // --- Billing ---
  { key: 'billing.view', module: 'billing', label: 'View Billing', description: 'View plan and subscription invoices', scope: 'company', dangerous: false },
  { key: 'billing.manage', module: 'billing', label: 'Manage Subscriptions', description: 'Upgrade, downgrade, or cancel plans', scope: 'company', dangerous: true }
];

/**
 * Legacy permission key mapping for 100% backward compatibility
 */
const LEGACY_PERMISSION_ALIASES = {
  'workspace.edit_settings': 'workspace.edit',
  'workspace.view_billing': 'billing.view',
  'workspace.manage_roles': 'role.create',
  'board.create': 'project.create',
  'board.edit_settings': 'project.edit_settings',
  'board.delete': 'project.delete',
  'board.manage_members': 'project.manage_members',
  'card.create': 'task.create',
  'card.edit': 'task.edit',
  'card.delete': 'task.delete',
  'card.move': 'task.move',
  'card.comment': 'comment.create',
  'card.manage_attachments': 'attachment.upload',
  'card.assign_members': 'task.assign',
  'member.view_all': 'member.view',
  'workspace.invite_members': 'member.invite',
  'workspace.manage_members': 'member.assign_role'
};

// Reverse map
const REVERSE_ALIASES = {};
for (const [oldKey, newKey] of Object.entries(LEGACY_PERMISSION_ALIASES)) {
  if (!REVERSE_ALIASES[newKey]) REVERSE_ALIASES[newKey] = [];
  REVERSE_ALIASES[newKey].push(oldKey);
}

/**
 * 6 System Roles (seeded per tenant, is_system = 1)
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
      (p) => !['company.delete', 'company.manage_billing', 'billing.manage'].includes(p.key)
    ).map((p) => p.key)
  },
  'Project Manager': {
    name: 'Project Manager',
    aliases: ['Manager'],
    rank: 60,
    is_system: 1,
    is_editable: 1,
    description: 'Manages projects, tasks, workflows, and team members. Cannot manage company settings or security.',
    permissions: PERMISSIONS.filter((p) => {
      const pmModules = [
        'project', 'view', 'list', 'task', 'subtask', 'checklist', 'comment',
        'attachment', 'file', 'session', 'label', 'custom_field', 'milestone',
        'sprint', 'backlog', 'epic', 'time', 'report', 'dashboard', 'notification',
        'activity', 'webhook', 'import_export', 'archive', 'search'
      ];
      if (pmModules.includes(p.module)) return true;
      if (['member.invite', 'member.view', 'team.view'].includes(p.key)) return true;
      return false;
    }).map((p) => p.key)
  },
  'Team Member': {
    name: 'Team Member',
    aliases: ['Member'],
    rank: 40,
    is_system: 1,
    is_editable: 1,
    description: 'Collaborates on assigned projects, creates and moves tasks, and logs time.',
    permissions: [
      'project.view',
      'view.view',
      'list.create',
      'task.view',
      'task.create',
      'task.edit',
      'task.move',
      'task.assign',
      'task.watch',
      'subtask.create',
      'subtask.edit',
      'checklist.create',
      'checklist.edit',
      'comment.view',
      'comment.create',
      'comment.edit_own',
      'comment.delete_own',
      'attachment.view',
      'attachment.upload',
      'attachment.delete_own',
      'file.view',
      'session.view_own',
      'session.revoke_own',
      'label.view',
      'label.create',
      'custom_field.view',
      'milestone.view',
      'sprint.view',
      'backlog.view',
      'epic.view',
      'time.view_own',
      'time.log',
      'time.edit_own',
      'report.view_project',
      'dashboard.view_project',
      'notification.view_own',
      'notification.manage_own',
      'activity.view',
      'search.use'
    ]
  },
  Viewer: {
    name: 'Viewer',
    aliases: [],
    rank: 20,
    is_system: 1,
    is_editable: 1,
    description: 'Read-only access to projects and tasks. Cannot modify or create resources.',
    permissions: PERMISSIONS.filter(
      (p) => p.key.endsWith('.view') || ['search.use', 'notification.view_own', 'notification.manage_own', 'session.view_own', 'session.revoke_own'].includes(p.key)
    ).map((p) => p.key)
  },
  Guest: {
    name: 'Guest',
    aliases: [],
    rank: 10,
    is_system: 1,
    is_editable: 1,
    description: 'Restricted external collaborator. Access only to explicitly shared projects with view and comment rights.',
    permissions: [
      'project.view',
      'view.view',
      'task.view',
      'comment.view',
      'comment.create',
      'attachment.view',
      'file.view',
      'notification.view_own',
      'notification.manage_own',
      'session.view_own',
      'session.revoke_own',
      'search.use'
    ]
  }
};

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

module.exports = {
  PERMISSIONS,
  SYSTEM_ROLES,
  LEGACY_PERMISSION_ALIASES,
  expandPermissionKeys
};

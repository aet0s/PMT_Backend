# Permission Enforcement Map

This document maps all 140 permissions defined in the system registry (`server/src/rbac/registry.js`) to their active enforcement points (Express routes, operations, socket events, UI controls) or classifies their un-enforced status.

---

## 1. Classification Summary

- **Total Registry Permissions**: 140
- **Currently Enforced**: 31
- **Category (a) - Belongs to Existing Feature (Must Be Enforced Now)**: 28
- **Category (b) - Planned Feature (Not Built Yet / Roadmap)**: 81

---

## 2. Active & Category (a) Enforced Permissions (Existing Features)

| Permission Key | Module | Scope | Enforcement Point(s) (Route / Operation / UI) | Classification |
|---|---|---|---|---|
| `workspace.view` | `workspace` | company | `GET /api/workspaces`, `GET /api/workspaces/:id`, Workspace dropdown | Currently Enforced |
| `workspace.create` | `workspace` | company | `POST /api/workspaces`, "Create Workspace" modal | Currently Enforced |
| `workspace.edit` | `workspace` | company | `PATCH /api/workspaces/:id`, Workspace Settings Tab | Currently Enforced |
| `workspace.delete` | `workspace` | company | `DELETE /api/workspaces/:id`, Danger Zone delete button | Currently Enforced |
| `workspace.archive` | `workspace` | company | `PATCH /api/workspaces/:id` (`is_archived: true`), Workspace archive toggle | Category (a) |
| `member.view` | `member` | company | `GET /api/workspaces/:id/members`, MembersTab directory | Currently Enforced |
| `member.invite` | `member` | company | `POST /api/workspaces/:id/members`, `POST /api/invitations`, Invite modal | Currently Enforced |
| `member.remove` | `member` | company | `DELETE /api/workspaces/:id/members/:userId`, Remove member button | Currently Enforced |
| `member.assign_role` | `member` | company | `PATCH /api/workspaces/:id/members/:userId/role`, Role select in MembersTab | Category (a) |
| `member.reset_password` | `member` | company | `POST /api/workspaces/:id/members/:userId/reset-password`, Reset password modal | Currently Enforced |
| `member.reset_2fa` | `member` | company | `POST /api/workspaces/:id/members/:userId/reset-2fa`, Reset 2FA action | Currently Enforced |
| `role.view` | `role` | company | `GET /api/workspaces/:id/roles`, RolesTab catalog | Currently Enforced |
| `role.create` | `role` | company | `POST /api/workspaces/:id/roles`, "Create Custom Role" modal | Currently Enforced |
| `role.edit` | `role` | company | `PATCH /api/workspaces/:id/roles/:roleId`, Role permission matrix editor | Category (a) |
| `role.delete` | `role` | company | `DELETE /api/workspaces/:id/roles/:roleId`, Delete role button | Category (a) |
| `role.assign` | `role` | company | `PATCH /api/workspaces/:id/members/:userId/role`, Role assignment handler | Category (a) |
| `project.view` | `project` | project | `GET /api/boards/:id`, Board view page, Board cards | Currently Enforced |
| `project.create` | `project` | company | `POST /api/boards`, "Create Board" modal & header | Currently Enforced |
| `project.edit_settings` | `project` | project | `PATCH /api/boards/:id` (name/background), Board settings menu | Currently Enforced |
| `project.delete` | `project` | project | `DELETE /api/boards/:id`, Board delete menu item | Currently Enforced |
| `project.archive` | `project` | project | `PATCH /api/boards/:id` (`is_archived`), Board archive action | Category (a) |
| `project.manage_members` | `project` | project | `POST /api/boards/:id/members`, `DELETE /api/boards/:id/members/:userId` | Currently Enforced |
| `list.create` | `list` | project | `POST /api/lists`, "Add another list" input button | Currently Enforced |
| `list.edit` | `list` | project | `PATCH /api/lists/:id` (name/is_archived), List header rename | Currently Enforced |
| `list.reorder` | `list` | project | `PATCH /api/lists/:id` (position), List drag & drop | Category (a) |
| `list.delete` | `list` | project | `DELETE /api/lists/:id`, List menu "Delete list" | Currently Enforced |
| `task.view` | `task` | project | `GET /api/cards/:id`, CardDetailModal view | Currently Enforced |
| `task.create` | `task` | project | `POST /api/cards`, "Add a card" composer | Currently Enforced |
| `task.edit` | `task` | project | `PATCH /api/cards/:id` (title, description, dates, complete, cover) | Currently Enforced |
| `task.move` | `task` | project | `PATCH /api/cards/:id` (list_id, position), Card drag & drop | Category (a) |
| `task.delete` | `task` | project | `DELETE /api/cards/:id`, Card modal "Delete card" | Currently Enforced |
| `task.assign` | `task` | project | `POST /api/cards/:id/members`, Assignee popover | Category (a) |
| `task.duplicate` | `task` | project | `POST /api/cards/:id/copy`, Card modal "Copy card" action | Category (a) |
| `task.archive` | `task` | project | `PATCH /api/cards/:id` (`is_archived: true`), Card archive action | Category (a) |
| `task.restore` | `task` | project | `PATCH /api/cards/:id` (`is_archived: false`), Card restore action | Category (a) |
| `checklist.create` | `checklist` | project | `POST /api/cards/:id/checklists`, "Add Checklist" modal | Category (a) |
| `checklist.edit` | `checklist` | project | `PATCH /api/cards/checklist-items/:id`, Toggle & rename checklist items | Category (a) |
| `checklist.delete` | `checklist` | project | `DELETE /api/cards/checklists/:id`, Delete checklist button | Category (a) |
| `comment.view` | `comment` | project | `GET /api/cards/:id/comments`, Card activity stream comments | Category (a) |
| `comment.create` | `comment` | project | `POST /api/cards/:id/comments`, Comment composer input | Currently Enforced |
| `comment.edit_own` | `comment` | project | `PATCH /api/cards/comments/:id`, Edit own comment action | Category (a) |
| `comment.delete_own` | `comment` | project | `DELETE /api/cards/comments/:id` (author match), Delete own comment | Category (a) |
| `comment.delete_any` | `comment` | project | `DELETE /api/cards/comments/:id` (moderator), Delete any comment | Category (a) |
| `attachment.view` | `attachment` | project | `GET /api/attachments/:id`, Attachment preview thumbnail | Category (a) |
| `attachment.upload` | `attachment` | project | `POST /api/cards/:id/attachments`, File/link upload dialog | Currently Enforced |
| `attachment.delete_own` | `attachment` | project | `DELETE /api/cards/attachments/:id` (uploader match), Delete own file | Category (a) |
| `attachment.delete_any` | `attachment` | project | `DELETE /api/cards/attachments/:id` (moderator), Delete any file | Category (a) |
| `file.view` | `file` | project | `GET /api/attachments/download/:id`, File download stream | Category (a) |
| `file.delete` | `file` | project | `DELETE /api/attachments/:id`, Physical file deletion | Category (a) |
| `session.view_own` | `session` | company | `GET /api/auth/sessions`, Active sessions list in settings | Currently Enforced |
| `session.revoke_own` | `session` | company | `DELETE /api/auth/sessions/:id` (own session), Log out session | Currently Enforced |
| `session.revoke_others`| `session` | company | `DELETE /api/auth/sessions/:id` (other user session), Admin revoke | Category (a) |
| `label.view` | `label` | project | `GET /api/boards/:id/labels`, Label picker popover | Category (a) |
| `label.create` | `label` | project | `POST /api/boards/:id/labels`, "Create a new label" modal | Category (a) |
| `label.edit` | `label` | project | `PATCH /api/boards/labels/:id`, Edit label color & text | Category (a) |
| `label.delete` | `label` | project | `DELETE /api/boards/labels/:id`, Delete label button | Category (a) |
| `activity.view` | `activity` | project | `GET /api/boards/:id/activity`, Board sidebar activity log | Category (a) |
| `audit.view` | `audit` | company | `GET /api/workspaces/:id/audit-logs`, Workspace Security Audit Tab | Currently Enforced |
| `audit.export` | `audit` | company | `GET /api/workspaces/:id/audit-logs/export`, Export Audit CSV button | Category (a) |
| `notification.view_own`| `notification` | company | `GET /api/notifications`, Notification dropdown & list | Currently Enforced |
| `notification.manage_own`| `notification` | company | `PATCH /api/notifications/preferences`, Preferences toggles | Currently Enforced |
| `archive.view` | `archive` | company | `GET /api/workspaces/:id/archived`, Workspace archive drawer | Category (a) |
| `archive.restore` | `archive` | company | `POST /api/boards/:id/restore`, `PATCH /api/cards/:id` (`is_archived: false`) | Category (a) |
| `archive.permanent_delete`| `archive`| company | `DELETE /api/boards/:id`, `DELETE /api/cards/:id` | Category (a) |
| `search.use` | `search` | company | `GET /api/search`, Global search bar and results | Category (a) |

---

## 3. Category (b) Planned Permissions (Roadmap / Unbuilt Modules)

The following 75 permissions are part of forward-looking product architecture but have no active API endpoints or database entities. In accordance with M-1 item 3, these are marked `planned: true` in the registry and excluded from active custom role creation until their respective modules are released.

| Module | Planned Permissions | Roadmap Milestones |
|---|---|---|
| `company` | `company.view`, `company.edit_settings`, `company.manage_security`, `company.manage_billing`, `company.delete`, `company.export_data` | Multi-Tenant Enterprise Tier |
| `team` | `team.view`, `team.create`, `team.edit`, `team.delete`, `team.manage_members` | Department & Team Spaces |
| `custom_field` | `custom_field.view`, `custom_field.create`, `custom_field.edit`, `custom_field.delete` | Custom Metadata Attributes |
| `milestone` | `milestone.view`, `milestone.create`, `milestone.edit`, `milestone.delete` | Gantt & Timeline Engine |
| `sprint` | `sprint.view`, `sprint.create`, `sprint.edit`, `sprint.start`, `sprint.complete`, `sprint.delete` | Agile & Scrum Boards |
| `backlog` | `backlog.view`, `backlog.reorder` | Product Backlog Prioritizer |
| `epic` | `epic.view`, `epic.create`, `epic.edit`, `epic.delete` | Epic & Portfolio Roll-ups |
| `time` | `time.view_own`, `time.log`, `time.edit_own`, `time.view_all`, `time.edit_all`, `time.approve_timesheet` | Time Tracking & Timesheets |
| `report` | `report.view_project`, `report.view_team`, `report.view_all`, `report.export`, `report.create_custom` | BI Analytics & Reporting |
| `dashboard` | `dashboard.view_project`, `dashboard.view_executive` | Executive Roll-up Dashboards |
| `api_key` | `api_key.view`, `api_key.create`, `api_key.revoke` | Developer REST API Tokens |
| `webhook` | `webhook.view`, `webhook.create`, `webhook.edit`, `webhook.delete` | Event Webhooks |
| `integration` | `integration.view`, `integration.manage` | Third-Party App Marketplace |
| `import_export` | `import_export.import`, `import_export.export` | Bulk CSV/Jira Importer |
| `billing` | `billing.view`, `billing.manage` | Stripe Billing Integration |
| `view` | `view.view`, `view.create`, `view.edit`, `view.delete` | Saved Custom Filters & Views |
| `subtask` | `subtask.create`, `subtask.edit`, `subtask.delete` | Hierarchical Subtasks |
| `task (advanced)` | `task.bulk_edit`, `task.bulk_delete`, `task.import`, `task.export`, `task.set_priority`, `task.watch` | Batch Card Management |
| `project (advanced)`| `project.manage_templates`, `project.change_status`, `project.view_dashboard` | Project Portfolio Management |
| `member (advanced)` | `member.deactivate` | Temporary User Deactivation |
| `attachment (adv.)` | `attachment.version` | File Version Control |

---

## 4. Enforcement Dependency Rules

When configuring custom roles or testing operation authorization, permissions cascade along prerequisite dependencies:

1. **Task Operations**:
   - `task.create`, `task.edit`, `task.move`, `task.delete`, `task.assign`, `task.duplicate`, `task.archive`, `task.restore` **require** `task.view` and `project.view`.
2. **Checklist Operations**:
   - `checklist.create`, `checklist.edit`, `checklist.delete` **require** `task.view` and `project.view`.
3. **Comment Operations**:
   - `comment.create`, `comment.edit_own`, `comment.delete_own`, `comment.delete_any` **require** `comment.view`, `task.view`, and `project.view`.
4. **Attachment Operations**:
   - `attachment.upload`, `attachment.delete_own`, `attachment.delete_any` **require** `attachment.view`, `task.view`, and `project.view`.
5. **List Operations**:
   - `list.create`, `list.edit`, `list.reorder`, `list.delete` **require** `project.view`.
6. **Role Operations**:
   - `role.create`, `role.edit`, `role.delete`, `role.assign` **require** `role.view` and `workspace.view`.
7. **Member Operations**:
   - `member.invite`, `member.remove`, `member.assign_role`, `member.reset_password`, `member.reset_2fa` **require** `member.view` and `workspace.view`.

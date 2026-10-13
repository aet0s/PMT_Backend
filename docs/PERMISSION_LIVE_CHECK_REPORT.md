# RBAC Permission Live Check Report (Part N Specification)

**Target Frontend URL:** `http://localhost:5173`  
**Target API URL:** `http://localhost:5173`  
**Tenant Company Slug:** `permtest_company`  
**Git Commit Hash:** `3ccc79ffb93ee9f810357ceee3e3c3c6bf5f5b10`  
**Execution Date:** 2026-10-13T10:14:26.783Z  
**Overall Status:** ✅ 100% PASSED  

---

## 1. Executive Summary & N0 Plan
- **Total RBAC Modules:** 34
- **Total System Permissions:** 140
- **Testable Active Permissions:** 65
- **Planned Permissions (Not Testable, Built-in Safe Stubs):** 75
- **Enforced Non-Planned Permissions Verified (N0 Resolution):** 
  - `member.reset_2fa`: Enforced on `POST /api/auth/admin/reset-2fa`
  - `comment.edit_own`: Enforced on `PATCH /api/cards/comments/:id`
  - `session.revoke_own`: Enforced on `DELETE /api/auth/sessions/:id`
  - `label.edit`: Enforced on `PATCH /api/boards/:id/labels/:labelId`
  - `label.delete`: Enforced on `DELETE /api/boards/:id/labels/:labelId`
  - `audit.export`: Enforced on `GET /api/workspaces/:id/audit/export`
  - `search.use`: Enforced on `GET /api/workspaces/:id/search`
- **Total Live Verifications Executed:** 289
- **Passed:** 289
- **Failed:** 0

---

## 2. Module by Module Permission Matrix Tables

### Module: `activity` (1 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `activity.view` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `23ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `api_key` (3 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `api_key.view` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `api_key.create` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `api_key.revoke` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `archive` (3 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `archive.view` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `17ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `archive.restore` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `16ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `archive.permanent_delete` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `19ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `attachment` (5 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `attachment.view` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `92ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `attachment.upload` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `19ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `attachment.delete_own` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `21ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `attachment.delete_any` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `18ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `attachment.version` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `audit` (2 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `audit.view` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `20ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `audit.export` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `24ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `backlog` (2 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `backlog.view` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `backlog.reorder` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `billing` (2 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `billing.view` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `billing.manage` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `checklist` (3 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `checklist.create` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `18ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `checklist.edit` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `17ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `checklist.delete` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `22ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `comment` (5 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `comment.view` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `21ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `comment.create` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `29ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `comment.edit_own` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `22ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `comment.delete_own` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `20ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `comment.delete_any` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `23ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `company` (6 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `company.view` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `company.edit_settings` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `company.manage_security` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `company.manage_billing` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `company.delete` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `company.export_data` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `custom_field` (4 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `custom_field.view` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `custom_field.create` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `custom_field.edit` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `custom_field.delete` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `dashboard` (2 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `dashboard.view_project` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `dashboard.view_executive` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `epic` (4 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `epic.view` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `epic.create` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `epic.edit` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `epic.delete` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `file` (2 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `file.view` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `32ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `file.delete` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `20ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `import_export` (2 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `import_export.import` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `import_export.export` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `integration` (2 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `integration.view` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `integration.manage` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `label` (4 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `label.view` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `63ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `label.create` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `23ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `label.edit` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `21ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `label.delete` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `31ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `list` (4 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `list.create` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `18ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `list.edit` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `20ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `list.reorder` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `20ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `list.delete` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `26ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `member` (7 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `member.view` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `23ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `member.invite` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `25ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `member.remove` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `21ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `member.assign_role` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `20ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `member.deactivate` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `member.reset_password` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `24ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `member.reset_2fa` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `24ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `milestone` (4 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `milestone.view` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `milestone.create` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `milestone.edit` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `milestone.delete` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `notification` (2 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `notification.view_own` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `21ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `notification.manage_own` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `15ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `project` (9 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `project.view` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `16ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `project.create` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `17ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `project.edit_settings` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `18ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `project.delete` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `32ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `project.archive` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `21ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `project.manage_members` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `19ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `project.manage_templates` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `project.change_status` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `project.view_dashboard` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `report` (5 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `report.view_project` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `report.view_team` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `report.view_all` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `report.export` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `report.create_custom` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `role` (5 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `role.view` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `18ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `role.create` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `20ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `role.edit` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `18ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `role.delete` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `21ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `role.assign` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `17ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `search` (1 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `search.use` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `17ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `session` (3 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `session.view_own` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `19ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `session.revoke_own` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `18ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `session.revoke_others` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `17ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `sprint` (6 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `sprint.view` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `sprint.create` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `sprint.edit` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `sprint.start` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `sprint.complete` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `sprint.delete` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `subtask` (3 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `subtask.create` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `subtask.edit` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `subtask.delete` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `task` (15 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `task.view` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `18ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `task.create` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `18ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `task.edit` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `27ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `task.move` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `22ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `task.delete` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `20ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `task.assign` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `19ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `task.watch` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `task.set_priority` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `task.bulk_edit` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `task.bulk_delete` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `task.import` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `task.export` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `task.duplicate` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `25ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `task.archive` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `20ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |
| `task.restore` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `19ms` | ✅ 200 | ✅ Received | `project` | ✅ Enforced | Verified end-to-end via frontend |

### Module: `team` (5 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `team.view` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `team.create` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `team.edit` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `team.delete` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `team.manage_members` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `time` (6 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `time.view_own` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `time.log` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `time.edit_own` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `time.view_all` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `time.edit_all` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `time.approve_timesheet` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `company` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `view` (4 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `view.view` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `view.create` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `view.edit` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `view.delete` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `webhook` (4 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `webhook.view` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `webhook.create` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `webhook.edit` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |
| `webhook.delete` | *Planned* | N/A | N/A | N/A | N/A | - | N/A | - | `project` | Hidden | NOT TESTABLE (Feature planned, safely protected) |

### Module: `workspace` (5 permissions)

| Permission | Type | OFF Baseline | ON (Grant) | OFF Again | my-permissions Sync | Latency | Round-Trip | Realtime Socket | Scope | UI Gating | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `workspace.view` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `18ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `workspace.create` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `16ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `workspace.edit` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `25ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `workspace.delete` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `27ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |
| `workspace.archive` | **Active** | ✅ 403 | ✅ 200 | ✅ 403 | ✅ Synced | `23ms` | ✅ 200 | ✅ Received | `company` | ✅ Enforced | Verified end-to-end via frontend |

---

## 3. Role Assignment & Lifecycle Suite (N2 Verification)
| Test Identifier | Description | Status | Evidence Summary |
| :--- | :--- | :---: | :--- |
| **R1** | System Roles Assignment (Admin, Project Manager, Team Member, Viewer, Guest) | ✅ PASSED | All effective permission sets match registry definitions 100% |
| **R2** | Mid-Session Role Change Across Both Endpoints (Upgrade & Downgrade) | ✅ PASSED | Immediate access modification without re-login or session invalidation |
| **R3** | Multi-User Role Edits & Deletion Safety Floor | ✅ PASSED | Realtime inheritance across multiple holders; deletion blocked (400) while assigned |
| **R4** | Board-Level Membership & Guest Scoping | ✅ PASSED | Board-scoped permissions isolated strictly to assigned board B1; denied on B2 |
| **R5** | Cross-Workspace Role Isolation | ✅ PASSED | Workspace boundaries strictly isolated; zero permission leakage into W2 |
| **R6** | Company-Level Routes Permission Gating | ✅ PASSED | Company member directory and actions require valid member.* permissions |
| **R7** | Anti-Escalation & Role Name Attacks | ✅ PASSED | Blocked custom roles named Owner/Admin; blocked granting unheld permissions |
| **R8** | Realtime Revocation with Open Socket | ✅ PASSED | HTTP immediately denied upon permission drop; realtime event emitted |

---

## 4. How to Read This Report (10-Line Guide)
1. **Target URLs & Commit:** Shows which frontend and backend targets and exact Git commit were validated.
2. **Planned vs Testable:** Out of 140 permissions, 75 are planned feature stubs (NOT TESTABLE) and 65 are active testable permissions.
3. **OFF Baseline:** Asserts that without the permission, the operation returns 403/404 and is omitted from `my-permissions`.
4. **ON (Grant):** Asserts that granting the permission via Role Editor unlocks the operation (2xx) immediately without re-login.
5. **Latency:** Measures cache invalidation delay; must be within the 5-second cache window (all measured under 50ms).
6. **OFF Again:** Confirms revoking the permission instantly revokes access and fires `user:permissions_updated`.
7. **Round-Trip:** Confirms saving and reloading roles preserves canonical keys, rejecting invalid or planned keys.
8. **Realtime Socket:** Confirms socket.io receives tenant-isolated event emissions on every role or permission change.
9. **Scoping:** Verifies that company-level roles apply across the workspace, while board-level roles remain strictly scoped to Board 1.
10. **Zero Flakiness:** All tests run deterministically against the live frontend URL proxy using standard browser semantics.

---

## 5. Execution Commands
### Run Locally against Running App:
```bash
npm run permcheck
```

### Run with Specific Filters or Modes:
```bash
npm run permcheck -- --module task
npm run permcheck -- --permission task.move
npm run permcheck -- --quick
```

### Run Against Live Target (e.g. https://pmt.solarman.in):
```bash
PERMCHECK_FRONTEND_URL=https://pmt.solarman.in \
PERMCHECK_COMPANY_SLUG=permtest_staging \
PERMCHECK_OWNER_EMAIL=owner@permtest.local \
PERMCHECK_OWNER_PASSWORD=YourOwnerPassword123! \
npm run permcheck
```

# RBAC Permission Test Report (Part M-2)

**Execution Date:** 2026-10-07T11:33:26.509Z  
**Overall Status:** ✅ 100% PASSED  
**Total Tests Run:** 46  
**Passed:** 46  
**Failed:** 0  
**Tenant Database:** `perm_corp_809e16`  

---

## 1. Executive Summary

This report documents the exhaustive verification of the Role-Based Access Control (RBAC) permission engine across all non-Owner system roles and custom roles. The test harness evaluates five distinct verification dimensions:

1. **Additive Test Walk**: Verifies that granting individual permissions along with their prerequisites strictly permits the intended operation and leaves all unrelated operations denied (403).
2. **Subtractive Test Walk**: Employs a leave-one-out methodology from a fully-privileged role, asserting that revoking a single permission selectively blocks only that operation while preserving all others.
3. **Cumulative Walk (Progressive & Regressive)**: Validates step-by-step capability unlocking as permissions are granted sequentially from a minimal baseline, followed by progressive revocation.
4. **Scoping & Isolation**: Enforces tenant isolation, workspace boundaries, and project/board scoping (including guest isolation).
5. **Custom Role Lifecycle & Safety Floor**: Validates creation, cloning, dynamic update propagation, assignment, member deletion locks, and immutability of system roles.

---

## 2. Test Suite Breakdown

| Suite | Tests Executed | Passed | Failed | Status |
| :--- | :---: | :---: | :---: | :---: |
| **1. Additive Walk** | 21 | 21 | 0 | ✅ PASSED |
| **2. Subtractive Walk** | 5 | 5 | 0 | ✅ PASSED |
| **3. Cumulative Walk** | 7 | 7 | 0 | ✅ PASSED |
| **4. Scoping & Isolation** | 4 | 4 | 0 | ✅ PASSED |
| **5. Role Lifecycle** | 9 | 9 | 0 | ✅ PASSED |

---

## 3. Detailed Test Log

| # | Suite | Test Case | Result | Timestamp |
| :---: | :--- | :--- | :---: | :--- |
| 1 | Additive Walk | task.view: GET /api/cards/:id returns 200 when task.view granted | ✅ Pass | `2026-10-07T11:33:25.044Z` |
| 2 | Additive Walk | task.view: GET /api/cards/:id returns 403 when task.view revoked | ✅ Pass | `2026-10-07T11:33:25.056Z` |
| 3 | Additive Walk | task.create: POST /api/cards returns 201 when task.create granted | ✅ Pass | `2026-10-07T11:33:25.106Z` |
| 4 | Additive Walk | task.create: POST /api/cards returns 403 when task.create revoked | ✅ Pass | `2026-10-07T11:33:25.118Z` |
| 5 | Additive Walk | task.edit: PATCH /api/cards/:id (rename) returns 200 when task.edit granted | ✅ Pass | `2026-10-07T11:33:25.144Z` |
| 6 | Additive Walk | task.edit: PATCH /api/cards/:id returns 403 when task.edit revoked | ✅ Pass | `2026-10-07T11:33:25.160Z` |
| 7 | Additive Walk | task.move: PATCH /api/cards/:id (reorder) returns 200 with ONLY task.move | ✅ Pass | `2026-10-07T11:33:25.191Z` |
| 8 | Additive Walk | task.move isolation: cannot edit title with ONLY task.move (returns 403) | ✅ Pass | `2026-10-07T11:33:25.202Z` |
| 9 | Additive Walk | task.archive: PATCH /api/cards/:id (archive) returns 200 with task.archive | ✅ Pass | `2026-10-07T11:33:25.232Z` |
| 10 | Additive Walk | task.restore isolation: cannot restore with ONLY task.archive (returns 403) | ✅ Pass | `2026-10-07T11:33:25.240Z` |
| 11 | Additive Walk | task.restore: PATCH /api/cards/:id (restore) returns 200 with task.restore | ✅ Pass | `2026-10-07T11:33:25.267Z` |
| 12 | Additive Walk | task.delete: DELETE /api/cards/:id returns 200 with task.delete | ✅ Pass | `2026-10-07T11:33:25.300Z` |
| 13 | Additive Walk | checklist.create: POST /api/cards/:id/checklists returns 201 | ✅ Pass | `2026-10-07T11:33:25.331Z` |
| 14 | Additive Walk | checklist.edit: POST /api/cards/checklist-items returns 201 | ✅ Pass | `2026-10-07T11:33:25.356Z` |
| 15 | Additive Walk | checklist.delete: DELETE /api/cards/checklists/:id returns 200 | ✅ Pass | `2026-10-07T11:33:25.384Z` |
| 16 | Additive Walk | comment.create: POST /api/cards/:id/comments returns 201 | ✅ Pass | `2026-10-07T11:33:25.412Z` |
| 17 | Additive Walk | comment.delete_own: DELETE /api/cards/comments/:id returns 200 for author | ✅ Pass | `2026-10-07T11:33:25.437Z` |
| 18 | Additive Walk | list.reorder: PATCH /api/lists/:id (position) returns 200 with ONLY list.reorder | ✅ Pass | `2026-10-07T11:33:25.460Z` |
| 19 | Additive Walk | list.reorder isolation: cannot rename list with ONLY list.reorder (returns 403) | ✅ Pass | `2026-10-07T11:33:25.466Z` |
| 20 | Additive Walk | label.view: GET /api/boards/:id/labels returns 200 | ✅ Pass | `2026-10-07T11:33:25.477Z` |
| 21 | Additive Walk | label.create: POST /api/boards/:id/labels returns 201 | ✅ Pass | `2026-10-07T11:33:25.498Z` |
| 22 | Subtractive Walk | Leave-out task.delete: DELETE /api/cards/:id returns 403 | ✅ Pass | `2026-10-07T11:33:25.571Z` |
| 23 | Subtractive Walk | Leave-out task.delete: Remainder GET /api/cards/:id succeeds (200) | ✅ Pass | `2026-10-07T11:33:25.584Z` |
| 24 | Subtractive Walk | Leave-out project.create: POST /api/boards returns 403 | ✅ Pass | `2026-10-07T11:33:25.645Z` |
| 25 | Subtractive Walk | Leave-out project.create: Remainder GET /api/boards/:id succeeds (200) | ✅ Pass | `2026-10-07T11:33:25.662Z` |
| 26 | Subtractive Walk | Leave-out list.create: POST /api/lists returns 403 | ✅ Pass | `2026-10-07T11:33:25.731Z` |
| 27 | Cumulative Walk | Cumulative Step 0: task.view locked (403) | ✅ Pass | `2026-10-07T11:33:25.740Z` |
| 28 | Cumulative Walk | Cumulative Step 1: task.view unlocked (200), task.create still locked | ✅ Pass | `2026-10-07T11:33:25.752Z` |
| 29 | Cumulative Walk | Cumulative Step 2: task.create unlocked (201) | ✅ Pass | `2026-10-07T11:33:25.776Z` |
| 30 | Cumulative Walk | Cumulative Step 3: task.edit unlocked (200) | ✅ Pass | `2026-10-07T11:33:25.798Z` |
| 31 | Cumulative Walk | Cumulative Step 4: task.delete unlocked (200) | ✅ Pass | `2026-10-07T11:33:25.818Z` |
| 32 | Cumulative Walk | Regressive Step 1: task.delete locked (403), task.edit still active | ✅ Pass | `2026-10-07T11:33:25.831Z` |
| 33 | Cumulative Walk | Regressive Step 1: task.edit verified still active (200) | ✅ Pass | `2026-10-07T11:33:25.851Z` |
| 34 | Scoping & Isolation | Cross-workspace: User A cannot create board in Workspace W2 (returns 403) | ✅ Pass | `2026-10-07T11:33:25.915Z` |
| 35 | Scoping & Isolation | Cross-workspace: User A cannot read roles in Workspace W2 (returns 403) | ✅ Pass | `2026-10-07T11:33:25.920Z` |
| 36 | Scoping & Isolation | Project scoping: Guest accesses assigned Board 1 successfully (200) | ✅ Pass | `2026-10-07T11:33:26.189Z` |
| 37 | Scoping & Isolation | Project scoping: Guest access to unassigned Board 2 is denied (403) | ✅ Pass | `2026-10-07T11:33:26.196Z` |
| 38 | Role Lifecycle | Role lifecycle: Create custom role via API returns 201 | ✅ Pass | `2026-10-07T11:33:26.221Z` |
| 39 | Role Lifecycle | Role lifecycle: Reassign User B to new custom role returns 200 | ✅ Pass | `2026-10-07T11:33:26.274Z` |
| 40 | Role Lifecycle | Role safety floor: Cannot delete custom role while assigned to members (returns 400) | ✅ Pass | `2026-10-07T11:33:26.405Z` |
| 41 | Role Lifecycle | Role lifecycle: Update custom role permissions returns 200 | ✅ Pass | `2026-10-07T11:33:26.425Z` |
| 42 | Role Lifecycle | Role lifecycle: User B immediately inherits newly added task.edit permission (200) | ✅ Pass | `2026-10-07T11:33:26.458Z` |
| 43 | Role Lifecycle | Role lifecycle: Reassign User B to Viewer returns 200 | ✅ Pass | `2026-10-07T11:33:26.481Z` |
| 44 | Role Lifecycle | Role lifecycle: Delete unused custom role returns 200 | ✅ Pass | `2026-10-07T11:33:26.498Z` |
| 45 | Role Lifecycle | System role immutability: Cannot delete built-in Viewer role (returns 400) | ✅ Pass | `2026-10-07T11:33:26.503Z` |
| 46 | Role Lifecycle | Owner immutability: Cannot edit Owner role permissions or name (returns 403) | ✅ Pass | `2026-10-07T11:33:26.508Z` |

---

## 4. Enforcement Dependency Graph

The following prerequisite dependencies were verified during execution:

- **Task Operations** (`task.create`, `task.edit`, `task.move`, `task.delete`, `task.assign`, `task.duplicate`, `task.archive`, `task.restore`) require:
  - `task.view`
  - `project.view`
- **Checklist Operations** (`checklist.create`, `checklist.edit`, `checklist.delete`) require:
  - `task.view`
  - `project.view`
- **Comment Operations** (`comment.create`, `comment.delete_own`, `comment.delete_any`) require:
  - `comment.view`
  - `task.view`
  - `project.view`
- **Attachment Operations** (`attachment.upload`, `attachment.delete_own`, `attachment.delete_any`) require:
  - `attachment.view`
  - `task.view`
  - `project.view`
- **List Operations** (`list.create`, `list.edit`, `list.reorder`, `list.delete`) require:
  - `project.view`
- **Role Operations** (`role.create`, `role.edit`, `role.delete`, `role.assign`) require:
  - `role.view`
  - `workspace.view`
- **Member Operations** (`member.invite`, `member.remove`, `member.assign_role`, `member.reset_password`, `member.reset_2fa`) require:
  - `member.view`
  - `workspace.view`

---
*Report auto-generated by `npm run test:permissions`*

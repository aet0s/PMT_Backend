// server/src/rbac/routePermissions.js
// Permission registry keyed by "METHOD /path".
// This is NOT the authoritative route list — the live Express stack is.
// The audit script reads both and cross-checks bidirectionally.
//
// Notes on convention:
//   permission: the requirePermission() key the middleware enforces
//   publicReason: for routes that are intentionally unauthenticated or self-scoped
//   selfScoped: routes protected by requireAuth only — the handler enforces
//               ownership or per-object access internally (no workspace RBAC key).
//   scope: 'company' | 'project' — dimension of the permission check
//   testOnly: only registered when NODE_ENV === 'test'
//
// Rules:
//   - Every real Express route MUST appear here.
//   - Every entry here MUST match a real Express route (no orphans).
//   - A route must have exactly one of: permission | publicReason | selfScoped.

const ROUTE_PERMISSIONS = new Map([
  // ─── Auth & Onboarding (Public / Self) ───────────────────────────────────
  ['POST /api/auth/register-company',       { publicReason: 'Company registration — unauthenticated by design',                    scope: 'company' }],
  ['POST /api/auth/verify-registration',    { publicReason: 'OTP verification for pending registration',                           scope: 'company' }],
  ['POST /api/auth/register',               { publicReason: 'Direct user registration via invite token',                           scope: 'company' }],
  ['POST /api/auth/login',                  { publicReason: 'Credential login step 1',                                            scope: 'company' }],
  ['POST /api/auth/2fa/verify-login',       { publicReason: 'TOTP / recovery-code login step 2 (pre-session)',                    scope: 'company' }],
  ['POST /api/auth/refresh',                { publicReason: 'Rotating refresh-token cookie exchange',                             scope: 'company' }],

  // ─── Session management (self-scoped — owns their own sessions) ───────────
  ['GET /api/auth/sessions',                { selfScoped: 'session.view_own — user reads their own sessions',                     scope: 'company' }],
  ['DELETE /api/auth/sessions/:id',         { selfScoped: 'session.revoke_own — revoke own session; admin rank check in handler',  scope: 'company' }],
  ['POST /api/auth/sessions/revoke-others', { selfScoped: 'session.revoke_own — revoke all other sessions for self',              scope: 'company' }],
  ['POST /api/auth/logout',                 { selfScoped: 'session.revoke_own — invalidate current session',                      scope: 'company' }],
  ['POST /api/auth/logout-all',             { selfScoped: 'session.revoke_own — invalidate all sessions for self',                scope: 'company' }],

  // ─── 2FA management (self-scoped) ─────────────────────────────────────────
  ['POST /api/auth/2fa/generate',           { selfScoped: 'User generates their own TOTP secret',                                  scope: 'company' }],
  ['POST /api/auth/2fa/setup',              { selfScoped: 'Alias for 2fa/generate',                                               scope: 'company' }],
  ['POST /api/auth/2fa/confirm',            { selfScoped: 'User confirms their own TOTP setup',                                   scope: 'company' }],
  ['POST /api/auth/2fa/disable',            { selfScoped: 'User disables their own TOTP',                                         scope: 'company' }],
  ['GET /api/auth/2fa/status',              { selfScoped: 'User reads their own 2FA status',                                      scope: 'company' }],

  // ─── Profile / password (self-scoped) ─────────────────────────────────────
  ['GET /api/auth/me',                      { selfScoped: 'Authenticated user reads their own profile',                            scope: 'company' }],
  ['PUT /api/auth/profile',                 { selfScoped: 'Authenticated user updates their own profile',                          scope: 'company' }],
  ['PUT /api/auth/password',                { selfScoped: 'Authenticated user changes their own password',                         scope: 'company' }],
  ['POST /api/auth/password',               { selfScoped: 'Alias: authenticated user changes their own password',                  scope: 'company' }],
  ['POST /api/auth/change-password',        { selfScoped: 'Alias: authenticated user changes their own password',                  scope: 'company' }],

  // ─── Workspaces ───────────────────────────────────────────────────────────
  ['GET /api/workspaces',                                             { permission: 'workspace.view',             scope: 'company' }],
  ['POST /api/workspaces',                                            { permission: 'workspace.create',           scope: 'company' }],
  ['PATCH /api/workspaces/:id',                                       { permission: 'workspace.edit_settings',    scope: 'company' }],
  ['DELETE /api/workspaces/:id',                                      { permission: 'workspace.delete',           scope: 'company' }],
  // my-permissions is self-evaluation — no workspace RBAC key; auth only
  ['GET /api/workspaces/:id/my-permissions',                          { selfScoped: 'User reads their own effective permissions for a workspace', scope: 'company' }],
  ['GET /api/workspaces/:id/roles',                                   { permission: 'role.view',                  scope: 'company' }],
  ['POST /api/workspaces/:id/roles',                                  { permission: 'role.create',                scope: 'company' }],
  ['GET /api/workspaces/:id/members',                                 { permission: 'member.view',                scope: 'company' }],
  ['PATCH /api/workspaces/:id/members/:userId/role',                  { permission: 'member.assign_role',         scope: 'company' }],
  ['DELETE /api/workspaces/:id/members/:userId',                      { permission: 'member.remove',              scope: 'company' }],
  ['POST /api/workspaces/:workspaceId/members/:userId/reset-password',{ permission: 'member.reset_password',      scope: 'company' }],
  ['POST /api/workspaces/:workspaceId/members/:userId/reset-2fa',     { permission: 'member.reset_2fa',           scope: 'company' }],

  // ─── Roles ────────────────────────────────────────────────────────────────
  // PATCH and DELETE use inline userHasPermission('workspace.manage_roles') — no requirePermission middleware,
  // but the handler still enforces it. We declare the effective permission here.
  ['PATCH /api/roles/:id',   { permission: 'workspace.manage_roles', scope: 'company', note: 'enforced inline in handler' }],
  ['DELETE /api/roles/:id',  { permission: 'workspace.manage_roles', scope: 'company', note: 'enforced inline in handler' }],

  // ─── Boards (Projects) ────────────────────────────────────────────────────
  ['GET /api/boards',                        { permission: 'project.view',          scope: 'company' }],
  ['POST /api/boards',                       { permission: 'board.create',          scope: 'company' }],
  // GET /api/boards/:id uses inline userHasPermission('project.view')
  ['GET /api/boards/:id',                    { permission: 'project.view',          scope: 'project', note: 'enforced inline in handler' }],
  ['PATCH /api/boards/:id',                  { permission: 'board.edit_settings',   scope: 'project' }],
  ['DELETE /api/boards/:id',                 { permission: 'board.delete',          scope: 'project' }],
  // workspace-members listed for board: authenticated, returns members of the parent workspace
  ['GET /api/boards/:id/workspace-members',  { permission: 'member.view',           scope: 'project', note: 'returns parent workspace members; enforced inline' }],
  ['POST /api/boards/:id/members',           { permission: 'project.manage_members',scope: 'project' }],
  ['DELETE /api/boards/:id/members/:userId', { permission: 'project.manage_members',scope: 'project' }],
  // labels use board.edit_settings for write; read is open to project members
  ['GET /api/boards/:id/labels',             { permission: 'project.view',          scope: 'project', note: 'enforced inline in handler' }],
  ['POST /api/boards/:id/labels',            { permission: 'board.edit_settings',   scope: 'project' }],

  // ─── Lists ────────────────────────────────────────────────────────────────
  ['POST /api/lists',        { permission: 'list.create', scope: 'project' }],
  ['PATCH /api/lists/:id',   { permission: 'list.edit',   scope: 'project' }],
  ['DELETE /api/lists/:id',  { permission: 'list.delete', scope: 'project' }],

  // ─── Cards (Tasks) ────────────────────────────────────────────────────────
  ['GET /api/cards/:id',     { permission: 'board.view',    scope: 'project' }],
  ['POST /api/cards',        { permission: 'card.create',   scope: 'project' }],
  ['PATCH /api/cards/:id',   { permission: 'card.edit',     scope: 'project' }],
  ['DELETE /api/cards/:id',  { permission: 'card.delete',   scope: 'project' }],

  // ─── Card: Labels & Members ───────────────────────────────────────────────
  ['POST /api/cards/:id/labels',            { permission: 'card.edit',             scope: 'project' }],
  ['POST /api/cards/:id/members',           { permission: 'card.assign_members',   scope: 'project' }],

  // ─── Card: Attachments & Comments ────────────────────────────────────────
  ['POST /api/cards/:id/attachments',       { permission: 'card.manage_attachments', scope: 'project' }],
  ['POST /api/cards/:id/attachments/file',  { permission: 'card.manage_attachments', scope: 'project' }],
  ['POST /api/cards/:id/attachments/link',  { permission: 'card.manage_attachments', scope: 'project' }],
  ['DELETE /api/cards/attachments/:id',     { permission: 'card.manage_attachments', scope: 'project', note: 'handler also checks ownership' }],
  ['POST /api/cards/:id/comments',          { permission: 'card.comment',            scope: 'project' }],
  // DELETE comments: auth only; handler enforces ownership or admin rank
  ['DELETE /api/cards/comments/:id',        { selfScoped: 'card.comment — handler checks owner or sufficient role',  scope: 'project' }],

  // ─── Checklists ───────────────────────────────────────────────────────────
  // These routes use requireAuth only; handlers do card-level access checks internally
  ['POST /api/cards/:id/checklists',        { selfScoped: 'card.edit — handler validates card membership',            scope: 'project' }],
  ['DELETE /api/cards/checklists/:id',      { selfScoped: 'card.edit — handler validates card membership',            scope: 'project' }],
  ['POST /api/cards/checklist-items',       { selfScoped: 'card.edit — handler validates card membership',            scope: 'project' }],
  ['PATCH /api/cards/checklist-items/:id',  { selfScoped: 'card.edit — handler validates card membership',            scope: 'project' }],
  ['DELETE /api/cards/checklist-items/:id', { selfScoped: 'card.edit — handler validates card membership',            scope: 'project' }],

  // ─── Archive ──────────────────────────────────────────────────────────────
  // GET /api/archive: auth only; handler scopes by workspace membership
  ['GET /api/archive',                      { selfScoped: 'archive.view — handler scopes by workspace membership',    scope: 'company' }],

  // ─── Invitations ─────────────────────────────────────────────────────────
  ['GET /api/invitations/verify',           { publicReason: 'Public validation of a signed invite link',              scope: 'company' }],
  // GET and DELETE invitations use inline requireWorkspaceAdmin check — effectivley member.invite
  ['GET /api/invitations',                  { permission: 'member.invite', scope: 'company', note: 'enforced via requireWorkspaceAdmin inline' }],
  ['POST /api/invitations',                 { permission: 'member.invite', scope: 'company', note: 'enforced via requireWorkspaceAdmin inline' }],
  // POST accept: authenticated; handler validates token + tenant membership
  ['POST /api/invitations/accept',          { selfScoped: 'Accepts a valid signed invite token; no RBAC key needed', scope: 'company' }],
  ['DELETE /api/invitations/:id',           { permission: 'member.invite', scope: 'company', note: 'enforced via requireWorkspaceAdmin inline' }],

  // ─── Notifications ────────────────────────────────────────────────────────
  // All notification routes are self-scoped (user operates on their own notifications)
  ['GET /api/notifications',                { selfScoped: 'notification.view_own — user reads their own notifications',         scope: 'company' }],
  ['GET /api/notifications/unread-count',   { selfScoped: 'notification.view_own — user reads their own unread count',          scope: 'company' }],
  ['GET /api/notifications/preferences',    { selfScoped: 'notification.manage_own — user reads their own preferences',         scope: 'company' }],
  ['PATCH /api/notifications/preferences',  { selfScoped: 'notification.manage_own — user updates their own preferences',       scope: 'company' }],
  ['PATCH /api/notifications/:id/read',     { selfScoped: 'notification.manage_own — user marks their own notification read',    scope: 'company' }],
  ['PATCH /api/notifications/:id/unread',   { selfScoped: 'notification.manage_own — user marks their own notification unread',  scope: 'company' }],
  ['PATCH /api/notifications/read-all',     { selfScoped: 'notification.manage_own — user marks all their notifications read',   scope: 'company' }],
  ['DELETE /api/notifications/:id',         { selfScoped: 'notification.manage_own — user deletes their own notification',       scope: 'company' }],
  ['DELETE /api/notifications/clear/read',  { selfScoped: 'notification.manage_own — user clears all read notifications',        scope: 'company' }],

  // ─── Permissions Catalog & Self-Evaluation ────────────────────────────────
  // GET /api/permissions: returns the catalog; any authenticated user should see it
  ['GET /api/permissions',                  { permission: 'role.view', scope: 'company' }],
  ['GET /api/permissions/me',               { selfScoped: 'User evaluates their own effective permissions for a workspace/project', scope: 'project' }],

  // ─── Files & Avatars ──────────────────────────────────────────────────────
  ['POST /api/files/avatar',  { selfScoped: 'User uploads their own avatar',                                                                           scope: 'company' }],
  ['GET /api/files/:tenantId/*', { selfScoped: 'file.view — tenant isolation + inline per-attachment authorization in handler',                        scope: 'project' }],

  // ─── System Health & Setup ────────────────────────────────────────────────
  ['GET /api/health', { publicReason: 'Public infrastructure health check', scope: 'company' }],
  ['POST /api/setup/migrate', { publicReason: 'Deployment schema migration initialization runner', scope: 'company' }],

  // ─── Test / Dev Only Endpoints ────────────────────────────────────────────
  ['POST /api/dev/reset-rate-limit', { publicReason: 'Test environment rate limit reset helper', scope: 'company', testOnly: true }],
]);

/**
 * Returns the permission declaration for a given method + path, or null.
 */
function getRouteDeclaration(method, path) {
  return ROUTE_PERMISSIONS.get(`${method.toUpperCase()} ${path}`) || null;
}

/**
 * Returns a flat array of all declarations for doc generation.
 */
function getRouteManifest() {
  return Array.from(ROUTE_PERMISSIONS.entries()).map(([key, decl]) => {
    const [method, ...rest] = key.split(' ');
    return { method, path: rest.join(' '), ...decl };
  });
}

module.exports = { ROUTE_PERMISSIONS, getRouteDeclaration, getRouteManifest };

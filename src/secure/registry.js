// server/src/secure/registry.js
// Strict explicit business operation registry for the POST-only hybrid-encrypted gateway.
// Every normal business API operation maps to an explicit handler, Zod schema, auth flag, and permission check.

const { z } = require('zod');
const commentService = require('../services/commentService');
const { userHasPermission } = require('../middleware/permissions');
const { dispatchInternal } = require('./internalDispatcher');
const path = require('path');
const fs = require('fs');

const registry = new Map();

function registerOperation(name, definition) {
  registry.set(name, {
    name,
    requireAuth: definition.requireAuth !== false, // default true
    permission: definition.permission || null,
    schema: definition.schema || z.any(),
    handler: definition.handler
  });
}

// ============================================================================
// 1. GATEWAY DIAGNOSTICS
// ============================================================================
registerOperation('gateway.ping', {
  requireAuth: false,
  schema: z.object({
    echo: z.string().optional()
  }).passthrough(),
  handler: async (ctx, data) => {
    return {
      status: 'ok',
      echo: data.echo || 'pong',
      gateway: 'TaskFlow Encrypted POST-Only Business Gateway v1',
      server_time: new Date().toISOString()
    };
  }
});

// ============================================================================
// 2. AUTHENTICATION & SESSIONS
// ============================================================================
registerOperation('auth.login', {
  requireAuth: false,
  schema: z.object({
    email: z.string().email(),
    password: z.string().min(1),
    company_slug: z.string().optional(),
    rememberMe: z.boolean().optional()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/login', body: data });
  }
});

registerOperation('auth.register', {
  requireAuth: false,
  schema: z.object({
    name: z.string().min(1),
    email: z.string().email(),
    password: z.string().min(1),
    company_name: z.string().optional()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/register', body: data });
  }
});

registerOperation('auth.register_company', {
  requireAuth: false,
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/register-company', body: data });
  }
});

registerOperation('auth.register.send_otp', {
  requireAuth: false,
  schema: z.object({
    email: z.string().email()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/register/send-otp', body: data });
  }
});

registerOperation('auth.register.verify_otp', {
  requireAuth: false,
  schema: z.object({
    email: z.string().email(),
    otp: z.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/register/verify-otp', body: data });
  }
});

registerOperation('auth.verify_registration', {
  requireAuth: false,
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/verify-registration', body: data });
  }
});

registerOperation('auth.check_email', {
  requireAuth: false,
  schema: z.object({
    email: z.string().email()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/auth/check-email', query: { email: data.email } });
  }
});

registerOperation('auth.refresh', {
  requireAuth: false,
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/refresh', body: data });
  }
});

registerOperation('auth.logout', {
  requireAuth: false, // Can be called even if token is expired to clear cookies
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/logout', body: data });
  }
});

registerOperation('auth.logout_all', {
  requireAuth: true,
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/logout-all', body: data });
  }
});

registerOperation('auth.me', {
  requireAuth: true,
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/auth/me', query: data });
  }
});

registerOperation('auth.profile.update', {
  requireAuth: true,
  schema: z.object({
    name: z.string().optional(),
    avatar_url: z.string().nullable().optional()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'PUT', url: '/api/auth/profile', body: data });
  }
});

registerOperation('auth.password.update', {
  requireAuth: true,
  schema: z.object({
    currentPassword: z.string().min(1),
    newPassword: z.string().min(6)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'PUT', url: '/api/auth/password', body: data });
  }
});

registerOperation('auth.forgot_password.send_otp', {
  requireAuth: false,
  schema: z.object({
    email: z.string().email()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/forgot-password/send-otp', body: data });
  }
});

registerOperation('auth.forgot_password.verify_otp', {
  requireAuth: false,
  schema: z.object({
    email: z.string().email(),
    otp: z.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/forgot-password/verify-otp', body: data });
  }
});

registerOperation('auth.forgot_password.verify_token', {
  requireAuth: false,
  schema: z.object({
    token: z.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/forgot-password/verify-token', body: data });
  }
});

registerOperation('auth.forgot_password.reset', {
  requireAuth: false,
  schema: z.object({
    email: z.string().optional(),
    token: z.string().optional(),
    reset_token: z.string().optional(),
    password: z.string().optional(),
    new_password: z.string().optional()
  }).refine((d) => (d.reset_token || d.token) && (d.new_password || d.password), {
    message: 'Reset token and new password are required'
  }).passthrough(),
  handler: async (ctx, data) => {
    const token = data.reset_token || data.token;
    const password = data.new_password || data.password;
    const body = {
      ...data,
      token,
      reset_token: token,
      password,
      new_password: password
    };
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/forgot-password/reset', body });
  }
});

registerOperation('auth.2fa.verify_login', {
  requireAuth: false,
  schema: z.object({
    temp_token: z.string().min(1),
    code: z.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/2fa/verify-login', body: data });
  }
});

registerOperation('auth.2fa.status', {
  requireAuth: true,
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/auth/2fa/status' });
  }
});

registerOperation('auth.2fa.generate', {
  requireAuth: true,
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/2fa/generate', body: data });
  }
});

registerOperation('auth.2fa.confirm', {
  requireAuth: true,
  schema: z.object({
    code: z.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/2fa/confirm', body: data });
  }
});

registerOperation('auth.2fa.disable', {
  requireAuth: true,
  schema: z.object({
    password: z.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/2fa/disable', body: data });
  }
});

registerOperation('auth.sessions.list', {
  requireAuth: true,
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/auth/sessions' });
  }
});

registerOperation('auth.sessions.revoke', {
  requireAuth: true,
  schema: z.object({
    session_id: z.coerce.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/auth/sessions/${data.session_id}` });
  }
});

registerOperation('auth.sessions.revoke_others', {
  requireAuth: true,
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/auth/sessions/revoke-others', body: data });
  }
});

registerOperation('auth.activity', {
  requireAuth: true,
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/auth/activity', query: data });
  }
});

// ============================================================================
// 3. WORKSPACES
// ============================================================================
registerOperation('workspaces.list', {
  permission: 'workspace.view',
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/workspaces', query: data });
  }
});

registerOperation('workspaces.create', {
  permission: 'workspace.create',
  schema: z.object({
    name: z.string().min(1),
    description: z.string().optional()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/workspaces', body: data });
  }
});

registerOperation('workspaces.get', {
  permission: 'workspace.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${data.workspace_id}` });
  }
});

registerOperation('workspaces.update', {
  permission: 'workspace.edit',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/workspaces/${workspace_id}`, body });
  }
});

registerOperation('workspaces.delete', {
  permission: 'workspace.delete',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/workspaces/${data.workspace_id}` });
  }
});

registerOperation('workspaces.my_permissions', {
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${data.workspace_id}/my-permissions` });
  }
});

registerOperation('workspaces.members.list', {
  permission: 'member.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${data.workspace_id}/members` });
  }
});

registerOperation('workspaces.members.add', {
  permission: 'member.invite',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/workspaces/${workspace_id}/members`, body });
  }
});

registerOperation('workspaces.members.update_role', {
  permission: 'member.assign_role',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, user_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/workspaces/${workspace_id}/members/${user_id}/role`, body });
  }
});

registerOperation('workspaces.members.remove', {
  permission: 'member.remove',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/workspaces/${data.workspace_id}/members/${data.user_id}` });
  }
});

registerOperation('workspaces.members.deactivate', {
  permission: 'member.deactivate',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/workspaces/${data.workspace_id}/members/${data.user_id}/deactivate` });
  }
});

registerOperation('workspaces.members.reactivate', {
  permission: 'member.deactivate',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/workspaces/${data.workspace_id}/members/${data.user_id}/reactivate` });
  }
});

registerOperation('workspaces.members.reset_password', {
  permission: 'member.reset_password',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/workspaces/${data.workspace_id}/members/${data.user_id}/reset-password` });
  }
});

registerOperation('workspaces.members.reset_2fa', {
  permission: 'member.reset_2fa',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/workspaces/${data.workspace_id}/members/${data.user_id}/reset-2fa` });
  }
});

registerOperation('workspaces.roles.list', {
  permission: 'role.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${data.workspace_id}/roles` });
  }
});

registerOperation('workspaces.roles.create', {
  permission: 'role.create',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/workspaces/${workspace_id}/roles`, body });
  }
});

registerOperation('workspaces.roles.update', {
  permission: 'role.edit',
  schema: z.object({
    role_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { role_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/roles/${role_id}`, body });
  }
});

registerOperation('workspaces.roles.delete', {
  permission: 'role.delete',
  schema: z.object({
    role_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/roles/${data.role_id}` });
  }
});

registerOperation('workspaces.roles.reset_default', {
  permission: 'role.edit',
  schema: z.object({
    role_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/roles/${data.role_id}/reset-default` });
  }
});

registerOperation('workspaces.activity', {
  permission: 'workspace.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${workspace_id}/activity`, query });
  }
});

registerOperation('workspaces.reports', {
  permission: 'report.view_project',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    board_id: z.union([z.coerce.number().positive(), z.literal('all')]).optional(),
    timeframe: z.enum(['all', '7d', '30d', '90d', 'this_month']).optional()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${workspace_id}/reports`, query });
  }
});

registerOperation('workspaces.company_members.list', {
  permission: 'member.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${workspace_id}/company-members`, query });
  }
});

registerOperation('workspaces.company_members.update_role', {
  permission: 'member.assign_role',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, user_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/workspaces/${workspace_id}/company-members/${user_id}/role`, body });
  }
});

registerOperation('workspaces.company_members.assign_workspaces', {
  permission: 'member.invite',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, user_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/workspaces/${workspace_id}/company-members/${user_id}/workspaces`, body });
  }
});

registerOperation('workspaces.company_members.assign_boards', {
  permission: 'member.invite',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, user_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/workspaces/${workspace_id}/company-members/${user_id}/boards`, body });
  }
});

registerOperation('workspaces.company_members.remove', {
  permission: 'member.remove',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/workspaces/${data.workspace_id}/company-members/${data.user_id}` });
  }
});

registerOperation('workspaces.company_members.update_credentials', {
  permission: 'member.assign_role',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, user_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/workspaces/${workspace_id}/company-members/${user_id}/credentials`, body });
  }
});

registerOperation('workspaces.daily_tracker', {
  permission: 'workspace.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${workspace_id}/daily-tracker`, query });
  }
});

registerOperation('workspaces.daily_tracker_people', {
  permission: 'workspace.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${workspace_id}/daily-tracker/people`, query });
  }
});

registerOperation('workspaces.leave_days.list', {
  permission: 'workspace.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${workspace_id}/leave-days`, query });
  }
});

registerOperation('workspaces.leave_days.create', {
  permission: 'workspace.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/workspaces/${workspace_id}/leave-days`, body });
  }
});

registerOperation('workspaces.leave_days.update', {
  permission: 'workspace.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    leave_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, leave_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/workspaces/${workspace_id}/leave-days/${leave_id}`, body });
  }
});

registerOperation('workspaces.leave_days.delete', {
  permission: 'workspace.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    leave_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/workspaces/${data.workspace_id}/leave-days/${data.leave_id}` });
  }
});

registerOperation('workspaces.checkins_pending', {
  permission: 'workspace.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${data.workspace_id}/checkins/pending` });
  }
});

registerOperation('workspaces.audit_events.list', {
  permission: 'audit.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${workspace_id}/audit-events`, query });
  }
});

registerOperation('workspaces.audit_events.get', {
  permission: 'audit.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    event_id: z.coerce.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${data.workspace_id}/audit-events/${data.event_id}` });
  }
});

registerOperation('workspaces.audit_events.facets', {
  permission: 'audit.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${data.workspace_id}/audit-events/facets` });
  }
});

registerOperation('workspaces.audit_events.verify', {
  permission: 'audit.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/workspaces/${workspace_id}/audit-events/verify`, body });
  }
});

registerOperation('workspaces.audit_events.export', {
  permission: 'audit.export',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${workspace_id}/audit-events/export`, query });
  }
});

registerOperation('workspaces.audit.list', {
  permission: 'audit.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${workspace_id}/audit`, query });
  }
});

registerOperation('workspaces.audit.export', {
  permission: 'audit.export',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${workspace_id}/audit/export`, query });
  }
});

registerOperation('workspaces.my_tasks', {
  schema: z.object({
    workspace_id: z.union([z.coerce.number().positive(), z.literal('all'), z.string()]).optional()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    const targetWs = workspace_id || 'all';
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${targetWs}/my-tasks`, query });
  }
});

registerOperation('workspaces.issues', {
  permission: 'workspace.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${workspace_id}/issues`, query });
  }
});

registerOperation('workspaces.search', {
  permission: 'workspace.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${workspace_id}/search`, query });
  }
});

registerOperation('workspaces.icon.set', {
  permission: 'workspace.edit',
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    icon_url: z.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    const workspaceId = Number(data.workspace_id);
    const iconUrl = data.icon_url;

    const [existingWs] = await ctx.db.query('SELECT * FROM workspaces WHERE id = ?', [workspaceId]);
    if (!existingWs) {
      const err = new Error('Workspace not found');
      err.status = 404;
      err.code = 'NOT_FOUND';
      throw err;
    }

    let settingsObj = {};
    if (existingWs?.settings) {
      try {
        settingsObj = typeof existingWs.settings === 'string' ? JSON.parse(existingWs.settings) : existingWs.settings;
      } catch {}
    }
    // If replacing existing icon, delete previous icon file from disk
    const previousIcon = existingWs?.icon_url || settingsObj.icon_url;
    if (previousIcon && previousIcon !== iconUrl) {
      try {
        const storage = require('../storage');
        const oldKey = previousIcon.replace(/^\/api\/files\//, '').replace(/^\/uploads\//, '');
        if (oldKey.includes('workspaces/')) {
          await storage.delete(oldKey);
        }
      } catch (cleanErr) {
        console.warn('Failed to clean up old workspace icon:', cleanErr.message);
      }
    }

    settingsObj.icon_url = iconUrl;

    try {
      await ctx.db.execute(
        'UPDATE workspaces SET icon_url = ?, settings = ? WHERE id = ?',
        [iconUrl, JSON.stringify(settingsObj), workspaceId]
      );
    } catch (colErr) {
      await ctx.db.execute(
        'UPDATE workspaces SET settings = ? WHERE id = ?',
        [JSON.stringify(settingsObj), workspaceId]
      );
    }

    const [updatedWs] = await ctx.db.query('SELECT w.* FROM workspaces w WHERE w.id = ?', [workspaceId]);
    let parsedSettings = updatedWs.settings;
    if (typeof parsedSettings === 'string') {
      try { parsedSettings = JSON.parse(parsedSettings); } catch {}
    }
    const wsPayload = {
      ...updatedWs,
      icon_url: iconUrl,
      settings: parsedSettings,
      require_2fa_for_admins: !!updatedWs.require_2fa_for_admins
    };

    try {
      const { broadcastWorkspaceEvent } = require('../socket');
      broadcastWorkspaceEvent(workspaceId, 'workspace:updated', { workspace: wsPayload }, ctx.req?.headers?.['x-origin-id'], ctx.tenant?.id);
    } catch (e) {}

    return {
      message: 'Workspace icon uploaded successfully',
      icon_url: iconUrl,
      workspace: wsPayload
    };
  }
});

registerOperation('workspaces.icon.remove', {
  permission: 'workspace.edit',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const workspaceId = Number(data.workspace_id);

    const [existingWs] = await ctx.db.query('SELECT * FROM workspaces WHERE id = ?', [workspaceId]);
    if (!existingWs) {
      const err = new Error('Workspace not found');
      err.status = 404;
      err.code = 'NOT_FOUND';
      throw err;
    }

    let settingsObj = {};
    if (existingWs?.settings) {
      try {
        settingsObj = typeof existingWs.settings === 'string' ? JSON.parse(existingWs.settings) : existingWs.settings;
      } catch {}
    }
    // Delete current icon file from storage
    const currentIcon = existingWs?.icon_url || settingsObj.icon_url;
    if (currentIcon) {
      try {
        const storage = require('../storage');
        const oldKey = currentIcon.replace(/^\/api\/files\//, '').replace(/^\/uploads\//, '');
        if (oldKey.includes('workspaces/')) {
          await storage.delete(oldKey);
        }
      } catch (cleanErr) {
        console.warn('Failed to clean up workspace icon file:', cleanErr.message);
      }
    }

    delete settingsObj.icon_url;

    try {
      await ctx.db.execute(
        'UPDATE workspaces SET icon_url = NULL, settings = ? WHERE id = ?',
        [JSON.stringify(settingsObj), workspaceId]
      );
    } catch (colErr) {
      await ctx.db.execute(
        'UPDATE workspaces SET settings = ? WHERE id = ?',
        [JSON.stringify(settingsObj), workspaceId]
      );
    }

    const [updatedWs] = await ctx.db.query('SELECT w.* FROM workspaces w WHERE w.id = ?', [workspaceId]);
    let parsedSettings = updatedWs.settings;
    if (typeof parsedSettings === 'string') {
      try { parsedSettings = JSON.parse(parsedSettings); } catch {}
    }
    const wsPayload = {
      ...updatedWs,
      icon_url: null,
      settings: parsedSettings,
      require_2fa_for_admins: !!updatedWs.require_2fa_for_admins
    };

    try {
      const { broadcastWorkspaceEvent } = require('../socket');
      broadcastWorkspaceEvent(workspaceId, 'workspace:updated', { workspace: wsPayload }, ctx.req?.headers?.['x-origin-id'], ctx.tenant?.id);
    } catch (e) {}

    return {
      message: 'Workspace icon removed successfully',
      workspace: wsPayload
    };
  }
});

registerOperation('workspaces.auto_archive', {
  permission: 'workspace.edit',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/workspaces/${workspace_id}/auto-archive`, body });
  }
});

registerOperation('workspaces.invitations.list', {
  permission: 'member.invite',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${data.workspace_id}/invitations` });
  }
});

registerOperation('workspaces.invitations.create', {
  permission: 'member.invite',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/workspaces/${workspace_id}/invitations`, body });
  }
});

registerOperation('workspaces.archived', {
  permission: 'workspace.view',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${data.workspace_id}/archived` });
  }
});

registerOperation('workspaces.security.get', {
  permission: 'company.manage_security',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/workspaces/${data.workspace_id}/security` });
  }
});

registerOperation('workspaces.security.update', {
  permission: 'company.manage_security',
  schema: z.object({
    workspace_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { workspace_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/workspaces/${workspace_id}/security`, body });
  }
});

// ============================================================================
// 4. BOARDS
// ============================================================================
registerOperation('boards.list', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/boards', query: data });
  }
});

registerOperation('boards.create', {
  schema: z.object({
    workspace_id: z.coerce.number().positive(),
    name: z.string().min(1).optional(),
    title: z.string().min(1).optional()
  }).passthrough().refine((data) => data.name || data.title, {
    message: 'Board name or title is required'
  }),
  handler: async (ctx, data) => {
    const payload = { ...data, name: data.name || data.title };
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/boards', body: payload });
  }
});

registerOperation('boards.get', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/boards/${data.board_id}` });
  }
});

registerOperation('boards.update', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { board_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/boards/${board_id}`, body });
  }
});

registerOperation('boards.delete', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/boards/${data.board_id}` });
  }
});

registerOperation('boards.archive', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/boards/${data.board_id}/archive` });
  }
});

registerOperation('boards.restore', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/boards/${data.board_id}/restore` });
  }
});

registerOperation('boards.archived', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/boards/${data.board_id}/archived` });
  }
});

registerOperation('boards.members.list', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/boards/${data.board_id}/members` });
  }
});

registerOperation('boards.members.add', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { board_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/boards/${board_id}/members`, body });
  }
});

registerOperation('boards.members.update_role', {
  schema: z.object({
    board_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { board_id, user_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/boards/${board_id}/members/${user_id}/role`, body });
  }
});

registerOperation('boards.members.remove', {
  schema: z.object({
    board_id: z.coerce.number().positive(),
    user_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/boards/${data.board_id}/members/${data.user_id}` });
  }
});

registerOperation('boards.workspace_members', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/boards/${data.board_id}/workspace-members` });
  }
});

registerOperation('boards.mention_candidates', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/boards/${data.board_id}/mention-candidates` });
  }
});

registerOperation('boards.labels.list', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/boards/${data.board_id}/labels` });
  }
});

registerOperation('boards.labels.create', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { board_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/boards/${board_id}/labels`, body });
  }
});

registerOperation('boards.labels.update', {
  schema: z.object({
    board_id: z.coerce.number().positive(),
    label_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { board_id, label_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/boards/${board_id}/labels/${label_id}`, body });
  }
});

registerOperation('boards.labels.delete', {
  schema: z.object({
    board_id: z.coerce.number().positive(),
    label_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/boards/${data.board_id}/labels/${data.label_id}` });
  }
});

registerOperation('boards.attachments', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/boards/${data.board_id}/attachments` });
  }
});

// ============================================================================
// 5. LISTS
// ============================================================================
registerOperation('lists.create', {
  schema: z.object({
    board_id: z.coerce.number().positive(),
    name: z.string().min(1).optional(),
    title: z.string().min(1).optional()
  }).passthrough().refine((data) => data.name || data.title, {
    message: 'List name or title is required'
  }),
  handler: async (ctx, data) => {
    const payload = { ...data, name: data.name || data.title };
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/lists', body: payload });
  }
});

registerOperation('lists.update', {
  schema: z.object({
    list_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { list_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/lists/${list_id}`, body });
  }
});

registerOperation('lists.delete', {
  schema: z.object({
    list_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/lists/${data.list_id}` });
  }
});

// ============================================================================
// 6. CARDS
// ============================================================================
registerOperation('cards.get', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/cards/${data.card_id}` });
  }
});

registerOperation('cards.create', {
  schema: z.object({
    board_id: z.coerce.number().positive().optional(),
    list_id: z.coerce.number().positive(),
    title: z.string().min(1).optional(),
    name: z.string().min(1).optional()
  }).passthrough().refine((data) => data.title || data.name, {
    message: 'Card title or name is required'
  }),
  handler: async (ctx, data) => {
    const payload = { ...data, title: data.title || data.name };
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/cards', body: payload });
  }
});

registerOperation('cards.update', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/cards/${card_id}`, body });
  }
});

registerOperation('cards.delete', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/cards/${data.card_id}` });
  }
});

registerOperation('cards.move', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/cards/${card_id}`, body });
  }
});

registerOperation('cards.labels.assign', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/cards/${card_id}/labels`, body });
  }
});

registerOperation('cards.assigners.assign', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/cards/${card_id}/assigners`, body });
  }
});

registerOperation('cards.members.assign', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/cards/${card_id}/members`, body });
  }
});

registerOperation('cards.copy', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/cards/${card_id}/copy`, body });
  }
});

registerOperation('cards.attachments.list', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/cards/${data.card_id}/attachments` });
  }
});

registerOperation('cards.attachments.create', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/cards/${card_id}/attachments`, body });
  }
});

registerOperation('cards.attachments.file', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/cards/${card_id}/attachments/file`, body });
  }
});

registerOperation('cards.attachments.link', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/cards/${card_id}/attachments/link`, body });
  }
});

registerOperation('cards.attachments.delete', {
  schema: z.object({
    attachment_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/cards/attachments/${data.attachment_id}` });
  }
});

registerOperation('cards.checklists.list', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/cards/${data.card_id}/checklists` });
  }
});

registerOperation('cards.checklists.create', {
  schema: z.object({
    card_id: z.coerce.number().positive(),
    title: z.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/cards/${card_id}/checklists`, body });
  }
});

registerOperation('cards.checklists.delete', {
  schema: z.object({
    checklist_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/cards/checklists/${data.checklist_id}` });
  }
});

registerOperation('cards.checklists.items.create', {
  schema: z.object({
    checklist_id: z.coerce.number().positive(),
    title: z.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/cards/checklist-items', body: data });
  }
});

registerOperation('cards.checklists.items.update', {
  schema: z.object({
    item_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { item_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/cards/checklist-items/${item_id}`, body });
  }
});

registerOperation('cards.checklists.items.delete', {
  schema: z.object({
    item_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/cards/checklist-items/${data.item_id}` });
  }
});

registerOperation('cards.checkins.list', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, ...query } = data;
    return await dispatchInternal(ctx, { method: 'GET', url: `/api/cards/${card_id}/checkins`, query });
  }
});

registerOperation('cards.checkins.create', {
  schema: z.object({
    card_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/cards/${card_id}/checkins`, body });
  }
});

registerOperation('cards.checkins.update', {
  schema: z.object({
    card_id: z.coerce.number().positive(),
    checkin_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { card_id, checkin_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/cards/${card_id}/checkins/${checkin_id}`, body });
  }
});

registerOperation('cards.checkins.review', {
  schema: z.object({
    checkin_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { checkin_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/checkins/${checkin_id}/review`, body });
  }
});

registerOperation('cards.checkins.answer', {
  schema: z.object({
    review_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    const { review_id, ...body } = data;
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/checkin-reviews/${review_id}/answer`, body });
  }
});

// ============================================================================
// 7. COMMENTS (PRESERVED IMPLEMENTATION)
// ============================================================================
registerOperation('comments.list', {
  permission: 'comment.view',
  schema: z.object({
    card_id: z.coerce.number().positive('card_id must be a positive integer')
  }),
  handler: async (ctx, data) => {
    return await commentService.getThreadedComments(ctx.db, Number(data.card_id));
  }
});

registerOperation('comments.create', {
  permission: 'comment.create',
  schema: z.object({
    card_id: z.coerce.number().positive(),
    body: z.string().min(1, 'Comment body cannot be empty'),
    parent_comment_id: z.coerce.number().positive().nullable().optional(),
    mentions: z.array(z.coerce.number()).optional()
  }),
  handler: async (ctx, data) => {
    const comment = await commentService.createComment(ctx.db, {
      cardId: Number(data.card_id),
      userId: ctx.user.id,
      body: data.body,
      parentCommentId: data.parent_comment_id ? Number(data.parent_comment_id) : null,
      clientMentionIds: data.mentions || [],
      originId: ctx.req.headers['x-origin-id'],
      tenantId: ctx.tenant?.id || null
    });
    ctx.res.status(201);
    return { comment };
  }
});

registerOperation('comments.update', {
  schema: z.object({
    comment_id: z.coerce.number().positive(),
    body: z.string().min(1, 'Updated comment body cannot be empty')
  }),
  handler: async (ctx, data) => {
    const commentId = Number(data.comment_id);
    const rows = await ctx.db.query('SELECT user_id, card_id FROM comments WHERE id = ?', [commentId]);
    if (!rows || rows.length === 0) {
      const err = new Error('Comment not found');
      err.status = 404;
      err.code = 'NOT_FOUND';
      throw err;
    }

    const isOwn = Number(rows[0].user_id) === Number(ctx.user.id);
    const hasPerm = isOwn
      ? await userHasPermission(ctx.user.id, ctx.workspaceId || ctx.tenant?.id || 1, 'comment.edit_own', ctx.db, null, ctx.req)
      : await userHasPermission(ctx.user.id, ctx.workspaceId || ctx.tenant?.id || 1, 'comment.edit_any', ctx.db, null, ctx.req);

    if (!hasPerm && !isOwn) {
      const err = new Error('Permission denied to edit comment');
      err.status = 403;
      err.code = 'FORBIDDEN';
      throw err;
    }

    const updated = await commentService.editComment(ctx.db, {
      commentId,
      userId: ctx.user.id,
      body: data.body,
      originId: ctx.req.headers['x-origin-id'],
      tenantId: ctx.tenant?.id || null
    });
    return { comment: updated };
  }
});

registerOperation('comments.delete', {
  schema: z.object({
    comment_id: z.coerce.number().positive()
  }),
  handler: async (ctx, data) => {
    const commentId = Number(data.comment_id);
    const rows = await ctx.db.query('SELECT user_id, card_id FROM comments WHERE id = ?', [commentId]);
    if (!rows || rows.length === 0) {
      const err = new Error('Comment not found');
      err.status = 404;
      err.code = 'NOT_FOUND';
      throw err;
    }

    const isOwn = Number(rows[0].user_id) === Number(ctx.user.id);
    const hasPerm = isOwn
      ? (await userHasPermission(ctx.user.id, ctx.workspaceId || ctx.tenant?.id || 1, 'comment.delete_own', ctx.db, null, ctx.req) ||
         await userHasPermission(ctx.user.id, ctx.workspaceId || ctx.tenant?.id || 1, 'comment.delete_any', ctx.db, null, ctx.req))
      : await userHasPermission(ctx.user.id, ctx.workspaceId || ctx.tenant?.id || 1, 'comment.delete_any', ctx.db, null, ctx.req);

    if (!hasPerm && !isOwn) {
      const err = new Error('Permission denied to delete comment');
      err.status = 403;
      err.code = 'FORBIDDEN';
      throw err;
    }

    await commentService.deleteComment(ctx.db, {
      commentId,
      userId: ctx.user.id,
      originId: ctx.req.headers['x-origin-id'],
      tenantId: ctx.tenant?.id || null
    });
    return { message: 'Comment deleted' };
  }
});

registerOperation('comments.candidates', {
  permission: 'comment.view',
  schema: z.object({
    card_id: z.coerce.number().positive(),
    query: z.string().optional().default(''),
    limit: z.coerce.number().max(50).optional().default(10)
  }),
  handler: async (ctx, data) => {
    const cardRows = await ctx.db.query(
      'SELECT l.board_id FROM cards c JOIN lists l ON c.list_id = l.id WHERE c.id = ?',
      [Number(data.card_id)]
    );
    if (!cardRows || cardRows.length === 0) {
      const err = new Error('Card not found');
      err.status = 404;
      err.code = 'NOT_FOUND';
      throw err;
    }
    const candidates = await commentService.searchMentionCandidates(ctx.db, {
      boardId: cardRows[0].board_id,
      query: data.query,
      limit: data.limit
    });
    return { candidates };
  }
});

// ============================================================================
// 8. NOTIFICATIONS
// ============================================================================
registerOperation('notifications.list', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/notifications', query: data });
  }
});

registerOperation('notifications.summary', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/notifications/summary' });
  }
});

registerOperation('notifications.unread_count', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/notifications/unread-count' });
  }
});

registerOperation('notifications.preferences.get', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/notifications/preferences' });
  }
});

registerOperation('notifications.preferences.update', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'PATCH', url: '/api/notifications/preferences', body: data });
  }
});

registerOperation('notifications.mutes.list', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/notifications/mutes' });
  }
});

registerOperation('notifications.mute', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/notifications/mute', body: data });
  }
});

registerOperation('notifications.unmute', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/notifications/unmute', body: data });
  }
});

registerOperation('notifications.mark_read', {
  schema: z.object({
    notification_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/notifications/${data.notification_id}/read` });
  }
});

registerOperation('notifications.mark_unread', {
  schema: z.object({
    notification_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/notifications/${data.notification_id}/unread` });
  }
});

registerOperation('notifications.mark_all_read', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'PATCH', url: '/api/notifications/read-all', body: data });
  }
});

registerOperation('notifications.board_mark_all_read', {
  schema: z.object({
    board_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'PATCH', url: `/api/notifications/board/${data.board_id}/read-all` });
  }
});

registerOperation('notifications.delete', {
  schema: z.object({
    notification_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/notifications/${data.notification_id}` });
  }
});

registerOperation('notifications.clear_read', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: '/api/notifications/clear/read' });
  }
});

// ============================================================================
// 9. INVITATIONS
// ============================================================================
registerOperation('invitations.list', {
  permission: 'member.invite',
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/invitations', query: data });
  }
});

registerOperation('invitations.create', {
  permission: 'member.invite',
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/invitations', body: data });
  }
});

registerOperation('invitations.verify', {
  requireAuth: false,
  schema: z.object({
    token: z.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/invitations/verify', query: { token: data.token } });
  }
});

registerOperation('invitations.accept', {
  requireAuth: false,
  schema: z.object({
    token: z.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/invitations/accept', body: data });
  }
});

registerOperation('invitations.regenerate', {
  permission: 'member.invite',
  schema: z.object({
    invitation_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/invitations/${data.invitation_id}/regenerate` });
  }
});

registerOperation('invitations.resend', {
  permission: 'member.invite',
  schema: z.object({
    invitation_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: `/api/invitations/${data.invitation_id}/resend` });
  }
});

registerOperation('invitations.delete', {
  permission: 'member.invite',
  schema: z.object({
    invitation_id: z.coerce.number().positive()
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/invitations/${data.invitation_id}` });
  }
});

// ============================================================================
// 10. ARCHIVE
// ============================================================================
registerOperation('archive.list', {
  permission: 'workspace.view',
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/archive', query: data });
  }
});

// ============================================================================
// 11. PUSH NOTIFICATIONS
// ============================================================================
registerOperation('push.subscriptions.list', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/push/subscriptions' });
  }
});

registerOperation('push.subscriptions.create', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/push/subscriptions', body: data });
  }
});

registerOperation('push.subscriptions.delete_current', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: '/api/push/subscriptions/current' });
  }
});

registerOperation('push.subscriptions.delete', {
  schema: z.object({
    id: z.coerce.string().min(1)
  }).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'DELETE', url: `/api/push/subscriptions/${data.id}` });
  }
});

registerOperation('push.test', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/push/test', body: data });
  }
});

// ============================================================================
// 12. PERMISSIONS
// ============================================================================
registerOperation('permissions.list', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/permissions' });
  }
});

registerOperation('permissions.me', {
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'GET', url: '/api/permissions/me' });
  }
});

// ============================================================================
// 13. FILES & PROTECTED DOWNLOADS
// ============================================================================
registerOperation('files.preview_token', {
  requireAuth: true,
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/files/preview-token', body: data });
  }
});

registerOperation('files.avatar', {
  requireAuth: true,
  schema: z.object({}).passthrough(),
  handler: async (ctx, data) => {
    return await dispatchInternal(ctx, { method: 'POST', url: '/api/files/avatar', body: data });
  }
});

registerOperation('files.download', {
  requireAuth: true,
  schema: z.object({
    file_id: z.coerce.number().optional(),
    attachment_id: z.coerce.number().optional(),
    file_path: z.string().optional(),
    tenant_id: z.coerce.number().optional()
  }).passthrough(),
  handler: async (ctx, data) => {
    let filePath = null;
    let fileName = 'download';
    let fileType = 'application/octet-stream';
    const tenantId = ctx.tenant?.id || 1;

    if (data.attachment_id || data.file_id) {
      const id = data.attachment_id || data.file_id;
      const rows = await ctx.db.query(
        `SELECT a.id, a.file_name, a.file_url, a.file_type, a.file_size_bytes,
                l.board_id, b.workspace_id
         FROM attachments a
         JOIN cards c ON a.card_id = c.id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE a.id = ?`,
        [id]
      );
      if (!rows || rows.length === 0) {
        const err = new Error('File not found');
        err.status = 404;
        err.code = 'NOT_FOUND';
        throw err;
      }
      const att = rows[0];
      const hasView = await userHasPermission(ctx.user.id, att.workspace_id, 'file.view', ctx.db, att.board_id)
        || await userHasPermission(ctx.user.id, att.workspace_id, 'attachment.view', ctx.db, att.board_id);
      if (!hasView) {
        const err = new Error('Access denied: attachment.view or file.view permission required');
        err.status = 403;
        err.code = 'FORBIDDEN';
        throw err;
      }
      filePath = att.file_url;
      fileName = att.file_name;
      fileType = att.file_type || fileType;
    } else if (data.file_path) {
      filePath = String(data.file_path).trim();

      // Strict authorization for file_path:
      // 1. Workspace icon check: workspaces/ws_:id_ or icon_url
      const wsMatch = filePath.match(/(?:^|\/)workspaces\/ws_(\d+)_/);
      if (wsMatch) {
        const wsId = Number(wsMatch[1]);
        const wsRows = await ctx.db.query('SELECT id, name, icon_url FROM workspaces WHERE id = ?', [wsId]);
        if (!wsRows || wsRows.length === 0) {
          const err = new Error('Workspace not found');
          err.status = 404;
          err.code = 'NOT_FOUND';
          throw err;
        }
        const hasWsView = await userHasPermission(ctx.user.id, wsId, 'workspace.view', ctx.db);
        if (!hasWsView) {
          const err = new Error('Access denied: workspace.view required');
          err.status = 403;
          err.code = 'FORBIDDEN';
          throw err;
        }
        fileName = `workspace_${wsId}_icon`;
        fileType = 'image/png';
      } else {
        // 2. Avatar check: any file in avatars/ directory
        const avatarMatch = filePath.match(/(?:^|\/)avatars\/([^/?#]+)/) || filePath.match(/(?:^|\/)(avatar_[^/?#]+)/);
        if (avatarMatch) {
          const userInTenant = await ctx.db.query('SELECT id FROM users WHERE id = ?', [ctx.user.id]);
          if (!userInTenant || userInTenant.length === 0) {
            const err = new Error('Access denied: member.view required');
            err.status = 403;
            err.code = 'FORBIDDEN';
            throw err;
          }
          fileName = path.basename(avatarMatch[1]);
          fileType = 'image/png';
        } else {
          // 3. Database attachment record check
          const attRows = await ctx.db.query(
            `SELECT a.id, a.file_name, a.file_url, a.file_type, a.file_size_bytes,
                    l.board_id, b.workspace_id
             FROM attachments a
             JOIN cards c ON a.card_id = c.id
             JOIN lists l ON c.list_id = l.id
             JOIN boards b ON l.board_id = b.id
             WHERE a.file_url = ? OR a.file_url LIKE ?`,
            [filePath, `%${filePath.replace(/^[/\\]+/, '')}`]
          );
          if (attRows && attRows.length > 0) {
            const att = attRows[0];
            const hasView = await userHasPermission(ctx.user.id, att.workspace_id, 'file.view', ctx.db, att.board_id)
              || await userHasPermission(ctx.user.id, att.workspace_id, 'attachment.view', ctx.db, att.board_id);
            if (!hasView) {
              const err = new Error('Access denied: attachment.view required');
              err.status = 403;
              err.code = 'FORBIDDEN';
              throw err;
            }
            fileName = att.file_name;
            fileType = att.file_type || fileType;
          } else {
            // Reject any arbitrary path without database ownership / permission
            const err = new Error('Access denied: Arbitrary file path not authorized');
            err.status = 403;
            err.code = 'FORBIDDEN';
            throw err;
          }
        }
      }
    } else {
      const err = new Error('File path or ID is required');
      err.status = 400;
      err.code = 'BAD_REQUEST';
      throw err;
    }

    const cleanSubpath = String(filePath)
      .replace(/^https?:\/\/[^\/]+/i, '')
      .split('?')[0]
      .replace(/^\/?(?:api\/)?(?:files|uploads)(?:\/\d+)?\//, '')
      .replace(/^[/\\]+/, '');

    if (cleanSubpath.includes('..') || path.isAbsolute(cleanSubpath)) {
      const err = new Error('Invalid file path');
      err.status = 400;
      err.code = 'INVALID_PATH';
      throw err;
    }

    const pathTenantMatch = String(filePath).match(/(?:\/api\/files\/|\/uploads\/)(\d+)\//);
    const effectiveTenantId = pathTenantMatch ? Number(pathTenantMatch[1]) : tenantId;

    const { resolveUploadFilePath } = require('../routes/files');
    const finalPath = resolveUploadFilePath(effectiveTenantId, cleanSubpath);

    if (!finalPath || !fs.existsSync(finalPath)) {
      console.warn(`[FILES_DOWNLOAD_NOT_FOUND] Tenant ${effectiveTenantId}, subpath: ${cleanSubpath}, resolved: ${finalPath}`);
      const err = new Error('File not found on storage');
      err.status = 404;
      err.code = 'NOT_FOUND';
      throw err;
    }

    const ext = path.extname(finalPath).toLowerCase();
    const mimeMap = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.webp': 'image/webp',
      '.gif': 'image/gif',
      '.svg': 'image/svg+xml',
      '.pdf': 'application/pdf',
      '.csv': 'text/csv'
    };
    if (mimeMap[ext]) {
      fileType = mimeMap[ext];
    }

    const buffer = fs.readFileSync(finalPath);
    return {
      file_name: fileName,
      file_type: fileType,
      file_size_bytes: buffer.length,
      data_base64: buffer.toString('base64')
    };
  }
});

function getOperation(name) {
  return registry.get(name) || null;
}

function getAllOperationNames() {
  return Array.from(registry.keys());
}

module.exports = {
  registry,
  registerOperation,
  getOperation,
  getAllOperationNames
};

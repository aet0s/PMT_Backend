// client/src/api/operationMapper.js
// Deterministic mapper converting legacy REST URLs and methods to explicit registered business operations.
// Eliminates dynamic endpoint dispatch and extracts path parameters into structured data.

function mapUrlToOperation(rawUrl, rawMethod = 'GET', initialData = {}) {
  const method = rawMethod.toUpperCase();
  let url = rawUrl;
  let queryParams = {};

  // Extract query string
  const qIdx = url.indexOf('?');
  if (qIdx !== -1) {
    const qs = url.substring(qIdx + 1);
    const searchParams = new URLSearchParams(qs);
    for (const [key, val] of searchParams.entries()) {
      queryParams[key] = val;
    }
    url = url.substring(0, qIdx);
  }

  // Remove leading /api if present
  let path = url;
  if (path.startsWith('/api/')) {
    path = path.substring(4);
  } else if (path.startsWith('/api')) {
    path = '/';
  } else if (!path.startsWith('/')) {
    path = '/' + path;
  }

  const mergedData = { ...queryParams, ...(initialData || {}) };

  // If already an operation name (e.g. 'workspaces.list' or starts with a domain prefix)
  if (!rawUrl.startsWith('/') && !rawUrl.startsWith('http') && rawUrl.includes('.')) {
    return { operation: rawUrl, data: mergedData };
  }

  // --- 1. AUTH ---
  if (path === '/auth/login' && method === 'POST') return { operation: 'auth.login', data: mergedData };
  if (path === '/auth/register' && method === 'POST') return { operation: 'auth.register', data: mergedData };
  if (path === '/auth/register-company' && method === 'POST') return { operation: 'auth.register_company', data: mergedData };
  if (path === '/auth/register/send-otp' && method === 'POST') return { operation: 'auth.register.send_otp', data: mergedData };
  if (path === '/auth/register/verify-otp' && method === 'POST') return { operation: 'auth.register.verify_otp', data: mergedData };
  if (path === '/auth/verify-registration' && method === 'POST') return { operation: 'auth.verify_registration', data: mergedData };
  if (path === '/auth/check-email' && method === 'GET') return { operation: 'auth.check_email', data: mergedData };
  if (path === '/auth/refresh' && method === 'POST') return { operation: 'auth.refresh', data: mergedData };
  if (path === '/auth/logout' && method === 'POST') return { operation: 'auth.logout', data: mergedData };
  if (path === '/auth/logout-all' && method === 'POST') return { operation: 'auth.logout_all', data: mergedData };
  if (path === '/auth/me' && method === 'GET') return { operation: 'auth.me', data: mergedData };
  if (path === '/auth/profile' && (method === 'PUT' || method === 'PATCH')) return { operation: 'auth.profile.update', data: mergedData };
  if ((path === '/auth/password' || path === '/auth/change-password') && (method === 'PUT' || method === 'POST')) return { operation: 'auth.password.update', data: mergedData };
  if (path === '/auth/forgot-password/send-otp' && method === 'POST') return { operation: 'auth.forgot_password.send_otp', data: mergedData };
  if (path === '/auth/forgot-password/verify-otp' && method === 'POST') return { operation: 'auth.forgot_password.verify_otp', data: mergedData };
  if (path === '/auth/forgot-password/verify-token' && method === 'POST') return { operation: 'auth.forgot_password.verify_token', data: mergedData };
  if (path === '/auth/forgot-password/reset' && method === 'POST') return { operation: 'auth.forgot_password.reset', data: mergedData };
  if (path === '/auth/2fa/verify-login' && method === 'POST') return { operation: 'auth.2fa.verify_login', data: mergedData };
  if (path === '/auth/2fa/status' && method === 'GET') return { operation: 'auth.2fa.status', data: mergedData };
  if ((path === '/auth/2fa/generate' || path === '/auth/2fa/setup') && method === 'POST') return { operation: 'auth.2fa.generate', data: mergedData };
  if ((path === '/auth/2fa/confirm' || path === '/auth/2fa/verify') && method === 'POST') return { operation: 'auth.2fa.confirm', data: mergedData };
  if (path === '/auth/2fa/disable' && method === 'POST') return { operation: 'auth.2fa.disable', data: mergedData };
  if (path === '/auth/sessions' && method === 'GET') return { operation: 'auth.sessions.list', data: mergedData };
  if (path.startsWith('/auth/sessions/') && method === 'DELETE') {
    const sessionId = path.substring('/auth/sessions/'.length);
    return { operation: 'auth.sessions.revoke', data: { ...mergedData, session_id: sessionId } };
  }
  if (path === '/auth/sessions/revoke-others' && method === 'POST') return { operation: 'auth.sessions.revoke_others', data: mergedData };
  if (path === '/auth/activity' && method === 'GET') return { operation: 'auth.activity', data: mergedData };

  // --- 2. WORKSPACES ---
  if (path === '/workspaces' && method === 'GET') return { operation: 'workspaces.list', data: mergedData };
  if (path === '/workspaces' && method === 'POST') return { operation: 'workspaces.create', data: mergedData };

  let m = path.match(/^\/workspaces\/([^/]+)$/);
  if (m) {
    const wsId = m[1];
    if (method === 'GET') return { operation: 'workspaces.get', data: { ...mergedData, workspace_id: wsId } };
    if (method === 'PATCH' || method === 'PUT') return { operation: 'workspaces.update', data: { ...mergedData, workspace_id: wsId } };
    if (method === 'DELETE') return { operation: 'workspaces.delete', data: { ...mergedData, workspace_id: wsId } };
  }

  m = path.match(/^\/workspaces\/([^/]+)\/my-permissions$/);
  if (m) return { operation: 'workspaces.my_permissions', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/members$/);
  if (m) {
    if (method === 'GET') return { operation: 'workspaces.members.list', data: { ...mergedData, workspace_id: m[1] } };
    if (method === 'POST') return { operation: 'workspaces.members.add', data: { ...mergedData, workspace_id: m[1] } };
  }

  m = path.match(/^\/workspaces\/([^/]+)\/members\/([^/]+)\/role$/);
  if (m) return { operation: 'workspaces.members.update_role', data: { ...mergedData, workspace_id: m[1], user_id: m[2] } };

  m = path.match(/^\/workspaces\/([^/]+)\/members\/([^/]+)$/);
  if (m && method === 'DELETE') return { operation: 'workspaces.members.remove', data: { ...mergedData, workspace_id: m[1], user_id: m[2] } };

  m = path.match(/^\/workspaces\/([^/]+)\/members\/([^/]+)\/deactivate$/);
  if (m) return { operation: 'workspaces.members.deactivate', data: { ...mergedData, workspace_id: m[1], user_id: m[2] } };

  m = path.match(/^\/workspaces\/([^/]+)\/members\/([^/]+)\/reactivate$/);
  if (m) return { operation: 'workspaces.members.reactivate', data: { ...mergedData, workspace_id: m[1], user_id: m[2] } };

  m = path.match(/^\/workspaces\/([^/]+)\/members\/([^/]+)\/reset-password$/);
  if (m) return { operation: 'workspaces.members.reset_password', data: { ...mergedData, workspace_id: m[1], user_id: m[2] } };

  m = path.match(/^\/workspaces\/([^/]+)\/members\/([^/]+)\/reset-2fa$/);
  if (m) return { operation: 'workspaces.members.reset_2fa', data: { ...mergedData, workspace_id: m[1], user_id: m[2] } };

  m = path.match(/^\/workspaces\/([^/]+)\/roles$/);
  if (m) {
    if (method === 'GET') return { operation: 'workspaces.roles.list', data: { ...mergedData, workspace_id: m[1] } };
    if (method === 'POST') return { operation: 'workspaces.roles.create', data: { ...mergedData, workspace_id: m[1] } };
  }

  m = path.match(/^\/roles\/([^/]+)$/);
  if (m) {
    if (method === 'PATCH' || method === 'PUT') return { operation: 'workspaces.roles.update', data: { ...mergedData, role_id: m[1] } };
    if (method === 'DELETE') return { operation: 'workspaces.roles.delete', data: { ...mergedData, role_id: m[1] } };
  }

  m = path.match(/^\/roles\/([^/]+)\/reset-default$/);
  if (m) return { operation: 'workspaces.roles.reset_default', data: { ...mergedData, role_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/activity$/);
  if (m) return { operation: 'workspaces.activity', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/reports$/);
  if (m) return { operation: 'workspaces.reports', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/company-members$/);
  if (m) return { operation: 'workspaces.company_members.list', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/company-members\/([^/]+)\/role$/);
  if (m) return { operation: 'workspaces.company_members.update_role', data: { ...mergedData, workspace_id: m[1], user_id: m[2] } };

  m = path.match(/^\/workspaces\/([^/]+)\/company-members\/([^/]+)\/workspaces$/);
  if (m) return { operation: 'workspaces.company_members.assign_workspaces', data: { ...mergedData, workspace_id: m[1], user_id: m[2] } };

  m = path.match(/^\/workspaces\/([^/]+)\/company-members\/([^/]+)\/boards$/);
  if (m) return { operation: 'workspaces.company_members.assign_boards', data: { ...mergedData, workspace_id: m[1], user_id: m[2] } };

  m = path.match(/^\/workspaces\/([^/]+)\/company-members\/([^/]+)$/);
  if (m && method === 'DELETE') return { operation: 'workspaces.company_members.remove', data: { ...mergedData, workspace_id: m[1], user_id: m[2] } };

  m = path.match(/^\/workspaces\/([^/]+)\/company-members\/([^/]+)\/credentials$/);
  if (m) return { operation: 'workspaces.company_members.update_credentials', data: { ...mergedData, workspace_id: m[1], user_id: m[2] } };

  m = path.match(/^\/workspaces\/([^/]+)\/daily-tracker$/);
  if (m) return { operation: 'workspaces.daily_tracker', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/daily-tracker\/people$/);
  if (m) return { operation: 'workspaces.daily_tracker_people', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/leave-days$/);
  if (m) {
    if (method === 'GET') return { operation: 'workspaces.leave_days.list', data: { ...mergedData, workspace_id: m[1] } };
    if (method === 'POST') return { operation: 'workspaces.leave_days.create', data: { ...mergedData, workspace_id: m[1] } };
  }

  m = path.match(/^\/workspaces\/([^/]+)\/leave-days\/([^/]+)$/);
  if (m) {
    if (method === 'PATCH' || method === 'PUT') return { operation: 'workspaces.leave_days.update', data: { ...mergedData, workspace_id: m[1], leave_id: m[2] } };
    if (method === 'DELETE') return { operation: 'workspaces.leave_days.delete', data: { ...mergedData, workspace_id: m[1], leave_id: m[2] } };
  }

  m = path.match(/^\/workspaces\/([^/]+)\/checkins\/pending$/);
  if (m) return { operation: 'workspaces.checkins_pending', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/audit-events$/);
  if (m) return { operation: 'workspaces.audit_events.list', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/audit-events\/facets$/);
  if (m) return { operation: 'workspaces.audit_events.facets', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/audit-events\/verify$/);
  if (m) return { operation: 'workspaces.audit_events.verify', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/audit-events\/export$/);
  if (m) return { operation: 'workspaces.audit_events.export', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/audit-events\/([^/]+)$/);
  if (m) return { operation: 'workspaces.audit_events.get', data: { ...mergedData, workspace_id: m[1], event_id: m[2] } };

  m = path.match(/^\/workspaces\/([^/]+)\/audit$/);
  if (m) return { operation: 'workspaces.audit.list', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/audit\/export$/);
  if (m) return { operation: 'workspaces.audit.export', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/my-tasks$/);
  if (m) return { operation: 'workspaces.my_tasks', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/issues$/);
  if (m) return { operation: 'workspaces.issues', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/search$/);
  if (m) return { operation: 'workspaces.search', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/icon$/);
  if (m) {
    if (method === 'POST') return { operation: 'workspaces.icon.set', data: { ...mergedData, workspace_id: m[1] } };
    if (method === 'DELETE') return { operation: 'workspaces.icon.remove', data: { ...mergedData, workspace_id: m[1] } };
  }

  m = path.match(/^\/workspaces\/([^/]+)\/auto-archive$/);
  if (m) return { operation: 'workspaces.auto_archive', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/invitations$/);
  if (m) {
    if (method === 'GET') return { operation: 'workspaces.invitations.list', data: { ...mergedData, workspace_id: m[1] } };
    if (method === 'POST') return { operation: 'workspaces.invitations.create', data: { ...mergedData, workspace_id: m[1] } };
  }

  m = path.match(/^\/workspaces\/([^/]+)\/archived$/);
  if (m) return { operation: 'workspaces.archived', data: { ...mergedData, workspace_id: m[1] } };

  m = path.match(/^\/workspaces\/([^/]+)\/security$/);
  if (m) {
    if (method === 'GET') return { operation: 'workspaces.security.get', data: { ...mergedData, workspace_id: m[1] } };
    if (method === 'PATCH' || method === 'PUT') return { operation: 'workspaces.security.update', data: { ...mergedData, workspace_id: m[1] } };
  }

  // --- 3. BOARDS ---
  if (path === '/boards' && method === 'GET') return { operation: 'boards.list', data: mergedData };
  if (path === '/boards' && method === 'POST') return { operation: 'boards.create', data: mergedData };

  m = path.match(/^\/boards\/([^/]+)$/);
  if (m) {
    const bId = m[1];
    if (method === 'GET') return { operation: 'boards.get', data: { ...mergedData, board_id: bId } };
    if (method === 'PATCH' || method === 'PUT') return { operation: 'boards.update', data: { ...mergedData, board_id: bId } };
    if (method === 'DELETE') return { operation: 'boards.delete', data: { ...mergedData, board_id: bId } };
  }

  m = path.match(/^\/boards\/([^/]+)\/archive$/);
  if (m) return { operation: 'boards.archive', data: { ...mergedData, board_id: m[1] } };

  m = path.match(/^\/boards\/([^/]+)\/restore$/);
  if (m) return { operation: 'boards.restore', data: { ...mergedData, board_id: m[1] } };

  m = path.match(/^\/boards\/([^/]+)\/archived$/);
  if (m) return { operation: 'boards.archived', data: { ...mergedData, board_id: m[1] } };

  m = path.match(/^\/boards\/([^/]+)\/members$/);
  if (m) {
    if (method === 'GET') return { operation: 'boards.members.list', data: { ...mergedData, board_id: m[1] } };
    if (method === 'POST') return { operation: 'boards.members.add', data: { ...mergedData, board_id: m[1] } };
  }

  m = path.match(/^\/boards\/([^/]+)\/members\/([^/]+)\/role$/);
  if (m) return { operation: 'boards.members.update_role', data: { ...mergedData, board_id: m[1], user_id: m[2] } };

  m = path.match(/^\/boards\/([^/]+)\/members\/([^/]+)$/);
  if (m && method === 'DELETE') return { operation: 'boards.members.remove', data: { ...mergedData, board_id: m[1], user_id: m[2] } };

  m = path.match(/^\/boards\/([^/]+)\/workspace-members$/);
  if (m) return { operation: 'boards.workspace_members', data: { ...mergedData, board_id: m[1] } };

  m = path.match(/^\/boards\/([^/]+)\/mention-candidates$/);
  if (m) return { operation: 'boards.mention_candidates', data: { ...mergedData, board_id: m[1] } };

  m = path.match(/^\/boards\/([^/]+)\/labels$/);
  if (m) {
    if (method === 'GET') return { operation: 'boards.labels.list', data: { ...mergedData, board_id: m[1] } };
    if (method === 'POST') return { operation: 'boards.labels.create', data: { ...mergedData, board_id: m[1] } };
  }

  m = path.match(/^\/boards\/([^/]+)\/labels\/([^/]+)$/);
  if (m) {
    if (method === 'PATCH' || method === 'PUT') return { operation: 'boards.labels.update', data: { ...mergedData, board_id: m[1], label_id: m[2] } };
    if (method === 'DELETE') return { operation: 'boards.labels.delete', data: { ...mergedData, board_id: m[1], label_id: m[2] } };
  }

  m = path.match(/^\/boards\/([^/]+)\/attachments$/);
  if (m) return { operation: 'boards.attachments', data: { ...mergedData, board_id: m[1] } };

  // --- 4. LISTS ---
  if (path === '/lists' && method === 'POST') return { operation: 'lists.create', data: mergedData };
  m = path.match(/^\/lists\/([^/]+)$/);
  if (m) {
    if (method === 'PATCH' || method === 'PUT') return { operation: 'lists.update', data: { ...mergedData, list_id: m[1] } };
    if (method === 'DELETE') return { operation: 'lists.delete', data: { ...mergedData, list_id: m[1] } };
  }

  // --- 5. CARDS & COMMENTS ---
  m = path.match(/^\/cards\/([^/]+)\/comments$/);
  if (m) {
    if (method === 'GET') return { operation: 'comments.list', data: { ...mergedData, card_id: m[1] } };
    if (method === 'POST') return { operation: 'comments.create', data: { ...mergedData, card_id: m[1] } };
  }

  m = path.match(/^\/cards\/comments\/([^/]+)$/);
  if (m) {
    if (method === 'PATCH' || method === 'PUT') return { operation: 'comments.update', data: { ...mergedData, comment_id: m[1] } };
    if (method === 'DELETE') return { operation: 'comments.delete', data: { ...mergedData, comment_id: m[1] } };
  }

  m = path.match(/^\/cards\/([^/]+)\/mention-candidates$/);
  if (m) return { operation: 'comments.candidates', data: { ...mergedData, card_id: m[1] } };

  if (path === '/cards' && method === 'POST') return { operation: 'cards.create', data: mergedData };

  m = path.match(/^\/cards\/([^/]+)$/);
  if (m) {
    const cId = m[1];
    if (method === 'GET') return { operation: 'cards.get', data: { ...mergedData, card_id: cId } };
    if (method === 'PATCH' || method === 'PUT') return { operation: 'cards.update', data: { ...mergedData, card_id: cId } };
    if (method === 'DELETE') return { operation: 'cards.delete', data: { ...mergedData, card_id: cId } };
  }

  m = path.match(/^\/cards\/([^/]+)\/labels$/);
  if (m) return { operation: 'cards.labels.assign', data: { ...mergedData, card_id: m[1] } };

  m = path.match(/^\/cards\/([^/]+)\/assigners$/);
  if (m) return { operation: 'cards.assigners.assign', data: { ...mergedData, card_id: m[1] } };

  m = path.match(/^\/cards\/([^/]+)\/members$/);
  if (m) return { operation: 'cards.members.assign', data: { ...mergedData, card_id: m[1] } };

  m = path.match(/^\/cards\/([^/]+)\/copy$/);
  if (m) return { operation: 'cards.copy', data: { ...mergedData, card_id: m[1] } };

  m = path.match(/^\/cards\/([^/]+)\/attachments$/);
  if (m) {
    if (method === 'GET') return { operation: 'cards.attachments.list', data: { ...mergedData, card_id: m[1] } };
    if (method === 'POST') return { operation: 'cards.attachments.create', data: { ...mergedData, card_id: m[1] } };
  }

  m = path.match(/^\/cards\/([^/]+)\/attachments\/file$/);
  if (m) return { operation: 'cards.attachments.file', data: { ...mergedData, card_id: m[1] } };

  m = path.match(/^\/cards\/([^/]+)\/attachments\/link$/);
  if (m) return { operation: 'cards.attachments.link', data: { ...mergedData, card_id: m[1] } };

  m = path.match(/^\/cards\/attachments\/([^/]+)$/);
  if (m && method === 'DELETE') return { operation: 'cards.attachments.delete', data: { ...mergedData, attachment_id: m[1] } };

  m = path.match(/^\/cards\/([^/]+)\/checklists$/);
  if (m) {
    if (method === 'GET') return { operation: 'cards.checklists.list', data: { ...mergedData, card_id: m[1] } };
    if (method === 'POST') return { operation: 'cards.checklists.create', data: { ...mergedData, card_id: m[1] } };
  }

  m = path.match(/^\/cards\/checklists\/([^/]+)$/);
  if (m && method === 'DELETE') return { operation: 'cards.checklists.delete', data: { ...mergedData, checklist_id: m[1] } };

  if (path === '/cards/checklist-items' && method === 'POST') return { operation: 'cards.checklists.items.create', data: mergedData };
  m = path.match(/^\/cards\/checklist-items\/([^/]+)$/);
  if (m) {
    if (method === 'PATCH' || method === 'PUT') return { operation: 'cards.checklists.items.update', data: { ...mergedData, item_id: m[1] } };
    if (method === 'DELETE') return { operation: 'cards.checklists.items.delete', data: { ...mergedData, item_id: m[1] } };
  }

  m = path.match(/^\/cards\/([^/]+)\/checkins$/);
  if (m) {
    if (method === 'GET') return { operation: 'cards.checkins.list', data: { ...mergedData, card_id: m[1] } };
    if (method === 'POST') return { operation: 'cards.checkins.create', data: { ...mergedData, card_id: m[1] } };
  }

  m = path.match(/^\/cards\/([^/]+)\/checkins\/([^/]+)$/);
  if (m && (method === 'PATCH' || method === 'PUT')) return { operation: 'cards.checkins.update', data: { ...mergedData, card_id: m[1], checkin_id: m[2] } };

  m = path.match(/^\/checkins\/([^/]+)\/review$/);
  if (m) return { operation: 'cards.checkins.review', data: { ...mergedData, checkin_id: m[1] } };

  m = path.match(/^\/checkin-reviews\/([^/]+)\/answer$/);
  if (m) return { operation: 'cards.checkins.answer', data: { ...mergedData, review_id: m[1] } };

  // --- 6. NOTIFICATIONS ---
  if (path === '/notifications' && method === 'GET') return { operation: 'notifications.list', data: mergedData };
  if (path === '/notifications/summary' && method === 'GET') return { operation: 'notifications.summary', data: mergedData };
  if (path === '/notifications/unread-count' && method === 'GET') return { operation: 'notifications.unread_count', data: mergedData };
  if (path === '/notifications/preferences' && method === 'GET') return { operation: 'notifications.preferences.get', data: mergedData };
  if (path === '/notifications/preferences' && (method === 'PATCH' || method === 'PUT')) return { operation: 'notifications.preferences.update', data: mergedData };
  if (path === '/notifications/mutes' && method === 'GET') return { operation: 'notifications.mutes.list', data: mergedData };
  if (path === '/notifications/mute' && method === 'POST') return { operation: 'notifications.mute', data: mergedData };
  if (path === '/notifications/unmute' && method === 'POST') return { operation: 'notifications.unmute', data: mergedData };
  if (path === '/notifications/read-all' && (method === 'PATCH' || method === 'POST')) return { operation: 'notifications.mark_all_read', data: mergedData };
  if (path === '/notifications/clear/read' && method === 'DELETE') return { operation: 'notifications.clear_read', data: mergedData };

  m = path.match(/^\/notifications\/board\/([^/]+)\/read-all$/);
  if (m) return { operation: 'notifications.board_mark_all_read', data: { ...mergedData, board_id: m[1] } };

  m = path.match(/^\/notifications\/([^/]+)\/read$/);
  if (m) return { operation: 'notifications.mark_read', data: { ...mergedData, notification_id: m[1] } };

  m = path.match(/^\/notifications\/([^/]+)\/unread$/);
  if (m) return { operation: 'notifications.mark_unread', data: { ...mergedData, notification_id: m[1] } };

  m = path.match(/^\/notifications\/([^/]+)$/);
  if (m && method === 'DELETE') return { operation: 'notifications.delete', data: { ...mergedData, notification_id: m[1] } };

  // --- 7. INVITATIONS ---
  if (path === '/invitations' && method === 'GET') return { operation: 'invitations.list', data: mergedData };
  if (path === '/invitations' && method === 'POST') return { operation: 'invitations.create', data: mergedData };
  if (path === '/invitations/verify' && (method === 'GET' || method === 'POST')) return { operation: 'invitations.verify', data: mergedData };
  if (path === '/invitations/accept' && method === 'POST') return { operation: 'invitations.accept', data: mergedData };

  m = path.match(/^\/invitations\/([^/]+)\/regenerate$/);
  if (m) return { operation: 'invitations.regenerate', data: { ...mergedData, invitation_id: m[1] } };

  m = path.match(/^\/invitations\/([^/]+)\/resend$/);
  if (m) return { operation: 'invitations.resend', data: { ...mergedData, invitation_id: m[1] } };

  m = path.match(/^\/invitations\/([^/]+)$/);
  if (m && method === 'DELETE') return { operation: 'invitations.delete', data: { ...mergedData, invitation_id: m[1] } };

  // --- 8. ARCHIVE ---
  if (path === '/archive' && method === 'GET') return { operation: 'archive.list', data: mergedData };

  // --- 9. PUSH ---
  if (path === '/push/subscriptions' && method === 'GET') return { operation: 'push.subscriptions.list', data: mergedData };
  if (path === '/push/subscriptions' && method === 'POST') return { operation: 'push.subscriptions.create', data: mergedData };
  if (path === '/push/subscriptions/current' && method === 'DELETE') return { operation: 'push.subscriptions.delete_current', data: mergedData };
  m = path.match(/^\/push\/subscriptions\/([^/]+)$/);
  if (m && method === 'DELETE') return { operation: 'push.subscriptions.delete', data: { ...mergedData, id: m[1] } };
  if (path === '/push/test' && method === 'POST') return { operation: 'push.test', data: mergedData };

  // --- 10. PERMISSIONS ---
  if (path === '/permissions' && method === 'GET') return { operation: 'permissions.list', data: mergedData };
  if (path === '/permissions/me' && method === 'GET') return { operation: 'permissions.me', data: mergedData };

  // --- 11. FILES ---
  if (path === '/files/preview-token' && method === 'POST') return { operation: 'files.preview_token', data: mergedData };
  if (path === '/files/avatar' && method === 'POST') return { operation: 'files.avatar', data: mergedData };
  if (path === '/files/download' && method === 'POST') return { operation: 'files.download', data: mergedData };

  // Fallback: clean normalized operation name if not matched (strictly fails closed if unmapped)
  const cleanOp = path.replace(/^\/+/, '').replace(/\//g, '.');
  return { operation: cleanOp || 'unmapped.operation', data: mergedData };
}

module.exports = { mapUrlToOperation };

// server/src/scripts/permcheck/operations.js
// Operation catalogue mapping every testable permission to its executable HTTP request.
// Reuses fixtures and matches client/src payload shapes and route registry.

const OPERATIONS = {
  // === WORKSPACE MODULE ===
  'workspace.view': {
    module: 'workspace',
    scope: 'company',
    name: 'GET /api/workspaces/:id',
    execute: async (client, ctx) => client.get(`/api/workspaces/${ctx.workspaceId}`)
  },
  'workspace.create': {
    module: 'workspace',
    scope: 'company',
    name: 'POST /api/workspaces',
    execute: async (client, ctx) => client.post('/api/workspaces', { name: `zz-permtest-ws-${Date.now()}` })
  },
  'workspace.edit': {
    module: 'workspace',
    scope: 'company',
    name: 'PATCH /api/workspaces/:id',
    execute: async (client, ctx) => client.patch(`/api/workspaces/${ctx.workspaceId}`, { name: `zz-permtest-ws-edit-${Date.now()}` })
  },
  'workspace.archive': {
    module: 'workspace',
    scope: 'company',
    name: 'POST /api/workspaces/:id/auto-archive',
    execute: async (client, ctx) => client.post(`/api/workspaces/${ctx.workspaceId}/auto-archive`, { days: 14 })
  },
  'workspace.delete': {
    module: 'workspace',
    scope: 'company',
    name: 'DELETE /api/workspaces/:subWsId',
    execute: async (client, ctx) => client.delete(`/api/workspaces/${ctx.deletableWorkspaceId}`)
  },

  // === MEMBER MODULE ===
  'member.view': {
    module: 'member',
    scope: 'company',
    name: 'GET /api/workspaces/:id/members',
    execute: async (client, ctx) => client.get(`/api/workspaces/${ctx.workspaceId}/members`)
  },
  'member.invite': {
    module: 'member',
    scope: 'company',
    name: 'POST /api/invitations',
    execute: async (client, ctx) => client.post('/api/invitations', {
      email: `zz-permtest-invite-${Date.now()}@example.com`,
      workspace_id: ctx.workspaceId,
      board_ids: [ctx.boardId]
    })
  },
  'member.assign_role': {
    module: 'member',
    scope: 'company',
    name: 'PATCH /api/workspaces/:id/members/:userId/role',
    execute: async (client, ctx) => client.patch(`/api/workspaces/${ctx.workspaceId}/members/${ctx.targetUserId}/role`, {
      role_id: ctx.viewerRoleId
    })
  },
  'member.reset_password': {
    module: 'member',
    scope: 'company',
    name: 'POST /api/workspaces/:id/members/:userId/reset-password',
    execute: async (client, ctx) => client.post(`/api/workspaces/${ctx.workspaceId}/members/${ctx.targetUserId}/reset-password`, {
      new_password: 'CompliantPass123!@#'
    })
  },
  'member.reset_2fa': {
    module: 'member',
    scope: 'company',
    name: 'POST /api/auth/admin/reset-2fa',
    execute: async (client, ctx) => client.post('/api/auth/admin/reset-2fa', {
      user_id: ctx.targetUserId,
      workspace_id: ctx.workspaceId
    })
  },
  'member.remove': {
    module: 'member',
    scope: 'company',
    name: 'DELETE /api/workspaces/:id/members/:userId',
    execute: async (client, ctx) => client.delete(`/api/workspaces/${ctx.workspaceId}/members/${ctx.removableUserId}`)
  },

  // === ROLE MODULE ===
  'role.view': {
    module: 'role',
    scope: 'company',
    name: 'GET /api/workspaces/:id/roles',
    execute: async (client, ctx) => client.get(`/api/workspaces/${ctx.workspaceId}/roles`)
  },
  'role.create': {
    module: 'role',
    scope: 'company',
    name: 'POST /api/workspaces/:id/roles',
    execute: async (client, ctx) => client.post(`/api/workspaces/${ctx.workspaceId}/roles`, {
      name: `zz-permtest-role-${Date.now()}`,
      permission_keys: ['workspace.view']
    })
  },
  'role.edit': {
    module: 'role',
    scope: 'company',
    name: 'PATCH /api/roles/:id',
    execute: async (client, ctx) => client.patch(`/api/roles/${ctx.deletableRoleId}`, {
      name: `zz-permtest-role-renamed-${Date.now()}`
    })
  },
  'role.delete': {
    module: 'role',
    scope: 'company',
    name: 'DELETE /api/roles/:id',
    execute: async (client, ctx) => client.delete(`/api/roles/${ctx.deletableRoleId}`)
  },
  'role.assign': {
    module: 'role',
    scope: 'company',
    name: 'PATCH /api/workspaces/:id/members/:userId/role (role.assign)',
    execute: async (client, ctx) => client.patch(`/api/workspaces/${ctx.workspaceId}/members/${ctx.targetUserId}/role`, {
      role_id: ctx.viewerRoleId
    })
  },

  // === PROJECT MODULE ===
  'project.view': {
    module: 'project',
    scope: 'project',
    name: 'GET /api/boards/:id',
    execute: async (client, ctx) => client.get(`/api/boards/${ctx.boardId}`)
  },
  'project.create': {
    module: 'project',
    scope: 'company',
    name: 'POST /api/boards',
    execute: async (client, ctx) => client.post('/api/boards', {
      workspace_id: ctx.workspaceId,
      name: `zz-permtest-board-${Date.now()}`
    })
  },
  'project.edit_settings': {
    module: 'project',
    scope: 'project',
    name: 'PATCH /api/boards/:id',
    execute: async (client, ctx) => client.patch(`/api/boards/${ctx.boardId}`, {
      name: `zz-permtest-board-edit-${Date.now()}`
    })
  },
  'project.archive': {
    module: 'project',
    scope: 'project',
    name: 'PATCH /api/boards/:id (archive)',
    execute: async (client, ctx) => client.patch(`/api/boards/${ctx.boardId}`, {
      is_archived: true
    })
  },
  'project.delete': {
    module: 'project',
    scope: 'project',
    name: 'DELETE /api/boards/:id',
    execute: async (client, ctx) => client.delete(`/api/boards/${ctx.deletableBoardId}`)
  },
  'project.manage_members': {
    module: 'project',
    scope: 'project',
    name: 'POST /api/boards/:id/members',
    execute: async (client, ctx) => client.post(`/api/boards/${ctx.boardId}/members`, {
      user_id: ctx.targetUserId,
      role: 'member'
    })
  },

  // === LIST MODULE ===
  'list.create': {
    module: 'list',
    scope: 'project',
    name: 'POST /api/lists',
    execute: async (client, ctx) => client.post('/api/lists', {
      board_id: ctx.boardId,
      name: `zz-permtest-list-${Date.now()}`
    })
  },
  'list.edit': {
    module: 'list',
    scope: 'project',
    name: 'PATCH /api/lists/:id',
    execute: async (client, ctx) => client.patch(`/api/lists/${ctx.listId}`, {
      name: `zz-permtest-list-renamed-${Date.now()}`
    })
  },
  'list.reorder': {
    module: 'list',
    scope: 'project',
    name: 'PATCH /api/lists/:id (reorder)',
    execute: async (client, ctx) => client.patch(`/api/lists/${ctx.listId}`, {
      position: 5000
    })
  },
  'list.delete': {
    module: 'list',
    scope: 'project',
    name: 'DELETE /api/lists/:id',
    execute: async (client, ctx) => client.delete(`/api/lists/${ctx.deletableListId}`)
  },

  // === TASK MODULE ===
  'task.view': {
    module: 'task',
    scope: 'project',
    name: 'GET /api/cards/:id',
    execute: async (client, ctx) => client.get(`/api/cards/${ctx.cardId}`)
  },
  'task.create': {
    module: 'task',
    scope: 'project',
    name: 'POST /api/cards',
    execute: async (client, ctx) => client.post('/api/cards', {
      list_id: ctx.listId,
      title: `zz-permtest-card-${Date.now()}`
    })
  },
  'task.edit': {
    module: 'task',
    scope: 'project',
    name: 'PATCH /api/cards/:id',
    execute: async (client, ctx) => client.patch(`/api/cards/${ctx.cardId}`, {
      title: `zz-permtest-card-renamed-${Date.now()}`
    })
  },
  'task.move': {
    module: 'task',
    scope: 'project',
    name: 'PATCH /api/cards/:id (move)',
    execute: async (client, ctx) => client.patch(`/api/cards/${ctx.cardId}`, {
      position: 7500
    })
  },
  'task.assign': {
    module: 'task',
    scope: 'project',
    name: 'POST /api/cards/:id/members',
    execute: async (client, ctx) => client.post(`/api/cards/${ctx.cardId}/members`, {
      user_id: ctx.targetUserId
    })
  },
  'task.duplicate': {
    module: 'task',
    scope: 'project',
    name: 'POST /api/cards/:id/copy',
    execute: async (client, ctx) => client.post(`/api/cards/${ctx.cardId}/copy`, {
      list_id: ctx.listId,
      title: `Copied Card ${Date.now()}`
    })
  },
  'task.archive': {
    module: 'task',
    scope: 'project',
    name: 'PATCH /api/cards/:id (archive)',
    execute: async (client, ctx) => client.patch(`/api/cards/${ctx.cardId}`, {
      is_archived: true
    })
  },
  'task.restore': {
    module: 'task',
    scope: 'project',
    name: 'PATCH /api/cards/:id (restore)',
    execute: async (client, ctx) => client.patch(`/api/cards/${ctx.archivedCardId || ctx.cardId}`, {
      is_archived: false
    })
  },
  'task.delete': {
    module: 'task',
    scope: 'project',
    name: 'DELETE /api/cards/:id',
    execute: async (client, ctx) => client.delete(`/api/cards/${ctx.deletableCardId}`)
  },

  // === CHECKLIST MODULE ===
  'checklist.create': {
    module: 'checklist',
    scope: 'project',
    name: 'POST /api/cards/:id/checklists',
    execute: async (client, ctx) => client.post(`/api/cards/${ctx.cardId}/checklists`, {
      title: `zz-permtest-chk-${Date.now()}`
    })
  },
  'checklist.edit': {
    module: 'checklist',
    scope: 'project',
    name: 'POST /api/cards/checklist-items',
    execute: async (client, ctx) => client.post('/api/cards/checklist-items', {
      checklist_id: ctx.checklistId,
      text: 'Test item'
    })
  },
  'checklist.delete': {
    module: 'checklist',
    scope: 'project',
    name: 'DELETE /api/cards/checklists/:id',
    execute: async (client, ctx) => client.delete(`/api/cards/checklists/${ctx.deletableChecklistId}`)
  },

  // === COMMENT MODULE ===
  'comment.view': {
    module: 'comment',
    scope: 'project',
    name: 'GET /api/cards/:id/comments',
    execute: async (client, ctx) => client.get(`/api/cards/${ctx.cardId}/comments`)
  },
  'comment.create': {
    module: 'comment',
    scope: 'project',
    name: 'POST /api/cards/:id/comments',
    execute: async (client, ctx) => client.post(`/api/cards/${ctx.cardId}/comments`, {
      body: `zz-permtest-comment-${Date.now()}`
    })
  },
  'comment.edit_own': {
    module: 'comment',
    scope: 'project',
    name: 'PATCH /api/cards/comments/:id',
    execute: async (client, ctx) => client.patch(`/api/cards/comments/${ctx.ownCommentId}`, {
      body: `zz-permtest-comment-edited-${Date.now()}`
    })
  },
  'comment.delete_own': {
    module: 'comment',
    scope: 'project',
    name: 'DELETE /api/cards/comments/:id (own)',
    execute: async (client, ctx) => client.delete(`/api/cards/comments/${ctx.ownDeletableCommentId}`)
  },
  'comment.delete_any': {
    module: 'comment',
    scope: 'project',
    name: 'DELETE /api/cards/comments/:id (any)',
    execute: async (client, ctx) => client.delete(`/api/cards/comments/${ctx.otherCommentId}`)
  },

  // === ATTACHMENT MODULE ===
  'attachment.view': {
    module: 'attachment',
    scope: 'project',
    name: 'GET /api/cards/:id/attachments',
    execute: async (client, ctx) => client.get(`/api/cards/${ctx.cardId}/attachments`)
  },
  'attachment.upload': {
    module: 'attachment',
    scope: 'project',
    name: 'POST /api/cards/:id/attachments',
    execute: async (client, ctx) => client.post(`/api/cards/${ctx.cardId}/attachments`, {
      file_name: 'test.txt',
      file_url: '/uploads/test.txt',
      file_size: 1024
    })
  },
  'attachment.delete_own': {
    module: 'attachment',
    scope: 'project',
    name: 'DELETE /api/cards/attachments/:id (own)',
    execute: async (client, ctx) => client.delete(`/api/cards/attachments/${ctx.ownAttachmentId}`)
  },
  'attachment.delete_any': {
    module: 'attachment',
    scope: 'project',
    name: 'DELETE /api/cards/attachments/:id (any)',
    execute: async (client, ctx) => client.delete(`/api/cards/attachments/${ctx.otherAttachmentId}`)
  },

  // === FILE MODULE ===
  'file.view': {
    module: 'file',
    scope: 'project',
    name: 'GET /api/files/:id',
    execute: async (client, ctx) => client.get(`/api/files/${ctx.fileId}`)
  },
  'file.delete': {
    module: 'file',
    scope: 'project',
    name: 'DELETE /api/files/:id',
    execute: async (client, ctx) => client.delete(`/api/files/${ctx.deletableFileId}`)
  },

  // === SESSION MODULE ===
  'session.view_own': {
    module: 'session',
    scope: 'company',
    name: 'GET /api/auth/sessions',
    execute: async (client, ctx) => client.get('/api/auth/sessions')
  },
  'session.revoke_own': {
    module: 'session',
    scope: 'company',
    name: 'DELETE /api/auth/sessions/:id (own)',
    execute: async (client, ctx) => client.delete(`/api/auth/sessions/${ctx.ownSessionId || 999999}`)
  },
  'session.revoke_others': {
    module: 'session',
    scope: 'company',
    name: 'DELETE /api/auth/sessions/:id (others)',
    execute: async (client, ctx) => client.delete(`/api/auth/sessions/${ctx.otherSessionId || 999999}`)
  },

  // === LABEL MODULE ===
  'label.view': {
    module: 'label',
    scope: 'project',
    name: 'GET /api/boards/:id/labels',
    execute: async (client, ctx) => client.get(`/api/boards/${ctx.boardId}/labels`)
  },
  'label.create': {
    module: 'label',
    scope: 'project',
    name: 'POST /api/boards/:id/labels',
    execute: async (client, ctx) => client.post(`/api/boards/${ctx.boardId}/labels`, {
      name: `zz-permtest-label-${Date.now()}`,
      color: '#3b82f6'
    })
  },
  'label.edit': {
    module: 'label',
    scope: 'project',
    name: 'PATCH /api/boards/:id/labels/:labelId',
    execute: async (client, ctx) => client.patch(`/api/boards/${ctx.boardId}/labels/${ctx.labelId}`, {
      name: `zz-permtest-label-renamed-${Date.now()}`
    })
  },
  'label.delete': {
    module: 'label',
    scope: 'project',
    name: 'DELETE /api/boards/:id/labels/:labelId',
    execute: async (client, ctx) => client.delete(`/api/boards/${ctx.boardId}/labels/${ctx.deletableLabelId}`)
  },

  // === NOTIFICATION MODULE ===
  'notification.view_own': {
    module: 'notification',
    scope: 'company',
    name: 'GET /api/notifications',
    execute: async (client, ctx) => client.get('/api/notifications')
  },
  'notification.manage_own': {
    module: 'notification',
    scope: 'company',
    name: 'PATCH /api/notifications/read-all',
    execute: async (client, ctx) => client.patch('/api/notifications/read-all', {})
  },

  // === AUDIT MODULE ===
  'audit.view': {
    module: 'audit',
    scope: 'company',
    name: 'GET /api/workspaces/:id/audit',
    execute: async (client, ctx) => client.get(`/api/workspaces/${ctx.workspaceId}/audit`)
  },
  'audit.export': {
    module: 'audit',
    scope: 'company',
    name: 'GET /api/workspaces/:id/audit/export',
    execute: async (client, ctx) => client.get(`/api/workspaces/${ctx.workspaceId}/audit/export`)
  },

  // === ACTIVITY MODULE ===
  'activity.view': {
    module: 'activity',
    scope: 'company',
    name: 'GET /api/workspaces/:id/activity',
    execute: async (client, ctx) => client.get(`/api/workspaces/${ctx.workspaceId}/activity`)
  },

  // === ARCHIVE MODULE ===
  'archive.view': {
    module: 'archive',
    scope: 'company',
    name: 'GET /api/workspaces/:id/archived',
    execute: async (client, ctx) => client.get(`/api/workspaces/${ctx.workspaceId}/archived`)
  },
  'archive.restore': {
    module: 'archive',
    scope: 'company',
    name: 'POST /api/cards/:id/restore',
    execute: async (client, ctx) => client.post(`/api/cards/${ctx.archivedCardId}/restore`, {})
  },
  'archive.permanent_delete': {
    module: 'archive',
    scope: 'company',
    name: 'DELETE /api/workspaces/:id/archived-cards',
    execute: async (client, ctx) => client.delete(`/api/workspaces/${ctx.workspaceId}/archived-cards`)
  },

  // === SEARCH MODULE ===
  'search.use': {
    module: 'search',
    scope: 'company',
    name: 'GET /api/workspaces/:id/search?q=test',
    execute: async (client, ctx) => client.get(`/api/workspaces/${ctx.workspaceId}/search?q=test`)
  }
};

module.exports = { OPERATIONS };

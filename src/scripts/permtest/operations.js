// server/src/scripts/permtest/operations.js
// Catalog of executable HTTP probes mapping RBAC permissions to real API operations.
// Used for matrix verification, isolation checks, toggle testing, and regression tests.

const crypto = require('crypto');

function getContextEntities(ctx, boardId) {
  if (boardId && (boardId === ctx.boardBId || boardId === 'boardB')) {
    return {
      boardId: ctx.boardBId,
      wsId: ctx.w1Id,
      listId: ctx.listBId,
      cardId: ctx.cardBId,
      checklistId: ctx.checklistBId,
      checklistItemId: ctx.checklistItemBId,
      commentId: ctx.commentBId,
      attachmentId: ctx.attachmentBId,
      labelId: ctx.labelBId || ctx.label1Id
    };
  }
  if (boardId && (boardId === ctx.boardCId || boardId === 'boardC')) {
    return {
      boardId: ctx.boardCId,
      wsId: ctx.w2Id,
      listId: ctx.listW2Id,
      cardId: ctx.cardW2Id,
      checklistId: ctx.checklistW2Id,
      checklistItemId: ctx.checklistItemW2Id,
      commentId: ctx.commentW2Id,
      attachmentId: ctx.attachmentW2Id,
      labelId: ctx.labelW2Id || ctx.label1Id
    };
  }
  return {
    boardId: ctx.boardAId,
    wsId: ctx.w1Id,
    listId: ctx.list1Id,
    cardId: ctx.card1Id,
    checklistId: ctx.checklist1Id,
    checklistItemId: ctx.checklistItem1Id,
    commentId: ctx.comment1Id,
    attachmentId: ctx.attachment1Id,
    labelId: ctx.label1Id
  };
}

const PROBES = {
  // === WORKSPACE MODULE ===
  'company.manage_security': {
    module: 'company',
    scope: 'company',
    method: 'GET',
    path: '/api/workspaces/:wId/security',
    execute: (client, ctx, boardId) => client.get(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}/security`)
  },
  'workspace.view': {
    module: 'workspace',
    scope: 'company',
    method: 'GET',
    path: '/api/workspaces/:wId',
    execute: (client, ctx, boardId) => client.get(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}`)
  },
  'workspace.create': {
    module: 'workspace',
    scope: 'company',
    method: 'POST',
    path: '/api/workspaces',
    execute: async (client, ctx) => {
      const res = await client.post('/api/workspaces', { name: `ws_probe_${Date.now()}` });
      const createdId = res.data?.workspace?.id || res.data?.id;
      if (createdId && ctx.tenantDb && client.user?.id) {
        try {
          await ctx.tenantDb.execute('DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?', [createdId, client.user.id]);
          await ctx.tenantDb.execute('DELETE FROM workspaces WHERE id = ?', [createdId]);
        } catch (e) {}
      }
      return res;
    }
  },
  'workspace.edit': {
    module: 'workspace',
    scope: 'company',
    method: 'PATCH',
    path: '/api/workspaces/:wId',
    execute: (client, ctx, boardId) => client.patch(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}`, { name: `W_Edited_${Date.now()}` })
  },
  'workspace.archive': {
    module: 'workspace',
    scope: 'company',
    method: 'PATCH',
    path: '/api/workspaces/:wId (archive)',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') {
        return client.patch(`/api/workspaces/${e.wsId}`, { is_archived: true });
      }
      const wsRes = await ctx.ownerClient.post('/api/workspaces', { name: `ws_arch_${Date.now()}` });
      const archWsId = wsRes.data?.workspace?.id || wsRes.data?.id;
      if (client.user?.id && client.user.id !== ctx.users['Owner']?.user?.id) {
        await ctx.tenantDb.execute(
          'INSERT INTO workspace_members (workspace_id, user_id, role_id) VALUES (?, ?, ?)',
          [archWsId, client.user.id, ctx.roleMap[client.roleName] || ctx.roleMap['Viewer']]
        );
      }
      return client.patch(`/api/workspaces/${archWsId}`, { is_archived: true });
    }
  },
  'workspace.delete': {
    module: 'workspace',
    scope: 'company',
    method: 'DELETE',
    path: '/api/workspaces/:wId',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') {
        return client.delete(`/api/workspaces/${e.wsId}`);
      }
      const wsRes = await ctx.ownerClient.post('/api/workspaces', { name: `ws_del_${Date.now()}` });
      const delWsId = wsRes.data?.workspace?.id || wsRes.data?.id;
      if (client.user?.id && client.user.id !== ctx.users['Owner']?.user?.id) {
        await ctx.tenantDb.execute(
          'INSERT INTO workspace_members (workspace_id, user_id, role_id) VALUES (?, ?, ?)',
          [delWsId, client.user.id, ctx.roleMap[client.roleName] || ctx.roleMap['Viewer']]
        );
      }
      return client.delete(`/api/workspaces/${delWsId}`);
    }
  },

  // === MEMBER MODULE ===
  'member.view': {
    module: 'member',
    scope: 'company',
    method: 'GET',
    path: '/api/workspaces/:wId/members',
    execute: (client, ctx, boardId) => client.get(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}/members`)
  },
  'member.invite': {
    module: 'member',
    scope: 'company',
    method: 'POST',
    path: '/api/invitations',
    execute: (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      return client.post('/api/invitations', {
        email: `invite_${Date.now()}@permtest.local`,
        workspace_id: e.wsId,
        board_ids: [e.boardId],
        role_id: ctx.roleMap['Team Member'] || ctx.roleMap['Viewer']
      });
    }
  },
  'member.invite_guest': {
    module: 'member',
    scope: 'company',
    method: 'POST',
    path: '/api/invitations (guest)',
    execute: (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      return client.post('/api/invitations', {
        email: `guest_${Date.now()}@permtest.local`,
        workspace_id: e.wsId,
        board_ids: [e.wsId === ctx.w1Id ? ctx.boardAId : ctx.boardCId],
        role_id: ctx.roleMap['Guest']
      });
    }
  },
  'member.remove': {
    module: 'member',
    scope: 'company',
    method: 'DELETE',
    path: '/api/workspaces/:wId/members/:userId',
    execute: async (client, ctx, boardId, targetUserId) => {
      const e = getContextEntities(ctx, boardId);
      if (targetUserId && targetUserId !== boardId) {
        return client.delete(`/api/workspaces/${e.wsId}/members/${targetUserId}`);
      }
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') {
        return client.delete(`/api/workspaces/${e.wsId}/members/999999`);
      }
      const thEmail = `del_mem_${Date.now()}_${Math.random().toString(36).substring(7)}@permtest.local`;
      const invRes = await ctx.ownerClient.post('/api/invitations', {
        email: thEmail,
        workspace_id: e.wsId,
        board_ids: [e.wsId === ctx.w1Id ? ctx.boardAId : ctx.boardCId],
        role_id: ctx.roleMap['Viewer']
      });
      const tkn = invRes.data?.invite_token || invRes.data?.invitation?.token || invRes.data?.token;
      const thClient = new client.constructor({ frontendUrl: ctx.frontendUrl });
      const reg = await thClient.post('/api/auth/register', {
        name: 'Throwaway Member',
        email: thEmail,
        password: 'Password123!@#',
        invite_token: tkn
      });
      const thId = reg.data?.user?.id;
      return client.delete(`/api/workspaces/${e.wsId}/members/${thId}`);
    }
  },
  'member.assign_role': {
    module: 'member',
    scope: 'company',
    method: 'PATCH',
    path: '/api/workspaces/:wId/members/:userId/role',
    execute: async (client, ctx, boardId, targetUserId) => {
      const e = getContextEntities(ctx, boardId);
      const defaultTarget = e.wsId === ctx.w2Id ? ctx.w2MemberId : (ctx.memberTargetId || ctx.users?.['Viewer']?.user?.id || 6);
      const tId = (targetUserId && targetUserId !== boardId) ? targetUserId : defaultTarget;
      const roleIdToAssign = e.wsId === ctx.w2Id ? ctx.assignableRoleW2Id : (ctx.assignableRoleW1Id || ctx.roleMap?.['Guest']);
      return client.patch(`/api/workspaces/${e.wsId}/members/${tId}/role`, {
        role_id: roleIdToAssign
      });
    }
  },
  'member.deactivate': {
    module: 'member',
    scope: 'company',
    method: 'POST',
    path: '/api/workspaces/:wId/members/:userId/deactivate',
    execute: async (client, ctx, boardId, targetUserId) => {
      const e = getContextEntities(ctx, boardId);
      const defaultTarget = e.wsId === ctx.w2Id ? ctx.w2MemberId : (ctx.memberTargetId || ctx.users?.['Viewer']?.user?.id || 6);
      const tId = (targetUserId && targetUserId !== boardId) ? targetUserId : defaultTarget;
      const res = await client.post(`/api/workspaces/${e.wsId}/members/${tId}/deactivate`, {});
      if (res.status === 200) {
        await ctx.ownerClient.post(`/api/workspaces/${e.wsId}/members/${tId}/reactivate`, {});
      }
      return res;
    }
  },
  'member.reset_password': {
    module: 'member',
    scope: 'company',
    method: 'POST',
    path: '/api/workspaces/:wId/members/:userId/reset-password',
    execute: (client, ctx, boardId, targetUserId) => {
      const e = getContextEntities(ctx, boardId);
      const defaultTarget = e.wsId === ctx.w2Id ? ctx.w2MemberId : (ctx.memberTargetId || ctx.users?.['Viewer']?.user?.id || 6);
      const tId = (targetUserId && targetUserId !== boardId) ? targetUserId : defaultTarget;
      return client.post(`/api/workspaces/${e.wsId}/members/${tId}/reset-password`, {
        new_password: 'ResetPass123!@#'
      });
    }
  },
  'member.reset_2fa': {
    module: 'member',
    scope: 'company',
    method: 'POST',
    path: '/api/workspaces/:wId/members/:userId/reset-2fa',
    execute: (client, ctx, boardId, targetUserId) => {
      const e = getContextEntities(ctx, boardId);
      const defaultTarget = e.wsId === ctx.w2Id ? ctx.w2MemberId : (ctx.memberTargetId || ctx.users?.['Viewer']?.user?.id || 6);
      const tId = (targetUserId && targetUserId !== boardId) ? targetUserId : defaultTarget;
      return client.post(`/api/workspaces/${e.wsId}/members/${tId}/reset-2fa`, {});
    }
  },

  // === ROLE MODULE ===
  'role.view': {
    module: 'role',
    scope: 'company',
    method: 'GET',
    path: '/api/workspaces/:wId/roles',
    execute: (client, ctx, boardId) => client.get(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}/roles`)
  },
  'role.create': {
    module: 'role',
    scope: 'company',
    method: 'POST',
    path: '/api/workspaces/:wId/roles',
    execute: (client, ctx, boardId) => client.post(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}/roles`, {
      name: `Role_${Date.now()}`,
      permission_keys: ['workspace.view']
    })
  },
  'role.edit': {
    module: 'role',
    scope: 'company',
    method: 'PATCH',
    path: '/api/roles/:id',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.patch('/api/roles/999999', { name: 'Hacked' });
      if (!ctx.editableCustomRoleId && ctx.ownerClient) {
        const createRes = await ctx.ownerClient.post(`/api/workspaces/${e.wsId}/roles`, {
          name: `Target_Role_${Date.now()}`,
          permission_keys: ['workspace.view']
        });
        ctx.editableCustomRoleId = createRes.data?.role?.id || createRes.data?.id;
      }
      const targetId = ctx.editableCustomRoleId || ctx.probeRoleId;
      return client.patch(`/api/roles/${targetId}`, {
        name: `Probe_Edit_${Date.now()}`,
        permission_keys: ['workspace.view']
      });
    }
  },
  'role.delete': {
    module: 'role',
    scope: 'company',
    method: 'DELETE',
    path: '/api/roles/:id',
    execute: async (client, ctx, boardId, roleId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.delete('/api/roles/999999');
      if (roleId) return client.delete(`/api/roles/${roleId}`);
      const createRes = await ctx.ownerClient.post(`/api/workspaces/${e.wsId}/roles`, {
        name: `Role_Del_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        permission_keys: ['workspace.view']
      });
      const rid = createRes.data?.role?.id || createRes.data?.id;
      return client.delete(`/api/roles/${rid}`);
    }
  },

  // === PROJECT MODULE (BOARDS) ===
  'project.access_all': {
    module: 'project',
    scope: 'company',
    method: 'GET',
    path: '/api/boards/:id (cross-board access)',
    execute: (client, ctx, boardId) => {
      const targetBoard = (boardId === ctx.boardCId) ? ctx.boardCId : ctx.boardBId;
      return client.get(`/api/boards/${targetBoard}`);
    }
  },
  'project.view': {
    module: 'project',
    scope: 'project',
    method: 'GET',
    path: '/api/boards/:id',
    execute: (client, ctx, boardId) => client.get(`/api/boards/${getContextEntities(ctx, boardId).boardId}`)
  },
  'project.create': {
    module: 'project',
    scope: 'company',
    method: 'POST',
    path: '/api/boards',
    execute: (client, ctx, boardId) => client.post('/api/boards', {
      workspace_id: getContextEntities(ctx, boardId).wsId,
      name: `Board_${Date.now()}`
    })
  },
  'project.edit_settings': {
    module: 'project',
    scope: 'project',
    method: 'PATCH',
    path: '/api/boards/:id',
    execute: (client, ctx, boardId) => client.patch(`/api/boards/${getContextEntities(ctx, boardId).boardId}`, {
      name: `Board_Renamed_${Date.now()}`
    })
  },
  'project.archive': {
    module: 'project',
    scope: 'project',
    method: 'POST',
    path: '/api/boards/:id/archive',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.post(`/api/boards/${e.boardId}/archive`, {});
      const bRes = await ctx.ownerClient.post('/api/boards', {
        workspace_id: e.wsId,
        name: `arch_b_${Date.now()}`
      });
      const archBId = bRes.data?.board?.id || bRes.data?.id;
      const isCallerMember = (boardId === ctx.boardAId || !boardId);
      if (isCallerMember && client.user?.id && client.user.id !== ctx.users['Owner']?.user?.id) {
        await ctx.tenantDb.execute(
          'INSERT INTO board_members (board_id, user_id) VALUES (?, ?)',
          [archBId, client.user.id]
        );
      }
      return client.post(`/api/boards/${archBId}/archive`, {});
    }
  },
  'project.delete': {
    module: 'project',
    scope: 'project',
    method: 'DELETE',
    path: '/api/boards/:id',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.delete(`/api/boards/${e.boardId}`);
      const bRes = await ctx.ownerClient.post('/api/boards', {
        workspace_id: e.wsId,
        name: `del_b_${Date.now()}`
      });
      const delBId = bRes.data?.board?.id || bRes.data?.id;
      const isCallerMember = (boardId === ctx.boardAId || !boardId);
      if (isCallerMember && client.user?.id && client.user.id !== ctx.users['Owner']?.user?.id) {
        await ctx.tenantDb.execute(
          'INSERT INTO board_members (board_id, user_id) VALUES (?, ?)',
          [delBId, client.user.id]
        );
      }
      return client.delete(`/api/boards/${delBId}`);
    }
  },
  'project.manage_members': {
    module: 'project',
    scope: 'project',
    method: 'POST',
    path: '/api/boards/:id/members',
    execute: (client, ctx, boardId) => {
      const targetId = (client.user?.id === ctx.memberTargetId) ? ctx.users['Owner']?.user?.id : ctx.memberTargetId;
      return client.post(`/api/boards/${getContextEntities(ctx, boardId).boardId}/members`, {
        user_id: targetId,
        role: 'member'
      });
    }
  },
  'project.assign_role': {
    module: 'project',
    scope: 'project',
    method: 'PATCH',
    path: '/api/boards/:id/members/:userId/role',
    execute: (client, ctx, boardId) => {
      const targetId = (client.user?.id === ctx.memberTargetId) ? ctx.users['Owner']?.user?.id : ctx.memberTargetId;
      return client.patch(`/api/boards/${getContextEntities(ctx, boardId).boardId}/members/${targetId}/role`, {
        role_id: ctx.roleMap['Team Member'] || ctx.roleMap['Viewer']
      });
    }
  },

  // === LIST MODULE ===
  'list.create': {
    module: 'list',
    scope: 'project',
    method: 'POST',
    path: '/api/lists',
    execute: (client, ctx, boardId) => client.post('/api/lists', {
      board_id: getContextEntities(ctx, boardId).boardId,
      name: `List_${Date.now()}`
    })
  },
  'list.edit': {
    module: 'list',
    scope: 'project',
    method: 'PATCH',
    path: '/api/lists/:id',
    execute: (client, ctx, boardId) => client.patch(`/api/lists/${getContextEntities(ctx, boardId).listId}`, {
      name: `List_Renamed_${Date.now()}`
    })
  },
  'list.reorder': {
    module: 'list',
    scope: 'project',
    method: 'PATCH',
    path: '/api/lists/:id (reorder)',
    execute: (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      return client.patch(`/api/lists/${e.listId}`, {
        position: 1
      });
    }
  },
  'list.delete': {
    module: 'list',
    scope: 'project',
    method: 'DELETE',
    path: '/api/lists/:id',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.delete(`/api/lists/${e.listId}`);
      const lRes = await ctx.ownerClient.post('/api/lists', {
        board_id: e.boardId,
        name: `del_l_${Date.now()}`
      });
      const delLId = lRes.data?.list?.id || lRes.data?.id;
      return client.delete(`/api/lists/${delLId}`);
    }
  },

  // === TASK MODULE (CARDS) ===
  'task.view': {
    module: 'task',
    scope: 'project',
    method: 'GET',
    path: '/api/cards/:id',
    execute: (client, ctx, boardId) => client.get(`/api/cards/${getContextEntities(ctx, boardId).cardId}`)
  },
  'task.create': {
    module: 'task',
    scope: 'project',
    method: 'POST',
    path: '/api/cards',
    execute: (client, ctx, boardId) => client.post('/api/cards', {
      list_id: getContextEntities(ctx, boardId).listId,
      title: `Task_${Date.now()}`
    })
  },
  'task.edit': {
    module: 'task',
    scope: 'project',
    method: 'PATCH',
    path: '/api/cards/:id (edit)',
    execute: (client, ctx, boardId) => client.patch(`/api/cards/${getContextEntities(ctx, boardId).cardId}`, {
      title: `Task_Renamed_${Date.now()}`
    })
  },
  'task.move': {
    module: 'task',
    scope: 'project',
    method: 'PATCH',
    path: '/api/cards/:id (move)',
    execute: (client, ctx, boardId) => client.patch(`/api/cards/${getContextEntities(ctx, boardId).cardId}`, {
      position: 50
    })
  },
  'task.assign': {
    module: 'task',
    scope: 'project',
    method: 'POST',
    path: '/api/cards/:id/members',
    execute: (client, ctx, boardId) => {
      const targetId = (client.user?.id === ctx.memberTargetId) ? ctx.users['Owner']?.user?.id : ctx.memberTargetId;
      return client.post(`/api/cards/${getContextEntities(ctx, boardId).cardId}/members`, {
        user_id: targetId
      });
    }
  },
  'task.assign_self': {
    module: 'task',
    scope: 'project',
    method: 'POST',
    path: '/api/cards/:id/members (self)',
    execute: (client, ctx, boardId) => client.post(`/api/cards/${getContextEntities(ctx, boardId).cardId}/members`, {
      user_id: client.user?.id
    })
  },
  'task.complete': {
    module: 'task',
    scope: 'project',
    method: 'PATCH',
    path: '/api/cards/:id (complete)',
    execute: (client, ctx, boardId) => client.patch(`/api/cards/${getContextEntities(ctx, boardId).cardId}`, {
      is_complete: true
    })
  },
  'task.archive': {
    module: 'task',
    scope: 'project',
    method: 'PATCH',
    path: '/api/cards/:id (archive)',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.patch(`/api/cards/${e.cardId}`, { is_archived: true });
      const cRes = await ctx.ownerClient.post('/api/cards', { list_id: e.listId, title: `arch_c_${Date.now()}` });
      const archCardId = cRes.data?.card?.id || cRes.data?.id;
      return client.patch(`/api/cards/${archCardId}`, { is_archived: true });
    }
  },
  'task.restore': {
    module: 'task',
    scope: 'project',
    method: 'PATCH',
    path: '/api/cards/:id (restore)',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.patch(`/api/cards/${e.cardId}`, { is_archived: false });
      const cRes = await ctx.ownerClient.post('/api/cards', { list_id: e.listId, title: `res_c_${Date.now()}` });
      const resCardId = cRes.data?.card?.id || cRes.data?.id;
      await ctx.ownerClient.patch(`/api/cards/${resCardId}`, { is_archived: true });
      return client.patch(`/api/cards/${resCardId}`, { is_archived: false });
    }
  },
  'task.delete': {
    module: 'task',
    scope: 'project',
    method: 'DELETE',
    path: '/api/cards/:id',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.delete(`/api/cards/${e.cardId}`);
      const cRes = await ctx.ownerClient.post('/api/cards', { list_id: e.listId, title: `del_c_${Date.now()}` });
      const delId = cRes.data?.card?.id || cRes.data?.id;
      return client.delete(`/api/cards/${delId}`);
    }
  },
  'task.delete_own': {
    module: 'task',
    scope: 'project',
    method: 'DELETE',
    path: '/api/cards/:id (own)',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.delete(`/api/cards/${e.cardId}`);
      if (ctx.tenantDb && client.user?.id) {
        const ins = await ctx.tenantDb.execute(
          'INSERT INTO cards (list_id, title, created_by, position) VALUES (?, ?, ?, 99)',
          [e.listId, `own_del_c_${Date.now()}`, client.user.id]
        );
        return client.delete(`/api/cards/${ins.insertId}`);
      }
      return client.delete(`/api/cards/${e.cardId}`);
    }
  },
  'task.duplicate': {
    module: 'task',
    scope: 'project',
    method: 'POST',
    path: '/api/cards/:id/copy',
    execute: (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      return client.post(`/api/cards/${e.cardId}/copy`, { list_id: e.listId });
    }
  },

  // === CHECKLIST MODULE ===
  'checklist.create': {
    module: 'checklist',
    scope: 'project',
    method: 'POST',
    path: '/api/cards/:id/checklists',
    execute: (client, ctx, boardId) => client.post(`/api/cards/${getContextEntities(ctx, boardId).cardId}/checklists`, {
      title: `Chk_${Date.now()}`
    })
  },
  'checklist.edit': {
    module: 'checklist',
    scope: 'project',
    method: 'PATCH',
    path: '/api/cards/checklist-items/:id',
    execute: (client, ctx, boardId) => client.patch(`/api/cards/checklist-items/${getContextEntities(ctx, boardId).checklistItemId}`, {
      text: `ChkItem_Edited_${Date.now()}`
    })
  },
  'checklist.delete': {
    module: 'checklist',
    scope: 'project',
    method: 'DELETE',
    path: '/api/cards/checklists/:id',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.delete(`/api/cards/checklists/${e.checklistId}`);
      const chkRes = await ctx.ownerClient.post(`/api/cards/${e.cardId}/checklists`, { title: `del_chk_${Date.now()}` });
      const delChkId = chkRes.data?.checklist?.id || chkRes.data?.id;
      return client.delete(`/api/cards/checklists/${delChkId}`);
    }
  },

  // === COMMENT MODULE ===
  'comment.view': {
    module: 'comment',
    scope: 'project',
    method: 'GET',
    path: '/api/cards/:id/comments',
    execute: (client, ctx, boardId) => client.get(`/api/cards/${getContextEntities(ctx, boardId).cardId}/comments`)
  },
  'comment.create': {
    module: 'comment',
    scope: 'project',
    method: 'POST',
    path: '/api/cards/:id/comments',
    execute: (client, ctx, boardId) => client.post(`/api/cards/${getContextEntities(ctx, boardId).cardId}/comments`, {
      body: `Comment_${Date.now()}`
    })
  },
  'comment.edit_own': {
    module: 'comment',
    scope: 'project',
    method: 'PATCH',
    path: '/api/cards/comments/:id (own)',
    execute: async (client, ctx, boardId, commentId) => {
      const e = getContextEntities(ctx, boardId);
      if (commentId && commentId !== boardId) {
        return client.patch(`/api/cards/comments/${commentId}`, { body: `Com_Edited_${Date.now()}` });
      }
      if (ctx.tenantDb && client.user?.id) {
        const ins = await ctx.tenantDb.execute(
          'INSERT INTO comments (card_id, user_id, body) VALUES (?, ?, ?)',
          [e.cardId, client.user.id, 'own comment to edit']
        );
        return client.patch(`/api/cards/comments/${ins.insertId}`, { body: `Com_Edited_${Date.now()}` });
      }
      return client.patch(`/api/cards/comments/${e.commentId}`, { body: `Com_Edited_${Date.now()}` });
    }
  },
  'comment.delete_own': {
    module: 'comment',
    scope: 'project',
    method: 'DELETE',
    path: '/api/cards/comments/:id (own)',
    execute: async (client, ctx, boardId, commentId) => {
      const e = getContextEntities(ctx, boardId);
      if (commentId && commentId !== boardId) {
        return client.delete(`/api/cards/comments/${commentId}`);
      }
      if (ctx.tenantDb && client.user?.id) {
        const ins = await ctx.tenantDb.execute(
          'INSERT INTO comments (card_id, user_id, body) VALUES (?, ?, ?)',
          [e.cardId, client.user.id, 'own comment to delete']
        );
        return client.delete(`/api/cards/comments/${ins.insertId}`);
      }
      return client.delete(`/api/cards/comments/${e.commentId}`);
    }
  },
  'comment.delete_any': {
    module: 'comment',
    scope: 'project',
    method: 'DELETE',
    path: '/api/cards/comments/:id (any)',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.delete(`/api/cards/comments/${e.commentId}`);
      const cRes = await ctx.ownerClient.post(`/api/cards/${e.cardId}/comments`, { body: `del_com_${Date.now()}` });
      const delComId = cRes.data?.comment?.id || cRes.data?.id;
      return client.delete(`/api/cards/comments/${delComId}`);
    }
  },

  // === ATTACHMENT & FILE MODULES ===
  'attachment.view': {
    module: 'attachment',
    scope: 'project',
    method: 'GET',
    path: '/api/cards/:id/attachments',
    execute: (client, ctx, boardId) => client.get(`/api/cards/${getContextEntities(ctx, boardId).cardId}/attachments`)
  },
  'attachment.upload': {
    module: 'attachment',
    scope: 'project',
    method: 'POST',
    path: '/api/cards/:id/attachments/link',
    execute: (client, ctx, boardId) => client.post(`/api/cards/${getContextEntities(ctx, boardId).cardId}/attachments/link`, {
      link_url: `https://example.com/probe_${Date.now()}`,
      display_name: 'Attachment Probe'
    })
  },
  'attachment.delete_own': {
    module: 'attachment',
    scope: 'project',
    method: 'DELETE',
    path: '/api/attachments/:id (own)',
    execute: async (client, ctx, boardId, attId) => {
      const e = getContextEntities(ctx, boardId);
      if (attId && attId !== boardId) {
        return client.delete(`/api/attachments/${attId}`);
      }
      if (ctx.tenantDb && client.user?.id) {
        const ins = await ctx.tenantDb.execute(
          'INSERT INTO attachments (card_id, uploaded_by_user_id, file_name, file_url, file_type) VALUES (?, ?, ?, ?, ?)',
          [e.cardId, client.user.id, 'own_att', 'https://example.com/own', 'link']
        );
        return client.delete(`/api/attachments/${ins.insertId}`);
      }
      return client.delete(`/api/attachments/${e.attachmentId}`);
    }
  },
  'attachment.delete_any': {
    module: 'attachment',
    scope: 'project',
    method: 'DELETE',
    path: '/api/attachments/:id (any)',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.delete(`/api/attachments/${e.attachmentId}`);
      const aRes = await ctx.ownerClient.post(`/api/cards/${e.cardId}/attachments/link`, {
        link_url: `https://example.com/att_${Date.now()}`,
        display_name: 'Del Att'
      });
      const delAttId = aRes.data?.attachment?.id || aRes.data?.id;
      return client.delete(`/api/attachments/${delAttId}`);
    }
  },
  'file.view': {
    module: 'file',
    scope: 'project',
    method: 'GET',
    path: '/api/attachments/:id',
    execute: (client, ctx, boardId) => client.get(`/api/attachments/${getContextEntities(ctx, boardId).attachmentId}`)
  },
  'file.delete': {
    module: 'file',
    scope: 'project',
    method: 'DELETE',
    path: '/api/attachments/:id?file_only=true',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.delete(`/api/attachments/${e.attachmentId}?file_only=true`);
      const aRes = await ctx.ownerClient.post(`/api/cards/${e.cardId}/attachments/link`, {
        link_url: `https://example.com/file_${Date.now()}`,
        display_name: 'Del File'
      });
      const delAttId = aRes.data?.attachment?.id || aRes.data?.id;
      return client.delete(`/api/attachments/${delAttId}?file_only=true`);
    }
  },

  // === SESSION & NOTIFICATIONS ===
  'session.view_own': {
    module: 'session',
    scope: 'company',
    method: 'GET',
    path: '/api/auth/sessions',
    execute: (client) => client.get('/api/auth/sessions')
  },
  'session.revoke_own': {
    module: 'session',
    scope: 'company',
    method: 'DELETE',
    path: '/api/auth/sessions/:id (own)',
    execute: async (client, ctx) => {
      const crypto = require('crypto');
      const extraSessId = crypto.randomUUID();
      if (ctx.tenantDb && client.user?.id) {
        await ctx.tenantDb.execute(
          'INSERT INTO sessions (id, user_id, refresh_token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 DAY))',
          [extraSessId, client.user.id, crypto.randomBytes(32).toString('hex'), crypto.randomUUID()]
        );
      }
      return client.delete(`/api/auth/sessions/${extraSessId}`);
    }
  },
  'session.revoke_others': {
    module: 'session',
    scope: 'company',
    method: 'DELETE',
    path: '/api/auth/sessions/:id (other)',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.delete('/api/auth/sessions/999999');
      const targetUserId = (client.user?.id === ctx.memberTargetId) ? ctx.users['Owner']?.user?.id : ctx.memberTargetId;
      const throwawaySessId = crypto.randomUUID();
      await ctx.tenantDb.execute(
        'INSERT INTO sessions (id, user_id, refresh_token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 1 DAY))',
        [throwawaySessId, targetUserId, crypto.randomBytes(32).toString('hex'), crypto.randomUUID()]
      );
      return client.delete(`/api/auth/sessions/${throwawaySessId}`);
    }
  },
  'notification.view_own': {
    module: 'notification',
    scope: 'company',
    method: 'GET',
    path: '/api/notifications',
    execute: (client) => client.get('/api/notifications')
  },
  'notification.manage_own': {
    module: 'notification',
    scope: 'company',
    method: 'PATCH',
    path: '/api/notifications/read-all',
    execute: (client) => client.patch('/api/notifications/read-all', {})
  },

  // === LABEL MODULE ===
  'label.view': {
    module: 'label',
    scope: 'project',
    method: 'GET',
    path: '/api/boards/:id/labels',
    execute: (client, ctx, boardId) => client.get(`/api/boards/${getContextEntities(ctx, boardId).boardId}/labels`)
  },
  'label.create': {
    module: 'label',
    scope: 'project',
    method: 'POST',
    path: '/api/boards/:id/labels',
    execute: (client, ctx, boardId) => client.post(`/api/boards/${getContextEntities(ctx, boardId).boardId}/labels`, {
      name: `Lbl_${Date.now()}`,
      color: '#10b981'
    })
  },
  'label.edit': {
    module: 'label',
    scope: 'project',
    method: 'PATCH',
    path: '/api/boards/:id/labels/:labelId',
    execute: (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      return client.patch(`/api/boards/${e.boardId}/labels/${e.labelId}`, {
        name: `Lbl_Edit_${Date.now()}`
      });
    }
  },
  'label.delete': {
    module: 'label',
    scope: 'project',
    method: 'DELETE',
    path: '/api/boards/:id/labels/:labelId',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id && client.roleName !== 'Owner') return client.delete(`/api/boards/${e.boardId}/labels/${e.labelId}`);
      const lRes = await ctx.ownerClient.post(`/api/boards/${e.boardId}/labels`, {
        name: `del_lbl_${Date.now()}`,
        color: '#6366f1'
      });
      const delLblId = lRes.data?.label?.id || lRes.data?.id;
      return client.delete(`/api/boards/${e.boardId}/labels/${delLblId}`);
    }
  },
  'label.delete_own': {
    module: 'label',
    scope: 'project',
    method: 'DELETE',
    path: '/api/boards/:id/labels/:labelId (own)',
    execute: async (client, ctx, boardId, labelId) => {
      const e = getContextEntities(ctx, boardId);
      if (labelId && labelId !== boardId) {
        return client.delete(`/api/boards/${e.boardId}/labels/${labelId}`);
      }
      if (ctx.tenantDb && client.user?.id) {
        const ins = await ctx.tenantDb.execute(
          'INSERT INTO labels (board_id, name, color, created_by_user_id) VALUES (?, ?, ?, ?)',
          [e.boardId, `OwnLbl_${Date.now()}`, '#10b981', client.user.id]
        );
        return client.delete(`/api/boards/${e.boardId}/labels/${ins.insertId}`);
      }
      return client.delete(`/api/boards/${e.boardId}/labels/${e.labelId}`);
    }
  },

  // === AUDIT MODULE ===
  'audit.view': {
    module: 'audit',
    scope: 'company',
    method: 'GET',
    path: '/api/workspaces/:wId/audit',
    execute: (client, ctx, boardId) => client.get(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}/audit`)
  },
  'audit.export': {
    module: 'audit',
    scope: 'company',
    method: 'GET',
    path: '/api/workspaces/:wId/audit/export',
    execute: (client, ctx, boardId) => client.get(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}/audit/export`)
  },

  // === ACTIVITY & SEARCH ===
  'activity.view': {
    module: 'activity',
    scope: 'company',
    method: 'GET',
    path: '/api/workspaces/:wId/activity',
    execute: (client, ctx, boardId) => client.get(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}/activity`)
  },
  'search.use': {
    module: 'search',
    scope: 'company',
    method: 'GET',
    path: '/api/workspaces/:id/search',
    execute: (client, ctx, boardId) => client.get(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}/search?q=test`)
  },

  // === REPORT MODULE ===
  'report.view_project': {
    module: 'report',
    scope: 'project',
    method: 'GET',
    path: '/api/workspaces/:wId/reports',
    execute: (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      return client.get(`/api/workspaces/${e.wsId}/reports?board_id=${e.boardId}`);
    }
  },

  // === ARCHIVE MODULE ===
  'archive.view': {
    module: 'archive',
    scope: 'company',
    method: 'GET',
    path: '/api/archive',
    execute: (client, ctx, boardId) => client.get(`/api/archive?workspace_id=${getContextEntities(ctx, boardId).wsId}`)
  },
  'archive.restore': {
    module: 'archive',
    scope: 'company',
    method: 'POST',
    path: '/api/boards/:id/restore',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id) return client.post(`/api/boards/${e.boardId}/restore`, {});
      const bRes = await ctx.ownerClient.post('/api/boards', {
        workspace_id: ctx.w1Id,
        name: `res_b_${Date.now()}`
      });
      const resBId = bRes.data?.board?.id || bRes.data?.id;
      if (client.user?.id && ctx.tenantDb && boardId !== ctx.boardBId) {
        await ctx.tenantDb.execute('INSERT IGNORE INTO board_members (board_id, user_id, role) VALUES (?, ?, ?)', [resBId, client.user.id, 'member']);
      }
      await ctx.ownerClient.post(`/api/boards/${resBId}/archive`, {});
      return client.post(`/api/boards/${resBId}/restore`, {});
    }
  },
  'archive.permanent_delete': {
    module: 'archive',
    scope: 'company',
    method: 'DELETE',
    path: '/api/boards/:id (permanent delete archived board)',
    execute: async (client, ctx, boardId) => {
      const e = getContextEntities(ctx, boardId);
      if (e.wsId !== ctx.w1Id) return client.delete(`/api/boards/${e.boardId}`);
      const bRes = await ctx.ownerClient.post('/api/boards', {
        workspace_id: ctx.w1Id,
        name: `perm_del_b_${Date.now()}`
      });
      const delBId = bRes.data?.board?.id || bRes.data?.id;
      if (client.user?.id && ctx.tenantDb && boardId !== ctx.boardBId) {
        await ctx.tenantDb.execute('INSERT IGNORE INTO board_members (board_id, user_id, role) VALUES (?, ?, ?)', [delBId, client.user.id, 'member']);
      }
      await ctx.ownerClient.post(`/api/boards/${delBId}/archive`, {});
      return client.delete(`/api/boards/${delBId}`);
    }
  },
  'daily_tracker.view': {
    module: 'daily_tracker',
    scope: 'company',
    method: 'GET',
    path: '/api/workspaces/:wId/daily-tracker',
    execute: (client, ctx, boardId) => client.get(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}/daily-tracker`)
  },
  'daily_tracker.view_people': {
    module: 'daily_tracker',
    scope: 'company',
    method: 'GET',
    path: '/api/workspaces/:wId/daily-tracker/people',
    execute: (client, ctx, boardId) => client.get(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}/daily-tracker/people`)
  },
  'task.focus': {
    module: 'task',
    scope: 'project',
    method: 'POST',
    path: '/api/cards/:id/focus',
    execute: (client, ctx, boardId) => client.post(`/api/cards/${getContextEntities(ctx, boardId).cardId}/focus`, {})
  },
  'task.mark_deep_work': {
    module: 'task',
    scope: 'project',
    method: 'POST',
    path: '/api/cards/:id/focus/deep-work',
    execute: (client, ctx, boardId) => client.post(`/api/cards/${getContextEntities(ctx, boardId).cardId}/focus/deep-work`, { deep_work: 1 })
  },
  'checkin.create': {
    module: 'checkin',
    scope: 'project',
    method: 'POST',
    path: '/api/cards/:id/checkins',
    execute: (client, ctx, boardId) => client.post(`/api/cards/${getContextEntities(ctx, boardId).cardId}/checkins`, {
      did: 'Investigated indexing and verified all query plans across tables.',
      next_step: 'Add schema migration and test'
    })
  },
  'checkin.view': {
    module: 'checkin',
    scope: 'project',
    method: 'GET',
    path: '/api/cards/:id/checkins',
    execute: (client, ctx, boardId) => client.get(`/api/cards/${getContextEntities(ctx, boardId).cardId}/checkins`)
  },
  'checkin.review': {
    module: 'checkin',
    scope: 'project',
    method: 'POST',
    path: '/api/checkins/:id/review',
    execute: (client, ctx, boardId) => client.post('/api/checkins/1/review', { action: 'ack', note: 'Acknowledged' })
  },
  'leave.request': {
    module: 'leave',
    scope: 'company',
    method: 'POST',
    path: '/api/workspaces/:wId/leave-days',
    execute: (client, ctx, boardId) => client.post(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}/leave-days`, {
      date: '2026-12-31',
      reason: 'Personal time off'
    })
  },
  'leave.approve': {
    module: 'leave',
    scope: 'company',
    method: 'PATCH',
    path: '/api/workspaces/:wId/leave-days/:id',
    execute: (client, ctx, boardId) => client.patch(`/api/workspaces/${getContextEntities(ctx, boardId).wsId}/leave-days/1`, {
      action: 'approve'
    })
  }
};

module.exports = { PROBES, getContextEntities };

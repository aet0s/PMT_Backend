// server/src/socket.js
// Tenant-namespaced WebSocket server with presence, dragging, and real-time event broadcasting.
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const { getJwtSecret } = require('./middleware/auth');
const { getTenantDb, getDevSingleDb } = require('./services/tenantPools');

let io = null;

// Store active board users: roomKey -> Map(socketId -> { userId, userName, email })
const boardUsersMap = new Map();

function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach((cookie) => {
    const parts = cookie.split('=');
    const name = parts.shift().trim();
    const val = decodeURIComponent(parts.join('='));
    if (name) list[name] = val;
  });
  return list;
}

function getBoardRoom(boardId, tenantId) {
  return tenantId ? `t:${tenantId}:board:${boardId}` : `board:${boardId}`;
}

function getUserRoom(userId, tenantId) {
  return tenantId ? `t:${tenantId}:user:${userId}` : `user:${userId}`;
}

function getWorkspaceRoom(workspaceId, tenantId) {
  return tenantId ? `t:${tenantId}:workspace:${workspaceId}` : `workspace:${workspaceId}`;
}

const { isOriginAllowed, getAllowedOrigins } = require('./utils/corsOrigins');

function initSocket(server) {
  io = new Server(server, {
    cors: {
      origin: (origin, callback) => {
        if (!origin) return callback(null, false);
        if (isOriginAllowed(origin)) {
          return callback(null, true);
        }
        return callback(null, false);
      },
      credentials: true
    },
    allowRequest: (req, callback) => {
      const origin = req.headers.origin;

      // 1. Missing Origin header (non-browser or stripped): reject
      if (!origin) {
        return callback('ORIGIN_REQUIRED: WebSocket handshake requires a valid Origin header.', false);
      }

      // 2. Null origin: reject
      if (origin === 'null') {
        return callback('ORIGIN_NOT_ALLOWED: Null origin is rejected.', false);
      }

      // 3. Foreign / disallowed origin: reject
      if (!isOriginAllowed(origin)) {
        return callback(`ORIGIN_NOT_ALLOWED: Origin '${origin}' is not authorized.`, false);
      }

      // Allowed
      return callback(null, true);
    }
  });

  // JWT Auth Middleware for Socket.io
  io.use(async (socket, next) => {
    try {
      const cookieHeader = socket.handshake.headers.cookie;
      const cookies = parseCookies(cookieHeader);
      const token = cookies.token || socket.handshake.auth?.token || socket.handshake.query?.token;

      if (!token) {
        return next(new Error('unauthorized'));
      }

      const payload = jwt.verify(token, getJwtSecret());
      const userId = Number(payload.sub || payload.userId);
      const tenantId = payload.tid ? Number(payload.tid) : (payload.tenantId ? Number(payload.tenantId) : null);
      const sessionId = payload.sid || null;

      // Item 3: Sockets re-verify the session on connect / reconnect
      if (sessionId) {
        const { checkSessionActive } = require('./middleware/auth');
        let db;
        if (tenantId) {
          db = await getTenantDb(tenantId);
        } else {
          db = getDevSingleDb();
        }
        const sessionStatus = await checkSessionActive(db, tenantId, sessionId);
        if (!sessionStatus.active) {
          return next(new Error(sessionStatus.code || 'SESSION_REVOKED'));
        }
      }

      socket.userId = userId;
      socket.tenantId = tenantId;
      socket.sessionId = sessionId;
      socket.userEmail = payload.email;
      socket.userName = payload.name || (payload.email ? payload.email.split('@')[0] : 'User');

      return next();
    } catch (err) {
      return next(new Error('unauthorized'));
    }
  });

  io.on('connection', (socket) => {
    // Join personal tenant-namespaced user room on connect
    const userRoom = getUserRoom(socket.userId, socket.tenantId);
    socket.join(userRoom);
    // Unconditionally join user room so direct user notifications always reach this user
    socket.join(`user:${socket.userId}`);

    // Join workspace room with tenant isolation
    socket.on('join_workspace', ({ workspaceId, tenantId }) => {
      if (!workspaceId) return;
      const wsId = Number(workspaceId);
      const effectiveTenantId = socket.tenantId || (tenantId ? Number(tenantId) : null);
      const room = getWorkspaceRoom(wsId, effectiveTenantId);
      socket.join(room);
      if (process.env.DEV_SINGLE_TENANT === '1') {
        socket.join(`workspace:${wsId}`);
      }
    });

    socket.on('leave_workspace', ({ workspaceId, tenantId }) => {
      if (!workspaceId) return;
      const wsId = Number(workspaceId);
      const effectiveTenantId = socket.tenantId || (tenantId ? Number(tenantId) : null);
      const room = getWorkspaceRoom(wsId, effectiveTenantId);
      socket.leave(room);
      if (process.env.DEV_SINGLE_TENANT === '1') {
        socket.leave(`workspace:${wsId}`);
      }
    });

    // Join board room with tenant isolation
    socket.on('join_board', async ({ boardId, tenantId }) => {
      if (!boardId) return;

      // Cross-tenant guard: if a tenantId is explicitly requested and doesn't match token tenantId
      if (tenantId && socket.tenantId && Number(tenantId) !== Number(socket.tenantId)) {
        socket.emit('error', { message: 'Cross-tenant board access denied', code: 'FORBIDDEN' });
        return;
      }

      const bId = Number(boardId);
      const effectiveTenantId = socket.tenantId || (tenantId ? Number(tenantId) : null);

      // Verify board existence and user permission in tenant DB to prevent unauthorized room joins
      if (effectiveTenantId) {
        try {
          const tenantDb = await getTenantDb(effectiveTenantId);
          const bRows = await tenantDb.query('SELECT id, workspace_id FROM boards WHERE id = ?', [bId]);
          if (!bRows || bRows.length === 0) {
            socket.emit('error', { message: 'Board not found in tenant', code: 'NOT_FOUND' });
            return;
          }
          const workspaceId = bRows[0].workspace_id;
          const { userHasPermission } = require('./middleware/permissions');
          const hasAccess = await userHasPermission(socket.userId, workspaceId, 'project.view', tenantDb, bId);
          if (!hasAccess) {
            socket.emit('error', { message: 'You do not have permission to view this project', code: 'PERMISSION_DENIED' });
            return;
          }
        } catch (err) {
          socket.emit('error', { message: 'Failed to verify board access', code: 'FORBIDDEN' });
          return;
        }
      }

      const room = getBoardRoom(bId, effectiveTenantId);

      socket.join(room);
      if (process.env.DEV_SINGLE_TENANT === '1') {
        socket.join(`board:${bId}`);
      }
      socket.currentBoardRoom = room;
      socket.currentBoardId = bId;

      if (!boardUsersMap.has(room)) {
        boardUsersMap.set(room, new Map());
      }
      const boardMap = boardUsersMap.get(room);
      boardMap.set(socket.id, { id: socket.userId, name: socket.userName, email: socket.userEmail });

      const uniqueMembers = Array.from(
        new Map(Array.from(boardMap.values()).map((m) => [m.id, m])).values()
      );

      io.to(room).emit('board:presence_update', {
        boardId: bId,
        onlineMembers: uniqueMembers
      });
    });

    // Leave board room
    socket.on('leave_board', ({ boardId, tenantId }) => {
      if (!boardId) return;
      const bId = Number(boardId);
      const effectiveTenantId = socket.tenantId || (tenantId ? Number(tenantId) : null);
      const room = getBoardRoom(bId, effectiveTenantId);

      socket.leave(room);

      if (boardUsersMap.has(room)) {
        const boardMap = boardUsersMap.get(room);
        boardMap.delete(socket.id);
        const uniqueMembers = Array.from(
          new Map(Array.from(boardMap.values()).map((m) => [m.id, m])).values()
        );

        io.to(room).emit('board:presence_update', {
          boardId: bId,
          onlineMembers: uniqueMembers
        });
      }
      delete socket.currentBoardRoom;
      delete socket.currentBoardId;
    });

    // Live Drag & Mouse Pointer Streaming
    socket.on('card_drag_move', ({ boardId, cardId, cardTitle, card, x, y }) => {
      if (!boardId) return;
      const room = getBoardRoom(Number(boardId), socket.tenantId);
      socket.to(room).emit('card:dragging', {
        socketId: socket.id,
        userId: socket.userId,
        userName: socket.userName,
        cardId,
        cardTitle,
        card,
        x,
        y
      });
    });

    socket.on('card_drag_end', ({ boardId, cardId }) => {
      if (!boardId) return;
      const room = getBoardRoom(Number(boardId), socket.tenantId);
      socket.to(room).emit('card:drag_ended', {
        socketId: socket.id,
        userId: socket.userId,
        cardId
      });
    });

    socket.on('list_drag_move', ({ boardId, listId, list, x, y }) => {
      if (!boardId) return;
      const room = getBoardRoom(Number(boardId), socket.tenantId);
      socket.to(room).emit('list:dragging', {
        socketId: socket.id,
        userId: socket.userId,
        userName: socket.userName,
        listId,
        list,
        x,
        y
      });
    });

    socket.on('list_drag_end', ({ boardId, listId }) => {
      if (!boardId) return;
      const room = getBoardRoom(Number(boardId), socket.tenantId);
      socket.to(room).emit('list:drag_ended', {
        socketId: socket.id,
        userId: socket.userId,
        listId
      });
    });

    // Disconnect cleanup
    socket.on('disconnect', () => {
      const room = socket.currentBoardRoom;
      const bId = socket.currentBoardId;
      if (room && boardUsersMap.has(room)) {
        const boardMap = boardUsersMap.get(room);
        boardMap.delete(socket.id);
        const uniqueMembers = Array.from(
          new Map(Array.from(boardMap.values()).map((m) => [m.id, m])).values()
        );

        io.to(room).emit('board:presence_update', {
          boardId: bId,
          onlineMembers: uniqueMembers
        });
      }
    });
  });

  return io;
}

function getIO() {
  if (!io) {
    throw new Error('Socket.io has not been initialized!');
  }
  return io;
}

function broadcastBoardEvent(boardId, eventName, payload, originId, tenantId = null, clientMutationId = null) {
  if (!io || !boardId) return;
  const bId = Number(boardId);
  const data = {
    ...payload,
    originId: originId || null,
    clientMutationId: clientMutationId || payload?.clientMutationId || null,
    updated_at: payload?.updated_at || payload?.card?.updated_at || new Date().toISOString(),
    timestamp: new Date().toISOString()
  };

  if (tenantId && process.env.DEV_SINGLE_TENANT !== '1') {
    io.to(`t:${tenantId}:board:${bId}`).emit(eventName, data);
  } else {
    // Emit to both namespaced and fallback rooms
    io.to(`board:${bId}`).emit(eventName, data);
    if (tenantId) {
      io.to(`t:${tenantId}:board:${bId}`).emit(eventName, data);
    }
  }
}

function broadcastWorkspaceEvent(workspaceId, eventName, payload, originId = null, tenantId = null) {
  if (!io || !workspaceId) return;
  const wsId = Number(workspaceId);
  const data = {
    ...payload,
    originId: originId || null,
    workspaceId: wsId,
    timestamp: new Date().toISOString()
  };

  if (tenantId && process.env.DEV_SINGLE_TENANT !== '1') {
    io.to(`t:${tenantId}:workspace:${wsId}`).emit(eventName, data);
  } else {
    io.to(`workspace:${wsId}`).emit(eventName, data);
    if (tenantId) {
      io.to(`t:${tenantId}:workspace:${wsId}`).emit(eventName, data);
    }
  }
}

function sendUserNotification(userId, notification, tenantId = null) {
  if (!io || !userId) return;
  if (tenantId) {
    io.to(`t:${tenantId}:user:${userId}`).emit('notification:new', notification);
  }
  io.to(`user:${userId}`).emit('notification:new', notification);
}

function sendUserEvent(userId, eventName, payload, tenantId = null) {
  if (!io || !userId) return;
  if (tenantId) {
    io.to(`t:${tenantId}:user:${userId}`).emit(eventName, payload);
  }
  io.to(`user:${userId}`).emit(eventName, payload);
}

/**
 * Item 3: Disconnects all active sockets for a specific user upon session revocation,
 * password change, role change, or member removal.
 */
function disconnectUserSockets(userId, tenantId = null, reason = 'SESSION_REVOKED') {
  if (!io || !userId) return;
  const targetUserId = Number(userId);
  const targetTenantId = tenantId ? Number(tenantId) : null;

  for (const [, socket] of io.sockets.sockets) {
    const sUserId = Number(socket.userId);
    const sTenantId = socket.tenantId ? Number(socket.tenantId) : null;

    if (sUserId === targetUserId && (!targetTenantId || sTenantId === targetTenantId)) {
      socket.emit('auth:revoked', {
        reason,
        message: 'Your session has been terminated. Please log in again.'
      });
      socket.disconnect(true);
    }
  }
}

/**
 * Disconnects all active sockets for all users belonging to a tenant (e.g. upon tenant suspension or deletion).
 */
function disconnectTenantSockets(tenantId, reason = 'TENANT_SUSPENDED') {
  if (!io || !tenantId) return;
  const targetTenantId = Number(tenantId);

  for (const [, socket] of io.sockets.sockets) {
    const sTenantId = socket.tenantId ? Number(socket.tenantId) : null;
    if (sTenantId === targetTenantId) {
      socket.emit('auth:revoked', {
        reason,
        message: 'Tenant organization has been suspended or deleted.'
      });
      socket.disconnect(true);
    }
  }
}

module.exports = {
  initSocket,
  getIO,
  broadcastBoardEvent,
  broadcastWorkspaceEvent,
  sendUserNotification,
  sendUserEvent,
  disconnectUserSockets,
  disconnectTenantSockets,
  getBoardRoom,
  getWorkspaceRoom,
  getUserRoom
};

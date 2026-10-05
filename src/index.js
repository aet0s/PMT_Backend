const express = require('express');
const http = require('http');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

// Safety check: Refuse to boot if DISABLE_RATE_LIMIT is set in production
if (process.env.NODE_ENV === 'production' && process.env.DISABLE_RATE_LIMIT) {
  console.error('[FATAL] Server boot refused: DISABLE_RATE_LIMIT is strictly prohibited when NODE_ENV=production.');
  process.exit(1);
}

const db = require('./db');
const { initSocket } = require('./socket');
const { initReminderCron } = require('./cron/reminders');

const authRouter = require('./routes/auth');
const workspacesRouter = require('./routes/workspaces');
const boardsRouter = require('./routes/boards');
const listsRouter = require('./routes/lists');
const cardsRouter = require('./routes/cards');
const archiveRouter = require('./routes/archive');
const invitationsRouter = require('./routes/invitations');
const notificationsRouter = require('./routes/notifications');
const permissionsRouter = require('./routes/permissions');
const rolesRouter = require('./routes/roles');
const filesRouter = require('./routes/files');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 5000;

// CORS setup for credentials (cookies)
app.use(
  cors({
    origin: process.env.CLIENT_URL || 'http://localhost:5173',
    credentials: true
  })
);

app.use(cookieParser());
app.use(express.json());

// Secure tenant-isolated file serving (requires authentication, prevents cross-tenant access and path traversal)
app.use('/uploads', (req, res, next) => {
  filesRouter(req, res, next);
});

// API Routes
app.use('/api/auth', authRouter);
app.use('/api/workspaces', workspacesRouter);
app.use('/api/boards', boardsRouter);
app.use('/api/lists', listsRouter);
app.use('/api/cards', cardsRouter);
app.use('/api/archive', archiveRouter);
app.use('/api/invitations', invitationsRouter);
app.use('/api/notifications', notificationsRouter);
app.use('/api/permissions', permissionsRouter);
app.use('/api/roles', rolesRouter);
app.use('/api/files', filesRouter);

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Dev/Test helper - ONLY registered when NODE_ENV === 'test'
if (process.env.NODE_ENV === 'test') {
  const { resetAllRateLimits } = require('./middleware/rateLimit');
  app.post('/api/dev/reset-rate-limit', (req, res) => {
    resetAllRateLimits();
    res.json({ ok: true });
  });
}

// Centralized Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled Server Error:', err);
  const status = err.status || 400;
  const message = err.message || 'Internal Server Error';
  const code = err.code || 'BAD_REQUEST';

  res.status(status).json({
    error: { message, code }
  });
});

// SPA Production / Build Static Hosting Fallback
const clientDist = path.resolve(__dirname, '../../client/dist');
if (fs.existsSync(clientDist)) {
  app.use('/assets', express.static(path.join(clientDist, 'assets'), {
    maxAge: '1y',
    immutable: true
  }));
  app.use(express.static(clientDist, {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('index.html')) {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      }
    }
  }));
  app.get('*', (req, res, next) => {
    if (
      req.path.startsWith('/api') ||
      req.path.startsWith('/socket.io') ||
      req.path.startsWith('/uploads') ||
      req.path.startsWith('/api/files')
    ) {
      return next();
    }
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.sendFile(path.join(clientDist, 'index.html'));
  });
}

const { assertEnv } = require('./config/env');

async function start() {
  assertEnv();
  await db.ensureRuntimeSchema();
  initSocket(server);
  initReminderCron();

  server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

if (require.main === module) {
  start().catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}

module.exports = { app, server, start };

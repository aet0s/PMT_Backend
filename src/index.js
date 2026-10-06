const express = require('express');
const http = require('http');
const https = require('https');
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

// Safety check: Refuse to boot with built-in HTTPS in production (Nginx reverse proxy must terminate TLS)
if (process.env.NODE_ENV === 'production' && process.env.HTTPS === 'true') {
  console.error('[FATAL] Server boot refused: Built-in HTTPS server (HTTPS=true) is prohibited in production. Nginx reverse proxy must terminate TLS.');
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
const attachmentsRouter = require('./routes/attachments');
const upload = require('./middleware/upload');
const localStorage = require('./storage');
const { requireAuth } = require('./middleware/auth');

const helmet = require('helmet');

const app = express();
const isHttps = process.env.HTTPS === 'true' && process.env.SSL_CERT && fs.existsSync(process.env.SSL_CERT);
const server = isHttps
  ? https.createServer(
      {
        cert: fs.readFileSync(process.env.SSL_CERT),
        key: fs.readFileSync(process.env.SSL_KEY)
      },
      app
    )
  : http.createServer(app);
const PORT = process.env.PORT || 5000;

// Trust reverse proxy (nginx) for real client IP, protocol, and Secure cookies
app.set('trust proxy', 1);

function getAllowedOrigins() {
  const list = (process.env.CORS_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const defaults = [
    'https://pmt.solarman.in',
    'https://pmtmgmt.solarman.in',
    'http://localhost:5173',
    'http://127.0.0.1:5173'
  ];
  for (const d of defaults) {
    if (!list.includes(d)) list.push(d);
  }
  if (process.env.CLIENT_URL) {
    const cUrl = process.env.CLIENT_URL.trim();
    if (!list.includes(cUrl)) list.push(cUrl);
  }
  return list;
}

const { requestIdMiddleware } = require('./middleware/requestId');
app.use(requestIdMiddleware);

// Helmet Security Headers with strict same-origin default and HSTS in production
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'same-origin' },
    contentSecurityPolicy: false,
    hsts: process.env.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false
  })
);

// Comprehensive Security Headers for all responses (including dev & reverse-proxied HTTPS)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Origin-Agent-Cluster', '?1');
  if (req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  next();
});

// Allow cross-origin embedding ONLY for authenticated tenant file route /api/files
app.use('/api/files', (req, res, next) => {
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  next();
});

// CORS setup for cross-subdomain credentials (cookies) and all frontend mutation headers
const allowedOrigins = getAllowedOrigins();
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || origin === 'null') {
        return callback(null, false);
      }
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(null, false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'x-origin-id',
      'x-client-mutation-id',
      'X-Requested-With',
      'Accept',
      'Origin',
      'Cache-Control',
      'X-Request-Id',
      'X-Forwarded-For'
    ],
    exposedHeaders: ['X-Request-Id'],
    maxAge: 86400
  })
);

const { csrfProtection } = require('./middleware/csrf');
app.use(csrfProtection(getAllowedOrigins));

app.use(cookieParser());
app.use(express.json());

// Direct access to /uploads is strictly prohibited in all environments.
// Files must only be accessed through the authenticated /api/files route with permission checks.
app.use('/uploads', (req, res) => {
  res.status(404).json({
    error: {
      message: 'Direct static access to /uploads is disabled. Files are only accessible via authenticated /api/files endpoints.',
      code: 'NOT_FOUND'
    }
  });
});

// API Routes
app.use('/api/auth', authRouter);
app.use('/api/workspaces', workspacesRouter);
app.use('/api/boards', boardsRouter);
app.use('/api/lists', listsRouter);
app.use('/api/cards', cardsRouter);
app.use('/api/archive', archiveRouter);
app.use('/api/archived', archiveRouter);
app.use('/api/attachments', attachmentsRouter);
app.use('/api/invitations', invitationsRouter);
app.use('/api/notifications', notificationsRouter);
app.use('/api/permissions', permissionsRouter);
app.use('/api/roles', rolesRouter);
app.use('/api/files', filesRouter);

// POST /api/upload - Standalone file upload endpoint
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: { message: 'File is required', code: 'BAD_REQUEST' } });
    }
    const saved = await localStorage.save(req.file, null, req.tenant ? req.tenant.id : 1);
    return res.status(201).json({
      message: 'File uploaded successfully',
      file: {
        file_name: saved.file_name,
        file_url: saved.file_url,
        file_type: saved.file_type,
        file_size_bytes: saved.file_size_bytes
      }
    });
  } catch (err) {
    next(err);
  }
});

const { getSystemHealthStatus } = require('./db/migrator');

// Health Check (Non-sensitive status: ok / migrating / degraded; no versions or names)
app.get('/api/health', (req, res) => {
  res.json({ status: getSystemHealthStatus(), timestamp: new Date().toISOString() });
});

// Dev/Test helper - ONLY registered when NODE_ENV === 'test'
if (process.env.NODE_ENV === 'test') {
  const { resetAllRateLimits } = require('./middleware/rateLimit');
  app.post('/api/dev/reset-rate-limit', (req, res) => {
    resetAllRateLimits();
    res.json({ ok: true });
  });
}

// Unknown /api route catch-all returns JSON 404
app.use('/api', (req, res) => {
  res.status(404).json({
    error: {
      message: `Endpoint ${req.method} ${req.originalUrl || req.path} not found`,
      code: 'NOT_FOUND',
      requestId: req.id
    }
  });
});

// Centralized Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(`[${req.id || 'NO_REQ_ID'}] Unhandled Server Error:`, err);
  const status = err.status || 400;
  const message = err.message || 'Internal Server Error';
  const code = err.code || 'BAD_REQUEST';

  res.status(status).json({
    error: { message, code, requestId: req.id }
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
const { checkProdEnv } = require('./scripts/checkProdEnv');

async function start() {
  assertEnv();

  // K-A.8.11: Automatically enforce full production security pre-flight checks on boot
  if (process.env.NODE_ENV === 'production') {
    const { errors, warnings } = checkProdEnv(process.env);
    if (warnings.length > 0) {
      console.log('\n⚠️  PRODUCTION PRE-FLIGHT WARNINGS:');
      for (const w of warnings) {
        console.warn(`  - ${w}`);
      }
    }
    if (errors.length > 0) {
      console.error('\n❌ PRODUCTION BOOT ABORTED: check:prod-env verification failed:');
      for (const err of errors) {
        console.error(`  ✖ ${err}`);
      }
      console.error('\nAborting startup. Correct these environment variables before deploying to production.\n');
      process.exit(1);
    }
  }

  try {
    await db.ensureRuntimeSchema();
  } catch (migErr) {
    console.error('\n❌ [FATAL] Boot schema migration failed. Aborting startup to prevent serving traffic on an unmigrated or corrupted schema:');
    console.error(`  ✖ ${migErr.message}\n`);
    process.exit(1);
  }

  initSocket(server);
  initReminderCron();
  const { startCleanupWorker } = require('./utils/fileCleanupQueue');
  startCleanupWorker();

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

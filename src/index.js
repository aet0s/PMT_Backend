const express = require('express');
const http = require('http');
const https = require('https');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

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
const { initRetentionCron } = require('./cron/retention');
const { initAutoArchiveCron } = require('./cron/autoArchive');

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
const checkinsRouter = require('./routes/checkins');
const pushRouter = require('./routes/push');
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

const { getAllowedOrigins, isOriginAllowed } = require('./utils/corsOrigins');

const { requestIdMiddleware } = require('./middleware/requestId');
app.use(requestIdMiddleware);

const { auditContextMiddleware } = require('./utils/auditContext');
app.use(auditContextMiddleware);

const { auditSafetyNetMiddleware } = require('./middleware/auditSafetyNet');
app.use(auditSafetyNetMiddleware);

// Helmet Security Headers with cross-origin resource policy for subdomains and HSTS in production
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
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
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  res.setHeader('Origin-Agent-Cluster', '?1');
  if (req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  next();
});

// Explicit CORS origin injector to guarantee headers on all responses (including early errors and preflights)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && isOriginAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    
    // Dynamically reflect requested headers to support extensions, auth headers, and tenant IDs
    const reqHeaders = req.headers['access-control-request-headers'];
    if (reqHeaders) {
      res.setHeader('Access-Control-Allow-Headers', reqHeaders);
    } else {
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, X-CSRF-Token, x-origin-id, x-client-mutation-id, X-Requested-With, Accept, Origin, Cache-Control, X-Request-Id, X-Forwarded-For, x-tenant-id, x-tenant-slug'
      );
    }
    res.setHeader('Access-Control-Expose-Headers', 'X-Request-Id, Date, X-Server-Time, X-CSRF-Token');
    res.setHeader('Access-Control-Max-Age', '86400');

    // Respond immediately to OPTIONS preflight requests
    if (req.method === 'OPTIONS') {
      return res.sendStatus(204);
    }
  }
  next();
});

// Allow cross-origin embedding for authenticated tenant file route /api/files
app.use('/api/files', (req, res, next) => {
  res.removeHeader('X-Frame-Options');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  next();
});

// CORS setup for cross-subdomain credentials (cookies) and all frontend mutation headers
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || origin === 'null') {
        return callback(null, false);
      }
      if (isOriginAllowed(origin)) {
        return callback(null, true);
      }
      return callback(null, false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    exposedHeaders: ['X-Request-Id', 'Date', 'X-Server-Time', 'X-CSRF-Token'],
    maxAge: 86400
  })
);

app.use((req, res, next) => {
  res.setHeader('X-Server-Time', new Date().toISOString());
  next();
});

app.use(cookieParser());

const { csrfProtection, injectCsrfCookie } = require('./middleware/csrf');
app.use((req, res, next) => {
  injectCsrfCookie(req, res);
  next();
});
app.use(csrfProtection(getAllowedOrigins));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Dedicated server time endpoint for instant client synchronization
app.get('/api/time', (req, res) => {
  const now = new Date();
  const csrf = req.cookies?.csrfToken || res.getHeader('X-CSRF-Token') || null;
  res.json({
    server_time: now.toISOString(),
    serverTime: now.toISOString(),
    server_time_ms: now.getTime(),
    timezone: process.env.APP_TIMEZONE || process.env.TZ || 'Asia/Kolkata',
    csrfToken: csrf,
    csrf_token: csrf
  });
});

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


// Public RSA key for hybrid encryption envelope (supports both /keys/server-public.pem and /api/public-key)
app.get(['/keys/server-public.pem', '/api/public-key'], (req, res) => {
  // 1. If active RSA private key is loaded, dynamically export its public key
  try {
    const { getPrivateKey } = require('./secure/crypto');
    const activeKey = getPrivateKey();
    if (activeKey && activeKey.keyObject) {
      const pubPem = crypto.createPublicKey(activeKey.keyObject).export({ type: 'spki', format: 'pem' });
      res.setHeader('Content-Type', 'application/x-pem-file');
      res.setHeader('Cache-Control', 'public, max-age=86400');
      return res.send(pubPem);
    }
  } catch (_) {}

  // 2. Candidate persistent and local public key file paths
  const candidatePubs = [
    process.env.SERVER_PUBLIC_KEY_PATH && path.resolve(process.env.SERVER_PUBLIC_KEY_PATH),
    path.resolve('/data/projects/pmt/keys/public.pem'),
    path.resolve(__dirname, '../../keys/public.pem'),
    path.resolve(__dirname, '../keys/public.pem'),
    path.resolve(process.cwd(), '../keys/public.pem'),
    path.resolve(process.cwd(), 'keys/public.pem'),
    path.resolve(__dirname, '../../client/public/keys/server-public.pem')
  ].filter(Boolean);

  for (const pubPath of candidatePubs) {
    if (fs.existsSync(pubPath)) {
      res.setHeader('Content-Type', 'application/x-pem-file');
      res.setHeader('Cache-Control', 'public, max-age=86400');
      return res.sendFile(pubPath);
    }
  }
  res.status(404).send('Public key not found');
});

// Encrypted POST-Only Business Gateway (POST /api/secure)
const { router: secureRouter } = require('./secure/gateway');
app.use('/api', secureRouter);

// RETIRED: Direct plaintext REST routes are permanently disabled.
// All business operations must use POST /api/secure with hybrid encryption.

// POST /api/upload - Standalone file upload endpoint supporting 'file', 'icon', and 'avatar' fields
function detectImageMagicBytes(buffer) {
  if (!buffer || buffer.length < 8) return null;
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return 'image/jpeg';
  if (
    buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47 &&
    buffer[4] === 0x0D && buffer[5] === 0x0A && buffer[6] === 0x1A && buffer[7] === 0x0A
  ) return 'image/png';
  const header6 = buffer.slice(0, 6).toString('ascii');
  if (header6 === 'GIF87a' || header6 === 'GIF89a') return 'image/gif';
  if (
    buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
    buffer.length >= 12 && buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50
  ) return 'image/webp';
  return null;
}

const genericUpload = upload.fields([
  { name: 'file', maxCount: 1 },
  { name: 'icon', maxCount: 1 },
  { name: 'avatar', maxCount: 1 }
]);

app.post('/api/upload', requireAuth, (req, res, next) => {
  genericUpload(req, res, (err) => {
    if (err) return next(err);
    if (!req.file && req.files) {
      req.file = req.files.file?.[0] || req.files.icon?.[0] || req.files.avatar?.[0];
    }
    next();
  });
}, async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: { message: 'File is required', code: 'BAD_REQUEST' } });
    }

    const tenantId = req.tenant ? req.tenant.id : 1;
    const purpose = String(req.body.purpose || '').trim();
    const { userHasPermission } = require('./middleware/permissions');

    // 1. WORKSPACE ICON UPLOAD
    if (purpose === 'workspace_icon' || req.body.workspace_id) {
      const workspaceId = Number(req.body.workspace_id);
      if (!workspaceId) {
        return res.status(400).json({ error: { message: 'workspace_id is required for workspace icon upload', code: 'BAD_REQUEST' } });
      }

      // Max size: 5MB
      if (req.file.size > 5 * 1024 * 1024) {
        return res.status(400).json({ error: { message: 'Image must not exceed 5MB', code: 'FILE_TOO_LARGE' } });
      }

      // Magic bytes check (JPEG, PNG, WebP, GIF, SVG)
      const verifiedMime = detectImageMagicBytes(req.file.buffer);
      const isSvg = (req.file.mimetype || '').includes('svg') || (req.file.originalname || '').toLowerCase().endsWith('.svg');
      if (!verifiedMime && !isSvg) {
        return res.status(400).json({
          error: {
            message: 'Invalid file format. Magic bytes do not match a valid JPEG, PNG, WebP, GIF, or SVG image.',
            code: 'INVALID_IMAGE_TYPE'
          }
        });
      }

      // Check workspace exists
      const ws = await req.db.query('SELECT id, name FROM workspaces WHERE id = ?', [workspaceId]);
      if (!ws || ws.length === 0) {
        return res.status(404).json({ error: { message: 'Workspace not found', code: 'NOT_FOUND' } });
      }

      // Check user membership & workspace.edit permission
      const hasEdit = await userHasPermission(req.user.id, workspaceId, 'workspace.edit', req.db);
      if (!hasEdit) {
        return res.status(403).json({ error: { message: 'Access denied: workspace.edit permission required', code: 'FORBIDDEN' } });
      }

      const saved = await localStorage.saveWorkspaceIcon(tenantId, workspaceId, req.file);
      return res.status(201).json({
        message: 'Workspace icon uploaded successfully',
        file: {
          file_name: req.file.originalname,
          file_url: saved.file_url,
          file_type: verifiedMime || (isSvg ? 'image/svg+xml' : 'image/png'),
          file_size_bytes: req.file.size
        }
      });
    }

    // 2. AVATAR UPLOAD
    if (purpose === 'avatar' || req.body.user_id) {
      const targetUserId = Number(req.body.user_id) || req.user.id;
      if (targetUserId !== req.user.id && req.user.role !== 'admin' && req.user.role !== 'owner') {
        return res.status(403).json({ error: { message: 'Access denied: cannot upload avatar for another user', code: 'FORBIDDEN' } });
      }

      if (req.file.size > 5 * 1024 * 1024) {
        return res.status(400).json({ error: { message: 'Image must not exceed 5MB', code: 'FILE_TOO_LARGE' } });
      }

      const verifiedMime = detectImageMagicBytes(req.file.buffer);
      if (!verifiedMime) {
        return res.status(400).json({ error: { message: 'Invalid file format: must be valid image', code: 'INVALID_IMAGE_TYPE' } });
      }

      const saved = await localStorage.saveAvatar(tenantId, targetUserId, req.file);
      return res.status(201).json({
        message: 'Avatar uploaded successfully',
        file: {
          file_name: req.file.originalname,
          file_url: saved.file_url,
          file_type: verifiedMime,
          file_size_bytes: req.file.size
        }
      });
    }

    // 3. CARD ATTACHMENT UPLOAD
    const cardId = req.body.card_id ? Number(req.body.card_id) : null;
    if (cardId) {
      const cardRows = await req.db.query(
        `SELECT c.id, l.board_id, b.workspace_id
         FROM cards c
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE c.id = ?`,
        [cardId]
      );
      if (!cardRows || cardRows.length === 0) {
        return res.status(404).json({ error: { message: 'Card not found', code: 'NOT_FOUND' } });
      }
      const card = cardRows[0];
      const hasUpload = await userHasPermission(req.user.id, card.workspace_id, 'attachment.upload', req.db, card.board_id);
      if (!hasUpload) {
        return res.status(403).json({ error: { message: 'Access denied: attachment.upload permission required', code: 'FORBIDDEN' } });
      }
    }

    const saved = await localStorage.save(req.file, cardId || 'temp', tenantId);
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

// Server Time endpoint (Public, returns server timestamp, IST time, and IST time-based greeting)
app.get('/api/time', (req, res) => {
  const now = new Date();
  const istFormatter = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Kolkata',
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric',
    hour12: false
  });
  const parts = istFormatter.formatToParts(now);
  const hourRaw = parts.find((p) => p.type === 'hour')?.value;
  const hour = hourRaw ? parseInt(hourRaw, 10) : now.getHours();
  const istHour = hour === 24 ? 0 : hour;

  let greeting = 'Good Evening';
  if (istHour < 12) {
    greeting = 'Good Morning';
  } else if (istHour < 17) {
    greeting = 'Good Afternoon';
  }

  res.json({
    serverTime: now.toISOString(),
    timeZone: 'Asia/Kolkata',
    istHour,
    greeting
  });
});

// Dev/Test helper - ONLY registered when NODE_ENV === 'test'
if (process.env.NODE_ENV === 'test') {
  const { resetAllRateLimits } = require('./middleware/rateLimit');
  app.post('/api/dev/reset-rate-limit', (req, res) => {
    resetAllRateLimits();
    res.json({ ok: true });
  });
}

// RETIREMENT OF ALL LEGACY PLAINTEXT BUSINESS API ACCESS PATHS
// Direct access to legacy REST routes is permanently disabled.
app.all('/api/*', (req, res) => {
  const origin = req.headers.origin;
  if (origin && isOriginAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  res.status(410).json({
    error: {
      message: `Endpoint retired: Direct plaintext REST API access to ${req.method} ${req.originalUrl || req.path} has been permanently disabled. All business operations must use POST /api/secure with hybrid encryption.`,
      code: 'ENDPOINT_RETIRED',
      requestId: req.id
    }
  });
});

// Centralized Error Handling Middleware
app.use((err, req, res, next) => {
  const origin = req.headers.origin;
  if (origin && isOriginAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  // Handle express.json() JSON parse errors gracefully
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      error: {
        message: 'Malformed JSON payload',
        code: 'INVALID_JSON',
        requestId: req.id
      }
    });
  }

  const isMulter = err.name === 'MulterError';
  const status = Number(err.status || err.statusCode) || (isMulter ? 400 : 500);

  if (status >= 500) {
    console.error(`[${req.id || 'NO_REQ_ID'}] Unhandled Server Error:`, err);
    // Never expose raw exception messages, stack traces, or internal errors to clients
    return res.status(status).json({
      error: {
        message: 'Internal Server Error',
        code: 'INTERNAL_ERROR',
        requestId: req.id
      }
    });
  }

  const message = err.message || 'Bad Request';
  const code = err.code || (isMulter ? 'UPLOAD_ERROR' : 'BAD_REQUEST');

  console.warn(`[${req.id || 'NO_REQ_ID'}] Client Error ${status} (${code}): ${message}`);

  return res.status(status).json({
    error: {
      message,
      code,
      requestId: req.id
    }
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
    const { syncAllTenantsPermissionCatalog } = require('./rbac/catalogSync');
    await syncAllTenantsPermissionCatalog();
  } catch (migErr) {
    console.error('\n❌ [FATAL] Boot schema migration failed. Aborting startup to prevent serving traffic on an unmigrated or corrupted schema:');
    console.error(`  ✖ ${migErr.message}\n`);
    process.exit(1);
  }

  initSocket(server);
  initReminderCron();
  initRetentionCron();
  initAutoArchiveCron();
  const { startCleanupWorker } = require('./utils/fileCleanupQueue');
  startCleanupWorker();

  server.listen(PORT, '0.0.0.0', () => {
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

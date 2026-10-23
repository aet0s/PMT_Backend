// server/src/routes/files.js
// Authenticated and tenant-isolated file serving and avatar upload endpoint.
const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const { requireAuth, getJwtSecret } = require('../middleware/auth');
const storage = require('../storage');
const auditService = require('../services/audit');

const router = express.Router();
const UPLOADS_DIR = storage.UPLOADS_DIR || (process.env.UPLOADS_DIR
  ? path.resolve(process.env.UPLOADS_DIR)
  : path.resolve(__dirname, '../../uploads'));

/**
 * Safely resolves an uploaded file path across known upload roots.
 * Strictly verifies against path traversal attacks.
 */
function resolveUploadFilePath(tenantId, relativeSubpath) {
  const cleanSubpath = String(relativeSubpath || '').replace(/^[/\\]+/, '');
  const tId = String(tenantId);

  const candidateBases = [];
  if (storage.UPLOADS_DIR) {
    candidateBases.push(storage.UPLOADS_DIR);
  }
  if (process.env.UPLOADS_DIR) {
    candidateBases.push(path.resolve(process.env.UPLOADS_DIR));
  }
  candidateBases.push(path.resolve(__dirname, '../../uploads'));
  candidateBases.push(path.resolve(__dirname, '../../../uploads'));
  candidateBases.push(path.resolve(process.cwd(), 'uploads'));
  candidateBases.push(path.resolve('/data/projects/pmt/server/uploads'));

  const uniqueBases = Array.from(new Set(candidateBases));

  for (const base of uniqueBases) {
    // 1. Candidate with tenant directory: <base>/<tenantId>/<cleanSubpath>
    const tenantTarget = path.resolve(base, tId, cleanSubpath);
    const tenantPrefix = path.resolve(base, tId);
    if ((tenantTarget.startsWith(tenantPrefix + path.sep) || tenantTarget === tenantPrefix) && fs.existsSync(tenantTarget)) {
      return tenantTarget;
    }

    // 2. Candidate directly under base: <base>/<cleanSubpath>
    const directTarget = path.resolve(base, cleanSubpath);
    const directPrefix = path.resolve(base);
    if ((directTarget.startsWith(directPrefix + path.sep) || directTarget === directPrefix) && fs.existsSync(directTarget)) {
      return directTarget;
    }
  }

  // Fallback to default expected path
  return path.resolve(UPLOADS_DIR, tId, cleanSubpath);
}

/**
 * Item 6: Verify magic bytes for images (JPEG, PNG, WebP, GIF)
 * rather than blindly trusting the user-provided MIME header.
 */
function detectImageMagicBytes(buffer) {
  if (!buffer || buffer.length < 8) return null;

  // JPEG: FF D8 FF
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return 'image/jpeg';
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4E &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0D &&
    buffer[5] === 0x0A &&
    buffer[6] === 0x1A &&
    buffer[7] === 0x0A
  ) {
    return 'image/png';
  }

  // GIF: GIF87a or GIF89a
  const header6 = buffer.slice(0, 6).toString('ascii');
  if (header6 === 'GIF87a' || header6 === 'GIF89a') {
    return 'image/gif';
  }

  // WebP: RIFF....WEBP
  if (
    buffer[0] === 0x52 &&
    buffer[1] === 0x49 &&
    buffer[2] === 0x46 &&
    buffer[3] === 0x46 &&
    buffer.length >= 12 &&
    buffer[8] === 0x57 &&
    buffer[9] === 0x45 &&
    buffer[10] === 0x42 &&
    buffer[11] === 0x50
  ) {
    return 'image/webp';
  }

  return null;
}

const avatarUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (!allowed.includes(file.mimetype)) {
      const err = new Error('Invalid file type. Only JPEG, PNG, WebP, and GIF images are permitted.');
      err.code = 'INVALID_IMAGE_TYPE';
      err.status = 400;
      return cb(err);
    }
    cb(null, true);
  }
});

// POST /api/files/avatar - Upload validated user avatar
router.post('/avatar', requireAuth, (req, res, next) => {
  avatarUpload.single('avatar')(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: { message: 'Image must not exceed 2MB', code: 'FILE_TOO_LARGE' } });
      }
      return res.status(err.status || 400).json({ error: { message: err.message, code: err.code || 'UPLOAD_ERROR' } });
    }

    if (!req.file) {
      return res.status(400).json({ error: { message: 'No image file uploaded', code: 'NO_FILE' } });
    }

    // Verify authentic image magic bytes
    const verifiedMime = detectImageMagicBytes(req.file.buffer);
    if (!verifiedMime) {
      return res.status(400).json({
        error: {
          message: 'Invalid file format. Magic bytes do not match a valid JPEG, PNG, WebP, or GIF image.',
          code: 'INVALID_IMAGE_TYPE'
        }
      });
    }

    try {
      const tenantId = req.tenant ? req.tenant.id : '1';
      const saveRes = await storage.saveAvatar(tenantId, req.user.id, req.file);

      await req.db.execute('UPDATE users SET avatar_url = ? WHERE id = ?', [saveRes.file_url, req.user.id]);

      await auditService.record({
        action: 'attachment.created',
        category: 'attachment',
        entityType: 'avatar',
        entityId: req.user.id,
        entityLabel: `Avatar: ${req.user.name || req.user.email}`,
        actorUserId: req.user.id,
        outcome: 'success',
        severity: 'info',
        changes: [{ field: 'avatar_url', from: '[PREVIOUS]', to: saveRes.file_url }],
        meta: {
          file_name: req.file.originalname,
          size_bytes: req.file.size,
          mimetype: req.file.mimetype
        },
        db: req.db
      }).catch((e) => console.warn('[WARN] Avatar audit record failed:', e.message));

      return res.json({
        message: 'Avatar uploaded successfully',
        avatar_url: saveRes.file_url
      });
    } catch (saveErr) {
      next(saveErr);
    }
  });
});

// POST /api/files/preview-token - Generate signed temporary token for external Office viewers
router.post('/preview-token', requireAuth, async (req, res, next) => {
  try {
    let { file_url } = req.body || {};
    if (!file_url || typeof file_url !== 'string') {
      return res.status(400).json({ error: { message: 'Invalid file URL', code: 'BAD_REQUEST' } });
    }

    // Strip origin if full URL was provided (e.g. https://pmtmgmt.solarman.in/api/files/...)
    if (/^https?:\/\//i.test(file_url)) {
      try {
        const parsed = new URL(file_url);
        file_url = parsed.pathname;
      } catch (e) {
        file_url = file_url.replace(/^https?:\/\/[^\/]+/i, '');
      }
    }

    // Support /api/files/:tenantId/..., /uploads/:tenantId/..., or relative key
    let cleanPath = '';
    if (file_url.startsWith('/api/files/')) {
      cleanPath = file_url.substring('/api/files/'.length);
    } else if (file_url.startsWith('/uploads/')) {
      cleanPath = file_url.substring('/uploads/'.length);
    } else if (file_url.startsWith('api/files/')) {
      cleanPath = file_url.substring('api/files/'.length);
    } else if (file_url.startsWith('uploads/')) {
      cleanPath = file_url.substring('uploads/'.length);
    } else {
      cleanPath = file_url.replace(/^\/+/, '');
    }

    let tenantId = null;
    let subpath = cleanPath;
    const parts = cleanPath.split('/');
    if (/^\d+$/.test(parts[0])) {
      tenantId = Number(parts[0]);
      subpath = parts.slice(1).join('/');
    }
    const userTenantId = req.tenant ? Number(req.tenant.id) : null;
    if (userTenantId && tenantId && tenantId !== userTenantId) {
      return res.status(403).json({ error: { message: 'Access denied', code: 'FORBIDDEN' } });
    }

    const effectiveTenantId = tenantId || userTenantId || 1;

    const token = jwt.sign(
      {
        purpose: 'file_preview',
        tenantId: effectiveTenantId,
        subpath,
        userId: req.user.id
      },
      getJwtSecret(),
      { expiresIn: '2h' }
    );

    return res.json({
      token,
      normalized_path: `/api/files/${effectiveTenantId}/${subpath}`,
      expires_in: 7200
    });
  } catch (err) {
    next(err);
  }
});

// Middleware: allow valid requireAuth, valid signed ?token=..., OR public avatar images
async function authOrPreviewToken(req, res, next) {
  const relativeSubpath = req.params[0] ? req.params[0].replace(/^[/\\]+/, '') : '';
  if (relativeSubpath.startsWith('avatars/') || relativeSubpath.startsWith('workspaces/')) {
    req.isAvatarRequest = true;
    return next();
  }

  if (req.query.token) {
    try {
      const payload = jwt.verify(req.query.token, getJwtSecret());
      if (
        payload.purpose === 'file_preview' &&
        Number(payload.tenantId) === Number(req.params.tenantId)
      ) {
        req.isPreviewToken = true;
        req.tenant = { id: payload.tenantId };
        return next();
      }
    } catch {
      // Invalid token, fall through to requireAuth
    }
  }
  return requireAuth(req, res, next);
}

// GET /api/files/avatars/:filename - Direct fallback for avatar filenames
router.get('/avatars/:filename', (req, res) => {
  const filename = path.basename(req.params.filename);
  const candidateBases = [];
  if (process.env.UPLOADS_DIR) candidateBases.push(path.resolve(process.env.UPLOADS_DIR));
  candidateBases.push(path.resolve(__dirname, '../../uploads'));
  candidateBases.push(path.resolve(__dirname, '../../../uploads'));
  candidateBases.push(path.resolve(process.cwd(), 'uploads'));

  for (const base of Array.from(new Set(candidateBases))) {
    if (!fs.existsSync(base)) continue;
    try {
      const entries = fs.readdirSync(base, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          const potentialPath = path.join(base, entry.name, 'avatars', filename);
          if (fs.existsSync(potentialPath)) {
            const ext = path.extname(potentialPath).toLowerCase();
            const mimeMap = {
              '.jpg': 'image/jpeg',
              '.jpeg': 'image/jpeg',
              '.png': 'image/png',
              '.webp': 'image/webp',
              '.gif': 'image/gif',
              '.svg': 'image/svg+xml'
            };
            const contentType = mimeMap[ext] || 'image/png';
            const stat = fs.statSync(potentialPath);
            res.writeHead(200, {
              'Content-Type': contentType,
              'Content-Length': stat.size,
              'Content-Disposition': 'inline',
              'Cache-Control': 'public, max-age=86400',
              'X-Content-Type-Options': 'nosniff'
            });
            return fs.createReadStream(potentialPath).pipe(res);
          }
        }
      }
    } catch {}
  }
  return res.status(404).json({ error: { message: 'Avatar not found', code: 'NOT_FOUND' } });
});

// GET /api/files/:tenantId/* - Tenant-isolated file download
router.get('/:tenantId/*', authOrPreviewToken, async (req, res, next) => {
  const requestedTenantId = Number(req.params.tenantId);
  const userTenantId = req.tenant ? Number(req.tenant.id) : null;

  // Item 6: Must return 403 if :tenantId differs from the token's tenant (only for non-avatar files)
  if (!req.isAvatarRequest && userTenantId && requestedTenantId !== userTenantId) {
    return res.status(403).json({
      error: { message: 'Access denied: Foreign tenant', code: 'FORBIDDEN' }
    });
  }

  // Extract relative subpath after /:tenantId/
  const relativeSubpath = req.params[0] ? req.params[0].replace(/^[/\\]+/, '') : '';
  if (!relativeSubpath) {
    return res.status(404).json({ error: { message: 'File not found', code: 'NOT_FOUND' } });
  }

  // Authorize by database record using unified userHasPermission (unless validated by preview token or avatar request)
  try {
    const { userHasPermission } = require('../middleware/permissions');

    if (!req.isPreviewToken && !req.isAvatarRequest) {
      // All non-avatar files (cards attachments, etc.) require board membership + file.view
      let boardId = null;
      let workspaceId = null;

        const fileUrl = `/api/files/${requestedTenantId}/${relativeSubpath}`;
        const attRows = await req.db.query(
          `SELECT a.id, a.card_id, l.board_id, b.workspace_id
           FROM attachments a
           JOIN cards c ON a.card_id = c.id
           JOIN lists l ON c.list_id = l.id
           JOIN boards b ON l.board_id = b.id
           WHERE a.file_url = ? OR a.file_url LIKE ?`,
          [fileUrl, `%${relativeSubpath}`]
        );

        if (attRows.length > 0) {
          boardId = attRows[0].board_id;
          workspaceId = attRows[0].workspace_id;
        } else {
          const match = relativeSubpath.match(/^cards\/(\d+)\//);
          if (match) {
            const cardId = Number(match[1]);
            const cardAccess = await req.db.query(
              `SELECT l.board_id, b.workspace_id FROM cards c
               JOIN lists l ON c.list_id = l.id
               JOIN boards b ON l.board_id = b.id
               WHERE c.id = ?`,
              [cardId]
            );
            if (cardAccess.length > 0) {
              boardId = cardAccess[0].board_id;
              workspaceId = cardAccess[0].workspace_id;
            }
          }
        }

        if (!boardId || !workspaceId) {
          return res.status(404).json({ error: { message: 'File not found', code: 'NOT_FOUND' } });
        }

        // Enforce board membership + file.view
        const hasFileView = await userHasPermission(req.user.id, workspaceId, 'file.view', req.db, boardId);
        if (!hasFileView) {
          return res.status(403).json({
            error: { message: 'Access denied: file.view and board membership required', code: 'FORBIDDEN' }
          });
        }
      }
  } catch (dbErr) {
    console.error('[FILES_DB_ERR]', dbErr.message);
    return res.status(404).json({ error: { message: 'File not found', code: 'NOT_FOUND' } });
  }

  // Prevent path traversal attacks and resolve file path across known upload roots
  const resolvedPath = resolveUploadFilePath(requestedTenantId, relativeSubpath);

  if (!fs.existsSync(resolvedPath)) {
    console.warn(`[FILES_NOT_FOUND] Tenant ${requestedTenantId}, subpath: ${relativeSubpath}, resolved: ${resolvedPath}`);
    return res.status(404).json({ error: { message: 'File not found', code: 'NOT_FOUND' } });
  }

  // Enforce correct content-type and security headers
  const ext = path.extname(resolvedPath).toLowerCase();
  const mimeMap = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.webp': 'image/webp',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.pdf': 'application/pdf',
    '.txt': 'text/plain; charset=utf-8',
    '.csv': 'text/csv; charset=utf-8',
    '.tsv': 'text/tab-separated-values; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.xml': 'application/xml; charset=utf-8',
    '.md': 'text/markdown; charset=utf-8',
    '.html': 'text/plain; charset=utf-8',
    '.htm': 'text/plain; charset=utf-8',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.xls': 'application/vnd.ms-excel',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.doc': 'application/msword',
    '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    '.ppt': 'application/vnd.ms-powerpoint',
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.ogg': 'video/ogg',
    '.mov': 'video/quicktime',
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/wav',
    '.m4a': 'audio/mp4',
    '.zip': 'application/zip',
    '.tar': 'application/x-tar',
    '.gz': 'application/gzip'
  };
  const mimeType = mimeMap[ext] || 'application/octet-stream';

  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else if (req.isPreviewToken) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  res.removeHeader('X-Frame-Options');
  res.removeHeader('Cross-Origin-Opener-Policy');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

  res.setHeader('Content-Type', mimeType);
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Allow PDF and embedded viewer to load inside iframes
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self' blob: data:; object-src 'self' blob:; frame-ancestors *;"
  );

  const isDownload = req.query.download === '1' || req.query.download === 'true';
  const downloadFilename = req.query.filename || path.basename(resolvedPath);
  res.setHeader(
    'Content-Disposition',
    `${isDownload ? 'attachment' : 'inline'}; filename="${encodeURIComponent(downloadFilename)}"`
  );

  return res.sendFile(resolvedPath);
});

module.exports = router;

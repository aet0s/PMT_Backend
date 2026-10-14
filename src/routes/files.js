// server/src/routes/files.js
// Authenticated and tenant-isolated file serving and avatar upload endpoint.
const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const { requireAuth, getJwtSecret } = require('../middleware/auth');
const storage = require('../storage');

const router = express.Router();
const UPLOADS_DIR = path.resolve(__dirname, '../../uploads');

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
    const { file_url } = req.body || {};
    if (!file_url || !file_url.startsWith('/api/files/')) {
      return res.status(400).json({ error: { message: 'Invalid file URL', code: 'BAD_REQUEST' } });
    }
    const cleanPath = file_url.replace('/api/files/', '');
    const [tenantIdStr, ...rest] = cleanPath.split('/');
    const tenantId = Number(tenantIdStr);
    const userTenantId = req.tenant ? Number(req.tenant.id) : null;
    if (userTenantId && tenantId !== userTenantId) {
      return res.status(403).json({ error: { message: 'Access denied', code: 'FORBIDDEN' } });
    }

    const subpath = rest.join('/');
    const token = jwt.sign(
      {
        purpose: 'file_preview',
        tenantId,
        subpath,
        userId: req.user.id
      },
      getJwtSecret(),
      { expiresIn: '2h' }
    );

    return res.json({ token, expires_in: 7200 });
  } catch (err) {
    next(err);
  }
});

// Middleware: allow EITHER valid requireAuth OR valid signed ?token=...
async function authOrPreviewToken(req, res, next) {
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

// GET /api/files/:tenantId/* - Tenant-isolated file download
router.get('/:tenantId/*', authOrPreviewToken, async (req, res, next) => {
  const requestedTenantId = Number(req.params.tenantId);
  const userTenantId = req.tenant ? Number(req.tenant.id) : null;

  // Item 6: Must return 404 if :tenantId differs from the token's tenant
  if (userTenantId && requestedTenantId !== userTenantId) {
    return res.status(404).json({
      error: { message: 'File not found', code: 'NOT_FOUND' }
    });
  }

  // Extract relative subpath after /:tenantId/
  const relativeSubpath = req.params[0];
  if (!relativeSubpath) {
    return res.status(404).json({ error: { message: 'File not found', code: 'NOT_FOUND' } });
  }

  // Authorize by database record using unified userHasPermission (unless validated by preview token)
  try {
    const { userHasPermission } = require('../middleware/permissions');

    if (!req.isPreviewToken && relativeSubpath.startsWith('cards/')) {
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
        const att = attRows[0];
        const hasPerm = await userHasPermission(req.user.id, att.workspace_id, 'file.view', req.db, att.board_id);
        if (!hasPerm) {
          return res.status(404).json({ error: { message: 'File not found', code: 'NOT_FOUND' } });
        }
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
          if (cardAccess.length === 0) {
            return res.status(404).json({ error: { message: 'File not found', code: 'NOT_FOUND' } });
          }
          const hasPerm = await userHasPermission(req.user.id, cardAccess[0].workspace_id, 'file.view', req.db, cardAccess[0].board_id);
          if (!hasPerm) {
            return res.status(404).json({ error: { message: 'File not found', code: 'NOT_FOUND' } });
          }
        }
      }
    } else if (relativeSubpath.startsWith('avatars/')) {
      const avatarFilename = path.basename(relativeSubpath);
      const userRows = await req.db.query(
        'SELECT id FROM users WHERE avatar_url LIKE ?',
        [`%${avatarFilename}`]
      );
      if (userRows.length === 0) {
        return res.status(404).json({ error: { message: 'File not found', code: 'NOT_FOUND' } });
      }
    }
  } catch (dbErr) {
    console.error('[FILES_DB_ERR]', dbErr.message);
    return res.status(404).json({ error: { message: 'File not found', code: 'NOT_FOUND' } });
  }

  // Prevent path traversal attacks
  const resolvedPath = path.resolve(UPLOADS_DIR, String(requestedTenantId), relativeSubpath);
  const expectedPrefix = path.resolve(UPLOADS_DIR, String(requestedTenantId));

  if (!resolvedPath.startsWith(expectedPrefix)) {
    return res.status(403).json({ error: { message: 'Access denied', code: 'FORBIDDEN' } });
  }

  if (!fs.existsSync(resolvedPath)) {
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

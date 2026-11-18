// server/src/storage/index.js
// Tenant-namespaced local disk storage wrapper with strict containment, path normalization, and deletion protection.
const fs = require('fs');
const path = require('path');

const UPLOADS_DIR = process.env.UPLOADS_DIR
  ? path.resolve(process.env.UPLOADS_DIR)
  : path.resolve(__dirname, '../../uploads');

// Ensure base upload directory exists
if (!fs.existsSync(UPLOADS_DIR)) {
  try {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
    console.log(`[STORAGE] Created uploads storage directory at: ${UPLOADS_DIR}`);
  } catch (err) {
    console.warn('[STORAGE] Could not create UPLOADS_DIR:', UPLOADS_DIR, err.message);
  }
}
console.log(`[STORAGE] Uploads storage directory initialized at: ${UPLOADS_DIR} (Custom external dir: ${Boolean(process.env.UPLOADS_DIR)})`);

/**
 * Validates and strictly sanitizes a storage key or subpath.
 * Enforces filesystem containment within the designated upload root and specific tenant directory.
 * Rejects path traversal attempts, null bytes, absolute paths, malformed characters, and symlinks.
 */
function sanitizeAndVerifyContainment(key, tenantId = null, options = {}) {
  if (!key || typeof key !== 'string') {
    const err = new Error('Invalid storage key');
    err.status = 400;
    err.code = 'INVALID_STORAGE_KEY';
    throw err;
  }

  // Reject null bytes and URL encoded traversal patterns
  if (key.includes('\0') || /%2e|%2f|%5c/i.test(key)) {
    const err = new Error('Path traversal attempt detected');
    err.status = 403;
    err.code = 'FORBIDDEN';
    throw err;
  }

  // Strip leading api/files or uploads prefixes if present
  let cleanKey = key
    .replace(/^https?:\/\/[^\/]+/i, '')
    .split('?')[0]
    .replace(/^\/?(?:api\/)?(?:files|uploads)\/?/, '')
    .replace(/^[/\\]+/, '');

  if (path.isAbsolute(cleanKey)) {
    const err = new Error('Absolute path rejected');
    err.status = 403;
    err.code = 'FORBIDDEN';
    throw err;
  }

  // Reject any path containing directory traversal dots
  const segments = cleanKey.split(/[/\\]+/);
  for (const seg of segments) {
    if (seg === '..' || seg === '.') {
      const err = new Error('Path traversal attempt rejected');
      err.status = 403;
      err.code = 'FORBIDDEN';
      throw err;
    }
  }

  const resolvedRoot = path.resolve(UPLOADS_DIR);

  // If tenantId is specified, enforce strict tenant-level containment
  if (tenantId !== null && tenantId !== undefined) {
    const tId = String(tenantId);
    const resolvedTenantDir = path.resolve(resolvedRoot, tId);

    // If cleanKey starts with a tenant prefix, verify it matches the required tenantId
    const tenantPrefixMatch = cleanKey.match(/^(\d+)[/\\](.*)$/);
    let subpath = cleanKey;
    if (tenantPrefixMatch) {
      const keyTenantId = tenantPrefixMatch[1];
      if (keyTenantId !== tId) {
        const err = new Error('Cross-tenant storage access violation: tenant mismatch');
        err.status = 403;
        err.code = 'FORBIDDEN';
        throw err;
      }
      subpath = tenantPrefixMatch[2];
    }

    const resolvedTarget = path.resolve(resolvedTenantDir, subpath);

    // Lexical containment verification within tenant directory
    if (!resolvedTarget.startsWith(resolvedTenantDir + path.sep) && resolvedTarget !== resolvedTenantDir) {
      const err = new Error('Filesystem containment violation: path outside tenant directory');
      err.status = 403;
      err.code = 'FORBIDDEN';
      throw err;
    }

    // Realpath and Symlink verification: Symlinks are strictly prohibited in managed storage
    if (fs.existsSync(resolvedTarget)) {
      try {
        const lstat = fs.lstatSync(resolvedTarget);
        if (lstat.isSymbolicLink()) {
          if (!options.forDeletion) {
            const err = new Error('Symbolic links are strictly prohibited in managed storage paths');
            err.status = 403;
            err.code = 'FORBIDDEN';
            throw err;
          }
          // Return targetPath for safe unlinking in delete handler
          return resolvedTarget;
        }

        const realPath = fs.realpathSync(resolvedTarget);
        if (!realPath.startsWith(resolvedTenantDir + path.sep) && realPath !== resolvedTenantDir) {
          const err = new Error('Filesystem containment violation: real path outside tenant directory');
          err.status = 403;
          err.code = 'FORBIDDEN';
          throw err;
        }
      } catch (err) {
        if (err.code === 'FORBIDDEN') throw err;
        const containmentErr = new Error('Filesystem containment validation failed');
        containmentErr.status = 403;
        containmentErr.code = 'FORBIDDEN';
        throw containmentErr;
      }
    }

    return resolvedTarget;
  }

  // Fallback root containment when tenantId is not provided
  const resolvedTarget = path.resolve(resolvedRoot, cleanKey);
  if (!resolvedTarget.startsWith(resolvedRoot + path.sep) && resolvedTarget !== resolvedRoot) {
    const err = new Error('Filesystem containment violation: path outside upload directory');
    err.status = 403;
    err.code = 'FORBIDDEN';
    throw err;
  }

  if (fs.existsSync(resolvedTarget)) {
    try {
      const lstat = fs.lstatSync(resolvedTarget);
      if (lstat.isSymbolicLink()) {
        const err = new Error('Symbolic links are strictly prohibited in managed storage paths');
        err.status = 403;
        err.code = 'FORBIDDEN';
        throw err;
      }
      const realPath = fs.realpathSync(resolvedTarget);
      if (!realPath.startsWith(resolvedRoot + path.sep) && realPath !== resolvedRoot) {
        const err = new Error('Filesystem containment violation: real path outside upload directory');
        err.status = 403;
        err.code = 'FORBIDDEN';
        throw err;
      }
    } catch (err) {
      if (err.code === 'FORBIDDEN') throw err;
      const containmentErr = new Error('Filesystem containment validation failed');
      containmentErr.status = 403;
      containmentErr.code = 'FORBIDDEN';
      throw containmentErr;
    }
  }

  return resolvedTarget;
}

const localStorage = {
  sanitizeAndVerifyContainment,

  async save(file, cardId, tenantId = 1) {
    const tId = String(tenantId || 1);
    const safeCardId = String(cardId).replace(/[^a-zA-Z0-9_-]/g, '');
    const cardDir = path.join(UPLOADS_DIR, tId, 'cards', safeCardId);
    if (!fs.existsSync(cardDir)) {
      fs.mkdirSync(cardDir, { recursive: true });
    }

    const ext = path.extname(file.originalname).slice(0, 10);
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
    const targetPath = path.join(cardDir, uniqueName);

    // Verify containment before writing
    sanitizeAndVerifyContainment(path.relative(UPLOADS_DIR, targetPath), tId);

    // Write file to target path
    if (file.buffer) {
      fs.writeFileSync(targetPath, file.buffer);
    } else if (file.path) {
      fs.copyFileSync(file.path, targetPath);
    }

    const relativeKey = `${tId}/cards/${safeCardId}/${uniqueName}`;
    return {
      key: relativeKey,
      file_url: `/api/files/${relativeKey}`,
      file_name: file.originalname,
      file_type: file.mimetype,
      file_size_bytes: file.size
    };
  },

  async saveAvatar(tenantId, userId, file) {
    const tId = String(tenantId || 1);
    const safeUserId = String(userId).replace(/[^0-9]/g, '');
    const avatarDir = path.join(UPLOADS_DIR, tId, 'avatars');
    if (!fs.existsSync(avatarDir)) {
      fs.mkdirSync(avatarDir, { recursive: true });
    }
    const ext = path.extname(file.originalname).slice(0, 10) || '.png';
    const uniqueName = `avatar_${safeUserId}_${Date.now()}${ext}`;
    const targetPath = path.join(avatarDir, uniqueName);

    sanitizeAndVerifyContainment(path.relative(UPLOADS_DIR, targetPath), tId);

    if (file.buffer) {
      fs.writeFileSync(targetPath, file.buffer);
    } else if (file.path) {
      fs.copyFileSync(file.path, targetPath);
    }
    const relativeKey = `${tId}/avatars/${uniqueName}`;
    return {
      key: relativeKey,
      file_url: `/api/files/${relativeKey}`
    };
  },

  async saveWorkspaceIcon(tenantId, workspaceId, file) {
    const tId = String(tenantId || 1);
    const safeWsId = String(workspaceId).replace(/[^0-9]/g, '');
    const wsDir = path.join(UPLOADS_DIR, tId, 'workspaces');
    if (!fs.existsSync(wsDir)) {
      fs.mkdirSync(wsDir, { recursive: true });
    }
    const ext = path.extname(file.originalname).slice(0, 10) || '.png';
    const uniqueName = `ws_${safeWsId}_${Date.now()}${ext}`;
    const targetPath = path.join(wsDir, uniqueName);

    sanitizeAndVerifyContainment(path.relative(UPLOADS_DIR, targetPath), tId);

    if (file.buffer) {
      fs.writeFileSync(targetPath, file.buffer);
    } else if (file.path) {
      fs.copyFileSync(file.path, targetPath);
    }
    const relativeKey = `${tId}/workspaces/${uniqueName}`;
    return {
      key: relativeKey,
      file_url: `/api/files/${relativeKey}`
    };
  },

  getUrl(key) {
    return `/api/files/${key}`;
  },

  /**
   * Secure deletion function:
   * Strictly restricted to managed files inside the intended upload root.
   * A deletion request must NEVER delete:
   * - Application source files (.js, .jsx, .ts, .tsx, .json)
   * - Environment files (.env, .env.*)
   * - Database files (.sqlite, .db, .sql)
   * - System files
   * - Files belonging to another tenant
   * - Files outside the application's managed storage directory.
   */
  async delete(key, tenantId = null) {
    if (!key || typeof key !== 'string') return false;

    const resolvedRoot = path.resolve(UPLOADS_DIR);
    const resolvedTenantDir = tenantId !== null && tenantId !== undefined
      ? path.resolve(resolvedRoot, String(tenantId))
      : resolvedRoot;

    // Strict containment and tenant isolation check
    let targetPath;
    try {
      targetPath = sanitizeAndVerifyContainment(key, tenantId, { forDeletion: true });
    } catch (err) {
      console.warn('[STORAGE_SECURITY] Deletion blocked due to invalid key or traversal attempt:', err.message);
      return false;
    }

    if (!targetPath.startsWith(resolvedRoot + path.sep)) {
      console.warn('[STORAGE_SECURITY] Deletion blocked: target is outside managed upload directory');
      return false;
    }

    if (tenantId !== null && tenantId !== undefined && !targetPath.startsWith(resolvedTenantDir + path.sep)) {
      console.warn('[STORAGE_SECURITY] Deletion blocked: target is outside tenant upload directory');
      return false;
    }

    // Never delete protected application file extensions or patterns
    const blockedExtensions = new Set(['.js', '.jsx', '.ts', '.tsx', '.json', '.env', '.sql', '.sqlite', '.db', '.pem', '.key']);
    const ext = path.extname(targetPath).toLowerCase();
    const basename = path.basename(targetPath).toLowerCase();

    if (blockedExtensions.has(ext) || basename.startsWith('.env')) {
      console.warn(`[STORAGE_SECURITY] Deletion blocked: protected file extension '${ext}' or filename '${basename}'`);
      return false;
    }

    // Check if target exists on filesystem
    try {
      const lstat = fs.lstatSync(targetPath);

      // If target is a symbolic link, remove the symlink itself without following it
      if (lstat.isSymbolicLink()) {
        console.warn('[STORAGE_SECURITY] Detected symlink in storage path. Removing symlink pointer without following target:', targetPath);
        fs.unlinkSync(targetPath);
        return true;
      }
    } catch (e) {
      // File does not exist
      return false;
    }

    // Verify real canonical path resides strictly within the requesting tenant's directory
    try {
      const realPath = fs.realpathSync(targetPath);

      if (tenantId !== null && tenantId !== undefined) {
        if (!realPath.startsWith(resolvedTenantDir + path.sep)) {
          console.warn('[STORAGE_SECURITY] Cross-tenant deletion blocked: real path outside tenant directory:', realPath);
          return false;
        }
      } else if (!realPath.startsWith(resolvedRoot + path.sep)) {
        console.warn('[STORAGE_SECURITY] Deletion blocked: real path outside upload root:', realPath);
        return false;
      }

      // Check it is a regular file, not a directory
      const stat = fs.statSync(realPath);
      if (!stat.isFile()) {
        console.warn('[STORAGE_SECURITY] Deletion blocked: target is not a regular file');
        return false;
      }

      fs.unlinkSync(realPath);
      return true;
    } catch (err) {
      console.warn('[STORAGE] Failed to safely delete file:', err.message);
      return false;
    }
  }
};

localStorage.UPLOADS_DIR = UPLOADS_DIR;

module.exports = localStorage;

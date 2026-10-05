// server/src/storage/index.js
// Tenant-namespaced local disk storage wrapper.
const fs = require('fs');
const path = require('path');

const UPLOADS_DIR = path.resolve(__dirname, '../../uploads');

// Ensure base upload directory exists
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const localStorage = {
  async save(file, cardId, tenantId = 1) {
    const tId = String(tenantId || 1);
    const cardDir = path.join(UPLOADS_DIR, tId, 'cards', String(cardId));
    if (!fs.existsSync(cardDir)) {
      fs.mkdirSync(cardDir, { recursive: true });
    }

    const ext = path.extname(file.originalname);
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
    const targetPath = path.join(cardDir, uniqueName);

    // Write file to target path
    if (file.buffer) {
      fs.writeFileSync(targetPath, file.buffer);
    } else if (file.path) {
      fs.copyFileSync(file.path, targetPath);
    }

    const relativeKey = `${tId}/cards/${cardId}/${uniqueName}`;
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
    const avatarDir = path.join(UPLOADS_DIR, tId, 'avatars');
    if (!fs.existsSync(avatarDir)) {
      fs.mkdirSync(avatarDir, { recursive: true });
    }
    const ext = path.extname(file.originalname) || '.png';
    const uniqueName = `avatar_${userId}_${Date.now()}${ext}`;
    const targetPath = path.join(avatarDir, uniqueName);
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

  getUrl(key) {
    return `/api/files/${key}`;
  },

  async delete(key) {
    const targetPath = path.join(UPLOADS_DIR, key);
    if (fs.existsSync(targetPath)) {
      try {
        fs.unlinkSync(targetPath);
      } catch (err) {
        console.warn('Failed to delete file from disk:', targetPath, err.message);
      }
    }
  }
};

module.exports = localStorage;

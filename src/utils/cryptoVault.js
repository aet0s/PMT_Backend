// server/src/utils/cryptoVault.js
// AES-256-GCM encryption and decryption at rest with key rotation support for TOTP secrets.
const crypto = require('crypto');

const DEFAULT_DEV_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

let keyRing = {};
let activeKeyId = 'v1';

function parseAndValidateKeyRing() {
  const rawKey = process.env.TOTP_ENC_KEY || (process.env.NODE_ENV === 'production' ? null : DEFAULT_DEV_KEY);
  if (!rawKey) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('FATAL: TOTP_ENC_KEY environment variable is missing in production.');
    }
  }

  const effectiveKey = rawKey || DEFAULT_DEV_KEY;
  keyRing = {};

  try {
    if (effectiveKey.trim().startsWith('{')) {
      // JSON keyring format: {"v1": "hex...", "v2": "hex..."}
      const parsed = JSON.parse(effectiveKey);
      for (const [kId, kHex] of Object.entries(parsed)) {
        const buf = Buffer.from(kHex, 'hex');
        if (buf.length !== 32) {
          throw new Error(`Key ${kId} is not 32 bytes (must be 64 hex characters)`);
        }
        keyRing[kId] = buf;
      }
      activeKeyId = process.env.TOTP_KEY_ID || Object.keys(parsed).pop() || 'v1';
    } else if (effectiveKey.includes(':')) {
      // keyId:hexKey format (e.g. v2:64hexchars)
      const [kId, kHex] = effectiveKey.split(':');
      const buf = Buffer.from(kHex.trim(), 'hex');
      if (buf.length !== 32) {
        throw new Error(`Key ${kId} is not 32 bytes (must be 64 hex characters)`);
      }
      keyRing[kId.trim()] = buf;
      activeKeyId = kId.trim();
    } else {
      // Plain 64-hex-character string
      const buf = Buffer.from(effectiveKey.trim(), 'hex');
      if (buf.length !== 32) {
        throw new Error('TOTP_ENC_KEY must be a 32-byte hex string (64 characters)');
      }
      keyRing['v1'] = buf;
      activeKeyId = 'v1';
    }
  } catch (err) {
    throw new Error(`Failed to initialize TOTP encryption vault: ${err.message}`);
  }
}

// Initialize on module load
parseAndValidateKeyRing();

/**
 * Encrypts a plaintext secret using AES-256-GCM.
 * Output format: enc:<keyId>:<ivHex>:<tagHex>:<cipherHex>
 */
function encryptSecret(plaintext, keyId = activeKeyId) {
  if (!plaintext) return null;
  const key = keyRing[keyId] || keyRing[activeKeyId];
  if (!key) {
    throw new Error(`Encryption key "${keyId}" not found in keyring`);
  }

  const iv = crypto.randomBytes(12); // 96-bit IV recommended for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `enc:${keyId}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypts an encrypted secret. If unencrypted (legacy), returns plaintext.
 */
function decryptSecret(ciphertext) {
  if (!ciphertext) return null;
  if (!String(ciphertext).startsWith('enc:')) {
    return String(ciphertext); // Unencrypted legacy fallback
  }

  const parts = String(ciphertext).split(':');
  if (parts.length !== 5) {
    throw new Error('Invalid encrypted ciphertext format');
  }

  const [, keyId, ivHex, tagHex, cipherHex] = parts;
  const key = keyRing[keyId];
  if (!key) {
    throw new Error(`Decryption key "${keyId}" not found in keyring (key rotation error)`);
  }

  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const cipherBuffer = Buffer.from(cipherHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(cipherBuffer), decipher.final()]);
  return decrypted.toString('utf8');
}

module.exports = {
  encryptSecret,
  decryptSecret,
  parseAndValidateKeyRing,
  getActiveKeyId: () => activeKeyId
};

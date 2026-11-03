// server/src/secure/crypto.js
// Server-side RSA-OAEP & AES-256-GCM decryption engine with key validation and rotation support.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SUPPORTED_VERSION = 1;
const DEFAULT_KEY_ID = 'server-rsa-v1';
const CLOCK_SKEW_WINDOW_SECONDS = 120; // +/- 120 seconds

let activePrivateKey = null;
const keyStore = new Map();

function resolvePrivateKeyPath() {
  const candidatePaths = [];

  if (process.env.SERVER_PRIVATE_KEY_PATH) {
    candidatePaths.push(path.resolve(process.env.SERVER_PRIVATE_KEY_PATH));
  }

  // Persistent external keys outside server deployment directory (preserved across git/tar deploys)
  candidatePaths.push(path.resolve('/data/projects/pmt/keys/private.pem'));
  candidatePaths.push(path.resolve(__dirname, '../../../keys/private.pem'));
  candidatePaths.push(path.resolve(process.cwd(), '../keys/private.pem'));
  candidatePaths.push(path.resolve('/data/keys/private.pem'));

  // Standard server/keys directory
  candidatePaths.push(path.resolve(__dirname, '../../keys/private.pem'));
  candidatePaths.push(path.resolve(process.cwd(), 'keys/private.pem'));

  for (const p of candidatePaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }

  return process.env.SERVER_PRIVATE_KEY_PATH
    ? path.resolve(process.env.SERVER_PRIVATE_KEY_PATH)
    : path.resolve(__dirname, '../../keys/private.pem');
}

function loadServerKeys() {
  let keyPem = '';
  let keySource = '';

  if (process.env.SERVER_PRIVATE_KEY_PEM) {
    keyPem = process.env.SERVER_PRIVATE_KEY_PEM.replace(/\\n/g, '\n');
    keySource = 'environment variable SERVER_PRIVATE_KEY_PEM';
  } else {
    const keyPath = resolvePrivateKeyPath();
    if (!fs.existsSync(keyPath)) {
      const errorMsg = `[FATAL] Server private key file not found at: ${keyPath}. Store your key at /data/projects/pmt/keys/private.pem or in .env as SERVER_PRIVATE_KEY_PATH=/data/projects/pmt/keys/private.pem to prevent removal during deployment.`;
      console.error(errorMsg);
      throw new Error(errorMsg);
    }
    keyPem = fs.readFileSync(keyPath, 'utf8');
    keySource = keyPath;
  }

  let privKeyObject;
  try {
    privKeyObject = crypto.createPrivateKey(keyPem);
  } catch (err) {
    throw new Error(`[FATAL] Invalid private key format from ${keySource}: ${err.message}`);
  }

  if (privKeyObject.asymmetricKeyType !== 'rsa') {
    throw new Error(`[FATAL] Unsupported private key type: ${privKeyObject.asymmetricKeyType}. Must be RSA.`);
  }

  const modulusBits = privKeyObject.asymmetricKeyDetails?.modulusLength || 0;
  if (modulusBits < 2048) {
    throw new Error(`[FATAL] Insecure RSA key length: ${modulusBits} bits. Minimum required is 2048 bits.`);
  }

  activePrivateKey = {
    keyId: DEFAULT_KEY_ID,
    keyObject: privKeyObject,
    modulusBits
  };

  keyStore.set(DEFAULT_KEY_ID, activePrivateKey);

  // Auto-sync public.pem file alongside private key if writable
  try {
    const derivedPub = crypto.createPublicKey(privKeyObject).export({ type: 'spki', format: 'pem' });
    const localKeysDir = path.resolve(__dirname, '../../keys');
    if (!fs.existsSync(localKeysDir)) {
      fs.mkdirSync(localKeysDir, { recursive: true });
    }
    const localPubFile = path.join(localKeysDir, 'public.pem');
    if (!fs.existsSync(localPubFile)) {
      fs.writeFileSync(localPubFile, derivedPub, 'utf8');
    }
    // Also sync to persistent external keys directory if it exists
    const persistentKeysDir = path.resolve('/data/projects/pmt/keys');
    if (fs.existsSync(persistentKeysDir)) {
      const persistentPubFile = path.join(persistentKeysDir, 'public.pem');
      if (!fs.existsSync(persistentPubFile)) {
        fs.writeFileSync(persistentPubFile, derivedPub, 'utf8');
      }
    }
  } catch (_) {}

  // Support secondary key for rotation if provided via SERVER_PREVIOUS_PRIVATE_KEY_PATH
  if (process.env.SERVER_PREVIOUS_PRIVATE_KEY_PATH && fs.existsSync(process.env.SERVER_PREVIOUS_PRIVATE_KEY_PATH)) {
    try {
      const prevPem = fs.readFileSync(process.env.SERVER_PREVIOUS_PRIVATE_KEY_PATH, 'utf8');
      const prevKeyObj = crypto.createPrivateKey(prevPem);
      const prevId = process.env.SERVER_PREVIOUS_KEY_ID || 'server-rsa-v0';
      keyStore.set(prevId, {
        keyId: prevId,
        keyObject: prevKeyObj,
        modulusBits: prevKeyObj.asymmetricKeyDetails?.modulusLength || 2048
      });
      console.log(`[KEY-ROTATION] Loaded secondary rotation key: ${prevId}`);
    } catch (e) {
      console.warn('[KEY-ROTATION] Could not load secondary rotation key:', e.message);
    }
  }

  console.log(`[SECURE-GATEWAY] Initialized RSA private key (${modulusBits}-bit, Key ID: ${DEFAULT_KEY_ID})`);
  return activePrivateKey;
}

function getPrivateKey(keyId = DEFAULT_KEY_ID) {
  if (!activePrivateKey) {
    loadServerKeys();
  }
  return keyStore.get(keyId) || null;
}

/**
 * Validates envelope structure, timestamp, decrypts payload, and verifies AES-GCM authentication.
 */
function decryptRequestEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    const err = new Error('Invalid request envelope: Expected JSON object');
    err.code = 'INVALID_ENVELOPE';
    err.status = 400;
    throw err;
  }

  const { version, key_id, timestamp, nonce, encrypted } = envelope;

  // 1. Protocol version validation
  if (Number(version) !== SUPPORTED_VERSION) {
    const err = new Error(`Unsupported protocol version: ${version}. Expected version ${SUPPORTED_VERSION}`);
    err.code = 'UNSUPPORTED_VERSION';
    err.status = 400;
    throw err;
  }

  // 2. Key ID validation & resolution
  const keyRecord = getPrivateKey(key_id);
  if (!keyRecord) {
    const err = new Error(`Unknown or deprecated key_id: ${key_id}`);
    err.code = 'UNKNOWN_KEY_ID';
    err.status = 400;
    throw err;
  }

  // 3. Timestamp validation
  if (!timestamp || typeof timestamp !== 'number' || isNaN(timestamp)) {
    const err = new Error('Invalid timestamp in request envelope');
    err.code = 'INVALID_TIMESTAMP';
    err.status = 400;
    throw err;
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const diffSec = Math.abs(nowSec - timestamp);
  if (diffSec > CLOCK_SKEW_WINDOW_SECONDS) {
    const err = new Error(`Request timestamp is outside the allowed window (skew: ${diffSec}s, max: ${CLOCK_SKEW_WINDOW_SECONDS}s)`);
    err.code = 'TIMESTAMP_OUT_OF_RANGE';
    err.status = 400;
    throw err;
  }

  // 4. Nonce validation
  if (!nonce || typeof nonce !== 'string' || nonce.length < 16) {
    const err = new Error('Invalid or missing nonce in request envelope');
    err.code = 'INVALID_NONCE';
    err.status = 400;
    throw err;
  }

  // 5. Encrypted payload structure extraction
  if (!encrypted) {
    const err = new Error('Missing encrypted payload field');
    err.code = 'MISSING_ENCRYPTED_PAYLOAD';
    err.status = 400;
    throw err;
  }

  let innerPackage;
  if (typeof encrypted === 'string') {
    try {
      const decodedStr = Buffer.from(encrypted, 'base64url').toString('utf8');
      innerPackage = JSON.parse(decodedStr);
    } catch {
      const err = new Error('Failed to parse encrypted package: Invalid encoding');
      err.code = 'INVALID_CIPHERTEXT_ENCODING';
      err.status = 400;
      throw err;
    }
  } else if (typeof encrypted === 'object') {
    innerPackage = encrypted;
  } else {
    const err = new Error('Invalid encrypted field type');
    err.code = 'INVALID_ENVELOPE';
    err.status = 400;
    throw err;
  }

  const { wrapped_key, iv, tag, ciphertext } = innerPackage;

  if (!wrapped_key || !iv || !tag || !ciphertext) {
    const err = new Error('Encrypted package is missing required fields (wrapped_key, iv, tag, ciphertext)');
    err.code = 'MALFORMED_ENCRYPTED_PACKAGE';
    err.status = 400;
    throw err;
  }

  // 6. RSA-OAEP SHA-256 decryption of ephemeral AES key
  let aesKey;
  try {
    const wrappedKeyBuf = Buffer.from(wrapped_key, 'base64url');
    aesKey = crypto.privateDecrypt(
      {
        key: keyRecord.keyObject,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      wrappedKeyBuf
    );
  } catch (rsaErr) {
    const err = new Error('Failed to unwrap encryption key: Ciphertext tampering or key mismatch');
    err.code = 'KEY_UNWRAP_FAILED';
    err.status = 400;
    throw err;
  }

  if (aesKey.length !== 32) {
    const err = new Error('Invalid AES key length: Expected 256 bits (32 bytes)');
    err.code = 'INVALID_KEY_LENGTH';
    err.status = 400;
    throw err;
  }

  // 7. AES-256-GCM authenticated decryption with bound AAD
  const ivBuf = Buffer.from(iv, 'base64url');
  const tagBuf = Buffer.from(tag, 'base64url');
  const ciphertextBuf = Buffer.from(ciphertext, 'base64url');

  if (ivBuf.length !== 12) {
    const err = new Error('Invalid IV length: Expected 96 bits (12 bytes)');
    err.code = 'INVALID_IV';
    err.status = 400;
    throw err;
  }

  if (tagBuf.length !== 16) {
    const err = new Error('Invalid authentication tag length: Expected 128 bits (16 bytes)');
    err.code = 'INVALID_TAG';
    err.status = 400;
    throw err;
  }

  const aad = Buffer.from(`v1|${key_id}|${timestamp}|${nonce}`, 'utf8');

  let plaintext;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, ivBuf);
    decipher.setAAD(aad);
    decipher.setAuthTag(tagBuf);
    plaintext = Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]).toString('utf8');
  } catch (gcmErr) {
    const err = new Error('Integrity check failed: Tampered ciphertext or authentication tag');
    err.code = 'CIPHERTEXT_INTEGRITY_FAILED';
    err.status = 400;
    throw err;
  }

  // 8. JSON parse of decrypted plaintext
  let decryptedBody;
  try {
    decryptedBody = JSON.parse(plaintext);
  } catch (jsonErr) {
    const err = new Error('Decrypted payload is not valid JSON');
    err.code = 'INVALID_DECRYPTED_JSON';
    err.status = 400;
    throw err;
  }

  return {
    version,
    key_id,
    timestamp,
    nonce,
    payload: decryptedBody
  };
}

module.exports = {
  loadServerKeys,
  getPrivateKey,
  decryptRequestEnvelope,
  SUPPORTED_VERSION,
  DEFAULT_KEY_ID,
  CLOCK_SKEW_WINDOW_SECONDS
};


// server/src/services/twoFactorService.js
// TOTP (Time-based One-Time Password) and single-use recovery codes service using otplib v13.
const { generateSecret, generateURI, verifySync } = require('otplib');
const qrcode = require('qrcode');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

async function generateTotpSetup(user, appOrTenantName = 'ProjectMgmt') {
  const secret = generateSecret();
  const label = `${user.email}`;
  const issuer = appOrTenantName || 'ProjectMgmt';
  const otpauthUrl = generateURI({ issuer, label, secret });
  const qrCodeDataUrl = await qrcode.toDataURL(otpauthUrl);

  return {
    secret,
    otpauth_url: otpauthUrl,
    qr_code: qrCodeDataUrl
  };
}

function verifyTotpCode(token, secret) {
  if (!token || !secret) return false;
  const cleanToken = token.toString().trim().replace(/\s+/g, '');
  try {
    const res = verifySync({ secret, token: cleanToken });
    return !!(res && res.valid);
  } catch (err) {
    return false;
  }
}

function formatRecoveryCode(raw) {
  // Format as 8 characters: XXXX-XXXX
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}`.toUpperCase();
}

async function generateRecoveryCodes(db, userId) {
  const plainCodes = [];
  const codeHashes = [];

  for (let i = 0; i < 10; i++) {
    const raw = crypto.randomBytes(4).toString('hex').toUpperCase(); // 8 hex chars
    const formatted = formatRecoveryCode(raw);
    plainCodes.push(formatted);
    // Hash recovery code using bcrypt cost 12
    const hash = await bcrypt.hash(formatted, 12);
    codeHashes.push(hash);
  }

  // Delete previous recovery codes for this user
  await db.execute('DELETE FROM recovery_codes WHERE user_id = ?', [userId]);

  // Insert new hashed recovery codes
  for (const hash of codeHashes) {
    await db.execute(
      'INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)',
      [userId, hash]
    );
  }

  return plainCodes;
}

async function verifyRecoveryCode(db, userId, submittedCode) {
  if (!submittedCode || typeof submittedCode !== 'string') return false;
  const cleanCode = submittedCode.trim().toUpperCase();

  const rows = await db.query(
    'SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL',
    [userId]
  );

  for (const row of rows) {
    const isMatch = await bcrypt.compare(cleanCode, row.code_hash);
    if (isMatch) {
      // Consume the recovery code (single-use)
      await db.execute(
        'UPDATE recovery_codes SET used_at = CURRENT_TIMESTAMP(3) WHERE id = ?',
        [row.id]
      );
      return true;
    }
  }

  return false;
}

async function disableTwoFactor(db, userId) {
  await db.execute(
    'UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_enrolled_at = NULL WHERE id = ?',
    [userId]
  );
  await db.execute('DELETE FROM recovery_codes WHERE user_id = ?', [userId]);
}

module.exports = {
  generateTotpSetup,
  verifyTotpCode,
  generateRecoveryCodes,
  verifyRecoveryCode,
  disableTwoFactor
};

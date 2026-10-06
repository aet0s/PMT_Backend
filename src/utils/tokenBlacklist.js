// server/src/utils/tokenBlacklist.js
// In-memory blacklist for revoked JWT tokens on logout

const blacklistedTokens = new Map();

/**
 * Adds a JWT token to the blacklist until expiration
 */
function blacklistToken(token) {
  if (!token || typeof token !== 'string') return;
  try {
    const parts = token.split('.');
    const key = parts[2] || token;
    // Keep in blacklist for 24 hours
    blacklistedTokens.set(key, Date.now() + 24 * 60 * 60 * 1000);
  } catch (e) {}
}

/**
 * Checks if a token has been blacklisted
 */
function isTokenBlacklisted(token) {
  if (!token || typeof token !== 'string') return false;
  try {
    const parts = token.split('.');
    const key = parts[2] || token;
    const expiresAt = blacklistedTokens.get(key);
    if (!expiresAt) return false;
    if (Date.now() > expiresAt) {
      blacklistedTokens.delete(key);
      return false;
    }
    return true;
  } catch (e) {
    return false;
  }
}

// Clean up expired tokens every 10 minutes
if (typeof setInterval !== 'undefined') {
  setInterval(() => {
    const now = Date.now();
    for (const [key, expiresAt] of blacklistedTokens.entries()) {
      if (now > expiresAt) {
        blacklistedTokens.delete(key);
      }
    }
  }, 10 * 60 * 1000).unref();
}

module.exports = {
  blacklistToken,
  isTokenBlacklisted
};

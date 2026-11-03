// server/src/utils/corsOrigins.js
// Strict centralized origin validation for Express CORS, CSRF protection, and Socket.IO.
require('dotenv').config();

const PRODUCTION_DEFAULT_ALLOWED_ORIGINS = [
  'https://pmt.solarman.in'
];

const DEVELOPMENT_DEFAULT_ALLOWED_ORIGINS = [
  'https://pmt.solarman.in',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:5000',
  'http://127.0.0.1:5000'
];

function isProduction() {
  return process.env.NODE_ENV === 'production';
}

function normalizeOrigin(origin) {
  if (!origin || typeof origin !== 'string') return '';
  return origin.trim().replace(/\/+$/, '');
}

function getAllowedOrigins() {
  const isProd = isProduction();
  const rawList = (process.env.CORS_ORIGINS || '').split(',').map(normalizeOrigin).filter(Boolean);

  let allowed = isProd
    ? [...PRODUCTION_DEFAULT_ALLOWED_ORIGINS]
    : [...DEVELOPMENT_DEFAULT_ALLOWED_ORIGINS];

  // Merge explicitly configured CORS_ORIGINS from environment
  for (const origin of rawList) {
    if (!origin) continue;
    if (isProd) {
      // In production, enforce HTTPS only and ban localhost / IP addresses
      try {
        const parsed = new URL(origin);
        if (parsed.protocol !== 'https:') {
          console.warn(`[CORS SECURITY WARNING] Ignored non-HTTPS origin in production: ${origin}`);
          continue;
        }
        if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '0.0.0.0') {
          console.warn(`[CORS SECURITY WARNING] Ignored localhost/loopback origin in production: ${origin}`);
          continue;
        }
      } catch {
        continue;
      }
    }
    if (!allowed.includes(origin)) {
      allowed.push(origin);
    }
  }

  // Handle CLIENT_URL if provided
  if (process.env.CLIENT_URL) {
    const cUrl = normalizeOrigin(process.env.CLIENT_URL);
    if (cUrl) {
      if (isProd) {
        try {
          const parsed = new URL(cUrl);
          if (parsed.protocol === 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
            if (!allowed.includes(cUrl)) allowed.push(cUrl);
          }
        } catch {}
      } else {
        if (!allowed.includes(cUrl)) allowed.push(cUrl);
      }
    }
  }

  return allowed;
}

function isOriginAllowed(origin) {
  if (!origin || typeof origin !== 'string') return false;
  const normalized = normalizeOrigin(origin);
  if (!normalized || normalized === 'null') return false;

  const allowedList = getAllowedOrigins();

  // Strict exact matching only. No loose wildcards or broad suffix matching.
  return allowedList.includes(normalized);
}

module.exports = { getAllowedOrigins, isOriginAllowed, isProduction };

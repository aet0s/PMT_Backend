// server/src/utils/corsOrigins.js
// Centralized origin validation for Express CORS, CSRF protection, and Socket.io.
require('dotenv').config();

function getAllowedOrigins() {
  const list = (process.env.CORS_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const defaults = [
    'https://pmt.solarman.in',
    'http://pmt.solarman.in',
    'https://www.pmt.solarman.in',
    'http://www.pmt.solarman.in',
    'https://pmtmgmt.solarman.in',
    'http://pmtmgmt.solarman.in',
    'https://www.pmtmgmt.solarman.in',
    'http://www.pmtmgmt.solarman.in',
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:5000',
    'http://127.0.0.1:5000'
  ];
  for (const d of defaults) {
    if (!list.includes(d)) list.push(d);
  }
  if (process.env.CLIENT_URL) {
    const cUrl = process.env.CLIENT_URL.trim();
    if (!list.includes(cUrl)) list.push(cUrl);
  }
  return list;
}

function isOriginAllowed(origin) {
  if (!origin || origin === 'null') return false;
  const normalized = origin.trim().replace(/\/+$/, '');
  const list = getAllowedOrigins();

  if (list.includes(normalized)) return true;

  try {
    const parsed = new URL(normalized);
    // Allow any solarman.in domain or subdomain (e.g. pmt.solarman.in, www.pmt.solarman.in, pmtmgmt.solarman.in)
    if (parsed.hostname === 'solarman.in' || parsed.hostname.endsWith('.solarman.in')) {
      return true;
    }
    // Allow localhost and 127.0.0.1 with any port
    if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
      return true;
    }
  } catch (e) {
    // Malformed URL
  }

  return false;
}

module.exports = { getAllowedOrigins, isOriginAllowed };

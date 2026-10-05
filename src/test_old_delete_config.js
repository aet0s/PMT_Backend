// server/src/test_old_delete_config.js
const assert = require('assert');
const express = require('express');
const cors = require('cors');
const http = require('http');

async function testOldCorsBehavior() {
  console.log('=== Reproducing Old CORS Configuration Behavior ===\n');

  // Old configuration used in commit 0311411:
  // app.use(cors({ origin: process.env.CLIENT_URL || 'http://localhost:5173', credentials: true }));
  const app = express();
  const oldClientUrl = undefined; // As on an unconfigured server where CLIENT_URL was unset

  app.use(cors({
    origin: oldClientUrl || 'http://localhost:5173',
    credentials: true
  }));

  app.delete('/api/boards/1', (req, res) => res.json({ ok: true }));

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    console.log('Sending preflight OPTIONS from live origin https://pmt.solarman.in against old config...');
    const preflightRes = await fetch(`http://127.0.0.1:${port}/api/boards/1`, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://pmt.solarman.in',
        'Access-Control-Request-Method': 'DELETE',
        'Access-Control-Request-Headers': 'x-origin-id,Content-Type'
      }
    });

    const allowOrigin = preflightRes.headers.get('access-control-allow-origin');
    console.log(`Preflight Access-Control-Allow-Origin returned: ${allowOrigin}`);

    assert.notStrictEqual(allowOrigin, 'https://pmt.solarman.in', 'Old config does not allow live origin');
    assert.strictEqual(allowOrigin, 'http://localhost:5173', 'Old config hardcoded fallback to localhost:5173');
    console.log('✓ Proven: The old configuration returned Access-Control-Allow-Origin: http://localhost:5173 to https://pmt.solarman.in, causing browser CORS rejection.\n');
  } finally {
    server.close();
  }
}

testOldCorsBehavior()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });

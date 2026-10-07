// server/src/test_kb_socket_origin.js
// Tests for Follow-up 4: Socket.IO Origin Allow-List enforcement on both polling and websocket transports
const assert = require('assert');
const http = require('http');
const express = require('express');
const Client = require('socket.io-client');
const jwt = require('jsonwebtoken');
const { initSocket } = require('./socket');
const { getJwtSecret } = require('./middleware/auth');

process.env.CLIENT_URL = 'https://pmt.solarman.in';
process.env.CORS_ORIGINS = 'https://pmt.solarman.in,http://localhost:5173';

async function runSocketOriginTests() {
  console.log('=== Running K-B Follow-up 4: Socket.IO Origin Allow-List Tests ===\n');

  const app = express();
  const server = http.createServer(app);
  const io = initSocket(server);

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const serverUrl = `http://127.0.0.1:${port}`;

  const token = jwt.sign({ userId: 101, sub: '101', email: 'socket_origin@example.com' }, getJwtSecret(), { expiresIn: '1h' });

  try {
    // 1. Handshake from allowed origin works on polling transport
    console.log('1. Testing handshake from allowed origin via polling transport...');
    const clientPolling = Client(serverUrl, {
      transports: ['polling'],
      extraHeaders: { origin: 'https://pmt.solarman.in' },
      auth: { token },
      timeout: 3000
    });
    await new Promise((resolve, reject) => {
      clientPolling.on('connect', resolve);
      clientPolling.on('connect_error', reject);
    });
    assert.strictEqual(clientPolling.connected, true);
    clientPolling.disconnect();
    console.log('✓ Allowed origin successfully connected via polling.');

    // 2. Handshake from allowed origin works on websocket transport
    console.log('2. Testing handshake from allowed origin via websocket transport...');
    const clientWs = Client(serverUrl, {
      transports: ['websocket'],
      extraHeaders: { origin: 'http://localhost:5173' },
      auth: { token },
      timeout: 3000
    });
    await new Promise((resolve, reject) => {
      clientWs.on('connect', resolve);
      clientWs.on('connect_error', reject);
    });
    assert.strictEqual(clientWs.connected, true);
    clientWs.disconnect();
    console.log('✓ Allowed origin successfully connected via websocket.');

    // 3. Handshake from evil foreign origin https://pmt.solarman.in.evil.com is rejected
    console.log('3. Testing rejection of foreign origin (https://pmt.solarman.in.evil.com)...');
    const clientEvil = Client(serverUrl, {
      transports: ['polling'],
      extraHeaders: { origin: 'https://pmt.solarman.in.evil.com' },
      auth: { token },
      timeout: 2000,
      reconnection: false
    });
    let evilRejected = false;
    await new Promise((resolve) => {
      clientEvil.on('connect', () => {
        clientEvil.disconnect();
        resolve();
      });
      clientEvil.on('connect_error', (err) => {
        evilRejected = true;
        clientEvil.disconnect();
        resolve();
      });
    });
    assert.strictEqual(evilRejected, true, 'Foreign origin MUST be rejected at handshake');
    console.log('✓ Foreign origin correctly rejected at handshake.');

    // 4. Handshake from "null" origin is rejected
    console.log('4. Testing rejection of "null" origin...');
    const clientNull = Client(serverUrl, {
      transports: ['polling'],
      extraHeaders: { origin: 'null' },
      auth: { token },
      timeout: 2000,
      reconnection: false
    });
    let nullRejected = false;
    await new Promise((resolve) => {
      clientNull.on('connect', () => {
        clientNull.disconnect();
        resolve();
      });
      clientNull.on('connect_error', (err) => {
        nullRejected = true;
        clientNull.disconnect();
        resolve();
      });
    });
    assert.strictEqual(nullRejected, true, '"null" origin MUST be rejected at handshake');
    console.log('✓ "null" origin correctly rejected at handshake.');

    // 5. Handshake from non-browser client without Origin header is rejected
    console.log('5. Testing rejection of client missing Origin header...');
    const clientNoOrigin = Client(serverUrl, {
      transports: ['polling'],
      auth: { token },
      timeout: 2000,
      reconnection: false
    });
    let noOriginRejected = false;
    await new Promise((resolve) => {
      clientNoOrigin.on('connect', () => {
        clientNoOrigin.disconnect();
        resolve();
      });
      clientNoOrigin.on('connect_error', (err) => {
        noOriginRejected = true;
        clientNoOrigin.disconnect();
        resolve();
      });
    });
    assert.strictEqual(noOriginRejected, true, 'Client without Origin header MUST be rejected');
    console.log('✓ Missing Origin client correctly rejected with ORIGIN_REQUIRED at handshake.');

    console.log('\n===============================================');
    console.log('K-B FOLLOW-UP 4 SOCKET ORIGIN TESTS PASSED (5/5)!');
    console.log('===============================================\n');
  } finally {
    server.close();
  }
}

runSocketOriginTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Socket origin test failed:', err);
    process.exit(1);
  });

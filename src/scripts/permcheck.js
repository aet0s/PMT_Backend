#!/usr/bin/env node
// server/src/scripts/permcheck.js
// CLI bridge to permcheck/index.js

const { main } = require('./permcheck/index.js');

main().catch((err) => {
  console.error('[FATAL PERMCHECK ERROR]:', err);
  process.exit(1);
});

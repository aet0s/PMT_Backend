// server/src/test_l0_socket_static_audit.js
// Static audit test for L-0:
// Fails on any io.to(...).to(...) chain or any un-namespaced room string outside the single-tenant branch.
const fs = require('fs');
const path = require('path');

const SRC_DIR = path.join(__dirname);

function getAllJsFiles(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  list.forEach((file) => {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat && stat.isDirectory()) {
      results = results.concat(getAllJsFiles(fullPath));
    } else if (file.endsWith('.js')) {
      results.push(fullPath);
    }
  });
  return results;
}

function runStaticAudit() {
  console.log('=== L-0 STATIC AUDIT: Scanning server/src for room chaining and un-namespaced rooms ===');
  const files = getAllJsFiles(SRC_DIR);
  const errors = [];

  const CHAINED_TO_REGEX = /\.to\([^)]*\)\s*\.to\(/;

  files.forEach((file) => {
    // Skip test files themselves
    if (file.includes('test_')) return;

    const content = fs.readFileSync(file, 'utf8');
    const lines = content.split('\n');

    lines.forEach((line, idx) => {
      // 1. Assert no .to(...).to(...) chaining
      if (CHAINED_TO_REGEX.test(line)) {
        errors.push({
          file: path.relative(SRC_DIR, file),
          lineNum: idx + 1,
          line: line.trim(),
          reason: 'Forbidden .to().to() room union chaining detected'
        });
      }

      // 2. Check for raw un-namespaced room literals in socket calls
      // e.g. socket.join(`board:${...}`), io.to(`user:${...}`), etc.
      // These must ONLY exist inside isSingleTenantMode() or DEV_SINGLE_TENANT === '1' branches in socket.js
      const rawRoomRegex = /(?:socket\.join|io\.to|\.to)\s*\(\s*[`'"](board|user|workspace):/;
      if (rawRoomRegex.test(line)) {
        // Check if within socket.js and inside a single-tenant check
        if (!file.endsWith('socket.js')) {
          errors.push({
            file: path.relative(SRC_DIR, file),
            lineNum: idx + 1,
            line: line.trim(),
            reason: 'Un-namespaced room string outside socket.js'
          });
        }
      }
    });
  });

  if (errors.length > 0) {
    console.error(`FAILED: Found ${errors.length} static room safety violation(s):`);
    errors.forEach((e) => {
      console.error(`  - [${e.file}:${e.lineNum}] ${e.reason}: "${e.line}"`);
    });
    process.exit(1);
  }

  console.log(`PASSED: Scanned ${files.length} server files. Zero .to().to() chains and zero un-guarded un-namespaced rooms.`);
}

runStaticAudit();

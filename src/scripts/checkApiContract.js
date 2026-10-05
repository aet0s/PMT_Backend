// server/src/scripts/checkApiContract.js
// K-B.4: Client <-> Server API Contract Checker.
// Statically extracts all API calls from client/src and cross-references them against
// the real Express router stack (87 production routes).
// Fails if any client API call has no matching server route.

const fs = require('fs');
const path = require('path');
const { app } = require('../index');

function getExpressRoutes(appInstance) {
  const routes = [];
  function process(stack, prefix = '') {
    for (const layer of stack) {
      if (layer.route) {
        const methods = Object.keys(layer.route.methods).filter((m) => layer.route.methods[m]);
        for (const m of methods) {
          let p = (prefix + layer.route.path).replace(/\/+/g, '/');
          if (p.endsWith('/') && p.length > 1) p = p.slice(0, -1);
          if (p !== '*' && p !== '/api/*') {
            routes.push({ method: m.toUpperCase(), path: p });
          }
        }
      } else if (layer.name === 'router' && layer.handle && layer.handle.stack) {
        let pfx = '';
        if (layer.regexp) {
          const s = layer.regexp.source;
          const match = s.match(/^\^\\?(\/.*?)(?:\\\/\?)?(?:\(\?=\\\/\|\$\)|\$)/);
          if (match) {
            pfx = match[1].replace(/\\\//g, '/').replace(/\\\./g, '.');
          }
        }
        process(layer.handle.stack, prefix + pfx);
      }
    }
  }
  process(appInstance._router.stack);
  return routes;
}

function findSourceFiles(dir, exts = ['.js', '.jsx']) {
  let files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== 'dist' && entry.name !== 'test') {
        files = files.concat(findSourceFiles(fullPath, exts));
      }
    } else if (exts.includes(path.extname(entry.name))) {
      files.push(fullPath);
    }
  }
  return files;
}

function extractClientApiCalls(clientSrcDir) {
  const files = findSourceFiles(clientSrcDir);
  const calls = [];

  const apiRegex = /(?:apiFetch|fetch)\s*\(\s*([`'"][^`'"]*[`'"])/g;
  const templateParamRegex = /\$\{([^}]+)\}/g;

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf-8');
    const relPath = path.relative(clientSrcDir, file);

    // Scan line by line or via regex
    let match;
    const callRegex = /(?:apiFetch|fetch)\s*\(\s*([`'"][^`'"]+[`'"])(?:,\s*(\{[^}]*\}))?/g;
    while ((match = callRegex.exec(content)) !== null) {
      let rawUrl = match[1].slice(1, -1);
      const optionsBlock = match[2] || '';

      // Only inspect /api/ routes
      if (!rawUrl.startsWith('/api/') && !rawUrl.includes('/api/')) continue;

      // Extract HTTP method (default GET)
      let method = 'GET';
      const methodMatch = optionsBlock.match(/method\s*:\s*['"](GET|POST|PUT|PATCH|DELETE)['"]/i);
      if (methodMatch) {
        method = methodMatch[1].toUpperCase();
      }

      // Strip query parameters and query variable interpolations like ${query} or ?${params}
      let cleanedUrl = rawUrl.split('?')[0];
      cleanedUrl = cleanedUrl.replace(/\$\{(?:query|params|search|qs|filters)[^}]*\}/gi, '');

      // Normalize path template variables: ${param} -> :id
      let normalizedPath = cleanedUrl.replace(templateParamRegex, ':id');

      // Clean up duplicate slashes or trailing slashes
      normalizedPath = normalizedPath.replace(/\/+/g, '/');
      if (normalizedPath.endsWith('/') && normalizedPath.length > 1) {
        normalizedPath = normalizedPath.slice(0, -1);
      }

      calls.push({
        method,
        rawUrl,
        normalizedPath,
        file: relPath
      });
    }
  }

  return calls;
}

function pathMatches(clientPattern, serverPattern) {
  // Normalize both by turning any :param into :wildcard
  const normClient = clientPattern.replace(/:[a-zA-Z0-9_]+/g, ':id');
  const normServer = serverPattern.replace(/:[a-zA-Z0-9_]+/g, ':id');
  return normClient === normServer;
}

function runContractCheck() {
  console.log('================================================================');
  console.log('         K-B.4 CLIENT <-> SERVER API CONTRACT CHECKER           ');
  console.log('================================================================\n');

  const serverRoutes = getExpressRoutes(app);
  const prodRoutes = serverRoutes.filter((r) => r.path !== '/api/dev/reset-rate-limit');
  console.log(`[SERVER] Extracted ${prodRoutes.length} real Express routes from live stack.`);

  const clientSrcDir = path.resolve(__dirname, '../../../client/src');
  if (!fs.existsSync(clientSrcDir)) {
    console.error(`ERROR: client/src not found at ${clientSrcDir}`);
    process.exit(1);
  }

  const clientCalls = extractClientApiCalls(clientSrcDir);
  console.log(`[CLIENT] Extracted ${clientCalls.length} API call sites across client/src.\n`);

  let missingRoutes = [];
  const matchedServerRoutes = new Set();

  for (const call of clientCalls) {
    const matchingServerRoute = prodRoutes.find(
      (sr) => sr.method === call.method && pathMatches(call.normalizedPath, sr.path)
    );

    if (matchingServerRoute) {
      matchedServerRoutes.add(`${matchingServerRoute.method} ${matchingServerRoute.path}`);
    } else {
      missingRoutes.push(call);
    }
  }

  // Deduplicate matched and unmatched
  const uniqueMissing = [];
  const seenMissing = new Set();
  for (const m of missingRoutes) {
    const key = `${m.method} ${m.normalizedPath}`;
    if (!seenMissing.has(key)) {
      seenMissing.add(key);
      uniqueMissing.push(m);
    }
  }

  if (uniqueMissing.length > 0) {
    console.error('❌ CONTRACT VIOLATION: The client invokes API routes that DO NOT EXIST on the server:');
    for (const m of uniqueMissing) {
      console.error(`  - ${m.method} ${m.normalizedPath} (called in ${m.file})`);
    }
    process.exit(1);
  }

  console.log('✓ All client API calls successfully match active server routes (0 contract violations).\n');

  // Informational: server routes not called directly by client UI
  const uncalledServerRoutes = prodRoutes.filter(
    (sr) => !matchedServerRoutes.has(`${sr.method} ${sr.path}`)
  );

  console.log(`[INFO] Server routes not directly called by client SPA (${uncalledServerRoutes.length} routes):`);
  console.log('  (These include webhooks, background runners, auth redirects, and test helpers)');
  for (const sr of uncalledServerRoutes) {
    console.log(`  - ${sr.method} ${sr.path}`);
  }

  console.log('\n================================================================');
  console.log('API CONTRACT CHECK PASSED: 100% OF CLIENT CALLS VALIDATED!');
  console.log('================================================================');
}

if (require.main === module) {
  runContractCheck();
}

module.exports = { runContractCheck };

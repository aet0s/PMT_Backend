// server/src/scripts/permtest/frontendReachability.js
// Parses client router config from client/src/App.jsx, asserts every declared route
// is represented, and verifies HTTP 200 with the valid Vite HTML SPA shell.

const http = require('http');
const fs = require('fs');
const path = require('path');

function parseClientRouterConfig() {
  const appJsxPath = path.resolve(__dirname, '../../../../client/src/App.jsx');
  if (!fs.existsSync(appJsxPath)) {
    throw new Error(`Client App.jsx not found at ${appJsxPath}`);
  }
  const content = fs.readFileSync(appJsxPath, 'utf8');

  // Find router declaration: createBrowserRouter([ ... ])
  const routerMatch = content.match(/createBrowserRouter\(\s*\[([\s\S]*?)\]\s*,\s*\{/);
  if (!routerMatch) {
    throw new Error('Could not locate createBrowserRouter in client/src/App.jsx');
  }

  // Extract all path properties
  const pathRegex = /path:\s*['"`]([^'"`]+)['"`]/g;
  const declaredPaths = new Set();
  let match;
  while ((match = pathRegex.exec(routerMatch[1])) !== null) {
    declaredPaths.add(match[1]);
  }

  return Array.from(declaredPaths);
}

function checkRoute(route) {
  return new Promise((resolve) => {
    const req = http.get(`http://localhost:5173${route}`, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        const isHtml = (res.headers['content-type'] || '').includes('text/html');
        const hasRoot = body.includes('id="root"');
        const hasMainScript = body.includes('/src/main.jsx') || body.includes('main.jsx');
        const validShell = isHtml && hasRoot && hasMainScript;

        resolve({
          route,
          status: res.statusCode,
          isHtml,
          hasRoot,
          hasMainScript,
          validShell,
          bytes: body.length
        });
      });
    });
    req.on('error', (err) => {
      resolve({
        route,
        status: 'ERROR',
        error: err.message,
        validShell: false
      });
    });
  });
}

async function runFrontendReachability() {
  console.log('================================================================');
  console.log('       FRONTEND ROUTER CONFIG & REACHABILITY AUDIT              ');
  console.log('================================================================\n');

  const declaredPaths = parseClientRouterConfig();
  console.log(`Parsed ${declaredPaths.length} declared route patterns from client/src/App.jsx:`);
  declaredPaths.forEach(p => console.log(`  - \`${p}\``));
  console.log('');

  // Map each declared pattern into one or more concrete testable paths
  const routeMapping = {
    '/': ['/'],
    '/login': ['/login'],
    '/register': ['/register'],
    '/forgot-password': ['/forgot-password'],
    '/reset-password': ['/reset-password'],
    '/invite': ['/invite'],
    '/invite/:token': ['/invite/sample_token_123'],
    '/dev/components': ['/dev/components'],
    '/account': ['/account'],
    '/account/:tab': ['/account/profile', '/account/security'],
    '/profile': ['/profile'],
    '/profile/:tab': ['/profile/profile'],
    '/w/:workspaceId/*': [
      '/w/1/home',
      '/w/1/b/1',
      '/w/1/settings',
      '/w/1/settings/roles',
      '/w/1/settings/members',
      '/w/1/members',
      '/w/1/activity',
      '/w/1/archive'
    ],
    '/b/:boardId': ['/b/1'],
    '/403': ['/403'],
    '/404': ['/404'],
    '*': ['/404']
  };

  // Assert every declared router path has an explicit mapping
  const missingPatterns = declaredPaths.filter(p => !routeMapping[p]);
  if (missingPatterns.length > 0) {
    throw new Error(`Router patterns declared in App.jsx missing concrete test mapping: ${missingPatterns.join(', ')}`);
  }

  // Compile full set of unique routes to verify
  const routesToVerify = [];
  const patternTested = new Set();
  for (const pattern of declaredPaths) {
    const concrete = routeMapping[pattern] || [];
    for (const r of concrete) {
      if (!routesToVerify.includes(r)) {
        routesToVerify.push(r);
      }
    }
    patternTested.add(pattern);
  }

  console.log(`Total concrete routes to verify against Vite SPA server: ${routesToVerify.length}\n`);
  console.log('| Client Route | Status | HTML | #root | /src/main.jsx | Result |');
  console.log('|---|---|---|---|---|---|');

  let passed = 0;
  for (const r of routesToVerify) {
    const res = await checkRoute(r);
    const pass = res.status === 200 && res.validShell;
    if (pass) passed++;
    console.log(
      `| \`${res.route}\` | ${res.status} | ${res.isHtml ? '✅' : '❌'} | ${res.hasRoot ? '✅' : '❌'} | ${res.hasMainScript ? '✅' : '❌'} | ${pass ? '✅ PASS' : '❌ FAIL'} |`
    );
  }

  console.log(`\nReachability: ${passed}/${routesToVerify.length} verified successfully.`);
  const allPassed = passed === routesToVerify.length && patternTested.size === declaredPaths.length;

  if (allPassed) {
    console.log('✅ ALL DECLARED CLIENT ROUTES PARSED AND VERIFIED WITH 200 VITE SPA SHELL.');
  } else {
    console.error('❌ SOME CLIENT ROUTES FAILED REACHABILITY VERIFICATION.');
  }

  return {
    passed,
    total: routesToVerify.length,
    declaredCount: declaredPaths.length,
    allPassed
  };
}

module.exports = { runFrontendReachability };

if (require.main === module) {
  runFrontendReachability().then(res => {
    if (!res.allPassed) process.exit(1);
  }).catch(err => {
    console.error(err);
    process.exit(1);
  });
}

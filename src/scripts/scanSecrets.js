#!/usr/bin/env node
// server/src/scripts/scanSecrets.js
/**
 * Repository Secrets & Firebase Credentials Scanner
 * Recursively scans project files to ensure no private keys, Firebase service account keys,
 * or credentials are inadvertently committed into the codebase.
 */
const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '../../../');

const EXCLUDED_DIRS = new Set([
  'node_modules',
  '.git',
  '.gemini',
  '.agents',
  'brain',
  'uploads',
  'dist',
  'build',
  'coverage',
  '.nyc_output',
  'tmp',
  'temp',
  '.turbo',
  '.cache'
]);

const EXCLUDED_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.ico',
  '.pdf',
  '.zip',
  '.tar',
  '.gz',
  '.mp3',
  '.wav',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot'
]);

// Secret patterns to flag
const SECRET_PATTERNS = [
  {
    name: 'Firebase / PKCS#8 Private Key',
    regex: /-----BEGIN\s+(RSA\s+|EC\s+)?PRIVATE\s+KEY-----/i
  },
  {
    name: 'Firebase Service Account JSON Structure',
    regex: /"type"\s*:\s*"service_account"[\s\S]{1,500}"private_key"\s*:\s*"-----BEGIN/i
  },
  {
    name: 'AWS Secret Access Key Pattern',
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/
  }
];

function scanDirectory(dir, results = { scanned: 0, violations: [] }) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    return results;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(ROOT_DIR, fullPath).replace(/\\/g, '/');

    if (entry.isDirectory()) {
      if (EXCLUDED_DIRS.has(entry.name)) continue;
      scanDirectory(fullPath, results);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (EXCLUDED_EXTENSIONS.has(ext)) continue;

      // Skip large binary files or archives
      let stat;
      try {
        stat = fs.statSync(fullPath);
        if (stat.size > 2 * 1024 * 1024) continue; // Skip files > 2MB
      } catch (_) {
        continue;
      }

      results.scanned++;

      // Check filename for service account leak
      if (
        /service[-_]?account.*\.json$/i.test(entry.name) ||
        /firebase[-_]?adminsdk.*\.json$/i.test(entry.name)
      ) {
        results.violations.push({
          file: relPath,
          issue: 'Firebase Service Account JSON file committed in repository'
        });
        continue;
      }

      // Check file content
      try {
        const content = fs.readFileSync(fullPath, 'utf8');

        // Ignore the scanner itself and test fixtures that explicitly mock keys
        if (relPath.includes('scanSecrets.js')) continue;

        for (const pattern of SECRET_PATTERNS) {
          if (pattern.regex.test(content)) {
            // Check if it's in a test file using dummy/mock keys or documentation
            if (
              relPath.includes('.test.') ||
              relPath.includes('test_') ||
              relPath.includes('docs/') ||
              relPath.includes('.example')
            ) {
              // Ensure it's not a real 2048-bit key even in test files
              if (content.includes('-----BEGIN PRIVATE KEY-----') && !content.includes('MOCK_PRIVATE_KEY') && !content.includes('TEST_PRIVATE_KEY') && content.length > 1500) {
                results.violations.push({
                  file: relPath,
                  issue: `Potential real ${pattern.name} found`
                });
              }
              continue;
            }

            results.violations.push({
              file: relPath,
              issue: `${pattern.name} detected`
            });
            break;
          }
        }
      } catch (_) {}
    }
  }

  return results;
}

function runSecretsScan() {
  console.log('================================================================================');
  console.log('                    REPOSITORY SECRETS & CREDENTIAL SCANNER                     ');
  console.log('================================================================================\n');

  const { scanned, violations } = scanDirectory(ROOT_DIR);

  console.log(`Scanned ${scanned} files across repository.`);

  if (violations.length > 0) {
    console.error(`\n❌ SECRETS SCAN FAILED: ${violations.length} secret violation(s) detected:`);
    for (const v of violations) {
      console.error(`  - [${v.file}]: ${v.issue}`);
    }
    console.error('\nImmediate Action: Revoke any exposed credentials and purge from git history.\n');
    console.log('================================================================================\n');
    return false;
  }

  console.log('✅ CLEAN: No private keys, service accounts, or leaked credentials found.');
  console.log('================================================================================\n');
  return true;
}

if (require.main === module) {
  const success = runSecretsScan();
  process.exit(success ? 0 : 1);
}

module.exports = { runSecretsScan };

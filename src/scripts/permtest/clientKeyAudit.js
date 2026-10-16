// server/src/scripts/permtest/clientKeyAudit.js
// Audits all permission keys referenced in client/src against the RBAC catalog.
// Asserts that every key exists, is non-planned, and is non-legacy.

const fs = require('fs');
const path = require('path');
const { PERMISSIONS, LEGACY_PERMISSION_ALIASES } = require('../../rbac/registry');

const CLIENT_SRC_DIR = path.resolve(__dirname, '../../../../client/src');

function getAllFiles(dir, exts = ['.js', '.jsx', '.ts', '.tsx']) {
  let files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== 'dist' && entry.name !== '.git') {
        files = files.concat(getAllFiles(full, exts));
      }
    } else if (exts.includes(path.extname(entry.name))) {
      files.push(full);
    }
  }
  return files;
}

function auditClientKeys() {
  console.log('================================================================');
  console.log('            CLIENT PERMISSION KEY AUDIT (client/src)           ');
  console.log('================================================================\n');

  const files = getAllFiles(CLIENT_SRC_DIR);
  console.log(`Scanning ${files.length} client files for permission key references...\n`);

  const activeCatalogKeys = new Map(PERMISSIONS.filter(p => !p.planned).map(p => [p.key, p]));
  const plannedCatalogKeys = new Map(PERMISSIONS.filter(p => p.planned).map(p => [p.key, p]));
  const legacyKeys = new Set(Object.keys(LEGACY_PERMISSION_ALIASES));

  // Regex patterns to capture permission keys
  // 1. can('key', ...), can("key", ...)
  // 2. hasPermission('key', ...), hasPermission("key", ...)
  // 3. <Can I="key" ...>, <Can perform="key" ...>, <Can permission="key" ...>
  const patterns = [
    /\bcan\(\s*['"]([a-z_]+(?:\.[a-z_]+)+)['"]/g,
    /\bhasPermission\(\s*['"]([a-z_]+(?:\.[a-z_]+)+)['"]/g,
    /\bcheckPermission\(\s*['"]([a-z_]+(?:\.[a-z_]+)+)['"]/g,
    /<Can\s+[^>]*\b(?:I|perform|permission)=['"]([a-z_]+(?:\.[a-z_]+)+)['"]/g,
    /\bpermission:\s*['"]([a-z_]+(?:\.[a-z_]+)+)['"]/g,
    /\bpermissionKey:\s*['"]([a-z_]+(?:\.[a-z_]+)+)['"]/g
  ];

  const keyUsage = new Map(); // key -> [{ file, line, raw }]

  for (const file of files) {
    const relFile = path.relative(CLIENT_SRC_DIR, file).replace(/\\/g, '/');
    const content = fs.readFileSync(file, 'utf8');
    const lines = content.split('\n');

    lines.forEach((line, idx) => {
      // Ignore comments
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) return;

      for (const regex of patterns) {
        regex.lastIndex = 0;
        let match;
        while ((match = regex.exec(line)) !== null) {
          const key = match[1];
          if (!keyUsage.has(key)) {
            keyUsage.set(key, []);
          }
          keyUsage.get(key).push({
            file: relFile,
            line: idx + 1,
            raw: line.trim()
          });
        }
      }
    });
  }

  console.log(`Found ${keyUsage.size} distinct permission keys used across client components:\n`);

  let invalidKeys = 0;
  let plannedCount = 0;
  let legacyCount = 0;
  let validActiveCount = 0;

  const sortedKeys = Array.from(keyUsage.keys()).sort();

  console.log('| Permission Key | Occurrences | Status | Scope | Sample File |');
  console.log('|---|---|---|---|---|');

  for (const key of sortedKeys) {
    const usages = keyUsage.get(key);
    const sample = `${usages[0].file}:${usages[0].line}`;
    let status = 'VALID_ACTIVE';

    if (legacyKeys.has(key)) {
      status = '❌ LEGACY_ALIAS';
      legacyCount++;
    } else if (plannedCatalogKeys.has(key)) {
      status = '⚠️ PLANNED (NOT_ACTIVE)';
      plannedCount++;
    } else if (activeCatalogKeys.has(key)) {
      status = '✅ ACTIVE';
      validActiveCount++;
    } else {
      status = '❌ UNKNOWN_KEY';
      invalidKeys++;
    }

    const def = activeCatalogKeys.get(key) || plannedCatalogKeys.get(key);
    const scope = def ? def.scope : 'UNKNOWN';

    console.log(`| \`${key}\` | ${usages.length} | ${status} | ${scope} | \`${sample}\` |`);
  }

  console.log('\n================================================================');
  console.log('AUDIT SUMMARY:');
  console.log(`  Total Keys Checked:   ${sortedKeys.length}`);
  console.log(`  Active Catalog Keys:  ${validActiveCount}`);
  console.log(`  Planned Keys:         ${plannedCount}`);
  console.log(`  Legacy Alias Keys:    ${legacyCount}`);
  console.log(`  Unknown Keys:         ${invalidKeys}`);
  console.log('================================================================\n');

  if (invalidKeys > 0 || plannedCount > 0 || legacyCount > 0) {
    console.error('❌ CLIENT KEY AUDIT FAILED: Non-canonical, planned, or legacy keys found in client/src!');
    return false;
  }

  console.log('✅ CLIENT KEY AUDIT PASSED: 100% of client permission keys exist in catalog, are non-planned, and non-legacy.');
  return true;
}

if (require.main === module) {
  const ok = auditClientKeys();
  process.exit(ok ? 0 : 1);
}

module.exports = { auditClientKeys };

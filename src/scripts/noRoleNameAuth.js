#!/usr/bin/env node
// server/src/scripts/noRoleNameAuth.js
// Lint script to enforce Section 2, Rule 6 & Section 3:
// "No code path may compare a role name to a string for authorization decisions.
// Role names are labels only.
// Rank-threshold authorization is banned everywhere except explicit hierarchy rules
// (acting on, assigning, resetting or removing users of lower rank)."

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '../..');
const SRC_DIR = path.resolve(ROOT_DIR, 'src');

// Excluded files / directories (seeding, migrations, rank definition tables, and test scripts)
const EXCLUDED_PATTERNS = [
  /[\\\/]db[\\\/]migrations/,
  /[\\\/]db[\\\/]seed\.js$/,
  /[\\\/]services[\\\/]tenantProvisioner\.js$/, // seed queries for initial workspace creation
  /[\\\/]rbac[\\\/]registry\.js$/, // system role definitions & catalog
  /[\\\/]rbac[\\\/]catalogSync\.js$/, // system role synchronization
  /[\\\/]utils[\\\/]roleRank\.js$/, // reserved role names and rank table lookup
  /[\\\/]scripts[\\\/]/, // test runners & admin scripts
  /[\\\/]__tests__[\\\/]/ // test files
];

// Patterns representing role-name branching in authorization logic
const FORBIDDEN_ROLE_PATTERNS = [
  /roleName\s*===\s*['"`](Owner|Admin|Viewer|Super Admin|Project Manager|Team Member|Guest)['"`]/i,
  /role\.name\s*===\s*['"`](Owner|Admin|Viewer|Super Admin|Project Manager|Team Member|Guest)['"`]/i,
  /r\.name\s*===\s*['"`](Owner|Admin|Viewer|Super Admin|Project Manager|Team Member|Guest)['"`]/i,
  /normalizedRole\s*===\s*['"`](owner|admin|viewer|super admin|project manager|team member|guest)['"`]/i,
  /\['Owner',\s*'Super Admin',\s*'Admin'\]\.includes/i,
  /\['owner',\s*'super admin',\s*'admin'/i,
  /\.includes\(roleName\)/,
  /\.includes\(normalizedRole\)/
];

// Patterns representing rank comparisons
const RANK_COMPARISON_PATTERNS = [
  /rank\s*>=/i,
  /getRoleRank\([^)]*\)\s*>=/i
];

// Allowed rank comparison lines (explicit user-on-user hierarchy checks)
const ALLOWED_HIERARCHY_CHECKS = [
  // User cannot assign/invite into a role equal or higher rank than themselves
  /newRank\s*>=\s*callerRank/,
  /newRoleRank\s*>=\s*callerRank/,
  // User cannot act on or reset a user of equal or higher rank
  /callerRank\s*<=\s*targetRank/,
  /targetRank\s*>=\s*callerRank/,
  // Catalog filter: allow planned keys probe check for Admin/Owner
  /userRoles\.some\(\(r\)\s*=>\s*getRoleRank\(r\)\s*>=\s*80\)/
];

function isExcluded(filePath) {
  return EXCLUDED_PATTERNS.some((pattern) => pattern.test(filePath));
}

function scanDirectory(dir, violations = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (!isExcluded(fullPath)) {
        scanDirectory(fullPath, violations);
      }
    } else if (entry.isFile() && fullPath.endsWith('.js')) {
      if (isExcluded(fullPath)) continue;

      const content = fs.readFileSync(fullPath, 'utf8');
      const lines = content.split('\n');

      lines.forEach((line, index) => {
        // Skip comment lines
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return;

        // 1. Check forbidden role-name string checks
        for (const pattern of FORBIDDEN_ROLE_PATTERNS) {
          if (pattern.test(line)) {
            violations.push({
              file: path.relative(ROOT_DIR, fullPath).replace(/\\/g, '/'),
              line: index + 1,
              content: trimmed,
              type: 'ROLE_NAME_AUTH',
              pattern: pattern.toString()
            });
            return;
          }
        }

        // 2. Check forbidden rank-threshold authorization checks
        for (const pattern of RANK_COMPARISON_PATTERNS) {
          if (pattern.test(line)) {
            const isAllowedHierarchy = ALLOWED_HIERARCHY_CHECKS.some((allow) => allow.test(line));
            if (!isAllowedHierarchy) {
              violations.push({
                file: path.relative(ROOT_DIR, fullPath).replace(/\\/g, '/'),
                line: index + 1,
                content: trimmed,
                type: 'RANK_THRESHOLD_AUTH',
                pattern: pattern.toString()
              });
              return;
            }
          }
        }
      });
    }
  }

  return violations;
}

function run() {
  console.log('=== RBAC LINT: Checking for Role-Name & Unauthorized Rank Authorization ===\n');
  const violations = scanDirectory(SRC_DIR);

  if (violations.length > 0) {
    console.error(`❌ FAILED: Found ${violations.length} forbidden authorization check(s):`);
    violations.forEach((v) => {
      console.error(`  - [${v.type}] ${v.file}:${v.line}`);
      console.error(`    ${v.content}`);
    });
    console.error('\nRules:');
    console.error('1. Authorization decisions must check pure permissions, NEVER role names.');
    console.error('2. Rank comparisons are banned for resource authorization and allowed ONLY for explicit hierarchy rules.\n');
    return false;
  }

  console.log('✅ PASSED: Zero forbidden role-name or rank-threshold authorization checks found in server/src.');
  return true;
}

if (require.main === module) {
  const passed = run();
  process.exit(passed ? 0 : 1);
}

module.exports = { run, scanDirectory };

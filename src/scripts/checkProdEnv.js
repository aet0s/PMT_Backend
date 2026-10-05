#!/usr/bin/env node
// server/src/scripts/checkProdEnv.js
/**
 * Production Environment Hardening & Pre-Flight Verification Script
 * Validates security requirements, secrets, permissions, and database parameters before production boot.
 * Prints clear, actionable remediation guidance without ever exposing secret values.
 * Supports --json flag for automated deployment pipelines.
 */
require('dotenv').config();
const path = require('path');
const fs = require('fs');

function checkProdEnv(env = process.env) {
  const issues = []; // { variable, problem, fix }
  const warnings = [];

  // Helper to add structured issue
  function addError(variable, problem, fix) {
    issues.push({ variable, problem, fix, message: `[${variable}] Problem: ${problem} | Fix: ${fix}` });
  }

  // 1. NODE_ENV Check
  if (env.NODE_ENV !== 'production') {
    addError('NODE_ENV', `NODE_ENV is '${env.NODE_ENV || 'undefined'}'`, "Set NODE_ENV=production in production environment");
  }

  // 2. Dev Flags Check
  if (env.DISABLE_RATE_LIMIT && env.DISABLE_RATE_LIMIT !== 'false' && env.DISABLE_RATE_LIMIT !== '0') {
    addError('DISABLE_RATE_LIMIT', 'Rate limit bypass flag is active', "Remove DISABLE_RATE_LIMIT or set to 'false' / '0'");
  }
  if (env.DEV_SINGLE_TENANT && env.DEV_SINGLE_TENANT !== 'false' && env.DEV_SINGLE_TENANT !== '0') {
    addError('DEV_SINGLE_TENANT', 'DEV_SINGLE_TENANT is enabled; production must run multi-tenant', "Set DEV_SINGLE_TENANT=0 or remove it");
  }

  // 3. Database User Check
  if (env.DB_USER === 'root') {
    addError('DB_USER', "DB_USER cannot be 'root' in production", "Provision and configure a dedicated restricted MariaDB user (e.g. DB_USER=pmt_app_user)");
  }

  // 4. Secrets Security Audit (NEVER print secret values)
  const WEAK_WORDS = ['secret', 'default', 'changeme', 'dev', '12345', 'password', 'demo', 'test'];
  const secretsToCheck = [
    { name: 'JWT_SECRET', minLen: 32 },
    { name: 'JWT_REFRESH_SECRET', minLen: 32 },
    { name: 'SESSION_SECRET', minLen: 32 },
    { name: 'INVITATION_SECRET', minLen: 32 }
  ];

  for (const { name, minLen } of secretsToCheck) {
    const val = env[name];
    if (!val) {
      addError(name, 'Secret variable is missing', `Generate a cryptographically secure random string of at least ${minLen} characters (e.g. 'node -e "console.log(crypto.randomBytes(32).toString(\'hex\'))"')`);
      continue;
    }
    if (val.length < minLen) {
      addError(name, `Secret is too short (${val.length} chars; minimum is ${minLen})`, `Generate a random secret of at least ${minLen} characters`);
    }
    const lower = val.toLowerCase();
    if (WEAK_WORDS.some((w) => lower === w || lower.includes(`_${w}`) || lower.includes(`${w}_`))) {
      addError(name, 'Secret contains predictable/weak keywords', 'Generate an unguessable cryptographic random string (avoid dictionary words)');
    }
  }

  // 5. TOTP Encryption Key
  if (!env.TOTP_ENC_KEY) {
    addError('TOTP_ENC_KEY', 'TOTP_ENC_KEY is missing (required for AES-256-GCM vault)', "Generate a 64-character hexadecimal key (32 bytes) with 'node -e \"console.log(crypto.randomBytes(32).toString(\'hex\'))\"'");
  } else if (!/^[0-9a-fA-F]{64}$/.test(env.TOTP_ENC_KEY.trim())) {
    addError('TOTP_ENC_KEY', `Invalid format (${env.TOTP_ENC_KEY.trim().length} chars, must be 64-char hex)`, "Generate a 64-character hex string (32 bytes)");
  }

  // 6. CLIENT_URL & CORS_ORIGINS HTTPS Verification
  if (!env.CLIENT_URL) {
    addError('CLIENT_URL', 'CLIENT_URL is missing', "Set CLIENT_URL to your public HTTPS frontend domain (e.g. 'https://pmt.solarman.in')");
  } else if (!env.CLIENT_URL.trim().startsWith('https://')) {
    addError('CLIENT_URL', `Insecure protocol in '${env.CLIENT_URL}'`, "CLIENT_URL must use 'https://' in production");
  }

  if (!env.CORS_ORIGINS) {
    addError('CORS_ORIGINS', 'CORS_ORIGINS is missing', "Set CORS_ORIGINS to comma-separated HTTPS allowed frontend origins (e.g. 'https://pmt.solarman.in')");
  } else {
    const origins = env.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean);
    for (const origin of origins) {
      if (!origin.startsWith('https://')) {
        addError('CORS_ORIGINS', `Insecure origin '${origin}'`, "All CORS origins must use 'https://' in production");
      }
    }
  }

  // 7. Open Registration & Verification Mode Guard
  const registrationEnabled = env.REGISTRATION_ENABLED !== 'false' && env.REGISTRATION_ENABLED !== '0';
  const verificationMode = (env.VERIFICATION_MODE || 'off').toLowerCase();

  if (registrationEnabled && verificationMode === 'off') {
    warnings.push(
      `Open registration is enabled without email/phone verification (VERIFICATION_MODE=off). Ensure ALLOW_OPEN_REGISTRATION=true is intentional.`
    );
    if (env.ALLOW_OPEN_REGISTRATION !== 'true') {
      addError('ALLOW_OPEN_REGISTRATION', 'Unverified open registration is enabled without explicit acknowledgement', "Set ALLOW_OPEN_REGISTRATION=true or configure VERIFICATION_MODE=otp");
    }
  }

  // 8. Uploads Directory Outside Web Root
  const uploadsDir = path.resolve(env.UPLOADS_DIR || path.join(__dirname, '../../uploads'));
  const publicDir = path.resolve(__dirname, '../../public');
  const clientDist = path.resolve(__dirname, '../../../client/dist');

  if (uploadsDir.startsWith(publicDir) || uploadsDir.startsWith(clientDist)) {
    addError('UPLOADS_DIR', `Uploads path (${uploadsDir}) resides inside public web root`, "Configure UPLOADS_DIR to a private directory outside the document root");
  }

  // 9. Backup Job Configuration
  const backupConfigured = env.BACKUP_JOB_CONFIGURED === 'true' || env.BACKUP_DIR;
  if (!backupConfigured) {
    addError('BACKUP_JOB_CONFIGURED', 'Automated backup job is not confirmed', "Configure daily cron backup ('npm run backup') and set BACKUP_JOB_CONFIGURED=true");
  }

  const errors = issues.map((i) => i.message);
  return { errors, warnings, issues };
}

if (require.main === module) {
  const isJson = process.argv.includes('--json');
  const { errors, warnings, issues } = checkProdEnv(process.env);

  if (isJson) {
    const output = {
      status: errors.length > 0 ? 'failed' : 'passed',
      errorCount: errors.length,
      warningCount: warnings.length,
      issues: issues.map(({ variable, problem, fix }) => ({ variable, problem, fix })),
      warnings
    };
    console.log(JSON.stringify(output, null, 2));
    process.exit(errors.length > 0 ? 1 : 0);
  }

  console.log('====================================================');
  console.log('TaskFlow Production Environment Pre-Flight Hardening');
  console.log('====================================================\n');

  if (warnings.length > 0) {
    console.log('⚠️  WARNINGS (non-blocking):');
    for (const w of warnings) {
      console.warn(`  - ${w}`);
    }
    console.log('');
  }

  if (errors.length > 0) {
    console.error('❌ HARDENING CHECK FAILED: The following criteria must be resolved:\n');
    console.error('--------------------------------------------------------------------------------');
    console.error(
      `${'VARIABLE'.padEnd(24)} | ${'PROBLEM'.padEnd(30)} | ${'HOW TO FIX'}`
    );
    console.error('--------------------------------------------------------------------------------');
    for (const item of issues) {
      console.error(
        `${item.variable.padEnd(24)} | ${item.problem.padEnd(30)} | ${item.fix}`
      );
    }
    console.error('--------------------------------------------------------------------------------\n');
    console.error('Aborting. Correct these environment variables before deploying to production.\n');
    process.exit(1);
  } else {
    console.log('✅ ALL PRODUCTION SECURITY CHECKS PASSED!');
    console.log('Environment is properly hardened for live deployment.\n');
    process.exit(0);
  }
}

module.exports = { checkProdEnv };

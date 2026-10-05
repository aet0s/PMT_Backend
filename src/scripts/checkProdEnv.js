#!/usr/bin/env node
// server/src/scripts/checkProdEnv.js
/**
 * Production Environment Hardening & Pre-Flight Verification Script
 * Validates security requirements, secrets, permissions, and database parameters before production boot.
 */
require('dotenv').config();
const path = require('path');
const fs = require('fs');

function checkProdEnv(env = process.env) {
  const errors = [];
  const warnings = [];

  console.log('====================================================');
  console.log('TaskFlow Production Environment Pre-Flight Hardening');
  console.log('====================================================\n');

  // 1. NODE_ENV Check
  if (env.NODE_ENV !== 'production') {
    errors.push(`[NODE_ENV] NODE_ENV must be set to 'production' (currently: '${env.NODE_ENV || 'undefined'}').`);
  }

  // 2. Dev Flags Check
  if (env.DISABLE_RATE_LIMIT && env.DISABLE_RATE_LIMIT !== 'false' && env.DISABLE_RATE_LIMIT !== '0') {
    errors.push(`[DEV_FLAGS] DISABLE_RATE_LIMIT must NOT be enabled in production.`);
  }
  if (env.DEV_SINGLE_TENANT && env.DEV_SINGLE_TENANT !== 'false' && env.DEV_SINGLE_TENANT !== '0') {
    errors.push(`[DEV_FLAGS] DEV_SINGLE_TENANT must NOT be enabled in production. Production must run multi-tenant.`);
  }

  // 3. Database User Check
  if (env.DB_USER === 'root') {
    errors.push(`[DATABASE] DB_USER cannot be 'root' in production. Use a dedicated restricted MariaDB user.`);
  }

  // 4. Secrets Security Audit
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
      errors.push(`[SECRETS] ${name} is missing.`);
      continue;
    }
    if (val.length < minLen) {
      errors.push(`[SECRETS] ${name} is too short (${val.length} chars). Must be at least ${minLen} characters.`);
    }
    const lower = val.toLowerCase();
    if (WEAK_WORDS.some((w) => lower === w || lower.includes(`_${w}`) || lower.includes(`${w}_`))) {
      errors.push(`[SECRETS] ${name} contains weak/predictable words. Use a cryptographically secure random string.`);
    }
  }

  // 5. TOTP Encryption Key
  if (!env.TOTP_ENC_KEY) {
    errors.push(`[SECRETS] TOTP_ENC_KEY is missing. Required for AES-256-GCM vault encryption.`);
  } else if (!/^[0-9a-fA-F]{64}$/.test(env.TOTP_ENC_KEY.trim())) {
    errors.push(`[SECRETS] TOTP_ENC_KEY must be a 64-character hexadecimal string (32 bytes).`);
  }

  // 6. CLIENT_URL & CORS_ORIGINS HTTPS Verification
  if (!env.CLIENT_URL) {
    errors.push(`[ORIGIN] CLIENT_URL is missing. Must be the public HTTPS frontend origin.`);
  } else if (!env.CLIENT_URL.trim().startsWith('https://')) {
    errors.push(`[ORIGIN] CLIENT_URL must start with 'https://' in production (got: '${env.CLIENT_URL}').`);
  }

  if (!env.CORS_ORIGINS) {
    errors.push(`[ORIGIN] CORS_ORIGINS is missing. Must specify comma-separated HTTPS allowed origins.`);
  } else {
    const origins = env.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean);
    for (const origin of origins) {
      if (!origin.startsWith('https://')) {
        errors.push(`[ORIGIN] CORS origin '${origin}' must use 'https://'. HTTP origins are prohibited in production.`);
      }
    }
  }

  // 7. Open Registration & Verification Mode Guard
  const registrationEnabled = env.REGISTRATION_ENABLED !== 'false' && env.REGISTRATION_ENABLED !== '0';
  const verificationMode = (env.VERIFICATION_MODE || 'off').toLowerCase();

  if (registrationEnabled && verificationMode === 'off') {
    warnings.push(
      `[SECURITY WARNING] Open registration is enabled without email/phone verification (VERIFICATION_MODE=off)!`
    );
    if (env.ALLOW_OPEN_REGISTRATION !== 'true') {
      errors.push(
        `[REGISTRATION] Open unverified registration requires explicit ALLOW_OPEN_REGISTRATION=true in environment to proceed.`
      );
    }
  }

  // 8. Uploads Directory Outside Web Root
  const uploadsDir = path.resolve(env.UPLOADS_DIR || path.join(__dirname, '../../uploads'));
  const publicDir = path.resolve(__dirname, '../../public');
  const clientDist = path.resolve(__dirname, '../../../client/dist');

  if (uploadsDir.startsWith(publicDir) || uploadsDir.startsWith(clientDist)) {
    errors.push(`[STORAGE] Uploads directory (${uploadsDir}) must be outside public web root to prevent direct script execution.`);
  }

  // 9. Backup Job Configuration
  const backupConfigured = env.BACKUP_JOB_CONFIGURED === 'true' || env.BACKUP_DIR;
  if (!backupConfigured) {
    errors.push(
      `[BACKUP] Automated backup job is not configured. Set BACKUP_JOB_CONFIGURED=true after configuring daily cron backup (npm run backup).`
    );
  }

  return { errors, warnings };
}

if (require.main === module) {
  const { errors, warnings } = checkProdEnv(process.env);

  if (warnings.length > 0) {
    console.log('\n⚠️  WARNINGS:');
    for (const w of warnings) {
      console.warn(`  - ${w}`);
    }
  }

  if (errors.length > 0) {
    console.error('\n❌ HARDENING CHECK FAILED: The following security criteria were not met:');
    for (const err of errors) {
      console.error(`  ✖ ${err}`);
    }
    console.error('\nAborting. Correct these environment variables before deploying to production.\n');
    process.exit(1);
  } else {
    console.log('\n✅ ALL PRODUCTION SECURITY CHECKS PASSED!');
    console.log('Environment is properly hardened for live deployment.\n');
    process.exit(0);
  }
}

module.exports = { checkProdEnv };

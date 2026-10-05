// server/src/config/env.js
// Validates environment variables and ensures the server fails fast with clear guidance.

function validateEnv(env = process.env) {
  const errors = [];

  if (!env.MYSQL_HOST) {
    errors.push('MYSQL_HOST is required (e.g. 127.0.0.1)');
  }
  if (!env.MYSQL_USER) {
    errors.push('MYSQL_USER is required (e.g. root)');
  }

  const isDevSingle = env.DEV_SINGLE_TENANT === '1';
  if (isDevSingle) {
    if (!env.MYSQL_DATABASE) {
      errors.push('MYSQL_DATABASE is required when DEV_SINGLE_TENANT=1 (e.g. pm_dev_single)');
    }
  } else {
    if (!env.MYSQL_MASTER_DATABASE) {
      errors.push('MYSQL_MASTER_DATABASE is required for multi-tenant mode (e.g. pm_master)');
    }
    if (!env.MYSQL_TENANT_PREFIX) {
      errors.push('MYSQL_TENANT_PREFIX is required for multi-tenant mode (e.g. pm_t_)');
    }
  }

  if (env.NODE_ENV === 'production') {
    if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) {
      errors.push('JWT_SECRET is required and must be at least 32 characters in production');
    }
  } else {
    if (!env.JWT_SECRET) {
      errors.push('JWT_SECRET is required');
    }
  }

  if (errors.length > 0) {
    const message = `FATAL: Configuration error. Missing or invalid required environment variables:\n  - ${errors.join('\n  - ')}`;
    return { valid: false, errors, message };
  }

  return { valid: true, errors: [], message: 'OK' };
}

function assertEnv(env = process.env) {
  const result = validateEnv(env);
  if (!result.valid) {
    console.error('\n========================================');
    console.error(result.message);
    console.error('Please check your .env file or refer to .env.example.');
    console.error('========================================\n');
    process.exit(1);
  }
}

module.exports = { validateEnv, assertEnv };

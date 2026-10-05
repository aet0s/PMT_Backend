// server/src/test_board_migration.js
// Verification of board background migration (0006) across legacy Tailwind class strings, hex, and unknown values.

const mysql = require('mysql2/promise');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const { runMigrationsOnDb, getDbConfig } = require('./db/migrator');

const VALID_BG_VALUES = new Set([
  'bg-board-neutral',
  'bg-board-mist-blue',
  'bg-board-lavender',
  'bg-board-sage',
  'bg-board-sand',
  'bg-board-blush',
  'bg-board-sky',
  'bg-board-mint',
  'bg-board-stone',
  'bg-board-peach',
  'bg-board-lilac'
]);

const ORIGINAL_12_CLASS_STRINGS = [
  'bg-gradient-to-br from-indigo-900 via-slate-900 to-purple-950',
  'bg-gradient-to-br from-blue-700 via-sky-800 to-indigo-900',
  'bg-gradient-to-br from-emerald-800 via-teal-900 to-slate-900',
  'bg-gradient-to-br from-rose-800 via-purple-900 to-slate-900',
  'bg-gradient-to-br from-amber-700 via-orange-900 to-slate-950',
  'bg-gradient-to-br from-slate-900 via-gray-900 to-zinc-950',
  'bg-gradient-to-br from-indigo-200 via-purple-100 to-violet-200',
  'bg-gradient-to-br from-sky-200 via-blue-100 to-cyan-200',
  'bg-gradient-to-br from-rose-200 via-pink-100 to-fuchsia-200',
  'bg-gradient-to-br from-emerald-200 via-teal-100 to-green-200',
  'bg-gradient-to-br from-amber-200 via-orange-100 to-yellow-200',
  'bg-gradient-to-br from-slate-300 via-blue-200 to-indigo-200'
];

const HEX_AND_OTHER_TEST_VALUES = [
  '#0f172a',
  '#1e1b4b',
  '#3b82f6',
  '#ffffff',
  null,
  '',
  'custom-dark-theme-123'
];

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) {
    console.log(`  ✓ ${msg}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${msg}`);
    failed++;
  }
}

// Emulate client/src/lib/palettes.js getBoardBgClass for render-time fallback test
function getBoardBgClass(bgClass) {
  const DEFAULT_BOARD_BG = 'bg-board-neutral';
  if (!bgClass) return DEFAULT_BOARD_BG;
  return VALID_BG_VALUES.has(bgClass) ? bgClass : DEFAULT_BOARD_BG;
}

async function dropDb(dbName) {
  const conn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || ''
  });
  try {
    await conn.query(`DROP DATABASE IF EXISTS \`${dbName}\``);
  } finally {
    await conn.end();
  }
}

async function setupTenantWithBaseline(dbName) {
  const rootConn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || ''
  });
  try {
    await rootConn.query(`DROP DATABASE IF EXISTS \`${dbName}\``);
    await rootConn.query(`CREATE DATABASE \`${dbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  } finally {
    await rootConn.end();
  }

  const conn = await mysql.createConnection(getDbConfig(dbName));
  try {
    await conn.query(`
      CREATE TABLE schema_migrations (
        version VARCHAR(50) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        checksum VARCHAR(64) NOT NULL,
        applied_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
      );
    `);

    // Run migrations 0001 through 0005 only
    const migrationsDir = path.join(__dirname, 'db', 'migrations', 'tenant');
    const files = ['0001_baseline.sql', '0002_add_must_change_password_to_users.sql', '0003_phase3_auth_sessions_2fa.sql', '0004_add_reset_2fa_permission.sql', '0005_phase4_rbac_system_roles_permissions.sql'];
    for (const f of files) {
      const sql = fs.readFileSync(path.join(migrationsDir, f), 'utf8');
      await conn.query(sql);
      const checksum = crypto.createHash('sha256').update(sql).digest('hex');
      const version = f.split('_')[0];
      await conn.query(
        'INSERT INTO schema_migrations (version, name, checksum) VALUES (?, ?, ?)',
        [version, f, checksum]
      );
    }

    // Insert dummy user and workspace
    const [userRes] = await conn.query(`
      INSERT INTO users (name, email, password_hash)
      VALUES ('Mig Test User', 'user@migtest.com', 'dummyhash')
    `);
    const userId = userRes.insertId;

    const [wsRes] = await conn.query(`
      INSERT INTO workspaces (name)
      VALUES ('Mig Test Workspace')
    `);
    const workspaceId = wsRes.insertId;

    // Seed all 12 original Tailwind classes + hex + null/empty/unknown
    const allSeedValues = [...ORIGINAL_12_CLASS_STRINGS, ...HEX_AND_OTHER_TEST_VALUES];
    for (let i = 0; i < allSeedValues.length; i++) {
      const val = allSeedValues[i];
      await conn.query(`
        INSERT INTO boards (name, background_color, workspace_id)
        VALUES (?, ?, ?)
      `, [`Test Board ${i + 1}`, val, workspaceId]);
    }
  } finally {
    await conn.end();
  }
}

async function getBoardBackgroundCounts(dbName) {
  const conn = await mysql.createConnection(getDbConfig(dbName));
  try {
    const [rows] = await conn.query(`
      SELECT COALESCE(background_color, 'NULL') AS bg, COUNT(*) AS count
      FROM boards
      GROUP BY background_color
      ORDER BY count DESC
    `);
    return rows;
  } finally {
    await conn.end();
  }
}

async function run() {
  console.log('================================================================');
  console.log('   TEST SUITE: BOARD BACKGROUND MIGRATION & FALLBACK VERIFICATION');
  console.log('================================================================');

  const suffix = Math.random().toString(36).substring(2, 7);
  const tenant1 = `pm_t_bgmig1_${suffix}`;
  const tenant2 = `pm_t_bgmig2_${suffix}`;

  try {
    console.log(`\n[STEP 1] Setting up test tenants (${tenant1}, ${tenant2}) with pre-migration baseline (0001-0005)...`);
    await setupTenantWithBaseline(tenant1);
    await setupTenantWithBaseline(tenant2);

    console.log('\n[STEP 2] BEFORE Migration Counts:');
    for (const t of [tenant1, tenant2]) {
      console.log(`\nTenant: ${t}`);
      const beforeCounts = await getBoardBackgroundCounts(t);
      console.table(beforeCounts);
    }

    console.log('\n[STEP 3] Running migration 0006_map_legacy_board_backgrounds.sql on both tenants...');
    const res1 = await runMigrationsOnDb(tenant1, 'tenant');
    const res2 = await runMigrationsOnDb(tenant2, 'tenant');
    assert(res1.some(m => m.includes('0006')), `Tenant 1 applied migration 0006`);
    assert(res2.some(m => m.includes('0006')), `Tenant 2 applied migration 0006`);

    console.log('\n[STEP 4] AFTER Migration Counts:');
    for (const t of [tenant1, tenant2]) {
      console.log(`\nTenant: ${t}`);
      const afterCounts = await getBoardBackgroundCounts(t);
      console.table(afterCounts);

      // Verify every single board ends on one of the 10 light values or neutral default
      const conn = await mysql.createConnection(getDbConfig(t));
      try {
        const [boards] = await conn.query('SELECT id, name, background_color FROM boards');
        for (const b of boards) {
          assert(
            VALID_BG_VALUES.has(b.background_color),
            `Board "${b.name}" ended on valid light background: "${b.background_color}"`
          );
        }
      } finally {
        await conn.end();
      }
    }

    console.log('\n[STEP 5] Testing Client Render-Time Fallback Logic:');
    assert(getBoardBgClass('bg-board-sage') === 'bg-board-sage', 'Valid light class "bg-board-sage" preserved');
    assert(getBoardBgClass('bg-board-mist-blue') === 'bg-board-mist-blue', 'Valid light class "bg-board-mist-blue" preserved');
    assert(getBoardBgClass('bg-gradient-to-br from-indigo-900') === 'bg-board-neutral', 'Legacy gradient falls back to "bg-board-neutral"');
    assert(getBoardBgClass('#0f172a') === 'bg-board-neutral', 'Legacy dark hex falls back to "bg-board-neutral"');
    assert(getBoardBgClass(null) === 'bg-board-neutral', 'null falls back to "bg-board-neutral"');
    assert(getBoardBgClass(undefined) === 'bg-board-neutral', 'undefined falls back to "bg-board-neutral"');
    assert(getBoardBgClass('') === 'bg-board-neutral', 'Empty string falls back to "bg-board-neutral"');
    assert(getBoardBgClass('unknown-gibberish') === 'bg-board-neutral', 'Unknown string falls back to "bg-board-neutral"');

  } finally {
    console.log('\n[CLEANUP] Cleaning up test databases...');
    await dropDb(tenant1);
    await dropDb(tenant2);
  }

  console.log('\n================================================================');
  console.log(`BOARD MIGRATION TESTS: ${passed} passed, ${failed} failed.`);
  console.log('================================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});

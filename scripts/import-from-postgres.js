// server/scripts/import-from-postgres.js
// Optional one-off data import script from PostgreSQL to MySQL.
// Uses `pg` as a devDependency only.
require('dotenv').config();
const { Pool } = require('pg');
const mysql = require('mysql2/promise');
const { ensureDatabase } = require('../src/db/migrator');

async function importFromPostgres() {
  const args = process.argv.slice(2);
  let tenantName = 'Default Company';
  const tenantNameIdx = args.indexOf('--tenant-name');
  if (tenantNameIdx !== -1 && args[tenantNameIdx + 1]) {
    tenantName = args[tenantNameIdx + 1];
  }

  const pgUrl = process.env.DATABASE_URL || 'postgresql://postgres@localhost:5432/trello_pm';
  const targetDb = process.env.MYSQL_DATABASE || 'pm_dev_single';

  console.log(`Starting optional migration from Postgres (${pgUrl}) to MySQL (${targetDb}) for tenant "${tenantName}"...`);

  // 1. Test Postgres connectivity
  let pgPool;
  try {
    pgPool = new Pool({ connectionString: pgUrl, connectionTimeoutMillis: 3000 });
    const test = await pgPool.query('SELECT 1 as ok');
    if (!test.rows[0]?.ok) throw new Error('Could not query Postgres');
    console.log('✓ Connected to PostgreSQL');
  } catch (err) {
    console.warn(`PostgreSQL is not reachable (${err.message}). Skipping import script (optional).`);
    if (pgPool) await pgPool.end();
    return;
  }

  // 2. Connect to MySQL target database
  await ensureDatabase(targetDb);
  const mysqlConn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || '',
    database: targetDb,
    multipleStatements: true,
    timezone: '+00:00',
    charset: 'utf8mb4'
  });

  console.log('✓ Connected to MySQL/MariaDB');

  const stats = [];

  try {
    await mysqlConn.query('SET FOREIGN_KEY_CHECKS = 0');

    // List of tables to migrate in sequence
    const tables = [
      'users',
      'workspaces',
      'permissions',
      'roles',
      'role_permissions',
      'workspace_members',
      'boards',
      'board_members',
      'lists',
      'cards',
      'labels',
      'card_labels',
      'card_members',
      'checklists',
      'checklist_items',
      'comments',
      'attachments',
      'activity_log',
      'notifications',
      'notification_preferences',
      'pending_invitations'
    ];

    for (const table of tables) {
      // Check if table exists in PG
      const pgExists = await pgPool.query(
        `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1)`,
        [table]
      );
      if (!pgExists.rows[0]?.exists) {
        continue;
      }

      const pgRowsRes = await pgPool.query(`SELECT * FROM ${table}`);
      const pgRows = pgRowsRes.rows;

      if (pgRows.length === 0) {
        stats.push({ table, pgCount: 0, mysqlCount: 0 });
        continue;
      }

      // Truncate target table
      await mysqlConn.query(`TRUNCATE TABLE ${table}`);

      if (table === 'pending_invitations') {
        // Special mapping for board_ids array -> invitation_boards
        await mysqlConn.query('TRUNCATE TABLE invitation_boards');
        for (const row of pgRows) {
          await mysqlConn.execute(
            `INSERT INTO pending_invitations (id, email, workspace_id, invited_by_user_id, token, status, created_at, accepted_at, accepted_by_user_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              row.id,
              row.email,
              row.workspace_id,
              row.invited_by_user_id,
              row.token,
              row.status || 'pending',
              row.created_at,
              row.accepted_at,
              row.accepted_by_user_id
            ]
          );

          if (Array.isArray(row.board_ids)) {
            for (const bId of row.board_ids) {
              await mysqlConn.execute(
                'INSERT IGNORE INTO invitation_boards (invitation_id, board_id) VALUES (?, ?)',
                [row.id, bId]
              );
            }
          }
        }
      } else {
        const columns = Object.keys(pgRows[0]);
        const placeholders = columns.map(() => '?').join(', ');
        const colList = columns.map((c) => `\`${c}\``).join(', ');

        for (const row of pgRows) {
          const values = columns.map((col) => {
            const val = row[col];
            if (typeof val === 'boolean') return val ? 1 : 0;
            if (typeof val === 'object' && val !== null && !(val instanceof Date)) {
              return JSON.stringify(val);
            }
            return val;
          });

          await mysqlConn.execute(
            `INSERT INTO \`${table}\` (${colList}) VALUES (${placeholders})`,
            values
          );
        }
      }

      const [mCount] = await mysqlConn.query(`SELECT COUNT(*) as count FROM \`${table}\``);
      stats.push({ table, pgCount: pgRows.length, mysqlCount: Number(mCount[0].count) });
    }

    await mysqlConn.query('SET FOREIGN_KEY_CHECKS = 1');

    console.log('\n--- Row Count Verification ---');
    console.table(stats);
    console.log('✓ Data import from PostgreSQL completed successfully!');
  } finally {
    await pgPool.end();
    await mysqlConn.end();
  }
}

if (require.main === module) {
  importFromPostgres().catch((err) => {
    console.error('Import error:', err);
    process.exit(1);
  });
}

module.exports = importFromPostgres;

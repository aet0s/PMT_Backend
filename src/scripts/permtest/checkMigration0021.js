const mysql = require('mysql2/promise');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env') });

async function checkMigrations() {
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    port: process.env.DB_PORT || 3306
  });

  const [dbs] = await conn.query("SHOW DATABASES LIKE 'pm_t_%'");
  let appliedCount = 0;
  let unappliedCount = 0;
  const appliedDbs = [];
  const unappliedDbs = [];

  for (const r of dbs) {
    const dbName = Object.values(r)[0];
    try {
      const [rows] = await conn.query("SELECT * FROM `" + dbName + "`._migrations WHERE name LIKE '%0021%'");
      if (rows.length > 0) {
        appliedCount++;
        appliedDbs.push(dbName);
      } else {
        unappliedCount++;
        unappliedDbs.push(dbName);
      }
    } catch(e) {
      unappliedCount++;
      unappliedDbs.push(dbName);
    }
  }

  console.log(`Migration 0021 Applied in: ${appliedCount} databases.`);
  console.log('Applied DBs:', appliedDbs);
  console.log(`Migration 0021 NOT applied in: ${unappliedCount} databases.`);
  console.log('Not Applied DBs:', unappliedDbs);
  await conn.end();
}

checkMigrations().catch(console.error);

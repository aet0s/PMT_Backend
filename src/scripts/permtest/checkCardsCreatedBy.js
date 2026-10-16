const mysql = require('mysql2/promise');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env') });

async function check() {
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    port: process.env.DB_PORT || 3306
  });

  const [dbs] = await conn.query("SHOW DATABASES LIKE 'pm_t_%'");
  console.log('Found ' + dbs.length + ' tenant databases.');
  let totalCards = 0;
  let totalNull = 0;

  for (const r of dbs) {
    const dbName = Object.values(r)[0];
    const [cols] = await conn.query(
      "SELECT COUNT(*) as c FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'cards' AND COLUMN_NAME = 'created_by'",
      [dbName]
    );
    if (cols[0].c > 0) {
      const [counts] = await conn.query(
        `SELECT COUNT(*) as total, SUM(CASE WHEN created_by IS NULL THEN 1 ELSE 0 END) as null_count FROM \`${dbName}\`.cards`
      );
      const total = Number(counts[0].total);
      const nulls = Number(counts[0].null_count || 0);
      if (total > 0) {
        console.log(`DB: ${dbName} -> total: ${total}, null: ${nulls}`);
      }
      totalCards += total;
      totalNull += nulls;
    } else {
      console.log(`DB: ${dbName} -> NO created_by column!`);
    }
  }

  console.log(`SUMMARY: Total cards: ${totalCards}, Total NULL created_by: ${totalNull}`);
  await conn.end();
}

check().catch(console.error);

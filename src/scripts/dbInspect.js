// server/src/scripts/dbInspect.js
const mysql = require('mysql2/promise');
require('dotenv').config();

async function inspect() {
  const conn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || ''
  });

  const [dbs] = await conn.query("SHOW DATABASES LIKE 'pm_%'");
  console.log('=== MariaDB Databases Matching pm_% ===');
  console.table(dbs);

  const getTableCounts = async (dbName) => {
    const [tables] = await conn.query(`SHOW TABLES FROM \`${dbName}\``);
    if (!tables.length) return [];
    const key = Object.keys(tables[0])[0];
    const results = [];
    for (const t of tables) {
      const tableName = t[key];
      const [[cnt]] = await conn.query(`SELECT COUNT(*) as c FROM \`${dbName}\`.\`${tableName}\``);
      results.push({ table: tableName, rows: cnt.c });
    }
    return results;
  };

  try {
    console.log('\n=== Table Row Counts: pm_t_alpha_corp ===');
    console.table(await getTableCounts('pm_t_alpha_corp'));
  } catch (e) {
    console.log('pm_t_alpha_corp not found or error:', e.message);
  }

  try {
    console.log('\n=== Table Row Counts: pm_t_beta_llc ===');
    console.table(await getTableCounts('pm_t_beta_llc'));
  } catch (e) {
    console.log('pm_t_beta_llc not found or error:', e.message);
  }

  try {
    console.log('\n=== Table Row Counts: pm_master ===');
    console.table(await getTableCounts('pm_master'));
  } catch (e) {
    console.log('pm_master not found or error:', e.message);
  }

  await conn.end();
}

inspect().catch(console.error);

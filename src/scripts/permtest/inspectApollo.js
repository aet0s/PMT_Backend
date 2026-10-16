const mysql = require('mysql2/promise');
require('dotenv').config({ path: require('path').resolve(__dirname, '../../../../.env') });

async function inspect() {
  const conn = await mysql.createConnection({
    host: '127.0.0.1',
    user: 'root',
    password: '',
  });

  const [tables] = await conn.query('SHOW TABLES FROM `pm_t_apollo_82816566`');
  console.log('Tables in Apollo:', tables.map(t => Object.values(t)[0]));

  const [roles] = await conn.query('SELECT * FROM `pm_t_apollo_82816566`.roles');
  console.log('Roles in Apollo:', roles);

  const [cardCols] = await conn.query('SHOW COLUMNS FROM `pm_t_apollo_82816566`.cards');
  console.log('Columns in Apollo cards:', cardCols.map(c => c.Field));

  const [cards] = await conn.query('SELECT COUNT(*) as c FROM `pm_t_apollo_82816566`.cards');
  console.log('Card count in Apollo:', cards[0].c);

  await conn.end();
}

inspect().catch(console.error);

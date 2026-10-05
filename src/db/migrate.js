const fs = require('fs');
const path = require('path');
const db = require('./index');

async function migrate() {
  try {
    console.log('Starting database migration...');
    const sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
    await db.query(sql);
    console.log('Migration completed successfully!');
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  } finally {
    await db.pool.end();
  }
}

if (require.main === module) {
  migrate();
}

module.exports = migrate;

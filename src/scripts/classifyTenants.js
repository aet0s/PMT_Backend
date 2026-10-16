// server/src/scripts/classifyTenants.js
const mysql = require('mysql2/promise');
require('dotenv').config();

async function runClassification() {
  const masterDb = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: 'pm_master'
  });

  const [tenants] = await masterDb.execute(
    'SELECT id, name, slug, db_name, status, created_at FROM tenants ORDER BY id ASC'
  );

  console.log(`Auditing and Classifying ${tenants.length} Tenants:\n`);

  const results = [];

  for (const t of tenants) {
    let classification = 'TEST';
    // Real tenants are the primary business/customer production tenants (apollo, solarman, titan)
    // Automated test fixtures/corporations are verify_corp_*, and persistent test environments are solarman_* / titan_*
    const isReal = ['apollo', 'solarman', 'titan'].includes(t.slug);
    classification = isReal ? 'REAL' : 'TEST';

    let conn;
    let userCount = 0;
    let wsCount = 0;
    let cardCount = 0;
    let customRoleCount = 0;
    let customRoles = [];
    let cardsWithNullCreatedBy = 0;
    let cardsWithCreatedBy = 0;

    try {
      conn = await mysql.createConnection({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: t.db_name
      });

      const [users] = await conn.execute('SELECT COUNT(*) as c FROM users');
      userCount = users[0].c;

      const [workspaces] = await conn.execute('SELECT COUNT(*) as c FROM workspaces');
      wsCount = workspaces[0].c;

      const [cards] = await conn.execute('SELECT COUNT(*) as c FROM cards');
      cardCount = cards[0].c;

      // Check created_by in cards
      const [colCheck] = await conn.execute(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_schema = ? AND table_name = 'cards' AND column_name = 'created_by'
      `, [t.db_name]);

      if (colCheck.length > 0) {
        const [nullCards] = await conn.execute('SELECT COUNT(*) as c FROM cards WHERE created_by IS NULL');
        cardsWithNullCreatedBy = nullCards[0].c;
        const [hasCards] = await conn.execute('SELECT COUNT(*) as c FROM cards WHERE created_by IS NOT NULL');
        cardsWithCreatedBy = hasCards[0].c;
      }

      // Check custom roles
      const [roles] = await conn.execute(`
        SELECT r.id, r.name, r.rank, r.workspace_id, COUNT(rp.permission_id) as perm_count
        FROM roles r
        LEFT JOIN role_permissions rp ON rp.role_id = r.id
        WHERE r.is_system = 0
        GROUP BY r.id, r.name, r.rank, r.workspace_id
      `);
      customRoleCount = roles.length;
      customRoles = roles;
    } catch (err) {
      console.error(`Error querying tenant ${t.slug} (${t.db_name}):`, err.message);
    } finally {
      if (conn) await conn.end();
    }

    results.push({
      id: t.id,
      name: t.name,
      slug: t.slug,
      db_name: t.db_name,
      classification,
      userCount,
      wsCount,
      cardCount,
      cardsWithCreatedBy,
      cardsWithNullCreatedBy,
      customRoleCount,
      customRoles
    });
  }

  await masterDb.end();

  // Print Summary Table
  console.log('| ID | Slug | Database | Name | Classification | Users | Workspaces | Cards | Custom Roles | Cards (created_by NULL) |');
  console.log('|---|---|---|---|---|---|---|---|---|---|');
  for (const r of results) {
    console.log(`| ${r.id} | \`${r.slug}\` | \`${r.db_name}\` | ${r.name} | **${r.classification}** | ${r.userCount} | ${r.wsCount} | ${r.cardCount} | ${r.customRoleCount} | ${r.cardsWithNullCreatedBy} |`);
  }

  const realTenants = results.filter(r => r.classification === 'REAL');
  const testTenants = results.filter(r => r.classification === 'TEST');

  console.log('\n================================================================');
  console.log('                 CLASSIFICATION AGGREGATE AUDIT                 ');
  console.log('================================================================');
  console.log(`Total Tenants: ${results.length}`);
  console.log(`  - REAL Tenants (${realTenants.length}): ${realTenants.map(t => t.slug).join(', ')}`);
  console.log(`  - TEST Tenants (${testTenants.length}): ${testTenants.map(t => t.slug).join(', ')}`);

  console.log('\n--- REAL TENANTS AUDIT ---');
  for (const t of realTenants) {
    console.log(`Tenant "${t.slug}" (${t.name}):`);
    console.log(`  Cards total: ${t.cardCount} (with created_by: ${t.cardsWithCreatedBy}, NULL: ${t.cardsWithNullCreatedBy})`);
    console.log(`  Custom roles: ${t.customRoleCount}`);
    if (t.customRoles.length > 0) {
      for (const cr of t.customRoles) {
        console.log(`    - Custom Role ID ${cr.id}: "${cr.name}" (Rank: ${cr.rank}, Grants: ${cr.perm_count})`);
      }
    } else {
      console.log('    (None - 0 custom roles)');
    }
  }

  console.log('\n--- TEST TENANTS AUDIT ---');
  const testCustomRolesCount = testTenants.reduce((sum, t) => sum + t.customRoleCount, 0);
  const testCardsCount = testTenants.reduce((sum, t) => sum + t.cardCount, 0);
  console.log(`Test tenants total cards: ${testCardsCount}`);
  console.log(`Test tenants total custom roles: ${testCustomRolesCount}`);
  for (const t of testTenants.filter(t => t.customRoleCount > 0)) {
    console.log(`  Tenant "${t.slug}" custom roles (${t.customRoleCount}):`);
    for (const cr of t.customRoles) {
      console.log(`    - Custom Role ID ${cr.id}: "${cr.name}" (Rank: ${cr.rank}, Grants: ${cr.perm_count})`);
    }
  }

  return { results, realTenants, testTenants };
}

if (require.main === module) {
  runClassification().catch(err => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { runClassification };

// server/src/scripts/permtest/tenantReconciliation.js
require('dotenv').config({ path: require('path').resolve(__dirname, '../../../../.env') });
const mysql = require('mysql2/promise');

async function main() {
  const dbConfig = {
    host: process.env.MYSQL_HOST || process.env.DB_HOST || '127.0.0.1',
    port: process.env.MYSQL_PORT ? parseInt(process.env.MYSQL_PORT, 10) : 3306,
    user: process.env.MYSQL_USER || process.env.DB_USER || 'root',
    password: process.env.MYSQL_PASSWORD || process.env.DB_PASSWORD || '',
  };

  const connection = await mysql.createConnection(dbConfig);

  console.log('================================================================');
  console.log('              ITEM 1: TENANT STATE RECONCILIATION              ');
  console.log('================================================================\n');

  // 1. List all databases
  const [dbs] = await connection.query('SHOW DATABASES');
  const allDbNames = dbs.map(d => Object.values(d)[0]);

  // Fetch tenants from masterDb
  const [masterTenantRows] = await connection.query('SELECT id, slug, db_name, status, created_at FROM pm_master.tenants');
  const tenantMapByDb = new Map();
  masterTenantRows.forEach(t => tenantMapByDb.set(t.db_name, t));

  const realDbs = [];
  const testDbs = [];
  const cloneDbs = [];
  const systemDbs = [];

  for (const name of allDbNames) {
    if (name === 'pm_master' || ['information_schema', 'mysql', 'performance_schema', 'sys'].includes(name)) {
      systemDbs.push(name);
    } else if (name.startsWith('permtest_clone_')) {
      cloneDbs.push(name);
    } else if (name.startsWith('pm_t_permtest_') || name.startsWith('pm_t_test_')) {
      testDbs.push(name);
    } else if (name.startsWith('pm_t_')) {
      realDbs.push(name);
    } else {
      systemDbs.push(name);
    }
  }

  console.log(`Total databases found: ${allDbNames.length}`);
  console.log(`- Real tenant DBs: ${realDbs.length}`);
  console.log(`- Test DBs (pm_t_permtest_*): ${testDbs.length}`);
  console.log(`- Clone DBs (permtest_clone_*): ${cloneDbs.length}`);
  console.log(`- System/Master DBs: ${systemDbs.length}\n`);

  console.log('REAL TENANT DATABASES:');
  realDbs.forEach(d => console.log(`  - ${d} (slug: ${tenantMapByDb.get(d)?.slug || 'not in master'})`));

  // Drop any remaining test/clone databases
  if (testDbs.length > 0 || cloneDbs.length > 0) {
    console.log('\n--- Cleaning up test/clone databases ---');
    for (const d of [...testDbs, ...cloneDbs]) {
      const t = tenantMapByDb.get(d);
      if (t) {
        await connection.query('DELETE FROM pm_master.tenants WHERE id = ?', [t.id]);
        await connection.query('DELETE FROM pm_master.tenant_user_directory WHERE tenant_id = ?', [t.id]);
      }
      await connection.query(`DROP DATABASE \`${d}\``);
      console.log(`✓ Dropped: ${d}`);
    }
  } else {
    console.log('\n✓ Zero leaked test/clone databases present.');
  }

  // 2. Reconcile REAL tenants using schema_migrations
  console.log('\n================================================================');
  console.log('         REAL TENANTS: MIGRATION & SCHEMA AUDIT (0021)          ');
  console.log('================================================================');

  const reconciliationReport = [];

  for (const dbName of realDbs) {
    const tenantMeta = tenantMapByDb.get(dbName);
    const reportItem = {
      dbName,
      slug: tenantMeta?.slug || 'unknown',
      migration0021Applied: false,
      appliedAt0021: null,
      hasTeamLead: false,
      hasAuditor: false,
      hasCardsCreatedBy: false,
      totalCards: 0,
      cardsBackfilled: 0,
      cardsNull: 0
    };

    try {
      // Check schema_migrations table
      const [migRows] = await connection.query(`
        SELECT name, applied_at FROM \`${dbName}\`.schema_migrations WHERE name LIKE '%0021%'
      `);
      if (migRows.length > 0) {
        reportItem.migration0021Applied = true;
        reportItem.appliedAt0021 = migRows[0].applied_at;
      }

      // Check roles table for Team Lead and Auditor
      const [roleRows] = await connection.query(`
        SELECT id, name, is_system, rank FROM \`${dbName}\`.roles WHERE name IN ('Team Lead', 'Auditor')
      `);
      reportItem.hasTeamLead = roleRows.some(r => r.name === 'Team Lead');
      reportItem.hasAuditor = roleRows.some(r => r.name === 'Auditor');
      reportItem.roleDetails = roleRows;

      // Check cards table for created_by column
      const [colRows] = await connection.query(`
        SHOW COLUMNS FROM \`${dbName}\`.cards LIKE 'created_by'
      `);
      reportItem.hasCardsCreatedBy = colRows.length > 0;

      if (reportItem.hasCardsCreatedBy) {
        const [cardStats] = await connection.query(`
          SELECT 
            COUNT(*) as total,
            COUNT(created_by) as populated,
            SUM(CASE WHEN created_by IS NULL THEN 1 ELSE 0 END) as null_count
          FROM \`${dbName}\`.cards
        `);
        reportItem.totalCards = Number(cardStats[0].total);
        reportItem.cardsBackfilled = Number(cardStats[0].populated);
        reportItem.cardsNull = Number(cardStats[0].null_count || 0);
      }
    } catch (err) {
      reportItem.error = err.message;
    }

    reconciliationReport.push(reportItem);
  }

  console.table(reconciliationReport.map(r => ({
    slug: r.slug,
    db: r.dbName,
    mig0021: r.migration0021Applied,
    appliedAt: r.appliedAt0021 ? r.appliedAt0021.toISOString() : 'N/A',
    TeamLead: r.hasTeamLead,
    Auditor: r.hasAuditor,
    has_created_by: r.hasCardsCreatedBy,
    totalCards: r.totalCards,
    populated: r.cardsBackfilled,
    nulls: r.cardsNull
  })));

  // 3. Activity_log correlation sample for 10 cards across real tenants
  console.log('\n================================================================');
  console.log('         SAMPLE 10 REAL CARDS WITH ACTIVITY_LOG CORRELATION    ');
  console.log('================================================================');

  let samplesFound = 0;
  for (const r of reconciliationReport) {
    if (r.totalCards > 0 && samplesFound < 10) {
      const [cards] = await connection.query(`
        SELECT c.id as card_id, c.title, c.created_by, c.created_at,
               a.id as activity_id, a.action_type, a.user_id as act_user_id, a.created_at as act_created_at
        FROM \`${r.dbName}\`.cards c
        LEFT JOIN \`${r.dbName}\`.activity_log a ON a.card_id = c.id AND a.action_type = 'created_card'
        ORDER BY c.id ASC
        LIMIT ${10 - samplesFound}
      `);

      for (const card of cards) {
        samplesFound++;
        console.log(`[Sample ${samplesFound}] Tenant: ${r.slug} (${r.dbName})`);
        console.log(`  Card ID: ${card.card_id} | Title: "${card.title}"`);
        console.log(`  Card created_by: ${card.created_by} | created_at: ${card.created_at}`);
        console.log(`  Activity Log row: id=${card.activity_id || 'NONE'}, action=${card.action_type || 'NONE'}, user_id=${card.act_user_id || 'NONE'}, created_at=${card.act_created_at || 'NONE'}`);
        console.log(`  Attribution Match: ${card.created_by === card.act_user_id ? 'EXACT MATCH WITH activity_log' : (card.created_by === null ? 'NULL (No activity row)' : 'OTHER')}`);
        console.log('----------------------------------------------------------------');
      }
    }
  }

  if (samplesFound === 0) {
    console.log('No cards found across real tenants to sample.');
  }

  await connection.end();
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});

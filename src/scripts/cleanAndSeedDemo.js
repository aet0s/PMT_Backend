// server/src/scripts/cleanAndSeedDemo.js
// Completely cleans local databases and sets up a rich Demo account with all 8 RBAC roles.

require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { migrateMaster, migrateSingleTenant } = require('../db/migrator');
const { syncPermissionCatalog } = require('../rbac/catalogSync');
const { closeAllPools } = require('../services/tenantPools');

const DEMO_PASSWORD = 'Password123!';
const DEMO_COMPANY_NAME = 'Demo Technologies';
const DEMO_SLUG = 'demo';
const DEMO_TENANT_DB = 'pm_t_demo';

const DEMO_ROLES = [
  { role: 'Owner', email: 'owner@demo.com', name: 'Olivia Owner' },
  { role: 'Admin', email: 'admin@demo.com', name: 'Arthur Admin' },
  { role: 'Project Manager', email: 'pm@demo.com', name: 'Pamela ProjectManager' },
  { role: 'Team Lead', email: 'teamlead@demo.com', name: 'Leo TeamLead' },
  { role: 'Team Member', email: 'member@demo.com', name: 'Miles Member' },
  { role: 'Team Member', email: 'member2@demo.com', name: 'Sarah Developer' },
  { role: 'Viewer', email: 'viewer@demo.com', name: 'Victor Viewer' },
  { role: 'Auditor', email: 'auditor@demo.com', name: 'Audrey Auditor' },
  { role: 'Guest', email: 'guest@demo.com', name: 'Grace Guest' }
];

async function cleanAndSeedDemo() {
  console.log('================================================================');
  console.log('       CLEANING LOCAL DATABASES & SEEDING DEMO ACCOUNT          ');
  console.log('================================================================');

  const rootConn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || ''
  });

  try {
    // -------------------------------------------------------------
    // STEP 1: DROP ALL TEST & TENANT DATABASES
    // -------------------------------------------------------------
    console.log('\n[1/6] Scanning and dropping all orphaned tenant databases...');
    const [allDbs] = await rootConn.query('SHOW DATABASES');
    const dbNames = allDbs.map((r) => Object.values(r)[0]);
    const tenantDbs = dbNames.filter(
      (name) => name.startsWith('pm_t_') || name.startsWith('pm_test_')
    );

    for (const tDb of tenantDbs) {
      await rootConn.query(`DROP DATABASE IF EXISTS \`${tDb}\``);
    }
    console.log(`✓ Dropped ${tenantDbs.length} tenant databases.`);

    // -------------------------------------------------------------
    // STEP 2: RECREATE MASTER AND DEV_SINGLE DATABASES
    // -------------------------------------------------------------
    const masterDbName = process.env.MYSQL_MASTER_DATABASE || 'pm_master';
    const devDbName = process.env.MYSQL_DATABASE || 'pm_dev_single';

    console.log(`\n[2/6] Resetting '${masterDbName}' and '${devDbName}'...`);
    await rootConn.query(`DROP DATABASE IF EXISTS \`${masterDbName}\``);
    await rootConn.query(`CREATE DATABASE \`${masterDbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);

    await rootConn.query(`DROP DATABASE IF EXISTS \`${devDbName}\``);
    await rootConn.query(`CREATE DATABASE \`${devDbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);

    // Create demo tenant database
    await rootConn.query(`DROP DATABASE IF EXISTS \`${DEMO_TENANT_DB}\``);
    await rootConn.query(`CREATE DATABASE \`${DEMO_TENANT_DB}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    console.log(`✓ Databases '${masterDbName}', '${devDbName}', and '${DEMO_TENANT_DB}' recreated.`);

    // -------------------------------------------------------------
    // STEP 3: RUN MIGRATIONS
    // -------------------------------------------------------------
    console.log('\n[3/6] Running migrations on master and tenant databases...');
    await migrateMaster();
    await migrateSingleTenant(DEMO_TENANT_DB);
    await migrateSingleTenant(devDbName);
    console.log('✓ All database schemas migrated successfully.');

    // Ensure password_resets on master
    await rootConn.query(`
      CREATE TABLE IF NOT EXISTS \`${masterDbName}\`.password_resets (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        otp_code VARCHAR(20) NOT NULL,
        otp_hash VARCHAR(255) NOT NULL,
        reset_token VARCHAR(500) NULL,
        attempts INT NOT NULL DEFAULT 0,
        verified TINYINT(1) NOT NULL DEFAULT 0,
        expires_at DATETIME(3) NOT NULL,
        created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
        INDEX idx_pr_email (email),
        INDEX idx_pr_expires (expires_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // -------------------------------------------------------------
    // STEP 4: REGISTER DEMO TENANT IN MASTER
    // -------------------------------------------------------------
    console.log('\n[4/6] Registering demo company in master database...');
    const masterConn = await mysql.createConnection({
      host: process.env.MYSQL_HOST || '127.0.0.1',
      port: Number(process.env.MYSQL_PORT || 3306),
      user: process.env.MYSQL_USER || 'root',
      password: process.env.MYSQL_PASSWORD || '',
      database: masterDbName
    });

    const tenantUuid = crypto.randomUUID();
    const [tRes] = await masterConn.execute(
      `INSERT INTO tenants (uuid, slug, name, db_name, status, plan, owner_email, created_at)
       VALUES (?, ?, ?, ?, 'active', 'enterprise', 'owner@demo.com', NOW())`,
      [tenantUuid, DEMO_SLUG, DEMO_COMPANY_NAME, DEMO_TENANT_DB]
    );
    const tenantId = tRes.insertId;
    console.log(`✓ Tenant '${DEMO_COMPANY_NAME}' (slug: '${DEMO_SLUG}', id: ${tenantId}) registered.`);

    // -------------------------------------------------------------
    // STEP 5: SYNC RBAC PERMISSION CATALOG
    // -------------------------------------------------------------
    console.log('\n[5/6] Synchronizing RBAC permission catalog and role grants in demo tenant...');
    const tenantConn = await mysql.createConnection({
      host: process.env.MYSQL_HOST || '127.0.0.1',
      port: Number(process.env.MYSQL_PORT || 3306),
      user: process.env.MYSQL_USER || 'root',
      password: process.env.MYSQL_PASSWORD || '',
      database: DEMO_TENANT_DB
    });

    // Wrapped db helper for catalog sync
    const tenantDbWrapper = {
      query: (sql, params) => tenantConn.query(sql, params).then(([rows]) => rows),
      execute: (sql, params) => tenantConn.execute(sql, params)
    };
    await syncPermissionCatalog(tenantDbWrapper);
    console.log('✓ Permission catalog & all 8 system roles synced.');

    // -------------------------------------------------------------
    // STEP 6: CREATE ALL ROLE ACCOUNTS & SEED RICH DUMMY DATA
    // -------------------------------------------------------------
    console.log('\n[6/6] Creating role accounts and rich dummy workspaces, boards, lists, cards...');
    const passwordHash = await bcrypt.hash(DEMO_PASSWORD, 10);

    // Fetch roles map
    const [roles] = await tenantConn.query('SELECT id, name, rank FROM roles WHERE workspace_id IS NULL');
    const roleMap = new Map(roles.map((r) => [r.name, r]));

    // Insert user accounts
    const userMap = new Map();
    for (const acc of DEMO_ROLES) {
      const [uRes] = await tenantConn.execute(
        `INSERT INTO users (name, email, password_hash, must_change_password, failed_login_attempts, created_at)
         VALUES (?, ?, ?, 0, 0, NOW())`,
        [acc.name, acc.email, passwordHash]
      );
      const userId = uRes.insertId;
      userMap.set(acc.email, { id: userId, ...acc });

      // Link in master tenant_user_directory for direct login
      await masterConn.execute(
        `INSERT INTO tenant_user_directory (tenant_id, email, created_at) VALUES (?, ?, NOW())`,
        [tenantId, acc.email]
      );
    }
    console.log(`✓ Created ${DEMO_ROLES.length} role-based user accounts with password '${DEMO_PASSWORD}'.`);

    // 1. Create Workspaces
    const ws1Settings = JSON.stringify({
      timezone: 'Asia/Kolkata',
      working_days: [1, 2, 3, 4, 5],
      cutoff_time: '17:00'
    });
    const [ws1Res] = await tenantConn.execute(
      `INSERT INTO workspaces (name, description, settings, is_archived, created_at)
       VALUES (?, ?, ?, 0, DATE_SUB(NOW(), INTERVAL 14 DAY))`,
      ['Core Product & Engineering', 'Primary engineering workspace for flagship web and mobile applications.', ws1Settings]
    );
    const ws1Id = ws1Res.insertId;

    const [ws2Res] = await tenantConn.execute(
      `INSERT INTO workspaces (name, description, settings, is_archived, created_at)
       VALUES (?, ?, ?, 0, DATE_SUB(NOW(), INTERVAL 10 DAY))`,
      ['Marketing & Growth', 'Go-to-market strategies, product launches, and content campaigns.', ws1Settings]
    );
    const ws2Id = ws2Res.insertId;

    const [ws3Res] = await tenantConn.execute(
      `INSERT INTO workspaces (name, description, settings, is_archived, created_at)
       VALUES (?, ?, ?, 1, DATE_SUB(NOW(), INTERVAL 30 DAY))`,
      ['Q2 2026 Archive', 'Archived historical initiatives workspace for testing archive and restore permissions.', ws1Settings]
    );
    const ws3Id = ws3Res.insertId;

    // Assign members to Workspace 1 (all roles)
    for (const acc of DEMO_ROLES) {
      const u = userMap.get(acc.email);
      const r = roleMap.get(acc.role);
      await tenantConn.execute(
        `INSERT INTO workspace_members (workspace_id, user_id, role_id, role, status)
         VALUES (?, ?, ?, ?, 'active')`,
        [ws1Id, u.id, r.id, acc.role]
      );
    }

    // Assign members to Workspace 2 (Owner, Admin, PM, Team Member)
    for (const email of ['owner@demo.com', 'admin@demo.com', 'pm@demo.com', 'member@demo.com']) {
      const u = userMap.get(email);
      const r = roleMap.get(u.role);
      await tenantConn.execute(
        `INSERT INTO workspace_members (workspace_id, user_id, role_id, role, status)
         VALUES (?, ?, ?, ?, 'active')`,
        [ws2Id, u.id, r.id, u.role]
      );
    }

    // 2. Create Boards
    // Board 1: Active Sprint Board (Workspace 1)
    const [b1Res] = await tenantConn.execute(
      `INSERT INTO boards (workspace_id, name, background_color, is_archived, created_at)
       VALUES (?, ?, ?, 0, DATE_SUB(NOW(), INTERVAL 14 DAY))`,
      [ws1Id, 'SaaS Platform v2.0', 'bg-gradient-to-br from-indigo-900 via-slate-900 to-purple-950']
    );
    const b1Id = b1Res.insertId;

    // Board 2: Mobile App Board (Workspace 1)
    const [b2Res] = await tenantConn.execute(
      `INSERT INTO boards (workspace_id, name, background_color, is_archived, created_at)
       VALUES (?, ?, ?, 0, DATE_SUB(NOW(), INTERVAL 8 DAY))`,
      [ws1Id, 'Mobile App Redesign', 'bg-gradient-to-br from-sky-900 via-slate-900 to-emerald-950']
    );
    const b2Id = b2Res.insertId;

    // Board 3: Archived Board (Workspace 1)
    const [b3Res] = await tenantConn.execute(
      `INSERT INTO boards (workspace_id, name, background_color, is_archived, created_at)
       VALUES (?, ?, ?, 1, DATE_SUB(NOW(), INTERVAL 25 DAY))`,
      [ws1Id, 'Legacy API v1 (Archived)', 'bg-slate-900']
    );
    const b3Id = b3Res.insertId;

    // Board 4: Marketing Board (Workspace 2)
    const [b4Res] = await tenantConn.execute(
      `INSERT INTO boards (workspace_id, name, background_color, is_archived, created_at)
       VALUES (?, ?, ?, 0, DATE_SUB(NOW(), INTERVAL 5 DAY))`,
      [ws2Id, 'Q3 Growth Campaign', 'bg-gradient-to-br from-rose-900 via-slate-900 to-amber-950']
    );
    const b4Id = b4Res.insertId;

    // Board Memberships
    // Board 1 has all core team members
    for (const acc of DEMO_ROLES) {
      const u = userMap.get(acc.email);
      const r = roleMap.get(acc.role);
      const bRole = acc.role === 'Owner' || acc.role === 'Admin' ? 'admin' : (acc.role === 'Guest' ? 'viewer' : 'member');
      await tenantConn.execute(
        `INSERT INTO board_members (board_id, user_id, role, role_id) VALUES (?, ?, ?, ?)`,
        [b1Id, u.id, bRole, r.id]
      );
    }

    // Board 2 has Owner, PM, and Member2 (Member1 is deliberately excluded to test board isolation)
    for (const email of ['owner@demo.com', 'admin@demo.com', 'pm@demo.com', 'member2@demo.com']) {
      const u = userMap.get(email);
      const r = roleMap.get(u.role);
      await tenantConn.execute(
        `INSERT INTO board_members (board_id, user_id, role, role_id) VALUES (?, ?, 'member', ?)`,
        [b2Id, u.id, r.id]
      );
    }

    // 3. Create Labels on Board 1
    const labelDefs = [
      ['Feature', '#3b82f6'],
      ['Bug', '#ef4444'],
      ['Design', '#ec4899'],
      ['Backend', '#10b981'],
      ['Frontend', '#8b5cf6'],
      ['Urgent', '#f59e0b'],
      ['DevOps', '#06b6d4'],
      ['Documentation', '#14b8a6']
    ];
    const labelMap = new Map();
    for (const [lName, color] of labelDefs) {
      const [lRes] = await tenantConn.execute(
        `INSERT INTO labels (board_id, name, color) VALUES (?, ?, ?)`,
        [b1Id, lName, color]
      );
      labelMap.set(lName, lRes.insertId);
    }

    // 4. Create Lists on Board 1
    const listDefs = [
      { name: 'Backlog', is_done: 0, wip: 0 },
      { name: 'To Do', is_done: 0, wip: 10 },
      { name: 'In Progress', is_done: 0, wip: 5 },
      { name: 'Review & QA', is_done: 0, wip: 4 },
      { name: 'Done', is_done: 1, wip: 0 }
    ];
    const listMap = new Map();
    let pos = 1000.0;
    for (const ld of listDefs) {
      const [lRes] = await tenantConn.execute(
        `INSERT INTO lists (board_id, name, position, wip_limit_enabled, wip_limit, is_done_list, created_at)
         VALUES (?, ?, ?, ?, ?, ?, DATE_SUB(NOW(), INTERVAL 14 DAY))`,
        [b1Id, ld.name, pos, ld.wip > 0 ? 1 : 0, ld.wip || null, ld.is_done]
      );
      listMap.set(ld.name, lRes.insertId);
      pos += 1000.0;
    }

    // 4b. Lists and Labels on Board 2 (Mobile App Redesign)
    const b2ListMap = new Map();
    for (const ld of listDefs) {
      const [lRes] = await tenantConn.execute(
        `INSERT INTO lists (board_id, name, position, wip_limit_enabled, wip_limit, is_done_list, created_at)
         VALUES (?, ?, ?, 0, ?, ?, DATE_SUB(NOW(), INTERVAL 8 DAY))`,
        [b2Id, ld.name, pos, ld.wip || null, ld.is_done]
      );
      b2ListMap.set(ld.name, lRes.insertId);
      pos += 1000.0;
    }

    const b2LabelMap = new Map();
    for (const [lName, color] of labelDefs.slice(0, 5)) {
      const [lRes] = await tenantConn.execute(
        `INSERT INTO labels (board_id, name, color) VALUES (?, ?, ?)`,
        [b2Id, lName, color]
      );
      b2LabelMap.set(lName, lRes.insertId);
    }

    // 4c. Lists and Labels on Board 4 (Q3 Growth Campaign, Workspace 2)
    const b4ListMap = new Map();
    for (const ld of listDefs) {
      const [lRes] = await tenantConn.execute(
        `INSERT INTO lists (board_id, name, position, wip_limit_enabled, wip_limit, is_done_list, created_at)
         VALUES (?, ?, ?, 0, ?, ?, DATE_SUB(NOW(), INTERVAL 5 DAY))`,
        [b4Id, ld.name, pos, ld.wip || null, ld.is_done]
      );
      b4ListMap.set(ld.name, lRes.insertId);
      pos += 1000.0;
    }

    const b4LabelMap = new Map();
    for (const [lName, color] of [
      ['Campaign', '#f59e0b'],
      ['Design', '#ec4899'],
      ['Content', '#10b981'],
      ['Urgent', '#ef4444'],
      ['Social', '#3b82f6']
    ]) {
      const [lRes] = await tenantConn.execute(
        `INSERT INTO labels (board_id, name, color) VALUES (?, ?, ?)`,
        [b4Id, lName, color]
      );
      b4LabelMap.set(lName, lRes.insertId);
    }

    const uOwner = userMap.get('owner@demo.com');
    const uPm = userMap.get('pm@demo.com');
    const uMember = userMap.get('member@demo.com');
    const uMember2 = userMap.get('member2@demo.com');

    // 5. Create Rich Cards on Board 1
    const cardTemplates = [
      {
        list: 'In Progress',
        title: 'Implement OAuth2 & SSO Authentication Flow',
        description: `<h2>Objective</h2><p>Provide enterprise Single Sign-On (SSO) via Google Workspace, GitHub, and SAML 2.0.</p><h3>Key Deliverables</h3><ul><li>JWT session rotation with cryptographic refresh tokens</li><li>Rate-limited OAuth callback endpoints</li><li>Audit log trail for security and login compliance</li></ul>`,
        assigners: [uOwner.id],
        members: [uMember.id, uMember2.id],
        labels: ['Feature', 'Security', 'Backend'],
        createdDaysAgo: 3,
        daysInProgress: 2,
        checklists: [
          {
            title: 'SSO Implementation',
            items: [
              { text: 'Configure Google OAuth Client ID & Secret', done: 1 },
              { text: 'Implement session cookie rotation', done: 1 },
              { text: 'Add CSRF token validation', done: 0 },
              { text: 'Write end-to-end integration tests', done: 0 }
            ]
          }
        ],
        comments: [
          { user: uOwner, text: 'Ensure the refresh token is strictly invalid after session revocation.' },
          { user: uMember, text: 'Implemented token blacklist and rotation window. Working smoothly in staging.' }
        ],
        checkins: [
          {
            user: uMember,
            workDate: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().slice(0, 10),
            createdAgoMinutes: 1440,
            did: 'Constructed the OAuth2 provider authorization handler and token generator logic for Google and GitHub logins.',
            next_step: 'Wire cookie rotation and store cryptographic token hashes in sessions table.',
            progress_pct: 40,
            status: 'on_track'
          },
          {
            user: uMember,
            workDate: new Date().toISOString().slice(0, 10),
            createdAgoMinutes: 120,
            did: 'Completed refresh token rotation endpoints and verified seamless session migration without forcing re-login.',
            next_step: 'Finalize SAML XML response parser and write unit test coverage.',
            progress_pct: 80,
            status: 'on_track'
          }
        ]
      },
      {
        list: 'In Progress',
        title: 'Payment Gateway Webhook Deduplication Lock',
        description: `<p>Ensure incoming payment processor webhook events are handled strictly once using distributed database locks to avoid duplicate customer charges.</p>`,
        assigners: [uPm.id],
        members: [uMember2.id],
        labels: ['Bug', 'Urgent', 'Backend'],
        createdDaysAgo: 2,
        daysInProgress: 1,
        checkins: [
          {
            user: uMember2,
            workDate: new Date().toISOString().slice(0, 10),
            createdAgoMinutes: 60,
            did: 'Investigated duplicate webhook dispatch traces and identified missing idempotency key constraint on charges ledger.',
            next_step: 'Apply unique index and implement advisory lock mechanism.',
            progress_pct: 50,
            status: 'blocked',
            blocker: 'Awaiting updated webhook sandbox credentials and test credit card numbers from finance department.'
          }
        ]
      },
      {
        list: 'To Do',
        title: 'Design System Dark Mode Color Palette Tokens',
        description: `<h3>Requirements</h3><p>Refactor all core color tokens to meet WCAG AAA contrast ratios in both light and dark themes.</p><ul><li>Contrast ratio >= 7:1 for body copy</li><li>Surface layers with subtle 2xs border separation</li><li>Accents in indigo, emerald, and amber</li></ul>`,
        assigners: [uPm.id],
        members: [uMember.id],
        labels: ['Design', 'Frontend'],
        createdDaysAgo: 1,
        checklists: [
          {
            title: 'Design Tasks',
            items: [
              { text: 'Audit existing text-muted contrast ratios', done: 0 },
              { text: 'Generate CSS variable token mappings', done: 0 },
              { text: 'Verify modal and card surfaces in dark mode', done: 0 }
            ]
          }
        ]
      },
      {
        list: 'Review & QA',
        title: 'Optimize MySQL Query Execution on Daily Tracker',
        description: `<p>Composite indexes on <code>(card_id, work_date)</code> and <code>(user_id, work_date)</code> reduced Daily Tracker query latency from 180ms to 4ms.</p>`,
        assigners: [uOwner.id],
        members: [uMember2.id],
        labels: ['Backend', 'DevOps'],
        createdDaysAgo: 4,
        checklists: [
          {
            title: 'Validation',
            items: [
              { text: 'Run EXPLAIN on multi-table JOINs', done: 1 },
              { text: 'Verify MariaDB query planner index scan', done: 1 },
              { text: 'Load test with 500 cards in progress', done: 1 }
            ]
          }
        ]
      },
      {
        list: 'Done',
        title: 'Setup Automated Daily Database Backups & Checksums',
        description: `<p>Configured automated mysqldump backup routines with SHA-256 integrity verification and automated S3 syncing.</p>`,
        assigners: [uOwner.id],
        members: [uMember.id],
        labels: ['DevOps', 'Security'],
        createdDaysAgo: 7,
        isComplete: true,
        completionNote: 'Tested automated backup and simulated a successful restoration run on dev container.'
      },
      {
        list: 'Backlog',
        title: 'Mobile Push Notifications for Approaching Due Dates',
        description: `<p>Deliver web push notifications 24 hours and 2 hours before card deadlines.</p>`,
        assigners: [uPm.id],
        members: [uMember.id],
        labels: ['Feature', 'Frontend'],
        createdDaysAgo: 5
      },
      {
        list: 'To Do',
        title: 'Weekly Automated Productivity Summary Email Digest',
        description: `<p>Summarize completed tasks, open items, and check-ins every Friday afternoon for all project managers.</p>`,
        assigners: [uOwner.id],
        members: [uMember2.id],
        labels: ['Feature', 'Backend'],
        createdDaysAgo: 2
      }
    ];

    async function seedCardsForBoard(targetBoardId, cardsList, targetListMap, targetLabelMap) {
      let cardPos = 1000.0;
      for (const cData of cardsList) {
        const listId = targetListMap.get(cData.list);
        if (!listId) continue;
        const isComplete = cData.isComplete ? 1 : 0;
        const completedAt = cData.isComplete ? 'NOW()' : null;

        const [cRes] = await tenantConn.execute(
          `INSERT INTO cards (list_id, title, description, position, is_complete, completed_at, completion_note, created_by, created_at)
           VALUES (?, ?, ?, ?, ?, ${completedAt ? 'NOW()' : 'NULL'}, ?, ?, DATE_SUB(NOW(), INTERVAL ? DAY))`,
          [listId, cData.title, cData.description, cardPos, isComplete, cData.completionNote || null, uOwner.id, cData.createdDaysAgo || 1]
        );
        const cardId = cRes.insertId;
        cardPos += 1000.0;

        // Assigners
        for (const aId of (cData.assigners || [])) {
          await tenantConn.execute(
            `INSERT INTO card_assigners (card_id, user_id) VALUES (?, ?)`,
            [cardId, aId]
          );
        }

        // Assignees
        for (const mId of (cData.members || [])) {
          await tenantConn.execute(
            `INSERT INTO card_members (card_id, user_id) VALUES (?, ?)`,
            [cardId, mId]
          );
        }

        // Labels
        for (const lName of (cData.labels || [])) {
          const lId = targetLabelMap.get(lName);
          if (lId) {
            await tenantConn.execute(
              `INSERT INTO card_labels (card_id, label_id) VALUES (?, ?)`,
              [cardId, lId]
            );
          }
        }

        // Checklists
        for (const chk of (cData.checklists || [])) {
          const [chRes] = await tenantConn.execute(
            `INSERT INTO checklists (card_id, title) VALUES (?, ?)`,
            [cardId, chk.title]
          );
          const chId = chRes.insertId;

          let itemPos = 1000.0;
          for (const it of (chk.items || [])) {
            await tenantConn.execute(
              `INSERT INTO checklist_items (checklist_id, text, is_checked, position, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, DATE_SUB(NOW(), INTERVAL 1 DAY))`,
              [chId, it.text, it.done ? 1 : 0, itemPos, uOwner.id]
            );
            itemPos += 1000.0;
          }
        }

        // Comments
        for (const comm of (cData.comments || [])) {
          await tenantConn.execute(
            `INSERT INTO comments (card_id, user_id, body, created_at)
             VALUES (?, ?, ?, DATE_SUB(NOW(), INTERVAL 1 DAY))`,
            [cardId, comm.user.id, comm.text]
          );
        }

        // Check-ins
        for (const ci of (cData.checkins || [])) {
          const flagList = ci.status === 'blocked' ? JSON.stringify(['blocked']) : JSON.stringify([]);
          await tenantConn.execute(
            `INSERT INTO check_ins (card_id, user_id, work_date, did, next_step, blocker, status, progress_pct, flags, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, DATE_SUB(NOW(), INTERVAL ? MINUTE))`,
            [cardId, ci.user.id, ci.workDate, ci.did, ci.next_step, ci.blocker || null, ci.status, ci.progress_pct, flagList, ci.createdAgoMinutes || 60]
          );
        }

        // Activity log entry
        await tenantConn.execute(
          `INSERT INTO activity_log (board_id, card_id, user_id, action_type, meta_json, created_at)
           VALUES (?, ?, ?, 'created_card', ?, DATE_SUB(NOW(), INTERVAL ? DAY))`,
          [targetBoardId, cardId, uOwner.id, JSON.stringify({ title: cData.title }), cData.createdDaysAgo || 1]
        );
      }
    }

    // Seed Board 1 (Workspace 1)
    await seedCardsForBoard(b1Id, cardTemplates, listMap, labelMap);

    // Seed Board 2 (Workspace 1)
    const b2Cards = [
      {
        list: 'In Progress',
        title: 'Biometric Auth & FaceID Keychain Storage',
        description: `<h2>Mobile Security</h2><p>Store encrypted user authentication tokens securely inside iOS Keychain and Android Keystore with biometric prompt fallback.</p>`,
        assigners: [uPm.id],
        members: [uMember2.id],
        labels: ['Feature', 'Backend'],
        createdDaysAgo: 2,
        checklists: [
          {
            title: 'Biometrics Checklist',
            items: [
              { text: 'LocalAuthentication iOS framework bindings', done: 1 },
              { text: 'BiometricPrompt Android API implementation', done: 1 },
              { text: 'Fallback passcode authentication support', done: 0 }
            ]
          }
        ],
        checkins: [
          {
            user: uMember2,
            workDate: new Date().toISOString().slice(0, 10),
            createdAgoMinutes: 90,
            did: 'Completed Android Keystore wrapper and validated fingerprint unlock on test devices.',
            next_step: 'Finalize iOS FaceID permission dialog flow and secure enclave unit test suite.',
            progress_pct: 65,
            status: 'on_track'
          }
        ]
      },
      {
        list: 'To Do',
        title: 'Offline SQLite Sync Engine for Mobile',
        description: `<p>Allow field team members to review tasks offline and sync state mutations back to the server upon reconnection.</p>`,
        assigners: [uOwner.id],
        members: [uMember2.id],
        labels: ['Feature'],
        createdDaysAgo: 1
      }
    ];
    await seedCardsForBoard(b2Id, b2Cards, b2ListMap, b2LabelMap);

    // Seed Board 4 (Workspace 2: Marketing & Growth)
    const b4Cards = [
      {
        list: 'In Progress',
        title: 'Landing Page A/B Testing & Funnel Analytics',
        description: `<h2>Growth Initiative</h2><p>Execute multi-variant experiments on the primary pricing and signup funnel to optimize customer conversion rates.</p>`,
        assigners: [uOwner.id],
        members: [uMember.id],
        labels: ['Campaign', 'Design'],
        createdDaysAgo: 3,
        checklists: [
          {
            title: 'Experiment Setup',
            items: [
              { text: 'Deploy Variant B pricing tier cards', done: 1 },
              { text: 'Set up Google Analytics 4 custom event triggers', done: 1 },
              { text: 'Review statistical significance after 1000 trials', done: 0 }
            ]
          }
        ],
        checkins: [
          {
            user: uMember,
            workDate: new Date().toISOString().slice(0, 10),
            createdAgoMinutes: 45,
            did: 'Configured UTM tracking parameters and launched Variant B pricing page to 50% incoming traffic.',
            next_step: 'Analyze heatmaps and drop-off rates on checkout steps.',
            progress_pct: 75,
            status: 'on_track'
          }
        ]
      },
      {
        list: 'In Progress',
        title: 'Q3 Product Hunt Launch Teaser & Video Production',
        description: `<p>Design high-resolution product demo motion graphics and record founder walkthrough video for the upcoming Product Hunt feature day.</p>`,
        assigners: [uOwner.id],
        members: [uMember.id],
        labels: ['Urgent', 'Campaign'],
        createdDaysAgo: 2,
        checkins: [
          {
            user: uMember,
            workDate: new Date().toISOString().slice(0, 10),
            createdAgoMinutes: 180,
            did: 'Storyboarding completed. Recorded 4K screencast walkthrough clips.',
            next_step: 'Audio voiceover mastering and video cut delivery.',
            progress_pct: 50,
            status: 'on_track'
          }
        ]
      }
    ];
    await seedCardsForBoard(b4Id, b4Cards, b4ListMap, b4LabelMap);

    console.log('✓ Seeded rich demo cards with check-ins, checklists, labels across Board 1, Board 2, and Board 4.');

    // -------------------------------------------------------------
    // STEP 7: DUPLICATE BASELINE INTO PM_DEV_SINGLE FOR SAFETY
    // -------------------------------------------------------------
    console.log(`\nMirroring baseline schema and users into '${devDbName}' for single-tenant mode compatibility...`);
    const devConn = await mysql.createConnection({
      host: process.env.MYSQL_HOST || '127.0.0.1',
      port: Number(process.env.MYSQL_PORT || 3306),
      user: process.env.MYSQL_USER || 'root',
      password: process.env.MYSQL_PASSWORD || '',
      database: devDbName
    });

    const devDbWrapper = {
      query: (sql, params) => devConn.query(sql, params).then(([rows]) => rows),
      execute: (sql, params) => devConn.execute(sql, params)
    };
    await syncPermissionCatalog(devDbWrapper);

    // Insert same users into dev_single
    for (const acc of DEMO_ROLES) {
      await devConn.execute(
        `INSERT INTO users (name, email, password_hash, must_change_password, failed_login_attempts, created_at)
         VALUES (?, ?, ?, 0, 0, NOW())`,
        [acc.name, acc.email, passwordHash]
      );
    }
    await devConn.end();
    console.log(`✓ '${devDbName}' populated with baseline users.`);

    await tenantConn.end();
    await masterConn.end();

    console.log('\n================================================================');
    console.log('             DEMO TESTING ENVIRONMENT READY!');
    console.log('================================================================');
    console.log(`Company Name: ${DEMO_COMPANY_NAME}`);
    console.log(`Company Slug: ${DEMO_SLUG}`);
    console.log(`All Accounts Password: ${DEMO_PASSWORD}\n`);

    const tableData = DEMO_ROLES.map((r) => ({
      Role: r.role,
      Name: r.name,
      Email: r.email,
      Password: DEMO_PASSWORD
    }));
    console.table(tableData);

  } catch (err) {
    console.error('Fatal error during clean and seed:', err);
    throw err;
  } finally {
    await rootConn.end();
    await closeAllPools();
  }
}

if (require.main === module) {
  cleanAndSeedDemo()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}

module.exports = { cleanAndSeedDemo, DEMO_PASSWORD, DEMO_ROLES };

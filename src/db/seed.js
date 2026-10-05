// server/src/db/seed.js
// Clean seed script for development
const bcrypt = require('bcryptjs');
const db = require('./index');

async function seed() {
  try {
    console.log('Clearing existing database entries & seeding clean roles data...');

    // 1. Ensure runtime schema migrations applied
    await db.ensureRuntimeSchema();

    // 2. Clear existing data safely
    await db.query('SET FOREIGN_KEY_CHECKS = 0');
    await db.query('TRUNCATE TABLE users');
    await db.query('TRUNCATE TABLE workspaces');
    await db.query('TRUNCATE TABLE workspace_members');
    await db.query('TRUNCATE TABLE boards');
    await db.query('TRUNCATE TABLE board_members');
    await db.query('TRUNCATE TABLE lists');
    await db.query('TRUNCATE TABLE cards');
    await db.query('TRUNCATE TABLE labels');
    await db.query('TRUNCATE TABLE card_labels');
    await db.query('TRUNCATE TABLE card_members');
    await db.query('TRUNCATE TABLE checklists');
    await db.query('TRUNCATE TABLE checklist_items');
    await db.query('TRUNCATE TABLE comments');
    await db.query('TRUNCATE TABLE attachments');
    await db.query('TRUNCATE TABLE activity_log');
    await db.query('TRUNCATE TABLE notifications');
    await db.query('TRUNCATE TABLE notification_preferences');
    await db.query('TRUNCATE TABLE pending_invitations');
    await db.query('TRUNCATE TABLE invitation_boards');
    await db.query('SET FOREIGN_KEY_CHECKS = 1');

    // 3. Create 5 Users (1 Super Admin, 2 Managers, 2 Team Members)
    const passwordHash = await bcrypt.hash('password123', 10);
    const users = [
      ['Alex Morgan (Super Admin)', 'superadmin@company.com', passwordHash],
      ['Marcus Vance (Manager 1)', 'manager1@company.com', passwordHash],
      ['Maria Garcia (Manager 2)', 'manager2@company.com', passwordHash],
      ['Taylor Swift (Member 1)', 'member1@company.com', passwordHash],
      ['David Chen (Member 2)', 'member2@company.com', passwordHash]
    ];

    const createdUsers = [];
    for (const [name, email, hash] of users) {
      const res = await db.execute(
        'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
        [name, email, hash]
      );
      createdUsers.push({ id: res.insertId, name, email });
    }
    const [superAdminUser, manager1User, manager2User, member1User, member2User] = createdUsers;

    // 4. Create Main Workspace
    const wsRes = await db.execute(
      'INSERT INTO workspaces (name) VALUES (?)',
      ['Acme Enterprise Project']
    );
    const workspaceId = wsRes.insertId;

    // 5. Fetch System Roles
    const superAdminRoleRes = await db.query(
      "SELECT id FROM roles WHERE is_system = 1 AND name = 'Super Admin' AND workspace_id IS NULL"
    );
    const superAdminRoleId = superAdminRoleRes[0]?.id;

    const managerRoleRes = await db.query(
      "SELECT id FROM roles WHERE is_system = 1 AND name = 'Manager' AND workspace_id IS NULL"
    );
    const managerRoleId = managerRoleRes[0]?.id;

    const teamMemberRoleRes = await db.query(
      "SELECT id FROM roles WHERE is_system = 1 AND name = 'Team Member' AND workspace_id IS NULL"
    );
    const teamMemberRoleId = teamMemberRoleRes[0]?.id;

    // 6. Assign Users to Workspace Members with exact role_ids
    const memberAssignments = [
      [workspaceId, superAdminUser.id, 'Super Admin', superAdminRoleId],
      [workspaceId, manager1User.id, 'Manager', managerRoleId],
      [workspaceId, manager2User.id, 'Manager', managerRoleId],
      [workspaceId, member1User.id, 'Team Member', teamMemberRoleId],
      [workspaceId, member2User.id, 'Team Member', teamMemberRoleId]
    ];

    for (const [wsId, uId, role, rId] of memberAssignments) {
      await db.execute(
        'INSERT INTO workspace_members (workspace_id, user_id, role, role_id) VALUES (?, ?, ?, ?)',
        [wsId, uId, role, rId]
      );
    }

    // 7. Create Board
    const boardRes = await db.execute(
      "INSERT INTO boards (workspace_id, name, background_color) VALUES (?, 'Core Sprint Board', 'bg-gradient-to-br from-indigo-900 via-slate-900 to-purple-950')",
      [workspaceId]
    );
    const boardId = boardRes.insertId;

    // Add board members
    for (const u of createdUsers) {
      await db.execute(
        'INSERT INTO board_members (board_id, user_id, role) VALUES (?, ?, ?)',
        [boardId, u.id, u.id === superAdminUser.id ? 'admin' : 'member']
      );
    }

    // Create default lists
    const lists = ['To Do', 'In Progress', 'Code Review', 'Done'];
    let pos = 1000.0;
    const createdLists = [];
    for (const lName of lists) {
      const lRes = await db.execute(
        'INSERT INTO lists (board_id, name, position) VALUES (?, ?, ?)',
        [boardId, lName, pos]
      );
      createdLists.push({ id: lRes.insertId, name: lName });
      pos += 1000.0;
    }

    // Create labels
    const labels = [
      ['Feature', '#3b82f6'],
      ['Bug', '#ef4444'],
      ['Design', '#ec4899'],
      ['Backend', '#10b981'],
      ['Urgent', '#f59e0b']
    ];
    for (const [lName, color] of labels) {
      await db.execute(
        'INSERT INTO labels (board_id, name, color) VALUES (?, ?, ?)',
        [boardId, lName, color]
      );
    }

    console.log('✓ Database seeded successfully!');
  } catch (err) {
    console.error('Seed failed:', err);
    process.exit(1);
  } finally {
    await db.pool.end();
  }
}

if (require.main === module) {
  seed();
}

module.exports = seed;

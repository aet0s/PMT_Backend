// server/src/services/tenantProvisioner.js
// Provisions tenant databases with strict name guarding, migrations, and automated initial seeding.
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const { getMasterDb, getTenantDbByName, evictTenantPool } = require('./tenantPools');
const migrator = require('../db/migrator');
require('dotenv').config();

const TENANT_DB_GUARD = /^pm_t_[a-z0-9_]+$/;

function validateTenantDbName(dbName) {
  if (typeof dbName !== 'string') {
    throw new Error('Tenant database name must be a string');
  }
  if (dbName.length > 64) {
    throw new Error(`Tenant database name exceeds maximum length of 64 characters (got ${dbName.length})`);
  }
  if (!TENANT_DB_GUARD.test(dbName)) {
    throw new Error(`Security violation: Invalid tenant database name "${dbName}". Must match strictly ^pm_t_[a-z0-9_]+$`);
  }
}

async function createTenantDatabase(dbName) {
  validateTenantDbName(dbName);
  const conn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || ''
  });
  try {
    await conn.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  } finally {
    await conn.end();
  }
}

async function dropTenantDatabase(dbName) {
  validateTenantDbName(dbName);
  if (dbName === 'pm_master' || dbName === 'pm_dev_single') {
    throw new Error(`FATAL: Cannot drop protected database "${dbName}"`);
  }
  const conn = await mysql.createConnection({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD || ''
  });
  try {
    await conn.query(`DROP DATABASE IF EXISTS \`${dbName}\``);
  } finally {
    await conn.end();
  }
}

function slugify(name) {
  if (!name || typeof name !== 'string') return '';
  const clean = name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 32);
  return clean || 'company';
}

function deriveTenantDbName(slug, suffix = null) {
  const cleanSlug = slugify(slug);
  const id8 = suffix || crypto.randomBytes(4).toString('hex');
  return `pm_t_${cleanSlug}_${id8}`;
}

async function provisionTenant({
  companyName,
  slug,
  ownerEmail,
  ownerPassword,
  ownerPasswordHash = null,
  ownerName = 'Administrator',
  plan = 'free'
}) {
  const masterDb = getMasterDb();
  const normalizedSlug = slugify(slug || companyName);
  const dbName = deriveTenantDbName(normalizedSlug);

  // 1. Verify slug uniqueness in master (Item 8: deleted slug stays reserved for 30 days)
  const existing = await masterDb.query(
    "SELECT id, slug, status, deleted_at, updated_at FROM tenants WHERE slug = ?",
    [normalizedSlug]
  );
  if (existing.length > 0) {
    const t = existing[0];
    if (t.status !== 'deleted') {
      const err = new Error(`A company with slug "${normalizedSlug}" already exists`);
      err.status = 409;
      err.code = 'SLUG_CONFLICT';
      throw err;
    }
    const delTime = t.deleted_at ? new Date(t.deleted_at).getTime() : new Date(t.updated_at).getTime();
    const daysSinceDeletion = (Date.now() - delTime) / (1000 * 60 * 60 * 24);
    if (daysSinceDeletion < 30) {
      const err = new Error(`Company slug "${normalizedSlug}" remains reserved for 30 days following deletion`);
      err.status = 409;
      err.code = 'SLUG_RESERVED';
      throw err;
    }
  }

  // 2. Validate DB name using the mandatory guard
  validateTenantDbName(dbName);

  const uuid = crypto.randomUUID();
  let tenantId = null;

  try {
    // 3. Insert tenant into master registry with status 'provisioning'
    const insRes = await masterDb.execute(
      `INSERT INTO tenants (uuid, slug, name, db_name, status, plan, owner_email)
       VALUES (?, ?, ?, ?, 'provisioning', ?, ?)`,
      [uuid, normalizedSlug, companyName.trim(), dbName, plan, ownerEmail.trim().toLowerCase()]
    );
    tenantId = insRes.insertId;

    // 4. Create database
    await createTenantDatabase(dbName);

    // 5. Run tenant schema migrations on the new database
    await migrator.runMigrationsOnDb(dbName, 'tenant');

    // 6. Connect to newly created tenant DB to seed initial owner and workspace
    const tenantDb = getTenantDbByName(dbName);

    // Create owner user
    let passwordHash = ownerPasswordHash;
    if (!passwordHash && ownerPassword) {
      const salt = await bcrypt.genSalt(10);
      passwordHash = await bcrypt.hash(ownerPassword, salt);
    }
    const userRes = await tenantDb.execute(
      `INSERT INTO users (name, email, password_hash)
       VALUES (?, ?, ?)`,
      [ownerName.trim(), ownerEmail.trim().toLowerCase(), passwordHash]
    );
    const ownerUserId = userRes.insertId;

    // Fetch Super Admin role
    const roles = await tenantDb.query(
      "SELECT id FROM roles WHERE name = 'Super Admin' AND is_system = 1 AND workspace_id IS NULL"
    );
    const superAdminRoleId = roles[0] ? roles[0].id : 1;

    // Create default workspace
    const wsRes = await tenantDb.execute(
      'INSERT INTO workspaces (name) VALUES (?)',
      [`${companyName.trim()} Workspace`]
    );
    const workspaceId = wsRes.insertId;

    // Add owner as Super Admin in workspace
    await tenantDb.execute(
      `INSERT INTO workspace_members (workspace_id, user_id, role, role_id)
       VALUES (?, ?, 'Super Admin', ?)`,
      [workspaceId, ownerUserId, superAdminRoleId]
    );

    // Create sample project board
    const boardRes = await tenantDb.execute(
      `INSERT INTO boards (workspace_id, name, background_color)
       VALUES (?, 'Getting Started', 'bg-gradient-to-br from-indigo-900 via-slate-900 to-purple-950')`,
      [workspaceId]
    );
    const boardId = boardRes.insertId;

    // Add owner to board
    await tenantDb.execute(
      "INSERT INTO board_members (board_id, user_id, role) VALUES (?, ?, 'admin')",
      [boardId, ownerUserId]
    );

    // Create default lists
    const lists = ['To Do', 'In Progress', 'Done'];
    let firstListId = null;
    for (let i = 0; i < lists.length; i++) {
      const lRes = await tenantDb.execute(
        'INSERT INTO lists (board_id, name, position) VALUES (?, ?, ?)',
        [boardId, lists[i], (i + 1) * 1000]
      );
      if (i === 0) firstListId = lRes.insertId;
    }

    // Create welcome card in 'To Do' list
    if (firstListId) {
      await tenantDb.execute(
        `INSERT INTO cards (list_id, title, description, position)
         VALUES (?, 'Welcome to your new workspace!', 'Explore boards, lists, cards, checklists, and invite your team.', 1000)`,
        [firstListId]
      );
    }

    // 7. Add to global tenant_user_directory
    await masterDb.execute(
      'INSERT IGNORE INTO tenant_user_directory (email, tenant_id) VALUES (?, ?)',
      [ownerEmail.trim().toLowerCase(), tenantId]
    );

    // 8. Update tenant status to 'active'
    await masterDb.execute("UPDATE tenants SET status = 'active' WHERE id = ?", [tenantId]);

    return {
      tenant: {
        id: tenantId,
        uuid,
        slug: normalizedSlug,
        name: companyName,
        db_name: dbName,
        status: 'active'
      },
      owner: {
        id: ownerUserId,
        email: ownerEmail.trim().toLowerCase(),
        name: ownerName.trim()
      },
      workspace: {
        id: workspaceId
      }
    };
  } catch (err) {
    // Rollback: drop database if created, delete tenant row
    console.error(`[ROLLBACK] Provisioning failed for "${dbName}". Reverting...`, err.message);
    try {
      await dropTenantDatabase(dbName);
    } catch (dropErr) {
      // ignore drop errors on rollback
    }
    if (tenantId) {
      try {
        await masterDb.execute('DELETE FROM tenants WHERE id = ?', [tenantId]);
        await masterDb.execute('DELETE FROM tenant_user_directory WHERE tenant_id = ?', [tenantId]);
      } catch (delErr) {
        // ignore
      }
      await evictTenantPool(tenantId);
    }
    if (err.code === 'ER_DUP_ENTRY' || err.errno === 1062) {
      err.status = 409;
      err.code = 'SLUG_CONFLICT';
    }
    throw err;
  }
}

module.exports = {
  TENANT_DB_GUARD,
  validateTenantDbName,
  createTenantDatabase,
  dropTenantDatabase,
  slugify,
  deriveTenantDbName,
  provisionTenant
};

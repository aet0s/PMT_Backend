// server/src/rbac/catalogSync.js
// Idempotent synchronization of the RBAC catalog from registry.js into tenant databases.

const { PERMISSIONS, SYSTEM_ROLES } = require('./registry');

/**
 * Synchronizes the permissions catalog and system role definitions for a given database.
 * 
 * Rules:
 * 1. Idempotently upserts every permission from registry.js (module, scope, dangerous, planned, label).
 * 2. Deprecates removed keys safely without deleting them from roles in use.
 * 3. Ensures 6 system roles exist with proper is_system, is_editable, and rank properties.
 * 4. Owner receives every non-planned permission automatically.
 * 5. Admin and other system roles receive permissions per their registry definitions.
 * 6. Custom roles are never automatically modified.
 */
async function syncPermissionCatalog(db, options = {}) {
  const useLock = options.advisoryLock !== false;

  if (useLock) {
    try {
      await db.query("SELECT GET_LOCK('rbac_catalog_sync_lock', 10) as acquired");
    } catch (e) {
      // Ignored if connection does not permit advisory locks
    }
  }

  try {
    // 1. Fail-safe column checks for planned and label
    try {
      await db.execute('ALTER TABLE permissions ADD COLUMN IF NOT EXISTS planned TINYINT(1) NOT NULL DEFAULT 0 AFTER dangerous');
      await db.execute('ALTER TABLE permissions ADD COLUMN IF NOT EXISTS label VARCHAR(100) NULL AFTER description');
    } catch (_) {
      // Columns may already exist
    }

    try {
      await db.execute('ALTER TABLE roles ADD COLUMN IF NOT EXISTS rank INT NOT NULL DEFAULT 30 AFTER is_editable');
    } catch (_) {
      // Column may already exist
    }

    // 2. Upsert catalog permissions from registry
    for (const perm of PERMISSIONS) {
      await db.execute(
        `INSERT INTO permissions (\`key\`, module, label, description, scope, dangerous, planned)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           module = VALUES(module),
           label = VALUES(label),
           description = VALUES(description),
           scope = VALUES(scope),
           dangerous = VALUES(dangerous),
           planned = VALUES(planned)`,
        [
          perm.key,
          perm.module,
          perm.label || perm.key,
          perm.description || '',
          perm.scope || 'project',
          perm.dangerous ? 1 : 0,
          perm.planned ? 1 : 0
        ]
      );
    }

async function safeQuery(db, sql, params = []) {
  const res = await db.query(sql, params);
  if (Array.isArray(res) && Array.isArray(res[0])) return res[0];
  return res || [];
}

    // 3. Deprecate database keys that are no longer present in the registry
    const registryKeys = new Set(PERMISSIONS.map((p) => p.key));
    const dbPermRows = await safeQuery(db, 'SELECT id, `key`, description FROM permissions');
    for (const row of dbPermRows) {
      if (!registryKeys.has(row.key)) {
        const desc = row.description || '';
        const newDesc = desc.startsWith('[DEPRECATED]') ? desc : `[DEPRECATED] ${desc}`.trim();
        await db.execute(
          'UPDATE permissions SET planned = 1, description = ? WHERE id = ?',
          [newDesc, row.id]
        );
      }
    }

    // Clean up role_permissions for any planned permissions
    await db.execute(
      `DELETE rp FROM role_permissions rp
       JOIN permissions p ON rp.permission_id = p.id
       WHERE p.planned = 1`
    );

    // 4. Ensure all 6 system roles exist with proper ranks (deduplicated by name WHERE workspace_id IS NULL)
    const SYSTEM_ROLE_SPECS = [
      { name: 'Owner', rank: 100, is_editable: 0 },
      { name: 'Admin', rank: 80, is_editable: 1 },
      { name: 'Project Manager', rank: 60, is_editable: 1 },
      { name: 'Team Member', rank: 40, is_editable: 1 },
      { name: 'Viewer', rank: 20, is_editable: 1 },
      { name: 'Guest', rank: 10, is_editable: 1 }
    ];

    for (const spec of SYSTEM_ROLE_SPECS) {
      const existingRows = await safeQuery(
        db,
        'SELECT id FROM roles WHERE name = ? AND workspace_id IS NULL ORDER BY id ASC',
        [spec.name]
      );
      if (existingRows.length > 0) {
        const canonicalId = existingRows[0].id;
        await db.execute(
          'UPDATE roles SET is_system = 1, is_editable = ?, rank = ? WHERE id = ?',
          [spec.is_editable, spec.rank, canonicalId]
        );
        // Clean up any duplicate system roles with same name
        if (existingRows.length > 1) {
          const duplicateIds = existingRows.slice(1).map((r) => r.id);
          for (const dupId of duplicateIds) {
            await db.execute('UPDATE workspace_members SET role_id = ? WHERE role_id = ?', [canonicalId, dupId]);
            await db.execute('DELETE FROM role_permissions WHERE role_id = ?', [dupId]);
            await db.execute('DELETE FROM roles WHERE id = ?', [dupId]);
          }
        }
      } else {
        await db.execute(
          'INSERT INTO roles (name, is_system, is_editable, rank, workspace_id) VALUES (?, 1, ?, ?, NULL)',
          [spec.name, spec.is_editable, spec.rank]
        );
      }
    }

    // 5. Fetch fresh permissions mapping (active vs planned)
    const activePermsRes = await safeQuery(db, 'SELECT id, `key` FROM permissions WHERE planned = 0');
    const activePermMap = new Map(activePermsRes.map((p) => [p.key, p.id]));

    // 6. Owner receives ALL active (non-planned) permissions automatically
    const ownerRoleRows = await safeQuery(
      db,
      "SELECT id FROM roles WHERE (name = 'Owner' OR name = 'Super Admin') AND is_system = 1 AND workspace_id IS NULL LIMIT 1"
    );
    const ownerRole = ownerRoleRows[0];

    if (ownerRole) {
      for (const p of activePermsRes) {
        await db.execute(
          'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
          [ownerRole.id, p.id]
        );
      }
    }

    // 7. Admin and other system roles receive permissions per registry definition
    for (const [roleName, roleDef] of Object.entries(SYSTEM_ROLES)) {
      if (roleName === 'Owner') continue;
      const rRows = await safeQuery(
        db,
        'SELECT id FROM roles WHERE name = ? AND is_system = 1 AND workspace_id IS NULL LIMIT 1',
        [roleName]
      );
      const rRow = rRows[0];
      if (!rRow) continue;

      for (const permKey of roleDef.permissions) {
        const pId = activePermMap.get(permKey);
        if (pId) {
          await db.execute(
            'INSERT IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)',
            [rRow.id, pId]
          );
        }
      }
    }

    return {
      syncedPermissionsCount: PERMISSIONS.length,
      activePermissionsCount: activePermsRes.length
    };
  } finally {
    if (useLock) {
      try {
        await db.query("SELECT RELEASE_LOCK('rbac_catalog_sync_lock')");
      } catch (_) {
        // Ignored
      }
    }
  }
}

/**
 * Runs syncPermissionCatalog across all tenant databases and single-tenant mode if active.
 */
async function syncAllTenantsPermissionCatalog() {
  const isSingleTenant = process.env.DEV_SINGLE_TENANT === '1' || process.env.DEV_SINGLE_TENANT === 'true';
  const { getMasterDb, getDevSingleDb, getTenantDb } = require('../services/tenantPools');

  if (isSingleTenant) {
    console.log('[catalogSync] Synchronizing single-tenant permission catalog...');
    const singleDb = getDevSingleDb();
    return await syncPermissionCatalog(singleDb);
  }

  const masterDb = getMasterDb();
  try {
    const tenants = await masterDb.query(
      "SELECT id, db_name, slug FROM tenants WHERE status = 'active'"
    );
    for (const t of tenants) {
      console.log(`[catalogSync] Synchronizing catalog for tenant ${t.slug} (${t.db_name})...`);
      const tenantDb = await getTenantDb(t.id);
      await syncPermissionCatalog(tenantDb);
    }
  } catch (err) {
    console.warn('[catalogSync] Could not iterate master tenants, falling back to devSingleDb:', err.message);
    const fallbackDb = getDevSingleDb();
    await syncPermissionCatalog(fallbackDb);
  }
}

module.exports = {
  syncPermissionCatalog,
  syncAllTenantsPermissionCatalog
};

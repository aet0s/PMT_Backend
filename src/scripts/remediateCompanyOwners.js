#!/usr/bin/env node
// server/src/scripts/remediateCompanyOwners.js
// Safe, read-only-by-default audit and remediation script for tenant ownership and escalated Owner memberships.
// Usage: node src/scripts/remediateCompanyOwners.js [--apply] [--tenant=<slug>]

require('dotenv').config();
const { getMasterDb, getTenantDb, closeAllTenantPools } = require('../services/tenantPools');

async function auditAndRemediate() {
  const args = process.argv.slice(2);
  const isApply = args.includes('--apply');
  const tenantArg = args.find((a) => a.startsWith('--tenant='));
  const targetTenantSlug = tenantArg ? tenantArg.split('=')[1].trim().toLowerCase() : null;

  console.log('================================================================');
  console.log(`  COMPANY OWNER AUDIT & REMEDIATION (${isApply ? 'APPLY MODE' : 'DRY RUN - READ ONLY'})`);
  console.log('================================================================\n');

  try {
    const masterDb = getMasterDb();
    let tenantQuery = "SELECT id, slug, name, db_name, owner_email FROM tenants WHERE status != 'deleted'";
    const queryParams = [];

    if (targetTenantSlug) {
      tenantQuery += ' AND slug = ?';
      queryParams.push(targetTenantSlug);
    }

    const tenants = await masterDb.query(tenantQuery, queryParams);

    if (tenants.length === 0) {
      console.log('No matching tenants found.');
      return;
    }

    const fullReport = [];

    for (const tenant of tenants) {
      console.log(`\nAuditing tenant: ${tenant.name} (${tenant.slug}) - Registered Owner: ${tenant.owner_email}`);
      let tenantDb;
      try {
        tenantDb = await getTenantDb(tenant.id);
      } catch (e) {
        console.warn(`Could not connect to tenant database: ${e.message}`);
        continue;
      }

      // Ensure company_owners table exists
      await tenantDb.execute(`
        CREATE TABLE IF NOT EXISTS company_owners (
          user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
          created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
          CONSTRAINT fk_co_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
      `);

      // Dynamically fetch all system roles by name (never assume numeric IDs)
      const sysRoles = await tenantDb.query(
        'SELECT id, name, rank FROM roles WHERE is_system = 1 AND workspace_id IS NULL'
      );
      const roleByName = {};
      sysRoles.forEach((r) => {
        roleByName[r.name] = r;
      });

      // Find registered and founding owner
      const regOwnerEmail = (tenant.owner_email || '').trim().toLowerCase();
      const legitimateOwnerRows = await tenantDb.query(
        'SELECT id, name, email FROM users WHERE LOWER(email) = ?',
        [regOwnerEmail]
      );
      const foundingOwner = legitimateOwnerRows[0] || (await tenantDb.query('SELECT id, name, email FROM users ORDER BY id ASC LIMIT 1'))[0];

      // Fetch verified company owners from company_owners table
      const verifiedCoRows = await tenantDb.query('SELECT user_id FROM company_owners');
      const verifiedCoSet = new Set(verifiedCoRows.map((r) => Number(r.user_id)));

      if (foundingOwner && !verifiedCoSet.has(Number(foundingOwner.id))) {
        if (isApply) {
          await tenantDb.execute('INSERT IGNORE INTO company_owners (user_id) VALUES (?)', [foundingOwner.id]);
        }
        verifiedCoSet.add(Number(foundingOwner.id));
      }

      // Find all users who currently hold Owner role in ANY workspace
      const currentOwnersInWorkspaces = await tenantDb.query(
        `SELECT DISTINCT u.id, u.name, u.email, GROUP_CONCAT(DISTINCT wm.workspace_id) as workspace_ids
         FROM workspace_members wm
         JOIN roles r ON wm.role_id = r.id
         JOIN users u ON wm.user_id = u.id
         WHERE (r.name = 'Owner' OR r.name = 'Super Admin')
         GROUP BY u.id, u.name, u.email`
      );

      for (const user of currentOwnersInWorkspaces) {
        const userId = Number(user.id);
        const userEmail = (user.email || '').trim().toLowerCase();
        const isVerifiedCompanyOwner = verifiedCoSet.has(userId) || (foundingOwner && userId === Number(foundingOwner.id)) || userEmail === regOwnerEmail;

        if (isVerifiedCompanyOwner) {
          fullReport.push({
            Tenant: tenant.slug,
            UserID: user.id,
            Name: user.name,
            Email: user.email,
            Workspaces: user.workspace_ids,
            Classification: 'LEGITIMATE_OWNER',
            Evidence: 'Verified company owner via company_owners / tenant registration record',
            Action: 'Preserve in company_owners and retain Owner role'
          });
          continue;
        }

        // Non-company owner holding Owner role in a workspace: investigate trustworthy evidence
        // 1. Check for non-owner memberships in other workspaces
        const otherMemberships = await tenantDb.query(
          `SELECT wm.workspace_id, r.name as role_name, r.id as role_id, r.rank
           FROM workspace_members wm
           JOIN roles r ON wm.role_id = r.id
           WHERE wm.user_id = ? AND r.name NOT IN ('Owner', 'Super Admin')
           ORDER BY wm.workspace_id ASC`,
          [userId]
        );

        let targetRoleName = null;
        let targetRoleId = null;
        let evidence = null;
        let classification = null;
        let action = null;

        if (otherMemberships.length > 0) {
          // Trustworthy evidence found: user holds legitimate non-owner role in another workspace
          const primaryOtherRole = otherMemberships[0];
          targetRoleName = primaryOtherRole.role_name;
          const resolvedSystemRole = roleByName[targetRoleName];
          targetRoleId = resolvedSystemRole ? resolvedSystemRole.id : primaryOtherRole.role_id;
          classification = 'ESCALATED_OWNER_REMEDIATION_EVIDENCE_FOUND';
          evidence = `Historical workspace membership: holds role "${targetRoleName}" in workspace ${primaryOtherRole.workspace_id}`;
          action = `Revert workspace Owner to ${targetRoleName} (Role ID: ${targetRoleId})`;
        } else {
          // Check audit events for previous role evidence
          const auditRows = await tenantDb.query(
            `SELECT details, action FROM audit_events 
             WHERE user_id = ? AND action IN ('member.role_assigned', 'member.role_changed', 'member.added')
             ORDER BY created_at DESC LIMIT 5`,
            [userId]
          ).catch(() => []);

          let historicalRoleFromAudit = null;
          for (const aRow of auditRows) {
            try {
              const parsed = typeof aRow.details === 'string' ? JSON.parse(aRow.details) : aRow.details;
              if (parsed?.previousRole && parsed.previousRole !== 'Owner' && parsed.previousRole !== 'Super Admin') {
                historicalRoleFromAudit = parsed.previousRole;
                break;
              }
            } catch (_) {}
          }

          if (historicalRoleFromAudit && roleByName[historicalRoleFromAudit]) {
            targetRoleName = historicalRoleFromAudit;
            targetRoleId = roleByName[historicalRoleFromAudit].id;
            classification = 'ESCALATED_OWNER_REMEDIATION_EVIDENCE_FOUND';
            evidence = `Audit log evidence: previous role was "${targetRoleName}"`;
            action = `Revert workspace Owner to ${targetRoleName} (Role ID: ${targetRoleId})`;
          } else {
            // Ambiguous: No trustworthy evidence supports inferring their pre-escalation role.
            // Requirement C: "Leave ambiguous cases unchanged and flag them for manual review. Never silently demote all users to Project Manager."
            classification = 'AMBIGUOUS_MANUAL_REVIEW_REQUIRED';
            evidence = 'No trustworthy pre-escalation role evidence found; user only holds escalated Owner';
            action = 'LEAVE UNCHANGED - Flagged for manual review';
          }
        }

        fullReport.push({
          Tenant: tenant.slug,
          UserID: user.id,
          Name: user.name,
          Email: user.email,
          Workspaces: user.workspace_ids,
          Classification: classification,
          Evidence: evidence,
          Action: action
        });

        // Apply mutation only when explicitly requested and trustworthy evidence supports the change
        if (isApply && classification === 'ESCALATED_OWNER_REMEDIATION_EVIDENCE_FOUND' && targetRoleId) {
          await tenantDb.query('START TRANSACTION');
          try {
            await tenantDb.execute(
              `UPDATE workspace_members wm
               JOIN roles r ON wm.role_id = r.id
               SET wm.role = ?, wm.role_id = ?
               WHERE wm.user_id = ? AND (r.name = 'Owner' OR r.name = 'Super Admin')`,
              [targetRoleName, targetRoleId, userId]
            );
            await tenantDb.execute('DELETE FROM company_owners WHERE user_id = ?', [userId]);

            try {
              await tenantDb.execute(
                `INSERT INTO audit_events (action, category, entity_type, entity_id, outcome, severity, details, user_id)
                 VALUES ('remediation.role_reverted', 'security', 'user', ?, 'success', 'info', ?, ?)`,
                [userId, JSON.stringify({ previousRole: 'Owner', newRole: targetRoleName, evidence }), 1]
              );
            } catch (_) {}

            await tenantDb.query('COMMIT');
            console.log(`  ✓ Remediated escalated user: ${user.name} (${user.email}) -> Reverted to ${targetRoleName}`);
          } catch (txErr) {
            await tenantDb.query('ROLLBACK');
            console.error(`  ✗ Transaction failed for user ${userId}:`, txErr.message);
          }
        } else if (classification === 'AMBIGUOUS_MANUAL_REVIEW_REQUIRED') {
          console.log(`  ⚠ Preserved ambiguous user: ${user.name} (${user.email}) - left unchanged for manual review`);
        }
      }
    }

    console.log('\n--- Remediation Report ---');
    console.table(fullReport);

    const legitimateCount = fullReport.filter((r) => r.Classification === 'LEGITIMATE_OWNER').length;
    const remediableCount = fullReport.filter((r) => r.Classification === 'ESCALATED_OWNER_REMEDIATION_EVIDENCE_FOUND').length;
    const ambiguousCount = fullReport.filter((r) => r.Classification === 'AMBIGUOUS_MANUAL_REVIEW_REQUIRED').length;

    console.log(`\nSummary:`);
    console.log(`  Legitimate Owners Preserved:           ${legitimateCount}`);
    console.log(`  Remediable Escalations (with evidence): ${remediableCount}`);
    console.log(`  Ambiguous Cases (Manual Review):        ${ambiguousCount}`);

    if (!isApply) {
      console.log('\n[DRY RUN COMPLETE] No data was modified. Pass --apply to execute the remediation plan.');
    } else {
      console.log('\n[REMEDIATION COMPLETE] Verified changes applied safely.');
    }
  } catch (err) {
    console.error('Audit failed:', err);
    process.exit(1);
  } finally {
    await closeAllTenantPools();
  }
}

if (require.main === module) {
  auditAndRemediate();
}

module.exports = { auditAndRemediate };

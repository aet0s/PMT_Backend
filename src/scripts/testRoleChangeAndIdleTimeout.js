// server/src/scripts/testRoleChangeAndIdleTimeout.js
const jwt = require('jsonwebtoken');
const { getDevSingleDb } = require('../services/tenantPools');
const { createSession } = require('../services/sessionService');
const { getJwtSecret } = require('../middleware/auth');

async function runVerification() {
  console.log('========================================================================');
  console.log('   VERIFY ROLE CHANGE LOGOUT FIX & 5-DAY IDLE SESSION TIMEOUT (PORT 5000) ');
  console.log('========================================================================\n');

  const baseUrl = 'http://localhost:5000';
  const db = getDevSingleDb();
  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✓ ${message} (PASS)`);
      passed++;
    } else {
      console.error(`  ✗ ${message} (FAIL)`);
      failed++;
    }
  }

  try {
    // 1. Find owner and member in workspace
    const [owner] = await db.query(
      `SELECT u.id, u.email, u.name, wm.workspace_id, wm.role_id, r.name as role_name
       FROM users u
       JOIN workspace_members wm ON u.id = wm.user_id
       JOIN roles r ON wm.role_id = r.id
       WHERE r.name = 'Owner'
       LIMIT 1`
    );

    const [member] = await db.query(
      `SELECT u.id, u.email, u.name, wm.workspace_id, wm.role_id, r.name as role_name
       FROM users u
       JOIN workspace_members wm ON u.id = wm.user_id
       JOIN roles r ON wm.role_id = r.id
       WHERE u.id != ? AND wm.workspace_id = ?
       LIMIT 1`,
      [owner.id, owner.workspace_id]
    );

    console.log(`Testing with Workspace ID: ${owner.workspace_id}`);
    console.log(`Owner: ${owner.name} (#${owner.id})`);
    console.log(`Member: ${member.name} (#${member.id}), current role: ${member.role_name} (role_id: ${member.role_id})\n`);

    // Create active sessions for both
    const ownerSession = await createSession(db, owner);
    const memberSession = await createSession(db, member);

    // ------------------------------------------------------------------------
    // TEST SECTION 1: 5-Day Access Token Expiry and Session Lifespan
    // ------------------------------------------------------------------------
    console.log('--- TEST SECTION 1: 5-Day Token Expiry & Cookie Options ---');

    assert(
      memberSession.expiresIn === 5 * 24 * 60 * 60,
      `Session expiresIn is 432,000 seconds (5 days) (Got: ${memberSession.expiresIn})`
    );

    const decoded = jwt.verify(memberSession.accessToken, getJwtSecret());
    const tokenLifespanSec = decoded.exp - decoded.iat;
    assert(
      tokenLifespanSec === 5 * 24 * 60 * 60,
      `Decoded JWT exp - iat is exactly 432,000 seconds (5 days) (Got: ${tokenLifespanSec})`
    );

    const refreshRes = await fetch(`${baseUrl}/api/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': `refreshToken=${memberSession.refreshToken}`
      }
    });

    const setCookies = refreshRes.headers.get('set-cookie') || '';
    if (setCookies) {
      const maxAgeMatch = setCookies.match(/Max-Age=(\d+)/i);
      const maxAgeSec = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
      assert(
        maxAgeSec >= 430000 && maxAgeSec <= 432000,
        `Token cookie Max-Age on live server is ~432,000 seconds (5 days) (Got: ${maxAgeSec})`
      );
    }

    // ------------------------------------------------------------------------
    // TEST SECTION 2: Role Change Does NOT Revoke Member Sessions
    // ------------------------------------------------------------------------
    console.log('\n--- TEST SECTION 2: Role Change Preserves Member Active Sessions ---');

    const roles = await db.query(
      `SELECT id, name FROM roles WHERE workspace_id = ? OR is_system = 1 ORDER BY id ASC`,
      [owner.workspace_id]
    );

    const testTargetRoles = roles.filter(r => r.name !== 'Owner' && r.id !== member.role_id);

    for (const targetRole of testTargetRoles.slice(0, 3)) {
      console.log(`\nChanging Member role to "${targetRole.name}" (ID: ${targetRole.id})...`);

      const patchRes = await fetch(`${baseUrl}/api/workspaces/${owner.workspace_id}/members/${member.id}/role`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${ownerSession.accessToken}`
        },
        body: JSON.stringify({ role_id: targetRole.id })
      });

      assert(
        patchRes.status === 200,
        `PATCH /api/workspaces/:id/members/:userId/role returned 200 OK (Got: ${patchRes.status})`
      );

      const [checkSession] = await db.query(
        'SELECT id, revoked_at, expires_at FROM sessions WHERE id = ?',
        [memberSession.sessionId]
      );
      assert(
        checkSession && checkSession.revoked_at === null,
        `Member session ${memberSession.sessionId} remains ACTIVE in DB (revoked_at is NULL)`
      );

      const memberReqRes = await fetch(`${baseUrl}/api/workspaces/${owner.workspace_id}/my-permissions`, {
        headers: {
          'Authorization': `Bearer ${memberSession.accessToken}`
        }
      });

      assert(
        memberReqRes.status === 200,
        `Member can still access /my-permissions with existing token without 401 (Got: ${memberReqRes.status})`
      );

      const permData = await memberReqRes.json();
      assert(
        permData.role?.name === targetRole.name,
        `Member /my-permissions immediately reflects new role "${targetRole.name}" (Got: ${permData.role?.name})`
      );

      const [wmRow] = await db.query(
        'SELECT role_id, role FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
        [owner.workspace_id, member.id]
      );
      assert(
        Number(wmRow.role_id) === Number(targetRole.id) && wmRow.role === targetRole.name,
        `workspace_members updated: role_id=${wmRow.role_id}, role="${wmRow.role}"`
      );
    }

    // ------------------------------------------------------------------------
    // SUMMARY
    // ------------------------------------------------------------------------
    console.log('\n========================================================================');
    console.log(`TOTAL ASSERTIONS: ${passed + failed}`);
    console.log(`PASSED:           ${passed}`);
    console.log(`FAILED:           ${failed}`);
    console.log('========================================================================\n');

    process.exit(failed > 0 ? 1 : 0);
  } catch (err) {
    console.error('Test execution failed:', err);
    process.exit(1);
  }
}

runVerification();

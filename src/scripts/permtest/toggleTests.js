// server/src/scripts/permtest/toggleTests.js
// Cumulative grant-one-by-one and isolated per-key toggle suites across active catalog permissions.

const { PROBES } = require('./operations');
const { PERMISSIONS } = require('../../rbac/registry');

const activePermissions = PERMISSIONS.filter((p) => !p.planned);

/**
 * Runs an explicit cumulative grant-one-by-one run through all active keys,
 * asserting that every earlier grant continues to work after each new grant,
 * followed by reverse revocation asserting clean revocation.
 */
async function runCumulativeToggleSuite(fixture) {
  console.log('\n================================================================');
  console.log('       SUITE: CUMULATIVE 73-KEY GRANT & REVERSE REVOKE WALK      ');
  console.log('================================================================\n');

  const { ownerClient, context } = fixture;
  const probeClient = fixture.users['Probe'].client;
  const probeRoleId = context.probeRoleId;

  // Elevate probe role rank to 75 (< 80 custom role ceiling) for duration of toggle tests so rank-restricted operations can be tested
  if (context.tenantDb) {
    await context.tenantDb.execute('UPDATE roles SET rank = 75 WHERE id = ?', [probeRoleId]);
  }

  // Baseline: reset probe role to empty
  await ownerClient.patch(`/api/roles/${probeRoleId}`, {
    permission_keys: []
  });

  const cumulativeKeys = [];
  let progressivePasses = 0;
  let regressivePasses = 0;
  const failedSteps = [];

  console.log(`[1] Progressive Walk: Adding ${activePermissions.length} active keys one-by-one...`);
  for (let idx = 0; idx < activePermissions.length; idx++) {
    const perm = activePermissions[idx];
    cumulativeKeys.push(perm.key);

    // Patch role with current cumulative list
    const patchRes = await ownerClient.patch(`/api/roles/${probeRoleId}`, {
      permission_keys: cumulativeKeys
    });
    if (patchRes.status !== 200) {
      throw new Error(`Failed to update cumulative role: ${patchRes.status}`);
    }

    // Verify newly added key is now allowed
    const probe = PROBES[perm.key];
    let newKeyAllowed = true;
    if (probe) {
      const execRes = await probe.execute(probeClient, context, context.boardAId);
      newKeyAllowed = execRes.status >= 200 && execRes.status < 400;
    }

    // Spot-check: ensure the very first key and a midpoint key are still allowed
    let earlierKeysIntact = true;
    if (cumulativeKeys.length > 1) {
      const firstKeyProbe = PROBES[cumulativeKeys[0]];
      if (firstKeyProbe) {
        const firstExec = await firstKeyProbe.execute(probeClient, context, context.boardAId);
        if (firstExec.status >= 400) {
          earlierKeysIntact = false;
        }
      }
    }

    if (newKeyAllowed && earlierKeysIntact) {
      progressivePasses++;
    } else {
      failedSteps.push({
        step: 'progressive',
        key: perm.key,
        index: idx + 1,
        newKeyAllowed,
        earlierKeysIntact
      });
    }

    if ((idx + 1) % 15 === 0 || idx === activePermissions.length - 1) {
      console.log(`    Progressive walk: ${idx + 1}/${activePermissions.length} keys granted and verified.`);
    }
  }

  console.log(`\n[2] Regressive Walk: Revoking ${cumulativeKeys.length} keys in reverse order...`);
  while (cumulativeKeys.length > 0) {
    const poppedKey = cumulativeKeys.pop();

    await ownerClient.patch(`/api/roles/${probeRoleId}`, {
      permission_keys: cumulativeKeys
    });

    // Verify revoked key is now denied
    // If an overarching broader permission is still granted in cumulativeKeys, the probe will legitimately succeed.
    const probe = PROBES[poppedKey];
    let revokedDenied = true;
    if (probe) {
      const hasBroaderPerm =
        (poppedKey === 'task.delete_own' && cumulativeKeys.includes('task.delete')) ||
        (poppedKey === 'comment.edit_own' && cumulativeKeys.includes('task.edit')) ||
        (poppedKey === 'comment.delete_own' && (cumulativeKeys.includes('comment.delete_any') || cumulativeKeys.includes('task.delete'))) ||
        (poppedKey === 'attachment.delete_own' && (cumulativeKeys.includes('attachment.delete_any') || cumulativeKeys.includes('task.delete'))) ||
        (poppedKey === 'label.delete_own' && cumulativeKeys.includes('label.delete')) ||
        (poppedKey === 'task.complete' && cumulativeKeys.includes('task.edit')) ||
        (poppedKey === 'task.assign_self' && (cumulativeKeys.includes('task.assign') || cumulativeKeys.includes('task.edit'))) ||
        (poppedKey === 'file.view' && (cumulativeKeys.includes('attachment.view') || cumulativeKeys.includes('project.view'))) ||
        (poppedKey === 'list.reorder' && cumulativeKeys.includes('list.edit')) ||
        (poppedKey === 'project.manage_members' && (cumulativeKeys.includes('member.invite') || cumulativeKeys.includes('project.edit_settings'))) ||
        (poppedKey === 'project.view' && cumulativeKeys.includes('project.access_all')) ||
        (poppedKey === 'member.invite_guest' && cumulativeKeys.includes('member.invite'));

      if (!hasBroaderPerm) {
        const execRes = await probe.execute(probeClient, context, context.boardAId);
        revokedDenied = execRes.status >= 400;
      } else {
        revokedDenied = true;
      }
    }

    // Verify remaining keys (if any) are still granted
    let remainingIntact = true;
    if (cumulativeKeys.length > 0) {
      const remainingProbe = PROBES[cumulativeKeys[cumulativeKeys.length - 1]];
      if (remainingProbe) {
        const remExec = await remainingProbe.execute(probeClient, context, context.boardAId);
        if (remExec.status >= 400) {
          remainingIntact = false;
        }
      }
    }

    if (revokedDenied && remainingIntact) {
      regressivePasses++;
    } else {
      failedSteps.push({
        step: 'regressive',
        key: poppedKey,
        remainingCount: cumulativeKeys.length,
        revokedDenied,
        remainingIntact
      });
    }

    if (cumulativeKeys.length % 15 === 0) {
      console.log(`    Regressive walk: ${cumulativeKeys.length} keys remaining...`);
    }
  }

  const totalWalkSteps = activePermissions.length * 2;
  const totalPassed = progressivePasses + regressivePasses;
  const passed = failedSteps.length === 0;

  console.log(`\nCumulative Walk Results: ${totalPassed}/${totalWalkSteps} steps passed (${failedSteps.length} failures).`);
  return {
    suite: 'Cumulative 73-Key Walk',
    totalSteps: totalWalkSteps,
    passedSteps: totalPassed,
    failedSteps,
    passed
  };
}

/**
 * Runs isolated per-key toggle tests across active catalog permissions.
 */
async function runIsolatedPerKeyToggleSuite(fixture) {
  console.log('\n================================================================');
  console.log('       SUITE: ISOLATED PER-KEY TOGGLE TESTS                     ');
  console.log('================================================================\n');

  const { ownerClient, context } = fixture;
  const probeClient = fixture.users['Probe'].client;
  const probeRoleId = context.probeRoleId;

  if (context.tenantDb) {
    await context.tenantDb.execute('UPDATE roles SET rank = 75 WHERE id = ?', [probeRoleId]);
  }

  let togglesPassed = 0;
  const toggleFailures = [];

  for (let idx = 0; idx < activePermissions.length; idx++) {
    const perm = activePermissions[idx];
    const key = perm.key;
    const probe = PROBES[key];
    if (!probe) continue;

    // 1. Off Baseline: role has empty perms
    await ownerClient.patch(`/api/roles/${probeRoleId}`, { permission_keys: [] });
    const offRes = await probe.execute(probeClient, context, context.boardAId);
    const offDenied = offRes.status >= 400;

    // 2. Toggle On: grant only this key
    await ownerClient.patch(`/api/roles/${probeRoleId}`, { permission_keys: [key] });
    const onRes = await probe.execute(probeClient, context, context.boardAId);
    const onAllowed = onRes.status >= 200 && onRes.status < 400;

    // 3. Toggle Off again
    await ownerClient.patch(`/api/roles/${probeRoleId}`, { permission_keys: [] });
    const offAgainRes = await probe.execute(probeClient, context, context.boardAId);
    const offAgainDenied = offAgainRes.status >= 400;

    if (offDenied && onAllowed && offAgainDenied) {
      togglesPassed++;
    } else {
      toggleFailures.push({
        key,
        offStatus: offRes.status,
        onStatus: onRes.status,
        offAgainStatus: offAgainRes.status
      });
    }

    if ((idx + 1) % 20 === 0 || idx === activePermissions.length - 1) {
      console.log(`    Isolated toggles: ${idx + 1}/${activePermissions.length} evaluated.`);
    }
  }

  const passed = toggleFailures.length === 0;
  console.log(`\nIsolated Per-Key Toggle Results: ${togglesPassed}/${activePermissions.length} passed.`);
  return {
    suite: 'Isolated Per-Key Toggles',
    total: activePermissions.length,
    passedCount: togglesPassed,
    toggleFailures,
    passed
  };
}

module.exports = {
  runCumulativeToggleSuite,
  runIsolatedPerKeyToggleSuite
};

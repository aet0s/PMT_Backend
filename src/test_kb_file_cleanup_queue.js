// server/src/test_kb_file_cleanup_queue.js
// Tests for Follow-Up 5: Persistent file cleanup retry queue, restart survival, and attempt capping
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const {
  queueFileCleanupRetry,
  processFileCleanupQueue,
  stopCleanupWorker,
  ensureCleanupTable
} = require('./utils/fileCleanupQueue');
const { getDevSingleDb } = require('./services/tenantPools');

process.env.DEV_SINGLE_TENANT = '1';
process.env.MYSQL_DATABASE = 'pm_dev_single';

async function runQueueTest() {
  console.log('=== Running K-B Follow-up 5: Persistent File Cleanup Queue Tests ===\n');

  const db = getDevSingleDb();
  await ensureCleanupTable();

  const tempDir = path.join(__dirname, '../uploads/test_cleanup_queue');
  fs.mkdirSync(tempDir, { recursive: true });

  const testFile1 = path.join(tempDir, `test_file_restart_${Date.now()}.txt`);
  fs.writeFileSync(testFile1, 'Temporary file for restart survival test');
  assert(fs.existsSync(testFile1), 'Test file must exist initially');

  try {
    // 1. Enqueue file cleanup
    console.log('1. Enqueueing file cleanup...');
    await queueFileCleanupRetry(testFile1, 1);

    // 2. Query DB directly to verify persistence
    const [rows] = await db.query(
      `SELECT * FROM file_cleanup_queue WHERE file_path = ? AND status = 'pending'`,
      [testFile1]
    );
    assert(rows, 'Queue item must be found in database');
    assert.strictEqual(rows.status, 'pending', 'Status must be pending');
    assert.strictEqual(rows.attempts, 0, 'Initial attempts must be 0');
    console.log(`✓ Verified: Queue item persisted in database (Row ID: ${rows.id}).`);

    // 3. Simulate Server Shutdown (Stop Worker)
    console.log('2. Simulating server shutdown (stop worker)...');
    stopCleanupWorker();

    // 4. Assert row survived shutdown in database
    const [survivedRows] = await db.query(
      `SELECT * FROM file_cleanup_queue WHERE id = ?`,
      [rows.id]
    );
    assert(survivedRows, 'Row must still exist in DB after shutdown');
    assert.strictEqual(survivedRows.status, 'pending');
    console.log('✓ Verified: Queue item survived server restart in database.');

    // 5. Simulate Server Boot (processFileCleanupQueue runs on startup)
    console.log('3. Simulating server boot processing...');
    await processFileCleanupQueue();

    // 6. Verify file is deleted and status is completed
    assert.strictEqual(fs.existsSync(testFile1), false, 'File must be deleted after queue processing');
    const [completedRows] = await db.query(
      `SELECT * FROM file_cleanup_queue WHERE id = ?`,
      [rows.id]
    );
    assert.strictEqual(completedRows.status, 'completed', 'Queue status must be updated to completed');
    console.log('✓ Verified: File was unlinked on boot and marked completed.');

    // 7. Test attempt capping (up to 5 attempts then marked failed)
    console.log('\n4. Testing attempt capping and failure logging...');
    const nonExistentForbiddenPath = 'C:\\forbidden\\non_existent_system_dir\\file.txt';
    // Insert with attempts = 4, max_attempts = 5
    const insRes = await db.query(
      `INSERT INTO file_cleanup_queue (tenant_id, file_path, attempts, max_attempts, next_run_at, status)
       VALUES (1, ?, 4, 5, NOW(), 'pending')`,
      [nonExistentForbiddenPath]
    );
    const failItemId = insRes.insertId;

    // Process: since file doesn't exist, fs.unlink isn't called, but let's test a file that throws an unlink error:
    // To trigger an unlink error in node on Windows, create a directory and try fs.unlinkSync on it!
    const lockDir = path.join(tempDir, `locked_dir_${Date.now()}`);
    fs.mkdirSync(lockDir, { recursive: true });

    const dirRes = await db.query(
      `INSERT INTO file_cleanup_queue (tenant_id, file_path, attempts, max_attempts, next_run_at, status)
       VALUES (1, ?, 4, 5, NOW(), 'pending')`,
      [lockDir]
    );
    const dirItemId = dirRes.insertId;

    await processFileCleanupQueue();

    const [failedRow] = await db.query(
      `SELECT * FROM file_cleanup_queue WHERE id = ?`,
      [dirItemId]
    );
    assert.strictEqual(failedRow.attempts, 5, 'Attempts must reach 5');
    assert.strictEqual(failedRow.status, 'failed', 'Row must be capped and marked failed after 5 attempts');
    assert(failedRow.error_message, 'Error message must be logged');
    console.log(`✓ Verified: Item reached max_attempts (5), marked status='failed', error recorded: "${failedRow.error_message}".`);

    // Cleanup test dir
    try { fs.rmdirSync(lockDir); } catch {}

    console.log('\n===============================================');
    console.log('K-B FOLLOW-UP 5 FILE CLEANUP QUEUE TESTS PASSED!');
    console.log('===============================================\n');
  } finally {
    stopCleanupWorker();
    if (fs.existsSync(tempDir)) {
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
    }
  }
}

runQueueTest()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Queue test failed:', err);
    process.exit(1);
  });

// Tests for the #279 SQLite backup helper.
//
// Coverage:
//   - row counts match source minus excluded tables (default + opt-in)
//   - metadata fields populated correctly
//   - excluded tables empty in the output
//   - --include-audit / --include-prompts preserve their data
//   - destination file is 0o600
//   - refuses to overwrite an existing destination
//   - backup runs concurrently with a write-heavy goroutine (online
//     backup property test)
//   - round-trip: backup → restore → backup again produces backups
//     whose USER-table row counts are identical (byte-equality is too
//     strict for sqlite's b-tree representation across two VACUUM
//     passes; we assert the per-table counts + the metadata roundtrip)

package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/rules"
)

// seedSourceForBackup populates a scratchStore with a representative
// mix of rows across every user table the backup-default set ships.
func seedSourceForBackup(t *testing.T, s *Store) {
	t.Helper()

	// rules (3 rows)
	for _, p := range []string{
		"SELECT:public.users",
		"INSERT:public.orders",
		"DELETE:secrets_*",
	} {
		_, err := s.AddRule(rules.ProxyRule{
			Pattern: p, Effect: rules.EffectAllow, Origin: rules.OriginUser,
		})
		require.NoError(t, err)
	}

	// decisions (5 rows)
	for i := 0; i < 5; i++ {
		_, err := s.RecordDecision(DecisionRow{
			At:              time.Now().UTC(),
			Dialect:         "postgres",
			Statement:       "SELECT 1",
			StatementType:   "SELECT",
			DecisionVerdict: "ALLOW",
			DecisionReason:  "seed",
			ModeAtDecision:  "cooperative",
		})
		require.NoError(t, err)
	}

	// pending_audit_events (2 rows)
	for i := 0; i < 2; i++ {
		_, err := s.AddPendingAuditEvent(
			PendingAuditEventAdminAction, `{"action":"seed"}`)
		require.NoError(t, err)
	}

	// pending_prompts (1 row) — requires an existing decision row id for
	// the FK constraint enabled at connection open.
	var firstDecisionID int64
	require.NoError(t, s.db.QueryRow(
		"SELECT id FROM decisions ORDER BY id LIMIT 1").Scan(&firstDecisionID))
	_, err := s.db.Exec(
		`INSERT INTO pending_prompts(
			created_at, decision_id, deny_reason, status
		) VALUES (?, ?, ?, 'pending')`,
		time.Now().UTC().Format(time.RFC3339),
		firstDecisionID, "seeded deny")
	require.NoError(t, err)
}

func TestBackup_DefaultExcludesHighVolumeTables(t *testing.T) {
	src := scratchStore(t)
	seedSourceForBackup(t, src)

	dir := t.TempDir()
	dst := filepath.Join(dir, "backup.db")
	meta, err := src.Backup(dst, BackupOptions{
		DbounceVersion: "v1.0.0-test",
		Hostname:       "test-host",
	})
	require.NoError(t, err)
	require.NotNil(t, meta)

	counts, err := CountRowsByTable(dst)
	require.NoError(t, err)

	// Default opt-out tables are EMPTY (preserved schema, no rows).
	assert.Equal(t, int64(0), counts["pending_audit_events"],
		"default backup MUST exclude pending_audit_events rows")
	assert.Equal(t, int64(0), counts["pending_prompts"],
		"default backup MUST exclude pending_prompts rows")

	// Kept tables retain their source counts.
	assert.Equal(t, int64(3), counts["rules"], "rules count preserved")
	assert.Equal(t, int64(5), counts["decisions"], "decisions count preserved")

	// Metadata table is present + carries the right flags.
	assert.Equal(t, int64(1), counts[backupMetadataTable],
		"backup file MUST embed the metadata row")
	assert.False(t, meta.IncludedAudit)
	assert.False(t, meta.IncludedPrompts)
	assert.Equal(t, "v1.0.0-test", meta.DbounceVersion)
	assert.Equal(t, SchemaVersion, meta.SchemaVersion)
	assert.NotEmpty(t, meta.SourceHostnameHash)
	assert.Len(t, meta.SourceHostnameHash, 12,
		"source_hostname_hash MUST be sha256[:12] per the spec")
	assert.WithinDuration(t, time.Now(), meta.CreatedAt, 5*time.Second)
}

func TestBackup_IncludeAuditFlagShipsTheTable(t *testing.T) {
	src := scratchStore(t)
	seedSourceForBackup(t, src)

	dir := t.TempDir()
	dst := filepath.Join(dir, "backup-with-audit.db")
	meta, err := src.Backup(dst, BackupOptions{
		IncludeAudit:   true,
		DbounceVersion: "v1.0.0-test",
		Hostname:       "test-host",
	})
	require.NoError(t, err)
	assert.True(t, meta.IncludedAudit)

	counts, err := CountRowsByTable(dst)
	require.NoError(t, err)
	assert.Equal(t, int64(2), counts["pending_audit_events"],
		"--include-audit MUST preserve pending_audit_events rows")
	// pending_prompts still excluded (no opt-in).
	assert.Equal(t, int64(0), counts["pending_prompts"])
}

func TestBackup_IncludePromptsFlagShipsTheTable(t *testing.T) {
	src := scratchStore(t)
	seedSourceForBackup(t, src)

	dir := t.TempDir()
	dst := filepath.Join(dir, "backup-with-prompts.db")
	meta, err := src.Backup(dst, BackupOptions{
		IncludePrompts: true,
		DbounceVersion: "v1.0.0-test",
		Hostname:       "test-host",
	})
	require.NoError(t, err)
	assert.True(t, meta.IncludedPrompts)

	counts, err := CountRowsByTable(dst)
	require.NoError(t, err)
	assert.Equal(t, int64(1), counts["pending_prompts"],
		"--include-prompts MUST preserve pending_prompts rows")
	// pending_audit_events still excluded (no opt-in).
	assert.Equal(t, int64(0), counts["pending_audit_events"])
}

func TestBackup_DestinationFilePermissions(t *testing.T) {
	src := scratchStore(t)
	seedSourceForBackup(t, src)

	dir := t.TempDir()
	dst := filepath.Join(dir, "backup.db")
	_, err := src.Backup(dst, BackupOptions{
		DbounceVersion: "v1.0.0-test",
		Hostname:       "test-host",
	})
	require.NoError(t, err)

	info, err := os.Stat(dst)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"backup file MUST be 0o600 (mirrors source DB privacy)")
}

func TestBackup_RefusesToOverwriteExistingFile(t *testing.T) {
	src := scratchStore(t)
	seedSourceForBackup(t, src)

	dir := t.TempDir()
	dst := filepath.Join(dir, "backup.db")
	// First backup succeeds.
	_, err := src.Backup(dst, BackupOptions{DbounceVersion: "v1"})
	require.NoError(t, err)
	// Second backup to the same path must refuse.
	_, err = src.Backup(dst, BackupOptions{DbounceVersion: "v1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to overwrite")
}

func TestBackup_ConcurrentWritesDuringBackup(t *testing.T) {
	// Online-backup property test: while a backup is running, a parallel
	// goroutine hammers the source DB with writes. The backup MUST
	// complete + the source MUST contain all written rows after the
	// backup returns.
	src := scratchStore(t)
	seedSourceForBackup(t, src)

	stop := make(chan struct{})
	var written int64
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := src.RecordDecision(DecisionRow{
				At:              time.Now().UTC(),
				Dialect:         "postgres",
				Statement:       "SELECT now()",
				StatementType:   "SELECT",
				DecisionVerdict: "ALLOW",
				DecisionReason:  "concurrent-writer",
				ModeAtDecision:  "cooperative",
			}); err == nil {
				atomic.AddInt64(&written, 1)
			}
		}
	}()
	// Give the writer a moment to ramp up so the backup overlaps real
	// concurrent activity.
	time.Sleep(50 * time.Millisecond)

	dir := t.TempDir()
	dst := filepath.Join(dir, "backup-concurrent.db")
	_, err := src.Backup(dst, BackupOptions{DbounceVersion: "v1"})
	require.NoError(t, err)

	close(stop)
	wg.Wait()

	// Backup completed; source still has at least the seeded rows + the
	// concurrent writes.
	srcCount, err := src.CountDecisions()
	require.NoError(t, err)
	w := atomic.LoadInt64(&written)
	assert.GreaterOrEqual(t, srcCount, int64(5)+w,
		"source DB MUST contain seeded rows + concurrent writes after backup returns")

	// Backup file's decisions count is a snapshot AT some point during
	// the run — bounded between the pre-backup count (5) and the
	// post-backup source count.
	dstCounts, err := CountRowsByTable(dst)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, dstCounts["decisions"], int64(5),
		"backup file MUST contain at least the seeded rows")
	assert.LessOrEqual(t, dstCounts["decisions"], srcCount,
		"backup file MUST NOT contain MORE rows than the source ends with")
}

func TestBackup_RoundTrip_BackupRestoreBackupPreservesCounts(t *testing.T) {
	// Round-trip property: backup → restore-into-fresh-db → backup
	// again. The second backup's per-table row counts MUST match the
	// first backup's per-table row counts (we don't assert byte-identity
	// because SQLite's b-tree pagination + VACUUM rebuild may legitimately
	// reshape the file even with identical logical content).
	src := scratchStore(t)
	seedSourceForBackup(t, src)

	dir := t.TempDir()
	backup1 := filepath.Join(dir, "backup1.db")
	_, err := src.Backup(backup1, BackupOptions{
		DbounceVersion: "v1.0.0-test",
		Hostname:       "test-host",
	})
	require.NoError(t, err)

	// Restore backup1 onto a fresh destination path. Use ProbePorts:[]
	// to skip the running-process probe (this test environment may have
	// real services bound on the default ports).
	fresh := filepath.Join(dir, "restored.db")
	_, _, rerr := Restore(backup1, fresh, RestoreOptions{
		DbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{}, // skip probe
	})
	require.NoError(t, rerr)

	// Re-open the restored DB + back IT up.
	restored, err := Open(fresh)
	require.NoError(t, err)
	defer restored.Close()
	backup2 := filepath.Join(dir, "backup2.db")
	_, err = restored.Backup(backup2, BackupOptions{
		DbounceVersion: "v1.0.0-test",
		Hostname:       "test-host",
	})
	require.NoError(t, err)

	counts1, err := CountRowsByTable(backup1)
	require.NoError(t, err)
	counts2, err := CountRowsByTable(backup2)
	require.NoError(t, err)

	// Per-user-table row counts MUST match (excluding the metadata table
	// which is regenerated on each backup).
	for table, count := range counts1 {
		if table == backupMetadataTable {
			// Metadata is always 1 row on both — but compare anyway.
		}
		assert.Equal(t, count, counts2[table],
			"round-trip backup MUST preserve row count for table %s", table)
	}
	for table := range counts2 {
		_, ok := counts1[table]
		assert.True(t, ok, "round-trip MUST NOT add new tables (saw %s only in backup2)", table)
	}
}

func TestBackup_IncludeAuditRoundTripPreservesRows(t *testing.T) {
	// Targeted assertion from the #279 spec: "Backup with --include-audit
	// captures pending_audit_events; round-trip preserves them."
	src := scratchStore(t)
	seedSourceForBackup(t, src)

	dir := t.TempDir()
	backup := filepath.Join(dir, "backup-audit.db")
	_, err := src.Backup(backup, BackupOptions{
		IncludeAudit:   true,
		DbounceVersion: "v1",
	})
	require.NoError(t, err)

	dst := filepath.Join(dir, "restored.db")
	_, _, err = Restore(backup, dst, RestoreOptions{
		DbounceVersion: "v1",
		ProbePorts:     []HostPort{}, // skip probe
	})
	require.NoError(t, err)

	restored, err := Open(dst)
	require.NoError(t, err)
	defer restored.Close()

	// Sanity: pending_audit_events row count survived the round-trip.
	var n int64
	require.NoError(t, restored.db.QueryRow(
		"SELECT COUNT(*) FROM pending_audit_events").Scan(&n))
	assert.Equal(t, int64(2), n,
		"--include-audit round-trip MUST preserve pending_audit_events rows")
}

func TestReadBackupMetadata_OnNonBackupFile(t *testing.T) {
	// A SQLite database that is NOT a dbounce backup file (no
	// dbounce_backup_metadata table) MUST return a friendly error
	// pointing at the missing table.
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.db")
	db, err := sql.Open("sqlite",
		"file:"+plain+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE unrelated (x INTEGER)`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	_, err = ReadBackupMetadata(plain)
	require.Error(t, err)
	assert.Contains(t, err.Error(), backupMetadataTable)
	assert.Contains(t, err.Error(), "dbounce backup file")
}

func TestHashHostname_DeterministicAndBounded(t *testing.T) {
	a := hashHostname("my-prod-host-01")
	b := hashHostname("my-prod-host-01")
	c := hashHostname("my-prod-host-02")
	assert.Equal(t, a, b)
	assert.NotEqual(t, a, c)
	assert.Len(t, a, 12)
	// Empty hostname → empty hash so the metadata stays informative.
	assert.Empty(t, hashHostname(""))
}

func TestFileSHA256_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	require.NoError(t, os.WriteFile(path, []byte("hello dbounce"), 0o600))
	sum, err := FileSHA256(path)
	require.NoError(t, err)
	// Pin: known sha256 of "hello dbounce" so the helper's correctness
	// doesn't drift silently.
	assert.Equal(t,
		"1a179b37506fcc00f1fe1f70f715cb20940d43859fec53abab16fd4e5a705ab0",
		sum)
}

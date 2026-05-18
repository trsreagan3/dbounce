// Tests for the #279 SQLite restore helper.
//
// Coverage:
//   - restore into empty DB succeeds + post-restore row counts match
//   - restore into non-empty DB without --force fails (ErrDestinationNotEmpty)
//   - restore with --force into non-empty DB succeeds + replaces content
//   - restore with mismatched schema_version fails (even with --force)
//   - restore with mismatched dbounce_version warns + succeeds with --force
//   - restore with running-process probe hitting an alive port refuses
//   - restore from a non-backup file refuses with a friendly error

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/rules"
)

func backupFromFresh(t *testing.T, opts BackupOptions) (string, *Store) {
	t.Helper()
	src := scratchStore(t)
	seedSourceForBackup(t, src)

	dir := t.TempDir()
	backup := filepath.Join(dir, "snapshot.db")
	if opts.DbounceVersion == "" {
		opts.DbounceVersion = "v1.0.0-test"
	}
	_, err := src.Backup(backup, opts)
	require.NoError(t, err)
	return backup, src
}

func TestRestore_IntoEmptyDestinationSucceeds(t *testing.T) {
	backup, _ := backupFromFresh(t, BackupOptions{})

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	result, warn, err := Restore(backup, dst, RestoreOptions{
		DbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{}, // skip probe
	})
	require.NoError(t, err)
	assert.Nil(t, warn)
	require.NotNil(t, result)

	// Row counts surfaced + a non-empty sha256.
	assert.NotEmpty(t, result.SHA256)
	assert.GreaterOrEqual(t, result.RowCounts["rules"], int64(3))
	assert.GreaterOrEqual(t, result.RowCounts["decisions"], int64(5))
}

func TestRestore_IntoPopulatedDestinationRefusesWithoutForce(t *testing.T) {
	backup, _ := backupFromFresh(t, BackupOptions{})

	// Populate the destination with a fresh store + seeded rows.
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	st, err := Open(dst)
	require.NoError(t, err)
	_, err = st.AddRule(rules.ProxyRule{
		Pattern: "SELECT:public.foo", Effect: rules.EffectAllow,
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	_, _, err = Restore(backup, dst, RestoreOptions{
		DbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDestinationNotEmpty)
}

func TestRestore_IntoPopulatedDestinationWithForceReplacesContent(t *testing.T) {
	backup, _ := backupFromFresh(t, BackupOptions{})

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	st, err := Open(dst)
	require.NoError(t, err)
	_, err = st.AddRule(rules.ProxyRule{
		Pattern: "SELECT:public.before", Effect: rules.EffectAllow,
		Note: "should be wiped by restore",
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	result, _, err := Restore(backup, dst, RestoreOptions{
		Force:          true,
		DbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// After restore the seeded rules from the backup are present; the
	// pre-restore "public.before" rule is gone.
	restored, err := Open(dst)
	require.NoError(t, err)
	defer restored.Close()
	rs, err := restored.ListRules()
	require.NoError(t, err)
	patterns := make([]string, 0, len(rs))
	for _, r := range rs {
		patterns = append(patterns, r.Rule.Pattern)
	}
	assert.NotContains(t, patterns, "SELECT:public.before",
		"restore --force MUST replace pre-restore content")
	assert.Contains(t, patterns, "SELECT:public.users",
		"restore MUST install the backup's rules")
}

func TestRestore_SchemaVersionMismatchRefused(t *testing.T) {
	// Build a "backup" with the metadata table claiming a
	// schema_version that does NOT match the running binary.
	backup, _ := backupFromFresh(t, BackupOptions{})

	// Open the backup file directly + overwrite the schema_version row
	// to simulate a cross-schema backup.
	db, err := sql.Open("sqlite",
		"file:"+backup+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	_, err = db.Exec(
		`UPDATE `+backupMetadataTable+` SET schema_version = ?`,
		SchemaVersion+1)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	_, _, err = Restore(backup, dst, RestoreOptions{
		Force:          true, // even with force
		DbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSchemaVersionMismatch,
		"schema_version mismatch MUST refuse even with --force")
}

func TestRestore_DbounceVersionMismatchWarnsAndRequiresForce(t *testing.T) {
	backup, _ := backupFromFresh(t, BackupOptions{
		DbounceVersion: "v1.0.0-test",
	})

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")

	// First attempt WITHOUT --force: surfaces the warning + errors.
	_, warn, err := Restore(backup, dst, RestoreOptions{
		DbounceVersion: "v1.1.0-test", // mismatch
		ProbePorts:     []HostPort{},
	})
	require.Error(t, err)
	require.NotNil(t, warn)
	assert.Equal(t, "v1.0.0-test", warn.BackupVersion)
	assert.Equal(t, "v1.1.0-test", warn.RunningVersion)
	assert.Contains(t, err.Error(), "dbounce_version mismatch")
	assert.Contains(t, err.Error(), "--force")

	// Second attempt WITH --force: warning surfaces + restore succeeds.
	dst2 := filepath.Join(dir, "dst2.db")
	result, warn2, err := Restore(backup, dst2, RestoreOptions{
		Force:          true,
		DbounceVersion: "v1.1.0-test",
		ProbePorts:     []HostPort{},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, warn2)
	assert.Contains(t, warn2.String(), "v1.0.0-test")
	assert.Contains(t, warn2.String(), "v1.1.0-test")
}

func TestRestore_RunningProcessProbeRefuses(t *testing.T) {
	backup, _ := backupFromFresh(t, BackupOptions{})

	// Start a real listener on a random port + tell Restore to probe it.
	// This simulates "dbounce run is already up" without depending on
	// the real default ports being available in the test env.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	_, _, err = Restore(backup, dst, RestoreOptions{
		DbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{{Host: "127.0.0.1", Port: port}},
		ProbeTimeout:   500 * time.Millisecond,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDbounceRunning)
	assert.Contains(t, err.Error(), fmt.Sprintf("%d", port),
		"error MUST name the port the probe hit")
}

func TestRestore_RunningProcessProbeSkippedWhenPortListEmpty(t *testing.T) {
	// Empty (non-nil) ProbePorts skips the probe entirely. nil ProbePorts
	// triggers the default-loopback set; tests that need to skip pass
	// []HostPort{} explicitly.
	backup, _ := backupFromFresh(t, BackupOptions{})

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	_, _, err := Restore(backup, dst, RestoreOptions{
		DbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	require.NoError(t, err)
}

func TestRestore_SourceNotABackupFileRefused(t *testing.T) {
	// A valid SQLite database that lacks the metadata table is refused
	// with a friendly "is this a dbounce backup file?" error.
	dir := t.TempDir()
	notABackup := filepath.Join(dir, "unrelated.db")
	db, err := sql.Open("sqlite",
		"file:"+notABackup+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE other (x INTEGER)`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	dst := filepath.Join(dir, "dst.db")
	_, _, err = Restore(notABackup, dst, RestoreOptions{
		DbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), backupMetadataTable)
}

func TestRestore_SourceFileMissingRefused(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	_, _, err := Restore(filepath.Join(dir, "nope.db"), dst, RestoreOptions{
		DbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, errSpaceFiller{}) || // never matches; keeps test future-proof
			err.Error() != "",
		"non-empty error required")
	assert.Contains(t, err.Error(), "source")
}

// errSpaceFiller is a no-op sentinel used in TestRestore_SourceFileMissing
// to keep the assertion expressive without depending on a specific
// wrapped-error chain.
type errSpaceFiller struct{}

func (errSpaceFiller) Error() string { return "space-filler" }

func TestRestore_PostRestoreSchemaVersionStamped(t *testing.T) {
	// After restore, opening the destination via Store.Open MUST
	// succeed + the schema_version row MUST be present (the migrate
	// path is idempotent + survives the restore's wholesale file
	// replacement).
	backup, _ := backupFromFresh(t, BackupOptions{})

	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	_, _, err := Restore(backup, dst, RestoreOptions{
		DbounceVersion: "v1.0.0-test",
		ProbePorts:     []HostPort{},
	})
	require.NoError(t, err)

	st, err := Open(dst)
	require.NoError(t, err)
	defer st.Close()

	var v int
	require.NoError(t, st.db.QueryRow(
		`SELECT version FROM schema_version LIMIT 1`).Scan(&v))
	assert.Equal(t, SchemaVersion, v,
		"post-restore schema_version row MUST be present + match the binary")
}

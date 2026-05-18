// Tests for `dbounce backup` + `dbounce restore` CLI surfaces per #279.
//
// Coverage:
//   - root cobra command wires both subcommands
//   - backup writes a file at --out + prints summary lines
//   - backup default filename includes a UTC RFC3339-ish timestamp
//   - restore --in REQUIRED
//   - restore succeeds end-to-end from a backup of a populated DB
//   - restore refuses without --force when destination has rows
//   - restore refuses + names port on a running-process probe hit

package cli

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

func TestRootCmd_WiresBackupAndRestore(t *testing.T) {
	r := newRootCmd()
	subs := map[string]bool{}
	for _, c := range r.Commands() {
		subs[c.Name()] = true
	}
	assert.True(t, subs["backup"], "root cobra MUST wire `dbounce backup`")
	assert.True(t, subs["restore"], "root cobra MUST wire `dbounce restore`")
}

func seedCLIStore(t *testing.T, dbPath string) {
	t.Helper()
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()
	_, err = st.AddRule(dbrules.ProxyRule{
		Pattern: "SELECT:public.users",
		Effect:  dbrules.EffectAllow,
		Origin:  dbrules.OriginUser,
	})
	require.NoError(t, err)
}

func TestBackupCmd_WritesFileAndPrintsSummary(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	seedCLIStore(t, dbPath)

	out := filepath.Join(dir, "backup.db")
	cmd := newBackupCmd()
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--out", out,
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	require.NoError(t, cmd.Execute())

	// File exists.
	_, err := os.Stat(out)
	require.NoError(t, err, "backup file MUST be on disk")

	// Summary lines mention schema_version + the metadata fields.
	s := stdout.String()
	assert.Contains(t, s, "wrote dbounce backup to")
	assert.Contains(t, s, "schema_version=")
	assert.Contains(t, s, "included_audit=false")
	assert.Contains(t, s, "included_prompts=false")
	assert.Contains(t, s, "tables:")
	assert.Contains(t, s, "rules")
}

func TestBackupCmd_IncludeAuditShipsTable(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	seedCLIStore(t, dbPath)

	// Seed a pending_audit_events row so the include test has signal.
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	_, err = st.AddPendingAuditEvent(
		store.PendingAuditEventAdminAction, `{"action":"seed"}`)
	require.NoError(t, err)
	require.NoError(t, st.Close())

	out := filepath.Join(dir, "with-audit.db")
	cmd := newBackupCmd()
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--out", out,
		"--include-audit",
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	require.NoError(t, cmd.Execute())

	assert.Contains(t, stdout.String(), "included_audit=true")
	counts, err := store.CountRowsByTable(out)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, counts["pending_audit_events"], int64(1))
}

func TestBackupCmd_DefaultFilenameTimestamped(t *testing.T) {
	ts := defaultBackupFilename(false)
	assert.True(t, strings.HasPrefix(ts, "dbounce-backup-"),
		"default filename MUST be dbounce-backup-<timestamp>.db")
	assert.True(t, strings.HasSuffix(ts, ".db"))
	// Pin: no-timestamp shape stays stable for CI managers.
	assert.Equal(t, "dbounce-backup.db", defaultBackupFilename(true))
}

func TestRestoreCmd_RequiresInFlag(t *testing.T) {
	cmd := newRestoreCmd()
	cmd.SetArgs([]string{}) // no --in
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.Execute()
	require.Error(t, err)
	// Cobra's required-flag error pattern.
	assert.Contains(t, err.Error(), "in")
}

func TestRestoreCmd_RoundTripFromBackup(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.db")
	seedCLIStore(t, srcPath)

	// Backup via the CLI surface (exercises the same write path the
	// operator hits).
	backupOut := filepath.Join(dir, "backup.db")
	backup := newBackupCmd()
	backup.SetArgs([]string{
		"--db", srcPath,
		"--out", backupOut,
	})
	var bOut, bErr bytes.Buffer
	backup.SetOut(&bOut)
	backup.SetErr(&bErr)
	require.NoError(t, backup.Execute())

	// Restore into a fresh destination path.
	dst := filepath.Join(dir, "restored.db")
	restore := newRestoreCmd()
	restore.SetArgs([]string{
		"--in", backupOut,
		"--db", dst,
		"--probe-skip",
	})
	var rOut, rErr bytes.Buffer
	restore.SetOut(&rOut)
	restore.SetErr(&rErr)
	require.NoError(t, restore.Execute())
	assert.Contains(t, rOut.String(), "restored dbounce state.db from")
	assert.Contains(t, rOut.String(), "sha256:")
	assert.Contains(t, rOut.String(), "rules")

	// Validate the restored DB has the seeded rule.
	st, err := store.Open(dst)
	require.NoError(t, err)
	defer st.Close()
	rs, err := st.ListRules()
	require.NoError(t, err)
	patterns := make([]string, 0, len(rs))
	for _, r := range rs {
		patterns = append(patterns, r.Rule.Pattern)
	}
	assert.Contains(t, patterns, "SELECT:public.users")
}

func TestRestoreCmd_RefusesPopulatedDestinationWithoutForce(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.db")
	seedCLIStore(t, srcPath)

	backupOut := filepath.Join(dir, "backup.db")
	st, err := store.Open(srcPath)
	require.NoError(t, err)
	// Pin the backup's stamped version to whatever the test-binary's
	// package-level `version` is so the version-match gate doesn't
	// fire ahead of the gate we're actually exercising.
	_, err = st.Backup(backupOut, store.BackupOptions{DbounceVersion: version})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	// Populate the destination so the gate trips.
	dst := filepath.Join(dir, "dst.db")
	dstSt, err := store.Open(dst)
	require.NoError(t, err)
	_, err = dstSt.AddRule(dbrules.ProxyRule{
		Pattern: "SELECT:public.before", Effect: dbrules.EffectAllow,
	})
	require.NoError(t, err)
	require.NoError(t, dstSt.Close())

	cmd := newRestoreCmd()
	cmd.SetArgs([]string{
		"--in", backupOut,
		"--db", dst,
		"--probe-skip",
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "destination database is not empty")
	assert.Contains(t, err.Error(), "--force")
}

func TestRestoreCmd_ProbePortRefusesWhenAlive(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.db")
	seedCLIStore(t, srcPath)

	backupOut := filepath.Join(dir, "backup.db")
	st, err := store.Open(srcPath)
	require.NoError(t, err)
	// Pin the backup's stamped version to whatever the test-binary's
	// package-level `version` is so the version-match gate doesn't
	// fire ahead of the gate we're actually exercising.
	_, err = st.Backup(backupOut, store.BackupOptions{DbounceVersion: version})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	// Open a random loopback port + point the probe at it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	dst := filepath.Join(dir, "dst.db")
	cmd := newRestoreCmd()
	cmd.SetArgs([]string{
		"--in", backupOut,
		"--db", dst,
		"--probe-port", fmt.Sprintf("%d", port),
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "appears to be running")
	assert.Contains(t, err.Error(), fmt.Sprintf("%d", port))
}

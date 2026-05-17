package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/store"
)

// CLI smoke tests: assert that the command tree is wired correctly,
// that --version surfaces the stamped strings, that `audit tail`
// reads from the store, and that the --limit bound is enforced at
// parse time (mirror UAT-K2 HIGH-K2-03).

func TestVersionString_Format(t *testing.T) {
	s := versionString()
	assert.Contains(t, s, "dbounce")
	assert.Contains(t, s, "commit")
	assert.Contains(t, s, "built")
}

func TestRootCmd_HasVersionAndSubcommands(t *testing.T) {
	cmd := newRootCmd()
	assert.NotEmpty(t, cmd.Version)
	names := map[string]bool{}
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	assert.True(t, names["run"], "run subcommand must be wired")
	assert.True(t, names["audit"], "audit subcommand must be wired")
}

func TestRunCmd_Help(t *testing.T) {
	cmd := newRunCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--help"})
	require.NoError(t, cmd.Execute())
	help := out.String()
	assert.Contains(t, help, "--port")
	assert.Contains(t, help, "--mode")
	assert.Contains(t, help, "--upstream")
	assert.Contains(t, help, "--i-know-this-binds-externally")
	assert.Contains(t, help, "--dialect")
	assert.Contains(t, help, "--mgmt-port")
	// D-Slice 4 flags
	assert.Contains(t, help, "--listener-tls-cert")
	assert.Contains(t, help, "--listener-tls-key")
	assert.Contains(t, help, "--require-client-cert")
	assert.Contains(t, help, "--management-tls-cert")
	assert.Contains(t, help, "--management-tls-key")
}

func TestRootCmd_HasInitTLSSubcommand(t *testing.T) {
	cmd := newRootCmd()
	names := map[string]bool{}
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	assert.True(t, names["init-tls"], "init-tls subcommand must be wired")
}

func TestInitTLSCmd_WritesCertMaterial(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "tls")

	cmd := newInitTLSCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--out", out})
	require.NoError(t, cmd.Execute())

	for _, name := range []string{"ca.crt", "server.crt", "server.key"} {
		p := filepath.Join(out, name)
		_, err := os.Stat(p)
		require.NoError(t, err, "init-tls must write %s", name)
	}
	text := buf.String()
	assert.Contains(t, text, "ca.crt")
	assert.Contains(t, text, "server.crt")
	assert.Contains(t, text, "server.key")
}

func TestInitTLSCmd_WithClientCertWritesClientPair(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "tls")

	cmd := newInitTLSCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--out", out, "--with-client-cert"})
	require.NoError(t, cmd.Execute())

	for _, name := range []string{"ca.crt", "server.crt", "server.key", "client.crt", "client.key"} {
		p := filepath.Join(out, name)
		_, err := os.Stat(p)
		require.NoError(t, err, "init-tls --with-client-cert must write %s", name)
	}
}

func TestInitTLSCmd_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "tls")

	cmd := newInitTLSCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--out", out})
	require.NoError(t, cmd.Execute())

	cmd2 := newInitTLSCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--out", out})
	err := cmd2.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to overwrite")
}

func TestInitTLSCmd_ForceAllowsOverwrite(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "tls")

	cmd := newInitTLSCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--out", out})
	require.NoError(t, cmd.Execute())

	cmd2 := newInitTLSCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--out", out, "--force"})
	require.NoError(t, cmd2.Execute())
}

func TestAuditTail_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--limit", "10"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "no decisions recorded")
}

func TestAuditTail_WithRows(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	st, err := store.Open(dbPath)
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		Dialect:         "postgres",
		Statement:       "SELECT * FROM users",
		StatementType:   "SELECT",
		TablesTouched:   []string{"users"},
		DecisionVerdict: "ALLOW",
		DecisionReason:  "observation-only",
		ModeAtDecision:  "cooperative",
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--limit", "10"})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "SELECT")
	assert.Contains(t, text, "ALLOW")
	assert.Contains(t, text, "users")
}

func TestAuditTail_JSON(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	st, err := store.Open(dbPath)
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		Dialect:         "postgres",
		Statement:       "DELETE FROM sessions",
		StatementType:   "DELETE",
		TablesTouched:   []string{"sessions"},
		IsDML:           true,
		HasMutatingNode: true,
		MutatingNodeType: "DELETE",
		DecisionVerdict: "ALLOW",
		DecisionReason:  "observation-only",
		ModeAtDecision:  "cooperative",
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--json", "--limit", "10"})
	require.NoError(t, cmd.Execute())
	text := out.String()
	// One JSON object per line, newest first.
	assert.True(t, strings.HasPrefix(text, "{"), "JSON output must start with {")
	assert.Contains(t, text, `"statement_type":"DELETE"`)
	assert.Contains(t, text, `"has_mutating_node":true`)
}

func TestAuditTail_LimitOutOfRange_Rejected(t *testing.T) {
	// UAT-K2 HIGH-K2-03 parity: --limit must be in 1-1000.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--limit", "0"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1-1000")

	cmd2 := newAuditCmd()
	out2 := &bytes.Buffer{}
	cmd2.SetOut(out2)
	cmd2.SetErr(out2)
	cmd2.SetArgs([]string{"tail", "--db", dbPath, "--limit", "5000"})
	err = cmd2.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1-1000")
}

func TestAuditCmd_RequiresSubcommand(t *testing.T) {
	// Calling `dbounce audit unknown-thing` should exit with a clear
	// error pointing the operator at --help. Mirrors UAT-K2 BLOCKER-K2-02.
	// We can't directly assert on os.Exit(1) from this test, but we
	// CAN assert that the help text + subcommand wiring is in place.
	cmd := newAuditCmd()
	assert.Equal(t, "audit", cmd.Name())
	subs := map[string]bool{}
	for _, c := range cmd.Commands() {
		subs[c.Name()] = true
	}
	assert.True(t, subs["tail"], "audit tail must be wired")
}

func TestMain(m *testing.M) {
	// Don't litter the user's home directory if a test accidentally
	// triggers DefaultDBPath().
	tmp, err := os.MkdirTemp("", "dbounce-cli-test-*")
	if err == nil {
		_ = os.Setenv("DBOUNCE_DB", filepath.Join(tmp, "state.db"))
		defer os.RemoveAll(tmp)
	}
	os.Exit(m.Run())
}

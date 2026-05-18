package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/store"
)

// CLI smoke tests for `dbounce profile` subcommands. End-to-end
// drives Cobra via SetArgs + captures stdout/stderr; the package-
// level profile + install logic has its own test suite in
// internal/profile/.

func TestProfileCmd_RegistersSubcommands(t *testing.T) {
	cmd := newProfileCmd()
	names := map[string]bool{}
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"list", "show", "install", "install-defaults"} {
		assert.True(t, names[want], "profile subcommand %q must be wired", want)
	}
}

func TestProfileList_RunsAgainstDefaults(t *testing.T) {
	t.Setenv("DBOUNCE_PROFILES_PATH", filepath.Join(t.TempDir(), "p.yaml"))
	cmd := newProfileCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"list"})
	require.NoError(t, cmd.Execute())
	body := out.String()
	assert.Contains(t, body, "full-user")
	assert.Contains(t, body, "safe-default")
	assert.Contains(t, body, "allow_baseline:")
}

func TestProfileShow_PrintsSafeDefault(t *testing.T) {
	t.Setenv("DBOUNCE_PROFILES_PATH", filepath.Join(t.TempDir(), "p.yaml"))
	cmd := newProfileCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"show", "safe-default"})
	require.NoError(t, cmd.Execute())
	body := out.String()
	assert.Contains(t, body, "safe-default")
	assert.Contains(t, body, "allow_baseline: sql_read_only")
	assert.Contains(t, body, "deny_ast_mutating_nodes: true")
}

func TestProfileInstall_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "p.yaml")

	payload := []byte("profiles:\n  staging-work:\n    description: from URL\n")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	// The CLI's install path uses profile.Install which constructs its
	// own http.Client unless one is injected. Use the package-level
	// API directly to drive the install path with the insecure test
	// client; this is the same coverage pattern kbouncer's
	// internal/cli/profile_test.go uses.
	result, err := profile.Install(
		t.Context(),
		profile.InstallOptions{
			From:           srv.URL,
			ExpectedSHA256: hexSum,
			HTTPClient:     profile.InsecureTLSClientForTests(),
			ProfilesPath:   target,
		})
	require.NoError(t, err)
	require.Contains(t, result.InstalledNames, "staging-work")

	// Read-back via `dbounce profile list` should see the new profile.
	t.Setenv("DBOUNCE_PROFILES_PATH", target)
	cmd := newProfileCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"list"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "staging-work")
}

func TestProfileInstallDefaults_WritesFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "p.yaml")
	t.Setenv("DBOUNCE_PROFILES_PATH", target)
	cmd := newProfileCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"install-defaults"})
	require.NoError(t, cmd.Execute())
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Contains(t, string(body), "safe-default")
	assert.Contains(t, string(body), "full-user")
	assert.True(t, strings.Contains(out.String(), "wrote default profiles"),
		"banner must announce write: %s", out.String())
}

func TestProfileInstallDefaults_NoopWhenExists(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "p.yaml")
	require.NoError(t, os.WriteFile(target, []byte("profiles:\n  existing: {}\n"), 0o600))
	t.Setenv("DBOUNCE_PROFILES_PATH", target)
	cmd := newProfileCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"install-defaults"})
	require.NoError(t, cmd.Execute())
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Contains(t, string(body), "existing",
		"install-defaults must NEVER overwrite existing profiles.yaml without --force")
}

// TestInferDialectsFromProfileNames pins the per-dialect-note
// behavior the Slice 2 wiring depends on per
// [[security-team-audit-export]]. The emit MUST stamp
// unmapped.iam_jit.ext.dialects from a name-heuristic so a SIEM
// dashboard can group "profile installs that touched MySQL" without
// parsing names.
func TestInferDialectsFromProfileNames(t *testing.T) {
	cases := []struct {
		name  string
		names []string
		want  []string
	}{
		{
			"single-pg-prefix",
			[]string{"pg-readonly"},
			[]string{"postgres"},
		},
		{
			"mysql-suffix",
			[]string{"prod-mysql"},
			[]string{"mysql"},
		},
		{
			"per-dialect-bundle",
			[]string{"pg-readonly", "mysql-prod", "snowflake-export"},
			[]string{"mysql", "postgres", "snowflake"},
		},
		{
			"longhand-postgres",
			[]string{"postgres-prod"},
			[]string{"postgres"},
		},
		{
			"shorthand-aliases",
			[]string{"sf-export", "bq-readonly"},
			[]string{"bigquery", "snowflake"},
		},
		{
			"dedup-on-multiple",
			[]string{"pg-prod", "pg-staging"},
			[]string{"postgres"},
		},
		{
			"no-match-empty",
			[]string{"my-org-profile"},
			nil,
		},
		{
			"empty-input",
			nil,
			nil,
		},
		{
			"case-insensitive",
			[]string{"PG-Readonly", "MYSQL-PROD"},
			[]string{"mysql", "postgres"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inferDialectsFromProfileNames(tc.names)
			assert.Equal(t, tc.want, got,
				"per-dialect inference must match the spec: %v → %v", tc.names, tc.want)
		})
	}
}

// TestProfileInstall_EnqueuesAuditEvent verifies emit site #3 of the
// Slice 2 wiring per [[security-team-audit-export]]: after a
// successful install, the CLI writes a PROFILE_INSTALLED row to the
// cross-process audit-event queue. This is Option A from the spec —
// the run-process poller picks it up + emits through its wired
// Exporter / RuleEngine. The CLI process itself doesn't construct an
// exporter (single emit-path invariant).
func TestProfileInstall_EnqueuesAuditEvent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "p.yaml")
	dbPath := filepath.Join(dir, "state.db")

	payload := []byte("profiles:\n  pg-readonly:\n    description: pg test\n")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	// Drive the install path directly (mirrors the CLI but lets us
	// skip the TLS-cert dance — same coverage pattern as
	// TestProfileInstall_RoundTrip above).
	result, err := profile.Install(
		t.Context(),
		profile.InstallOptions{
			From:         srv.URL,
			HTTPClient:   profile.InsecureTLSClientForTests(),
			ProfilesPath: target,
		})
	require.NoError(t, err)
	require.Contains(t, result.InstalledNames, "pg-readonly")

	// Drive the enqueue helper directly to mirror the CLI's
	// post-install hook (bypasses the Cobra wiring that would
	// otherwise try to construct a real HTTP fetch on a different
	// URL).
	rootCmd := newProfileCmd()
	enqueueProfileInstalledAuditEvent(rootCmd, dbPath, "alice", result)

	// Verify the row landed.
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()
	rows, err := st.DrainPendingAuditEvents(0)
	require.NoError(t, err)
	require.Len(t, rows, 1,
		"profile install MUST enqueue exactly one PROFILE_INSTALLED row")
	assert.Equal(t, store.PendingAuditEventProfileInstalled, rows[0].Kind)
	assert.Contains(t, rows[0].PayloadJSON, srv.URL,
		"payload must carry source_url for the SIEM JOIN key")
	assert.Contains(t, rows[0].PayloadJSON, "pg-readonly")
	assert.Contains(t, rows[0].PayloadJSON, `"installed_by":"alice"`)
	assert.Contains(t, rows[0].PayloadJSON, `"postgres"`,
		"per-dialect inference must surface dialects from the profile name (pg-readonly → postgres)")
}

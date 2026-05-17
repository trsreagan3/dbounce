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

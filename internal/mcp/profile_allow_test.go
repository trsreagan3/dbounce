// profile_allow_test.go — #387 / §A25 Phase 2 MCP tool tests.

package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/profile"
)

func writeMCPProfile(t *testing.T, dir, name, source string) string {
	t.Helper()
	body := "profiles:\n  " + name + ":\n    description: test\n"
	if source != "" {
		body += "    source: " + source + "\n"
	}
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMcpTool_ProfileAllow_PendingByDefault(t *testing.T) {
	dir := t.TempDir()
	qp := filepath.Join(dir, "pending.jsonl")
	t.Setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH", qp)
	path := writeMCPProfile(t, dir, "full-user", "")
	ps, _ := profile.LoadProfiles(path)
	active, _ := ps.Active("full-user")

	srv, _ := newTestServer(t, active)
	// override profiles path for this test (TestServer hard-codes a path)
	srv.cfg.ProfilesPath = path

	out := rpcCallTool(t, srv, "dbounce_profile_allow", map[string]any{
		"target": "*.staging.internal",
		"action": []any{"SELECT:public.users"},
		"reason": "agent reads staging",
	})
	require.Equal(t, true, out["ok"], "got %v", out)
	require.Equal(t, "pending_approval", out["status"])
	require.NotNil(t, out["pending_entry"])
}

func TestMcpTool_ProfileAllow_RefusesWildcardTarget(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH", filepath.Join(dir, "pending.jsonl"))
	path := writeMCPProfile(t, dir, "full-user", "")
	ps, _ := profile.LoadProfiles(path)
	active, _ := ps.Active("full-user")
	srv, _ := newTestServer(t, active)
	srv.cfg.ProfilesPath = path

	out := rpcCallTool(t, srv, "dbounce_profile_allow", map[string]any{
		"target": "*",
		"action": []any{"SELECT:public.users"},
		"reason": "broad",
	})
	require.Equal(t, false, out["ok"])
	require.Equal(t, "target_too_broad", out["code"])
}

func TestMcpTool_DeniesRecent_ReturnsList(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	out := rpcCallTool(t, srv, "dbounce_denies_recent", map[string]any{"since": "1h"})
	require.Equal(t, true, out["ok"])
	require.Equal(t, "dbounce", out["bouncer"])
	rows, _ := out["rows"].([]any)
	require.NotNil(t, rows)
}

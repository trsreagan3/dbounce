// profile_allow_test.go — #387 / §A25 Phase 2 MCP tool tests.

package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/store"
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

// TestMcpTool_ProfileAllow_EmitsAdminActionAuditEvent pins the #391 fix:
// the dbounce_profile_allow MCP tool MUST enqueue an OCSF admin-action
// audit event via the pending_audit_events SQLite queue. Pre-#391 the
// EmitAudit callback was nil, so the event was silently dropped.
//
// Verification: capture the pending_audit_events queue depth before + after
// the MCP tool call; the depth MUST increase by at least 1 (the admin-action
// row). Then drain + decode the event to assert action + actor fields match
// the profileallow constants.
func TestMcpTool_ProfileAllow_EmitsAdminActionAuditEvent(t *testing.T) {
	dir := t.TempDir()
	qp := filepath.Join(dir, "pending.jsonl")
	t.Setenv("IAM_JIT_PROFILE_ALLOW_PENDING_PATH", qp)
	t.Setenv("IAM_JIT_BOUNCER_ALLOW_AGENT_SELF_GRANT", "true") // apply immediately
	path := writeMCPProfile(t, dir, "full-user", "")
	ps, _ := profile.LoadProfiles(path)
	active, _ := ps.Active("full-user")

	srv, st := newTestServer(t, active)
	srv.cfg.ProfilesPath = path

	// Baseline queue depth before the MCP call.
	depthBefore, err := st.CountPendingAuditEvents()
	require.NoError(t, err)

	out := rpcCallTool(t, srv, "dbounce_profile_allow", map[string]any{
		"target": "*.staging.internal",
		"action": []any{"SELECT:public.users"},
		"reason": "incident response test",
	})
	require.Equal(t, true, out["ok"], "tool call must succeed: %v", out)

	// Drain the queue and find our admin-action event.
	events, derr := st.DrainPendingAuditEvents(16)
	require.NoError(t, derr)

	depthAfter := int64(len(events)) + depthBefore
	assert.Greater(t, depthAfter, depthBefore,
		"#391: dbounce_profile_allow MCP call MUST enqueue at least one audit event "+
			"(queue depth must increase after the call)")

	// Find the admin_action event among the drained rows.
	var foundEvent *store.PendingAuditEvent
	for i := range events {
		if events[i].Kind == store.PendingAuditEventAdminAction {
			foundEvent = &events[i]
			break
		}
	}
	require.NotNil(t, foundEvent,
		"#391: MCP dbounce_profile_allow MUST enqueue a PendingAuditEventAdminAction row — "+
			"the HTTP path emits it; the MCP path was the missing surface before this fix")

	// Decode the payload and assert the action + actor fields match the
	// profileallow package's stable constants.
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(foundEvent.PayloadJSON), &payload),
		"audit event payload MUST be valid JSON")
	action, _ := payload["action"].(string)
	assert.Equal(t, "profile.allow.added", action,
		"#391: action MUST be profile.allow.added "+
			"(profileallow.AdminActionProfileAllowAdded)")
	resourceType, _ := payload["resource_type"].(string)
	assert.Equal(t, "profile", resourceType,
		"#391: resource_type MUST be 'profile' (EntityKind from the AuditEvent)")
}

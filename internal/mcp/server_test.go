package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
	"github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

// MCP server tests mirror kbouncer/internal/mcp/server_test.go: a
// short rpcCall helper that round-trips one request → response, plus
// per-tool BB+WB scenarios for tools/list, recommend_mode_for_task
// (DETERMINISTIC matrix), rules CRUD, decide (read + write under
// safe-default), tail_decisions, profile introspection.

func newTestServer(t *testing.T, ap *profile.Profile) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	cfg := Config{
		Store:         st,
		ActiveProfile: ap,
		ProfilesPath:  "/tmp/test/profiles.yaml",
		Mode:          proxy.ModeCooperative,
		DefaultPolicy: proxy.DefaultPolicyDeny,
		Dialect:       proxy.DialectPostgres,
	}
	return NewServer(cfg), st
}

// rpcCall encodes one JSON-RPC request, runs the server's Serve loop
// against the encoded bytes, and decodes the response. Same shape as
// kbouncer's helper.
func rpcCall(t *testing.T, srv *Server, method string, params map[string]any) map[string]any {
	t.Helper()
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
	}
	if params != nil {
		reqBody["params"] = params
	}
	reqBytes, err := json.Marshal(reqBody)
	require.NoError(t, err)
	in := bytes.NewReader(append(reqBytes, '\n'))
	out := &bytes.Buffer{}
	require.NoError(t, srv.Serve(in, out))
	var resp map[string]any
	require.NoError(t, json.NewDecoder(out).Decode(&resp), "decode response: %s", out.String())
	return resp
}

// rpcCallTool wraps the inner tools/call → structuredContent map.
func rpcCallTool(t *testing.T, srv *Server, tool string, args map[string]any) map[string]any {
	t.Helper()
	resp := rpcCall(t, srv, "tools/call", map[string]any{
		"name":      tool,
		"arguments": args,
	})
	result, ok := resp["result"].(map[string]any)
	require.True(t, ok, "missing result: %v", resp)
	sc, ok := result["structuredContent"].(map[string]any)
	require.True(t, ok, "missing structuredContent: %v", result)
	return sc
}

func TestServer_Initialize(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := rpcCall(t, srv, "initialize", nil)
	result := resp["result"].(map[string]any)
	assert.Equal(t, ProtocolVersion, result["protocolVersion"])
	info := result["serverInfo"].(map[string]any)
	assert.Equal(t, ServerName, info["name"])
}

func TestServer_ToolsList_AllToolsPresent(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := rpcCall(t, srv, "tools/list", nil)
	result := resp["result"].(map[string]any)
	toolsAny := result["tools"].([]any)
	names := map[string]bool{}
	for _, t := range toolsAny {
		m := t.(map[string]any)
		names[m["name"].(string)] = true
	}
	// At least the 9 tools we ship. Adding new ones is non-breaking;
	// the BB assertion is "these all exist."
	want := []string{
		"dbounce_active_mode",
		"dbounce_active_profile",
		"dbounce_active_task",
		"dbounce_recommend_mode_for_task",
		"dbounce_list_rules",
		"dbounce_add_rule",
		"dbounce_remove_rule",
		"dbounce_decide",
		"dbounce_tail_decisions",
	}
	for _, n := range want {
		assert.True(t, names[n], "tool %q must be in tools/list", n)
	}
}

func TestTool_ActiveMode(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sc := rpcCallTool(t, srv, "dbounce_active_mode", nil)
	assert.Equal(t, "cooperative", sc["mode"])
	assert.Equal(t, "deny", sc["default_policy"])
	assert.Equal(t, "postgres", sc["dialect"])
}

func TestTool_ActiveProfile_FullUser(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sc := rpcCallTool(t, srv, "dbounce_active_profile", nil)
	assert.Equal(t, profile.FullUserProfileName, sc["name"])
	assert.Equal(t, false, sc["deny_ast_mutating"])
}

func TestTool_ActiveProfile_SafeDefault(t *testing.T) {
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	srv, _ := newTestServer(t, sd)
	sc := rpcCallTool(t, srv, "dbounce_active_profile", nil)
	assert.Equal(t, "safe-default", sc["name"])
	assert.Equal(t, true, sc["deny_ast_mutating"])
	assert.Equal(t, string(profile.BaselineSQLReadOnly), sc["allow_baseline"])
}

func TestTool_RecommendMode_ReadsOnly_Cooperative(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sc := rpcCallTool(t, srv, "dbounce_recommend_mode_for_task", map[string]any{
		"description": "SELECT * from public.users WHERE id < 100",
	})
	assert.Equal(t, "cooperative", sc["mode"])
	assert.Equal(t, true, sc["deterministic"])
}

func TestTool_RecommendMode_ProdWrites_Transparent(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sc := rpcCallTool(t, srv, "dbounce_recommend_mode_for_task", map[string]any{
		"description":  "DELETE FROM users WHERE deleted_at IS NULL",
		"targets_prod": true,
	})
	assert.Equal(t, "transparent", sc["mode"])
	assert.Contains(t, sc["reason"].(string), "transparent mode")
}

func TestTool_RecommendMode_NonProdWrites_Cooperative(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sc := rpcCallTool(t, srv, "dbounce_recommend_mode_for_task", map[string]any{
		"description":  "UPDATE staging.reports SET v = 1",
		"targets_prod": false,
	})
	assert.Equal(t, "cooperative", sc["mode"],
		"non-prod writes get cooperative + admin pause per safety-mode-lean-permissive")
}

func TestTool_RecommendMode_AmbiguousIsCooperative(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sc := rpcCallTool(t, srv, "dbounce_recommend_mode_for_task", map[string]any{
		"description": "investigate something",
	})
	assert.Equal(t, "cooperative", sc["mode"],
		"ambiguous → cooperative per safety-mode-lean-permissive")
}

func TestTool_RecommendMode_AuditOnlyOverridesProdWrite(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sc := rpcCallTool(t, srv, "dbounce_recommend_mode_for_task", map[string]any{
		"description":      "DELETE FROM prod_users",
		"targets_prod":     true,
		"wants_audit_only": true,
	})
	assert.Equal(t, "cooperative", sc["mode"],
		"wants_audit_only must short-circuit the prod-write transparent branch")
}

func TestTool_AddListRemoveRule(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	add := rpcCallTool(t, srv, "dbounce_add_rule", map[string]any{
		"pattern": "SELECT:public.*",
		"effect":  "allow",
		"note":    "from mcp",
	})
	require.NotZero(t, add["id"])
	id := int64(add["id"].(float64))

	list := rpcCallTool(t, srv, "dbounce_list_rules", nil)
	assert.Equal(t, float64(1), list["count"])

	rm := rpcCallTool(t, srv, "dbounce_remove_rule", map[string]any{"id": id})
	assert.Equal(t, true, rm["removed"])
}

func TestTool_Decide_UnderSafeDefault(t *testing.T) {
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	srv, _ := newTestServer(t, sd)

	// Pure SELECT → allow via sql_read_only baseline.
	sc := rpcCallTool(t, srv, "dbounce_decide", map[string]any{
		"statement": "SELECT id FROM public.users LIMIT 1",
	})
	assert.Equal(t, "allow", sc["verdict"])
	assert.Equal(t, profile.SourceProfileAllow, sc["decision_source"])

	// DELETE → deny via AST-walk backstop.
	sc = rpcCallTool(t, srv, "dbounce_decide", map[string]any{
		"statement": "DELETE FROM public.users WHERE id = 1",
	})
	assert.Equal(t, "deny", sc["verdict"])
	assert.Equal(t, profile.SourceProfile, sc["decision_source"])
}

func TestTool_TailDecisions(t *testing.T) {
	srv, st := newTestServer(t, nil)
	// Seed one decision row so we have something to read back.
	_, err := st.AddRule(rules.ProxyRule{Pattern: "SELECT:*", Effect: rules.EffectAllow})
	require.NoError(t, err)
	sc := rpcCallTool(t, srv, "dbounce_tail_decisions", map[string]any{"limit": 10})
	assert.NotNil(t, sc["decisions"])
}

func TestServer_UnknownTool(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := rpcCall(t, srv, "tools/call", map[string]any{
		"name":      "nope",
		"arguments": map[string]any{},
	})
	// Tool errors come back as result.error (per the kbouncer
	// convention) rather than JSON-RPC error.
	result := resp["result"].(map[string]any)
	sc := result["structuredContent"].(map[string]any)
	assert.Contains(t, sc["error"].(string), "unknown tool")
}

func TestServer_ParseError(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	out := &bytes.Buffer{}
	require.NoError(t, srv.Serve(strings.NewReader("not json\n"), out))
	var resp map[string]any
	require.NoError(t, json.NewDecoder(out).Decode(&resp))
	errMap := resp["error"].(map[string]any)
	assert.Equal(t, float64(-32700), errMap["code"])
}

// TestServer_EOFExitsCleanly is a smoke test ensuring Serve returns
// on EOF without blocking.
func TestServer_EOFExitsCleanly(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	err := srv.Serve(strings.NewReader(""), io.Discard)
	require.NoError(t, err)
}

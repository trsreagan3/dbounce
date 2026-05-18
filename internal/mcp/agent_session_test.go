// Tests for [[agent-identity-in-audit]] Feature 2 — MCP per-connection
// session ID lifecycle: mint on `initialize`, retire on Serve() return,
// emit SESSION_ENDED via the wired AuditExporter.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
	"github.com/trsreagan3/dbounce/internal/store"
)

// newTestServerWithExporter builds an MCP server wired with a real
// LogWriter-backed AuditExporter + a shared AgentRegistry so the test
// can read SESSION_ENDED events out of the JSONL file after Serve
// returns.
func newTestServerWithExporter(t *testing.T, ap *profile.Profile) (*Server, *audit.Exporter, string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	logPath := filepath.Join(dir, "audit.jsonl")
	lw, err := audit.NewLogWriter(audit.LogOptions{Path: logPath, Fsync: true})
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = lw.Shutdown(ctx)
	})
	exporter := audit.NewExporter(lw, nil, "mcp-stdio", "")

	cfg := Config{
		Store:         st,
		ActiveProfile: ap,
		ProfilesPath:  "/tmp/test/profiles.yaml",
		Mode:          proxy.ModeCooperative,
		DefaultPolicy: proxy.DefaultPolicyDeny,
		Dialect:       proxy.DialectPostgres,
		AuditExporter: exporter,
		AgentRegistry: audit.NewAgentRegistry(),
	}
	return NewServer(cfg), exporter, logPath, st
}

// readAuditLines reads + parses JSONL events from the audit log path.
// Drains LogWriter on shutdown so all in-flight events are flushed.
func readAuditLines(t *testing.T, exp *audit.Exporter, path string) []map[string]any {
	t.Helper()
	// Force flush by shutting down the exporter's log writer.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if exp != nil {
		_ = exp.Shutdown(ctx)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			break
		}
		out = append(out, m)
	}
	return out
}

// TestMCP_Initialize_MintsSessionWithClientInfo: the initialize
// handler MUST capture clientInfo + mint a session id in the
// AgentRegistry. We dispatch directly (rather than Serve, which would
// retire on return) so we can inspect the live session.
func TestMCP_Initialize_MintsSessionWithClientInfo(t *testing.T) {
	srv, _, _, _ := newTestServerWithExporter(t, nil)
	params, _ := json.Marshal(map[string]any{
		"clientInfo": map[string]any{
			"name":    "claude-code",
			"version": "1.2.3",
		},
	})
	resp := srv.dispatch(rawRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "initialize",
		Params:  params,
	})
	require.NotNil(t, resp)
	sid := srv.SessionID()
	require.NotEmpty(t, sid, "session id MUST be minted on initialize")
	// Look up the agent in the registry.
	a, ok := srv.cfg.AgentRegistry.Lookup(sid)
	require.True(t, ok)
	assert.Equal(t, "claude-code", a.Name)
	assert.Equal(t, "1.2.3", a.Version)
	assert.Equal(t, audit.DetectedFromMCPClientInfo, a.DetectedFrom)
}

// TestMCP_Initialize_MissingClientInfo_StillMintsUnknown: per the
// memo, a missing clientInfo block MUST result in name="unknown" + the
// session still mints so SESSION_ENDED still fires on close.
func TestMCP_Initialize_MissingClientInfo_StillMintsUnknown(t *testing.T) {
	srv, _, _, _ := newTestServerWithExporter(t, nil)
	resp := srv.dispatch(rawRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "initialize",
	})
	require.NotNil(t, resp)
	sid := srv.SessionID()
	require.NotEmpty(t, sid)
	a, ok := srv.cfg.AgentRegistry.Lookup(sid)
	require.True(t, ok)
	assert.Equal(t, "unknown", a.Name)
}

// TestMCP_Serve_EmitsSessionEndedOnClose: the Serve loop MUST emit a
// SESSION_ENDED synthetic event when the stdio peer closes (Serve
// returns), so a SIEM consumer can JOIN every preceding event from
// that session id against this terminator.
func TestMCP_Serve_EmitsSessionEndedOnClose(t *testing.T) {
	srv, exp, logPath, _ := newTestServerWithExporter(t, nil)

	// One initialize → then EOF closes Serve.
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"clientInfo": map[string]any{"name": "cursor", "version": "0.50"},
		},
	}
	raw, _ := json.Marshal(reqBody)
	in := bytes.NewReader(append(raw, '\n'))
	out := &bytes.Buffer{}
	require.NoError(t, srv.Serve(in, out))

	// After Serve returns, the SESSION_ENDED event must have been
	// emitted via the AuditExporter. Drain + read the JSONL.
	events := readAuditLines(t, exp, logPath)

	var sessionEnded map[string]any
	for _, e := range events {
		um, _ := e["unmapped"].(map[string]any)
		ij, _ := um["iam_jit"].(map[string]any)
		if ij["event_type"] == "SESSION_ENDED" {
			sessionEnded = e
			break
		}
	}
	require.NotNil(t, sessionEnded, "expected a SESSION_ENDED event in audit log; got %v", events)

	// Verify the retired session's agent block landed correctly.
	um := sessionEnded["unmapped"].(map[string]any)
	ij := um["iam_jit"].(map[string]any)
	agent := ij["agent"].(map[string]any)
	assert.Equal(t, "cursor", agent["name"])
	assert.Equal(t, "0.50", agent["version"])
	assert.NotEmpty(t, agent["session_id"])
	assert.Equal(t, "mcp_clientinfo", agent["detected_from"])
}

// TestMCP_Serve_NoSessionWhenInitializeNeverFires: if the peer closes
// before sending initialize, SessionID stays empty + no SESSION_ENDED
// event fires. Defensive: a connect-disconnect doesn't pollute the
// audit stream.
func TestMCP_Serve_NoSessionWhenInitializeNeverFires(t *testing.T) {
	srv, exp, logPath, _ := newTestServerWithExporter(t, nil)
	require.NoError(t, srv.Serve(bytes.NewReader(nil), io.Discard))
	assert.Empty(t, srv.SessionID(),
		"session id MUST NOT mint without an initialize request")
	events := readAuditLines(t, exp, logPath)
	for _, e := range events {
		um, _ := e["unmapped"].(map[string]any)
		ij, _ := um["iam_jit"].(map[string]any)
		if ij["event_type"] == "SESSION_ENDED" {
			t.Fatalf("unexpected SESSION_ENDED event: %v", e)
		}
	}
}

// TestMCP_Initialize_ReinitRotatesSessionAndEmitsPriorEnded: a peer
// that re-handshakes mid-session (rare but supported) MUST rotate the
// session id + emit a SESSION_ENDED for the previous id so the SIEM
// sees a clean state machine.
func TestMCP_Initialize_ReinitRotatesSessionAndEmitsPriorEnded(t *testing.T) {
	srv, exp, logPath, _ := newTestServerWithExporter(t, nil)

	// Two initialize calls + EOF.
	mk := func(id int, name string) []byte {
		raw, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"method":  "initialize",
			"params": map[string]any{
				"clientInfo": map[string]any{"name": name, "version": "1.0"},
			},
		})
		return append(raw, '\n')
	}
	in := bytes.NewReader(append(mk(1, "claude-code"), mk(2, "cursor")...))
	out := &bytes.Buffer{}
	require.NoError(t, srv.Serve(in, out))

	events := readAuditLines(t, exp, logPath)
	endedNames := []string{}
	for _, e := range events {
		um, _ := e["unmapped"].(map[string]any)
		ij, _ := um["iam_jit"].(map[string]any)
		if ij["event_type"] == "SESSION_ENDED" {
			agent := ij["agent"].(map[string]any)
			endedNames = append(endedNames, agent["name"].(string))
		}
	}
	assert.Contains(t, endedNames, "claude-code",
		"reinit MUST emit SESSION_ENDED for the previous session")
	assert.Contains(t, endedNames, "cursor",
		"Serve return MUST emit SESSION_ENDED for the final session")
}

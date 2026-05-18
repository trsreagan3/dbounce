// Tests for [[agent-identity-in-audit]] Feature 1+2 — per-dialect
// agent detection (PG application_name parsing) + per-connection
// session id lifecycle (mint on handshake, retire on close with a
// SESSION_ENDED synthetic event). Sibling agents in ibounce + kbounce
// ship the equivalent against their respective transports.

package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/store"
)

// newTestServerWithExporter spins up a proxy.Server with a real
// LogWriter-backed AuditExporter so per-decision OCSF events + the
// SESSION_ENDED synthetic land in a real JSONL file we can read back.
//
// The returned shutdown closure orchestrates the teardown sequence
// the audit-export plumbing requires: first close the wire listener
// (so no new connections arrive), then wait briefly for in-flight
// serveConn goroutines to finish their deferred emitSessionEnded
// calls, THEN shut the exporter down. Calling exporter.Shutdown while
// serveConn is still queuing SESSION_ENDED events races on the
// LogWriter's channel close.
func newTestServerWithExporter(t *testing.T) (*Server, string, *store.Store, string, *audit.Exporter, func()) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	logPath := filepath.Join(dir, "audit.jsonl")
	lw, err := audit.NewLogWriter(audit.LogOptions{Path: logPath, Fsync: true})
	require.NoError(t, err)
	exporter := audit.NewExporter(lw, nil, "127.0.0.1:0", "")

	wireL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cfg := Config{
		Host:          "127.0.0.1",
		Port:          wireL.Addr().(*net.TCPAddr).Port,
		MgmtHost:      "127.0.0.1",
		MgmtPort:      mgmtL.Addr().(*net.TCPAddr).Port,
		Mode:          ModeCooperative,
		Dialect:       DialectPostgres,
		DefaultPolicy: DefaultPolicyAllow,
		IdleTimeout:   5 * time.Second,
		WireListener:  wireL,
		MgmtListener:  mgmtL,
	}.Normalize()

	srv := NewServer(cfg, st)
	srv.SetAuditExporter(exporter)
	go func() { _ = srv.Serve() }()

	// Poll until listener ready.
	addr := wireL.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		// srv.Shutdown waits on connWG so the deferred
		// emitSessionEnded calls drain BEFORE this returns; safe to
		// close the exporter right after per the LogWriter "stop
		// sending before Shutdown" invariant.
		_ = srv.Shutdown(ctx)
		_ = exporter.Shutdown(ctx)
	}
	t.Cleanup(shutdown)
	return srv, addr, st, logPath, exporter, shutdown
}

// sendStartupMessageWithAppName writes a PG StartupMessage that
// includes user / database / application_name params per
// [[agent-identity-in-audit]] Feature 1. The proxy's PG observation-
// only handshake handler MUST pull application_name out + mint a
// session id stamped with the corresponding agent name.
func sendStartupMessageWithAppName(t *testing.T, conn net.Conn, appName string) {
	t.Helper()
	params := []byte(
		"user\x00tester\x00database\x00postgres\x00application_name\x00" + appName + "\x00\x00")
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body[0:4], 196608) // protocol 3.0
	copy(body[4:], params)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(4+len(body)))
	_, err := conn.Write(hdr)
	require.NoError(t, err)
	_, err = conn.Write(body)
	require.NoError(t, err)
}

// readEventsFromLog reads + parses JSONL audit events from disk. The
// CALLER must have already invoked the test's shutdown closure (which
// stops the server + drains the exporter in the correct order) so the
// log file is fully flushed.
func readEventsFromLog(t *testing.T, path string) []map[string]any {
	t.Helper()
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

// TestPGProxy_ApplicationName_FlowsToAuditEvent: an inbound PG
// connection that declares application_name=psql MUST result in an
// audit event with unmapped.iam_jit.agent.name="psql" +
// detected_from="pg_application_name".
func TestPGProxy_ApplicationName_FlowsToAuditEvent(t *testing.T) {
	srv, addr, _, logPath, _, shutdown := newTestServerWithExporter(t)

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	sendStartupMessageWithAppName(t, conn, "psql")
	readUntilReadyForQuery(t, conn, 10)
	sendQuery(t, conn, "SELECT 1")
	readUntilReadyForQuery(t, conn, 10)
	// Close the client → triggers SESSION_ENDED on the server side.
	_ = conn.Close()

	// Orchestrate the teardown: stop the listener, wait for the
	// in-flight serveConn defer to drain its emitSessionEnded call,
	// THEN shut the exporter down. Calling exporter.Shutdown while
	// serveConn is still emitting races the LogWriter channel close.
	shutdown()

	events := readEventsFromLog(t, logPath)
	require.NotEmpty(t, events, "expected at least one audit event")

	// Find the SELECT decision event.
	var decisionAgent map[string]any
	var sessionEnded map[string]any
	for _, e := range events {
		um, _ := e["unmapped"].(map[string]any)
		ij, _ := um["iam_jit"].(map[string]any)
		evtType, _ := ij["event_type"].(string)
		switch {
		case evtType == "SESSION_ENDED":
			sessionEnded = e
		case e["activity_name"] == "select":
			if a, ok := ij["agent"].(map[string]any); ok {
				decisionAgent = a
			}
		}
	}
	require.NotNil(t, decisionAgent, "SELECT decision must carry agent block; events=%v", events)
	assert.Equal(t, "psql", decisionAgent["name"])
	assert.Equal(t, "pg_application_name", decisionAgent["detected_from"])
	assert.NotEmpty(t, decisionAgent["session_id"])

	require.NotNil(t, sessionEnded, "SESSION_ENDED event must fire on connection close")
	endedUM := sessionEnded["unmapped"].(map[string]any)
	endedIJ := endedUM["iam_jit"].(map[string]any)
	endedAgent := endedIJ["agent"].(map[string]any)
	assert.Equal(t, decisionAgent["session_id"], endedAgent["session_id"],
		"SESSION_ENDED's session_id MUST match the decision's so SIEM can JOIN")

	_ = srv // keep srv referenced for cleanup
}

// TestPGProxy_MissingApplicationName_StillMintsUnknownSession: an
// inbound PG connection that DOESN'T declare application_name MUST
// still get a session id minted (so SESSION_ENDED fires on close); the
// name normalizes to "unknown" per the memo.
func TestPGProxy_MissingApplicationName_StillMintsUnknownSession(t *testing.T) {
	_, addr, _, logPath, _, shutdown := newTestServerWithExporter(t)

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// No application_name field — just user + database.
	params := []byte("user\x00alice\x00database\x00postgres\x00\x00")
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body[0:4], 196608)
	copy(body[4:], params)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(4+len(body)))
	_, err = conn.Write(hdr)
	require.NoError(t, err)
	_, err = conn.Write(body)
	require.NoError(t, err)
	readUntilReadyForQuery(t, conn, 10)
	sendQuery(t, conn, "SELECT 42")
	readUntilReadyForQuery(t, conn, 10)
	_ = conn.Close()
	shutdown()

	events := readEventsFromLog(t, logPath)
	var found map[string]any
	for _, e := range events {
		if e["activity_name"] == "select" {
			um, _ := e["unmapped"].(map[string]any)
			ij, _ := um["iam_jit"].(map[string]any)
			if a, ok := ij["agent"].(map[string]any); ok {
				found = a
				break
			}
		}
	}
	require.NotNil(t, found, "agent block must be present even for sessions without application_name")
	assert.Equal(t, "unknown", found["name"])
	assert.NotEmpty(t, found["session_id"],
		"session id MUST still be minted to support SESSION_ENDED on close")
}

// TestScanMySQLHandshakeAttrs_FindsAttrsBlockInPayload exercises the
// proxy's MySQL HandshakeResponse41 attrs scanner against a synthetic
// payload that mimics what MySQL Connector/J sends. Per
// [[agent-identity-in-audit]] Feature 1 the scanner is robust to
// preceding capability bits / variable-length auth response — it
// scans for well-known attr keys + walks back to the block start.
func TestScanMySQLHandshakeAttrs_FindsAttrsBlockInPayload(t *testing.T) {
	// Build a minimal attrs block: total length-encoded int + key/value
	// length-encoded string pairs.
	encStr := func(s string) []byte {
		out := []byte{byte(len(s))}
		out = append(out, []byte(s)...)
		return out
	}
	var inner []byte
	inner = append(inner, encStr("_client_name")...)
	inner = append(inner, encStr("MySQL Connector/J")...)
	inner = append(inner, encStr("_client_version")...)
	inner = append(inner, encStr("8.4.0")...)
	inner = append(inner, encStr("_program_name")...)
	inner = append(inner, encStr("mysqlsh")...)

	// Prepend a synthetic "header" + capability bytes + reserved
	// padding + the length-encoded total + the inner block. The
	// scanner walks backward from the first `_client_name` it finds so
	// the header bytes can be arbitrary.
	header := []byte{0x05, 0x82, 0x00, 0x00} // some bytes that look like the start of a HandshakeResponse41
	header = append(header, make([]byte, 23)...) // reserved padding
	header = append(header, []byte("alice\x00")...) // username
	header = append(header, 0x14)                   // auth-response length
	header = append(header, make([]byte, 0x14)...)  // 20-byte fake auth response

	// Total-block-length is len(inner); for a small block, fits in 1
	// length-byte (< 251).
	var full []byte
	full = append(full, header...)
	full = append(full, byte(len(inner)))
	full = append(full, inner...)

	attrs := scanMySQLHandshakeAttrs(full)
	require.NotEmpty(t, attrs,
		"scanner must find the attrs block when _client_name is present")
	assert.Equal(t, "MySQL Connector/J", attrs["_client_name"])
	assert.Equal(t, "8.4.0", attrs["_client_version"])
	assert.Equal(t, "mysqlsh", attrs["_program_name"])
}

// TestScanMySQLHandshakeAttrs_NoAttrsReturnsEmptyMap: an older client
// that doesn't set CLIENT_CONNECT_ATTRS produces a payload without
// the _client_name key; the scanner must return an empty map without
// panicking.
func TestScanMySQLHandshakeAttrs_NoAttrsReturnsEmptyMap(t *testing.T) {
	payload := []byte("the quick brown fox jumps over the lazy dog")
	attrs := scanMySQLHandshakeAttrs(payload)
	assert.Empty(t, attrs)
}

// TestParsePGStartupAppName_PsycopgRecognized confirms the
// psycopg2-family detection works on the full literal app_name that
// psycopg2 v2.x sends.
func TestParsePGStartupAppName_PsycopgRecognized(t *testing.T) {
	name, raw := audit.ParsePGStartupAppName(map[string]string{
		"application_name": "psycopg2",
	})
	assert.Equal(t, "psycopg2", name)
	assert.Equal(t, "psycopg2", raw)
}

// TestAgentRegistry_SessionLifecycle_OnServer: the per-Server
// AgentRegistry is process-wide for the proxy; mint+retire are
// exposed via emitSessionEnded; ActiveCount tracks live sessions.
//
// Constructs the Server WITHOUT starting Serve so the test exercises
// only the registry + emit semantics — Serve / Shutdown race surface
// is covered by the other Serve-driven tests in this file.
func TestAgentRegistry_SessionLifecycle_OnServer(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	srv := NewServer(Config{
		Host:          "127.0.0.1",
		Port:          1,
		MgmtHost:      "127.0.0.1",
		MgmtPort:      1,
		Mode:          ModeCooperative,
		Dialect:       DialectPostgres,
		DefaultPolicy: DefaultPolicyAllow,
	}, st)
	reg := srv.AgentRegistry()
	require.NotNil(t, reg)
	sid := reg.Mint(audit.Agent{Name: "claude-code", DetectedFrom: audit.DetectedFromMCPClientInfo})
	assert.Equal(t, 1, reg.ActiveCount())

	srv.emitSessionEnded(sid)
	assert.Equal(t, 0, reg.ActiveCount(),
		"emitSessionEnded retires the session in the registry")

	// Idempotent: second call no-ops, ActiveCount stays at 0.
	srv.emitSessionEnded(sid)
	assert.Equal(t, 0, reg.ActiveCount())
}

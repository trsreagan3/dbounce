package proxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/dynamicdeny"
	"github.com/trsreagan3/dbounce/internal/store"
)

// startTestServer spins up a Server on a random local port + a random
// management port. Returns the running server + the wire-protocol
// addr + the mgmt /healthz URL. Cleanup is registered with t.
func startTestServer(t *testing.T) (*Server, string, string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	cfg := Config{
		Host:     "127.0.0.1",
		Port:     0, // any
		MgmtHost: "127.0.0.1",
		MgmtPort: 0,
		Mode:     ModeCooperative,
		Dialect:  DialectPostgres,
		// Default-allow keeps the wire-protocol smoke tests focused on
		// transport correctness; D-Slice 3's composition-order tests
		// drive the rule engine via in-process decide() calls instead.
		DefaultPolicy: DefaultPolicyAllow,
		IdleTimeout:   5 * time.Second,
	}.Normalize()
	// Replace port 0 sentinels (Normalize would set defaults). We pre-
	// bind both listeners on ephemeral ports + hand them through Config
	// so Server.Serve does not close→re-Listen + race against another
	// process / test grabbing the freed port. See #244.
	wireL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	wirePort := wireL.Addr().(*net.TCPAddr).Port
	mgmtPort := mgmtL.Addr().(*net.TCPAddr).Port

	cfg.Port = wirePort
	cfg.MgmtPort = mgmtPort
	cfg.WireListener = wireL
	cfg.MgmtListener = mgmtL

	srv := NewServer(cfg, st)
	go func() {
		_ = srv.Serve()
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// Brief poll until the listeners accept.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", wirePort), 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", mgmtPort))
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	return srv,
		fmt.Sprintf("127.0.0.1:%d", wirePort),
		fmt.Sprintf("http://127.0.0.1:%d/healthz", mgmtPort),
		st
}

// sendStartupMessage writes a minimal PG StartupMessage that asks for
// user `tester` + database `postgres` + protocol 3.0. dbounce's
// handshake should ack with AuthenticationOk + ReadyForQuery.
func sendStartupMessage(t *testing.T, conn net.Conn) {
	t.Helper()
	// "user\0tester\0database\0postgres\0\0"
	params := []byte("user\x00tester\x00database\x00postgres\x00\x00")
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body[0:4], 196608) // protocol 3.0 (0x00030000)
	copy(body[4:], params)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(4+len(body)))
	_, err := conn.Write(hdr)
	require.NoError(t, err)
	_, err = conn.Write(body)
	require.NoError(t, err)
}

// readUntilReadyForQuery consumes wire-protocol messages from conn
// until it sees a ReadyForQuery ('Z'). Returns the count of messages
// consumed. Used by tests to know the server is done responding.
func readUntilReadyForQuery(t *testing.T, conn net.Conn, max int) int {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	count := 0
	for count < max {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			t.Fatalf("read header: %v", err)
		}
		msgType := hdr[0]
		length := binary.BigEndian.Uint32(hdr[1:5])
		if length < 4 {
			t.Fatalf("bogus length %d", length)
		}
		body := make([]byte, length-4)
		if length > 4 {
			if _, err := io.ReadFull(conn, body); err != nil {
				t.Fatalf("read body: %v", err)
			}
		}
		count++
		if msgType == 'Z' {
			return count
		}
	}
	t.Fatalf("ReadyForQuery not seen within %d messages", max)
	return count
}

// sendQuery writes a PG simple-protocol Query message ('Q').
func sendQuery(t *testing.T, conn net.Conn, sql string) {
	t.Helper()
	payload := append([]byte(sql), 0)
	hdr := make([]byte, 5)
	hdr[0] = 'Q'
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
	_, err := conn.Write(hdr)
	require.NoError(t, err)
	_, err = conn.Write(payload)
	require.NoError(t, err)
}

func TestWireProtocol_HandshakeAndQuery(t *testing.T) {
	_, addr, _, st := startTestServer(t)

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	sendStartupMessage(t, conn)
	// After StartupMessage we expect AuthenticationOk + BackendKeyData
	// + ReadyForQuery.
	readUntilReadyForQuery(t, conn, 10)

	// Send a SELECT.
	sendQuery(t, conn, "SELECT 1")
	readUntilReadyForQuery(t, conn, 10)

	// The proxy must have audit-logged ONE decision row.
	n, err := st.CountDecisions()
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "SELECT", rows[0].StatementType)
	assert.Equal(t, "ALLOW", rows[0].DecisionVerdict)
	assert.Equal(t, "cooperative", rows[0].ModeAtDecision)
	assert.False(t, rows[0].Enforced,
		"cooperative mode must NEVER enforce — advisory-only invariant")
	// D-Slice 3 source tagging: with no rules + default-allow, the
	// verdict comes from the default-policy fall-through.
	assert.Equal(t, SourceDefault, rows[0].DecisionSource)
}

func TestWireProtocol_MultipleQueries(t *testing.T) {
	_, addr, _, st := startTestServer(t)

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	sendStartupMessage(t, conn)
	readUntilReadyForQuery(t, conn, 10)

	queries := []string{
		"SELECT * FROM users",
		"INSERT INTO audit_log (event) VALUES ('login')",
		"UPDATE sessions SET active = false WHERE id = 1",
	}
	for _, q := range queries {
		sendQuery(t, conn, q)
		readUntilReadyForQuery(t, conn, 10)
	}

	n, err := st.CountDecisions()
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
}

func TestWireProtocol_MalformedMessage_DoesNotPanic(t *testing.T) {
	// Per the audit-cadence self-check: bogus message-length bytes
	// MUST close the connection cleanly without panicking.
	_, addr, _, _ := startTestServer(t)

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	sendStartupMessage(t, conn)
	readUntilReadyForQuery(t, conn, 10)

	// Bogus message: type 'Q', length 0xFFFFFFFF (way over the cap).
	bogus := []byte{'Q', 0xFF, 0xFF, 0xFF, 0xFF}
	_, err = conn.Write(bogus)
	require.NoError(t, err)

	// Server should close the connection. Reading should now return
	// an error / EOF rather than hang forever.
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	require.Error(t, err, "server must close after malformed message")
}

func TestHealthz_Shape(t *testing.T) {
	_, _, healthzURL, st := startTestServer(t)
	resp, err := http.Get(healthzURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var payload map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))

	assert.Equal(t, "ok", payload["status"])
	assert.Equal(t, "cooperative", payload["mode"])
	assert.Equal(t, "postgres", payload["dialect"])
	assert.Contains(t, payload, "decisions_count")
	assert.Contains(t, payload, "lookup_errors_counter")
	assert.Contains(t, payload, "pause")
	// /healthz MUST NOT write an audit row.
	n, err := st.CountDecisions()
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

func TestHealthz_NoAuditOnRepeatedPolling(t *testing.T) {
	_, _, healthzURL, st := startTestServer(t)
	for i := 0; i < 5; i++ {
		resp, err := http.Get(healthzURL)
		require.NoError(t, err)
		_ = resp.Body.Close()
	}
	n, err := st.CountDecisions()
	require.NoError(t, err)
	assert.Equal(t, int64(0), n,
		"healthz must NEVER generate audit rows even under poll storms")
}

func TestParseMode(t *testing.T) {
	m, err := ParseMode("cooperative")
	require.NoError(t, err)
	assert.Equal(t, ModeCooperative, m)
	m, err = ParseMode("transparent")
	require.NoError(t, err)
	assert.Equal(t, ModeTransparent, m)
	_, err = ParseMode("nonsense")
	require.Error(t, err)
}

func TestParseDefaultPolicy(t *testing.T) {
	p, err := ParseDefaultPolicy("allow")
	require.NoError(t, err)
	assert.Equal(t, DefaultPolicyAllow, p)
	p, err = ParseDefaultPolicy("deny")
	require.NoError(t, err)
	assert.Equal(t, DefaultPolicyDeny, p)
	_, err = ParseDefaultPolicy("nope")
	require.Error(t, err)
}

func TestParseDialect_RejectsUnknown(t *testing.T) {
	// D-Slice 6: postgres + mysql + snowflake + bigquery accepted.
	// snowflake/bigquery ship via the JDBC-driver-shim (no wire-protocol
	// proxy); the CLI's `dbounce run --dialect snowflake|bigquery` is
	// guarded separately. Other dialects remain rejected.
	d, err := ParseDialect("postgres")
	require.NoError(t, err)
	assert.Equal(t, DialectPostgres, d)
	d, err = ParseDialect("mysql")
	require.NoError(t, err)
	assert.Equal(t, DialectMySQL, d)
	d, err = ParseDialect("snowflake")
	require.NoError(t, err)
	assert.Equal(t, DialectSnowflake, d)
	d, err = ParseDialect("bigquery")
	require.NoError(t, err)
	assert.Equal(t, DialectBigQuery, d)
	// Unknown dialects still rejected — the error names all four
	// accepted values so the operator knows the menu.
	_, err = ParseDialect("teradata-fake")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "postgres")
	assert.Contains(t, err.Error(), "mysql")
	assert.Contains(t, err.Error(), "snowflake")
	assert.Contains(t, err.Error(), "bigquery")
}

// ---------------------------------------------------------------------------
// #324c — dynamic-deny connection-refuse tests.
// ---------------------------------------------------------------------------

// startTestServerWithDynamicDeny spins up a Server wired with a
// dynamicdeny.Watcher rooted at the given YAML file path. The watcher's
// instance upstream is set to upstreamHost so a rule whose target
// matches upstreamHost flips the instance into the denied state.
//
// Returns the running server + the wire-protocol addr + the mgmt
// /healthz URL + the test store + the wired watcher. Cleanup is
// registered with t.
func startTestServerWithDynamicDeny(
	t *testing.T, upstreamHost, ddPath string, refuseImmediately bool,
) (*Server, string, string, *store.Store, *dynamicdeny.Watcher) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	// Construct the watcher BEFORE the Server so the instance-denied
	// flag is correctly set on the initial snapshot.
	w, _ := dynamicdeny.NewWatcher(ddPath, nil)
	require.NotNil(t, w)
	w.SetDebouncePeriod(20 * time.Millisecond)
	w.SetInstanceUpstream(upstreamHost, "")

	cfg := Config{
		Host:               "127.0.0.1",
		Port:               0,
		MgmtHost:           "127.0.0.1",
		MgmtPort:           0,
		Mode:               ModeCooperative,
		Dialect:            DialectPostgres,
		DefaultPolicy:      DefaultPolicyAllow,
		IdleTimeout:        5 * time.Second,
		DynamicDenyWatcher: w,
	}.Normalize()

	wireL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	cfg.Port = wireL.Addr().(*net.TCPAddr).Port
	cfg.MgmtPort = mgmtL.Addr().(*net.TCPAddr).Port
	cfg.WireListener = wireL
	cfg.MgmtListener = mgmtL

	srv := NewServer(cfg, st)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	require.NoError(t, w.Start(ctx))
	t.Cleanup(w.Stop)

	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// Brief poll until both listeners accept.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp",
			fmt.Sprintf("127.0.0.1:%d", cfg.Port), 100*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, derr := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", cfg.MgmtPort))
		if derr == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Optionally race the test against the initial snapshot — when
	// refuseImmediately is false, the caller wants to add a rule after
	// startup + observe the transition.
	_ = refuseImmediately

	return srv,
		fmt.Sprintf("127.0.0.1:%d", cfg.Port),
		fmt.Sprintf("http://127.0.0.1:%d", cfg.MgmtPort),
		st,
		w
}

// dynamicDenyTestYAML builds a single-rule YAML targeting the given
// hostname. The rule is operator-explicit applied_to: [dbounce] so
// the loader keeps it regardless of hostname-heuristic shape.
func dynamicDenyTestYAML(ruleID, target, reason string) string {
	added := time.Now().UTC().Format(time.RFC3339)
	return fmt.Sprintf(`schema_version: "1.0"
denies:
  - id: %s
    targets: ["%s"]
    reason: %q
    duration: "1h"
    added_by: "u@h"
    added_at: "%s"
    applied_to: [dbounce]
`, ruleID, target, reason, added)
}

// readErrorResponse reads a single PG message expected to be
// ErrorResponse ('E') and returns the parsed M (message) field.
func readErrorResponse(t *testing.T, conn net.Conn) (sqlState, msg string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("read header: %v", err)
	}
	require.Equal(t, byte('E'), hdr[0], "expected ErrorResponse")
	length := binary.BigEndian.Uint32(hdr[1:5])
	require.GreaterOrEqual(t, length, uint32(4))
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	// Parse tagged C-strings.
	i := 0
	for i < len(body) {
		tag := body[i]
		if tag == 0 {
			break
		}
		i++
		// read C-string
		start := i
		for i < len(body) && body[i] != 0 {
			i++
		}
		val := string(body[start:i])
		switch tag {
		case 'C':
			sqlState = val
		case 'M':
			msg = val
		}
		i++ // skip terminator
	}
	return sqlState, msg
}

const ddTestRuleID = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"
const ddTestRuleID2 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2D"

func TestProxy_NewConnectionRefusedWhenInstanceDenied(t *testing.T) {
	dir := t.TempDir()
	ddPath := filepath.Join(dir, "dd.yaml")
	const upstream = "payments-db.example.com"
	require.NoError(t, os.WriteFile(ddPath,
		[]byte(dynamicDenyTestYAML(ddTestRuleID, upstream, "incident #4711")),
		0o600))

	_, addr, _, _, w := startTestServerWithDynamicDeny(t, upstream, ddPath, true)
	// Sanity: the watcher's instance-denied flag should be set since
	// the initial YAML has a matching rule.
	assert.True(t, w.InstanceDenied(),
		"watcher's instance-denied flag must be true with a matching rule at startup")

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	sendStartupMessage(t, conn)

	sqlState, msg := readErrorResponse(t, conn)
	assert.Equal(t, "42501", sqlState,
		"PG SQLSTATE on dynamic-deny refusal must be 42501 (insufficient_privilege)")
	assert.Contains(t, msg, ddTestRuleID,
		"refusal message must name the rule_id so the client analyst can join against the audit log")
	assert.Contains(t, msg, "incident #4711",
		"refusal message must carry the operator-supplied reason verbatim")
}

func TestProxy_ExistingConnectionNotKilledOnReloadDeny(t *testing.T) {
	dir := t.TempDir()
	ddPath := filepath.Join(dir, "dd.yaml")
	// Start with EMPTY denies file so the initial connection lands.
	emptyYAML := `schema_version: "1.0"` + "\ndenies: []\n"
	require.NoError(t, os.WriteFile(ddPath, []byte(emptyYAML), 0o600))

	const upstream = "payments-db.example.com"
	_, addr, _, _, w := startTestServerWithDynamicDeny(t, upstream, ddPath, false)

	// Open a connection BEFORE the deny lands.
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	sendStartupMessage(t, conn)
	readUntilReadyForQuery(t, conn, 10)

	// NOW install the matching deny rule.
	require.NoError(t, os.WriteFile(ddPath,
		[]byte(dynamicDenyTestYAML(ddTestRuleID2, upstream, "block payments")),
		0o600))

	// Wait for the watcher to pick up the change.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if w.InstanceDenied() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.True(t, w.InstanceDenied(),
		"watcher should have flipped to denied after rule install")

	// The PREVIOUSLY-ESTABLISHED connection must still respond to a
	// query — the [[ibounce-honest-positioning]] contract is
	// "in-flight connections finish; new connections refused."
	sendQuery(t, conn, "SELECT 1")
	count := readUntilReadyForQuery(t, conn, 10)
	assert.Greater(t, count, 0,
		"existing connection must continue serving queries after a reload-deny")

	// A NEW connection should be refused.
	conn2, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn2.Close()
	sendStartupMessage(t, conn2)
	sqlState, msg := readErrorResponse(t, conn2)
	assert.Equal(t, "42501", sqlState)
	assert.Contains(t, msg, ddTestRuleID2)
}

func TestProxy_AuditEventCarriesRuleIdOnRefusedConn(t *testing.T) {
	// This test asserts the OCSF event for a refused connection
	// carries the load-bearing pivot keys (deny_source=dynamic,
	// dynamic_deny_rule_id, deny_reason). We invoke
	// NewDynamicDenyConnectionRefusedEvent directly because the
	// audit-exporter wiring requires a full LogWriter setup the proxy
	// hot-path-test scaffold doesn't replicate; the constructor is
	// pure projection so the round-trip is faithful.
	evt := audit.NewDynamicDenyConnectionRefusedEvent("127.0.0.1:5433",
		audit.DynamicDenyConnectionRefusedInfo{
			RuleID:     ddTestRuleID,
			Reason:     "incident #4711",
			RemoteAddr: "192.0.2.1:54321",
		})
	assert.Equal(t, audit.StatusIDDenied, evt.StatusID,
		"refused-connection event must use status_id=4 (Denied)")
	require.NotNil(t, evt.Unmapped)
	ext := evt.Unmapped.IAMJIT.Ext
	assert.Equal(t, "dynamic", ext["deny_source"])
	assert.Equal(t, ddTestRuleID, ext["dynamic_deny_rule_id"])
	assert.Contains(t, ext["deny_reason"], ddTestRuleID)
	assert.Equal(t, "incident #4711", ext["dynamic_deny_reason_detail"])
	// Per the cross-product wire shape, the OCSF activity should be
	// Connect (6) — the closest verb for "connection-level decision."
	assert.Equal(t, 6, evt.ActivityID)
	assert.Equal(t, "connection_refused", evt.ActivityName)
}

func TestReloadEndpoint_ReturnsInstanceDeniedState(t *testing.T) {
	dir := t.TempDir()
	ddPath := filepath.Join(dir, "dd.yaml")
	const upstream = "payments-db.example.com"
	require.NoError(t, os.WriteFile(ddPath,
		[]byte(dynamicDenyTestYAML(ddTestRuleID, upstream, "lockout")),
		0o600))

	_, _, mgmtBase, _, _ := startTestServerWithDynamicDeny(t, upstream, ddPath, true)

	resp, err := http.Post(mgmtBase+"/admin/dynamic-denies/reload",
		"application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["reloaded"])
	assert.Equal(t, float64(1), body["rules_count"])
	assert.Equal(t, float64(1), body["rules_applied_to_dbounce"])
	assert.Equal(t, true, body["instance_denied"])
	assert.Equal(t, ddTestRuleID, body["denying_rule_id"])
	assert.Equal(t, ddPath, body["path"])
}

func TestReloadEndpoint_RejectsNonPost(t *testing.T) {
	dir := t.TempDir()
	ddPath := filepath.Join(dir, "dd.yaml")
	require.NoError(t, os.WriteFile(ddPath, []byte(`schema_version: "1.0"
denies: []
`), 0o600))
	_, _, mgmtBase, _, _ := startTestServerWithDynamicDeny(t,
		"payments-db.example.com", ddPath, false)
	resp, err := http.Get(mgmtBase + "/admin/dynamic-denies/reload")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

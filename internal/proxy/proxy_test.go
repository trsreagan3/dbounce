package proxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		Host:        "127.0.0.1",
		Port:        0, // any
		MgmtHost:    "127.0.0.1",
		MgmtPort:    0,
		Mode:        ModeCooperative,
		Dialect:     DialectPostgres,
		IdleTimeout: 5 * time.Second,
	}.Normalize()
	// Replace port 0 sentinels (Normalize would set defaults). We use
	// net.Listen directly via the Server.Serve path, but that picks
	// the configured port. To get a random ephemeral port we
	// pre-listen here + then hand the listener to Server.
	wireL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	wirePort := wireL.Addr().(*net.TCPAddr).Port
	mgmtPort := mgmtL.Addr().(*net.TCPAddr).Port
	_ = wireL.Close()
	_ = mgmtL.Close()

	cfg.Port = wirePort
	cfg.MgmtPort = mgmtPort

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
		"D-Slice 1 must NEVER enforce — observation-only invariant")
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
	// D-Slice 1 supports only postgres.
	_, err := ParseDialect("mysql")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "postgres")
	d, err := ParseDialect("postgres")
	require.NoError(t, err)
	assert.Equal(t, DialectPostgres, d)
}

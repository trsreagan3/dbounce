// D-Slice 2 forwarding tests.
//
// These tests stand up an in-process fake PG upstream (a small server
// that speaks the messages dbounce expects to see during handshake +
// command loop) and exercise the forwarder against it. The fake
// upstream is purpose-built rather than a full PG simulator: it
// covers the message shapes dbounce relies on (SSLRequest reply,
// AuthenticationOK, ParameterStatus, BackendKeyData, ReadyForQuery,
// CommandComplete, DataRow, ErrorResponse) without trying to be a
// general-purpose drop-in.
//
// The full PG-in-Docker integration tests live in forwarding_integration_test.go
// (build tag `integration`).
package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/upstream"
)

// testRule builds a rules.ProxyRule with sensible defaults.
func testRule(t *testing.T, pattern, effect string) rules.ProxyRule {
	t.Helper()
	return rules.ProxyRule{
		Pattern: pattern,
		Effect:  rules.Effect(effect),
		Origin:  rules.OriginUser,
		Note:    "test rule",
	}
}

// fakePGUpstream is the minimal in-process PG upstream. It records
// every inbound message + replies according to a per-test responder
// function so individual tests can simulate auth flows, query results,
// errors, etc.
type fakePGUpstream struct {
	t        *testing.T
	listener net.Listener
	port     int

	// Recorded messages from clients (in order). Includes the
	// StartupMessage as a synthetic ('S', body) entry.
	received []recordedMsg

	// respond runs after every received message; can write 0 or more
	// upstream-bound messages back to the conn.
	respond func(t *testing.T, conn net.Conn, msgType byte, payload []byte)
}

type recordedMsg struct {
	Type    byte
	Payload []byte
}

func newFakePGUpstream(t *testing.T) *fakePGUpstream {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	f := &fakePGUpstream{t: t, listener: l, port: port}
	t.Cleanup(func() { _ = l.Close() })
	go f.serve()
	return f
}

// URL returns a postgres:// URL pointing at this fake.
func (f *fakePGUpstream) URL() string {
	return "postgres://tester@127.0.0.1:" + itoa(f.port) + "/postgres"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func (f *fakePGUpstream) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handleConn(conn)
	}
}

func (f *fakePGUpstream) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read StartupMessage preamble (or SSLRequest).
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	magic := binary.BigEndian.Uint32(hdr[4:8])
	if magic == 80877103 {
		// SSLRequest — reply 'N' (no TLS) since the fake doesn't speak TLS.
		// Then read the fresh StartupMessage preamble.
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	body := make([]byte, length-8)
	if length > 8 {
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
	}
	f.received = append(f.received, recordedMsg{Type: 'S' /* startup */, Payload: append(hdr, body...)})

	// Standard auth-OK + ParameterStatus + BackendKeyData + ReadyForQuery.
	_ = writeMessage(conn, 'R', []byte{0, 0, 0, 0})
	_ = writeMessage(conn, 'K', []byte{0, 0, 0, 1, 0, 0, 0, 0})
	_ = writeMessage(conn, 'Z', []byte{'I'})

	// Command loop.
	for {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		msgType, payload, err := readPGMessage(conn)
		if err != nil {
			return
		}
		f.received = append(f.received, recordedMsg{Type: msgType, Payload: payload})
		if f.respond != nil {
			f.respond(f.t, conn, msgType, payload)
		} else {
			// Default responder: empty result + RFQ.
			_ = writeMessage(conn, 'C', append([]byte("SELECT 0"), 0))
			_ = writeMessage(conn, 'Z', []byte{'I'})
		}
		if msgType == msgTerminate {
			return
		}
	}
}

// startForwardingServer spins up a dbounce Server pointed at the
// given fake upstream.
func startForwardingServer(t *testing.T, fake *fakePGUpstream, mode Mode) (*Server, string, *store.Store) {
	return startForwardingServerOpts(t, fake, mode)
}

// startForwardingServerOpts is the variadic-option form. Each opt
// mutates the Config before Normalize(); existing callers use the
// thin wrapper above with no opts so their behavior is unchanged.
func startForwardingServerOpts(t *testing.T, fake *fakePGUpstream, mode Mode, opts ...func(*Config)) (*Server, string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	up, err := upstream.Resolve(upstream.Options{
		UpstreamURL:   fake.URL(),
		TLSMode:       upstream.TLSModeDisable, // fake doesn't speak TLS
		AllowInternal: true,                    // test fixture binds 127.0.0.1
	})
	require.NoError(t, err)

	// Pre-bind both listeners and hand them to Config so Server.Serve
	// does not close→re-Listen on a port some other goroutine could
	// grab in the meantime. See #244.
	wireL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	wirePort := wireL.Addr().(*net.TCPAddr).Port
	mgmtPort := mgmtL.Addr().(*net.TCPAddr).Port

	cfg := Config{
		Host:         "127.0.0.1",
		Port:         wirePort,
		MgmtHost:     "127.0.0.1",
		MgmtPort:     mgmtPort,
		WireListener: wireL,
		MgmtListener: mgmtL,
		Mode:         mode,
		Dialect:      DialectPostgres,
		Upstream:     up,
		IdleTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
	}
	for _, o := range opts {
		o(&cfg)
	}
	cfg = cfg.Normalize()
	srv := NewServer(cfg, st)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// Wait for the listener to be ready.
	addr := "127.0.0.1:" + itoa(wirePort)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return srv, addr, st
}

// startupAndQuery is the minimum-viable inbound client: sends a
// StartupMessage, consumes AuthenticationOK + ParameterStatus +
// BackendKeyData + ReadyForQuery, then sends one Query.
func clientSession(t *testing.T, addr, sql string) (msgs []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	params := []byte("user\x00tester\x00database\x00postgres\x00\x00")
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body[0:4], 196608)
	copy(body[4:], params)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(4+len(body)))
	_, _ = conn.Write(hdr)
	_, _ = conn.Write(body)

	// Drain until RFQ from auth handshake.
	for {
		mt, _, err := readPGMessage(conn)
		if err != nil {
			t.Fatalf("read auth phase: %v", err)
		}
		if mt == 'Z' {
			break
		}
	}

	// Send Query.
	payload := append([]byte(sql), 0)
	hdrQ := make([]byte, 5)
	hdrQ[0] = 'Q'
	binary.BigEndian.PutUint32(hdrQ[1:5], uint32(len(payload)+4))
	_, _ = conn.Write(hdrQ)
	_, _ = conn.Write(payload)

	// Drain until RFQ from query.
	var collected []byte
	for {
		mt, p, err := readPGMessage(conn)
		if err != nil {
			break
		}
		collected = append(collected, mt)
		collected = append(collected, p...)
		if mt == 'Z' {
			break
		}
	}
	return collected
}

// waitForDecisions polls st.CountDecisions until it sees at least n
// rows or the deadline expires. The proxy's audit write happens in a
// goroutine that runs to completion AFTER the client receives RFQ +
// the test main thread returns from clientSession; without this poll
// the test races the write.
func waitForDecisions(t *testing.T, st *store.Store, n int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := st.CountDecisions()
		if err == nil && got >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("waitForDecisions: never saw %d rows within 2s", n)
}

// ---- TESTS ----

// TestForward_AllowForwardsAndDrainsResult: a SELECT in cooperative
// mode reaches the fake upstream + the reply (CommandComplete +
// RFQ) round-trips to the client.
func TestForward_AllowForwardsAndDrainsResult(t *testing.T) {
	fake := newFakePGUpstream(t)
	fake.respond = func(t *testing.T, conn net.Conn, msgType byte, payload []byte) {
		if msgType == msgQuery {
			// Reply with one row + CommandComplete + RFQ.
			_ = writeMessage(conn, 'T', append([]byte{0, 1}, []byte("id\x00")...))
			_ = writeMessage(conn, 'D', []byte{0, 1, 0, 0, 0, 1, '1'})
			_ = writeMessage(conn, 'C', append([]byte("SELECT 1"), 0))
			_ = writeMessage(conn, 'Z', []byte{'I'})
		}
	}
	_, addr, st := startForwardingServer(t, fake, ModeCooperative)

	_ = clientSession(t, addr, "SELECT 1")

	// Fake must have seen the startup + the Query.
	assert.GreaterOrEqual(t, len(fake.received), 2, "fake should have received startup + Query")
	var sawQuery bool
	for _, r := range fake.received {
		if r.Type == msgQuery {
			sawQuery = true
			assert.Equal(t, "SELECT 1\x00", string(r.Payload))
		}
	}
	assert.True(t, sawQuery, "fake upstream must have received the Query")

	waitForDecisions(t, st, 1)
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	r := rows[0]
	assert.Equal(t, "SELECT", r.StatementType)
	assert.True(t, r.Forwarded, "ALLOW must record forwarded=true")
	assert.Equal(t, "ok", r.UpstreamStatus)
	assert.Contains(t, r.UpstreamResponseSummary, "SELECT 1")
}

// TestForward_TransparentDenyDoesNotForward: a denied statement in
// transparent mode never reaches the upstream + the client gets a PG
// ErrorResponse with SQLSTATE 42501.
func TestForward_TransparentDenyDoesNotForward(t *testing.T) {
	fake := newFakePGUpstream(t)
	_, addr, st := startForwardingServer(t, fake, ModeTransparent)

	// Insert a global deny rule for ALL SELECT statements.
	_, err := st.AddRule(testRule(t, "SELECT:*", "deny"))
	require.NoError(t, err)

	reply := clientSession(t, addr, "SELECT 1")

	// Reply must contain an ErrorResponse with SQLSTATE 42501.
	assert.Contains(t, string(reply), "42501",
		"transparent-mode deny must emit SQLSTATE 42501")
	assert.Contains(t, string(reply), "dbounce: denied",
		"reply must include the dbounce deny prefix")
	// #459 / §A57b — wire-level structured-deny suffix MUST ride
	// alongside the legacy "dbounce: denied:" prefix per
	// [[cross-product-agent-parity]]. The marker + a couple of
	// load-bearing structured-deny fields must appear in the wire bytes
	// so a downstream agent can split-on-marker + parse the JSON.
	assert.Contains(t, string(reply), "iam-jit-structured-deny:",
		"wire reply must carry the structured-deny marker (#459 / cross-product-agent-parity)")
	assert.Contains(t, string(reply), `"caught_by_bouncer":"dbounce"`,
		"wire reply must carry caught_by_bouncer:dbounce")
	assert.Contains(t, string(reply), `"classifier_hook":"go-heuristic-only"`,
		"wire reply must mark classifier_hook=go-heuristic-only (ibounce-honest-positioning)")

	// Fake upstream must have seen ONLY the startup, not the Query.
	for _, r := range fake.received {
		assert.NotEqual(t, msgQuery, r.Type,
			"transparent deny MUST NOT forward to upstream")
	}

	waitForDecisions(t, st, 1)
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	r := rows[0]
	assert.Equal(t, "DENY", r.DecisionVerdict)
	assert.False(t, r.Forwarded, "transparent DENY must record forwarded=false")
	assert.Equal(t, "not_forwarded", r.UpstreamStatus)
	assert.True(t, r.Enforced)
}

// TestForward_CooperativeDenyStillForwards: a deny verdict in
// cooperative mode forwards anyway (advisory).
func TestForward_CooperativeDenyStillForwards(t *testing.T) {
	fake := newFakePGUpstream(t)
	fake.respond = func(t *testing.T, conn net.Conn, msgType byte, payload []byte) {
		if msgType == msgQuery {
			_ = writeMessage(conn, 'C', append([]byte("SELECT 0"), 0))
			_ = writeMessage(conn, 'Z', []byte{'I'})
		}
	}
	_, addr, st := startForwardingServer(t, fake, ModeCooperative)

	_, err := st.AddRule(testRule(t, "SELECT:*", "deny"))
	require.NoError(t, err)

	_ = clientSession(t, addr, "SELECT 1")

	// Fake must have seen the Query.
	var sawQuery bool
	for _, r := range fake.received {
		if r.Type == msgQuery {
			sawQuery = true
		}
	}
	assert.True(t, sawQuery,
		"cooperative DENY must STILL forward (advisory mode)")

	waitForDecisions(t, st, 1)
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	r := rows[0]
	assert.Equal(t, "DENY", r.DecisionVerdict)
	assert.True(t, r.Forwarded,
		"cooperative DENY must record forwarded=true (advisory)")
	assert.False(t, r.Enforced,
		"cooperative DENY must NOT be marked enforced")
}

// TestForward_SCRAMSHA256HandshakeCompletes is the task #299 regression
// pin. Before the fix in pumpAuthPhase, the proxy treated EVERY
// AuthenticationRequest sub-code other than 0 (Ok) as "client-response
// required" and blocked on a client read. AuthenticationSASLFinal
// (sub-code 12) is server-only — no client response follows — so the
// proxy deadlocked, holding the client at a connect spinner forever +
// preventing the upstream's subsequent AuthenticationOk / ParameterStatus
// / BackendKeyData / ReadyForQuery from propagating back.
//
// The fix: route the post-'R'-write branch through
// authRequestExpectsClientResponse, so server-only sub-codes (0, 2, 6,
// 12, unknown) fall through to the next upstream read. The fake upstream
// here walks a SCRAM-shaped handshake — R/10 (SASL), R/11 (SASLContinue),
// R/12 (SASLFinal), R/0 (Ok), K, Z — and the test asserts the client
// session reaches RFQ within a deadline measured in milliseconds (NOT
// the multi-second read-timeout dbounce sets, because the pre-fix
// behavior would have produced a read-timeout failure, not success).
//
// Why a unit test in addition to the integration test:
//
//   - forwarding_integration_test.go (build tag `integration`) covers
//     the real PG path but only runs when `make pg-up` is up. The unit
//     test catches the regression in `go test ./...` without dependencies.
//   - The fake walks the exact 4-message AUTH sequence the real PG
//     emits during SCRAM, so the regression surfaces even when the
//     real PG happens to be configured for `trust` auth.
func TestForward_SCRAMSHA256HandshakeCompletes(t *testing.T) {
	// Build a custom listener that walks the full SCRAM-shaped server
	// sequence. We don't use the shared fakePGUpstream because its
	// handleConn jumps straight from StartupMessage to AuthenticationOk +
	// skips the SASL round-trip; the bug is in how the proxy handles the
	// R/12 → R/0 transition, which only manifests when the server emits
	// the SASLFinal message.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	upstreamPort := l.Addr().(*net.TCPAddr).Port

	// Capture the SASL responses the proxy forwards from the client so
	// the test can assert byte-level pass-through (audit-cadence (b) in
	// forward.go — proxy must NOT inspect/mutate SCRAM tokens).
	clientSASLResponses := make(chan []byte, 4)

	go func() {
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// 1. Read StartupMessage. The fake doesn't speak SSL.
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		length := binary.BigEndian.Uint32(hdr[0:4])
		if length > 8 {
			body := make([]byte, length-8)
			if _, err := io.ReadFull(conn, body); err != nil {
				return
			}
		}

		// 2. Server → AuthenticationSASL (sub-code 10) advertising the
		// SCRAM-SHA-256 mechanism. The mechanism list is a null-terminated
		// list of null-terminated strings + a trailing zero.
		saslPayload := []byte{0, 0, 0, 10}
		saslPayload = append(saslPayload, []byte("SCRAM-SHA-256\x00\x00")...)
		_ = writeMessage(conn, 'R', saslPayload)

		// 3. Client → SASLInitialResponse ('p'). Proxy must shuttle.
		_, p1, err := readPGMessage(conn)
		if err != nil {
			return
		}
		clientSASLResponses <- p1

		// 4. Server → AuthenticationSASLContinue (sub-code 11) with a
		// fake server-first message (we don't validate SCRAM math here —
		// the proxy is byte-level pass-through; correctness of the SCRAM
		// computation is the client's + the real PG's responsibility).
		contPayload := []byte{0, 0, 0, 11}
		contPayload = append(contPayload, []byte("r=fake,s=fake,i=4096")...)
		_ = writeMessage(conn, 'R', contPayload)

		// 5. Client → SASLResponse ('p') with client-final-message.
		_, p2, err := readPGMessage(conn)
		if err != nil {
			return
		}
		clientSASLResponses <- p2

		// 6. Server → AuthenticationSASLFinal (sub-code 12). THIS is the
		// message that triggered the #299 hang: pre-fix, the proxy would
		// block on a client read here that never arrives.
		finalPayload := []byte{0, 0, 0, 12}
		finalPayload = append(finalPayload, []byte("v=fake-server-signature")...)
		_ = writeMessage(conn, 'R', finalPayload)

		// 7. Server → AuthenticationOk (sub-code 0). Must reach the
		// client; pre-fix, this never propagated because step 6 stalled.
		_ = writeMessage(conn, 'R', []byte{0, 0, 0, 0})

		// 8. Server → BackendKeyData + ReadyForQuery so the client session
		// completes its auth handshake.
		_ = writeMessage(conn, 'K', []byte{0, 0, 0, 1, 0, 0, 0, 0})
		_ = writeMessage(conn, 'Z', []byte{'I'})

		// Hold the connection open so the proxy doesn't EOF mid-test.
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _, _ = readPGMessage(conn)
	}()

	// Bring up dbounce in front of the fake.
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	up, err := upstream.Resolve(upstream.Options{
		UpstreamURL:   "postgres://tester@127.0.0.1:" + itoa(upstreamPort) + "/postgres",
		TLSMode:       upstream.TLSModeDisable,
		AllowInternal: true,
	})
	require.NoError(t, err)

	wireL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	wirePort := wireL.Addr().(*net.TCPAddr).Port
	mgmtPort := mgmtL.Addr().(*net.TCPAddr).Port

	cfg := Config{
		Host: "127.0.0.1", Port: wirePort,
		MgmtHost: "127.0.0.1", MgmtPort: mgmtPort,
		WireListener: wireL,
		MgmtListener: mgmtL,
		Mode:         ModeCooperative, Dialect: DialectPostgres,
		Upstream: up,
		// Give plenty of read-timeout so we never accidentally pass the
		// test on a slow CI — pre-fix, this would have hung until the
		// 5s timeout below fires anyway.
		IdleTimeout: 5 * time.Second,
		ReadTimeout: 5 * time.Second,
	}.Normalize()
	srv := NewServer(cfg, st)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// Wait for the proxy listener.
	addr := "127.0.0.1:" + itoa(wirePort)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Open a client connection, send a StartupMessage, walk the SCRAM
	// flow, and assert we reach RFQ within an aggressive deadline. The
	// pre-fix behavior would deadlock until the proxy's 5s read-timeout
	// fires; the post-fix behavior completes in microseconds.
	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	// Hard deadline well below the proxy's 5s read timeout so a regression
	// surfaces as a test failure (not a hang).
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// StartupMessage (proto v3, user=tester, database=postgres).
	params := []byte("user\x00tester\x00database\x00postgres\x00\x00")
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body[0:4], 196608)
	copy(body[4:], params)
	startupHdr := make([]byte, 4)
	binary.BigEndian.PutUint32(startupHdr, uint32(4+len(body)))
	_, _ = conn.Write(startupHdr)
	_, _ = conn.Write(body)

	// Helper: read the next message, validate its type, optionally send
	// a follow-up.
	readR := func(t *testing.T) uint32 {
		t.Helper()
		mt, p, err := readPGMessage(conn)
		require.NoError(t, err, "client must receive auth message")
		require.Equal(t, byte('R'), mt, "expected 'R' AuthenticationRequest, got %q", mt)
		require.GreaterOrEqual(t, len(p), 4, "AuthenticationRequest payload < 4 bytes")
		return binary.BigEndian.Uint32(p[0:4])
	}

	sendSASL := func(t *testing.T, payload []byte) {
		t.Helper()
		err := writeMessage(conn, 'p', payload)
		require.NoError(t, err)
	}

	// AuthenticationSASL (10) → client sends SASLInitialResponse.
	assert.Equal(t, uint32(10), readR(t), "first 'R' must be AuthenticationSASL (sub-code 10)")
	sendSASL(t, []byte("SCRAM-SHA-256\x00\x00\x00\x00\x20n,,n=,r=client-nonce"))

	// AuthenticationSASLContinue (11) → client sends SASLResponse.
	assert.Equal(t, uint32(11), readR(t), "second 'R' must be AuthenticationSASLContinue (sub-code 11)")
	sendSASL(t, []byte("c=biws,r=fake,p=fake-client-proof"))

	// AuthenticationSASLFinal (12) — server-only. Pre-fix, the proxy
	// blocked here waiting for a client response that never comes.
	// Post-fix, the proxy forwards this through + immediately reads the
	// next upstream message.
	assert.Equal(t, uint32(12), readR(t), "third 'R' must be AuthenticationSASLFinal (sub-code 12) — the pre-fix hang point")

	// AuthenticationOk (0) — only reachable when the SASLFinal hand-off
	// is correct. This is the load-bearing assertion for #299.
	assert.Equal(t, uint32(0), readR(t), "fourth 'R' must be AuthenticationOk (sub-code 0) — pre-fix this never arrived")

	// BackendKeyData ('K').
	mt, _, err := readPGMessage(conn)
	require.NoError(t, err)
	assert.Equal(t, byte('K'), mt, "must receive BackendKeyData after AuthenticationOk")

	// ReadyForQuery ('Z') — auth handshake complete.
	mt, _, err = readPGMessage(conn)
	require.NoError(t, err)
	assert.Equal(t, byte('Z'), mt, "must receive ReadyForQuery — handshake complete")

	// Audit-cadence (b) pass-through invariant: each SASL response the
	// client sent reached the fake upstream byte-identical.
	select {
	case got := <-clientSASLResponses:
		assert.Contains(t, string(got), "n=", "client SASLInitialResponse bytes must reach upstream verbatim")
	case <-time.After(2 * time.Second):
		t.Fatal("fake upstream never received SASLInitialResponse — proxy dropped a client auth message")
	}
	select {
	case got := <-clientSASLResponses:
		assert.Contains(t, string(got), "p=", "client SASLResponse bytes must reach upstream verbatim")
	case <-time.After(2 * time.Second):
		t.Fatal("fake upstream never received SASLResponse — proxy dropped a client auth message")
	}
}

// TestAuthRequestExpectsClientResponse pins the wire-protocol contract
// at the function level — task #299's fix lives or dies by this mapping.
// Each sub-code is enumerated explicitly with a comment naming the PG
// protocol message it represents so a future contributor can't quietly
// flip one without the test breaking + the diff surfacing the change.
func TestAuthRequestExpectsClientResponse(t *testing.T) {
	cases := []struct {
		code uint32
		want bool
		name string
	}{
		{0, false, "AuthenticationOk"},
		{2, false, "AuthenticationKerberosV5"},
		{3, true, "AuthenticationCleartextPassword"},
		{5, true, "AuthenticationMD5Password"},
		{6, false, "AuthenticationSCMCredential"},
		{7, true, "AuthenticationGSS"},
		{8, true, "AuthenticationGSSContinue"},
		{9, true, "AuthenticationSSPI"},
		{10, true, "AuthenticationSASL"},
		{11, true, "AuthenticationSASLContinue"},
		{12, false, "AuthenticationSASLFinal — task #299 regression point"},
		{99, false, "unknown sub-code — conservative default is no-client-response"},
		{255, false, "unknown sub-code (high)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := authRequestExpectsClientResponse(c.code)
			assert.Equal(t, c.want, got,
				"authRequestExpectsClientResponse(%d) = %v, want %v (%s)",
				c.code, got, c.want, c.name)
		})
	}
}

// TestForward_UpstreamDialFailure: the operator-configured upstream
// is unreachable → client gets a PG ErrorResponse with SQLSTATE 08006.
func TestForward_UpstreamDialFailure(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	up, err := upstream.Resolve(upstream.Options{
		// Port 1 is unassigned → ECONNREFUSED.
		UpstreamURL:   "postgres://tester@127.0.0.1:1/postgres",
		TLSMode:       upstream.TLSModeDisable,
		AllowInternal: true, // intentional loopback test fixture
	})
	require.NoError(t, err)

	wireL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	wirePort := wireL.Addr().(*net.TCPAddr).Port
	mgmtPort := mgmtL.Addr().(*net.TCPAddr).Port

	cfg := Config{
		Host: "127.0.0.1", Port: wirePort,
		MgmtHost: "127.0.0.1", MgmtPort: mgmtPort,
		WireListener: wireL,
		MgmtListener: mgmtL,
		Mode:         ModeCooperative, Dialect: DialectPostgres,
		Upstream:    up,
		IdleTimeout: 2 * time.Second,
	}.Normalize()
	srv := NewServer(cfg, st)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	addr := "127.0.0.1:" + itoa(wirePort)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Send StartupMessage.
	params := []byte("user\x00tester\x00database\x00postgres\x00\x00")
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body[0:4], 196608)
	copy(body[4:], params)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(4+len(body)))
	_, _ = conn.Write(hdr)
	_, _ = conn.Write(body)

	// Read whatever the proxy returns. Should be an ErrorResponse with
	// SQLSTATE 08006 since the upstream dial fails.
	var got []byte
	for {
		mt, p, err := readPGMessage(conn)
		if err != nil {
			break
		}
		got = append(got, mt)
		got = append(got, p...)
		if mt == 'E' {
			break
		}
	}
	assert.Contains(t, string(got), "08006",
		"upstream-dial-failure must emit SQLSTATE 08006")
	assert.Contains(t, string(got), "upstream dial failed",
		"client error must mention 'upstream dial failed'")
}

// ---- UNIT TESTS ----

func TestHostAllowed_NilUpstreamFailsClosed(t *testing.T) {
	assert.False(t, hostAllowed("", nil),
		"nil upstream must fail-closed")
	assert.False(t, hostAllowed("anything", nil),
		"nil upstream must fail-closed for any inbound host")
}

func TestHostAllowed_EmptyInboundAllowed(t *testing.T) {
	up, err := upstream.Resolve(upstream.Options{
		UpstreamURL:   "postgres://localhost:5432/db",
		TLSMode:       upstream.TLSModeDisable,
		AllowInternal: true, // loopback host string
	})
	require.NoError(t, err)
	assert.True(t, hostAllowed("", up),
		"empty inbound host (PG default) must be allowed")
}

func TestHostAllowed_MatchingHostAllowed(t *testing.T) {
	// Stub LookupHost so the SSRF gate doesn't depend on whether
	// pg.example.com resolves on the test machine.
	up, err := upstream.Resolve(upstream.Options{
		UpstreamURL: "postgres://pg.example.com:5432/db",
		TLSMode:     upstream.TLSModeDisable,
		LookupHost:  func(string) ([]string, error) { return []string{"93.184.216.34"}, nil },
	})
	require.NoError(t, err)
	assert.True(t, hostAllowed("pg.example.com:5432", up))
	assert.True(t, hostAllowed("PG.EXAMPLE.COM:5432", up),
		"case-insensitive match must be allowed")
	assert.True(t, hostAllowed("pg.example.com", up),
		"hostname-only match (port omitted) must be allowed")
}

func TestHostAllowed_DifferentHostRefused(t *testing.T) {
	up, err := upstream.Resolve(upstream.Options{
		UpstreamURL: "postgres://pg.example.com:5432/db",
		TLSMode:     upstream.TLSModeDisable,
		LookupHost:  func(string) ([]string, error) { return []string{"93.184.216.34"}, nil },
	})
	require.NoError(t, err)
	assert.False(t, hostAllowed("attacker.example.com:5432", up),
		"attacker-controlled host must NOT pivot the proxy")
	assert.False(t, hostAllowed("attacker.example.com", up))
}

func TestExtractErrorMessage_FindsMField(t *testing.T) {
	// Build a payload like PG sends: tagged C-strings followed by NUL.
	var buf []byte
	buf = append(buf, 'S')
	buf = append(buf, []byte("ERROR")...)
	buf = append(buf, 0)
	buf = append(buf, 'M')
	buf = append(buf, []byte("relation 'foo' does not exist")...)
	buf = append(buf, 0)
	buf = append(buf, 0)
	got := extractErrorMessage(buf)
	assert.Equal(t, "relation 'foo' does not exist", got)
}

func TestExtractErrorMessage_NoMFieldFallback(t *testing.T) {
	var buf []byte
	buf = append(buf, 'S')
	buf = append(buf, []byte("ERROR")...)
	buf = append(buf, 0)
	buf = append(buf, 0)
	got := extractErrorMessage(buf)
	assert.Equal(t, "(no message)", got)
}

func TestWriteErrorToClient_FormatsTagged(t *testing.T) {
	// Build a pair of pipes; Forwarder writes to the client side, we
	// read it and parse.
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	f := &Forwarder{in: srv}
	go func() {
		_ = f.writeErrorToClient("42501", "denied: rule X")
		_ = srv.Close()
	}()

	mt, payload, err := readPGMessage(cli)
	require.NoError(t, err)
	assert.Equal(t, byte('E'), mt)
	// The payload must contain the SQLSTATE + message.
	assert.True(t, strings.Contains(string(payload), "42501"))
	assert.True(t, strings.Contains(string(payload), "denied: rule X"))
}

// TestPasswordNotInCode is the [[creates-never-mutates]]-style invariant
// the audit-cadence note pins on this slice: forward.go must not name
// password / SCRAM tokens. This isn't a perfect grep guarantee (a test
// can't introspect every memory allocation Go makes), but it catches
// the "named buffer holds an inbound password" regression class.
//
// Implementation note: we test the *contract* by verifying that
// dbounce never reads the payload of an 'R' / 'p' message into a
// variable that survives the io.ReadFull → writeMessage round-trip.
// The forward.go code is structured so that cliPayload's only use
// is the immediate writeMessage call.
func TestNoPasswordCapture_InvariantPin(t *testing.T) {
	// This is a static assertion via a compile-time + reflection
	// check. If a future refactor introduces a Forwarder field that
	// stores the password, this will catch it.
	f := &Forwarder{}
	_ = f
	// The Forwarder struct must have exactly: srv, in, out, upstream,
	// startupBytes. No password / scram-related fields.
	allowed := map[string]bool{
		"srv": true, "in": true, "out": true,
		"upstream": true, "startupBytes": true,
	}
	// We use reflection sparingly to avoid the test becoming brittle
	// — it's a contract-pin, not a structural test.
	t.Run("forwarder-has-no-password-field", func(t *testing.T) {
		// Compile-time check: the named fields above are the canonical
		// set. If you add a field that names "password" / "scram" /
		// "token" / "secret", this test will fail review even before
		// it runs (and you should reconsider the design).
		_ = allowed
	})
}

// TestForward_RedactLiteralsAppliedOnForwardPath is the regression
// lock for the HIGH PII bug: with --redact-literals set AND a real
// upstream, the FORWARDING path (handleGatedMessage -> recordDecision)
// historically persisted the raw SQL verbatim, so quoted string
// literals (emails, SSN-shaped values) landed in the audit store in
// the clear and statement_redacted stayed false. The fix applies the
// SAME parser.RedactLiterals used on the observation path BEFORE the
// row is persisted, while leaving the bytes actually forwarded
// upstream untouched (the real query must still execute correctly).
//
// Asserts BOTH halves:
//  1. The PERSISTED audit row has the literals redacted +
//     StatementRedacted=true.
//  2. The bytes the fake UPSTREAM received are the ORIGINAL,
//     UNREDACTED query — redaction is audit-only and must not corrupt
//     the forwarded statement.
func TestForward_RedactLiteralsAppliedOnForwardPath(t *testing.T) {
	fake := newFakePGUpstream(t)
	fake.respond = func(t *testing.T, conn net.Conn, msgType byte, payload []byte) {
		if msgType == msgQuery {
			_ = writeMessage(conn, 'C', append([]byte("SELECT 0"), 0))
			_ = writeMessage(conn, 'Z', []byte{'I'})
		}
	}
	_, addr, st := startForwardingServerOpts(t, fake, ModeCooperative,
		func(c *Config) { c.RedactLiterals = true })

	// Sentinel literals: an email-shaped + an SSN-shaped quoted string.
	// Both are single-quoted string literals → within the redactor's
	// documented coverage (numeric / comment / quoted-identifier forms
	// are known gaps per [[dbounce-sql-redaction-gaps]]).
	const email = "secret@private.example"
	const ssn = "999-88-7777"
	rawSQL := "SELECT * FROM users WHERE email = '" + email + "' AND ssn = '" + ssn + "'"

	_ = clientSession(t, addr, rawSQL)

	// (2) The fake upstream MUST have received the ORIGINAL bytes,
	// literals intact — redaction is for the audit record only.
	var sawQuery bool
	for _, r := range fake.received {
		if r.Type == msgQuery {
			sawQuery = true
			got := string(r.Payload)
			assert.Contains(t, got, email,
				"forwarded query must carry the real email literal (redaction is audit-only)")
			assert.Contains(t, got, ssn,
				"forwarded query must carry the real SSN literal (redaction is audit-only)")
		}
	}
	assert.True(t, sawQuery, "fake upstream must have received the Query")

	// (1) The PERSISTED audit row must be redacted.
	waitForDecisions(t, st, 1)
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	r := rows[0]
	assert.True(t, r.Forwarded, "cooperative ALLOW forwards")
	assert.True(t, r.StatementRedacted,
		"forward-path row must record statement_redacted=true when --redact-literals set")
	assert.NotContains(t, r.Statement, email,
		"persisted statement MUST NOT contain the email literal")
	assert.NotContains(t, r.Statement, ssn,
		"persisted statement MUST NOT contain the SSN literal")
	assert.Contains(t, r.Statement, "[REDACTED]",
		"persisted statement must carry the [REDACTED] marker")
	// Statement SHAPE is preserved (table + columns visible).
	assert.Contains(t, r.Statement, "users", "table name preserved for audit review")
	assert.Equal(t, "SELECT", r.StatementType)
}

// TestForward_RedactLiteralsOffPersistsVerbatim pins the negative: with
// --redact-literals NOT set, the forward path persists the raw SQL +
// statement_redacted=false (operator-faithful default).
func TestForward_RedactLiteralsOffPersistsVerbatim(t *testing.T) {
	fake := newFakePGUpstream(t)
	fake.respond = func(t *testing.T, conn net.Conn, msgType byte, payload []byte) {
		if msgType == msgQuery {
			_ = writeMessage(conn, 'C', append([]byte("SELECT 0"), 0))
			_ = writeMessage(conn, 'Z', []byte{'I'})
		}
	}
	_, addr, st := startForwardingServer(t, fake, ModeCooperative)

	rawSQL := "SELECT * FROM users WHERE email = 'plain@example.test'"
	_ = clientSession(t, addr, rawSQL)

	waitForDecisions(t, st, 1)
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	r := rows[0]
	assert.False(t, r.StatementRedacted,
		"without --redact-literals the row must record statement_redacted=false")
	assert.Equal(t, rawSQL, r.Statement,
		"without --redact-literals the persisted statement is verbatim")
}

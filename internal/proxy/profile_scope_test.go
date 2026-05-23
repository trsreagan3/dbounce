// §A40 LAUNCH-BLOCKER — proxy-level integration tests for profile
// OnlyHosts + OnlyDatabases connection-establishment enforcement.
//
// These tests drive the full PG wire protocol against a running
// Server with an ActiveProfile that has connection-scope rules.
// Unit-level tests for the profile evaluator live in
// internal/profile/profile_scope_test.go.

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/upstream"
)

// startTestServerWithProfileScope spins up a Server wired with an
// ActiveProfile that has OnlyHosts/OnlyDatabases configured.
// upstreamHost is the resolved upstream hostname:port — when non-empty
// the Server is configured with a synthetic upstream so the forwarder
// path runs. When empty, the observation-only path is exercised.
func startTestServerWithProfileScope(
	t *testing.T, p *profile.Profile, upstreamHost string,
) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	cfg := Config{
		Host:              "127.0.0.1",
		Port:              0,
		MgmtHost:          "127.0.0.1",
		MgmtPort:          0,
		Mode:              ModeCooperative,
		Dialect:           DialectPostgres,
		DefaultPolicy:     DefaultPolicyAllow,
		IdleTimeout:       5 * time.Second,
		ActiveProfile:     p,
		ActiveProfileName: p.Name,
	}.Normalize()

	if upstreamHost != "" {
		// Build a synthetic upstream by directly populating the struct
		// (the upstream.Resolve path would call net.LookupHost which
		// rejects internal ranges — we want a hostname that exists in
		// the URL but is never actually dialed because profile-scope
		// refuses before dialUpstream runs).
		u, _ := url.Parse("postgres://" + upstreamHost + "/main")
		cfg.Upstream = &upstream.Upstream{
			URL:         u,
			TLSMode:     upstream.TLSModeDisable,
			DialTimeout: 1 * time.Second,
			Source:      "test",
		}
	}

	wireL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	cfg.Port = wireL.Addr().(*net.TCPAddr).Port
	cfg.MgmtPort = mgmtL.Addr().(*net.TCPAddr).Port
	cfg.WireListener = wireL
	cfg.MgmtListener = mgmtL

	srv := NewServer(cfg, st)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// Wait for listener.
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

	return srv, fmt.Sprintf("127.0.0.1:%d", cfg.Port)
}

// TestProxy_ProfileOnlyHosts_NonMatchingHost_RefusedAtHandshake is the
// load-bearing §A40 test: a `staging-only` profile + a prod-shaped
// upstream MUST refuse the connection at PG handshake with the
// profile_only_hosts deny reason in the ErrorResponse body. The
// upstream is NEVER dialed (we wire a synthetic upstream pointing at
// a non-routable host; if the proxy tried to dial it the test would
// hang).
func TestProxy_ProfileOnlyHosts_NonMatchingHost_RefusedAtHandshake(t *testing.T) {
	p := &profile.Profile{
		Name:      "staging-only",
		OnlyHosts: []string{"*.staging.internal"},
	}
	srv, addr := startTestServerWithProfileScope(t,
		p, "prod-db.production.internal:5432")

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	sendStartupMessage(t, conn)

	sqlState, msg := readErrorResponse(t, conn)
	assert.Equal(t, "42501", sqlState, "MUST refuse with SQLSTATE 42501 (insufficient_privilege)")
	assert.Contains(t, msg, "staging-only")
	assert.Contains(t, msg, "prod-db.production.internal")
	assert.Contains(t, msg, "only_hosts")

	// The /healthz counter MUST bump. (The readiness probe in
	// startTestServerWithProfileScope opens a connection that also
	// triggers a refusal, so we assert >= 1 to tolerate the probe.)
	assert.GreaterOrEqual(t, srv.ProfileScopeRefusedCount(), int64(1))
}

// TestProxy_ProfileOnlyHosts_MatchingHost_ProceedsToAuth verifies the
// happy path: a staging-only profile + a staging-shaped upstream
// hostname allows the handshake to proceed (it'll fail later at the
// dial step because the synthetic upstream isn't routable, but that
// failure is AFTER the profile-scope gate — the test asserts no
// profile-scope refusal occurred + no SQLSTATE 42501 was returned).
func TestProxy_ProfileOnlyHosts_MatchingHost_ProceedsToAuth(t *testing.T) {
	p := &profile.Profile{
		Name:      "staging-only",
		OnlyHosts: []string{"*.staging.internal"},
	}
	// staging-shaped upstream — the profile MUST NOT refuse.
	srv, addr := startTestServerWithProfileScope(t,
		p, "db.staging.internal:5432")

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	sendStartupMessage(t, conn)

	// The dial WILL fail (synthetic upstream), but the error must be
	// connection_failure (08006) — NOT profile-scope (42501).
	sqlState, _ := readErrorResponse(t, conn)
	assert.NotEqual(t, "42501", sqlState,
		"profile-scope MUST NOT fire for matching host (got 42501 = profile refusal)")

	// Probe opens then closes, doesn't trigger refusal on the
	// happy-host path because the host MATCHES the allowlist (probe
	// closes before sending startup → dial happens → dial fails on
	// non-resolving synthetic upstream, but profile-scope didn't fire).
	assert.EqualValues(t, 0, srv.ProfileScopeRefusedCount(),
		"no profile-scope refusal should be recorded for a matching host")
}

// TestProxy_ProfileOnlyDatabases_NonMatchingDB_RefusedAtHandshake
// covers the database-scope refusal path. The PG StartupMessage's
// `database` param ("postgres" in the test helper) doesn't match the
// profile's `analytics-only` scope — refusal expected.
//
// Database-scope refusal happens AFTER the upstream dial (because we
// need the parsed StartupMessage body to know the database name). So
// the synthetic upstream must accept the connection — we stand up a
// raw TCP listener that just accepts + reads bytes.
func TestProxy_ProfileOnlyDatabases_NonMatchingDB_RefusedAtHandshake(t *testing.T) {
	p := &profile.Profile{
		Name:          "analytics-only",
		OnlyDatabases: []string{"analytics"},
	}
	upstreamAddr := startNoopUpstream(t)
	srv, addr := startTestServerWithProfileScope(t, p, upstreamAddr)

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// sendStartupMessage asks for database "postgres" — not analytics.
	sendStartupMessage(t, conn)

	sqlState, msg := readErrorResponse(t, conn)
	assert.Equal(t, "42501", sqlState)
	assert.Contains(t, msg, "analytics-only")
	assert.Contains(t, msg, "only_databases")
	assert.GreaterOrEqual(t, srv.ProfileScopeRefusedCount(), int64(1))
}

// startNoopUpstream spins up a loopback TCP listener that accepts +
// reads bytes silently. Used by the database-scope test where the
// upstream MUST accept the TCP dial (for the forwarder to reach the
// handshakeAndAuth body-parse phase) but doesn't need to speak PG.
func startNoopUpstream(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(cc net.Conn) {
				defer cc.Close()
				buf := make([]byte, 4096)
				for {
					if _, rerr := cc.Read(buf); rerr != nil {
						return
					}
				}
			}(c)
		}
	}()
	return l.Addr().String()
}

// TestProxy_ProfileOnlyHosts_ObservationOnly verifies the no-upstream
// path also enforces. Per the spec, when OnlyHosts is set but no
// upstream is configured, the empty host fails-closed — refusal.
// Loud failure beats silent permit.
func TestProxy_ProfileOnlyHosts_ObservationOnly_NoUpstream_Denies(t *testing.T) {
	p := &profile.Profile{
		Name:      "staging-only",
		OnlyHosts: []string{"*.staging.internal"},
	}
	// upstreamHost="" — observation-only path.
	srv, addr := startTestServerWithProfileScope(t, p, "")

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	sendStartupMessage(t, conn)

	// In observation-only mode, pgHandshakeWithPreamble writes the
	// synthetic AuthenticationOk + ReadyForQuery sequence BEFORE the
	// scope gate runs. So we may see those messages then an
	// ErrorResponse. Drain until we hit 'E'.
	sqlState, msg := readUntilError(t, conn)
	assert.Equal(t, "42501", sqlState)
	assert.Contains(t, msg, "only_hosts")
	assert.EqualValues(t, 1, srv.ProfileScopeRefusedCount())
}

// TestProxy_ProfileFullUser_AbstainsAlways — backward-compat: a
// full-user profile MUST NOT enforce scope even if OnlyHosts is set
// (defense-in-depth for [[bounce-default-profile-pattern]] full-user
// invariant).
func TestProxy_ProfileFullUser_AbstainsAlways(t *testing.T) {
	p := &profile.Profile{
		Name:      profile.FullUserProfileName,
		OnlyHosts: []string{"*.staging.internal"},
	}
	srv, addr := startTestServerWithProfileScope(t,
		p, "prod-db.production.internal:5432")

	conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	sendStartupMessage(t, conn)

	sqlState, _ := readErrorResponse(t, conn)
	// dial will fail (synthetic upstream not routable) → 08006 or some
	// connection-failure SQLSTATE. The key invariant: NOT 42501.
	assert.NotEqual(t, "42501", sqlState,
		"full-user MUST never fire profile-scope refusal")
	assert.EqualValues(t, 0, srv.ProfileScopeRefusedCount())
}

// readUntilError drains PG messages until an 'E' arrives, returning
// its sqlState + message. Times out via the conn deadline.
func readUntilError(t *testing.T, conn net.Conn) (sqlState, msg string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 32; i++ {
		hdr := make([]byte, 5)
		if _, err := readFullOrTimeout(conn, hdr); err != nil {
			t.Fatalf("readUntilError: %v", err)
		}
		mt := hdr[0]
		length := beUint32(hdr[1:5])
		body := make([]byte, length-4)
		if length > 4 {
			if _, err := readFullOrTimeout(conn, body); err != nil {
				t.Fatalf("readUntilError body: %v", err)
			}
		}
		if mt == 'E' {
			// Parse tagged C-strings.
			j := 0
			for j < len(body) {
				tag := body[j]
				if tag == 0 {
					break
				}
				j++
				start := j
				for j < len(body) && body[j] != 0 {
					j++
				}
				val := string(body[start:j])
				switch tag {
				case 'C':
					sqlState = val
				case 'M':
					msg = val
				}
				j++
			}
			return sqlState, msg
		}
	}
	t.Fatalf("readUntilError: never saw ErrorResponse within 32 messages")
	return "", ""
}

// readFullOrTimeout is a tiny shim so the read-loop above doesn't
// pull io into the test file.
func readFullOrTimeout(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// beUint32 unpacks the PG message length without pulling encoding/binary.
func beUint32(b []byte) uint32 {
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}

// TestAuditEvent_ProfileOnlyHostsDeny_OCSFShape verifies the audit
// event projection has the expected OCSF class-6003 envelope shape
// with the §A40-specific ext fields.
func TestAuditEvent_ProfileOnlyHostsDeny_OCSFShape(t *testing.T) {
	evt := audit.NewProfileScopeRefusedEvent("127.0.0.1:5433",
		audit.ProfileScopeRefusedInfo{
			ProfileName: "staging-only",
			DenyReason:  profile.DenyReasonOnlyHosts,
			Reason:      `profile "staging-only": upstream host "prod.db" does not match only_hosts [*.staging.*]`,
			Host:        "prod.db",
			Database:    "main",
			RemoteAddr:  "10.0.0.1:54321",
		})

	assert.Equal(t, 6003, evt.ClassUID)
	assert.Equal(t, 6, evt.ActivityID, "Connect activity for connection-level event")
	assert.Equal(t, 600306, evt.TypeUID, "type_uid == 600300 + activity_id (OCSF invariant)")
	assert.Equal(t, "connection_refused", evt.ActivityName)
	assert.Equal(t, 4, evt.StatusID, "status_id=4 (Denied) for policy refusal")
	assert.Equal(t, "Denied", evt.Status)

	require.NotNil(t, evt.Unmapped)
	ext := evt.Unmapped.IAMJIT.Ext
	require.NotNil(t, ext)
	assert.Equal(t, "profile_scope", ext["deny_source"])
	assert.Equal(t, profile.DenyReasonOnlyHosts, ext["deny_reason"])
	assert.Equal(t, "staging-only", ext["profile_name"])
	assert.Equal(t, "prod.db", ext["profile_scope_host"])
	assert.Equal(t, "main", ext["profile_scope_database"])
}

// TestAuditEvent_ProfileOnlyDatabasesDeny_OCSFShape covers the
// database-scope variant.
func TestAuditEvent_ProfileOnlyDatabasesDeny_OCSFShape(t *testing.T) {
	evt := audit.NewProfileScopeRefusedEvent("127.0.0.1:5433",
		audit.ProfileScopeRefusedInfo{
			ProfileName: "analytics-only",
			DenyReason:  profile.DenyReasonOnlyDatabases,
			Reason:      "...",
			Host:        "db.staging.internal",
			Database:    "billing",
		})
	require.NotNil(t, evt.Unmapped)
	ext := evt.Unmapped.IAMJIT.Ext
	assert.Equal(t, profile.DenyReasonOnlyDatabases, ext["deny_reason"])
	assert.Equal(t, "billing", ext["profile_scope_database"])
}

// TestResolvePGDatabase_PrefersStartupParam covers the database
// resolution preference order.
func TestResolvePGDatabase_PrefersStartupParam(t *testing.T) {
	// Synthetic startup body: "database\x00analytics\x00\x00"
	body := []byte("user\x00alice\x00database\x00analytics\x00\x00")
	u, _ := url.Parse("postgres://h/fallback")
	up := &upstream.Upstream{URL: u}
	got := resolvePGDatabase(body, up)
	assert.Equal(t, "analytics", got, "startup param wins over upstream URL path")
}

// TestResolvePGDatabase_FallsBackToUpstreamURL covers the case where
// the client omits the `database` param (PG defaults to user name on
// the server; for scope-matching we use the operator's configured URL).
func TestResolvePGDatabase_FallsBackToUpstreamURL(t *testing.T) {
	body := []byte("user\x00alice\x00\x00")
	u, _ := url.Parse("postgres://h/configured-db")
	up := &upstream.Upstream{URL: u}
	got := resolvePGDatabase(body, up)
	assert.Equal(t, "configured-db", got)
}

// TestResolvePGDatabase_EmptyAllSources returns empty string.
func TestResolvePGDatabase_EmptyAllSources(t *testing.T) {
	got := resolvePGDatabase(nil, nil)
	assert.Empty(t, got)
}

// TestWritePGScopeRefusalErrorResponse_ContainsDenyReasonAndMessage
// verifies the wire-format projection of the refusal includes the
// deny_reason as a Detail field and the message as M.
func TestWritePGScopeRefusalErrorResponse_ContainsDenyReasonAndMessage(t *testing.T) {
	in, out := net.Pipe()
	defer in.Close()
	defer out.Close()

	go func() {
		_ = writePGScopeRefusalErrorResponse(in,
			profile.DenyReasonOnlyHosts,
			"dbounce: profile staging-only refused")
	}()

	hdr := make([]byte, 5)
	_, err := readFullOrTimeout(out, hdr)
	require.NoError(t, err)
	assert.Equal(t, byte('E'), hdr[0])
	length := beUint32(hdr[1:5])
	body := make([]byte, length-4)
	_, err = readFullOrTimeout(out, body)
	require.NoError(t, err)

	bodyStr := string(body)
	assert.True(t, strings.Contains(bodyStr, "42501"),
		"body must contain SQLSTATE 42501")
	assert.True(t, strings.Contains(bodyStr, "dbounce: profile staging-only refused"),
		"body must contain the operator-facing message")
	assert.True(t, strings.Contains(bodyStr, profile.DenyReasonOnlyHosts),
		"body must contain the deny_reason as a Detail field")
}

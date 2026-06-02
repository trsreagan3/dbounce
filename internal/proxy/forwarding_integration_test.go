//go:build integration

// D-Slice 2 integration tests against a real Postgres-in-Docker.
//
// Run with: go test -tags=integration -timeout 5m ./internal/proxy/
//
// Requires a running Postgres at localhost:5432 with password "test".
// The `make pg-up` target in the repo root spins one up via docker.
//
// If you don't have docker / colima, skip with the build tag.
package proxy

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/audit"
	dbstore "github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/upstream"
)

// pgURLFromEnv returns the upstream PG URL the integration tests
// connect to. Defaults to the standard docker-compose stub.
func pgURLFromEnv() string {
	if v := os.Getenv("DBOUNCE_INTEGRATION_PG_URL"); v != "" {
		return v
	}
	return "postgres://postgres:test@127.0.0.1:5432/postgres?sslmode=disable"
}

// dbounceURL returns the URL libpq uses to dial dbounce-proxied PG.
func dbounceURL(port int) string {
	return fmt.Sprintf("postgres://postgres:test@127.0.0.1:%d/postgres?sslmode=disable", port)
}

// startProxyAgainstRealPG spins dbounce up in front of the real PG.
func startProxyAgainstRealPG(t *testing.T, mode Mode) (int, *dbstore.Store) {
	port, st, _ := startProxyAgainstRealPGOpts(t, mode)
	return port, st
}

// startProxyAgainstRealPGOpts is the variadic-option form; each opt
// mutates the Config before Normalize(). Returns the started Server so
// tests can wire an audit exporter onto it.
func startProxyAgainstRealPGOpts(t *testing.T, mode Mode, opts ...func(*Config)) (int, *dbstore.Store, *Server) {
	t.Helper()
	dir := t.TempDir()
	st, err := dbstore.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	up, err := upstream.Resolve(upstream.Options{
		UpstreamURL:   pgURLFromEnv(),
		TLSMode:       upstream.TLSModeDisable,
		AllowInternal: true, // integration test uses local PG (127.0.0.1)
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
		Mode:         mode, Dialect: DialectPostgres,
		Upstream:    up,
		IdleTimeout: 10 * time.Second,
		ReadTimeout: 10 * time.Second,
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

	// Wait for listener.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", wirePort), 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return wirePort, st, srv
}

// requirePGReachable skips the test when the upstream PG isn't up.
func requirePGReachable(t *testing.T) {
	t.Helper()
	db, err := sql.Open("postgres", pgURLFromEnv())
	if err != nil {
		t.Skipf("postgres URL parse error (skip): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("postgres not reachable at %s — `make pg-up` first (skip): %v", pgURLFromEnv(), err)
	}
	_ = db.Close()
}

func TestIntegration_SCRAMAuthThroughProxy(t *testing.T) {
	requirePGReachable(t)
	port, _ := startProxyAgainstRealPG(t, ModeCooperative)

	db, err := sql.Open("postgres", dbounceURL(port))
	require.NoError(t, err)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, db.PingContext(ctx),
		"SCRAM auth must pass through dbounce verbatim")
}

func TestIntegration_SelectRoundTripsRows(t *testing.T) {
	requirePGReachable(t)
	port, _ := startProxyAgainstRealPG(t, ModeCooperative)

	db, err := sql.Open("postgres", dbounceURL(port))
	require.NoError(t, err)
	defer db.Close()

	var n int
	require.NoError(t, db.QueryRow("SELECT 42").Scan(&n))
	assert.Equal(t, 42, n,
		"SELECT result must round-trip identically through the proxy")
}

func TestIntegration_TransparentDenyReturnsPGError(t *testing.T) {
	requirePGReachable(t)
	port, st := startProxyAgainstRealPG(t, ModeTransparent)

	_, err := st.AddRule(testRule(t, "SELECT:*", "deny"))
	require.NoError(t, err)

	db, err := sql.Open("postgres", dbounceURL(port))
	require.NoError(t, err)
	defer db.Close()

	_, qErr := db.Query("SELECT 1")
	require.Error(t, qErr,
		"transparent-mode deny must return a PG error to libpq")
	assert.Contains(t, qErr.Error(), "denied",
		"libpq error must include dbounce's deny message")
}

func TestIntegration_DDLForwardedWhenAllowed(t *testing.T) {
	requirePGReachable(t)
	port, _ := startProxyAgainstRealPG(t, ModeCooperative)

	db, err := sql.Open("postgres", dbounceURL(port))
	require.NoError(t, err)
	defer db.Close()

	tmpTable := fmt.Sprintf("dbounce_int_test_%d", time.Now().UnixNano())
	_, err = db.Exec(fmt.Sprintf("CREATE TEMP TABLE %s (id int)", tmpTable))
	require.NoError(t, err, "DDL must reach the upstream when allowed")
}

func TestIntegration_MultipleQueriesOnSameSession(t *testing.T) {
	requirePGReachable(t)
	port, _ := startProxyAgainstRealPG(t, ModeCooperative)

	db, err := sql.Open("postgres", dbounceURL(port))
	require.NoError(t, err)
	defer db.Close()

	for i := 0; i < 5; i++ {
		var n int
		require.NoError(t, db.QueryRow("SELECT $1::int", i).Scan(&n))
		assert.Equal(t, i, n)
	}
}

// TestIntegration_RedactLiteralsForwardPath is the REAL-Postgres
// verification for the HIGH PII fix: with --redact-literals + a real
// upstream, a SELECT carrying an email + an SSN-shaped quoted literal
// must (a) still execute correctly against PG (correct rows returned),
// while (b) BOTH the persisted SQLite audit row AND the JSONL export
// have the literals REDACTED + statement_redacted=true.
func TestIntegration_RedactLiteralsForwardPath(t *testing.T) {
	requirePGReachable(t)

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	logWriter, err := audit.NewLogWriter(audit.LogOptions{Path: logPath})
	require.NoError(t, err)
	exporter := audit.NewExporter(logWriter, nil, "127.0.0.1:0", "")

	port, st, srv := startProxyAgainstRealPGOpts(t, ModeCooperative,
		func(c *Config) { c.RedactLiterals = true })
	// Wire the exporter onto the already-running server BEFORE the first
	// client query so the SELECT fans out to the JSONL log.
	srv.SetAuditExporter(exporter)

	db, err := sql.Open("postgres", dbounceURL(port))
	require.NoError(t, err)

	const email = "secret@private.example"
	const ssn = "999-88-7777"
	// (a) The query must EXECUTE correctly. We compute a value PG returns
	// so we can assert the real result round-trips. The literals appear in
	// a comparison that PG evaluates to a known boolean.
	rawSQL := fmt.Sprintf(
		"SELECT ('%s' = '%s')::int AS email_match, ('%s' = '%s')::int AS ssn_match",
		email, email, ssn, "000-00-0000")
	var emailMatch, ssnMatch int
	require.NoError(t, db.QueryRow(rawSQL).Scan(&emailMatch, &ssnMatch),
		"redacted-audit query must still execute correctly against real PG")
	assert.Equal(t, 1, emailMatch, "PG must evaluate the email literal comparison (forwarded query is NOT redacted)")
	assert.Equal(t, 0, ssnMatch, "PG must evaluate the ssn literal comparison")

	// Close the client BEFORE draining the exporter so the connection
	// handler isn't mid-emit when the exporter's channel closes. The
	// short settle lets the SESSION_ENDED emit (fired on conn close)
	// complete before Shutdown closes the exporter channel — a benign
	// teardown race the proxy recovers from, but we avoid the noise.
	require.NoError(t, db.Close())
	time.Sleep(100 * time.Millisecond)

	// Drain the exporter so the JSONL file is fully written.
	require.NoError(t, exporter.Shutdown(context.Background()))

	// (b1) SQLite row: redacted + statement_redacted=true.
	deadline := time.Now().Add(3 * time.Second)
	var found *dbstore.DecisionRow
	for time.Now().Before(deadline) {
		rows, rerr := st.RecentDecisions(20)
		require.NoError(t, rerr)
		for i := range rows {
			if rows[i].StatementType == "SELECT" {
				r := rows[i]
				found = &r
				break
			}
		}
		if found != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NotNil(t, found, "expected a persisted SELECT decision row")
	assert.True(t, found.StatementRedacted, "SQLite row must record statement_redacted=true")
	assert.NotContains(t, found.Statement, email, "SQLite statement MUST NOT leak the email literal")
	assert.NotContains(t, found.Statement, ssn, "SQLite statement MUST NOT leak the SSN literal")
	assert.Contains(t, found.Statement, "[REDACTED]", "SQLite statement must carry the [REDACTED] marker")

	// (b2) JSONL export: redacted + statement_redacted=true.
	f, err := os.Open(logPath)
	require.NoError(t, err)
	defer f.Close()
	raw, err := io.ReadAll(f)
	require.NoError(t, err)
	jsonl := string(raw)
	assert.NotContains(t, jsonl, email, "JSONL export MUST NOT leak the email literal")
	assert.NotContains(t, jsonl, ssn, "JSONL export MUST NOT leak the SSN literal")
	assert.Contains(t, jsonl, "[REDACTED]", "JSONL export must carry the [REDACTED] marker")
	assert.Contains(t, jsonl, `"statement_redacted":true`, "JSONL export must mark statement_redacted=true")
}

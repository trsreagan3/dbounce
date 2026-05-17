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
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	t.Helper()
	dir := t.TempDir()
	st, err := dbstore.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	up, err := upstream.Resolve(upstream.Options{
		UpstreamURL: pgURLFromEnv(),
		TLSMode:     upstream.TLSModeDisable,
	})
	require.NoError(t, err)

	wireL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	wirePort := wireL.Addr().(*net.TCPAddr).Port
	mgmtPort := mgmtL.Addr().(*net.TCPAddr).Port
	_ = wireL.Close()
	_ = mgmtL.Close()

	cfg := Config{
		Host: "127.0.0.1", Port: wirePort,
		MgmtHost: "127.0.0.1", MgmtPort: mgmtPort,
		Mode: mode, Dialect: DialectPostgres,
		Upstream:    up,
		IdleTimeout: 10 * time.Second,
		ReadTimeout: 10 * time.Second,
	}.Normalize()
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
	return wirePort, st
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

// anomaly_block_live_test.go proves Phase H block-mode ENFORCEMENT
// through the REAL dbounce decision path (iam-jit#59) — actual SQL
// statements flowing through the PG forwarder's handleGatedMessage
// against a fake upstream, not Detector.Decide in isolation.
//
// Coverage:
//   - TestBlockModeEnforcesViaPreDecisionLivePath: a volume-spike burst
//     of identical statements in mode=block is eventually DENIED (PG
//     ErrorResponse, SQLSTATE 42501) by the live proxy.
//   - TestBlockModeCannotLoosenFloorDenyLivePath: a global deny-rule
//     floor-deny stays denied even under an anomalous burst — the anomaly
//     path is consulted only on a non-deny floor and never loosens.
//   - TestAlertModeNeverDeniesLivePath: the same burst in alert mode is
//     never denied (every statement forwards) — default behavior kept.
//   - TestDisabledDetectorNeverDeniesLivePath: default-off never denies.
package proxy

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/anomaly"
	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/upstream"
)

func dbAnomalyCfg(mode string) anomaly.Config {
	c := anomaly.DefaultConfig()
	c.Enabled = true
	c.Mode = mode
	c.Sensitivity = "medium"
	c.MinActionsForBaseline = 5
	return c
}

// startAnomalyForwardingServer mirrors startForwardingServer but pins
// DefaultPolicy=allow (so the floor ALLOWs SELECT and only the anomaly
// path can deny it) and wires the given anomaly config.
func startAnomalyForwardingServer(t *testing.T, fake *fakePGUpstream, mode Mode, cfg anomaly.Config) (*Server, string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	up, err := upstream.Resolve(upstream.Options{
		UpstreamURL:   fake.URL(),
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

	serverCfg := Config{
		Host:          "127.0.0.1",
		Port:          wirePort,
		MgmtHost:      "127.0.0.1",
		MgmtPort:      mgmtPort,
		WireListener:  wireL,
		MgmtListener:  mgmtL,
		Mode:          mode,
		Dialect:       DialectPostgres,
		Upstream:      up,
		DefaultPolicy: DefaultPolicyAllow,
		IdleTimeout:   5 * time.Second,
		ReadTimeout:   5 * time.Second,
	}.Normalize()
	srv := NewServer(serverCfg, st)
	srv.SetAnomalyDetector(srv.NewAnomalyDetector(cfg))
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
	return srv, addr, st
}

func okResponder() func(t *testing.T, conn net.Conn, msgType byte, payload []byte) {
	return func(t *testing.T, conn net.Conn, msgType byte, payload []byte) {
		if msgType == msgQuery {
			_ = writeMessage(conn, 'C', append([]byte("SELECT 1"), 0))
			_ = writeMessage(conn, 'Z', []byte{'I'})
		}
	}
}

func TestBlockModeEnforcesViaPreDecisionLivePath(t *testing.T) {
	fake := newFakePGUpstream(t)
	fake.respond = okResponder()
	_, addr, _ := startAnomalyForwardingServer(t, fake, ModeTransparent, dbAnomalyCfg("block"))

	// A burst of identical SELECTs (floor ALLOWs via DefaultPolicy=allow).
	// The recent-window rate climbs above the learned per-hour baseline
	// mean, so Decide tightens allow->deny BEFORE forwarding.
	denied := false
	for i := 0; i < 400; i++ {
		reply := clientSession(t, addr, "SELECT 1")
		if strings.Contains(string(reply), "42501") && strings.Contains(string(reply), "dbounce: denied") {
			denied = true
			break
		}
	}
	if !denied {
		t.Fatalf("block mode never DENIED an anomalous burst through the live path; " +
			"block is not enforcing pre-decision")
	}
}

func TestBlockModeCannotLoosenFloorDenyLivePath(t *testing.T) {
	fake := newFakePGUpstream(t)
	fake.respond = okResponder()
	_, addr, st := startAnomalyForwardingServer(t, fake, ModeTransparent, dbAnomalyCfg("block"))

	// Global deny rule for ALL SELECTs = the deterministic floor.
	_, err := st.AddRule(testRule(t, "SELECT:*", "deny"))
	require.NoError(t, err)

	// Every SELECT must stay denied (42501) — never loosened to a forward
	// by the anomaly machinery, regardless of how many we send.
	for i := 0; i < 50; i++ {
		reply := clientSession(t, addr, "SELECT 1")
		if !strings.Contains(string(reply), "42501") {
			t.Fatalf("floor-deny statement #%d was not denied (no 42501); anomaly must NEVER loosen a deny", i)
		}
	}
	// The fake upstream must never have received a Query.
	for _, r := range fake.received {
		if r.Type == msgQuery {
			t.Fatalf("a floor-denied statement reached the upstream; deny must be enforced")
		}
	}
}

func TestAlertModeNeverDeniesLivePath(t *testing.T) {
	fake := newFakePGUpstream(t)
	fake.respond = okResponder()
	srv, addr, _ := startAnomalyForwardingServer(t, fake, ModeTransparent, dbAnomalyCfg("alert"))

	for i := 0; i < 400; i++ {
		reply := clientSession(t, addr, "SELECT 1")
		if strings.Contains(string(reply), "42501") {
			t.Fatalf("alert mode DENIED statement #%d (42501); alert must never block", i)
		}
	}
	if flagged := srv.anomalyDetector.Status()["anomalies_flagged"].(int64); flagged < 1 {
		t.Fatalf("alert mode should still FLAG the spike for review; anomalies_flagged=%d", flagged)
	}
}

func TestDisabledDetectorNeverDeniesLivePath(t *testing.T) {
	fake := newFakePGUpstream(t)
	fake.respond = okResponder()
	_, addr, _ := startAnomalyForwardingServer(t, fake, ModeTransparent, anomaly.DefaultConfig()) // disabled

	for i := 0; i < 200; i++ {
		reply := clientSession(t, addr, "SELECT 1")
		if strings.Contains(string(reply), "42501") {
			t.Fatalf("disabled detector DENIED statement #%d (42501); default-off must never block", i)
		}
	}
}

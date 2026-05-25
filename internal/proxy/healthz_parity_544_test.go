package proxy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/store"
)

// healthz_parity_544_test.go — #544 / MRR-5 M2 + M3 cross-bouncer
// parity tests for the dbounce /healthz endpoint. Asserts the wire-
// shape OBSERVABLE through the HTTP probe (never inspects internal
// struct fields) so the field set stays aligned with ibounce's
// /healthz per [[cross-product-agent-parity]].
//
// The 6-test corpus mirrors the same shape filed against gbounce +
// kbouncer; the cross-bouncer composite monitor in MRR-5 §2 relies on
// the key set being identical across all four bouncers.

// startTestServerWithExporter spins a dbounce Server with an
// optionally-configured audit.Exporter. When withExporter=true the
// exporter is built with a JSONL log writer so Enabled() returns true
// + chain_initialized flips on. When withExporter=false no exporter
// is wired (the FREE-tier dev-laptop default).
//
// Mirrors the existing startTestServer pattern in proxy_test.go but
// exposes the exporter-vs-no-exporter toggle the parity tests need.
func startTestServerWithExporter(t *testing.T, withExporter bool) string {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	cfg := Config{
		Host:          "127.0.0.1",
		Port:          0,
		MgmtHost:      "127.0.0.1",
		MgmtPort:      0,
		Mode:          ModeCooperative,
		Dialect:       DialectPostgres,
		DefaultPolicy: DefaultPolicyAllow,
		IdleTimeout:   5 * time.Second,
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
	if withExporter {
		// Wire a JSONL-log-only exporter — Enabled() returns true
		// when Log is non-nil per audit/exporter.go:109. No webhook so
		// the test doesn't need a fake HTTP server.
		logPath := filepath.Join(dir, "audit.jsonl")
		lw, err := audit.NewLogWriter(audit.LogOptions{Path: logPath, Fsync: false})
		require.NoError(t, err)
		t.Cleanup(func() {
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer shutCancel()
			_ = lw.Shutdown(shutCtx)
		})
		exporter := audit.NewExporter(lw, nil, "127.0.0.1:0", "")
		srv.SetAuditExporter(exporter)
	}

	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	healthzURL := "http://" + mgmtL.Addr().String() + "/healthz"

	// Poll until /healthz responds (matches existing startTestServer pattern).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthzURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return healthzURL
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("dbounce mgmt /healthz never came up")
	return ""
}

// fetchHealthzBody is the shared GET + JSON-decode + 200-check helper.
func fetchHealthzBody(t *testing.T, healthURL string) map[string]any {
	t.Helper()
	resp, err := http.Get(healthURL)
	require.NoError(t, err, "GET %s", healthURL)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected 200 from /healthz")
	var payload map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
	return payload
}

// TestHealthz_HasChainInitialized — #544 — bare /healthz must include
// the chain_initialized key per [[cross-product-agent-parity]]. The
// absence of the key would break any composite monitor that asserts a
// uniform key set across all four bouncers.
func TestHealthz_HasChainInitialized(t *testing.T) {
	healthURL := startTestServerWithExporter(t, false)
	body := fetchHealthzBody(t, healthURL)
	_, ok := body["chain_initialized"]
	assert.True(t, ok, "/healthz missing chain_initialized field: %#v", body)
}

// TestHealthz_ChainInitializedTrueWhenConfigured — #544 — when an
// audit exporter is wired AND Enabled (JSONL log writer attached),
// chain_initialized must be true. Verifies the field tracks the
// underlying exporter state rather than being hard-coded.
func TestHealthz_ChainInitializedTrueWhenConfigured(t *testing.T) {
	healthURL := startTestServerWithExporter(t, true)
	body := fetchHealthzBody(t, healthURL)
	got, ok := body["chain_initialized"].(bool)
	require.True(t, ok, "chain_initialized not a bool: %#v (type %T)",
		body["chain_initialized"], body["chain_initialized"])
	assert.True(t, got,
		"chain_initialized = false; want true when audit exporter is wired + Enabled")
}

// TestHealthz_ChainInitializedFalseWhenNoChain — #544 — when no audit
// exporter is wired, chain_initialized must be false. Closes the
// cold-start gap noted in MRR-5-MONITORING-RUNBOOK §6 M2: a non-
// configured audit chain MUST surface immediately on /healthz, not on
// the first decision attempt.
func TestHealthz_ChainInitializedFalseWhenNoChain(t *testing.T) {
	healthURL := startTestServerWithExporter(t, false)
	body := fetchHealthzBody(t, healthURL)
	got, ok := body["chain_initialized"].(bool)
	require.True(t, ok, "chain_initialized not a bool: %#v (type %T)",
		body["chain_initialized"], body["chain_initialized"])
	assert.False(t, got,
		"chain_initialized = true; want false when no audit exporter is wired")
}

// TestHealthz_HasLlmBudget — #544 — /healthz must include the
// llm_budget key per [[cross-product-agent-parity]]. Symmetric to
// TestHealthz_HasChainInitialized.
func TestHealthz_HasLlmBudget(t *testing.T) {
	healthURL := startTestServerWithExporter(t, false)
	body := fetchHealthzBody(t, healthURL)
	_, ok := body["llm_budget"]
	assert.True(t, ok, "/healthz missing llm_budget field: %#v", body)
}

// TestHealthz_LlmBudgetEnabledFalse — #544 — Go bouncers don't run
// LLM per [[bouncer-zero-llm-when-agent-in-loop]] so the llm_budget
// block must report enabled=false unconditionally. This is honest per
// [[ibounce-honest-positioning]] (not a stub) — if dbounce ever adds
// LLM features, this test should fail loudly so the parity shape gets
// re-evaluated against ibounce's full disabled→enabled shape.
func TestHealthz_LlmBudgetEnabledFalse(t *testing.T) {
	healthURL := startTestServerWithExporter(t, false)
	body := fetchHealthzBody(t, healthURL)
	llmBudget, ok := body["llm_budget"].(map[string]any)
	require.True(t, ok, "llm_budget not an object: %#v (type %T)",
		body["llm_budget"], body["llm_budget"])
	enabled, ok := llmBudget["enabled"].(bool)
	require.True(t, ok, "llm_budget.enabled not a bool: %#v (type %T)",
		llmBudget["enabled"], llmBudget["enabled"])
	assert.False(t, enabled,
		"llm_budget.enabled = true; dbounce doesn't run LLM per [[bouncer-zero-llm-when-agent-in-loop]]")
}

// TestHealthz_LlmBudgetShapeMatchesIbounceWhenDisabled — #544 — when
// the side-LLM is OFF, ibounce reports exactly `{"enabled": false}`
// (single key, no other fields). Go bouncers' disabled-shape MUST
// match byte-for-byte so a cross-bouncer SRE monitor that parses
// llm_budget.enabled doesn't trip on unexpected extra fields. Per
// MRR-5 §2 the composite monitor reads this block uniformly.
func TestHealthz_LlmBudgetShapeMatchesIbounceWhenDisabled(t *testing.T) {
	healthURL := startTestServerWithExporter(t, false)
	body := fetchHealthzBody(t, healthURL)
	llmBudget, ok := body["llm_budget"].(map[string]any)
	require.True(t, ok, "llm_budget not an object: %#v", body["llm_budget"])
	assert.Len(t, llmBudget, 1,
		"llm_budget has %d keys; want exactly 1 (enabled) to match ibounce's disabled-shape: %#v",
		len(llmBudget), llmBudget)
	_, ok = llmBudget["enabled"]
	assert.True(t, ok, "llm_budget missing required 'enabled' key: %#v", llmBudget)
}

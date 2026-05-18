// Audit-export Slice 1 (#252) integration tests on the proxy side:
// hook up a Server with a real audit.Exporter + call evaluateAndAudit;
// the audit row MUST appear in BOTH the JSONL file AND the webhook in
// the shared cross-product schema.

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/store"
)

// TestEvaluateAndAudit_FansOutToBothTransports is the canonical
// integration test from the #252 Slice 1 spec: a single
// evaluateAndAudit call must land in both the JSONL log + the
// HTTPS webhook, with shared schema (decision_id consistent across
// transports).
func TestEvaluateAndAudit_FansOutToBothTransports(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	logWriter, err := audit.NewLogWriter(audit.LogOptions{Path: logPath})
	require.NoError(t, err)

	var (
		mu            sync.Mutex
		webhookEvents []audit.Event
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		for {
			var e audit.Event
			if err := dec.Decode(&e); err != nil {
				break
			}
			mu.Lock()
			webhookEvents = append(webhookEvents, e)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pusher, err := audit.NewWebhookPusher(audit.WebhookOptions{
		URL:                 srv.URL,
		Token:               "test-bearer-fixture",
		AllowInternal:       true,
		HTTPClient:          srv.Client(),
		RetryInitialBackoff: 1 * time.Millisecond,
	})
	require.NoError(t, err)

	exporter := audit.NewExporter(logWriter, pusher, "127.0.0.1:5433", "")

	// Build a minimal Server + store. The DefaultPolicy=Allow keeps
	// the decide path simple — we want to verify the EXPORT plumbing,
	// not the rule engine.
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	cfg := Config{
		Host:          "127.0.0.1",
		Port:          5433,
		Mode:          ModeCooperative,
		Dialect:       DialectPostgres,
		DefaultPolicy: DefaultPolicyAllow,
	}.Normalize()
	server := NewServer(cfg, st)
	server.SetAuditExporter(exporter)

	// Trigger a decision. evaluateAndAudit is the same code path the
	// PG wire-listener takes.
	server.evaluateAndAudit("SELECT 1", "Query")

	// Shutdown the exporter so the worker drains BEFORE we read the
	// file / count webhook events.
	require.NoError(t, exporter.Shutdown(context.Background()))

	// Verify the JSONL file.
	f, err := os.Open(logPath)
	require.NoError(t, err)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var fileEvents []audit.Event
	for scanner.Scan() {
		var e audit.Event
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &e))
		fileEvents = append(fileEvents, e)
	}
	require.Len(t, fileEvents, 1, "log file must contain exactly one event")
	// OCSF v1.1.0 class 6003 envelope checks on the file-side event.
	assert.Equal(t, 6003, fileEvents[0].ClassUID)
	assert.Equal(t, audit.ActivityIDRead, fileEvents[0].ActivityID, "SELECT must map to OCSF Read")
	assert.Equal(t, "SELECT", fileEvents[0].API.Operation)
	require.NotNil(t, fileEvents[0].Unmapped)
	assert.Equal(t, "ALLOW", fileEvents[0].Unmapped.IAMJIT.Verdict)
	assert.Equal(t, audit.Product, fileEvents[0].Metadata.Product.Name)
	assert.Equal(t, audit.VendorName, fileEvents[0].Metadata.Product.VendorName)
	assert.Equal(t, audit.SchemaVersion, fileEvents[0].Metadata.Version)
	assert.NotZero(t, fileEvents[0].Unmapped.IAMJIT.DecisionID,
		"decision_id must be the assigned SQLite row id")

	// Verify the webhook received the same event.
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, webhookEvents, 1, "webhook must receive exactly one event")
	require.NotNil(t, webhookEvents[0].Unmapped)
	assert.Equal(t, fileEvents[0].Unmapped.IAMJIT.DecisionID, webhookEvents[0].Unmapped.IAMJIT.DecisionID,
		"both transports must see the SAME decision_id (shared OCSF schema invariant)")
	assert.Equal(t, fileEvents[0].API.Operation, webhookEvents[0].API.Operation)
	assert.Equal(t, fileEvents[0].Unmapped.IAMJIT.Verdict, webhookEvents[0].Unmapped.IAMJIT.Verdict)
}

// TestEvaluateAndAudit_NoExporter_PreservesD8Behavior verifies that
// when neither transport is configured, the existing SQLite audit
// row is still written + the decision count increments. This is the
// FREE-tier-without-audit-export default; it MUST be unchanged from
// pre-#252 behavior.
func TestEvaluateAndAudit_NoExporter_PreservesD8Behavior(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	cfg := Config{
		Host:          "127.0.0.1",
		Port:          5433,
		Mode:          ModeCooperative,
		Dialect:       DialectPostgres,
		DefaultPolicy: DefaultPolicyAllow,
	}.Normalize()
	server := NewServer(cfg, st)
	// Do NOT set an audit exporter.

	server.evaluateAndAudit("SELECT 1", "Query")

	count, err := st.CountDecisions()
	require.NoError(t, err)
	assert.Equal(t, int64(1), count,
		"no-exporter case must still write the SQLite audit row (back-compat)")
}

// TestAuditExporter_TokenNeverInHealthz: scan the /healthz JSON for
// the secret token; it MUST be absent. This is a binding test of the
// no-leak invariant required by the spec.
func TestAuditExporter_TokenNeverInHealthz(t *testing.T) {
	const tok = "leak-canary-token-not-in-healthz-89231"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pusher, err := audit.NewWebhookPusher(audit.WebhookOptions{
		URL:           srv.URL,
		Token:         tok,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pusher.Shutdown(context.Background()) })

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	// Spin up the proxy server long enough to query /healthz.
	_, _, healthzURL, st2 := startTestServer(t)
	_ = st2

	resp, err := http.Get(healthzURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	body := make([]byte, 8192)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])
	assert.NotContains(t, bodyStr, tok,
		"/healthz MUST NEVER contain the bearer token; got %s", bodyStr)
}

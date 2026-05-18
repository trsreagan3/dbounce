package audit

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

	"github.com/trsreagan3/dbounce/internal/store"
)

// TestExporter_NilSafeAcrossSurface verifies a nil Exporter is OK at
// every public-API call site. The proxy hot-path calls these without
// guarding for nil; success = no panic.
func TestExporter_NilSafeAcrossSurface(t *testing.T) {
	var e *Exporter
	assert.False(t, e.Enabled())
	assert.NoError(t, e.EmitDecision(context.Background(), store.DecisionRow{}, 1))
	assert.NoError(t, e.Emit(context.Background(), Event{}))
	assert.NoError(t, e.Shutdown(context.Background()))
	st := e.Status()
	assert.False(t, st.Configured)
}

// TestExporter_LogOnly verifies a log-only exporter (FREE-tier
// deployment) projects each decision through.
func TestExporter_LogOnly(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	w, err := NewLogWriter(LogOptions{Path: logPath})
	require.NoError(t, err)

	e := NewExporter(w, nil, "127.0.0.1:5433", "")
	require.True(t, e.Enabled())

	row := store.DecisionRow{
		At:              time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC),
		Dialect:         "postgres",
		StatementType:   "SELECT",
		Statement:       "SELECT 1",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
	}
	require.NoError(t, e.EmitDecision(context.Background(), row, 42))
	require.NoError(t, e.Shutdown(context.Background()))

	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	var got Event
	require.NoError(t, json.Unmarshal(data[:len(data)-1], &got)) // drop trailing \n
	require.NotNil(t, got.Unmapped)
	assert.Equal(t, int64(42), got.Unmapped.IAMJIT.DecisionID)
	assert.Equal(t, "SELECT", got.API.Operation)
	require.NotNil(t, got.SrcEndpoint)
	assert.Equal(t, "127.0.0.1", got.SrcEndpoint.Hostname)
	assert.Equal(t, 5433, got.SrcEndpoint.Port)
}

// TestExporter_BothTransports_ReceiveSameEvent: a single EmitDecision
// must land in BOTH the JSONL file + the webhook POST. This is the
// "proxy.decide → both channels receive event in shared schema"
// integration test from the spec.
func TestExporter_BothTransports_ReceiveSameEvent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	w, err := NewLogWriter(LogOptions{Path: logPath})
	require.NoError(t, err)

	var (
		mu            sync.Mutex
		webhookEvents []Event
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		for {
			var e Event
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

	p, err := NewWebhookPusher(WebhookOptions{
		URL:                 srv.URL,
		Token:               secretToken,
		AllowInternal:       true,
		HTTPClient:          srv.Client(),
		RetryInitialBackoff: 1 * time.Millisecond,
	})
	require.NoError(t, err)

	e := NewExporter(w, p, "127.0.0.1:5433", "pg.example.com:5432")

	row := store.DecisionRow{
		At:              time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC),
		Dialect:         "postgres",
		Statement:       "DELETE FROM users",
		StatementType:   "DELETE",
		IsDML:           true,
		HasMutatingNode: true,
		DecisionVerdict: "DENY",
		ModeAtDecision:  "transparent",
		Enforced:        true,
		TablesTouched:   []string{"public.users"},
	}
	require.NoError(t, e.EmitDecision(context.Background(), row, 7))
	require.NoError(t, e.Shutdown(context.Background()))

	// File received it.
	f, err := os.Open(logPath)
	require.NoError(t, err)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	fileEvents := []Event{}
	for scanner.Scan() {
		var got Event
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &got))
		fileEvents = append(fileEvents, got)
	}
	require.Len(t, fileEvents, 1)
	require.NotNil(t, fileEvents[0].Unmapped)
	assert.Equal(t, int64(7), fileEvents[0].Unmapped.IAMJIT.DecisionID)
	assert.Equal(t, "DELETE", fileEvents[0].API.Operation)

	// Webhook received it.
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, webhookEvents, 1)
	require.NotNil(t, webhookEvents[0].Unmapped)
	assert.Equal(t, int64(7), webhookEvents[0].Unmapped.IAMJIT.DecisionID)
	assert.Equal(t, "DELETE", webhookEvents[0].API.Operation)

	// Both transports saw the SAME OCSF shape (shared schema invariant).
	assert.Equal(t, fileEvents[0].API.Operation, webhookEvents[0].API.Operation)
	assert.Equal(t, fileEvents[0].Unmapped.IAMJIT.Verdict, webhookEvents[0].Unmapped.IAMJIT.Verdict)
	assert.Equal(t, fileEvents[0].Unmapped.IAMJIT.DecisionID, webhookEvents[0].Unmapped.IAMJIT.DecisionID)
	assert.Equal(t, fileEvents[0].Unmapped.IAMJIT.Mode, webhookEvents[0].Unmapped.IAMJIT.Mode)
	assert.Equal(t, fileEvents[0].Metadata.Product.Name, webhookEvents[0].Metadata.Product.Name)
	assert.Equal(t, fileEvents[0].ClassUID, webhookEvents[0].ClassUID)
	// Enforced-DENY mapped to OCSF Failure on both transports.
	assert.Equal(t, StatusIDFailure, fileEvents[0].StatusID)
	assert.Equal(t, StatusIDFailure, webhookEvents[0].StatusID)
}

// TestExporter_StatusReflectsBothTransports verifies the MCP status
// snapshot reflects both transports' configured flag + counters.
func TestExporter_StatusReflectsBothTransports(t *testing.T) {
	dir := t.TempDir()
	w, err := NewLogWriter(LogOptions{Path: filepath.Join(dir, "audit.jsonl")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Shutdown(context.Background()) })

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	p, err := NewWebhookPusher(WebhookOptions{
		URL:           srv.URL,
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	e := NewExporter(w, p, "127.0.0.1:5433", "")
	st := e.Status()
	assert.True(t, st.Configured)
	require.NotNil(t, st.Log)
	assert.True(t, st.Log.Configured)
	require.NotNil(t, st.Webhook)
	assert.True(t, st.Webhook.Configured)
}

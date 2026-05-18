package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretToken is the bearer credential used in EVERY webhook test. We
// assert it NEVER appears in any captured-output buffer: not in stats
// strings, not in error messages, not in RedactedURL output, not in
// startup-banner equivalents.
const secretToken = "super-secret-bearer-not-in-logs-92847" //nolint:gosec // test fixture

// TestWebhookPusher_RejectsHTTP rejects http:// at construction —
// auth token + audit payload would travel in cleartext.
func TestWebhookPusher_RejectsHTTP(t *testing.T) {
	_, err := NewWebhookPusher(WebhookOptions{
		URL:           "http://example.com/audit",
		Token:         secretToken,
		AllowInternal: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

// TestWebhookPusher_RejectsEmptyToken: token is mandatory when URL is set.
func TestWebhookPusher_RejectsEmptyToken(t *testing.T) {
	_, err := NewWebhookPusher(WebhookOptions{
		URL:           "https://example.com/audit",
		Token:         "",
		AllowInternal: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

// TestWebhookPusher_SSRFGate_RejectsRFC1918 — the gate REUSES the
// upstream package's MED-D8-06 logic + must point the operator at the
// webhook-specific opt-in flag (not the upstream one).
func TestWebhookPusher_SSRFGate_RejectsRFC1918(t *testing.T) {
	cases := []struct {
		name string
		host string
		want string
	}{
		{"rfc1918-10/8", "https://10.0.0.1/audit", "10.0.0.0/8"},
		{"rfc1918-192.168", "https://192.168.1.1/audit", "192.168.0.0/16"},
		{"loopback", "https://127.0.0.1/audit", "127.0.0.0/8"},
		{"link-local", "https://169.254.169.254/audit", "169.254.0.0/16"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewWebhookPusher(WebhookOptions{
				URL:   tc.host,
				Token: secretToken,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want,
				"SSRF gate must name the matching internal range")
			assert.Contains(t, err.Error(), "--allow-internal-webhook",
				"error must point at the webhook-specific opt-in flag, NOT --allow-internal-upstream")
		})
	}
}

// TestWebhookPusher_SSRFGate_RejectsInternalTLD: .internal / .local
// suffixes are rejected without DNS lookup.
func TestWebhookPusher_SSRFGate_RejectsInternalTLD(t *testing.T) {
	_, err := NewWebhookPusher(WebhookOptions{
		URL:        "https://collector.internal/audit",
		Token:      secretToken,
		LookupHost: func(string) ([]string, error) { return []string{"1.2.3.4"}, nil },
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), ".internal")
	assert.Contains(t, err.Error(), "--allow-internal-webhook")
}

// TestWebhookPusher_AllowInternalOptIn unlocks the loopback case for
// legitimate local-collector deployments.
func TestWebhookPusher_AllowInternalOptIn(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p, err := NewWebhookPusher(WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    srv.Client(),
	})
	require.NoError(t, err, "loopback URL must work when AllowInternal=true")
	require.NoError(t, p.Shutdown(context.Background()))
}

// TestWebhookPusher_SuccessfulDelivery_AsyncNonBlocking: a happy
// delivery must succeed + Push must never block the proxy hot-path.
func TestWebhookPusher_SuccessfulDelivery_AsyncNonBlocking(t *testing.T) {
	var (
		mu        sync.Mutex
		bodies    [][]byte
		seenAuth  string
		seenCTHdr string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		seenAuth = r.Header.Get("Authorization")
		seenCTHdr = r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p, err := NewWebhookPusher(WebhookOptions{
		URL:                 srv.URL + "/audit",
		Token:               secretToken,
		AllowInternal:       true,
		HTTPClient:          srv.Client(),
		BatchSize:           1,
		RetryInitialBackoff: 1 * time.Millisecond,
		RetryMaxBackoff:     5 * time.Millisecond,
	})
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		pushDone := make(chan struct{})
		go func(id int) {
			require.NoError(t, p.Push(context.Background(), testDecisionEvent(int64(id))))
			close(pushDone)
		}(i)
		select {
		case <-pushDone:
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Push blocked > 100ms; async-never-blocks-proxy invariant broken")
		}
	}
	require.NoError(t, p.Shutdown(context.Background()))

	mu.Lock()
	defer mu.Unlock()
	assert.GreaterOrEqual(t, len(bodies), 1, "at least one POST should have landed")
	assert.Equal(t, "Bearer "+secretToken, seenAuth,
		"Authorization header must contain Bearer + token")
	assert.Equal(t, "application/x-ndjson", seenCTHdr)
	// Body must be valid NDJSON.
	for _, b := range bodies {
		for _, line := range bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var e Event
			require.NoError(t, json.Unmarshal(line, &e),
				"each POST body line must be a valid Event")
			assert.Equal(t, Product, e.Metadata.Product.Name)
			assert.Equal(t, SchemaVersion, e.Metadata.Version)
		}
	}
}

// TestWebhookPusher_RetriesOn5xx: a 503 must trigger backoff retry +
// eventual delivery on the 200.
func TestWebhookPusher_RetriesOn5xx(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p, err := NewWebhookPusher(WebhookOptions{
		URL:                 srv.URL + "/audit",
		Token:               secretToken,
		AllowInternal:       true,
		HTTPClient:          srv.Client(),
		RetryInitialBackoff: 1 * time.Millisecond,
		RetryMaxBackoff:     5 * time.Millisecond,
		MaxAttempts:         5,
	})
	require.NoError(t, err)

	require.NoError(t, p.Push(context.Background(), testDecisionEvent(1)))
	require.NoError(t, p.Shutdown(context.Background()))
	assert.GreaterOrEqual(t, attempts.Load(), int32(3), "must retry until 2xx (or maxAttempts)")
	assert.Equal(t, int64(1), p.Stats().Delivered, "ultimate 200 must increment Delivered")
	assert.Equal(t, int64(0), p.Stats().Dropped, "retry-then-200 must NOT increment Dropped")
}

// TestWebhookPusher_GivesUpAfterMaxAttempts: persistent 5xx must drop +
// the final-failure log line MUST NOT leak the token.
func TestWebhookPusher_GivesUpAfterMaxAttempts(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p, err := NewWebhookPusher(WebhookOptions{
		URL:                 srv.URL + "/audit",
		Token:               secretToken,
		AllowInternal:       true,
		HTTPClient:          srv.Client(),
		RetryInitialBackoff: 1 * time.Millisecond,
		RetryMaxBackoff:     5 * time.Millisecond,
		MaxAttempts:         3,
	})
	require.NoError(t, err)
	require.NoError(t, p.Push(context.Background(), testDecisionEvent(99)))
	require.NoError(t, p.Shutdown(context.Background()))

	stats := p.Stats()
	assert.Equal(t, int64(1), stats.Dropped, "persistent 5xx must drop after MaxAttempts")
	// CRITICAL: the lastError MUST NOT contain the token.
	assert.NotContains(t, stats.LastError, secretToken,
		"retry-failure log message MUST NOT leak the bearer token")
	// LastError must mention the retry context so the operator can triage.
	assert.Contains(t, stats.LastError, "attempt")
}

// TestWebhookPusher_NonRetryable4xx: a 401 means the operator's token
// is wrong; we MUST NOT keep retrying (each retry sends the same wrong
// token + burns capacity).
func TestWebhookPusher_NonRetryable4xx(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p, err := NewWebhookPusher(WebhookOptions{
		URL:                 srv.URL + "/audit",
		Token:               secretToken,
		AllowInternal:       true,
		HTTPClient:          srv.Client(),
		RetryInitialBackoff: 1 * time.Millisecond,
		MaxAttempts:         5,
	})
	require.NoError(t, err)
	require.NoError(t, p.Push(context.Background(), testDecisionEvent(1)))
	require.NoError(t, p.Shutdown(context.Background()))
	assert.Equal(t, int32(1), attempts.Load(),
		"401 must not retry (each retry sends the same bad token)")
	assert.Equal(t, int64(1), p.Stats().Dropped)
}

// TestWebhookPusher_DropsOnOverflow_AndEmitsAuditDropped: when the
// bounded queue overflows, drops must be counted + a synthetic
// AUDIT_DROPPED event eventually pushed with the drop count.
func TestWebhookPusher_DropsOnOverflow_AndEmitsAuditDropped(t *testing.T) {
	// Block the server briefly so the queue actually fills up.
	release := make(chan struct{})
	var (
		mu       sync.Mutex
		received []Event
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		body, _ := io.ReadAll(r.Body)
		for _, line := range bytes.Split(bytes.TrimRight(body, "\n"), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var e Event
			if err := json.Unmarshal(line, &e); err == nil {
				mu.Lock()
				received = append(received, e)
				mu.Unlock()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p, err := NewWebhookPusher(WebhookOptions{
		URL:                 srv.URL + "/audit",
		Token:               secretToken,
		AllowInternal:       true,
		HTTPClient:          srv.Client(),
		QueueSize:           2,
		RetryInitialBackoff: 1 * time.Millisecond,
		MaxAttempts:         2,
	})
	require.NoError(t, err)

	// Pump events while the server is blocked.
	for i := 0; i < 100; i++ {
		_ = p.Push(context.Background(), testDecisionEvent(int64(i)))
	}
	// Release the server + let the worker drain.
	close(release)
	require.NoError(t, p.Shutdown(context.Background()))

	stats := p.Stats()
	assert.Greater(t, stats.Dropped, int64(0),
		"saturated bounded queue must drop SOME events (queue size 2 + 100 sends)")

	mu.Lock()
	defer mu.Unlock()
	sawAuditDropped := false
	for _, e := range received {
		if e.ActivityName == "audit_dropped" {
			sawAuditDropped = true
			require.NotNil(t, e.Unmapped)
			assert.Equal(t, string(EventTypeAuditDropped), e.Unmapped.IAMJIT.EventType)
			assert.Greater(t, e.Unmapped.IAMJIT.DroppedCount, int64(0))
		}
	}
	assert.True(t, sawAuditDropped,
		"AUDIT_DROPPED synthetic event MUST be emitted so the downstream consumer sees the gap")
}

// TestWebhookPusher_RedactedURL_NeverLeaksUserinfo masks basic-auth-in-
// URL even though the standard usage uses the bearer header.
func TestWebhookPusher_RedactedURL_NeverLeaksUserinfo(t *testing.T) {
	p, err := NewWebhookPusher(WebhookOptions{
		URL:           "https://alice:hunter2@example.com/audit",
		Token:         secretToken,
		AllowInternal: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	red := p.RedactedURL()
	assert.NotContains(t, red, "hunter2",
		"RedactedURL MUST mask URL userinfo password")
	assert.NotContains(t, red, "alice",
		"RedactedURL MUST mask URL username")
	// url.User("***") percent-encodes to %2A%2A%2A — both forms are
	// acceptable so long as the original credentials never appear.
	assert.True(t,
		strings.Contains(red, "***") || strings.Contains(red, "%2A%2A%2A"),
		"RedactedURL must replace userinfo with an opaque marker, got %q", red)

	// Stats().URLRedacted must also be safe.
	assert.NotContains(t, p.Stats().URLRedacted, "hunter2")
}

// TestWebhookPusher_TokenNeverInStats: every field of the Stats
// snapshot — across all transports — must be scanned + the token must
// not appear anywhere. This is the most important test in the file.
func TestWebhookPusher_TokenNeverInStats(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p, err := NewWebhookPusher(WebhookOptions{
		URL:                 srv.URL + "/audit",
		Token:               secretToken,
		AllowInternal:       true,
		HTTPClient:          srv.Client(),
		RetryInitialBackoff: 1 * time.Millisecond,
		MaxAttempts:         2,
	})
	require.NoError(t, err)
	require.NoError(t, p.Push(context.Background(), testDecisionEvent(1)))
	require.NoError(t, p.Shutdown(context.Background()))

	stats := p.Stats()
	raw, _ := json.Marshal(stats)
	assert.NotContains(t, string(raw), secretToken,
		"Stats() JSON MUST NOT contain the bearer token under any field")
	assert.NotContains(t, p.String(), secretToken,
		"Stringer MUST mask the token (defense against accidental log.Printf %v)")

	// Even an explicit RedactedURL call after delivery + retries must
	// not contain the token.
	assert.NotContains(t, p.RedactedURL(), secretToken)
}

// TestWebhookPusher_AsyncNeverBlocksOnSlowServer is the proxy-hot-path
// invariant: regardless of how slow the collector is, Push MUST return
// in bounded time (queue not exceeded ⇒ enqueue immediately; queue
// full ⇒ drop immediately). This is the single most important property
// of the entire feature for production safety.
func TestWebhookPusher_AsyncNeverBlocksOnSlowServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // simulate collector outage
	}))
	defer srv.Close()

	p, err := NewWebhookPusher(WebhookOptions{
		URL:           srv.URL + "/audit",
		Token:         secretToken,
		AllowInternal: true,
		HTTPClient:    &http.Client{Timeout: 100 * time.Millisecond},
		QueueSize:     10,
		MaxAttempts:   1,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = p.Shutdown(ctx)
	})

	for i := 0; i < 100; i++ {
		start := time.Now()
		_ = p.Push(context.Background(), testDecisionEvent(int64(i)))
		if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
			t.Fatalf("Push took %v on attempt %d; proxy-hot-path-never-blocks invariant broken", elapsed, i)
		}
	}
}

// TestWebhookPusher_BatchSize_GroupsMultipleEvents verifies the
// --audit-webhook-batch-size flag groups multiple decisions into one
// POST body.
func TestWebhookPusher_BatchSize_GroupsMultipleEvents(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies [][]byte
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p, err := NewWebhookPusher(WebhookOptions{
		URL:                 srv.URL + "/audit",
		Token:               secretToken,
		AllowInternal:       true,
		HTTPClient:          srv.Client(),
		BatchSize:           5,
		RetryInitialBackoff: 1 * time.Millisecond,
	})
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		require.NoError(t, p.Push(context.Background(), testDecisionEvent(int64(i))))
	}
	require.NoError(t, p.Shutdown(context.Background()))

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(bodies), 1)
	// At least one body should contain multiple NDJSON lines.
	sawBatched := false
	for _, b := range bodies {
		if strings.Count(strings.TrimRight(string(b), "\n"), "\n")+1 > 1 {
			sawBatched = true
		}
	}
	assert.True(t, sawBatched, "batch-size 5 must produce at least one multi-line POST body")
}

// TestWebhookPusher_BatchSizeTooLarge rejects beyond the cap to
// prevent the operator from accidentally configuring a request body
// the collector will reject.
func TestWebhookPusher_BatchSizeTooLarge(t *testing.T) {
	_, err := NewWebhookPusher(WebhookOptions{
		URL:           "https://example.com/audit",
		Token:         secretToken,
		AllowInternal: true,
		BatchSize:     MaxWebhookBatchSize + 1,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "batch-size")
}

// TestWebhookPusher_HostStampInDroppedEvent: the synthetic
// AUDIT_DROPPED event must carry the proxy listener host so the
// downstream consumer can correlate gaps to proxy instances.
func TestWebhookPusher_HostStampInDroppedEvent(t *testing.T) {
	evt := NewAuditDroppedEvent(5, "10.10.10.10:5433")
	require.NotNil(t, evt.SrcEndpoint)
	assert.Equal(t, "10.10.10.10", evt.SrcEndpoint.Hostname)
	assert.Equal(t, 5433, evt.SrcEndpoint.Port)
	require.NotNil(t, evt.Unmapped)
	assert.Equal(t, int64(5), evt.Unmapped.IAMJIT.DroppedCount)
}

// TestWebhookPusher_ShutdownIdempotent: a second Shutdown call must
// not panic / deadlock.
func TestWebhookPusher_ShutdownIdempotent(t *testing.T) {
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
	require.NoError(t, p.Shutdown(context.Background()))
	require.NoError(t, p.Shutdown(context.Background()), "second Shutdown must be no-op")
}

// silence unused import on platforms where fmt isn't used (defense
// against future refactors that change the test surface).
var _ = fmt.Sprintf

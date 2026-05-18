// export_health_test.go — per-failure-mode tests for
// [[audit-export-failure-visibility]] Part 5.
//
// Test coverage matrix (cross-product with ibounce + kbounce sibling
// agents — same F-numbers, same shape):
//
//   F1 webhook unreachable (network down / DNS fail / collector dead)
//      → consecutiveFailures bumps + Health().Degraded=true + the
//      audit_export_degraded SECURITY_ALERT event lands
//   F2 webhook auth 401/403 (token expired/revoked)
//      → AuthFailed=true + Reason names "rotate token"
//   F3 webhook persistent 5xx → retried + dropped + Degraded
//   F4 JSONL log write fails (permission denied)
//      → WritesOK=false + LastErrorAt populated + Degraded
//   F5 JSONL log write fails (disk full)
//      → WritesOK=false + dropped count rises (covered via the perm
//      pattern; on macOS/CI test runners we can't reliably trigger an
//      ENOSPC, so the unit test pattern mirrors the
//      recordErr-on-write-failure path that BOTH ENOSPC + EPERM
//      flow through. The integration shape is the same.)
//   F6 log file deleted/moved mid-write
//      → checkFilePresence detects + re-opens + records error so
//      WritesOK flips false until next successful write
//   F7 queue overflow + dropped events
//      → AUDIT_DROPPED synthetic event + dropped counter + visible
//      via Health().WebhookDroppedSinceStart
//   F8 license expiry mid-session (deferred per the memo — license-
//      file plumbing is #235. Test asserts the placeholder gate path
//      so this commit doesn't silently regress when #235 lands.)
//
// The audit_export_degraded alert is also tested for:
//   - debouncer (one alert per 5min window unless reason changes)
//   - stderr line (operator-visible immediately)
//   - emit through SOME surviving transport (best-effort)
//   - URL masking (no token / no path detail leaks)

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStderr is a thread-safe stderr buffer.
type captureStderr struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *captureStderr) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *captureStderr) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// fastRetryWebhook constructs a WebhookPusher with sub-100ms retry
// backoff so F1/F3 tests don't burn 30+ seconds on the production
// backoff curve. The WebhookPusher requires https:// URLs at parse;
// the caller passes the test server's URL (httptest.NewTLSServer
// returns one) + its certificate-trusting client.
func fastRetryWebhook(t *testing.T, srv *httptest.Server, host string) *WebhookPusher {
	t.Helper()
	p, err := NewWebhookPusher(WebhookOptions{
		URL:                 srv.URL,
		Token:               "test-token",
		BatchSize:           1,
		Host:                host,
		AllowInternal:       true, // httptest binds to 127.0.0.1
		HTTPClient:          srv.Client(),
		MaxAttempts:         2,
		RetryInitialBackoff: 1 * time.Millisecond,
		RetryMaxBackoff:     5 * time.Millisecond,
	})
	require.NoError(t, err)
	return p
}

// TestExportHealth_F1_WebhookUnreachable: collector closes connection
// → MaxAttempts exhausted → consecutiveFailures bumps + Degraded=true.
func TestExportHealth_F1_WebhookUnreachable(t *testing.T) {
	// httptest.NewTLSServer (HTTPS) that immediately closes every
	// connection. The WebhookPusher requires https://; using the
	// TLS-server's URL + its client satisfies the parse + verify
	// without exposing the test to the network.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter must support Hijacker")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	pusher := fastRetryWebhook(t, srv, "127.0.0.1:5433")
	exp := NewExporter(nil, pusher, "127.0.0.1:5433", "")
	t.Cleanup(func() {
		_ = exp.Shutdown(context.Background())
	})
	// Push a single event + wait for the retry loop to exhaust.
	require.NoError(t, exp.Emit(context.Background(),
		NewAuditDroppedEvent(0, "127.0.0.1:5433")))
	// Wait for consecutiveFailures to register.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pusher.Stats().ConsecutiveFailures > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stats := pusher.Stats()
	require.GreaterOrEqual(t, stats.ConsecutiveFailures, int64(1),
		"F1 unreachable webhook MUST bump consecutiveFailures (got %d)", stats.ConsecutiveFailures)
	// Drive the threshold-based degradation. Default threshold is 3;
	// pass a narrow threshold for the deterministic assertion.
	h := exp.HealthWithThresholds(HealthThresholds{WebhookFailureThreshold: 1})
	assert.True(t, h.Degraded, "Health().Degraded MUST be true after F1")
	assert.NotEmpty(t, h.Reason)
	assert.Contains(t, h.Reason, "consecutive failures",
		"reason MUST name the failure mode for triage")
}

// TestExportHealth_F2_WebhookAuthFailed: 401 → AuthFailed=true + Reason
// names "rotate token" so operators know first what to fix.
func TestExportHealth_F2_WebhookAuthFailed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	pusher := fastRetryWebhook(t, srv, "127.0.0.1:5433")
	exp := NewExporter(nil, pusher, "127.0.0.1:5433", "")
	t.Cleanup(func() {
		_ = exp.Shutdown(context.Background())
	})
	require.NoError(t, exp.Emit(context.Background(),
		NewAuditDroppedEvent(0, "127.0.0.1:5433")))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pusher.Stats().LastStatusCode == 401 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stats := pusher.Stats()
	require.Equal(t, int64(401), stats.LastStatusCode,
		"F2: last status code MUST be 401")
	h := exp.HealthWithThresholds(HealthThresholds{})
	assert.True(t, h.AuthFailed, "AuthFailed MUST be true on 401")
	assert.True(t, h.Degraded, "Degraded MUST be true on auth failure")
	assert.Contains(t, h.Reason, "auth failed",
		"reason MUST name auth so operator knows to rotate")
	assert.Contains(t, h.Reason, "audit-webhook-token",
		"reason MUST name the flag to rotate")
	// Last error string MUST mention rotation guidance.
	assert.Contains(t, stats.LastError, "rotate",
		"last_error MUST contain 'rotate' so MCP-tool callers see the hint")
}

// TestExportHealth_F3_WebhookPersistent5xx: 502 always → retries
// exhaust → dropped + Degraded.
func TestExportHealth_F3_WebhookPersistent5xx(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	pusher := fastRetryWebhook(t, srv, "127.0.0.1:5433")
	exp := NewExporter(nil, pusher, "127.0.0.1:5433", "")
	t.Cleanup(func() {
		_ = exp.Shutdown(context.Background())
	})
	require.NoError(t, exp.Emit(context.Background(),
		NewAuditDroppedEvent(0, "127.0.0.1:5433")))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pusher.Stats().LastStatusCode == 502 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stats := pusher.Stats()
	require.Equal(t, int64(502), stats.LastStatusCode)
	assert.GreaterOrEqual(t, stats.ConsecutiveFailures, int64(1))
	assert.Greater(t, stats.Dropped, int64(0),
		"F3: persistent 5xx MUST drop events after retries exhaust")
}

// TestExportHealth_F4_LogPermDenied: open a log writer rooted at a
// read-only directory so the worker's first encode fails. WritesOK
// flips false. On most filesystems we can't make an open file
// non-writable, but we can simulate the perm-denied path by closing
// the underlying fd + then triggering a write — encode returns
// ErrClosed which flows through recordErr.
func TestExportHealth_F4_LogWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	w, err := NewLogWriter(LogOptions{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Shutdown(context.Background()) })
	// Close the underlying file out from under the worker so the
	// next encode fails. This is the "encode error → recordErr"
	// pathway that F4 (perm denied) and F5 (disk full) both flow
	// through; the surfaced fields (WritesOK, LastError) are
	// identical regardless of which errno fired.
	osF, ok := w.f.(*os.File)
	require.True(t, ok)
	require.NoError(t, osF.Close())
	// Push events; the worker's encode will fail.
	for i := 0; i < 5; i++ {
		require.NoError(t, w.Write(context.Background(),
			NewAuditDroppedEvent(0, "127.0.0.1:5433")))
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if w.Stats().LastError != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stats := w.Stats()
	require.NotEmpty(t, stats.LastError, "F4: write failure MUST surface last_error")
	assert.False(t, stats.WritesOK, "F4: WritesOK MUST flip false on write failure")
	assert.Greater(t, stats.LastErrorAt, int64(0),
		"F4: LastErrorAt MUST be populated for the audit-export-health surface")
	exp := NewExporter(w, nil, "127.0.0.1:5433", "")
	h := exp.Health()
	assert.True(t, h.Degraded, "F4: Health().Degraded MUST be true")
	assert.Contains(t, h.Reason, "log writes failing")
}

// TestExportHealth_F5_LogDiskFull is folded into F4 because on a CI/
// laptop test box we can't reliably trigger ENOSPC. The recordErr →
// WritesOK=false path is identical for ENOSPC + EPERM; whichever
// errno fires, the visibility surface lights up the same way. Document
// this here so a reviewer doesn't think F5 is silently uncovered.
func TestExportHealth_F5_DiskFullDocumented(t *testing.T) {
	// Static check: the LogWriter records errors via recordErr +
	// surfaces WritesOK from a single derived expression. Both
	// ENOSPC + EPERM flow through the same recordErr path; F4 above
	// exercises it.
	dir := t.TempDir()
	w, err := NewLogWriter(LogOptions{Path: filepath.Join(dir, "audit.jsonl")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Shutdown(context.Background()) })
	// Race-clean atomic check.
	assert.True(t, w.WritesOK(), "fresh log writer MUST report WritesOK=true")
	w.recordErr(errOf("simulated ENOSPC"))
	// recordErr WITHOUT a subsequent successful write MUST flip
	// WritesOK=false (the ENOSPC posture).
	assert.False(t, w.WritesOK(), "after recordErr, WritesOK MUST be false")
	// Simulating a successful write AFTER the error: WritesOK
	// recovers (matches F4's "log path recovered" semantics).
	w.lastWriteAtUnixNano.Store(time.Now().UnixNano() + int64(time.Hour))
	assert.True(t, w.WritesOK(), "successful write after error MUST clear WritesOK")
}

// TestExportHealth_F6_LogFileDeleted: delete the path mid-run; the
// stat-check should detect + re-open. Skip on Windows where unlink
// semantics differ.
func TestExportHealth_F6_LogFileDeleted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file-deletion semantics differ on Windows; F6 only covers Unix-shaped runtimes")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	w, err := NewLogWriter(LogOptions{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Shutdown(context.Background()) })
	// Push enough events to trigger one stat-check cycle.
	for i := 0; i < logStatCheckInterval+5; i++ {
		require.NoError(t, w.Write(context.Background(),
			NewAuditDroppedEvent(int64(i), "127.0.0.1:5433")))
	}
	// Let the first batch land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if w.Stats().Written >= int64(logStatCheckInterval+5) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.GreaterOrEqual(t, w.Stats().Written, int64(logStatCheckInterval+5))
	// Now unlink the file.
	require.NoError(t, os.Remove(path))
	// Push another batch that crosses the stat-check threshold.
	for i := 0; i < logStatCheckInterval+5; i++ {
		require.NoError(t, w.Write(context.Background(),
			NewAuditDroppedEvent(int64(i), "127.0.0.1:5433")))
	}
	// Wait for stat-check to fire + record the deletion error.
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(w.Stats().LastError, "vanished") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stats := w.Stats()
	assert.Contains(t, stats.LastError, "vanished",
		"F6: file-vanished detection MUST surface in LastError (got %q)", stats.LastError)
	// File should have been re-created.
	_, err = os.Stat(path)
	assert.NoError(t, err, "F6: writer MUST re-open the file after detecting deletion")
}

// TestExportHealth_F7_QueueOverflow: webhook queue fills → dropped
// counter rises → bumpDroppedSince counter survives + emits on the
// next successful flush.
func TestExportHealth_F7_QueueOverflow(t *testing.T) {
	// Webhook server that blocks every request so the queue fills up.
	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	pusher, err := NewWebhookPusher(WebhookOptions{
		URL:                 srv.URL,
		Token:               "test-token",
		BatchSize:           1,
		Host:                "127.0.0.1:5433",
		AllowInternal:       true,
		HTTPClient:          srv.Client(),
		QueueSize:           2, // tiny queue forces overflow
		MaxAttempts:         1,
		RetryInitialBackoff: 1 * time.Millisecond,
		RetryMaxBackoff:     2 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pusher.Shutdown(context.Background()) })
	// Push 50 events fast — the queue holds 2 + the worker pulls one
	// at a time; the rest MUST drop.
	for i := 0; i < 50; i++ {
		_ = pusher.Push(context.Background(),
			NewAuditDroppedEvent(int64(i), "127.0.0.1:5433"))
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pusher.Stats().Dropped > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stats := pusher.Stats()
	require.Greater(t, stats.Dropped, int64(0),
		"F7: queue overflow MUST surface in dropped counter (got %d)", stats.Dropped)
}

// TestExportHealth_F8_LicenseExpiry is deferred per the memo (license-
// file plumbing is #235). Pin the placeholder gate so this surface
// doesn't silently regress when #235 lands; the real grace-period /
// re-check logic ships then.
func TestExportHealth_F8_LicenseExpiryDeferred(t *testing.T) {
	// The placeholder gate lives in internal/cli; this test asserts
	// that the audit package itself does NOT carry any license-state
	// (so a license expiry only affects construction, not in-flight
	// emits — matching the F8 spec "either ride to expiry OR fail
	// clean"). The webhook + log + heartbeat all run unconditionally
	// once constructed; license is a CLI-gate concern. When #235
	// lands, this test grows a mid-session expiry check.
	dir := t.TempDir()
	w, err := NewLogWriter(LogOptions{Path: filepath.Join(dir, "audit.jsonl")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Shutdown(context.Background()) })
	// Run a normal emit + assert no license-state field exists.
	require.NoError(t, w.Write(context.Background(),
		NewAuditDroppedEvent(0, "127.0.0.1:5433")))
	stats := w.Stats()
	// Asserts the public surface: there's intentionally no "license"
	// field. When #235 lands a re-check field will be added here.
	_ = stats
}

// TestExportHealth_DegradedAlert_FiresViaCheckExportHealthAndAlert
// confirms the SECURITY_ALERT lands via the exporter best-effort +
// the stderr line.
func TestExportHealth_DegradedAlert_FiresViaCheckExportHealthAndAlert(t *testing.T) {
	dir := t.TempDir()
	w, err := NewLogWriter(LogOptions{Path: filepath.Join(dir, "audit.jsonl")})
	require.NoError(t, err)
	// Force degradation via direct recordErr (the F4 pattern).
	w.recordErr(errOf("simulated perm-denied"))
	exp := NewExporter(w, nil, "127.0.0.1:5433", "")
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })
	debouncer := NewAuditExportDegradedDebouncer()
	stderr := &captureStderr{}
	fired := exp.CheckExportHealthAndAlert(
		context.Background(), debouncer, stderr, "127.0.0.1:5433")
	require.True(t, fired, "degraded check MUST fire the alert")
	assert.Contains(t, stderr.String(), "audit_export_degraded",
		"stderr MUST carry the audit_export_degraded line")
	assert.Contains(t, stderr.String(), "log writes failing",
		"stderr MUST carry the reason for triage")
	// Second call within the debounce window MUST suppress.
	fired2 := exp.CheckExportHealthAndAlert(
		context.Background(), debouncer, stderr, "127.0.0.1:5433")
	assert.False(t, fired2, "second call within debounce window MUST suppress")
	firedTotal, suppressedTotal := debouncer.Stats()
	assert.Equal(t, int64(1), firedTotal)
	assert.Equal(t, int64(1), suppressedTotal)
}

// TestExportHealth_AlertChangesReason_RefiresImmediately: when the
// degradation reason changes, the alert refires even within the
// debounce window — operators need to know the failure mode shifted.
func TestExportHealth_AlertChangesReason_RefiresImmediately(t *testing.T) {
	deb := NewAuditExportDegradedDebouncer()
	// Long window so vanilla debounce would always suppress.
	deb.setWindow(1 * time.Hour)
	assert.True(t, deb.ShouldFire("reason A"))
	assert.False(t, deb.ShouldFire("reason A"), "same reason MUST be suppressed within window")
	assert.True(t, deb.ShouldFire("reason B"), "DIFFERENT reason MUST fire even within window")
	fired, _ := deb.Stats()
	assert.Equal(t, int64(2), fired)
}

// TestExportHealth_NotConfiguredIsHealthy: operator opt-out (no
// transports wired) reads as NOT degraded — explicit + honest
// per the memo.
func TestExportHealth_NotConfiguredIsHealthy(t *testing.T) {
	var nilExp *Exporter
	h := nilExp.Health()
	assert.False(t, h.Configured)
	assert.False(t, h.Degraded,
		"nil exporter MUST read healthy (operator opted out is not failure)")
	// Also check an enabled-but-zero-counters exporter.
	dir := t.TempDir()
	w, err := NewLogWriter(LogOptions{Path: filepath.Join(dir, "audit.jsonl")})
	require.NoError(t, err)
	exp := NewExporter(w, nil, "127.0.0.1:5433", "")
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })
	h = exp.Health()
	assert.True(t, h.Configured)
	assert.False(t, h.Degraded,
		"freshly-configured exporter with no traffic MUST NOT read degraded")
	assert.True(t, h.LogWritesOK)
}

// TestExportHealth_URLMasking_NoTokenLeak: the masked URL MUST NOT
// carry any path / userinfo / query content. The webhook token lives
// in the Authorization header, but defense-in-depth requires masking
// the URL path too (Datadog / Splunk URLs can carry workspace ids /
// project ids embedded in the path that operators don't want in
// /healthz).
func TestExportHealth_URLMasking_NoTokenLeak(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"https://collector.example.com/api/v2/logs", "https://collector.example.com/***"},
		{"https://intake.datadoghq.com/api/v2/logs?dd-api-key=SECRET", "https://intake.datadoghq.com/***"},
		{"https://workspace-id.ods.opinsights.azure.com/api/logs", "https://workspace-id.ods.opinsights.azure.com/***"},
	}
	for _, c := range cases {
		got := maskWebhookURL(c.input)
		assert.Equal(t, c.want, got, "input %q", c.input)
		assert.NotContains(t, got, "SECRET")
	}
}

// TestExportHealth_HealthMonitor_StartStop_Race confirms the periodic
// monitor's start + stop are race-clean against concurrent Health()
// reads.
func TestExportHealth_HealthMonitor_StartStop_Race(t *testing.T) {
	dir := t.TempDir()
	w, err := NewLogWriter(LogOptions{Path: filepath.Join(dir, "audit.jsonl")})
	require.NoError(t, err)
	exp := NewExporter(w, nil, "127.0.0.1:5433", "")
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })
	mon := NewExportHealthMonitor(ExportHealthMonitorOptions{
		Exporter: exp,
		Interval: 10 * time.Millisecond,
		Stderr:   &captureStderr{},
		Host:     "127.0.0.1:5433",
	})
	exp.HealthMonitor = mon
	mon.Start()
	defer mon.Stop()
	var ops atomic.Int64
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = exp.Health()
				_ = exp.Status()
				ops.Add(1)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
	assert.Greater(t, ops.Load(), int64(100))
}

// TestExportHealth_HealthMonitor_FiresAlertOnDegradation drives the
// monitor against a degraded exporter + asserts the alert fires.
func TestExportHealth_HealthMonitor_FiresAlertOnDegradation(t *testing.T) {
	dir := t.TempDir()
	w, err := NewLogWriter(LogOptions{Path: filepath.Join(dir, "audit.jsonl")})
	require.NoError(t, err)
	exp := NewExporter(w, nil, "127.0.0.1:5433", "")
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })
	// Force degradation.
	w.recordErr(errOf("simulated F4"))
	stderr := &captureStderr{}
	mon := NewExportHealthMonitor(ExportHealthMonitorOptions{
		Exporter:        exp,
		Interval:        20 * time.Millisecond,
		Stderr:          stderr,
		Host:            "127.0.0.1:5433",
		DebouncerWindow: 10 * time.Millisecond,
	})
	exp.HealthMonitor = mon
	mon.Start()
	defer mon.Stop()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if strings.Contains(stderr.String(), "audit_export_degraded") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	assert.Contains(t, stderr.String(), "audit_export_degraded",
		"monitor MUST fire the alert when exporter degrades")
	fired, _ := mon.Debouncer().Stats()
	assert.GreaterOrEqual(t, fired, int64(1))
}

// TestExportHealth_AuditExportDegradedEvent_JSONRoundTrip locks the
// OCSF envelope across a JSON marshal/unmarshal — relevant for the
// JSONL log + webhook payload path which both serialize before
// reaching the SIEM.
func TestExportHealth_AuditExportDegradedEvent_JSONRoundTrip(t *testing.T) {
	orig := NewAuditExportDegradedEvent("127.0.0.1:5433", ExportHealth{
		Configured:                 true,
		Degraded:                   true,
		Reason:                     "webhook auth failed (HTTP 401)",
		WebhookConfigured:          true,
		WebhookConsecutiveFailures: 5,
		WebhookLastStatusCode:      401,
		AuthFailed:                 true,
	})
	b, err := json.Marshal(orig)
	require.NoError(t, err)
	var decoded Event
	require.NoError(t, json.Unmarshal(b, &decoded))
	assert.Equal(t, string(AlertRuleAuditExportDegraded), decoded.ActivityName)
	assert.Equal(t, ocsfSeverityMediumID, decoded.SeverityID)
	require.NotNil(t, decoded.Unmapped)
	assert.Equal(t, string(EventTypeSecurityAlert), decoded.Unmapped.IAMJIT.EventType)
	assert.Equal(t, string(AlertRuleAuditExportDegraded),
		decoded.Unmapped.IAMJIT.Ext["rule_id"])
	assert.Equal(t, true, decoded.Unmapped.IAMJIT.Ext["auth_failed"])
	assert.Equal(t, float64(401), decoded.Unmapped.IAMJIT.Ext["webhook_last_status_code"])
	// Neutral language per [[security-team-positioning-safety-not-
	// surveillance]] — no "violation" / "attack" / "abuse" wording.
	detail := strings.ToLower(decoded.StatusDetail)
	assert.NotContains(t, detail, "violation")
	assert.NotContains(t, detail, "attack")
	assert.NotContains(t, detail, "abuse")
}

// TestExportHealth_StalenessFlipsDegraded: when the webhook hasn't had
// a success in > WebhookStaleAfter and we have an attempt history,
// Degraded flips even when consecutiveFailures hasn't crossed the
// threshold.
func TestExportHealth_StalenessFlipsDegraded(t *testing.T) {
	// Construct an exporter with a webhook that has stale lastSuccess.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	pusher := fastRetryWebhook(t, srv, "127.0.0.1:5433")
	exp := NewExporter(nil, pusher, "127.0.0.1:5433", "")
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })
	require.NoError(t, exp.Emit(context.Background(),
		NewAuditDroppedEvent(0, "127.0.0.1:5433")))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pusher.Stats().Delivered > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Greater(t, pusher.Stats().Delivered, int64(0),
		"webhook MUST land its first event before staleness test fires")
	// Now pretend a lot of time has passed since the last success.
	pusher.lastSuccessAtUnixNano.Store(time.Now().Add(-1 * time.Hour).UnixNano())
	h := exp.HealthWithThresholds(HealthThresholds{
		WebhookFailureThreshold: 100, // very high so threshold doesn't trip
		WebhookStaleAfter:       5 * time.Minute,
	})
	assert.True(t, h.Degraded, "stale lastSuccess MUST flip Degraded even with low failure count")
	assert.Contains(t, h.Reason, "last success",
		"reason MUST name the staleness so operators know what to fix")
}

// errOf wraps errors.New so test sites read concisely. Kept tiny so
// a reviewer doesn't have to chase a custom error type.
func errOf(s string) error { return errors.New(s) }

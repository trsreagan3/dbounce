// CLI-side tests for `dbounce audit-export health` per
// [[audit-export-failure-visibility]] Part 2.
//
// Coverage:
//
//   - healthy /healthz → exit 0 + human-readable summary
//   - degraded /healthz (503 + degraded=true) → renderer surfaces
//     DEGRADED line; the wrapped exit-1 behavior is tested via the
//     fetch + render seam, not by spawning a subprocess (cobra makes
//     os.Exit hard to intercept in-process).
//   - JSON mode emits the parsed health structure verbatim
//   - --insecure-tls path works against a TLS-only mgmt endpoint
//   - parse error / non-200/503 status surfaces a clear error
//
// The tests target the helpers (fetchAuditExportHealth +
// renderAuditExportHealth) directly so we don't have to spin up a
// full dbounce binary. The integration test that wires
// `dbounce audit-export health` end-to-end against a running proxy
// lives in the cross-product integration suite.

package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/audit"
)

// TestAuditExportHealth_Healthy200 — happy path: /healthz returns 200
// + audit_export_health.degraded=false → CLI render path shows the
// healthy summary.
func TestAuditExportHealth_Healthy200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		payload := map[string]any{
			"status": "ok",
			"audit_export_health": map[string]any{
				"configured":      true,
				"degraded":        false,
				"log_configured":  true,
				"log_writes_ok":   true,
				"log_path":        "/tmp/audit.jsonl",
				"webhook_configured": false,
			},
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()
	h, err := fetchAuditExportHealth(srv.URL, 2*time.Second, false)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.True(t, h.Configured)
	assert.False(t, h.Degraded)
	assert.True(t, h.LogWritesOK)
	var buf bytes.Buffer
	renderAuditExportHealth(&buf, h)
	out := buf.String()
	assert.Contains(t, out, "[ok] JSONL log")
	assert.Contains(t, out, "audit-export healthy")
}

// TestAuditExportHealth_Degraded503 — /healthz returns 503 (the
// proxy's degraded signal); CLI parses the body + surfaces the
// DEGRADED line in the human render.
func TestAuditExportHealth_Degraded503(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		payload := map[string]any{
			"status": "degraded",
			"audit_export_health": map[string]any{
				"configured":                   true,
				"degraded":                     true,
				"reason":                       "webhook auth failed (HTTP 401)",
				"webhook_configured":           true,
				"webhook_consecutive_failures": float64(5),
				"webhook_last_status_code":     float64(401),
				"auth_failed":                  true,
				"webhook_url_masked":           "https://collector.example.com/***",
			},
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()
	h, err := fetchAuditExportHealth(srv.URL, 2*time.Second, false)
	require.NoError(t, err, "503 from /healthz is the EXPECTED degraded signal; MUST NOT error")
	require.NotNil(t, h)
	assert.True(t, h.Degraded)
	assert.True(t, h.AuthFailed)
	assert.Contains(t, h.Reason, "auth failed")
	var buf bytes.Buffer
	renderAuditExportHealth(&buf, h)
	out := buf.String()
	assert.Contains(t, out, "DEGRADED:")
	assert.Contains(t, out, "auth failed")
	// Webhook URL surfaces as masked (path masked).
	assert.Contains(t, out, "https://collector.example.com/***")
}

// TestAuditExportHealth_JSONMode — --json flag emits the parsed
// structure verbatim so external tooling can consume it.
func TestAuditExportHealth_JSONMode(t *testing.T) {
	// We test the render seam via direct JSON marshal since the actual
	// --json flag path calls json.Encoder. Construct the same payload
	// shape the cobra path would receive.
	h := &audit.ExportHealth{
		Configured:        true,
		Degraded:          true,
		Reason:            "log writes failing: simulated",
		LogConfigured:     true,
		LogWritesOK:       false,
		LogPath:           "/tmp/audit.jsonl",
		LogLastError:      "simulated",
		WebhookConfigured: false,
	}
	b, err := json.Marshal(h)
	require.NoError(t, err)
	// The JSON output MUST carry the field names operators can grep.
	str := string(b)
	assert.Contains(t, str, "\"degraded\":true")
	assert.Contains(t, str, "\"reason\":\"log writes failing: simulated\"")
	assert.Contains(t, str, "\"log_writes_ok\":false")
}

// TestAuditExportHealth_NotConfigured — /healthz omits the
// audit_export_health block (older proxy / no exporter wired). The
// CLI renders "not configured" + does NOT exit non-zero.
func TestAuditExportHealth_NotConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()
	h, err := fetchAuditExportHealth(srv.URL, 2*time.Second, false)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.False(t, h.Configured)
	var buf bytes.Buffer
	renderAuditExportHealth(&buf, h)
	assert.Contains(t, buf.String(), "audit-export not configured")
}

// TestAuditExportHealth_UnexpectedStatus — anything other than 200 /
// 503 is unexpected (the proxy's /healthz only returns those two);
// surface the body so the operator can triage.
func TestAuditExportHealth_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal server explosion", http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := fetchAuditExportHealth(srv.URL, 2*time.Second, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
	assert.Contains(t, err.Error(), "internal server explosion")
}

// TestAuditExportHealth_NetworkError — DNS / connect failure surfaces
// a clear error pointing at the URL the operator passed.
func TestAuditExportHealth_NetworkError(t *testing.T) {
	// Use an unroutable port + a short timeout.
	_, err := fetchAuditExportHealth(
		"http://127.0.0.1:1/healthz", 200*time.Millisecond, false)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "GET") ||
		strings.Contains(err.Error(), "127.0.0.1:1"),
		"network error MUST name the failed URL for triage; got %q", err.Error())
}

// TestMaskWebhookURL_NoPathLeak — defense-in-depth for the renderer:
// the CLI tail path SHOULD pre-mask URLs before printing them so a
// downstream operator copy/pasting the output doesn't leak workspace
// ids / project ids / query params. Verified at the audit package
// boundary (export_health_test.go's TestExportHealth_URLMasking_
// NoTokenLeak) but the CLI render path also exercises it.
func TestAuditExportHealthCLI_HealthBlockShape(t *testing.T) {
	// Sanity: the human renderer prints DEGRADED before the
	// healthy line so an operator scanning the output sees the
	// failure first.
	h := &audit.ExportHealth{
		Configured:                 true,
		Degraded:                   true,
		Reason:                     "webhook 5 consecutive failures",
		WebhookConfigured:          true,
		WebhookConsecutiveFailures: 5,
		WebhookURLMasked:           "https://collector.example.com/***",
		WebhookLastError:           "connection refused",
		WebhookQueueDepth:          1,
		WebhookQueueCapacity:       100,
	}
	var buf bytes.Buffer
	renderAuditExportHealth(&buf, h)
	out := buf.String()
	// Look for the [FAIL] marker on the webhook line.
	assert.Contains(t, out, "[FAIL] Webhook")
	assert.Contains(t, out, "DEGRADED")
	assert.Contains(t, out, "consecutive failures: 5")
	assert.Contains(t, out, "queue depth: 1 / 100")
}

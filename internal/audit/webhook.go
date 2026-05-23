// WebhookPusher — HTTPS webhook push for #252 Slice 1 audit-export.
//
// Posts JSON-encoded Events (one per request, or batched when
// --audit-webhook-batch-size > 1) to an operator-owned HTTPS endpoint.
// Bounded queue + bounded retries with exponential backoff; the proxy
// hot-path NEVER blocks on the webhook (Push is non-blocking against a
// buffered channel + drops on overflow with a synthetic AUDIT_DROPPED
// event).
//
// Per the [[security-team-audit-export]] memo:
//
//   - Ships in the v1.0 free + open-source release per
//     project_oss_only_launch_decision.md (license-file plumbing in
//     internal/cli/cli.go --audit-webhook-url validation is retained
//     for any future paid tier but does NOT gate this transport at
//     v1.0).
//   - SSRF gate REUSES the existing internal/upstream MED-D8-06
//     closure (upstream.GuardInternalHost with GuardKindWebhook). Same
//     CIDR + .internal/.local-suffix table; same DNS-rebind resistance;
//     same opt-in escape (--allow-internal-webhook).
//   - Token MUST NEVER appear in startup banner, /healthz, log files,
//     error messages, or retry-failure log lines. The String() /
//     redactedURL helpers mask it at every emission point.
//   - Backpressure on the queue MUST be visible — overflow synthesizes
//     an AUDIT_DROPPED event with the count since last drop so the
//     downstream consumer sees the gap rather than silently losing
//     visibility.
//
// Per [[ibounce-honest-positioning]]: webhook delivery is OPERATOR
// VISIBILITY, not adversary defense. A compromised proxy process can
// withhold or fabricate events; the audit log is the post-hoc-review
// tool, not a real-time trust anchor.
//
// Per [[no-hosted-saas]]: iam-jit-the-company NEVER hosts the webhook
// endpoint. The operator's --audit-webhook-url is THEIR endpoint
// (Datadog, Splunk, Elastic, a custom collector, etc.).

package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trsreagan3/dbounce/internal/upstream"
)

// WebhookPusher posts JSONL Events to an operator-configured HTTPS
// endpoint. Construct with NewWebhookPusher; close with Shutdown.
type WebhookPusher struct {
	url        string
	parsedURL  *url.URL
	token      string
	batchSize  int
	host       string // proxy listener host for synthesizing AUDIT_DROPPED
	httpClient *http.Client
	// preset names the vendor adapter (generic/datadog/splunk-hec/
	// sentinel). The deliver loop dispatches every batch through
	// BuildRequest(preset, batch) so vendor-specific URL/headers/body
	// shapes are applied at send-time. The canonical OCSF event in
	// the JSONL log file is unaffected. See internal/audit/presets.go
	// for the per-preset adapter implementations.
	preset PresetConfig

	ch         chan Event
	doneCh     chan struct{}
	shutdownOnce sync.Once

	// dropped + delivered counters surfaced via Stats(); read by the
	// dbounce_audit_export_status MCP tool.
	dropped    atomic.Int64
	delivered  atomic.Int64
	inFlight   atomic.Int64
	lastErrMu  sync.Mutex
	lastErr    string

	// Per [[audit-export-failure-visibility]] F1/F2/F3: the operator
	// needs more than just last_error to triage. lastSuccessAtUnixNano
	// + lastAttemptAtUnixNano answer "is the channel currently
	// reachable?" without a JOIN against the SIEM. lastStatusCode
	// answers "what HTTP code did the most recent attempt return?"
	// (401 vs 502 vs ECONNREFUSED → different operator actions).
	// consecutiveFailures drives the audit_export_degraded alert
	// threshold + /healthz 503 flip. All atomic for race-clean read
	// from /healthz + the audit-export health CLI.
	lastSuccessAtUnixNano atomic.Int64
	lastAttemptAtUnixNano atomic.Int64
	lastStatusCode        atomic.Int64
	consecutiveFailures   atomic.Int64

	// droppedSinceLastSynthetic tracks the count since the last
	// AUDIT_DROPPED event was emitted. Reset to 0 on each emission so
	// the synthetic event names the DELTA — consumers can sum deltas
	// to get the cumulative.
	droppedSinceMu     sync.Mutex
	droppedSinceLast   int64
}

// WebhookOptions wires the WebhookPusher from CLI flags.
type WebhookOptions struct {
	// URL is the operator-configured webhook endpoint. Must be HTTPS
	// (HTTP rejected at parse). Required.
	URL string
	// Token is the Bearer credential. Sent as Authorization header.
	// Required. NEVER logged or echoed.
	Token string
	// BatchSize is how many events fit in one POST body. Default 1.
	// Range 1-1000 (CLI clamps).
	BatchSize int
	// Host is the proxy's listener host:port; stamped into synthetic
	// AUDIT_DROPPED events so the downstream consumer can correlate.
	Host string
	// AllowInternal is the --allow-internal-webhook flag value. Off by
	// default rejects RFC1918 / loopback / link-local / metadata / TLD
	// suffixes via the upstream package's reused SSRF gate.
	AllowInternal bool
	// LookupHost lets tests inject a stub DNS resolver. Production
	// callers leave nil; upstream.GuardInternalHost falls back to
	// net.LookupHost.
	LookupHost func(string) ([]string, error)
	// QueueSize bounds the in-flight chan. Defaults to 1000.
	QueueSize int
	// HTTPClient lets tests inject an httptest-backed client. Nil
	// uses the production default (10s timeout, TLS 1.2 minimum, no
	// custom RootCAs — operator's collector is expected to present a
	// publicly-trusted cert or be reached via a customer-owned trust
	// store).
	HTTPClient *http.Client
	// MaxAttempts bounds retries. Default 5.
	MaxAttempts int
	// RetryInitialBackoff is the first sleep before retry 1. Default 1s.
	// Tests pass small values to keep test latency low.
	RetryInitialBackoff time.Duration
	// RetryMaxBackoff caps the exponential growth. Default 32s.
	RetryMaxBackoff time.Duration
	// Preset names the vendor adapter (default generic ≡ pre-preset
	// wire shape — Bearer auth + NDJSON OCSF body). Per the
	// [[audit-webhook-presets]] memo the operator picks via the
	// --audit-webhook-preset flag. Empty / unrecognized falls back to
	// generic.
	Preset Preset
	// PresetExtraTags is the --audit-webhook-tags value appended to
	// the datadog preset's ddtags. Stored at construction so other
	// presets that may consume free-form tags later can read it
	// without an options-shape change.
	PresetExtraTags string
	// PresetSentinelTable is the --audit-webhook-sentinel-table value
	// (default IamJitBouncer per [[audit-webhook-presets]]). Used as
	// the Log-Type header by the sentinel preset.
	PresetSentinelTable string
	// PresetProduct overrides the product name the per-preset
	// overlays stamp (default the package Product const). Operators
	// who run multiple dbounce instances behind one collector can set
	// this per-deployment to disambiguate.
	PresetProduct string
}

// MaxWebhookBatchSize bounds batch-size at CLI parse + Normalize time.
// 1000 is generous for any per-call body; bigger batches risk hitting
// downstream collector size limits + reduce retry granularity (one
// failed batch loses N events vs 1).
const MaxWebhookBatchSize = 1000

// NewWebhookPusher validates the URL + SSRF-gates the host + starts
// the worker goroutine. Returns the pusher ready to accept Push calls.
//
// Errors before the worker starts:
//
//   - URL empty / not HTTPS
//   - URL host fails the SSRF gate (unless AllowInternal=true)
//   - Token empty
//
// Per [[deliberate-feature-completion]] all three are fail-fast at
// pusher construction — the operator gets a clear error at startup, not
// a silently-broken pusher at the first decision.
func NewWebhookPusher(opts WebhookOptions) (*WebhookPusher, error) {
	if opts.URL == "" {
		return nil, errors.New("audit: WebhookPusher requires a non-empty URL")
	}
	parsed, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("audit: parse webhook URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf(
			"audit: --audit-webhook-url must be https:// (got scheme %q); "+
				"HTTP is rejected because the Bearer token + audit-row "+
				"contents would travel in cleartext",
			parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, errors.New("audit: webhook URL missing host")
	}
	if opts.Token == "" {
		return nil, errors.New("audit: --audit-webhook-token is required when --audit-webhook-url is set")
	}
	// SSRF gate REUSE — same internal/upstream MED-D8-06 closure logic
	// as the --upstream URL. Per the spec memo: don't duplicate. The
	// GuardKindWebhook kind switches error messages to point at
	// --allow-internal-webhook (not --allow-internal-upstream).
	if !opts.AllowInternal {
		if err := upstream.GuardInternalHost(parsed.Hostname(), opts.LookupHost, upstream.GuardKindWebhook); err != nil {
			return nil, err
		}
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 1
	}
	if opts.BatchSize > MaxWebhookBatchSize {
		return nil, fmt.Errorf(
			"audit: --audit-webhook-batch-size %d exceeds max %d",
			opts.BatchSize, MaxWebhookBatchSize)
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = chanCapacityDefault
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = 5
	}
	if opts.RetryInitialBackoff <= 0 {
		opts.RetryInitialBackoff = 1 * time.Second
	}
	if opts.RetryMaxBackoff <= 0 {
		opts.RetryMaxBackoff = 32 * time.Second
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		}
	}
	// Preset config — Normalize fills defaults (generic if empty,
	// product=dbounce if blank, sentinel table=IamJitBouncer) +
	// validates per-preset prerequisites (sentinel: URL contains a
	// workspace-id subdomain + token decodes as base64). Per
	// [[deliberate-feature-completion]] this fires BEFORE the worker
	// goroutine starts so an operator with a typo'd sentinel URL
	// fails at startup, not at the first decision.
	presetCfg := PresetConfig{
		Preset:        opts.Preset,
		URL:           opts.URL,
		Token:         opts.Token,
		Product:       opts.PresetProduct,
		ExtraTags:     opts.PresetExtraTags,
		SentinelTable: opts.PresetSentinelTable,
	}
	if err := presetCfg.Normalize(); err != nil {
		return nil, err
	}
	w := &WebhookPusher{
		url:        opts.URL,
		parsedURL:  parsed,
		token:      opts.Token,
		batchSize:  opts.BatchSize,
		host:       opts.Host,
		httpClient: client,
		preset:     presetCfg,
		ch:         make(chan Event, opts.QueueSize),
		doneCh:     make(chan struct{}),
	}
	go w.runWorker(opts.MaxAttempts, opts.RetryInitialBackoff, opts.RetryMaxBackoff)
	return w, nil
}

// Push enqueues evt for the worker to POST. Non-blocking: if the queue
// is full, the event is DROPPED and the dropped counter is incremented.
// Worker periodically synthesizes an EventTypeAuditDropped row carrying
// the drop count since last synthesis, so the downstream consumer sees
// the gap rather than silent loss.
//
// Per the spec: the proxy hot-path NEVER blocks on the webhook. A slow
// collector becomes a drop spike + AUDIT_DROPPED events, not SQL-client
// timeouts.
func (w *WebhookPusher) Push(ctx context.Context, evt Event) error {
	if w == nil {
		return nil
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			w.dropped.Add(1)
			w.bumpDroppedSince(1)
			return ctx.Err()
		default:
		}
	}
	select {
	case w.ch <- evt:
		return nil
	default:
		w.dropped.Add(1)
		w.bumpDroppedSince(1)
		return nil
	}
}

// runWorker drains the channel, batches into POST bodies, and retries
// 5xx/network errors with exponential backoff (1s → 2s → 4s → 8s → 16s
// → 32s cap, up to MaxAttempts).
//
// Why an in-goroutine batch buffer instead of a periodic flush timer:
// batches are bounded by --audit-webhook-batch-size; when the channel
// idles (no more events arriving), the worker flushes the current
// partial batch immediately rather than waiting for a timer to fire.
// That keeps the latency between decision + delivery bounded to one
// flush call regardless of arrival rate.
func (w *WebhookPusher) runWorker(maxAttempts int, initialBackoff, maxBackoff time.Duration) {
	defer close(w.doneCh)
	buf := make([]Event, 0, w.batchSize)
	for {
		// Block on the FIRST event of a batch. Once we have one, drain
		// up to batchSize-1 more without blocking + flush.
		evt, ok := <-w.ch
		if !ok {
			return
		}
		buf = append(buf, evt)
		for len(buf) < w.batchSize {
			select {
			case next, ok := <-w.ch:
				if !ok {
					// Channel closed mid-batch: flush what we have then exit.
					if len(buf) > 0 {
						w.deliver(buf, maxAttempts, initialBackoff, maxBackoff)
					}
					return
				}
				buf = append(buf, next)
			default:
				goto flush
			}
		}
	flush:
		// Synthesize an AUDIT_DROPPED event when we have a backlog of
		// drops to surface. Emits BEFORE the regular batch so the
		// downstream consumer sees the gap in chronological order.
		if dropCount := w.takeDroppedSince(); dropCount > 0 {
			synth := NewAuditDroppedEvent(dropCount, w.host)
			w.deliver([]Event{synth}, maxAttempts, initialBackoff, maxBackoff)
		}
		w.deliver(buf, maxAttempts, initialBackoff, maxBackoff)
		buf = buf[:0]
	}
}

// deliver posts a batch + retries on 5xx + network errors. Each retry
// attempt is bounded by the per-call http.Client timeout (default 10s);
// the inter-attempt sleep grows exponentially per the spec.
//
// On final failure (maxAttempts exhausted), the batch is DROPPED + the
// dropped counter incremented. Per the spec: final failure logs the
// REDACTED URL only (token + URL userinfo masked) so the operator can
// triage without leaking the credential to wherever stderr goes.
func (w *WebhookPusher) deliver(batch []Event, maxAttempts int, initialBackoff, maxBackoff time.Duration) {
	if len(batch) == 0 {
		return
	}
	w.inFlight.Add(int64(len(batch)))
	defer w.inFlight.Add(-int64(len(batch)))

	backoff := initialBackoff
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Per [[audit-webhook-presets]]: BuildRequest is called PER
		// DELIVERY ATTEMPT — not pre-computed across retries — because
		// the sentinel preset's HMAC signature includes x-ms-date,
		// which would expire between the first attempt + a slow
		// retry. For generic/datadog/splunk-hec the per-attempt rebuild
		// is a few hundred bytes of allocation; not worth the
		// complexity of caching.
		parts, err := BuildRequest(w.preset, batch)
		if err != nil {
			w.recordErr(fmt.Errorf("build request (attempt %d/%d): %w", attempt, maxAttempts, err))
			w.dropped.Add(int64(len(batch)))
			w.bumpDroppedSince(int64(len(batch)))
			return
		}
		targetURL := parts.URL
		if targetURL == "" {
			targetURL = w.url
		}
		req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(parts.Body))
		if err != nil {
			w.recordErr(fmt.Errorf("build request (attempt %d/%d): %w", attempt, maxAttempts, err))
			break
		}
		for k, v := range parts.Headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("User-Agent", "dbounce-audit-export/"+SchemaVersion)
		w.lastAttemptAtUnixNano.Store(time.Now().UnixNano())
		resp, err := w.httpClient.Do(req)
		if err != nil {
			// Network-level error. Retry unless we've exhausted.
			w.lastStatusCode.Store(0)
			w.recordErr(fmt.Errorf(
				"webhook POST %s attempt %d/%d: network error: %w",
				w.RedactedURL(), attempt, maxAttempts, err))
			if attempt == maxAttempts {
				w.consecutiveFailures.Add(1)
				w.dropped.Add(int64(len(batch)))
				w.bumpDroppedSince(int64(len(batch)))
				return
			}
			sleepWithCap(backoff)
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}
		// Drain + close so the connection pools.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		w.lastStatusCode.Store(int64(resp.StatusCode))
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			w.delivered.Add(int64(len(batch)))
			w.lastSuccessAtUnixNano.Store(time.Now().UnixNano())
			// Recovery: a successful delivery clears the consecutive-
			// failure counter so the audit_export_degraded alert can
			// re-fire on the NEXT sustained outage (debounce reset).
			w.consecutiveFailures.Store(0)
			return
		case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
			// Retryable. Don't burn an attempt on the 5xx itself if
			// retries remain.
			w.recordErr(fmt.Errorf(
				"webhook POST %s attempt %d/%d: HTTP %d (retryable)",
				w.RedactedURL(), attempt, maxAttempts, resp.StatusCode))
			if attempt == maxAttempts {
				w.consecutiveFailures.Add(1)
				w.dropped.Add(int64(len(batch)))
				w.bumpDroppedSince(int64(len(batch)))
				return
			}
			sleepWithCap(backoff)
			backoff = nextBackoff(backoff, maxBackoff)
		default:
			// 4xx (non-429) = config / auth error. Don't retry — the
			// next request would just repeat the same failure. Drop +
			// surface so the operator fixes the URL/token. Per
			// [[audit-export-failure-visibility]] F2: 401 should read
			// distinctly in last_error so the operator triages "rotate
			// the token" vs "fix the network."
			authHint := ""
			if resp.StatusCode == http.StatusUnauthorized ||
				resp.StatusCode == http.StatusForbidden {
				authHint = " — webhook auth failed; rotate --audit-webhook-token"
			}
			w.recordErr(fmt.Errorf(
				"webhook POST %s attempt %d/%d: HTTP %d (non-retryable; check URL + token)%s",
				w.RedactedURL(), attempt, maxAttempts, resp.StatusCode, authHint))
			w.consecutiveFailures.Add(1)
			w.dropped.Add(int64(len(batch)))
			w.bumpDroppedSince(int64(len(batch)))
			return
		}
	}
}

// nextBackoff doubles backoff but caps at maxBackoff. Exponential
// growth: 1s → 2s → 4s → 8s → 16s → 32s (cap).
func nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}

// sleepWithCap sleeps for d, used between retries. Indirection so tests
// can override via a build-tag if test-latency becomes an issue (Slice
// 1 ships small retry counts in tests instead).
func sleepWithCap(d time.Duration) {
	time.Sleep(d)
}

// Shutdown closes the channel + waits for the worker to drain in-flight
// events + their retries. Idempotent. Caller MUST stop calling Push
// BEFORE calling Shutdown.
func (w *WebhookPusher) Shutdown(ctx context.Context) error {
	if w == nil {
		return nil
	}
	w.shutdownOnce.Do(func() {
		close(w.ch)
	})
	select {
	case <-w.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WebhookStats is the snapshot the dbounce_audit_export_status MCP tool
// reads. Race-free: all fields are atomics or mutex-guarded.
//
// Per [[audit-export-failure-visibility]]: LastSuccessAt / LastAttemptAt
// / LastStatusCode / ConsecutiveFailures are surfaced so /healthz +
// `dbounce audit-export health` can answer F1/F2/F3 without re-
// inspecting the network. ConsecutiveFailures drives the 503 flip on
// /healthz + the audit_export_degraded alert threshold.
type WebhookStats struct {
	URLRedacted         string
	Delivered           int64
	Dropped             int64
	InFlight            int64
	LastError           string
	BatchSize           int
	QueueDepth          int
	QueueLimit          int
	Configured          bool
	LastSuccessAt       int64
	LastAttemptAt       int64
	LastStatusCode      int64
	ConsecutiveFailures int64
}

// Stats returns the current counters. Safe to call concurrently.
func (w *WebhookPusher) Stats() WebhookStats {
	if w == nil {
		return WebhookStats{Configured: false}
	}
	w.lastErrMu.Lock()
	last := w.lastErr
	w.lastErrMu.Unlock()
	return WebhookStats{
		URLRedacted:         w.RedactedURL(),
		Delivered:           w.delivered.Load(),
		Dropped:             w.dropped.Load(),
		InFlight:            w.inFlight.Load(),
		LastError:           last,
		BatchSize:           w.batchSize,
		QueueDepth:          len(w.ch),
		QueueLimit:          cap(w.ch),
		Configured:          true,
		LastSuccessAt:       w.lastSuccessAtUnixNano.Load(),
		LastAttemptAt:       w.lastAttemptAtUnixNano.Load(),
		LastStatusCode:      w.lastStatusCode.Load(),
		ConsecutiveFailures: w.consecutiveFailures.Load(),
	}
}

// RedactedURL returns the webhook URL with userinfo (basic-auth in URL)
// masked. The Bearer token is NEVER in the URL (it's in the header)
// but we mask userinfo defensively in case an operator put creds in the
// URL — that pattern should not surface in logs / banner / MCP output.
func (w *WebhookPusher) RedactedURL() string {
	if w == nil || w.parsedURL == nil {
		return ""
	}
	// Re-build the URL without userinfo. Doesn't mutate w.parsedURL.
	u := *w.parsedURL
	if u.User != nil {
		u.User = url.User("***")
	}
	return u.String()
}

// bumpDroppedSince atomically increments the since-last-synthetic
// counter. Worker reads + zeroes it via takeDroppedSince before each
// flush so the AUDIT_DROPPED event carries the delta.
func (w *WebhookPusher) bumpDroppedSince(n int64) {
	w.droppedSinceMu.Lock()
	w.droppedSinceLast += n
	w.droppedSinceMu.Unlock()
}

// takeDroppedSince returns + zeroes the since-last-synthetic counter.
// Worker-only.
func (w *WebhookPusher) takeDroppedSince() int64 {
	w.droppedSinceMu.Lock()
	defer w.droppedSinceMu.Unlock()
	n := w.droppedSinceLast
	w.droppedSinceLast = 0
	return n
}

// recordErr stores err as the most-recent worker-side error. Bounded
// to ~512 chars to keep the MCP last_error field from leaking arbitrary
// downstream-error verbosity into agent context windows.
func (w *WebhookPusher) recordErr(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	if len(msg) > 512 {
		msg = msg[:509] + "..."
	}
	w.lastErrMu.Lock()
	w.lastErr = msg
	w.lastErrMu.Unlock()
}

// Make sure we don't accidentally surface the bare URL anywhere — the
// Stringer here returns the redacted form so a stray log.Info().Msgf()
// can't leak userinfo / token via interface dispatch.
func (w *WebhookPusher) String() string { return w.RedactedURL() }

// guard against silently-unused imports if a test file is removed later.
var _ = net.LookupHost

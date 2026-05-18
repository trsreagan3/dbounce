// Audit-export failure visibility per
// [[audit-export-failure-visibility]].
//
// Slice 1 shipped the JSONL log + HTTPS webhook transports. Slice 1's
// BB+WB audit flagged a STEALTH BYPASS: if the webhook silently fails
// (collector dead / 401 / disk full / log path unwritable), the
// operator's security posture is silently compromised. last_error on
// the MCP status tool is necessary but not sufficient — operators
// would have to actively poll. The fix is FIVE-PART per the memo:
//
//  1. /healthz audit_export section with per-transport health (delivered
//     via proxy.go's healthz handler reading Exporter.Health()).
//  2. `dbounce audit-export health` CLI command (delivered via cli.go).
//  3. `audit_export_degraded` alert rule that emits SECURITY_ALERT
//     through whichever transports survive AND writes to stderr AND
//     flips /healthz to 503 (delivered via the RuleEngine + the
//     dedicated CheckExportHealth method below).
//  4. Optional dead-letter local fallback (POST-LAUNCH per the memo;
//     not in this slice).
//  5. Per-failure-mode tests F1-F8 (see export_health_test.go).
//
// This file provides the DERIVED health computation that the other
// surfaces consume. The underlying counters live on LogWriter +
// WebhookPusher (log.go / webhook.go); ExportHealth is a pure
// projection — race-free read of those atomic fields, no mutable
// state of its own.
//
// Per [[scorer-is-ground-truth]] this code NEVER gates a decision.
// A degraded audit-export is a SIEM alert + an operator notification,
// NOT a reason to deny SQL traffic. The proxy hot-path remains
// independent of audit-export health.
//
// Per [[security-team-positioning-safety-not-surveillance]] the
// degraded-alert language NAMES the failure mode + SUGGESTS the
// operator action (rotate token, check disk space, fix the URL); it
// never accuses the operator of negligence.
//
// Per [[deliberate-feature-completion]]: both halves ship together —
// the computation AND every surface (healthz, CLI, alert) AND the
// per-failure-mode tests. Half-shipping this would leave the stealth-
// bypass open in production while creating a false sense of progress.

package audit

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultDegradedWebhookFailureThreshold is the consecutive-failure
// count at which the webhook is considered "degraded" — flips /healthz
// to 503 + (when wired) triggers the audit_export_degraded alert.
//
// 3 is permissive enough to absorb a transient hiccup (a single 502 +
// retry-cycle is just one consecutive-failure increment) while still
// catching a sustained outage well before the SIEM's own absence
// detection (typically 5m) fires. Sibling agents in ibounce + kbounce
// use the SAME default so cross-product dashboards have one threshold.
const DefaultDegradedWebhookFailureThreshold = 3

// DefaultDegradedWebhookStaleAfter is the wall-clock duration past the
// LastSuccessAt that flips the webhook to "degraded" even when the
// failure counter hasn't crossed the threshold yet. Catches the case
// where the bouncer is idle (no decisions emitted ⇒ no new attempts ⇒
// consecutiveFailures never bumps) but the network path to the
// collector is broken — the operator should learn at health-check
// time, not on the next decision.
//
// 5 minutes mirrors the typical SIEM absence-detection window
// recommended in the spec memo.
const DefaultDegradedWebhookStaleAfter = 5 * time.Minute

// ExportHealth is the cross-transport derived view of audit-export
// health. The Exporter computes it on demand from the per-transport
// Stats() snapshots; nothing here owns mutable state.
//
// Field names mirror the spec memo's /healthz JSON shape so the proxy
// healthz handler + the CLI command + the SIEM alert all read the same
// names. Sibling agents in ibounce + kbounce ship under the SAME field
// names so a cross-product dashboard works.
type ExportHealth struct {
	// Configured is true when at least one transport is wired. False
	// is the "operator opted out" posture — not a failure. Per the
	// memo: operator-OFF MUST NOT read as degraded.
	Configured bool `json:"configured"`

	// Degraded is the top-level summary: true when ANY transport is
	// degraded (log_writes_ok=false OR webhook_consecutive_failures >=
	// threshold OR webhook_last_success_seconds_ago > stale_after).
	// /healthz reads this; true ⇒ status flips to 503.
	Degraded bool `json:"degraded"`

	// Reason names the SPECIFIC failure mode driving Degraded=true.
	// Empty when Degraded=false. Operators triaging an alert read this
	// first to know which surface to fix.
	Reason string `json:"reason,omitempty"`

	// Log per-transport health.
	LogConfigured           bool   `json:"log_configured"`
	LogWritesOK             bool   `json:"log_writes_ok"`
	LogPath                 string `json:"log_path,omitempty"`
	LogLastError            string `json:"log_last_error,omitempty"`
	LogLastErrorSecondsAgo  int64  `json:"log_last_error_seconds_ago,omitempty"`
	LogDroppedSinceStart    int64  `json:"log_dropped_since_start"`

	// Webhook per-transport health.
	WebhookConfigured              bool   `json:"webhook_configured"`
	WebhookURLMasked               string `json:"webhook_url_masked,omitempty"`
	WebhookLastSuccessSecondsAgo   int64  `json:"webhook_last_success_seconds_ago,omitempty"`
	WebhookLastAttemptSecondsAgo   int64  `json:"webhook_last_attempt_seconds_ago,omitempty"`
	WebhookLastStatusCode          int64  `json:"webhook_last_status_code,omitempty"`
	WebhookConsecutiveFailures     int64  `json:"webhook_consecutive_failures"`
	WebhookLastError               string `json:"webhook_last_error,omitempty"`
	WebhookDroppedSinceStart       int64  `json:"webhook_dropped_since_start"`
	WebhookQueueDepth              int    `json:"webhook_queue_depth"`
	WebhookQueueCapacity           int    `json:"webhook_queue_capacity"`

	// AuthFailed surfaces F2 (401/403) so the operator's first triage
	// hop is "rotate the token" not "check the network." True when
	// the most recent webhook attempt returned 401 or 403.
	AuthFailed bool `json:"auth_failed"`
}

// HealthThresholds parameterizes the degraded-detection logic. Tests
// pass narrow thresholds for fast assertions; production uses defaults.
type HealthThresholds struct {
	// WebhookFailureThreshold is the consecutive-failure count at
	// which the webhook reads degraded. 0 = use default.
	WebhookFailureThreshold int64

	// WebhookStaleAfter is the wall-clock duration past LastSuccessAt
	// that flips degraded when the failure counter hasn't crossed the
	// threshold (covers the idle-bouncer case). 0 = use default.
	WebhookStaleAfter time.Duration

	// Now lets tests inject a fixed clock without monkey-patching
	// time.Now. nil = real wall clock.
	Now func() time.Time
}

func (t HealthThresholds) normalize() HealthThresholds {
	if t.WebhookFailureThreshold <= 0 {
		t.WebhookFailureThreshold = DefaultDegradedWebhookFailureThreshold
	}
	if t.WebhookStaleAfter <= 0 {
		t.WebhookStaleAfter = DefaultDegradedWebhookStaleAfter
	}
	if t.Now == nil {
		t.Now = time.Now
	}
	return t
}

// Health computes the current ExportHealth using the default
// thresholds. Read-only; safe to call concurrently. Returns
// Configured=false when no transport is wired — the caller decides
// whether that's a degraded state (it ISN'T; operator opt-out is
// intentional per the memo).
func (e *Exporter) Health() ExportHealth {
	return e.HealthWithThresholds(HealthThresholds{})
}

// HealthWithThresholds is the test-injectable variant. Production
// callers use Health(); tests pass narrow thresholds + a fixed clock.
func (e *Exporter) HealthWithThresholds(t HealthThresholds) ExportHealth {
	t = t.normalize()
	out := ExportHealth{
		Configured: e != nil && e.Enabled(),
	}
	if e == nil {
		return out
	}
	st := e.Status()
	now := t.Now()
	if st.Log != nil {
		out.LogConfigured = st.Log.Configured
		out.LogPath = st.Log.Path
		out.LogLastError = st.Log.LastError
		out.LogDroppedSinceStart = st.Log.Dropped
		out.LogWritesOK = st.Log.WritesOK
		if st.Log.LastErrorAt > 0 {
			delta := now.Sub(time.Unix(0, st.Log.LastErrorAt))
			if delta < 0 {
				delta = 0
			}
			out.LogLastErrorSecondsAgo = int64(delta.Seconds())
		}
	} else {
		// Log not wired: treat as healthy (the operator didn't ask
		// for it). The aggregate Degraded flag below ignores log
		// when LogConfigured=false.
		out.LogWritesOK = true
	}
	if st.Webhook != nil {
		out.WebhookConfigured = st.Webhook.Configured
		out.WebhookURLMasked = maskWebhookURL(st.Webhook.URLRedacted)
		out.WebhookLastError = st.Webhook.LastError
		out.WebhookDroppedSinceStart = st.Webhook.Dropped
		out.WebhookQueueDepth = st.Webhook.QueueDepth
		out.WebhookQueueCapacity = st.Webhook.QueueLimit
		out.WebhookConsecutiveFailures = st.Webhook.ConsecutiveFailures
		out.WebhookLastStatusCode = st.Webhook.LastStatusCode
		out.AuthFailed = st.Webhook.LastStatusCode == 401 ||
			st.Webhook.LastStatusCode == 403
		if st.Webhook.LastSuccessAt > 0 {
			delta := now.Sub(time.Unix(0, st.Webhook.LastSuccessAt))
			if delta < 0 {
				delta = 0
			}
			out.WebhookLastSuccessSecondsAgo = int64(delta.Seconds())
		}
		if st.Webhook.LastAttemptAt > 0 {
			delta := now.Sub(time.Unix(0, st.Webhook.LastAttemptAt))
			if delta < 0 {
				delta = 0
			}
			out.WebhookLastAttemptSecondsAgo = int64(delta.Seconds())
		}
	}
	// Aggregate Degraded + Reason. Order matters: report the FIRST
	// failure mode encountered so the operator's triage starts at the
	// most-actionable surface (the log write — local + fixable) before
	// the network-shaped surface (the webhook).
	switch {
	case out.LogConfigured && !out.LogWritesOK:
		out.Degraded = true
		out.Reason = "log writes failing: " + out.LogLastError
	case out.WebhookConfigured && out.AuthFailed:
		out.Degraded = true
		out.Reason = fmt.Sprintf(
			"webhook auth failed (HTTP %d); rotate --audit-webhook-token",
			out.WebhookLastStatusCode)
	case out.WebhookConfigured &&
		out.WebhookConsecutiveFailures >= t.WebhookFailureThreshold:
		out.Degraded = true
		out.Reason = fmt.Sprintf(
			"webhook %d consecutive failures (threshold %d): %s",
			out.WebhookConsecutiveFailures, t.WebhookFailureThreshold,
			out.WebhookLastError)
	case out.WebhookConfigured &&
		st.Webhook.LastAttemptAt > 0 &&
		st.Webhook.LastSuccessAt > 0 &&
		out.WebhookLastSuccessSecondsAgo >
			int64(t.WebhookStaleAfter.Seconds()):
		out.Degraded = true
		out.Reason = fmt.Sprintf(
			"webhook last success %ds ago (threshold %ds); collector unreachable?",
			out.WebhookLastSuccessSecondsAgo,
			int64(t.WebhookStaleAfter.Seconds()))
	}
	return out
}

// maskWebhookURL further redacts the URL for /healthz emission. The
// WebhookPusher's RedactedURL already strips userinfo; we additionally
// mask the path so a logged URL doesn't leak a workspace id / project
// id / customer id embedded in the path. Format: scheme://host:port/
// + first 4 chars of path + asterisks + final path component (if any).
//
// Per [[audit-export-failure-visibility]] "Don't expose the webhook
// token in any health-check surface" + defense-in-depth on the URL
// itself (a Datadog URL like https://http-intake.logs.datadoghq.com/
// api/v2/logs/?dd-api-key=... should NEVER appear in /healthz; the
// scheme + host are enough to identify the collector for triage).
func maskWebhookURL(redacted string) string {
	if redacted == "" {
		return ""
	}
	// The WebhookPusher already strips userinfo; we just truncate the
	// path component so a logged value can't carry secrets embedded in
	// the query string / path. Find the first / after the scheme.
	idx := strings.Index(redacted, "://")
	if idx < 0 {
		return redacted
	}
	rest := redacted[idx+3:]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return redacted
	}
	host := rest[:slash]
	scheme := redacted[:idx]
	return scheme + "://" + host + "/***"
}

// AuditExportDegradedDebouncer enforces the "fire once per 5min window"
// invariant for the audit_export_degraded alert per the memo. Avoids
// alert spam when the webhook is sustained-down for hours.
//
// Per [[audit-export-failure-visibility]] "Don't make the
// audit_export_degraded alert chatty — fire once per 5min window, not
// every dropped event."
type AuditExportDegradedDebouncer struct {
	mu             sync.Mutex
	lastFiredAt    time.Time
	lastReason     string
	windowDuration time.Duration
	now            func() time.Time

	// firedTotal is exported for the MCP status tool + tests.
	firedTotal atomic.Int64
	// suppressedTotal counts the cases where the rule WOULD have
	// fired but was within the debounce window. Surfaced so an
	// operator can see "we're still degraded; we suppressed N alerts
	// in the window." Composes with the firedTotal counter.
	suppressedTotal atomic.Int64
}

// NewAuditExportDegradedDebouncer returns a debouncer with the spec-
// required 5min window. Tests pass a shorter window via the
// time-injection setter.
func NewAuditExportDegradedDebouncer() *AuditExportDegradedDebouncer {
	return &AuditExportDegradedDebouncer{
		windowDuration: 5 * time.Minute,
		now:            time.Now,
	}
}

// SetWindow + SetNow let tests use narrow values. Production code never
// calls these. NOT exported via a constructor option (the production
// shape is single-purpose) — these are direct setters used only by tests.
func (d *AuditExportDegradedDebouncer) setWindow(w time.Duration) {
	d.mu.Lock()
	d.windowDuration = w
	d.mu.Unlock()
}
func (d *AuditExportDegradedDebouncer) setNow(now func() time.Time) {
	d.mu.Lock()
	d.now = now
	d.mu.Unlock()
}

// ShouldFire reports whether an alert with the given reason should fire
// now. Updates the debouncer's state assuming the caller will fire
// (returns true) or has suppressed (returns false). Race-clean via the
// mutex; called from the rule-engine's per-observe hook + the CLI
// health check, both of which run on goroutines independent of the
// hot-path.
//
// Logic: fire if (we have NEVER fired) OR (the window has elapsed
// since the last fire) OR (the reason changed — the operator needs
// to know the failure mode shifted).
func (d *AuditExportDegradedDebouncer) ShouldFire(reason string) bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	shouldFire := d.lastFiredAt.IsZero() ||
		now.Sub(d.lastFiredAt) >= d.windowDuration ||
		(reason != "" && reason != d.lastReason)
	if !shouldFire {
		d.suppressedTotal.Add(1)
		return false
	}
	d.lastFiredAt = now
	d.lastReason = reason
	d.firedTotal.Add(1)
	return true
}

// Stats returns the per-debouncer counters surfaced via the MCP tool.
func (d *AuditExportDegradedDebouncer) Stats() (fired, suppressed int64) {
	if d == nil {
		return 0, 0
	}
	return d.firedTotal.Load(), d.suppressedTotal.Load()
}

// ExportHealthMonitor periodically polls the Exporter's Health() +
// fires the audit_export_degraded alert (via CheckExportHealthAndAlert)
// when degraded. Default OFF: the operator opts in by passing a non-
// zero Interval at construction. Sibling agents in ibounce + kbounce
// ship the equivalent monitor under the same defaults so cross-
// product alerting cadence is uniform.
//
// Race-clean by construction: holds no mutable shared state on the
// poll path beyond the debouncer (which has its own mutex). Stop is
// idempotent + ordering-safe before Exporter.Shutdown (the goroutine
// stops emitting BEFORE the exporter's transport channels close).
type ExportHealthMonitor struct {
	exporter  *Exporter
	debouncer *AuditExportDegradedDebouncer
	stderr    io.Writer
	host      string
	interval  time.Duration

	stop chan struct{}
	wg   sync.WaitGroup
	// running guards double-Start. Atomic CAS so a misuse doesn't
	// spawn duplicate goroutines.
	running atomic.Bool
}

// ExportHealthMonitorOptions wires the monitor from the CLI. All
// fields optional except Exporter; empty Interval = monitor never
// runs (the operator didn't opt in to periodic alerts; the /healthz
// surface + the manual CLI command remain the failure-visibility
// channels).
type ExportHealthMonitorOptions struct {
	// Exporter is the audit-export pipeline the monitor watches.
	// Required (a nil exporter means there's nothing to watch).
	Exporter *Exporter

	// Interval is how often the monitor polls Health(). Zero
	// disables. Practical range: 5s (high-fidelity) - 5m (low-
	// overhead). Defaults are not set here — the CLI translates
	// --audit-export-health-interval to this value.
	Interval time.Duration

	// Stderr is where the audit_export_degraded line prints. Defaults
	// to os.Stderr; tests override.
	Stderr io.Writer

	// Host is the listener "host:port" stamped onto the OCSF
	// audit_export_degraded event.
	Host string

	// DebouncerWindow lets tests pass a narrow window. Zero uses the
	// production 5min default.
	DebouncerWindow time.Duration
}

// NewExportHealthMonitor constructs the monitor. Always safe to call;
// when Interval=0, Start is a no-op so the CLI can construct
// unconditionally + the operator's opt-in is the single switch.
func NewExportHealthMonitor(opts ExportHealthMonitorOptions) *ExportHealthMonitor {
	deb := NewAuditExportDegradedDebouncer()
	if opts.DebouncerWindow > 0 {
		deb.setWindow(opts.DebouncerWindow)
	}
	return &ExportHealthMonitor{
		exporter:  opts.Exporter,
		debouncer: deb,
		stderr:    opts.Stderr,
		host:      opts.Host,
		interval:  opts.Interval,
		stop:      make(chan struct{}),
	}
}

// Configured reports whether the operator turned the monitor on.
func (m *ExportHealthMonitor) Configured() bool {
	return m != nil && m.exporter != nil && m.interval > 0
}

// Start launches the poll goroutine. No-op when not Configured.
// Idempotent: double-Start is detected via running CAS + returns
// silently.
func (m *ExportHealthMonitor) Start() {
	if !m.Configured() {
		return
	}
	if !m.running.CompareAndSwap(false, true) {
		return
	}
	m.wg.Add(1)
	go m.pollLoop()
}

// Stop signals the poll goroutine + waits for it to drain.
// Idempotent. Caller MUST call Stop BEFORE the Exporter's Shutdown
// so an in-flight CheckExportHealthAndAlert finishes its emit before
// the transport channels close.
func (m *ExportHealthMonitor) Stop() {
	if m == nil || !m.running.CompareAndSwap(true, false) {
		return
	}
	close(m.stop)
	m.wg.Wait()
}

// Debouncer returns the underlying debouncer so the MCP tool can
// surface fired/suppressed counters.
func (m *ExportHealthMonitor) Debouncer() *AuditExportDegradedDebouncer {
	if m == nil {
		return nil
	}
	return m.debouncer
}

func (m *ExportHealthMonitor) pollLoop() {
	defer m.wg.Done()
	t := time.NewTicker(m.interval)
	defer t.Stop()
	// Immediate check at start so an already-degraded pipeline fires
	// without waiting one Interval. The debouncer prevents this
	// initial check from spamming if the pipeline is degraded for
	// hours.
	_ = m.exporter.CheckExportHealthAndAlert(
		context.Background(), m.debouncer, m.stderr, m.host)
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			_ = m.exporter.CheckExportHealthAndAlert(
				context.Background(), m.debouncer, m.stderr, m.host)
		}
	}
}

// CheckExportHealthAndAlert is the self-emitting check the proxy +
// CLI invoke periodically (or on operator demand) to fire the
// audit_export_degraded alert when the exporter is unhealthy.
//
// Per [[audit-export-failure-visibility]] "Self-emitting concern:
// when the audit-export pipeline IS the failure, the alert can't ride
// the audit-export pipeline. Solution: this specific alert ALWAYS
// writes to local stderr + the bouncer's /healthz status flips to 503.
// The alert ALSO goes to the audit-export channel best-effort — if it
// lands, great; if not, the stderr + healthz are the signal."
//
// Returns true when an alert WAS fired (either lane); false when
// healthy OR debounced. Caller may inspect for test assertions; the
// production proxy ignores the return.
//
// Per [[deliberate-feature-completion]] all three landing places ship
// at once: stderr (operator-immediate), exporter.Emit best-effort
// (SIEM via whichever transport survives), and the /healthz flip
// (which happens implicitly via Health() returning Degraded=true on
// the next request — no separate call needed here).
func (e *Exporter) CheckExportHealthAndAlert(
	ctx context.Context,
	debouncer *AuditExportDegradedDebouncer,
	stderr io.Writer,
	host string,
) bool {
	if e == nil {
		return false
	}
	health := e.Health()
	if !health.Degraded {
		return false
	}
	if debouncer != nil && !debouncer.ShouldFire(health.Reason) {
		return false
	}
	if stderr != nil {
		fmt.Fprintf(stderr,
			"dbounce: audit_export_degraded — %s; /healthz now reports degraded; "+
				"see `dbounce audit-export health` for the full picture\n",
			health.Reason)
	}
	// Best-effort SIEM emission. Per the memo: the alert ALSO goes
	// to the audit-export channel — if it lands, great; if not, the
	// stderr + healthz are the signal. We deliberately don't check
	// the error from Emit; the transport's drop counter is the
	// visibility channel.
	evt := NewAuditExportDegradedEvent(host, health)
	_ = e.Emit(ctx, evt)
	return true
}

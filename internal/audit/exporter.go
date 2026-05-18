// Exporter — combined fan-out over the configured audit-export
// transports (LogWriter + WebhookPusher). The proxy holds ONE
// *Exporter and calls Emit per decision; the Exporter forwards to
// whichever transports are configured.
//
// Why a combined fan-out instead of the proxy calling each transport
// directly: a future Slice 2 alerting / Slice 3 syslog / Slice 4 S3-
// archive transport can be added here without churning every
// evaluateAndAudit / handleGatedMessage / handleGatedQuery call-site.
// The proxy stays unaware of how many transports exist.
//
// Per [[deliberate-feature-completion]]: Slice 1 ships with two
// transports + the combined plumbing; Slice 2's alert engine will
// register its own subscriber via this Exporter.
//
// Per [[ibounce-honest-positioning]]: emission is best-effort; an
// Emit call NEVER blocks the proxy hot-path. Each transport applies
// its own bounded-queue + drop discipline. The proxy is told nothing
// about per-transport failures — those surface via the MCP status
// tool + zerolog warnings.

package audit

import (
	"context"
	"errors"

	"github.com/trsreagan3/dbounce/internal/store"
)

// Exporter fans an Event out to zero, one, or both configured
// transports. Construct via NewExporter; Emit per decision; Shutdown
// on proxy stop.
//
// Either field MAY be nil — the exporter handles partial configuration
// gracefully (e.g. operator passed --audit-log-path but no webhook).
type Exporter struct {
	Log       *LogWriter
	Webhook   *WebhookPusher
	Heartbeat *Heartbeater

	// host is the proxy listener address ("127.0.0.1:5433") stamped
	// onto every event's Event.Host field. Provided at construction
	// time so we don't re-read s.cfg per decision.
	host string

	// upstream is the resolved upstream URL host:port (empty when
	// observation-only). Stamped onto Event.Upstream.
	upstream string
}

// NewExporter constructs an Exporter from already-built transports.
// Either may be nil. Pass host = the proxy listener "host:port" + the
// resolved upstream "host:port" (empty for observation-only) so the
// exporter can stamp them onto every event without per-decision config
// reads.
func NewExporter(log *LogWriter, webhook *WebhookPusher, host, upstream string) *Exporter {
	return &Exporter{
		Log:      log,
		Webhook:  webhook,
		host:     host,
		upstream: upstream,
	}
}

// Enabled reports whether ANY transport is configured. The proxy's
// hot-path SHOULD short-circuit when this is false so we don't even
// build the Event projection.
func (e *Exporter) Enabled() bool {
	if e == nil {
		return false
	}
	return e.Log != nil || e.Webhook != nil
}

// EmitDecision projects a store.DecisionRow into the cross-product
// schema + dispatches it to every configured transport. Per the spec:
// non-blocking — each transport applies its own queue discipline.
//
// Returns a wrapped error joining per-transport errors so callers that
// want to log them can. The proxy currently ignores the return (the
// transport-level lastErr surfaces via the MCP status tool); the field
// is reserved for tests that want to assert per-transport failure.
func (e *Exporter) EmitDecision(ctx context.Context, row store.DecisionRow, decisionID int64) error {
	if !e.Enabled() {
		return nil
	}
	evt := FromDecisionRow(row, decisionID, e.host, e.upstream)
	return e.emit(ctx, evt)
}

// Emit dispatches a pre-built Event. Used by tests; production
// callers go through EmitDecision.
func (e *Exporter) Emit(ctx context.Context, evt Event) error {
	if !e.Enabled() {
		return nil
	}
	return e.emit(ctx, evt)
}

func (e *Exporter) emit(ctx context.Context, evt Event) error {
	var errs []error
	if e.Log != nil {
		if err := e.Log.Write(ctx, evt); err != nil {
			errs = append(errs, err)
		}
	}
	if e.Webhook != nil {
		if err := e.Webhook.Push(ctx, evt); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// Shutdown closes every configured transport. Idempotent. Caller MUST
// stop calling Emit BEFORE Shutdown.
//
// Order matters: Heartbeater MUST stop FIRST so its final in-flight
// tick / gap alert drains to the transports BEFORE Log / Webhook close
// their channels. Without this, Stop racing with Shutdown can deadlock
// the heartbeater's emit goroutine on a closed transport channel.
func (e *Exporter) Shutdown(ctx context.Context) error {
	if e == nil {
		return nil
	}
	if e.Heartbeat != nil {
		e.Heartbeat.Stop()
	}
	var errs []error
	if e.Log != nil {
		if err := e.Log.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if e.Webhook != nil {
		if err := e.Webhook.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// ExporterStatus is the snapshot the MCP status tool reads. Holds the
// per-transport stats + a top-level "configured" flag so the tool can
// answer "is anything wired up?" without inspecting nil fields.
type ExporterStatus struct {
	Configured bool            `json:"configured"`
	Log        *LogStats       `json:"log,omitempty"`
	Webhook    *WebhookStats   `json:"webhook,omitempty"`
	Heartbeat  *HeartbeatStats `json:"heartbeat,omitempty"`
	Host       string          `json:"host,omitempty"`
	Upstream   string          `json:"upstream,omitempty"`
}

// Status returns the current per-transport stats. Safe for concurrent
// callers; the underlying Stats() calls are race-free.
func (e *Exporter) Status() ExporterStatus {
	if e == nil {
		return ExporterStatus{Configured: false}
	}
	out := ExporterStatus{
		Configured: e.Enabled(),
		Host:       e.host,
		Upstream:   e.upstream,
	}
	if e.Log != nil {
		s := e.Log.Stats()
		out.Log = &s
	}
	if e.Webhook != nil {
		s := e.Webhook.Stats()
		out.Webhook = &s
	}
	if e.Heartbeat != nil && e.Heartbeat.Configured() {
		s := e.Heartbeat.Stats()
		out.Heartbeat = &s
	}
	return out
}

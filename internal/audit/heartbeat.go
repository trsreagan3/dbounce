// Heartbeat events + heartbeat_gap watchdog per
// [[prompt-injection-disable-bouncer-threat]].
//
// Threat model: an attacker who induces an operator (or an AI agent)
// to disable / pause / kill the bouncer process eliminates dbounce's
// audit + gating surface — but the disappearance itself is a signal.
// Heartbeat events emitted on a fixed cadence let a SIEM consumer alert
// on the ABSENCE of recent heartbeats. The heartbeat_gap rule fires
// in-process when the bouncer detects ITS OWN tick loop fell behind
// (process suspended, CPU starved, container throttled, debugger
// attached) so the alert reaches the SIEM via the same export channel
// before the gap is wide enough to look like a full silence.
//
// Per [[security-team-positioning-safety-not-surveillance]]: heartbeats
// default OFF. The operator enables via --heartbeat-interval DURATION;
// any non-zero positive value turns on both the periodic heartbeat AND
// the gap watchdog. Sibling agents (ibounce / kbounce) ship the SAME
// flag name + the SAME OCSF schema so a single SIEM rule keyed on
// activity_name=heartbeat works cross-product.
//
// Per [[deliberate-feature-completion]] the gap alert lands in three
// places at once:
//
//   1) OCSF SECURITY_ALERT event through the wired Exporter (so the
//      SIEM sees it on the same channel as every other audit event)
//   2) stderr line (so an operator tailing the proxy log sees it
//      immediately, even if the export transport is broken)
//   3) /healthz status flips to "degraded" (so a Kubernetes liveness
//      probe / load-balancer health check can drain traffic from a
//      throttled instance)
//
// Per [[scorer-is-ground-truth]] the heartbeater NEVER touches the
// decide() path — it observes wall-clock + emits metadata; it cannot
// allow or deny a SQL statement.
//
// Per the spec memo: race-clean. The Heartbeater holds zero mutable
// shared state on the read path beyond an atomic last-tick timestamp +
// an atomic "degraded" flag. `go test -race -count=10` is the bar.

package audit

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// HeartbeatOptions wires the Heartbeater from CLI flags. All fields
// optional: an empty struct yields a disabled heartbeater.
//
// Per the spec: default OFF (Interval == 0). Operators who don't think
// about heartbeats get zero behavior change vs. pre-heartbeat builds;
// operators who do opt in via a single duration flag.
type HeartbeatOptions struct {
	// Interval is how often the tick loop emits a HEARTBEAT event.
	// Zero (default) disables the heartbeater entirely — Start is a
	// no-op + Stats reports Configured=false. Practical range: 5s
	// (high-fidelity, ~17k events/day) to 5m (low-overhead, ~290
	// events/day). The CLI clamps to 1s-1h at parse time.
	Interval time.Duration

	// GapThreshold is the wall-clock delta past Interval that fires
	// the heartbeat_gap alert. Zero defaults to 2.5 * Interval — wide
	// enough that a single late tick from a normal GC pause doesn't
	// fire (Go's GC is sub-100ms even on small heaps), narrow enough
	// that a 30s sleep / suspend gets caught well under the typical
	// SIEM absence-detection window (which is often 5m).
	GapThreshold time.Duration

	// Host stamps src_endpoint.hostname on every heartbeat + gap alert
	// event so the SIEM correlates by listener. Same value the
	// Exporter holds — the CLI passes the proxy's "host:port".
	Host string

	// Stderr is where gap alerts print a one-line operator-visible
	// notice. Defaults to os.Stderr; tests override to a *bytes.Buffer
	// to assert the line format without touching the real terminal.
	Stderr io.Writer

	// emit is the heartbeat-event sink. Production callers leave it
	// nil; SetExporter wires it to the live Exporter at startup. Tests
	// pass a captured-slice stub.
	emit func(ctx context.Context, evt Event) error

	// gapEmit is the gap-alert sink. Defaults to the same emit
	// channel as periodic heartbeats so a SIEM sees both on the same
	// transport. Separately injectable for tests that want to assert
	// the gap alert in isolation.
	gapEmit func(ctx context.Context, evt Event) error
}

// Heartbeater emits OCSF HEARTBEAT events on a fixed cadence + fires a
// heartbeat_gap alert when the tick loop detects its own clock fell
// behind. Construct via NewHeartbeater; wire the export channel via
// SetExporter; Start to launch the goroutines; Stop on Shutdown.
//
// Race-clean by construction: the tick loop owns its own state; the
// watchdog loop reads lastTickUnixNano via atomic; the degraded flag
// + counters are atomic. Stats() takes no locks. The emit pointer is
// guarded by a sync.RWMutex taken only on rare wire-time changes (the
// CLI sets it once; tests may swap mid-flight) — never blocks the tick
// path because the tick path holds the RLock once per emission.
type Heartbeater struct {
	opts HeartbeatOptions

	// emitMu guards emit + gapEmit so SetExporter is race-clean with
	// concurrent tick + gap emissions. RLock is taken once per emit;
	// no allocation, no blocking under normal load.
	emitMu  sync.RWMutex
	emit    func(ctx context.Context, evt Event) error
	gapEmit func(ctx context.Context, evt Event) error

	// lastTickUnixNano is the Unix-nano timestamp of the most-recent
	// successful tick (after emit returned). Atomic so the watchdog
	// reads it without taking emitMu — the tick loop is the only
	// writer; the watchdog is the only reader.
	lastTickUnixNano atomic.Int64

	// startedAtUnixNano is the wall-clock at Start() so Stats can
	// report uptime + the watchdog can debounce its first check
	// (don't fire gap on the very first interval — there's no prior
	// tick to gap against).
	startedAtUnixNano atomic.Int64

	// degraded is set by the watchdog when a gap fires; cleared on the
	// next successful tick. The proxy's /healthz reads this via
	// IsDegraded() + flips the response Status to "degraded" when set.
	// Atomic-only access; never gated by emitMu.
	degraded atomic.Bool

	// Counters surfaced via Stats() to the
	// dbounce_audit_export_status MCP tool + /healthz.
	emitted      atomic.Int64
	gapFired     atomic.Int64
	missedTicks  atomic.Int64

	// stop signals tick + watchdog goroutines to exit. wg waits for
	// both to drain before Stop returns.
	stop chan struct{}
	wg   sync.WaitGroup

	// running guards double-Start. Atomic CAS so a misuse doesn't
	// spawn duplicate goroutines.
	running atomic.Bool
}

// NewHeartbeater constructs a Heartbeater. Always safe to call — even
// with Interval=0; the returned instance reports Configured=false +
// Start is a no-op. The CLI calls Start unconditionally so the heartbeat
// surface composes cleanly with the existing exporter wiring.
//
// When GapThreshold is zero, it defaults to 2.5 * Interval — wide
// enough that one missed tick from a GC pause / brief network IO doesn't
// fire, narrow enough that a 30s container freeze gets caught well
// before the typical SIEM 5-minute absence window.
func NewHeartbeater(opts HeartbeatOptions) *Heartbeater {
	if opts.GapThreshold == 0 && opts.Interval > 0 {
		// 2.5x → 5 * Interval / 2; integer math avoids float
		// rounding on small intervals.
		opts.GapThreshold = (opts.Interval * 5) / 2
	}
	return &Heartbeater{
		opts:    opts,
		emit:    opts.emit,
		gapEmit: opts.gapEmit,
		stop:    make(chan struct{}),
	}
}

// SetExporter wires both the periodic-heartbeat + gap-alert channels
// to a live *Exporter. Safe to call concurrently with Start / tick
// emissions (the emit pointers are mutex-guarded). Pass nil to detach
// (e.g. during Shutdown before the exporter closes).
//
// Both heartbeats and gap alerts flow through the SAME exporter per the
// memo: a SIEM consuming one endpoint sees the heartbeat stream + the
// gap alerts in chronological order alongside decision audit events.
func (h *Heartbeater) SetExporter(exp *Exporter) {
	if h == nil {
		return
	}
	h.emitMu.Lock()
	defer h.emitMu.Unlock()
	if exp == nil {
		h.emit = nil
		h.gapEmit = nil
		return
	}
	emit := func(ctx context.Context, evt Event) error {
		return exp.Emit(ctx, evt)
	}
	h.emit = emit
	h.gapEmit = emit
}

// Configured reports whether the operator turned the heartbeater on.
// False when Interval == 0 (the safe-default OFF posture per the spec).
func (h *Heartbeater) Configured() bool {
	if h == nil {
		return false
	}
	return h.opts.Interval > 0
}

// Start launches the tick + watchdog goroutines. No-op when not
// Configured. Idempotent: double-Start is detected via running CAS +
// returns silently (the second call doesn't spawn dup goroutines).
//
// The two goroutines:
//
//   - tickLoop: ticks every Interval; builds a HEARTBEAT event +
//     emits via the wired Exporter; updates lastTickUnixNano +
//     clears degraded.
//
//   - watchdogLoop: ticks every Interval/4 (or 500ms, whichever is
//     smaller); reads lastTickUnixNano; if (now - last) > Interval +
//     GapThreshold AND the heartbeater has been running long enough
//     to have had at least one tick, fires the heartbeat_gap alert
//     (debounced: one alert per uninterrupted gap, not one per
//     watchdog cycle inside the gap).
func (h *Heartbeater) Start() {
	if !h.Configured() {
		return
	}
	if !h.running.CompareAndSwap(false, true) {
		return
	}
	now := time.Now().UnixNano()
	h.startedAtUnixNano.Store(now)
	h.lastTickUnixNano.Store(now)

	h.wg.Add(2)
	go h.tickLoop()
	go h.watchdogLoop()
}

// Stop signals both goroutines + waits for them to drain. Idempotent;
// safe to call when never Started. Caller MUST call Stop BEFORE the
// Exporter's Shutdown so the in-flight final HEARTBEAT (if any) drains
// to the transport ahead of the per-transport channel close.
func (h *Heartbeater) Stop() {
	if h == nil || !h.running.CompareAndSwap(true, false) {
		return
	}
	close(h.stop)
	h.wg.Wait()
}

// IsDegraded reports whether the watchdog observed a gap that hasn't
// yet been cleared by a successful tick. The proxy's /healthz reads
// this + flips Status to "degraded" so a Kubernetes liveness probe
// drains traffic from a throttled instance.
func (h *Heartbeater) IsDegraded() bool {
	if h == nil {
		return false
	}
	return h.degraded.Load()
}

// tickLoop emits a HEARTBEAT event every Interval. Holds emitMu's
// RLock around the actual emit call so SetExporter swap is race-clean.
// Updates lastTickUnixNano AFTER emit returns so the watchdog sees a
// stale timestamp during a slow emit (which a watchdog-fired gap alert
// will correctly surface).
func (h *Heartbeater) tickLoop() {
	defer h.wg.Done()
	t := time.NewTicker(h.opts.Interval)
	defer t.Stop()
	// Fire one immediate heartbeat at start so the SIEM has a
	// confirmed-alive signal without waiting a full Interval. The
	// emit BEFORE the first tick of the ticker; the ticker's first
	// fire is one Interval later as usual.
	h.emitOneTick()
	for {
		select {
		case <-h.stop:
			return
		case <-t.C:
			h.emitOneTick()
		}
	}
}

// emitOneTick builds + emits one HEARTBEAT event, then updates
// lastTickUnixNano + clears degraded. Error from emit is intentionally
// swallowed (same posture as exporter elsewhere — the transport's drop
// counter is the visibility channel).
func (h *Heartbeater) emitOneTick() {
	h.emitMu.RLock()
	emit := h.emit
	h.emitMu.RUnlock()
	evt := NewHeartbeatEvent(h.opts.Host, h.opts.Interval)
	if emit != nil {
		_ = emit(context.Background(), evt)
	}
	// Update AFTER emit so a long emit shows up as a stale
	// lastTickUnixNano + a watchdog gap fires correctly.
	h.lastTickUnixNano.Store(time.Now().UnixNano())
	h.emitted.Add(1)
	// Successful tick clears any prior degraded state. Use CAS so we
	// only count the unique recovery transitions, not every tick.
	if h.degraded.CompareAndSwap(true, false) {
		// Cleared. No additional event — the next heartbeat IS the
		// recovery signal (its presence after a gap alert means
		// "we're back"). Keeping recovery silent avoids doubling the
		// SIEM event volume on every transient hiccup.
	}
}

// watchdogLoop polls the wall-clock + fires heartbeat_gap when the
// tick loop detects its own clock fell behind by more than
// (Interval + GapThreshold). Debounced via the degraded flag: one gap
// alert per uninterrupted gap, not one per watchdog cycle.
func (h *Heartbeater) watchdogLoop() {
	defer h.wg.Done()
	// Watchdog cadence: a fraction of Interval so we detect gaps
	// promptly without busy-spinning. Min 100ms, max 1s, default
	// Interval/4. Caps avoid pathological values on extreme
	// Intervals (1h interval would otherwise poll every 15m, missing
	// short freezes).
	period := h.opts.Interval / 4
	if period < 100*time.Millisecond {
		period = 100 * time.Millisecond
	}
	if period > time.Second {
		period = time.Second
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-t.C:
			h.checkGap()
		}
	}
}

// checkGap reads lastTickUnixNano + emits a gap alert when the elapsed
// wall time exceeds (Interval + GapThreshold). Debounced via the
// degraded CAS — only the transition from healthy → degraded fires the
// alert; subsequent watchdog cycles inside the same gap stay silent.
func (h *Heartbeater) checkGap() {
	last := h.lastTickUnixNano.Load()
	started := h.startedAtUnixNano.Load()
	if last == 0 || started == 0 {
		return
	}
	now := time.Now().UnixNano()
	threshold := int64(h.opts.Interval + h.opts.GapThreshold)
	elapsed := now - last
	// Debounce: only the rising edge (healthy → degraded) emits. The
	// CAS guarantees exactly-once alert per gap; cleared on the next
	// successful tick.
	if elapsed <= threshold {
		return
	}
	if !h.degraded.CompareAndSwap(false, true) {
		return
	}
	h.gapFired.Add(1)
	h.missedTicks.Add(elapsed / int64(h.opts.Interval))

	gapDur := time.Duration(elapsed)
	// (1) stderr line — operator-visible immediately even if export
	// transport is broken. Format mirrors the OCSF event's
	// status_detail so a grep on either surface finds the same gap.
	if h.opts.Stderr != nil {
		fmt.Fprintf(h.opts.Stderr,
			"dbounce: heartbeat_gap observed (last tick %s ago, interval %s, "+
				"threshold %s); /healthz now reports degraded — "+
				"consider distributing a profile that keeps the proxy "+
				"resident on a non-throttled instance\n",
			gapDur.Round(time.Millisecond),
			h.opts.Interval, h.opts.GapThreshold)
	}

	// (2) OCSF SECURITY_ALERT event through the wired Exporter.
	h.emitMu.RLock()
	gapEmit := h.gapEmit
	h.emitMu.RUnlock()
	if gapEmit == nil {
		return
	}
	evt := NewHeartbeatGapEvent(h.opts.Host, h.opts.Interval, h.opts.GapThreshold, gapDur)
	_ = gapEmit(context.Background(), evt)
}

// HeartbeatStats is the snapshot the dbounce_audit_export_status MCP
// tool + /healthz read for the heartbeater. Race-free: all underlying
// counters are atomic.
type HeartbeatStats struct {
	Configured       bool          `json:"configured"`
	Interval         string        `json:"interval,omitempty"`
	GapThreshold     string        `json:"gap_threshold,omitempty"`
	Emitted          int64         `json:"emitted"`
	GapFired         int64         `json:"gap_fired"`
	MissedTicks      int64         `json:"missed_ticks"`
	Degraded         bool          `json:"degraded"`
	LastTickUnixNano int64         `json:"last_tick_unix_nano,omitempty"`
	IntervalNanos    time.Duration `json:"-"`
	GapThresholdNs   time.Duration `json:"-"`
}

// Stats returns the current heartbeater counters. Safe to call
// concurrently.
func (h *Heartbeater) Stats() HeartbeatStats {
	if h == nil {
		return HeartbeatStats{Configured: false}
	}
	out := HeartbeatStats{
		Configured:     h.Configured(),
		Emitted:        h.emitted.Load(),
		GapFired:       h.gapFired.Load(),
		MissedTicks:    h.missedTicks.Load(),
		Degraded:       h.degraded.Load(),
		IntervalNanos:  h.opts.Interval,
		GapThresholdNs: h.opts.GapThreshold,
	}
	if h.Configured() {
		out.Interval = h.opts.Interval.String()
		out.GapThreshold = h.opts.GapThreshold.String()
		out.LastTickUnixNano = h.lastTickUnixNano.Load()
	}
	return out
}

// heartbeat_test.go — unit + race tests for the
// [[prompt-injection-disable-bouncer-threat]] heartbeat + gap watchdog.
//
// Per the spec memo: dbounce has the port-race fix (53d97d3) + the
// cross-process sync-prompt poll (d82ded9) + the connWG cleanup
// (183f1ca) + many concurrency-sensitive features. The Heartbeater MUST
// be race-clean; TestHeartbeater_RaceClean stresses every emit /
// watchdog / Stop surface concurrently + this file is invoked under
// `go test -race -count=10` per the spec.
//
// Tests cover:
//
//   - default-OFF posture (Interval=0 → Configured()=false, Start no-op)
//   - GapThreshold defaulting to 2.5x Interval
//   - periodic emit cadence (HEARTBEAT events appear at Interval)
//   - HEARTBEAT event schema (OCSF v1.1.0 class-6003, activity_id=99,
//     activity_name="heartbeat", severity Informational)
//   - heartbeat_gap event schema (SECURITY_ALERT, severity Medium,
//     activity_name="heartbeat_gap", ext.rule_id="heartbeat_gap",
//     ext.{interval,threshold,observed}_seconds populated)
//   - stderr line on gap fire
//   - IsDegraded() flips on gap + clears on next successful tick
//   - gap debounce (only one alert per uninterrupted gap)
//   - Stop is idempotent + doesn't leak goroutines
//   - SetExporter race-safe (concurrent Set + emit don't race)
//   - JSON round-trip safety on both HEARTBEAT + heartbeat_gap events

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syncBuffer is a thread-safe bytes.Buffer for the stderr capture path.
// The watchdog goroutine writes the gap line concurrently with the test
// goroutine reading String() — without the mutex `go test -race`
// flags the unsynchronized access.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newCaptureHB constructs a Heartbeater wired to an in-memory capture
// sink. Returns the heartbeater + a snapshot getter that returns the
// captured events. Tests that don't need a real Exporter use this so
// per-tick assertions stay deterministic + cheap.
func newCaptureHB(opts HeartbeatOptions) (*Heartbeater, func() []Event, *syncBuffer) {
	var (
		mu     sync.Mutex
		events []Event
	)
	emit := func(_ context.Context, evt Event) error {
		mu.Lock()
		defer mu.Unlock()
		// Deep-copy via the snapshot path below — the test snapshot
		// getter clones, so storing the value as-is is safe.
		events = append(events, evt)
		return nil
	}
	stderr := &syncBuffer{}
	opts.emit = emit
	opts.gapEmit = emit
	opts.Stderr = stderr
	return NewHeartbeater(opts), func() []Event {
		mu.Lock()
		defer mu.Unlock()
		out := make([]Event, len(events))
		copy(out, events)
		return out
	}, stderr
}

// TestHeartbeater_DefaultOff verifies the safety-not-surveillance
// posture: Interval=0 → NOT Configured, Start no-op, no events emitted.
func TestHeartbeater_DefaultOff(t *testing.T) {
	hb, snapshot, _ := newCaptureHB(HeartbeatOptions{})
	assert.False(t, hb.Configured(),
		"Interval=0 MUST default to OFF (safety-not-surveillance posture)")
	hb.Start()
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, snapshot(),
		"disabled heartbeater MUST NOT emit any events")
	stats := hb.Stats()
	assert.False(t, stats.Configured)
	assert.Equal(t, int64(0), stats.Emitted)
	hb.Stop()
}

// TestHeartbeater_GapThresholdDefault locks in the 2.5x-Interval
// default. Per the spec memo: wide enough that a GC pause doesn't
// fire, narrow enough that a 30s freeze gets caught well below a
// typical 5m SIEM absence window.
func TestHeartbeater_GapThresholdDefault(t *testing.T) {
	hb := NewHeartbeater(HeartbeatOptions{Interval: 4 * time.Second})
	assert.Equal(t, 10*time.Second, hb.opts.GapThreshold,
		"GapThreshold MUST default to 2.5x Interval when zero")
}

// TestHeartbeater_GapThresholdExplicit confirms a caller-supplied
// threshold isn't overwritten by the default.
func TestHeartbeater_GapThresholdExplicit(t *testing.T) {
	hb := NewHeartbeater(HeartbeatOptions{
		Interval:     1 * time.Second,
		GapThreshold: 250 * time.Millisecond,
	})
	assert.Equal(t, 250*time.Millisecond, hb.opts.GapThreshold,
		"explicit GapThreshold MUST be preserved verbatim")
}

// TestHeartbeater_PeriodicEmit confirms HEARTBEAT events appear on
// schedule. Uses short intervals to keep the test fast.
func TestHeartbeater_PeriodicEmit(t *testing.T) {
	hb, snapshot, _ := newCaptureHB(HeartbeatOptions{
		Interval: 150 * time.Millisecond,
		Host:     "127.0.0.1:5433",
	})
	hb.Start()
	defer hb.Stop()
	// Wait ~3 ticks worth — first emit is immediate at Start, then
	// every Interval.
	time.Sleep(500 * time.Millisecond)
	events := snapshot()
	assert.GreaterOrEqual(t, len(events), 2,
		"expected at least 2 heartbeats in 500ms with 150ms interval; got %d", len(events))
	// Schema sanity on the first event.
	evt := events[0]
	assert.Equal(t, 6003, evt.ClassUID)
	assert.Equal(t, ActivityIDOther, evt.ActivityID)
	assert.Equal(t, "heartbeat", evt.ActivityName)
	assert.Equal(t, ocsfSeverityInformationalID, evt.SeverityID,
		"heartbeat is bookkeeping — severity MUST stay Informational")
	require.NotNil(t, evt.Unmapped)
	assert.Equal(t, string(EventTypeHeartbeat), evt.Unmapped.IAMJIT.EventType)
	// interval_seconds is in the ext payload so a SIEM consumer can
	// answer "how often SHOULD this be emitting?" without a JOIN.
	require.NotNil(t, evt.Unmapped.IAMJIT.Ext)
	assert.Equal(t, 0.15, evt.Unmapped.IAMJIT.Ext["interval_seconds"])
	assert.Equal(t, "127.0.0.1", evt.SrcEndpoint.Hostname)
	assert.Equal(t, 5433, evt.SrcEndpoint.Port)
}

// TestHeartbeater_GapFiresOnStallEmission triggers a synthetic gap by
// freezing the lastTick timestamp + waiting for the watchdog to notice.
// Per the spec: gap alert fires on stderr + as a SECURITY_ALERT event.
func TestHeartbeater_GapFiresOnStall(t *testing.T) {
	hb, snapshot, stderr := newCaptureHB(HeartbeatOptions{
		Interval:     200 * time.Millisecond,
		GapThreshold: 100 * time.Millisecond,
		Host:         "127.0.0.1:5433",
	})
	hb.Start()
	defer hb.Stop()

	// Wait for the first heartbeat to confirm the loop is alive.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(snapshot()) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.GreaterOrEqual(t, len(snapshot()), 1, "first heartbeat MUST land")

	// Simulate a stall: rewind lastTick into the past so the watchdog
	// sees (now - last) > Interval + GapThreshold. This is the same
	// signal the watchdog observes when the tick loop was throttled.
	staleAt := time.Now().Add(-1 * time.Second).UnixNano()
	hb.lastTickUnixNano.Store(staleAt)

	// Watchdog runs on min(Interval/4, 1s, 100ms) = 50ms here, so
	// within a few hundred ms it MUST notice.
	deadline = time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if hb.IsDegraded() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.True(t, hb.IsDegraded(),
		"watchdog MUST detect the synthetic stall + flip degraded")

	// stderr line landed (operator-visible immediate signal).
	assert.Contains(t, stderr.String(), "heartbeat_gap observed",
		"gap MUST write to stderr; got: %q", stderr.String())
	assert.Contains(t, stderr.String(), "/healthz now reports degraded",
		"stderr line MUST mention /healthz so operators know what to expect")

	// OCSF SECURITY_ALERT event landed via gapEmit.
	var alert *Event
	for i := range snapshot() {
		e := snapshot()[i]
		if e.ActivityName == string(AlertRuleHeartbeatGap) {
			ev := e
			alert = &ev
			break
		}
	}
	require.NotNil(t, alert, "heartbeat_gap SECURITY_ALERT MUST be emitted")
	assert.Equal(t, ocsfSeverityMediumID, alert.SeverityID)
	assert.Equal(t, string(EventTypeSecurityAlert),
		alert.Unmapped.IAMJIT.EventType)
	assert.Equal(t, string(AlertRuleHeartbeatGap),
		alert.Unmapped.IAMJIT.Ext["rule_id"])
	// Neutral language per [[security-team-positioning-safety-not-
	// surveillance]] — no "violation" / "attack" / "abuse" wording.
	detail := strings.ToLower(alert.StatusDetail)
	assert.NotContains(t, detail, "violation")
	assert.NotContains(t, detail, "attack")
	assert.NotContains(t, detail, "abuse")
	assert.Contains(t, detail, "consider distributing",
		"detail MUST use the neutral cross-rule suggestion phrasing")
}

// TestHeartbeater_GapDebounced confirms that ONE gap → ONE alert; the
// watchdog doesn't spam alerts on every poll inside the same gap. Uses
// a long Interval so the tick loop doesn't overwrite our pinned stale
// timestamp mid-test (which would prematurely clear degraded + un-debounce
// the test setup, not the production code path).
func TestHeartbeater_GapDebounced(t *testing.T) {
	hb, snapshot, _ := newCaptureHB(HeartbeatOptions{
		Interval:     5 * time.Second, // long enough that the tick loop won't run again
		GapThreshold: 100 * time.Millisecond,
		Host:         "127.0.0.1:5433",
	})
	hb.Start()
	defer hb.Stop()

	// First tick fires immediately at Start; pin lastTick into the
	// past so the gap sustains across watchdog cycles without the tick
	// loop firing again (Interval=5s gives us ~5s headroom).
	time.Sleep(50 * time.Millisecond)
	staleAt := time.Now().Add(-30 * time.Second).UnixNano()
	hb.lastTickUnixNano.Store(staleAt)

	// Watchdog period = min(Interval/4, 1s, but bounded to 100ms min,
	// 1s max) = 1s here. Wait long enough for several watchdog cycles
	// — if the debounce CAS is broken we'd see multiple alerts.
	time.Sleep(3500 * time.Millisecond)

	var gapCount int
	for _, e := range snapshot() {
		if e.ActivityName == string(AlertRuleHeartbeatGap) {
			gapCount++
		}
	}
	assert.Equal(t, 1, gapCount,
		"exactly ONE gap alert per uninterrupted gap (debounce via CAS); got %d", gapCount)
}

// TestHeartbeater_DegradedClearsOnNextTick confirms the degraded flag
// is cleared on the next successful tick after a gap — so a transient
// hiccup recovers cleanly without manual intervention.
//
// Uses a longer Interval (2s) so that we can deterministically observe
// (a) the watchdog flipping degraded after we pin a stale timestamp,
// (b) the next natural tick clearing it. With short intervals the tick
// loop races the watchdog + the test becomes flaky on a loaded CI box.
func TestHeartbeater_DegradedClearsOnNextTick(t *testing.T) {
	hb, _, _ := newCaptureHB(HeartbeatOptions{
		Interval:     1500 * time.Millisecond,
		GapThreshold: 100 * time.Millisecond,
		Host:         "127.0.0.1:5433",
	})
	hb.Start()
	defer hb.Stop()
	// Let the first tick land.
	time.Sleep(80 * time.Millisecond)

	// Force degraded by pinning lastTick far enough in the past that
	// the watchdog's next poll (period 375ms, capped at 1s) sees it.
	staleAt := time.Now().Add(-30 * time.Second).UnixNano()
	hb.lastTickUnixNano.Store(staleAt)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if hb.IsDegraded() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.True(t, hb.IsDegraded(),
		"watchdog must flip degraded after a sustained synthetic stall")

	// Within the next Interval (1500ms) the natural tick MUST clear it.
	deadline = time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !hb.IsDegraded() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.False(t, hb.IsDegraded(),
		"successful tick after a gap MUST clear degraded (recovery)")
}

// TestHeartbeater_StopIdempotent confirms Stop can be called multiple
// times + before Start, without panicking / racing.
func TestHeartbeater_StopIdempotent(t *testing.T) {
	hb, _, _ := newCaptureHB(HeartbeatOptions{
		Interval: 100 * time.Millisecond,
	})
	// Stop before Start — no-op.
	hb.Stop()
	hb.Start()
	hb.Stop()
	// Double-Stop — no-op.
	hb.Stop()
}

// TestHeartbeater_SetExporterRaceClean stresses SetExporter against
// concurrent tick emissions. The mutex on emit makes the swap
// race-clean per the spec memo.
func TestHeartbeater_SetExporterRaceClean(t *testing.T) {
	hb, _, _ := newCaptureHB(HeartbeatOptions{
		Interval: 10 * time.Millisecond, // ticks fast
	})
	hb.Start()
	defer hb.Stop()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Concurrent SetExporter swaps from multiple goroutines.
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
				hb.SetExporter(nil)
				time.Sleep(time.Millisecond)
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestHeartbeater_RaceClean — invoked with -race; runs every public
// surface concurrently to catch any unsynchronized field access.
func TestHeartbeater_RaceClean(t *testing.T) {
	hb, snapshot, _ := newCaptureHB(HeartbeatOptions{
		Interval:     10 * time.Millisecond,
		GapThreshold: 5 * time.Millisecond,
	})
	hb.Start()
	defer hb.Stop()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var ops atomic.Int64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = hb.Stats()
				_ = hb.IsDegraded()
				_ = hb.Configured()
				_ = snapshot()
				ops.Add(1)
			}
		}()
	}
	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
	assert.Greater(t, ops.Load(), int64(100),
		"the stress loop must have actually run")
}

// TestHeartbeater_StatsConfigured surfaces the operator-visible
// snapshot fields the MCP tool + /healthz read.
func TestHeartbeater_StatsConfigured(t *testing.T) {
	hb, _, _ := newCaptureHB(HeartbeatOptions{
		Interval:     200 * time.Millisecond,
		GapThreshold: 100 * time.Millisecond,
		Host:         "127.0.0.1:5433",
	})
	hb.Start()
	defer hb.Stop()
	time.Sleep(250 * time.Millisecond)
	stats := hb.Stats()
	assert.True(t, stats.Configured)
	assert.Equal(t, "200ms", stats.Interval)
	assert.Equal(t, "100ms", stats.GapThreshold)
	assert.GreaterOrEqual(t, stats.Emitted, int64(1))
	assert.False(t, stats.Degraded)
	assert.Greater(t, stats.LastTickUnixNano, int64(0))
}

// TestHeartbeatEvent_JSONRoundTrip confirms the OCSF envelope survives
// a JSON-marshal-unmarshal trip with no surprises — relevant for the
// JSONL log file + webhook payload path which both serialize to JSON
// before reaching the SIEM.
func TestHeartbeatEvent_JSONRoundTrip(t *testing.T) {
	orig := NewHeartbeatEvent("127.0.0.1:5433", 30*time.Second)
	b, err := json.Marshal(orig)
	require.NoError(t, err)
	var decoded Event
	require.NoError(t, json.Unmarshal(b, &decoded))
	assert.Equal(t, orig.ActivityName, decoded.ActivityName)
	assert.Equal(t, orig.SeverityID, decoded.SeverityID)
	require.NotNil(t, decoded.Unmapped)
	assert.Equal(t, string(EventTypeHeartbeat), decoded.Unmapped.IAMJIT.EventType)
	assert.Equal(t, float64(30), decoded.Unmapped.IAMJIT.Ext["interval_seconds"])
}

// TestHeartbeatGapEvent_JSONRoundTrip mirrors the round-trip check for
// the SECURITY_ALERT path.
func TestHeartbeatGapEvent_JSONRoundTrip(t *testing.T) {
	orig := NewHeartbeatGapEvent(
		"127.0.0.1:5433",
		30*time.Second,
		15*time.Second,
		77*time.Second)
	b, err := json.Marshal(orig)
	require.NoError(t, err)
	var decoded Event
	require.NoError(t, json.Unmarshal(b, &decoded))
	assert.Equal(t, string(AlertRuleHeartbeatGap), decoded.ActivityName)
	assert.Equal(t, ocsfSeverityMediumID, decoded.SeverityID)
	require.NotNil(t, decoded.Unmapped)
	assert.Equal(t, string(EventTypeSecurityAlert), decoded.Unmapped.IAMJIT.EventType)
	assert.Equal(t, string(AlertRuleHeartbeatGap),
		decoded.Unmapped.IAMJIT.Ext["rule_id"])
	assert.Equal(t, float64(30), decoded.Unmapped.IAMJIT.Ext["interval_seconds"])
	assert.Equal(t, float64(15), decoded.Unmapped.IAMJIT.Ext["threshold_seconds"])
	assert.Equal(t, float64(77),
		decoded.Unmapped.IAMJIT.Ext["observed_gap_seconds"])
}

// TestExporter_ShutdownStopsHeartbeaterFirst guards the ordering
// invariant in Exporter.Shutdown: heartbeater MUST stop before
// LogWriter / WebhookPusher close their channels. Without this order,
// the heartbeater's in-flight emit can race a closed channel.
func TestExporter_ShutdownStopsHeartbeaterFirst(t *testing.T) {
	dir := t.TempDir()
	lw, err := NewLogWriter(LogOptions{Path: dir + "/audit.jsonl", Fsync: true})
	require.NoError(t, err)
	exp := NewExporter(lw, nil, "127.0.0.1:0", "")
	hb := NewHeartbeater(HeartbeatOptions{
		Interval: 20 * time.Millisecond,
		Host:     "127.0.0.1:0",
	})
	hb.SetExporter(exp)
	exp.Heartbeat = hb
	hb.Start()
	time.Sleep(80 * time.Millisecond)
	// Now Shutdown — the ordering invariant means the heartbeater's
	// goroutines drain BEFORE the LogWriter closes its channel. If the
	// invariant is broken, this Shutdown deadlocks / races (test
	// timeout would catch it).
	require.NoError(t, exp.Shutdown(context.Background()))
}

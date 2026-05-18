// Slice 2 wiring integration tests per [[security-team-audit-export]].
// Three emit sites + the cross-process drain poller:
//
//   1. Admin-fallback grant (pause-window demote of transparent DENY)
//      fires ADMIN_FALLBACK alongside the decision event on the
//      in-process Exporter + RuleEngine.
//
//   2. Admin-fallback end (pause stop + pause-window expiry) writes a
//      pending_audit_events row that the poller drains + emits as
//      ADMIN_FALLBACK_END.
//
//   3. Profile install writes a pending_audit_events row that the
//      poller drains + emits as PROFILE_INSTALLED (and feeds the
//      RuleEngine.ObserveProfileInstall hook for the
//      non_org_profile_install alert).

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
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

// captureExporter returns a JSONL-log-only audit.Exporter writing to
// a temp file + a snapshot getter that reads the file back. Tests use
// this in place of spinning up an httptest webhook for every case.
//
// LogWriter is ASYNC (writes are queued onto a channel + drained by a
// worker goroutine), so the snapshot uses Stats().Written to wait for
// the worker to catch up to the most-recently-queued event before
// reading the file. The wait is bounded (200ms default) so a test
// asserting "exactly N events" doesn't hang when fewer than N events
// actually fire.
func captureExporter(t *testing.T) (*audit.Exporter, func() []audit.Event) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	lw, err := audit.NewLogWriter(audit.LogOptions{
		Path: logPath,
	})
	require.NoError(t, err)
	exp := audit.NewExporter(lw, nil, "127.0.0.1:5433", "")
	t.Cleanup(func() {
		_ = exp.Shutdown(context.Background())
	})
	snapshot := func() []audit.Event {
		// Wait briefly for the LogWriter worker to drain queued
		// writes — async write semantics mean an Emit() that just
		// returned has only ENQUEUED, not flushed. The exporter
		// status returns Written = total events flushed; we wait
		// until it stops climbing within a 200ms window.
		deadline := time.Now().Add(500 * time.Millisecond)
		var last int64
		stable := 0
		for time.Now().Before(deadline) {
			st := exp.Status()
			if st.Log == nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if st.Log.Written == last {
				stable++
				if stable >= 3 {
					break
				}
			} else {
				stable = 0
			}
			last = st.Log.Written
			time.Sleep(10 * time.Millisecond)
		}
		f, err := os.Open(logPath)
		if err != nil {
			return nil
		}
		defer f.Close()
		var out []audit.Event
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			var e audit.Event
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				continue
			}
			out = append(out, e)
		}
		return out
	}
	return exp, snapshot
}

// captureAlertEngine returns a RuleEngine wired to a slice-collector
// emit so tests can assert which RULE-FIRED alerts the engine
// emitted (separate from the lifecycle synthetics the Exporter
// receives directly).
func captureAlertEngine(t *testing.T) (*audit.RuleEngine, func() []audit.Event) {
	t.Helper()
	var (
		mu     sync.Mutex
		events []audit.Event
	)
	engine := audit.NewRuleEngine(audit.RuleEngineOptions{
		Host: "127.0.0.1:5433",
	})
	engine.SetEmitForTest(func(ctx context.Context, evt audit.Event) error {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
		return nil
	})
	return engine, func() []audit.Event {
		mu.Lock()
		defer mu.Unlock()
		out := make([]audit.Event, len(events))
		copy(out, events)
		return out
	}
}

// TestPauseDemote_FiresAdminFallbackSynthetic verifies emit site #1
// of the Slice 2 wiring: when a transparent-mode DENY is DEMOTED to
// ALLOW by an active pause window, an ADMIN_FALLBACK synthetic flows
// through the wired Exporter alongside the decision event.
func TestPauseDemote_FiresAdminFallbackSynthetic(t *testing.T) {
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyDeny, false)
	exp, expSnapshot := captureExporter(t)
	srv.SetAuditExporter(exp)
	engine, _ := captureAlertEngine(t)
	srv.SetAlertEngine(engine)

	// Open a pause + drain the supersede/expiry queue artifact (none
	// from the open path; defensive).
	_, _, err := st.StartPause("live demo", "alice", 1*time.Hour)
	require.NoError(t, err)
	_, _ = st.DrainPendingAuditEvents(0)

	srv.evaluateAndAudit("SELECT 1", "Query")

	got := expSnapshot()
	var fallbackEvents []audit.Event
	for _, e := range got {
		if e.ActivityName == "admin_fallback" {
			fallbackEvents = append(fallbackEvents, e)
		}
	}
	require.Len(t, fallbackEvents, 1,
		"pause-demote of transparent DENY MUST fire exactly one ADMIN_FALLBACK synthetic; got %d events total",
		len(got))
	fb := fallbackEvents[0]
	require.NotNil(t, fb.Unmapped)
	assert.Equal(t, string(audit.EventTypeAdminFallback), fb.Unmapped.IAMJIT.EventType)
	require.NotNil(t, fb.Unmapped.IAMJIT.Ext)
	assert.Equal(t, "alice", fb.Unmapped.IAMJIT.Ext["started_by"],
		"the synthetic must carry the pause's started_by for SIEM triage")
	assert.Equal(t, "live demo", fb.Unmapped.IAMJIT.Ext["reason"])
	assert.Equal(t, "SELECT", fb.Unmapped.IAMJIT.Ext["statement_type"],
		"the synthetic must correlate with the underlying statement")
}

// TestPauseDemote_NoSyntheticInCooperativeMode verifies the wiring
// matches the existing pause-demote scope (transparent-mode DENYs
// only — cooperative DENYs are already advisory + non-enforcing, so
// the demote never fires).
func TestPauseDemote_NoSyntheticInCooperativeMode(t *testing.T) {
	srv, st := newPausePromptServer(t, ModeCooperative, DefaultPolicyDeny, false)
	exp, expSnapshot := captureExporter(t)
	srv.SetAuditExporter(exp)

	_, _, err := st.StartPause("debug", "alice", 1*time.Hour)
	require.NoError(t, err)
	_, _ = st.DrainPendingAuditEvents(0)

	srv.evaluateAndAudit("SELECT 1", "Query")
	got := expSnapshot()
	for _, e := range got {
		assert.NotEqual(t, "admin_fallback", e.ActivityName,
			"cooperative-mode DENYs are advisory; no ADMIN_FALLBACK synthetic should fire")
	}
}

// TestPoller_DrainsAdminFallbackEnd verifies emit site #2 of the
// Slice 2 wiring: when `dbounce pause stop` (running in a separate
// process) writes a pending_audit_events row, the run-process poller
// drains it + emits an ADMIN_FALLBACK_END synthetic through the
// wired Exporter.
func TestPoller_DrainsAdminFallbackEnd(t *testing.T) {
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyDeny, false)
	exp, expSnapshot := captureExporter(t)
	srv.SetAuditExporter(exp)

	// Simulate the cross-process StopPause path: an out-of-proc CLI
	// writes the row directly (the CLI cannot reach the run-proc's
	// Exporter).
	_, err := st.AddPendingAuditEvent(
		store.PendingAuditEventAdminFallbackEnd,
		`{"pause_id":42,"started_by":"alice","reason":"demo","end_kind":"manual"}`)
	require.NoError(t, err)

	// Manually fire one poller tick (we don't want to spin a goroutine
	// + sleep 1s in this unit test).
	srv.drainPendingAuditEventsOnce()

	got := expSnapshot()
	require.NotEmpty(t, got)
	var endEvents []audit.Event
	for _, e := range got {
		if e.ActivityName == "admin_fallback_end" {
			endEvents = append(endEvents, e)
		}
	}
	require.Len(t, endEvents, 1,
		"poller must drain ADMIN_FALLBACK_END row + emit exactly one synthetic")
	end := endEvents[0]
	require.NotNil(t, end.Unmapped)
	require.NotNil(t, end.Unmapped.IAMJIT.Ext)
	// JSON round-trip turns numbers into float64.
	assert.EqualValues(t, 42, toInt64(end.Unmapped.IAMJIT.Ext["pause_id"]))
	assert.Equal(t, "manual", end.Unmapped.IAMJIT.Ext["end_kind"])
	assert.Equal(t, "alice", end.Unmapped.IAMJIT.Ext["started_by"])

	// After drain, depth must be zero (idempotent: a second drain
	// returns nothing).
	depth, err := st.PendingAuditEventDepth()
	require.NoError(t, err)
	assert.Equal(t, 0, depth, "drained rows must be deleted in-txn")
}

// TestPoller_DrainsProfileInstalled verifies emit site #3 of the
// Slice 2 wiring (the cross-process Option A path): when
// `dbounce profile install --from URL` (running in a separate process)
// writes a pending_audit_events row, the run-process poller drains it
// + emits BOTH a PROFILE_INSTALLED lifecycle synthetic on the
// Exporter AND a non_org_profile_install SECURITY_ALERT via
// RuleEngine.ObserveProfileInstall (when the source isn't on the
// operator's allowlist).
func TestPoller_DrainsProfileInstalled(t *testing.T) {
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyDeny, false)
	exp, expSnapshot := captureExporter(t)
	srv.SetAuditExporter(exp)
	engine, ruleSnapshot := captureAlertEngine(t)
	srv.SetAlertEngine(engine)

	_, err := st.AddPendingAuditEvent(
		store.PendingAuditEventProfileInstalled,
		`{"source_url":"https://random.example/profiles.yaml","profile_names":["pg-readonly","mysql-prod"],"sha256":"deadbeef","sha256_verified":false,"installed_by":"alice","dialects":["mysql","postgres"]}`)
	require.NoError(t, err)

	srv.drainPendingAuditEventsOnce()

	// Lifecycle event lands on the Exporter.
	exportedGot := expSnapshot()
	var lifecycleEvents []audit.Event
	for _, e := range exportedGot {
		if e.ActivityName == "profile_installed" {
			lifecycleEvents = append(lifecycleEvents, e)
		}
	}
	require.Len(t, lifecycleEvents, 1,
		"poller MUST emit exactly one PROFILE_INSTALLED lifecycle event")
	life := lifecycleEvents[0]
	require.NotNil(t, life.Unmapped.IAMJIT.Ext)
	assert.Equal(t, "https://random.example/profiles.yaml",
		life.Unmapped.IAMJIT.Ext["source_url"])
	dialects, ok := life.Unmapped.IAMJIT.Ext["dialects"].([]any)
	require.True(t, ok, "ext.dialects must be present + slice-shaped per spec")
	assert.Len(t, dialects, 2,
		"per-dialect note: dialects {mysql, postgres} survive round-trip")

	// Non-org alert lands on the RuleEngine.
	ruleGot := ruleSnapshot()
	var alertEvents []audit.Event
	for _, e := range ruleGot {
		if e.ActivityName == "non_org_profile_install" {
			alertEvents = append(alertEvents, e)
		}
	}
	require.Len(t, alertEvents, 1,
		"empty allowlist → non_org_profile_install alert MUST fire too "+
			"(Slice 2 contract per [[security-team-audit-export]])")
}

// TestPoller_DrainsAdminAction verifies the ADMIN_ACTION wiring per
// [[basic-app-hygiene-features]] TIER 1 #4 +
// [[security-team-audit-export]]: when an admin CLI subcommand
// (running in a separate process from `dbounce run`) writes a
// pending_audit_events row, the run-process poller drains it + emits
// an ADMIN_ACTION OCSF event through the wired Exporter.
//
// Cross-product contract: ext.config_change.{action, actor,
// resource_*, dialects, details} all land on the wire; sibling agents
// in ibounce + kbounce ship the same shape.
func TestPoller_DrainsAdminAction(t *testing.T) {
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyDeny, false)
	exp, expSnapshot := captureExporter(t)
	srv.SetAuditExporter(exp)

	// Simulate the cross-process admin CLI path: an out-of-proc
	// `dbounce rules add` writes the row directly (the CLI cannot
	// reach the run-proc's Exporter — Option A: SQLite queue with
	// 1s drain cadence per the spec).
	_, err := st.AddPendingAuditEvent(
		store.PendingAuditEventAdminAction,
		`{"action":"rules.add","actor":"alice","resource_type":"rule",`+
			`"resource_id":"42","result":"success","dialects":["mysql"],`+
			`"details":{"pattern":"SELECT:mysql.app_db.*","effect":"allow"}}`)
	require.NoError(t, err)

	srv.drainPendingAuditEventsOnce()

	got := expSnapshot()
	var adminEvents []audit.Event
	for _, e := range got {
		if e.ActivityName == "admin_action" {
			adminEvents = append(adminEvents, e)
		}
	}
	require.Len(t, adminEvents, 1,
		"poller MUST drain ADMIN_ACTION row + emit exactly one synthetic")
	evt := adminEvents[0]
	require.NotNil(t, evt.Unmapped)
	assert.Equal(t, string(audit.EventTypeAdminAction),
		evt.Unmapped.IAMJIT.EventType)
	cc, ok := evt.Unmapped.IAMJIT.Ext["config_change"].(map[string]any)
	require.True(t, ok,
		"ext.config_change MUST survive cross-process round-trip "+
			"(SQLite payload → poller → audit.NewAdminActionEvent → JSONL)")
	assert.Equal(t, "rules.add", cc["action"])
	assert.Equal(t, "alice", cc["actor"])
	assert.Equal(t, "rule", cc["resource_type"])
	assert.Equal(t, "42", cc["resource_id"])
	dialects, ok := cc["dialects"].([]any)
	require.True(t, ok,
		"per-dialect note: config_change.dialects MUST be present + "+
			"slice-shaped per the spec")
	require.Len(t, dialects, 1)
	assert.Equal(t, "mysql", dialects[0])
	details, ok := cc["details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "SELECT:mysql.app_db.*", details["pattern"])

	// After drain, depth must be zero (idempotent: the queue's
	// SELECT+DELETE inside one txn rules out double-emission).
	depth, err := st.PendingAuditEventDepth()
	require.NoError(t, err)
	assert.Equal(t, 0, depth, "drained rows must be deleted in-txn")
}

// TestPoller_DrainsAdminAction_DialectAgnostic verifies the per-
// dialect note's flip side: when the admin action carries no dialect
// signal (e.g. pause.start, or a cross-dialect rule with table-glob
// "public.*"), config_change.dialects MUST be ABSENT on the wire so
// SIEM dashboards that filter "where dialects is set" don't false-
// positive on dialect-agnostic actions.
func TestPoller_DrainsAdminAction_DialectAgnostic(t *testing.T) {
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyDeny, false)
	exp, expSnapshot := captureExporter(t)
	srv.SetAuditExporter(exp)

	_, err := st.AddPendingAuditEvent(
		store.PendingAuditEventAdminAction,
		`{"action":"pause.start","actor":"bob","resource_type":"pause",`+
			`"resource_id":"7","result":"success",`+
			`"details":{"ttl_seconds":1800,"reason":"live demo"}}`)
	require.NoError(t, err)

	srv.drainPendingAuditEventsOnce()
	got := expSnapshot()
	var adminEvents []audit.Event
	for _, e := range got {
		if e.ActivityName == "admin_action" {
			adminEvents = append(adminEvents, e)
		}
	}
	require.Len(t, adminEvents, 1)
	cc, ok := adminEvents[0].Unmapped.IAMJIT.Ext["config_change"].(map[string]any)
	require.True(t, ok)
	_, hasDialects := cc["dialects"]
	assert.False(t, hasDialects,
		"config_change.dialects MUST be omitted for dialect-agnostic "+
			"actions like pause.start")
	// Sanity: the details DID survive the round-trip.
	details, ok := cc["details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "live demo", details["reason"])
}

// TestPoller_DrainsMultipleRowsInOrder verifies the drain ordering
// invariant: rows MUST be emitted in id-ASC order so a SIEM consumer
// sees lifecycle events in the same sequence the originating CLI
// processes wrote them.
func TestPoller_DrainsMultipleRowsInOrder(t *testing.T) {
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyDeny, false)
	exp, expSnapshot := captureExporter(t)
	srv.SetAuditExporter(exp)

	// Enqueue three rows of different kinds.
	_, err := st.AddPendingAuditEvent(
		store.PendingAuditEventAdminFallbackEnd,
		`{"pause_id":1,"end_kind":"manual"}`)
	require.NoError(t, err)
	_, err = st.AddPendingAuditEvent(
		store.PendingAuditEventProfileInstalled,
		`{"source_url":"https://x/a.yaml","profile_names":["a"]}`)
	require.NoError(t, err)
	_, err = st.AddPendingAuditEvent(
		store.PendingAuditEventAdminFallbackEnd,
		`{"pause_id":2,"end_kind":"expired"}`)
	require.NoError(t, err)

	srv.drainPendingAuditEventsOnce()

	got := expSnapshot()
	var lifecycle []audit.Event
	for _, e := range got {
		if e.ActivityName == "admin_fallback_end" ||
			e.ActivityName == "profile_installed" {
			lifecycle = append(lifecycle, e)
		}
	}
	require.Len(t, lifecycle, 3, "all three drained rows must surface as lifecycle events")
	// Order: end-1, profile, end-2 (id-ASC).
	assert.Equal(t, "admin_fallback_end", lifecycle[0].ActivityName)
	assert.Equal(t, "profile_installed", lifecycle[1].ActivityName)
	assert.Equal(t, "admin_fallback_end", lifecycle[2].ActivityName)
}

// TestPoller_UnknownKindDropsCleanly verifies the forward-compat
// guarantee: a future schema-additive kind that the current binary
// doesn't recognize is logged + dropped, not panicking.
func TestPoller_UnknownKindDropsCleanly(t *testing.T) {
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyDeny, false)
	exp, expSnapshot := captureExporter(t)
	srv.SetAuditExporter(exp)

	_, err := st.AddPendingAuditEvent("future_kind_we_dont_know", `{}`)
	require.NoError(t, err)

	require.NotPanics(t, func() {
		srv.drainPendingAuditEventsOnce()
	})
	// Row was dropped (not re-enqueued).
	depth, err := st.PendingAuditEventDepth()
	require.NoError(t, err)
	assert.Equal(t, 0, depth)
	// Nothing emitted for the unknown kind.
	for _, e := range expSnapshot() {
		assert.NotContains(t, e.ActivityName, "future_kind",
			"unknown kinds MUST be dropped, never emitted as-is")
	}
}

// TestPoller_NoCrashOnEmptyQueue is a sanity check: the polling
// goroutine MUST tolerate empty drains (the typical steady state).
func TestPoller_NoCrashOnEmptyQueue(t *testing.T) {
	srv, _ := newPausePromptServer(t, ModeTransparent, DefaultPolicyDeny, false)
	exp, _ := captureExporter(t)
	srv.SetAuditExporter(exp)
	require.NotPanics(t, func() {
		srv.drainPendingAuditEventsOnce()
	})
}

// TestPoller_Goroutine_StartsAndStops verifies the runPendingAuditEventsPoller
// lifecycle: the poller starts as part of Serve + stops cleanly on
// Shutdown. Per [[deliberate-feature-completion]] the goroutine MUST
// join via connWG without deadlocking — this matches the burst
// sweeper + heartbeater shutdown-ordering pattern.
func TestPoller_Goroutine_StartsAndStops(t *testing.T) {
	srv, _, _, _ := startTestServer(t)
	// Give the poller a moment to start.
	time.Sleep(20 * time.Millisecond)
	// Shutdown returns within the deadline → both the burst sweeper +
	// the audit-events poller drained cleanly.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := srv.Shutdown(ctx)
	assert.NoError(t, err,
		"Shutdown must return cleanly — burst sweeper + audit-events "+
			"poller both join via connWG with the cancel-then-wait pattern")
}

// toInt64 normalizes a JSON-round-tripped number to int64. JSON
// numbers decode as float64; some tests use raw int64. This helper
// keeps the assertion-side typing uniform across both shapes.
func toInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case float64:
		return int64(t)
	case int:
		return int64(t)
	default:
		return 0
	}
}

// alerts_test.go — unit + race tests for the #252 Slice 2
// suspicious-activity rule engine.
//
// Per the spec: dbounce has the port-race fix (53d97d3) + the cross-
// process sync-prompt poll (d82ded9) + many concurrency-sensitive
// features. The RuleEngine MUST be race-clean; the
// TestRuleEngine_RaceClean test runs every Observe* surface
// concurrently + this file is invoked under `go test -race -count=10`
// in CI per the slice plan.
//
// Tests cover:
//
//   - per-dialect verb table (postgres / mysql / snowflake / bigquery)
//   - non_org_profile_install rule (with + without allowlist)
//   - unusual_high_risk_action rule (verb path + sensitive-schema DML)
//   - CALL allowlist semantics
//   - neutral SQL-shaped suggestion text (no "violation" / "abuse")
//   - SECURITY_ALERT envelope is OCSF-compliant (class 6003,
//     activity_id=99, severity_id>=3)
//   - JSON round-trip safety (event from a marshaled+unmarshaled wire
//     event still matches the rule)
//   - the engine does NOT recurse on its own emitted alerts
//   - nil-safety of the public surface
//   - Enabled() short-circuit when no emit sink wired
//   - SetExporter wires + nil-detaches without race

package audit

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/store"
)

// captureEmit returns a thread-safe emit closure + a snapshot getter
// that returns the captured events. Used in place of the live
// Exporter so tests assert per-event payload contents without spinning
// up disk/IO transports.
func captureEmit() (func(context.Context, Event) error, func() []Event) {
	var (
		mu     sync.Mutex
		events []Event
	)
	emit := func(_ context.Context, evt Event) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, evt)
		return nil
	}
	snapshot := func() []Event {
		mu.Lock()
		defer mu.Unlock()
		out := make([]Event, len(events))
		copy(out, events)
		return out
	}
	return emit, snapshot
}

// newTestEngine builds an engine wired to a capture sink. Useful for
// every test that doesn't want to construct a full LogWriter +
// WebhookPusher pipeline.
func newTestEngine(t *testing.T, opts RuleEngineOptions) (*RuleEngine, func() []Event) {
	t.Helper()
	emit, snapshot := captureEmit()
	opts.emit = emit
	return NewRuleEngine(opts), snapshot
}

// decisionEvent is a thin wrapper around FromDecisionRow that pre-fills
// the dialect + statement_type fields most tests vary.
func decisionEvent(dialect, stmtType, verdict string, tables []string) Event {
	return FromDecisionRow(store.DecisionRow{
		Dialect:         dialect,
		StatementType:   stmtType,
		DecisionVerdict: verdict,
		ModeAtDecision:  "cooperative",
		TablesTouched:   tables,
		IsDML:           stmtType == "INSERT" || stmtType == "UPDATE" || stmtType == "DELETE" || stmtType == "MERGE",
		IsDDL:           stmtType == "DROP" || stmtType == "TRUNCATE" || stmtType == "ALTER",
	}, 1, "127.0.0.1:5433", "")
}

// TestHighRiskVerbsForDialect locks the per-dialect verb table the
// rule engine fires on. The exact UPPERCASE strings are PART OF THE
// CONTRACT — downstream SIEM rules + cross-product correlation keys
// depend on them. Sibling agents in ibounce + kbounce ship the SAME
// names for the cross-dialect verbs.
func TestHighRiskVerbsForDialect(t *testing.T) {
	cases := []struct {
		dialect string
		want    []string
	}{
		{
			dialect: "postgres",
			want:    []string{"ALTER", "CALL", "DROP", "EXECUTE", "GRANT", "REVOKE", "TRUNCATE"},
		},
		{
			dialect: "mysql",
			want:    []string{"ALTER", "CALL", "DROP", "EXECUTE", "GRANT", "REVOKE", "TRUNCATE"},
		},
		{
			dialect: "snowflake",
			want:    []string{"ALTER", "CALL", "COPY_INTO", "DROP", "EXECUTE", "EXPORT_DATA", "GRANT", "REVOKE", "TRUNCATE", "UNDROP"},
		},
		{
			dialect: "bigquery",
			want:    []string{"ALTER", "CALL", "COPY_INTO", "DROP", "EXECUTE", "EXPORT_DATA", "GRANT", "REVOKE", "TRUNCATE"},
		},
		{
			dialect: "unknown",
			want:    nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.dialect, func(t *testing.T) {
			got := HighRiskVerbsForDialect(tc.dialect)
			assert.Equal(t, tc.want, got,
				"per-dialect high-risk verb set MUST match the spec — "+
					"sibling agents in ibounce/kbounce ship the SAME set + "+
					"downstream SIEM rules depend on the exact UPPERCASE strings")
		})
	}
}

// TestRuleEngine_ObserveDecision_HighRiskVerb fires the verb path for
// every supported dialect + verb. Confirms the alert is emitted with
// the OCSF SECURITY_ALERT envelope + neutral suggestion text.
func TestRuleEngine_ObserveDecision_HighRiskVerb(t *testing.T) {
	cases := []struct {
		name     string
		dialect  string
		stmtType string
		tables   []string
	}{
		{"pg-drop-table", "postgres", "DROP", []string{"public.users"}},
		{"pg-truncate", "postgres", "TRUNCATE", []string{"public.users"}},
		{"pg-grant", "postgres", "GRANT", nil},
		{"mysql-drop", "mysql", "DROP", []string{"app.orders"}},
		{"snowflake-export-data", "snowflake", "EXPORT_DATA", []string{"analytics.events"}},
		{"snowflake-copy-into", "snowflake", "COPY_INTO", []string{"analytics.events"}},
		{"snowflake-undrop", "snowflake", "UNDROP", nil},
		{"bigquery-export-data", "bigquery", "EXPORT_DATA", []string{"analytics.events"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, snapshot := newTestEngine(t, RuleEngineOptions{
				Host: "127.0.0.1:5433",
			})
			evt := decisionEvent(tc.dialect, tc.stmtType, "ALLOW", tc.tables)
			engine.ObserveDecision(context.Background(), evt)

			events := snapshot()
			require.Len(t, events, 1, "exactly one alert should fire")
			alert := events[0]

			// OCSF envelope.
			assert.Equal(t, 6003, alert.ClassUID)
			assert.Equal(t, ActivityIDOther, alert.ActivityID)
			assert.Equal(t, string(AlertRuleUnusualHighRiskAction), alert.ActivityName)
			assert.Equal(t, ocsfTypeUIDBase+ActivityIDOther, alert.TypeUID)
			assert.Equal(t, ocsfSeverityMediumID, alert.SeverityID)
			assert.Equal(t, ocsfSeverityMedium, alert.Severity)
			assert.Equal(t, StatusIDOther, alert.StatusID)

			// unmapped.iam_jit.event_type marks this as SECURITY_ALERT.
			require.NotNil(t, alert.Unmapped)
			assert.Equal(t, string(EventTypeSecurityAlert), alert.Unmapped.IAMJIT.EventType)

			// rule_id + dialect + statement_type pinned into ext.
			ext := alert.Unmapped.IAMJIT.Ext
			require.NotNil(t, ext)
			assert.Equal(t, string(AlertRuleUnusualHighRiskAction), ext["rule_id"])
			assert.Equal(t, tc.dialect, ext["dialect"])
			assert.Equal(t, tc.stmtType, ext["statement_type"])
			assert.Equal(t, "verb", ext["matched_reason"])

			// Neutral language: NEVER use accusatory words. SQL-specific
			// suggestion text per the spec.
			detail := strings.ToLower(alert.StatusDetail)
			assert.NotContains(t, detail, "violation")
			assert.NotContains(t, detail, "unauthorized")
			assert.NotContains(t, detail, "attack")
			assert.NotContains(t, detail, "abuse")
			assert.Contains(t, detail, "consider distributing a profile",
				"SQL-specific suggestion text per the spec")
		})
	}
}

// TestRuleEngine_ObserveDecision_NoFireOnSafeVerbs confirms SELECT /
// INSERT / UPDATE / etc. do NOT fire the verb-path alert on any
// dialect.
func TestRuleEngine_ObserveDecision_NoFireOnSafeVerbs(t *testing.T) {
	cases := []struct {
		dialect  string
		stmtType string
	}{
		{"postgres", "SELECT"},
		{"postgres", "INSERT"},
		{"postgres", "UPDATE"},
		{"mysql", "SELECT"},
		{"snowflake", "SELECT"},
		{"bigquery", "INSERT"},
	}
	for _, tc := range cases {
		t.Run(tc.dialect+"-"+tc.stmtType, func(t *testing.T) {
			engine, snapshot := newTestEngine(t, RuleEngineOptions{Host: "127.0.0.1:5433"})
			evt := decisionEvent(tc.dialect, tc.stmtType, "ALLOW", []string{"public.users"})
			engine.ObserveDecision(context.Background(), evt)
			assert.Empty(t, snapshot(),
				"safe verb on standard table MUST NOT fire the alert")
		})
	}
}

// TestRuleEngine_ObserveDecision_SensitiveSchemaDML fires the
// second-path (DML against operator-configured sensitive schema).
func TestRuleEngine_ObserveDecision_SensitiveSchemaDML(t *testing.T) {
	engine, snapshot := newTestEngine(t, RuleEngineOptions{
		Host:             "127.0.0.1:5433",
		SensitiveSchemas: []string{"prod", "billing"},
	})

	// UPDATE against billing.invoices → fires (schema match).
	evt := decisionEvent("postgres", "UPDATE", "ALLOW", []string{"billing.invoices"})
	engine.ObserveDecision(context.Background(), evt)
	events := snapshot()
	require.Len(t, events, 1)
	alert := events[0]
	assert.Equal(t, "sensitive_schema", alert.Unmapped.IAMJIT.Ext["matched_reason"])
	assert.Equal(t, []string{"billing.invoices"}, normalizeStringSlice(alert.Unmapped.IAMJIT.Ext["matched_tables"]))
	detail := strings.ToLower(alert.StatusDetail)
	assert.Contains(t, detail, "sensitive-schema")
	assert.Contains(t, detail, "consider distributing a profile")
}

// TestRuleEngine_ObserveDecision_SensitiveSchemaIgnoredWhenUnset
// confirms an operator with no SensitiveSchemas configured DOES NOT
// get the DML-against-schema alert (the safe default — solo operators
// see only verb-based alerts).
func TestRuleEngine_ObserveDecision_SensitiveSchemaIgnoredWhenUnset(t *testing.T) {
	engine, snapshot := newTestEngine(t, RuleEngineOptions{Host: "127.0.0.1:5433"})
	evt := decisionEvent("postgres", "UPDATE", "ALLOW", []string{"billing.invoices"})
	engine.ObserveDecision(context.Background(), evt)
	assert.Empty(t, snapshot(),
		"UPDATE against billing.* with empty SensitiveSchemas MUST NOT fire")
}

// TestRuleEngine_CallAllowlist suppresses CALL/EXECUTE alerts when
// every named function is on the allowlist.
func TestRuleEngine_CallAllowlist(t *testing.T) {
	engine, snapshot := newTestEngine(t, RuleEngineOptions{
		Host:          "127.0.0.1:5433",
		CallAllowlist: []string{"audit_log_event", "refresh_materialized_view"},
	})

	// CALL audit_log_event() — allowlisted; no fire.
	row := store.DecisionRow{
		Dialect:         "postgres",
		StatementType:   "CALL",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
		FunctionsCalled: []string{"audit_log_event"},
	}
	engine.ObserveDecision(context.Background(), FromDecisionRow(row, 1, "127.0.0.1:5433", ""))
	assert.Empty(t, snapshot(), "allowlisted CALL must not fire")

	// CALL rotate_secrets() — NOT allowlisted; fires.
	row.FunctionsCalled = []string{"rotate_secrets"}
	engine.ObserveDecision(context.Background(), FromDecisionRow(row, 2, "127.0.0.1:5433", ""))
	require.Len(t, snapshot(), 1, "un-allowlisted CALL must fire")
}

// TestRuleEngine_CallWithNoAllowlistAlwaysFires confirms the safe-
// default: when no CallAllowlist is configured, every CALL/EXECUTE
// fires the alert (so a solo operator doesn't silently miss stored-
// proc activity).
func TestRuleEngine_CallWithNoAllowlistAlwaysFires(t *testing.T) {
	engine, snapshot := newTestEngine(t, RuleEngineOptions{Host: "127.0.0.1:5433"})
	row := store.DecisionRow{
		Dialect:         "postgres",
		StatementType:   "CALL",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
		FunctionsCalled: []string{"audit_log_event"},
	}
	engine.ObserveDecision(context.Background(), FromDecisionRow(row, 1, "127.0.0.1:5433", ""))
	require.Len(t, snapshot(), 1)
}

// TestRuleEngine_ObserveProfileInstall_NonOrg fires the
// non_org_profile_install rule when no allowlist is configured (every
// install is "non-org" from a solo-operator's POV).
func TestRuleEngine_ObserveProfileInstall_NonOrg(t *testing.T) {
	engine, snapshot := newTestEngine(t, RuleEngineOptions{Host: "127.0.0.1:5433"})
	engine.ObserveProfileInstall(context.Background(), InstallObservation{
		SourceURL:      "https://gist.githubusercontent.com/random/profiles.yaml",
		ProfileNames:   []string{"weekend-debug"},
		SHA256:         "abc123",
		SHA256Verified: false,
	})

	events := snapshot()
	require.Len(t, events, 1)
	alert := events[0]

	assert.Equal(t, string(AlertRuleNonOrgProfileInstall), alert.ActivityName)
	assert.Equal(t, ocsfSeverityMediumID, alert.SeverityID)

	ext := alert.Unmapped.IAMJIT.Ext
	require.NotNil(t, ext)
	assert.Equal(t, "https://gist.githubusercontent.com/random/profiles.yaml", ext["source_url"])
	assert.Equal(t, []string{"weekend-debug"}, normalizeStringSlice(ext["profile_names"]))
	assert.Equal(t, "abc123", ext["sha256"])
	assert.Equal(t, false, ext["sha256_verified"])

	detail := strings.ToLower(alert.StatusDetail)
	assert.Contains(t, detail, "non-org source")
	assert.Contains(t, detail, "configure --audit-alert-org-source-prefix",
		"empty allowlist suggestion text should point operator at the config flag")
	assert.NotContains(t, detail, "violation")
}

// TestRuleEngine_ObserveProfileInstall_OrgSourceSuppresses confirms a
// configured allowlist prefix matches + suppresses the alert.
func TestRuleEngine_ObserveProfileInstall_OrgSourceSuppresses(t *testing.T) {
	engine, snapshot := newTestEngine(t, RuleEngineOptions{
		Host:                      "127.0.0.1:5433",
		OrgProfileSourceAllowlist: []string{"https://internal.example.com/profiles/"},
	})

	// Org-source install — no alert.
	engine.ObserveProfileInstall(context.Background(), InstallObservation{
		SourceURL:    "https://internal.example.com/profiles/safe-default.yaml",
		ProfileNames: []string{"safe-default"},
	})
	assert.Empty(t, snapshot(), "org-source install must not fire alert")

	// Non-org install — alert with allowlist suggestion text.
	engine.ObserveProfileInstall(context.Background(), InstallObservation{
		SourceURL:    "https://gist.github.com/random/sneaky.yaml",
		ProfileNames: []string{"weekend-debug"},
	})
	events := snapshot()
	require.Len(t, events, 1)
	detail := strings.ToLower(events[0].StatusDetail)
	assert.Contains(t, detail, "consider distributing org-curated profiles",
		"allowlist-configured suggestion text should point operator at org distribution")

	ext := events[0].Unmapped.IAMJIT.Ext
	allowlist := normalizeStringSlice(ext["org_source_allowlist"])
	assert.Equal(t, []string{"https://internal.example.com/profiles/"}, allowlist,
		"alert ext MUST surface the operator-configured allowlist for context")
}

// TestRuleEngine_OrgSourceMatchCaseInsensitive confirms the URL
// prefix match is case-insensitive (Windows operators may type
// HTTPS://INTERNAL.EXAMPLE.COM/...).
func TestRuleEngine_OrgSourceMatchCaseInsensitive(t *testing.T) {
	engine, snapshot := newTestEngine(t, RuleEngineOptions{
		Host:                      "127.0.0.1:5433",
		OrgProfileSourceAllowlist: []string{"HTTPS://INTERNAL.example.com/"},
	})
	engine.ObserveProfileInstall(context.Background(), InstallObservation{
		SourceURL:    "https://internal.example.com/profiles/safe.yaml",
		ProfileNames: []string{"safe"},
	})
	assert.Empty(t, snapshot())
}

// TestRuleEngine_DisabledShortCircuit confirms a Disabled engine does
// NO observation work + emits NO alerts.
func TestRuleEngine_DisabledShortCircuit(t *testing.T) {
	engine, snapshot := newTestEngine(t, RuleEngineOptions{
		Disabled: true,
		Host:     "127.0.0.1:5433",
	})
	engine.ObserveDecision(context.Background(),
		decisionEvent("postgres", "DROP", "ALLOW", []string{"public.users"}))
	engine.ObserveProfileInstall(context.Background(), InstallObservation{
		SourceURL: "https://random.example/x.yaml",
	})
	assert.Empty(t, snapshot())

	stats := engine.Stats()
	assert.Zero(t, stats.ObservedDecisions, "Disabled engine MUST NOT increment counters")
	assert.Zero(t, stats.ObservedInstalls)
}

// TestRuleEngine_NoEmitNoObservation confirms an engine with no emit
// sink wired (production state between NewRuleEngine + SetExporter)
// short-circuits cleanly — no panic, no counter bumps.
func TestRuleEngine_NoEmitNoObservation(t *testing.T) {
	e := NewRuleEngine(RuleEngineOptions{Host: "127.0.0.1:5433"})
	require.False(t, e.Enabled(), "no emit wired → not Enabled")
	e.ObserveDecision(context.Background(),
		decisionEvent("postgres", "DROP", "ALLOW", []string{"public.users"}))
	e.ObserveProfileInstall(context.Background(), InstallObservation{SourceURL: "x"})
	assert.Zero(t, e.Stats().ObservedDecisions)
}

// TestRuleEngine_SetExporterWiresAndDetaches confirms SetExporter
// installs the live exporter's emit + setting nil cleanly detaches.
func TestRuleEngine_SetExporterWiresAndDetaches(t *testing.T) {
	// Build a Log-only exporter to avoid HTTPS plumbing.
	dir := t.TempDir()
	lw, err := NewLogWriter(LogOptions{Path: dir + "/audit.jsonl"})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = lw.Shutdown(context.Background())
	})
	exp := NewExporter(lw, nil, "127.0.0.1:5433", "")

	engine := NewRuleEngine(RuleEngineOptions{Host: "127.0.0.1:5433"})
	require.False(t, engine.Enabled())

	engine.SetExporter(exp)
	require.True(t, engine.Enabled())

	engine.ObserveDecision(context.Background(),
		decisionEvent("postgres", "DROP", "ALLOW", []string{"public.users"}))
	require.NoError(t, lw.Shutdown(context.Background()))

	// Detach.
	engine.SetExporter(nil)
	require.False(t, engine.Enabled())
}

// TestRuleEngine_DoesNotRecurseOnOwnAlerts confirms the engine does
// NOT re-fire when handed back a SECURITY_ALERT or AUDIT_DROPPED
// event. This invariant prevents infinite loops if a future hook
// pipes the exporter's emit stream back through ObserveDecision.
func TestRuleEngine_DoesNotRecurseOnOwnAlerts(t *testing.T) {
	engine, snapshot := newTestEngine(t, RuleEngineOptions{Host: "127.0.0.1:5433"})

	// Synthesize a SECURITY_ALERT + feed it back through Observe.
	alert := NewSecurityAlertEvent(AlertRuleUnusualHighRiskAction,
		AlertSeverityMedium, "127.0.0.1:5433", "test", nil)
	engine.ObserveDecision(context.Background(), alert)

	// Synthesize an AUDIT_DROPPED + feed it back.
	dropped := NewAuditDroppedEvent(7, "127.0.0.1:5433")
	engine.ObserveDecision(context.Background(), dropped)

	assert.Empty(t, snapshot(),
		"engine MUST NOT fire on its own alert / synthetic events")
}

// TestRuleEngine_JSONRoundTripStillMatches confirms that an event
// which transited JSON marshaling+unmarshaling (e.g. a SIEM that
// re-ingests events) still triggers the matcher. The ext map's typed
// []string becomes []any after unmarshal — normalizeStringSlice
// handles both shapes.
func TestRuleEngine_JSONRoundTripStillMatches(t *testing.T) {
	engine, snapshot := newTestEngine(t, RuleEngineOptions{Host: "127.0.0.1:5433"})
	orig := decisionEvent("snowflake", "EXPORT_DATA", "ALLOW", []string{"analytics.events"})
	raw, err := json.Marshal(orig)
	require.NoError(t, err)
	var roundtripped Event
	require.NoError(t, json.Unmarshal(raw, &roundtripped))

	engine.ObserveDecision(context.Background(), roundtripped)
	require.Len(t, snapshot(), 1,
		"JSON-round-tripped event MUST still match the matcher (ext []string → []any unwrap)")
}

// TestRuleEngine_NilSafety pins the public surface against nil-
// dereference panics. The proxy calls Observe* unconditionally — a
// nil engine MUST be a no-op.
func TestRuleEngine_NilSafety(t *testing.T) {
	var e *RuleEngine
	assert.NotPanics(t, func() {
		e.SetExporter(nil)
		_ = e.Enabled()
		e.ObserveDecision(context.Background(), Event{})
		e.ObserveProfileInstall(context.Background(), InstallObservation{})
		_ = e.Stats()
	})
}

// TestRuleEngine_RaceClean exercises every Observe* surface from many
// concurrent goroutines. Per the spec: `go test -race -count=10` MUST
// stay clean on this test file. The test fans out 50 goroutines each
// issuing 200 mixed Observe calls + SetExporter swaps in flight.
//
// We use a counter sink (not a slice) so the sink itself can't race
// (the alerts.go RuleEngine MUST handle the race; the test must not
// hide it).
func TestRuleEngine_RaceClean(t *testing.T) {
	// We deliberately use a closure-free emit that mutates NO shared
	// state — the engine's own atomics + emit mutex are the race
	// targets. A counter sink would itself need to be race-safe; using
	// no-op keeps the test focused on the engine's race behavior.
	emitNoOp := func(_ context.Context, _ Event) error { return nil }

	engine := NewRuleEngine(RuleEngineOptions{
		Host:                      "127.0.0.1:5433",
		OrgProfileSourceAllowlist: []string{"https://internal.example/"},
		SensitiveSchemas:          []string{"billing", "prod"},
		CallAllowlist:             []string{"audit_log_event"},
		emit:                      emitNoOp,
	})

	const goroutines = 50
	const perG = 200
	events := []Event{
		decisionEvent("postgres", "DROP", "ALLOW", []string{"public.users"}),
		decisionEvent("snowflake", "EXPORT_DATA", "ALLOW", []string{"analytics.events"}),
		decisionEvent("postgres", "SELECT", "ALLOW", []string{"public.users"}),
		decisionEvent("postgres", "UPDATE", "ALLOW", []string{"billing.invoices"}),
		decisionEvent("postgres", "UPDATE", "ALLOW", []string{"public.users"}),
	}

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				engine.ObserveDecision(context.Background(), events[(seed+i)%len(events)])
				if i%17 == 0 {
					engine.ObserveProfileInstall(context.Background(),
						InstallObservation{
							SourceURL:    "https://random.example/x.yaml",
							ProfileNames: []string{"x"},
						})
				}
			}
		}(g)
	}
	// SetExporter swaps in flight to exercise the emitMu — we use a
	// thread-safe in-process emit closure (NOT a real LogWriter
	// whose channel-close races against an in-flight write). The
	// engine MUST handle a concurrent SetExporter swap; the test
	// MUST NOT artificially race the sink's own shutdown semantics
	// (the LogWriter spec explicitly forbids Write-after-Shutdown).
	swapEmit := func() func(context.Context, Event) error {
		return func(_ context.Context, _ Event) error { return nil }
	}
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				engine.emitMu.Lock()
				engine.emit = swapEmit()
				engine.emitMu.Unlock()
				// Periodically detach + reattach via the public API
				// so SetExporter's own locking path is exercised.
				if i%5 == 0 {
					engine.SetExporter(nil)
				}
			}
		}()
	}
	wg.Wait()

	// Sanity: the engine observed at least SOME of the decisions
	// (the exact total depends on how many fell into a detached-emit
	// window — those Enabled()==false calls short-circuit BEFORE the
	// counter bump). The point of this test is the race detector, not
	// a precise observation count; we assert only that the engine
	// made forward progress + didn't deadlock.
	stats := engine.Stats()
	assert.Greater(t, stats.ObservedDecisions, int64(0),
		"engine should have observed at least some decisions while emit was wired")
}

// TestRuleEngine_StatsShape locks the JSON-serializable Stats shape
// so the dbounce_audit_export_status MCP tool's downstream consumers
// (operators reading the JSON) don't break on a field-rename.
func TestRuleEngine_StatsShape(t *testing.T) {
	engine, _ := newTestEngine(t, RuleEngineOptions{
		Host:                      "127.0.0.1:5433",
		OrgProfileSourceAllowlist: []string{"https://internal.example/"},
		SensitiveSchemas:          []string{"prod"},
		CallAllowlist:             []string{"audit_log_event"},
	})
	stats := engine.Stats()
	raw, err := json.Marshal(stats)
	require.NoError(t, err)
	got := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &got))
	for _, k := range []string{
		"configured", "disabled",
		"observed_decisions", "observed_installs",
		"fired_non_org_profile_install", "fired_unusual_high_risk_action",
		"org_prefix_count", "sensitive_schema_count", "call_allowlist_size",
		"host",
	} {
		_, ok := got[k]
		assert.True(t, ok, "stats JSON must include %q", k)
	}
}

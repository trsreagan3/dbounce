// detector_test.go exercises the Phase H behavioral-deviation core
// (#718 ADOPT-4). BYTE-IDENTICAL across gbounce / kbouncer / dbounce
// per [[config-export-wire-divergence]] — the core is protocol-
// agnostic so its tests are too.
//
// Coverage:
//   - baseline-then-deviation FIRES (volume spike + off-hours)
//   - normal traffic does NOT fire
//   - the emitted event is NEUTRAL (no accusatory language) + OCSF-shaped
//   - default mode is ALERT, NOT block (request decision unchanged)
//   - the /healthz + query status surface reports honest state
package anomaly

import (
	"strings"
	"testing"
	"time"
)

// fixedClock returns a clock function pinned at the given unix second.
func fixedClock(unix int64) func() time.Time {
	return func() time.Time { return time.Unix(unix, 0).UTC() }
}

func mediumEnabledConfig() Config {
	c := DefaultConfig()
	c.Enabled = true
	c.Mode = "alert"
	c.Sensitivity = "medium"
	c.MinActionsForBaseline = 5
	return c
}

// TestBaselineThenDeviationFires establishes a baseline of normal
// daytime traffic then injects an off-hours volume spike + asserts the
// detector flags it.
func TestBaselineThenDeviationFires(t *testing.T) {
	cfg := mediumEnabledConfig()
	// 10am UTC on a fixed day.
	base := int64(1_700_000_000) // some fixed instant
	baseHour := time.Unix(base, 0).UTC().Hour()
	store := NewBaselineStore(cfg.BaselineWindowSeconds, cfg.BaselineDecayRate)
	store.withClock(fixedClock(base))

	// Establish a baseline: many same-hour observations.
	for i := 0; i < 40; i++ {
		store.Observe("agent-a", "GET", "arn:aws:s3:::prod-bucket/obj", base-int64(i*60))
	}
	summary := store.SummaryFor("agent-a", "GET", "arn:aws:s3:::prod-bucket/obj", base)
	if summary.TotalObservationsRolling < cfg.MinActionsForBaseline {
		t.Fatalf("baseline too small: %d", summary.TotalObservationsRolling)
	}

	// Inject a deviation: an off-hours observation far from the baseline
	// hour, AND a volume spike (observed count >> baseline mean).
	devHour := (baseHour + 12) % 24
	in := NewScoreInput("GET", "agent-a", "arn:aws:s3:::prod-bucket/obj")
	in.ObservedHour = devHour
	in.ObservedActionCount = 10000 // huge spike vs the per-hour baseline mean
	res := ScoreAnomaly(in, summary, cfg)
	if res.Verdict != VerdictAnomalous {
		t.Fatalf("expected anomalous verdict, got %q (score=%.3f)", res.Verdict, res.AnomalyScore)
	}
	// At least one dimension must be flagged as contributing.
	any := false
	for _, e := range res.Explanations {
		if e.Contributing {
			any = true
		}
	}
	if !any {
		t.Fatalf("expected at least one contributing dimension; explanations=%+v", res.Explanations)
	}
}

// TestNormalTrafficDoesNotFire asserts that a request matching the
// established baseline scores normal.
func TestNormalTrafficDoesNotFire(t *testing.T) {
	cfg := mediumEnabledConfig()
	base := int64(1_700_000_000)
	baseHour := time.Unix(base, 0).UTC().Hour()
	store := NewBaselineStore(cfg.BaselineWindowSeconds, cfg.BaselineDecayRate)
	store.withClock(fixedClock(base))
	for i := 0; i < 40; i++ {
		store.Observe("agent-b", "GET", "arn:aws:s3:::prod-bucket/obj", base-int64(i*60))
	}
	summary := store.SummaryFor("agent-b", "GET", "arn:aws:s3:::prod-bucket/obj", base)

	in := NewScoreInput("GET", "agent-b", "arn:aws:s3:::prod-bucket/obj")
	in.ObservedHour = baseHour                                           // same hour as baseline
	in.ObservedActionCount = summary.Dimensions["action_frequency"].Mean // on the mean
	res := ScoreAnomaly(in, summary, cfg)
	if res.Verdict == VerdictAnomalous {
		t.Fatalf("expected non-anomalous verdict for normal traffic, got anomalous (score=%.3f)", res.AnomalyScore)
	}
}

// TestColdStartInsufficientData asserts that a tiny baseline + a benign
// action yields insufficient_data rather than a false-positive anomaly.
func TestColdStartInsufficientData(t *testing.T) {
	cfg := mediumEnabledConfig()
	base := int64(1_700_000_000)
	store := NewBaselineStore(cfg.BaselineWindowSeconds, cfg.BaselineDecayRate)
	store.withClock(fixedClock(base))
	store.Observe("agent-c", "GET", "arn:aws:s3:::prod-bucket/obj", base)
	summary := store.SummaryFor("agent-c", "GET", "arn:aws:s3:::prod-bucket/obj", base)
	in := NewScoreInput("GET", "agent-c", "arn:aws:s3:::prod-bucket/obj")
	res := ScoreAnomaly(in, summary, cfg)
	if res.Verdict != VerdictInsufficientData {
		t.Fatalf("expected insufficient_data on cold start, got %q", res.Verdict)
	}
}

// TestColdStartBackstopFires asserts the self-contained adversarial
// backstop flags a known-sensitive action even with no baseline.
func TestColdStartBackstopFires(t *testing.T) {
	cfg := mediumEnabledConfig()
	base := int64(1_700_000_000)
	store := NewBaselineStore(cfg.BaselineWindowSeconds, cfg.BaselineDecayRate)
	store.withClock(fixedClock(base))
	summary := store.SummaryFor("agent-d", "cloudtrail:DeleteTrail", "*", base)
	in := NewScoreInput("cloudtrail:DeleteTrail", "agent-d", "*")
	res := ScoreAnomaly(in, summary, cfg)
	if res.Verdict != VerdictAnomalous {
		t.Fatalf("expected backstop to flag a known-adversarial action, got %q", res.Verdict)
	}
	if !res.ColdStartFallbackUsed {
		t.Fatalf("expected cold_start_fallback_used=true")
	}
}

// TestDefaultModeAlertsNotBlocks asserts a fresh Detector in the
// default (alert) mode leaves the floor decision unchanged on an
// anomalous verdict.
func TestDefaultModeAlertsNotBlocks(t *testing.T) {
	cfg := mediumEnabledConfig() // mode=alert
	var captured map[string]any
	d := NewDetector(cfg, func(ev map[string]any) { captured = ev }, false)
	d.Store().withClock(fixedClock(1_700_000_000))
	// Prime a baseline so the next call can be judged.
	for i := 0; i < 40; i++ {
		d.Store().Observe("agent-e", "GET", "arn:aws:s3:::prod-bucket/obj", 1_700_000_000-int64(i*60))
	}
	out := d.Run(RunInput{
		Action:              "GET",
		AgentIdentity:       "agent-e",
		Resource:            "arn:aws:s3:::prod-bucket/obj",
		ObservedHour:        (time.Unix(1_700_000_000, 0).UTC().Hour() + 12) % 24,
		ObservedActionCount: 10000,
		FloorDecision:       "allow",
		RecordObservation:   true,
	})
	if out.Decision != "allow" {
		t.Fatalf("alert mode must NOT change the decision; got %q", out.Decision)
	}
	if !out.EmittedAlert || captured == nil {
		t.Fatalf("expected a neutral alert to be emitted in alert mode")
	}
}

// primeSpike establishes a baseline + a recent burst on the store so a
// subsequent Decide/scoreLive call scores the (agent, action, resource)
// as an anomalous volume spike. Returns the detector ready to Decide.
func primeSpike(t *testing.T, cfg Config, agent string) *Detector {
	t.Helper()
	d := NewDetector(cfg, func(map[string]any) {}, false)
	base := int64(1_700_000_000)
	d.Store().withClock(fixedClock(base))
	// Establish a baseline of steady same-hour traffic.
	for i := 0; i < 40; i++ {
		d.Store().Observe(agent, "GET", "arn:aws:s3:::prod-bucket/obj", base-int64(i*60))
	}
	// A sharp recent burst so the recent-window rate spikes far above the
	// learned per-hour mean (scoreLive derives this rate from the store).
	for i := 0; i < 300; i++ {
		d.Store().Observe(agent, "GET", "arn:aws:s3:::prod-bucket/obj", base-int64(i))
	}
	return d
}

// TestBlockModeEnforcesViaPreDecision asserts block-mode ENFORCEMENT
// through the core Decide path (iam-jit#59): an anomalous request on an
// allow floor is TIGHTENED to deny + a high-severity event is emitted.
// (The full live-decision-path proof lives in the per-repo proxy wire
// test; this exercises the shared tighten logic.)
func TestBlockModeEnforcesViaPreDecision(t *testing.T) {
	cfg := mediumEnabledConfig()
	cfg.Mode = "block"
	var captured map[string]any
	d := NewDetector(cfg, func(ev map[string]any) { captured = ev }, false)
	base := int64(1_700_000_000)
	d.Store().withClock(fixedClock(base))
	for i := 0; i < 40; i++ {
		d.Store().Observe("agent-f", "GET", "arn:aws:s3:::prod-bucket/obj", base-int64(i*60))
	}
	for i := 0; i < 300; i++ {
		d.Store().Observe("agent-f", "GET", "arn:aws:s3:::prod-bucket/obj", base-int64(i))
	}
	out := d.Decide(DecideInput{
		Action:        "GET",
		AgentIdentity: "agent-f",
		Resource:      "arn:aws:s3:::prod-bucket/obj",
		FloorDecision: "allow",
	})
	// Block ENFORCES: allow is tightened to deny.
	if out.Decision != "deny" || !out.Tightened {
		t.Fatalf("block mode must TIGHTEN allow->deny on an anomalous request; got decision=%q tightened=%v", out.Decision, out.Tightened)
	}
	if !out.EmittedAlert || captured == nil {
		t.Fatalf("a block-mode deny must emit a high-severity event for the operator")
	}
	if out.Anomaly == nil || out.Anomaly.Verdict != VerdictAnomalous {
		t.Fatalf("expected an anomalous verdict; got %+v", out.Anomaly)
	}
	if sev, _ := captured["severity_id"].(int); sev != 4 {
		t.Fatalf("expected High (4) severity on the emitted event; got %v", captured["severity_id"])
	}
}

// TestDecideNeverLoosensDenyFloor is the TIGHTEN-ONLY proof: even with a
// wildly anomalous request, Decide must NEVER turn a deterministic deny
// floor into an allow. A deny stays a deny.
func TestDecideNeverLoosensDenyFloor(t *testing.T) {
	cfg := mediumEnabledConfig()
	cfg.Mode = "block"
	d := primeSpike(t, cfg, "agent-deny")
	out := d.Decide(DecideInput{
		Action:        "GET",
		AgentIdentity: "agent-deny",
		Resource:      "arn:aws:s3:::prod-bucket/obj",
		FloorDecision: "deny",
	})
	if out.Decision != "deny" {
		t.Fatalf("Decide must NEVER loosen a deny floor; got %q", out.Decision)
	}
	if out.Tightened {
		t.Fatalf("a deny floor cannot be 'tightened' (it is already maximally restrictive); got tightened=true")
	}
}

// TestDecideAlertModeNeverTightens asserts that in alert mode (the
// default) Decide is a pure pass-through even on an anomalous request:
// no allow->deny, no emit. Tightening is block-only.
func TestDecideAlertModeNeverTightens(t *testing.T) {
	cfg := mediumEnabledConfig() // mode=alert
	emitted := 0
	d := NewDetector(cfg, func(map[string]any) { emitted++ }, false)
	base := int64(1_700_000_000)
	d.Store().withClock(fixedClock(base))
	for i := 0; i < 40; i++ {
		d.Store().Observe("agent-al", "GET", "arn:aws:s3:::prod-bucket/obj", base-int64(i*60))
	}
	for i := 0; i < 300; i++ {
		d.Store().Observe("agent-al", "GET", "arn:aws:s3:::prod-bucket/obj", base-int64(i))
	}
	out := d.Decide(DecideInput{
		Action:        "GET",
		AgentIdentity: "agent-al",
		Resource:      "arn:aws:s3:::prod-bucket/obj",
		FloorDecision: "allow",
	})
	if out.Decision != "allow" || out.Tightened {
		t.Fatalf("alert mode Decide must pass allow through untouched; got decision=%q tightened=%v", out.Decision, out.Tightened)
	}
	if emitted != 0 {
		t.Fatalf("alert-mode Decide must not emit (alerting is the observe path's job); emitted=%d", emitted)
	}
}

// TestDecideDetectionOnlyNeverTightens asserts detection-only forces a
// pass-through in Decide even when cfg.Mode == block.
func TestDecideDetectionOnlyNeverTightens(t *testing.T) {
	cfg := mediumEnabledConfig()
	cfg.Mode = "block"
	d := NewDetector(cfg, func(map[string]any) {}, true) // detectionOnly
	base := int64(1_700_000_000)
	d.Store().withClock(fixedClock(base))
	for i := 0; i < 40; i++ {
		d.Store().Observe("agent-do", "GET", "arn:aws:s3:::prod-bucket/obj", base-int64(i*60))
	}
	for i := 0; i < 300; i++ {
		d.Store().Observe("agent-do", "GET", "arn:aws:s3:::prod-bucket/obj", base-int64(i))
	}
	out := d.Decide(DecideInput{
		Action:        "GET",
		AgentIdentity: "agent-do",
		Resource:      "arn:aws:s3:::prod-bucket/obj",
		FloorDecision: "allow",
	})
	if out.Decision != "allow" || out.Tightened {
		t.Fatalf("detection-only must never tighten; got decision=%q tightened=%v", out.Decision, out.Tightened)
	}
}

// TestDecideDisabledNoOp asserts a disabled detector's Decide is a
// pass-through (default-off preserved).
func TestDecideDisabledNoOp(t *testing.T) {
	cfg := DefaultConfig() // disabled
	d := NewDetector(cfg, func(map[string]any) { t.Fatal("disabled detector emitted from Decide") }, false)
	out := d.Decide(DecideInput{Action: "GET", AgentIdentity: "x", FloorDecision: "allow"})
	if out.Decision != "allow" || out.Tightened {
		t.Fatalf("disabled Decide must pass allow through; got decision=%q tightened=%v", out.Decision, out.Tightened)
	}
}

// TestDetectionOnlyNeverBlocks asserts detection-only forces alert
// behavior even when cfg.Mode == block.
func TestDetectionOnlyNeverBlocks(t *testing.T) {
	cfg := mediumEnabledConfig()
	cfg.Mode = "block"
	d := NewDetector(cfg, func(map[string]any) {}, true) // detectionOnly
	d.Store().withClock(fixedClock(1_700_000_000))
	for i := 0; i < 40; i++ {
		d.Store().Observe("agent-g", "GET", "arn:aws:s3:::prod-bucket/obj", 1_700_000_000-int64(i*60))
	}
	out := d.Run(RunInput{
		Action:              "GET",
		AgentIdentity:       "agent-g",
		Resource:            "arn:aws:s3:::prod-bucket/obj",
		ObservedHour:        (time.Unix(1_700_000_000, 0).UTC().Hour() + 12) % 24,
		ObservedActionCount: 10000,
		FloorDecision:       "allow",
		RecordObservation:   true,
	})
	if out.Decision != "allow" {
		t.Fatalf("detection-only must never block; got %q", out.Decision)
	}
}

// TestEmittedEventIsNeutralOCSF asserts the emitted event uses the OCSF
// class-6003 anomaly shape + carries NO accusatory language anywhere in
// its serialized strings, per [[ibounce-honest-positioning]].
func TestEmittedEventIsNeutralOCSF(t *testing.T) {
	SetProduct("bounce-test")
	cfg := mediumEnabledConfig()
	store := NewBaselineStore(cfg.BaselineWindowSeconds, cfg.BaselineDecayRate)
	store.withClock(fixedClock(1_700_000_000))
	for i := 0; i < 40; i++ {
		store.Observe("agent-h", "GET", "arn:aws:s3:::prod-bucket/obj", 1_700_000_000-int64(i*60))
	}
	summary := store.SummaryFor("agent-h", "GET", "arn:aws:s3:::prod-bucket/obj", 1_700_000_000)
	in := NewScoreInput("GET", "agent-h", "arn:aws:s3:::prod-bucket/obj")
	in.ObservedHour = (time.Unix(1_700_000_000, 0).UTC().Hour() + 12) % 24
	in.ObservedActionCount = 10000
	res := ScoreAnomaly(in, summary, cfg)
	ev := buildOCSFAnomalyEvent("GET", "arn:aws:s3:::prod-bucket/obj", "agent-h", res, "alert", false)

	if ev["class_uid"].(int) != 6003 {
		t.Fatalf("expected OCSF class_uid 6003, got %v", ev["class_uid"])
	}
	if ev["activity_name"].(string) != "anomaly_detected" {
		t.Fatalf("expected activity_name anomaly_detected, got %v", ev["activity_name"])
	}
	// Neutral-language scan across all string values.
	forbidden := []string{"violation", "infraction", "unauthorized", "malicious", "attack", "breach"}
	hay := strings.ToLower(stringifyAll(ev))
	for _, w := range forbidden {
		if strings.Contains(hay, w) {
			t.Fatalf("emitted event contains forbidden accusatory word %q: %s", w, hay)
		}
	}
	// Honest framing present.
	if !strings.Contains(hay, "signal for review") {
		t.Fatalf("expected honest 'signal for review' framing in the event")
	}
}

// TestStatusSurface asserts the detector reports honest status for the
// /healthz + query surface.
func TestStatusSurface(t *testing.T) {
	cfg := mediumEnabledConfig()
	d := NewDetector(cfg, func(map[string]any) {}, false)
	st := d.Status()
	if st["enabled"].(bool) != true {
		t.Fatalf("expected enabled=true in status")
	}
	if st["mode"].(string) != "alert" {
		t.Fatalf("expected mode=alert in status, got %v", st["mode"])
	}
	if _, ok := st["baseline"]; !ok {
		t.Fatalf("expected baseline sub-block in status")
	}
}

// TestDisabledDetectorNoOp asserts a disabled detector passes the floor
// decision through + emits nothing.
func TestDisabledDetectorNoOp(t *testing.T) {
	cfg := DefaultConfig() // disabled
	d := NewDetector(cfg, func(map[string]any) { t.Fatal("disabled detector emitted") }, false)
	out := d.Run(RunInput{Action: "GET", AgentIdentity: "x", FloorDecision: "allow", RecordObservation: true})
	if out.Decision != "allow" || out.Mode != "disabled" {
		t.Fatalf("disabled detector should pass through allow/disabled; got %q/%q", out.Decision, out.Mode)
	}
}

// stringifyAll walks a nested map/slice and concatenates every string
// value (keys + values) so the neutral-language scan covers the whole
// event payload.
func stringifyAll(v any) string {
	var b strings.Builder
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			b.WriteString(t)
			b.WriteByte(' ')
		case map[string]any:
			for k, vv := range t {
				b.WriteString(k)
				b.WriteByte(' ')
				walk(vv)
			}
		case []any:
			for _, vv := range t {
				walk(vv)
			}
		case []map[string]any:
			for _, vv := range t {
				walk(vv)
			}
		}
	}
	walk(v)
	return b.String()
}

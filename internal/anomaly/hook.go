// hook.go ports anomaly_detection/hook.py: the per-request glue that
// observes, scores, builds the neutral OCSF anomaly event, and applies
// the operator-configured mode (alert vs block).
//
// DEFAULT = ALERT, NOT BLOCK per [[safety-mode-lean-permissive]]: a
// fresh Detector with the default config (or an explicit mode=alert)
// lets the request through + surfaces an anomaly event; it never
// blocks.
//
// BLOCK MODE ENFORCES via the PRE-DECISION path (iam-jit#59). Two
// distinct entry points share this core:
//
//   - Decide (PRE-decision): consulted on a non-deny floor verdict
//     BEFORE the proxy serves the response. In mode=block an anomalous
//     verdict TIGHTENS allow->deny + emits a high-severity OCSF event.
//     TIGHTEN-ONLY: Decide may only make a decision MORE restrictive
//     (allow->deny); it never turns a deny into allow and never widens.
//     In alert / detection-only / disabled mode Decide is a pass-through
//     no-op (no score, no emit) — alerting stays on the observe path.
//   - Run (POST-decision): observes the (possibly tightened) decision
//     into the per-agent baseline for learning AND, in alert mode, scores
//     + emits the neutral alert. When the floor already denied (including
//     a deny that Decide just tightened to) Run short-circuits, so block
//     never double-counts or double-emits.
//
// This split keeps OBSERVE post-decision (learning is fine after the
// fact) while moving the SCORING that gates a block to a pre-decision
// point so the deny can actually be returned.
//
// Per [[ibounce-honest-positioning]] every operator-facing string uses
// NEUTRAL language — "your bouncer noticed something unusual", never
// "ANOMALY" / "VIOLATION".
//
// This file is BYTE-IDENTICAL across gbounce / kbouncer / dbounce. The
// OCSF event is returned as a generic map[string]any so the core has no
// dependency on any repo's audit package; the thin per-repo wire_*.go
// adapts it onto the product's audit.Emitter.
package anomaly

import (
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// product is the bouncer product name stamped onto emitted events. The
// per-repo wire_*.go sets it via SetProduct at construction so the core
// stays byte-identical (no per-repo string literal in this file).
var product atomic.Value // string

// SetProduct records the bouncer product name (e.g. "gbounce") used in
// emitted OCSF metadata.product.name. Idempotent; safe before/after
// NewDetector.
func SetProduct(name string) {
	if name != "" {
		product.Store(name)
	}
}

func productName() string {
	if v, ok := product.Load().(string); ok && v != "" {
		return v
	}
	return "bounce"
}

// HookResult is the per-request outcome. Ports hook.py HookResult.
type HookResult struct {
	// Decision is the effective verdict ("allow"/"deny"). On the Run
	// (post-decision) path this is the floor verdict passed through. On
	// the Decide (pre-decision) path mode=block may TIGHTEN it from
	// "allow" to "deny" on an anomalous verdict — never the reverse (see
	// the package doc + iam-jit#59).
	Decision string
	// Tightened is true only when the Decide (pre-decision) path flipped
	// a non-deny floor verdict to "deny" under mode=block. Lets the wire
	// distinguish an anomaly-driven block from a pass-through.
	Tightened bool
	// Anomaly is the full scoring result; nil when the detector is
	// disabled.
	Anomaly *AnomalyResult
	// EmittedAlert is true when a neutral OCSF anomaly event was built
	// (anomalous verdict).
	EmittedAlert bool
	// Event is the OCSF anomaly_detected event (nil unless an alert
	// was emitted). Generic map so the core stays audit-package-free.
	Event map[string]any
	// OperatorMessage is the neutral framing for stderr / surfaces.
	OperatorMessage string
	// Mode is "alert" | "block" | "detection-only" | "disabled".
	Mode string
}

// AlertEmitter receives the neutral OCSF anomaly event when one fires.
// The per-repo wire_*.go adapts the map onto the product's audit
// transport. nil is allowed (the detector then records but does not
// forward).
type AlertEmitter func(event map[string]any)

// Detector wires the baseline store + config + optional emitter. Ports
// hook.py _HookState + the install/run functions, collapsed into a
// value type so each bouncer owns its instance (no process singleton).
type Detector struct {
	mu            sync.Mutex
	cfg           Config
	store         *BaselineStore
	emitter       AlertEmitter
	detectionOnly bool

	scored  atomic.Int64
	flagged atomic.Int64
	emitted atomic.Int64

	// blockArmedOnce logs a single honest INFO the first time a
	// block-configured detector runs, confirming pre-decision
	// enforcement is armed (block now tightens allow->deny via Decide,
	// iam-jit#59).
	blockArmedOnce sync.Once
}

// NewDetector builds a Detector. A disabled config yields a no-op
// detector (Run always passes the floor decision through). detectionOnly
// forces alert behavior regardless of cfg.Mode (the "detection-only
// deployment" posture: score + surface, never block).
func NewDetector(cfg Config, emitter AlertEmitter, detectionOnly bool) *Detector {
	store := NewBaselineStore(cfg.BaselineWindowSeconds, cfg.BaselineDecayRate)
	return &Detector{
		cfg:           cfg,
		store:         store,
		emitter:       emitter,
		detectionOnly: detectionOnly,
	}
}

// Store exposes the baseline store (diagnostics + tests).
func (d *Detector) Store() *BaselineStore { return d.store }

// Enabled reports whether scoring runs.
func (d *Detector) Enabled() bool { return d != nil && d.cfg.Enabled }

// effectiveMode returns the runtime mode after the detection-only
// override.
func (d *Detector) effectiveMode() string {
	if d.detectionOnly {
		return "alert"
	}
	return d.cfg.Mode
}

// RunInput is the per-request input to Run. ObservedHour < 0 / count <
// 0 use the "not provided" sentinels (see ScoreInput).
type RunInput struct {
	Action              string
	AgentIdentity       string
	Resource            string
	ObservedHour        int
	ObservedActionCount float64
	// FloorDecision is the deterministic scorer's decision: "allow" or
	// "deny". When the floor already denied we short-circuit (don't
	// double-count) per [[scorer-is-ground-truth]].
	FloorDecision     string
	FloorDenyReason   string
	RecordObservation bool
}

// Run scores one request + applies the operator-configured mode. Ports
// hook.py run_anomaly_hook. Always returns a HookResult so callers can
// splat it without branching on enabled-ness.
func (d *Detector) Run(in RunInput) HookResult {
	floor := in.FloorDecision
	if floor == "" {
		floor = "allow"
	}
	if d == nil || !d.cfg.Enabled {
		return HookResult{Decision: floor, Mode: "disabled"}
	}
	mode := d.effectiveMode()

	// Always learn (the baseline tracks regardless of the decision).
	if in.RecordObservation {
		d.store.Observe(in.AgentIdentity, in.Action, in.Resource, 0)
	}

	// When the floor already denied, the deny path owns the surface.
	// This is also the path a block-mode tighten takes: Decide flipped
	// the verdict to "deny" PRE-decision (emitting the high-severity
	// event itself), so Run only records the observation here and does
	// NOT re-score or re-emit — no double-count, no double-emit.
	if floor == "deny" && !d.detectionOnly {
		return HookResult{
			Decision:        "deny",
			OperatorMessage: in.FloorDenyReason,
			Mode:            mode,
		}
	}

	// BLOCK: scoring + emission on a non-deny floor belong to the
	// PRE-decision Decide path (so the deny can actually be returned).
	// On this POST-decision observe path we only LEARN in block mode —
	// scoring/emitting here would be both too late to deny and a
	// duplicate of what Decide already surfaced. (Run still scores+emits
	// in alert / detection-only mode, where there is no Decide step.)
	if mode == "block" && !d.detectionOnly {
		return HookResult{Decision: floor, Mode: mode}
	}

	summary := d.store.SummaryFor(in.AgentIdentity, in.Action, in.Resource, 0)
	si := ScoreInput{
		Action:              in.Action,
		AgentIdentity:       in.AgentIdentity,
		Resource:            in.Resource,
		ObservedHour:        in.ObservedHour,
		ObservedActionCount: in.ObservedActionCount,
	}
	if in.ObservedHour == 0 && in.ObservedActionCount == 0 {
		// Caller used the zero value; treat both as "not provided".
		si.ObservedHour = -1
		si.ObservedActionCount = -1
	}
	res := ScoreAnomaly(si, summary, d.cfg)
	d.scored.Add(1)

	if res.Verdict != VerdictAnomalous {
		return HookResult{Decision: floor, Anomaly: &res, Mode: mode}
	}
	d.flagged.Add(1)

	event := buildOCSFAnomalyEvent(in.Action, in.Resource, in.AgentIdentity, res, mode, d.detectionOnly)
	emitted := false
	if d.emitter != nil {
		d.emitter(event)
		emitted = true
		d.emitted.Add(1)
	}

	// Reached only in alert / detection-only effective mode (block
	// returned above). Surface the neutral alert; never change the
	// decision here.
	return HookResult{
		Decision:        floor,
		Anomaly:         &res,
		EmittedAlert:    emitted,
		Event:           event,
		OperatorMessage: friendlySummary(in.Action, res, mode),
		Mode:            mode,
	}
}

// DecideInput is the PRE-decision input to Decide. The detector derives
// the deviation signals (hour-of-day from the store clock + the recent-
// window action rate from the baseline) itself so the wire passes only
// the structural shapes + the floor verdict — privacy preserved.
type DecideInput struct {
	Action        string
	AgentIdentity string
	Resource      string
	// FloorDecision is the deterministic scorer's verdict so far:
	// "allow" or "deny". Decide is TIGHTEN-ONLY — it is consulted ONLY
	// to make a non-deny verdict more restrictive.
	FloorDecision string
}

// Decide is the PRE-DECISION enforcement check (iam-jit#59). It runs in
// the LIVE decision path BEFORE the response is served and is the ONLY
// place the anomaly signal can change a verdict.
//
// TIGHTEN-ONLY INVARIANT (the security contract): Decide may only make a
// decision MORE restrictive. Concretely:
//
//   - floor == "deny"            -> returned UNCHANGED (never loosened).
//   - mode != block (alert /
//     detection-only / disabled)  -> floor returned UNCHANGED, no score,
//     no emit (alerting is the observe path's job, post-decision).
//   - mode == block, floor allow,
//     verdict anomalous           -> TIGHTEN allow->deny + emit event.
//   - mode == block, floor allow,
//     verdict not anomalous       -> floor (allow) returned UNCHANGED.
//
// The only mutation Decide ever performs is allow->deny; there is no
// code path that returns a verdict less restrictive than the floor.
//
// Decide does NOT record an observation: learning stays on the Run
// (post-decision) path so the baseline reflects what actually happened.
// FAIL-SOFT: Decide never panics out; any internal scoring weirdness
// degrades to the floor decision (allow stays allow) rather than denying
// spuriously or breaking the request path. The per-repo wire wraps the
// call so a detector error also falls through to the floor.
func (d *Detector) Decide(in DecideInput) HookResult {
	floor := in.FloorDecision
	if floor == "" {
		floor = "allow"
	}
	// Disabled / unwired: pass through.
	if d == nil || !d.cfg.Enabled {
		return HookResult{Decision: floor, Mode: "disabled"}
	}
	mode := d.effectiveMode()

	// TIGHTEN-ONLY GUARD #1: never consult the signal on a deny floor.
	// A deny stays a deny — Decide cannot loosen it.
	if floor == "deny" {
		return HookResult{Decision: "deny", Mode: mode}
	}
	// TIGHTEN-ONLY GUARD #2: only mode=block (and not detection-only)
	// may tighten. Everything else passes the floor through untouched;
	// the alert/observe surface stays on the Run path so we neither
	// double-score nor double-emit.
	if mode != "block" || d.detectionOnly {
		return HookResult{Decision: floor, Mode: mode}
	}

	// mode == block, floor is non-deny (allow). Score WITHOUT observing
	// (learning happens post-decision in Run). Derive the live deviation
	// signals from the store the same way the observe path does.
	res := d.scoreLive(in.Action, in.AgentIdentity, in.Resource)
	d.scored.Add(1)
	if res.Verdict != VerdictAnomalous {
		// Not anomalous: floor (allow) passes through UNCHANGED.
		return HookResult{Decision: floor, Anomaly: &res, Mode: mode}
	}
	d.flagged.Add(1)

	event := buildOCSFAnomalyEvent(in.Action, in.Resource, in.AgentIdentity, res, mode, d.detectionOnly)
	emitted := false
	if d.emitter != nil {
		d.emitter(event)
		emitted = true
		d.emitted.Add(1)
	}
	d.blockArmedOnce.Do(func() {
		log.Printf("[anomaly] anomaly_detection.mode=block is ARMED: anomalous requests are " +
			"DENIED pre-decision (allow->deny) and a high-severity event is emitted. " +
			"Tighten-only: a deny is never loosened. (iam-jit#59)")
	})
	// TIGHTEN: allow -> deny. This is the ONLY mutation Decide performs.
	return HookResult{
		Decision:        "deny",
		Tightened:       true,
		Anomaly:         &res,
		EmittedAlert:    emitted,
		Event:           event,
		OperatorMessage: friendlySummary(in.Action, res, mode),
		Mode:            mode,
	}
}

// scoreLive derives the live deviation signals (hour-of-day from the
// store clock + recent-window action rate from the baseline) and scores
// the sample WITHOUT recording an observation. Shared by Decide so the
// pre-decision verdict uses the same signals the observe path feeds.
func (d *Detector) scoreLive(action, agentIdentity, resource string) AnomalyResult {
	now := d.store.NowUTC()
	observedHour := now.Hour()
	observedRate := d.store.RecentRate(agentIdentity, action, resource, 0)
	summary := d.store.SummaryFor(agentIdentity, action, resource, 0)
	si := ScoreInput{
		Action:              action,
		AgentIdentity:       agentIdentity,
		Resource:            resource,
		ObservedHour:        observedHour,
		ObservedActionCount: observedRate,
	}
	return ScoreAnomaly(si, summary, d.cfg)
}

// Status returns a diagnostics snapshot for /healthz + the query
// surface. Neutral, honest framing per [[ibounce-honest-positioning]].
func (d *Detector) Status() map[string]any {
	if d == nil {
		return map[string]any{"enabled": false}
	}
	st := map[string]any{
		"enabled":           d.cfg.Enabled,
		"mode":              d.effectiveMode(),
		"detection_only":    d.detectionOnly,
		"sensitivity":       d.cfg.Sensitivity,
		"sigma_threshold":   d.cfg.SigmaThreshold(),
		"events_scored":     d.scored.Load(),
		"anomalies_flagged": d.flagged.Load(),
		"alerts_emitted":    d.emitted.Load(),
		"baseline":          d.store.Status(),
	}
	return st
}

// severityID / severityName map the verdict onto OCSF severity. An
// anomalous verdict is High (4); everything else Low (2). Matches
// hook.py _build_ocsf_anomaly_event.
func severityID(v Verdict) (int, string) {
	if v == VerdictAnomalous {
		return 4, "High"
	}
	return 2, "Low"
}

// buildOCSFAnomalyEvent composes the neutral OCSF class-6003
// anomaly_detected event. Ports hook.py _build_ocsf_anomaly_event. The
// product-specific fields ride under unmapped.iam_jit (matching the
// suite's existing alert wire shape).
func buildOCSFAnomalyEvent(action, resource, agentIdentity string, res AnomalyResult, mode string, detectionOnly bool) map[string]any {
	sevID, sevName := severityID(res.Verdict)
	actor := agentIdentity
	if actor == "" {
		actor = "anonymous"
	}
	return map[string]any{
		"metadata": map[string]any{
			"version": "1.1.0",
			"product": map[string]any{
				"name":        productName(),
				"vendor_name": "iam-jit",
			},
		},
		"class_uid":     6003,
		"class_name":    "API Activity",
		"category_uid":  6,
		"category_name": "Application Activity",
		"activity_id":   99,
		"activity_name": "anomaly_detected",
		"type_uid":      6003*100 + 99,
		"type_name":     "API Activity: Other",
		"severity_id":   sevID,
		"severity":      sevName,
		"status_id":     99,
		"status":        "Other",
		"status_detail": friendlySummary(action, res, mode),
		"actor": map[string]any{
			"user": map[string]any{"name": actor},
		},
		"api": map[string]any{
			"operation": "anomaly_detected",
			"service":   map[string]any{"name": "anomaly_detection"},
		},
		"resources": []any{},
		"unmapped": map[string]any{
			"iam_jit": map[string]any{
				"event_type":     "ANOMALY_DETECTED",
				"pattern":        "behavioral_deviation",
				"anomaly":        res.ToMap(),
				"mode":           mode,
				"detection_only": detectionOnly,
				"action":         action,
				"resource":       resource,
				"suggestion":     suggestion(res),
			},
		},
	}
}

// friendlySummary builds the neutral operator-facing message. Ports
// hook.py _friendly_summary. Leads with "noticed something unusual",
// never accusatory.
func friendlySummary(action string, res AnomalyResult, mode string) string {
	// NOTE: even under mode=block the head stays "noticed", never
	// "blocked" — block DOES enforce (allow->deny on anomalous via the
	// pre-decision Decide path, iam-jit#59); the neutral phrasing is
	// deliberate per [[ibounce-honest-positioning]]: accusatory language
	// would be dishonest if the signal is a false positive.
	head := "Your bouncer noticed something unusual"
	var contributing []string
	for _, e := range res.Explanations {
		if e.Contributing {
			contributing = append(contributing, e.Dimension)
		}
	}
	sort.Strings(contributing)
	parts := []string{
		head + ": " + action,
		"  score: " + formatFloat(res.AnomalyScore) + " (a signal for review, not proof of a problem)",
		"  baseline observations: " + formatInt(res.BaselineObservations),
	}
	if res.ColdStartFallbackUsed {
		parts = append(parts, "  cold-start: adversarial-pattern backstop fired (baseline still small)")
	}
	if len(contributing) > 0 {
		parts = append(parts, "  contributing dimensions: "+joinComma(contributing))
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "\n" + p
	}
	return out
}

// suggestion is the neutral next-step hint surfaced under
// unmapped.iam_jit.suggestion. Per [[ibounce-honest-positioning]].
func suggestion(res AnomalyResult) string {
	if res.ColdStartFallbackUsed {
		return "the baseline is still small for this agent; this action matched a known-sensitive pattern and is worth a quick look. add an allow rule if it is expected for this workflow."
	}
	return "this action deviates from the agent's learned baseline; review the context to confirm it is expected. no action is needed if it is."
}

// --- small formatting helpers (kept local so the core stays
// self-contained + byte-identical across repos) ---

func formatFloat(f float64) string {
	return strconv.FormatFloat(round(f, 2), 'f', 2, 64)
}

func formatInt(n int) string {
	return strconv.Itoa(n)
}

func joinComma(xs []string) string {
	return strings.Join(xs, ", ")
}

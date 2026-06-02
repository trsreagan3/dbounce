// hook.go ports anomaly_detection/hook.py: the per-request glue that
// observes, scores, builds the neutral OCSF anomaly event, and applies
// the operator-configured mode (alert vs block).
//
// DEFAULT = ALERT, NOT BLOCK per [[safety-mode-lean-permissive]]: a
// fresh Detector with the default config (or an explicit mode=alert)
// lets the request through + surfaces an anomaly event; it never
// blocks. Block mode is opt-in (mode=block) and even then is strictly
// more restrictive than the floor, never less.
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
	// Decision is the floor verdict passed through ("allow"/"deny") OR
	// "deny" when block mode chose to deny on an anomalous verdict.
	Decision string
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
	FloorDecision    string
	FloorDenyReason  string
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
	if floor == "deny" && !d.detectionOnly {
		return HookResult{
			Decision:        "deny",
			OperatorMessage: in.FloorDenyReason,
			Mode:            mode,
		}
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

	mode = d.effectiveMode()
	event := buildOCSFAnomalyEvent(in.Action, in.Resource, in.AgentIdentity, res, mode, d.detectionOnly)
	emitted := false
	if d.emitter != nil {
		d.emitter(event)
		emitted = true
		d.emitted.Add(1)
	}

	decision := floor
	if mode == "block" && !d.detectionOnly {
		decision = "deny"
	}
	return HookResult{
		Decision:        decision,
		Anomaly:         &res,
		EmittedAlert:    emitted,
		Event:           event,
		OperatorMessage: friendlySummary(in.Action, res, mode),
		Mode:            mode,
	}
}

// Status returns a diagnostics snapshot for /healthz + the query
// surface. Neutral, honest framing per [[ibounce-honest-positioning]].
func (d *Detector) Status() map[string]any {
	if d == nil {
		return map[string]any{"enabled": false}
	}
	st := map[string]any{
		"enabled":         d.cfg.Enabled,
		"mode":            d.effectiveMode(),
		"detection_only":  d.detectionOnly,
		"sensitivity":     d.cfg.Sensitivity,
		"sigma_threshold": d.cfg.SigmaThreshold(),
		"events_scored":   d.scored.Load(),
		"anomalies_flagged": d.flagged.Load(),
		"alerts_emitted":  d.emitted.Load(),
		"baseline":        d.store.Status(),
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
	head := "Your bouncer noticed something unusual"
	if mode == "block" {
		head = "Your bouncer blocked an unusual action"
	}
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

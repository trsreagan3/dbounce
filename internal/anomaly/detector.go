// detector.go ports anomaly_detection/detector.py: the pure-function
// anomaly scorer.
//
// ScoreAnomaly(action, agentIdentity, summary, config, ...) ->
// AnomalyResult. Pure: no side effects. The caller owns Observe()
// BEFORE scoring if the event should count toward future baselines.
//
// Per [[scorer-is-ground-truth]] this signal is ADVISORY. The hook
// layer decides alert-vs-block; the deterministic deny floor still
// wins on conflict.
//
// Composition (matches detector.py):
//  1. Per-dimension z-scores -> Explanation list (F.1 explainability).
//  2. Combined z-score from explanations (sigmoid-squashed max sigma).
//  3. Cold-start verdict when the baseline is below the configured
//     minimum AND no adversarial-pattern backstop fired.
//  4. Combined score = max(z_score, coldStartScore).
//
// Divergence from the Python reference, kept deliberately: the Python
// cold-start path calls the #404 deny-classifier + #407 threat-feed
// (separate modules). The Go port keeps a small SELF-CONTAINED
// adversarial-pattern backstop (the canonical KNOWN_ADVERSARIAL set the
// Python classifier hard-codes) so the core stays byte-identical across
// the three repos with no cross-package imports. Honest framing per
// [[ibounce-honest-positioning]]: a backstop hit is a signal for
// review, not proof of malice.
package anomaly

import (
	"math"
	"strings"
)

// Verdict is the detector's per-event classification.
type Verdict string

const (
	VerdictNormal           Verdict = "normal"
	VerdictAnomalous        Verdict = "anomalous"
	VerdictInsufficientData Verdict = "insufficient_data"
)

// coldStartFlagThreshold mirrors detector.py _COLD_START_FLAG_THRESHOLD.
const coldStartFlagThreshold = 0.7

// Explanation is the F.1 per-dimension breakdown surfaced to operators.
// Ports detector.py Explanation.
type Explanation struct {
	Dimension     string
	BaselineMean  float64
	BaselineStd   float64
	Observed      float64
	SigmaDistance float64
	Contributing  bool
}

// ToMap renders the explanation for the OCSF event payload (rounded
// like detector.py Explanation.to_dict).
func (e Explanation) ToMap() map[string]any {
	return map[string]any{
		"dimension":      e.Dimension,
		"baseline_mean":  round(e.BaselineMean, 4),
		"baseline_stddev": round(e.BaselineStd, 4),
		"observed":       round(e.Observed, 4),
		"sigma_distance": round(e.SigmaDistance, 3),
		"contributing":   e.Contributing,
	}
}

// AnomalyResult is the detector output. Ports detector.py AnomalyResult.
type AnomalyResult struct {
	AnomalyScore          float64
	Verdict               Verdict
	Explanations          []Explanation
	ColdStartFallbackUsed bool
	BaselineObservations  int
	Note                  string
}

// ToMap renders the result for the OCSF event payload (ports
// AnomalyResult.to_dict).
func (r AnomalyResult) ToMap() map[string]any {
	exps := make([]map[string]any, 0, len(r.Explanations))
	for _, e := range r.Explanations {
		exps = append(exps, e.ToMap())
	}
	return map[string]any{
		"anomaly_score":            round(r.AnomalyScore, 4),
		"verdict":                  string(r.Verdict),
		"explanations":             exps,
		"cold_start_fallback_used": r.ColdStartFallbackUsed,
		"baseline_observations":    r.BaselineObservations,
		"note":                     r.Note,
	}
}

// ScoreInput carries the optional observed-value overrides for one
// scoring call. ObservedHour < 0 means "not provided" (hour_of_day is
// skipped). ObservedActionCount < 0 means "single-event scoring" — the
// action_frequency dimension uses the baseline mean as the observed
// value (0 sigma), matching detector.py's None default; callers wanting
// spike detection pass the actual recent-window count.
type ScoreInput struct {
	Action              string
	AgentIdentity       string
	Resource            string
	ObservedHour        int
	ObservedActionCount float64
}

// NewScoreInput returns a ScoreInput with the "not provided" sentinels
// set, so callers only fill the fields they have.
func NewScoreInput(action, agentIdentity, resource string) ScoreInput {
	return ScoreInput{
		Action:              action,
		AgentIdentity:       agentIdentity,
		Resource:            resource,
		ObservedHour:        -1,
		ObservedActionCount: -1,
	}
}

// knownAdversarialActions is the canonical cold-start backstop catalog
// (the set the Python deny-classifier hard-codes as
// KNOWN_ADVERSARIAL_PATTERNS). Substring, case-insensitive match on the
// action verb. Generous on purpose — these are the
// visibility-blinding / takeover / exfil shapes that warrant a look
// even before a baseline exists.
var knownAdversarialActions = []string{
	"deletetrail", "stoplogging", "deleteloggroup", "putbucketpolicy",
	"deletebucketpolicy", "deletedetector", "disable", "createaccesskey",
	"createloginprofile", "attachrolepolicy", "putuserpolicy",
	"deletecluster", "deletenamespace", "drop ", "drop table", "drop database",
	"truncate", "grant all", "delete from",
}

// perDimensionZ builds the F.1 explanation list. Ports detector.py
// _per_dimension_z. Always one entry per dimension present so the
// operator sees the full picture (contributing or not).
func perDimensionZ(summary BaselineSummary, in ScoreInput, sigmaThreshold float64) []Explanation {
	var exps []Explanation
	for dimName, stats := range summary.Dimensions {
		switch {
		case strings.Contains(dimName, "action_frequency"):
			observed := stats.Mean
			if in.ObservedActionCount >= 0 {
				observed = in.ObservedActionCount
			}
			z := stats.ZScore(observed)
			exps = append(exps, Explanation{
				Dimension:     dimName,
				BaselineMean:  stats.Mean,
				BaselineStd:   stats.Stddev,
				Observed:      observed,
				SigmaDistance: z,
				Contributing:  z >= sigmaThreshold,
			})
		case strings.Contains(dimName, "hour_of_day"):
			if in.ObservedHour < 0 {
				continue
			}
			observed := float64(in.ObservedHour)
			z := stats.ZScore(observed)
			exps = append(exps, Explanation{
				Dimension:     dimName,
				BaselineMean:  stats.Mean,
				BaselineStd:   stats.Stddev,
				Observed:      observed,
				SigmaDistance: z,
				Contributing:  z >= sigmaThreshold,
			})
		}
	}
	return exps
}

// aggregateZToScore combines per-dimension z-scores into a single
// anomaly score in [0,1]. Ports detector.py _aggregate_z_to_score: the
// max sigma_distance through a sigmoid centred at sigma=2 with
// steepness 0.8 (2σ≈0.5, 4σ≈0.88, 6σ→0.99).
func aggregateZToScore(exps []Explanation) float64 {
	if len(exps) == 0 {
		return 0.0
	}
	maxSig := exps[0].SigmaDistance
	for _, e := range exps[1:] {
		if e.SigmaDistance > maxSig {
			maxSig = e.SigmaDistance
		}
	}
	return 1.0 / (1.0 + math.Exp(-(maxSig-2.0)*0.8))
}

// coldStartBackstop scans the action for a known-adversarial pattern.
// Returns (fired, score). Ports the self-contained slice of detector.py
// _try_classifier_fallback (the hard backstop against
// KNOWN_ADVERSARIAL_PATTERNS).
func coldStartBackstop(action, resource string, cfg Config) (bool, float64) {
	if !cfg.ColdStartFallback {
		return false, 0.0
	}
	hay := strings.ToLower(action + " " + resource)
	for _, p := range knownAdversarialActions {
		if strings.Contains(hay, p) {
			return true, 0.9
		}
	}
	return false, 0.0
}

// ScoreAnomaly scores one (agent, action, resource) sample against the
// baseline. Pure function. Ports detector.py score_anomaly.
func ScoreAnomaly(in ScoreInput, summary BaselineSummary, cfg Config) AnomalyResult {
	sigma := cfg.SigmaThreshold()
	exps := perDimensionZ(summary, in, sigma)
	zScore := aggregateZToScore(exps)

	rolling := summary.TotalObservationsRolling
	isColdStart := rolling < cfg.MinActionsForBaseline

	backstopFired := false
	fallbackScore := 0.0
	if isColdStart {
		backstopFired, fallbackScore = coldStartBackstop(in.Action, in.Resource, cfg)
	}

	combined := math.Max(zScore, fallbackScore)

	// Verdict band: convert the sigma threshold into a score band via
	// the same sigmoid the aggregator uses (ports detector.py).
	scoreBand := 1.0 / (1.0 + math.Exp(-(sigma-2.0)*0.8))

	var verdict Verdict
	note := ""
	switch {
	case isColdStart && !backstopFired:
		verdict = VerdictInsufficientData
		note = "baseline below minimum; cold-start backstop found no adversarial signal"
	case combined >= scoreBand:
		verdict = VerdictAnomalous
	default:
		verdict = VerdictNormal
	}

	return AnomalyResult{
		AnomalyScore:          combined,
		Verdict:               verdict,
		Explanations:          exps,
		ColdStartFallbackUsed: backstopFired,
		BaselineObservations:  rolling,
		Note:                  note,
	}
}

// round rounds x to n decimal places (matches Python round() for the
// to_dict surfaces).
func round(x float64, n int) float64 {
	p := math.Pow(10, float64(n))
	return math.Round(x*p) / p
}

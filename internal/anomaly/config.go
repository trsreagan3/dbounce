// Package anomaly ports iam-jit's Phase H behavioral-deviation /
// anomaly detector (the Python iam_jit.anomaly_detection package) to
// the Go Bounce suite. ADOPT-4 / #718.
//
// WHAT IT DETECTS (matches the Python Phase H reference):
//
//   - A lightweight per-agent (per-session) BEHAVIORAL BASELINE is
//     learned from the bouncer's own decision/audit stream. We track
//     structural signals only — never raw values — per
//     [[independence-as-security-property]] + the Python baseline's
//     privacy invariant: action shape, a canonical resource pattern
//     (ARN-env / k8s-namespace-env / sql-schema-env bucket), time
//     bucket (hour-of-day) and counts.
//   - DEVIATIONS are scored with per-dimension z-scores (volume spike
//     via action_frequency, off-hours via hour_of_day) plus a
//     cold-start verdict when the baseline is too small to be
//     authoritative. This mirrors detector.score_anomaly().
//   - The detector emits a NEUTRAL OCSF anomaly_detected event
//     (class_uid 6003, activity_id 99) — a SIGNAL for review, not a
//     proof of malice, per [[ibounce-honest-positioning]]. Severity
//     scales with the deviation.
//
// DEFAULT = ALERT, NOT BLOCK, per [[safety-mode-lean-permissive]] +
// [[anomaly-detection-mode-phase-h]]: enabled bouncers surface +
// alert; they do not block by default. Block mode is opt-in.
//
// CROSS-PRODUCT INVARIANT per [[config-export-wire-divergence]]: the
// core of this package (config.go + baseline.go + detector.go +
// hook.go) is BYTE-IDENTICAL across gbounce / kbouncer / dbounce. Only
// the thin protocol-specific signal extraction + audit wiring (the
// wire_*.go file) differs. Keep the four core files in lockstep when
// editing any one of them.
//
// config.go ports anomaly_detection/config.py: the declarative config
// block + sensitivity presets.
package anomaly

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SensitivityPresets resolve the operator-facing sensitivity label
// into the z-score (sigma) threshold the detector flags above. Ported
// verbatim from config.py SENSITIVITY_PRESETS.
//
//	low    -> 3.0 sigma  (flags only large deviations)
//	medium -> 2.0 sigma  (the honest default)
//	high   -> 1.5 sigma  (flags smaller deviations; noisier)
var SensitivityPresets = map[string]float64{
	"low":    3.0,
	"medium": 2.0,
	"high":   1.5,
}

const (
	defaultWindow      = "14d"
	defaultDecayRate   = 0.96
	defaultMinActions  = 50
	defaultMode        = "alert"
	defaultSensitivity = "medium"
)

// durationRE accepts "30d" / "12h" / "60m" / "3600s" / raw seconds.
var durationRE = regexp.MustCompile(`^\s*(\d+)\s*([smhd]?)\s*$`)

var durationUnits = map[string]int{"s": 1, "m": 60, "h": 3600, "d": 86400, "": 1}

// ConfigError is returned when an anomaly_detection config block is
// malformed. Mirrors config.py ConfigError (a ValueError subclass).
type ConfigError struct{ msg string }

func (e *ConfigError) Error() string { return e.msg }

func configErr(format string, args ...any) error {
	return &ConfigError{msg: fmt.Sprintf(format, args...)}
}

// parseDurationToSeconds converts a duration string ("14d") or a
// positive integer (seconds) into seconds. Ports config.py
// _parse_duration_to_seconds.
func parseDurationToSeconds(raw any, field string) (int, error) {
	switch v := raw.(type) {
	case nil:
		return 0, configErr("%s is required", field)
	case int:
		if v <= 0 {
			return 0, configErr("%s must be > 0; got %d", field, v)
		}
		return v, nil
	case int64:
		if v <= 0 {
			return 0, configErr("%s must be > 0; got %d", field, v)
		}
		return int(v), nil
	case float64:
		// YAML / JSON numbers decode to float64. Accept whole numbers.
		iv := int(v)
		if float64(iv) != v || iv <= 0 {
			return 0, configErr("%s must be a positive integer of seconds; got %v", field, v)
		}
		return iv, nil
	case string:
		m := durationRE.FindStringSubmatch(v)
		if m == nil {
			return 0, configErr("%s must be like '14d' / '12h' / '60m' / '3600s'; got %q", field, v)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, configErr("%s must be like '14d' / '12h' / '60m' / '3600s'; got %q", field, v)
		}
		unit := m[2]
		if unit == "" {
			unit = "s"
		}
		seconds := n * durationUnits[unit]
		if seconds <= 0 {
			return 0, configErr("%s must be > 0; got %q", field, v)
		}
		return seconds, nil
	default:
		return 0, configErr("%s must be a duration string like '14d' or positive integer seconds; got %T", field, raw)
	}
}

// Config is the validated anomaly_detection config. Ports config.py
// AnomalyDetectionConfig. Zero value is the disabled default, matching
// the Python dataclass defaults.
type Config struct {
	Enabled bool
	// Mode is "alert" | "block". alert (default) flags + emits a neutral
	// high-severity event but never denies. block ENFORCES: an anomalous
	// request is DENIED pre-decision (allow->deny) via Detector.Decide in
	// the live decision path, and the same high-severity event is
	// emitted. Tighten-only — a deterministic deny is never loosened
	// (iam-jit#59). detection-only deployments force alert regardless.
	Mode                  string
	Sensitivity           string // "low" | "medium" | "high"
	BaselineWindowSeconds int
	BaselineDecayRate     float64
	MinActionsForBaseline int
	ColdStartFallback     bool
}

// DefaultConfig returns the conservative, DISABLED default per
// [[ibounce-honest-positioning]]: mode=alert, sensitivity=medium,
// cold-start fallback on. Enabled=false until an operator opts in.
func DefaultConfig() Config {
	return Config{
		Enabled:               false,
		Mode:                  defaultMode,
		Sensitivity:           defaultSensitivity,
		BaselineWindowSeconds: 14 * 86400,
		BaselineDecayRate:     defaultDecayRate,
		MinActionsForBaseline: defaultMinActions,
		ColdStartFallback:     true,
	}
}

// SigmaThreshold returns the z-score threshold the detector flags
// above for the configured sensitivity. Ports the sigma_threshold
// property. Falls back to medium for an unknown sensitivity (defensive
// — LoadConfig rejects unknown values, but a zero-value Config built
// directly should still behave).
func (c Config) SigmaThreshold() float64 {
	if s, ok := SensitivityPresets[c.Sensitivity]; ok {
		return s
	}
	return SensitivityPresets[defaultSensitivity]
}

// LoadConfig validates + returns a Config from a parsed
// anomaly_detection block (a map decoded from YAML/JSON). A nil block
// returns the disabled default. Ports config.py load_config, including
// the unknown-key rejection (mirrors additionalProperties:false so a
// typo never silently no-ops).
func LoadConfig(block map[string]any) (Config, error) {
	if block == nil {
		return DefaultConfig(), nil
	}

	cfg := DefaultConfig()
	cfg.Enabled = asBool(block["enabled"], false)

	mode := strings.ToLower(strings.TrimSpace(asString(block["mode"], defaultMode)))
	if mode != "alert" && mode != "block" {
		return Config{}, configErr("anomaly_detection.mode must be 'alert' or 'block'; got %q", mode)
	}
	cfg.Mode = mode

	sens := strings.ToLower(strings.TrimSpace(asString(block["sensitivity"], defaultSensitivity)))
	if _, ok := SensitivityPresets[sens]; !ok {
		return Config{}, configErr("anomaly_detection.sensitivity must be one of [high low medium]; got %q", sens)
	}
	cfg.Sensitivity = sens

	windowRaw, ok := block["baseline_window"]
	if !ok {
		windowRaw = defaultWindow
	}
	ws, err := parseDurationToSeconds(windowRaw, "anomaly_detection.baseline_window")
	if err != nil {
		return Config{}, err
	}
	cfg.BaselineWindowSeconds = ws

	decay := asFloat(block["baseline_decay_rate"], defaultDecayRate)
	if !(decay > 0.0 && decay <= 1.0) {
		return Config{}, configErr("anomaly_detection.baseline_decay_rate must be in (0, 1]; got %v", decay)
	}
	cfg.BaselineDecayRate = decay

	minActions := asInt(block["min_actions_for_baseline"], defaultMinActions)
	if minActions < 0 {
		return Config{}, configErr("anomaly_detection.min_actions_for_baseline must be >= 0; got %d", minActions)
	}
	cfg.MinActionsForBaseline = minActions

	cfg.ColdStartFallback = asBool(block["cold_start_fallback"], true)

	allowed := map[string]struct{}{
		"enabled": {}, "mode": {}, "sensitivity": {}, "baseline_window": {},
		"baseline_decay_rate": {}, "min_actions_for_baseline": {},
		"cold_start_fallback": {},
	}
	var extra []string
	for k := range block {
		if _, ok := allowed[k]; !ok {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		return Config{}, configErr("anomaly_detection has unknown key(s) %v; allowed: [baseline_decay_rate baseline_window cold_start_fallback enabled min_actions_for_baseline mode sensitivity]", sortedStrings(extra))
	}

	return cfg, nil
}

// --- small typed-coercion helpers (YAML/JSON decode to any) ---

func asBool(v any, def bool) bool {
	if v == nil {
		return def
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

func asString(v any, def string) string {
	if v == nil {
		return def
	}
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

func asFloat(v any, def float64) float64 {
	switch n := v.(type) {
	case nil:
		return def
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return def
	}
}

func asInt(v any, def int) int {
	switch n := v.(type) {
	case nil:
		return def
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return def
	}
}

func sortedStrings(xs []string) []string {
	out := make([]string, len(xs))
	copy(out, xs)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

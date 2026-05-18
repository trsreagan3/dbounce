// Deployment presets — single-flag shortcuts for common dbounce
// deployment shapes.
//
// A deployment preset is a NAMED BUNDLE of run-command flag values.
// `dbounce run --preset security-observe` is equivalent to typing out
// the canonical 6-7 flags by hand; the preset just makes the common
// deployment one-flag for the operator (+ documents intent).
//
// Per [[cross-product-agent-parity]]: same preset NAMES + same
// HARD-vs-SOFT override semantics across ibounce / kbounce / dbounce /
// gbounce. The HARD flag for `security-observe` is `--mode` (the
// entire point of the preset is transparent); SOFT flags are the
// audit-export sinks + heartbeat cadence (operators have different
// SIEMs).
//
// Per [[security-team-positioning-safety-not-surveillance]]: preset
// descriptions use NEUTRAL language. No "violation" / "infraction" /
// "unauthorized" — these are observability tools.

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PresetOverridePolicy tags each preset value as HARD or SOFT.
type PresetOverridePolicy string

const (
	PresetHard PresetOverridePolicy = "hard"
	PresetSoft PresetOverridePolicy = "soft"
)

// PresetValue is one (flag → value, override-policy) entry.
type PresetValue struct {
	Key    string
	Value  string
	Policy PresetOverridePolicy
}

// DeploymentPreset is a named bundle of run-command flag values.
type DeploymentPreset struct {
	Name        string
	Description string
	Order       []string
	Values      map[string]PresetValue
}

// DefaultAuditLogPath returns the per-product default JSONL audit-log
// path the security-observe preset uses. Honors $XDG_STATE_HOME →
// $HOME/.dbounce/audit/<product>.jsonl.
func DefaultAuditLogPath(product string) string {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home := os.Getenv("HOME")
		if home == "" {
			home = "."
		}
		base = filepath.Join(home, ".dbounce")
	}
	return filepath.Join(base, "audit", product+".jsonl")
}

// BuildSecurityObserve returns the security-team observation preset
// for dbounce.
//
// dbounce ships heartbeat + audit-export-health-interval, but NOT a
// rule-engine alert framework like ibounce/kbounce — alert defaults
// in dbounce are realized via the audit_export_degraded periodic
// poll. The preset wires that on; the absent --alert-rules is
// silently skipped by the run command's preset-resolution path
// (dbounce never registers the flag).
func BuildSecurityObserve(product string) DeploymentPreset {
	return DeploymentPreset{
		Name: "security-observe",
		Description: "security-team observation: transparent mode + JSONL audit + " +
			"30s heartbeat + 30s audit-export health poll. Designed for the " +
			"'gather data first; author profile second' starting shape per " +
			"[[bouncer-mode-selection-for-agents]]. Use when the security team " +
			"is establishing a baseline of agent behavior before deciding " +
			"which calls to gate.",
		Order: []string{
			"mode",
			"default-policy",
			"audit-log-path",
			"heartbeat-interval",
			"audit-export-health-interval",
		},
		Values: map[string]PresetValue{
			// HARD: the whole point of this preset is transparent.
			"mode": {Key: "mode", Value: "transparent", Policy: PresetHard},
			// SOFT: transparent observation; do not surprise the
			// operator with denies on rules they have not yet authored.
			"default-policy": {Key: "default-policy", Value: "allow", Policy: PresetSoft},
			// SOFT: per-product default path. Operator points at their
			// own location.
			"audit-log-path": {
				Key: "audit-log-path", Value: DefaultAuditLogPath(product),
				Policy: PresetSoft,
			},
			// SOFT: 30s heartbeat per #264 recommendation.
			"heartbeat-interval": {
				Key: "heartbeat-interval", Value: "30s",
				Policy: PresetSoft,
			},
			// SOFT: 30s audit-export health poll matches the heartbeat
			// cadence so a SIEM gets consistent fidelity from both
			// channels. Tracks audit_export_degraded.
			"audit-export-health-interval": {
				Key: "audit-export-health-interval", Value: "30s",
				Policy: PresetSoft,
			},
		},
	}
}

// GetPreset returns the preset by name, or nil if unknown.
func GetPreset(name, product string) *DeploymentPreset {
	switch name {
	case "security-observe":
		p := BuildSecurityObserve(product)
		return &p
	}
	return nil
}

// ListPresetNames returns the v1.0 preset names.
func ListPresetNames() []string {
	return []string{"security-observe"}
}

// PresetOverrideError signals a HARD-override conflict.
type PresetOverrideError struct {
	Preset      string
	Flag        string
	PresetValue string
	GivenValue  string
}

func (e *PresetOverrideError) Error() string {
	return fmt.Sprintf(
		"--preset %s sets --%s=%q (HARD); cannot override with operator-supplied --%s=%q. "+
			"Either drop the --preset flag, OR drop the explicit --%s flag.",
		e.Preset, e.Flag, e.PresetValue, e.Flag, e.GivenValue, e.Flag,
	)
}

// PresetResolution describes which preset values applied + which the
// operator overrode + which the product skipped.
type PresetResolution struct {
	DerivedKeys    []string
	SkippedKeys    []string
	OverriddenKeys []string
}

// ApplyPreset resolves a preset against the operator's flag set.
func ApplyPreset(
	preset *DeploymentPreset,
	operatorChanged map[string]bool,
	currentValues map[string]string,
	skipKeys map[string]bool,
) (*PresetResolution, error) {
	res := &PresetResolution{}
	for _, key := range preset.Order {
		pv := preset.Values[key]
		if skipKeys != nil && skipKeys[key] {
			res.SkippedKeys = append(res.SkippedKeys, key)
			continue
		}
		if operatorChanged[key] {
			given := currentValues[key]
			if pv.Policy == PresetHard && given != pv.Value {
				return nil, &PresetOverrideError{
					Preset:      preset.Name,
					Flag:        key,
					PresetValue: pv.Value,
					GivenValue:  given,
				}
			}
			res.OverriddenKeys = append(res.OverriddenKeys, key)
			continue
		}
		res.DerivedKeys = append(res.DerivedKeys, key)
	}
	return res, nil
}

// FormatBanner returns stderr lines describing the active preset.
// Format identical across all four Bounce products per
// [[cross-product-agent-parity]].
func FormatBanner(preset *DeploymentPreset, res *PresetResolution) []string {
	lines := []string{fmt.Sprintf("deployment preset: %s", preset.Name)}
	for _, key := range preset.Order {
		derived := false
		for _, dk := range res.DerivedKeys {
			if dk == key {
				derived = true
				break
			}
		}
		if !derived {
			continue
		}
		pv := preset.Values[key]
		lines = append(lines, fmt.Sprintf(
			"  --%s = %q (from preset; %s)",
			pv.Key, pv.Value, pv.Policy,
		))
	}
	for _, key := range preset.Order {
		skipped := false
		for _, sk := range res.SkippedKeys {
			if sk == key {
				skipped = true
				break
			}
		}
		if !skipped {
			continue
		}
		pv := preset.Values[key]
		lines = append(lines, fmt.Sprintf(
			"  --%s: not applicable to this product (preset value skipped)",
			pv.Key,
		))
	}
	return lines
}

// MustParseDuration is a helper for the run-command's preset
// resolution path; preset values are author-controlled string
// literals so any parse error is a programming bug.
func MustParseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic(fmt.Sprintf("deployment preset: invalid duration literal %q: %v", s, err))
	}
	return d
}

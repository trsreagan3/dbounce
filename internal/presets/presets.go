// Package presets ships dbounce's built-in preset library (per
// [[evolving-preset-library]] tier 1: built-in).
//
// Embedded at compile time via go:embed so the binary is a single
// file; no runtime YAML lookup, no on-disk pack loading. Operators
// browse with `dbounce presets list`, inspect with
// `dbounce presets show NAME`, and install with
// `dbounce presets apply NAME` which CREATES a new profile from the
// preset's rules (never mutates an existing profile — per
// [[creates-never-mutates]]).
//
// Tier 2 (org-curated) + tier 3 (personal-recurring auto-evolved) come
// post-launch. This package only owns the read-only tier-1 catalog.
package presets

import (
	_ "embed"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/trsreagan3/dbounce/internal/rules"
)

//go:embed presets.yaml
var embeddedYAML []byte

// PresetRule is the YAML representation of one rule inside a preset.
// Surfaced as its own type (rather than reusing rules.ProxyRule
// directly) because the YAML field names are snake_case + the preset
// version intentionally omits the Origin field (presets always set
// Origin=rules.OriginPreset at conversion time).
type PresetRule struct {
	Pattern       string `yaml:"pattern"`
	Effect        string `yaml:"effect"`
	SchemaScope   string `yaml:"schema_scope,omitempty"`
	TableScope    string `yaml:"table_scope,omitempty"`
	FunctionScope string `yaml:"function_scope,omitempty"`
	Note          string `yaml:"note,omitempty"`
}

// Preset is one entry in the embedded library.
type Preset struct {
	ID          string       `yaml:"id"`
	Title       string       `yaml:"title"`
	Description string       `yaml:"description"`
	AllowRules  []PresetRule `yaml:"allow_rules"`
	DenyRules   []PresetRule `yaml:"deny_rules"`
}

// catalog is the parsed YAML, populated by load() at init time so all
// callers see a consistent view + parse errors fail-fast at binary
// startup rather than at first `presets list` invocation.
var catalog []Preset

func init() {
	parsed, err := load(embeddedYAML)
	if err != nil {
		panic(fmt.Sprintf("dbounce: parse embedded presets.yaml: %v", err))
	}
	catalog = parsed
}

// load is the testable parser entry point. Exposed for tests that want
// to validate against an alternate YAML blob; production always uses
// the embedded copy.
func load(blob []byte) ([]Preset, error) {
	var wrapper struct {
		Presets []Preset `yaml:"presets"`
	}
	if err := yaml.Unmarshal(blob, &wrapper); err != nil {
		return nil, fmt.Errorf("yaml unmarshal: %w", err)
	}
	// Validate: each preset must have a unique id + at least one
	// allow_rule or deny_rule. Rule patterns must round-trip through
	// the rules package's ParsePattern so a malformed preset surfaces
	// at startup rather than first-use.
	seen := make(map[string]struct{}, len(wrapper.Presets))
	for i, p := range wrapper.Presets {
		if p.ID == "" {
			return nil, fmt.Errorf("preset[%d]: id is required", i)
		}
		if _, dup := seen[p.ID]; dup {
			return nil, fmt.Errorf("preset[%d]: duplicate id %q", i, p.ID)
		}
		seen[p.ID] = struct{}{}
		if len(p.AllowRules) == 0 && len(p.DenyRules) == 0 {
			return nil, fmt.Errorf("preset %q: no rules defined", p.ID)
		}
		for j, r := range p.AllowRules {
			if _, _, err := rules.ParsePattern(r.Pattern); err != nil {
				return nil, fmt.Errorf("preset %q allow_rules[%d]: %v",
					p.ID, j, err)
			}
		}
		for j, r := range p.DenyRules {
			if _, _, err := rules.ParsePattern(r.Pattern); err != nil {
				return nil, fmt.Errorf("preset %q deny_rules[%d]: %v",
					p.ID, j, err)
			}
		}
	}
	return wrapper.Presets, nil
}

// List returns all presets sorted by id for stable CLI output.
func List() []Preset {
	out := make([]Preset, len(catalog))
	copy(out, catalog)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns the preset with the given id, or (nil, false) when
// missing. Comparison is exact (no case-folding) — preset ids are
// part of the binary's interface contract, just like a CLI subcommand
// name.
func Get(id string) (*Preset, bool) {
	for i := range catalog {
		if catalog[i].ID == id {
			p := catalog[i]
			return &p, true
		}
	}
	return nil, false
}

// ToProxyRules converts the preset's allow + deny rules to the
// rules.ProxyRule shape the proxy + the store understand. Effect is
// forced to match the list (allow_rules → EffectAllow, deny_rules →
// EffectDeny) so a typo'd YAML "effect" field can't subvert intent.
// Origin is set to rules.OriginPreset so the audit-row decision-source
// downstream can color-code preset-derived rows.
func (p *Preset) ToProxyRules() (allow []rules.ProxyRule, deny []rules.ProxyRule) {
	for _, r := range p.AllowRules {
		allow = append(allow, rules.ProxyRule{
			Pattern:       r.Pattern,
			Effect:        rules.EffectAllow,
			SchemaScope:   r.SchemaScope,
			TableScope:    r.TableScope,
			FunctionScope: r.FunctionScope,
			Note:          r.Note,
			Origin:        rules.OriginPreset,
		})
	}
	for _, r := range p.DenyRules {
		deny = append(deny, rules.ProxyRule{
			Pattern:       r.Pattern,
			Effect:        rules.EffectDeny,
			SchemaScope:   r.SchemaScope,
			TableScope:    r.TableScope,
			FunctionScope: r.FunctionScope,
			Note:          r.Note,
			Origin:        rules.OriginPreset,
		})
	}
	return allow, deny
}

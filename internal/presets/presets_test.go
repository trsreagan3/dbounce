package presets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/rules"
)

func TestEmbeddedCatalog_ParsesSuccessfully(t *testing.T) {
	all := List()
	require.NotEmpty(t, all, "embedded catalog must produce at least one preset")
	// Sanity bound: catalog is intentionally small so the operator can
	// read it end-to-end. 50+ entries would mean tier-2 work crept in
	// somewhere it shouldn't.
	assert.LessOrEqual(t, len(all), 50)
}

func TestStarterPresets_AllPresent(t *testing.T) {
	// The 5 starter presets the dbounce-build-plan §D-Slice 8 calls
	// out by id. Regression bait: removing one of these breaks the
	// announced surface area.
	for _, id := range []string{
		"analytics-engineer",
		"dba-investigation",
		"migration-runner",
		"incident-readonly",
		"schema-survey",
	} {
		t.Run(id, func(t *testing.T) {
			p, ok := Get(id)
			require.True(t, ok, "starter preset %q must exist", id)
			assert.NotEmpty(t, p.Title)
			assert.NotEmpty(t, p.Description)
			assert.True(t, len(p.AllowRules)+len(p.DenyRules) > 0,
				"starter preset %q must define at least one rule", id)
		})
	}
}

func TestPreset_ToProxyRules_ForcesEffect(t *testing.T) {
	p, ok := Get("incident-readonly")
	require.True(t, ok)
	allow, deny := p.ToProxyRules()
	for _, r := range allow {
		assert.Equal(t, rules.EffectAllow, r.Effect,
			"allow_rules MUST surface as EffectAllow regardless of YAML")
		assert.Equal(t, rules.OriginPreset, r.Origin)
	}
	for _, r := range deny {
		assert.Equal(t, rules.EffectDeny, r.Effect,
			"deny_rules MUST surface as EffectDeny regardless of YAML")
		assert.Equal(t, rules.OriginPreset, r.Origin)
	}
}

func TestList_Stable(t *testing.T) {
	a := List()
	b := List()
	require.Equal(t, len(a), len(b))
	for i := range a {
		assert.Equal(t, a[i].ID, b[i].ID, "List() must be deterministically ordered")
	}
}

func TestGet_Missing(t *testing.T) {
	_, ok := Get("no-such-preset")
	assert.False(t, ok)
}

func TestLoad_RejectsDuplicateID(t *testing.T) {
	blob := []byte(`presets:
  - id: dup
    title: a
    allow_rules: [{pattern: "SELECT:*", effect: allow}]
  - id: dup
    title: b
    deny_rules: [{pattern: "DELETE:*", effect: deny}]`)
	_, err := load(blob)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate id")
}

func TestLoad_RejectsMalformedPattern(t *testing.T) {
	blob := []byte(`presets:
  - id: bad
    title: bad
    allow_rules: [{pattern: "this is not a valid pattern", effect: allow}]`)
	_, err := load(blob)
	require.Error(t, err)
}

func TestLoad_RejectsEmptyRuleList(t *testing.T) {
	blob := []byte(`presets:
  - id: empty
    title: empty`)
	_, err := load(blob)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rules defined")
}

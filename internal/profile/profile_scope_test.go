// §A40 LAUNCH-BLOCKER tests — profile-level OnlyHosts + OnlyDatabases
// connection-establishment scope enforcement.
//
// Cross-references the wire-level integration in
// internal/proxy/profile_scope_test.go (which exercises the full PG
// handshake path).

package profile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestProfile_OnlyHosts_AllowedHostPassesThrough covers the
// "staging-only profile + staging host" happy path: the connection
// MUST NOT be denied. The glob `*.staging.internal` matches any
// subdomain of `.staging.internal`.
func TestProfile_OnlyHosts_AllowedHostPassesThrough(t *testing.T) {
	p := &Profile{
		Name:      "staging-only",
		OnlyHosts: []string{"*.staging.internal"},
	}
	v := p.EvaluateConnection("db.staging.internal", "main")
	assert.False(t, v.Denied, "db.staging.internal must match *.staging.internal glob")
	assert.Empty(t, v.DenyReason)
}

// TestProfile_OnlyHosts_NonMatchingHostDenied is the load-bearing
// regression for §A40 — same `staging-only` profile MUST refuse a
// prod-shaped host even though the proxy is otherwise pointed at the
// upstream. This is the canonical "founder accidentally swapped
// --upstream to prod" scenario.
func TestProfile_OnlyHosts_NonMatchingHostDenied(t *testing.T) {
	p := &Profile{
		Name:      "staging-only",
		OnlyHosts: []string{"*.staging.*"},
	}
	v := p.EvaluateConnection("prod.db.internal", "main")
	assert.True(t, v.Denied, "prod.db.internal must NOT match *.staging.* glob")
	assert.Equal(t, DenyReasonOnlyHosts, v.DenyReason)
	assert.Equal(t, "staging-only", v.ProfileName)
	assert.Contains(t, v.Reason, "prod.db.internal")
	assert.Contains(t, v.Reason, "only_hosts")
}

// TestProfile_OnlyDatabases_AllowedDatabasePassesThrough covers the
// "analytics-only profile + analytics DB" happy path.
func TestProfile_OnlyDatabases_AllowedDatabasePassesThrough(t *testing.T) {
	p := &Profile{
		Name:          "analytics-only",
		OnlyDatabases: []string{"analytics"},
	}
	v := p.EvaluateConnection("db.internal", "analytics")
	assert.False(t, v.Denied)
}

// TestProfile_OnlyDatabases_NonMatchingDatabaseDenied: same
// `analytics-only` profile MUST refuse the billing DB.
func TestProfile_OnlyDatabases_NonMatchingDatabaseDenied(t *testing.T) {
	p := &Profile{
		Name:          "analytics-only",
		OnlyDatabases: []string{"analytics"},
	}
	v := p.EvaluateConnection("db.internal", "billing")
	assert.True(t, v.Denied)
	assert.Equal(t, DenyReasonOnlyDatabases, v.DenyReason)
	assert.Equal(t, "analytics-only", v.ProfileName)
	assert.Contains(t, v.Reason, "billing")
	assert.Contains(t, v.Reason, "only_databases")
}

// TestProfile_OnlyHosts_Wildcard_LeadingStar covers `*.staging.internal`.
func TestProfile_OnlyHosts_Wildcard_LeadingStar(t *testing.T) {
	p := &Profile{
		Name:      "staging-only",
		OnlyHosts: []string{"*.staging.internal"},
	}
	cases := []struct {
		host    string
		allowed bool
	}{
		{"staging.staging.internal", true},
		{"a.staging.internal", true},
		{"deep.nested.staging.internal", true},
		{"staging.internal", false},
		{"prod.staging.com", false},
		{"prod.internal", false},
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			v := p.EvaluateConnection(c.host, "main")
			if c.allowed {
				assert.False(t, v.Denied, "%q should be allowed", c.host)
			} else {
				assert.True(t, v.Denied, "%q should be denied", c.host)
			}
		})
	}
}

// TestProfile_OnlyHosts_Wildcard_MiddleStar covers `db.*.internal`.
func TestProfile_OnlyHosts_Wildcard_MiddleStar(t *testing.T) {
	p := &Profile{
		Name:      "scoped",
		OnlyHosts: []string{"db.*.internal"},
	}
	v := p.EvaluateConnection("db.staging.internal", "main")
	assert.False(t, v.Denied)
	v = p.EvaluateConnection("db.prod.internal", "main")
	assert.False(t, v.Denied, "middle-star matches any segment")
	v = p.EvaluateConnection("api.staging.internal", "main")
	assert.True(t, v.Denied, "prefix must match exactly")
}

// TestProfile_OnlyHosts_ExactMatch covers a literal hostname with no
// glob metacharacters.
func TestProfile_OnlyHosts_ExactMatch(t *testing.T) {
	p := &Profile{
		Name:      "single-host",
		OnlyHosts: []string{"staging.db.internal"},
	}
	v := p.EvaluateConnection("staging.db.internal", "main")
	assert.False(t, v.Denied)
	v = p.EvaluateConnection("staging.db.internal.evil.com", "main")
	assert.True(t, v.Denied, "literal must not match a longer suffix")
	v = p.EvaluateConnection("evil.staging.db.internal", "main")
	assert.True(t, v.Denied, "literal must not match a longer prefix")
}

// TestProfile_OnlyHosts_CaseInsensitive covers RFC 1035 hostname
// case-insensitivity — `*.STAGING.*` must match `prod.staging.com`.
func TestProfile_OnlyHosts_CaseInsensitive(t *testing.T) {
	p := &Profile{
		Name:      "case-test",
		OnlyHosts: []string{"*.STAGING.*"},
	}
	v := p.EvaluateConnection("prod.staging.com", "main")
	assert.False(t, v.Denied, "glob match must be case-insensitive")
}

// TestProfile_OnlyHosts_MultipleGlobs_AnyMatchAllows tests that a
// list of globs is OR-matched (any single match allows).
func TestProfile_OnlyHosts_MultipleGlobs_AnyMatchAllows(t *testing.T) {
	p := &Profile{
		Name:      "multi-staging",
		OnlyHosts: []string{"*.staging.internal", "*.staging.local"},
	}
	v := p.EvaluateConnection("db.staging.internal", "main")
	assert.False(t, v.Denied)
	v = p.EvaluateConnection("db.staging.local", "main")
	assert.False(t, v.Denied)
	v = p.EvaluateConnection("db.prod.internal", "main")
	assert.True(t, v.Denied, "neither glob matches prod")
}

// TestProfile_OnlyHosts_EmptyHost_NonEmptyAllowlist_Denies covers
// the fail-closed shape: a missing host with a non-empty allowlist
// MUST refuse. Loud failure beats silent permit.
func TestProfile_OnlyHosts_EmptyHost_NonEmptyAllowlist_Denies(t *testing.T) {
	p := &Profile{
		Name:      "scoped",
		OnlyHosts: []string{"*.staging.*"},
	}
	v := p.EvaluateConnection("", "main")
	assert.True(t, v.Denied, "empty host with non-empty allowlist MUST fail closed")
}

// TestProfile_EmptyOnlyHosts_NoRestriction is the backward-compat
// invariant — pre-§A40 profiles without these fields MUST continue
// to allow every host.
func TestProfile_EmptyOnlyHosts_NoRestriction(t *testing.T) {
	p := &Profile{
		Name: "legacy",
	}
	v := p.EvaluateConnection("any.host.com", "any-db")
	assert.False(t, v.Denied, "empty allowlist = backward-compat: no restriction")
}

// TestProfile_FullUser_AlwaysAbstainsOnConnection mirrors the
// Evaluate full-user abstain behavior — even if someone sets
// OnlyHosts on the full-user sentinel, the EvaluateConnection path
// MUST abstain.
func TestProfile_FullUser_AlwaysAbstainsOnConnection(t *testing.T) {
	p := &Profile{
		Name:      FullUserProfileName,
		OnlyHosts: []string{"*.staging.*"},
	}
	v := p.EvaluateConnection("prod.db.com", "main")
	assert.False(t, v.Denied, "full-user MUST always abstain regardless of fields")
}

// TestProfile_NilReceiver_Abstains covers the nil-safe contract.
func TestProfile_NilReceiver_Abstains(t *testing.T) {
	var p *Profile
	v := p.EvaluateConnection("any.host", "db")
	assert.False(t, v.Denied)
}

// TestProfile_OnlyHosts_PortStrippedByCaller — the contract is that
// the CALLER strips the port; EvaluateConnection compares against
// the bare hostname. If a port slips through, the glob almost
// certainly won't match. Documenting via test.
func TestProfile_OnlyHosts_PortStrippedByCaller(t *testing.T) {
	p := &Profile{
		Name:      "scoped",
		OnlyHosts: []string{"*.staging.internal"},
	}
	// Caller bug: port included in host. The bare-hostname glob
	// should NOT match — this is the load-bearing contract for
	// callers (Forwarder.HostnameOnly() in proxy/forward.go).
	v := p.EvaluateConnection("db.staging.internal:5432", "main")
	assert.True(t, v.Denied, "callers MUST strip port before EvaluateConnection")
}

// TestProfile_OnlyHostsAndOnlyDatabases_BothMatchAllows checks
// the AND semantics — both lists must succeed to allow.
func TestProfile_OnlyHostsAndOnlyDatabases_BothMatchAllows(t *testing.T) {
	p := &Profile{
		Name:          "scoped",
		OnlyHosts:     []string{"*.staging.*"},
		OnlyDatabases: []string{"analytics"},
	}
	v := p.EvaluateConnection("db.staging.internal", "analytics")
	assert.False(t, v.Denied, "both match -> allow")
}

// TestProfile_OnlyHostsAndOnlyDatabases_OneFailsDenies ensures
// either-side failure denies.
func TestProfile_OnlyHostsAndOnlyDatabases_OneFailsDenies(t *testing.T) {
	p := &Profile{
		Name:          "scoped",
		OnlyHosts:     []string{"*.staging.*"},
		OnlyDatabases: []string{"analytics"},
	}
	// Host fails.
	v := p.EvaluateConnection("db.prod.internal", "analytics")
	assert.True(t, v.Denied)
	assert.Equal(t, DenyReasonOnlyHosts, v.DenyReason, "host fails first")
	// Host OK, database fails.
	v = p.EvaluateConnection("db.staging.internal", "billing")
	assert.True(t, v.Denied)
	assert.Equal(t, DenyReasonOnlyDatabases, v.DenyReason)
}

// TestProfileYAML_RoundTrip_OnlyHostsAndOnlyDatabases verifies
// UnmarshalYAML round-trips the new fields.
func TestProfileYAML_RoundTrip_OnlyHostsAndOnlyDatabases(t *testing.T) {
	src := `
description: staging-only scope
only_hosts:
  - "*.staging.internal"
  - "*.staging.local"
only_databases:
  - "main"
  - "analytics*"
`
	var p Profile
	require.NoError(t, yaml.Unmarshal([]byte(src), &p))
	assert.Equal(t, []string{"*.staging.internal", "*.staging.local"}, p.OnlyHosts)
	assert.Equal(t, []string{"main", "analytics*"}, p.OnlyDatabases)
	assert.Equal(t, "staging-only scope", p.Description)

	// Round-trip back to YAML + re-parse.
	out, err := yaml.Marshal(&p)
	require.NoError(t, err)
	var p2 Profile
	require.NoError(t, yaml.Unmarshal(out, &p2))
	assert.Equal(t, p.OnlyHosts, p2.OnlyHosts)
	assert.Equal(t, p.OnlyDatabases, p2.OnlyDatabases)
}

// TestProfileYAML_BackwardCompat_OmitOnlyFields ensures legacy
// profile YAML without `only_hosts:` / `only_databases:` round-trips
// with zero-valued fields.
func TestProfileYAML_BackwardCompat_OmitOnlyFields(t *testing.T) {
	src := `
description: legacy
deny_keywords:
  - prod
`
	var p Profile
	require.NoError(t, yaml.Unmarshal([]byte(src), &p))
	assert.Empty(t, p.OnlyHosts)
	assert.Empty(t, p.OnlyDatabases)
	assert.Equal(t, []string{"prod"}, p.DenyKeywords)
}

// TestLoadProfiles_OnlyHostsRoundTrip ensures the full
// profileFile/Profiles loader path round-trips the new fields.
func TestLoadProfiles_OnlyHostsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	doc := `profiles:
  staging-only:
    description: scoped to staging
    only_hosts:
      - "*.staging.internal"
    only_databases:
      - "main"
`
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))
	ps, err := LoadProfiles(path)
	require.NoError(t, err)
	p, err := ps.Active("staging-only")
	require.NoError(t, err)
	assert.Equal(t, []string{"*.staging.internal"}, p.OnlyHosts)
	assert.Equal(t, []string{"main"}, p.OnlyDatabases)
}

// TestProfileInstall_FromGeneratorShape_WithOnlyHosts anticipates
// §A38: the generator may emit `only_hosts` / `only_databases` in
// either the canonical shape OR the generator-shape body. We accept
// the canonical-shape top-level fields (the generator-shim merge
// path is for denies/allows lists; scope fields are passed through
// by the rawProfile decoder).
func TestProfileInstall_FromGeneratorShape_WithOnlyHosts(t *testing.T) {
	// Simulate a generator-emitted dbounce.yaml that includes BOTH
	// generator-shape `denies:` AND canonical `only_hosts:` —
	// realistic for §A38 (generator infers the host scope from the
	// audit log's observed connection endpoints + emits both).
	src := `
profile_name: generated-staging-only
bouncer: dbounce
provenance:
  source: audit-derived
only_hosts:
  - "*.staging.internal"
only_databases:
  - "main"
denies:
  - sql_patterns:
      - DROP DATABASE prod
    reason: prod database name is denylisted
`
	var p Profile
	require.NoError(t, yaml.Unmarshal([]byte(src), &p))
	assert.Equal(t, []string{"*.staging.internal"}, p.OnlyHosts)
	assert.Equal(t, []string{"main"}, p.OnlyDatabases)
	// Generator-shape `denies:` is still merged through the shim
	// (the canonical-shape `deny_keywords:` field now contains the
	// extracted identifier tokens). prod is the only non-reserved
	// token in `DROP DATABASE prod`.
	assert.Contains(t, p.DenyKeywords, "prod")
}

// TestProfileInstall_FromGeneratorShape_OnlyHostsAlone ensures a
// generator emission that contains ONLY scope fields (no
// denies/allows yet) parses correctly.
func TestProfileInstall_FromGeneratorShape_OnlyHostsAlone(t *testing.T) {
	src := `
profile_name: generated-scope-only
bouncer: dbounce
only_hosts:
  - "*.staging.internal"
`
	var p Profile
	require.NoError(t, yaml.Unmarshal([]byte(src), &p))
	assert.Equal(t, []string{"*.staging.internal"}, p.OnlyHosts)
	assert.Empty(t, p.DenyKeywords, "no denies → no keywords merged")
}

// TestProfile_OnlyHosts_BlankGlobIgnored covers a defensive case:
// a YAML with an accidental empty-string glob entry shouldn't make
// every host match.
func TestProfile_OnlyHosts_BlankGlobIgnored(t *testing.T) {
	p := &Profile{
		Name:      "scoped",
		OnlyHosts: []string{"  ", "*.staging.*"},
	}
	v := p.EvaluateConnection("prod.internal", "main")
	assert.True(t, v.Denied, "blank glob entries MUST NOT match any host")
}

// TestProfile_OnlyDatabases_QuestionMarkGlob covers `?` (single char).
func TestProfile_OnlyDatabases_QuestionMarkGlob(t *testing.T) {
	p := &Profile{
		Name:          "scoped",
		OnlyDatabases: []string{"db?"},
	}
	v := p.EvaluateConnection("h", "db1")
	assert.False(t, v.Denied)
	v = p.EvaluateConnection("h", "db")
	assert.True(t, v.Denied, "? requires exactly one char")
	v = p.EvaluateConnection("h", "db12")
	assert.True(t, v.Denied, "? requires exactly one char")
}


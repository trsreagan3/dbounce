package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
)

// LOW-D8-13 (AUDIT-WB-DSLICES-1-8.md) closure tests: --quiet-banner
// must reduce the startup banner to address + dialect only, dropping
// every fingerprint-sensitive field. The fully-rendered banner is also
// tested so a regression that silently shipped the non-quiet shape
// under --quiet-banner would fail loudly.

func bannerCfg() proxy.Config {
	return proxy.Config{
		Host:          "127.0.0.1",
		Port:          5433,
		MgmtHost:      "127.0.0.1",
		MgmtPort:      8768,
		Mode:          proxy.ModeCooperative,
		DefaultPolicy: proxy.DefaultPolicyDeny,
		Dialect:       proxy.DialectPostgres,
	}.Normalize()
}

func TestWriteStartupBanner_Full_IncludesAllFields(t *testing.T) {
	var buf bytes.Buffer
	writeStartupBanner(&buf, bannerOpts{
		Cfg:                  bannerCfg(),
		StoredAuditDBPath:    "/tmp/state.db",
		ActiveProfileName:    "safe-default",
		ResolvedProfilesPath: "/etc/dbounce/profiles.yaml",
		ProfileFromFlag:      true,
		Quiet:                false,
	})
	got := buf.String()
	// Sanity: every field the audit doc flagged as fingerprint-leak
	// IS present in the full banner.
	for _, want := range []string{
		"wire listener",
		"mode=cooperative",
		"default-policy=deny",
		"dialect=postgres",
		"audit db",
		"/tmp/state.db",
		"profile               : safe-default",
		"/healthz",
		"mode                  :",
		"read vs write",
		"Ctrl+C to stop.",
	} {
		assert.Contains(t, got, want,
			"non-quiet banner MUST include %q", want)
	}
}

func TestWriteStartupBanner_Quiet_SuppressesFingerprintFields(t *testing.T) {
	var buf bytes.Buffer
	writeStartupBanner(&buf, bannerOpts{
		Cfg:                  bannerCfg(),
		StoredAuditDBPath:    "/tmp/state.db",
		ActiveProfileName:    "safe-default",
		ResolvedProfilesPath: "/etc/dbounce/profiles.yaml",
		ProfileFromFlag:      true,
		Quiet:                true,
	})
	got := buf.String()

	// What MUST be present in quiet mode: address + dialect + transport
	// + Ctrl+C cue.
	for _, want := range []string{
		"wire listener",
		"127.0.0.1:5433",
		"dialect=postgres",
		"transport=tcp",
		"Ctrl+C to stop.",
	} {
		assert.Contains(t, got, want,
			"quiet banner MUST include %q", want)
	}

	// What MUST NOT be present in quiet mode (the audit-flagged
	// fingerprint fields).
	for _, leaky := range []string{
		"mode=cooperative",
		"default-policy=deny",
		"safe-default",                  // active profile name
		"/tmp/state.db",                 // audit db path
		"/etc/dbounce/profiles.yaml",    // profiles path
		"D-Slice 1 is OBSERVATION-ONLY", // read-vs-write framing
		"audit db",
	} {
		assert.NotContains(t, got, leaky,
			"quiet banner MUST suppress %q (LOW-D8-13)", leaky)
	}
}

func TestWriteStartupBanner_Quiet_ExplicitHealthzNote(t *testing.T) {
	// The quiet-banner /healthz line MUST tell the operator that the
	// full config is still reachable via the management endpoint — so
	// nobody reads the minimal banner and concludes the gate is
	// degraded.
	var buf bytes.Buffer
	writeStartupBanner(&buf, bannerOpts{
		Cfg:               bannerCfg(),
		StoredAuditDBPath: "/tmp/state.db",
		Quiet:             true,
	})
	assert.Contains(t, buf.String(),
		"full configuration available via /healthz",
		"quiet banner MUST note that /healthz still exposes the full config")
}

// UC-34 admin-tight startup warning. Per MRR-1 audit (commit 7d69e68):
// PostgreSQL handler + no admin-grant allow_rules in the active
// profile → WARNING line emitted at startup. Without this hint
// operators are surprised when their first GRANT is denied by the
// admin-tight floor.

func TestStartupWarningEmittedForPostgresWithoutAdminGrantRules(t *testing.T) {
	// Profile with NO allow_rule matching GRANT → warning must fire.
	emptyProfile := &profile.Profile{Name: "test-empty"}
	var buf bytes.Buffer
	writeStartupBanner(&buf, bannerOpts{
		Cfg:                  bannerCfg(),
		StoredAuditDBPath:    "/tmp/state.db",
		ActiveProfileName:    "test-empty",
		ResolvedProfilesPath: "/etc/dbounce/profiles.yaml",
		ProfileFromFlag:      true,
		Quiet:                false,
		ActiveProfile:        emptyProfile,
	})
	got := buf.String()
	assert.Contains(t, got, "WARNING:",
		"PostgreSQL + no admin-grant rules MUST emit a WARNING line")
	assert.Contains(t, got, "admin-grant rules in profile",
		"warning text must name admin-grant rules")
	assert.Contains(t, got, "GRANT / ALTER DEFAULT PRIVILEGES",
		"warning must name the affected statement types so operators know what to expect")
	assert.Contains(t, got, "REVOKE is unaffected",
		"warning must clarify REVOKE is NOT denied (cleanup direction)")
	assert.Contains(t, got, "dbounce rules add 'GRANT:*' --effect allow",
		"warning must show the override-rule one-liner so operators have the fix")
}

func TestStartupWarningSuppressedWhenProfileAllowsGrant(t *testing.T) {
	// Profile with GRANT:* allow_rule → warning suppressed (operator
	// already wired the override).
	pwithGrant := &profile.Profile{
		Name: "test-with-grant",
		AllowRules: []profile.ProfileAllowRule{
			{Pattern: "GRANT:*", Note: "admin DCL allowed"},
		},
	}
	var buf bytes.Buffer
	writeStartupBanner(&buf, bannerOpts{
		Cfg:                  bannerCfg(),
		StoredAuditDBPath:    "/tmp/state.db",
		ActiveProfileName:    "test-with-grant",
		ResolvedProfilesPath: "/etc/dbounce/profiles.yaml",
		ProfileFromFlag:      true,
		Quiet:                false,
		ActiveProfile:        pwithGrant,
	})
	assert.NotContains(t, buf.String(), "WARNING:",
		"profile with GRANT:* allow_rule MUST suppress the admin-grant warning")
}

func TestStartupWarningSuppressedWhenProfileWildcardAllow(t *testing.T) {
	// Profile with a bare wildcard allow_rule → warning suppressed
	// (the * matches GRANT among everything else).
	pwithStar := &profile.Profile{
		Name: "test-wildcard",
		AllowRules: []profile.ProfileAllowRule{
			{Pattern: "*"},
		},
	}
	var buf bytes.Buffer
	writeStartupBanner(&buf, bannerOpts{
		Cfg:                  bannerCfg(),
		StoredAuditDBPath:    "/tmp/state.db",
		ActiveProfileName:    "test-wildcard",
		ResolvedProfilesPath: "/etc/dbounce/profiles.yaml",
		ProfileFromFlag:      true,
		Quiet:                false,
		ActiveProfile:        pwithStar,
	})
	assert.NotContains(t, buf.String(), "WARNING:",
		"profile with wildcard allow_rule MUST suppress the admin-grant warning")
}

func TestStartupWarningQuietSuppresses(t *testing.T) {
	// --quiet-banner mode → warning suppressed alongside the rest of
	// the banner content. /healthz still surfaces the floor state.
	emptyProfile := &profile.Profile{Name: "test-empty"}
	var buf bytes.Buffer
	writeStartupBanner(&buf, bannerOpts{
		Cfg:                  bannerCfg(),
		StoredAuditDBPath:    "/tmp/state.db",
		ActiveProfileName:    "test-empty",
		ResolvedProfilesPath: "/etc/dbounce/profiles.yaml",
		ProfileFromFlag:      true,
		Quiet:                true,
		ActiveProfile:        emptyProfile,
	})
	assert.NotContains(t, buf.String(), "WARNING:",
		"--quiet-banner MUST suppress the admin-grant warning (opt-in suppression)")
}

func TestStartupWarningSuppressedWhenNilProfile(t *testing.T) {
	// Defensive: a nil ActiveProfile (banner can't introspect) →
	// warning suppressed. Better to emit no hint than a misleading one.
	var buf bytes.Buffer
	writeStartupBanner(&buf, bannerOpts{
		Cfg:                  bannerCfg(),
		StoredAuditDBPath:    "/tmp/state.db",
		ActiveProfileName:    "unknown",
		ResolvedProfilesPath: "/etc/dbounce/profiles.yaml",
		ProfileFromFlag:      true,
		Quiet:                false,
		ActiveProfile:        nil,
	})
	assert.NotContains(t, buf.String(), "WARNING:",
		"nil ActiveProfile MUST suppress the admin-grant warning (indeterminate state)")
}

func TestStartupWarningSuppressedForNonPostgresDialect(t *testing.T) {
	// MySQL dialect → no warning (MySQL classifier doesn't surface DCL
	// yet; separate follow-up task). The floor only applies to PG.
	cfg := bannerCfg()
	cfg.Dialect = proxy.DialectMySQL
	emptyProfile := &profile.Profile{Name: "test-empty"}
	var buf bytes.Buffer
	writeStartupBanner(&buf, bannerOpts{
		Cfg:                  cfg,
		StoredAuditDBPath:    "/tmp/state.db",
		ActiveProfileName:    "test-empty",
		ResolvedProfilesPath: "/etc/dbounce/profiles.yaml",
		ProfileFromFlag:      true,
		Quiet:                false,
		ActiveProfile:        emptyProfile,
	})
	assert.NotContains(t, buf.String(), "WARNING:",
		"non-PostgreSQL dialect MUST suppress the admin-grant warning (MySQL DCL classifier is a follow-up task)")
}

func TestWriteStartupBanner_Full_UpstreamObservationOnlyNote(t *testing.T) {
	// Sanity for the no-upstream observation-only path that the full
	// banner still emits clearly. Not a fingerprint suppression issue —
	// here we just guard against a regression in the existing wording.
	var buf bytes.Buffer
	writeStartupBanner(&buf, bannerOpts{
		Cfg:                  bannerCfg(),
		StoredAuditDBPath:    "/tmp/state.db",
		ActiveProfileName:    "full-user",
		ResolvedProfilesPath: "/etc/dbounce/profiles.yaml",
		ProfileFromFlag:      false,
		ProfileEnvSet:        false,
		Quiet:                false,
	})
	got := buf.String()
	assert.Contains(t, got, "observation-only mode")
	assert.Contains(t, got, "no --profile / DBOUNCE_PROFILE set",
		"non-quiet banner must surface the 'no profile selected' hint when neither flag nor env is set")
}

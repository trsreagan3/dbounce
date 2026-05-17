package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

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

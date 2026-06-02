// #252 Slice 1 CLI-side tests: license-gate, license-gate-overridable
// (for tests in production code paths), token-not-in-banner, and the
// buildAuditExporter integration.

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/proxy"
)

// TestBuildAuditExporter_NoFlags_ReturnsNilNil verifies the FREE-tier
// default — no audit-export wired.
func TestBuildAuditExporter_NoFlags_ReturnsNilNil(t *testing.T) {
	e, err := buildAuditExporter("", false, -1, -1, -1, "", "", 0, false, "", "", "", "", 0, 0, 0, "127.0.0.1:5433", "", "", "", "", "", 0, "", "", "", "", "", 0, 0, "", false)
	require.NoError(t, err)
	assert.Nil(t, e, "no audit-export flags = no exporter (FREE-tier default)")
}

// TestBuildAuditExporter_LogOnly_FreeTier exercises the JSONL log
// transport which is available on ALL tiers without a license check.
func TestBuildAuditExporter_LogOnly_FreeTier(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	e, err := buildAuditExporter(path, false, -1, -1, -1, "", "", 0, false, "", "", "", "", 0, 0, 0, "127.0.0.1:5433", "", "", "", "", "", 0, "", "", "", "", "", 0, 0, "", false)
	require.NoError(t, err, "log-only transport must work without a license (FREE tier)")
	require.NotNil(t, e)
	require.True(t, e.Enabled())
	require.NoError(t, e.Shutdown(context.Background()))
}

// TestBuildAuditExporter_WebhookGateReinstateableForV1_1: the
// license-gate function (licensedForAuditWebhook) is retained at
// v1.0 per [[oss-only-launch-decision]] as the future-reinstate
// hook for the v1.1+ paid tier. This test PINS the reinstate path
// by overriding the function with a rejecting closure + asserting
// the error propagates through buildAuditExporter unchanged. When
// v1.1 launches, swapping the default-implementation back to a
// rejecting closure (gated on actual license-file verification)
// re-enables paid-tier enforcement without touching the call sites.
func TestBuildAuditExporter_WebhookGateReinstateableForV1_1(t *testing.T) {
	prev := licensedForAuditWebhook
	licensedForAuditWebhook = func() error {
		return errors.New(
			"--audit-webhook-url requires an Enterprise license " +
				"(simulated v1.1+ paid-tier rejection: dbounce's " +
				"license-file plumbing rejected the request; #235)")
	}
	t.Cleanup(func() { licensedForAuditWebhook = prev })

	_, err := buildAuditExporter("", false, -1, -1, -1, "https://collector.example.com/audit", "some-token", 1, false,
		"", "", "",
		"", // alertRoutesPath
		0, 0, 0,
		"127.0.0.1:5433", "", "", "", "", "", 0, "", "", "", "", "", 0, 0, "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Enterprise license",
		"reinstate path: the rejecting closure's error must propagate")
	assert.Contains(t, err.Error(), "#235",
		"reinstate path: the closure's #235 reference must propagate")
}

// TestBuildAuditExporter_WebhookNoLicenseShipsFree pins the v1.0
// OSS-only behavior per [[oss-only-launch-decision]]: with the
// default (now no-op) licensedForAuditWebhook gate, --audit-webhook-url
// constructs cleanly without a license-file present. The downstream
// failure (if any) must NOT mention licensing — confirming the
// calibration claim that the webhook ships free at v1.0.
func TestBuildAuditExporter_WebhookNoLicenseShipsFree(t *testing.T) {
	// Use the DEFAULT license-gate (no override) — proves the
	// default-implementation no longer rejects per
	// [[oss-only-launch-decision]].
	_, err := buildAuditExporter("", false, -1, -1, -1, "https://93.184.216.34/audit", "test-token", 1, false,
		"", "", "",
		"", // alertRoutesPath
		0, 0, 0,
		"127.0.0.1:5433", "", "", "", "", "", 0, "", "", "", "", "", 0, 0, "", false)
	if err != nil {
		// Downstream IO failures are acceptable (the SSRF / DNS / TLS
		// guards are orthogonal to licensing). The calibration
		// assertion is the error MUST NOT mention licensing — that
		// would prove the gate is still active.
		assert.NotContains(t, err.Error(), "Enterprise license",
			"v1.0 OSS-only disable: webhook construction must not produce a license error")
		assert.NotContains(t, err.Error(), "license", // belt-and-suspenders
			"v1.0 OSS-only disable: webhook construction must not mention licensing")
		t.Logf("webhook downstream failure (expected; not a license error): %v", err)
		return
	}
	// If construction succeeds outright, that's also a valid pass —
	// the SSRF gate may have allowed the public IP.
}

// TestBuildAuditExporter_WebhookWithLicenseOverride: when the license
// gate returns nil (production after #235), the webhook transport is
// constructed normally.
func TestBuildAuditExporter_WebhookWithLicenseOverride(t *testing.T) {
	prev := licensedForAuditWebhook
	licensedForAuditWebhook = func() error { return nil }
	t.Cleanup(func() { licensedForAuditWebhook = prev })

	// Use a public IP literal that passes the SSRF gate.
	e, err := buildAuditExporter("", false, -1, -1, -1, "https://93.184.216.34/audit", "test-token", 1, false,
		"", "", "",
		"", // alertRoutesPath
		0, 0, 0,
		"127.0.0.1:5433", "", "", "", "", "", 0, "", "", "", "", "", 0, 0, "", false)
	require.NoError(t, err)
	require.NotNil(t, e)
	require.True(t, e.Enabled())
	require.NoError(t, e.Shutdown(context.Background()))
}

// TestBuildAuditExporter_AlertRoutesNoLicenseShipsFree pins the v1.0
// OSS-only behavior per [[oss-only-launch-decision]]: the #280 per-org
// routing engine ships FREE at v1.0. Writes a minimal valid routes.yaml
// + asserts the routes engine constructs cleanly + the Exporter wires
// it (exp.Routes != nil).
func TestBuildAuditExporter_AlertRoutesNoLicenseShipsFree(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AUDIT_NLSF_TOKEN", "test-token")
	routesYAML := `routes:
  - name: all-events
    match: {}
    destinations:
      - webhook:
          url: https://93.184.216.34/audit
          token: ${AUDIT_NLSF_TOKEN}
`
	routesPath := filepath.Join(dir, "routes.yaml")
	require.NoError(t, os.WriteFile(routesPath, []byte(routesYAML), 0o600))

	exp, err := buildAuditExporter(filepath.Join(dir, "audit.jsonl"), false, -1, -1, -1, "", "", 0, false,
		"", "", "",
		routesPath,
		0, 0, 0,
		"127.0.0.1:5433", "", "", "", "", "", 0, "", "", "", "", "", 0, 0, "", false)
	require.NoError(t, err,
		"--alert-routes ships FREE at v1.0 per [[oss-only-launch-decision]]")
	require.NotNil(t, exp)
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })
}

// TestAudit_LicenseSentinelsStillExported pins that the license error
// sentinels stay exported at v1.0 — they're the v1.1+ paid-tier
// reinstate hook per [[oss-only-launch-decision]].
func TestAudit_LicenseSentinelsStillExported(t *testing.T) {
	require.NotNil(t, audit.ErrRoutesLicenseRequired,
		"sentinel must stay exported; future paid tier reinstates via this symbol")
	require.NotEmpty(t, audit.ErrRoutesLicenseRequired.Error())
}

// TestRunCmdRegistersAlertRoutesFlag confirms the #280 --alert-routes
// flag is registered on `dbounce run`. Cross-product parity (ibounce
// + kbouncer) ships the same flag name + YAML schema.
func TestRunCmdRegistersAlertRoutesFlag(t *testing.T) {
	cmd := newRunCmd()
	require.NotNil(t, cmd.Flags().Lookup("alert-routes"),
		"--alert-routes flag must be registered on `dbounce run`")
}

// TestBuildAuditExporter_TokenWithoutURL_Rejected: token without a URL
// is almost certainly a typo / forgotten flag; fail-fast.
func TestBuildAuditExporter_TokenWithoutURL_Rejected(t *testing.T) {
	_, err := buildAuditExporter("", false, -1, -1, -1, "", "stray-token", 0, false,
		"", "", "",
		"", // alertRoutesPath
		0, 0, 0,
		"127.0.0.1:5433", "", "", "", "", "", 0, "", "", "", "", "", 0, 0, "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--audit-webhook-token")
}

// TestStartupBanner_TokenNeverPresent: the spec requires the bearer
// token to NEVER appear in the startup banner. Build an Exporter
// with a known-distinctive token + render the banner + scan the
// captured output.
func TestStartupBanner_TokenNeverPresent(t *testing.T) {
	const tok = "banner-leak-canary-token-72631"

	prev := licensedForAuditWebhook
	licensedForAuditWebhook = func() error { return nil }
	t.Cleanup(func() { licensedForAuditWebhook = prev })

	dir := t.TempDir()
	e, err := buildAuditExporter(
		filepath.Join(dir, "audit.jsonl"), false,
		-1, -1, -1,
		"https://93.184.216.34/audit", tok, 1, false,
		"", "", "",
		"", // alertRoutesPath
		0, 0, 0,
		"127.0.0.1:5433", "", "", "", "", "", 0,
		"", "", "", "", "", 0, 0, "", false)
	require.NoError(t, err)
	require.NotNil(t, e)
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })

	var buf bytes.Buffer
	writeStartupBanner(&buf, bannerOpts{
		Cfg: proxy.Config{
			Host:    "127.0.0.1",
			Port:    5433,
			Dialect: proxy.DialectPostgres,
			Mode:    proxy.ModeCooperative,
		}.Normalize(),
		StoredAuditDBPath:    "/tmp/test.db",
		ActiveProfileName:    "full-user",
		ResolvedProfilesPath: "/tmp/profiles.yaml",
		AuditExporter:        e,
	})

	out := buf.String()
	assert.NotContains(t, out, tok,
		"startup banner MUST NEVER contain the webhook bearer token; got:\n%s", out)
	// But the audit-export lines SHOULD be visible.
	assert.Contains(t, out, "audit-export log",
		"banner should show the audit-export log line so the operator can verify it's wired")
	assert.Contains(t, out, "audit-export webhook",
		"banner should show the audit-export webhook line so the operator can verify it's wired")
	assert.Contains(t, out, "token masked",
		"banner webhook line should explicitly state the token is masked (operator confidence)")
}

// TestStartupBanner_NoExporter_NoAuditLines: when no audit-export is
// wired, the banner must NOT include the audit-export lines (avoid
// implying a feature is active when it isn't).
func TestStartupBanner_NoExporter_NoAuditLines(t *testing.T) {
	var buf bytes.Buffer
	writeStartupBanner(&buf, bannerOpts{
		Cfg: proxy.Config{
			Host:    "127.0.0.1",
			Port:    5433,
			Dialect: proxy.DialectPostgres,
			Mode:    proxy.ModeCooperative,
		}.Normalize(),
		StoredAuditDBPath:    "/tmp/test.db",
		ActiveProfileName:    "full-user",
		ResolvedProfilesPath: "/tmp/profiles.yaml",
	})
	out := buf.String()
	assert.NotContains(t, out, "audit-export log")
	assert.NotContains(t, out, "audit-export webhook")
}

// TestAuditEventSchemaVersion_PinsToOCSF1_1_0 pins the cross-product
// schema version to OCSF v1.1.0 per [[ocsf-audit-schema]]. Sibling
// agents in ibounce/kbounce MUST emit "1.1.0" too. Bumping requires a
// coordinated cross-product change AND a SIEM-mapping review (OCSF
// minor-version bumps may add required fields).
func TestAuditEventSchemaVersion_PinsToOCSF1_1_0(t *testing.T) {
	assert.Equal(t, "1.1.0", audit.SchemaVersion,
		"schema version is a cross-product OCSF contract; bumping requires all three Bounce products to bump together")
	// Also guard the product name + vendor so a refactor doesn't
	// silently change what downstream SIEM dashboards see.
	assert.Equal(t, "dbounce", audit.Product)
	assert.Equal(t, "iam-jit", audit.VendorName)
}

// Make sure the test file's strings import is used even if a future
// refactor drops the only string assertion.
var _ = strings.Contains

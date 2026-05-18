// #252 Slice 1 CLI-side tests: license-gate, license-gate-overridable
// (for tests in production code paths), token-not-in-banner, and the
// buildAuditExporter integration.

package cli

import (
	"bytes"
	"context"
	"errors"
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
	e, err := buildAuditExporter("", false, "", "", 0, false, "", "", "", 0, 0, "127.0.0.1:5433", "")
	require.NoError(t, err)
	assert.Nil(t, e, "no audit-export flags = no exporter (FREE-tier default)")
}

// TestBuildAuditExporter_LogOnly_FreeTier exercises the JSONL log
// transport which is available on ALL tiers without a license check.
func TestBuildAuditExporter_LogOnly_FreeTier(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	e, err := buildAuditExporter(path, false, "", "", 0, false, "", "", "", 0, 0, "127.0.0.1:5433", "")
	require.NoError(t, err, "log-only transport must work without a license (FREE tier)")
	require.NotNil(t, e)
	require.True(t, e.Enabled())
	require.NoError(t, e.Shutdown(context.Background()))
}

// TestBuildAuditExporter_WebhookWithoutLicense_Rejected: the placeholder
// license gate must reject --audit-webhook-url + error must point at
// the FREE-tier fallback + the #235 issue.
func TestBuildAuditExporter_WebhookWithoutLicense_Rejected(t *testing.T) {
	// Make sure we're using the default (rejecting) license gate.
	prev := licensedForAuditWebhook
	licensedForAuditWebhook = func() error {
		return errors.New(
			"--audit-webhook-url requires an Enterprise license " +
				"(placeholder: dbounce's license-file plumbing has not yet " +
				"landed — tracked as #235)")
	}
	t.Cleanup(func() { licensedForAuditWebhook = prev })

	_, err := buildAuditExporter("", false,
		"https://collector.example.com/audit", "some-token", 1, false,
		"", "", "",
		0, 0,
		"127.0.0.1:5433", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Enterprise license",
		"webhook flag without license must produce a license-tier error")
	assert.Contains(t, err.Error(), "#235",
		"error must reference the license-file plumbing issue")
}

// TestBuildAuditExporter_WebhookWithLicenseOverride: when the license
// gate returns nil (production after #235), the webhook transport is
// constructed normally.
func TestBuildAuditExporter_WebhookWithLicenseOverride(t *testing.T) {
	prev := licensedForAuditWebhook
	licensedForAuditWebhook = func() error { return nil }
	t.Cleanup(func() { licensedForAuditWebhook = prev })

	// Use a public IP literal that passes the SSRF gate.
	e, err := buildAuditExporter("", false,
		"https://93.184.216.34/audit", "test-token", 1, false,
		"", "", "",
		0, 0,
		"127.0.0.1:5433", "")
	require.NoError(t, err)
	require.NotNil(t, e)
	require.True(t, e.Enabled())
	require.NoError(t, e.Shutdown(context.Background()))
}

// TestBuildAuditExporter_TokenWithoutURL_Rejected: token without a URL
// is almost certainly a typo / forgotten flag; fail-fast.
func TestBuildAuditExporter_TokenWithoutURL_Rejected(t *testing.T) {
	_, err := buildAuditExporter("", false, "", "stray-token", 0, false,
		"", "", "",
		0, 0,
		"127.0.0.1:5433", "")
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
		"https://93.184.216.34/audit", tok, 1, false,
		"", "", "",
		0, 0,
		"127.0.0.1:5433", "")
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

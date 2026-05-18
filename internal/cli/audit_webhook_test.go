package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/audit"
)

// TestAuditWebhookPresetsListHumanReadable confirms the operator-
// facing surface enumerates all four presets + carries the documented
// pointer to the cross-product WEBHOOK-PRESETS.md.
func TestAuditWebhookPresetsListHumanReadable(t *testing.T) {
	var buf bytes.Buffer
	err := runAuditWebhookPresetsList(&buf, false)
	require.NoError(t, err)
	out := buf.String()
	for _, name := range []string{"generic", "datadog", "splunk-hec", "sentinel"} {
		assert.Contains(t, out, name, "preset %q missing from CLI output", name)
	}
	assert.Contains(t, out, "WEBHOOK-PRESETS.md")
}

// TestAuditWebhookPresetsListJSON confirms the --json output parses
// + carries the cross-product descriptor shape.
func TestAuditWebhookPresetsListJSON(t *testing.T) {
	var buf bytes.Buffer
	err := runAuditWebhookPresetsList(&buf, true)
	require.NoError(t, err)

	var descriptors []audit.PresetDescriptor
	require.NoError(t, json.Unmarshal(buf.Bytes(), &descriptors))
	require.Len(t, descriptors, 4)
	want := []string{"generic", "datadog", "splunk-hec", "sentinel"}
	for i, desc := range descriptors {
		assert.Equal(t, want[i], desc.Name)
		assert.NotEmpty(t, desc.Description)
		assert.NotEmpty(t, desc.AuthHeader)
		assert.NotEmpty(t, desc.BodyShape)
		assert.Contains(t, desc.RequiredFlags, "--audit-webhook-url")
		assert.Contains(t, desc.RequiredFlags, "--audit-webhook-token")
	}
}

// TestAuditWebhookPresetDescriptorsMatchAuditPackage: every preset
// name returned by audit.AllPresets() MUST appear in the descriptor
// list. Prevents the CLI / MCP surface from drifting silently from
// the actual adapter registry.
func TestAuditWebhookPresetDescriptorsMatchAuditPackage(t *testing.T) {
	registry := map[string]bool{}
	for _, p := range audit.AllPresets() {
		registry[string(p)] = true
	}
	descNames := map[string]bool{}
	for _, d := range audit.PresetDescriptors() {
		descNames[d.Name] = true
	}
	assert.Equal(t, registry, descNames,
		"audit-webhook descriptor list out of sync with audit.AllPresets()")
}

// TestAuditWebhookPresetsListNoSurveillanceLanguage: per
// [[security-team-positioning-safety-not-surveillance]].
func TestAuditWebhookPresetsListNoSurveillanceLanguage(t *testing.T) {
	var buf bytes.Buffer
	_ = runAuditWebhookPresetsList(&buf, false)
	low := strings.ToLower(buf.String())
	for _, bad := range []string{"violation", "infraction", "unauthorized"} {
		assert.NotContains(t, low, bad,
			"forbidden word %q in operator-facing CLI output", bad)
	}
}

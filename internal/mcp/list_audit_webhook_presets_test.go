package mcp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListAuditWebhookPresetsRegisteredInToolsList confirms the new
// MCP tool is wired up in the tools/list surface.
func TestListAuditWebhookPresetsRegisteredInToolsList(t *testing.T) {
	tools := ToolDescriptors()
	names := map[string]bool{}
	for _, t := range tools {
		if n, ok := t["name"].(string); ok {
			names[n] = true
		}
	}
	assert.True(t, names["list_audit_webhook_presets"],
		"list_audit_webhook_presets missing from ToolDescriptors()")
}

// TestListAuditWebhookPresetsToolReturnsFourPresets confirms the
// agent-facing surface returns the four cross-product presets.
func TestListAuditWebhookPresetsToolReturnsFourPresets(t *testing.T) {
	s := &Server{}
	result, err := s.toolListAuditWebhookPresets(nil)
	require.NoError(t, err)
	presets, ok := result["presets"].([]map[string]any)
	require.True(t, ok, "expected presets []map[string]any; got %T", result["presets"])
	require.Len(t, presets, 4)
	want := []string{"generic", "datadog", "splunk-hec", "sentinel"}
	for i, preset := range presets {
		assert.Equal(t, want[i], preset["name"])
		for _, field := range []string{
			"description", "auth_header", "body_shape",
			"required_flags", "optional_flags",
		} {
			_, has := preset[field]
			assert.True(t, has, "preset %q missing field %q", preset["name"], field)
		}
	}
}

// TestListAuditWebhookPresetsToolCarriesNoSecret: per
// [[security-team-audit-export]] + [[self-host-zero-billing-
// dependency]]: descriptor lists ONLY shape metadata.
func TestListAuditWebhookPresetsToolCarriesNoSecret(t *testing.T) {
	s := &Server{}
	result, err := s.toolListAuditWebhookPresets(nil)
	require.NoError(t, err)
	var sb strings.Builder
	for _, preset := range result["presets"].([]map[string]any) {
		for _, val := range preset {
			sb.WriteString(strings.ToLower(toString(val)))
			sb.WriteByte(',')
		}
	}
	payload := sb.String()
	for _, bad := range []string{
		"bearer abc", "password=", "secret=",
		"dd_api_key=", "splunk_token=", "shared_key=",
	} {
		assert.NotContains(t, payload, bad,
			"unexpected literal %q in MCP tool descriptor", bad)
	}
}

func toString(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case []any:
		var parts []string
		for _, x := range n {
			parts = append(parts, toString(x))
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

package mcpinstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Smoke tests for the package-level mcpinstall API. Mirrors
// kbouncer/internal/mcpinstall/install_test.go shape.

func TestServerConfigDict_Shape(t *testing.T) {
	cfg := ServerConfigDict()
	servers := cfg["mcpServers"].(map[string]any)
	dbounceEntry := servers["dbounce"].(map[string]any)
	assert.Equal(t, "dbounce", dbounceEntry["command"])
	args := dbounceEntry["args"].([]string)
	assert.Equal(t, []string{"mcp", "serve"}, args)
}

func TestInstallClaudeCode_CreatesNew(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "claude.json")
	res, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	assert.True(t, res.Created)
	assert.False(t, res.Updated)
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.NotNil(t, parsed["mcpServers"].(map[string]any)["dbounce"])
}

func TestInstallClaudeCode_UpdateExisting(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "claude.json")
	// First install creates.
	_, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	// Second install REPLACES the dbounce entry.
	res, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	assert.True(t, res.Updated)
	assert.False(t, res.Created)
}

func TestInstall_PreservesOtherServers(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "cfg.json")
	pre := `{"mcpServers": {"kbounce": {"command": "kbounce", "args": ["mcp", "serve"], "env": {}}}}`
	require.NoError(t, os.WriteFile(target, []byte(pre), 0o600))
	_, err := InstallCursor(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	servers := parsed["mcpServers"].(map[string]any)
	assert.NotNil(t, servers["dbounce"])
	assert.NotNil(t, servers["kbounce"], "OTHER MCP servers must survive")
}

func TestInstall_RefusesMalformedWithoutForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(target, []byte("not json"), 0o600))
	_, err := InstallCursor(Options{Path: target, Out: &bytes.Buffer{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--force")
}

func TestInstall_ForceOverwritesMalformed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(target, []byte("not json"), 0o600))
	_, err := InstallCursor(Options{Path: target, Force: true, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.NotNil(t, parsed["mcpServers"].(map[string]any)["dbounce"])
}

func TestInstallCodex_TOMLPathPrintsSnippet(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.toml")
	out := &bytes.Buffer{}
	res, err := InstallCodex(Options{Path: target, Out: out})
	require.NoError(t, err)
	assert.True(t, res.Manual)
	assert.Contains(t, out.String(), "[mcp_servers.dbounce]")
	_, err = os.Stat(target)
	assert.True(t, os.IsNotExist(err),
		"install-codex must NOT write to a .toml file")
}

func TestInstallCodex_JSONPathInstalls(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "codex.json")
	res, err := InstallCodex(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)
	assert.False(t, res.Manual)
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.NotNil(t, parsed["mcpServers"].(map[string]any)["dbounce"])
}

func TestShowConfig_JSON(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, ShowConfig(out, ShapeJSON))
	body := out.String()
	assert.Contains(t, body, `"command": "dbounce"`)
	assert.Contains(t, body, "install-claude-code")
}

func TestShowConfig_YAML(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, ShowConfig(out, ShapeYAML))
	body := out.String()
	assert.Contains(t, body, "mcpServers:")
	assert.Contains(t, body, "dbounce:")
	assert.Contains(t, body, "- mcp")
}

func TestFormatToolList_SortsByName(t *testing.T) {
	out := &bytes.Buffer{}
	entries := []ToolListEntry{
		{Name: "dbounce_zzz", Description: "z."},
		{Name: "dbounce_aaa", Description: "a."},
	}
	require.NoError(t, FormatToolList(out, entries))
	body := out.String()
	aIdx := strings.Index(body, "dbounce_aaa")
	zIdx := strings.Index(body, "dbounce_zzz")
	assert.True(t, aIdx >= 0 && zIdx > aIdx, "alphabetical order required")
}

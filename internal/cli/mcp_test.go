package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/mcpinstall"
)

// CLI smoke tests for `dbounce mcp` subcommands. Mirrors
// kbouncer/internal/cli/mcp_install_test.go shape.

func TestMCPCmd_RegistersSubcommands(t *testing.T) {
	cmd := newMCPCmd()
	names := map[string]bool{}
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{
		"serve",
		"install-claude-code",
		"install-cursor",
		"install-codex",
		"show-config",
		"list-tools",
	} {
		assert.True(t, names[want], "mcp subcommand %q must be wired", want)
	}
}

func TestMCPShowConfig_JSON(t *testing.T) {
	cmd := newMCPCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"show-config"})
	require.NoError(t, cmd.Execute())
	// Strip the comment trailer + parse the JSON body.
	body := out.String()
	// JSON object ends at the first '}' on a fresh line followed by
	// the footer; simpler approach: find the first '{' + last '}' bound
	// before the footer comment.
	jsonStart := strings.Index(body, "{")
	require.GreaterOrEqual(t, jsonStart, 0)
	jsonEnd := strings.LastIndex(body[:strings.Index(body, "\n#")], "}")
	require.Greater(t, jsonEnd, jsonStart)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(body[jsonStart:jsonEnd+1]), &parsed))
	servers := parsed["mcpServers"].(map[string]any)
	dbounceEntry := servers["dbounce"].(map[string]any)
	assert.Equal(t, "dbounce", dbounceEntry["command"])
}

func TestMCPListTools_PrintsAllTools(t *testing.T) {
	cmd := newMCPCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"list-tools"})
	require.NoError(t, cmd.Execute())
	body := out.String()
	for _, want := range []string{
		"dbounce_active_mode",
		"dbounce_active_profile",
		"dbounce_recommend_mode_for_task",
		"dbounce_decide",
		"dbounce_add_rule",
	} {
		assert.Contains(t, body, want, "tool %q must appear in list-tools output", want)
	}
}

func TestMCPInstallClaudeCode_WritesConfig(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "claude.json")
	cmd := newMCPCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"install-claude-code", "--path", target})
	require.NoError(t, cmd.Execute())
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	servers := parsed["mcpServers"].(map[string]any)
	dbounceEntry := servers["dbounce"].(map[string]any)
	assert.Equal(t, "dbounce", dbounceEntry["command"])
	args := dbounceEntry["args"].([]any)
	assert.Equal(t, "mcp", args[0])
	assert.Equal(t, "serve", args[1])
}

func TestMCPInstallCursor_PreservesOtherServers(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "cursor.json")
	pre := `{"mcpServers": {"other-agent": {"command": "/bin/foo", "args": [], "env": {}}}}`
	require.NoError(t, os.WriteFile(target, []byte(pre), 0o600))

	cmd := newMCPCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"install-cursor", "--path", target})
	require.NoError(t, cmd.Execute())
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	servers := parsed["mcpServers"].(map[string]any)
	assert.NotNil(t, servers["other-agent"], "merge must preserve other mcpServers entries")
	assert.NotNil(t, servers["dbounce"], "dbounce entry must be added")
}

func TestMCPInstallCodex_TOMLPrintsManualSnippet(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.toml")
	cmd := newMCPCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"install-codex", "--path", target})
	require.NoError(t, cmd.Execute())
	body := out.String()
	assert.Contains(t, body, "manual install")
	assert.Contains(t, body, "[mcp_servers.dbounce]")
	// MUST NOT have written to the .toml file.
	_, err := os.Stat(target)
	assert.True(t, os.IsNotExist(err),
		"install-codex must NOT touch a .toml file in place")
}

func TestMCPInstall_JSONShapeConsistentAcrossClients(t *testing.T) {
	// Cross-product agent-parity invariant: all three install-*
	// commands (claude-code / cursor / codex.json) write the SAME
	// mcpServers entry shape. Mirrors the ibounce + kbouncer
	// consistency check.
	dir := t.TempDir()
	for _, sub := range []string{"install-claude-code", "install-cursor", "install-codex"} {
		target := filepath.Join(dir, sub+".json")
		cmd := newMCPCmd()
		out := &bytes.Buffer{}
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{sub, "--path", target})
		require.NoError(t, cmd.Execute(), "subcommand %s", sub)
		body, err := os.ReadFile(target)
		require.NoError(t, err, "subcommand %s output", sub)
		var parsed map[string]any
		require.NoError(t, json.Unmarshal(body, &parsed))
		entry := parsed["mcpServers"].(map[string]any)["dbounce"].(map[string]any)
		assert.Equal(t, "dbounce", entry["command"])
	}
}

// Sanity that mcpinstall's ServerEntry shape matches what the install
// commands materialize (regression guard against drift).
func TestMCPInstall_ServerEntryHasMCPServe(t *testing.T) {
	e := mcpinstall.ServerEntry()
	args := e["args"].([]string)
	assert.Equal(t, []string{"mcp", "serve"}, args)
}

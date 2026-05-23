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

// ---------------------------------------------------------------------
// #366 / §A35 — agent-attribution env-var injection. The install-*
// commands must emit a non-empty env block so the agent runtime can
// stamp X-Agent-Name + X-Agent-Session-Id headers on outbound HTTP
// traffic. Mirrors the parallel ibounce + kbouncer slices per
// [[cross-product-agent-parity]].
// ---------------------------------------------------------------------

// readDbounceEnv is the shared helper: reads the JSON config at
// target + returns the env block stamped under
// mcpServers.dbounce.env.
func readDbounceEnv(t *testing.T, target string) map[string]any {
	t.Helper()
	body, err := os.ReadFile(target)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	servers, ok := parsed["mcpServers"].(map[string]any)
	require.True(t, ok, "mcpServers must be an object")
	entry, ok := servers["dbounce"].(map[string]any)
	require.True(t, ok, "mcpServers.dbounce must be an object")
	env, ok := entry["env"].(map[string]any)
	require.True(t, ok, "mcpServers.dbounce.env must be an object (not %T)", entry["env"])
	return env
}

func TestMcpInstall_EmitsAgentEnv(t *testing.T) {
	// install-claude-code must stamp BOTH the agent-name + the
	// (empty) session id so the runtime can later mint a UUID v7
	// into the latter.
	dir := t.TempDir()
	target := filepath.Join(dir, "claude.json")
	_, err := InstallClaudeCode(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)

	env := readDbounceEnv(t, target)
	assert.NotEmpty(t, env, "env block must NOT be {} — #366 launch-blocker")

	// Existence + key shape (operators / agent runtimes match on the
	// "AGENT_NAME" + "AGENT_SESSION_ID" suffix per
	// [[cross-product-agent-parity]]).
	assert.Contains(t, env, AgentNameEnvVar)
	assert.Contains(t, env, AgentSessionIDEnvVar)

	// Default claude-code install stamps the matching agent name.
	assert.Equal(t, "claude-code", env[AgentNameEnvVar])
	// Session id is deliberately empty in the static snippet — the
	// agent runtime mints a fresh UUID v7 on each connection.
	assert.Equal(t, "", env[AgentSessionIDEnvVar])

	// Suffix-shape assertions so a downstream rename of the env-var
	// prefix (e.g. DBOUNCE_ → BOUNCE_) doesn't silently drop the
	// agent-attribution surface.
	foundNameSuffix := false
	foundSessionSuffix := false
	for k := range env {
		if strings.HasSuffix(k, "AGENT_NAME") {
			foundNameSuffix = true
		}
		if strings.HasSuffix(k, "AGENT_SESSION_ID") {
			foundSessionSuffix = true
		}
	}
	assert.True(t, foundNameSuffix, "env must carry an *AGENT_NAME key")
	assert.True(t, foundSessionSuffix, "env must carry an *AGENT_SESSION_ID key")
}

func TestMcpInstall_CursorAgentClient(t *testing.T) {
	// install-cursor must stamp AgentNameEnvVar=cursor so the agent
	// runtime reports itself accurately on outbound HTTP traffic.
	dir := t.TempDir()
	target := filepath.Join(dir, "cursor.json")
	_, err := InstallCursor(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)

	env := readDbounceEnv(t, target)
	assert.Equal(t, "cursor", env[AgentNameEnvVar])
	assert.Equal(t, "", env[AgentSessionIDEnvVar])
}

func TestMcpInstall_CodexAgentClient(t *testing.T) {
	// install-codex with a JSON path must stamp
	// AgentNameEnvVar=openai-codex. The TOML manual path is covered
	// separately by TestInstallCodex_TOMLPathPrintsSnippet +
	// TestMcpInstall_CodexTOMLSnippetIncludesAgentEnv below.
	dir := t.TempDir()
	target := filepath.Join(dir, "codex.json")
	_, err := InstallCodex(Options{Path: target, Out: &bytes.Buffer{}})
	require.NoError(t, err)

	env := readDbounceEnv(t, target)
	assert.Equal(t, "openai-codex", env[AgentNameEnvVar])
	assert.Equal(t, "", env[AgentSessionIDEnvVar])
}

func TestMcpInstall_CodexTOMLSnippetIncludesAgentEnv(t *testing.T) {
	// When install-codex falls back to the manual TOML snippet, the
	// snippet must still carry the agent-attribution env keys so an
	// operator who hand-pastes gets the same identity wiring as the
	// JSON path.
	dir := t.TempDir()
	target := filepath.Join(dir, "config.toml")
	out := &bytes.Buffer{}
	res, err := InstallCodex(Options{Path: target, Out: out})
	require.NoError(t, err)
	require.True(t, res.Manual)
	snippet := res.Snippet
	assert.Contains(t, snippet, AgentNameEnvVar)
	assert.Contains(t, snippet, AgentSessionIDEnvVar)
	assert.Contains(t, snippet, "openai-codex")
}

func TestShowConfig_JSON_IncludesAgentEnv(t *testing.T) {
	// `dbounce mcp show-config --shape json` must surface the same
	// env block the install-* commands write — otherwise an operator
	// who copies show-config output into a custom MCP client loses
	// the agent-attribution surface.
	out := &bytes.Buffer{}
	require.NoError(t, ShowConfig(out, ShapeJSON))
	body := out.String()
	assert.Contains(t, body, AgentNameEnvVar)
	assert.Contains(t, body, AgentSessionIDEnvVar)
	assert.Contains(t, body, DefaultAgentName)
}

func TestShowConfig_YAML_IncludesAgentEnv(t *testing.T) {
	out := &bytes.Buffer{}
	require.NoError(t, ShowConfig(out, ShapeYAML))
	body := out.String()
	assert.Contains(t, body, AgentNameEnvVar)
	assert.Contains(t, body, AgentSessionIDEnvVar)
	// Must NOT contain the old empty-env shape.
	assert.NotContains(t, body, "env: {}",
		"YAML env block must be populated — #366 launch-blocker")
}

func TestServerEntryForAgent_FallsBackToDefault(t *testing.T) {
	// Empty agent name falls through to DefaultAgentName so external
	// callers (or a buggy clientName lookup) don't silently emit an
	// empty AGENT_NAME value.
	entry := ServerEntryForAgent("")
	env := entry["env"].(map[string]any)
	assert.Equal(t, DefaultAgentName, env[AgentNameEnvVar])
}

func TestAgentNameForClient_KnownClients(t *testing.T) {
	cases := map[string]string{
		"claude-code": "claude-code",
		"cursor":      "cursor",
		"codex":       "openai-codex",
		"unknown":     DefaultAgentName,
		"":            DefaultAgentName,
	}
	for client, want := range cases {
		client, want := client, want
		t.Run(client, func(t *testing.T) {
			assert.Equal(t, want, agentNameForClient(client))
		})
	}
}

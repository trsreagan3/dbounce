package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// D-Slice 6 CLI tests:
//
//   - `dbounce run --dialect snowflake|bigquery` fails fast with a
//     clear error pointing the operator at docs/SHIM-INTEGRATION.md.
//     No wire-protocol proxy for these dialects in v1.0.
//
//   - `dbounce decide --dialect snowflake|bigquery` works on sample
//     SELECT + UPDATE statements (the supported invocation path).
//
//   - `dbounce decide --dialect postgres|mysql` also works so shim
//     code can use the same exec path uniformly across all 4 dialects.

func TestRunCmd_RejectsSnowflakeWithShimDocsPointer(t *testing.T) {
	cmd := newRunCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{
		"--dialect=snowflake",
		"--db", filepath.Join(t.TempDir(), "x.db"),
		"--port", "0", "--mgmt-port", "0",
		"--host", "127.0.0.1",
	})
	err := cmd.Execute()
	require.Error(t, err,
		"`dbounce run --dialect snowflake` MUST fail fast — no wire-protocol proxy in v1.0")
	assert.Contains(t, err.Error(), "snowflake")
	assert.Contains(t, err.Error(), "SHIM-INTEGRATION.md",
		"error MUST point operator at the shim docs")
	assert.Contains(t, err.Error(), "dbounce decide",
		"error MUST point operator at the supported invocation path")
}

func TestRunCmd_RejectsBigQueryWithShimDocsPointer(t *testing.T) {
	cmd := newRunCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{
		"--dialect=bigquery",
		"--db", filepath.Join(t.TempDir(), "x.db"),
		"--port", "0", "--mgmt-port", "0",
		"--host", "127.0.0.1",
	})
	err := cmd.Execute()
	require.Error(t, err,
		"`dbounce run --dialect bigquery` MUST fail fast — no wire-protocol proxy in v1.0")
	assert.Contains(t, err.Error(), "bigquery")
	assert.Contains(t, err.Error(), "SHIM-INTEGRATION.md")
	assert.Contains(t, err.Error(), "dbounce decide")
}

func TestDecideCmd_Wired(t *testing.T) {
	root := newRootCmd()
	names := map[string]bool{}
	for _, c := range root.Commands() {
		names[c.Name()] = true
	}
	assert.True(t, names["decide"],
		"D-Slice 6 must wire the `decide` subcommand — the supported "+
			"invocation path for the JDBC-shim integration")
}

func TestDecideCmd_Help(t *testing.T) {
	cmd := newDecideCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--help"})
	require.NoError(t, cmd.Execute())
	help := out.String()
	assert.Contains(t, help, "--dialect")
	assert.Contains(t, help, "--statement")
	assert.Contains(t, help, "--stdin")
	assert.Contains(t, help, "SHIM-INTEGRATION.md",
		"decide help MUST reference the shim docs")
}

// `dbounce decide --dialect snowflake --statement "SELECT 1"` should
// emit a verdict + return cleanly. We can't easily intercept os.Exit
// for the deny path here; we exercise the allow path (default-policy
// allow + no rules) so the command returns nil.
func TestDecideCmd_SnowflakeSelectAllow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	cmd := newDecideCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"--dialect=snowflake",
		"--statement", "SELECT 1",
		"--db", dbPath,
		"--default-policy", "allow",
	})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "verdict: allow")
	assert.Contains(t, text, "type:    SELECT")
}

func TestDecideCmd_BigQuerySelectAllow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	cmd := newDecideCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"--dialect=bigquery",
		"--statement", "SELECT * FROM ds.users",
		"--db", dbPath,
		"--default-policy", "allow",
	})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "verdict: allow")
	assert.Contains(t, text, "type:    SELECT")
}

// `dbounce decide --statement "UPDATE ..."` on snowflake with
// default-policy=allow + no rules should ALLOW (parser surfaces UPDATE
// + MutatingNodeType but the rule engine has nothing to match against,
// so the default-policy fall-through fires).
func TestDecideCmd_SnowflakeUpdateAllowsViaDefault(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	cmd := newDecideCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"--dialect=snowflake",
		"--statement", "UPDATE orders SET status='paid' WHERE id=1",
		"--db", dbPath,
		"--default-policy", "allow",
	})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "verdict: allow")
	assert.Contains(t, text, "type:    UPDATE")
}

// JSON shape parity with the dbounce_decide MCP tool — shim code can
// reuse a single parser across CLI + JSON-RPC.
func TestDecideCmd_JSONShape(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	cmd := newDecideCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"--dialect=postgres",
		"--statement", "SELECT 1",
		"--db", dbPath,
		"--default-policy", "allow",
		"--json",
	})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.True(t, strings.HasPrefix(text, "{"), "JSON output MUST start with {")
	assert.Contains(t, text, `"verdict":"allow"`)
	assert.Contains(t, text, `"statement_type":"SELECT"`)
	assert.Contains(t, text, `"dialect":"postgres"`)
}

// Empty SQL is rejected so an accidentally-empty shim call doesn't
// silently allow.
func TestDecideCmd_EmptySQLRejected(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	cmd := newDecideCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{
		"--dialect=snowflake",
		"--statement", "",
		"--db", dbPath,
	})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no SQL")
}

// --statement and --stdin together is operator intent ambiguous.
func TestDecideCmd_StatementAndStdinMutuallyExclusive(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	cmd := newDecideCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{
		"--dialect=postgres",
		"--statement", "SELECT 1",
		"--stdin",
		"--db", dbPath,
	})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// TestDecideCmd_AgentName_FlagSurfaceInJSON pins
// [[agent-identity-in-audit]] Feature 1 JDBC-shim wiring: the
// --agent-name flag MUST surface in the decideResult JSON so the shim
// wrapper sees confirmation that the agent name flowed through.
// Missing flag defaults to "unknown" per the memo.
func TestDecideCmd_AgentName_FlagSurfaceInJSON(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	cmd := newDecideCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"--dialect=snowflake",
		"--statement", "SELECT 1",
		"--db", dbPath,
		"--default-policy", "allow",
		"--agent-name", "claude-code",
		"--agent-version", "1.2.3",
		"--json",
	})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, `"agent_name":"claude-code"`)
}

func TestDecideCmd_AgentName_DefaultsToUnknown(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	cmd := newDecideCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"--dialect=snowflake",
		"--statement", "SELECT 1",
		"--db", dbPath,
		"--default-policy", "allow",
		"--json",
	})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, `"agent_name":"unknown"`,
		"--agent-name absent MUST default to 'unknown' per "+
			"[[agent-identity-in-audit]] memo")
}

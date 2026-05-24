package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
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

// ---------------------------------------------------------------------------
// #559 — CLI dry-run admin-tight floor parity with proxy.decide().
//
// Per [[ibounce-honest-positioning]]: `dbounce decide` MUST report the
// same verdict the running proxy would emit on the same SQL. Before
// #559 the CLI's evalDecide silently ALLOWED admin-grant DCL under
// default-allow because the floor was inline in proxy.decide(). After
// #559 the floor lives in internal/decision/AdminTightFloor + both
// call sites consume the same primitive.
//
// State-verification: each test asserts the CLI's observable stdout
// (verdict line OR JSON verdict field) matches the production hot-path
// verdict on identical DCL inputs.
// ---------------------------------------------------------------------------

// TestDecideCmd_PostgresGrant_DeniesUnderDefaultAllow pins the
// regression that #559 closes: PG GRANT under --default-policy=allow
// + no rules MUST report deny via the admin-tight floor. Before #559
// the CLI silently allowed this while the proxy correctly denied it.
//
// Decide command exits 1 on deny via os.Exit — we observe via the
// emitted stdout BEFORE the exit. cmd.Execute returns nil for allow
// AND the print runs unconditionally before the exit branch, so we
// can't easily intercept os.Exit. Instead we exercise evalDecide
// directly to assert state without the exit-1 branch firing.
func TestEvalDecide_PostgresGrant_DeniesUnderDefaultAllow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	res, err := evalDecideForTest(t, st, nil, "postgres", "allow",
		"GRANT ALL ON TABLE foo TO PUBLIC")
	require.NoError(t, err)
	assert.Equal(t, "deny", res.Verdict,
		"PG GRANT under default-allow + no rules MUST report DENY via admin-tight floor "+
			"(was silently ALLOW before #559)")
	assert.Equal(t, "default", res.DecisionSource,
		"admin-tight floor tags SourceDefault (matches proxy.decide byte-for-byte)")
	assert.Contains(t, res.Reason, "admin-tight floor",
		"CLI reason MUST name the floor (matches proxy.decide reason shape)")
	assert.Contains(t, res.Reason, "GRANT")
	assert.Contains(t, res.Reason, "default-policy=allow",
		"CLI reason MUST surface the default-policy the floor superseded")
}

// TestEvalDecide_MySQLGrant_DeniesUnderDefaultAllow pins MySQL parity
// for #559: MySQL GRANT MUST report DENY via the admin-tight floor on
// the CLI dry-run path (was silently ALLOW before).
func TestEvalDecide_MySQLGrant_DeniesUnderDefaultAllow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	res, err := evalDecideForTest(t, st, nil, "mysql", "allow",
		"GRANT ALL ON foo.* TO 'bob'@'%'")
	require.NoError(t, err)
	assert.Equal(t, "deny", res.Verdict,
		"MySQL GRANT under default-allow + no rules MUST report DENY via admin-tight floor "+
			"(was silently ALLOW before #559)")
	assert.Equal(t, "default", res.DecisionSource)
	assert.Contains(t, res.Reason, "admin-tight floor")
}

// TestEvalDecide_PostgresSelect_AllowsUnderDefaultAllow pins the
// non-regression: SELECT statements (non-DCL) MUST still report ALLOW
// under default-allow. #559 MUST NOT introduce false-positive denies
// on non-DCL statements.
func TestEvalDecide_PostgresSelect_AllowsUnderDefaultAllow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	res, err := evalDecideForTest(t, st, nil, "postgres", "allow",
		"SELECT 1")
	require.NoError(t, err)
	assert.Equal(t, "allow", res.Verdict,
		"non-DCL SELECT under default-allow MUST still report ALLOW "+
			"(#559 floor MUST NOT introduce false-positive denies)")
	assert.Equal(t, "default", res.DecisionSource)
	assert.NotContains(t, res.Reason, "admin-tight floor",
		"SELECT reason MUST NOT name the floor (floor not applicable)")
}

// TestEvalDecide_PostgresGrantWithGlobalAllowRule_Allows pins the
// override path: a global allow_rule matching GRANT lets the admin
// operate. Fires BEFORE the floor (mirrors proxy.decide composition
// order). Cross-validates that the CLI dry-run honors operator-
// configured overrides the same way production does.
func TestEvalDecide_PostgresGrantWithGlobalAllowRule_Allows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	// Add a global allow rule matching GRANT.
	addGlobalAllowRuleForTest(t, st, "GRANT:*")

	res, err := evalDecideForTest(t, st, nil, "postgres", "allow",
		"GRANT SELECT ON TABLE foo TO bob")
	require.NoError(t, err)
	assert.Equal(t, "allow", res.Verdict,
		"explicit global allow_rule MUST override the admin-tight floor "+
			"(parity with proxy.decide)")
	assert.Equal(t, "global.allow", res.DecisionSource)
	assert.NotContains(t, res.Reason, "admin-tight floor",
		"reason MUST name the matched allow rule, NOT the floor")
}

// ---------------------------------------------------------------------------
// #559 test helpers — keep the evalDecide-direct call shape small so
// the BB tests above stay readable.
// ---------------------------------------------------------------------------

func openStoreForTest(t *testing.T, dbPath string) (*store.Store, error) {
	t.Helper()
	return store.Open(dbPath)
}

func evalDecideForTest(
	t *testing.T,
	st *store.Store,
	prof *profile.Profile,
	dialectStr string,
	defaultPolStr string,
	sql string,
) (*decideResult, error) {
	t.Helper()
	dialect, err := proxy.ParseDialect(dialectStr)
	require.NoError(t, err)
	defaultPol, err := proxy.ParseDefaultPolicy(defaultPolStr)
	require.NoError(t, err)
	return evalDecide(st, prof, dialect, defaultPol, sql)
}

func addGlobalAllowRuleForTest(t *testing.T, st *store.Store, pattern string) {
	t.Helper()
	_, err := st.AddRule(dbrules.ProxyRule{
		Pattern: pattern,
		Effect:  dbrules.EffectAllow,
	})
	require.NoError(t, err)
}

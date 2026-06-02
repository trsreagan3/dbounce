package cli

import (
	"bytes"
	"encoding/json"
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
// #586 — PG role/user management CLI parity.
// ---------------------------------------------------------------------------
//
// UAT-C 2026-05-25 found PG CREATE/ALTER/DROP ROLE+USER bypassed the
// admin-tight floor entirely under --default-policy=allow. The classifier
// fix in internal/parser/postgres.go (CreateRoleStmt / AlterRoleStmt /
// DropRoleStmt now classify as StmtAlterPrivileges + IsDCL=true) flows
// through the shared AdminTightFloor. The CLI dry-run path consumes the
// SAME helper as proxy.decide, so these tests pin that the dry-run
// reports DENY on the same statements the proxy would deny.

// TestEvalDecide_PGCreateRole_DeniesUnderDefaultAllow pins the #586
// regression: CREATE ROLE attacker SUPERUSER under default-allow + no
// rules MUST report deny via the admin-tight floor on the CLI dry-run
// path (was silently ALLOW pre-#586).
func TestEvalDecide_PGCreateRole_DeniesUnderDefaultAllow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	res, err := evalDecideForTest(t, st, nil, "postgres", "allow",
		"CREATE ROLE attacker SUPERUSER")
	require.NoError(t, err)
	assert.Equal(t, "deny", res.Verdict,
		"PG CREATE ROLE SUPERUSER under default-allow MUST report DENY via admin-tight floor "+
			"(was silently ALLOW pre-#586)")
	assert.Equal(t, "default", res.DecisionSource,
		"admin-tight floor tags SourceDefault (matches proxy.decide)")
	assert.Contains(t, res.Reason, "admin-tight floor",
		"CLI reason MUST name the floor (parity with proxy.decide)")
	assert.Contains(t, res.Reason, "default-policy=allow",
		"CLI reason MUST surface the default-policy the floor superseded")
}

// TestEvalDecide_PGAlterUser_DeniesUnderDefaultAllow pins ALTER USER
// SUPERUSER via the CLI dry-run path.
func TestEvalDecide_PGAlterUser_DeniesUnderDefaultAllow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	res, err := evalDecideForTest(t, st, nil, "postgres", "allow",
		"ALTER USER bob SUPERUSER")
	require.NoError(t, err)
	assert.Equal(t, "deny", res.Verdict,
		"PG ALTER USER SUPERUSER under default-allow MUST report DENY (#586)")
	assert.Contains(t, res.Reason, "admin-tight floor")
}

// TestEvalDecide_PGDropUser_DeniesUnderDefaultAllow pins DROP USER via
// the CLI dry-run path.
func TestEvalDecide_PGDropUser_DeniesUnderDefaultAllow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	res, err := evalDecideForTest(t, st, nil, "postgres", "allow",
		"DROP USER bob")
	require.NoError(t, err)
	assert.Equal(t, "deny", res.Verdict,
		"PG DROP USER under default-allow MUST report DENY (#586)")
	assert.Contains(t, res.Reason, "admin-tight floor")
}

// TestEvalDecide_PGCreateRoleWithAllowRule_Allows pins the override
// path on the CLI side: a global allow_rule matching ALTER_PRIVILEGES
// lets CREATE ROLE through. Parity with proxy.decide.
func TestEvalDecide_PGCreateRoleWithAllowRule_Allows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	addGlobalAllowRuleForTest(t, st, "ALTER_PRIVILEGES:*")

	res, err := evalDecideForTest(t, st, nil, "postgres", "allow",
		"CREATE ROLE service_acct LOGIN")
	require.NoError(t, err)
	assert.Equal(t, "allow", res.Verdict,
		"explicit allow_rule MUST override admin-tight floor for CREATE ROLE (#586 parity)")
	assert.Equal(t, "global.allow", res.DecisionSource)
	assert.NotContains(t, res.Reason, "admin-tight floor",
		"reason MUST name the matched allow rule, NOT the floor")
}

// ---------------------------------------------------------------------------
// #588 — MySQL DROP USER CLI dry-run parity with proxy.decide().
// ---------------------------------------------------------------------------
//
// UAT-C 2026-05-25 found MySQL `DROP USER 'bob'@'%'` was classified as
// StmtRevoke (cleanup verb) and bypassed admin-tight floor even with
// --profile safe-default --default-policy allow. Same classifier-gap
// shape as #586 (just fixed for PG); cross-dialect inconsistency in
// MySQL. The classifier fix in internal/parser/mysql_dcl.go
// (populateMySQLDropUser + populateMySQLDropRole now classify as
// StmtAlterPrivileges + IsDCL=true) flows through the shared
// AdminTightFloor. The CLI dry-run path consumes the SAME helper as
// proxy.decide (per #559), so these tests pin that the dry-run reports
// DENY on the same statements the proxy would deny.

// TestCLIEvalDecide_MySQLDropUser_Denies pins the #588 regression:
// MySQL DROP USER 'bob'@'%' under default-allow + no rules MUST report
// deny via the admin-tight floor on the CLI dry-run path (was silently
// ALLOW pre-#588 per UAT-C 2026-05-25).
func TestCLIEvalDecide_MySQLDropUser_Denies(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	res, err := evalDecideForTest(t, st, nil, "mysql", "allow",
		"DROP USER 'bob'@'%'")
	require.NoError(t, err)
	assert.Equal(t, "deny", res.Verdict,
		"MySQL DROP USER under default-allow MUST report DENY via admin-tight floor "+
			"(was silently ALLOW pre-#588 per UAT-C 2026-05-25)")
	assert.Equal(t, "default", res.DecisionSource,
		"admin-tight floor tags SourceDefault (matches proxy.decide byte-for-byte)")
	assert.Contains(t, res.Reason, "admin-tight floor",
		"CLI reason MUST name the floor (parity with proxy.decide)")
	assert.Contains(t, res.Reason, "default-policy=allow",
		"CLI reason MUST surface the default-policy the floor superseded")
}

// TestCLIEvalDecide_MySQLRevoke_AllowsUnderDefaultAllow pins the
// regression-guard on the CLI surface: REVOKE (cleanup direction) MUST
// still report ALLOW under default-allow. #588's classifier change MUST
// NOT accidentally spill into REVOKE — the safer half of every
// GRANT/REVOKE pair stays unmolested.
func TestCLIEvalDecide_MySQLRevoke_AllowsUnderDefaultAllow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	res, err := evalDecideForTest(t, st, nil, "mysql", "allow",
		"REVOKE SELECT ON foo.* FROM 'bob'@'%'")
	require.NoError(t, err)
	assert.Equal(t, "allow", res.Verdict,
		"MySQL REVOKE under default-allow MUST still report ALLOW "+
			"(#588 regression-guard: cleanup direction is always allowed)")
	assert.NotContains(t, res.Reason, "admin-tight floor",
		"MySQL REVOKE reason MUST NOT name the floor (#588 must not spill into REVOKE)")
}

// ---------------------------------------------------------------------------
// #587 — CLI dry-run multi-statement parity with proxy.decide().
//
// Per UAT-C 2026-05-25: dbounce evaluated only the FIRST statement in a
// multi-statement batch. Adversarial DCL embedded at position 2+ was
// completely invisible. The fix (decision.EvaluateMultiStatement) runs
// the admin-tight floor on EVERY statement; both proxy.decide() +
// cli.evalDecide() consume the same helper (no parity drift per #559).
//
// The test below is spec test #12 (task #587 Step 3): mirrors the
// internal/decision/multi_statement_test.go TestMultiStmt_GrantInPosition2
// shape but via the CLI dry-run path. Failing this test means the
// CLI/proxy divergence has reappeared.
// ---------------------------------------------------------------------------

// TestCLIEvalDecide_MultiStmtWithGrant_Denies pins the #587 CRIT closure
// via the CLI surface: `SELECT 1; GRANT ALL ON foo TO PUBLIC; SELECT 2`
// MUST report DENY with a reason naming statement 2/3. Was silently
// ALLOW before the fix.
func TestCLIEvalDecide_MultiStmtWithGrant_Denies(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	res, err := evalDecideForTest(t, st, nil, "postgres", "allow",
		"SELECT 1; GRANT ALL ON foo TO PUBLIC; SELECT 2")
	require.NoError(t, err)
	assert.Equal(t, "deny", res.Verdict,
		"#587 CRIT — embedded GRANT at position 2 MUST report DENY via the CLI dry-run path "+
			"(was silently ALLOW pre-fix; bypass closed when this test passes)")
	assert.Equal(t, "default", res.DecisionSource,
		"multi-statement floor MUST tag SourceDefault (parity with proxy.decide)")
	assert.Contains(t, res.Reason, "statement 2/3",
		"reason MUST name the offending position so operators can debug")
	assert.Contains(t, res.Reason, "admin-tight floor",
		"reason MUST name the floor (SIEM filter contract)")
	assert.Contains(t, res.Reason, "GRANT",
		"reason MUST name the statement type that triggered the floor")
}

// TestCLIEvalDecide_MultiStmtAllAllow_PassesThrough pins the negative
// counterpart: a multi-statement batch of all benign SELECTs MUST
// report ALLOW under default-allow. #587 fix MUST NOT introduce false-
// positive denies on non-DCL batches.
func TestCLIEvalDecide_MultiStmtAllAllow_PassesThrough(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	res, err := evalDecideForTest(t, st, nil, "postgres", "allow",
		"SELECT 1; SELECT 2; SELECT 3")
	require.NoError(t, err)
	assert.Equal(t, "allow", res.Verdict,
		"all-SELECT batch under default-allow MUST report ALLOW (no false-positive)")
	assert.NotContains(t, res.Reason, "admin-tight floor",
		"reason MUST NOT name the floor when no DCL is present")
}

// ---------------------------------------------------------------------------
// #589 — decideResult JSON includes indicators field with RiskIndicators.
//
// Per #589: operators using `dbounce decide --json` for incident response
// need the WHY alongside the verdict. The indicators field surfaces the
// parser's RiskIndicators so a SIEM/script can pivot on "why was this
// GRANT denied" without re-parsing the SQL.
// ---------------------------------------------------------------------------

// TestDecideResult_IndicatorsInJSON pins that evalDecide populates the
// indicators field for a MySQL GRANT that triggers multiple risk indicators.
// The statement `GRANT ALL ON *.* TO 'attacker'@'%' WITH GRANT OPTION`
// produces: all_privileges, wildcard_host, with_grant_option. These are
// the parser's RiskIndicators, not a secret internal state — they're
// the stable SIEM vocabulary documented in parser.go.
func TestDecideResult_IndicatorsInJSON(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	// Use a GRANT that populates multiple indicators so the field is
	// observably non-empty even under default-deny (the verdict is deny
	// from admin-tight floor; indicators still surfaced).
	res, err := evalDecideForTest(t, st, nil, "mysql", "allow",
		"GRANT ALL ON *.* TO 'attacker'@'%' WITH GRANT OPTION")
	require.NoError(t, err)
	assert.Equal(t, "deny", res.Verdict,
		"GRANT ALL to wildcard host MUST deny via admin-tight floor")
	assert.NotEmpty(t, res.Indicators,
		"#589: indicators field MUST be non-empty for DCL with risk flags — "+
			"operator running --json for incident response needs the WHY")
	assert.Contains(t, res.Indicators, "all_privileges",
		"all_privileges indicator MUST surface (GRANT ALL shape)")
	assert.Contains(t, res.Indicators, "wildcard_host",
		"wildcard_host indicator MUST surface ('@'%'' host)")
	assert.Contains(t, res.Indicators, "with_grant_option",
		"with_grant_option indicator MUST surface (WITH GRANT OPTION)")
}

// TestDecideResult_IndicatorsEmptyForNonDCL pins that non-DCL
// statements (SELECT, INSERT, etc.) produce an empty indicators field
// so the JSON output is clean for the common case.
func TestDecideResult_IndicatorsEmptyForNonDCL(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	res, err := evalDecideForTest(t, st, nil, "postgres", "allow",
		"CREATE TABLE foo (id SERIAL PRIMARY KEY)")
	require.NoError(t, err)
	assert.Equal(t, "allow", res.Verdict)
	assert.Empty(t, res.Indicators,
		"#589: non-DCL statement MUST produce empty indicators field (no false noise)")
}

// TestDecideResult_IndicatorsInJSONEncoding pins that the JSON-encoded
// decideResult includes the indicators key when populated. This is the
// wire-shape test: shim code parsing `dbounce decide --json` output sees
// the field. We use the evalDecide path directly to avoid the os.Exit(1)
// deny branch; the JSON encoding is verified via json.Marshal on the result.
func TestDecideResult_IndicatorsInJSONEncoding(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	res, err := evalDecideForTest(t, st, nil, "mysql", "allow",
		"GRANT ALL ON *.* TO 'x'@'%'")
	require.NoError(t, err)
	require.NotEmpty(t, res.Indicators,
		"#589 pre-condition: indicators must be populated for this GRANT shape")

	raw, merr := json.Marshal(res)
	require.NoError(t, merr)
	jsonStr := string(raw)
	assert.Contains(t, jsonStr, `"indicators"`,
		"#589 JSON encoding MUST include indicators key (shim wire-shape contract)")
	assert.Contains(t, jsonStr, "all_privileges",
		"#589 JSON encoding MUST include all_privileges indicator value")
}

// ---------------------------------------------------------------------------
// fix/16-decide-path-redaction — PII-consistency: at-rest SQLite row +
// JSONL for the sync-prompt path must have redacted statement, matching
// the `run` path's MED-D8-09 behaviour.
//
// decideSyncPromptStoredStatement is the unit under test; the integration
// test confirms the store row reflects [REDACTED] + StatementRedacted=true,
// and that the verdict decision is not affected by the stored form.
// ---------------------------------------------------------------------------

// TestDecideSyncPromptStoredStatement_RedactsLiterals pins the unit
// contract: a statement with single-quoted literals is redacted, the
// boolean indicates the change.
func TestDecideSyncPromptStoredStatement_RedactsLiterals(t *testing.T) {
	secretSQL := "INSERT INTO users (email, password) VALUES ('alice@example.com', 'super_secret_password_123')"
	stored, redacted := decideSyncPromptStoredStatement(secretSQL)
	assert.True(t, redacted,
		"statement containing string literals MUST be marked as redacted")
	assert.NotContains(t, stored, "alice@example.com",
		"PII email MUST NOT appear in the stored statement")
	assert.NotContains(t, stored, "super_secret_password_123",
		"secret password MUST NOT appear in the stored statement")
	assert.Contains(t, stored, "[REDACTED]",
		"stored statement MUST contain the redaction placeholder")
	// The SQL structure (INSERT INTO users) is preserved — audit reviewers
	// still see the shape.
	assert.Contains(t, stored, "INSERT INTO users")
}

// TestDecideSyncPromptStoredStatement_NoLiterals_NotRedacted pins the
// non-regression: a statement without string literals reports
// redacted=false and returns the original string unchanged.
func TestDecideSyncPromptStoredStatement_NoLiterals_NotRedacted(t *testing.T) {
	sql := "SELECT COUNT(*) FROM users WHERE id = 42"
	stored, redacted := decideSyncPromptStoredStatement(sql)
	assert.False(t, redacted,
		"statement without string literals MUST NOT be marked as redacted")
	assert.Equal(t, sql, stored,
		"statement without string literals MUST pass through unchanged")
}

// TestDecideSyncPromptStoredStatement_EmptySQL_NotRedacted pins the
// empty-input path: empty string passes through unchanged.
func TestDecideSyncPromptStoredStatement_EmptySQL_NotRedacted(t *testing.T) {
	stored, redacted := decideSyncPromptStoredStatement("")
	assert.False(t, redacted)
	assert.Equal(t, "", stored)
}

// TestDecideSyncPromptStoredStatement_AtRestRowHasRedactedStatement is the
// integration-level test: persist a sync-prompt decision row (as decide.go's
// sync-prompt branch does) and read it back from the store to confirm
// (a) the at-rest SQLite row has [REDACTED] instead of the secret literal,
// (b) StatementRedacted = true,
// (c) the verdict/reason/type columns are unaffected by the redaction.
//
// This is the reproduce-then-confirm test for the PII-consistency gap:
// prior to fix/16-decide-path-redaction, strings(state.db) surfaced the
// raw secret. After the fix, the at-rest row contains only [REDACTED].
func TestDecideSyncPromptStoredStatement_AtRestRowHasRedactedStatement(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()

	secretSQL := "INSERT INTO sessions (token, user_id) VALUES ('tok_s3cr3t_b34r3r', 99)"
	storedStmt, wasRedacted := decideSyncPromptStoredStatement(secretSQL)

	// Write the row exactly as the decide.go sync-prompt branch does
	// after the fix.
	id, err := st.RecordDecision(store.DecisionRow{
		Dialect:           "postgres",
		Statement:         storedStmt,
		StatementRedacted: wasRedacted,
		StatementType:     "INSERT",
		IsDML:             true,
		HasMutatingNode:   true,
		DecisionVerdict:   "DENY",
		DecisionReason:    "decide-path sync-prompt block (reason: default policy deny)",
		ModeAtDecision:    "transparent",
		DecisionSource:    "default",
	})
	require.NoError(t, err)
	require.NotZero(t, id)

	// Read it back from the store.
	rows, err := st.RecentDecisions(5)
	require.NoError(t, err)
	require.Len(t, rows, 1, "exactly one decision row must be present")
	row := rows[0]

	// (a) Secret literal must not appear in the at-rest row.
	assert.NotContains(t, row.Statement, "tok_s3cr3t_b34r3r",
		"secret bearer token MUST NOT appear in the at-rest SQLite row "+
			"(reproduce-then-confirm: this was the pre-fix leak)")
	assert.Contains(t, row.Statement, "[REDACTED]",
		"at-rest row MUST contain [REDACTED] placeholder")

	// (b) StatementRedacted flag must be set.
	assert.True(t, row.StatementRedacted,
		"StatementRedacted MUST be true so audit consumers know the SQL is not replayable")

	// (c) Verdict columns are unaffected — the decision is still DENY.
	assert.Equal(t, "DENY", row.DecisionVerdict,
		"verdict MUST be unaffected by statement redaction")
	assert.Equal(t, "INSERT", row.StatementType,
		"statement_type MUST be unaffected by statement redaction")
	assert.Equal(t, "default", row.DecisionSource,
		"decision_source MUST be unaffected by statement redaction")
}

// TestDecideSyncPromptStoredStatement_DecisionCorrectness confirms that
// the eval decision returned by evalDecide (the verdict returned to the
// caller, i.e. the JDBC shim) is based on the ORIGINAL sql, not the
// redacted form. Redaction applies only to the stored record.
//
// The verdict path flows through evalDecide which never sees the stored
// form; this test pins that a secret-bearing INSERT gets the same verdict
// with or without literals.
func TestDecideSyncPromptStoredStatement_DecisionCorrectness(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := openStoreForTest(t, dbPath)
	require.NoError(t, err)
	defer st.Close()

	// A secret-bearing INSERT under default-allow with no deny rules
	// MUST still report allow — the presence of a secret literal in the
	// SQL must not change the verdict.
	secretSQL := "INSERT INTO sessions (token) VALUES ('tok_abc123')"
	res, err := evalDecideForTest(t, st, nil, "postgres", "allow", secretSQL)
	require.NoError(t, err)
	assert.Equal(t, "allow", res.Verdict,
		"verdict MUST be based on the SQL semantics (INSERT), not the literal values: "+
			"redaction is for the stored record only and MUST NOT influence the verdict")
	assert.Equal(t, "INSERT", res.StatementType,
		"statement_type MUST reflect the original SQL correctly")

	// Also confirm a statement without literals gets the same verdict.
	plainSQL := "INSERT INTO sessions (user_id) VALUES (42)"
	resPlain, err := evalDecideForTest(t, st, nil, "postgres", "allow", plainSQL)
	require.NoError(t, err)
	assert.Equal(t, res.Verdict, resPlain.Verdict,
		"verdict MUST be identical for equivalent INSERT regardless of whether literals are present")
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

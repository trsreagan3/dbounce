package proxy

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/parser"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/tasks"
)

// D-Slice 3 composition-order BB+WB tests. Drive Server.decide()
// directly via in-process Server + Store. These tests are the
// load-bearing invariants for the entire rule engine — the four
// composition-order scenarios that the dbounce-build-plan §"D-Slice 3
// composition order" calls out as load-bearing.
//
// Tests:
//   - default-policy fall-through (allow + deny variants)
//   - global rule allow (no task active)
//   - global rule deny beats default-allow
//   - global rule deny fires regardless of task scope
//   - task-deny beats global-allow
//   - task-allow on top of global-deny → still DENY (admin's baseline wins)
//   - task active + no task-allow + global-allow → ALLOW with global source
//   - task active + no task-allow + no global match → DENY out-of-scope
//   - MUTATING:* catches CTE-wrapped writes via HasMutatingNode
//   - audit row carries decision_source + task_id correctly

func newDecideTestServer(t *testing.T, defaultPol DefaultPolicy) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	cfg := Config{
		Host:          "127.0.0.1",
		Port:          0,
		MgmtHost:      "127.0.0.1",
		MgmtPort:      0,
		Mode:          ModeCooperative,
		Dialect:       DialectPostgres,
		DefaultPolicy: defaultPol,
	}.Normalize()
	srv := NewServer(cfg, st)
	return srv, st
}

func parse(t *testing.T, sql string) *parser.ParsedStatement {
	t.Helper()
	ps := parser.Parse(parser.DialectPostgres, sql)
	require.NotNil(t, ps)
	return ps
}

func TestDecide_DefaultAllow_NoRules(t *testing.T) {
	srv, _ := newDecideTestServer(t, DefaultPolicyAllow)
	d := srv.decide(parse(t, "SELECT 1"))
	assert.Equal(t, VerdictAllow, d.Verdict)
	assert.Equal(t, SourceDefault, d.Source)
}

func TestDecide_DefaultDeny_NoRules(t *testing.T) {
	srv, _ := newDecideTestServer(t, DefaultPolicyDeny)
	d := srv.decide(parse(t, "SELECT 1"))
	assert.Equal(t, VerdictDeny, d.Verdict)
	assert.Equal(t, SourceDefault, d.Source)
}

func TestDecide_GlobalAllow_NoTask(t *testing.T) {
	srv, st := newDecideTestServer(t, DefaultPolicyDeny)
	_, err := st.AddRule(dbrules.ProxyRule{
		Pattern: "SELECT:public.*", Effect: dbrules.EffectAllow,
	})
	require.NoError(t, err)
	d := srv.decide(parse(t, "SELECT * FROM public.users"))
	assert.Equal(t, VerdictAllow, d.Verdict)
	assert.Equal(t, SourceGlobalAllow, d.Source)
}

func TestDecide_GlobalDeny_BeatsDefaultAllow(t *testing.T) {
	srv, st := newDecideTestServer(t, DefaultPolicyAllow)
	_, err := st.AddRule(dbrules.ProxyRule{
		Pattern: "*:public.secrets", Effect: dbrules.EffectDeny,
	})
	require.NoError(t, err)
	d := srv.decide(parse(t, "SELECT * FROM public.secrets"))
	assert.Equal(t, VerdictDeny, d.Verdict)
	assert.Equal(t, SourceGlobalDeny, d.Source)
}

func TestDecide_TaskDeny_BeatsGlobalAllow(t *testing.T) {
	srv, st := newDecideTestServer(t, DefaultPolicyAllow)
	// Global allow that would normally let the SELECT through.
	_, err := st.AddRule(dbrules.ProxyRule{
		Pattern: "SELECT:*", Effect: dbrules.EffectAllow,
	})
	require.NoError(t, err)
	// Task explicitly denies anything touching public.audit.
	scope, err := tasks.BuildScope(
		"investigate prod",
		[]dbrules.ProxyRule{{Pattern: "SELECT:*", Effect: dbrules.EffectAllow}},
		[]dbrules.ProxyRule{{Pattern: "*:public.audit", Effect: dbrules.EffectDeny}},
		30, "alice", "",
	)
	require.NoError(t, err)
	require.NoError(t, st.AddTask(scope))

	// LOAD-BEARING: task-deny beats global-allow.
	d := srv.decide(parse(t, "SELECT * FROM public.audit"))
	assert.Equal(t, VerdictDeny, d.Verdict, "task-deny MUST beat global-allow")
	assert.Equal(t, SourceTaskDeny, d.Source)
	assert.Equal(t, scope.TaskID, d.TaskID)
}

func TestDecide_GlobalDeny_BeatsTaskAllow(t *testing.T) {
	srv, st := newDecideTestServer(t, DefaultPolicyAllow)
	// Global deny — the admin's baseline.
	_, err := st.AddRule(dbrules.ProxyRule{
		Pattern: "*:public.secrets", Effect: dbrules.EffectDeny,
	})
	require.NoError(t, err)
	// Task tries to allow the very thing global denied.
	scope, err := tasks.BuildScope(
		"investigate prod",
		[]dbrules.ProxyRule{{Pattern: "SELECT:*", Effect: dbrules.EffectAllow}},
		nil,
		30, "alice", "",
	)
	require.NoError(t, err)
	require.NoError(t, st.AddTask(scope))

	// LOAD-BEARING: global-deny beats task-allow (admin's baseline is sacred).
	d := srv.decide(parse(t, "SELECT * FROM public.secrets"))
	assert.Equal(t, VerdictDeny, d.Verdict, "global-deny MUST beat task-allow")
	assert.Equal(t, SourceGlobalDeny, d.Source)
}

func TestDecide_TaskActive_NoTaskAllow_GlobalAllowPassThrough(t *testing.T) {
	srv, st := newDecideTestServer(t, DefaultPolicyDeny)
	// Global allow — infrastructure-level baseline.
	_, err := st.AddRule(dbrules.ProxyRule{
		Pattern: "READ:*", Effect: dbrules.EffectAllow,
	})
	require.NoError(t, err)
	// Task narrows DML only — doesn't mention SELECT.
	scope, err := tasks.BuildScope(
		"insert reports",
		[]dbrules.ProxyRule{{Pattern: "INSERT:reports.*", Effect: dbrules.EffectAllow}},
		nil,
		30, "alice", "",
	)
	require.NoError(t, err)
	require.NoError(t, st.AddTask(scope))

	// SELECT isn't in task-allow but global-allow READ:* matches —
	// passes through with global source (infrastructure call pattern).
	d := srv.decide(parse(t, "SELECT 1"))
	assert.Equal(t, VerdictAllow, d.Verdict)
	assert.Equal(t, SourceGlobalAllow, d.Source)
	assert.Equal(t, scope.TaskID, d.TaskID, "audit row still references the active task")
}

func TestDecide_TaskActive_NoTaskAllow_NoGlobalMatch_DenyOutOfScope(t *testing.T) {
	srv, st := newDecideTestServer(t, DefaultPolicyAllow)
	// Task narrows to INSERT only — SELECT isn't allowed by task OR
	// global. With a task active, unmatched-by-task = out-of-scope DENY.
	scope, err := tasks.BuildScope(
		"insert reports",
		[]dbrules.ProxyRule{{Pattern: "INSERT:reports.*", Effect: dbrules.EffectAllow}},
		nil,
		30, "alice", "",
	)
	require.NoError(t, err)
	require.NoError(t, st.AddTask(scope))

	d := srv.decide(parse(t, "SELECT 1"))
	assert.Equal(t, VerdictDeny, d.Verdict,
		"with task active + no task-allow match + no global-allow → DENY out-of-scope")
	assert.Equal(t, SourceTaskDeny, d.Source)
	assert.Equal(t, scope.TaskID, d.TaskID)
}

func TestDecide_MutatingCategory_CatchesCTEHiddenWrite(t *testing.T) {
	srv, st := newDecideTestServer(t, DefaultPolicyAllow)
	_, err := st.AddRule(dbrules.ProxyRule{
		Pattern: "MUTATING:*", Effect: dbrules.EffectDeny,
	})
	require.NoError(t, err)

	// A CTE-wrapped DELETE — top-level keyword WITH, real shape is a
	// mutation. The parser sets HasMutatingNode=true + StatementType=
	// WITH-WRITE. MUTATING:* MUST catch it.
	sql := `WITH gone AS (DELETE FROM public.users WHERE id < 100 RETURNING id) ` +
		`SELECT COUNT(*) FROM gone`
	ps := parse(t, sql)
	assert.True(t, ps.HasMutatingNode,
		"parser must flag CTE-wrapped DELETE as mutating (load-bearing precondition)")

	d := srv.decide(ps)
	assert.Equal(t, VerdictDeny, d.Verdict,
		"MUTATING:* rule MUST fire on CTE-hidden writes via HasMutatingNode — "+
			"this is the load-bearing safety claim for the whole rule engine")
	assert.Equal(t, SourceGlobalDeny, d.Source)
}

func TestDecide_MultiStatementBatch_AnyTableMatches(t *testing.T) {
	srv, st := newDecideTestServer(t, DefaultPolicyAllow)
	_, err := st.AddRule(dbrules.ProxyRule{
		Pattern: "*:public.secrets", Effect: dbrules.EffectDeny,
	})
	require.NoError(t, err)

	// Multi-statement batch: SELECT touches public.users, second
	// statement touches public.secrets. The parser collects ALL touched
	// tables across the batch; the rule's table glob must match if ANY
	// statement in the batch touches the scoped table.
	sql := `SELECT 1 FROM public.users; UPDATE public.secrets SET v = 1`
	ps := parse(t, sql)
	require.Contains(t, ps.TablesTouched, "public.secrets",
		"parser must collect tables across multi-statement batches")

	d := srv.decide(ps)
	assert.Equal(t, VerdictDeny, d.Verdict,
		"rule scoped on a table MUST match when ANY statement in a multi-statement batch touches it")
	assert.Equal(t, SourceGlobalDeny, d.Source)
}

func TestDecide_CallStmt_FunctionScopeAllowlist(t *testing.T) {
	srv, st := newDecideTestServer(t, DefaultPolicyDeny)
	// Allow only the approved stored procedure.
	_, err := st.AddRule(dbrules.ProxyRule{
		Pattern: "CALL:*", Effect: dbrules.EffectAllow,
		FunctionScope: "approved_proc",
	})
	require.NoError(t, err)

	d := srv.decide(parse(t, "CALL approved_proc()"))
	assert.Equal(t, VerdictAllow, d.Verdict)
	assert.Equal(t, SourceGlobalAllow, d.Source)

	d2 := srv.decide(parse(t, "CALL sketchy_proc()"))
	assert.Equal(t, VerdictDeny, d2.Verdict,
		"CALL outside the function-scope allowlist falls through to default-deny")
	assert.Equal(t, SourceDefault, d2.Source)
}

func TestDecide_AuditRowCarriesTaskIDAndSource(t *testing.T) {
	srv, st := newDecideTestServer(t, DefaultPolicyAllow)
	scope, err := tasks.BuildScope(
		"narrow task",
		[]dbrules.ProxyRule{{Pattern: "SELECT:reports.*", Effect: dbrules.EffectAllow}},
		nil,
		30, "alice", "",
	)
	require.NoError(t, err)
	require.NoError(t, st.AddTask(scope))

	srv.evaluateAndAudit("SELECT * FROM reports.monthly", "Query")

	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "ALLOW", rows[0].DecisionVerdict)
	assert.Equal(t, SourceTaskAllow, rows[0].DecisionSource)
	assert.Equal(t, scope.TaskID, rows[0].TaskID)
}

func TestDecide_TransparentMode_DenyMarkedEnforced(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	cfg := Config{
		Host:          "127.0.0.1",
		Port:          0,
		MgmtHost:      "127.0.0.1",
		MgmtPort:      0,
		Mode:          ModeTransparent,
		Dialect:       DialectPostgres,
		DefaultPolicy: DefaultPolicyDeny,
	}.Normalize()
	srv := NewServer(cfg, st)

	srv.evaluateAndAudit("SELECT 1", "Query")
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "DENY", rows[0].DecisionVerdict)
	assert.True(t, rows[0].Enforced,
		"transparent mode + DENY verdict MUST mark Enforced=true so D-Slice 2's "+
			"forwarding handler can return a SQL error to the client")
}

func TestDecide_CooperativeMode_DenyNotEnforced(t *testing.T) {
	srv, _ := newDecideTestServer(t, DefaultPolicyDeny)
	srv.evaluateAndAudit("SELECT 1", "Query")
	rows, err := srv.store.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "DENY", rows[0].DecisionVerdict)
	assert.False(t, rows[0].Enforced,
		"cooperative mode must NEVER set Enforced=true — observation-only "+
			"invariant survives the rule engine landing")
}

// ---------------------------------------------------------------------------
// MED-D8-09 (AUDIT-WB-DSLICES-1-8.md): --redact-literals round-trip tests.
// ---------------------------------------------------------------------------

func newRedactTestServer(t *testing.T, redact bool) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	cfg := Config{
		Host:           "127.0.0.1",
		MgmtHost:       "127.0.0.1",
		Mode:           ModeCooperative,
		Dialect:        DialectPostgres,
		DefaultPolicy:  DefaultPolicyAllow,
		RedactLiterals: redact,
	}.Normalize()
	srv := NewServer(cfg, st)
	return srv, st
}

func TestDecide_RedactLiteralsOff_PreservesSecrets(t *testing.T) {
	// Default behavior (backward compat): full SQL persisted.
	srv, st := newRedactTestServer(t, false)
	srv.evaluateAndAudit(`SELECT * FROM t WHERE pwd='supersecret'`, "Query")
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Contains(t, rows[0].Statement, "supersecret",
		"with --redact-literals=false (default), the secret stays in the audit row")
	assert.False(t, rows[0].StatementRedacted,
		"statement_redacted column must be false in default mode")
}

func TestDecide_RedactLiteralsOn_SwapsSecrets(t *testing.T) {
	srv, st := newRedactTestServer(t, true)
	srv.evaluateAndAudit(`SELECT pwd_hash FROM auth WHERE user='alice'`, "Query")
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.NotContains(t, rows[0].Statement, "alice",
		"with --redact-literals=true the string literal MUST be swapped before persistence")
	assert.Contains(t, rows[0].Statement, "[REDACTED]",
		"redacted statement must carry the [REDACTED] placeholder")
	assert.True(t, rows[0].StatementRedacted,
		"statement_redacted column MUST be true when redaction fired")
	// Identifiers + statement-type metadata remain intact — audit row is
	// still useful for shape review.
	assert.Contains(t, rows[0].Statement, "pwd_hash")
	assert.Contains(t, rows[0].Statement, "auth")
	assert.Equal(t, "SELECT", rows[0].StatementType,
		"redaction MUST NOT affect statement_type")
	assert.Equal(t, []string{"auth"}, rows[0].TablesTouched,
		"redaction MUST NOT affect tables_touched (parser ran on raw SQL)")
}

func TestDecide_RedactLiteralsOn_NoSecretsLeavesStatementUntouched(t *testing.T) {
	// SQL without any string literals → statement_redacted MUST remain
	// false (the operator sees "this row had nothing to redact" vs
	// "this row was processed by the redactor and changed").
	srv, st := newRedactTestServer(t, true)
	srv.evaluateAndAudit("SELECT count(*) FROM users WHERE id = 42", "Query")
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "SELECT count(*) FROM users WHERE id = 42", rows[0].Statement,
		"no string literals → original SQL preserved")
	assert.False(t, rows[0].StatementRedacted,
		"statement_redacted must be false when no literal was actually swapped")
}

func TestDecide_RedactLiteralsOn_UTF8SecretsScrubbed(t *testing.T) {
	// Edge case the audit doc highlighted: non-Latin-1 quoted string
	// literals MUST round-trip cleanly through the redactor.
	srv, st := newRedactTestServer(t, true)
	srv.evaluateAndAudit(
		`SELECT * FROM t WHERE greeting = 'こんにちは' AND user_name = 'héllo'`, "Query")
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.NotContains(t, rows[0].Statement, "こんにちは")
	assert.NotContains(t, rows[0].Statement, "héllo")
	assert.True(t, rows[0].StatementRedacted)
}

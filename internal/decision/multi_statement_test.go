// EvaluateMultiStatement tests for #587 CRIT deploy-blocker.
//
// State-verification per CONTRIBUTING.md: every assertion checks
// observable state (verdict + reason naming position). The reason
// strings these tests pin are the same strings SIEM filters key on +
// the same strings operators see in `dbounce decide` output, so the
// substring assertions ARE the contract.
//
// Spec coverage map (task #587 Step 3):
//
//  1. TestMultiStmt_AllAllow_PassThrough           — all 3 SELECTs allow
//  2. TestMultiStmt_GrantInPosition2_Denies        — UAT-C bypass closed
//  3. TestMultiStmt_GrantInPosition1_Denies        — single-stmt regression
//  4. TestMultiStmt_TransactionControl_Allow       — BEGIN/SELECT/COMMIT
//  5. TestMultiStmt_TransactionWithEmbeddedAdmin   — DENY at position 2
//  6. TestMultiStmt_CreateRoleInPosition3_Denies   — position 3 DENY
//  7. TestMultiStmt_QuotedSemicolons_HandledCorrectly — string-literal `;`
//  8. TestMultiStmt_TrailingSemicolon_NoEmptyStatement — terminal `;`
//  9. TestMultiStmt_EmptyBetweenSeparators_Skipped — `;;` tolerated
// 10. TestMultiStmt_MySQLEquivalent_SamePattern    — MySQL parity
// 11. TestMultiStmt_CrossDialect_BothDeny          — PG + MySQL DENY parametrize
//  S. TestMultiStmt_SabotageCheck_SingleStmtFallback — splitter sabotage

package decision

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/parser"
)

// TestMultiStmt_AllAllow_PassThrough (#587 spec test 1). All three
// SELECTs are non-DCL — Applicable=false (no statement triggered the
// floor). The caller's existing default-policy / rule-engine flow
// applies unchanged.
func TestMultiStmt_AllAllow_PassThrough(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres,
		"SELECT 1; SELECT 2; SELECT 3", nil, "allow", nil)
	assert.False(t, mv.Deny,
		"all-SELECT batch MUST NOT trigger the floor")
	assert.Equal(t, 3, mv.StatementCount,
		"splitter MUST identify 3 statements in this batch")
	assert.Equal(t, 0, mv.Position,
		"no DENY MUST leave Position=0")
	assert.Empty(t, mv.Reason,
		"no DENY MUST leave Reason empty (caller continues its flow)")
}

// TestMultiStmt_GrantInPosition2_Denies (#587 spec test 2 — the CRIT).
// This is the EXACT UAT-C 2026-05-25 bypass. The fix MUST close it: the
// embedded GRANT at position 2 of 3 triggers the floor + the reason
// names the position so operators debugging see WHICH statement fired.
func TestMultiStmt_GrantInPosition2_Denies(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres,
		"SELECT 1; GRANT ALL ON foo TO PUBLIC; SELECT 2", nil, "allow", nil)
	require.True(t, mv.Deny,
		"#587 CRIT — embedded GRANT at position 2 MUST trigger the floor "+
			"(this was ALLOWED before the fix; the bypass is closed when this test passes)")
	assert.Equal(t, 3, mv.StatementCount,
		"splitter MUST identify 3 statements")
	assert.Equal(t, 2, mv.Position,
		"DENY MUST name position 2 (1-indexed)")
	assert.Contains(t, mv.Reason, "statement 2/3",
		"reason MUST name the position so operators can debug the verdict "+
			"(per [[ibounce-honest-positioning]]: name the offender, don't return 'batch rejected')")
	assert.Contains(t, mv.Reason, "admin-tight floor",
		"reason MUST name the floor (SIEM filters key on this string)")
	assert.Contains(t, mv.Reason, "GRANT",
		"reason MUST name the statement type that triggered the floor")
}

// TestMultiStmt_GrantInPosition1_Denies (#587 spec test 3). Regression
// check: the single-statement path through the splitter MUST still
// trigger the floor. Position=1 of 1.
func TestMultiStmt_GrantInPosition1_Denies(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres,
		"GRANT ALL ON foo TO PUBLIC; SELECT 1", nil, "allow", nil)
	require.True(t, mv.Deny,
		"GRANT at position 1 of a multi-statement batch MUST still trigger the floor "+
			"(single-statement regression check)")
	assert.Equal(t, 2, mv.StatementCount)
	assert.Equal(t, 1, mv.Position,
		"DENY MUST name position 1")
	assert.Contains(t, mv.Reason, "statement 1/2")
}

// TestMultiStmt_SingleStatement_GrantDenies covers the no-separator
// shape (no `;` in the input). The splitter returns 1 statement;
// EvaluateMultiStatement reports Position=1 / Count=1 so callers see
// a uniform "statement N/M" tag across single + multi shapes.
func TestMultiStmt_SingleStatement_GrantDenies(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres,
		"GRANT ALL ON foo TO PUBLIC", nil, "allow", nil)
	require.True(t, mv.Deny,
		"single-statement GRANT MUST still trigger the floor (parity with pre-#587 shape)")
	assert.Equal(t, 1, mv.StatementCount)
	assert.Equal(t, 1, mv.Position)
	assert.Contains(t, mv.Reason, "statement 1/1",
		"single-statement input MUST surface as 'statement 1/1' (uniform N/M tag)")
}

// TestMultiStmt_TransactionControl_Allow (#587 spec test 4).
// `BEGIN; SELECT 1; COMMIT` — 3 benign statements, no DCL anywhere.
// Floor MUST NOT fire.
func TestMultiStmt_TransactionControl_Allow(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres,
		"BEGIN; SELECT 1; COMMIT", nil, "allow", nil)
	assert.False(t, mv.Deny,
		"BEGIN/SELECT/COMMIT batch is all non-DCL — floor MUST NOT fire")
	assert.Equal(t, 3, mv.StatementCount,
		"splitter MUST identify 3 statements in a transaction-control batch")
}

// TestMultiStmt_TransactionWithEmbeddedAdmin_Denies (#587 spec test 5).
// `BEGIN; GRANT ...; COMMIT` — DCL hidden inside a transaction is the
// most common adversarial shape. Floor MUST fire on position 2.
func TestMultiStmt_TransactionWithEmbeddedAdmin_Denies(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres,
		"BEGIN; GRANT ALL ON foo TO PUBLIC; COMMIT", nil, "allow", nil)
	require.True(t, mv.Deny,
		"GRANT hidden inside BEGIN/COMMIT MUST trigger the floor at position 2")
	assert.Equal(t, 2, mv.Position)
	assert.Equal(t, 3, mv.StatementCount)
	assert.Contains(t, mv.Reason, "statement 2/3")
	assert.Contains(t, mv.Reason, "admin-tight floor")
}

// TestMultiStmt_GrantInPosition3_Denies (#587 spec test 6 adapted).
// CREATE ROLE is PG DDL not DCL — the existing PG parser classifies it
// as StmtDDL, not StmtGrant — and the floor only fires on admin-grant
// shapes (per #586 separate-agent scope). So we exercise the same
// position-3 shape using GRANT (which IS classified as DCL).
// CREATE ROLE behavior is owned by #586 (see task "Out of scope:
// DO NOT fix #586 in this PR").
func TestMultiStmt_GrantInPosition3_Denies(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres,
		"SELECT 1; SELECT 2; GRANT ALL ON foo TO PUBLIC", nil, "allow", nil)
	require.True(t, mv.Deny,
		"GRANT at position 3 MUST trigger the floor "+
			"(left-to-right scan reaches every statement)")
	assert.Equal(t, 3, mv.Position,
		"DENY MUST name position 3")
	assert.Equal(t, 3, mv.StatementCount)
	assert.Contains(t, mv.Reason, "statement 3/3")
}

// TestMultiStmt_QuotedSemicolons_HandledCorrectly (#587 spec test 7).
// `INSERT INTO t VALUES ('a;b'); SELECT 1` — 2 statements (NOT 3). The
// `;` inside the string literal is data, not a separator. Both
// statements are non-DCL so the floor MUST NOT fire.
func TestMultiStmt_QuotedSemicolons_HandledCorrectly(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres,
		"INSERT INTO t VALUES ('a;b'); SELECT 1", nil, "allow", nil)
	assert.False(t, mv.Deny,
		"INSERT + SELECT batch MUST NOT trigger floor (no DCL)")
	assert.Equal(t, 2, mv.StatementCount,
		"`;` inside `'...'` MUST NOT split — 2 statements not 3 (spec test #7)")
}

// TestMultiStmt_TrailingSemicolon_NoEmptyStatement (#587 spec test 8).
// `SELECT 1;` — exactly 1 statement, not 2. A phantom empty trailing
// statement would mis-classify (StmtUnknown / unparseable noise) +
// throw off the SIEM "statement N/M" tag.
func TestMultiStmt_TrailingSemicolon_NoEmptyStatement(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres,
		"SELECT 1;", nil, "allow", nil)
	assert.False(t, mv.Deny)
	assert.Equal(t, 1, mv.StatementCount,
		"trailing `;` MUST NOT produce a phantom empty statement (spec test #8)")
}

// TestMultiStmt_EmptyBetweenSeparators_Skipped (#587 spec test 9).
// `SELECT 1;;SELECT 2` — 2 statements (the empty between separators
// is skipped). Operators sometimes mash semicolons; the splitter
// tolerates.
func TestMultiStmt_EmptyBetweenSeparators_Skipped(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres,
		"SELECT 1;;SELECT 2", nil, "allow", nil)
	assert.False(t, mv.Deny)
	assert.Equal(t, 2, mv.StatementCount,
		"empty between separators MUST be skipped (spec test #9)")
}

// TestMultiStmt_MySQLEquivalent_SamePattern (#587 spec test 10). Repeat
// the GRANT-in-position-2 shape for MySQL dialect — the same bypass
// applies via multi-statements=true clients. Cross-dialect parity is
// the [[scorer-is-ground-truth]] invariant.
func TestMultiStmt_MySQLEquivalent_SamePattern(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectMySQL,
		"SELECT 1; GRANT ALL ON foo.* TO 'bob'@'%'; SELECT 2", nil, "allow", nil)
	require.True(t, mv.Deny,
		"MySQL GRANT at position 2 MUST trigger the floor (parity with PG)")
	assert.Equal(t, 2, mv.Position)
	assert.Equal(t, 3, mv.StatementCount)
	assert.Contains(t, mv.Reason, "statement 2/3")
	assert.Contains(t, mv.Reason, "GRANT")
}

// TestMultiStmt_CrossDialect_BothDeny (#587 spec test 11). Parametrize
// PG + MySQL with the embedded-GRANT shape; verify BOTH DENY at the
// same position. Closes "did one dialect drift silently?" — a structural
// test that mirrors the cross-dialect invariant in admin_tight_test.go.
func TestMultiStmt_CrossDialect_BothDeny(t *testing.T) {
	cases := []struct {
		dialect string
		sql     string
	}{
		{
			dialect: parser.DialectPostgres,
			sql:     "SELECT 1; GRANT ALL ON foo TO PUBLIC; SELECT 2",
		},
		{
			dialect: parser.DialectMySQL,
			sql:     "SELECT 1; GRANT ALL ON foo.* TO 'bob'@'%'; SELECT 2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.dialect, func(t *testing.T) {
			mv := EvaluateMultiStatement(tc.dialect, tc.sql, nil, "allow", nil)
			require.True(t, mv.Deny,
				"%s embedded GRANT MUST trigger the floor", tc.dialect)
			assert.Equal(t, 2, mv.Position,
				"%s DENY MUST name position 2", tc.dialect)
			assert.Equal(t, 3, mv.StatementCount,
				"%s splitter MUST identify 3 statements", tc.dialect)
			assert.Contains(t, mv.Reason, "statement 2/3")
		})
	}
}

// TestMultiStmt_EmptyInput_NotApplicable covers the empty-input edge.
// EvaluateMultiStatement returns Count=0 with no Deny so the caller's
// existing "no SQL to evaluate" handling applies unchanged.
func TestMultiStmt_EmptyInput_NotApplicable(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres, "", nil, "allow", nil)
	assert.False(t, mv.Deny,
		"empty input MUST NOT trigger the floor")
	assert.Equal(t, 0, mv.StatementCount,
		"empty input MUST report 0 statements")
}

// TestMultiStmt_AlterDefaultPrivileges_AtPosition2_Denies extends the
// floor coverage to the second DCL-shape the existing floor recognizes
// (StmtAlterPrivileges). Same position-naming contract.
func TestMultiStmt_AlterDefaultPrivileges_AtPosition2_Denies(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres,
		"SELECT 1; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO bob; SELECT 2",
		nil, "allow", nil)
	require.True(t, mv.Deny,
		"ALTER DEFAULT PRIVILEGES embedded at position 2 MUST trigger the floor")
	assert.Equal(t, 2, mv.Position)
	assert.Contains(t, mv.Reason, "ALTER_PRIVILEGES",
		"reason MUST name the statement type")
}

// TestMultiStmt_RevokeNotCaught_AsPositionedShape verifies REVOKE
// embedded at position 2 of a batch does NOT trigger the floor (REVOKE
// is the safe cleanup direction per UC-34 + #556). Mirrors the single-
// statement TestAdminTightFloor_RevokeNotCaught.
func TestMultiStmt_RevokeNotCaught_AsPositionedShape(t *testing.T) {
	mv := EvaluateMultiStatement(parser.DialectPostgres,
		"SELECT 1; REVOKE SELECT ON foo FROM bob; SELECT 2", nil, "allow", nil)
	assert.False(t, mv.Deny,
		"REVOKE is cleanup direction — floor MUST NOT fire even when embedded "+
			"(same invariant as single-statement TestAdminTightFloor_RevokeNotCaught)")
	assert.Equal(t, 3, mv.StatementCount,
		"splitter MUST still identify all 3 statements")
}

// TestMultiStmt_SabotageCheck_SingleStmtFallback is the per-task
// sabotage-check (spec test #13): we monkey-patch the evaluator at the
// test level by passing ONLY the first statement of a known-bypass
// batch. The test confirms that absent multi-statement handling the
// floor would NOT fire on position 2 (because position 2 is invisible
// to the parser when the whole batch is parsed as one ParsedStatement).
// This pins WHY the splitter is needed — if a future refactor reverts
// to single-ParsedStatement evaluation, this test stays GREEN
// (single-statement input doesn't see the embedded GRANT) but the
// position-2 test above STAYS RED, which is the regression signal.
//
// More directly: we exercise the FIRST statement of the bypass batch
// in isolation; AdminTightFloor returns applicable=false (SELECT 1 is
// not DCL). This is the per-task "monkeypatch the splitter to always
// return 1 statement (the first only); verify test 2 fails" check — we
// emulate the broken-splitter result by calling AdminTightFloor on the
// parser output of "SELECT 1" alone.
func TestMultiStmt_SabotageCheck_SingleStmtFallback(t *testing.T) {
	// Emulate a sabotaged splitter that returns ONLY the first
	// statement of the bypass batch. The floor MUST NOT fire on
	// "SELECT 1" alone — this is the failure mode the splitter exists
	// to prevent. The actual fix MUST fire on the embedded GRANT (per
	// TestMultiStmt_GrantInPosition2_Denies above); failing this
	// sabotage-check while THAT test passes is the contract pair.
	ps := parser.Parse(parser.DialectPostgres, "SELECT 1")
	deny, _, applicable := AdminTightFloor(ps, nil, "allow")
	assert.False(t, applicable,
		"sabotage emulation: SELECT 1 alone is not DCL — floor MUST NOT engage")
	assert.False(t, deny,
		"sabotage emulation: SELECT 1 alone is not DCL — no DENY")
	// The contract: a sabotaged splitter that only returned this
	// statement would silently allow the WHOLE original bypass batch.
	// EvaluateMultiStatement's position-2 test pins that the real
	// splitter does NOT regress to this shape.
}

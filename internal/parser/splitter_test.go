// SplitStatements tests for #587 CRIT deploy-blocker — multi-statement
// batch evaluation. State-verification tests per CONTRIBUTING.md: every
// assertion checks observable output (the returned slice's length and
// contents), not implementation internals.

package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSplitStatements_Empty covers the no-input edge case. Empty +
// whitespace-only + comment-only inputs return nil/empty so the caller's
// existing "no statements" handling applies unchanged.
func TestSplitStatements_Empty(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"empty", ""},
		{"whitespace only", "   \t\n  "},
		{"single-line comment only", "-- just a comment\n"},
		{"block comment only", "/* nothing here */"},
		{"semicolons only", ";;;"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitStatements(DialectPostgres, tc.sql)
			assert.Empty(t, got,
				"empty / whitespace-only / comment-only / sep-only input MUST return no statements")
		})
	}
}

// TestSplitStatements_SingleStatement_NoSeparator covers the most
// common case: a single SQL statement with no trailing `;`. Splitter
// returns the whole input as one statement so single-statement callers
// see no behavior change.
func TestSplitStatements_SingleStatement_NoSeparator(t *testing.T) {
	got := SplitStatements(DialectPostgres, "SELECT 1")
	assert.Equal(t, []string{"SELECT 1"}, got,
		"single statement with no separator MUST return [stmt]")
}

// TestSplitStatements_TrailingSemicolon_NoEmptyStatement pins the
// per-spec invariant: `SELECT 1;` produces ONE statement, not two.
// Test #8 of the spec: terminal `;` is end-of-batch, not a separator
// for a phantom empty statement.
func TestSplitStatements_TrailingSemicolon_NoEmptyStatement(t *testing.T) {
	got := SplitStatements(DialectPostgres, "SELECT 1;")
	assert.Equal(t, []string{"SELECT 1"}, got,
		"trailing `;` MUST NOT produce a phantom empty trailing statement (spec test #8)")
}

// TestSplitStatements_TwoStatements_BothReturned pins the basic multi-
// statement shape: `SELECT 1; SELECT 2` returns both statements.
func TestSplitStatements_TwoStatements_BothReturned(t *testing.T) {
	got := SplitStatements(DialectPostgres, "SELECT 1; SELECT 2")
	assert.Equal(t, []string{"SELECT 1", "SELECT 2"}, got)
}

// TestSplitStatements_ThreeStatements_AllReturned exercises a longer
// batch that the spec test #1 (TestMultiStmt_AllAllow_PassThrough)
// will feed into the decision layer.
func TestSplitStatements_ThreeStatements_AllReturned(t *testing.T) {
	got := SplitStatements(DialectPostgres, "SELECT 1; SELECT 2; SELECT 3")
	assert.Equal(t, []string{"SELECT 1", "SELECT 2", "SELECT 3"}, got)
}

// TestSplitStatements_EmptyBetweenSeparators_Skipped pins spec test #9:
// `SELECT 1;;SELECT 2` → 2 statements (the empty between separators is
// skipped). Operators sometimes mash extra semicolons; the splitter
// MUST tolerate.
func TestSplitStatements_EmptyBetweenSeparators_Skipped(t *testing.T) {
	got := SplitStatements(DialectPostgres, "SELECT 1;;SELECT 2")
	assert.Equal(t, []string{"SELECT 1", "SELECT 2"}, got,
		"empty statements between separators MUST be skipped (spec test #9)")
}

// TestSplitStatements_QuotedSemicolons_HandledCorrectly pins spec test
// #7: `;` inside a single-quoted string literal is LITERAL TEXT, not a
// separator. This is the load-bearing string-literal correctness check
// — getting it wrong causes false-split mid-statement.
func TestSplitStatements_QuotedSemicolons_HandledCorrectly(t *testing.T) {
	got := SplitStatements(DialectPostgres,
		"INSERT INTO t VALUES ('a;b'); SELECT 1")
	assert.Equal(t, []string{
		"INSERT INTO t VALUES ('a;b')",
		"SELECT 1",
	}, got, "`;` inside `'...'` MUST NOT split (spec test #7)")
}

// TestSplitStatements_QuotedSemicolons_DoubleQuoted covers the double-
// quoted-identifier case. PostgreSQL `"..."` is an identifier; MySQL
// `"..."` is a string (mode-dependent). Either way the `;` inside
// MUST be literal text, not a separator.
func TestSplitStatements_QuotedSemicolons_DoubleQuoted(t *testing.T) {
	got := SplitStatements(DialectPostgres,
		`SELECT "col;name" FROM t; SELECT 2`)
	assert.Equal(t, []string{
		`SELECT "col;name" FROM t`,
		"SELECT 2",
	}, got, "`;` inside `\"...\"` MUST NOT split")
}

// TestSplitStatements_QuotedSemicolons_Backtick covers MySQL backtick-
// quoted identifiers. Same invariant: `;` inside “ `...` “ is literal.
func TestSplitStatements_QuotedSemicolons_Backtick(t *testing.T) {
	got := SplitStatements(DialectMySQL,
		"SELECT `col;name` FROM t; SELECT 2")
	assert.Equal(t, []string{
		"SELECT `col;name` FROM t",
		"SELECT 2",
	}, got, "`;` inside `` ` ` `` MUST NOT split")
}

// TestSplitStatements_DoubledQuoteEscape_HandledCorrectly covers the
// SQL-standard `”` escape inside `'...'`: the doubled quote is a
// literal single quote, NOT a string terminator. A `;` after the `”`
// stays INSIDE the string.
func TestSplitStatements_DoubledQuoteEscape_HandledCorrectly(t *testing.T) {
	got := SplitStatements(DialectPostgres,
		"INSERT INTO t VALUES ('it''s; fine'); SELECT 1")
	assert.Equal(t, []string{
		"INSERT INTO t VALUES ('it''s; fine')",
		"SELECT 1",
	}, got, "doubled-quote `''` MUST NOT terminate the string (`;` stays inside)")
}

// TestSplitStatements_BackslashEscape_HandledCorrectly covers the
// MySQL/Snowflake `\'` escape inside `'...'`: the backslash + quote is
// a literal quote, NOT a terminator. `;` after the `\'` stays INSIDE
// the string.
func TestSplitStatements_BackslashEscape_HandledCorrectly(t *testing.T) {
	got := SplitStatements(DialectMySQL,
		`INSERT INTO t VALUES ('it\'s; fine'); SELECT 1`)
	assert.Equal(t, []string{
		`INSERT INTO t VALUES ('it\'s; fine')`,
		"SELECT 1",
	}, got, "backslash-quote `\\'` MUST NOT terminate the string (`;` stays inside)")
}

// TestSplitStatements_SingleLineComment_SemicolonInside pins the
// single-line-comment correctness invariant: `;` inside `-- ... \n`
// is comment text, NOT a separator.
func TestSplitStatements_SingleLineComment_SemicolonInside(t *testing.T) {
	got := SplitStatements(DialectPostgres,
		"SELECT 1 -- ; not a separator\n; SELECT 2")
	assert.Equal(t, []string{
		"SELECT 1 -- ; not a separator",
		"SELECT 2",
	}, got, "`;` inside `-- ...\\n` MUST NOT split (the `;` after \\n IS a separator)")
}

// TestSplitStatements_BlockComment_SemicolonInside pins the block-
// comment correctness invariant: `;` inside `/* ... */` is comment
// text, NOT a separator.
func TestSplitStatements_BlockComment_SemicolonInside(t *testing.T) {
	got := SplitStatements(DialectPostgres,
		"SELECT 1 /* ignore ; this */; SELECT 2")
	assert.Equal(t, []string{
		"SELECT 1 /* ignore ; this */",
		"SELECT 2",
	}, got, "`;` inside `/* ... */` MUST NOT split")
}

// TestSplitStatements_BlockComment_Nested pins the nested-block-
// comment correctness invariant (PostgreSQL + Snowflake nest; we treat
// all dialects as nesting conservatively per the stripcomments.go
// invariant). `;` inside ANY level of nesting MUST NOT split.
func TestSplitStatements_BlockComment_Nested(t *testing.T) {
	got := SplitStatements(DialectPostgres,
		"SELECT 1 /* outer /* inner ; still inside */ outer ; still */; SELECT 2")
	assert.Equal(t, []string{
		"SELECT 1 /* outer /* inner ; still inside */ outer ; still */",
		"SELECT 2",
	}, got, "`;` inside nested `/* /* */ */` MUST NOT split")
}

// TestSplitStatements_TransactionControl_ThreeStatements pins the
// transaction-control shape from spec test #4: `BEGIN; SELECT 1; COMMIT`
// → 3 statements. The decision layer then evaluates each individually.
func TestSplitStatements_TransactionControl_ThreeStatements(t *testing.T) {
	got := SplitStatements(DialectPostgres, "BEGIN; SELECT 1; COMMIT")
	assert.Equal(t, []string{"BEGIN", "SELECT 1", "COMMIT"}, got,
		"transaction-control batch MUST produce 3 statements (spec test #4)")
}

// TestSplitStatements_GrantInPosition2 pins the EXACT UAT-C bypass
// shape — the splitter MUST identify GRANT as statement 2 of 3 so the
// downstream decision layer can apply the floor to it. Failing this
// test means the CRIT bypass is still live.
func TestSplitStatements_GrantInPosition2(t *testing.T) {
	got := SplitStatements(DialectPostgres,
		"SELECT 1; GRANT ALL ON foo TO PUBLIC; SELECT 2")
	assert.Equal(t, []string{
		"SELECT 1",
		"GRANT ALL ON foo TO PUBLIC",
		"SELECT 2",
	}, got, "UAT-C 2026-05-25 #587 — splitter MUST identify GRANT as the position-2 statement")
}

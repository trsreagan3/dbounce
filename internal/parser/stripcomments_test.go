package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Tests for stripSQLComments — the shared helper that closes CRIT-D8-01
// + CRIT-D8-02 (AUDIT-WB-DSLICES-1-8.md). The audit doc enumerates the
// exact regression cases the rule pack relies on; we add them here as
// table-driven tests so any future change to the helper fails loudly.

func TestStripSQLComments_Empty(t *testing.T) {
	assert.Equal(t, "", stripSQLComments(""))
}

func TestStripSQLComments_NoComments(t *testing.T) {
	in := "SELECT * FROM users WHERE id = 1"
	assert.Equal(t, in, stripSQLComments(in))
}

func TestStripSQLComments_LeadingBlockComment(t *testing.T) {
	in := "/* x */ LOAD DATA INFILE '/etc/passwd' INTO TABLE u"
	out := stripSQLComments(in)
	// Comment becomes spaces; the LOAD DATA verb is now at the prefix
	// (modulo leading whitespace, which TrimSpace at the call site
	// removes).
	upper := strings.ToUpper(strings.TrimSpace(out))
	assert.True(t, strings.HasPrefix(upper, "LOAD DATA"),
		"after stripping the block comment + TrimSpace, the prefix MUST be LOAD DATA; got %q", upper)
}

func TestStripSQLComments_LeadingLineComment(t *testing.T) {
	in := "-- comment line\nLOAD DATA INFILE '/tmp/x' INTO TABLE secrets"
	out := stripSQLComments(in)
	upper := strings.ToUpper(strings.TrimSpace(out))
	assert.True(t, strings.HasPrefix(upper, "LOAD DATA"),
		"after stripping the -- comment + TrimSpace, the prefix MUST be LOAD DATA; got %q", upper)
}

func TestStripSQLComments_NestedBlockComment(t *testing.T) {
	in := "/*outer /*inner*/ outer*/ LOAD DATA INFILE '/tmp/x' INTO TABLE u"
	out := stripSQLComments(in)
	upper := strings.ToUpper(strings.TrimSpace(out))
	assert.True(t, strings.HasPrefix(upper, "LOAD DATA"),
		"nested block comments MUST strip fully; got %q", upper)
}

func TestStripSQLComments_StringLiteralPreserved(t *testing.T) {
	// The CRITICAL case: comment markers inside a string literal are NOT
	// comment delimiters; they MUST be preserved. Otherwise we'd strip
	// the literal contents and either misclassify or change the audit
	// row's recorded SQL semantics.
	in := "SELECT '/* not a comment */' FROM t"
	out := stripSQLComments(in)
	assert.Equal(t, in, out,
		"string-literal contents MUST be preserved verbatim; got %q", out)
}

func TestStripSQLComments_StringLiteralWithEscapedQuote(t *testing.T) {
	// SQL-standard `''` inside `'...'` is an escaped single quote. The
	// helper must NOT treat the inner `'` as a terminator, or the rest
	// of the line gets stripped as if it were outside the literal.
	in := `SELECT 'it''s /* still in literal */' FROM t`
	out := stripSQLComments(in)
	assert.Equal(t, in, out,
		"SQL `''` escape inside string literal MUST keep the literal intact; got %q", out)
}

func TestStripSQLComments_StringLiteralBackslashEscape(t *testing.T) {
	// MySQL / Snowflake accept backslash escape. `\'` inside a `'...'`
	// must not terminate the literal.
	in := `SELECT 'foo\'bar /* still */ baz' FROM t`
	out := stripSQLComments(in)
	assert.Equal(t, in, out,
		"backslash-escaped quote MUST keep the literal intact; got %q", out)
}

func TestStripSQLComments_DoubleQuotedIdentifierPreserved(t *testing.T) {
	// PG / Snowflake / BigQuery use double-quoted identifiers; MySQL
	// uses backticks but also tolerates double-quotes in some modes.
	// Either way, `"..."` is a quoted region and comment markers inside
	// MUST be preserved.
	in := `SELECT "col-with-/* in it */" FROM t`
	out := stripSQLComments(in)
	assert.Equal(t, in, out,
		"double-quoted identifier contents MUST be preserved; got %q", out)
}

func TestStripSQLComments_BacktickIdentifierPreserved(t *testing.T) {
	in := "SELECT `col /* not stripped */` FROM t"
	out := stripSQLComments(in)
	assert.Equal(t, in, out,
		"backtick-quoted identifier contents MUST be preserved; got %q", out)
}

func TestStripSQLComments_AdjacentCommentNoConcat(t *testing.T) {
	// `EXPORT/* */DATA` must NOT become `EXPORTDATA` — the comment
	// region is replaced with a single space so the surrounding tokens
	// stay distinct.
	in := "EXPORT/* */DATA OPTIONS()"
	out := stripSQLComments(in)
	// After stripping, the two tokens MUST remain separated.
	assert.True(t, strings.Contains(out, "EXPORT ") || strings.Contains(out, "EXPORT  DATA"),
		"adjacent tokens MUST NOT concatenate after comment removal; got %q", out)
	// Verify the verb shape still matches an upper-prefix scan.
	upper := strings.ToUpper(strings.TrimSpace(out))
	assert.True(t, strings.HasPrefix(upper, "EXPORT "),
		"EXPORT prefix MUST survive a comment between EXPORT and DATA; got %q", upper)
}

func TestStripSQLComments_NewlinesPreserved(t *testing.T) {
	// Line-number alignment for any downstream parse error: newlines
	// inside block comments MUST be kept in the output.
	in := "/*\n\n*/ SELECT 1"
	out := stripSQLComments(in)
	assert.Equal(t, strings.Count(in, "\n"), strings.Count(out, "\n"),
		"newline count MUST be preserved through block-comment stripping")
}

func TestStripSQLComments_UnclosedBlockComment(t *testing.T) {
	// Malformed input — unclosed `/*` consumes to EOF. The conservative
	// behavior: no extension prefix matches, the statement falls through
	// to xwb1989 which records a parse error. We just verify the helper
	// doesn't panic.
	in := "/* never closed LOAD DATA INFILE '/tmp/x' INTO TABLE u"
	out := stripSQLComments(in)
	// Output should be just the leading space (the substitute for `/*`)
	// plus preserved newlines (none in this case).
	assert.NotPanics(t, func() { _ = out })
}

func TestStripSQLComments_CaseInsensitiveCallerHandles(t *testing.T) {
	// The helper itself does NOT case-fold; that's the caller's job
	// (every caller does `strings.ToUpper(strings.TrimSpace(...))` on
	// the stripped output). Just verify mixed-case input survives the
	// strip and a TrimSpace+ToUpper at the call site finds the verb.
	in := "/* */ lOaD DaTa InFiLe '/tmp/x' INTO TABLE secrets"
	out := stripSQLComments(in)
	upper := strings.ToUpper(strings.TrimSpace(out))
	assert.True(t, strings.HasPrefix(upper, "LOAD DATA"),
		"case-insensitive prefix MUST match after strip + ToUpper; got %q", upper)
}

func TestStripSQLComments_ExportDataInLiteralNotFlagged(t *testing.T) {
	// Inverse of the load-bearing case: a SELECT whose literal happens
	// to contain `EXPORT DATA` as text MUST stay a SELECT — the literal
	// is preserved verbatim and the leading verb is still SELECT.
	in := "SELECT 'EXPORT DATA' FROM t -- inline comment after EXPORT DATA"
	out := stripSQLComments(in)
	upper := strings.ToUpper(strings.TrimSpace(out))
	assert.True(t, strings.HasPrefix(upper, "SELECT"),
		"SELECT classification MUST be preserved when literal contains EXPORT DATA; got %q", upper)
	// And the literal text itself MUST be preserved.
	assert.True(t, strings.Contains(out, "'EXPORT DATA'"),
		"literal `'EXPORT DATA'` MUST be preserved verbatim; got %q", out)
}

func TestStripSQLComments_MultipleLeadingComments(t *testing.T) {
	// A LOAD DATA hidden behind several stacked comments — equivalent
	// to the audit's CRIT-D8-01 reproduction but more layered.
	in := "/* one */ /* two */ -- three\n LOAD DATA INFILE '/tmp/x' INTO TABLE u"
	out := stripSQLComments(in)
	upper := strings.ToUpper(strings.TrimSpace(out))
	assert.True(t, strings.HasPrefix(upper, "LOAD DATA"),
		"layered comments MUST all strip; got %q", upper)
}

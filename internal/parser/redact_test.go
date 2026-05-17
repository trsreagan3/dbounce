package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Tests for RedactLiterals (MED-D8-09 closure). Mirror the literal-
// preservation invariants stripcomments_test.go locks in — if either
// test set fails, the audit-log shape is wrong in a security-relevant
// way.

func TestRedactLiterals_Empty(t *testing.T) {
	assert.Equal(t, "", RedactLiterals(""))
}

func TestRedactLiterals_NoLiterals_Unchanged(t *testing.T) {
	in := "SELECT count(*) FROM users WHERE id = 42"
	assert.Equal(t, in, RedactLiterals(in))
}

func TestRedactLiterals_SingleQuotedLiteral_Swapped(t *testing.T) {
	in := "SELECT * FROM users WHERE name = 'alice'"
	want := "SELECT * FROM users WHERE name = '[REDACTED]'"
	assert.Equal(t, want, RedactLiterals(in))
}

func TestRedactLiterals_MultipleLiterals_AllSwapped(t *testing.T) {
	in := "INSERT INTO sessions VALUES ('alice', 'sk-live-abc123', '2026-01-01')"
	got := RedactLiterals(in)
	assert.NotContains(t, got, "alice")
	assert.NotContains(t, got, "sk-live-abc123")
	assert.NotContains(t, got, "2026-01-01")
	// Three literals → three placeholders.
	assert.Equal(t, 3, strings.Count(got, RedactedPlaceholder))
}

func TestRedactLiterals_NumericLiteralPreserved(t *testing.T) {
	// Numbers are not credential candidates — preserve them.
	in := "UPDATE users SET visits = 42 WHERE id = 7"
	assert.Equal(t, in, RedactLiterals(in))
}

func TestRedactLiterals_DoubleQuotedIdentifierPreserved(t *testing.T) {
	// PG/Snowflake/BigQuery double-quoted identifiers MUST NOT be
	// redacted — they're table/column names, not secrets.
	in := `SELECT "user-id" FROM "my schema"."my table" WHERE name = 'bob'`
	got := RedactLiterals(in)
	assert.Contains(t, got, `"user-id"`, "double-quoted identifier preserved")
	assert.Contains(t, got, `"my schema"`, "double-quoted identifier preserved")
	assert.Contains(t, got, `"my table"`, "double-quoted identifier preserved")
	assert.NotContains(t, got, "bob")
	assert.Contains(t, got, RedactedPlaceholder)
}

func TestRedactLiterals_BacktickIdentifierPreserved(t *testing.T) {
	in := "SELECT `col with space` FROM `my-table` WHERE name = 'eve'"
	got := RedactLiterals(in)
	assert.Contains(t, got, "`col with space`")
	assert.Contains(t, got, "`my-table`")
	assert.NotContains(t, got, "eve")
}

func TestRedactLiterals_SQLStandardEscapedQuote(t *testing.T) {
	// `''` inside `'...'` is a literal single quote. The redactor MUST
	// treat the whole inner span as one literal, not terminate early.
	in := "SELECT * FROM t WHERE name = 'it''s a test' AND id = 1"
	got := RedactLiterals(in)
	assert.NotContains(t, got, "it''s")
	assert.NotContains(t, got, "test")
	// id = 1 (numeric) must survive.
	assert.Contains(t, got, "id = 1")
	// Exactly one placeholder (we swallowed the whole `'it''s a test'`).
	assert.Equal(t, 1, strings.Count(got, RedactedPlaceholder))
}

func TestRedactLiterals_BackslashEscapedQuote(t *testing.T) {
	// MySQL/Snowflake `\'` escape. Same invariant — the redactor MUST
	// NOT terminate on the escaped quote and leak the rest.
	in := `INSERT INTO t VALUES ('foo\'bar', 'next')`
	got := RedactLiterals(in)
	assert.NotContains(t, got, "foo")
	assert.NotContains(t, got, "bar")
	assert.NotContains(t, got, "next")
	assert.Equal(t, 2, strings.Count(got, RedactedPlaceholder))
}

func TestRedactLiterals_UTF8MultiByteLiteral(t *testing.T) {
	// Non-Latin-1 string literals must redact cleanly — byte-level
	// scanning is UTF-8 safe because continuation bytes never collide
	// with ASCII syntactic markers.
	in := "SELECT * FROM t WHERE greeting = 'こんにちは' AND user = 'héllo'"
	got := RedactLiterals(in)
	assert.NotContains(t, got, "こんにちは")
	assert.NotContains(t, got, "héllo")
	assert.Equal(t, 2, strings.Count(got, RedactedPlaceholder))
}

func TestRedactLiterals_LiteralLooksLikeIdentifier(t *testing.T) {
	// A literal whose contents look like an identifier MUST still be
	// redacted — the QUOTE TYPE is what determines the category.
	in := "SELECT * FROM t WHERE col = 'my_secret_value'"
	got := RedactLiterals(in)
	assert.NotContains(t, got, "my_secret_value")
}

func TestRedactLiterals_PasswordHashShapeRedacted(t *testing.T) {
	// The motivating case from the audit doc.
	in := "SELECT pwd_hash FROM auth WHERE user='alice'"
	got := RedactLiterals(in)
	assert.NotContains(t, got, "alice")
	// Identifier `pwd_hash` is not a quoted literal → preserved.
	assert.Contains(t, got, "pwd_hash")
	assert.Contains(t, got, "auth")
}

func TestRedactLiterals_ConnectionStringSecretRedacted(t *testing.T) {
	// The other motivating case: an agent submits SQL containing a
	// password-bearing connection string as a literal.
	in := "INSERT INTO log VALUES ('postgres://user:pass@host:5432/db')"
	got := RedactLiterals(in)
	assert.NotContains(t, got, "pass")
	assert.NotContains(t, got, "postgres://user")
	assert.Equal(t, 1, strings.Count(got, RedactedPlaceholder))
}

func TestRedactLiterals_IdempotentOnPlaceholder(t *testing.T) {
	// Running RedactLiterals on already-redacted SQL must be a no-op
	// (the placeholder itself is a quoted literal — but its CONTENTS
	// are already the redacted token, so re-redaction is fine + idempotent).
	once := RedactLiterals("SELECT * FROM t WHERE c = 'x'")
	twice := RedactLiterals(once)
	assert.Equal(t, once, twice,
		"redactor must be idempotent — RedactLiterals(RedactLiterals(s)) == RedactLiterals(s)")
}

func TestRedactLiterals_MatchesStripcommentsInvariant(t *testing.T) {
	// Cross-check with the stripcomments invariants the existing tests
	// lock in (TestStripSQLComments_StringLiteralPreserved etc.).
	// The redactor handles the same set of escape forms.
	for _, in := range []string{
		"SELECT '/* not a comment */' FROM t",            // block-comment-shaped literal
		`SELECT 'it''s /* still in literal */' FROM t`,   // `''` escape
		`SELECT 'foo\'bar /* still */ baz' FROM t`,       // `\'` escape
	} {
		out := RedactLiterals(in)
		assert.NotEqual(t, in, out, "input MUST be redacted: %s", in)
		assert.Equal(t, 1, strings.Count(out, RedactedPlaceholder),
			"exactly one literal-region detected in: %s", in)
	}
}

// SQL comment stripping for the dialect parsers' keyword pre-checks.
//
// Why this exists: every dialect parser (mysql.go / snowflake.go /
// bigquery.go) runs a `strings.HasPrefix(strings.ToUpper(...))` test on
// the raw SQL bytes to catch dialect-specific verbs the underlying
// xwb1989 grammar doesn't model (LOAD DATA, EXPORT DATA, COPY INTO @,
// PUT, GET, UNDROP, etc.). The real SQL engines (MySQL / Snowflake /
// BigQuery) all accept leading SQL comments before any keyword, so a
// statement like `/* */ LOAD DATA INFILE '/etc/passwd' INTO TABLE x`
// executes successfully on the upstream — but the prefix test misses
// because the byte at position 0 is `/`, not `L`. The statement falls
// through to xwb1989, which doesn't recognize LOAD-DATA either, and the
// final classification is StmtUnparseable. In cooperative mode (the
// default) the audit row records "parser couldn't read this" while the
// statement IS forwarded upstream — opposite of the intended exfil
// signal.
//
// CRIT-D8-01 + CRIT-D8-02 (AUDIT-WB-DSLICES-1-8.md) closure: strip
// comments BEFORE the prefix test. This file is the shared helper.
//
// Correctness requirements (load-bearing per [[scorer-is-ground-truth]];
// if any case below is wrong, the gate misclassifies):
//
//   - Single-line: `-- foo\n` becomes whitespace through end-of-line.
//   - Block: `/* foo */` becomes whitespace.
//   - Nested blocks: `/*outer /*inner*/ outer*/` — PostgreSQL and
//     Snowflake nest; MySQL and BigQuery do not. To be conservative
//     across all dialects, treat ALL block comments as nesting (the
//     stripped output is identical when no nesting is present).
//   - String literals: comment markers inside `'...'`, `"..."`, or
//     `` `...` `` (MySQL identifier quoting) are LITERAL TEXT, not
//     comment delimiters. `SELECT '/* not a comment */' FROM t` must
//     retain the literal verbatim — the prefix test then correctly sees
//     SELECT, not COMMENT.
//   - SQL string-literal escaping: `''` inside `'...'` is a literal
//     single quote (SQL-standard escaping), not a string terminator
//     followed by re-open. Snowflake / MySQL also accept backslash
//     escapes (`\'`); we honor both forms to avoid false-positives.
//   - Newlines preserved: the stripped output keeps newlines so line
//     numbers in downstream parser errors remain aligned with the
//     operator's original input.
//
// What this helper does NOT do:
//   - It does not strip ALL whitespace — just turns comment regions
//     into spaces. The trim + uppercasing happens at the caller.
//   - It does not validate that the SQL is well-formed. A malformed
//     comment (`/* never closed`) is preserved as-is from the point
//     of the offending token forward; the prefix test then runs against
//     the original suffix, which is the conservative behavior (we
//     surface to xwb1989 which records a parse error).
//   - It does not understand dialect-specific comment forms beyond
//     `--`, `/* */`, and string literals. Conditional-comment shapes
//     like MySQL's `/*! INSERT ... */` and `/*+ HINT */` Oracle-style
//     hints are stripped as ordinary block comments — the inner verbs
//     LOSE their executability hint, but the statement bytes are still
//     re-checked against the prefix list, so a `/*! LOAD DATA */` shape
//     would still be detected. Stripping conditionals more carefully
//     can wait for a calibration corpus that demonstrates a false-
//     negative; for now the conservative behavior is to treat them all
//     as comments.
//
// Per [[creates-never-mutates]]: this file PARSES STRINGS. No execution,
// no connection, no credentials.

package parser

import "strings"

// stripSQLComments removes single-line (`--`) and block (`/* */`) SQL
// comments from the input, returning a normalized string suitable for
// keyword-prefix detection. Newlines are preserved so line numbers in
// downstream parser errors stay aligned. String literals are honored —
// comment markers inside quoted strings are NOT stripped.
//
// See the file header for the full correctness contract.
func stripSQLComments(sql string) string {
	if sql == "" {
		return sql
	}

	// We allocate the output buffer at the full input length up front;
	// the stripped result is always <= input length. Using strings.Builder
	// keeps the implementation allocation-free in the common case where
	// no comments are present (Grow + WriteString of the whole input).
	var b strings.Builder
	b.Grow(len(sql))

	// Treat the input as bytes — ASCII is the only character class with
	// SQL syntactic meaning here, and the multi-byte UTF-8 continuation
	// bytes (0x80-0xBF) never collide with `-`, `/`, `*`, `'`, `"`, or
	// `` ` ``. So byte-level iteration is safe and avoids the per-char
	// overhead of range-over-string's rune decoding.
	i := 0
	n := len(sql)
	for i < n {
		c := sql[i]

		// String literals: SQL-standard single-quoted strings, plus
		// MySQL / Snowflake / BigQuery double-quoted strings, plus
		// MySQL backtick-quoted identifiers. Comment markers INSIDE
		// these are literal text — we copy through verbatim until the
		// matching terminator.
		if c == '\'' || c == '"' || c == '`' {
			term := c
			b.WriteByte(c)
			i++
			for i < n {
				ch := sql[i]
				// Backslash escape (MySQL / Snowflake accept; ANSI SQL
				// doesn't but tolerating it is safe — the alternative
				// is a false-positive terminator on `\'`).
				if ch == '\\' && i+1 < n {
					b.WriteByte(ch)
					b.WriteByte(sql[i+1])
					i += 2
					continue
				}
				if ch == term {
					// SQL-standard escape: doubled quote inside a quoted
					// string is a literal quote, not a terminator. `''`
					// inside `'...'` and `""` inside `"..."`.
					if i+1 < n && sql[i+1] == term {
						b.WriteByte(ch)
						b.WriteByte(ch)
						i += 2
						continue
					}
					b.WriteByte(ch)
					i++
					break
				}
				b.WriteByte(ch)
				i++
			}
			continue
		}

		// Single-line comment: `--` runs to end-of-line. Replace with
		// a single space so the surrounding tokens don't accidentally
		// concatenate (e.g. `EXPORT--\nDATA` must NOT become `EXPORTDATA`).
		// The newline that ends the comment IS preserved, so line
		// numbers stay aligned.
		if c == '-' && i+1 < n && sql[i+1] == '-' {
			b.WriteByte(' ')
			i += 2
			for i < n && sql[i] != '\n' {
				i++
			}
			// Don't consume the newline itself; the next loop iteration
			// will copy it through.
			continue
		}

		// Block comment: `/* ... */` with nesting. Same space-substitution
		// reasoning as the single-line case. Nesting count tracks the
		// depth so `/*outer /*inner*/ outer*/` strips to a single space.
		if c == '/' && i+1 < n && sql[i+1] == '*' {
			b.WriteByte(' ')
			depth := 1
			i += 2
			for i < n && depth > 0 {
				// Preserve newlines inside comments so line numbers stay
				// aligned in any downstream parse error.
				if sql[i] == '\n' {
					b.WriteByte('\n')
					i++
					continue
				}
				if sql[i] == '/' && i+1 < n && sql[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if sql[i] == '*' && i+1 < n && sql[i+1] == '/' {
					depth--
					i += 2
					continue
				}
				i++
			}
			// If depth > 0 (unclosed block comment), we've consumed to
			// EOF — the caller's prefix test runs against the prefix we
			// already wrote, which is empty here. The conservative
			// behavior: no extension verb gets matched, statement falls
			// through to xwb1989 which records a parse error. That's
			// correct for the malformed-SQL case.
			continue
		}

		b.WriteByte(c)
		i++
	}

	return b.String()
}

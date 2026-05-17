// SQL literal redaction for the audit log.
//
// Why this exists: dbounce records the raw SQL statement on every
// decision row so audit reviewers can reconstruct what the client sent.
// That is the right default — losing the SQL makes the audit log
// useless for post-incident review. But raw SQL routinely contains
// secret-shaped string literals: API keys, password hashes, session
// tokens, OAuth bearer values, customer PII. When the audit log is
// exposed to an MCP-connected agent or surfaced via `dbounce audit
// tail --json`, those literals leak.
//
// MED-D8-09 (AUDIT-WB-DSLICES-1-8.md) closure: ship an opt-in
// `--redact-literals` flag. When enabled, every audit row's statement
// has its quoted string literals swapped for `[REDACTED]` BEFORE the
// row is persisted. The audit reviewer still sees the SQL SHAPE
// (statement_type, table list, function list, parser flags), and the
// per-row `statement_redacted` boolean tells downstream consumers the
// stored SQL is NOT replayable.
//
// What gets redacted:
//   - Single-quoted string literals: `'alice'`            → `'[REDACTED]'`
//   - Backslash-escaped string literals (MySQL/Snowflake):
//     `'foo\'bar'`                                         → `'[REDACTED]'`
//   - SQL-standard `''`-escaped string literals:
//     `'it''s a test'`                                     → `'[REDACTED]'`
//
// What is INTENTIONALLY preserved:
//   - Identifiers (table/column names) — they are SCHEMA-PRIVATE, not
//     credential candidates, and rule packs match on them. Double-quoted
//     identifiers (`"col-name"`) and backtick-quoted identifiers
//     (`` `col-name` ``) are NOT touched.
//   - Numeric literals — not credential candidates; statement shape +
//     row counts inform audit reviewers.
//   - SQL comments — `--` and `/* ... */`. They contain operator-
//     written hints, not credentials. Comment-stripping is a separate
//     concern (stripcomments.go for the keyword-prefix gate).
//
// Cross-dialect: this is regex-based on the byte stream. It does NOT
// use libpg_query (PG) or xwb1989 (MySQL/Snowflake/BigQuery) because:
//   1. We have to handle the StmtUnparseable case (statement couldn't
//      parse but might still contain secrets). A regex pass works on
//      any string.
//   2. The AST-walker approach across 4 dialects would multiply
//      complexity (different node types per dialect) for negligible
//      semantic gain — the only thing we touch is quoted literals,
//      and the quote-tokenization rules are uniform across dialects.
//   3. The audit doc explicitly authorized a regex fallback ("fall
//      back to regex if AST visitor doesn't cover quoted strings
//      reliably").
//
// Correctness contract (per [[scorer-is-ground-truth]]): the redactor
// MUST NOT swap identifiers, must handle every quote-escape form the
// stripcomments tests already lock in (`''` escape, `\'` escape,
// double-quoted identifier, backtick identifier), and must round-trip
// the test cases the audit doc spelled out.
//
// UTF-8: SQL string literals can contain UTF-8 multi-byte sequences
// (e.g. `'héllo'`, `'こんにちは'`). The byte-level scan is UTF-8-safe
// because the multi-byte continuation bytes (0x80-0xBF) never collide
// with the ASCII single-quote (0x27), backslash (0x5C), or other
// syntactic markers. We just copy bytes through verbatim between the
// open + close quotes, then emit `[REDACTED]` instead.
//
// Per [[creates-never-mutates]]: this file PARSES STRINGS. No execution,
// no connection, no credentials.

package parser

import "strings"

// RedactedPlaceholder is the token swapped in place of each quoted
// string literal. Exposed so tests + downstream consumers can grep
// audit rows for redacted statements without re-deriving the constant.
const RedactedPlaceholder = "[REDACTED]"

// RedactLiterals returns sql with every quoted string literal replaced
// by '[REDACTED]'. Identifiers, numeric literals, and comments are
// preserved. See the file header for the full correctness contract.
//
// Returns the original string unchanged when sql contains no string
// literals — common path for SELECT count(*) / SHOW VARIABLES / etc.
func RedactLiterals(sql string) string {
	if sql == "" {
		return sql
	}
	// Cheap pre-check: no `'` byte anywhere → nothing to redact, return
	// the input unchanged (no allocation).
	if !strings.ContainsRune(sql, '\'') {
		return sql
	}
	var b strings.Builder
	b.Grow(len(sql))
	i := 0
	n := len(sql)
	for i < n {
		c := sql[i]
		// Skip over double-quoted identifiers + backtick identifiers
		// verbatim. Comment-marker handling inside these matches
		// stripcomments.go's invariant — the identifier contents are
		// LITERAL TEXT, not subject to redaction either.
		if c == '"' || c == '`' {
			term := c
			b.WriteByte(c)
			i++
			for i < n {
				ch := sql[i]
				if ch == '\\' && i+1 < n {
					// Backslash escape inside a quoted identifier is rare
					// but valid in MySQL; copy both bytes through.
					b.WriteByte(ch)
					b.WriteByte(sql[i+1])
					i += 2
					continue
				}
				if ch == term {
					// SQL-standard doubled-quote escape inside quoted
					// identifier: `""` is a literal `"`, not a terminator.
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
		// Single-quoted string literal: the credential surface. Consume
		// the full literal up to its terminator (handling `''` + `\'`
		// escapes) WITHOUT writing the contents to the output buffer.
		// Then emit `'[REDACTED]'` so downstream tools / readers still
		// see "this is a string literal" + the parser fixup re-parses
		// cleanly if it's ever fed back.
		if c == '\'' {
			// Find the matching terminator. Handle two escape forms:
			//   1. `''` — SQL-standard escape for a literal `'`.
			//   2. `\'` — MySQL/Snowflake backslash escape.
			i++
			for i < n {
				ch := sql[i]
				if ch == '\\' && i+1 < n {
					i += 2
					continue
				}
				if ch == '\'' {
					if i+1 < n && sql[i+1] == '\'' {
						// `''` inside string → consume both bytes.
						i += 2
						continue
					}
					// Terminator.
					i++
					break
				}
				i++
			}
			b.WriteByte('\'')
			b.WriteString(RedactedPlaceholder)
			b.WriteByte('\'')
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// SQL statement splitter for #587 multi-statement batch evaluation.
//
// Why this exists: UAT-C 2026-05-25 surfaced a CRIT deploy-blocker —
// dbounce evaluated only the FIRST statement in a multi-statement
// batch. Adversarial DCL embedded at position 2+ was completely
// invisible:
//
//	SELECT 1; GRANT ALL ON foo TO PUBLIC; SELECT 2
//
// ALLOWED under --default-policy allow AND under safe-default. Same
// UC-34 bypass class via the batching channel. Real adversarial vector
// in batch-capable clients: Snowflake JDBC EXECUTE_MULTIPLE, psql `\;`,
// MySQL multi-statements=true, ORM-generated batches, stored proc
// bodies with embedded DCL.
//
// The fix per UAT-C Option A: parse + evaluate EACH statement; deny on
// any deny. This file is the splitter half — it identifies statement
// boundaries; internal/decision/EvaluateMultiStatement loops over each
// piece and composes the per-statement verdict into a batch verdict.
//
// Correctness contract (load-bearing per [[scorer-is-ground-truth]];
// if any case below is wrong, the gate misclassifies):
//
//   - `;` separator outside quoted strings + comments. A `;` inside
//     `'...'` or `"..."` or “ `...` “ (MySQL identifier quoting) is
//     literal text, NOT a separator. A `;` inside `-- ... \n` or
//     `/* ... */` is comment text, NOT a separator.
//
//   - Terminal `;` does NOT produce an empty trailing statement.
//     `SELECT 1;` → 1 statement.
//
//   - Empty statements between separators are skipped. `SELECT 1;;SELECT 2`
//     → 2 statements. `;;;` → 0 statements.
//
//   - Newlines preserved within statements so downstream parser errors
//     stay line-aligned (same invariant stripcomments.go upholds).
//
//   - Backslash escapes inside string literals are honored (MySQL +
//     Snowflake accept `\'`). Standard SQL doubled-quote `”` is also
//     honored.
//
//   - Nested block comments (PostgreSQL / Snowflake nest; MySQL +
//     BigQuery do not). Conservative: ALL block comments treated as
//     nesting — the stripped output is identical when no nesting is
//     present.
//
// What this splitter does NOT do:
//
//   - It does not strip comments from the returned statements (each
//     piece is the verbatim slice of the input including any leading /
//     trailing comments). The dialect parsers run their own comment
//     stripping for their keyword pre-checks.
//
//   - It does not parse / validate SQL syntax. A malformed string (an
//     unclosed quote) is consumed to EOF as part of the current
//     statement — the dialect parser then records the parse error.
//     Conservative: better to surface ONE oversized statement that the
//     parser flags than to silently split on a `;` that the upstream
//     SQL engine would have treated as literal text.
//
//   - It does not handle dialect-specific separators like psql's `\g` /
//     `\;`. Those are CLIENT-side constructs that get transmitted to
//     the server as ordinary `;`-separated batches; the splitter sees
//     them after the client has done its rewrite.
//
// Per [[creates-never-mutates]]: this file SPLITS STRINGS. No
// execution, no connection, no credentials.
package parser

import "strings"

// SplitStatements splits raw SQL into individual statements at
// top-level `;` separators (outside of string literals + comments).
// Empty statements (between consecutive `;` or before the first
// non-whitespace char) are skipped.
//
// Returns a slice of statement strings, each trimmed of surrounding
// whitespace. An empty / whitespace-only / comment-only input returns
// an empty slice (caller should treat as "no statements to evaluate").
//
// The dialect string is reserved for future per-dialect tweaks (e.g.
// PostgreSQL `$$ ... $$` dollar-quoted strings or T-SQL `GO` batch
// separator). v1.0 ships with the same separator semantics across all
// supported dialects (postgres / mysql / snowflake / bigquery) — the
// SQL-standard `;` outside strings + comments. The signature accepts
// dialect upfront so a future per-dialect divergence is an additive
// change at one call-site.
func SplitStatements(dialect, sql string) []string {
	if sql == "" {
		return nil
	}
	out := make([]string, 0, 4)
	// start tracks the byte index of the current statement's first
	// byte. We advance past `;` separators by writing the slice
	// sql[start:i] into out (after trimming) and resetting start = i+1.
	start := 0
	n := len(sql)
	i := 0
	for i < n {
		c := sql[i]

		// String literals: `'...'`, `"..."`, `` `...` ``. Comment
		// markers and `;` inside these are literal text — copy through
		// until the matching terminator.
		if c == '\'' || c == '"' || c == '`' {
			term := c
			i++
			for i < n {
				ch := sql[i]
				// Backslash escape (MySQL / Snowflake accept; ANSI SQL
				// doesn't but tolerating it is safe — the alternative
				// is a false-positive terminator on `\'`).
				if ch == '\\' && i+1 < n {
					i += 2
					continue
				}
				if ch == term {
					// SQL-standard escape: doubled quote inside a quoted
					// string is a literal quote, not a terminator. `''`
					// inside `'...'` and `""` inside `"..."`.
					if i+1 < n && sql[i+1] == term {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
			continue
		}

		// Single-line comment: `-- ... \n`. `;` inside a single-line
		// comment is comment text, NOT a separator.
		if c == '-' && i+1 < n && sql[i+1] == '-' {
			i += 2
			for i < n && sql[i] != '\n' {
				i++
			}
			// Don't consume the newline itself; the next loop iteration
			// will handle it as ordinary whitespace.
			continue
		}

		// Block comment: `/* ... */` with nesting. `;` inside a block
		// comment is comment text, NOT a separator.
		if c == '/' && i+1 < n && sql[i+1] == '*' {
			depth := 1
			i += 2
			for i < n && depth > 0 {
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
			// If depth > 0 we've consumed to EOF (unclosed block
			// comment) — the rest of the input is the current
			// statement's tail. The dialect parser will flag the
			// malformed comment.
			continue
		}

		// Top-level `;` — statement separator.
		if c == ';' {
			piece := sql[start:i]
			if !isEffectivelyEmpty(piece) {
				out = append(out, strings.TrimSpace(piece))
			}
			start = i + 1
			i++
			continue
		}

		i++
	}

	// Tail: the bytes after the last `;` (or the whole input if no
	// separator was seen). Skip when empty / whitespace-only /
	// comment-only so a terminal `;` doesn't produce a phantom empty
	// statement + an all-comment input doesn't surface as a noise row.
	if start < n {
		tail := sql[start:]
		if !isEffectivelyEmpty(tail) {
			out = append(out, strings.TrimSpace(tail))
		}
	}

	return out
}

// isEffectivelyEmpty reports whether a candidate statement is whitespace-
// only, comment-only, or both — the shapes that should NOT count as
// statements. Uses the existing stripSQLComments helper so the
// "what is a comment" definition stays in one place (the splitter +
// the dialect parsers' prefix tests use the same comment grammar).
func isEffectivelyEmpty(piece string) bool {
	return strings.TrimSpace(stripSQLComments(piece)) == ""
}

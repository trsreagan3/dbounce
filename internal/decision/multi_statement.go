// Multi-statement batch evaluation for #587 CRIT deploy-blocker.
//
// Why this exists: UAT-C 2026-05-25 confirmed dbounce evaluated only the
// FIRST statement in a multi-statement batch. Adversarial DCL embedded
// at position 2+ was completely invisible:
//
//	SELECT 1; GRANT ALL ON foo TO PUBLIC; SELECT 2
//
// ALLOWED under --default-policy allow AND under safe-default. Same
// UC-34 bypass class via the batching channel.
//
// Fix shape (UAT-C Option A): EvaluateMultiStatement splits the raw SQL
// at top-level `;` separators via parser.SplitStatements, parses each
// piece individually, and applies the admin-tight floor to EACH parsed
// statement. DENY on any DENY — reason names the position so operators
// debugging the verdict see WHICH statement triggered the floor.
//
// Both proxy.decide() (production hot path) and cli.evalDecide() (dry-
// run CLI per #559) consume this helper. Per [[ibounce-honest-
// positioning]] + #559 lesson: CLI/proxy divergence is a calibration-
// drift bug class — single source of truth lives here.
//
// Per [[scorer-is-ground-truth]]: this function is pure (no I/O, no
// mutation). The caller owns the audit-write side.

package decision

import (
	"fmt"

	"github.com/trsreagan3/dbounce/internal/parser"
	"github.com/trsreagan3/dbounce/internal/profile"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
)

// MultiStatementVerdict reports the per-batch result of the admin-tight
// floor evaluated across every statement in a multi-statement SQL batch.
//
// Deny=false + Applicable=true → at least one statement was a DCL shape
// that the floor evaluated but none denied. Caller MUST continue with
// its remaining decision pipeline (rule engine, default policy, etc.)
// for the whole batch — the floor did not fire.
//
// Deny=false + Applicable=false → no statement in the batch was an
// admin-grant shape. The floor doesn't apply to this batch at all.
// Caller MUST continue.
//
// Deny=true + Applicable=true → at least one statement was an admin-
// grant DCL that the floor denied. Caller MUST short-circuit with the
// returned Reason (which names the offending position so operators can
// debug the verdict).
//
// StatementCount is the number of non-empty statements the splitter
// produced for this batch (zero for empty / whitespace-only / comment-
// only inputs). Surfaced so caller reasons (and tests) can name the
// batch size in deny / observability messages.
//
// Position is the 1-indexed position of the statement that triggered
// the deny (1 for single-statement inputs that fire the floor). Zero
// when Deny=false.
type MultiStatementVerdict struct {
	Deny           bool
	Applicable     bool
	Reason         string
	StatementCount int
	Position       int
}

// EvaluateMultiStatement splits the raw SQL into individual statements
// at top-level `;` separators and applies the admin-tight floor to
// each. Returns the first DENY verdict encountered (left-to-right scan)
// with a Reason naming the position so operators can debug the verdict.
//
// dialect is the parser dialect for both the splitter (reserved for
// future per-dialect tweaks) and the per-statement parser dispatch.
// One of parser.DialectPostgres / DialectMySQL / DialectSnowflake /
// DialectBigQuery. Empty string defaults to DialectPostgres (preserves
// parser.Parse's existing behavior).
//
// prof is the active profile (may be nil — full-user equivalent).
// Threaded into AdminTightFloor for the override path.
//
// defaultPolicy is the surrounding default policy ("allow" / "deny" /
// "") interpolated into the deny reason for audit visibility — the
// same shape AdminTightFloor uses today.
//
// globalRules is the per-process global rules table (the same RuleSet
// proxy.decide()'s Step 4 evaluates). May be nil. When non-nil, EACH
// statement in the batch is evaluated against the rules; a matching
// global-allow rule short-circuits the per-statement floor (mirroring
// proxy.decide Step 5's existing override path). Per-statement allow
// ONLY skips the floor for that statement — sibling statements still
// see the per-stmt floor evaluation. Global DENY rules are NOT acted
// on here (the caller's Step 3 + Step 4 deny short-circuits already
// fired against the whole-batch ps; the multi-statement helper owns
// the floor short-circuit only).
//
// Single-statement inputs (no `;` separator) behave identically to a
// direct AdminTightFloor call but with Position=1 in the verdict, so
// callers can use the same code path for both shapes.
//
// Empty / whitespace-only / comment-only inputs return Applicable=false
// with StatementCount=0 — the caller's existing handling of "empty
// input" applies unchanged.
//
// Per UAT-C recommendation Option A: DENY on any DENY. The whole batch
// is refused if any embedded statement is an admin-grant DCL the floor
// denies. Per [[ibounce-honest-positioning]]: the reason names the
// position so operators debugging the verdict see WHICH statement
// triggered the floor — never return a vague "batch rejected."
func EvaluateMultiStatement(
	dialect string,
	rawSQL string,
	prof *profile.Profile,
	defaultPolicy string,
	globalRules *dbrules.RuleSet,
) MultiStatementVerdict {
	statements := parser.SplitStatements(dialect, rawSQL)
	count := len(statements)
	if count == 0 {
		return MultiStatementVerdict{StatementCount: 0}
	}
	for i, piece := range statements {
		ps := parser.Parse(dialect, piece)

		// Per-statement override: a matching global allow rule lets the
		// statement through (mirrors proxy.decide Step 5's
		// global-allow short-circuit, run per-statement so a multi-stmt
		// batch with both an allow-rule-matching GRANT + a benign
		// SELECT both pass). Mirrors proxy.decide()'s composition order
		// for the per-statement equivalent: an operator who wrote
		// `dbounce rules add --pattern "GRANT:*" --effect allow` to
		// permit admin-grant traffic still gets the same override
		// here. Per-statement allow ONLY skips the floor for THIS
		// statement; subsequent statements re-run the full per-stmt
		// check (so an allow-rule matching SELECT doesn't bypass the
		// floor for a sibling GRANT).
		if globalRules != nil {
			stmtView := &dbrules.ParsedStatement{
				StatementType:    ps.StatementType,
				TablesTouched:    ps.TablesTouched,
				FunctionsCalled:  ps.FunctionsCalled,
				IsDML:            ps.IsDML,
				IsDDL:            ps.IsDDL,
				HasMutatingNode:  ps.HasMutatingNode,
				IsExplain:        ps.IsExplain,
				IsExplainAnalyze: ps.IsExplainAnalyze,
			}
			if r := globalRules.Evaluate(stmtView); r != nil &&
				r.Effect == dbrules.EffectAllow {
				continue
			}
		}

		deny, reason, applicable := AdminTightFloor(ps, prof, defaultPolicy)
		if !applicable {
			continue
		}
		if !deny {
			// Floor applied (DCL shape) and was overridden by a profile
			// allow_rule. Continue the scan — a subsequent statement
			// might still trigger the floor.
			continue
		}
		// Honest deny per [[ibounce-honest-positioning]]: name the
		// position so operators debugging the verdict know WHICH
		// statement triggered the floor (not a vague "batch rejected").
		// For single-statement inputs the position is 1 — surfaced
		// uniformly so SIEM filters keying on "statement N/M" handle
		// both shapes.
		return MultiStatementVerdict{
			Deny:       true,
			Applicable: true,
			Reason: fmt.Sprintf(
				"multi-statement batch: statement %d/%d: %s",
				i+1, count, reason),
			StatementCount: count,
			Position:       i + 1,
		}
	}
	// No statement in the batch triggered the floor. Applicable=false
	// so the caller's existing flow proceeds unchanged — the floor
	// short-circuit is the only behavior the helper owns.
	return MultiStatementVerdict{StatementCount: count}
}

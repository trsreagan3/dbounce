// Package rules implements dbounce's deterministic rule engine for
// SQL statements.
//
// A ProxyRule is the SQL analog of kbounce's K8s ProxyRule + the
// Python iam-jit-bouncer's ProxyRule. Pattern shape:
// `statement_type:table_glob` — e.g. `SELECT:*`, `DELETE:public.users`,
// `DML:reports_*`. Scoped fields layer on top:
//
//   - SchemaScope    — glob matched against the schema half of any
//     parsed table (e.g. "public", "reporting", "prod-*")
//   - TableScope     — glob matched against the full schema.table id
//     of any parsed table (redundant with the table_glob in the
//     pattern but exists for backward compat with rule rows seeded by
//     other tooling)
//   - FunctionScope  — glob matched against any function the statement
//     calls (handy for narrowing CALL / DO / EXECUTE shapes:
//     `CALL:*#approved_proc`)
//
// Pattern statement_type accepts the canonical parser constants
// (SELECT, INSERT, UPDATE, DELETE, MERGE, DDL, CALL, DO, EXECUTE,
// WITH-WRITE, ...) or one of four CATEGORIES:
//
//   - DML       — INSERT, UPDATE, DELETE, MERGE, WITH-WRITE
//   - DDL       — CREATE/ALTER/DROP/TRUNCATE/RENAME/COMMENT
//                 (parser surfaces these as StmtDDL or StmtTruncate
//                 or StmtComment)
//   - MUTATING  — DML ∪ DDL ∪ CALL ∪ DO ∪ EXECUTE ∪ WITH-WRITE
//                 ∪ any statement with HasMutatingNode = true
//                 (the load-bearing CTE-hidden-write catch)
//   - READ      — SELECT, EXPLAIN, SHOW (parser uses SET for SHOW),
//                 plus ImpersonatedRole=="" SET ROLE traffic; in
//                 practice this means StmtSelect and StmtExplain
//
// The MUTATING category checks HasMutatingNode unconditionally — a
// statement whose top-level keyword is SELECT but whose AST walker
// flagged a CTE-wrapped UPDATE still matches `MUTATING:*`. This is
// the load-bearing invariant the dbounce-build-plan describes as
// "rules matching on StatementType need to ALSO consider
// HasMutatingNode."
//
// Evaluation order per the iam-jit-bouncer Python RuleSet semantics
// (mirror keeps cross-product audit-log review consistent):
//
//  1. Any matching DENY rule  -> Effect.Deny (explicit deny beats allow)
//  2. Else any matching ALLOW -> Effect.Allow
//  3. Else nil                 (caller falls through to its next layer)
//
// Per [[scorer-is-ground-truth]] precedent: rule matching is
// deterministic. No LLM in this path. Predictable behavior is the
// whole point of a gate.
package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// Effect is a rule's verdict when matched.
type Effect string

const (
	// EffectAllow allows the matched statement through.
	EffectAllow Effect = "allow"
	// EffectDeny denies the matched statement.
	EffectDeny Effect = "deny"
)

// IsValid returns true for the two canonical effect values.
func (e Effect) IsValid() bool {
	switch e {
	case EffectAllow, EffectDeny:
		return true
	}
	return false
}

// Origin labels how a rule entered the store. Stable enum so the
// audit-review UI can color-code "user-added" vs "task-derived" rows.
const (
	// OriginUser was added explicitly by an operator via `rules add`.
	OriginUser = "user"
	// OriginTask was synthesized from an active task scope (rules in
	// tasks live on the task row, NOT in the rules table; this label is
	// reserved for the in-memory rules a TaskScope builds).
	OriginTask = "task"
	// OriginLearn was auto-captured in learn mode (future).
	OriginLearn = "learn"
	// OriginPreset came from a built-in baseline / community preset.
	OriginPreset = "preset"
	// OriginRecommended came from the recommender (post-launch).
	OriginRecommended = "recommended"
	// OriginDefault is reserved for built-in defaults.
	OriginDefault = "default"
)

// Statement-type categories used in rule patterns. Mirror the parser's
// per-statement constants but expressed as buckets the operator can
// write in one rule. The category constants intentionally do NOT
// collide with the parser's per-statement constants — a literal
// `MUTATING` is not a valid PG keyword so we can distinguish "category"
// from "specific statement" cleanly.
const (
	CategoryDML      = "DML"
	CategoryDDL      = "DDL"
	CategoryMutating = "MUTATING"
	CategoryRead     = "READ"
	WildcardAny      = "*"
)

// IsCategory returns true when typ is one of the rule categories
// (case-insensitive). Used by Matches to dispatch category vs literal
// statement-type comparison.
func IsCategory(typ string) bool {
	switch strings.ToUpper(typ) {
	case CategoryDML, CategoryDDL, CategoryMutating, CategoryRead:
		return true
	}
	return false
}

// ProxyRule is one row in dbounce's RuleSet.
type ProxyRule struct {
	// Pattern is `statement_type:table_glob`. Required.
	//
	// Accepted shapes:
	//   statement_type:table_glob   e.g. "SELECT:*", "DELETE:public.users",
	//                               "DML:reports_*"
	//   *:table_glob                e.g. "*:public.audit_log" (any
	//                               statement touching audit_log)
	//   statement_type:*            e.g. "MUTATING:*" (any mutating
	//                               statement, any table — relies on the
	//                               walker's HasMutatingNode for CTE-hidden
	//                               writes)
	//   *                           bare wildcard = match anything
	//                               (normalized to "*:*")
	//
	// table_glob may include "*" and "?". statement_type may be a parser
	// constant (SELECT, INSERT, UPDATE, DELETE, MERGE, DDL, CALL, DO,
	// EXECUTE, WITH-WRITE), one of the four CATEGORIES (DML, DDL,
	// MUTATING, READ), or "*". Empty parts and whitespace are rejected.
	Pattern string

	// Effect is the verdict when this rule matches. Defaults to allow
	// when zero-valued, but New / parseRule force an explicit value.
	Effect Effect

	// SchemaScope is a glob matched against the schema half of any
	// parsed table. Empty or "*" = match any schema. Statements with
	// no tables (e.g. DO blocks, SET ROLE) do not match a non-wildcard
	// schema scope — conservative; caller falls through.
	SchemaScope string

	// TableScope is a glob matched against the full schema-qualified
	// table identifier of any parsed table. Empty or "*" = match any
	// table. Same conservative behavior as SchemaScope for tableless
	// statements.
	TableScope string

	// FunctionScope is a glob matched against any function the statement
	// calls (parser's FunctionsCalled list). Empty or "*" = match any
	// function (and matches even when FunctionsCalled is empty). When
	// non-wildcard, the statement must call at least one matching
	// function — useful for narrowing CALL / DO / EXECUTE shapes to a
	// known allowlist.
	FunctionScope string

	// Note is an operator-readable description of why this rule exists.
	Note string

	// Origin labels how the rule entered the store. See Origin* consts.
	Origin string
}

// ID is the rule's row id in the rules table. Zero for in-memory rules
// (task-scope-derived, defaults, etc.).
type ID int64

// StoredRule pairs a ProxyRule with its database id. Returned by the
// store's ListRules so callers know which row to remove on `rules remove`.
type StoredRule struct {
	ID   ID
	Rule ProxyRule
}

// ToMap returns a JSON-friendly representation. Used by the CLI's
// --json output mode + audit-log detail payloads.
func (r ProxyRule) ToMap() map[string]any {
	return map[string]any{
		"pattern":        r.Pattern,
		"effect":         string(r.Effect),
		"schema_scope":   r.SchemaScope,
		"table_scope":    r.TableScope,
		"function_scope": r.FunctionScope,
		"note":           r.Note,
		"origin":         r.Origin,
	}
}

// ParsedStatement is the minimal view of a SQL statement the rule
// engine matches against. Kept local to this package so the engine
// can be unit-tested without dragging in the parser package.
//
// Symmetric to kbounce's rules.ParsedRequest; the proxy populates this
// from parser.ParsedStatement. The two are intentionally distinct so
// the rule engine has no parser-package dependency and so the rules
// view can grow SQL-specific fields the parser doesn't surface.
type ParsedStatement struct {
	// StatementType is the parser's classifier output (SELECT, INSERT,
	// UPDATE, DELETE, MERGE, DDL, CALL, DO, EXECUTE, WITH-WRITE,
	// EXPLAIN, EXPLAIN-ANALYZE, TRUNCATE, COMMENT, ...).
	StatementType string

	// TablesTouched is the set of schema-qualified table identifiers the
	// statement references. Lowercased. A rule scoped by table matches
	// if ANY entry in this list matches the scope glob — this is the
	// load-bearing multi-statement-batch behavior dbounce-build-plan
	// describes ("A rule scoping on table SHOULD match if ANY statement
	// in the batch touches the scoped table").
	TablesTouched []string

	// FunctionsCalled is the set of functions the statement invokes
	// (volatile-function calls, CALL targets, aggregates). Used by
	// FunctionScope matching.
	FunctionsCalled []string

	// IsDML is true for INSERT / UPDATE / DELETE / MERGE.
	IsDML bool

	// IsDDL is true for CREATE / ALTER / DROP / TRUNCATE / RENAME /
	// COMMENT.
	IsDDL bool

	// HasMutatingNode is the Layer-2 backstop: AST walker found at least
	// one mutating node anywhere in the tree. Critical for catching
	// CTE-wrapped writes whose top-level keyword is WITH/SELECT.
	HasMutatingNode bool

	// IsExplain is true for EXPLAIN (without ANALYZE). EXPLAIN alone
	// does not execute the inner statement.
	IsExplain bool

	// IsExplainAnalyze is true for EXPLAIN ANALYZE. The inner statement
	// DOES execute, so the verdict must honor the inner mutating shape.
	IsExplainAnalyze bool
}

// ErrInvalidPattern is returned by ParsePattern + RuleSet.Add for
// malformed patterns. Wrapping in an explicit error type lets the
// store reject bad rules at insert time (matches the kbounce
// InvalidPattern pattern that closed WB23 MED-23-02).
type ErrInvalidPattern struct {
	Pattern string
	Reason  string
}

func (e *ErrInvalidPattern) Error() string {
	return fmt.Sprintf("dbounce: invalid rule pattern %q: %s", e.Pattern, e.Reason)
}

// ParsePattern splits a `statement_type:table_glob` pattern. Returns
// (statement_type, table_glob, nil) or ("", "", *ErrInvalidPattern) on
// malformed input.
//
// The statement_type half is normalized to upper-case (the parser
// emits upper-case constants; rule writers shouldn't have to mirror
// that exactly). The table_glob half is normalized to lower-case (the
// parser lower-cases table identifiers; rule writers similarly
// shouldn't have to mirror that).
//
// Mirrors kbounce ParsePattern semantics with SQL statement_type
// taking the place of K8s resource and table_glob taking the place of
// verb_glob.
func ParsePattern(pattern string) (string, string, error) {
	token := strings.TrimSpace(pattern)
	if token == "" {
		return "", "", &ErrInvalidPattern{Pattern: pattern, Reason: "pattern is empty"}
	}
	if strings.ContainsAny(token, " \t\n") {
		return "", "", &ErrInvalidPattern{Pattern: pattern, Reason: "pattern contains whitespace"}
	}
	// Bare "*" = any statement, any table.
	if token == WildcardAny {
		return WildcardAny, WildcardAny, nil
	}
	parts := strings.Split(token, ":")
	if len(parts) != 2 {
		return "", "", &ErrInvalidPattern{
			Pattern: pattern,
			Reason: "must be 'statement_type:table_glob' " +
				"(e.g. 'SELECT:*', 'DELETE:public.users', 'MUTATING:*')",
		}
	}
	stmtType, tableGlob := parts[0], parts[1]
	if stmtType == "" || tableGlob == "" {
		return "", "", &ErrInvalidPattern{
			Pattern: pattern,
			Reason:  "statement_type and table_glob halves must both be non-empty",
		}
	}
	// statement_type may be "*" (any statement) or a literal type / a
	// category. Partial wildcards like "SEL*" are rejected — the
	// classifier output is a flat enum so a wildcard at the statement-
	// type half would imply matching semantics we don't have. Use "*"
	// for the wildcard or list explicit types.
	if stmtType != WildcardAny && strings.Contains(stmtType, "*") {
		return "", "", &ErrInvalidPattern{
			Pattern: pattern,
			Reason: "statement_type half may be '*', a literal type, " +
				"or a category; partial wildcards are rejected",
		}
	}
	return strings.ToUpper(stmtType), strings.ToLower(tableGlob), nil
}

// globToRegex translates an AWS-IAM-style glob (only `*` and `?` are
// meta) into a compiled regex. We do NOT use Go's path.Match because
// it admits `[abc]` character classes that AWS IAM-style globs don't
// support — a user writing a literal `[` in a pattern would get
// character-class semantics they didn't ask for. Same fix kbounce
// closed in WB23 LOW-23-02.
func globToRegex(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString(`\A`)
	for _, ch := range pattern {
		switch ch {
		case '*':
			b.WriteString(`.*`)
		case '?':
			b.WriteString(`.`)
		default:
			b.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	b.WriteString(`\z`)
	return regexp.Compile(b.String())
}

func globMatch(value, pattern string) bool {
	re, err := globToRegex(pattern)
	if err != nil {
		// Defensive: a malformed glob never matches. Caller has
		// already accepted the pattern at insert time so this is rare.
		return false
	}
	return re.MatchString(value)
}

// matchesStatementType returns true when the rule's statement_type
// half (after ParsePattern normalization) covers the parsed statement.
// Handles the four categories (DML, DDL, MUTATING, READ) + the bare
// wildcard + literal-type comparison. The MUTATING category always
// consults HasMutatingNode (catches CTE-hidden writes).
func matchesStatementType(patternType string, ps *ParsedStatement) bool {
	if patternType == WildcardAny {
		return true
	}
	if IsCategory(patternType) {
		switch patternType {
		case CategoryDML:
			// IsDML covers INSERT/UPDATE/DELETE/MERGE. WITH-WRITE is the
			// CTE-wrapped variant; the walker sets HasMutatingNode for
			// both. We treat WITH-WRITE as DML too — semantically it IS
			// a write, the WITH wrapper is just syntax.
			if ps.IsDML {
				return true
			}
			if ps.StatementType == "WITH-WRITE" {
				return true
			}
			return false
		case CategoryDDL:
			return ps.IsDDL
		case CategoryMutating:
			// LOAD-BEARING per dbounce-build-plan §"CTE-hidden writes":
			// MUTATING checks HasMutatingNode unconditionally so a
			// SELECT whose AST contains an UPDATE under a CTE still
			// matches. This is what makes `MUTATING:*` denies actually
			// safe rather than security theater.
			if ps.HasMutatingNode || ps.IsDML || ps.IsDDL {
				return true
			}
			switch ps.StatementType {
			case "CALL", "DO", "EXECUTE", "WITH-WRITE":
				return true
			case "EXPLAIN-ANALYZE":
				// EXPLAIN ANALYZE actually executes the inner statement.
				// Treat as mutating when the inner statement was a write
				// (HasMutatingNode already covers this, but be explicit).
				return ps.HasMutatingNode
			}
			return false
		case CategoryRead:
			// EXPLAIN (without ANALYZE) is informational; the inner
			// statement does NOT execute. SELECT is the canonical read.
			// EXPLAIN ANALYZE is NOT a read — it executes. SET ROLE is
			// not a read either (it changes session state).
			if ps.IsExplainAnalyze {
				return false
			}
			switch ps.StatementType {
			case "SELECT", "EXPLAIN":
				return true
			}
			return false
		}
		return false
	}
	// Literal statement-type comparison. Case already normalized
	// upper-case by ParsePattern; the parser also emits upper-case.
	return strings.EqualFold(patternType, ps.StatementType)
}

// tableMatches returns true when at least one of the statement's
// touched tables matches the glob. Wildcard / empty glob always
// matches (statements with no tables also satisfy the wildcard).
//
// For non-wildcard globs, statements with no tables NEVER match (the
// scope can't apply). Same conservative behavior as kbounce's
// namespace/resource scope handling.
func tableMatches(tables []string, glob string) bool {
	if glob == "" || glob == WildcardAny {
		return true
	}
	if len(tables) == 0 {
		return false
	}
	for _, t := range tables {
		if globMatch(t, glob) {
			return true
		}
	}
	return false
}

// schemaMatches checks the schema half of each touched table against
// the glob. Tables with no schema qualifier are treated as schema "".
// Wildcard / empty glob always matches.
func schemaMatches(tables []string, glob string) bool {
	if glob == "" || glob == WildcardAny {
		return true
	}
	if len(tables) == 0 {
		return false
	}
	for _, t := range tables {
		schema := ""
		if dot := strings.Index(t, "."); dot >= 0 {
			schema = t[:dot]
		}
		if globMatch(schema, glob) {
			return true
		}
	}
	return false
}

// functionMatches checks that at least one called function matches the
// glob. Wildcard / empty glob always matches (statements with no
// functions called also satisfy the wildcard).
func functionMatches(funcs []string, glob string) bool {
	if glob == "" || glob == WildcardAny {
		return true
	}
	if len(funcs) == 0 {
		return false
	}
	for _, fn := range funcs {
		if globMatch(fn, glob) {
			return true
		}
	}
	return false
}

// Matches returns true iff the rule matches the given parsed
// statement. All comparisons are case-insensitive on the statement_type
// half (parser emits upper-case, rule writers may write either) and
// case-sensitive on the table/function halves (parser already
// lower-cases identifiers).
func (r ProxyRule) Matches(ps *ParsedStatement) bool {
	if ps == nil {
		return false
	}
	patternType, tableGlob, err := ParsePattern(r.Pattern)
	if err != nil {
		// Malformed rule never matches; the store should reject these
		// at insert time but a hand-edited DB could still surface one.
		return false
	}
	if !matchesStatementType(patternType, ps) {
		return false
	}
	if !tableMatches(ps.TablesTouched, tableGlob) {
		return false
	}
	if !schemaMatches(ps.TablesTouched, r.SchemaScope) {
		return false
	}
	if !tableMatches(ps.TablesTouched, r.TableScope) {
		return false
	}
	if !functionMatches(ps.FunctionsCalled, r.FunctionScope) {
		return false
	}
	return true
}

// RuleSet is an ordered collection of ProxyRules with deterministic
// evaluation. Safe for concurrent reads after construction; not safe
// for concurrent Add. The store owns the canonical RuleSet; callers
// snapshot via Store.LoadRuleSet().
type RuleSet struct {
	rules []ProxyRule
}

// NewRuleSet builds a RuleSet from the given rules. Order is preserved
// for first-match semantics.
func NewRuleSet(rs []ProxyRule) *RuleSet {
	return &RuleSet{rules: append([]ProxyRule(nil), rs...)}
}

// Rules returns a shallow copy of the underlying rule slice. Used by
// callers that need to introspect the set (CLI list, audit display).
func (rs *RuleSet) Rules() []ProxyRule {
	if rs == nil {
		return nil
	}
	out := make([]ProxyRule, len(rs.rules))
	copy(out, rs.rules)
	return out
}

// Len reports the number of rules in the set.
func (rs *RuleSet) Len() int {
	if rs == nil {
		return 0
	}
	return len(rs.rules)
}

// Add appends a rule. Returns an error if the pattern is malformed.
// Callers that want pre-validated rules can use the zero-error path by
// validating with ParsePattern first.
func (rs *RuleSet) Add(r ProxyRule) error {
	if _, _, err := ParsePattern(r.Pattern); err != nil {
		return err
	}
	if r.Effect != "" && !r.Effect.IsValid() {
		return fmt.Errorf("dbounce: invalid rule effect %q (want allow or deny)", r.Effect)
	}
	rs.rules = append(rs.rules, r)
	return nil
}

// EvalResult is what Evaluate returns: the matched rule's effect plus
// the rule itself (so the caller can carry it into the audit log). Nil
// when no rule matched.
type EvalResult struct {
	Effect Effect
	Rule   ProxyRule
}

// Evaluate runs the rule set against the parsed statement and returns
// the effective verdict.
//
// Order (deny-beats-allow, first-match within each class):
//  1. Any matching DENY  -> EffectDeny + that rule
//  2. Any matching ALLOW -> EffectAllow + that rule
//  3. No match           -> nil (caller falls through)
//
// Pure: no I/O, no side effects.
func (rs *RuleSet) Evaluate(ps *ParsedStatement) *EvalResult {
	if rs == nil || len(rs.rules) == 0 || ps == nil {
		return nil
	}
	var matchedDeny *ProxyRule
	var matchedAllow *ProxyRule
	for i := range rs.rules {
		r := &rs.rules[i]
		if !r.Matches(ps) {
			continue
		}
		if r.Effect == EffectDeny && matchedDeny == nil {
			matchedDeny = r
		} else if r.Effect == EffectAllow && matchedAllow == nil {
			matchedAllow = r
		}
	}
	if matchedDeny != nil {
		return &EvalResult{Effect: EffectDeny, Rule: *matchedDeny}
	}
	if matchedAllow != nil {
		return &EvalResult{Effect: EffectAllow, Rule: *matchedAllow}
	}
	return nil
}

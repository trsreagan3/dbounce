// Package profile implements environment-aware dbounce profiles.
//
// A profile is a named, switchable rule layer that adds SQL-domain
// deny semantics + an allow_baseline classifier on top of dbounce's
// per-task scope and global rule engine. When active, a profile's
// denies are a HARD FLOOR — they fire even if a task scope or global
// rule would have allowed the call. This is the property SecOps teams
// need to approve the install: "if I say 'safe-default', the agent
// CAN NOT mutate a table regardless of which other rules are loaded."
//
// Profiles are symmetric across dbounce (this package), kbouncer's
// internal/profile, and the Python iam-jit-bouncer; the YAML schema is
// intentionally identical so an operator who reads one understands the
// other.
//
// Composition order (LOAD-BEARING — do not reorder):
//
//  1. Profile deny_keywords match (and not in exceptions)  → DENY (source=profile)
//  2. Profile deny_actions match                           → DENY (source=profile)
//  3. allow_baseline classifier (sql_read_only) +
//     deny_ast_mutating_nodes check                        → DENY (source=profile)
//     when the parsed statement is NOT a pure read or has
//     a mutating AST node, and the resource is not in
//     exempt_resources
//  4. Profile allow_rules                                  → ALLOW (source=profile.allow)
//  5. Active task-scope deny                               → DENY (source=task)
//  6. Active task-scope allow                              → ALLOW (source=task)
//  7. Global rules                                         → standard match flow
//
// Profile rules fire BEFORE task / global rules. A permissive task
// scope CANNOT override a profile deny. See [[safety-mode-two-modes]]
// and [[safety-mode-lean-permissive]] in the product memory.
//
// Embedded default profiles (only two, intentionally per
// [[bounce-default-profile-pattern]]):
//
//   - full-user    — passthrough sentinel (zero rules). Default when no
//     --profile / DBOUNCE_PROFILE is selected.
//   - safe-default — cross-product safe-by-default. Uses allow_baseline
//     `sql_read_only` (pure SELECT statements pass) + the AST-walk
//     Layer 2 backstop (HasMutatingNode / IsDML / IsDDL flagged
//     statements deny regardless of the top-level keyword, catching
//     CTE-wrapped writes). NOT a confidentiality boundary — reads of
//     sensitive tables still pass; pair with deny_keywords to block
//     known-sensitive table names.
//
// Backward-compat aliases (mapped to canonical name at lookup;
// deprecation-warned in v1.0, removed in v1.1):
//
//   - "none"          → "full-user"
//   - "prod-readonly" → "safe-default"
//   - "readonly"      → "safe-default"
//
// Other environment-specific profiles (staging-work, dev-only,
// incident-response) install via `dbounce profile install --from URL`
// from the dbounce repo's `community-profiles/` directory.
package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// KeywordMatchMode controls how deny_keywords are compared to the
// candidate strings (table name, schema name, function name).
type KeywordMatchMode string

const (
	// MatchWordBoundary uses Python-style `(?:^|[^A-Za-z0-9])kw(?:$|[^A-Za-z0-9])`
	// (case-insensitive). "prod" matches "prod_users" and "prod-table"
	// but NOT "productivity". Per [[cross-product-word-boundary]]:
	// underscore IS a boundary so the same YAML matches identically
	// across iam-jit-bouncer / kbouncer / dbounce.
	MatchWordBoundary KeywordMatchMode = "word_boundary"

	// MatchSubstring uses raw substring containment (case-insensitive).
	// "prod" matches "productivity" too. Easier to bypass; useful for
	// stricter ops teams that accept the false-positive rate.
	MatchSubstring KeywordMatchMode = "substring"
)

// IsValid returns true for known match modes.
func (m KeywordMatchMode) IsValid() bool {
	switch m {
	case MatchWordBoundary, MatchSubstring:
		return true
	}
	return false
}

// KeywordTarget names a field on the parsed statement that
// deny_keywords are compared against. Multiple targets compose with OR
// — a match on any one fires the deny.
type KeywordTarget string

const (
	// TargetTable compares against each touched table identifier
	// (schema-qualified, lowercase: "public.users", "reports.monthly").
	TargetTable KeywordTarget = "table"

	// TargetSchema compares against the schema half of each touched
	// table (the bit before the '.', or "" for unqualified tables).
	TargetSchema KeywordTarget = "schema"

	// TargetFunction compares against each function the statement
	// invokes (CALL targets, aggregates, volatile functions).
	TargetFunction KeywordTarget = "function"
)

// IsValid returns true for known keyword targets.
func (t KeywordTarget) IsValid() bool {
	switch t {
	case TargetTable, TargetSchema, TargetFunction:
		return true
	}
	return false
}

// AllowBaseline names a built-in statement classifier used by the
// profile's allow path. The classifier is a small deterministic
// predicate; it is NOT a separate rule engine.
//
// Only ONE baseline ships in D-Slice 7:
//
//   - sql_read_only — matches statements that classify as a pure
//     SELECT / EXPLAIN (without ANALYZE) AND have no mutating AST
//     node anywhere in the tree (IsDML / IsDDL / HasMutatingNode all
//     false). CTE-wrapped writes therefore FAIL this classifier
//     (HasMutatingNode=true), which is the load-bearing safety claim.
type AllowBaseline string

const (
	// BaselineSQLReadOnly identifies pure SELECT (no DML/DDL/CALL/etc.)
	// statements. See decideAllowBaseline.
	BaselineSQLReadOnly AllowBaseline = "sql_read_only"
)

// IsValid returns true for known allow baselines.
func (b AllowBaseline) IsValid() bool {
	switch b {
	case "", BaselineSQLReadOnly:
		return true
	}
	return false
}

// ParsedStatement is the minimal view of a SQL statement profile
// evaluation needs. The proxy populates it from its own
// parser.ParsedStatement; we keep it local to this package so the
// profile engine can be unit-tested without dragging in the parser.
//
// Symmetric to dbounce's rules.ParsedStatement; the fields parallel
// the parser's audit-row spine.
type ParsedStatement struct {
	// StatementType is the parser's classifier output ("SELECT",
	// "INSERT", "UPDATE", "DELETE", "DDL", "CALL", "DO", "EXECUTE",
	// "WITH-WRITE", "EXPLAIN", "EXPLAIN-ANALYZE", ...).
	StatementType string

	// TablesTouched is the set of schema-qualified table identifiers
	// (lowercase). Profile keyword denies match against each entry.
	TablesTouched []string

	// FunctionsCalled is the set of functions the statement invokes.
	// Profile keyword denies on TargetFunction match against each.
	FunctionsCalled []string

	// IsDML is true for INSERT / UPDATE / DELETE / MERGE.
	IsDML bool

	// IsDDL is true for CREATE / ALTER / DROP / TRUNCATE / RENAME /
	// COMMENT.
	IsDDL bool

	// IsDCL is true for GRANT / REVOKE / ALTER DEFAULT PRIVILEGES — the
	// privilege-management family. Surfaced from the parser so the
	// profile evaluator can refuse PUBLIC-targeting grants without
	// having to keyword-sniff the raw SQL. Per task #302 / KNOWN-CAVEATS
	// §A5 (the dbounce DCL-classifier gap fix).
	IsDCL bool

	// DCLTargetsPublic is true when a GRANT (or ALTER DEFAULT
	// PRIVILEGES ... GRANT) statement lists the PG `PUBLIC` pseudo-role
	// as a grantee. The safe-default profile treats this as a hard deny
	// (privilege escalation to all sessions). Always false for REVOKE —
	// revoking FROM PUBLIC is cleanup.
	DCLTargetsPublic bool

	// HasMutatingNode is the Layer-2 AST-walk backstop signal. True
	// when ANY AST node anywhere in the tree mutates state. Catches
	// CTE-wrapped writes whose top-level keyword is WITH/SELECT plus
	// MySQL multi-statement batches whose first statement is SELECT
	// but second is UPDATE. LOAD-BEARING for the safe-default profile.
	HasMutatingNode bool

	// IsExplain is true for EXPLAIN (without ANALYZE). EXPLAIN alone
	// does NOT execute the inner statement → safe to treat as a read.
	IsExplain bool

	// IsExplainAnalyze is true for EXPLAIN ANALYZE on a mutating inner
	// statement. The inner statement DOES execute → MUST be treated as
	// mutating for safety.
	IsExplainAnalyze bool
}

// ProfileAllowRule is one allow rule embedded in a profile.
//
// Shape mirrors kbouncer + iam-jit-bouncer ProfileAllowRule so YAML
// profiles round-trip across all three products. dbounce's evaluator
// consumes the Pattern field directly (see Profile.Evaluate); the
// scope fields are preserved for round-trip but not yet consulted by
// the profile-level allow path (the proxy's task + global rule engine
// own those semantics).
type ProfileAllowRule struct {
	// Pattern is the rule pattern. For dbounce, the canonical shape is
	// rules.ProxyRule's "statement_type:table_glob" — e.g. "SELECT:*",
	// "CALL:*". Profile-scoped allow rules are evaluated by the same
	// rules.RuleSet semantics as global rules.
	Pattern string `yaml:"pattern"`

	// ArnScope is preserved for round-trip with iam-jit-bouncer YAML
	// (AWS-shaped). dbounce ignores this field.
	ArnScope string `yaml:"arn_scope,omitempty"`

	// RegionScope is preserved for round-trip with iam-jit-bouncer
	// YAML. dbounce ignores this field.
	RegionScope string `yaml:"region_scope,omitempty"`

	// Note is an operator-readable description of why this rule exists.
	Note string `yaml:"note,omitempty"`
}

// Profile is one named environment profile.
type Profile struct {
	// Name is the YAML key, set by LoadProfiles after parsing.
	Name string `yaml:"-"`

	// Description is the human-readable summary shown by `profile list`
	// and surfaced in audit reasons. Optional.
	Description string `yaml:"description,omitempty"`

	// AllowBaseline names the built-in classifier used by the profile's
	// allow path. Currently the only value is "sql_read_only"; empty
	// means "no built-in baseline" (allow_rules are the only allow
	// surface).
	AllowBaseline AllowBaseline `yaml:"allow_baseline,omitempty"`

	// DenyASTMutatingNodes, when true, denies any statement the parser
	// flagged as mutating (IsDML / IsDDL / HasMutatingNode) UNLESS the
	// touched tables are all in ExemptResources OR the statement type
	// is in ExemptActions. This is the AST-walk Layer 2 backstop per
	// [[structured-classifier-backstop-pattern]] — it catches
	// CTE-wrapped writes that look like SELECT at the top.
	DenyASTMutatingNodes bool `yaml:"deny_ast_mutating_nodes,omitempty"`

	// DenyDCLTargetsPublic, when true, hard-denies any statement whose
	// parsed shape has DCLTargetsPublic=true. The intended target is
	// `GRANT ALL PRIVILEGES ... TO PUBLIC` (and the equivalent ALTER
	// DEFAULT PRIVILEGES shape) — both fan privilege out to every
	// database role, which is the canonical safe-default-tripping
	// failure mode per KNOWN-CAVEATS §A5 / task #302. Fires BEFORE the
	// allow_baseline classifier so a permissive sql_read_only baseline
	// can't accidentally let a privilege escalation through. REVOKE
	// statements never set DCLTargetsPublic (revoke FROM PUBLIC is
	// cleanup) so REVOKE traffic passes this gate unchanged. ExemptActions
	// + ExemptResources are NOT consulted for this floor — a PUBLIC-
	// targeting GRANT is the kind of statement an operator should have
	// to write explicitly as an allow_rule, not implicitly inherit via
	// a per-table carve-out.
	DenyDCLTargetsPublic bool `yaml:"deny_dcl_targets_public,omitempty"`

	// DenyActions lists statement types that always deny when the
	// profile is active, regardless of allow_rules. Each entry is a
	// parser.StatementType constant ("INSERT", "UPDATE", "DELETE",
	// "DDL", "CALL", "DO", "EXECUTE", ...) or one of the rule
	// categories ("DML", "DDL", "MUTATING", "READ"). Empty = no
	// action-level denies (relies on deny_keywords +
	// deny_ast_mutating_nodes for safety).
	DenyActions []string `yaml:"deny_actions,omitempty"`

	// AllowRules are profile-scoped allow rules. Parsed + serialized
	// for round-trip with the Python bouncer's profile shape; dbounce
	// uses them as a profile-level allow layer that fires AFTER the
	// allow_baseline classifier abstains and BEFORE task/global rules.
	AllowRules []ProfileAllowRule `yaml:"allow_rules,omitempty"`

	// ExemptResources is a per-profile carve-out for table identifiers
	// the operator wants to permit mutations on even when
	// deny_ast_mutating_nodes is on. Match is full schema.table
	// (lowercase). Example: ["public.audit_log"] permits the audit
	// writer to keep working under safe-default.
	ExemptResources []string `yaml:"exempt_resources,omitempty"`

	// ExemptActions is a per-profile carve-out for statement types
	// (e.g. ["INSERT_INTO_audit_log"]) that bypass the
	// deny_ast_mutating_nodes / deny_actions floors. Free-form
	// strings; the operator picks vocabulary. dbounce checks this
	// list literally against the parser's StatementType BEFORE
	// applying the AST-walk floor.
	ExemptActions []string `yaml:"exempt_actions,omitempty"`

	// DenyKeywords are case-insensitive tokens that, if matched
	// against any of KeywordTargets on the parsed statement and NOT
	// present in Exceptions, cause a deny.
	DenyKeywords []string `yaml:"deny_keywords,omitempty"`

	// KeywordTargets selects which fields DenyKeywords compare
	// against. Defaults to [table, schema] when unset.
	KeywordTargets []KeywordTarget `yaml:"keyword_targets,omitempty"`

	// KeywordMatch picks the comparison mode. Defaults to
	// MatchWordBoundary when unset.
	KeywordMatch KeywordMatchMode `yaml:"keyword_match,omitempty"`

	// Exceptions is a false-positive allowlist. If any exception
	// string appears as a substring of any keyword target field, the
	// keyword deny is suppressed (deny_actions / deny_ast_mutating_nodes
	// are NOT suppressed).
	Exceptions []string `yaml:"exceptions,omitempty"`

	// Source records provenance. Empty or "local" → user-edited.
	// A URL (set by `profile install --from URL`) → org-distributed,
	// READ-ONLY at the CLI surface (UpsertProfile refuses to overwrite
	// a non-local source). Mirrors kbouncer + iam-jit-bouncer of the
	// same name.
	Source string `yaml:"source,omitempty"`

	// OnlyHosts is a hostname-glob allowlist evaluated at CONNECTION
	// ESTABLISHMENT. Empty = no restriction (preserves backward compat
	// for profiles authored before §A40). Non-empty = the inbound
	// upstream host (the hostname portion of the proxy's `--upstream`
	// URL, NOT the client's listener address) must match at least one
	// glob or the connection is REFUSED at PG StartupMessage / MySQL
	// HandshakeResponse time with `deny_reason="profile_only_hosts"`.
	//
	// Glob shape: AWS-IAM-style `*` (any chars) + `?` (single char).
	// Case-insensitive — hostnames are case-insensitive per RFC 1035.
	//
	// Per [[multi-account-region-cluster-use-case]] §A40 LAUNCH-BLOCKER:
	// closes the multi-host workflow where the same `staging-only`
	// profile must DENY when accidentally used against a prod-shaped
	// upstream. The proxy instance config IS the scope today; OnlyHosts
	// adds a profile-level scope FLOOR that travels with the profile
	// regardless of which `--upstream` flag the operator passed.
	//
	// Per [[v1-scope-bar]]: no `OnlyAccounts` (dbounce has no AWS
	// account concept), no `OnlyRegions` (no region awareness for SQL).
	// Just host + database — the two scopes that exist for a SQL
	// connection.
	OnlyHosts []string `yaml:"only_hosts,omitempty"`

	// OnlyDatabases is a database-name-glob allowlist evaluated at
	// CONNECTION ESTABLISHMENT. Empty = no restriction. Non-empty = the
	// inbound database name (parsed from PG StartupMessage `database`
	// param OR — when absent — from the upstream URL path) must match
	// at least one glob or the connection is REFUSED with
	// `deny_reason="profile_only_databases"`.
	//
	// MySQL caveat: in v1.0 we extract the database name from the
	// upstream URL path only (the MySQL HandshakeResponse's optional
	// schema field requires deeper handshake parsing per
	// [[v1-scope-bar]] — deferred). PG covers both startup-param +
	// upstream-URL fallback.
	//
	// Glob shape: AWS-IAM-style `*` + `?`. Case-insensitive — most SQL
	// engines fold database identifiers in some way; the safe-by-
	// default match treats them as case-insensitive.
	OnlyDatabases []string `yaml:"only_databases,omitempty"`

	// compiledKeywords holds pre-compiled regexes for word_boundary
	// mode. Built lazily on first Evaluate via compileOnce; safe for
	// concurrent callers thereafter.
	compiledKeywords []*regexp.Regexp
	compileOnce      sync.Once
	compileErr       error
}

// IsLocalSource reports whether the profile is editable at the CLI
// surface (i.e., it was not installed from an org URL).
func (p *Profile) IsLocalSource() bool {
	if p == nil {
		return true
	}
	return p.Source == "" || p.Source == "local"
}

// generatorProfileShim is the shape `iam-jit profile generate-from-
// audit` emits per-bouncer (see iam-roles/src/iam_jit/llm/
// profile_generator.py:_render_profile_yaml). UnmarshalYAML on
// Profile decodes BOTH the canonical shape AND this shape so the
// generated YAML can install without a manual translation step.
//
// Per §A26 (#349). Pre-fix, a generator-emitted dbounce.yaml parsed
// into a Profile with every enforcement field empty — denies fired
// for nothing.
type generatorProfileShim struct {
	// SchemaVersion + ProfileName + Bouncer are bundle-routing fields;
	// recognized + ignored at parse time (the install path already has
	// the bouncer routing baked in: a dbounce-emitted file installs
	// into dbounce).
	SchemaVersion any `yaml:"schema_version,omitempty"`
	ProfileName   any `yaml:"profile_name,omitempty"`
	Bouncer       any `yaml:"bouncer,omitempty"`
	Provenance    any `yaml:"provenance,omitempty"`

	// Allows + Denies carry the generator's rule lists. The dbounce-
	// side schema mostly uses sql_patterns + reason fields per-entry;
	// some entries are bouncer-other shapes (target/actions for
	// ibounce, target/verbs for kbounce) and are skipped at the
	// translator because dbounce can't enforce them.
	Allows []generatorRule `yaml:"allows,omitempty"`
	Denies []generatorRule `yaml:"denies,omitempty"`

	// FlaggedForReview + Skipped are operator-review metadata,
	// recognized but unused at parse time.
	FlaggedForReview []any `yaml:"flagged_for_review,omitempty"`
	Skipped          []any `yaml:"skipped,omitempty"`
}

// generatorRule is one entry under generator-shape `denies:` /
// `allows:`. The fields are a superset across the four bouncers so
// the same struct decodes ibounce / kbounce / dbounce / gbounce
// rules; the dbounce translator only consults SQLPatterns + Reason +
// Bouncer (the per-rule bouncer override; rare).
type generatorRule struct {
	Target      any      `yaml:"target,omitempty"`
	Actions     []string `yaml:"actions,omitempty"`
	Verbs       []string `yaml:"verbs,omitempty"`
	Resources   []string `yaml:"resources,omitempty"`
	Scope       any      `yaml:"scope,omitempty"`
	SQLPatterns []string `yaml:"sql_patterns,omitempty"`
	Reason      string   `yaml:"reason,omitempty"`
	Bouncer     string   `yaml:"bouncer,omitempty"`
}

// UnmarshalYAML accepts the canonical Profile shape AND the generator
// shape. The two never collide structurally — the canonical shape has
// no `denies:` field at all and the generator shape has no
// `deny_actions:` field at all — so a body containing fields from
// both shapes is interpreted as the canonical author having layered
// a generator-shape addendum on top (each shape's fields are merged).
//
// Per [[creates-never-mutates]]: pre-existing canonical profiles
// continue to parse identically (the generator-shape fields are
// optional + default to their zero values).
func (p *Profile) UnmarshalYAML(node *yaml.Node) error {
	// First, decode into a type-alias of Profile so the standard
	// yaml.v3 reflection-based decoder runs without recursing into
	// our custom UnmarshalYAML. The Go pattern: alias the type so it
	// loses the method set, decode, copy back.
	type rawProfile Profile
	var canonical rawProfile
	if err := node.Decode(&canonical); err != nil {
		return err
	}
	*p = Profile(canonical)

	// Then decode the same node into the generator shim. yaml.v3
	// silently ignores fields the target struct doesn't declare, so
	// this is a no-op for profiles that don't use the shim's fields.
	var shim generatorProfileShim
	if err := node.Decode(&shim); err != nil {
		return err
	}
	if len(shim.Denies) == 0 && len(shim.Allows) == 0 {
		return nil
	}

	// Merge the shim's rules into the canonical Profile fields. For
	// dbounce the only directly-actionable shape from the generator's
	// rules is `sql_patterns` (identifier tokens become deny_keywords)
	// + bouncer-other shapes are deliberately skipped.
	seenKW := make(map[string]struct{}, len(p.DenyKeywords))
	for _, k := range p.DenyKeywords {
		seenKW[strings.ToLower(k)] = struct{}{}
	}
	for _, rule := range shim.Denies {
		// Bouncer-other rule shapes (ibounce target/actions,
		// kbounce verbs/resources) are skipped here — dbounce
		// cannot enforce an AWS action or a K8s verb. The install-
		// time bundle routing already targeted this file at
		// dbounce so a per-rule `bouncer:` override that names a
		// different product is also skipped silently.
		if rule.Bouncer != "" && !strings.EqualFold(rule.Bouncer, "dbounce") {
			continue
		}
		for _, pat := range rule.SQLPatterns {
			for _, kw := range extractKeywordsFromSQLPattern(pat) {
				lk := strings.ToLower(kw)
				if _, ok := seenKW[lk]; ok {
					continue
				}
				seenKW[lk] = struct{}{}
				p.DenyKeywords = append(p.DenyKeywords, kw)
			}
		}
	}

	// allow rules: when the rule names an explicit statement type or
	// table glob, lift it into AllowRules under the canonical pattern
	// shape (`statement_type:table_glob`). dbounce's allow_rules
	// matcher already understands this shape.
	seenAllow := make(map[string]struct{}, len(p.AllowRules))
	for _, ar := range p.AllowRules {
		seenAllow[strings.ToLower(ar.Pattern)] = struct{}{}
	}
	for _, rule := range shim.Allows {
		if rule.Bouncer != "" && !strings.EqualFold(rule.Bouncer, "dbounce") {
			continue
		}
		for _, pat := range rule.SQLPatterns {
			for _, allowPat := range allowPatternsFromSQLPattern(pat) {
				lk := strings.ToLower(allowPat)
				if _, ok := seenAllow[lk]; ok {
					continue
				}
				seenAllow[lk] = struct{}{}
				p.AllowRules = append(p.AllowRules, ProfileAllowRule{
					Pattern: allowPat,
					Note:    rule.Reason,
				})
			}
		}
	}
	return nil
}

// extractKeywordsFromSQLPattern walks a SQL-pattern string from a
// generator-shape rule (e.g. `DROP DATABASE mysql`, `GRANT * TO
// PUBLIC`, `DROP SCHEMA pg_catalog*`) and returns the identifier-
// like tokens that are worth turning into deny_keywords. The
// canonical bridge: pull the bare-word tokens that aren't SQL
// reserved verbs and use them as substring/word-boundary keys
// against the parsed statement's tables + schemas.
//
// Per [[v1-scope-bar]] we deliberately do NOT build a SQL-pattern
// matcher — that's a follow-up. The keyword bridge handles the
// 80%-case (catching schema/database/table names in destructive
// statements) without inventing new enforcement primitives.
func extractKeywordsFromSQLPattern(pattern string) []string {
	if pattern == "" {
		return nil
	}
	// Reserved-token set kept tiny + lowercased; anything not here
	// is considered an identifier candidate. Glob metacharacters are
	// stripped (`*` / `?`) since they're not part of any identifier.
	reserved := map[string]struct{}{
		"select": {}, "from": {}, "where": {}, "and": {}, "or": {},
		"insert": {}, "into": {}, "values": {}, "update": {}, "set": {},
		"delete": {}, "drop": {}, "create": {}, "alter": {}, "truncate": {},
		"table": {}, "database": {}, "schema": {}, "grant": {}, "revoke": {},
		"to": {}, "on": {}, "by": {}, "all": {}, "any": {}, "privileges": {},
		"public": {}, "user": {}, "role": {}, "with": {},
	}
	rawTokens := strings.FieldsFunc(pattern, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', ',', ';', '(', ')', '*', '?', '\'', '"', '`':
			return true
		}
		return false
	})
	var out []string
	seen := make(map[string]struct{}, len(rawTokens))
	for _, raw := range rawTokens {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		// Skip glob-only tokens.
		if strings.TrimLeft(t, "*?") == "" {
			continue
		}
		// Strip trailing globs from identifier-like prefixes
		// (`pg_catalog*` → `pg_catalog`).
		core := strings.TrimRight(t, "*?")
		if core == "" {
			continue
		}
		if _, isReserved := reserved[strings.ToLower(core)]; isReserved {
			continue
		}
		// Require at least one letter to avoid pulling numeric
		// literals.
		hasLetter := false
		for _, r := range core {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				hasLetter = true
				break
			}
		}
		if !hasLetter {
			continue
		}
		key := strings.ToLower(core)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, core)
	}
	return out
}

// allowPatternsFromSQLPattern is the inverse for allows. For now we
// reduce to a permissive `SELECT:<table>` wildcard per identifier
// token (the safe assumption when an audit-derived rule says "this
// table is observed"). This is a minimal bridge — operators tuning
// further allow shapes should hand-author the AllowRules entry.
func allowPatternsFromSQLPattern(pattern string) []string {
	tokens := extractKeywordsFromSQLPattern(pattern)
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, "SELECT:"+strings.ToLower(t))
	}
	return out
}

// Profiles is a loaded collection of named profiles plus metadata.
type Profiles struct {
	// Path is the on-disk YAML the profiles were loaded from, or "" when
	// loaded from defaults / in-memory.
	Path string

	// All is the name → Profile map. FullUserProfileName is always
	// present; LoadProfiles ensures this.
	All map[string]*Profile
}

// Verdict is what Evaluate returns. When Denied=true, the proxy
// short-circuits to a DENY decision with Source / Reason carried into
// the audit log. When Allowed=true, the proxy short-circuits to an
// ALLOW decision (the allow_baseline classifier matched or an
// AllowRule fired). When both are false, the profile abstains; the
// caller falls through to task / global rules.
type Verdict struct {
	// Denied is true when the profile blocks the request.
	Denied bool
	// Allowed is true when the profile explicitly allows the request
	// (via allow_baseline or allow_rules). Mutually exclusive with
	// Denied.
	Allowed bool
	// Reason is a one-line audit-log-ready description.
	Reason string
	// Source is the rule layer that produced the verdict.
	Source string
	// ProfileName is the name of the profile that fired.
	ProfileName string
}

// SourceProfile is the decision_source value the proxy records when a
// profile deny fires.
const SourceProfile = "profile"

// SourceProfileAllow is the decision_source value when a profile's
// allow_baseline classifier or allow_rules layer fires.
const SourceProfileAllow = "profile.allow"

// DenyReasonOnlyHosts is the deny_reason tag emitted on the OCSF audit
// event when a connection is refused because the upstream host does
// not match the profile's OnlyHosts allowlist. Stable string — SIEM
// filters key on it. Per §A40.
const DenyReasonOnlyHosts = "profile_only_hosts"

// DenyReasonOnlyDatabases is the deny_reason tag emitted when a
// connection is refused because the database name does not match the
// profile's OnlyDatabases allowlist. Per §A40.
const DenyReasonOnlyDatabases = "profile_only_databases"

// FullUserProfileName is the reserved profile name that disables
// profile rules entirely. Always present in Profiles.All.
const FullUserProfileName = "full-user"

// NoneProfileName is the legacy alias for FullUserProfileName.
//
// Deprecated: use FullUserProfileName.
const NoneProfileName = "none"

// SafeDefaultProfileName is the reserved profile name for the
// cross-product safe-by-default deny layer.
const SafeDefaultProfileName = "safe-default"

// ReadonlyProfileName is the legacy alias for SafeDefaultProfileName.
//
// Deprecated: use SafeDefaultProfileName.
const ReadonlyProfileName = "readonly"

// profileAliases maps legacy profile names to their canonical
// replacement. Lookups that hit an alias emit a one-shot deprecation
// warning + transparently resolve to the canonical name. v1.1 removes
// this map.
var profileAliases = map[string]string{
	"none":          FullUserProfileName,
	"prod-readonly": SafeDefaultProfileName,
	"readonly":      SafeDefaultProfileName,
}

// resolveProfileAlias returns the canonical profile name for an alias,
// plus a bool indicating whether the input was an alias.
func resolveProfileAlias(name string) (string, bool) {
	if canonical, ok := profileAliases[name]; ok {
		return canonical, true
	}
	return name, false
}

// ErrUnknownProfile is returned by Profiles.Active when the requested
// name is not in the loaded set.
var ErrUnknownProfile = errors.New("dbounce: unknown profile")

// ErrInvalidProfile is returned by LoadProfiles when a profile's
// fields are internally inconsistent.
var ErrInvalidProfile = errors.New("dbounce: invalid profile")

// ErrProfileExists is returned by Profiles.AddLocalProfile when a
// profile with the requested name already exists on disk. Callers
// that want collision-avoidance (e.g. the CLI's `--target` auto-name
// flow per [[profile-auto-naming]]) should pre-check via
// ExistingProfileNames / NamesSorted before calling AddLocalProfile;
// this error is the last-line backstop against a TOCTOU race where
// the file was edited between LoadProfiles and the append.
var ErrProfileExists = errors.New("dbounce: profile already exists")

// profileFile is the on-disk YAML shape.
type profileFile struct {
	Profiles map[string]*Profile `yaml:"profiles"`
}

// LoadProfiles reads profiles.yaml from path and returns the parsed
// collection. If path is "" or the file doesn't exist, the embedded
// default profiles are returned (with Profiles.Path = "").
//
// FullUserProfileName is always synthesized into the result even if
// the YAML omits it, so callers can always look it up.
func LoadProfiles(path string) (*Profiles, error) {
	if path != "" {
		raw, err := os.ReadFile(path)
		if err == nil {
			return parseProfiles(raw, path)
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("dbounce: read profiles %q: %w", path, err)
		}
	}
	return parseProfiles(DefaultProfilesYAML(), "")
}

// parseProfiles is the shared YAML→Profiles deserializer used by both
// LoadProfiles and the in-memory default loader.
func parseProfiles(raw []byte, path string) (*Profiles, error) {
	var pf profileFile
	if err := yaml.Unmarshal(raw, &pf); err != nil {
		return nil, fmt.Errorf("dbounce: parse profiles yaml: %w", err)
	}
	if pf.Profiles == nil {
		pf.Profiles = map[string]*Profile{}
	}
	for name, p := range pf.Profiles {
		if p == nil {
			// Allow `staging-work:` with empty body.
			p = &Profile{}
			pf.Profiles[name] = p
		}
		p.Name = name
		if err := p.validate(); err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidProfile, name, err)
		}
	}
	if _, ok := pf.Profiles[FullUserProfileName]; !ok {
		pf.Profiles[FullUserProfileName] = &Profile{
			Name:        FullUserProfileName,
			Description: "No profile active; statements parsed + audit-logged + advisory. Default.",
		}
	}
	return &Profiles{Path: path, All: pf.Profiles}, nil
}

// validate checks for internal inconsistencies that should surface at
// load time rather than on the first matching statement.
func (p *Profile) validate() error {
	if p.KeywordMatch != "" && !p.KeywordMatch.IsValid() {
		return fmt.Errorf("keyword_match %q is not one of: %s, %s",
			p.KeywordMatch, MatchWordBoundary, MatchSubstring)
	}
	for _, t := range p.KeywordTargets {
		if !t.IsValid() {
			return fmt.Errorf("keyword_targets contains unknown target %q (want table, schema, function)", t)
		}
	}
	if p.AllowBaseline != "" && !p.AllowBaseline.IsValid() {
		return fmt.Errorf("allow_baseline %q is not recognized (want %q)",
			p.AllowBaseline, BaselineSQLReadOnly)
	}
	return nil
}

// Active returns the named profile or ErrUnknownProfile. Backward-
// compat: legacy profile names ("none", "prod-readonly", "readonly")
// resolve to their canonical replacements with a one-line deprecation
// notice to stderr. v1.1 removes the alias path.
func (ps *Profiles) Active(name string) (*Profile, error) {
	if ps == nil {
		return nil, ErrUnknownProfile
	}
	if name == "" {
		return ps.All[FullUserProfileName], nil
	}
	canonical, wasAlias := resolveProfileAlias(name)
	if wasAlias {
		fmt.Fprintf(os.Stderr,
			"dbounce: profile name %q is deprecated; use %q. "+
				"Aliases remain in v1.0 + are removed in v1.1.\n",
			name, canonical)
	}
	p, ok := ps.All[canonical]
	if !ok {
		return nil, fmt.Errorf("%w: %q (loaded: %s)", ErrUnknownProfile, name, ps.NamesSorted())
	}
	return p, nil
}

// NamesSorted returns the loaded profile names in lexical order.
func (ps *Profiles) NamesSorted() []string {
	if ps == nil {
		return nil
	}
	out := make([]string, 0, len(ps.All))
	for name := range ps.All {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Evaluate runs profile rules in the documented composition order and
// returns the verdict. A nil receiver, the full-user profile, or a
// profile with zero rules returns Denied=false (abstain).
//
// The function is pure: no I/O, no audit-store writes. The caller
// (proxy) is responsible for recording the verdict + carrying
// Source / Reason into the audit row.
func (p *Profile) Evaluate(ps *ParsedStatement) Verdict {
	if p == nil || p.Name == FullUserProfileName || ps == nil {
		return Verdict{}
	}

	// Order 1: deny_keywords (with exceptions allowlist).
	if len(p.DenyKeywords) > 0 {
		mode := p.KeywordMatch
		if mode == "" {
			mode = MatchWordBoundary
		}
		targets := p.KeywordTargets
		if len(targets) == 0 {
			targets = []KeywordTarget{TargetTable, TargetSchema}
		}
		candidates := collectCandidates(ps, targets)
		if !p.matchesAnyException(candidates) {
			if matched, keyword, field, candidate := p.matchKeywords(candidates, mode); matched {
				return Verdict{
					Denied:      true,
					Reason:      fmt.Sprintf("profile %q: %s %q matched keyword %q", p.Name, field, candidate, keyword),
					Source:      SourceProfile,
					ProfileName: p.Name,
				}
			}
		}
	}

	// Order 2: deny_actions (literal statement_type or category).
	if len(p.DenyActions) > 0 && !p.isExemptAction(ps.StatementType) {
		if action, matched := matchAnyAction(p.DenyActions, ps); matched {
			return Verdict{
				Denied:      true,
				Reason:      fmt.Sprintf("profile %q: action %q matched deny_actions entry %q", p.Name, ps.StatementType, action),
				Source:      SourceProfile,
				ProfileName: p.Name,
			}
		}
	}

	// Order 2.5: DCL-targets-public hard floor. Per task #302 /
	// KNOWN-CAVEATS §A5: a `GRANT ALL PRIVILEGES ... TO PUBLIC` is a
	// privilege escalation that fans out to every database role and
	// MUST NOT slip past safe-default. We deny BEFORE the allow_baseline
	// classifier so the sql_read_only baseline (which is permissive by
	// design — it only inspects read-vs-write shape, not privilege
	// targets) can't accidentally let a PUBLIC-targeting grant through.
	// ExemptActions / ExemptResources are NOT consulted — a PUBLIC-
	// targeting GRANT must be written as an explicit allow_rule, not
	// implicitly carved out.
	if p.DenyDCLTargetsPublic && ps.DCLTargetsPublic {
		return Verdict{
			Denied: true,
			Reason: fmt.Sprintf(
				"profile %q: DCL targets PUBLIC — %s grants privilege to every "+
					"database role; safe-default refuses privilege escalation to PUBLIC",
				p.Name, ps.StatementType),
			Source:      SourceProfile,
			ProfileName: p.Name,
		}
	}

	// Order 3: allow_baseline + AST-walk Layer 2 backstop.
	// The classifier returns three possible outcomes:
	//
	//   "allow"  → statement matches the baseline (sql_read_only: pure
	//              SELECT/EXPLAIN, no DML/DDL/mutating AST nodes) →
	//              short-circuit ALLOW with source=profile.allow.
	//   "deny"   → safe-default's deny_ast_mutating_nodes is set AND the
	//              statement has a mutating shape AND no exempt carve-out
	//              matches → short-circuit DENY with source=profile.
	//   "abstain"→ classifier doesn't apply (no allow_baseline set, or
	//              the statement is mutating but the profile didn't ask
	//              for the AST backstop) → fall through to allow_rules.
	if p.AllowBaseline != "" || p.DenyASTMutatingNodes {
		verdict := p.decideAllowBaseline(ps)
		if verdict.Denied || verdict.Allowed {
			return verdict
		}
	}

	// Order 4: profile-scoped allow_rules. dbounce evaluates these via
	// a local matcher so the pattern semantics line up with global
	// rules without importing the rules package (acyclic graph).
	if len(p.AllowRules) > 0 {
		if matched, pattern := matchAnyAllowRule(p.AllowRules, ps); matched {
			return Verdict{
				Allowed:     true,
				Reason:      fmt.Sprintf("profile %q: allow_rule pattern %q matched", p.Name, pattern),
				Source:      SourceProfileAllow,
				ProfileName: p.Name,
			}
		}
	}

	// No profile rule fired; defer to the next layer.
	return Verdict{}
}

// ConnectionVerdict is what EvaluateConnection returns. When Denied
// is true, the proxy MUST refuse the inbound connection at the wire-
// protocol handshake (PG: ErrorResponse with SQLSTATE 42501 + close;
// MySQL: ErrPacket access-denied + close). DenyReason is one of the
// DenyReason* constants — the SIEM keys filter rules on this value.
type ConnectionVerdict struct {
	// Denied is true when the profile blocks the connection.
	Denied bool
	// Reason is a one-line audit-log-ready description ("upstream host
	// 'prod-db.production.internal' does not match profile %q
	// only_hosts entries [*.staging.internal]").
	Reason string
	// DenyReason is the stable string SIEM consumers filter on
	// (DenyReasonOnlyHosts / DenyReasonOnlyDatabases).
	DenyReason string
	// ProfileName is the name of the profile that fired.
	ProfileName string
}

// EvaluateConnectionHost runs ONLY the OnlyHosts portion of the
// connection-scope evaluation. Used by the upstream-forwarding path's
// pre-dial gate, where we know the upstream host but haven't yet
// parsed the StartupMessage `database` param. Returns Denied=true
// when OnlyHosts is non-empty AND host doesn't match; Denied=false
// when OnlyHosts is empty (defer) or matches.
//
// Per §A40: the host pre-gate is the load-bearing safety —
// refusing BEFORE the upstream dial avoids burning a TCP connection
// + reveals the misconfigured-host case at the operator's terminal
// without the upstream side seeing a single byte.
func (p *Profile) EvaluateConnectionHost(host string) ConnectionVerdict {
	if p == nil || p.Name == FullUserProfileName {
		return ConnectionVerdict{}
	}
	if len(p.OnlyHosts) == 0 {
		return ConnectionVerdict{}
	}
	if !matchAnyHostGlob(host, p.OnlyHosts) {
		return ConnectionVerdict{
			Denied: true,
			Reason: fmt.Sprintf(
				"profile %q: upstream host %q does not match only_hosts %v",
				p.Name, host, p.OnlyHosts),
			DenyReason:  DenyReasonOnlyHosts,
			ProfileName: p.Name,
		}
	}
	return ConnectionVerdict{}
}

// EvaluateConnectionDatabase runs ONLY the OnlyDatabases portion of
// the connection-scope evaluation. Used by the upstream-forwarding
// path's post-startup-body gate, where the database name is now
// known. Returns Denied=true when OnlyDatabases is non-empty AND
// database doesn't match; Denied=false when empty (defer) or matches.
func (p *Profile) EvaluateConnectionDatabase(database string) ConnectionVerdict {
	if p == nil || p.Name == FullUserProfileName {
		return ConnectionVerdict{}
	}
	if len(p.OnlyDatabases) == 0 {
		return ConnectionVerdict{}
	}
	if !matchAnyDatabaseGlob(database, p.OnlyDatabases) {
		return ConnectionVerdict{
			Denied: true,
			Reason: fmt.Sprintf(
				"profile %q: database %q does not match only_databases %v",
				p.Name, database, p.OnlyDatabases),
			DenyReason:  DenyReasonOnlyDatabases,
			ProfileName: p.Name,
		}
	}
	return ConnectionVerdict{}
}

// EvaluateConnection runs the profile's connection-level scope rules
// (OnlyHosts + OnlyDatabases) against the resolved upstream host +
// database name. Returns Denied=true when the connection violates a
// scope; Denied=false when the profile abstains (empty allowlists) OR
// the connection matches at least one glob in every non-empty list.
//
// Inputs:
//
//   - host: the upstream hostname (NOT the listener host). PORT MUST
//     BE STRIPPED before calling — the OnlyHosts globs match against
//     the bare hostname per RFC 1035 case-insensitivity.
//   - database: the resolved database name. For PG this is the
//     StartupMessage `database` param (falling back to the upstream
//     URL path when the client omitted it). For MySQL this is the
//     upstream URL path only in v1.0.
//
// A nil receiver OR a full-user profile OR a profile with both
// allowlists empty returns Denied=false (abstain) immediately — the
// fast path covers the common no-scope case without allocating.
//
// Per §A40: enforcement at connection-establishment is load-bearing.
// A profile-allowed connection-handshake that then per-statement-denies
// a host violation defeats the operator intent ("the agent should never
// have touched this prod host"). This function is the gate.
//
// Per [[creates-never-mutates]]: pure function, no I/O. Caller owns
// the audit-event emit + connection close.
func (p *Profile) EvaluateConnection(host, database string) ConnectionVerdict {
	if p == nil || p.Name == FullUserProfileName {
		return ConnectionVerdict{}
	}
	if len(p.OnlyHosts) == 0 && len(p.OnlyDatabases) == 0 {
		return ConnectionVerdict{}
	}
	if len(p.OnlyHosts) > 0 {
		if !matchAnyHostGlob(host, p.OnlyHosts) {
			return ConnectionVerdict{
				Denied: true,
				Reason: fmt.Sprintf(
					"profile %q: upstream host %q does not match only_hosts %v",
					p.Name, host, p.OnlyHosts),
				DenyReason:  DenyReasonOnlyHosts,
				ProfileName: p.Name,
			}
		}
	}
	if len(p.OnlyDatabases) > 0 {
		if !matchAnyDatabaseGlob(database, p.OnlyDatabases) {
			return ConnectionVerdict{
				Denied: true,
				Reason: fmt.Sprintf(
					"profile %q: database %q does not match only_databases %v",
					p.Name, database, p.OnlyDatabases),
				DenyReason:  DenyReasonOnlyDatabases,
				ProfileName: p.Name,
			}
		}
	}
	return ConnectionVerdict{}
}

// matchAnyHostGlob returns true when the host matches at least one
// glob in the list. Empty host with a non-empty list never matches
// (an unparseable startup that yields no host should be REFUSED, not
// silently allowed — the safer fail-closed shape for §A40).
func matchAnyHostGlob(host string, globs []string) bool {
	if host == "" {
		return false
	}
	lh := strings.ToLower(strings.TrimSpace(host))
	for _, g := range globs {
		lg := strings.ToLower(strings.TrimSpace(g))
		if lg == "" {
			continue
		}
		re, err := compileGlob(lg)
		if err != nil {
			continue
		}
		if re.MatchString(lh) {
			return true
		}
	}
	return false
}

// matchAnyDatabaseGlob mirrors matchAnyHostGlob for database names.
// Kept distinct so a future v1.1 can tune case-folding rules per
// dialect without touching the host path.
func matchAnyDatabaseGlob(database string, globs []string) bool {
	if database == "" {
		return false
	}
	ld := strings.ToLower(strings.TrimSpace(database))
	for _, g := range globs {
		lg := strings.ToLower(strings.TrimSpace(g))
		if lg == "" {
			continue
		}
		re, err := compileGlob(lg)
		if err != nil {
			continue
		}
		if re.MatchString(ld) {
			return true
		}
	}
	return false
}

// decideAllowBaseline runs the allow_baseline classifier + the
// AST-walk Layer 2 backstop. Returns:
//
//   - Denied: backstop fires (statement is mutating, exempt list
//     doesn't carve it out)
//   - Allowed: baseline classifier accepts the statement as a pure read
//   - Abstain (both false): caller falls through to allow_rules
//
// This is the load-bearing safety logic for safe-default per
// [[safe-default-is-readonly-admin-minus]]. Splitting the classifier
// out into its own function (a) keeps Evaluate readable, (b) lets the
// AST-walk integration test target the predicate directly without
// driving the full proxy pipeline.
func (p *Profile) decideAllowBaseline(ps *ParsedStatement) Verdict {
	// First: is the statement a pure read per the baseline?
	if p.AllowBaseline == BaselineSQLReadOnly && isSQLReadOnly(ps) {
		return Verdict{
			Allowed:     true,
			Reason:      fmt.Sprintf("profile %q: sql_read_only baseline matched (statement_type=%s)", p.Name, ps.StatementType),
			Source:      SourceProfileAllow,
			ProfileName: p.Name,
		}
	}
	// Not a pure read. If the AST-walk backstop is configured, deny —
	// UNLESS the statement type is in exempt_actions or every touched
	// table is in exempt_resources. The exempt list is checked BEFORE
	// the deny per the spec ("exempt_actions: [INSERT_INTO_audit_log]
	// — exempt list checked BEFORE the AST-walk denies").
	if !p.DenyASTMutatingNodes {
		return Verdict{}
	}
	if p.isExemptAction(ps.StatementType) {
		return Verdict{}
	}
	if isMutatingShape(ps) {
		// exempt_resources: if EVERY touched table is exempt, allow
		// the call to proceed past the backstop. If only SOME tables
		// are exempt, the deny still fires — the safer reading of
		// "exempt this audit table" is "the call must touch ONLY that
		// table." A multi-table batch that includes a non-exempt
		// mutation should fail closed.
		if len(p.ExemptResources) > 0 && allTablesExempt(ps.TablesTouched, p.ExemptResources) {
			return Verdict{}
		}
		mutKind := ps.StatementType
		if ps.HasMutatingNode {
			mutKind = "mutating-node:" + ps.StatementType
		}
		return Verdict{
			Denied: true,
			Reason: fmt.Sprintf(
				"profile %q: AST-walk backstop — %s is mutating; safe-default's "+
					"deny_ast_mutating_nodes catches mutations regardless of nesting depth",
				p.Name, mutKind),
			Source:      SourceProfile,
			ProfileName: p.Name,
		}
	}
	return Verdict{}
}

// isSQLReadOnly is the sql_read_only baseline predicate. A statement
// matches when (a) the top-level keyword is SELECT or EXPLAIN, (b)
// no DML/DDL classifier flags are set, (c) no AST node anywhere in
// the tree mutates state, (d) EXPLAIN ANALYZE (which DOES execute
// the inner statement) does not match.
//
// Per [[scorer-is-ground-truth]] + the build-plan: the classifier
// reflects actual semantics — a CTE-wrapped UPDATE has
// HasMutatingNode=true and therefore FAILS this predicate even though
// its top-level keyword is WITH (parser surfaces as WITH-WRITE).
func isSQLReadOnly(ps *ParsedStatement) bool {
	if ps == nil {
		return false
	}
	if ps.IsExplainAnalyze {
		return false
	}
	if ps.IsDML || ps.IsDDL || ps.HasMutatingNode {
		return false
	}
	switch ps.StatementType {
	case "SELECT", "EXPLAIN", "SHOW":
		return true
	}
	return false
}

// isMutatingShape returns true when the parsed statement has any
// mutating signal. Used by the AST-walk backstop.
//
// DCL (GRANT / REVOKE / ALTER DEFAULT PRIVILEGES) is intentionally NOT
// in the mutating set here. The DCL hard-floor lives at
// `DenyDCLTargetsPublic` (Order 2.5) which fires ONLY on the dangerous
// PUBLIC-targeting shape; routine GRANTs to specific users (the common
// admin shape) deserve their own per-deployment policy via allow_rules
// rather than being implicitly denied by the read-only baseline.
// Per KNOWN-CAVEATS §A5 + task #302.
func isMutatingShape(ps *ParsedStatement) bool {
	if ps == nil {
		return false
	}
	if ps.IsDML || ps.IsDDL || ps.HasMutatingNode {
		return true
	}
	switch ps.StatementType {
	case "CALL", "DO", "EXECUTE", "WITH-WRITE", "TRUNCATE", "MERGE",
		"COMMENT", "COPY", "LOAD", "VACUUM":
		return true
	case "EXPLAIN-ANALYZE":
		return ps.HasMutatingNode
	}
	return false
}

// isExemptAction returns true when the given statement type is in
// the profile's ExemptActions list (case-insensitive literal match).
func (p *Profile) isExemptAction(stmtType string) bool {
	if len(p.ExemptActions) == 0 || stmtType == "" {
		return false
	}
	for _, e := range p.ExemptActions {
		if strings.EqualFold(strings.TrimSpace(e), stmtType) {
			return true
		}
	}
	return false
}

// allTablesExempt returns true iff EVERY touched table appears in
// exempt (case-insensitive). Empty tables list returns false (a
// tableless mutation like a DO block can't be carved out by table
// name).
func allTablesExempt(tables, exempt []string) bool {
	if len(tables) == 0 {
		return false
	}
	exemptSet := make(map[string]struct{}, len(exempt))
	for _, e := range exempt {
		exemptSet[strings.ToLower(strings.TrimSpace(e))] = struct{}{}
	}
	for _, t := range tables {
		if _, ok := exemptSet[strings.ToLower(t)]; !ok {
			return false
		}
	}
	return true
}

// matchAnyAction returns the first deny_actions entry that matches
// the parsed statement (literal type or category).
func matchAnyAction(actions []string, ps *ParsedStatement) (string, bool) {
	for _, a := range actions {
		token := strings.ToUpper(strings.TrimSpace(a))
		if token == "" {
			continue
		}
		if matchesActionToken(token, ps) {
			return a, true
		}
	}
	return "", false
}

// matchesActionToken returns true when token (already upper-cased)
// matches the parsed statement. Categories: DML, DDL, MUTATING, READ.
// Otherwise: literal statement_type comparison.
func matchesActionToken(token string, ps *ParsedStatement) bool {
	switch token {
	case "*":
		return true
	case "DML":
		if ps.IsDML {
			return true
		}
		return ps.StatementType == "WITH-WRITE"
	case "DDL":
		return ps.IsDDL
	case "MUTATING":
		if ps.HasMutatingNode || ps.IsDML || ps.IsDDL {
			return true
		}
		switch ps.StatementType {
		case "CALL", "DO", "EXECUTE", "WITH-WRITE":
			return true
		case "EXPLAIN-ANALYZE":
			return ps.HasMutatingNode
		}
		return false
	case "READ":
		if ps.IsExplainAnalyze {
			return false
		}
		switch ps.StatementType {
		case "SELECT", "EXPLAIN":
			return true
		}
		return false
	}
	return strings.EqualFold(token, ps.StatementType)
}

// matchAnyAllowRule returns the first profile-scoped allow rule that
// matches.
func matchAnyAllowRule(allowRules []ProfileAllowRule, ps *ParsedStatement) (bool, string) {
	for _, ar := range allowRules {
		pattern := strings.TrimSpace(ar.Pattern)
		if pattern == "" {
			continue
		}
		if allowRuleMatches(pattern, ps) {
			return true, pattern
		}
	}
	return false, ""
}

// allowRuleMatches is the local matcher for ProfileAllowRule. Accepts
// the same "statement_type:table_glob" shape rules.ParsePattern does,
// plus the bare "*" wildcard. Mirrors rules.ProxyRule.Matches without
// importing the rules package.
func allowRuleMatches(pattern string, ps *ParsedStatement) bool {
	stmtType, tableGlob, ok := splitAllowRulePattern(pattern)
	if !ok {
		return false
	}
	if !matchesActionToken(stmtType, ps) {
		return false
	}
	if !tableGlobMatches(ps.TablesTouched, tableGlob) {
		return false
	}
	return true
}

// splitAllowRulePattern parses the "statement_type:table_glob" form.
// Bare "*" is normalized to "*:*". Returns ok=false on malformed.
func splitAllowRulePattern(pattern string) (string, string, bool) {
	token := strings.TrimSpace(pattern)
	if token == "" {
		return "", "", false
	}
	if token == "*" {
		return "*", "*", true
	}
	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return strings.ToUpper(parts[0]), strings.ToLower(parts[1]), true
}

// tableGlobMatches returns true when at least one of the statement's
// touched tables matches the glob, OR the glob is the wildcard. A
// non-wildcard glob never matches a statement with no tables.
func tableGlobMatches(tables []string, glob string) bool {
	if glob == "" || glob == "*" {
		return true
	}
	if len(tables) == 0 {
		return false
	}
	re, err := compileGlob(glob)
	if err != nil {
		return false
	}
	for _, t := range tables {
		if re.MatchString(t) {
			return true
		}
	}
	return false
}

// compileGlob translates an AWS-IAM-style glob (only `*` and `?` are
// meta) into a compiled regex.
func compileGlob(pattern string) (*regexp.Regexp, error) {
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

// collectCandidates pulls the candidate strings for the configured
// targets. Returns a map field-name → values so the audit reason can
// name which field matched.
//
// Unlike kbouncer (one value per target), dbounce's table /
// schema / function targets each carry MULTIPLE candidate strings
// (every touched table, every called function).
func collectCandidates(ps *ParsedStatement, targets []KeywordTarget) map[KeywordTarget][]string {
	out := make(map[KeywordTarget][]string, len(targets))
	for _, t := range targets {
		switch t {
		case TargetTable:
			out[t] = append(out[t], ps.TablesTouched...)
		case TargetSchema:
			seen := make(map[string]struct{})
			for _, full := range ps.TablesTouched {
				schema := ""
				if dot := strings.Index(full, "."); dot >= 0 {
					schema = full[:dot]
				}
				if _, ok := seen[schema]; !ok {
					seen[schema] = struct{}{}
					out[t] = append(out[t], schema)
				}
			}
		case TargetFunction:
			out[t] = append(out[t], ps.FunctionsCalled...)
		}
	}
	return out
}

// matchesAnyException returns true if any exception is a substring
// (case-insensitive) of any candidate value across any target.
func (p *Profile) matchesAnyException(candidates map[KeywordTarget][]string) bool {
	if len(p.Exceptions) == 0 {
		return false
	}
	for _, values := range candidates {
		for _, val := range values {
			if val == "" {
				continue
			}
			lv := strings.ToLower(val)
			for _, ex := range p.Exceptions {
				if ex == "" {
					continue
				}
				if strings.Contains(lv, strings.ToLower(ex)) {
					return true
				}
			}
		}
	}
	return false
}

// matchKeywords returns the first (keyword, field, candidate) that
// fires a deny.
func (p *Profile) matchKeywords(candidates map[KeywordTarget][]string, mode KeywordMatchMode) (bool, string, KeywordTarget, string) {
	fields := make([]KeywordTarget, 0, len(candidates))
	for f := range candidates {
		fields = append(fields, f)
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i] < fields[j] })

	if mode == MatchWordBoundary {
		p.compileOnce.Do(func() {
			p.compiledKeywords = make([]*regexp.Regexp, 0, len(p.DenyKeywords))
			for _, kw := range p.DenyKeywords {
				if kw == "" {
					p.compiledKeywords = append(p.compiledKeywords, nil)
					continue
				}
				// Per [[cross-product-word-boundary]]: use the same
				// regex shape iam-jit-bouncer + kbouncer use so a
				// shared YAML matches identically across products.
				pat := `(?i)(?:^|[^A-Za-z0-9])` +
					regexp.QuoteMeta(kw) +
					`(?:$|[^A-Za-z0-9])`
				re, err := regexp.Compile(pat)
				if err != nil {
					p.compileErr = err
					p.compiledKeywords = append(p.compiledKeywords, nil)
					continue
				}
				p.compiledKeywords = append(p.compiledKeywords, re)
			}
		})
		for _, f := range fields {
			for _, val := range candidates[f] {
				if val == "" {
					continue
				}
				for i, re := range p.compiledKeywords {
					if re == nil {
						continue
					}
					if re.MatchString(val) {
						return true, p.DenyKeywords[i], f, val
					}
				}
			}
		}
		return false, "", "", ""
	}

	for _, f := range fields {
		for _, val := range candidates[f] {
			if val == "" {
				continue
			}
			lv := strings.ToLower(val)
			for _, kw := range p.DenyKeywords {
				if kw == "" {
					continue
				}
				if strings.Contains(lv, strings.ToLower(kw)) {
					return true, kw, f, val
				}
			}
		}
	}
	return false, "", "", ""
}

// DefaultProfilesPath returns ~/.dbounce/profiles.yaml or honors
// DBOUNCE_PROFILES_PATH if set.
func DefaultProfilesPath() (string, error) {
	if override := os.Getenv("DBOUNCE_PROFILES_PATH"); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("dbounce: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".dbounce", "profiles.yaml"), nil
}

// AddLocalProfile appends a new local-source profile to the on-disk
// profiles file at path. The receiver is consulted only for in-memory
// shape; the on-disk YAML is RE-READ before the append so concurrent
// writes (another `dbounce` invocation, an `install --from URL`) don't
// get clobbered. Returns ErrProfileExists if a profile with the same
// name already lives on disk; callers responsible for collision-avoid
// using internal/naming should still pre-check via ExistingProfileNames
// to surface a friendly error before the disk round-trip.
//
// Behavior:
//
//   - p.Source is forced to "local" regardless of what the caller set
//     (a non-local source would make the profile read-only and trip
//     UpsertProfile's invariant later; an AddLocalProfile-created
//     profile is by definition operator-authored).
//   - p.validate() runs before the disk write; an invalid profile
//     never lands on disk.
//   - The write is atomic (temp file + rename), same shape as
//     writeInstalledProfiles, so a crash between truncate + write
//     can never leave a half-written profiles.yaml.
//   - If the parent directory of path doesn't exist, it's created
//     with 0700 (mirrors EnsureDefaultProfilesFile).
//
// Per [[creates-never-mutates]]: this CREATES a new profile entry;
// it NEVER overwrites an existing one. The ErrProfileExists return
// is load-bearing for that invariant.
func (ps *Profiles) AddLocalProfile(path string, p *Profile) error {
	if p == nil || p.Name == "" {
		return errors.New("dbounce: AddLocalProfile: Profile.Name is required")
	}
	resolved := path
	if resolved == "" {
		rp, err := DefaultProfilesPath()
		if err != nil {
			return fmt.Errorf("dbounce: resolve profiles path: %w", err)
		}
		resolved = rp
	}
	// Force local source per the docstring invariant. An AddLocalProfile
	// caller cannot accidentally (or maliciously) plant a profile whose
	// source field would later make it read-only at the CLI surface.
	p.Source = "local"
	if verr := p.validate(); verr != nil {
		return fmt.Errorf("%w: %q: %v", ErrInvalidProfile, p.Name, verr)
	}

	if dir := filepath.Dir(resolved); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("dbounce: mkdir %q: %w", dir, err)
		}
	}

	// Re-read the on-disk YAML so a concurrent writer (another dbounce
	// CLI invocation, `profile install --from URL`) doesn't get its
	// changes silently dropped. The Profiles receiver's in-memory `All`
	// map is intentionally NOT consulted here — it may be stale.
	merged := profileFile{Profiles: map[string]*Profile{}}
	if raw, err := os.ReadFile(resolved); err == nil {
		if uerr := yaml.Unmarshal(raw, &merged); uerr != nil {
			return fmt.Errorf("dbounce: parse existing profiles yaml: %w", uerr)
		}
		if merged.Profiles == nil {
			merged.Profiles = map[string]*Profile{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("dbounce: read profiles yaml: %w", err)
	}

	if _, exists := merged.Profiles[p.Name]; exists {
		return fmt.Errorf("%w: %q", ErrProfileExists, p.Name)
	}

	merged.Profiles[p.Name] = p

	out, err := yaml.Marshal(&merged)
	if err != nil {
		return fmt.Errorf("dbounce: encode profiles yaml: %w", err)
	}

	// Atomic write: temp file in the same directory (so os.Rename is a
	// metadata-only operation on the same filesystem) + chmod + rename.
	// Mirrors writeInstalledProfiles so a future audit can grep for one
	// pattern across both code paths.
	tmp, err := os.CreateTemp(filepath.Dir(resolved), ".profiles-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("dbounce: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("dbounce: write temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("dbounce: chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("dbounce: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, resolved); err != nil {
		return fmt.Errorf("dbounce: rename into place: %w", err)
	}

	// Best-effort in-memory sync so a long-lived Profiles handle sees
	// the new entry without re-loading. Callers that need authoritative
	// state should re-call LoadProfiles.
	if ps != nil {
		if ps.All == nil {
			ps.All = map[string]*Profile{}
		}
		ps.All[p.Name] = p
		if ps.Path == "" {
			ps.Path = resolved
		}
	}
	return nil
}

// EnsureDefaultProfilesFile writes the embedded default profiles YAML
// to path iff path doesn't already exist.
func EnsureDefaultProfilesFile(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("dbounce: stat profiles %q: %w", path, err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return false, fmt.Errorf("dbounce: mkdir %q: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, DefaultProfilesYAML(), 0o600); err != nil {
		return false, fmt.Errorf("dbounce: write profiles %q: %w", path, err)
	}
	return true, nil
}

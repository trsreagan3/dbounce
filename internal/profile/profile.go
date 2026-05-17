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

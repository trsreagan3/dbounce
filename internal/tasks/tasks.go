// Package tasks implements dbounce's per-task scope feature.
//
// Mirrors kbouncer's tasks.go + the iam-jit-bouncer Python tasks.py
// (translated to SQL semantics + Go idioms). An agent declares a TASK
// SCOPE at task start; dbounce enforces that scope for the task's
// duration; the audit chain captures the task lifecycle. When the
// task ends (explicit end OR time-based expiry), the scope drops and
// the proxy returns to its baseline behavior.
//
// Composition with global rules (mirrors the Python decisions.py
// composition; load-bearing across all three products):
//
//   ALLOW = (no profile-deny matches)
//           AND (no task-explicit-deny matches)
//           AND (
//               task-allow-rule matches
//               OR (no task allow rules apply AND global rules allow)
//           )
//
// In plain English:
//   - Profile deny (D-Slice 7) ALWAYS wins (the admin's baseline can't
//     be overridden by a task scope).
//   - Task explicit deny ALSO wins (the agent saying "no prod"
//     enforces even if global rules would have allowed).
//   - Task allow takes precedence when it matches (the agent's
//     positive declaration is what the task is for).
//   - Unmatched-by-task-allow falls through to global rules (so
//     infrastructure calls like a discovery probe that the agent
//     didn't think to declare still work if global rules allow them).
//
// Per [[agent-friendly-not-bypassable]]:
//   - Lens A: agent declares the task at start; the bouncer enforces
//     during the duration; agents get a clear answer for every call.
//   - Lens B: every task lifecycle event is audit-logged; decisions
//     during the task reference the active task_id so post-incident
//     review can answer "what was this agent authorized to do, and
//     did anything escape that scope?"
package tasks

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/trsreagan3/dbounce/internal/rules"
)

// shorthandScopeRe enforces that the schema and table scope segments
// of a task shorthand match the SQL-identifier-ish charset:
// lowercase letters, digits, underscores, dots (schema.table), hyphens,
// and the glob metachars `*` / `?`. Closes the dbounce equivalent of
// UAT-K2 HIGH-K2-01: a prior parser would silently accept `@schema=value`
// (user habit from SQL grammar) and produce a never-matching rule —
// reject hard with a pointer at the correct shape.
var shorthandScopeRe = regexp.MustCompile(`^[a-z0-9_.*?-]+$`)

// Status is the lifecycle state of a task scope.
type Status string

const (
	// StatusActive — task is open + enforcing.
	StatusActive Status = "active"
	// StatusCompleted — explicitly ended via the CLI/MCP.
	StatusCompleted Status = "completed"
	// StatusExpired — auto-ended on duration expiry.
	StatusExpired Status = "expired"
	// StatusReplaced — superseded by a newer task (future; single-active today).
	StatusReplaced Status = "replaced"
)

// IsValid returns true for canonical status values.
func (s Status) IsValid() bool {
	switch s {
	case StatusActive, StatusCompleted, StatusExpired, StatusReplaced:
		return true
	}
	return false
}

// MinDurationMinutes / MaxDurationMinutes bracket what BuildScope
// accepts. 1 minute floor avoids zero-length tasks; 24h cap aligns
// with the kbounce + Python side (multi-day tasks signal the user
// wants something else — re-issue with a clear new scope).
const (
	MinDurationMinutes = 1
	MaxDurationMinutes = 24 * 60
)

// Scope is an agent's declared task scope. Once built it should be
// treated as immutable for the lifetime of the task (the store may
// rewrite status/end_at on close, but allow/deny rules don't change).
type Scope struct {
	TaskID      string
	Description string
	AllowRules  []rules.ProxyRule
	DenyRules   []rules.ProxyRule
	StartedAt   string // ISO-8601 UTC
	ExpiresAt   string // ISO-8601 UTC
	StartedBy   string
	Status      Status
	EndedAt     string // empty until status moves off ACTIVE
	EndedBy     string
	EndReason   string
	Owner       string // empty = "default owner" slot (single-active per-machine)
}

// ToMap returns a JSON-friendly representation for CLI --json output
// and audit-log detail payloads.
func (s *Scope) ToMap() map[string]any {
	allow := make([]map[string]any, 0, len(s.AllowRules))
	for _, r := range s.AllowRules {
		allow = append(allow, r.ToMap())
	}
	deny := make([]map[string]any, 0, len(s.DenyRules))
	for _, r := range s.DenyRules {
		deny = append(deny, r.ToMap())
	}
	return map[string]any{
		"task_id":     s.TaskID,
		"description": s.Description,
		"allow_rules": allow,
		"deny_rules":  deny,
		"started_at":  s.StartedAt,
		"expires_at":  s.ExpiresAt,
		"started_by":  s.StartedBy,
		"status":      string(s.Status),
		"ended_at":    s.EndedAt,
		"ended_by":    s.EndedBy,
		"end_reason":  s.EndReason,
		"owner":       s.Owner,
	}
}

// IsExpired returns true iff the task's wall-clock expiry has passed.
// Only meaningful for active tasks; returns false for completed /
// expired / replaced tasks since their lifecycle is already settled.
func (s *Scope) IsExpired(now time.Time) bool {
	if s.Status != StatusActive {
		return false
	}
	exp, err := parseISO(s.ExpiresAt)
	if err != nil {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return !now.Before(exp)
}

// AllowRuleSet returns the task's allow rules wrapped in a RuleSet for
// evaluation. Rebuilt each call so callers can't accidentally share
// state (RuleSet snapshots a copy on construction).
func (s *Scope) AllowRuleSet() *rules.RuleSet {
	return rules.NewRuleSet(s.AllowRules)
}

// DenyRuleSet mirrors AllowRuleSet for the deny half.
func (s *Scope) DenyRuleSet() *rules.RuleSet {
	return rules.NewRuleSet(s.DenyRules)
}

// ValidationError signals a malformed input to BuildScope. Surfaced
// by the CLI (exit 2) and the MCP path (return as agent-readable error).
type ValidationError struct {
	Reason string
}

func (e *ValidationError) Error() string { return "dbounce: " + e.Reason }

// BuildScope is the validating constructor used by the CLI + (later)
// MCP. Mirrors the Python build_task_scope + kbounce BuildScope
// semantics.
//
// allowRules / denyRules entries are coerced — Effect is forced to
// the list they're in (the distinction is which list, not a per-rule
// field). Origin is set to OriginTask. Patterns are validated via
// ParsePattern; malformed patterns raise *ValidationError.
//
// durationMinutes defaults to 30 when zero. taskID defaults to a
// random 12-char hex when empty. owner is normalized: empty -> ""
// (default-owner slot), whitespace-trimmed otherwise.
func BuildScope(
	description string,
	allowRules []rules.ProxyRule,
	denyRules []rules.ProxyRule,
	durationMinutes int,
	startedBy string,
	owner string,
) (*Scope, error) {
	desc := strings.TrimSpace(description)
	if desc == "" {
		return nil, &ValidationError{Reason: "description is required and must be non-empty"}
	}
	if len(desc) > 2000 {
		return nil, &ValidationError{Reason: "description max length is 2000 chars"}
	}
	if durationMinutes == 0 {
		durationMinutes = 30
	}
	if durationMinutes < MinDurationMinutes {
		return nil, &ValidationError{Reason: fmt.Sprintf(
			"duration_minutes must be >= %d", MinDurationMinutes)}
	}
	if durationMinutes > MaxDurationMinutes {
		return nil, &ValidationError{Reason: fmt.Sprintf(
			"duration_minutes max is %d (24h); use multiple tasks for longer work",
			MaxDurationMinutes)}
	}
	sb := strings.TrimSpace(startedBy)
	if sb == "" {
		return nil, &ValidationError{Reason: "started_by is required and must be non-empty"}
	}
	if len(sb) > 256 {
		return nil, &ValidationError{Reason: "started_by max length is 256 chars"}
	}
	cleanedOwner := strings.TrimSpace(owner)
	if cleanedOwner != "" && len(cleanedOwner) > 256 {
		return nil, &ValidationError{Reason: "owner max length is 256 chars"}
	}

	allowClean, err := coerceRules(allowRules, rules.EffectAllow)
	if err != nil {
		return nil, err
	}
	denyClean, err := coerceRules(denyRules, rules.EffectDeny)
	if err != nil {
		return nil, err
	}
	if len(allowClean) == 0 && len(denyClean) == 0 {
		return nil, &ValidationError{
			Reason: "at least one allow_rule or deny_rule is required — " +
				"a task scope with no rules has no effect",
		}
	}

	now := time.Now().UTC()
	taskID, err := randomTaskID()
	if err != nil {
		return nil, fmt.Errorf("dbounce: generate task id: %w", err)
	}
	return &Scope{
		TaskID:      taskID,
		Description: desc,
		AllowRules:  allowClean,
		DenyRules:   denyClean,
		StartedAt:   formatISO(now),
		ExpiresAt:   formatISO(now.Add(time.Duration(durationMinutes) * time.Minute)),
		StartedBy:   sb,
		Status:      StatusActive,
		Owner:       cleanedOwner,
	}, nil
}

func coerceRules(in []rules.ProxyRule, effect rules.Effect) ([]rules.ProxyRule, error) {
	out := make([]rules.ProxyRule, 0, len(in))
	for _, r := range in {
		// Force the effect to match the list it's in.
		r.Effect = effect
		if r.Origin == "" {
			r.Origin = rules.OriginTask
		}
		if _, _, err := rules.ParsePattern(r.Pattern); err != nil {
			return nil, &ValidationError{Reason: fmt.Sprintf(
				"rule pattern %q is malformed; must be 'statement_type:table_glob' "+
					"(e.g. 'SELECT:*', 'DML:public.*', 'MUTATING:*')", r.Pattern)}
		}
		out = append(out, r)
	}
	return out, nil
}

// ParseShorthand parses a CLI rule shorthand into a ProxyRule. Legacy
// signature kept for callers that don't care about validation errors;
// ParseShorthandStrict is the preferred entry point + returns a
// validation error rather than silently producing a never-matching rule.
//
// Shape: `pattern[@schema_scope][#function_scope]`. Both scopes
// optional. Effect is set by the caller (allow / deny list).
//
// Examples:
//   SELECT:public.*@public                  -> SELECT:public.* scoped to schema public
//   CALL:*#approved_proc                    -> CALL scoped to function approved_proc
//   *:secrets.*                              -> any statement touching secrets schema
//
// Picks `@` for schema-scope and `#` for function-scope (mirrors the
// kbounce shorthand's `@namespace #resource` pair — same mental model
// of "pattern + extra scopes," translated to the SQL domain).
func ParseShorthand(s string) rules.ProxyRule {
	r, _ := ParseShorthandStrict(s)
	return r
}

// ParseShorthandStrict parses a CLI rule shorthand into a ProxyRule
// + validates the schema/function scope segments. Closes the dbounce
// equivalent of UAT-K2 HIGH-K2-01.
//
// Returns *ValidationError when the scope contains characters outside
// the SQL-identifier-ish charset (lowercase letters, digits,
// underscores, dots, hyphens, glob metachars `*` / `?`). The common
// bad input is `@schema=public` (user habit from key=value config);
// the correct shape is `@public`.
func ParseShorthandStrict(s string) (rules.ProxyRule, error) {
	pattern := s
	var schemaScope, functionScope string
	if at := strings.Index(pattern, "@"); at >= 0 {
		afterAt := pattern[at+1:]
		pattern = pattern[:at]
		if hash := strings.Index(afterAt, "#"); hash >= 0 {
			schemaScope = afterAt[:hash]
			functionScope = afterAt[hash+1:]
		} else {
			schemaScope = afterAt
		}
	} else if hash := strings.Index(pattern, "#"); hash >= 0 {
		functionScope = pattern[hash+1:]
		pattern = pattern[:hash]
	}
	schemaScope = strings.TrimSpace(schemaScope)
	functionScope = strings.TrimSpace(functionScope)
	pattern = strings.TrimSpace(pattern)

	if schemaScope != "" && !shorthandScopeRe.MatchString(schemaScope) {
		return rules.ProxyRule{}, &ValidationError{
			Reason: fmt.Sprintf(
				"shorthand %q: schema scope %q is malformed — "+
					"use bare names (e.g. `@public`), not "+
					"key=value (e.g. `@schema=public`); allowed "+
					"chars are [a-z0-9_.-] plus glob `*` / `?`",
				s, schemaScope),
		}
	}
	if functionScope != "" && !shorthandScopeRe.MatchString(functionScope) {
		return rules.ProxyRule{}, &ValidationError{
			Reason: fmt.Sprintf(
				"shorthand %q: function scope %q is malformed — "+
					"use bare names (e.g. `#approved_proc`), not "+
					"key=value (e.g. `#fn=approved_proc`); allowed "+
					"chars are [a-z0-9_.-] plus glob `*` / `?`",
				s, functionScope),
		}
	}

	return rules.ProxyRule{
		Pattern:       pattern,
		SchemaScope:   schemaScope,
		FunctionScope: functionScope,
		Origin:        rules.OriginTask,
	}, nil
}

// ParseShorthandList parses a comma-separated list of shorthand rules.
// Used by the CLI's --allow / --deny CSV flag form. Legacy signature;
// see ParseShorthandListStrict for the error-surfacing variant.
func ParseShorthandList(csv string) []rules.ProxyRule {
	out, _ := ParseShorthandListStrict(csv)
	return out
}

// ParseShorthandListStrict is the validation-surfacing variant of
// ParseShorthandList. Returns the first ValidationError encountered;
// callers that want all errors should iterate manually using
// ParseShorthandStrict.
func ParseShorthandListStrict(csv string) ([]rules.ProxyRule, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, nil
	}
	out := make([]rules.ProxyRule, 0, 4)
	for _, part := range strings.Split(csv, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		r, err := ParseShorthandStrict(p)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func formatISO(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func parseISO(s string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05Z", s)
}

func randomTaskID() (string, error) {
	b := make([]byte, 6) // 12 hex chars
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

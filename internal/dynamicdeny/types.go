// Package dynamicdeny implements dbounce's consumer side of the
// cross-product dynamic-deny rules surface (#324c).
//
// The full cross-product design lives in the iam-roles repo at
// `docs/DYNAMIC-DENY-RULES.md`; the on-disk YAML shape is described by
// `docs/schemas/dynamic-denies-v1.json`. This package implements:
//
//   - Loader: reads + validates `~/.iam-jit/dynamic-denies.yaml`
//     against the v1.0 schema shape, then filters down to rules whose
//     `applied_to` includes `dbounce` OR whose target patterns shape-
//     match the dbounce lane (hostname heuristic + `rds:*` ARN
//     pattern). Operator-explicit `applied_to: [dbounce]` always wins.
//
//   - Watcher: fsnotify-driven hot reload of the YAML file. On parse
//     error, retains the previous in-memory rule set (fail-closed per
//     `[[ibounce-honest-positioning]]`) + emits an admin-action OCSF
//     event so the operator sees the failure without grepping.
//
// CONNECTION-LEVEL GATE (vs gbounce's per-request matcher)
// --------------------------------------------------------
//
// Unlike gbounce — where one proxy instance routes many distinct
// outbound hostnames + the matcher runs per-request — a dbounce
// instance points at ONE upstream database. A dynamic-deny rule
// either applies to the whole instance or doesn't. The deny does NOT
// gate per-statement; it gates the whole connection.
//
// Implementation choice: at startup + on YAML reload, compute "is this
// dbounce instance now denied?" by matching the rules' Targets against
// the configured upstream hostname + (optional operator-supplied) RDS
// ARN. If yes, REFUSE new connections at the PG StartupMessage with a
// PG ErrorResponse naming the rule_id + reason. Existing connections
// continue normally (don't kill mid-transaction; per
// [[ibounce-honest-positioning]] the honest contract is "new
// connections refused; in-flight queries finish").
package dynamicdeny

import "time"

// Rule is one dynamic-deny rule, deserialized from the YAML file +
// filtered for dbounce applicability. Mirrors the on-disk schema field
// names so a future yaml-round-trip writer can reuse this struct as-is.
type Rule struct {
	// ID is the rule's stable identifier (`dd_<ULID>`). Surfaces in the
	// audit `ext.dynamic_deny_rule_id` field when the rule fires.
	ID string `yaml:"id" json:"id"`
	// Targets are the operator-supplied target patterns. For dbounce
	// these are hostnames (glob-shaped) or RDS ARNs (`arn:aws:rds:...`).
	Targets []string `yaml:"targets" json:"targets"`
	// Reason is the operator's free-text reason — surfaces in the
	// connection-refused ErrorResponse + the deny audit event verbatim
	// so a downstream operator sees `why` without context-switching.
	Reason string `yaml:"reason" json:"reason"`
	// Duration is the Go-style duration string (`30m`, `3h`, `7d`) or
	// the literal `permanent`. Anchors `ExpiresAt`.
	Duration string `yaml:"duration" json:"duration"`
	// AddedBy / AddedAt / ExpiresAt are audit-trail metadata. ExpiresAt
	// is nil for `duration: permanent`.
	AddedBy   string     `yaml:"added_by" json:"added_by"`
	AddedAt   time.Time  `yaml:"added_at" json:"added_at"`
	ExpiresAt *time.Time `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`
	// AppliedTo names which bouncer(s) this rule applies to. The loader
	// keeps rules whose AppliedTo contains "dbounce"; additionally it
	// keeps rules whose targets shape-match the dbounce lane (hostname
	// or rds:* ARN heuristic) so a YAML installed by hand without the
	// cross-product CLI resolver still routes correctly.
	AppliedTo []string `yaml:"applied_to" json:"applied_to"`
	// AppliesToRecommender is consumed by the iam-jit recommender
	// (#324f); dbounce ignores it but preserves the field so a
	// round-trip writer doesn't lose data.
	AppliesToRecommender bool `yaml:"applies_to_recommender" json:"applies_to_recommender"`
	// Source provenance — cli / mcp / org-distributed / imported.
	Source string `yaml:"source,omitempty" json:"source,omitempty"`
	// OrgDistributedURL is only present when Source == "org-distributed".
	OrgDistributedURL string `yaml:"org_distributed_url,omitempty" json:"org_distributed_url,omitempty"`
}

// File is the top-level on-disk YAML shape. Field names match the
// v1.0 schema byte-for-byte so a round-trip writer can emit the same
// file an operator hand-edits.
type File struct {
	SchemaVersion      string `yaml:"schema_version" json:"schema_version"`
	Product            string `yaml:"product,omitempty" json:"product,omitempty"`
	ExportedAt         string `yaml:"exported_at,omitempty" json:"exported_at,omitempty"`
	SourceHostnameHash string `yaml:"source_hostname_hash,omitempty" json:"source_hostname_hash,omitempty"`
	Denies             []Rule `yaml:"denies" json:"denies"`
}

// RuleSet is the in-memory snapshot the proxy consults. Filtered to
// rules applicable to dbounce + not yet expired.
type RuleSet struct {
	// Rules are the filtered + active rules (applied_to contains
	// "dbounce" OR pattern-heuristic matched dbounce lane AND not
	// expired at load time).
	Rules []Rule
	// SourcePath is the path the rules were loaded from. Surfaces in
	// the startup banner + /healthz so an operator who configured a
	// non-default path sees it back.
	SourcePath string
	// LoadedAt is the wall-clock timestamp the snapshot was built.
	// Surfaces in /healthz so an operator can see "last successful
	// reload was N seconds ago."
	LoadedAt time.Time
}

// Empty returns an empty RuleSet — used by callers that need a
// non-nil placeholder before the first load.
func Empty() *RuleSet { return &RuleSet{Rules: nil} }

// AppliesToInstance reports whether ANY rule in the set matches the
// given upstream hostname or RDS ARN. The first match wins; the caller
// uses MatchingRule to recover the full rule for audit purposes.
//
// Empty upstreamHost + empty upstreamRDSARN → never matches (the proxy
// was started in observation-only mode without an upstream; there is
// no target to match against).
func (rs *RuleSet) AppliesToInstance(upstreamHost, upstreamRDSARN string) bool {
	return rs.MatchingRule(upstreamHost, upstreamRDSARN) != nil
}

// MatchingRule returns the first rule in the set whose Targets match
// the configured upstream hostname or RDS ARN. Returns nil when no
// rule matches.
//
// Matching semantics:
//   - upstreamHost is compared against each target using glob-style
//     wildcards (`*` matches any run of chars). A literal hostname
//     target matches only when it equals upstreamHost exactly.
//   - upstreamRDSARN, when non-empty, is compared against each target
//     using the same glob shape. Bare hostname targets are NOT matched
//     against an ARN, and ARN-shaped targets are NOT matched against a
//     hostname — they're orthogonal axes per the design doc's cross-
//     protocol resolver.
func (rs *RuleSet) MatchingRule(upstreamHost, upstreamRDSARN string) *Rule {
	if rs == nil || len(rs.Rules) == 0 {
		return nil
	}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		for _, t := range r.Targets {
			if upstreamHost != "" && !isARNPattern(t) {
				if globMatch(t, upstreamHost) {
					return r
				}
			}
			if upstreamRDSARN != "" && isARNPattern(t) {
				if globMatch(t, upstreamRDSARN) {
					return r
				}
			}
		}
	}
	return nil
}

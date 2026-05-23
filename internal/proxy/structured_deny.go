// #459 / §A57b — port the Python ibounce structured 403 deny shape
// into dbounce's PG ErrorResponse + MySQL ErrPacket emit paths. Per
// [[cross-product-agent-parity]] every Bounce gets matching
// agent-facing wire fields. Per [[creates-never-mutates]] the legacy
// error message text is preserved unchanged at the front; the
// structured-deny JSON rides as a suffix behind the canonical
// `WireMarker` so an agent can split-on-marker without touching
// legacy clients.
//
// Per [[ibounce-honest-positioning]] the Go bouncers ship a LOCAL
// heuristic classifier ONLY (no Python LLM round-trip). The
// classifier_hook field is set to "go-heuristic-only" so an operator
// can tell at a glance that this deny was not classified by the LLM.
package proxy

import (
	"strconv"
	"strings"

	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/structureddeny"
)

// dbounceBouncerName is the wire-level caught_by_bouncer string for
// dbounce — matches the Python ibounce shape so an agent sees
// "caught_by_bouncer: dbounce" alongside "caught_by_bouncer: ibounce"
// from the IAM bouncer per [[cross-product-agent-parity]].
const dbounceBouncerName = "dbounce"

// buildDbounceStructuredDeny synthesizes a StructuredDeny payload from
// the existing decision row + dialect. Used by every transparent-mode
// deny site to produce the suffix that rides alongside the legacy
// human-friendly message text on the wire.
func buildDbounceStructuredDeny(row store.DecisionRow, dialect string) structureddeny.StructuredDeny {
	action := dbounceStructuredDenyAction(row, dialect)
	resource := dbounceStructuredDenyResource(row)
	denySource := dbounceStructuredDenySource(row.DecisionSource)
	suggested := dbounceSuggestedAllowCommand(row, dialect, denySource)
	return structureddeny.Build(structureddeny.BuildOptions{
		Bouncer:               dbounceBouncerName,
		Action:                action,
		Resource:              resource,
		DenyReason:            row.DecisionReason,
		DenySource:            denySource,
		RuleIDIfDynamic:       formatRuleID(row.MatchedRuleID),
		SuggestedAllowCommand: suggested,
	})
}

// formatRuleID renders a *int64 MatchedRuleID as the wire-level
// rule_id_if_dynamic string. Empty when nil so the deny_event_id seed
// stays stable for static-profile denies.
func formatRuleID(rid *int64) string {
	if rid == nil {
		return ""
	}
	return strconv.FormatInt(*rid, 10)
}

// dbounceStructuredDenyAction builds the dbounce-shaped action
// "<STMT_TYPE>:<dialect>" used by the structureddeny heuristic.
// Empty STMT_TYPE → dialect-only (e.g. ":postgres") so the heuristic
// + the deny_event_id seed always have stable input.
func dbounceStructuredDenyAction(row store.DecisionRow, dialect string) string {
	d := strings.ToLower(strings.TrimSpace(dialect))
	if d == "" {
		d = strings.ToLower(strings.TrimSpace(row.Dialect))
	}
	if d == "" {
		d = "unknown"
	}
	st := strings.ToUpper(strings.TrimSpace(row.StatementType))
	if st == "" {
		st = "UNKNOWN"
	}
	return st + ":" + d
}

// dbounceStructuredDenyResource pulls a stable resource identifier
// from the decision row. Today this is the first touched table (when
// the parser reached AST classification) — empty otherwise. Used as
// the suggested-allow `--target` arg + as the deny_event_id seed.
func dbounceStructuredDenyResource(row store.DecisionRow) string {
	if len(row.TablesTouched) > 0 {
		return row.TablesTouched[0]
	}
	return ""
}

// dbounceStructuredDenySource maps dbounce's existing DecisionSource
// string onto the canonical deny_source enum the structureddeny
// package understands. Keeps the wire-level deny_source_classified
// stable across the Python + Go bouncers per
// [[cross-product-agent-parity]].
func dbounceStructuredDenySource(src string) string {
	s := strings.ToLower(strings.TrimSpace(src))
	switch {
	case s == "" || s == "unknown":
		return "unknown"
	case strings.HasPrefix(s, "dynamic"):
		return "dynamic_deny"
	case strings.HasPrefix(s, "profile"):
		return "static_profile"
	case strings.HasPrefix(s, "task"):
		return "task_scope"
	case strings.HasPrefix(s, "global"):
		return "global_scope"
	case strings.HasPrefix(s, "default") || strings.Contains(s, "safe"):
		return "safe_default"
	case strings.HasPrefix(s, "sync-prompt"):
		return "sync_prompt"
	}
	return s
}

// dbounceSuggestedAllowCommand synthesizes a one-line `dbounce
// profile allow ...` command. When the deny is a dynamic-deny rule
// the command starts with `#` so DeriveRecommendedAction routes the
// agent to rephrase+retry — dynamic-deny rules aren't allow-able
// from the CLI; the operator has to edit the dynamic-denies YAML.
func dbounceSuggestedAllowCommand(row store.DecisionRow, dialect, denySource string) string {
	if denySource == "dynamic_deny" {
		rid := formatRuleID(row.MatchedRuleID)
		return "# dynamic-deny rule " + rid +
			" — edit the dynamic-deny YAML to allow this; rephrase+retry"
	}
	target := dbounceStructuredDenyResource(row)
	if target == "" {
		target = "*"
	}
	st := strings.ToUpper(strings.TrimSpace(row.StatementType))
	if st == "" {
		st = "*"
	}
	return "dbounce profile allow --target " + target +
		" --action " + st +
		" --reason '<why is this safe?>'"
}

// dbounceDenyMessageWithStructured wraps a legacy "dbounce: denied:
// ..." message with the canonical structured-deny suffix. Returns the
// composite string suitable for the PG ErrorResponse 'M' / MySQL
// ErrPacket message fields.
//
// Per [[creates-never-mutates]]: the legacy message text rides at the
// front unchanged so old grep-on-`denied:` clients keep working; the
// structured-deny JSON rides as a suffix behind WireMarker.
func dbounceDenyMessageWithStructured(legacyMsg string, row store.DecisionRow, dialect string) string {
	sd := buildDbounceStructuredDeny(row, dialect)
	return sd.AppendToMessage(legacyMsg)
}

// Shared helpers for [[basic-app-hygiene-features]] TIER 1 #4 +
// [[security-team-audit-export]] admin-action audit events.
//
// Every CLI subcommand that MUTATES dbounce's gating surface (rules
// add / rules remove / rules recommend (when --save-as-profile) /
// pause start / presets apply / alert-rule edit / license install /
// config import+export) invokes enqueueAdminAction here AFTER the
// mutation succeeds. The helper writes a pending_audit_events row
// that the running `dbounce run` process drains every 1s
// (proxy.runPendingAuditEventsPoller, shipped 24eca0c) + emits as an
// ADMIN_ACTION OCSF event through the wired Exporter + RuleEngine.
//
// Best-effort by design: a queue-write failure is surfaced via stderr
// but NEVER fails the user-facing operation. The mutation already
// succeeded; the synthetic is observability metadata. Two reasons:
//
//   1. [[creates-never-mutates]] composes: rolling back a rule add
//      because the audit row failed would itself be a mutation —
//      worse, an INVISIBLE one (no audit event to record the
//      rollback). Better to record the original mutation succeeded
//      + surface the audit-write failure to the operator who can
//      investigate.
//
//   2. Mirrors the existing PROFILE_INSTALLED + ADMIN_FALLBACK_END
//      enqueue helpers (24eca0c): same SQLite queue, same JSON shape,
//      same best-effort posture. One pattern across all admin
//      subcommands keeps the audit-event surface easy to review.
//
// Cross-process: the run-process is the only writer to the operator-
// configured audit-log file + the only client of the webhook URL. A
// second exporter in the CLI would double-write the log or worse
// race the webhook ordering. The SQLite queue is the cross-process
// channel — same Option A architecture the spec calls out.
//
// Per-dialect inference: dbounce admin actions may have per-dialect
// implications (a rule's table-glob may match only one dialect's
// catalog; a preset may target a specific dialect; a profile-derived
// action carries the profile-name dialect heuristic). When the action
// carries dialect signal, the helper STAMPS the affected set under
// unmapped.iam_jit.config_change.dialects so a SIEM dashboard can
// filter "rule edits that touched the MySQL surface." Empty/omitted
// when the action is dialect-agnostic — most pause + cross-dialect
// rule paths fall here.

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/trsreagan3/dbounce/internal/store"
)

// adminActionEnqueueParams is the input to enqueueAdminAction. The
// caller fills only the fields its action carries — Action + Actor
// are required (the helper rejects empty strings to defend against
// silent unattributed audit rows); everything else is optional.
//
// ResourceType + ResourceID name the mutated object so a SIEM can
// pivot on "all changes to rule 42" or "all preset applies of
// analytics-engineer." Result defaults to "success" when empty (the
// caller only enqueues AFTER the mutation lands).
type adminActionEnqueueParams struct {
	// Action is the cross-product stable id ("rules.add",
	// "rules.remove", "pause.start", "presets.apply", ...). Sibling
	// agents in ibounce + kbounce share the id space so a single
	// SIEM correlation key works across products.
	Action string

	// Actor is the human/system identity (--actor flag, $USER
	// fallback, or "unknown"). Resolved via resolveActor at the
	// call site so the policy stays uniform with the existing pause
	// + prompts paths.
	Actor string

	// ResourceType names what changed ("rule", "profile", "preset",
	// "pause", ...). Optional but recommended — a SIEM dashboard
	// that groups by resource_type surfaces "rule edits today" at
	// a glance.
	ResourceType string

	// ResourceID names the specific instance ("42", "pg-readonly",
	// "analytics-engineer", ...). Optional; pause.start has no
	// per-resource handle until the pause id is allocated, in
	// which case the caller can populate it post-StartPause.
	ResourceID string

	// Result is one of "success", "failure", "noop". Defaults to
	// "success" when empty. The CLI enqueues AFTER the mutation
	// lands; "failure" is reserved for cases where the mutation
	// landed but a downstream step (e.g. profile materialization)
	// noisily failed.
	Result string

	// Dialects is the per-dialect implication when the action
	// affects only some dialects. Empty/omitted = dialect-agnostic
	// (the common case for pause + cross-dialect rules).
	Dialects []string

	// Details is the action-specific payload (rule pattern + effect
	// + scope axes; preset id + target profile; pause ttl + reason;
	// ...). Open-ended so a future action can extend without
	// reshaping the helper.
	Details map[string]any
}

// enqueueAdminAction writes a pending_audit_events row carrying an
// ADMIN_ACTION payload. Best-effort: a failure is surfaced via the
// passed errOut writer but does NOT propagate — the caller's
// user-facing operation already succeeded.
//
// dbPath is forwarded to store.Open verbatim (empty string =
// default ~/.dbounce/state.db, honors DBOUNCE_DB env). The store is
// opened + closed per call rather than threaded through the CLI —
// each admin subcommand is a one-shot Cobra invocation, so the
// per-call open cost is amortized over the user's typing time + the
// connection lifetime never exceeds a single subcommand run.
func enqueueAdminAction(errOut io.Writer, dbPath string, params adminActionEnqueueParams) {
	if errOut == nil {
		errOut = io.Discard
	}
	if params.Action == "" {
		// Defensive: a missing action means the call site forgot to
		// populate the field — surface loudly so the bug doesn't
		// silently produce unattributable audit rows. We still don't
		// fail the user-facing op.
		fmt.Fprintln(errOut,
			"dbounce: note: admin-action audit-event enqueue skipped — "+
				"action id missing (caller bug; not user-facing)")
		return
	}
	if params.Actor == "" {
		params.Actor = "unknown"
	}
	if params.Result == "" {
		params.Result = "success"
	}
	payload := map[string]any{
		"action":        params.Action,
		"actor":         params.Actor,
		"resource_type": params.ResourceType,
		"resource_id":   params.ResourceID,
		"result":        params.Result,
	}
	if len(params.Dialects) > 0 {
		// Defensive copy so a downstream mutation of the caller's
		// slice doesn't reach the encoded payload.
		payload["dialects"] = append([]string(nil), params.Dialects...)
	}
	if len(params.Details) > 0 {
		// Shallow-copy the details so a downstream mutation of the
		// caller's map doesn't reach the encoded payload.
		details := make(map[string]any, len(params.Details))
		for k, v := range params.Details {
			details[k] = v
		}
		payload["details"] = details
	}
	b, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(errOut,
			"dbounce: note: marshal ADMIN_ACTION payload failed: %v "+
				"(operation succeeded; audit event NOT emitted)\n", err)
		return
	}
	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(errOut,
			"dbounce: note: open state.db for admin-action audit-event "+
				"enqueue failed: %v (operation succeeded; ADMIN_ACTION audit "+
				"event NOT emitted)\n", err)
		return
	}
	defer st.Close()
	if _, err := st.AddPendingAuditEvent(
		store.PendingAuditEventAdminAction, string(b)); err != nil {
		fmt.Fprintf(errOut,
			"dbounce: note: enqueue ADMIN_ACTION audit event failed: %v "+
				"(operation succeeded; the running `dbounce run` process will "+
				"not see this admin action on its next drain tick)\n", err)
	}
}

// inferDialectsFromRulePattern extracts dialect tokens from a rule
// pattern's table-glob half. dbounce rule patterns are dialect-
// agnostic at the language level (STMT_TYPE:table_glob applies
// across all parsers), BUT operators commonly include the dialect
// as the schema prefix in their table-glob ("snowflake.public.*",
// "mysql.app_db.*", "pg.*", ...) — when present, the prefix names
// the dialect the rule effectively scopes to.
//
// Returns the matched dialects deduped + sorted; empty when no
// dialect prefix is recognized (the common case for cross-dialect
// rules like "SELECT:public.*"). Empty means "stamp NO dialects
// field on the audit event" — see [[security-team-audit-export]]
// per-dialect note.
//
// Match is case-insensitive on the first token of the table-glob
// (everything up to the first '.'). The token aliases mirror the
// profile-name inference in profile.go so the dialect vocabulary
// stays consistent across the two helpers.
func inferDialectsFromRulePattern(pattern string) []string {
	if pattern == "" {
		return nil
	}
	// Pattern is "STMT_TYPE:table_glob" — split + take the glob half.
	parts := strings.SplitN(pattern, ":", 2)
	if len(parts) < 2 {
		return nil
	}
	glob := strings.TrimSpace(parts[1])
	if glob == "" || glob == "*" {
		return nil
	}
	// First dotted segment is the candidate dialect prefix.
	first := glob
	if dot := strings.Index(glob, "."); dot >= 0 {
		first = glob[:dot]
	}
	first = strings.ToLower(strings.TrimSpace(first))
	aliases := dialectAliasMap()
	if d, ok := aliases[first]; ok {
		return []string{d}
	}
	return nil
}

// inferDialectsFromPresetID maps a built-in preset id to the dialect
// set the preset effectively targets. Most presets are dialect-
// agnostic (analytics-engineer, dba-investigation, ...) — the
// helper returns empty for those. Future per-dialect presets
// (e.g. "snowflake-analyst", "bigquery-readonly") would land here
// with their dialect token recognized.
//
// Same token vocabulary as inferDialectsFromRulePattern +
// inferDialectsFromProfileNames so the cross-helper dialect set is
// uniform.
func inferDialectsFromPresetID(id string) []string {
	if id == "" {
		return nil
	}
	lower := strings.ToLower(id)
	tokens := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	aliases := dialectAliasMap()
	seen := map[string]struct{}{}
	for _, tok := range tokens {
		if d, ok := aliases[tok]; ok {
			seen[d] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// dialectAliasMap centralizes the dialect-token vocabulary shared by
// inferDialectsFromRulePattern + inferDialectsFromPresetID +
// inferDialectsFromProfileNames (in profile.go). One map keeps the
// short-form aliases (pg, sf, bq) consistent across surfaces.
func dialectAliasMap() map[string]string {
	return map[string]string{
		"postgres":   "postgres",
		"postgresql": "postgres",
		"pg":         "postgres",
		"mysql":      "mysql",
		"snowflake":  "snowflake",
		"sf":         "snowflake",
		"bigquery":   "bigquery",
		"bq":         "bigquery",
	}
}

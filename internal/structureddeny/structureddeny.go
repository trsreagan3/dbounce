// Package structureddeny is the Go port of the canonical Python
// iam_jit.structured_deny module (#459 / §A57b). It produces the
// structured-deny payload merged into dbounce's deny wire body so an
// agent receives the same shape it sees from ibounce — per
// [[cross-product-agent-parity]] every Bounce gets matching agent UX.
//
// Per [[ambient-value-prop-and-friction-framing]] every operator-facing
// string here LEADS with caught_by_bouncer framing — never "ERROR"
// / "DENIED" / "BLOCKED".
//
// Per [[ibounce-honest-positioning]] the Go bouncers ship a LOCAL
// heuristic classifier ONLY (no LLM round-trip). The classifier_hook
// field is set to "go-heuristic-only" so an operator can tell at a
// glance that this deny was not classified by the LLM (which Python
// ibounce can call). A v1.1 enhancement may add an opt-in Python-
// classifier RPC; for v1.0 the heuristic is the honest backstop.
//
// Per [[creates-never-mutates]] the structured-deny fields are
// ADDITIVE — the existing PG ErrorResponse / MySQL ErrPacket message
// text is preserved unchanged at the front; the structured-deny JSON
// rides as a suffix behind a `| iam-jit-structured-deny: ` marker so
// an agent can split-on-marker without changing legacy clients.
//
// Sync this module with kbouncer + gbounce's structureddeny packages
// — the wire-protocol field names + heuristic patterns MUST match
// across all three Go bouncers.
package structureddeny

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Recommended-action enum (mirrors Python RECOMMENDED_ACTION_*).
const (
	RecommendedActionEasyAllow     = "easy-allow"
	RecommendedActionHaltEscalate  = "halt+escalate"
	RecommendedActionRephraseRetry = "rephrase+retry"
)

// Injection-classification enum (mirrors Python INJECTION_*).
const (
	InjectionAppearsLegitimate  = "appears_legitimate"
	InjectionAmbiguous          = "ambiguous"
	InjectionAppearsAdversarial = "appears_adversarial"
)

// SchemaVersion is the wire-protocol schema version surfaced on every
// structured-deny payload. Bumped only on additive-incompatible changes;
// readers MUST tolerate unknown fields.
const SchemaVersion = "1.0"

// ClassifierHookGoHeuristic — see kbouncer's structureddeny doc for
// the [[ibounce-honest-positioning]] rationale.
const ClassifierHookGoHeuristic = "go-heuristic-only"

// WireMarker is the in-band marker an agent uses to split a dbounce
// error message into (legacy-text, structured-deny-JSON). PG +
// MySQL wire protocols carry the deny as a single text field — this
// is the simplest cross-protocol way to ride structured data through.
// Agents do:
//
//	idx := strings.Index(msg, structureddeny.WireMarker)
//	if idx >= 0 {
//	    json.Unmarshal([]byte(msg[idx+len(WireMarker):]), &sd)
//	}
const WireMarker = " | iam-jit-structured-deny: "

// KnownAdversarialPatterns mirrors the destructive-verb backstop in
// iam_jit.structured_deny.response.classify_injection_likelihood. Kept
// IN SYNC across all three Go bouncers so the parity guarantee holds.
//
// dbounce's action shape is "<STMT_TYPE>:<dialect>" (e.g.
// "DROP:postgres", "DELETE:mysql"). The substring matcher catches
// DROP/DELETE/TRUNCATE on the STMT_TYPE side automatically.
var KnownAdversarialPatterns = []string{
	"delete",
	"destroy",
	"terminate",
	"remove",
	"drop",
	"truncate",
	"grant",
	"stoploggingactivity",
	"putuserpolicy",
	"attachuserpolicy",
	"createaccesskey",
	"deactivatemfadevice",
	"passrole",
}

// StructuredDeny is the canonical structured-deny payload shape. JSON
// tags match the wire-protocol field names that Python ibounce emits
// (see iam_jit.bouncer.proxy.py:~3060).
type StructuredDeny struct {
	CaughtByBouncer                 string `json:"caught_by_bouncer"`
	IsLikelyInjectionClassification string `json:"is_likely_injection_classification"`
	SuggestedAllowCommand           string `json:"suggested_allow_command"`
	RecommendedAction               string `json:"recommended_action"`
	DenyEventID                     string `json:"deny_event_id"`
	ClassifierHook                  string `json:"classifier_hook"`
	DenySourceClassified            string `json:"deny_source_classified"`
	StructuredDenySchemaVersion     string `json:"structured_deny_schema_version"`
}

// AsMap returns the structured-deny payload as a map[string]any for
// callers that want to merge the fields into a JSON envelope.
func (s StructuredDeny) AsMap() map[string]any {
	return map[string]any{
		"caught_by_bouncer":                  s.CaughtByBouncer,
		"is_likely_injection_classification": s.IsLikelyInjectionClassification,
		"suggested_allow_command":            s.SuggestedAllowCommand,
		"recommended_action":                 s.RecommendedAction,
		"deny_event_id":                      s.DenyEventID,
		"classifier_hook":                    s.ClassifierHook,
		"deny_source_classified":             s.DenySourceClassified,
		"structured_deny_schema_version":     s.StructuredDenySchemaVersion,
	}
}

// JSON returns the canonical JSON encoding (no trailing newline) for
// embedding into an in-band wire message.
func (s StructuredDeny) JSON() string {
	b, err := json.Marshal(s)
	if err != nil {
		// Defensive: json.Marshal can't fail on a flat struct of
		// strings. Return an empty JSON object so callers can still
		// concat without producing malformed output.
		return "{}"
	}
	return string(b)
}

// AppendToMessage produces "<msg><WireMarker><json>" — the canonical
// in-band shape an agent can split on. When msg is empty the marker
// is still emitted (with the leading space trimmed) so an agent's
// strings.Index lookup still hits.
func (s StructuredDeny) AppendToMessage(msg string) string {
	marker := WireMarker
	if msg == "" {
		marker = strings.TrimLeft(WireMarker, " ")
	}
	return msg + marker + s.JSON()
}

// ClassifyHeuristic — see kbouncer's structureddeny package for the
// canonical doc. Returns (classification, hookName).
func ClassifyHeuristic(action string) (string, string) {
	act := strings.ToLower(strings.TrimSpace(action))
	if act != "" {
		for _, marker := range KnownAdversarialPatterns {
			if strings.Contains(act, marker) {
				return InjectionAppearsAdversarial, ClassifierHookGoHeuristic
			}
		}
	}
	return InjectionAmbiguous, ClassifierHookGoHeuristic
}

// DeriveRecommendedAction — see kbouncer's structureddeny doc.
func DeriveRecommendedAction(denySource, classification, suggestedAllowCommand string) string {
	if classification == InjectionAppearsAdversarial {
		return RecommendedActionHaltEscalate
	}
	switch denySource {
	case "dynamic_deny", "profile_only_account_ids", "profile_only_regions":
		return RecommendedActionRephraseRetry
	}
	if trimmed := strings.TrimLeft(suggestedAllowCommand, " \t"); strings.HasPrefix(trimmed, "#") {
		return RecommendedActionRephraseRetry
	}
	return RecommendedActionEasyAllow
}

// BuildOptions are the inputs to Build.
type BuildOptions struct {
	// Bouncer is the wire-level caught_by_bouncer string. Required.
	Bouncer string

	// Action is the bouncer-shaped denied action — for dbounce this is
	// "<STMT_TYPE>:<dialect>" (e.g. "DROP:postgres" or "DELETE:mysql").
	Action string

	// Resource is the bouncer-shaped resource identifier — for dbounce
	// this is the touched table (e.g. "public.users") or empty when
	// the statement didn't reach AST classification.
	Resource string

	// DenyReason is the human-friendly reason string (e.g. the
	// existing decision reason).
	DenyReason string

	// DenySource is the existing decision-source label (e.g.
	// "static_profile" / "dynamic_deny" / "task_scope").
	DenySource string

	// RuleIDIfDynamic is the dynamic-deny rule id when DenySource is
	// "dynamic_deny"; empty otherwise.
	RuleIDIfDynamic string

	// SuggestedAllowCommand is the one-line shell-friendly allow
	// command the bouncer recommends.
	SuggestedAllowCommand string

	// When is the ISO-8601 timestamp; defaults to time.Now().UTC().
	When string
}

// Build produces a fully-populated StructuredDeny from BuildOptions.
func Build(opts BuildOptions) StructuredDeny {
	bouncer := opts.Bouncer
	if bouncer == "" {
		bouncer = "unknown"
	}
	denySource := opts.DenySource
	if denySource == "" {
		denySource = "unknown"
	}
	classification, hook := ClassifyHeuristic(opts.Action)
	recommended := DeriveRecommendedAction(denySource, classification, opts.SuggestedAllowCommand)

	when := opts.When
	if when == "" {
		when = time.Now().UTC().Format(time.RFC3339)
	}

	eventID := synthDenyEventID(bouncer, when, opts.Action, opts.Resource, opts.RuleIDIfDynamic)

	return StructuredDeny{
		CaughtByBouncer:                 bouncer,
		IsLikelyInjectionClassification: classification,
		SuggestedAllowCommand:           opts.SuggestedAllowCommand,
		RecommendedAction:               recommended,
		DenyEventID:                     eventID,
		ClassifierHook:                  hook,
		DenySourceClassified:            denySource,
		StructuredDenySchemaVersion:     SchemaVersion,
	}
}

// synthDenyEventID mirrors iam_jit.structured_deny.response.
// _synth_deny_event_id — sha256 over a stable JSON payload of the
// load-bearing deny fields, truncated to 12 hex chars.
func synthDenyEventID(bouncer, when, action, resource, ruleID string) string {
	payload := map[string]string{
		"bouncer":  bouncer,
		"when":     when,
		"action":   action,
		"resource": resource,
		"rule":     ruleID,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		b = []byte(bouncer + ":" + when + ":" + action + ":" + resource + ":" + ruleID)
	}
	sum := sha256.Sum256(b)
	sha := hex.EncodeToString(sum[:])[:12]
	return "evt_" + bouncer + "_" + sha
}

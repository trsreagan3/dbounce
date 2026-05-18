// Package audit implements dbounce's security-team audit-export
// transport (#252 Slice 1). Sibling agents ship the equivalent in
// kbounce (Go) + ibounce (Python); the JSON schema below is the
// cross-product contract per the [[security-team-audit-export]] memo so
// a single downstream aggregator can consume all three products without
// per-product parsing branches.
//
// Slice 1 ships TWO transports built on this Event schema:
//
//	JSONL log file  — internal/audit/log.go        — FREE tier
//	HTTPS webhook   — internal/audit/webhook.go    — Enterprise (license-gated)
//
// Slice 2 (alerting rules) layers SECURITY_ALERT events on the SAME
// transports + the SAME schema; this package's Event will gain an
// EventType in that slice. v1.0 emits only the DECISION shape.
//
// Per [[ibounce-honest-positioning]]: this is OPERATOR VISIBILITY +
// post-hoc-review surface, not adversary defense. An attacker who can
// reach the SQL listener can also reach the audit ringbuffer; the audit
// + alerts catch what HAPPENED for the security team to review.
//
// Per [[scorer-is-ground-truth]]: this package CONSUMES decisions; it
// MUST NOT mutate, re-score, or LLM-enrich them. The schema is a
// faithful projection of store.DecisionRow.
//
// Per [[no-hosted-saas]]: iam-jit-the-company never receives webhook
// traffic. The operator's --audit-webhook-url is THEIR endpoint.

package audit

import (
	"strings"
	"time"

	"github.com/trsreagan3/dbounce/internal/store"
)

// EventType names the kind of event in the audit stream. Slice 1 emits
// only EventTypeDecision + EventTypeAuditDropped; Slice 2 will add
// EventTypeSecurityAlert.
type EventType string

const (
	// EventTypeDecision is one proxy decision (the existing audit-row
	// emitted by every evaluateAndAudit / handleGatedMessage call).
	EventTypeDecision EventType = "DECISION"

	// EventTypeAuditDropped is synthesized by the WebhookPusher when its
	// bounded queue fills up. Count names how many decisions were
	// dropped between this synthetic event + the previous one; consumers
	// flag a drop spike as an alert. Per the spec: webhook backpressure
	// MUST NOT silently lose events without a trace.
	EventTypeAuditDropped EventType = "AUDIT_DROPPED"
)

// Product names the originating Bounce product. The schema is shared
// across kbounce / ibounce / dbounce so downstream consumers can branch
// on product without per-product schema variants.
const Product = "dbounce"

// SchemaVersion is the audit-export schema version. Bumped only on
// breaking schema changes (renames / type changes); additive fields
// don't bump. Consumers should pin against MAJOR + tolerate additive
// MINOR.
const SchemaVersion = "1.0.0"

// Event is the cross-product JSONL schema. JSON tags MATCH the spec in
// the [[security-team-audit-export]] memo verbatim.
//
// Field ordering reflects the doc order; the omitempty markers preserve
// downstream parsers' ability to assume "if present, populated" without
// having to special-case zero values.
type Event struct {
	// EventType is "DECISION" (default for every proxy decision) or
	// "AUDIT_DROPPED" (synthesized by the WebhookPusher on overflow).
	EventType EventType `json:"event_type"`

	// Ts is the decision timestamp in RFC3339Nano UTC. Mirrored on the
	// JSONL writer + the webhook body so consumers can deduplicate by
	// (product, ts, decision_id) if a retry double-delivers.
	Ts string `json:"ts"`

	// Product names the originating Bounce product (always "dbounce"
	// here). Lets one downstream aggregator consume all three Bounce
	// products without per-product topic branches.
	Product string `json:"product"`

	// Version is the SchemaVersion constant.
	Version string `json:"version"`

	// DecisionID is the monotonic SQLite row id from store.RecordDecision.
	// Consumers use this to re-order events when retries reorder webhook
	// delivery (the queue worker dispatches in order; the operator's
	// receiver might not).
	DecisionID int64 `json:"decision_id"`

	// Mode is the cooperative/transparent mode the proxy was in.
	Mode string `json:"mode"`

	// Profile is the ActiveProfileName at decision time. Empty when
	// no profile was active (full-user equivalent).
	Profile string `json:"profile,omitempty"`

	// Verdict is "allow" | "deny" | "bypass" (last is Slice-2 reserved).
	Verdict string `json:"verdict"`

	// Reason is the rule engine's human-readable explanation.
	Reason string `json:"reason,omitempty"`

	// Principal identifies the inbound caller (kbounce + ibounce
	// populate this from request context; dbounce v1.0 leaves it empty
	// pending #196 PG principal capture). Field present in the schema
	// so the JSONL contract is product-uniform.
	Principal string `json:"principal,omitempty"`

	// Action is the operation the caller invoked. dbounce populates
	// this with the statement_type ("SELECT" / "INSERT" / "DELETE" /
	// ...) so the cross-product schema reads "principal X did action Y"
	// uniformly.
	Action string `json:"action,omitempty"`

	// Resource is the primary target the action touched. dbounce
	// populates this with the comma-joined TablesTouched list (or the
	// first one if you'd rather; we ship comma-join for human
	// readability in TUI viewers).
	Resource string `json:"resource,omitempty"`

	// RequestID is left empty in Slice 1; reserved for Slice 2 when
	// the proxy gains per-request UUIDs.
	RequestID string `json:"request_id,omitempty"`

	// Enforced is true when the verdict CHANGED upstream behavior
	// (transparent-mode DENY blocked the request). False on
	// cooperative advisories + pause-window demotes.
	Enforced bool `json:"enforced"`

	// Host names the proxy listener host:port the decision came in on.
	Host string `json:"host,omitempty"`

	// Upstream names the resolved upstream URL (host:port) the proxy
	// forwarded — or would have forwarded — the call to.
	Upstream string `json:"upstream,omitempty"`

	// Ext carries product-specific fields. dbounce populates the
	// dialect (postgres / mysql / snowflake / bigquery) + the parsed
	// statement context (is_dml / is_ddl / has_mutating_node / parse
	// errors) so the downstream schema can branch per dialect WITHOUT
	// adding non-shared top-level fields to the cross-product schema.
	Ext map[string]any `json:"ext,omitempty"`

	// DroppedCount is set ONLY on EventTypeAuditDropped events. Counts
	// how many decisions were dropped since the previous synthetic
	// AUDIT_DROPPED event. Omitted on DECISION events.
	DroppedCount int64 `json:"dropped_count,omitempty"`
}

// FromDecisionRow projects a store.DecisionRow into the cross-product
// Event schema. Centralized here (not per-call-site in proxy.go /
// forward.go / mysql.go) so the schema mapping is auditable in one
// place + sibling agents can mirror the projection exactly in
// kbounce/ibounce.
//
// Empty / zero values omit from the Event so the JSONL line is the
// smallest faithful representation per decision. Per
// [[scorer-is-ground-truth]] this function NEVER re-scores, mutates, or
// LLM-enriches the row — it is a pure projection.
//
// decisionID is the row id returned by store.RecordDecision; passed
// separately because store.DecisionRow itself does not carry it (the
// store assigns it on insert).
//
// host is the wire-listener address ("127.0.0.1:5433") — projected onto
// Event.Host so downstream consumers can group events by listener.
// upstream is the resolved upstream URL host:port, or empty when the
// proxy is observation-only.
func FromDecisionRow(row store.DecisionRow, decisionID int64, host, upstream string) Event {
	ts := row.At
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	return Event{
		EventType:  EventTypeDecision,
		Ts:         ts.UTC().Format(time.RFC3339Nano),
		Product:    Product,
		Version:    SchemaVersion,
		DecisionID: decisionID,
		Mode:       row.ModeAtDecision,
		Profile:    row.ProfileName,
		Verdict:    row.DecisionVerdict,
		Reason:     row.DecisionReason,
		// Action = statement_type so the cross-product schema reads
		// "principal did action SELECT" uniformly. dbounce v1.0 does
		// not yet capture per-call principal (#196); the field stays
		// present-but-empty so the JSONL row shape is product-uniform.
		Action:   row.StatementType,
		Resource: joinResources(row.TablesTouched),
		Enforced: row.Enforced,
		Host:     host,
		Upstream: upstream,
		Ext:      buildExt(row),
	}
}

// joinResources turns the parsed tables-touched slice into a single
// comma-joined string for the shared Resource field. We keep the FULL
// list in Ext.tables so a downstream aggregator that wants individual
// tables can still find them.
func joinResources(tables []string) string {
	if len(tables) == 0 {
		return ""
	}
	return strings.Join(tables, ",")
}

// buildExt populates the dialect-specific ext fields. Dialect names
// (postgres / mysql / snowflake / bigquery) round-trip from the parser;
// the parsed-statement context (is_dml / is_ddl / has_mutating_node /
// parse_errors / functions_called / impersonated_role / pause_id) lets
// security-team filters downstream ask "show me all MUTATING rows that
// touched function X under profile Y" without the consumer having to
// run their own SQL parse.
//
// Why a map instead of a typed struct per dialect: the spec doc names
// `ext` as "product-specific" — leaving it open-ended means a future
// schema-additive field doesn't force a Go API break in this package.
// Per [[deliberate-feature-completion]] the price is operator-facing
// surface area (downstream parsers must tolerate unknown keys); the
// gain is that the audit-export schema can extend without churning
// every product's exporter on each addition.
func buildExt(row store.DecisionRow) map[string]any {
	ext := make(map[string]any, 16)
	if row.Dialect != "" {
		ext["dialect"] = row.Dialect
	}
	if row.Statement != "" {
		// Always include — even when redacted, the consumer wants the
		// SQL text. The statement_redacted flag below tells them
		// whether to trust it for replay.
		ext["statement"] = row.Statement
	}
	if row.StatementRedacted {
		ext["statement_redacted"] = true
	}
	if len(row.FunctionsCalled) > 0 {
		// Copy to defend against downstream mutation of the slice
		// (json.Marshal does not deep-copy; if the consumer modifies
		// the JSONified slice the original audit-row's
		// FunctionsCalled would be touched).
		ext["functions"] = append([]string(nil), row.FunctionsCalled...)
	}
	if len(row.TablesTouched) > 0 {
		ext["tables"] = append([]string(nil), row.TablesTouched...)
	}
	if row.IsDML {
		ext["is_dml"] = true
	}
	if row.IsDDL {
		ext["is_ddl"] = true
	}
	if row.HasMutatingNode {
		ext["has_mutating_node"] = true
	}
	if row.MutatingNodeType != "" {
		ext["mutating_node_type"] = row.MutatingNodeType
	}
	if row.IsExplain {
		ext["is_explain"] = true
	}
	if row.IsExplainAnalyze {
		ext["is_explain_analyze"] = true
	}
	if row.ImpersonatedRole != "" {
		ext["impersonated_role"] = row.ImpersonatedRole
	}
	if len(row.ParseErrors) > 0 {
		ext["parse_errors"] = append([]string(nil), row.ParseErrors...)
	}
	if row.DecisionSource != "" {
		ext["decision_source"] = row.DecisionSource
	}
	if row.MatchedRuleID != nil {
		ext["matched_rule_id"] = *row.MatchedRuleID
	}
	if row.TaskID != "" {
		ext["task_id"] = row.TaskID
	}
	if row.PauseID != nil {
		ext["pause_id"] = *row.PauseID
	}
	if row.IsStream {
		ext["is_stream"] = true
	}
	if row.StreamKind != "" {
		ext["stream_kind"] = row.StreamKind
	}
	if row.Forwarded {
		ext["forwarded"] = true
	}
	if row.UpstreamStatus != "" {
		ext["upstream_status"] = row.UpstreamStatus
	}
	if row.UpstreamResponseSummary != "" {
		ext["upstream_response_summary"] = row.UpstreamResponseSummary
	}
	if len(ext) == 0 {
		return nil
	}
	return ext
}

// NewAuditDroppedEvent constructs the synthetic event the WebhookPusher
// emits when its bounded queue fills + it has to drop. The count is
// how many DECISION events were dropped since the previous synthetic
// AUDIT_DROPPED event (NOT the cumulative total — consumers want the
// rate).
//
// Schema note: this event uses the SAME envelope as a DECISION (Ts,
// Product, Version) so downstream parsers can branch on EventType
// without a separate parser path. DecisionID is zero on these synthetic
// events.
func NewAuditDroppedEvent(droppedSinceLast int64, host string) Event {
	return Event{
		EventType:    EventTypeAuditDropped,
		Ts:           time.Now().UTC().Format(time.RFC3339Nano),
		Product:      Product,
		Version:      SchemaVersion,
		Host:         host,
		DroppedCount: droppedSinceLast,
		Reason:       "webhook queue overflowed; events were dropped without delivery — increase --audit-webhook-batch-size or downstream consumer throughput",
	}
}

// Package audit implements dbounce's security-team audit-export
// transport (#252 Slice 1). Sibling agents ship the equivalent in
// kbounce (Go) + ibounce (Python); the JSON schema below is the
// cross-product contract per the [[ocsf-audit-schema]] memo so a single
// downstream aggregator (AWS Security Lake, Splunk, Cloudflare, IBM,
// any OCSF-aware SIEM) can ingest all three products with zero
// per-product mapping.
//
// Schema: OCSF v1.1.0 class 6003 (API Activity).
// Reference: https://schema.ocsf.io/1.1.0/classes/api_activity
//
// Slice 1 ships TWO transports built on this Event schema:
//
//	JSONL log file  — internal/audit/log.go        — FREE tier
//	HTTPS webhook   — internal/audit/webhook.go    — Enterprise (license-gated)
//
// Slice 2 (alerting rules) layers SECURITY_ALERT events on the SAME
// transports + the SAME OCSF schema; per the memo, Slice 2 events use
// activity_id=99 with a descriptive activity_name and elevated
// severity_id. v1.0 emits only the DECISION shape (+ the AUDIT_DROPPED
// synthetic on webhook overflow).
//
// Per [[ibounce-honest-positioning]]: this is OPERATOR VISIBILITY +
// post-hoc-review surface, not adversary defense. An attacker who can
// reach the SQL listener can also reach the audit ringbuffer; the audit
// + alerts catch what HAPPENED for the security team to review.
//
// Per [[scorer-is-ground-truth]]: this package CONSUMES decisions; it
// MUST NOT mutate, re-score, or LLM-enrich them. The OCSF projection is
// a faithful, deterministic mapping of store.DecisionRow.
//
// Per [[no-hosted-saas]]: iam-jit-the-company never receives webhook
// traffic. The operator's --audit-webhook-url is THEIR endpoint.
//
// Per [[security-team-positioning-safety-not-surveillance]]: severity
// defaults to Informational + status uses OCSF's neutral
// Success/Failure framing — aligned with the safety-not-surveillance
// language of the security-team docs.

package audit

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/trsreagan3/dbounce/internal/store"
)

// EventType names the kind of event in the audit stream. Slice 1 emits
// only EventTypeDecision + EventTypeAuditDropped; Slice 2 will add
// EventTypeSecurityAlert via activity_id=99 + a descriptive
// activity_name (see memo).
//
// EventType is NOT part of the OCSF schema — it lives ONLY under
// unmapped.iam_jit.event_type so consumers that want our native
// "what kind of synthetic is this?" branch can read it without parsing
// activity_name. OCSF consumers branch on class_uid + activity_id.
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

	// EventTypeSecurityAlert is synthesized by the #252 Slice 2 rule
	// engine when an observed event matches a configured alert rule
	// (non-org profile install, unusual high-risk SQL action, etc.).
	// Carries severity_id >= 3 (Medium) so SIEM dashboards surface it
	// above the Informational decision stream. activity_id=99 (Other);
	// activity_name carries the rule's stable id so downstream
	// consumers can branch per-rule without parsing free-form text.
	//
	// Per [[security-team-positioning-safety-not-surveillance]] the
	// alert language is NEUTRAL: it NAMES what triggered (the pattern,
	// the dialect, the table) and SUGGESTS the operator distribute a
	// narrower profile; it never says "violation" / "unauthorized" /
	// "attack." The security team interprets the alert in context.
	EventTypeSecurityAlert EventType = "SECURITY_ALERT"

	// EventTypeSessionEnded synthesizes when an MCP stdio connection
	// closes OR a SQL TCP connection closes. Per
	// [[agent-identity-in-audit]] Feature 2: "When the MCP connection
	// closes (agent exits), the session ID retires + a SESSION_ENDED
	// event emits." Lets a SIEM consumer answer "when did agent session
	// X end?" without inferring from the absence of subsequent rows.
	// activity_id=99 (Other); activity_name="session_ended"; severity
	// Informational (this is bookkeeping, not an alert).
	EventTypeSessionEnded EventType = "SESSION_ENDED"

	// EventTypeHeartbeat is the periodic liveness signal emitted by the
	// Heartbeater goroutine when --heartbeat-interval is configured. Per
	// [[prompt-injection-disable-bouncer-threat]]: an attacker who
	// induces an operator (or an AI agent) to disable / pause / kill
	// the bouncer eliminates dbounce's audit + gating surface; the
	// HEARTBEAT cadence lets a SIEM consumer alert on the ABSENCE of
	// recent heartbeats. Sibling agents in ibounce + kbounce ship the
	// same event under the same schema so one cross-product absence
	// rule catches all three. activity_id=99 (Other); activity_name=
	// "heartbeat"; severity Informational (this is bookkeeping, not an
	// alert — the GAP alert below is the elevated signal).
	EventTypeHeartbeat EventType = "HEARTBEAT"
)

// Product names the originating Bounce product. Stamped into
// metadata.product.name per the shared OCSF schema so downstream
// consumers can branch on product without per-product topic branches.
const Product = "dbounce"

// VendorName is the OCSF metadata.product.vendor_name shared across
// all three Bounce products. A single SIEM rule keyed on vendor_name
// catches events from any iam-jit product without per-product wiring.
const VendorName = "iam-jit"

// SchemaVersion is the OCSF schema version we emit. v1.1.0 is the
// version backed by AWS Security Lake + Splunk + the major SIEMs.
// Surfaced via metadata.version on every event.
const SchemaVersion = "1.1.0"

// OCSF class constants for class 6003 (API Activity). See the schema
// reference URL in the package docstring.
const (
	ocsfClassUID    = 6003
	ocsfClassName   = "API Activity"
	ocsfCategoryUID = 6
	ocsfCategoryNm  = "Application Activity"

	// Type UID base. type_uid = (class_uid * 100) + activity_id per the
	// OCSF spec. For class 6003 the base is 600300.
	ocsfTypeUIDBase = 600300

	// Severity. Default to Informational (1) for every decision per
	// [[security-team-positioning-safety-not-surveillance]]; higher
	// severities are reserved for Slice 2 alert events.
	ocsfSeverityInformationalID = 1
	ocsfSeverityInformational   = "Informational"
	ocsfSeverityMediumID        = 3
	ocsfSeverityMedium          = "Medium"
)

// OCSF activity_id values for class 6003 (see memo). Used in
// activity_id, type_uid computation, and the per-dialect SQL mapping
// below.
const (
	ActivityIDUnknown = 0
	ActivityIDCreate  = 1
	ActivityIDRead    = 2
	ActivityIDUpdate  = 3
	ActivityIDDelete  = 4
	ActivityIDOther   = 99
)

// OCSF status_id values for class 6003 (see memo).
const (
	StatusIDUnknown = 0
	StatusIDSuccess = 1
	StatusIDFailure = 2
	StatusIDOther   = 99
)

// BuildVersion is the dbounce binary version stamped into
// metadata.product.version. Overridden at build time via
// -ldflags "-X github.com/trsreagan3/dbounce/internal/audit.BuildVersion=...".
// Unstamped builds report "dev".
//
// Why a separate variable from internal/cli.version: the audit package
// can't import the cli package (cli imports audit transitively); the
// build pipeline stamps both. Tests pin the default so a missing
// -ldflags doesn't silently surface as "undefined" in customer events.
var BuildVersion = "dev"

// Event is the cross-product OCSF v1.1.0 class 6003 envelope. Every
// field has the exact JSON tag the OCSF schema names so a SIEM with
// OCSF-native parsing accepts the JSONL line directly.
//
// Field ordering follows the OCSF schema spec doc order: metadata,
// classification, severity/status, actors, api, resources, endpoints,
// then unmapped vendor extension. The `omitempty` markers preserve
// downstream parsers' ability to assume "if present, populated" without
// having to special-case zero values.
type Event struct {
	// Metadata identifies the producing product + the schema version.
	// Required by OCSF on every event.
	Metadata Metadata `json:"metadata"`

	// Time is the event timestamp in Unix milliseconds (OCSF requirement
	// — NOT RFC3339; the spec says int64 epoch-ms).
	Time int64 `json:"time"`

	// ClassUID identifies the OCSF event class. Always 6003 (API
	// Activity) for dbounce decisions + AUDIT_DROPPED synthetics.
	ClassUID int `json:"class_uid"`

	// ClassName is the OCSF class display name. Always "API Activity".
	ClassName string `json:"class_name"`

	// CategoryUID identifies the OCSF event category. Always 6
	// (Application Activity) for class 6003.
	CategoryUID int `json:"category_uid"`

	// CategoryName is the OCSF category display name.
	CategoryName string `json:"category_name"`

	// ActivityID is the OCSF action verb (1=Create / 2=Read / 3=Update /
	// 4=Delete / 99=Other). For dbounce, derived from statement_type via
	// activityIDFromStatementType.
	ActivityID int `json:"activity_id"`

	// ActivityName names the action in human-readable form. For dbounce
	// this is the lower-cased statement_type ("select", "insert",
	// "load_data", ...) so per-dialect specificity survives.
	ActivityName string `json:"activity_name"`

	// TypeUID = (class_uid * 100) + activity_id per OCSF spec; for class
	// 6003 the base is 600300. SIEM dashboards use type_uid as the
	// canonical fan-out key.
	TypeUID int `json:"type_uid"`

	// TypeName is the OCSF type display name in "Class: Verb" form.
	TypeName string `json:"type_name"`

	// SeverityID is the OCSF severity. Defaults to 1 (Informational) for
	// every decision per [[security-team-positioning-safety-not-
	// surveillance]]. Slice 2 alert events use 2-5.
	SeverityID int `json:"severity_id"`

	// Severity is the human-readable severity name.
	Severity string `json:"severity"`

	// StatusID is the OCSF outcome of the API call. ALLOW + advisory-
	// DENY + BYPASS map to 1 (Success); enforced DENY (transparent mode)
	// maps to 2 (Failure). See verdictToStatus per the memo.
	StatusID int `json:"status_id"`

	// Status is the human-readable status name.
	Status string `json:"status"`

	// StatusDetail carries the rule engine's deny / bypass reason so
	// the operator can triage from the audit-export without a JOIN back
	// to the SQLite audit row.
	StatusDetail string `json:"status_detail,omitempty"`

	// Actor describes who made the request (DB user / session). For
	// dbounce v1.0 the DB user is not yet captured per-call (#196); the
	// field is omitted from the wire when neither user nor session is
	// available (pointer-to-struct so Go's omitempty actually drops the
	// zero case rather than emitting `"actor":{}`).
	Actor *Actor `json:"actor,omitempty"`

	// API describes the API call (operation + service + request_uid).
	// For dbounce, operation=statement_type, service.name=dialect.
	API API `json:"api"`

	// Resources lists the resource(s) the API call targeted. For
	// dbounce, one entry per table touched.
	Resources []Resource `json:"resources,omitempty"`

	// SrcEndpoint is the proxy listener address the inbound SQL hit.
	SrcEndpoint *Endpoint `json:"src_endpoint,omitempty"`

	// DstEndpoint is the resolved upstream DB host:port (only set when
	// a forwarder is configured + the upstream URL is reachable).
	DstEndpoint *Endpoint `json:"dst_endpoint,omitempty"`

	// Unmapped is the OCSF vendor-extension hook. Per the memo we use
	// it for fields without OCSF mappings (mode, profile, verdict,
	// decision_id, enforced, per-product ext map). Consumers that want
	// the bouncer's native semantics read this; pure-OCSF consumers
	// ignore it.
	Unmapped *Unmapped `json:"unmapped,omitempty"`
}

// Metadata is the OCSF metadata field. Required on every event.
type Metadata struct {
	Version string   `json:"version"`
	Product Product_ `json:"product"`
}

// Product_ is the OCSF metadata.product sub-object. Trailing underscore
// avoids the package-level Product const collision.
type Product_ struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}

// Actor is the OCSF actor object. Sub-fields user + session per the
// schema; we populate only what's available.
type Actor struct {
	User    *User    `json:"user,omitempty"`
	Session *Session `json:"session,omitempty"`
}

// User is the OCSF actor.user sub-object.
type User struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

// Session is the OCSF actor.session sub-object. Holds the task_id when
// the decision happened inside a D-Slice 3 task scope.
type Session struct {
	UID string `json:"uid,omitempty"`
}

// API is the OCSF api object. operation = the action verb, service =
// the upstream service name (dialect for dbounce), request.uid =
// decision_id (as a string per OCSF — request UIDs are strings).
type API struct {
	Operation string   `json:"operation,omitempty"`
	Service   Service  `json:"service,omitempty"`
	Request   *Request `json:"request,omitempty"`
}

// Service is the OCSF api.service sub-object.
type Service struct {
	Name string `json:"name,omitempty"`
}

// Request is the OCSF api.request sub-object.
type Request struct {
	UID string `json:"uid,omitempty"`
}

// Resource is one entry in the OCSF resources array. For dbounce, one
// per table the statement touched ({name: "schema.table", uid:
// "schema.table", type: "sql table"}).
type Resource struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
	Type string `json:"type,omitempty"`
}

// Endpoint is an OCSF endpoint object (used for src_endpoint +
// dst_endpoint). We populate hostname + port; ip is left empty when
// we don't have a resolved address (the upstream URL is a hostname,
// not a resolved IP — leaving ip unset is preferable to fabricating
// one).
type Endpoint struct {
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
}

// Unmapped is the OCSF vendor-extension hook. iam_jit holds all
// iam-jit-specific fields that don't have an OCSF home.
type Unmapped struct {
	IAMJIT IAMJITExt `json:"iam_jit"`
}

// IAMJITExt is the iam-jit vendor-extension payload. Per the memo:
// mode, profile, verdict, decision_id, enforced + a per-product ext
// map (dialect / tables_touched / is_dml / is_ddl / has_mutating_node /
// mutating_node_type for dbounce).
//
// EventType + DroppedCount + QueueSize are populated only on the
// AUDIT_DROPPED synthetic.
//
// Agent (Feature 1 + 2 of [[agent-identity-in-audit]]) is the agent-
// fingerprint + persistent session id block. Pointer-to-struct so an
// event WITHOUT agent context (observation-only smoke test before any
// real client connected) omits the field entirely from the JSONL wire
// rather than emitting `"agent":{}`. Populated by the proxy +
// MCP-server call paths via AgentRegistry.Lookup at projection time.
// Sibling agents in ibounce + kbounce ship under the SAME JSON path
// (unmapped.iam_jit.agent) so a single SIEM filter spans all three.
type IAMJITExt struct {
	Mode       string         `json:"mode,omitempty"`
	Profile    string         `json:"profile,omitempty"`
	Verdict    string         `json:"verdict,omitempty"`
	DecisionID int64          `json:"decision_id,omitempty"`
	Enforced   bool           `json:"enforced"`
	Ext        map[string]any `json:"ext,omitempty"`
	Agent      *Agent         `json:"agent,omitempty"`

	// Synthetic-event-only fields (populated for AUDIT_DROPPED, omitted
	// for DECISION events).
	EventType    string `json:"event_type,omitempty"`
	DroppedCount int64  `json:"dropped_count,omitempty"`
	QueueSize    int    `json:"queue_size,omitempty"`
}

// FromDecisionRow projects a store.DecisionRow into the OCSF v1.1.0
// class 6003 Event schema. Centralized here (not per-call-site in
// proxy.go / forward.go / mysql.go) so the schema mapping is auditable
// in one place + sibling agents can mirror the projection exactly in
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
// host is the proxy wire-listener address ("127.0.0.1:5433") —
// projected onto src_endpoint so downstream consumers can group events
// by listener.
//
// upstream is the resolved upstream URL host:port, or empty when the
// proxy is observation-only — projected onto dst_endpoint when set.
//
// For the agent-fingerprint variant (Feature 1 + 2 of
// [[agent-identity-in-audit]]) callers go through FromDecisionRowWithAgent
// below — this wrapper preserves backward-compatibility for the existing
// kbounce/ibounce-symmetric callsites that don't yet thread agent
// context.
func FromDecisionRow(row store.DecisionRow, decisionID int64, host, upstream string) Event {
	return FromDecisionRowWithAgent(row, decisionID, host, upstream, Agent{})
}

// FromDecisionRowWithAgent is the agent-aware projection. When agent
// is non-empty, unmapped.iam_jit.agent is populated per the
// [[agent-identity-in-audit]] schema:
//
//	"unmapped": {
//	  "iam_jit": {
//	    "agent": {
//	      "name": "claude-code" | "cursor" | "psql" | "unknown",
//	      "version": "1.2.3" | null,
//	      "session_id": "<UUID v7>",
//	      "detected_from": "mcp_clientinfo" | "pg_application_name" |
//	                        "mysql_client_attrs" | "decide_flag" |
//	                        "unknown"
//	    }, ...
//	  }
//	}
//
// An empty Agent omits the agent block (the json:"agent,omitempty" tag
// drops the field) — operators in observation-only mode without any
// connected agent see the historical event shape unchanged.
func FromDecisionRowWithAgent(row store.DecisionRow, decisionID int64, host, upstream string, agent Agent) Event {
	at := row.At
	if at.IsZero() {
		at = time.Now().UTC()
	}

	stmtType := strings.ToUpper(strings.TrimSpace(row.StatementType))
	activityID := activityIDFromStatementType(stmtType)
	activityName := strings.ToLower(stmtType)
	if activityName == "" {
		activityName = "unknown"
	}

	verdictUpper := strings.ToUpper(strings.TrimSpace(row.DecisionVerdict))
	statusID, statusName := verdictToStatus(verdictUpper, row.Enforced)

	evt := Event{
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: Product_{
				Name:       Product,
				VendorName: VendorName,
				Version:    BuildVersion,
			},
		},
		Time:         at.UTC().UnixMilli(),
		ClassUID:     ocsfClassUID,
		ClassName:    ocsfClassName,
		CategoryUID:  ocsfCategoryUID,
		CategoryName: ocsfCategoryNm,
		ActivityID:   activityID,
		ActivityName: activityName,
		TypeUID:      ocsfTypeUIDBase + activityID,
		TypeName:     typeNameFor(activityID),
		SeverityID:   ocsfSeverityInformationalID,
		Severity:     ocsfSeverityInformational,
		StatusID:     statusID,
		Status:       statusName,
		StatusDetail: row.DecisionReason,
		Actor:        buildActor(row),
		API: API{
			Operation: stmtType,
			Service:   Service{Name: row.Dialect},
			Request:   &Request{UID: strconv.FormatInt(decisionID, 10)},
		},
		Resources:   buildResources(row.TablesTouched),
		SrcEndpoint: parseEndpoint(host),
		DstEndpoint: parseEndpoint(upstream),
		Unmapped: &Unmapped{
			IAMJIT: IAMJITExt{
				Mode:       row.ModeAtDecision,
				Profile:    row.ProfileName,
				Verdict:    verdictUpper,
				DecisionID: decisionID,
				Enforced:   row.Enforced,
				Ext:        buildExt(row),
				Agent:      agentPtrOrNil(agent),
			},
		},
	}
	return evt
}

// agentPtrOrNil returns &a when a has any populated field, otherwise
// nil. The Unmapped.IAMJIT.Agent field uses json:"agent,omitempty" on
// a pointer type so the JSON marshaller drops the entire block when
// no agent context is available — observation-only smoke events stay
// the same shape they had before [[agent-identity-in-audit]] landed.
//
// Normalize ensures empty Name → "unknown" + empty DetectedFrom →
// DetectedFromUnknown so SIEM dashboards always see SOME value when an
// agent block is present.
func agentPtrOrNil(a Agent) *Agent {
	if a.IsEmpty() {
		return nil
	}
	norm := a.Normalize()
	return &norm
}

// activityIDFromStatementType maps a SQL statement type to the OCSF
// class-6003 activity_id per the memo:
//
//	SELECT                                                → 2 (Read)
//	INSERT                                                → 1 (Create)
//	UPDATE / ALTER / MERGE                                → 3 (Update)
//	DELETE / DROP / TRUNCATE                              → 4 (Delete)
//	CALL / DO / EXECUTE / WITH-WRITE / LOAD_DATA /
//	  EXPORT_DATA / COPY_INTO                             → 99 (Other)
//	(unrecognized)                                        → 99 (Other)
//
// Empty statement_type maps to 0 (Unknown) so a missing parse doesn't
// silently look like a known shape.
func activityIDFromStatementType(stmtType string) int {
	if stmtType == "" {
		return ActivityIDUnknown
	}
	switch stmtType {
	case "SELECT":
		return ActivityIDRead
	case "INSERT":
		return ActivityIDCreate
	case "UPDATE", "ALTER", "MERGE":
		return ActivityIDUpdate
	case "DELETE", "DROP", "TRUNCATE":
		return ActivityIDDelete
	case "CALL", "DO", "EXECUTE", "WITH-WRITE",
		"LOAD_DATA", "EXPORT_DATA", "COPY_INTO":
		return ActivityIDOther
	default:
		return ActivityIDOther
	}
}

// typeNameFor returns the OCSF type_name string for a class-6003
// activity_id. Used by FromDecisionRow + NewAuditDroppedEvent.
func typeNameFor(activityID int) string {
	switch activityID {
	case ActivityIDCreate:
		return "API Activity: Create"
	case ActivityIDRead:
		return "API Activity: Read"
	case ActivityIDUpdate:
		return "API Activity: Update"
	case ActivityIDDelete:
		return "API Activity: Delete"
	case ActivityIDOther:
		return "API Activity: Other"
	case ActivityIDUnknown:
		return "API Activity: Unknown"
	default:
		return "API Activity: Other"
	}
}

// verdictToStatus maps the bouncer's native verdict + enforced flag to
// OCSF status_id + status name per the memo:
//
//	ALLOW                                          → 1 Success
//	DENY  + enforced=true   (transparent blocked)  → 2 Failure
//	DENY  + enforced=false  (cooperative advisory) → 1 Success
//	BYPASS (pause-window-active)                   → 1 Success
//	(unknown / empty verdict)                      → 0 Unknown
//
// The bouncer's native semantics are preserved under unmapped.iam_jit
// for downstream tools that want them; the OCSF status reflects whether
// the upstream call SUCCEEDED, which is the only honest framing for
// SIEM consumers that don't know what a "bouncer DENY" means.
func verdictToStatus(verdict string, enforced bool) (int, string) {
	switch verdict {
	case "ALLOW":
		return StatusIDSuccess, "Success"
	case "DENY":
		if enforced {
			return StatusIDFailure, "Failure"
		}
		return StatusIDSuccess, "Success"
	case "BYPASS":
		return StatusIDSuccess, "Success"
	case "":
		return StatusIDUnknown, "Unknown"
	default:
		return StatusIDUnknown, "Unknown"
	}
}

// buildActor populates the OCSF actor object from a DecisionRow. For
// dbounce v1.0 the DB-user-per-call capture is not yet wired (#196);
// we ONLY emit actor.user when ImpersonatedRole is set (a `SET ROLE
// alice` was the most-recent identity change in this session) and
// actor.session.uid when a TaskID is present.
//
// Returns nil when neither field is available so the json:"actor,
// omitempty" tag on Event drops it from the wire (rather than emitting
// `"actor":{}`, which clutters the JSONL line + can confuse OCSF
// schema validators that expect required actor.user.* when actor is
// present).
func buildActor(row store.DecisionRow) *Actor {
	if row.ImpersonatedRole == "" && row.TaskID == "" {
		return nil
	}
	actor := &Actor{}
	if row.ImpersonatedRole != "" {
		actor.User = &User{
			Name: row.ImpersonatedRole,
			UID:  row.ImpersonatedRole,
		}
	}
	if row.TaskID != "" {
		actor.Session = &Session{UID: row.TaskID}
	}
	return actor
}

// buildResources converts the parser's tables-touched slice into the
// OCSF resources array. One entry per touched table; name + uid both
// hold "schema.table" so downstream tools can correlate either field.
// type is "sql table" per the memo.
//
// Empty input → nil so the json:"resources,omitempty" tag drops the
// field from the wire on resourceless events.
func buildResources(tables []string) []Resource {
	if len(tables) == 0 {
		return nil
	}
	out := make([]Resource, 0, len(tables))
	for _, t := range tables {
		if t == "" {
			continue
		}
		out = append(out, Resource{
			Name: t,
			UID:  t,
			Type: "sql table",
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseEndpoint splits a "host:port" string into an OCSF Endpoint with
// hostname + port. Returns nil on empty input or on parse failure (the
// json:"src_endpoint,omitempty" tag drops it).
//
// We deliberately don't resolve hostnames to IPs here — fabricating
// an IP when none was actually used would mislead SIEM consumers; the
// memo says "ip if resolved" not "ip always."
func parseEndpoint(hostPort string) *Endpoint {
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return nil
	}
	idx := strings.LastIndex(hostPort, ":")
	if idx < 0 {
		// No port — treat the whole string as a hostname.
		return &Endpoint{Hostname: hostPort}
	}
	host := hostPort[:idx]
	portStr := hostPort[idx+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		// Malformed port — keep what looks like a host so the
		// audit-export still names the listener; drop the port.
		return &Endpoint{Hostname: hostPort}
	}
	return &Endpoint{Hostname: host, Port: port}
}

// buildExt populates the dbounce-specific ext fields under
// unmapped.iam_jit.ext. Per the memo:
//
//	dialect, tables_touched, is_dml, is_ddl, has_mutating_node,
//	mutating_node_type
//
// We additionally carry the operational fields downstream reviewers
// have asked for since pre-launch: the parsed-statement context
// (statement / statement_redacted / functions / parse_errors), the
// decision-source layer (decision_source / matched_rule_id / pause_id),
// the forwarder outcome (forwarded / upstream_status /
// upstream_response_summary), + streaming flags. The map is open-ended
// per the memo's "small product-specific fields" guidance.
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
	if len(row.TablesTouched) > 0 {
		// Always present in ext.tables_touched per the memo spec.
		// Copy to defend against downstream mutation of the slice.
		ext["tables_touched"] = append([]string(nil), row.TablesTouched...)
	}
	// is_dml / is_ddl / has_mutating_node / mutating_node_type are
	// named in the memo as REQUIRED dbounce ext fields. Emit even when
	// false so per-dialect SIEM filters can pin on them.
	ext["is_dml"] = row.IsDML
	ext["is_ddl"] = row.IsDDL
	ext["has_mutating_node"] = row.HasMutatingNode
	if row.MutatingNodeType != "" {
		ext["mutating_node_type"] = row.MutatingNodeType
	}

	// Operationally-useful carry-over (NOT in the memo's required list
	// but reviewers asked for these pre-launch; keep them since the
	// memo's "small product-specific fields" guidance allows it).
	if row.Statement != "" {
		ext["statement"] = row.Statement
	}
	if row.StatementRedacted {
		ext["statement_redacted"] = true
	}
	if len(row.FunctionsCalled) > 0 {
		ext["functions"] = append([]string(nil), row.FunctionsCalled...)
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
	return ext
}

// AlertRuleID names a stable rule identifier stamped into both the
// SECURITY_ALERT event's activity_name + unmapped.iam_jit.ext.rule_id.
// Sibling agents in ibounce + kbounce ship the SAME rule ids so a
// single cross-product SIEM correlation key (rule_id) works without
// per-product translation.
type AlertRuleID string

const (
	// AlertRuleNonOrgProfileInstall fires when a profile is installed
	// from a source other than the operator-configured org-source
	// allowlist. Catches the "engineer-installed-a-random-profile-from-
	// the-internet" failure shape that bypasses IT's curated set.
	AlertRuleNonOrgProfileInstall AlertRuleID = "non_org_profile_install"

	// AlertRuleUnusualHighRiskAction fires when an observed decision
	// matches a per-dialect high-risk SQL pattern (DROP TABLE / TRUNCATE
	// / unscoped DELETE / EXPORT_DATA / COPY INTO stage / GRANT /
	// UNDROP / un-allowlisted CALL / DML against a sensitive schema).
	// The per-dialect verb table lives in alerts.go::highRiskByDialect.
	AlertRuleUnusualHighRiskAction AlertRuleID = "unusual_high_risk_action"

	// AlertRuleHeartbeatGap fires when the in-process Heartbeater's
	// watchdog detects the tick loop fell behind by more than
	// (Interval + GapThreshold). Per
	// [[prompt-injection-disable-bouncer-threat]]: catches the case
	// where the bouncer process was suspended / CPU-throttled /
	// debugger-attached / paused but didn't fully die — the heartbeats
	// went silent for long enough that a SIEM would otherwise have to
	// wait for its own absence-detection window. The gap alert lands
	// on the export channel BEFORE the silence is wide enough to look
	// like a full disable. Sibling agents in ibounce + kbounce ship
	// the same rule_id so a cross-product SIEM correlation works.
	AlertRuleHeartbeatGap AlertRuleID = "heartbeat_gap"
)

// AlertSeverity names the SECURITY_ALERT severity level. Maps to OCSF
// severity_id (3=Medium, 4=High). v1.0 emits only Medium for both
// rules; future rules MAY emit High when the pattern is unambiguous
// (e.g. a `GRANT ALL ON *.* TO 'public'`).
type AlertSeverity int

const (
	AlertSeverityMedium AlertSeverity = ocsfSeverityMediumID // 3
	AlertSeverityHigh   AlertSeverity = 4
)

// ocsfSeverityHighID + ocsfSeverityHigh are the OCSF v1.1.0 values
// for severity_id=4. Named here (not next to the Medium constants) so
// the alert-only severity isn't accidentally surfaced as a
// per-decision default.
const (
	ocsfSeverityHighID = 4
	ocsfSeverityHigh   = "High"
)

func severityName(s AlertSeverity) (int, string) {
	switch s {
	case AlertSeverityHigh:
		return ocsfSeverityHighID, ocsfSeverityHigh
	default:
		return ocsfSeverityMediumID, ocsfSeverityMedium
	}
}

// NewSecurityAlertEvent constructs the OCSF v1.1.0 class-6003
// SECURITY_ALERT envelope shared by every alert rule. The rule-engine
// per-rule constructors below populate ext with the rule-specific
// payload; this helper centralizes the OCSF envelope so a future rule
// can be added by writing one factory + one matcher, not by re-stating
// the OCSF shape.
//
// Schema: class_uid=6003, activity_id=99 (Other),
// activity_name=string(rule), type_uid=600399, severity_id per the
// caller, status_id=99 (Other) because neither Success nor Failure
// honestly describes "we observed a pattern."
//
// Per [[scorer-is-ground-truth]] the alert NEVER re-scores the
// underlying decision — it pattern-matches against the already-emitted
// OCSF event + records the match. The DecisionRow's verdict is the
// single source of truth.
func NewSecurityAlertEvent(rule AlertRuleID, severity AlertSeverity, host, detail string, ext map[string]any) Event {
	sevID, sevName := severityName(severity)
	if ext == nil {
		ext = map[string]any{}
	}
	ext["rule_id"] = string(rule)
	return Event{
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: Product_{
				Name:       Product,
				VendorName: VendorName,
				Version:    BuildVersion,
			},
		},
		Time:         time.Now().UTC().UnixMilli(),
		ClassUID:     ocsfClassUID,
		ClassName:    ocsfClassName,
		CategoryUID:  ocsfCategoryUID,
		CategoryName: ocsfCategoryNm,
		ActivityID:   ActivityIDOther,
		ActivityName: string(rule),
		TypeUID:      ocsfTypeUIDBase + ActivityIDOther,
		TypeName:     typeNameFor(ActivityIDOther),
		SeverityID:   sevID,
		Severity:     sevName,
		StatusID:     StatusIDOther,
		Status:       "Other",
		StatusDetail: detail,
		SrcEndpoint:  parseEndpoint(host),
		Unmapped: &Unmapped{
			IAMJIT: IAMJITExt{
				EventType: string(EventTypeSecurityAlert),
				Enforced:  false,
				Ext:       ext,
			},
		},
	}
}

// NewSessionEndedEvent constructs the synthetic event emitted when an
// agent's stdio MCP connection OR a SQL TCP connection closes. Per
// [[agent-identity-in-audit]] Feature 2: "When the MCP connection
// closes (agent exits), the session ID retires + a SESSION_ENDED
// event emits."
//
// The transport (PG forwarder / MySQL forwarder / observation-only PG
// loop / MCP server) calls AgentRegistry.Retire to remove the session
// + receives the previously-stored Agent, then hands that Agent here
// for the synthetic event. The decisionID arg is 0 (this isn't a
// decision); api.operation = "session_ended"; severity = Informational.
//
// Schema: class_uid=6003, activity_id=99 (Other), activity_name=
// "session_ended", type_uid=600399, severity_id=1 (Informational),
// status_id=99 (Other). The agent block under unmapped.iam_jit.agent
// carries the retired session_id so a SIEM consumer can JOIN every
// preceding event from that session_id against this terminator.
//
// Per [[security-team-positioning-safety-not-surveillance]]: this is
// bookkeeping, not an alert — Informational severity keeps it below
// the dashboard noise floor.
func NewSessionEndedEvent(agent Agent, host string) Event {
	return Event{
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: Product_{
				Name:       Product,
				VendorName: VendorName,
				Version:    BuildVersion,
			},
		},
		Time:         time.Now().UTC().UnixMilli(),
		ClassUID:     ocsfClassUID,
		ClassName:    ocsfClassName,
		CategoryUID:  ocsfCategoryUID,
		CategoryName: ocsfCategoryNm,
		ActivityID:   ActivityIDOther,
		ActivityName: "session_ended",
		TypeUID:      ocsfTypeUIDBase + ActivityIDOther,
		TypeName:     typeNameFor(ActivityIDOther),
		SeverityID:   ocsfSeverityInformationalID,
		Severity:     ocsfSeverityInformational,
		StatusID:     StatusIDOther,
		Status:       "Other",
		StatusDetail: "agent session ended",
		API: API{
			Operation: "session_ended",
		},
		SrcEndpoint: parseEndpoint(host),
		Unmapped: &Unmapped{
			IAMJIT: IAMJITExt{
				EventType: string(EventTypeSessionEnded),
				Enforced:  false,
				Agent:     agentPtrOrNil(agent),
			},
		},
	}
}

// NewHeartbeatEvent constructs the synthetic periodic-liveness event
// the Heartbeater emits on each tick. Per
// [[prompt-injection-disable-bouncer-threat]]: the heartbeat cadence
// is the cross-product signal a SIEM uses to detect a disabled /
// killed / suspended bouncer. Severity Informational keeps the volume
// below the dashboard noise floor while still indexable for absence
// detection.
//
// Schema: class_uid=6003, activity_id=99 (Other), activity_name=
// "heartbeat", type_uid=600399, severity_id=1 (Informational),
// status_id=99 (Other). The interval is stamped under
// unmapped.iam_jit.ext.interval_seconds so a SIEM operator triaging
// an absence alert can answer "how often SHOULD this bouncer be
// emitting?" without a JOIN against config.
func NewHeartbeatEvent(host string, interval time.Duration) Event {
	ext := map[string]any{
		"interval_seconds": interval.Seconds(),
	}
	return Event{
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: Product_{
				Name:       Product,
				VendorName: VendorName,
				Version:    BuildVersion,
			},
		},
		Time:         time.Now().UTC().UnixMilli(),
		ClassUID:     ocsfClassUID,
		ClassName:    ocsfClassName,
		CategoryUID:  ocsfCategoryUID,
		CategoryName: ocsfCategoryNm,
		ActivityID:   ActivityIDOther,
		ActivityName: "heartbeat",
		TypeUID:      ocsfTypeUIDBase + ActivityIDOther,
		TypeName:     typeNameFor(ActivityIDOther),
		SeverityID:   ocsfSeverityInformationalID,
		Severity:     ocsfSeverityInformational,
		StatusID:     StatusIDOther,
		Status:       "Other",
		StatusDetail: "bouncer alive",
		API: API{
			Operation: "heartbeat",
		},
		SrcEndpoint: parseEndpoint(host),
		Unmapped: &Unmapped{
			IAMJIT: IAMJITExt{
				EventType: string(EventTypeHeartbeat),
				Enforced:  false,
				Ext:       ext,
			},
		},
	}
}

// NewHeartbeatGapEvent constructs the SECURITY_ALERT event the
// Heartbeater's watchdog emits when the tick loop fell behind by more
// than (Interval + GapThreshold). Per
// [[prompt-injection-disable-bouncer-threat]]: this is the
// in-process counterpart to the SIEM-side absence detection — the
// alert reaches the SIEM via the export channel BEFORE the silence
// is wide enough to register as a full disable.
//
// Schema: class_uid=6003, activity_id=99 (Other), activity_name=
// "heartbeat_gap", type_uid=600399, severity_id=3 (Medium),
// status_id=99 (Other). Per [[security-team-positioning-safety-not-
// surveillance]]: status_detail is NEUTRAL — names the observation
// + suggests redistribution; never accuses the operator.
func NewHeartbeatGapEvent(host string, interval, threshold, observed time.Duration) Event {
	detail := fmt.Sprintf(
		"heartbeat gap observed (last tick %s ago; interval %s; "+
			"threshold %s); consider distributing the proxy onto a "+
			"non-throttled instance",
		observed.Round(time.Millisecond), interval, threshold)
	ext := map[string]any{
		"rule_id":              string(AlertRuleHeartbeatGap),
		"interval_seconds":     interval.Seconds(),
		"threshold_seconds":    threshold.Seconds(),
		"observed_gap_seconds": observed.Seconds(),
	}
	return Event{
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: Product_{
				Name:       Product,
				VendorName: VendorName,
				Version:    BuildVersion,
			},
		},
		Time:         time.Now().UTC().UnixMilli(),
		ClassUID:     ocsfClassUID,
		ClassName:    ocsfClassName,
		CategoryUID:  ocsfCategoryUID,
		CategoryName: ocsfCategoryNm,
		ActivityID:   ActivityIDOther,
		ActivityName: string(AlertRuleHeartbeatGap),
		TypeUID:      ocsfTypeUIDBase + ActivityIDOther,
		TypeName:     typeNameFor(ActivityIDOther),
		SeverityID:   ocsfSeverityMediumID,
		Severity:     ocsfSeverityMedium,
		StatusID:     StatusIDOther,
		Status:       "Other",
		StatusDetail: detail,
		SrcEndpoint:  parseEndpoint(host),
		Unmapped: &Unmapped{
			IAMJIT: IAMJITExt{
				EventType: string(EventTypeSecurityAlert),
				Enforced:  false,
				Ext:       ext,
			},
		},
	}
}

// NewAuditDroppedEvent constructs the synthetic event the WebhookPusher
// emits when its bounded queue fills + it has to drop. The count is
// how many DECISION events were dropped since the previous synthetic
// AUDIT_DROPPED event (NOT the cumulative total — consumers want the
// rate).
//
// Schema: OCSF class 6003, activity_id=99 (Other), activity_name=
// "audit_dropped", type_uid=600399, severity_id=3 (Medium) so this
// surfaces with elevated priority in a SIEM dashboard (per the memo).
// status_id=99 (Other) since neither Success nor Failure honestly
// describes "we dropped our own event."
//
// queueSize is the bounded-queue capacity (cap(ch)) at the time of
// emission — exposed under unmapped.iam_jit.queue_size so an operator
// triaging a drop spike sees the queue size that was exceeded.
func NewAuditDroppedEvent(droppedSinceLast int64, host string) Event {
	const detailFmt = "audit-export webhook dropped events due to backpressure"
	return Event{
		Metadata: Metadata{
			Version: SchemaVersion,
			Product: Product_{
				Name:       Product,
				VendorName: VendorName,
				Version:    BuildVersion,
			},
		},
		Time:         time.Now().UTC().UnixMilli(),
		ClassUID:     ocsfClassUID,
		ClassName:    ocsfClassName,
		CategoryUID:  ocsfCategoryUID,
		CategoryName: ocsfCategoryNm,
		ActivityID:   ActivityIDOther,
		ActivityName: "audit_dropped",
		TypeUID:      ocsfTypeUIDBase + ActivityIDOther,
		TypeName:     typeNameFor(ActivityIDOther),
		SeverityID:   ocsfSeverityMediumID,
		Severity:     ocsfSeverityMedium,
		StatusID:     StatusIDOther,
		Status:       "Other",
		StatusDetail: detailFmt,
		SrcEndpoint:  parseEndpoint(host),
		Unmapped: &Unmapped{
			IAMJIT: IAMJITExt{
				EventType:    string(EventTypeAuditDropped),
				DroppedCount: droppedSinceLast,
				Enforced:     false,
			},
		},
	}
}

// Agent fingerprinting + persistent session ID for the cross-product
// audit-export schema. Per the [[agent-identity-in-audit]] memo:
//
//   Today's audit row has good USER identity but weak AGENT identity.
//   Two features close that gap:
//   (1) agent fingerprinting via User-Agent / MCP clientInfo / process
//       inspection → unmapped.iam_jit.agent.{name, version, session_id}
//   (2) persistent agent session ID minted at MCP-connect, bound across
//       calls.
//
// Sibling agents in ibounce + kbounce ship the equivalent under the
// same JSON path (unmapped.iam_jit.agent) so a single SIEM filter keyed
// on `unmapped.iam_jit.agent.name` works across all three products.
//
// This file owns:
//
//   - the Agent struct (the projection target under unmapped.iam_jit.agent)
//   - DetectedFrom enum (which signal we used to fingerprint)
//   - a process-wide AgentRegistry that mints + retires session IDs
//     (UUID v7, per the memo; v1.6.0's google/uuid package supports v7)
//   - the per-dialect helpers (ParsePGStartupAppName for
//     application_name from a PG StartupMessage, ParseMySQLClientAttrs
//     for client attributes from a MySQL HandshakeResponse) so the proxy
//     forwarders + observation-only paths share one detection codepath
//
// Per [[scorer-is-ground-truth]] this package NEVER mutates a decision
// based on the detected agent — it ONLY decorates the audit-export
// event. Detection failure (agent name = "unknown") MUST be a soft
// degradation, never a deny. The agent name is metadata for the SIEM,
// not a gating signal.
//
// Per the memo's "Don't" section:
//   - Don't claim fingerprinting is 100% — best-effort. "unknown"
//     fallback is normal + supported.
//   - Don't make session ID predictable. UUID v7 has a random component
//     after its time prefix so an adversarial agent can't forge "this
//     came from session X."
//   - Don't propagate parent-PID / exe-path to the webhook by default.
//     dbounce v1.0 doesn't capture process-tree info — SQL wire protocols
//     don't carry a User-Agent, so the application_name / handshake-attrs
//     paths suffice for the supported clients (psql, pgcli, psycopg2,
//     MySQL Connector/J, etc.).

package audit

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// #318 / §A16 — cross-bouncer agent-attribution regexes. Mirror gbounce
// + ibounce + kbouncer byte-for-byte so a SIEM filter on
// `unmapped.iam_jit.agent.name=X` / `agent.session_id=X` is portable
// across all four Bounce products.
//
// dbounce sees the SQL wire protocol, not HTTP, so the canonical agent
// declaration is the PostgreSQL `application_name` startup parameter
// (MySQL `_program_name` connection-attribute is the equivalent). When
// the operator sets:
//
//	application_name = iam-jit-agent:claude-code:01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef
//
// dbounce splits on `:`, validates `NAME` against `agentNameRe` +
// `SESSIONID` against `sessionIDRe`, and stamps the parsed pieces onto
// the same `unmapped.iam_jit.agent.{name, session_id, detected_from}`
// block the HTTP-shaped Bouncers populate. `detected_from=pg_app_name`
// flags the SQL provenance so a SIEM filter can distinguish wire-
// protocol-attributed events from HTTP-attributed ones.

var agentNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// IsValidAgentName returns true when s matches the canonical
// X-Agent-Name shape ([A-Za-z0-9._-]{1,64}). Cross-product invariant:
// a name accepted by dbounce MUST be accepted by every other Bouncer.
func IsValidAgentName(s string) bool { return agentNameRe.MatchString(s) }

// IsValidSessionID is defined in recorder.go (same package); it
// validates `[A-Za-z0-9_-]{1,128}` — the canonical X-Agent-Session-Id
// shape. UUIDs (v4 + v7 + v6) all fit — operators may use any UUID
// flavor. We re-export reference here for #318 / §A16 callers that
// want symmetry with `IsValidAgentName` next to the cross-bouncer
// regex documentation.

// AgentAppNameTagPrefix is the canonical `application_name` prefix that
// declares an iam-jit agent attribution per the
// [[cross-product-agent-parity]] convention. The full shape is:
//
//	iam-jit-agent:NAME:SESSIONID
//
// Documented at iam-roles/docs/AGENT-ATTRIBUTION.md §SQL.
const AgentAppNameTagPrefix = "iam-jit-agent:"

// ParseAgentTagFromAppName attempts to extract `(name, sessionID, ok)`
// from a PG `application_name` value of the documented shape:
//
//	iam-jit-agent:NAME:SESSIONID
//
// Returns ok=false when the prefix doesn't match (the caller falls
// through to the existing known-client app-name table). When the
// prefix matches but either piece fails the validation regex, ok=false
// AND `name` / `sessionID` carry the raw invalid pieces so the caller
// can log the rejection + bump a counter.
//
// Per [[security-team-positioning-safety-not-surveillance]]: validation
// failures are SAFETY signal (operator visibility) — the raw value is
// truncated by the rejection-log helper before any stderr output, so
// shell-injection payloads can't pivot through the log.
func ParseAgentTagFromAppName(appName string) (name, sessionID string, ok bool) {
	if !strings.HasPrefix(appName, AgentAppNameTagPrefix) {
		return "", "", false
	}
	tail := strings.TrimPrefix(appName, AgentAppNameTagPrefix)
	// Expect exactly NAME:SESSIONID. A missing colon = malformed; we
	// return raw + false so the caller bumps the rejection counter.
	idx := strings.Index(tail, ":")
	if idx < 0 {
		return tail, "", false
	}
	rawName := tail[:idx]
	rawSessionID := tail[idx+1:]
	if !IsValidAgentName(rawName) || !IsValidSessionID(rawSessionID) {
		return rawName, rawSessionID, false
	}
	return rawName, rawSessionID, true
}

// DetectedFrom names which signal produced the agent fingerprint. Used
// in the OCSF unmapped.iam_jit.agent.detected_from field so a SIEM
// reviewer can answer "is this a high-confidence MCP clientInfo capture
// or a best-effort SQL handshake heuristic?"
type DetectedFrom string

const (
	// DetectedFromMCPClientInfo names the MCP `initialize` request's
	// `clientInfo.{name, version}` block — the highest-confidence signal,
	// per the MCP spec. Claude Code sends name="claude-code", Cursor
	// sends "cursor", Codex sends "codex", Devin sends "devin".
	DetectedFromMCPClientInfo DetectedFrom = "mcp_clientinfo"

	// DetectedFromPGAppName names the `application_name` parameter from
	// a PG StartupMessage. PG drivers + clients usually set this:
	//   - psql sets "psql"
	//   - pgcli sets "pgcli"
	//   - psycopg2 sets "psycopg2"
	//   - JDBC driver sets "PostgreSQL JDBC Driver"
	//   - Claude Code (when invoking psql via a tool call) inherits psql
	// Lower-confidence than MCP clientInfo (a user can spoof
	// application_name) but high-signal in honest usage.
	DetectedFromPGAppName DetectedFrom = "pg_application_name"

	// DetectedFromMySQLAttrs names the `attrs` key/value map from a
	// MySQL HandshakeResponse. MySQL Connector/J + caching_sha2_password
	// clients send `_client_name`, `_client_version`, `_program_name`
	// in this map. Same confidence tier as PG application_name.
	DetectedFromMySQLAttrs DetectedFrom = "mysql_client_attrs"

	// DetectedFromDecideFlag names the `dbounce decide --agent-name`
	// CLI flag — the JDBC-shim path's explicit declaration. The shim
	// (Snowflake / BigQuery) is invoked by an operator-controlled
	// wrapper that knows what's calling it; passing --agent-name turns
	// the otherwise-opaque shim invocation into a fingerprinted call.
	// Confidence depends on the operator's wrapper, but it's an
	// explicit declaration rather than an inference.
	DetectedFromDecideFlag DetectedFrom = "decide_flag"

	// DetectedFromUnknown is the fallback when nothing identified the
	// caller. Per the memo: "unknown" is supported + expected — don't
	// gate decisions on it, don't surface it as a privacy concern.
	DetectedFromUnknown DetectedFrom = "unknown"
)

// Agent is the projection target under unmapped.iam_jit.agent. JSON
// tags match the [[agent-identity-in-audit]] memo's schema sample
// exactly so the cross-product SIEM rule works without per-product
// field-name translation.
//
// SessionID is mint-per-connection: each MCP stdio connection gets one;
// each PG/MySQL TCP connection gets one. Threads through every audit
// row + every SESSION_ENDED synthetic event.
//
// Name + Version are best-effort. Empty Name → projection emits "unknown"
// so consumers always see SOME value (a single null-branch in a SIEM
// dashboard is uglier than a known-unknown bucket).
//
// DetectedFrom names the detection source so a reviewer can triage
// confidence per row.
//
// HeaderRejection is the #320 / §A18 structured breadcrumb that lands
// at `unmapped.iam_jit.ext.agent_header_rejection` when the agent's
// `application_name=iam-jit-agent:...` tag was malformed. Stamped at
// connection-registration time + threaded onto every subsequent
// audit event from that session so a SOC analyst querying the audit
// log can see which connection had a misconfigured agent SDK +
// which reason (charset / length / unparseable tag body). NEVER
// includes the raw value — only the rejected value's length, for
// safe forensics per
// [[security-team-positioning-safety-not-surveillance]].
type Agent struct {
	Name            string         `json:"name,omitempty"`
	Version         string         `json:"version,omitempty"`
	SessionID       string         `json:"session_id,omitempty"`
	DetectedFrom    DetectedFrom   `json:"detected_from,omitempty"`
	HeaderRejection map[string]any `json:"-"`
}

// IsEmpty reports whether nothing was populated (no name / no session
// id / no detection source / no rejection). The projection branches
// on this to keep the JSONL line minimal — an event without any
// agent information omits the entire unmapped.iam_jit.agent block
// rather than emitting a stub `"agent":{"detected_from":"unknown"}`
// clutter on every row that happens to lack agent context (e.g.
// observation-only smoke tests before any client has connected).
func (a Agent) IsEmpty() bool {
	return a.Name == "" && a.Version == "" && a.SessionID == "" &&
		a.DetectedFrom == "" && len(a.HeaderRejection) == 0
}

// Normalize fills in DetectedFromUnknown when DetectedFrom is empty +
// Name is set (the detection happened but the source label wasn't
// stamped — defensive, callers should always set DetectedFrom). When
// Name is empty + we have a session id (an MCP connection that didn't
// surface clientInfo), Normalize stamps name="unknown" so SIEM
// dashboards have a stable bucket for "session active but client
// identity not declared."
func (a Agent) Normalize() Agent {
	if a.IsEmpty() {
		return a
	}
	out := a
	if out.Name == "" {
		out.Name = "unknown"
	}
	if out.DetectedFrom == "" {
		out.DetectedFrom = DetectedFromUnknown
	}
	return out
}

// NewSessionID mints a UUID v7 (time-ordered with a random component
// per RFC 9562) for use as a persistent agent session id. Per the memo:
// "Don't make session ID predictable (use UUID v7 with random component,
// not a counter) — predictable IDs let a malicious agent forge 'this
// came from session X.'"
//
// On the extraordinarily unlikely UUID generator failure (only on
// crypto/rand failure — kernel entropy starvation), falls back to a
// deterministic-looking time-based ID so the audit row still has SOME
// session identifier rather than an empty string. The fallback is
// non-secure on purpose: it's only emitted when the secure RNG has
// already failed, at which point the whole system is in trouble + the
// session id is the smallest concern.
func NewSessionID() string {
	id, err := uuid.NewV7()
	if err != nil {
		// Fallback: NOT predictable in the sense an attacker can replay
		// (timestamp-based and monotonically increasing), but obviously
		// weaker than a v7 with a random tail. We surface this via a
		// distinct prefix so a SIEM reviewer can spot the degraded mode.
		return "rand-failed-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	return id.String()
}

// AgentRegistry is a process-wide registry of active agent sessions.
// One MCP server connection OR one SQL TCP connection mints a session
// here; subsequent audit events for that connection look up the
// stamped Agent via the session id.
//
// The registry is read-mostly (one mint + many lookups + one retire per
// connection lifetime) so a sync.RWMutex is the right shape. A sync.Map
// would also work but the cardinality is small (one entry per live
// agent connection — typically O(10) on a dev laptop, O(100) on a
// shared bouncer host).
//
// Per [[ibounce-honest-positioning]] this is OPERATOR VISIBILITY, not
// adversary defense — an attacker who has wire-protocol access can
// always create a new session with a forged name. The registry's job
// is to let an honest reviewer answer "which events came from the
// same Claude Code session?" by joining on session_id.
type AgentRegistry struct {
	mu       sync.RWMutex
	sessions map[string]Agent
}

// NewAgentRegistry constructs an empty registry.
func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{sessions: make(map[string]Agent)}
}

// Mint creates a new session and stores the agent against it. Returns
// the minted session id. The agent argument's SessionID is ignored;
// Mint always assigns a fresh v7. Empty Name → "unknown".
func (r *AgentRegistry) Mint(a Agent) string {
	sid := NewSessionID()
	a.SessionID = sid
	if a.Name == "" {
		a.Name = "unknown"
	}
	if a.DetectedFrom == "" {
		a.DetectedFrom = DetectedFromUnknown
	}
	r.mu.Lock()
	r.sessions[sid] = a
	r.mu.Unlock()
	return sid
}

// MintWithSessionID is the #318 / §A16 variant that registers the agent
// under a CALLER-SUPPLIED session id (sourced from the canonical
// `application_name=iam-jit-agent:NAME:SESSIONID` tag). Used so the
// session id the agent declared is the one that lands on every
// dbounce audit event for that connection — the load-bearing
// invariant for cross-bouncer correlation by `agent.session_id`.
//
// The supplied sid MUST have already passed `IsValidSessionID` (the
// caller — registerPGAgentFromBody — validates as part of tag parsing).
// An empty / invalid sid falls back to `Mint` behaviour (fresh UUID v7)
// to preserve the SESSION_ENDED bookend.
func (r *AgentRegistry) MintWithSessionID(a Agent, sid string) string {
	if !IsValidSessionID(sid) {
		return r.Mint(a)
	}
	a.SessionID = sid
	if a.Name == "" {
		a.Name = "unknown"
	}
	if a.DetectedFrom == "" {
		a.DetectedFrom = DetectedFromUnknown
	}
	r.mu.Lock()
	r.sessions[sid] = a
	r.mu.Unlock()
	return sid
}

// Lookup returns the Agent for a session id + a found bool. Concurrent-
// safe.
func (r *AgentRegistry) Lookup(sid string) (Agent, bool) {
	r.mu.RLock()
	a, ok := r.sessions[sid]
	r.mu.RUnlock()
	return a, ok
}

// Retire removes the session id from the registry. Idempotent — calling
// Retire twice (e.g. on a defer + on an explicit close path) does not
// panic + returns the previously-stored Agent + true on the first call,
// zero-value + false on subsequent calls. Callers use the returned
// Agent to populate a SESSION_ENDED audit event.
func (r *AgentRegistry) Retire(sid string) (Agent, bool) {
	r.mu.Lock()
	a, ok := r.sessions[sid]
	if ok {
		delete(r.sessions, sid)
	}
	r.mu.Unlock()
	return a, ok
}

// ActiveCount returns the number of live sessions. Used by /healthz +
// the MCP status tool so an operator can answer "how many agents are
// currently connected?" without grepping the log.
func (r *AgentRegistry) ActiveCount() int {
	r.mu.RLock()
	n := len(r.sessions)
	r.mu.RUnlock()
	return n
}

// ---------------------------------------------------------------------
// Per-dialect detection helpers.
// ---------------------------------------------------------------------

// ParsePGStartupParams parses a PG StartupMessage body (the bytes AFTER
// the 4-byte protocol version, which is everything in
// Forwarder.startupBytes[8:] + the body it then reads on the wire) into
// a key/value map. PG StartupMessage param format: a sequence of null-
// terminated UTF-8 strings, alternating key + value, terminated by an
// extra null byte. Empty body → empty map (not nil).
//
// Returns the params as a map for callers that want to fish out other
// fields (user, database, options) later. ParsePGStartupAppName is the
// convenience wrapper for the application_name field that the audit
// path actually uses.
//
// Defensive: malformed bodies (no trailing null, odd number of strings,
// etc.) return whatever was successfully parsed without an error —
// agent fingerprinting is best-effort + must never break a connection.
func ParsePGStartupParams(body []byte) map[string]string {
	out := make(map[string]string)
	if len(body) == 0 {
		return out
	}
	// Walk null-separated strings, pair them.
	parts := make([]string, 0, 16)
	start := 0
	for i := 0; i < len(body); i++ {
		if body[i] == 0 {
			parts = append(parts, string(body[start:i]))
			start = i + 1
			// Trailing double-null terminates the param block.
			if start < len(body) && body[start] == 0 {
				break
			}
		}
	}
	// Don't include the trailing empty string the PG protocol uses as
	// a sentinel — it would otherwise become a "" key.
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	for i := 0; i+1 < len(parts); i += 2 {
		k := parts[i]
		v := parts[i+1]
		if k != "" {
			out[k] = v
		}
	}
	return out
}

// ParsePGStartupAppName returns the application_name parameter from a
// parsed-startup-params map, with a best-effort detection of the agent
// name implied by common app names. Empty string → no application_name
// was sent (the parameter is optional per PG protocol).
//
// Mapping:
//
//	"iam-jit-agent:NAME:SESSIONID"         → name="NAME" (cross-bouncer #318)
//	"psql"                                 → name="psql"
//	"pgcli"                                → name="pgcli"
//	"psycopg2"                             → name="psycopg2"
//	"PostgreSQL JDBC Driver"               → name="pg-jdbc"
//	"claude-code"                          → name="claude-code"
//	"cursor"                               → name="cursor"
//	any other non-empty value              → name=<the literal value>
//
// The `iam-jit-agent:NAME:SESSIONID` shape (#318 / §A16) is the canonical
// cross-bouncer agent-attribution channel for SQL connections — it's
// the wire-protocol equivalent of HTTP's `X-Agent-Name` +
// `X-Agent-Session-Id` headers. When the shape parses cleanly,
// `name`=NAME (validated) — the SESSIONID is extracted via
// ParsePGStartupAppNameWithSession below.
//
// Per the memo: we don't try to magic-detect "this is really Claude
// Code calling psql under the hood" — that's a process-tree heuristic
// which dbounce v1.0 explicitly defers. The application_name we record
// is what the immediate client declared.
func ParsePGStartupAppName(params map[string]string) (name, raw string) {
	name, _, raw, _ = ParsePGStartupAppNameWithSession(params)
	return name, raw
}

// ParsePGStartupAppNameWithSession is the cross-bouncer #318 / §A16
// variant that also returns the parsed session id when the canonical
// `iam-jit-agent:NAME:SESSIONID` shape was supplied. Returns
// `(name, sessionID, raw, tagInvalid)` where:
//
//   - `name` is the canonical agent name (validated when from the tag
//     prefix; raw / known-client when from the legacy fallback).
//   - `sessionID` is the validated session id (empty unless the tag
//     prefix was supplied AND both pieces passed validation).
//   - `raw` is the unmodified application_name parameter value
//     (empty when no application_name was sent).
//   - `tagInvalid` is true ONLY when the iam-jit-agent: prefix matched
//     but the parsed pieces failed validation — the caller bumps the
//     rejection counter + logs in that case.
//
// Per [[cross-product-agent-parity]] the parsed `name` + `sessionID`
// land on the same `unmapped.iam_jit.agent.{name, session_id}` block
// that gbounce / ibounce / kbouncer populate from HTTP headers; a SIEM
// query on `agent.session_id=X` resolves across all four products.
func ParsePGStartupAppNameWithSession(params map[string]string) (name, sessionID, raw string, tagInvalid bool) {
	raw = strings.TrimSpace(params["application_name"])
	if raw == "" {
		return "", "", "", false
	}
	// #318 — cross-bouncer canonical tag has the highest precedence.
	// When the prefix matches but validation fails, surface
	// `tagInvalid=true` so the caller can log + count the rejection.
	if strings.HasPrefix(raw, AgentAppNameTagPrefix) {
		tagName, tagSession, ok := ParseAgentTagFromAppName(raw)
		if ok {
			return tagName, tagSession, raw, false
		}
		// Tag prefix matched but a piece failed validation. We DO NOT
		// stamp the malformed pieces onto the audit event — fall
		// through to known-client / verbatim handling on the raw value
		// (which won't match anything meaningful + lands at name=raw)
		// AND flag the rejection.
		_ = tagName
		_ = tagSession
		return "", "", raw, true
	}
	lower := strings.ToLower(raw)
	switch {
	case lower == "psql":
		return "psql", "", raw, false
	case lower == "pgcli":
		return "pgcli", "", raw, false
	case strings.Contains(lower, "psycopg"):
		return "psycopg2", "", raw, false
	case strings.Contains(lower, "jdbc"):
		return "pg-jdbc", "", raw, false
	case lower == "claude-code" || strings.HasPrefix(lower, "claude-code/"):
		return "claude-code", "", raw, false
	case lower == "cursor" || strings.HasPrefix(lower, "cursor/"):
		return "cursor", "", raw, false
	case lower == "codex" || strings.HasPrefix(lower, "codex/"):
		return "codex", "", raw, false
	case lower == "devin" || strings.HasPrefix(lower, "devin/"):
		return "devin", "", raw, false
	default:
		return raw, "", raw, false
	}
}

// ParseMySQLClientAttrs parses MySQL's connection-attributes block from
// a HandshakeResponse41 payload. The block lives after the
// auth-response section, gated by the CLIENT_CONNECT_ATTRS capability
// flag (0x00100000). When the capability is set the block is a
// length-encoded-string-pair sequence:
//
//	len-enc-int  total-block-length
//	(len-enc-string key, len-enc-string value) *
//
// Common keys MySQL Connector/J + caching_sha2_password clients send:
//
//	_client_name      "MySQL Connector/J" / "libmysql" / "Python-mysql"
//	_client_version   "8.4.0" / "8.0.33"
//	_program_name     "mysql" / "mysqlsh" / "/path/to/our-app"
//	_pid              the calling process PID (we ignore for privacy)
//
// dbounce v1.0 only inspects the _client_name + _client_version +
// _program_name fields. The pid + os fields are NOT propagated to the
// audit row per the memo's "don't propagate process-tree info to the
// webhook by default" guidance.
//
// Defensive: returns an empty map on any parse error rather than
// surfacing the error. Agent fingerprinting must never break a
// connection.
func ParseMySQLClientAttrs(attrsBlock []byte) map[string]string {
	out := make(map[string]string)
	i := 0
	for i < len(attrsBlock) {
		k, consumed, ok := mysqlReadLenEncString(attrsBlock[i:])
		if !ok {
			return out
		}
		i += consumed
		v, consumed2, ok := mysqlReadLenEncString(attrsBlock[i:])
		if !ok {
			return out
		}
		i += consumed2
		if k != "" {
			out[k] = v
		}
	}
	return out
}

// ParseMySQLAgentFromAttrs returns a best-effort agent name + version
// from a MySQL connection-attributes map. Mapping:
//
//	_client_name == "MySQL Connector/J"      → name="mysql-connector-j"
//	_client_name contains "libmysql"         → name="libmysql"
//	_client_name contains "python"           → name="python-mysql"
//	_program_name == "mysql" or "mysqlsh"    → name="mysql-cli"
//	_program_name == "claude-code"           → name="claude-code"
//	any other _client_name                   → name=<the literal value>
//	(none of the above)                      → name="" (unknown)
//
// The _client_version field (when present) becomes version unchanged.
func ParseMySQLAgentFromAttrs(attrs map[string]string) (name, version string) {
	version = strings.TrimSpace(attrs["_client_version"])
	clientName := strings.ToLower(strings.TrimSpace(attrs["_client_name"]))
	programName := strings.ToLower(strings.TrimSpace(attrs["_program_name"]))
	switch {
	case clientName == "mysql connector/j":
		return "mysql-connector-j", version
	case strings.Contains(clientName, "libmysql"):
		return "libmysql", version
	case strings.Contains(clientName, "python"):
		return "python-mysql", version
	case programName == "mysql" || programName == "mysqlsh":
		return "mysql-cli", version
	case programName == "claude-code" || strings.HasPrefix(programName, "claude-code/"):
		return "claude-code", version
	case clientName != "":
		// Surface the literal so the SIEM has SOMETHING for unknown
		// clients (mysql2, go-sql-driver, etc.).
		return attrs["_client_name"], version
	case programName != "":
		return attrs["_program_name"], version
	default:
		return "", version
	}
}

// mysqlReadLenEncString reads one length-encoded string from b.
// Returns the string, the number of bytes consumed, and ok. Mirrors
// the wire format used in MySQL connection attributes per the protocol
// spec.
func mysqlReadLenEncString(b []byte) (string, int, bool) {
	n, consumed, ok := mysqlReadLenEncInt(b)
	if !ok {
		return "", 0, false
	}
	if uint64(len(b)-consumed) < n {
		return "", 0, false
	}
	return string(b[consumed : consumed+int(n)]), consumed + int(n), true
}

// mysqlReadLenEncInt reads one MySQL length-encoded integer from b.
// Returns the value, the number of bytes consumed, and ok. Per the
// MySQL protocol:
//
//	first byte 0x00-0xfa = 1-byte int (value = first byte)
//	first byte 0xfc      = 2-byte little-endian int follows
//	first byte 0xfd      = 3-byte little-endian int follows
//	first byte 0xfe      = 8-byte little-endian int follows
//	first byte 0xfb/0xff = reserved (treat as parse failure)
func mysqlReadLenEncInt(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	first := b[0]
	switch {
	case first < 0xfb:
		return uint64(first), 1, true
	case first == 0xfc:
		if len(b) < 3 {
			return 0, 0, false
		}
		return uint64(b[1]) | uint64(b[2])<<8, 3, true
	case first == 0xfd:
		if len(b) < 4 {
			return 0, 0, false
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4, true
	case first == 0xfe:
		if len(b) < 9 {
			return 0, 0, false
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16 | uint64(b[4])<<24 |
			uint64(b[5])<<32 | uint64(b[6])<<40 | uint64(b[7])<<48 | uint64(b[8])<<56, 9, true
	default:
		// 0xfb (NULL marker) or 0xff (reserved). Either is an unexpected
		// leading byte for a connection-attributes length-prefix; the
		// memo's "must never break a connection" rule means we return
		// "parse failure" rather than panic.
		return 0, 0, false
	}
}

// MCPClientInfoToAgent maps the MCP `initialize` request's clientInfo
// block (`{name, version}` per the MCP spec) into an Agent suitable for
// AgentRegistry.Mint. Per the memo: Claude Code sends name="claude-
// code", Cursor sends "cursor", etc. We pass through the values
// verbatim (no whitelist) since the MCP spec already constrains what
// values an honest client will send + an attacker reaching the MCP
// stdio is already inside the trust boundary.
//
// Empty name → name="unknown" so the registry's "always has SOME name"
// invariant holds.
func MCPClientInfoToAgent(name, version string) Agent {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "unknown"
	}
	return Agent{
		Name:         name,
		Version:      strings.TrimSpace(version),
		DetectedFrom: DetectedFromMCPClientInfo,
	}
}

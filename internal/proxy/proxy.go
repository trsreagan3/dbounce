// Package proxy is dbounce's TCP listener + decision pipeline. D-Slice
// 1 ships the observation-only PostgreSQL wire-protocol shape: parse
// inbound Query / Parse / Bind / Execute messages, classify the SQL,
// audit-log the decision, return a synthetic ReadyForQuery to the
// client. D-Slice 2 wires real upstream forwarding; D-Slice 3 wires
// the rule engine + per-task scopes (this file's `decide()` is where
// the composition order lives).
//
// Per [[creates-never-mutates]]: the proxy NEVER executes SQL against
// a real database without an explicit upstream configured. The
// synthetic ReadyForQuery keeps well-behaved clients happy enough to
// send the next statement so the operator can preview the full audit
// trail before flipping to real forwarding.
//
// Per [[safety-mode-lean-permissive]]: D-Slice 1's default verdict
// was always ALLOW (advisory). D-Slice 3 introduces real gating via
// task scopes + global rules + default-policy fall-through.
package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/parser"
	"github.com/trsreagan3/dbounce/internal/profile"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/tasks"
	"github.com/trsreagan3/dbounce/internal/upstream"
)

// Mode names dbounce's two operating shapes. Same vocabulary kbounce +
// ibounce use.
type Mode string

const (
	ModeCooperative Mode = "cooperative"
	ModeTransparent Mode = "transparent"
)

// IsValid reports whether m is one of the recognized values.
func (m Mode) IsValid() bool {
	return m == ModeCooperative || m == ModeTransparent
}

// SyncPromptDefault names the fallback verdict for #203 sync-prompt
// timeouts. Two values (parallel to DefaultPolicy on purpose — the
// shape is "what if nobody answers?", same question, different layer).
type SyncPromptDefault string

const (
	SyncPromptDefaultAllow SyncPromptDefault = "allow"
	SyncPromptDefaultDeny  SyncPromptDefault = "deny"
)

// IsValid reports whether d is one of the recognized values.
func (d SyncPromptDefault) IsValid() bool {
	return d == SyncPromptDefaultAllow || d == SyncPromptDefaultDeny
}

// ParseSyncPromptDefault parses a CLI flag value.
func ParseSyncPromptDefault(s string) (SyncPromptDefault, error) {
	d := SyncPromptDefault(s)
	if d.IsValid() {
		return d, nil
	}
	return "", fmt.Errorf("dbounce: unknown sync-prompt-default %q (want allow | deny)", s)
}

// DefaultPolicy names what dbounce does when no rule matches a
// statement in transparent mode. D-Slice 3 consults it at the end of
// the composition order.
type DefaultPolicy string

const (
	DefaultPolicyAllow DefaultPolicy = "allow"
	DefaultPolicyDeny  DefaultPolicy = "deny"
)

// IsValid reports whether p is one of the recognized values.
func (p DefaultPolicy) IsValid() bool {
	return p == DefaultPolicyAllow || p == DefaultPolicyDeny
}

// Dialect names a SQL wire protocol.
//
//   - postgres  (D-Slice 1) — PG wire-protocol listener + libpg_query parser.
//   - mysql     (D-Slice 5) — MySQL wire-protocol listener + xwb1989/sqlparser.
//   - snowflake (D-Slice 6) — JDBC-driver-shim only (no wire-protocol proxy
//     in v1.0); parser uses xwb1989/sqlparser with Snowflake keyword
//     extensions. calibration_status: experimental — see
//     docs/SHIM-INTEGRATION.md for the honest trade-offs.
//   - bigquery  (D-Slice 6) — JDBC-driver-shim only (no wire-protocol proxy
//     in v1.0); parser uses xwb1989/sqlparser with BigQuery keyword
//     extensions. calibration_status: experimental — see
//     docs/SHIM-INTEGRATION.md for the honest trade-offs.
//
// Per [[v1-scope-bar]] + [[scorer-is-ground-truth]]: shipping snowflake +
// bigquery via the shim path (vs the PG/MySQL native wire-protocol path)
// is a deliberate honest trade-off — the customer's app MUST cooperate
// with the shim; an adversarial client that calls the underlying driver
// directly bypasses dbounce entirely. The CLI's `dbounce run --dialect
// snowflake|bigquery` fails fast pointing at docs/SHIM-INTEGRATION.md;
// the supported invocation path for these dialects is `dbounce decide`
// (or the dbounce_decide MCP tool) called from a shim wrapper.
type Dialect string

const (
	DialectPostgres  Dialect = "postgres"
	DialectMySQL     Dialect = "mysql"
	DialectSnowflake Dialect = "snowflake"
	DialectBigQuery  Dialect = "bigquery"
)

// IsValid reports whether d is one of the recognized values.
func (d Dialect) IsValid() bool {
	return d == DialectPostgres || d == DialectMySQL ||
		d == DialectSnowflake || d == DialectBigQuery
}

// Verdict names dbounce's gating outcome on a single statement.
type Verdict string

const (
	VerdictAllow Verdict = "ALLOW"
	VerdictDeny  Verdict = "DENY"
)

// DecisionSource* constants tag the audit row's decision_source column
// with the rule layer that produced the verdict. Mirrors kbounce's
// SourceProfile / SourceTask / SourceGlobal / SourceDefault enum so
// cross-product audit-log scrapers can JOIN on a consistent label set.
const (
	// SourceProfile tags verdicts fired by the D-Slice 7 environment
	// profile's deny layer (deny_keywords / deny_actions / AST-walk
	// Layer 2 backstop). Always the source label for profile-level
	// denies regardless of which sub-rule fired.
	SourceProfile = "profile"
	// SourceProfileAllow tags verdicts fired by the profile's allow
	// layer (allow_baseline classifier or allow_rules pattern match).
	// Distinct from SourceGlobalAllow so reviewers can answer
	// "what did safe-default's sql_read_only baseline pass?" without
	// joining on the rule id.
	SourceProfileAllow = "profile.allow"
	// SourceTaskAllow / SourceTaskDeny tag verdicts fired by the active
	// per-task scope. Distinct labels (allow vs deny) so reviewers can
	// filter "what did this task explicitly block?" without joining on
	// verdict.
	SourceTaskAllow = "task.allow"
	SourceTaskDeny  = "task.deny"
	// SourceGlobalAllow / SourceGlobalDeny tag verdicts fired by a row
	// in the global rules table.
	SourceGlobalAllow = "global.allow"
	SourceGlobalDeny  = "global.deny"
	// SourceDefault tags fall-through verdicts from --default-policy
	// (no rule matched).
	SourceDefault = "default"
	// SourceObservationLegacy is the D-Slice 1 label preserved for
	// backward compat: rows recorded before the rule engine landed.
	SourceObservationLegacy = "d-slice-1-observation-only"
)

// Decision is the full verdict packet evaluateAndAudit assembles for
// the audit row. Carries the verdict + reason + audit-trail fields
// (matched rule id, task id, decision source) so RecordDecision can
// stamp every column the cross-product log scraper expects.
type Decision struct {
	Verdict       Verdict
	Reason        string
	Source        string
	MatchedRuleID *int64
	TaskID        string
}

// Config wires the proxy. CLI fills this from flags + the store + the
// parser pkg's dialect dispatcher.
type Config struct {
	Host          string
	Port          int
	MgmtHost      string
	MgmtPort      int
	Mode          Mode
	DefaultPolicy DefaultPolicy
	Dialect       Dialect
	UpstreamURL   string // captured for audit + startup-banner; the load-bearing forwarding target lives on Upstream below
	// Upstream is the D-Slice 2 forwarding target. Nil = observation-only.
	// Non-nil = serveConn dials this on every inbound session + pumps
	// SCRAM auth + forwards ALLOW verdicts.
	Upstream      *upstream.Upstream
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	IdleTimeout   time.Duration
	// ActiveProfileName is the name of the active profile (e.g.
	// "safe-default"). Stamped onto every audit row. Populated by the
	// CLI from the resolved *profile.Profile so the audit row + the
	// MCP server's introspection tools see the same string.
	ActiveProfileName string

	// ActiveProfile is the D-Slice 7 environment profile wired into
	// decide(). Nil = no profile (full-user equivalent). When non-nil
	// + not the full-user sentinel, the profile's deny_keywords /
	// deny_actions / allow_baseline + AST-walk backstop / allow_rules
	// fire BEFORE task / global rules per the composition order on
	// decide() below. Per [[bounce-default-profile-pattern]]: the
	// proxy synthesizes full-user when none is selected so this field
	// is always safe to dereference for name lookup.
	ActiveProfile *profile.Profile

	// ListenerTLS is D-Slice 4's listener-side TLS state. Nil = plaintext
	// listener (the D-Slice 1 + 2 default). Non-nil = SSLRequest gets
	// 'S' + a TLS handshake before the StartupMessage parser fires. Per
	// the audit-cadence note: listener TLS and outbound (upstream) TLS
	// are INDEPENDENT — the proxy may speak TLS to the client + plaintext
	// to the upstream, or vice versa.
	ListenerTLS *listenerTLS

	// MgmtTLSCertFile + MgmtTLSKeyFile, when both non-empty, switch the
	// management HTTP listener from HTTP to HTTPS. Empty (default)
	// preserves D-Slice 1's plaintext /healthz on loopback. Stored as
	// paths (not a *tls.Config) so the http.Server's own ServeTLS path
	// owns the loading.
	MgmtTLSCertFile string
	MgmtTLSKeyFile  string

	// PromptOnDeny — when true, transparent-mode DENY decisions enqueue
	// a row in pending_prompts BEFORE applying enforcement, so the
	// operator can review + answer asynchronously without blocking the
	// SQL wire-protocol call (which times out long before the human
	// can react). D-Slice 8 wires the enqueue; the answer side lives
	// in `dbounce prompts answer`. Default false to preserve the
	// D-Slice 3 transparent-mode behavior.
	PromptOnDeny bool

	// SyncPromptOnDeny — #203 (synchronous deny-prompt v1.1). When
	// true AND mode=transparent AND an upstream is configured AND no
	// pause is active, every DENY enqueues a sync prompt + BLOCKS the
	// request goroutine waiting for `dbounce prompts answer`. Answer
	// allow → forward upstream + relay actual result rows. Answer
	// deny or timeout → emit the existing DENY ErrorResponse (PG) /
	// ERR_Packet (MySQL).
	//
	// Mutually exclusive with PromptOnDeny (the CLI rejects both flags
	// on the same `dbounce run`). Has no effect in cooperative mode
	// (advisory DENYs don't merit a sync block) or observation-only
	// mode (no upstream to forward to — CLI rejects at parse).
	//
	// Per [[ibounce-honest-positioning]]: deterrent UX for legitimate
	// human-in-loop, NOT adversarial defense. An attacker who can
	// reach the SQL listener can also reach pending_prompts via
	// `dbounce prompts answer` (same-UID, by design — local laptop
	// safety).
	SyncPromptOnDeny bool

	// SyncPromptTimeout bounds how long a SyncPromptOnDeny block
	// waits for an operator answer. After expiry, SyncPromptDefault
	// fires. CLI clamps to 5s-300s; the in-band default (Normalize)
	// is 30s.
	SyncPromptTimeout time.Duration

	// SyncPromptDefault — the fallback verdict applied when the sync
	// block times out without an operator answer. "deny" (the default)
	// matches the operator's likely posture ("if I'm not here to
	// approve, refuse"); "allow" suits the rarer
	// "approval-is-the-bottleneck, fail-open if I'm asleep" stance.
	// Two values: store.PromptDecisionAllow / store.PromptDecisionDeny.
	SyncPromptDefault SyncPromptDefault

	// RedactLiterals — MED-D8-09 (AUDIT-WB-DSLICES-1-8.md) closure.
	// When true, every audit row's Statement field has its quoted
	// string literals swapped for [REDACTED] BEFORE persistence, and
	// the row's statement_redacted column is set so downstream
	// consumers know to NOT trust the SQL for replay. Default false
	// preserves the audit-reconstruction-friendly behavior; operators
	// who route audit data to MCP-connected agents or centralized
	// observability should turn this on to keep secrets out of the
	// log. See parser.RedactLiterals for the redaction contract.
	RedactLiterals bool

	// WireListener and MgmtListener let tests hand pre-bound listeners
	// to Serve so the test process can reserve an ephemeral port (via
	// net.Listen "127.0.0.1:0") and pass it through WITHOUT a
	// close → re-Listen window that races against the OS port reuse
	// pool. Production binds via Host+Port (these stay nil and the
	// existing net.Listen branches fire). When non-nil, Shutdown closes
	// them exactly once via the listener / http.Server it owns.
	WireListener net.Listener
	MgmtListener net.Listener
}

// Normalize fills in zero-valued fields with sensible defaults.
func (c Config) Normalize() Config {
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if c.Port == 0 {
		// 5433 — one above PG's default 5432 so dbounce coexists with a
		// local PG install without conflict.
		c.Port = 5433
	}
	if c.MgmtHost == "" {
		c.MgmtHost = "127.0.0.1"
	}
	if c.MgmtPort == 0 {
		// 8768 — kbounce uses 8766, ibounce uses 8767. All three
		// products on the same laptop simultaneously is the v1.0 target
		// per [[house-of-bounce]].
		c.MgmtPort = 8768
	}
	if c.Mode == "" {
		c.Mode = ModeCooperative
	}
	if c.DefaultPolicy == "" {
		c.DefaultPolicy = DefaultPolicyDeny
	}
	if c.Dialect == "" {
		c.Dialect = DialectPostgres
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 30 * time.Second
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 30 * time.Second
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 5 * time.Minute
	}
	// #203 sync-prompt defaults. Timeout defaults to 30s (long enough
	// that an operator at the terminal has a real window to answer +
	// short enough that an inattentive operator doesn't pin a SQL
	// session for minutes). SyncPromptDefault defaults to deny — the
	// safer "I'm not here, refuse" posture; operators who want fail-
	// open opt in explicitly via --sync-prompt-default=allow.
	if c.SyncPromptTimeout == 0 {
		c.SyncPromptTimeout = 30 * time.Second
	}
	if c.SyncPromptDefault == "" {
		c.SyncPromptDefault = SyncPromptDefaultDeny
	}
	return c
}

// LookupErrorsCount mirrors kbounce + ibounce's counter shape. Surfaced
// via /healthz so monitors can flag degraded SQLite persistence
// without parsing logs. Bumped from any code path that fails a
// non-critical store lookup (pause lookup, audit-write, etc.).
var lookupErrorsCounter atomic.Int64

// LookupErrorsCount returns the current counter value. Read-only.
func LookupErrorsCount() int64 { return lookupErrorsCounter.Load() }

// BumpLookupErrors increments the counter. Exported so the rule-engine
// path + audit-write path can flag their own errors without re-
// importing the proxy package.
func BumpLookupErrors() { lookupErrorsCounter.Add(1) }

// Server holds dbounce's running state: the wire listener, the
// management HTTP server, and the underlying store.
type Server struct {
	cfg      Config
	store    *store.Store
	listener net.Listener
	mgmtSrv  *http.Server

	// auditExporter is the #252 Slice 1 audit-export fan-out. May be
	// nil when neither --audit-log-path nor --audit-webhook-url is
	// configured (FREE-tier dev-laptop default). Always called via
	// recordDecisionAndExport so the per-decision projection happens
	// AFTER the existing SQLite RecordDecision (so the row already has
	// its assigned id + the existing audit-row write is the cross-cut
	// invariant — the export is additive, never substitutive).
	auditExporter *audit.Exporter

	// alertEngine is the #252 Slice 2 suspicious-activity rule
	// engine. May be nil when alerts are disabled or never wired.
	// Called AFTER the auditExporter.EmitDecision so the rule engine
	// reacts to OBSERVED events rather than gating decisions — per
	// the spec: "rule engine reacts to observed events; doesn't
	// gate." A bug in the alert engine CANNOT change a decide()
	// verdict.
	alertEngine *audit.RuleEngine

	// agentRegistry is the per-process registry of live agent-session
	// fingerprints per [[agent-identity-in-audit]]. Each incoming PG /
	// MySQL TCP connection mints a session id at handshake time + binds
	// the detected agent (application_name / client attrs); each gated
	// statement looks up the agent via the session id + projects it into
	// unmapped.iam_jit.agent on the audit event. Retire fires on
	// connection close + emits a SESSION_ENDED synthetic event so a SIEM
	// consumer can JOIN every preceding event from that session id
	// against this terminator.
	//
	// Initialized in NewServer (never nil) so call sites can call Mint /
	// Lookup / Retire unconditionally. Process-wide single registry
	// (small cardinality: O(10) live agents on a dev laptop, O(100) on
	// a shared bouncer host) — sync.RWMutex inside the registry handles
	// the concurrency.
	agentRegistry *audit.AgentRegistry

	// connWG tracks in-flight serveConn / serveMySQLConn goroutines so
	// Shutdown can wait for them to complete + their deferred
	// emitSessionEnded (per [[agent-identity-in-audit]] Feature 2) to
	// drain into the AuditExporter BEFORE the caller closes the
	// exporter. Without this, the LogWriter's "Caller MUST stop
	// sending to Write BEFORE calling Shutdown" invariant races with
	// the per-connection defer chain. Bumped at the top of every
	// per-conn handler, decremented in the same defer chain.
	connWG sync.WaitGroup
}

// NewServer constructs a Server without starting it.
func NewServer(cfg Config, st *store.Store) *Server {
	return &Server{
		cfg:           cfg.Normalize(),
		store:         st,
		agentRegistry: audit.NewAgentRegistry(),
	}
}

// AgentRegistry returns the per-process agent-session registry. Surfaced
// for tests + the MCP introspection tool. Never nil after NewServer.
func (s *Server) AgentRegistry() *audit.AgentRegistry {
	return s.agentRegistry
}

// SetAuditExporter wires the #252 Slice 1 audit-export fan-out. May be
// called once after NewServer + before Serve; nil is permitted (no-op
// at decision time). Not goroutine-safe by design — only the CLI's
// pre-Serve sequence calls it. Tests that need a custom exporter
// construct a fresh Server.
func (s *Server) SetAuditExporter(e *audit.Exporter) {
	s.auditExporter = e
}

// AuditExporter returns the wired exporter (may be nil). Surfaced for
// the MCP status tool + /healthz. Read-only — callers must not mutate
// the returned pointer's fields.
func (s *Server) AuditExporter() *audit.Exporter {
	return s.auditExporter
}

// SetAlertEngine wires the #252 Slice 2 RuleEngine. May be called
// once after NewServer + before Serve; nil is permitted (no-op at
// decision time). Not goroutine-safe by design — only the CLI's
// pre-Serve sequence calls it.
//
// Per the spec: the rule engine MUST observe AFTER the audit-export
// emit so the decision is in flight before the engine reacts. The
// engine NEVER gates the decision.
func (s *Server) SetAlertEngine(e *audit.RuleEngine) {
	s.alertEngine = e
}

// AlertEngine returns the wired rule engine (may be nil). Surfaced
// for the MCP status tool + tests. Read-only — callers must not
// mutate the returned pointer's fields.
func (s *Server) AlertEngine() *audit.RuleEngine {
	return s.alertEngine
}

// exportDecisionRow is the load-bearing fan-out call. Invoked AFTER
// the existing store.RecordDecision succeeds + the row has its
// decisionID. Per the spec: never blocks the proxy hot-path (each
// transport's Push/Write is non-blocking with drop-on-overflow).
//
// The exporter + alert engine are both nil-safe; callers can invoke
// unconditionally.
//
// Per the #252 Slice 2 spec: the rule engine observe call fires
// AFTER the audit-export emit, so the rule engine reacts to OBSERVED
// events rather than gating decisions. A bug in the alert engine
// CANNOT change a decide() verdict — this composition order is the
// invariant that keeps the safety story honest.
//
// Wrapper preserves the no-agent call-shape for code that doesn't yet
// thread agent context (none after the [[agent-identity-in-audit]]
// rollout — but kept for symmetry with FromDecisionRow's wrapper).
func (s *Server) exportDecisionRow(row store.DecisionRow, decisionID int64) {
	s.exportDecisionRowWithAgent(row, decisionID, "")
}

// exportDecisionRowWithAgent is the agent-aware variant per
// [[agent-identity-in-audit]] Feature 1+2. sessionID, when non-empty,
// is looked up against the per-process AgentRegistry; the resolved
// Agent (with name, version, session_id, detected_from) is projected
// onto unmapped.iam_jit.agent. An empty sessionID OR a registry miss
// (rare — session retired mid-flight) results in no agent block in the
// emitted event (the existing observation-only-no-agent shape).
//
// Per [[scorer-is-ground-truth]]: the agent fingerprint NEVER affects
// the decision — it ONLY decorates the audit-export event for post-hoc
// SIEM review.
func (s *Server) exportDecisionRowWithAgent(row store.DecisionRow, decisionID int64, sessionID string) {
	exporterOn := s.auditExporter != nil && s.auditExporter.Enabled()
	alertsOn := s.alertEngine != nil && s.alertEngine.Enabled()
	if !exporterOn && !alertsOn {
		return
	}
	var agent audit.Agent
	if sessionID != "" && s.agentRegistry != nil {
		if a, ok := s.agentRegistry.Lookup(sessionID); ok {
			agent = a
		} else {
			// Registry miss is possible if the connection close ran
			// concurrently with a final in-flight decision. Stamp
			// session_id only — at least the SIEM has the correlation
			// key even when the name is gone.
			agent = audit.Agent{SessionID: sessionID, DetectedFrom: audit.DetectedFromUnknown}
		}
	}
	// Project once + reuse. FromDecisionRowWithAgent is a pure
	// projection (per [[scorer-is-ground-truth]]); the rule engine +
	// the exporter both read the same OCSF Event so they see the same
	// view. The host + upstream strings are immutable post-construction
	// so we read s.cfg directly instead of round-tripping through the
	// exporter's Status() (which would allocate a stats struct on every
	// decision).
	evt := audit.FromDecisionRowWithAgent(
		row, decisionID, s.listenerAddr(), s.upstreamAddr(), agent)
	// context.Background() — the exporter has its own bounded queue;
	// honoring a request ctx here would tear down a per-request
	// goroutine BEFORE the export had a chance to enqueue. The
	// per-transport workers have their own Shutdown contexts surfaced
	// via Server.Shutdown.
	if exporterOn {
		_ = s.auditExporter.Emit(context.Background(), evt)
	}
	// Rule engine observe AFTER the export emit (per the spec). The
	// engine NEVER gates; emit errors are intentionally swallowed
	// here for the same reason the export side does — the proxy
	// hot-path MUST NOT block on observability plumbing.
	if alertsOn {
		s.alertEngine.ObserveDecision(context.Background(), evt)
	}
}

// emitSessionEnded fires a SESSION_ENDED synthetic event for the
// connection identified by sessionID. Called from the per-protocol
// connection-close path (PG forwarder + observation-only PG loop +
// MySQL forwarder + observation-only MySQL loop) so a SIEM consumer
// can JOIN every preceding event from that session_id against the
// terminator.
//
// Idempotent: Retire returns ok=false if the session was already
// retired (defensive against double-close paths); when that happens we
// don't emit a second SESSION_ENDED.
//
// Per [[agent-identity-in-audit]]: emit even when the agent was never
// fully fingerprinted (clientInfo block was absent in MCP path or
// application_name wasn't sent on PG StartupMessage). The retired
// Agent still has the session_id; an absence of name is preserved as
// "unknown" so the SIEM dashboard has a stable bucket.
func (s *Server) emitSessionEnded(sessionID string) {
	if sessionID == "" || s.agentRegistry == nil {
		return
	}
	agent, ok := s.agentRegistry.Retire(sessionID)
	if !ok {
		return
	}
	exporterOn := s.auditExporter != nil && s.auditExporter.Enabled()
	alertsOn := s.alertEngine != nil && s.alertEngine.Enabled()
	if !exporterOn && !alertsOn {
		return
	}
	evt := audit.NewSessionEndedEvent(agent, s.listenerAddr())
	if exporterOn {
		_ = s.auditExporter.Emit(context.Background(), evt)
	}
	if alertsOn {
		s.alertEngine.ObserveDecision(context.Background(), evt)
	}
}

// listenerAddr returns the "host:port" of the proxy wire listener
// for the OCSF src_endpoint projection. Reads directly from Config so
// the per-decision path doesn't allocate a stats struct.
func (s *Server) listenerAddr() string {
	return fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
}

// upstreamAddr returns the "host:port" of the configured upstream for
// the OCSF dst_endpoint projection. Empty when observation-only.
func (s *Server) upstreamAddr() string {
	if s.cfg.Upstream == nil {
		return ""
	}
	return s.cfg.Upstream.Host()
}

// Serve binds the wire-protocol listener + the management HTTP
// listener, then accepts connections until Shutdown is called.
//
// When Config.WireListener / Config.MgmtListener are non-nil the
// pre-bound listener is used as-is (test path — eliminates the
// close → re-Listen race). When nil, net.Listen runs against
// Host+Port / MgmtHost+MgmtPort (production path).
func (s *Server) Serve() error {
	var l net.Listener
	if s.cfg.WireListener != nil {
		l = s.cfg.WireListener
	} else {
		addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("dbounce: bind %s: %w", addr, err)
		}
		l = ln
	}
	s.listener = l

	mgmtAddr := fmt.Sprintf("%s:%d", s.cfg.MgmtHost, s.cfg.MgmtPort)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	s.mgmtSrv = &http.Server{
		Addr:              mgmtAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	// D-Slice 4: /healthz over HTTPS when both --management-tls-cert
	// and --management-tls-key are set. Default is HTTP for backward
	// compat with D-Slice 1's loopback-only liveness check.
	//
	// When MgmtListener is pre-bound (test path), call Serve / ServeTLS
	// against it directly; http.Server takes ownership + closes it on
	// Shutdown. Otherwise fall through to ListenAndServe(TLS).
	mgmtL := s.cfg.MgmtListener
	go func() {
		var err error
		useTLS := s.cfg.MgmtTLSCertFile != "" && s.cfg.MgmtTLSKeyFile != ""
		switch {
		case mgmtL != nil && useTLS:
			err = s.mgmtSrv.ServeTLS(mgmtL, s.cfg.MgmtTLSCertFile, s.cfg.MgmtTLSKeyFile)
		case mgmtL != nil:
			err = s.mgmtSrv.Serve(mgmtL)
		case useTLS:
			err = s.mgmtSrv.ListenAndServeTLS(s.cfg.MgmtTLSCertFile, s.cfg.MgmtTLSKeyFile)
		default:
			err = s.mgmtSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn().Err(err).Str("addr", mgmtAddr).Msg("dbounce: management server stopped")
		}
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("dbounce: accept: %w", err)
		}
		go s.serveConn(conn)
	}
}

// Shutdown stops the listener + the management HTTP server + waits
// for in-flight serveConn goroutines (including their deferred
// emitSessionEnded calls per [[agent-identity-in-audit]]) to complete
// so the caller can safely close the AuditExporter afterwards without
// racing the LogWriter's "stop sending before Shutdown" invariant.
//
// Listener.Close() makes the Accept loop return + new connections get
// refused; existing per-conn goroutines continue until their own
// read loops detect EOF / timeout (clients dropping their connection
// is the fast path). connWG.Wait blocks Shutdown until all per-conn
// defers (which include the SESSION_ENDED emit) have drained.
//
// Honors ctx via a select against connWG completion; if ctx fires
// first the function returns ctx.Err() without continuing to
// mgmtSrv.Shutdown so the caller sees the original deadline-exceeded
// signal.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	done := make(chan struct{})
	go func() {
		s.connWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if s.mgmtSrv != nil {
		return s.mgmtSrv.Shutdown(ctx)
	}
	return nil
}

// serveConn is the per-client read loop.
func (s *Server) serveConn(conn net.Conn) {
	s.connWG.Add(1)
	defer s.connWG.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Warn().Interface("panic", r).
				Str("remote", conn.RemoteAddr().String()).
				Msg("dbounce: recovered panic in connection handler")
		}
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(s.cfg.IdleTimeout))

	// D-Slice 5: dialect dispatch. MySQL gets its own wire-protocol
	// handler in mysql.go; the PG path below is unchanged. The dispatch
	// branches BEFORE the upstream check because the MySQL handler
	// owns its own observation-only vs forwarding decision (different
	// auth + COM_QUERY semantics; no benefit in reusing the PG
	// forwarder for MySQL bytes).
	if s.cfg.Dialect == DialectMySQL {
		s.serveMySQLConn(conn)
		return
	}

	// D-Slice 2: when an upstream is configured, dispatch to the
	// forwarding handler. D-Slice 4's listener-side TLS upgrade lives
	// INSIDE the forwarder's negotiateSSL because it already owns the
	// SSLRequest preamble.
	if s.upstreamForwardingActive() {
		s.serveConnWithUpstream(conn)
		return
	}

	// D-Slice 4: observation-only path. Read the 8-byte preamble + branch
	// on SSLRequest vs StartupMessage. The TLS upgrade swaps the conn
	// substrate before pgHandshake parses the StartupMessage proper.
	preamble, err := readPGSSLPreamble(conn)
	if err != nil {
		log.Debug().Err(err).Str("remote", conn.RemoteAddr().String()).
			Msg("dbounce: read preamble failed")
		return
	}
	working := conn
	consumed := preamble
	if looksLikeSSLRequest(preamble) {
		upgraded, uerr := upgradeListenerTLS(conn, preamble, s.cfg.ListenerTLS)
		if uerr != nil {
			log.Debug().Err(uerr).Str("remote", conn.RemoteAddr().String()).
				Msg("dbounce: listener TLS upgrade failed")
			return
		}
		if upgraded != nil {
			working = upgraded
		}
		// Whether upgraded or 'N' was sent, the next bytes from the
		// client are a fresh StartupMessage preamble.
		consumed = nil
	}

	startupBody, err := pgHandshakeWithPreamble(working, consumed)
	if err != nil {
		log.Debug().Err(err).Str("remote", conn.RemoteAddr().String()).
			Msg("dbounce: handshake failed")
		return
	}
	conn = working

	// [[agent-identity-in-audit]] Feature 1+2: parse application_name
	// from the StartupMessage body + mint a per-connection session id.
	// Best-effort: a malformed body or missing application_name results
	// in an "unknown" agent name + the session id still propagating
	// through subsequent audit events so the SIEM has a correlation
	// key even when the client identity wasn't declared.
	sessionID := s.registerPGAgentFromBody(startupBody)
	defer s.emitSessionEnded(sessionID)

	for {
		_ = conn.SetDeadline(time.Now().Add(s.cfg.IdleTimeout))
		msgType, payload, err := readPGMessage(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Debug().Err(err).Str("remote", conn.RemoteAddr().String()).
					Msg("dbounce: read message")
			}
			return
		}
		switch msgType {
		case msgTerminate:
			return
		case msgQuery:
			sql := readCString(payload)
			s.evaluateAndAuditWithAgent(sql, "Query", sessionID)
			if err := writeReadyForQuery(conn); err != nil {
				return
			}
		case msgParse:
			_ = readCString(payload) // stmt name (discarded for now)
			rest := payload[firstNullPlus1(payload):]
			sql := readCString(rest)
			s.evaluateAndAuditWithAgent(sql, "Parse", sessionID)
			if err := writeParseComplete(conn); err != nil {
				return
			}
			if err := writeReadyForQuery(conn); err != nil {
				return
			}
		case msgBind:
			if err := writeBindComplete(conn); err != nil {
				return
			}
			if err := writeReadyForQuery(conn); err != nil {
				return
			}
		case msgExecute:
			if err := writeCommandComplete(conn, "SELECT 0"); err != nil {
				return
			}
			if err := writeReadyForQuery(conn); err != nil {
				return
			}
		case msgSync:
			if err := writeReadyForQuery(conn); err != nil {
				return
			}
		case msgFlush, msgDescribe, msgClose:
			// Acked silently.
		default:
			log.Debug().Uint8("type", msgType).
				Str("remote", conn.RemoteAddr().String()).
				Msg("dbounce: unsupported wire-protocol message; closing connection")
			return
		}
	}
}

// evaluateAndAudit parses one inbound SQL statement, computes the
// D-Slice 3 composition-order verdict, and writes a row to the audit
// log.
//
// Per the audit-cadence self-check: this is where the audit row gets
// enough fact for D-Slices 7+ to JOIN against. We include statement,
// statement_type, tables, functions, decision_verdict, decision_source,
// matched_rule_id, task_id + the parser's flag bag so the recommender
// + the live-action-tail UI can compose against rows already on disk.
//
// D-Slice 8 wires two cross-cutting hooks on top of decide():
//
//  1. Pause window (per [[safety-mode-lean-permissive]] escape hatch):
//     when IsPaused() returns true, a transparent-mode DENY DEMOTES to
//     ALLOW + Enforced=false; the audit row records pause_id so post-
//     incident review can answer "what would have been blocked had the
//     pause not been active?" The DecisionReason preserves the original
//     rule-engine intent so reviewers see why the pause mattered.
//
//  2. Prompt-on-deny: when PromptOnDeny + transparent + DENY and NOT
//     paused, enqueue a pending_prompts row. The wire-protocol call
//     still gets the DENY (we can't keep the SQL client waiting on a
//     human); the prompt is an out-of-band review channel for the
//     operator to flip the rule shape via `dbounce prompts answer`.
// registerPGAgentFromBody parses a PG StartupMessage body for
// application_name, maps it to a known agent name (or stamps the
// literal value for unknown clients), and mints a session id in the
// per-process AgentRegistry. Returns the minted session id; an empty
// return is reserved for a registry-not-wired test path.
//
// Per [[agent-identity-in-audit]] Feature 1: this is best-effort
// detection. The session id ALWAYS gets minted (so SESSION_ENDED can
// fire on close + audit rows have the correlation key) even when no
// application_name was sent — name falls back to "unknown".
func (s *Server) registerPGAgentFromBody(body []byte) string {
	if s.agentRegistry == nil {
		return ""
	}
	params := audit.ParsePGStartupParams(body)
	name, rawAppName := audit.ParsePGStartupAppName(params)
	agent := audit.Agent{
		Name:         name,
		DetectedFrom: audit.DetectedFromPGAppName,
	}
	if rawAppName == "" {
		// No application_name sent. Mint anyway so the session id
		// threads through the audit; name will be normalized to
		// "unknown" inside Mint.
		agent.Name = ""
		agent.DetectedFrom = audit.DetectedFromUnknown
	}
	return s.agentRegistry.Mint(agent)
}

// evaluateAndAudit is preserved as the legacy 2-arg shape (existing
// tests pre-date [[agent-identity-in-audit]] + don't care about the
// session id). New callers — and the production serveConn path — go
// through evaluateAndAuditWithAgent so the per-connection session id
// threads onto the OCSF event.
func (s *Server) evaluateAndAudit(sql, source string) {
	s.evaluateAndAuditWithAgent(sql, source, "")
}

func (s *Server) evaluateAndAuditWithAgent(sql, source, sessionID string) {
	ps := parser.Parse(string(s.cfg.Dialect), sql)
	d := s.decide(ps)

	// D-Slice 8 pause-window demote. Consult IsPaused() up-front so the
	// audit row reflects pause-window decisions consistently regardless
	// of which downstream path consumes them.
	var pauseID *int64
	enforced := s.cfg.Mode == ModeTransparent && d.Verdict == VerdictDeny
	pauseDemoted := false
	if s.store != nil {
		if paused, pid, perr := s.store.IsPaused(); perr != nil {
			BumpLookupErrors()
			log.Warn().Err(perr).Msg("dbounce: IsPaused lookup failed")
		} else if paused {
			id := pid
			pauseID = &id
			if d.Verdict == VerdictDeny && s.cfg.Mode == ModeTransparent {
				// Demote: the rule engine wanted DENY but the pause
				// window says "let it pass with the audit record."
				enforced = false
				pauseDemoted = true
			}
		}
	}

	verdictForRow := d.Verdict
	reasonForRow := d.Reason
	if pauseDemoted {
		verdictForRow = VerdictAllow
		reasonForRow = fmt.Sprintf(
			"pause-window demoted (pause_id=%d): rule engine wanted DENY (%s)",
			*pauseID, d.Reason)
	}

	// MED-D8-09 closure: optionally redact quoted string literals in
	// the persisted Statement field. The original parser already ran
	// on the raw SQL above (so the audit row still has accurate
	// statement_type / tables / functions / parse_errors), but the
	// row's recorded SQL is now stripped of credential-shaped content.
	storedStatement := sql
	statementRedacted := false
	if s.cfg.RedactLiterals {
		storedStatement = parser.RedactLiterals(sql)
		statementRedacted = storedStatement != sql
	}

	row := store.DecisionRow{
		At:               time.Now().UTC(),
		Dialect:          ps.Dialect,
		Statement:        storedStatement,
		StatementType:    ps.StatementType,
		TablesTouched:    ps.TablesTouched,
		FunctionsCalled:  ps.FunctionsCalled,
		IsDML:            ps.IsDML,
		IsDDL:            ps.IsDDL,
		HasMutatingNode:  ps.HasMutatingNode,
		MutatingNodeType: ps.MutatingNodeType,
		IsExplain:        ps.IsExplain,
		IsExplainAnalyze: ps.IsExplainAnalyze,
		ImpersonatedRole: ps.ImpersonatedRole,
		ParseErrors:      ps.ParseErrors,
		DecisionVerdict:  string(verdictForRow),
		DecisionReason:   reasonForRow,
		ModeAtDecision:   string(s.cfg.Mode),
		// Enforcement requires (a) transparent mode AND (b) a DENY
		// verdict AND (c) D-Slice 2's forwarding wired AND (d) no
		// active pause window demoting the DENY. D-Slice 3 sets
		// (a)+(b); D-Slice 2's forwarding handler honors it.
		Enforced:       enforced,
		ProfileName:       s.cfg.ActiveProfileName,
		DecisionSource:    d.Source,
		MatchedRuleID:     d.MatchedRuleID,
		TaskID:            d.TaskID,
		PauseID:           pauseID,
		StatementRedacted: statementRedacted,
	}
	decisionID, err := s.store.RecordDecision(row)
	if err != nil {
		BumpLookupErrors()
		log.Warn().Err(err).Str("source", source).
			Msg("dbounce: record decision failed")
		return
	}

	// #252 Slice 1: fan out to configured audit-export transports
	// (JSONL log file + HTTPS webhook). No-op when neither is
	// configured. Bounded queue + drop-on-overflow inside the exporter
	// so this never blocks the proxy hot-path. Audit row remains the
	// source of truth in SQLite; this export is ADDITIVE for security-
	// team consumption. Per [[scorer-is-ground-truth]] the exporter
	// projects the row faithfully — no re-scoring, no LLM enrichment.
	//
	// [[agent-identity-in-audit]] Feature 1+2: thread sessionID so the
	// per-connection agent fingerprint (parsed from PG application_name
	// at handshake time) lands under unmapped.iam_jit.agent on every
	// audit event. Empty sessionID falls through to the no-agent path —
	// preserves the legacy event shape for callers that haven't yet
	// threaded agent context.
	s.exportDecisionRowWithAgent(row, decisionID, sessionID)

	// D-Slice 8 prompt-on-deny enqueue. We only enqueue when:
	//   - prompt-on-deny is enabled
	//   - the decision was a DENY
	//   - we're in transparent mode (cooperative DENYs are advisory; an
	//     async prompt for an advisory verdict would be noise)
	//   - the pause window did NOT demote (a demoted DENY is "the
	//     operator already said let it through; no prompt needed")
	if s.cfg.PromptOnDeny && d.Verdict == VerdictDeny &&
		s.cfg.Mode == ModeTransparent && !pauseDemoted && s.store != nil {
		_, perr := s.store.AddPendingPrompt(store.PendingPrompt{
			DecisionID:      decisionID,
			StatementType:   ps.StatementType,
			TablesTouched:   ps.TablesTouched,
			FunctionsCalled: ps.FunctionsCalled,
			DenyReason:      d.Reason,
		})
		if perr != nil {
			BumpLookupErrors()
			log.Warn().Err(perr).
				Int64("decision_id", decisionID).
				Msg("dbounce: enqueue pending prompt failed")
		}
	}
}

// decide runs the D-Slice 3 composition order over a parsed statement
// and returns a Decision packet. The composition order is load-bearing
// — a single bug here turns the entire safety story upside down — so
// it's written in strict step-by-step form that mirrors the Python
// decisions.py and kbounce's EvaluateRequestFull semantics.
//
// Composition order (each step is fall-through unless it short-circuits):
//
//  1. Profile keyword-deny / verb-deny / account-deny (HARD FLOOR;
//     D-Slice 7 fills this; D-Slice 3 leaves a no-op placeholder).
//  2. Profile allow rules (D-Slice 7).
//  3. Active task scope's DENY rules → DENY (task-explicit-deny beats
//     EVERYTHING below — the agent saying "no prod" is binding even
//     when global rules would have allowed).
//  4. Global rules from the rules table — first-match (within the
//     matcher, DENY beats ALLOW).
//     - Global DENY → DENY (fires regardless of task scope; the admin's
//       baseline can't be overridden by a task-allow).
//     - Global ALLOW match noted but not committed; task-allow may
//       still override depending on step 5.
//  5. Active task scope's ALLOW rules → ALLOW.
//     - Task-allow match → ALLOW.
//     - With a task active and no task-allow match:
//         * Global ALLOW matched in step 4 → ALLOW (the global
//           baseline still blessed this; the task didn't reject it).
//         * Otherwise → DENY out-of-task-scope (the agent's positive
//           declaration IS the allowlist when a task is active).
//  6. No task active + no rule matched → default-policy fall-through.
//
// Per [[creates-never-mutates]]: this function NEVER mutates state.
// All side effects (audit write) live in evaluateAndAudit.
//
// Per the audit-cadence self-check: the order above is the SINGLE
// authoritative document. Any future slice that re-orders steps MUST
// update this comment + add a regression test that proves the new
// order against the BB+WB scenarios in proxy_test.go.
func (s *Server) decide(ps *parser.ParsedStatement) Decision {
	// Step 1+2: profile gates. D-Slice 7 wires the safe-default
	// environment profile + its AST-walk Layer 2 backstop. The profile
	// evaluator runs deny_keywords → deny_actions → allow_baseline +
	// deny_ast_mutating_nodes → allow_rules in that order. A profile
	// deny short-circuits the whole composition order (HARD FLOOR);
	// a profile allow short-circuits with Source=profile.allow so a
	// permissive task scope can't lower the bar further. Abstain →
	// fall through to the task / global rules below.
	if s.cfg.ActiveProfile != nil && s.cfg.ActiveProfile.Name != profile.FullUserProfileName {
		profileView := &profile.ParsedStatement{
			StatementType:    ps.StatementType,
			TablesTouched:    ps.TablesTouched,
			FunctionsCalled:  ps.FunctionsCalled,
			IsDML:            ps.IsDML,
			IsDDL:            ps.IsDDL,
			HasMutatingNode:  ps.HasMutatingNode,
			IsExplain:        ps.IsExplain,
			IsExplainAnalyze: ps.IsExplainAnalyze,
		}
		pv := s.cfg.ActiveProfile.Evaluate(profileView)
		if pv.Denied {
			return Decision{
				Verdict: VerdictDeny,
				Reason:  pv.Reason,
				Source:  SourceProfile,
			}
		}
		if pv.Allowed {
			return Decision{
				Verdict: VerdictAllow,
				Reason:  pv.Reason,
				Source:  pv.Source, // "profile.allow"
			}
		}
	}

	// Build the rules-package view of the statement. Symmetric to
	// kbounce's ruleReq construction (kept distinct from
	// parser.ParsedStatement so the rule engine has no parser-pkg
	// dependency).
	stmtView := &dbrules.ParsedStatement{
		StatementType:    ps.StatementType,
		TablesTouched:    ps.TablesTouched,
		FunctionsCalled:  ps.FunctionsCalled,
		IsDML:            ps.IsDML,
		IsDDL:            ps.IsDDL,
		HasMutatingNode:  ps.HasMutatingNode,
		IsExplain:        ps.IsExplain,
		IsExplainAnalyze: ps.IsExplainAnalyze,
	}

	// Step 3 setup: load the active task (if any). Read failure is
	// logged + treated as "no active task" so a transient SQLite hiccup
	// doesn't crash the proxy. Same policy as kbounce + ibounce.
	var activeTask *tasks.Scope
	if s.store != nil {
		at, terr := s.store.GetActiveTask("")
		if terr != nil {
			BumpLookupErrors()
			log.Warn().Err(terr).Msg("dbounce: active-task lookup failed")
		} else {
			activeTask = at
		}
	}

	// Step 3: task-explicit-deny short-circuits with DENY.
	if activeTask != nil {
		if td := activeTask.DenyRuleSet().Evaluate(stmtView); td != nil {
			return Decision{
				Verdict: VerdictDeny,
				Reason: fmt.Sprintf(
					"task-explicit-deny (task %s, pattern %q)",
					activeTask.TaskID, td.Rule.Pattern),
				Source: SourceTaskDeny,
				TaskID: activeTask.TaskID,
			}
		}
	}

	// Step 4: global rules from the rules table. Loaded fresh per
	// decision in D-Slice 3 (small table; if it grows we'll add an
	// in-memory cache invalidated by a config-event hook).
	var ruleSet *dbrules.RuleSet
	if s.store != nil {
		rs, rerr := s.store.LoadRuleSet()
		if rerr != nil {
			BumpLookupErrors()
			log.Warn().Err(rerr).Msg("dbounce: load ruleset failed")
		} else {
			ruleSet = rs
		}
	}
	var globalMatch *dbrules.EvalResult
	if ruleSet != nil {
		globalMatch = ruleSet.Evaluate(stmtView)
	}
	if globalMatch != nil && globalMatch.Effect == dbrules.EffectDeny {
		return Decision{
			Verdict: VerdictDeny,
			Reason: fmt.Sprintf(
				"explicit-deny rule (pattern %q)", globalMatch.Rule.Pattern),
			Source: SourceGlobalDeny,
			TaskID: taskIDOrEmpty(activeTask),
		}
	}

	// Step 5: task-allow (when a task is active).
	if activeTask != nil {
		if ta := activeTask.AllowRuleSet().Evaluate(stmtView); ta != nil && ta.Effect == dbrules.EffectAllow {
			return Decision{
				Verdict: VerdictAllow,
				Reason: fmt.Sprintf(
					"task-allow rule (task %s, pattern %q)",
					activeTask.TaskID, ta.Rule.Pattern),
				Source: SourceTaskAllow,
				TaskID: activeTask.TaskID,
			}
		}
		// With a task active and no task-allow match: global-allow can
		// still let infrastructure calls through (per kbounce + Python
		// decisions.py composition). Otherwise it's out-of-task-scope.
		if globalMatch != nil && globalMatch.Effect == dbrules.EffectAllow {
			return Decision{
				Verdict: VerdictAllow,
				Reason: fmt.Sprintf(
					"explicit-allow rule (global, pattern %q; not declared in task %s)",
					globalMatch.Rule.Pattern, activeTask.TaskID),
				Source: SourceGlobalAllow,
				TaskID: activeTask.TaskID,
			}
		}
		return Decision{
			Verdict: VerdictDeny,
			Reason: fmt.Sprintf(
				"out-of-task-scope (task %s active; unmatched by task allow rules)",
				activeTask.TaskID),
			Source: SourceTaskDeny,
			TaskID: activeTask.TaskID,
		}
	}

	// No active task: a global explicit-allow stands if it matched.
	if globalMatch != nil && globalMatch.Effect == dbrules.EffectAllow {
		return Decision{
			Verdict: VerdictAllow,
			Reason: fmt.Sprintf(
				"explicit-allow rule (pattern %q)", globalMatch.Rule.Pattern),
			Source: SourceGlobalAllow,
		}
	}

	// Step 6: default-policy fall-through.
	verdict := VerdictAllow
	reason := "default policy: allow (no rule matched)"
	if s.cfg.DefaultPolicy == DefaultPolicyDeny {
		verdict = VerdictDeny
		reason = "default policy: deny (no rule matched)"
	}
	return Decision{
		Verdict: verdict,
		Reason:  reason,
		Source:  SourceDefault,
	}
}

// taskIDOrEmpty returns the active task id or "" when nil. Tiny helper
// to keep the decide() short-circuits readable.
func taskIDOrEmpty(at *tasks.Scope) string {
	if at == nil {
		return ""
	}
	return at.TaskID
}

// healthz responds 200 with a small JSON liveness payload. Bypasses
// the SQL-wire listener entirely; never writes audit rows.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	type HealthzPause struct {
		ID        int64  `json:"id"`
		StartedAt string `json:"started_at"`
		EndsAt    string `json:"ends_at"`
		Reason    string `json:"reason,omitempty"`
	}
	// #252 Slice 1: surface the audit-export transport status on
	// /healthz so monitors can alert on drop spikes / persistent
	// webhook failures. The Stats() snapshot is race-free + NEVER
	// contains the bearer token (WebhookStats.URLRedacted is the
	// userinfo-masked URL; the token is in the Authorization header
	// only). Per the spec docstring: token absence from /healthz is
	// a tested invariant.
	type HealthzAuditExport = audit.ExporterStatus
	payload := struct {
		Status              string             `json:"status"`
		Mode                string             `json:"mode"`
		DefaultPolicy       string             `json:"default_policy"`
		Dialect             string             `json:"dialect"`
		ActiveProfile       string             `json:"active_profile"`
		DecisionsCount      int64              `json:"decisions_count"`
		LookupErrorsCounter int64              `json:"lookup_errors_counter"`
		Pause               *HealthzPause      `json:"pause"`
		AuditExport         *HealthzAuditExport `json:"audit_export,omitempty"`
	}{
		Status:              "ok",
		Mode:                string(s.cfg.Mode),
		DefaultPolicy:       string(s.cfg.DefaultPolicy),
		Dialect:             string(s.cfg.Dialect),
		ActiveProfile:       s.cfg.ActiveProfileName,
		LookupErrorsCounter: LookupErrorsCount(),
	}
	if s.store != nil {
		if n, err := s.store.CountDecisions(); err == nil {
			payload.DecisionsCount = n
		} else {
			payload.Status = "degraded"
		}
		if active, err := s.store.GetActivePause(); err == nil && active != nil {
			payload.Pause = &HealthzPause{
				ID:        active.ID,
				StartedAt: active.StartedAt,
				EndsAt:    active.EndsAt,
				Reason:    active.Reason,
			}
		}
	}
	if s.auditExporter != nil && s.auditExporter.Enabled() {
		st := s.auditExporter.Status()
		payload.AuditExport = &st
	}
	w.WriteHeader(http.StatusOK)
	if err := writeJSON(w, payload); err != nil {
		log.Warn().Err(err).Msg("dbounce: encode /healthz failed")
	}
}

// EnsureLogger applies a minimal zerolog config when the caller has
// not set one.
func EnsureLogger() {
	zerolog.TimeFieldFormat = time.RFC3339
	level := zerolog.InfoLevel
	if v := lookupEnv("DBOUNCE_LOG_LEVEL"); v != "" {
		if parsed, err := zerolog.ParseLevel(v); err == nil {
			level = parsed
		}
	}
	zerolog.SetGlobalLevel(level)
}

// ParseMode parses a CLI flag value into a Mode.
func ParseMode(s string) (Mode, error) {
	m := Mode(s)
	if m.IsValid() {
		return m, nil
	}
	return "", fmt.Errorf("dbounce: unknown mode %q (want cooperative | transparent)", s)
}

// ParseDefaultPolicy parses a CLI flag value into a DefaultPolicy.
func ParseDefaultPolicy(s string) (DefaultPolicy, error) {
	p := DefaultPolicy(s)
	if p.IsValid() {
		return p, nil
	}
	return "", fmt.Errorf("dbounce: unknown default-policy %q (want allow | deny)", s)
}

// ParseDialect parses a CLI flag value into a Dialect.
func ParseDialect(s string) (Dialect, error) {
	d := Dialect(s)
	if d.IsValid() {
		return d, nil
	}
	return "", fmt.Errorf("dbounce: unknown dialect %q (want postgres, mysql, snowflake, or bigquery)", s)
}

// ---------------------------------------------------------------------------
// PostgreSQL wire-protocol helpers (D-Slice 1 minimum)
// ---------------------------------------------------------------------------

const (
	msgQuery     byte = 'Q'
	msgParse     byte = 'P'
	msgBind      byte = 'B'
	msgExecute   byte = 'E'
	msgSync      byte = 'S'
	msgFlush     byte = 'H'
	msgDescribe  byte = 'D'
	msgClose     byte = 'C'
	msgTerminate byte = 'X'
)

// pgHandshakeWithPreamble runs the post-SSL plaintext PG handshake.
// preamble, when non-nil + 8 bytes, is a pre-read startup header (used
// after D-Slice 4's TLS upgrade path has already consumed bytes from
// the wire). Nil = read fresh.
//
// Returns the StartupMessage body bytes (the parameters block after
// the 4-byte protocol version) so the caller can parse
// application_name + other params per [[agent-identity-in-audit]]
// Feature 1. Empty body is valid (PG allows a connection with no
// parameters); a nil return is reserved for the error case.
func pgHandshakeWithPreamble(conn net.Conn, preamble []byte) ([]byte, error) {
	hdr := preamble
	if hdr == nil {
		hdr = make([]byte, 8)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return nil, fmt.Errorf("read startup header: %w", err)
		}
	} else if len(hdr) != 8 {
		return nil, fmt.Errorf("preamble must be 8 bytes (got %d)", len(hdr))
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	magic := binary.BigEndian.Uint32(hdr[4:8])

	if magic == 80877103 {
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return nil, fmt.Errorf("write SSL-no: %w", err)
		}
		hdr = make([]byte, 8)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return nil, fmt.Errorf("read second startup header: %w", err)
		}
		length = binary.BigEndian.Uint32(hdr[0:4])
		magic = binary.BigEndian.Uint32(hdr[4:8])
	}

	if magic == 80877104 {
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return nil, fmt.Errorf("write GSS-no: %w", err)
		}
		hdr = make([]byte, 8)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return nil, fmt.Errorf("read third startup header: %w", err)
		}
		length = binary.BigEndian.Uint32(hdr[0:4])
		magic = binary.BigEndian.Uint32(hdr[4:8])
	}

	if magic == 80877102 {
		return nil, errors.New("CancelRequest received; nothing to cancel in D-Slice 1")
	}

	if length < 8 || length > 1<<20 {
		return nil, fmt.Errorf("implausible startup length: %d", length)
	}
	body := make([]byte, length-8)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("read startup body: %w", err)
	}

	if err := writeMessage(conn, 'R', []byte{0, 0, 0, 0}); err != nil {
		return nil, err
	}
	bkd := make([]byte, 8)
	binary.BigEndian.PutUint32(bkd[0:4], 1)
	binary.BigEndian.PutUint32(bkd[4:8], 0)
	if err := writeMessage(conn, 'K', bkd); err != nil {
		return nil, err
	}
	if err := writeMessage(conn, 'Z', []byte{'I'}); err != nil {
		return nil, err
	}
	return body, nil
}

// pgHandshake is the legacy entry point preserved for compatibility
// with existing tests. New paths should call pgHandshakeWithPreamble
// directly.
func pgHandshake(conn net.Conn) error {
	_, err := pgHandshakeWithPreamble(conn, nil)
	return err
}

func readPGMessage(conn net.Conn) (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, err
	}
	msgType := hdr[0]
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length < 4 || length > 16<<20 {
		return 0, nil, fmt.Errorf("implausible message length: %d", length)
	}
	payload := make([]byte, length-4)
	if length > 4 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, nil, err
		}
	}
	return msgType, payload, nil
}

func writeMessage(conn net.Conn, msgType byte, payload []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = msgType
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
	if _, err := conn.Write(hdr); err != nil {
		return fmt.Errorf("write %c header: %w", msgType, err)
	}
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return fmt.Errorf("write %c payload: %w", msgType, err)
		}
	}
	return nil
}

func writeReadyForQuery(conn net.Conn) error {
	return writeMessage(conn, 'Z', []byte{'I'})
}

func writeParseComplete(conn net.Conn) error {
	return writeMessage(conn, '1', nil)
}

func writeBindComplete(conn net.Conn) error {
	return writeMessage(conn, '2', nil)
}

func writeCommandComplete(conn net.Conn, tag string) error {
	payload := append([]byte(tag), 0)
	return writeMessage(conn, 'C', payload)
}

func readCString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func firstNullPlus1(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i + 1
		}
	}
	return len(b)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func writeJSON(w io.Writer, v any) error {
	return jsonEncode(w, v)
}

func lookupEnv(key string) string { return osLookupEnv(key) }

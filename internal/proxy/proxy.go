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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/dbounce/internal/anomaly"
	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/decision"
	"github.com/trsreagan3/dbounce/internal/dynamicdeny"
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

	// AuditEventsToken (#271) is the bearer token clients must present
	// on GET /audit/events when the mgmt port is bound off-loopback.
	// Empty + loopback mgmt host = no auth (the loopback bind is the
	// trust anchor); empty + external mgmt host = the CLI refuses to
	// start.
	AuditEventsToken string

	// DynamicDenyWatcher (#324c) is the dbounce-side consumer of the
	// cross-product `~/.iam-jit/dynamic-denies.yaml` channel. When
	// non-nil, the proxy consults the watcher's instance-denied flag
	// before accepting EACH new connection — a denied instance refuses
	// new connections at PG StartupMessage with SQLSTATE 42501 and a
	// structured reason naming the rule_id. Existing connections
	// continue normally (don't kill mid-transaction per
	// [[ibounce-honest-positioning]]).
	DynamicDenyWatcher *dynamicdeny.Watcher

	// UpstreamRDSARN (#324c) is the optional operator-supplied RDS ARN
	// the dynamic-deny matcher compares each rule's `arn:aws:rds:*`
	// targets against. Empty disables RDS-ARN matching; the matcher
	// still consults the hostname axis derived from `--upstream`.
	UpstreamRDSARN string

	// DiskPressure (#461 / §A63c) is the optional disk-pressure
	// circuit-breaker state. When non-nil the proxy:
	//   - surfaces an audit_log block on /healthz with disk usage +
	//     mode + refuse_requests flag,
	//   - refuses new DB connections with a PG ErrorResponse
	//     SQLSTATE 53300 ("too many connections" — closest standard
	//     SQLSTATE for "server unwilling to accept connections") on
	//     every accept when state.RefuseRequests() reports true
	//     (pause-requests mode at critical / emergency),
	//   - starts a background periodic goroutine in Serve() that ticks
	//     every DiskPressureCheckInterval to re-evaluate state +
	//     emit admin-action disk_pressure.transition OCSF events on
	//     status changes.
	// When nil the proxy behavior is byte-identical to the pre-#461
	// shape per [[creates-never-mutates]].
	DiskPressure *audit.DiskPressureState
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

	// #718 ADOPT-4 — Phase H behavioral-deviation / anomaly detector.
	// Nil disables the channel. When wired (anomaly_detection.enabled),
	// every decision is observed into a per-agent behavioral baseline +
	// scored for deviation; an anomalous verdict surfaces a NEUTRAL OCSF
	// anomaly_detected event. ALERT by default (never blocks) per
	// [[safety-mode-lean-permissive]].
	anomalyDetector *anomaly.Detector
	anomalyMu       sync.Mutex
	anomalyRecent   []map[string]any

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
	//
	// The burst sweeper goroutine (runBurstSweeper, per
	// [[bulk-prompt-answer-ux]]) also joins via connWG so Shutdown
	// drains it on the same wait — mirrors the heartbeater shutdown
	// ordering closed in 276298f.
	connWG sync.WaitGroup

	// burst is the bulk-prompt-answer burst detector per
	// [[bulk-prompt-answer-ux]]. nil when disabled (zero threshold);
	// non-nil + Record-called by evaluateAndAuditWithAgent when a
	// pending prompt is enqueued. Reset by `dbounce prompts
	// bulk-answer` after the operator has resolved the burst.
	burst *BurstDetector

	// profileMu guards activeProfile + activeProfileName for the
	// hot-swap path per [[bulk-prompt-answer-ux]]. decide() takes a
	// read-lock per evaluation; SwapProfile takes a write-lock. RWMutex
	// because the read path is hot + the swap path is rare (operator
	// answers a burst).
	profileMu         sync.RWMutex
	activeProfile     *profile.Profile
	activeProfileName string

	// profilesPath is the on-disk profiles.yaml the proxy was started
	// with; the burst sweeper reads it when applying a profile-swap
	// signal (so the hot-swap loads from the SAME source the operator
	// invoked `dbounce run --profiles-path X` with — not whatever
	// path a parallel CLI happens to point at). Empty = the
	// profile.DefaultProfilesPath() lookup runs.
	profilesPath string

	// burstSweeperCancel is the context.CancelFunc the burst sweeper
	// goroutine listens on. Set in Serve when the sweeper is started;
	// invoked by Shutdown BEFORE waiting on connWG so the sweeper
	// stops promptly (per the heartbeater shutdown ordering closed in
	// 276298f). nil-safe.
	burstSweeperCancel context.CancelFunc

	// auditEventsPollerCancel is the context.CancelFunc the Slice 2
	// cross-process audit-event poller goroutine listens on per
	// [[security-team-audit-export]]. Same shutdown-ordering
	// constraint as burstSweeperCancel: invoked by Shutdown BEFORE
	// connWG.Wait so the 1s-cadence ticker exits + the goroutine's
	// connWG.Done fires. nil-safe.
	auditEventsPollerCancel context.CancelFunc

	// diskPressureCancel is the context.CancelFunc the #461 / §A63c
	// disk-pressure check loop listens on. Same shutdown-ordering
	// constraint as the burst sweeper: cancelled by Shutdown BEFORE
	// connWG.Wait so the periodic ticker exits + the admin-action
	// emit channel can drain. nil-safe.
	diskPressureCancel context.CancelFunc

	// totalAgentHeadersRejected (#318 / §A16) counts inbound
	// `application_name` values that match the canonical
	// `iam-jit-agent:NAME:SESSIONID` cross-bouncer prefix but fail
	// validation. Surfaced via /healthz so operators see agent-config
	// drift (e.g. an agent setting application_name to a shell-injection
	// payload). Mirrors gbounce + ibounce + kbouncer counter of the same
	// name byte-for-byte per [[cross-product-agent-parity]].
	totalAgentHeadersRejected atomic.Int64

	// #324c — dynamic-deny watcher. May be nil (FREE-tier default; the
	// CLI passed --disable-dynamic-denies OR no path could be resolved).
	// Hot-path readers consult InstanceDenied() before accepting a new
	// connection; reloads emit OCSF admin-action events via the
	// watcher's EmitFunc + transition between accept / refuse posture.
	dynamicDeny *dynamicdeny.Watcher

	// #324c — counters surfaced via /healthz so an operator monitor sees
	// dynamic-deny activity without grepping the audit log.
	totalDynamicDenyConnectionsRefused atomic.Int64
	totalDynamicDenyReloads            atomic.Int64
	totalDynamicDenyParseErrors        atomic.Int64

	// §A40 — counter surfaced via /healthz so an operator monitor sees
	// profile-scope refusals (an agent repeatedly trying a misconfigured
	// upstream against a scoped profile) without grepping the audit log.
	// Bumped from Forwarder.refuseIfProfileScopeViolation +
	// observation-only profile-scope refuse paths.
	totalProfileScopeRefused atomic.Int64
}

// recordRejectedAgentTag bumps the per-Server rejection counter + logs
// one stderr line for an `application_name=iam-jit-agent:...` value
// that failed validation. Mirrors gbounce's `logAgentHeaderRejected`
// + ibounce's `_log_agent_header_rejected` + kbouncer's
// `recordRejectedAgentHeader` — same wire-protocol-equivalent
// rejection-surface so operators get the same signal across the suite.
//
// Per [[security-team-positioning-safety-not-surveillance]]: surfacing
// the rejection is SAFETY (operator sees attribution gap); the
// truncation + control-char stripping are privacy-shaped (a malicious
// value can't reposition the operator's terminal cursor). The raw
// value is NEVER written into the audit event regardless.
func (s *Server) recordRejectedAgentTag(rawValue string) {
	if s == nil {
		return
	}
	s.totalAgentHeadersRejected.Add(1)
	truncated := rawValue
	if len(truncated) > 64 {
		truncated = truncated[:64] + "..."
	}
	clean := make([]byte, 0, len(truncated))
	for i := 0; i < len(truncated); i++ {
		c := truncated[i]
		if c < 0x20 || c > 0x7e {
			clean = append(clean, '?')
		} else {
			clean = append(clean, c)
		}
	}
	log.Warn().
		Str("application_name", string(clean)).
		Msg("dbounce: rejected invalid iam-jit-agent: application_name tag — connection audited as anonymous")
}

// NewServer constructs a Server without starting it.
func NewServer(cfg Config, st *store.Store) *Server {
	nc := cfg.Normalize()
	s := &Server{
		cfg:               nc,
		store:             st,
		agentRegistry:     audit.NewAgentRegistry(),
		activeProfile:     nc.ActiveProfile,
		activeProfileName: nc.ActiveProfileName,
		dynamicDeny:       nc.DynamicDenyWatcher,
	}
	// Bulk-prompt-answer UX per [[bulk-prompt-answer-ux]]: detector
	// always-on by default. Operators who explicitly want to disable
	// the burst flow can build with a custom BurstDetector (future
	// config knob); v1.0 ships with sane defaults to make the safety
	// valve discoverable.
	s.burst = NewBurstDetector(DefaultBurstThreshold, DefaultBurstWindow, DefaultBurstCooldown)
	return s
}

// SetProfilesPath records the on-disk profiles.yaml path so the burst
// sweeper goroutine can reload + hot-swap the active profile when a
// bulk-answer override is posted per [[bulk-prompt-answer-ux]]. Empty
// string is valid (resolver falls back to profile.DefaultProfilesPath).
// Idempotent; safe to call before Serve.
func (s *Server) SetProfilesPath(path string) { s.profilesPath = path }

// ProfilesPath returns the on-disk profiles.yaml path the proxy was
// started with. Exposed so tests can verify the path was wired through
// + so future introspection can surface it.
func (s *Server) ProfilesPath() string { return s.profilesPath }

// BurstDetector returns the bulk-prompt-answer burst detector. May be
// nil when explicitly disabled. Exposed so tests + the CLI / MCP
// surfaces can render the snapshot.
func (s *Server) BurstDetector() *BurstDetector { return s.burst }

// SwapProfile atomically replaces the active profile per
// [[bulk-prompt-answer-ux]] hot-swap. Safe for concurrent callers
// (write-lock). The next decide() call sees the new profile. Nil is
// accepted (resets to full-user equivalent).
func (s *Server) SwapProfile(p *profile.Profile) {
	s.profileMu.Lock()
	defer s.profileMu.Unlock()
	s.activeProfile = p
	if p != nil {
		s.activeProfileName = p.Name
	} else {
		s.activeProfileName = ""
	}
}

// loadActiveProfile is the hot-path read for decide() + healthz +
// audit. Read-locks the profile mutex so SwapProfile can race
// uncoordinated. Returns the pointer (no copy — Profile is
// effectively-immutable post-construction; loader-level edits go via
// a fresh *Profile that SwapProfile installs).
func (s *Server) loadActiveProfile() (*profile.Profile, string) {
	s.profileMu.RLock()
	defer s.profileMu.RUnlock()
	return s.activeProfile, s.activeProfileName
}

// ActiveProfileName returns the currently-active profile name (after
// any hot-swap). Used by the burst sweeper to compare against the
// pending override + by /healthz to render the current state. Empty
// when no profile bound (full-user equivalent).
func (s *Server) ActiveProfileName() string {
	_, name := s.loadActiveProfile()
	return name
}

// activeProfileNameSnapshot is the audit-write companion. Same as
// ActiveProfileName but kept internal to make grep'ing audit-row
// projections easier.
func (s *Server) activeProfileNameSnapshot() string {
	_, name := s.loadActiveProfile()
	return name
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
	// #718 ADOPT-4 — Phase H behavioral-deviation tap. Runs INDEPENDENT
	// of the audit-export / alert engines (it's a separate channel), so
	// it sits ahead of the exporter/alerts early-return below. Observes
	// the decision into the per-agent baseline + scores it; an anomalous
	// verdict surfaces a NEUTRAL signal. Fail-soft + no-op when unwired.
	// ALERT by default; never blocks per [[safety-mode-lean-permissive]].
	s.observeAnomaly(sqlAnomalyAgent(s, sessionID), row)

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

// emitAdminFallback fires the ADMIN_FALLBACK synthetic on the wired
// Exporter + RuleEngine per [[security-team-audit-export]] Slice 2.
// Called from evaluateAndAuditWithAgent IMMEDIATELY AFTER the
// decision event is exported, so the SIEM sees the decision row
// first + then the synthetic that explains the demote.
//
// Nil-safe: when neither Exporter nor RuleEngine is wired (FREE-tier
// default), the function is a no-op. Best-effort emit — the
// ObserveDecision shape is fire-and-forget per the Slice 2 spec, and
// a failed alert MUST NOT take down the proxy hot path.
func (s *Server) emitAdminFallback(info audit.AdminFallbackInfo) {
	exporterOn := s.auditExporter != nil && s.auditExporter.Enabled()
	alertsOn := s.alertEngine != nil && s.alertEngine.Enabled()
	if !exporterOn && !alertsOn {
		return
	}
	// Look up the pause window's started_by + reason so the synthetic
	// carries the human-readable triage context. Best-effort: a store
	// lookup failure surfaces as an unannotated synthetic (still has
	// pause_id + decision_id, which is the load-bearing JOIN key).
	if s.store != nil {
		if active, err := s.store.GetActivePause(); err == nil && active != nil &&
			active.ID == info.PauseID {
			info.StartedBy = active.StartedBy
			info.Reason = active.Reason
		}
	}
	evt := audit.NewAdminFallbackEvent(s.listenerAddr(), info)
	if exporterOn {
		_ = s.auditExporter.Emit(context.Background(), evt)
	}
	if alertsOn {
		s.alertEngine.ObserveDecision(context.Background(), evt)
	}
}

// emitAdminFallbackEnd fires the ADMIN_FALLBACK_END synthetic on the
// wired Exporter + RuleEngine. Called from
// runPendingAuditEventsPoller when an ADMIN_FALLBACK_END row is
// drained from the cross-process queue (the queue is fed by
// store.StopPause + store.GetActivePause's expiry GC +
// store.StartPause's supersede branch — all three close-paths funnel
// through the same synthetic).
//
// Nil-safe + best-effort identical to emitAdminFallback.
func (s *Server) emitAdminFallbackEnd(info audit.AdminFallbackInfo) {
	exporterOn := s.auditExporter != nil && s.auditExporter.Enabled()
	alertsOn := s.alertEngine != nil && s.alertEngine.Enabled()
	if !exporterOn && !alertsOn {
		return
	}
	evt := audit.NewAdminFallbackEndEvent(s.listenerAddr(), info)
	if exporterOn {
		_ = s.auditExporter.Emit(context.Background(), evt)
	}
	if alertsOn {
		s.alertEngine.ObserveDecision(context.Background(), evt)
	}
}

// emitProfileInstalled fires the PROFILE_INSTALLED synthetic on the
// wired Exporter AND the non_org_profile_install alert (via
// RuleEngine.ObserveProfileInstall) per the Slice 2 spec. Called from
// runPendingAuditEventsPoller when a PROFILE_INSTALLED row is drained
// from the cross-process queue (the queue is fed by `dbounce profile
// install --from URL` which runs in a SEPARATE process from `dbounce
// run` — Option A: SQLite queue with 1s drain cadence per the spec).
//
// Nil-safe + best-effort. The RuleEngine.ObserveProfileInstall hook
// pattern-matches the source URL against the operator-configured
// org-source allowlist + fires a SECURITY_ALERT when the URL isn't
// on the allowlist — that alert AND this lifecycle event flow through
// the same Exporter so the SIEM sees both signals chronologically.
func (s *Server) emitProfileInstalled(info audit.ProfileInstalledInfo) {
	exporterOn := s.auditExporter != nil && s.auditExporter.Enabled()
	alertsOn := s.alertEngine != nil && s.alertEngine.Enabled()
	if !exporterOn && !alertsOn {
		return
	}
	evt := audit.NewProfileInstalledEvent(s.listenerAddr(), info)
	if exporterOn {
		_ = s.auditExporter.Emit(context.Background(), evt)
	}
	if alertsOn {
		// Lifecycle observe path (so the synthetic itself counts in
		// rule-engine stats / no-fires-on-synthetics guard).
		s.alertEngine.ObserveDecision(context.Background(), evt)
		// Non-org-source alert path: this is the load-bearing
		// observability signal per the Slice 2 spec — the rule
		// engine's non_org_profile_install matcher fires here.
		s.alertEngine.ObserveProfileInstall(context.Background(),
			audit.InstallObservation{
				SourceURL:      info.SourceURL,
				ProfileNames:   info.ProfileNames,
				SHA256:         info.SHA256,
				SHA256Verified: info.SHA256Verified,
			})
	}
}

// emitAdminAction fires the ADMIN_ACTION synthetic on the wired
// Exporter + RuleEngine per [[basic-app-hygiene-features]] TIER 1 #4
// + [[security-team-audit-export]] admin-action wiring. Called from
// runPendingAuditEventsPoller when an ADMIN_ACTION row is drained
// from the cross-process queue. Every admin CLI subcommand runs in a
// separate process from `dbounce run`, so the SQLite queue is the
// only path; this method is NEVER called from in-process code paths.
//
// Nil-safe + best-effort identical to emitAdminFallbackEnd. The
// RuleEngine.ObserveDecision feed lets a future alert rule key on
// config_change.action without re-routing the synthetic.
func (s *Server) emitAdminAction(info audit.AdminActionInfo) {
	exporterOn := s.auditExporter != nil && s.auditExporter.Enabled()
	alertsOn := s.alertEngine != nil && s.alertEngine.Enabled()
	if !exporterOn && !alertsOn {
		return
	}
	evt := audit.NewAdminActionEvent(s.listenerAddr(), info)
	if exporterOn {
		_ = s.auditExporter.Emit(context.Background(), evt)
	}
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

// refuseObservationProfileScopeViolation is the observation-only
// counterpart to Forwarder.refuseIfProfileScopeViolation. The proxy
// has no upstream configured but the operator may still want OnlyHosts
// / OnlyDatabases enforcement (e.g. running `dbounce run --profile
// staging-only` without an upstream as a dry-run gate). Returns true
// when the connection was refused — caller must close + return.
//
// Database resolution: PG StartupMessage `database` param only (no
// upstream URL to fall back on). Host resolution: empty (no upstream)
// — when OnlyHosts is set on observation-only mode we still ENFORCE
// (an empty host never matches a non-empty allowlist, per the
// fail-closed shape in matchAnyHostGlob), surfacing "you scoped the
// profile to hosts but didn't configure an upstream" as a refusal +
// audit signal. Loud failure beats silent permit.
func (s *Server) refuseObservationProfileScopeViolation(conn net.Conn, startupBody []byte) bool {
	activeProfile, _ := s.loadActiveProfile()
	if activeProfile == nil || activeProfile.Name == profile.FullUserProfileName {
		return false
	}
	if len(activeProfile.OnlyHosts) == 0 && len(activeProfile.OnlyDatabases) == 0 {
		return false
	}
	host := ""
	if s.cfg.Upstream != nil {
		host = s.cfg.Upstream.HostnameOnly()
	}
	database := ""
	params := audit.ParsePGStartupParams(startupBody)
	if d := strings.TrimSpace(params["database"]); d != "" {
		database = d
	} else if s.cfg.Upstream != nil {
		database = s.cfg.Upstream.Database()
	}
	// Host check first (matches forwarder ordering for parity).
	verdict := activeProfile.EvaluateConnectionHost(host)
	if !verdict.Denied {
		verdict = activeProfile.EvaluateConnectionDatabase(database)
	}
	if !verdict.Denied {
		return false
	}
	s.totalProfileScopeRefused.Add(1)
	msg := fmt.Sprintf("dbounce: %s", verdict.Reason)
	if werr := writePGScopeRefusalErrorResponse(conn, verdict.DenyReason, msg); werr != nil {
		log.Debug().Err(werr).
			Str("remote", conn.RemoteAddr().String()).
			Str("deny_reason", verdict.DenyReason).
			Msg("dbounce: write profile-scope refusal (observation-only) failed")
	}
	s.emitProfileScopeRefused(audit.ProfileScopeRefusedInfo{
		ProfileName: verdict.ProfileName,
		DenyReason:  verdict.DenyReason,
		Reason:      verdict.Reason,
		Host:        host,
		Database:    database,
		RemoteAddr:  conn.RemoteAddr().String(),
	})
	log.Warn().
		Str("remote", conn.RemoteAddr().String()).
		Str("profile", verdict.ProfileName).
		Str("deny_reason", verdict.DenyReason).
		Str("upstream_host", host).
		Str("database", database).
		Msg("dbounce: refused new connection by profile scope (observation-only)")
	return true
}

// emitProfileScopeRefused fires the §A40 profile-scope-refused
// synthetic on the wired Exporter + RuleEngine. Called from the PG
// forwarder + observation-only PG path when the active profile's
// OnlyHosts / OnlyDatabases scope refused the inbound connection.
//
// Nil-safe + best-effort identical to emitProfileInstalled. The
// RuleEngine.ObserveDecision feed lets a future alert rule key on
// deny_source="profile_scope" without re-routing the synthetic.
func (s *Server) emitProfileScopeRefused(info audit.ProfileScopeRefusedInfo) {
	exporterOn := s.auditExporter != nil && s.auditExporter.Enabled()
	alertsOn := s.alertEngine != nil && s.alertEngine.Enabled()
	if !exporterOn && !alertsOn {
		return
	}
	evt := audit.NewProfileScopeRefusedEvent(s.listenerAddr(), info)
	if exporterOn {
		_ = s.auditExporter.Emit(context.Background(), evt)
	}
	if alertsOn {
		s.alertEngine.ObserveDecision(context.Background(), evt)
	}
}

// ProfileScopeRefusedCount returns the §A40 counter for /healthz +
// tests. Read-only.
func (s *Server) ProfileScopeRefusedCount() int64 {
	if s == nil {
		return 0
	}
	return s.totalProfileScopeRefused.Load()
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

	// [[bulk-prompt-answer-ux]]: start the burst sweeper. Goroutine
	// joins via connWG so Shutdown drains it on the same wait as the
	// per-conn handlers. The cancel func is invoked by Shutdown BEFORE
	// connWG.Wait so the sweeper drains its final tick promptly,
	// mirroring the heartbeater shutdown-ordering pattern closed in
	// 276298f. When the store is nil (rare test path) the sweeper
	// still runs but its work paths short-circuit harmlessly.
	sweepCtx, sweepCancel := context.WithCancel(context.Background())
	s.burstSweeperCancel = sweepCancel
	go s.runBurstSweeper(sweepCtx)

	// [[security-team-audit-export]] Slice 2 cross-process audit-event
	// poller. Drains store.pending_audit_events rows enqueued by
	// out-of-process CLI commands (`dbounce pause stop`, `dbounce
	// profile install`, the GetActivePause expiry-GC path) + emits
	// them through the wired Exporter / RuleEngine. Same goroutine
	// shape + connWG-joined / cancel-driven shutdown ordering as
	// runBurstSweeper. Faster tick cadence (1s vs the burst sweeper's
	// 5s) because operators expect lifecycle signals — especially
	// admin-fallback-end on `pause stop` — to land in the SIEM
	// promptly. Per the spec d82ded9 sync-prompt poll precedent: the
	// 1s cadence balances "SIEM expects prompt visibility" against
	// "no busy-loop CPU burn when the queue is empty."
	pollCtx, pollCancel := context.WithCancel(context.Background())
	s.auditEventsPollerCancel = pollCancel
	go s.runPendingAuditEventsPoller(pollCtx)

	// #461 / §A63c — disk-pressure check loop. Ticks every
	// DiskPressureCheckInterval (60s); admin-action transition
	// events ride the wired auditExporter so the SIEM dashboard
	// sees status crossings on the same stream as proxy decisions.
	if s.cfg.DiskPressure != nil {
		dpCtx, dpCancel := context.WithCancel(context.Background())
		s.diskPressureCancel = dpCancel
		go func() {
			stop := make(chan struct{})
			go func() {
				<-dpCtx.Done()
				close(stop)
			}()
			var emit audit.DiskPressureEmitFunc
			if s.auditExporter != nil {
				emit = func(ctx context.Context, evt audit.Event) error {
					return s.auditExporter.Emit(ctx, evt)
				}
			}
			audit.RunDiskPressureLoop(dpCtx, s.cfg.DiskPressure, emit, s.listenerAddr(), stop)
		}()
	}

	mgmtAddr := fmt.Sprintf("%s:%d", s.cfg.MgmtHost, s.cfg.MgmtPort)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	// #276 — GET /schemas/config serves the embedded
	// dbounce-config.schema.json byte-for-byte. Agents that want to
	// validate a proposed `dbounce config import` payload against
	// the LIVE bouncer's accepted shape fetch this rather than
	// relying on a stale GitHub URL. Per [[cross-product-agent-
	// parity]]: ibounce + kbounce + gbounce ship the same endpoint
	// shape with their own product schema. READ-ONLY; no auth
	// (matches /healthz — the schema is non-sensitive metadata).
	mux.HandleFunc("/schemas/config", schemasConfigHandler)
	// #271 — GET /audit/events ships the headless audit-tail query
	// surface. Same filter language as `dbounce audit tail --filter`;
	// the cross-bouncer `iam-jit audit query` CLI calls this endpoint
	// in parallel against each reachable bouncer to produce a single
	// merged stream.
	mux.HandleFunc("/audit/events", auditEventsHandler(s.store, s.cfg.AuditEventsToken))
	// #272 — GET / serves the minimal live audit-stream web UI on
	// the same mgmt port as /healthz + /audit/events. The page polls
	// /audit/events every 2 s. Same auth model as /audit/events:
	// loopback no header; external bind takes the bearer token
	// through the URL `#token=...` fragment so the rendered HTML
	// body never embeds the secret. Cross-product-identical HTML
	// shape with ibounce / kbounce / gbounce.
	mux.HandleFunc("/", auditEventsUIHandler(s.cfg.AuditEventsToken))
	// #324c — POST /admin/dynamic-denies/reload triggers an immediate
	// reload of the dynamic-deny YAML from disk. Useful for the
	// cross-bouncer fan-out CLI (#324e), which writes the YAML +
	// then calls this endpoint on each Bounce product's mgmt port
	// to confirm "rules are live." Same bearer-token auth model as
	// /audit/events.
	//
	// #524 BB-3 — defense-in-depth middleware closes the residual gap
	// when a future code path bypasses the CLI's bind-time
	// --audit-events-token requirement (config-file loader, programmatic
	// embed, test harness). Handler-internal bearer check ALSO fires
	// (belt-and-suspenders); requireMgmtAuth adds the "external bind
	// without token → 503" failure case the handler-internal check
	// can't enforce because it has no view of the bind host.
	mux.HandleFunc("/admin/dynamic-denies/reload",
		requireMgmtAuth(s.dynamicDenyReloadHandler(s.cfg.AuditEventsToken),
			s.cfg.AuditEventsToken, s.cfg.MgmtHost))
	// #387 / §A25 Phase 2 — POST /admin/profile/reload mgmt endpoint.
	// Re-reads profiles.yaml from disk + hot-swaps the active profile
	// pointer so a `dbounce profile allow` mutation takes effect on
	// the very next decision without a bouncer restart. Same auth
	// model as /audit/events. Mirrors ibounce + kbouncer response
	// shape per [[cross-product-agent-parity]].
	mux.HandleFunc("/admin/profile/reload",
		requireMgmtAuth(s.profileReloadHandler(s.cfg.AuditEventsToken, ""),
			s.cfg.AuditEventsToken, s.cfg.MgmtHost))
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
	// [[bulk-prompt-answer-ux]]: cancel the burst sweeper BEFORE
	// waiting on connWG so its for-loop exits + its connWG.Done fires.
	// Same shutdown-ordering pattern the heartbeater follows
	// (276298f) — without this, connWG.Wait would block on the
	// sweeper's ticker indefinitely.
	if s.diskPressureCancel != nil {
		s.diskPressureCancel()
	}
	if s.burstSweeperCancel != nil {
		s.burstSweeperCancel()
	}
	// [[security-team-audit-export]] Slice 2 audit-event poller —
	// same shutdown ordering as the burst sweeper.
	if s.auditEventsPollerCancel != nil {
		s.auditEventsPollerCancel()
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

// refuseIfDynamicDenied is the #324c hot-path gate. When a dynamic-deny
// rule applies to THIS dbounce instance (the watcher's instance-denied
// flag is true), the proxy:
//
//   - Bumps the totalDynamicDenyConnectionsRefused counter (surfaced
//     via /healthz).
//   - Reads the inbound StartupMessage preamble enough to identify a
//     PG client + writes a PG ErrorResponse with SQLSTATE 42501
//     (insufficient_privilege) + a structured message naming the
//     rule_id + the operator reason.
//   - Emits an OCSF v1.1.0 class 6003 audit event with
//     `status_id=4` (Denied), `unmapped.iam_jit.ext.deny_source=
//     "dynamic"`, `dynamic_deny_rule_id=<id>`, + the operator's
//     verbatim reason as deny_reason context.
//   - Closes the connection.
//
// MySQL clients get the same audit event + the same connection-close,
// but no protocol-specific error packet — the MySQL handshake hasn't
// run yet, so a PG ErrorResponse to a MySQL client would just be
// garbled bytes. The audit trail (+ the operator's loud stderr line)
// is the load-bearing signal in the MySQL path until #324c-MySQL
// (post-launch).
//
// Returns true when the connection was refused (caller must NOT
// continue the dispatch); false when no dynamic-deny rule applies +
// the normal handler should proceed.
func (s *Server) refuseIfDynamicDenied(conn net.Conn) bool {
	if s == nil || s.dynamicDeny == nil {
		return false
	}
	if !s.dynamicDeny.InstanceDenied() {
		return false
	}
	ruleID, reason := s.dynamicDeny.DenyingRule()
	s.totalDynamicDenyConnectionsRefused.Add(1)

	// PG path: read preamble (handle SSLRequest), then send a
	// minimally-shaped ErrorResponse with SQLSTATE 42501. The PG client
	// receives an actionable error message rather than a silent TCP
	// reset — surfaces the deny reason at the analyst's terminal.
	if s.cfg.Dialect == DialectPostgres {
		_ = writePGRefusalErrorResponse(conn, ruleID, reason)
	}

	// Emit the OCSF audit event regardless of dialect so the analyst
	// has a SIEM-queryable record of the refusal.
	if s.auditExporter != nil && s.auditExporter.Enabled() {
		evt := audit.NewDynamicDenyConnectionRefusedEvent(s.listenerAddr(),
			audit.DynamicDenyConnectionRefusedInfo{
				RuleID:     ruleID,
				Reason:     reason,
				RemoteAddr: conn.RemoteAddr().String(),
			})
		_ = s.auditExporter.Emit(context.Background(), evt)
	}
	if s.alertEngine != nil && s.alertEngine.Enabled() {
		evt := audit.NewDynamicDenyConnectionRefusedEvent(s.listenerAddr(),
			audit.DynamicDenyConnectionRefusedInfo{
				RuleID:     ruleID,
				Reason:     reason,
				RemoteAddr: conn.RemoteAddr().String(),
			})
		s.alertEngine.ObserveDecision(context.Background(), evt)
	}

	log.Warn().
		Str("remote", conn.RemoteAddr().String()).
		Str("rule_id", ruleID).
		Str("reason", reason).
		Msg("dbounce: refused new connection by dynamic-deny rule")
	return true
}

// writePGRefusalErrorResponse consumes the inbound PG startup preamble
// enough to identify a PG client (handles SSLRequest by replying 'N'),
// then writes an ErrorResponse with SQLSTATE 42501 naming the rule.
// Best-effort; an early read failure just closes the conn without an
// error packet (the client will see TCP close — which is the same
// outcome as if the SSL preamble itself failed).
func writePGRefusalErrorResponse(conn net.Conn, ruleID, reason string) error {
	// Read the 8-byte startup header.
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	magic := binary.BigEndian.Uint32(hdr[4:8])
	// SSLRequest: reply 'N' to decline TLS + read a fresh StartupMessage
	// header so the client moves past its SSL negotiation phase.
	if magic == 80877103 {
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return err
		}
	}
	// Drop the body bytes (we don't care what user/database the client
	// asked for; the refusal is connection-level).
	length := binary.BigEndian.Uint32(hdr[0:4])
	if length >= 8 && length < 1<<20 {
		body := make([]byte, length-8)
		_, _ = io.ReadFull(conn, body)
	}
	// Build ErrorResponse with SQLSTATE 42501 + operator-facing message.
	msg := fmt.Sprintf("dbounce: refused by dynamic-deny rule %s (%s)", ruleID, reason)
	var b []byte
	b = append(b, 'S')
	b = append(b, []byte("FATAL")...)
	b = append(b, 0)
	b = append(b, 'V')
	b = append(b, []byte("FATAL")...)
	b = append(b, 0)
	b = append(b, 'C')
	b = append(b, []byte("42501")...)
	b = append(b, 0)
	b = append(b, 'M')
	b = append(b, []byte(msg)...)
	b = append(b, 0)
	b = append(b, 0)
	hdrBuf := make([]byte, 5)
	hdrBuf[0] = 'E'
	binary.BigEndian.PutUint32(hdrBuf[1:5], uint32(len(b)+4))
	if _, err := conn.Write(hdrBuf); err != nil {
		return err
	}
	if _, err := conn.Write(b); err != nil {
		return err
	}
	return nil
}

// refuseIfDiskPressure is the #461 / §A63c hot-path gate. When the
// disk-pressure subsystem has flipped this instance into pause-
// requests-at-critical (or emergency), refuse the new connection at
// the wire-protocol layer with a PG ErrorResponse SQLSTATE 53300
// ("too many connections" — closest standard SQLSTATE for "server
// unwilling to accept new connections"; clients display it as
// "FATAL: too many connections" which honestly maps to the operator
// experience of "the bouncer paused itself because the audit log
// is at risk").
//
// Returns true when the connection was refused (caller must NOT
// continue the dispatch); false when no disk-pressure refusal
// applies + the normal handler should proceed.
//
// MySQL clients get the same audit trail (via the periodic loop's
// admin-action emit) but no protocol-specific error packet — the
// MySQL handshake hasn't run yet, so a PG ErrorResponse would be
// garbled bytes. Mirrors the existing refuseIfDynamicDenied posture.
func (s *Server) refuseIfDiskPressure(conn net.Conn) bool {
	if s == nil || s.cfg.DiskPressure == nil {
		return false
	}
	if !s.cfg.DiskPressure.RefuseRequests() {
		return false
	}
	snap := s.cfg.DiskPressure.Snapshot()
	usedPct := 0.0
	if snap.UsedPct != nil {
		usedPct = *snap.UsedPct
	}
	reason := fmt.Sprintf(audit.PauseRequestsRefusalReasonTemplate, usedPct, snap.CritPct)
	// PG path: consume the startup preamble + send a structured
	// ErrorResponse. Best-effort; failures fall through to TCP close.
	if s.cfg.Dialect == DialectPostgres {
		_ = writePGDiskPressureErrorResponse(conn, reason)
	}
	log.Warn().
		Str("remote", conn.RemoteAddr().String()).
		Float64("used_pct", usedPct).
		Str("status", snap.Status).
		Msg("dbounce: refused new connection — disk-pressure pause-requests at critical")
	return true
}

// writePGDiskPressureErrorResponse consumes the inbound PG startup
// preamble enough to identify a PG client (handles SSLRequest by
// replying 'N'), then writes an ErrorResponse with SQLSTATE 53300
// + the operator-facing disk-pressure reason. Mirrors the structure
// of writePGRefusalErrorResponse with a different SQLSTATE + reason
// template.
func writePGDiskPressureErrorResponse(conn net.Conn, reason string) error {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	magic := binary.BigEndian.Uint32(hdr[4:8])
	if magic == 80877103 {
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return err
		}
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	if length >= 8 && length < 1<<20 {
		body := make([]byte, length-8)
		_, _ = io.ReadFull(conn, body)
	}
	// PG ErrorResponse with SQLSTATE 53300. "S" severity FATAL means
	// the client will not retry on this connection (correct: the
	// bouncer is paused, the disk hasn't moved yet).
	var b []byte
	b = append(b, 'S')
	b = append(b, []byte("FATAL")...)
	b = append(b, 0)
	b = append(b, 'V')
	b = append(b, []byte("FATAL")...)
	b = append(b, 0)
	b = append(b, 'C')
	b = append(b, []byte("53300")...)
	b = append(b, 0)
	b = append(b, 'M')
	b = append(b, []byte("dbounce: "+reason)...)
	b = append(b, 0)
	b = append(b, 0)
	hdrBuf := make([]byte, 5)
	hdrBuf[0] = 'E'
	binary.BigEndian.PutUint32(hdrBuf[1:5], uint32(len(b)+4))
	if _, err := conn.Write(hdrBuf); err != nil {
		return err
	}
	if _, err := conn.Write(b); err != nil {
		return err
	}
	return nil
}

// writePGScopeRefusalPreambleErrorResponse is the §A40 variant of
// writePGRefusalErrorResponse. Mirrors the #324c shape (consumes
// the SSLRequest preamble + drops startup body bytes) but produces
// an operator-facing message that honestly names the profile-scope
// path rather than mis-labeling as "dynamic-deny rule." Used by
// the upstream-forwarding host pre-gate where the StartupMessage
// has NOT yet been read.
func writePGScopeRefusalPreambleErrorResponse(conn net.Conn, profileName, denyReason, reason string) error {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	magic := binary.BigEndian.Uint32(hdr[4:8])
	if magic == 80877103 {
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return err
		}
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	if length >= 8 && length < 1<<20 {
		body := make([]byte, length-8)
		_, _ = io.ReadFull(conn, body)
	}
	msg := fmt.Sprintf("dbounce: profile %q refused connection: %s",
		profileName, reason)
	var b []byte
	b = append(b, 'S')
	b = append(b, []byte("FATAL")...)
	b = append(b, 0)
	b = append(b, 'V')
	b = append(b, []byte("FATAL")...)
	b = append(b, 0)
	b = append(b, 'C')
	b = append(b, []byte("42501")...)
	b = append(b, 0)
	b = append(b, 'M')
	b = append(b, []byte(msg)...)
	b = append(b, 0)
	// Detail field carries the stable deny_reason constant for SIEM
	// + scripted client mapping (psql surfaces D as a "DETAIL:" line).
	b = append(b, 'D')
	b = append(b, []byte(denyReason)...)
	b = append(b, 0)
	b = append(b, 0)
	hdrBuf := make([]byte, 5)
	hdrBuf[0] = 'E'
	binary.BigEndian.PutUint32(hdrBuf[1:5], uint32(len(b)+4))
	if _, err := conn.Write(hdrBuf); err != nil {
		return err
	}
	if _, err := conn.Write(b); err != nil {
		return err
	}
	return nil
}

// DynamicDenyCounters exposes the per-Server #324c counters for
// /healthz + tests. Read-only.
func (s *Server) DynamicDenyCounters() (refused, reloads, parseErrors int64) {
	if s == nil {
		return 0, 0, 0
	}
	return s.totalDynamicDenyConnectionsRefused.Load(),
		s.totalDynamicDenyReloads.Load(),
		s.totalDynamicDenyParseErrors.Load()
}

// BumpDynamicDenyReload + BumpDynamicDenyParseError are exposed for
// the CLI's watcher emit callback so the /healthz counters reflect
// reload activity without a circular package import.
func (s *Server) BumpDynamicDenyReload()     { s.totalDynamicDenyReloads.Add(1) }
func (s *Server) BumpDynamicDenyParseError() { s.totalDynamicDenyParseErrors.Add(1) }

// DynamicDeny returns the wired watcher (may be nil). Surfaced for
// the mgmt-port reload handler + tests.
func (s *Server) DynamicDeny() *dynamicdeny.Watcher { return s.dynamicDeny }

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

	// #461 / §A63c — disk-pressure circuit breaker. In pause-requests
	// mode at critical / emergency the proxy refuses every new
	// connection with a PG ErrorResponse (SQLSTATE 53300) BEFORE
	// running the dynamic-deny check or any forwarder logic.
	// Refusing pre-handshake avoids the audit-write race when the
	// disk is already at the wall. Other modes
	// (rotate-aggressively / archive-and-purge) never flip
	// refuse_requests so this is a no-op for them. Mirrors the
	// dynamic-deny gate's connection-refuse contract.
	if s.refuseIfDiskPressure(conn) {
		return
	}
	// #324c — dynamic-deny instance gate. When the watcher has flipped
	// this instance into the denied state, refuse new connections at
	// the wire-protocol layer. Existing connections (already running
	// loops past this point) continue per [[ibounce-honest-
	// positioning]] — we don't kill mid-transaction; "new connections
	// refused" is the honest behavioral contract.
	if s.refuseIfDynamicDenied(conn) {
		return
	}

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

	// §A40 profile-scope gate (observation-only path). pgHandshakeWithPreamble
	// has already replied with the synthetic AuthenticationOk +
	// ReadyForQuery sequence so the client thinks it's authenticated; a
	// scope refusal here writes an ErrorResponse + closes. Done after
	// handshake (not before) because pgHandshakeWithPreamble owns the
	// preamble-read state machine; emitting an early refuse would require
	// duplicating that. Per [[ibounce-honest-positioning]]: the
	// observation-only path is the dev-laptop default; refusing AFTER the
	// synthetic-ack is still the operator's intended signal — the
	// connection didn't reach any upstream because there is no upstream.
	// Production deployments use the upstream-forwarding path
	// (refuseIfProfileScopeViolation), which refuses BEFORE any upstream
	// dial completes.
	if s.refuseObservationProfileScopeViolation(conn, startupBody) {
		return
	}

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
//
// #318 / §A16 — when application_name carries the canonical
// `iam-jit-agent:NAME:SESSIONID` cross-bouncer tag, the parsed
// SESSIONID is used as the registered session id (instead of a fresh
// v7 UUID) so cross-bouncer correlation by `agent.session_id` resolves
// across all four products. Invalid tags bump the per-Server
// rejection counter + log to stderr. The raw value is NEVER written
// into the audit event.
func (s *Server) registerPGAgentFromBody(body []byte) string {
	if s.agentRegistry == nil {
		return ""
	}
	params := audit.ParsePGStartupParams(body)
	name, sessionID, rawAppName, tagInvalid := audit.ParsePGStartupAppNameWithSession(params)
	agent := audit.Agent{
		Name:         name,
		DetectedFrom: audit.DetectedFromPGAppName,
	}
	if tagInvalid {
		s.recordRejectedAgentTag(rawAppName)
		// #320 / §A18: stamp the structured rejection breadcrumb on
		// the session's Agent so every subsequent audit event from
		// this connection carries it under
		// `unmapped.iam_jit.ext.agent_header_rejection`. Pre-§A18
		// the only signal was the /healthz counter + the truncated
		// stderr line; SOC analysts querying the audit log directly
		// couldn't tell which connection had the misconfigured
		// agent SDK. The breadcrumb names the field
		// (`application_name`), a bounded enum reason
		// (invalid_name_charset / invalid_name_length /
		// invalid_session_id_format / invalid_session_id_length /
		// application_name_unparseable), AND the rejected tail's
		// length — never the raw value. Per
		// [[security-team-positioning-safety-not-surveillance]].
		fullTail := rawAppName
		if strings.HasPrefix(rawAppName, audit.AgentAppNameTagPrefix) {
			fullTail = strings.TrimPrefix(rawAppName, audit.AgentAppNameTagPrefix)
		}
		// Re-parse the malformed pieces so the classifier can pick the
		// most-specific reason. ParseAgentTagFromAppName already returns
		// the raw pieces when validation failed but ok=false; we call
		// it again because ParsePGStartupAppNameWithSession's tag-invalid
		// branch discards them.
		rawName, rawSession, _ := audit.ParseAgentTagFromAppName(rawAppName)
		agent.HeaderRejection = audit.ClassifyApplicationNameTagRejection(
			rawName, rawSession, fullTail)
	}
	if rawAppName == "" {
		// No application_name sent. Mint anyway so the session id
		// threads through the audit; name will be normalized to
		// "unknown" inside Mint.
		agent.Name = ""
		agent.DetectedFrom = audit.DetectedFromUnknown
	}
	// #318 — when the agent supplied a session id via the canonical
	// tag, register under THAT session id so cross-bouncer correlation
	// works. MintWithSessionID falls back to a fresh v7 when the
	// session id is empty or invalid.
	if sessionID != "" {
		return s.agentRegistry.MintWithSessionID(agent, sessionID)
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

	// #320 / §A18: resolve the agent fingerprint UP-FRONT so the
	// SQLite row carries the same agent.name / agent.session_id /
	// agent.detected_from values the JSONL log + webhook pipeline
	// already emit. Pre-#320 these were dropped on the store side
	// (the in-process registry was the only source of truth) and
	// the HTTP /audit/events endpoint surfaced an empty agent block
	// — cross-bouncer correlation by `agent.session_id` returned
	// zero dbounce events. Lookup is best-effort: a registry miss
	// (concurrent connection close + final in-flight decision) still
	// stamps the session_id so the cross-bouncer pivot resolves.
	var agentName, agentSessionID, agentDetectedFrom string
	if sessionID != "" && s.agentRegistry != nil {
		if a, ok := s.agentRegistry.Lookup(sessionID); ok {
			agentName = a.Name
			agentSessionID = a.SessionID
			agentDetectedFrom = string(a.DetectedFrom)
		} else {
			agentSessionID = sessionID
			agentDetectedFrom = string(audit.DetectedFromUnknown)
		}
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
		ProfileName:       s.activeProfileNameSnapshot(),
		DecisionSource:    d.Source,
		MatchedRuleID:     d.MatchedRuleID,
		TaskID:            d.TaskID,
		PauseID:           pauseID,
		StatementRedacted: statementRedacted,
		// #320 / §A18: agent attribution persisted alongside the
		// row so /audit/events + audit tail readers see the same
		// `unmapped.iam_jit.agent.{name, session_id, detected_from}`
		// block the JSONL log + webhook pipeline already emit.
		AgentName:      agentName,
		AgentSessionID: agentSessionID,
		DetectedFrom:   agentDetectedFrom,
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

	// #252 Slice 2 wiring per [[security-team-audit-export]]: when a
	// transparent-mode DENY was DEMOTED to ALLOW by an active pause
	// window, fire an ADMIN_FALLBACK synthetic alongside the decision
	// event. dbounce's equivalent of the kbounce + ibounce
	// "admin-fallback grant" emit site. The decision row itself
	// already carries pause_id under unmapped.iam_jit.ext; this
	// synthetic gives SIEM consumers a SECOND, easy-to-filter signal
	// (activity_name="admin_fallback") without parsing decision rows.
	// Fires AFTER the decision-event emit so a SIEM consumer sees
	// the decision in chronological order before the synthetic that
	// brackets it.
	if pauseDemoted && pauseID != nil {
		s.emitAdminFallback(audit.AdminFallbackInfo{
			PauseID:       *pauseID,
			DecisionID:    decisionID,
			StatementType: ps.StatementType,
			TablesTouched: ps.TablesTouched,
		})
	}

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
		} else if s.burst != nil {
			// [[bulk-prompt-answer-ux]]: record the enqueue in the
			// burst detector. When the threshold is crossed, the
			// detector arms + the next `dbounce prompts bulk-pending`
			// (CLI / MCP) surfaces the bulk-answer affordance.
			if armed := s.burst.Record(time.Now()); armed {
				log.Info().Int("count_in_window", DefaultBurstThreshold).
					Dur("window", DefaultBurstWindow).
					Msg("dbounce: BURST_DETECTED — bulk-answer affordance armed (see `dbounce prompts bulk-answer`)")
			}
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
	// [[bulk-prompt-answer-ux]]: read the active profile through the
	// RWMutex-guarded accessor so SwapProfile can swap it mid-flight
	// without racing the decision loop. The pointer is taken once per
	// decide() call; subsequent Evaluate calls below see a consistent
	// snapshot even if the burst sweeper hot-swaps between iterations.
	activeProfile, _ := s.loadActiveProfile()

	// Step 0: multi-statement admin-tight floor (#587 UAT-C CRIT).
	// Fires BEFORE the profile gate because UAT-C 2026-05-25 confirmed
	// that an embedded GRANT/ALTER_PRIVILEGES at position 2+ slips past
	// safe-default's `sql_read_only` baseline (the whole-batch
	// ParsedStatement classifies as SELECT — the first statement type —
	// so the profile happily ALLOWS the batch). Per UC-34 + UAT-C: the
	// floor MUST fire on any admin-grant DCL anywhere in the batch, even
	// when the whole-batch StatementType masks it.
	//
	// EvaluateMultiStatement splits the raw SQL at top-level `;`
	// separators + parses each piece individually + applies
	// AdminTightFloor to each. The global rules table is threaded
	// through so a per-statement allow-rule match preserves the
	// existing override semantics (an operator who wrote
	// `dbounce rules add --pattern "GRANT:*" --effect allow` to permit
	// admin-grant traffic still gets that override per-statement). DENY
	// on any DENY; reason names the position so operators debugging
	// the verdict see WHICH statement fired (per
	// [[ibounce-honest-positioning]]). Single-statement inputs (no `;`)
	// get Position=1 in the verdict so SIEM filters keying on
	// "statement N/M" handle both shapes uniformly.
	//
	// proxy.decide + cli.evalDecide consume the same helper — no parity
	// drift per the #559 lesson.
	var step0Rules *dbrules.RuleSet
	if s.store != nil {
		if rs, rerr := s.store.LoadRuleSet(); rerr == nil {
			step0Rules = rs
		}
	}
	if mv := decision.EvaluateMultiStatement(
		ps.Dialect, ps.Raw, activeProfile,
		string(s.cfg.DefaultPolicy), step0Rules); mv.Deny {
		return Decision{
			Verdict: VerdictDeny,
			Reason:  mv.Reason,
			Source:  SourceDefault,
		}
	}

	// Step 1+2: profile gates. D-Slice 7 wires the safe-default
	// environment profile + its AST-walk Layer 2 backstop. The profile
	// evaluator runs deny_keywords → deny_actions → allow_baseline +
	// deny_ast_mutating_nodes → allow_rules in that order. A profile
	// deny short-circuits the whole composition order (HARD FLOOR);
	// a profile allow short-circuits with Source=profile.allow so a
	// permissive task scope can't lower the bar further. Abstain →
	// fall through to the task / global rules below.
	if activeProfile != nil && activeProfile.Name != profile.FullUserProfileName {
		profileView := &profile.ParsedStatement{
			StatementType:    ps.StatementType,
			TablesTouched:    ps.TablesTouched,
			FunctionsCalled:  ps.FunctionsCalled,
			IsDML:            ps.IsDML,
			IsDDL:            ps.IsDDL,
			IsDCL:            ps.IsDCL,
			DCLTargetsPublic: ps.DCLTargetsPublic,
			HasMutatingNode:  ps.HasMutatingNode,
			IsExplain:        ps.IsExplain,
			IsExplainAnalyze: ps.IsExplainAnalyze,
		}
		pv := activeProfile.Evaluate(profileView)
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

	// Step 5.5 (admin-tight floor) now fires as Step 0 at the top of
	// decide() per #587 UAT-C 2026-05-25. Pre-#587 the floor lived
	// here; UAT-C surfaced that an embedded DCL at position 2+ slipped
	// past the profile gate because the floor ran AFTER Step 1+2.
	// Moving the floor to Step 0 closes the bypass for both
	// default-allow + profile-allow shapes. The per-statement
	// global-allow override is honored inside EvaluateMultiStatement
	// (preserves the operator-configured `GRANT:*` allow-rule
	// override).
	//
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
	// HealthzAuditExportHealth surfaces the [[audit-export-failure-
	// visibility]] derived view: per-transport health + the aggregate
	// degraded flag + the human-readable reason. Distinct from
	// AuditExport (which is the raw per-transport counters) so a
	// downstream monitor scraping /healthz can read either the raw
	// view or the health-derived view depending on what its
	// alerting rule needs. The derived view also drives the 503 flip
	// below — when audit_export_health.degraded=true, /healthz
	// returns 503 so external monitors / Kubernetes liveness probes
	// alert. Per the memo: silently-failing audit IS a stealth
	// bypass; making it loud closes the gap.
	type HealthzAuditExportHealth = audit.ExportHealth
	// #324c — dynamic-deny /healthz fields. Surfaced unconditionally
	// (even when the watcher is nil) so a monitor scraping the
	// endpoint sees a consistent shape across deployments.
	denyRefused, denyReloads, denyParseErrs := s.DynamicDenyCounters()
	dynamicDeniesEnabled := s.dynamicDeny != nil
	dynamicDeniesPath := ""
	dynamicDeniesCount := 0
	upstreamDenied := false
	upstreamDeniedRuleID := ""
	if s.dynamicDeny != nil {
		dynamicDeniesPath = s.dynamicDeny.Path()
		if snap := s.dynamicDeny.Snapshot(); snap != nil {
			dynamicDeniesCount = len(snap.Rules)
		}
		upstreamDenied = s.dynamicDeny.InstanceDenied()
		upstreamDeniedRuleID, _ = s.dynamicDeny.DenyingRule()
	}

	// #544 / MRR-5 M3 — cross-bouncer parity llm_budget shape. Go
	// bouncers don't run LLM per [[bouncer-zero-llm-when-agent-in-loop]]
	// (they're deterministic by default), so the field is the constant
	// {"enabled": false}. Honest per [[ibounce-honest-positioning]] —
	// NOT a stub. Returned unconditionally so a cross-bouncer SRE
	// composite monitor (MRR-5 §2) sees the same key set across all
	// four bouncers. If dbounce ever adds optional LLM features,
	// expand to match ibounce's full enabled-shape (used_today_usd,
	// cap_per_day_usd, remaining_usd, percent_consumed,
	// approaching_limit).
	type HealthzLlmBudget struct {
		Enabled bool `json:"enabled"`
	}
	payload := struct {
		Status                              string                       `json:"status"`
		Mode                                string                       `json:"mode"`
		DefaultPolicy                       string                       `json:"default_policy"`
		Dialect                             string                       `json:"dialect"`
		ActiveProfile                       string                       `json:"active_profile"`
		DecisionsCount                      int64                        `json:"decisions_count"`
		LookupErrorsCounter                 int64                        `json:"lookup_errors_counter"`
		TotalAgentHeadersRejected           int64                        `json:"total_agent_headers_rejected"`
		Pause                               *HealthzPause                `json:"pause"`
		AuditExport                         *HealthzAuditExport          `json:"audit_export,omitempty"`
		AuditExportHealth                   *HealthzAuditExportHealth    `json:"audit_export_health,omitempty"`
		DynamicDeniesEnabled                bool                         `json:"dynamic_denies_enabled"`
		DynamicDeniesPath                   string                       `json:"dynamic_denies_path,omitempty"`
		DynamicDeniesCount                  int                          `json:"dynamic_denies_count"`
		UpstreamDenied                      bool                         `json:"upstream_denied"`
		UpstreamDeniedRuleID                string                       `json:"upstream_denied_rule_id,omitempty"`
		TotalDynamicDenyConnectionsRefused  int64                        `json:"total_dynamic_deny_connections_refused"`
		TotalDynamicDenyReloads             int64                        `json:"total_dynamic_deny_reloads"`
		TotalDynamicDenyParseErrors         int64                        `json:"total_dynamic_deny_parse_errors"`
		// §A40 — profile scope refusal counter.
		TotalProfileScopeRefused int64 `json:"total_profile_scope_refused"`
		// #461 / §A63c — disk-pressure circuit-breaker snapshot.
		AuditLog *audit.DiskPressureSnapshot `json:"audit_log,omitempty"`
		// #544 / MRR-5 M2 — top-level chain_initialized bool. True iff
		// the audit exporter is wired AND enabled (matches the same
		// predicate the per-decision emit path uses, so a False here
		// means a decision attempted right now would not be exported).
		// False covers "no exporter wired" AND "exporter wired but
		// disabled". Closes the cold-start gap noted in
		// MRR-5-MONITORING-RUNBOOK.md §6 M2 where audit-init failure
		// surfaced in the bouncer log but NOT on /healthz until the
		// first decision tried to emit. Per
		// [[cross-product-agent-parity]] all four bouncers surface the
		// same field for SRE composite monitors.
		ChainInitialized bool             `json:"chain_initialized"`
		AuditChain       map[string]any   `json:"audit_chain"`
		LlmBudget        HealthzLlmBudget `json:"llm_budget"`
		// #718 ADOPT-4 — Phase H behavioral-deviation / anomaly detector
		// status. Always present (enabled:false when unwired) so the
		// composite monitor key set stays stable per
		// [[cross-product-agent-parity]]. Visibility surface only; ALERT
		// by default, never an enforcement signal.
		Anomaly map[string]any `json:"anomaly"`
	}{
		Status:                              "ok",
		Mode:                                string(s.cfg.Mode),
		DefaultPolicy:                       string(s.cfg.DefaultPolicy),
		Dialect:                             string(s.cfg.Dialect),
		ActiveProfile:                       s.ActiveProfileName(),
		LookupErrorsCounter:                 LookupErrorsCount(),
		TotalAgentHeadersRejected:           s.totalAgentHeadersRejected.Load(),
		DynamicDeniesEnabled:                dynamicDeniesEnabled,
		DynamicDeniesPath:                   dynamicDeniesPath,
		DynamicDeniesCount:                  dynamicDeniesCount,
		UpstreamDenied:                      upstreamDenied,
		UpstreamDeniedRuleID:                upstreamDeniedRuleID,
		TotalDynamicDenyConnectionsRefused:  denyRefused,
		TotalDynamicDenyReloads:             denyReloads,
		TotalDynamicDenyParseErrors:         denyParseErrs,
		TotalProfileScopeRefused:            s.ProfileScopeRefusedCount(),
		LlmBudget:                           HealthzLlmBudget{Enabled: false},
		Anomaly:                             s.anomalyHealthz(),
	}
	// ADOPT-10 / #734 — chain_initialized now reports whether the
	// tamper-evident hash-chain is ACTUALLY stamping rows (honest
	// forensic posture), not merely that an exporter is wired+enabled.
	// The audit_chain block surfaces the real head seq/hash + manifest
	// signature presence for SOC analysts / composite monitors.
	if s.auditExporter != nil && s.auditExporter.Log != nil && s.auditExporter.Log.ChainEnabled() {
		lw := s.auditExporter.Log
		payload.ChainInitialized = true
		chainBody := map[string]any{
			"enabled":   true,
			"head_seq":  lw.ChainHeadSeq(),
			"head_hash": lw.ChainHeadHash(),
		}
		if ms := lw.ManifestStatus(); ms != nil {
			chainBody["manifest"] = ms
		} else {
			chainBody["manifest"] = map[string]any{"configured": false}
		}
		payload.AuditChain = chainBody
	} else {
		payload.ChainInitialized = false
		payload.AuditChain = map[string]any{"enabled": false}
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
		// Heartbeat watchdog degraded → /healthz reports degraded +
		// returns 503 so a Kubernetes liveness probe / load-balancer
		// health check drains traffic from a throttled instance. Per
		// [[prompt-injection-disable-bouncer-threat]]: the gap alert
		// fires on stderr + OCSF + here in lockstep.
		if st.Heartbeat != nil && st.Heartbeat.Degraded {
			payload.Status = "degraded"
		}
		// [[audit-export-failure-visibility]] /healthz section: surface
		// per-transport health + aggregate Degraded flag. When
		// degraded, flip the response status so external monitors
		// alert (same 503 pathway the heartbeat watchdog uses). The
		// derived health view computes from race-free atomic reads of
		// the per-transport stats; no per-decision overhead.
		health := s.auditExporter.Health()
		payload.AuditExportHealth = &health
		if health.Degraded {
			payload.Status = "degraded"
		}
	}
	// #461 / §A63c — surface disk-pressure subsystem + flip to 503
	// when refuse_requests is true so external monitors (liveness
	// probes, monit) see the same paused-bouncer signal the connection
	// hot path uses.
	if s.cfg.DiskPressure != nil {
		snap := s.cfg.DiskPressure.Snapshot()
		payload.AuditLog = &snap
		if snap.RefuseRequests {
			payload.Status = "degraded"
		}
	}
	status := http.StatusOK
	if payload.Status == "degraded" {
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
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

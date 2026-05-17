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
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/dbounce/internal/parser"
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

// Dialect names a SQL wire protocol. D-Slice 1 supports only postgres.
type Dialect string

const (
	DialectPostgres Dialect = "postgres"
)

// IsValid reports whether d is one of the recognized values.
func (d Dialect) IsValid() bool {
	return d == DialectPostgres
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
	// SourceProfile is reserved for the D-Slice 7 environment-profile
	// hard floor (keyword-deny / verb-deny / account-deny). D-Slice 3
	// leaves the placeholder; D-Slice 7 wires it.
	SourceProfile = "profile"
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
	// ActiveProfileName is filled by D-Slice 7. Stays empty through D-Slice 6.
	ActiveProfileName string
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
}

// NewServer constructs a Server without starting it.
func NewServer(cfg Config, st *store.Store) *Server {
	return &Server{cfg: cfg.Normalize(), store: st}
}

// Serve binds the wire-protocol listener + the management HTTP
// listener, then accepts connections until Shutdown is called.
func (s *Server) Serve() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("dbounce: bind %s: %w", addr, err)
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
	go func() {
		if err := s.mgmtSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// Shutdown stops the listener + the management HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.mgmtSrv != nil {
		return s.mgmtSrv.Shutdown(ctx)
	}
	return nil
}

// serveConn is the per-client read loop.
func (s *Server) serveConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Warn().Interface("panic", r).
				Str("remote", conn.RemoteAddr().String()).
				Msg("dbounce: recovered panic in connection handler")
		}
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(s.cfg.IdleTimeout))

	// D-Slice 2: when an upstream is configured, dispatch to the
	// forwarding handler. The observation-only handshake remains for
	// the no-upstream case so `dbounce run` keeps working as a
	// parse-only audit-tap without a real database.
	if s.upstreamForwardingActive() {
		s.serveConnWithUpstream(conn)
		return
	}

	if err := pgHandshake(conn); err != nil {
		log.Debug().Err(err).Str("remote", conn.RemoteAddr().String()).
			Msg("dbounce: handshake failed")
		return
	}

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
			s.evaluateAndAudit(sql, "Query")
			if err := writeReadyForQuery(conn); err != nil {
				return
			}
		case msgParse:
			_ = readCString(payload) // stmt name (discarded for now)
			rest := payload[firstNullPlus1(payload):]
			sql := readCString(rest)
			s.evaluateAndAudit(sql, "Parse")
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
func (s *Server) evaluateAndAudit(sql, source string) {
	ps := parser.Parse(sql)
	d := s.decide(ps)
	row := store.DecisionRow{
		At:               time.Now().UTC(),
		Dialect:          ps.Dialect,
		Statement:        sql,
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
		DecisionVerdict:  string(d.Verdict),
		DecisionReason:   d.Reason,
		ModeAtDecision:   string(s.cfg.Mode),
		// Enforcement requires (a) transparent mode AND (b) a DENY
		// verdict AND (c) D-Slice 2's forwarding wired. D-Slice 3 sets
		// (a)+(b); D-Slice 2's forwarding handler honors it.
		Enforced:       s.cfg.Mode == ModeTransparent && d.Verdict == VerdictDeny,
		ProfileName:    s.cfg.ActiveProfileName,
		DecisionSource: d.Source,
		MatchedRuleID:  d.MatchedRuleID,
		TaskID:         d.TaskID,
	}
	if _, err := s.store.RecordDecision(row); err != nil {
		BumpLookupErrors()
		log.Warn().Err(err).Str("source", source).
			Msg("dbounce: record decision failed")
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
	// Step 1+2: profile gates. D-Slice 7 placeholder. When wired,
	// profile-deny short-circuits with Source=SourceProfile (verdict
	// DENY); profile-allow falls through. The placeholder is documented
	// rather than wired so D-Slice 7's diff is purely additive.

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
	payload := struct {
		Status              string        `json:"status"`
		Mode                string        `json:"mode"`
		DefaultPolicy       string        `json:"default_policy"`
		Dialect             string        `json:"dialect"`
		ActiveProfile       string        `json:"active_profile"`
		DecisionsCount      int64         `json:"decisions_count"`
		LookupErrorsCounter int64         `json:"lookup_errors_counter"`
		Pause               *HealthzPause `json:"pause"`
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
	return "", fmt.Errorf("dbounce: unknown dialect %q (D-Slice 1 supports: postgres)", s)
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

func pgHandshake(conn net.Conn) error {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("read startup header: %w", err)
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	magic := binary.BigEndian.Uint32(hdr[4:8])

	if magic == 80877103 {
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return fmt.Errorf("write SSL-no: %w", err)
		}
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return fmt.Errorf("read second startup header: %w", err)
		}
		length = binary.BigEndian.Uint32(hdr[0:4])
		magic = binary.BigEndian.Uint32(hdr[4:8])
	}

	if magic == 80877104 {
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return fmt.Errorf("write GSS-no: %w", err)
		}
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return fmt.Errorf("read third startup header: %w", err)
		}
		length = binary.BigEndian.Uint32(hdr[0:4])
		magic = binary.BigEndian.Uint32(hdr[4:8])
	}

	if magic == 80877102 {
		return errors.New("CancelRequest received; nothing to cancel in D-Slice 1")
	}

	if length < 8 || length > 1<<20 {
		return fmt.Errorf("implausible startup length: %d", length)
	}
	body := make([]byte, length-8)
	if _, err := io.ReadFull(conn, body); err != nil {
		return fmt.Errorf("read startup body: %w", err)
	}

	if err := writeMessage(conn, 'R', []byte{0, 0, 0, 0}); err != nil {
		return err
	}
	bkd := make([]byte, 8)
	binary.BigEndian.PutUint32(bkd[0:4], 1)
	binary.BigEndian.PutUint32(bkd[4:8], 0)
	if err := writeMessage(conn, 'K', bkd); err != nil {
		return err
	}
	if err := writeMessage(conn, 'Z', []byte{'I'}); err != nil {
		return err
	}
	return nil
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

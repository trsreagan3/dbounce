// Package proxy is dbounce's TCP listener + decision pipeline. D-Slice
// 1 ships the observation-only PostgreSQL wire-protocol shape: parse
// inbound Query / Parse / Bind / Execute messages, classify the SQL,
// audit-log the decision, return a synthetic ReadyForQuery to the
// client. No upstream forwarding — that ships in D-Slice 2.
//
// Per [[creates-never-mutates]]: the proxy NEVER executes SQL against
// a real database in D-Slice 1. The synthetic ReadyForQuery keeps
// well-behaved clients happy enough to send the next statement so the
// operator can preview the full audit trail before flipping to D-Slice
// 2's real forwarding.
//
// Per [[safety-mode-lean-permissive]]: D-Slice 1's default verdict is
// ALLOW (advisory) — the proxy observes + logs; it never blocks. The
// transparent-mode block path is wired in D-Slice 2 once real
// forwarding lands.
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
	"github.com/trsreagan3/dbounce/internal/store"
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
// statement in transparent mode. D-Slice 1 has no rule engine, so the
// flag is scaffolding for D-Slice 3.
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

// Config wires the proxy. CLI fills this from flags + the store + the
// parser pkg's dialect dispatcher.
type Config struct {
	Host                string
	Port                int
	MgmtHost            string
	MgmtPort            int
	Mode                Mode
	DefaultPolicy       DefaultPolicy
	Dialect             Dialect
	UpstreamURL         string // captured for audit in D-Slice 1; D-Slice 2 dials it
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	// ActiveProfile is filled by D-Slice 7. Stays nil through D-Slice 6.
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

// BumpLookupErrors increments the counter. Exported so the future
// rule-engine path + audit-write path can flag their own errors
// without re-importing the proxy package.
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
// listener, then accepts connections until Shutdown is called. Returns
// the first listener error; the management server's errors are logged
// + the wire-protocol listener wins.
//
// D-Slice 1 listener: per-connection goroutine reads PG wire-protocol
// messages, hands each parsed statement to evaluateAndAudit, and writes
// a synthetic ReadyForQuery back. No upstream dial; the connection
// stays open as long as the client keeps sending well-formed messages.
func (s *Server) Serve() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("dbounce: bind %s: %w", addr, err)
	}
	s.listener = l

	// Start the management HTTP server. /healthz only in D-Slice 1.
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

// Shutdown stops the listener + the management HTTP server. Pending
// connections see net.ErrClosed on their next read; they exit cleanly.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.mgmtSrv != nil {
		return s.mgmtSrv.Shutdown(ctx)
	}
	return nil
}

// serveConn is the per-client read loop. Handles the PG wire-protocol
// startup handshake (we ack but don't authenticate against an upstream
// in D-Slice 1) then loops reading message envelopes. Every Query /
// Parse / Bind / Execute hands the embedded SQL to the parser + audit
// log, then a synthetic ReadyForQuery is sent.
//
// Per the audit-cadence self-check: malformed messages NEVER panic.
// Read errors close the connection + log at debug; classify-errors
// audit a row with statement_type=UNPARSEABLE + close the connection.
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

	// Handshake. PG clients start with a StartupMessage (or
	// SSLRequest). We refuse SSLRequest in D-Slice 1 (TLS lands in
	// D-Slice 4); for StartupMessage we send AuthenticationOk +
	// ParameterStatus + BackendKeyData + ReadyForQuery, then enter the
	// command loop.
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
			// Client said goodbye. Clean exit.
			return
		case msgQuery:
			sql := readCString(payload)
			s.evaluateAndAudit(sql, "Query")
			if err := writeReadyForQuery(conn); err != nil {
				return
			}
		case msgParse:
			// Parse: stmtName \0 sql \0 numParamTypes int16, then param oids.
			// D-Slice 1: we only care about the SQL text; the rest is
			// preserved for D-Slice 2's prepared-statement support.
			_ = readCString(payload) // stmt name (discarded for now)
			rest := payload[firstNullPlus1(payload):]
			sql := readCString(rest)
			s.evaluateAndAudit(sql, "Parse")
			// Per the PG protocol the client expects a ParseComplete + a
			// later Sync; we keep things simple and answer the implicit
			// Sync with ReadyForQuery so a libpq client doesn't hang.
			if err := writeParseComplete(conn); err != nil {
				return
			}
			if err := writeReadyForQuery(conn); err != nil {
				return
			}
		case msgBind:
			// Bind binds a portal to a prepared statement. No SQL
			// surface; D-Slice 1 just acks BindComplete + ReadyForQuery.
			if err := writeBindComplete(conn); err != nil {
				return
			}
			if err := writeReadyForQuery(conn); err != nil {
				return
			}
		case msgExecute:
			// Execute runs a previously-bound portal. No SQL surface;
			// the SQL itself was already captured at the Parse step.
			// D-Slice 1 acks CommandComplete + ReadyForQuery without
			// executing.
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
			// Acked silently. D-Slice 1 doesn't need to track portals.
		default:
			// Unknown / unsupported message type. Per the audit-cadence
			// self-check, malformed messages MUST NOT panic — we log
			// + close gracefully.
			log.Debug().Uint8("type", msgType).
				Str("remote", conn.RemoteAddr().String()).
				Msg("dbounce: unsupported wire-protocol message; closing connection")
			return
		}
	}
}

// evaluateAndAudit parses one inbound SQL statement, computes the
// D-Slice 1 verdict (always ALLOW; advisory), and writes a row to the
// audit log. Surfaced as a method on Server so D-Slices 3 + 7 can wire
// their gating layers in without restructuring.
//
// Per the audit-cadence self-check: this is where the audit row gets
// enough fact for D-Slices 3+ to JOIN against. We include statement,
// statement_type, tables, functions, decision_verdict, and the parser's
// flag bag so the rule engine + recommender can compose against rows
// already on disk.
func (s *Server) evaluateAndAudit(sql, source string) {
	ps := parser.Parse(sql)
	verdict, reason := s.decide(ps)
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
		DecisionVerdict:  string(verdict),
		DecisionReason:   reason,
		ModeAtDecision:   string(s.cfg.Mode),
		Enforced:         false, // D-Slice 1: never enforced (no forwarding)
		ProfileName:      s.cfg.ActiveProfileName,
		DecisionSource:   "d-slice-1-observation-only",
	}
	if _, err := s.store.RecordDecision(row); err != nil {
		BumpLookupErrors()
		log.Warn().Err(err).Str("source", source).
			Msg("dbounce: record decision failed")
	}
}

// decide is the D-Slice 1 verdict function: ALWAYS allow, with a
// human-readable reason that explains the observation-only stance.
// D-Slices 3 + 7 + 8 layer real gating on top.
func (s *Server) decide(ps *parser.ParsedStatement) (Verdict, string) {
	// Per [[safety-mode-lean-permissive]]: D-Slice 1 is observation-
	// only. The proxy never blocks; the audit row captures intent so
	// the operator can preview what transparent mode would have done
	// once D-Slice 2 lands.
	reason := fmt.Sprintf(
		"observation-only (statement_type=%s, tables=%d, functions=%d); "+
			"D-Slice 1 never forwards or blocks",
		ps.StatementType, len(ps.TablesTouched), len(ps.FunctionsCalled),
	)
	return VerdictAllow, reason
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
// not set one. CLI calls this at startup so library users (tests) get
// plain JSON logs without configuring the logger themselves.
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

// ParseMode parses a CLI flag value into a Mode, returning an error
// for unknown values. Kept here so cmd/ doesn't have to repeat the
// validation.
func ParseMode(s string) (Mode, error) {
	m := Mode(s)
	if m.IsValid() {
		return m, nil
	}
	return "", fmt.Errorf("dbounce: unknown mode %q (want cooperative | transparent)", s)
}

// ParseDefaultPolicy parses a CLI flag value into a DefaultPolicy,
// returning an error for unknown values.
func ParseDefaultPolicy(s string) (DefaultPolicy, error) {
	p := DefaultPolicy(s)
	if p.IsValid() {
		return p, nil
	}
	return "", fmt.Errorf("dbounce: unknown default-policy %q (want allow | deny)", s)
}

// ParseDialect parses a CLI flag value into a Dialect, returning an
// error for unknown values. D-Slice 1 accepts only postgres.
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
	// Frontend message type bytes per the PG protocol.
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

// pgHandshake reads the StartupMessage / SSLRequest and writes the
// minimum-viable startup response so a libpq client transitions into
// the command loop.
//
// D-Slice 1 always answers AuthenticationOk (we don't dial an upstream
// to check credentials; that's D-Slice 2). This is safe because the
// listener defaults to 127.0.0.1 (per the loopback guard in the CLI).
func pgHandshake(conn net.Conn) error {
	// First 4 bytes = total length (BE int32). Next 4 bytes = protocol
	// version OR SSLRequest magic (80877103).
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("read startup header: %w", err)
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	magic := binary.BigEndian.Uint32(hdr[4:8])

	// SSLRequest = 80877103. D-Slice 1 doesn't speak TLS yet; respond
	// 'N' (no SSL) per the protocol and let the client decide whether
	// to continue in plaintext.
	if magic == 80877103 {
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return fmt.Errorf("write SSL-no: %w", err)
		}
		// After 'N' the client sends a fresh StartupMessage.
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return fmt.Errorf("read second startup header: %w", err)
		}
		length = binary.BigEndian.Uint32(hdr[0:4])
		magic = binary.BigEndian.Uint32(hdr[4:8])
	}

	// GSSENCRequest = 80877104. Same treatment as SSLRequest.
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

	// CancelRequest = 80877102. Operator pressed Ctrl+C in psql. We
	// don't have a backend session to cancel in D-Slice 1; close.
	if magic == 80877102 {
		return errors.New("CancelRequest received; nothing to cancel in D-Slice 1")
	}

	// Now `length` is the StartupMessage length INCLUDING the 4-byte
	// length prefix; magic is the protocol-version int32. Read the
	// rest of the body (length - 8 bytes already consumed).
	if length < 8 || length > 1<<20 {
		return fmt.Errorf("implausible startup length: %d", length)
	}
	body := make([]byte, length-8)
	if _, err := io.ReadFull(conn, body); err != nil {
		return fmt.Errorf("read startup body: %w", err)
	}
	// We ignore the parameter pairs in D-Slice 1.

	// Write AuthenticationOk (R, length 8, code 0).
	if err := writeMessage(conn, 'R', []byte{0, 0, 0, 0}); err != nil {
		return err
	}
	// Write a minimal BackendKeyData (K, length 12, pid + secret) so
	// libpq clients have something to track.
	bkd := make([]byte, 8)
	binary.BigEndian.PutUint32(bkd[0:4], 1) // pid
	binary.BigEndian.PutUint32(bkd[4:8], 0) // secret
	if err := writeMessage(conn, 'K', bkd); err != nil {
		return err
	}
	// ReadyForQuery (Z, length 5, status 'I' = idle).
	if err := writeMessage(conn, 'Z', []byte{'I'}); err != nil {
		return err
	}
	return nil
}

// readPGMessage reads a single non-startup wire-protocol message.
// Returns the message type byte + the payload (without the 4-byte
// length prefix).
func readPGMessage(conn net.Conn) (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, err
	}
	msgType := hdr[0]
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length < 4 || length > 16<<20 {
		// Per the audit-cadence self-check: malformed length bytes
		// MUST NOT panic. Return an error; the caller closes the
		// connection cleanly.
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

// writeMessage writes a single non-startup wire-protocol message.
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

// readCString reads bytes up to the first NUL byte from b and returns
// them as a string. Returns the entire buffer when no NUL is present
// (malformed messages — caller decides what to do).
func readCString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// firstNullPlus1 returns the index after the first NUL byte in b, or
// len(b) when no NUL is present. Used to skip past the statement-name
// field in Parse messages.
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

// writeJSON is a tiny wrapper so /healthz doesn't directly depend on
// encoding/json — keeps the JSON encoder swappable should we ever want
// to do batched-flush output in a later slice.
func writeJSON(w io.Writer, v any) error {
	return jsonEncode(w, v)
}

// lookupEnv is a tiny wrapper to keep `os` import contained.
func lookupEnv(key string) string { return osLookupEnv(key) }

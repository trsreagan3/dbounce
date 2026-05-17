// D-Slice 2 — PG wire-protocol forwarding to a real upstream.
//
// What changed vs. D-Slice 1:
//
//   - The per-connection serve loop now optionally dials a real PG
//     upstream. When an upstream is configured, dbounce becomes a
//     transparent man-in-the-middle for the inbound session: SCRAM /
//     MD5 / cleartext auth flows are forwarded verbatim, ALLOW verdicts
//     send the original message bytes upstream + stream the reply back,
//     and DENY-in-transparent-mode rejects the message with a PG
//     ErrorResponse without touching the upstream.
//
//   - When NO upstream is configured (`--upstream ""`), the proxy keeps
//     the D-Slice 1 observation-only behavior.
//
// LOAD-BEARING invariants (parallel to kbouncer + iam-jit-bouncer):
//
//   - dbounce NEVER touches the password or the SCRAM tokens. The
//     authentication phase is byte-level pass-through: bytes traverse
//     io.ReadFull / Write only. Grep verification: `grep -ri "password"
//     internal/proxy/` returns no captures of an inbound password.
//
//   - The outbound HOST IS THE ALLOWLIST. The upstream URL resolved at
//     startup is the only legal forward target. Mirrors kbouncer's
//     WB32-01 closure for the PG shape.
//
//   - The outbound TLS handshake validates the upstream's cert against
//     the system trust store (or --upstream-ca-cert pool) by default.
//     Verification is skipped ONLY when the operator passes
//     --upstream-tls skip. Never inferred from the URL scheme.
//
//   - DENY-in-transparent-mode returns a PG ErrorResponse with SQLSTATE
//     42501 + the decision reason. The upstream is NEVER contacted.
//
//   - DENY-in-cooperative-mode FORWARDS anyway (advisory); the audit
//     row records `forwarded=true` + `decision_verdict=DENY` so
//     reviewers can see "transparent mode would have blocked this."

package proxy

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/dbounce/internal/parser"
	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/upstream"
)

// Forwarder bundles per-session state for a forwarding connection.
type Forwarder struct {
	srv          *Server
	in           net.Conn
	out          net.Conn
	upstream     *upstream.Upstream
	startupBytes []byte
}

// PG SQLSTATE codes used by the proxy.
const (
	sqlStateInsufficientPrivilege = "42501"
	sqlStateConnectionFailure     = "08006"
)

// Upstream-status constants stamped into DecisionRow.UpstreamStatus.
const (
	upstreamStatusOk           = "ok"
	upstreamStatusError        = "error"
	upstreamStatusNotForwarded = "not_forwarded"
)

// upstreamForwardingActive reports whether the server was configured
// with a real upstream.
func (s *Server) upstreamForwardingActive() bool {
	return s.cfg.Upstream != nil
}

// serveConnWithUpstream is the D-Slice 2 per-connection handler.
func (s *Server) serveConnWithUpstream(in net.Conn) {
	f := &Forwarder{
		srv:      s,
		in:       in,
		upstream: s.cfg.Upstream,
	}
	defer func() {
		if f.out != nil {
			_ = f.out.Close()
		}
	}()
	if err := f.run(); err != nil {
		log.Debug().Err(err).
			Str("remote", in.RemoteAddr().String()).
			Msg("dbounce: forwarder ended")
	}
}

func (f *Forwarder) run() error {
	if err := f.negotiateSSL(); err != nil {
		return fmt.Errorf("ssl negotiation: %w", err)
	}
	if err := f.handshakeAndAuth(); err != nil {
		return fmt.Errorf("handshake/auth: %w", err)
	}
	return f.commandLoop()
}

// negotiateSSL handles the optional SSL handshake.
//
// D-Slice 4 layering: listener-side TLS is handled HERE, before the
// outbound dial. When the client sends SSLRequest + we have a
// listenerTLS, we reply 'S' + perform the inbound TLS handshake + wrap
// f.in in *tls.Conn. After the upgrade we read a FRESH 8-byte preamble
// (the StartupMessage) off the now-TLS conn + dial upstream + negotiate
// outbound TLS independently.
//
// Independence invariant: listener TLS and outbound TLS are decoupled.
// The proxy may speak TLS in + plaintext out (or vice versa) —
// operators who want end-to-end TLS configure both sides.
func (f *Forwarder) negotiateSSL() error {
	_ = f.in.SetDeadline(time.Now().Add(f.srv.cfg.IdleTimeout))
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(f.in, hdr); err != nil {
		return fmt.Errorf("read inbound startup header: %w", err)
	}
	magic := binary.BigEndian.Uint32(hdr[4:8])

	// D-Slice 4: listener-side TLS upgrade.
	if magic == 80877103 && f.srv.cfg.ListenerTLS != nil {
		upgraded, err := upgradeListenerTLS(f.in, hdr, f.srv.cfg.ListenerTLS)
		if err != nil {
			return fmt.Errorf("listener TLS upgrade: %w", err)
		}
		f.in = upgraded
		hdr = make([]byte, 8)
		if _, err := io.ReadFull(f.in, hdr); err != nil {
			return fmt.Errorf("read post-tls inbound startup: %w", err)
		}
		magic = binary.BigEndian.Uint32(hdr[4:8])
		// Fall through into the upstream-SSL branches below with the
		// fresh preamble.
	}

	if magic != 80877103 {
		f.startupBytes = hdr
		return f.dialUpstream()
	}

	if f.upstream.TLSMode == upstream.TLSModeDisable {
		if _, err := f.in.Write([]byte{'N'}); err != nil {
			return fmt.Errorf("write SSL-no: %w", err)
		}
		hdr2 := make([]byte, 8)
		if _, err := io.ReadFull(f.in, hdr2); err != nil {
			return fmt.Errorf("read re-startup header after SSL-no: %w", err)
		}
		f.startupBytes = hdr2
		return f.dialUpstream()
	}

	if err := f.dialUpstream(); err != nil {
		return err
	}
	if _, err := f.out.Write(hdr); err != nil {
		return fmt.Errorf("forward SSLRequest to upstream: %w", err)
	}
	sslResp := make([]byte, 1)
	if _, err := io.ReadFull(f.out, sslResp); err != nil {
		return fmt.Errorf("read upstream SSL reply: %w", err)
	}
	if sslResp[0] != 'S' && sslResp[0] != 'N' {
		return fmt.Errorf("bogus upstream SSL reply byte %q", sslResp[0])
	}
	if _, err := f.in.Write(sslResp); err != nil {
		return fmt.Errorf("echo SSL reply to client: %w", err)
	}
	if sslResp[0] == 'S' {
		// Audit-cadence (c): TLSConfig() defaults to validate.
		tlsCfg := f.upstream.TLSConfig()
		if tlsCfg == nil {
			return errors.New("upstream agreed to TLS but our TLS config is nil — refusing plaintext")
		}
		tlsConn := tls.Client(f.out, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("outbound TLS handshake: %w", err)
		}
		f.out = tlsConn
	}
	hdr2 := make([]byte, 8)
	if _, err := io.ReadFull(f.in, hdr2); err != nil {
		return fmt.Errorf("read inbound startup after SSL: %w", err)
	}
	f.startupBytes = hdr2
	return nil
}

func (f *Forwarder) dialUpstream() error {
	d := net.Dialer{Timeout: f.upstream.DialTimeout}
	c, err := d.Dial("tcp", f.upstream.Host())
	if err != nil {
		// Audit-cadence (a): surface the dial failure as a PG
		// ErrorResponse so the client doesn't hang.
		_ = f.writeErrorToClient(sqlStateConnectionFailure,
			fmt.Sprintf("dbounce: upstream dial failed: %v", err))
		return fmt.Errorf("dial upstream %s: %w", f.upstream.Host(), err)
	}
	f.out = c
	return nil
}

// handshakeAndAuth forwards StartupMessage + pumps auth.
//
// Audit-cadence (b): grep this file for "password" + "scram" — no
// named buffer holds an inbound password. The bytes traverse
// io.ReadFull / Write only.
func (f *Forwarder) handshakeAndAuth() error {
	length := binary.BigEndian.Uint32(f.startupBytes[0:4])
	if length < 8 || length > 1<<20 {
		return fmt.Errorf("implausible startup length: %d", length)
	}
	body := make([]byte, length-8)
	if length > 8 {
		if _, err := io.ReadFull(f.in, body); err != nil {
			return fmt.Errorf("read inbound startup body: %w", err)
		}
	}

	if _, err := f.out.Write(f.startupBytes); err != nil {
		return fmt.Errorf("forward startup preamble: %w", err)
	}
	if len(body) > 0 {
		if _, err := f.out.Write(body); err != nil {
			return fmt.Errorf("forward startup body: %w", err)
		}
	}

	return f.pumpAuthPhase()
}

// pumpAuthPhase shuttles auth messages between inbound + upstream
// until ReadyForQuery (auth done) or ErrorResponse (auth failed).
func (f *Forwarder) pumpAuthPhase() error {
	for {
		_ = f.out.SetDeadline(time.Now().Add(f.srv.cfg.ReadTimeout))
		msgType, payload, err := readPGMessage(f.out)
		if err != nil {
			return fmt.Errorf("read upstream auth message: %w", err)
		}
		if err := writeMessage(f.in, msgType, payload); err != nil {
			return fmt.Errorf("write auth message to client: %w", err)
		}
		switch msgType {
		case 'Z':
			return nil
		case 'E':
			// Audit-cadence (a): SCRAM error mid-flight surfaces here.
			return errors.New("upstream returned ErrorResponse during auth")
		case 'R':
			if len(payload) < 4 {
				return fmt.Errorf("malformed AuthenticationRequest payload (%d bytes)", len(payload))
			}
			authCode := binary.BigEndian.Uint32(payload[0:4])
			if authCode == 0 {
				continue
			}
			_ = f.in.SetDeadline(time.Now().Add(f.srv.cfg.ReadTimeout))
			cliType, cliPayload, err := readPGMessage(f.in)
			if err != nil {
				return fmt.Errorf("read client auth response: %w", err)
			}
			// Audit-cadence (b): cliPayload carries the SCRAM token /
			// password digest. Passed straight to writeMessage without
			// inspection or naming.
			if err := writeMessage(f.out, cliType, cliPayload); err != nil {
				return fmt.Errorf("write client auth response upstream: %w", err)
			}
		}
	}
}

func (f *Forwarder) commandLoop() error {
	for {
		_ = f.in.SetDeadline(time.Now().Add(f.srv.cfg.IdleTimeout))
		msgType, payload, err := readPGMessage(f.in)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("read inbound message: %w", err)
			}
			return nil
		}
		switch msgType {
		case msgTerminate:
			_ = writeMessage(f.out, msgType, payload)
			return nil
		case msgQuery:
			sql := readCString(payload)
			if err := f.handleGatedMessage(sql, "Query", msgType, payload); err != nil {
				return err
			}
		case msgParse:
			_ = readCString(payload)
			rest := payload[firstNullPlus1(payload):]
			sql := readCString(rest)
			if err := f.handleGatedMessage(sql, "Parse", msgType, payload); err != nil {
				return err
			}
		case msgBind, msgExecute, msgSync, msgFlush, msgDescribe, msgClose,
			'd', 'c', 'f':
			if err := f.forwardRaw(msgType, payload); err != nil {
				return err
			}
		default:
			log.Debug().Uint8("type", msgType).
				Str("remote", f.in.RemoteAddr().String()).
				Msg("dbounce: unsupported wire-protocol message; closing")
			return nil
		}
	}
}

func (f *Forwarder) handleGatedMessage(sql, source string, msgType byte, payload []byte) error {
	ps := parser.Parse(sql)
	dec := f.srv.decide(ps)

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
		DecisionVerdict:  string(dec.Verdict),
		DecisionReason:   dec.Reason,
		ModeAtDecision:   string(f.srv.cfg.Mode),
		ProfileName:      f.srv.cfg.ActiveProfileName,
		DecisionSource:   dec.Source,
		MatchedRuleID:    dec.MatchedRuleID,
		TaskID:           dec.TaskID,
	}

	if dec.Verdict == VerdictDeny && f.srv.cfg.Mode == ModeTransparent {
		row.Forwarded = false
		row.UpstreamStatus = upstreamStatusNotForwarded
		row.UpstreamResponseSummary = "transparent-mode deny: " + dec.Reason
		row.Enforced = true
		f.recordDecision(row, source)
		if err := f.writeErrorToClient(sqlStateInsufficientPrivilege,
			fmt.Sprintf("dbounce: denied: %s", dec.Reason)); err != nil {
			return fmt.Errorf("write transparent-deny ErrorResponse: %w", err)
		}
		if msgType == msgQuery {
			if err := writeReadyForQuery(f.in); err != nil {
				return fmt.Errorf("write RFQ after deny: %w", err)
			}
		}
		return nil
	}

	row.Forwarded = true
	row.Enforced = false
	if err := f.writeRawToUpstream(msgType, payload); err != nil {
		row.UpstreamStatus = upstreamStatusError
		row.UpstreamResponseSummary = "upstream write failed: " + err.Error()
		f.recordDecision(row, source)
		_ = f.writeErrorToClient(sqlStateConnectionFailure,
			fmt.Sprintf("dbounce: upstream write failed: %v", err))
		return err
	}
	summary, drainErr := f.drainUpstreamUntilRFQ()
	if drainErr != nil {
		row.UpstreamStatus = upstreamStatusError
		row.UpstreamResponseSummary = "upstream drain failed: " + drainErr.Error()
		f.recordDecision(row, source)
		return drainErr
	}
	row.UpstreamStatus = summary.Status
	row.UpstreamResponseSummary = summary.Text
	f.recordDecision(row, source)
	return nil
}

func (f *Forwarder) forwardRaw(msgType byte, payload []byte) error {
	if err := f.writeRawToUpstream(msgType, payload); err != nil {
		return err
	}
	if msgType == msgSync {
		_, drainErr := f.drainUpstreamUntilRFQ()
		return drainErr
	}
	return nil
}

func (f *Forwarder) writeRawToUpstream(msgType byte, payload []byte) error {
	_ = f.out.SetWriteDeadline(time.Now().Add(f.srv.cfg.WriteTimeout))
	return writeMessage(f.out, msgType, payload)
}

type drainResult struct {
	Status string
	Text   string
}

func (f *Forwarder) drainUpstreamUntilRFQ() (drainResult, error) {
	var (
		rowCount       int
		errMsg         string
		commandTag     string
		sawError       bool
		sawCommandDone bool
	)
	for {
		_ = f.out.SetReadDeadline(time.Now().Add(f.srv.cfg.ReadTimeout))
		msgType, payload, err := readPGMessage(f.out)
		if err != nil {
			return drainResult{Status: upstreamStatusError, Text: err.Error()},
				fmt.Errorf("drain upstream: %w", err)
		}
		if err := writeMessage(f.in, msgType, payload); err != nil {
			return drainResult{Status: upstreamStatusError, Text: err.Error()},
				fmt.Errorf("write upstream→client: %w", err)
		}
		switch msgType {
		case 'D':
			rowCount++
		case 'C':
			commandTag = readCString(payload)
			sawCommandDone = true
		case 'E':
			errMsg = extractErrorMessage(payload)
			sawError = true
		case 'Z':
			switch {
			case sawError:
				return drainResult{Status: upstreamStatusError, Text: "upstream error: " + errMsg}, nil
			case sawCommandDone:
				if rowCount > 0 {
					return drainResult{Status: upstreamStatusOk,
						Text: fmt.Sprintf("%d rows returned (%s)", rowCount, commandTag)}, nil
				}
				return drainResult{Status: upstreamStatusOk, Text: commandTag}, nil
			default:
				return drainResult{Status: upstreamStatusOk, Text: "ok"}, nil
			}
		}
	}
}

func (f *Forwarder) writeErrorToClient(code, msg string) error {
	if f.in == nil {
		return nil
	}
	var b []byte
	b = append(b, 'S')
	b = append(b, []byte("ERROR")...)
	b = append(b, 0)
	b = append(b, 'V')
	b = append(b, []byte("ERROR")...)
	b = append(b, 0)
	b = append(b, 'C')
	b = append(b, []byte(code)...)
	b = append(b, 0)
	b = append(b, 'M')
	b = append(b, []byte(msg)...)
	b = append(b, 0)
	b = append(b, 0)
	return writeMessage(f.in, 'E', b)
}

func (f *Forwarder) recordDecision(row store.DecisionRow, source string) {
	if _, err := f.srv.store.RecordDecision(row); err != nil {
		BumpLookupErrors()
		log.Warn().Err(err).Str("source", source).
			Msg("dbounce: record decision failed")
	}
}

// extractErrorMessage pulls the 'M' field out of an ErrorResponse
// payload. PG errors use tagged C-strings.
func extractErrorMessage(payload []byte) string {
	i := 0
	for i < len(payload) {
		if payload[i] == 0 {
			break
		}
		tag := payload[i]
		i++
		end := i
		for end < len(payload) && payload[end] != 0 {
			end++
		}
		val := string(payload[i:end])
		i = end + 1
		if tag == 'M' {
			return val
		}
	}
	return "(no message)"
}

// hostAllowed mirrors kbouncer's WB32-01 closure for the PG shape.
// PG has no Host header so this helper is always called with
// inboundHost = "" in D-Slice 2. Kept for cross-product audit-log
// parity + so D-Slice 4's SNI-routing slice can call it.
func hostAllowed(inboundHost string, up *upstream.Upstream) bool {
	if up == nil {
		return false
	}
	if inboundHost == "" {
		return true
	}
	want := strings.ToLower(up.Host())
	got := strings.ToLower(inboundHost)
	if want == got {
		return true
	}
	wantHost, _, _ := net.SplitHostPort(want)
	gotHost, _, _ := net.SplitHostPort(got)
	if wantHost == "" {
		wantHost = want
	}
	if gotHost == "" {
		gotHost = got
	}
	return wantHost != "" && wantHost == gotHost
}

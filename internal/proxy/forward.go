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

	// startupBody is the PG StartupMessage parameter block (everything
	// after the protocol version), captured during handshakeAndAuth so
	// the agent-fingerprint helper can pull application_name out of it
	// per [[agent-identity-in-audit]] Feature 1. nil after handshake on
	// connections that didn't carry params (which is unusual — a real
	// PG client always sends at least user + database).
	startupBody []byte

	// sessionID is the per-connection agent-session id minted by
	// registerPGAgentFromBody after handshakeAndAuth completes. Empty
	// until set; threads onto every exportDecisionRowWithAgent call so
	// unmapped.iam_jit.agent carries the per-connection fingerprint.
	// Retired on connection close + emits a SESSION_ENDED synthetic.
	sessionID string
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

// syncPromptActive reports whether #203's synchronous deny-prompt
// path should fire for THIS request. The check intentionally mirrors
// the "block before deny" gate exactly so PG + MySQL forwarders agree
// without a per-protocol fork:
//
//   - --sync-prompt-on-deny must be set (operator opt-in)
//   - mode must be transparent (cooperative DENYs are advisory; sync
//     would be theater)
//   - an upstream must be configured (otherwise there's nowhere to
//     forward an allow answer to; the CLI also rejects this at parse,
//     so this is a defensive duplicate)
//   - no pause window may be active (pause supersedes — the operator
//     already said "let it through")
//
// Lookup-failure on IsPaused logs + treats as "not paused" (same
// policy as the rest of the proxy — a flaky SQLite read must not
// silently disable a security gate).
func (s *Server) syncPromptActive() bool {
	if !s.cfg.SyncPromptOnDeny {
		return false
	}
	if s.cfg.Mode != ModeTransparent {
		return false
	}
	if !s.upstreamForwardingActive() {
		return false
	}
	if s.store == nil {
		return false
	}
	paused, _, err := s.store.IsPaused()
	if err != nil {
		BumpLookupErrors()
		log.Warn().Err(err).Msg("dbounce: IsPaused lookup failed in syncPromptActive; treating as not paused")
		return true
	}
	return !paused
}

// awaitSyncPromptDecision enqueues a sync prompt + blocks the calling
// goroutine until the operator answers, the timeout expires, or the
// caller's context fires. Returns the decision applied (allow / deny /
// timeout) along with the prompt id that was created (audit-row
// linkage) and the sync_wait_id (so callers can log it).
//
// SHARED across PG + MySQL forwarders so the lifecycle is in one
// place. The protocol-specific bytes ("emit ErrorResponse" vs "emit
// ERR_Packet" / "forward the original packet" vs "forward the
// original message") still live in each forwarder; this helper owns
// the channel + timeout + cancel-on-exit lifecycle.
//
// CROSS-PROCESS WAKEUP: The in-memory registry channel works ONLY
// when the proxy + the `dbounce prompts answer` invocation share a
// process (rare; the CLI typically runs as a separate command). To
// make the cross-process case work, this helper ALSO polls the
// pending_prompts row's status column on a 200ms cadence + maps the
// persisted answer kind onto a PromptDecision. Both paths race; the
// first one wins. The poll is cheap (single indexed lookup against
// SQLite) and bounded by the same timeout.
func (s *Server) awaitSyncPromptDecision(ps *parsedStatementView, decisionID int64, denyReason string) (store.PromptDecision, int64, string) {
	if s.store == nil {
		// Defensive: callers gate on syncPromptActive() which already
		// requires a store, but be conservative.
		return resolveSyncPromptTimeout(s.cfg.SyncPromptDefault), 0, ""
	}
	promptID, waitID, ch, err := s.store.AddSyncPendingPrompt(store.PendingPrompt{
		DecisionID:      decisionID,
		StatementType:   ps.StatementType,
		TablesTouched:   ps.TablesTouched,
		FunctionsCalled: ps.FunctionsCalled,
		DenyReason:      denyReason,
	})
	if err != nil {
		BumpLookupErrors()
		log.Warn().Err(err).Int64("decision_id", decisionID).
			Msg("dbounce: enqueue sync pending prompt failed; falling back to deny")
		// Audit invariant: we'd rather over-deny than silently allow
		// on storage-layer failure. The CLI's transparent-mode DENY
		// path fires next.
		return store.PromptDecisionDeny, 0, ""
	}
	timeout := s.cfg.SyncPromptTimeout
	if timeout <= 0 {
		// Defensive: Normalize sets a default, but if a caller
		// constructs Config directly without Normalize() this
		// prevents a 0-duration timer (fires immediately) from
		// silently turning sync into "always use the default".
		timeout = 30 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	// Cross-process poll. 200ms strikes the balance between operator-
	// perceived latency ("I answered, why is the query still hung?")
	// + SQLite read overhead (negligible for an indexed single-row
	// lookup, but no point hammering it). Stops on the same defer
	// chain as `timer`.
	poll := time.NewTicker(200 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case decision, ok := <-ch:
			if !ok {
				return resolveSyncPromptTimeout(s.cfg.SyncPromptDefault), promptID, waitID
			}
			log.Info().Str("sync_wait_id", waitID).Int64("prompt_id", promptID).
				Str("decision", string(decision)).
				Msg("dbounce: sync deny-prompt resolved by operator answer (same-process channel)")
			return decision, promptID, waitID
		case <-poll.C:
			// Cross-process path: read the row's status. The CLI's
			// `prompts answer` UPDATEd the row (via the same SQLite
			// file) but couldn't wake our in-memory channel because
			// it's a separate process. We poll for the change.
			p, perr := s.store.GetPendingPrompt(promptID)
			if perr != nil {
				BumpLookupErrors()
				log.Warn().Err(perr).Int64("prompt_id", promptID).
					Msg("dbounce: poll sync prompt status failed; continuing")
				continue
			}
			if p == nil || p.Status == store.PromptPending {
				continue
			}
			// Operator answered cross-process. Cancel our registry
			// entry so it doesn't leak; map answer kind → decision.
			s.store.CancelSyncPendingPrompt(waitID)
			decision := store.PromptDecisionDeny
			switch p.AnswerKind {
			case "always", "profile":
				decision = store.PromptDecisionAllow
			case "ignore":
				decision = store.PromptDecisionDeny
			default:
				// Defensive: an unrecognized kind defaults to deny.
				decision = store.PromptDecisionDeny
			}
			log.Info().Str("sync_wait_id", waitID).Int64("prompt_id", promptID).
				Str("answer_kind", p.AnswerKind).Str("decision", string(decision)).
				Msg("dbounce: sync deny-prompt resolved by operator answer (cross-process poll)")
			return decision, promptID, waitID
		case <-timer.C:
			s.store.CancelSyncPendingPrompt(waitID)
			applied := resolveSyncPromptTimeout(s.cfg.SyncPromptDefault)
			log.Info().Str("sync_wait_id", waitID).Int64("prompt_id", promptID).
				Dur("timeout", timeout).Str("applied", string(applied)).
				Msg("dbounce: sync deny-prompt timed out; applying --sync-prompt-default")
			return applied, promptID, waitID
		}
	}
}

// parsedStatementView is the small subset of parser.ParsedStatement
// the sync-prompt helper needs to enqueue a row. Kept proxy-private
// so the helper doesn't pull in the parser pkg dependency
// unnecessarily.
type parsedStatementView struct {
	StatementType   string
	TablesTouched   []string
	FunctionsCalled []string
}

// resolveSyncPromptTimeout maps the operator's --sync-prompt-default
// to the corresponding PromptDecision. Timeout is its own distinct
// PromptDecision in the wakeup ch path, but here we project it onto
// the applied verdict so downstream decide-branches stay binary
// (forward vs not-forward).
func resolveSyncPromptTimeout(d SyncPromptDefault) store.PromptDecision {
	if d == SyncPromptDefaultAllow {
		return store.PromptDecisionAllow
	}
	return store.PromptDecisionDeny
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
		// [[agent-identity-in-audit]] Feature 2: emit SESSION_ENDED on
		// connection close. emitSessionEnded is idempotent + handles an
		// empty sessionID (handshake failed before mint) by short-
		// circuiting.
		s.emitSessionEnded(f.sessionID)
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
	// [[agent-identity-in-audit]] Feature 1+2: mint the per-connection
	// agent session AFTER auth succeeds (handshakeAndAuth captures the
	// StartupMessage body into f.startupBody) but BEFORE the command
	// loop starts so the first audit-export event already carries the
	// session id + the parsed application_name.
	f.sessionID = f.srv.registerPGAgentFromBody(f.startupBody)
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
	// [[agent-identity-in-audit]] Feature 1: stash the body so run()
	// can pull application_name out of it after auth completes. The
	// bytes themselves still forward to the upstream verbatim below.
	f.startupBody = body

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
	ps := parser.Parse(string(f.srv.cfg.Dialect), sql)
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
		// #203 sync-prompt-on-deny: BLOCK this goroutine waiting for
		// the operator's answer BEFORE we commit to denying. If the
		// operator answers allow (kind=always or kind=profile), we
		// flip the local decision to allow + fall through to the
		// forward path. If they answer deny (kind=ignore) or the
		// timeout fires with --sync-prompt-default=deny, we proceed
		// with the existing transparent-deny path.
		//
		// We record the DENY audit row FIRST (so the sync prompt has
		// a real decision_id FK to point at + the audit log captures
		// "the rule engine wanted DENY"), then re-record the eventual
		// resolved outcome as a second row. That double-row pattern
		// keeps both halves of the decision visible to post-incident
		// review: "rule wanted deny, operator allowed via sync prompt
		// at HH:MM:SS, request forwarded with N rows returned."
		syncFlippedToAllow := false
		if f.srv.syncPromptActive() {
			pendingRow := row
			pendingRow.Forwarded = false
			pendingRow.UpstreamStatus = upstreamStatusNotForwarded
			pendingRow.UpstreamResponseSummary = "sync-prompt-on-deny: blocking for operator answer (reason: " + dec.Reason + ")"
			pendingRow.Enforced = false
			pendingDecisionID, recErr := f.srv.store.RecordDecision(pendingRow)
			if recErr != nil {
				BumpLookupErrors()
				log.Warn().Err(recErr).Str("source", source).
					Msg("dbounce: record sync-prompt pending decision failed; falling back to plain deny")
			} else {
				psv := &parsedStatementView{
					StatementType:   row.StatementType,
					TablesTouched:   row.TablesTouched,
					FunctionsCalled: row.FunctionsCalled,
				}
				outcome, promptID, waitID := f.srv.awaitSyncPromptDecision(psv, pendingDecisionID, dec.Reason)
				if outcome == store.PromptDecisionAllow {
					row.DecisionVerdict = string(VerdictAllow)
					row.DecisionReason = fmt.Sprintf(
						"sync-prompt-on-deny allowed by operator (rule engine wanted DENY: %s; sync_wait_id=%s, prompt_id=%d)",
						dec.Reason, waitID, promptID)
					row.DecisionSource = "sync-prompt.allow"
					syncFlippedToAllow = true
				} else {
					// PromptDecisionDeny (operator said ignore) OR
					// PromptDecisionTimeout-projected-to-deny.
					row.DecisionReason = fmt.Sprintf(
						"%s (sync prompt %d: %s; sync_wait_id=%s)",
						dec.Reason, promptID, string(outcome), waitID)
				}
			}
		}
		if !syncFlippedToAllow {
			row.Forwarded = false
			row.UpstreamStatus = upstreamStatusNotForwarded
			row.UpstreamResponseSummary = "transparent-mode deny: " + row.DecisionReason
			row.Enforced = true
			f.recordDecision(row, source)
			if err := f.writeErrorToClient(sqlStateInsufficientPrivilege,
				fmt.Sprintf("dbounce: denied: %s", row.DecisionReason)); err != nil {
				return fmt.Errorf("write transparent-deny ErrorResponse: %w", err)
			}
			if msgType == msgQuery {
				if err := writeReadyForQuery(f.in); err != nil {
					return fmt.Errorf("write RFQ after deny: %w", err)
				}
			}
			return nil
		}
		// syncFlippedToAllow=true: fall through into the forward path
		// below — the operator's "allow" answer turns this into the
		// equivalent of cooperative-mode forwarding.
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
	decisionID, err := f.srv.store.RecordDecision(row)
	if err != nil {
		BumpLookupErrors()
		log.Warn().Err(err).Str("source", source).
			Msg("dbounce: record decision failed")
		return
	}
	// #252 Slice 1 audit-export fan-out. See proxy.go
	// exportDecisionRow for the rationale. The PG forwarder records
	// multiple rows per gated message (sync-prompt pending + final
	// outcome); each row exports separately so the downstream consumer
	// sees the full state machine in JSONL order.
	//
	// [[agent-identity-in-audit]] Feature 1+2: thread f.sessionID so
	// the per-connection agent fingerprint (parsed from PG
	// application_name) lands under unmapped.iam_jit.agent on every
	// audit event.
	f.srv.exportDecisionRowWithAgent(row, decisionID, f.sessionID)
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

// D-Slice 5 — MySQL wire-protocol handler.
//
// Parallels forward.go's PG implementation. The split is intentional:
// MySQL's protocol shape (length-prefixed packets with a sequence id,
// COM_* command bytes, caching_sha2_password / mysql_native_password
// auth flows) is materially different from PG's (typed messages,
// SCRAM/MD5/cleartext auth) — sharing helpers would obscure both
// rather than simplify. forward.go's `pumpAuthPhase` stays PG-specific;
// this file's pumpMySQLAuthPhase is the MySQL analog.
//
// LOAD-BEARING invariants (parallel to forward.go's audit-cadence
// closures + the SCRAM pass-through pattern):
//
//   - dbounce NEVER touches the password, the caching_sha2_password
//     scramble, the mysql_native_password challenge, or the public-key
//     exchange. Auth bytes traverse readMySQLPacket / writeMySQLPacket
//     only — no named buffer holds an inbound password. Same grep-
//     verifiable property the PG side has.
//
//   - The outbound HOST IS THE ALLOWLIST. The Upstream URL resolved at
//     startup is the only legal forward target. Same WB32-01 closure
//     the PG side enforces.
//
//   - COM_QUERY (0x03) is the only statement entry point gated in v1.0.
//     COM_STMT_PREPARE (0x16) + COM_STMT_EXECUTE (0x17) are EXPLICITLY
//     REJECTED with a clear ErrPacket directing the operator to use
//     direct queries until D-Slice 6 (or post-launch — TODO in the
//     MySQL rule pack metadata).
//
//   - MySQL listener TLS is NOT supported in v1.0 — the CLI rejects
//     --listener-tls-cert + --dialect mysql with a clear error so we
//     fail-fast rather than silently downgrade. The MySQL handshake's
//     SSL_REQUEST + CLIENT_SSL capability bit is left UNSET in the
//     observation-only Initial Handshake, and forwarded verbatim in
//     upstream mode (the upstream's announcement decides; the client
//     opts in via SSL_REQUEST on the wire and we forward those bytes
//     unchanged). D-Slice 4 ships listener TLS for PG; the MySQL
//     listener follows post-launch.
//
//   - DENY-in-transparent-mode returns an ErrPacket (server protocol
//     error 1142 ER_TABLEACCESS_DENIED_ERROR equivalent — we use 1227
//     ER_SPECIFIC_ACCESS_DENIED_ERROR + the decision reason). Upstream
//     is NEVER contacted.
//
//   - DENY-in-cooperative-mode FORWARDS anyway (advisory) — same
//     pattern as the PG side.

package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/parser"
	"github.com/trsreagan3/dbounce/internal/store"
)

// MySQL packet header constants.
const (
	mysqlPacketHeaderLen = 4

	// Command bytes (see MySQL docs §"Command Phase").
	mysqlComSleep           byte = 0x00
	mysqlComQuit            byte = 0x01
	mysqlComInitDB          byte = 0x02
	mysqlComQuery           byte = 0x03
	mysqlComFieldList       byte = 0x04
	mysqlComPing            byte = 0x0e
	mysqlComStmtPrepare     byte = 0x16
	mysqlComStmtExecute     byte = 0x17
	mysqlComStmtClose       byte = 0x19
	mysqlComStmtReset       byte = 0x1a
	mysqlComSetOption       byte = 0x1b

	// Response-packet leading bytes.
	mysqlOKPacketByte  byte = 0x00
	mysqlErrPacketByte byte = 0xff
	mysqlEOFPacketByte byte = 0xfe

	// MySQL error codes (subset).
	mysqlErrSpecificAccessDenied uint16 = 1227 // ER_SPECIFIC_ACCESS_DENIED_ERROR
	mysqlErrUnknown              uint16 = 1105 // ER_UNKNOWN_ERROR
	mysqlSQLStateAccessDenied    string = "42000"
	mysqlSQLStateGeneral         string = "HY000"
)

// serveMySQLConn is the MySQL counterpart of serveConn's PG branch.
// Dispatches to the upstream-forwarding handler when an upstream is
// configured, otherwise serves an observation-only loop.
func (s *Server) serveMySQLConn(conn net.Conn) {
	if s.upstreamForwardingActive() {
		s.serveMySQLConnWithUpstream(conn)
		return
	}
	handshakeResponse, err := mysqlObservationHandshake(conn)
	if err != nil {
		log.Debug().Err(err).Str("remote", conn.RemoteAddr().String()).
			Msg("dbounce: mysql handshake failed")
		return
	}
	// [[agent-identity-in-audit]] Feature 1+2: parse client connection
	// attributes from the HandshakeResponse payload + mint a per-
	// connection session id. The MySQL Initial Handshake we sent
	// advertises CLIENT_CONNECT_ATTRS (0x00100000) in the upper-cap
	// byte; honest clients (MySQL Connector/J, libmysql, mysql CLI)
	// echo their _client_name + _client_version + _program_name in the
	// response. Best-effort: missing attrs → name="unknown" + the
	// session id still propagates.
	sessionID := s.registerMySQLAgentFromHandshakeResponse(handshakeResponse)
	defer s.emitSessionEnded(sessionID)
	for {
		_ = conn.SetDeadline(time.Now().Add(s.cfg.IdleTimeout))
		seq, payload, err := readMySQLPacket(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Debug().Err(err).Str("remote", conn.RemoteAddr().String()).
					Msg("dbounce: mysql read message")
			}
			return
		}
		if len(payload) == 0 {
			continue
		}
		cmd := payload[0]
		switch cmd {
		case mysqlComQuit:
			return
		case mysqlComPing:
			if err := writeMySQLOK(conn, seq+1, 0, 0); err != nil {
				return
			}
		case mysqlComInitDB:
			if err := writeMySQLOK(conn, seq+1, 0, 0); err != nil {
				return
			}
		case mysqlComQuery:
			sql := string(payload[1:])
			s.evaluateAndAuditWithAgent(sql, "mysql.Query", sessionID)
			// Observation-only: send back a minimal OK (zero rows).
			if err := writeMySQLOK(conn, seq+1, 0, 0); err != nil {
				return
			}
		case mysqlComStmtPrepare:
			// Prepared statements are out-of-scope for v1.0.
			_ = writeMySQLErr(conn, seq+1, mysqlErrSpecificAccessDenied,
				mysqlSQLStateAccessDenied,
				"dbounce: prepared statements not yet supported in v1.0; use direct queries")
			return
		default:
			// Unknown / unsupported commands close the connection cleanly.
			log.Debug().Uint8("cmd", cmd).
				Str("remote", conn.RemoteAddr().String()).
				Msg("dbounce: unsupported mysql command; closing")
			return
		}
	}
}

// mysqlObservationHandshake sends a minimal Initial Handshake v10 to
// the client + accepts whatever auth response the client returns,
// without validating it. The observation-only mode is for operators
// who want to point a MySQL client at dbounce + see the audit log
// populate even with no real DB on the other side. Same role
// pgHandshake plays for the PG observation-only path.
//
// NOTE: dbounce does NOT compute caching_sha2_password / mysql_native_
// password scrambles. We send mysql_native_password as the auth plugin
// name + accept the auth response opaquely, then return an OK packet.
// The connection isn't a real DB session; the client's first COM_QUERY
// will be audit-logged + acked with an empty OK.
//
// Returns the HandshakeResponse payload bytes so the caller can parse
// the connection-attributes block per
// [[agent-identity-in-audit]] Feature 1. A successful call always
// returns a non-nil byte slice (may be empty when the client sent an
// empty response); nil is reserved for the error case.
func mysqlObservationHandshake(conn net.Conn) ([]byte, error) {
	// Build Initial Handshake packet.
	const serverVersion = "8.0.0-dbounce-observation\x00"

	pkt := make([]byte, 0, 128)
	pkt = append(pkt, 0x0a) // protocol version 10
	pkt = append(pkt, []byte(serverVersion)...)
	// connection_id (4 bytes)
	pkt = append(pkt, 0x01, 0x00, 0x00, 0x00)
	// auth_plugin_data_part_1 (8 bytes) — random-looking but
	// deterministic (we don't validate the response anyway)
	pkt = append(pkt, 'd', 'b', 'o', 'u', 'n', 'c', 'e', '0')
	pkt = append(pkt, 0x00) // filler
	// capability_flags_lower (2 bytes): CLIENT_PROTOCOL_41 (0x0200)
	// CLIENT_SECURE_CONNECTION (0x8000) + CLIENT_PLUGIN_AUTH (0x80000)
	// in upper. Use the basic set the client expects.
	pkt = append(pkt, 0x0d, 0xa2) // 0xa20d — long flag + connect with db + protocol 41 + transactions + secure conn
	pkt = append(pkt, 0x21)       // utf8 charset
	pkt = append(pkt, 0x02, 0x00) // status flags
	pkt = append(pkt, 0x00, 0x80) // capability_flags_upper: plugin auth (0x0008 << 16)
	pkt = append(pkt, 21)         // auth_plugin_data_len
	pkt = append(pkt, make([]byte, 10)...) // reserved (10 bytes of 0x00)
	// auth_plugin_data_part_2 (12 bytes + 1 NUL = 13)
	pkt = append(pkt, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', 0x00)
	pkt = append(pkt, []byte("mysql_native_password\x00")...)

	if err := writeMySQLPacket(conn, 0, pkt); err != nil {
		return nil, fmt.Errorf("write initial handshake: %w", err)
	}

	// Read client's HandshakeResponse — opaque to the auth path but
	// fed back to the agent-fingerprint parser so we can pull the
	// _client_name / _client_version / _program_name attrs.
	_, response, err := readMySQLPacket(conn)
	if err != nil {
		return nil, fmt.Errorf("read handshake response: %w", err)
	}

	// Reply OK (auth accepted in observation mode).
	if err := writeMySQLOK(conn, 2, 0, 0); err != nil {
		return nil, err
	}
	return response, nil
}

// readMySQLPacket reads one MySQL wire-protocol packet from the conn:
// 3-byte little-endian length, 1-byte sequence id, then payload.
//
// Returns (seq, payload, err). Implausible lengths (>16 MiB) are
// rejected before allocation to bound memory.
func readMySQLPacket(conn net.Conn) (byte, []byte, error) {
	hdr := make([]byte, mysqlPacketHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, err
	}
	// 24-bit little-endian length.
	length := uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16
	seq := hdr[3]
	if length > 16<<20 {
		return 0, nil, fmt.Errorf("dbounce mysql: implausible packet length %d", length)
	}
	if length == 0 {
		return seq, nil, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return seq, payload, nil
}

// writeMySQLPacket writes a MySQL wire-protocol packet to the conn.
// Packets larger than 16 MiB - 1 should be split per the spec; the
// observation-only path never produces such packets, and the forwarding
// path passes upstream bytes verbatim (so the upstream's segmentation
// is preserved).
func writeMySQLPacket(conn net.Conn, seq byte, payload []byte) error {
	length := len(payload)
	if length >= 1<<24 {
		return fmt.Errorf("dbounce mysql: packet too large (%d bytes); split unimplemented", length)
	}
	hdr := []byte{
		byte(length),
		byte(length >> 8),
		byte(length >> 16),
		seq,
	}
	if _, err := conn.Write(hdr); err != nil {
		return fmt.Errorf("write mysql header: %w", err)
	}
	if length > 0 {
		if _, err := conn.Write(payload); err != nil {
			return fmt.Errorf("write mysql payload: %w", err)
		}
	}
	return nil
}

// writeMySQLOK writes an OK_Packet to the client. affectedRows +
// lastInsertID are length-encoded integers; for the observation path
// they're always 0.
func writeMySQLOK(conn net.Conn, seq byte, affectedRows, lastInsertID uint64) error {
	pkt := make([]byte, 0, 8)
	pkt = append(pkt, mysqlOKPacketByte)
	pkt = append(pkt, mysqlEncodeLengthInt(affectedRows)...)
	pkt = append(pkt, mysqlEncodeLengthInt(lastInsertID)...)
	pkt = append(pkt, 0x02, 0x00) // status flags
	pkt = append(pkt, 0x00, 0x00) // warnings
	return writeMySQLPacket(conn, seq, pkt)
}

// writeMySQLErr writes an ERR_Packet to the client with the given
// MySQL error code, SQLSTATE, and message.
func writeMySQLErr(conn net.Conn, seq byte, code uint16, sqlState, msg string) error {
	pkt := make([]byte, 0, 16+len(sqlState)+len(msg))
	pkt = append(pkt, mysqlErrPacketByte)
	codeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(codeBytes, code)
	pkt = append(pkt, codeBytes...)
	pkt = append(pkt, '#')
	if len(sqlState) != 5 {
		sqlState = mysqlSQLStateGeneral
	}
	pkt = append(pkt, []byte(sqlState)...)
	pkt = append(pkt, []byte(msg)...)
	return writeMySQLPacket(conn, seq, pkt)
}

// registerMySQLAgentFromHandshakeResponse parses a MySQL
// HandshakeResponse41 payload for the connection-attributes block,
// maps the standard attrs (_client_name / _client_version /
// _program_name) to a known agent name (or stamps the literal client
// name for unknown drivers), and mints a session id in the per-
// process AgentRegistry. Returns the minted session id; empty when
// the registry isn't wired.
//
// Per [[agent-identity-in-audit]] Feature 1: best-effort. Most clients
// in practice (mysql-cli, Connector/J, libmysql, mysql2) DO send the
// _client_name attr; a missing attrs block (older clients) → name
// falls back to "unknown" but the session id still threads through so
// SIEM correlation still works.
//
// Parse strategy: walk the HandshakeResponse41 layout — capabilities
// (4) + max_packet (4) + charset (1) + reserved (23) + null-terminated
// username, then the variable-length auth response, the optional
// database, the optional auth plugin name, and FINALLY the optional
// length-encoded attrs block (when CLIENT_CONNECT_ATTRS is set in
// capabilities). Rather than re-implement the full HandshakeResponse41
// parser (each branch depending on capability bits the client may or
// may not have set), we use a defensive heuristic: scan the tail of
// the response for a sequence of length-encoded string pairs that
// match well-known attr keys (`_client_name` / `_pid` / `_client_
// version` / `_program_name` / `_os` / `_platform`). The heuristic is
// robust to caching_sha2_password vs mysql_native_password vs cleartext
// + the various capability-flag layouts.
//
// Defensive: any parse failure surfaces as agent.name="" + the session
// is still minted. Never breaks a connection.
func (s *Server) registerMySQLAgentFromHandshakeResponse(payload []byte) string {
	if s.agentRegistry == nil {
		return ""
	}
	attrs := scanMySQLHandshakeAttrs(payload)
	name, version := audit.ParseMySQLAgentFromAttrs(attrs)
	agent := audit.Agent{
		Name:         name,
		Version:      version,
		DetectedFrom: audit.DetectedFromMySQLAttrs,
	}
	if name == "" {
		agent.DetectedFrom = audit.DetectedFromUnknown
	}
	return s.agentRegistry.Mint(agent)
}

// scanMySQLHandshakeAttrs finds the connection-attributes block in a
// HandshakeResponse41 payload by scanning for the well-known attr key
// prefix `_client_name` (or `_program_name`) preceded by its length-
// encoded-string length byte. When found, parses backward from that
// position to the start of the attrs block (the length-encoded total
// block size) and forward to extract every key/value pair via
// audit.ParseMySQLClientAttrs. Returns an empty map on no match.
//
// The scan is defensive: an empty payload, a payload without attrs,
// or a corrupt attrs block all return an empty map rather than
// surfacing an error.
func scanMySQLHandshakeAttrs(payload []byte) map[string]string {
	// Look for `_client_name`, `_program_name`, or `_client_version` —
	// any of these is a strong signal the attrs block starts here.
	probes := [][]byte{
		[]byte("_client_name"),
		[]byte("_program_name"),
		[]byte("_client_version"),
	}
	for _, probe := range probes {
		idx := indexBytes(payload, probe)
		if idx <= 0 {
			continue
		}
		// The byte BEFORE the key bytes is the key's length-encoded-
		// string length prefix (single-byte for keys < 251 chars, which
		// _client_name etc. always are). Walk back to that byte, then
		// back one more for the value-pair structure's length-encoded
		// total. The attrs block starts at the most recent length-
		// encoded int that names a plausible total size.
		keyLenIdx := idx - 1
		if keyLenIdx < 0 || int(payload[keyLenIdx]) != len(probe) {
			continue
		}
		// Walk back further for the total-attrs-len byte. The total
		// block size is at most 64 KiB in practice; scan back up to 8
		// bytes for a length prefix that matches the remainder.
		for back := 1; back <= 8 && keyLenIdx-back >= 0; back++ {
			start := keyLenIdx - back
			n, consumed, ok := mysqlReadLenEncInt(payload[start:])
			if !ok {
				continue
			}
			blockStart := start + consumed
			if blockStart > len(payload) {
				continue
			}
			// Tolerate trailing padding by capping at the remainder.
			end := blockStart + int(n)
			if end > len(payload) {
				end = len(payload)
			}
			attrs := audit.ParseMySQLClientAttrs(payload[blockStart:end])
			if len(attrs) > 0 {
				return attrs
			}
		}
	}
	return map[string]string{}
}

// mysqlReadLenEncInt mirrors audit.mysqlReadLenEncInt so the proxy
// pkg's attrs scanner doesn't need to re-export the audit pkg helper.
// Kept private to the proxy pkg; the audit pkg has its own copy used
// by ParseMySQLClientAttrs.
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
		return 0, 0, false
	}
}

// indexBytes is the tiny stdlib-shim search; defensive against an
// empty needle (returns -1) so callers don't false-positive on every
// payload.
func indexBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// mysqlEncodeLengthInt encodes a uint64 as a MySQL length-encoded
// integer (see MySQL docs §"Length-Encoded Integer").
func mysqlEncodeLengthInt(v uint64) []byte {
	switch {
	case v < 251:
		return []byte{byte(v)}
	case v < 1<<16:
		return []byte{0xfc, byte(v), byte(v >> 8)}
	case v < 1<<24:
		return []byte{0xfd, byte(v), byte(v >> 8), byte(v >> 16)}
	default:
		return []byte{
			0xfe,
			byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
			byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56),
		}
	}
}

// ---------------------------------------------------------------------------
// MySQL forwarder (used when --upstream is set + --dialect mysql).
// ---------------------------------------------------------------------------

// mysqlForwarder bundles per-session state for a MySQL forwarding
// connection. Parallels the PG Forwarder struct in forward.go.
type mysqlForwarder struct {
	srv *Server
	in  net.Conn
	out net.Conn

	// sessionID is the per-connection agent-session id per
	// [[agent-identity-in-audit]] Feature 2. Minted in pumpMySQLAuthPhase
	// from the parsed HandshakeResponse attrs (best-effort detection of
	// the client driver / agent name). Threaded onto every audit-export
	// event the forwarder emits + retired on connection close so a
	// SESSION_ENDED synthetic fires.
	sessionID string
}

// serveMySQLConnWithUpstream is the MySQL counterpart of
// serveConnWithUpstream. Same shape; different wire-protocol.
func (s *Server) serveMySQLConnWithUpstream(in net.Conn) {
	f := &mysqlForwarder{srv: s, in: in}
	defer func() {
		if f.out != nil {
			_ = f.out.Close()
		}
		// [[agent-identity-in-audit]] Feature 2: emit SESSION_ENDED on
		// connection close (idempotent — emitSessionEnded short-circuits
		// when the session was already retired).
		s.emitSessionEnded(f.sessionID)
	}()
	if err := f.run(); err != nil {
		log.Debug().Err(err).
			Str("remote", in.RemoteAddr().String()).
			Msg("dbounce: mysql forwarder ended")
	}
}

func (f *mysqlForwarder) run() error {
	if err := f.dialUpstream(); err != nil {
		return fmt.Errorf("dial upstream: %w", err)
	}
	if err := f.pumpMySQLAuthPhase(); err != nil {
		return fmt.Errorf("auth phase: %w", err)
	}
	return f.commandLoop()
}

func (f *mysqlForwarder) dialUpstream() error {
	up := f.srv.cfg.Upstream
	d := net.Dialer{Timeout: up.DialTimeout}
	c, err := d.Dial("tcp", up.Host())
	if err != nil {
		// Best-effort ErrPacket to the client so it doesn't hang.
		_ = writeMySQLErr(f.in, 0, mysqlErrUnknown, mysqlSQLStateGeneral,
			fmt.Sprintf("dbounce: upstream dial failed: %v", err))
		return fmt.Errorf("dial upstream %s: %w", up.Host(), err)
	}
	f.out = c
	return nil
}

// pumpMySQLAuthPhase shuttles handshake / auth packets between the
// inbound client and the upstream MySQL server until the server sends
// an OK or ERR packet that terminates the auth flow.
//
// Audit-cadence (parallel to forward.go's pumpAuthPhase): the auth
// payloads (mysql_native_password scramble, caching_sha2_password
// public-key exchange) traverse readMySQLPacket / writeMySQLPacket
// only — no named buffer holds an inbound password. Grep this file
// for "password" and you'll see only docs strings.
func (f *mysqlForwarder) pumpMySQLAuthPhase() error {
	// Loop: server speaks first (Initial Handshake), client responds,
	// server may respond with AuthSwitchRequest / further data exchange,
	// eventually OK or ERR terminates.
	const maxAuthHops = 16 // defensive — auth shouldn't exceed a handful
	for hop := 0; hop < maxAuthHops; hop++ {
		_ = f.out.SetReadDeadline(time.Now().Add(f.srv.cfg.ReadTimeout))
		seq, payload, err := readMySQLPacket(f.out)
		if err != nil {
			return fmt.Errorf("read upstream auth packet: %w", err)
		}
		if err := writeMySQLPacket(f.in, seq, payload); err != nil {
			return fmt.Errorf("forward auth packet to client: %w", err)
		}
		// Auth termination: OK or ERR as the first payload byte.
		if len(payload) > 0 {
			switch payload[0] {
			case mysqlOKPacketByte:
				return nil
			case mysqlErrPacketByte:
				return errors.New("upstream returned ERR during auth")
			}
		}
		// Wait for the client's reply.
		_ = f.in.SetReadDeadline(time.Now().Add(f.srv.cfg.ReadTimeout))
		cliSeq, cliPayload, err := readMySQLPacket(f.in)
		if err != nil {
			return fmt.Errorf("read client auth packet: %w", err)
		}
		// [[agent-identity-in-audit]] Feature 1+2: the FIRST client
		// packet in the auth phase is the HandshakeResponse41 that
		// carries the connection-attributes block. Capture client
		// fingerprint + mint the per-connection session id BEFORE
		// forwarding the packet so an upstream failure still leaves a
		// minted session that SESSION_ENDED can retire. Subsequent hops
		// (AuthMoreData / AuthSwitchResponse) are skipped — the attrs
		// block is in the HandshakeResponse only.
		if hop == 0 && f.sessionID == "" {
			f.sessionID = f.srv.registerMySQLAgentFromHandshakeResponse(cliPayload)
		}
		// LOAD-BEARING: cliPayload carries the auth response. Passed
		// straight to writeMySQLPacket without inspection or naming.
		if err := writeMySQLPacket(f.out, cliSeq, cliPayload); err != nil {
			return fmt.Errorf("forward client auth packet to upstream: %w", err)
		}
	}
	return errors.New("mysql auth phase exceeded max hops")
}

func (f *mysqlForwarder) commandLoop() error {
	for {
		_ = f.in.SetReadDeadline(time.Now().Add(f.srv.cfg.IdleTimeout))
		seq, payload, err := readMySQLPacket(f.in)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("read inbound mysql packet: %w", err)
			}
			return nil
		}
		if len(payload) == 0 {
			// Empty packet — forward verbatim so the upstream sees the
			// exact wire pattern.
			if err := writeMySQLPacket(f.out, seq, payload); err != nil {
				return err
			}
			continue
		}
		cmd := payload[0]
		switch cmd {
		case mysqlComQuit:
			_ = writeMySQLPacket(f.out, seq, payload)
			return nil
		case mysqlComQuery:
			sql := string(payload[1:])
			if err := f.handleGatedQuery(sql, seq, payload); err != nil {
				return err
			}
		case mysqlComStmtPrepare:
			// Reject prepared statements at the proxy boundary; never
			// reach upstream. The MySQL rule pack metadata documents
			// this as a post-launch upgrade.
			prepSQL := string(payload[1:])
			if err := writeMySQLErr(f.in, seq+1, mysqlErrSpecificAccessDenied,
				mysqlSQLStateAccessDenied,
				"dbounce: prepared statements not yet supported in v1.0; use direct queries"); err != nil {
				return err
			}
			// Also record a deny row so the audit log shows the attempt.
			f.recordPreparedReject(prepSQL, "mysql.StmtPrepare")
		default:
			// Forward COM_PING / COM_INIT_DB / COM_FIELD_LIST / etc.
			// verbatim — they don't carry SQL.
			if err := writeMySQLPacket(f.out, seq, payload); err != nil {
				return err
			}
			if err := f.drainUpstreamUntilReady(); err != nil {
				return err
			}
		}
	}
}

func (f *mysqlForwarder) handleGatedQuery(sql string, seq byte, payload []byte) error {
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
		// #203 sync-prompt-on-deny — parallel to forward.go's PG path.
		// See that file's commentary for the audit-row double-record
		// pattern + the syncPromptActive gate.
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
				log.Warn().Err(recErr).
					Msg("dbounce: record mysql sync-prompt pending decision failed; falling back to plain deny")
			} else {
				// #252 Slice 1: also fan out to audit-export transports.
				// Thread sessionID per [[agent-identity-in-audit]].
				f.srv.exportDecisionRowWithAgent(pendingRow, pendingDecisionID, f.sessionID)
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
			f.recordMySQLDecision(row)
			if err := writeMySQLErr(f.in, seq+1, mysqlErrSpecificAccessDenied,
				mysqlSQLStateAccessDenied,
				"dbounce: denied: "+row.DecisionReason); err != nil {
				return fmt.Errorf("write transparent-deny ErrPacket: %w", err)
			}
			return nil
		}
		// syncFlippedToAllow=true — fall through to forward path.
	}

	row.Forwarded = true
	row.Enforced = false
	// Forward the original packet bytes verbatim. We rebuilt the SQL
	// from payload[1:] but the wire-level packet is unchanged: same
	// seq, same payload.
	if err := writeMySQLPacket(f.out, seq, payload); err != nil {
		row.UpstreamStatus = upstreamStatusError
		row.UpstreamResponseSummary = "upstream write failed: " + err.Error()
		f.recordMySQLDecision(row)
		return err
	}
	summary, drainErr := f.drainUpstreamResultSet()
	if drainErr != nil {
		row.UpstreamStatus = upstreamStatusError
		row.UpstreamResponseSummary = "upstream drain failed: " + drainErr.Error()
		f.recordMySQLDecision(row)
		return drainErr
	}
	row.UpstreamStatus = summary.Status
	row.UpstreamResponseSummary = summary.Text
	f.recordMySQLDecision(row)
	return nil
}

// recordMySQLDecision writes one audit row to the store + fans out to
// the #252 Slice 1 audit-export transports. Centralizes the
// store-write + export-emit pair so every MySQL gated-query exit path
// goes through the same plumbing — matches the PG forwarder's
// Forwarder.recordDecision shape.
//
// Threads f.sessionID into the export call so unmapped.iam_jit.agent
// carries the per-connection fingerprint per
// [[agent-identity-in-audit]].
func (f *mysqlForwarder) recordMySQLDecision(row store.DecisionRow) {
	decisionID, err := f.srv.store.RecordDecision(row)
	if err != nil {
		BumpLookupErrors()
		return
	}
	f.srv.exportDecisionRowWithAgent(row, decisionID, f.sessionID)
}

// drainUpstreamResultSet shuttles every packet the upstream sends in
// response to a COM_QUERY back to the client, until we see a packet
// that terminates the result set (OK, ERR, or EOF).
//
// Simplified vs the PG drain: MySQL result sets are either
// - OK packet (no rows: INSERT/UPDATE/DELETE response)
// - ERR packet (failure)
// - column-count length-encoded int, then ColumnDefinition packets,
//   EOF, then DataRow packets, EOF (or OK with CLIENT_DEPRECATE_EOF)
//
// We don't need to parse the contents — we just forward packets until
// the terminator. Counting DataRow packets between EOFs gives us a
// rough "N rows returned" for the audit row.
func (f *mysqlForwarder) drainUpstreamResultSet() (drainResult, error) {
	var (
		seenColumnHeader bool
		rowCount         int
		eofCount         int
		errMsg           string
	)
	for {
		_ = f.out.SetReadDeadline(time.Now().Add(f.srv.cfg.ReadTimeout))
		seq, payload, err := readMySQLPacket(f.out)
		if err != nil {
			return drainResult{Status: upstreamStatusError, Text: err.Error()},
				fmt.Errorf("drain upstream mysql: %w", err)
		}
		if err := writeMySQLPacket(f.in, seq, payload); err != nil {
			return drainResult{Status: upstreamStatusError, Text: err.Error()},
				fmt.Errorf("write upstream→client: %w", err)
		}
		if len(payload) == 0 {
			continue
		}
		first := payload[0]
		switch {
		case !seenColumnHeader && first == mysqlOKPacketByte:
			// OK = end of statement (no rows: INSERT/UPDATE/DELETE).
			return drainResult{Status: upstreamStatusOk, Text: "ok"}, nil
		case first == mysqlErrPacketByte:
			errMsg = mysqlExtractErrMessage(payload)
			return drainResult{Status: upstreamStatusError, Text: "upstream error: " + errMsg}, nil
		case first == mysqlEOFPacketByte && len(payload) < 9:
			// EOF marker (legacy protocol). Two EOFs = end of result set.
			eofCount++
			if eofCount >= 2 {
				return drainResult{Status: upstreamStatusOk,
					Text: fmt.Sprintf("%d rows returned", rowCount)}, nil
			}
			seenColumnHeader = true
		case seenColumnHeader && first == mysqlOKPacketByte:
			// With CLIENT_DEPRECATE_EOF, an OK packet terminates the
			// result set instead of the second EOF.
			return drainResult{Status: upstreamStatusOk,
				Text: fmt.Sprintf("%d rows returned", rowCount)}, nil
		default:
			// First packet (column count) or DataRow.
			if !seenColumnHeader {
				// Column-count packet — next packets are column defs.
				seenColumnHeader = true
			} else if eofCount >= 1 {
				rowCount++
			}
		}
	}
}

// drainUpstreamUntilReady reads one packet from the upstream + forwards
// it to the client. Used for COM_PING / COM_INIT_DB / COM_FIELD_LIST
// shapes whose reply is a single OK/ERR.
func (f *mysqlForwarder) drainUpstreamUntilReady() error {
	_ = f.out.SetReadDeadline(time.Now().Add(f.srv.cfg.ReadTimeout))
	seq, payload, err := readMySQLPacket(f.out)
	if err != nil {
		return fmt.Errorf("drain upstream after command: %w", err)
	}
	return writeMySQLPacket(f.in, seq, payload)
}

// recordPreparedReject writes a deny row when COM_STMT_PREPARE is
// rejected at the proxy boundary so reviewers can see "client tried
// a prepared statement, dbounce blocked it."
func (f *mysqlForwarder) recordPreparedReject(sql, source string) {
	row := store.DecisionRow{
		At:                      time.Now().UTC(),
		Dialect:                 string(parser.DialectMySQL),
		Statement:               sql,
		StatementType:           parser.StmtExecute,
		DecisionVerdict:         string(VerdictDeny),
		DecisionReason:          "prepared statements not yet supported in v1.0",
		ModeAtDecision:          string(f.srv.cfg.Mode),
		Enforced:                true,
		Forwarded:               false,
		UpstreamStatus:          upstreamStatusNotForwarded,
		UpstreamResponseSummary: "rejected at proxy: COM_STMT_PREPARE not supported",
	}
	decisionID, err := f.srv.store.RecordDecision(row)
	if err != nil {
		BumpLookupErrors()
		log.Warn().Err(err).Str("source", source).
			Msg("dbounce: record prepared-stmt reject failed")
		return
	}
	// #252 Slice 1: fan out to audit-export transports so a rejected
	// prepared-statement attempt also surfaces in the security-team
	// audit stream. Thread sessionID per [[agent-identity-in-audit]].
	f.srv.exportDecisionRowWithAgent(row, decisionID, f.sessionID)
}

// mysqlExtractErrMessage pulls the human-readable message out of an
// ERR_Packet payload. Format: 0xff (1) + error code (2 LE) + '#' +
// SQLSTATE (5) + message (until end).
func mysqlExtractErrMessage(payload []byte) string {
	if len(payload) < 9 || payload[0] != mysqlErrPacketByte {
		return "(malformed err packet)"
	}
	// Skip header byte + error code (2) + '#' (1) + SQLSTATE (5) = 9
	if len(payload) <= 9 {
		return ""
	}
	return string(payload[9:])
}

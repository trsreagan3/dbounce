// D-Slice 4 — listener-side TLS for the PG wire protocol.
//
// PostgreSQL's wire protocol negotiates TLS via a pre-StartupMessage
// SSLRequest message: the client sends `int32(length=8) + int32(80877103)`,
// then waits for a single byte reply — 'S' to proceed with TLS, 'N' to
// continue in plaintext. After 'S', both sides perform a standard TLS
// handshake; the StartupMessage proper arrives only AFTER the TLS layer
// is in place.
//
// This file owns dbounce's side of that negotiation:
//
//   - looksLikeSSLRequest peeks the first 8 bytes the client sent + tells
//     the caller "yes, this is an SSLRequest" or "no, treat as plaintext
//     StartupMessage."
//   - upgradeListenerTLS performs the 'S' reply + the TLS handshake,
//     returning a *tls.Conn that implements net.Conn so the rest of the
//     wire-protocol flow is substrate-agnostic.
//   - loadListenerTLS builds the *tls.Config from operator flag-supplied
//     cert + key + optional mTLS CA bundle.
//
// LOAD-BEARING invariants (audit-cadence pin):
//
//   - listener-side TLS and OUTBOUND TLS are independent. D-Slice 2's
//     upstream.TLSConfig() controls outbound to the real PG; this file
//     controls inbound from the client. The proxy may speak TLS to the
//     client AND plaintext to the upstream (or vice versa).
//   - When mTLS is configured, ClientAuth = RequireAndVerifyClientCert +
//     the CA pool is set to the operator-supplied bundle. A nil ClientCAs
//     with ClientAuth = RequireAndVerifyClientCert is a misconfiguration
//     that crypto/tls would surface at handshake time anyway — we fail
//     loud at config-build time so the operator gets a clear error.
//   - The TLS upgrade happens BEFORE the StartupMessage parse. Forwarder.run
//     in forward.go is unchanged; we wrap the inbound conn before calling
//     the existing handshakeAndAuth.
//   - Per [[creates-never-mutates]]: dbounce never modifies the operator's
//     cert / key files. Read-only loads via tls.LoadX509KeyPair +
//     os.ReadFile.

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

// pgSSLRequestMagic is the second int32 a client sends to request TLS.
// Defined by the PostgreSQL protocol; not a dbounce invention.
const pgSSLRequestMagic = 80877103

// looksLikeSSLRequest inspects the 8 leading bytes of an inbound PG
// session. Returns true iff they parse as `int32(8) + int32(80877103)`.
//
// The caller is expected to pass the FIRST 8 bytes off the wire — this
// helper does not read from the conn itself so it remains pure +
// trivially testable.
func looksLikeSSLRequest(hdr []byte) bool {
	if len(hdr) < 8 {
		return false
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	magic := binary.BigEndian.Uint32(hdr[4:8])
	return length == 8 && magic == pgSSLRequestMagic
}

// sslReplyAccept is the single-byte reply the client expects when the
// server agrees to TLS. Defined by the PG protocol.
const sslReplyAccept byte = 'S'

// sslReplyReject is the single-byte reply the client expects when the
// server refuses TLS — the client may then proceed in plaintext or
// abort, depending on its sslmode setting.
const sslReplyReject byte = 'N'

// listenerTLS owns the operator-configured listener-side TLS state.
// Nil when no certs were configured (D-Slice 1 / D-Slice 2 plaintext
// behavior preserved).
type listenerTLS struct {
	// Config is what tls.Server consumes per upgraded conn. Built once
	// at server start; reused for every inbound session.
	Config *tls.Config

	// RequireClientCert mirrors the --require-client-cert flag. Kept
	// separately so the /healthz payload + the startup banner can
	// surface it without re-introspecting Config.ClientAuth.
	RequireClientCert bool
}

// LoadListenerTLS is the CLI-facing wrapper around loadListenerTLS so
// the cli package can construct the Config.ListenerTLS field without
// reaching into proxy-package internals. The returned value is opaque
// to callers — they only ever set it on the Config + read it back.
func LoadListenerTLS(certFile, keyFile, caCertFile string, requireClientCert bool) (*ListenerTLS, error) {
	return loadListenerTLS(certFile, keyFile, caCertFile, requireClientCert)
}

// ListenerTLS is the exported type alias so callers can refer to the
// configured listener-TLS state without depending on the unexported
// listenerTLS name (kept lowercase to discourage manual construction).
type ListenerTLS = listenerTLS

// loadListenerTLS reads the operator's cert + key from disk + returns
// a listenerTLS ready to serve. Both certFile and keyFile must be
// non-empty.
//
// When requireClientCert is true, caCertFile must also be non-empty.
// The CA pool is built from that file's PEM contents + applied to
// Config.ClientCAs; ClientAuth becomes RequireAndVerifyClientCert.
func loadListenerTLS(certFile, keyFile, caCertFile string, requireClientCert bool) (*listenerTLS, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New(
			"dbounce: listener TLS requires both --listener-tls-cert and --listener-tls-key")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("dbounce: load listener TLS cert/key: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if requireClientCert {
		if caCertFile == "" {
			return nil, errors.New(
				"dbounce: --require-client-cert requires --listener-tls-client-ca " +
					"(the CA bundle clients' certs are verified against)")
		}
		caBytes, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("dbounce: read client CA bundle %q: %w", caCertFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf(
				"dbounce: client CA bundle at %q is not valid PEM", caCertFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return &listenerTLS{
		Config:            cfg,
		RequireClientCert: requireClientCert,
	}, nil
}

// upgradeListenerTLS executes the inbound TLS upgrade.
//
// Wire sequence:
//
//  1. Read 8 bytes from conn — the SSLRequest preamble. Already happened
//     in the caller; the leading bytes are passed in as hdr.
//  2. Reply with 'S' (TLS accepted) when l != nil. Reply 'N' (no TLS)
//     when l == nil so plaintext clients keep working.
//  3. After 'S', wrap conn in tls.Server + Handshake().
//  4. Return the *tls.Conn so the caller's wire-protocol code reads
//     subsequent bytes (StartupMessage proper) through the TLS layer.
//
// When l is nil (no listener TLS configured) this function writes 'N'
// to the client + returns (nil, nil) — the caller continues with the
// plaintext path. Errors only when 'N' itself fails to write.
//
// Per the audit-cadence note: dbounce NEVER reads the StartupMessage
// before this function returns. The 8 hdr bytes are the LAST plaintext
// bytes the client sends when TLS is in use.
func upgradeListenerTLS(conn net.Conn, hdr []byte, l *listenerTLS) (net.Conn, error) {
	if !looksLikeSSLRequest(hdr) {
		return nil, errors.New(
			"upgradeListenerTLS: leading bytes are not an SSLRequest")
	}
	if l == nil {
		if _, err := conn.Write([]byte{sslReplyReject}); err != nil {
			return nil, fmt.Errorf("write SSL-no reply: %w", err)
		}
		return nil, nil // signal "continue plaintext"
	}
	if _, err := conn.Write([]byte{sslReplyAccept}); err != nil {
		return nil, fmt.Errorf("write SSL-accept reply: %w", err)
	}
	tlsConn := tls.Server(conn, l.Config)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("inbound TLS handshake: %w", err)
	}
	return tlsConn, nil
}

// readPGSSLPreamble reads exactly 8 bytes from conn — the SSLRequest
// preamble OR the leading bytes of a plaintext StartupMessage. Tiny
// helper so the call sites don't repeat the io.ReadFull pattern.
func readPGSSLPreamble(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("read SSL/startup preamble: %w", err)
	}
	return hdr, nil
}

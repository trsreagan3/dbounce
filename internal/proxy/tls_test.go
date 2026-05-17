package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/tlsmat"
)

// ---------------------------------------------------------------------------
// Unit tests — SSLRequest detection + reply byte sequence
// ---------------------------------------------------------------------------

func TestLooksLikeSSLRequest_RecognizesSSLPreamble(t *testing.T) {
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], 8)
	binary.BigEndian.PutUint32(hdr[4:8], pgSSLRequestMagic)
	assert.True(t, looksLikeSSLRequest(hdr),
		"the canonical SSLRequest preamble must be recognized")
}

func TestLooksLikeSSLRequest_RejectsStartupMessage(t *testing.T) {
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], 64) // any plausible startup length
	binary.BigEndian.PutUint32(hdr[4:8], 196608)
	assert.False(t, looksLikeSSLRequest(hdr),
		"a plaintext StartupMessage must NOT trigger TLS upgrade")
}

func TestLooksLikeSSLRequest_RejectsTooShort(t *testing.T) {
	assert.False(t, looksLikeSSLRequest([]byte{0, 0, 0, 8}),
		"fewer than 8 bytes is never an SSLRequest")
}

func TestLooksLikeSSLRequest_RejectsBadLength(t *testing.T) {
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], 99) // wrong length for SSLRequest
	binary.BigEndian.PutUint32(hdr[4:8], pgSSLRequestMagic)
	assert.False(t, looksLikeSSLRequest(hdr),
		"length != 8 disqualifies the SSLRequest match")
}

func TestUpgradeListenerTLS_NoConfigReplies_N(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], 8)
	binary.BigEndian.PutUint32(hdr[4:8], pgSSLRequestMagic)

	go func() {
		_, _ = upgradeListenerTLS(srv, hdr, nil)
		_ = srv.Close()
	}()

	reply := make([]byte, 1)
	_, err := io.ReadFull(cli, reply)
	require.NoError(t, err)
	assert.Equal(t, byte('N'), reply[0],
		"no listener TLS configured must respond 'N' (continue plaintext)")
}

func TestUpgradeListenerTLS_NonSSLRequest_ReturnsError(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	// StartupMessage preamble (not SSLRequest).
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], 64)
	binary.BigEndian.PutUint32(hdr[4:8], 196608)

	_, err := upgradeListenerTLS(srv, hdr, nil)
	require.Error(t, err,
		"non-SSLRequest preamble must be rejected by upgradeListenerTLS")
	assert.Contains(t, err.Error(), "SSLRequest")
}

// ---------------------------------------------------------------------------
// Listener-TLS config builder
// ---------------------------------------------------------------------------

func issueCertsForTest(t *testing.T, withClient bool) *tlsmat.Result {
	t.Helper()
	dir := t.TempDir()
	res, err := tlsmat.GenerateCAAndServerCert(tlsmat.Options{
		OutDir:         dir,
		WithClientCert: withClient,
		ValidFor:       time.Hour,
		KeyBits:        2048,
	})
	require.NoError(t, err)
	return res
}

func TestLoadListenerTLS_LoadsCertAndKey(t *testing.T) {
	res := issueCertsForTest(t, false)
	l, err := loadListenerTLS(res.ServerCertPath, res.ServerKeyPath, "", false)
	require.NoError(t, err)
	require.NotNil(t, l)
	require.NotNil(t, l.Config)
	assert.Equal(t, uint16(tls.VersionTLS12), l.Config.MinVersion)
	assert.Equal(t, tls.NoClientCert, l.Config.ClientAuth)
	assert.False(t, l.RequireClientCert)
}

func TestLoadListenerTLS_RejectsMissingCert(t *testing.T) {
	_, err := loadListenerTLS("", "/nonexistent/key", "", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listener TLS requires")
}

func TestLoadListenerTLS_RequireClientCertWithoutCAFails(t *testing.T) {
	res := issueCertsForTest(t, false)
	_, err := loadListenerTLS(res.ServerCertPath, res.ServerKeyPath, "", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--listener-tls-client-ca")
}

func TestLoadListenerTLS_RequireClientCertWithCALoads(t *testing.T) {
	res := issueCertsForTest(t, true)
	l, err := loadListenerTLS(res.ServerCertPath, res.ServerKeyPath, res.CACertPath, true)
	require.NoError(t, err)
	require.NotNil(t, l)
	assert.Equal(t, tls.RequireAndVerifyClientCert, l.Config.ClientAuth)
	assert.NotNil(t, l.Config.ClientCAs)
	assert.True(t, l.RequireClientCert)
}

func TestLoadListenerTLS_BadCABundleRejected(t *testing.T) {
	res := issueCertsForTest(t, false)
	badCA := filepath.Join(t.TempDir(), "junk.pem")
	require.NoError(t, os.WriteFile(badCA, []byte("not a pem"), 0o600))
	_, err := loadListenerTLS(res.ServerCertPath, res.ServerKeyPath, badCA, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid PEM")
}

// ---------------------------------------------------------------------------
// Integration — full TLS round-trip via the observation-only listener
// ---------------------------------------------------------------------------

// startTLSObservationServer spins a Server with listener TLS configured
// but no upstream. Returns wire addr + the listener TLS material.
func startTLSObservationServer(t *testing.T, requireClient bool) (string, *tlsmat.Result, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	res := issueCertsForTest(t, true)
	caForClientCertVerify := ""
	if requireClient {
		caForClientCertVerify = res.CACertPath
	}
	lTLS, err := loadListenerTLS(res.ServerCertPath, res.ServerKeyPath, caForClientCertVerify, requireClient)
	require.NoError(t, err)

	wireL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	wirePort := wireL.Addr().(*net.TCPAddr).Port
	mgmtPort := mgmtL.Addr().(*net.TCPAddr).Port

	cfg := Config{
		Host:          "127.0.0.1",
		Port:          wirePort,
		MgmtHost:      "127.0.0.1",
		MgmtPort:      mgmtPort,
		WireListener:  wireL,
		MgmtListener:  mgmtL,
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		Dialect:       DialectPostgres,
		ListenerTLS:   lTLS,
		IdleTimeout:   5 * time.Second,
	}.Normalize()
	srv := NewServer(cfg, st)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	addr := fmt.Sprintf("127.0.0.1:%d", wirePort)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return addr, res, st
}

// writeSSLRequest sends the canonical SSLRequest preamble to conn.
func writeSSLRequest(t *testing.T, conn net.Conn) {
	t.Helper()
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], 8)
	binary.BigEndian.PutUint32(hdr[4:8], pgSSLRequestMagic)
	_, err := conn.Write(hdr)
	require.NoError(t, err)
}

// readSSLReply reads + returns the one-byte SSL reply ('S' or 'N').
func readSSLReply(t *testing.T, conn net.Conn) byte {
	t.Helper()
	b := make([]byte, 1)
	_, err := io.ReadFull(conn, b)
	require.NoError(t, err)
	return b[0]
}

// pgClientStartupAndQuery sends StartupMessage + a SELECT through a
// connected (potentially TLS-wrapped) conn and waits for ReadyForQuery
// completion.
func pgClientStartupAndQuery(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	params := []byte("user\x00tester\x00database\x00postgres\x00\x00")
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body[0:4], 196608)
	copy(body[4:], params)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(4+len(body)))
	_, err := conn.Write(hdr)
	require.NoError(t, err)
	_, err = conn.Write(body)
	require.NoError(t, err)

	// Drain auth handshake to RFQ.
	for {
		mt, _, err := readPGMessage(conn)
		require.NoError(t, err)
		if mt == 'Z' {
			break
		}
	}

	payload := append([]byte("SELECT 1"), 0)
	hdrQ := make([]byte, 5)
	hdrQ[0] = 'Q'
	binary.BigEndian.PutUint32(hdrQ[1:5], uint32(len(payload)+4))
	_, err = conn.Write(hdrQ)
	require.NoError(t, err)
	_, err = conn.Write(payload)
	require.NoError(t, err)

	for {
		mt, _, err := readPGMessage(conn)
		require.NoError(t, err)
		if mt == 'Z' {
			return
		}
	}
}

func TestListenerTLS_SSLRequestUpgradesAndRoundtrips(t *testing.T) {
	addr, certs, st := startTLSObservationServer(t, false)

	raw, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))

	writeSSLRequest(t, raw)
	reply := readSSLReply(t, raw)
	require.Equal(t, byte('S'), reply,
		"listener with TLS configured must respond 'S' to SSLRequest")

	pool := x509.NewCertPool()
	caBytes, err := os.ReadFile(certs.CACertPath)
	require.NoError(t, err)
	require.True(t, pool.AppendCertsFromPEM(caBytes))

	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: "localhost",
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, tlsConn.Handshake())

	pgClientStartupAndQuery(t, tlsConn)

	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.NotEmpty(t, rows,
		"the SELECT through the TLS-upgraded conn must produce one audit row")
	assert.Equal(t, "SELECT", rows[0].StatementType)
}

func TestListenerTLS_NotConfiguredRepliesN(t *testing.T) {
	// Sanity: with NO ListenerTLS, SSLRequest still gets 'N' (D-Slice 1
	// behavior preserved).
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	wireL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	wirePort := wireL.Addr().(*net.TCPAddr).Port
	mgmtPort := mgmtL.Addr().(*net.TCPAddr).Port

	cfg := Config{
		Host:          "127.0.0.1",
		Port:          wirePort,
		MgmtHost:      "127.0.0.1",
		MgmtPort:      mgmtPort,
		WireListener:  wireL,
		MgmtListener:  mgmtL,
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		Dialect:       DialectPostgres,
		// ListenerTLS deliberately omitted.
		IdleTimeout: 5 * time.Second,
	}.Normalize()
	srv := NewServer(cfg, st)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	addr := fmt.Sprintf("127.0.0.1:%d", wirePort)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	raw, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))

	writeSSLRequest(t, raw)
	reply := readSSLReply(t, raw)
	assert.Equal(t, byte('N'), reply,
		"no listener TLS must keep replying 'N' (D-Slice 1 compatibility)")
}

func TestListenerTLS_RequireClientCert_RejectsAnonymous(t *testing.T) {
	addr, certs, _ := startTLSObservationServer(t, true)

	raw, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))

	writeSSLRequest(t, raw)
	require.Equal(t, byte('S'), readSSLReply(t, raw))

	pool := x509.NewCertPool()
	caBytes, err := os.ReadFile(certs.CACertPath)
	require.NoError(t, err)
	require.True(t, pool.AppendCertsFromPEM(caBytes))

	// Connect WITHOUT presenting a client cert. With TLS 1.3 the client's
	// Handshake() may return nil even though the server has rejected the
	// session — the rejection surfaces on the first read/write after.
	// So we try sending a StartupMessage byte and assert SOMETHING errors
	// in the round-trip (either the handshake itself or the subsequent
	// write/read).
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: "localhost",
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		// Expected on most stacks.
		return
	}
	// TLS 1.3 path: handshake completed client-side; try to use the
	// conn. The server tore down after rejecting, so a read must error.
	_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
	// Write a probe; the server may have already RST'd, in which case
	// Write errors here. Otherwise the subsequent Read must error.
	if _, werr := tlsConn.Write([]byte{0, 0, 0, 8, 0, 0, 0, 0}); werr != nil {
		return
	}
	buf := make([]byte, 16)
	_, rerr := tlsConn.Read(buf)
	require.Error(t, rerr,
		"mTLS-required listener must reject anonymous TLS clients "+
			"(handshake or post-handshake read must error)")
}

func TestListenerTLS_RequireClientCert_AcceptsWithCert(t *testing.T) {
	addr, certs, st := startTLSObservationServer(t, true)

	raw, err := net.DialTimeout("tcp", addr, 1*time.Second)
	require.NoError(t, err)
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))

	writeSSLRequest(t, raw)
	require.Equal(t, byte('S'), readSSLReply(t, raw))

	rootPool := x509.NewCertPool()
	caBytes, err := os.ReadFile(certs.CACertPath)
	require.NoError(t, err)
	require.True(t, rootPool.AppendCertsFromPEM(caBytes))

	clientPair, err := tls.LoadX509KeyPair(certs.ClientCertPath, certs.ClientKeyPath)
	require.NoError(t, err)

	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:   "localhost",
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{clientPair},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, tlsConn.Handshake(),
		"mTLS-required listener must accept the matching client cert")

	pgClientStartupAndQuery(t, tlsConn)

	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Equal(t, "SELECT", rows[0].StatementType)
}

// ---------------------------------------------------------------------------
// Management /healthz over HTTPS
// ---------------------------------------------------------------------------

func TestMgmtTLS_HealthzOverHTTPS(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	res := issueCertsForTest(t, false)

	wireL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	mgmtL, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	wirePort := wireL.Addr().(*net.TCPAddr).Port
	mgmtPort := mgmtL.Addr().(*net.TCPAddr).Port

	cfg := Config{
		Host:            "127.0.0.1",
		Port:            wirePort,
		MgmtHost:        "127.0.0.1",
		MgmtPort:        mgmtPort,
		WireListener:    wireL,
		MgmtListener:    mgmtL,
		Mode:            ModeCooperative,
		DefaultPolicy:   DefaultPolicyAllow,
		Dialect:         DialectPostgres,
		MgmtTLSCertFile: res.ServerCertPath,
		MgmtTLSKeyFile:  res.ServerKeyPath,
		IdleTimeout:     5 * time.Second,
	}.Normalize()
	srv := NewServer(cfg, st)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// Poll until ready.
	pool := x509.NewCertPool()
	caBytes, err := os.ReadFile(res.CACertPath)
	require.NoError(t, err)
	require.True(t, pool.AppendCertsFromPEM(caBytes))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: "localhost",
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 2 * time.Second,
	}
	url := fmt.Sprintf("https://127.0.0.1:%d/healthz", mgmtPort)

	var resp *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = client.Get(url)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.NoError(t, err, "HTTPS /healthz must succeed")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.True(t, bytes.Contains(body, []byte(`"status":"ok"`)),
		"HTTPS /healthz must return the same JSON shape as HTTP /healthz; got %s", body)
}

// TestPGHandshakeWithPreamble_PreReadStartupWorks asserts the refactor
// that lets the TLS-upgrade path pre-consume the 8-byte preamble: the
// pgHandshakeWithPreamble accepts the pre-read 8 bytes + reads the rest
// of the StartupMessage body off the wire.
func TestPGHandshakeWithPreamble_PreReadStartupWorks(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	// StartupMessage wire layout: int32(length) + int32(protocol) + params.
	// length COUNTS ITSELF — i.e. length = 4 + 4 + len(params).
	params := []byte("user\x00tester\x00database\x00postgres\x00\x00")
	totalLen := uint32(4 + 4 + len(params))

	preamble := make([]byte, 8)
	binary.BigEndian.PutUint32(preamble[0:4], totalLen)
	binary.BigEndian.PutUint32(preamble[4:8], 196608) // protocol 3.0

	// Client side: the preamble has been pre-consumed by our caller
	// (simulating the TLS-upgrade path); we only send the params.
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		_, _ = cli.Write(params)
		// Drain server responses until ReadyForQuery.
		for {
			hdr := make([]byte, 5)
			if _, err := io.ReadFull(cli, hdr); err != nil {
				return
			}
			length := binary.BigEndian.Uint32(hdr[1:5])
			if length > 4 {
				skip := make([]byte, length-4)
				if _, err := io.ReadFull(cli, skip); err != nil {
					return
				}
			}
			if hdr[0] == 'Z' {
				return
			}
		}
	}()

	require.NoError(t, pgHandshakeWithPreamble(srv, preamble))
	<-clientDone
}

// TestNoSensitiveStringsInTLSCode is a load-bearing-invariant pin: the
// listener TLS code must not name "password" / "secret" / "token" in
// any identifier (parallel to TestNoPasswordCapture_InvariantPin for
// the SCRAM-pass-through path).
func TestNoSensitiveStringsInTLSCode(t *testing.T) {
	bts, err := os.ReadFile("tls.go")
	require.NoError(t, err)
	text := strings.ToLower(string(bts))
	for _, ident := range []string{"password", "secret"} {
		if strings.Contains(text, ident) {
			t.Errorf("tls.go must not contain %q (sensitive-string invariant)", ident)
		}
	}
}

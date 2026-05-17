// Package upstream resolves the real PostgreSQL server dbounce's proxy
// forwards ALLOW verdicts to. D-Slice 2.
//
// Built to mirror kbounce's internal/upstream shape so the cross-product
// agent-parity invariant ([[cross-product-agent-parity]]) holds: the
// resolver returns an Upstream value with the same Host()/Source surface
// kbounce + ibounce expose, but the wire-protocol underneath is PG
// (not HTTP).
//
// What this package does NOT do:
//
//   - It does NOT load the client's password or SCRAM tokens. dbounce
//     NEVER re-authenticates a request; the inbound SCRAM challenge-
//     response is forwarded verbatim between client + upstream. The proxy
//     is a gating layer, not an identity broker. See [[creates-never-mutates]]
//     in product memory + the SCRAM pass-through audit-cadence note in
//     proxy/forward.go.
//   - It does NOT call the upstream PG at startup to verify connectivity.
//     An upstream outage on launch must not block the proxy from binding
//     (and surfacing a useful PG ErrorResponse to clients).
//
// The Upstream returned is reused for every forwarded connection; each
// inbound client gets its own outbound TCP dial (PG sessions are not
// pooled — every client has its own backend on the upstream).
package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// ErrNoUpstream is returned when --upstream is empty + the caller
// expected a real forwarding target. The CLI distinguishes the
// no-upstream / observation-only case explicitly so we don't surface
// this in normal operation.
var ErrNoUpstream = errors.New("dbounce: no upstream URL configured " +
	"(pass --upstream postgres://user@host:port/database)")

// TLSMode controls outbound TLS behavior.
type TLSMode string

const (
	// TLSModeVerify (default) — outbound TLS handshake validates the
	// upstream's cert against the system trust store (or --upstream-ca-cert
	// if supplied). Mirrors kbounce's "secure by default" stance.
	TLSModeVerify TLSMode = "verify"
	// TLSModeSkip — outbound TLS handshake skips cert verification. Use
	// only for local/dev clusters with self-signed certs. Must be operator-
	// explicit; never inferred.
	TLSModeSkip TLSMode = "skip"
	// TLSModeDisable — refuse to negotiate TLS even when the upstream
	// offers it. The proxy sends SSLRequest 'N' to the inbound client
	// regardless of upstream support. Documented escape hatch for
	// air-gapped local-only setups.
	TLSModeDisable TLSMode = "disable"
)

// IsValid reports whether m is one of the recognized values.
func (m TLSMode) IsValid() bool {
	return m == TLSModeVerify || m == TLSModeSkip || m == TLSModeDisable
}

// Options carries the inputs Resolve consumes. Built from CLI flags so
// the resolver can be tested without env / filesystem dependencies.
type Options struct {
	// UpstreamURL is the canonical postgres:// URL. Required; an empty
	// value returns ErrNoUpstream.
	UpstreamURL string

	// CACertPath, when non-empty, names a PEM file whose certs are
	// pooled into the outbound TLS RootCAs. Empty = system trust store.
	CACertPath string

	// TLSMode controls outbound TLS behavior. Defaults to verify when
	// the zero value is seen.
	TLSMode TLSMode

	// DialTimeout caps how long the proxy waits for the outbound TCP
	// dial. Zero defaults to 10s.
	DialTimeout time.Duration
}

// Upstream is the resolved PG target the proxy dials per inbound
// session. Construct once at startup; reuse for every forwarded conn.
type Upstream struct {
	// URL is the operator-supplied postgres URL (parsed). The Host/Port/
	// Database/User fields are extracted from it for the StartupMessage
	// rewrite.
	URL *url.URL

	// CACertPath is surfaced for logging so the startup banner can show
	// whether a custom CA was loaded.
	CACertPath string

	// TLSMode controls outbound TLS behavior on the SSLRequest reply +
	// the actual handshake. Stored on the Upstream so the proxy doesn't
	// need to re-parse the CLI flag per connection.
	TLSMode TLSMode

	// DialTimeout caps per-conn outbound TCP dial.
	DialTimeout time.Duration

	// rootCAs is the loaded CA pool (or nil when system trust is used).
	rootCAs *x509.CertPool

	// Source describes where the URL came from. Always "flag" in
	// D-Slice 2 (kbounce's "kubeconfig" / "in-cluster" sources don't
	// apply to PG). Kept for cross-product audit-log parity.
	Source string
}

// Host returns the host[:port] of the upstream URL — used by the
// forward-host-allowlist check in proxy/forward.go.
func (u *Upstream) Host() string {
	if u == nil || u.URL == nil {
		return ""
	}
	return u.URL.Host
}

// HostnameOnly returns the host without the port. Used for SNI +
// cert-CN verification when the cert is bound to the hostname only.
func (u *Upstream) HostnameOnly() string {
	if u == nil || u.URL == nil {
		return ""
	}
	if h, _, err := net.SplitHostPort(u.URL.Host); err == nil {
		return h
	}
	return u.URL.Host
}

// Database returns the database name from the URL path. Empty when
// not specified.
func (u *Upstream) Database() string {
	if u == nil || u.URL == nil {
		return ""
	}
	return strings.TrimPrefix(u.URL.Path, "/")
}

// User returns the username from the URL (if any). Falls back to
// empty when not specified — the inbound StartupMessage's user param
// is what reaches the upstream in that case.
func (u *Upstream) User() string {
	if u == nil || u.URL == nil || u.URL.User == nil {
		return ""
	}
	return u.URL.User.Username()
}

// TLSConfig returns a *tls.Config suitable for the outbound PG TLS
// upgrade. Returns nil when TLSMode is "disable".
//
// Per the audit-cadence self-check (c): default validates certs;
// InsecureSkipVerify is true ONLY when TLSMode == TLSModeSkip.
func (u *Upstream) TLSConfig() *tls.Config {
	if u == nil || u.TLSMode == TLSModeDisable {
		return nil
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: u.HostnameOnly(),
	}
	switch u.TLSMode {
	case TLSModeSkip:
		cfg.InsecureSkipVerify = true
	case TLSModeVerify, "":
		// Default: validate against system trust + (optional) operator CA.
		cfg.InsecureSkipVerify = false
		if u.rootCAs != nil {
			cfg.RootCAs = u.rootCAs
		}
	}
	return cfg
}

// Resolve produces an Upstream from the given options.
//
// Validation:
//   - opts.UpstreamURL must be non-empty (returns ErrNoUpstream otherwise).
//   - Scheme must be postgres or postgresql.
//   - Host must be present.
//   - CACertPath, when set, must point to a readable PEM file.
//   - TLSMode must be one of the recognized values (empty defaults to verify).
func Resolve(opts Options) (*Upstream, error) {
	if opts.UpstreamURL == "" {
		return nil, ErrNoUpstream
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 10 * time.Second
	}
	if opts.TLSMode == "" {
		opts.TLSMode = TLSModeVerify
	}
	if !opts.TLSMode.IsValid() {
		return nil, fmt.Errorf("dbounce: invalid --upstream-tls %q (want verify | skip | disable)", opts.TLSMode)
	}

	parsed, err := url.Parse(opts.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("dbounce: parse upstream URL %q: %w", opts.UpstreamURL, err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "postgres" && scheme != "postgresql" {
		return nil, fmt.Errorf("dbounce: upstream URL scheme %q not supported (want postgres or postgresql)", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("dbounce: upstream URL %q missing host", opts.UpstreamURL)
	}
	// If port is missing, append the default PG port. Lets the operator
	// say `postgres://localhost/mydb` and have it work.
	if _, _, splitErr := net.SplitHostPort(parsed.Host); splitErr != nil {
		parsed.Host = parsed.Host + ":5432"
	}

	up := &Upstream{
		URL:         parsed,
		CACertPath:  opts.CACertPath,
		TLSMode:     opts.TLSMode,
		DialTimeout: opts.DialTimeout,
		Source:      "flag",
	}

	if opts.CACertPath != "" {
		pem, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("dbounce: read CA cert %q: %w", opts.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("dbounce: CA bundle at %q is not valid PEM", opts.CACertPath)
		}
		up.rootCAs = pool
	}

	return up, nil
}

// ParseTLSMode is the CLI flag-parsing helper.
func ParseTLSMode(s string) (TLSMode, error) {
	m := TLSMode(strings.ToLower(s))
	if m.IsValid() {
		return m, nil
	}
	return "", fmt.Errorf("dbounce: invalid --upstream-tls %q (want verify | skip | disable)", s)
}

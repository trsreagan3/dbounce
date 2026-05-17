package upstream

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolve_EmptyURL_ReturnsErrNoUpstream(t *testing.T) {
	_, err := Resolve(Options{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoUpstream)
}

func TestResolve_RejectsNonPostgresScheme(t *testing.T) {
	_, err := Resolve(Options{UpstreamURL: "mysql://localhost:3306/foo"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func TestResolve_RejectsMissingHost(t *testing.T) {
	_, err := Resolve(Options{UpstreamURL: "postgres:"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing host")
}

func TestResolve_AppendsDefaultPort(t *testing.T) {
	up, err := Resolve(Options{
		UpstreamURL:   "postgres://localhost/mydb",
		AllowInternal: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "localhost:5432", up.Host(),
		"missing port must default to PG's 5432")
	assert.Equal(t, "mydb", up.Database())
}

func TestResolve_ExtractsUserAndDatabase(t *testing.T) {
	up, err := Resolve(Options{
		UpstreamURL: "postgres://alice@pg.example.com:5432/orders",
		LookupHost:  func(string) ([]string, error) { return []string{"93.184.216.34"}, nil },
	})
	require.NoError(t, err)
	assert.Equal(t, "alice", up.User())
	assert.Equal(t, "orders", up.Database())
	assert.Equal(t, "pg.example.com:5432", up.Host())
	assert.Equal(t, "pg.example.com", up.HostnameOnly())
}

func TestResolve_PostgresqlSchemeAlsoAccepted(t *testing.T) {
	up, err := Resolve(Options{
		UpstreamURL:   "postgresql://pg/db",
		AllowInternal: true, // bare "pg" hostname may not resolve under test
	})
	require.NoError(t, err)
	assert.Equal(t, "pg:5432", up.Host())
}

func TestResolve_DefaultsTLSModeToVerify(t *testing.T) {
	up, err := Resolve(Options{
		UpstreamURL:   "postgres://localhost/db",
		AllowInternal: true,
	})
	require.NoError(t, err)
	assert.Equal(t, TLSModeVerify, up.TLSMode,
		"default TLS mode must be 'verify' — operator opts out explicitly")
	cfg := up.TLSConfig()
	require.NotNil(t, cfg)
	assert.False(t, cfg.InsecureSkipVerify,
		"default TLS config must validate certs (audit-cadence check c)")
}

func TestResolve_TLSModeSkipFlipsInsecureSkipVerify(t *testing.T) {
	up, err := Resolve(Options{
		UpstreamURL:   "postgres://localhost/db",
		TLSMode:       TLSModeSkip,
		AllowInternal: true,
	})
	require.NoError(t, err)
	cfg := up.TLSConfig()
	require.NotNil(t, cfg)
	assert.True(t, cfg.InsecureSkipVerify,
		"--upstream-tls skip must set InsecureSkipVerify")
}

func TestResolve_TLSModeDisableReturnsNilTLSConfig(t *testing.T) {
	up, err := Resolve(Options{
		UpstreamURL:   "postgres://localhost/db",
		TLSMode:       TLSModeDisable,
		AllowInternal: true,
	})
	require.NoError(t, err)
	assert.Nil(t, up.TLSConfig(),
		"--upstream-tls disable must produce nil TLSConfig")
}

func TestResolve_RejectsBogusTLSMode(t *testing.T) {
	_, err := Resolve(Options{
		UpstreamURL:   "postgres://localhost/db",
		TLSMode:       "maybe",
		AllowInternal: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --upstream-tls")
}

func TestResolve_LoadsCACertWhenProvided(t *testing.T) {
	caPath := writeTestCA(t)
	up, err := Resolve(Options{
		UpstreamURL:   "postgres://localhost/db",
		CACertPath:    caPath,
		AllowInternal: true,
	})
	require.NoError(t, err)
	cfg := up.TLSConfig()
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.RootCAs, "--upstream-ca-cert must populate RootCAs")
}

func TestResolve_RejectsUnreadableCACert(t *testing.T) {
	_, err := Resolve(Options{
		UpstreamURL:   "postgres://localhost/db",
		CACertPath:    "/nonexistent/ca.pem",
		AllowInternal: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read CA cert")
}

func TestResolve_RejectsMalformedCACert(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "garbage.pem")
	require.NoError(t, os.WriteFile(bad, []byte("not a cert"), 0o600))
	_, err := Resolve(Options{
		UpstreamURL:   "postgres://localhost/db",
		CACertPath:    bad,
		AllowInternal: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid PEM")
}

func TestHostnameOnly_HandlesHostWithoutPort(t *testing.T) {
	up := &Upstream{URL: mustParseURL(t, "postgres://pg.example.com/db")}
	assert.Equal(t, "pg.example.com", up.HostnameOnly())
}

func TestParseTLSMode(t *testing.T) {
	for _, want := range []TLSMode{TLSModeVerify, TLSModeSkip, TLSModeDisable} {
		got, err := ParseTLSMode(string(want))
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	_, err := ParseTLSMode("nonsense")
	require.Error(t, err)
}

func TestTLSConfig_MinVersionTLS12(t *testing.T) {
	up, err := Resolve(Options{
		UpstreamURL:   "postgres://localhost/db",
		AllowInternal: true,
	})
	require.NoError(t, err)
	cfg := up.TLSConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion,
		"outbound TLS must never silently negotiate < TLS 1.2")
}

// ---------------------------------------------------------------------------
// MED-D8-06 (AUDIT-WB-DSLICES-1-8.md): SSRF allowlist on upstream URL.
// ---------------------------------------------------------------------------

func TestResolve_SSRF_RejectsLoopbackIPv4(t *testing.T) {
	_, err := Resolve(Options{
		UpstreamURL: "postgres://tester@127.0.0.1:5432/db",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "127.0.0.0/8",
		"error must name the CIDR range that triggered the SSRF gate")
	assert.Contains(t, err.Error(), "MED-D8-06")
}

func TestResolve_SSRF_RejectsLoopbackIPv6(t *testing.T) {
	_, err := Resolve(Options{
		UpstreamURL: "postgres://[::1]:5432/db",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "::1/128")
}

func TestResolve_SSRF_RejectsCloudMetadataIPv4(t *testing.T) {
	_, err := Resolve(Options{
		UpstreamURL: "postgres://x@169.254.169.254:5432/db",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "169.254.0.0/16",
		"AWS/GCP/Azure metadata endpoint must be flagged with its CIDR")
}

func TestResolve_SSRF_RejectsRFC1918_10(t *testing.T) {
	_, err := Resolve(Options{UpstreamURL: "postgres://10.0.0.1:5432/db"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "10.0.0.0/8")
}

func TestResolve_SSRF_RejectsRFC1918_172(t *testing.T) {
	_, err := Resolve(Options{UpstreamURL: "postgres://172.16.5.10:5432/db"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "172.16.0.0/12")
}

func TestResolve_SSRF_RejectsRFC1918_192(t *testing.T) {
	_, err := Resolve(Options{UpstreamURL: "postgres://192.168.1.1:5432/db"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "192.168.0.0/16")
}

func TestResolve_SSRF_RejectsLinkLocalIPv6(t *testing.T) {
	_, err := Resolve(Options{UpstreamURL: "postgres://[fe80::1]:5432/db"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fe80::/10")
}

func TestResolve_SSRF_RejectsRFC4193IPv6(t *testing.T) {
	_, err := Resolve(Options{UpstreamURL: "postgres://[fc00::1]:5432/db"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fc00::/7")
}

func TestResolve_SSRF_RejectsDotInternalTLD(t *testing.T) {
	_, err := Resolve(Options{
		UpstreamURL: "postgres://pg.svc.internal:5432/db",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), ".internal",
		".internal TLD must be rejected before DNS lookup")
}

func TestResolve_SSRF_RejectsDotLocalTLD(t *testing.T) {
	_, err := Resolve(Options{
		UpstreamURL: "postgres://pg.local:5432/db",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), ".local")
}

func TestResolve_SSRF_DNSReboundHostIsBlockedViaLookup(t *testing.T) {
	// DNS-rebinding shape: the URL hostname looks public, but the
	// resolver returns a private IP. The gate MUST use net.LookupHost
	// (not just URL string parsing) to catch this — the load-bearing
	// invariant the audit doc spelled out.
	_, err := Resolve(Options{
		UpstreamURL: "postgres://attacker.example.com:5432/db",
		LookupHost: func(string) ([]string, error) {
			return []string{"10.0.0.42"}, nil
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "10.0.0.0/8",
		"DNS-rebinding probe (public host → private IP) MUST be caught by LookupHost-based check")
}

func TestResolve_SSRF_DNSReboundHostBlockedOnAnyMatch(t *testing.T) {
	// Mixed return: one public IP + one private IP. The gate must
	// reject on ANY private match — the proxy could dial either.
	_, err := Resolve(Options{
		UpstreamURL: "postgres://mixed.example.com:5432/db",
		LookupHost: func(string) ([]string, error) {
			return []string{"93.184.216.34", "10.1.2.3"}, nil
		},
	})
	require.Error(t, err)
}

func TestResolve_SSRF_PublicHostAllowed(t *testing.T) {
	// Sanity: a host that resolves to a non-internal IP MUST pass.
	up, err := Resolve(Options{
		UpstreamURL: "postgres://pg.example.com:5432/db",
		LookupHost: func(string) ([]string, error) {
			return []string{"93.184.216.34"}, nil
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "pg.example.com:5432", up.Host())
}

func TestResolve_SSRF_AllowInternalOptInWorks(t *testing.T) {
	// With AllowInternal=true the operator-explicit override permits
	// the loopback case. Required for legitimate intranet DB scenarios.
	up, err := Resolve(Options{
		UpstreamURL:   "postgres://127.0.0.1:5432/db",
		AllowInternal: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:5432", up.Host())
}

func TestResolve_SSRF_AllowInternalAlsoBypassesTLDCheck(t *testing.T) {
	up, err := Resolve(Options{
		UpstreamURL:   "postgres://pg.svc.internal:5432/db",
		AllowInternal: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "pg.svc.internal:5432", up.Host())
}

func TestResolve_SSRF_LookupErrorIsRejected(t *testing.T) {
	// When the resolver fails, we MUST NOT silently pass — the gate
	// refuses the URL since we can't confirm it's public.
	_, err := Resolve(Options{
		UpstreamURL: "postgres://nonexistent.example.com:5432/db",
		LookupHost: func(string) ([]string, error) {
			return nil, errors.New("simulated DNS failure")
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lookup upstream host")
}

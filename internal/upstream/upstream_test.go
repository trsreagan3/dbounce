package upstream

import (
	"crypto/tls"
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
	up, err := Resolve(Options{UpstreamURL: "postgres://localhost/mydb"})
	require.NoError(t, err)
	assert.Equal(t, "localhost:5432", up.Host(),
		"missing port must default to PG's 5432")
	assert.Equal(t, "mydb", up.Database())
}

func TestResolve_ExtractsUserAndDatabase(t *testing.T) {
	up, err := Resolve(Options{UpstreamURL: "postgres://alice@pg.example.com:5432/orders"})
	require.NoError(t, err)
	assert.Equal(t, "alice", up.User())
	assert.Equal(t, "orders", up.Database())
	assert.Equal(t, "pg.example.com:5432", up.Host())
	assert.Equal(t, "pg.example.com", up.HostnameOnly())
}

func TestResolve_PostgresqlSchemeAlsoAccepted(t *testing.T) {
	up, err := Resolve(Options{UpstreamURL: "postgresql://pg/db"})
	require.NoError(t, err)
	assert.Equal(t, "pg:5432", up.Host())
}

func TestResolve_DefaultsTLSModeToVerify(t *testing.T) {
	up, err := Resolve(Options{UpstreamURL: "postgres://localhost/db"})
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
		UpstreamURL: "postgres://localhost/db",
		TLSMode:     TLSModeSkip,
	})
	require.NoError(t, err)
	cfg := up.TLSConfig()
	require.NotNil(t, cfg)
	assert.True(t, cfg.InsecureSkipVerify,
		"--upstream-tls skip must set InsecureSkipVerify")
}

func TestResolve_TLSModeDisableReturnsNilTLSConfig(t *testing.T) {
	up, err := Resolve(Options{
		UpstreamURL: "postgres://localhost/db",
		TLSMode:     TLSModeDisable,
	})
	require.NoError(t, err)
	assert.Nil(t, up.TLSConfig(),
		"--upstream-tls disable must produce nil TLSConfig")
}

func TestResolve_RejectsBogusTLSMode(t *testing.T) {
	_, err := Resolve(Options{
		UpstreamURL: "postgres://localhost/db",
		TLSMode:     "maybe",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --upstream-tls")
}

func TestResolve_LoadsCACertWhenProvided(t *testing.T) {
	caPath := writeTestCA(t)
	up, err := Resolve(Options{
		UpstreamURL: "postgres://localhost/db",
		CACertPath:  caPath,
	})
	require.NoError(t, err)
	cfg := up.TLSConfig()
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.RootCAs, "--upstream-ca-cert must populate RootCAs")
}

func TestResolve_RejectsUnreadableCACert(t *testing.T) {
	_, err := Resolve(Options{
		UpstreamURL: "postgres://localhost/db",
		CACertPath:  "/nonexistent/ca.pem",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read CA cert")
}

func TestResolve_RejectsMalformedCACert(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "garbage.pem")
	require.NoError(t, os.WriteFile(bad, []byte("not a cert"), 0o600))
	_, err := Resolve(Options{
		UpstreamURL: "postgres://localhost/db",
		CACertPath:  bad,
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
	up, err := Resolve(Options{UpstreamURL: "postgres://localhost/db"})
	require.NoError(t, err)
	cfg := up.TLSConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion,
		"outbound TLS must never silently negotiate < TLS 1.2")
}

package tlsmat

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadCert reads a PEM cert file and returns the parsed x509.Certificate.
func loadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	pemBytes, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "PEM must decode")
	require.Equal(t, "CERTIFICATE", block.Type)
	c, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return c
}

func TestGenerateCAAndServerCert_ProducesValidChain(t *testing.T) {
	dir := t.TempDir()
	res, err := GenerateCAAndServerCert(Options{
		OutDir:   dir,
		ValidFor: time.Hour,
		KeyBits:  2048,
	})
	require.NoError(t, err)
	require.NotNil(t, res)

	for _, p := range []string{res.CACertPath, res.ServerCertPath, res.ServerKeyPath} {
		_, err := os.Stat(p)
		require.NoError(t, err, "expected file %s to exist", p)
	}
	assert.Empty(t, res.ClientCertPath, "no client cert when WithClientCert=false")
	assert.Empty(t, res.ClientKeyPath)

	ca := loadCert(t, res.CACertPath)
	srv := loadCert(t, res.ServerCertPath)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err = srv.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err, "server cert must verify against generated CA")

	assert.Contains(t, srv.DNSNames, "localhost")
	var sawV4 bool
	for _, ip := range srv.IPAddresses {
		if ip.To4() != nil && ip.String() == "127.0.0.1" {
			sawV4 = true
		}
	}
	assert.True(t, sawV4, "127.0.0.1 must be in default SAN IP list")

	_, err = tls.LoadX509KeyPair(res.ServerCertPath, res.ServerKeyPath)
	require.NoError(t, err, "tls.LoadX509KeyPair must accept the issued material")
}

func TestGenerateCAAndServerCert_FilePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions are not enforced on windows")
	}
	dir := t.TempDir()
	res, err := GenerateCAAndServerCert(Options{
		OutDir:         dir,
		WithClientCert: true,
		ValidFor:       time.Hour,
		KeyBits:        2048,
	})
	require.NoError(t, err)

	check := func(path string, want os.FileMode) {
		t.Helper()
		st, err := os.Stat(path)
		require.NoError(t, err)
		got := st.Mode().Perm()
		assert.Equal(t, want, got, "perm mismatch for %s: want %o got %o", path, want, got)
	}
	check(res.CACertPath, 0o644)
	check(res.ServerCertPath, 0o644)
	check(res.ServerKeyPath, 0o600)
	check(res.ClientCertPath, 0o644)
	check(res.ClientKeyPath, 0o600)
}

func TestGenerateCAAndServerCert_WithClientCertVerifiable(t *testing.T) {
	dir := t.TempDir()
	res, err := GenerateCAAndServerCert(Options{
		OutDir:         dir,
		WithClientCert: true,
		ValidFor:       time.Hour,
		KeyBits:        2048,
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.ClientCertPath)

	ca := loadCert(t, res.CACertPath)
	cli := loadCert(t, res.ClientCertPath)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err = cli.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err, "client cert must verify against generated CA")
}

func TestGenerateCAAndServerCert_RefusesOverwriteByDefault(t *testing.T) {
	dir := t.TempDir()
	_, err := GenerateCAAndServerCert(Options{
		OutDir:   dir,
		ValidFor: time.Hour,
		KeyBits:  2048,
	})
	require.NoError(t, err)

	_, err = GenerateCAAndServerCert(Options{
		OutDir:   dir,
		ValidFor: time.Hour,
		KeyBits:  2048,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to overwrite")
}

func TestGenerateCAAndServerCert_OverwriteExistingReplaces(t *testing.T) {
	dir := t.TempDir()
	first, err := GenerateCAAndServerCert(Options{
		OutDir:   dir,
		ValidFor: time.Hour,
		KeyBits:  2048,
	})
	require.NoError(t, err)

	caFirst, err := os.ReadFile(first.CACertPath)
	require.NoError(t, err)

	second, err := GenerateCAAndServerCert(Options{
		OutDir:            dir,
		OverwriteExisting: true,
		ValidFor:          time.Hour,
		KeyBits:           2048,
	})
	require.NoError(t, err)

	caSecond, err := os.ReadFile(second.CACertPath)
	require.NoError(t, err)

	assert.NotEqual(t, caFirst, caSecond,
		"overwrite must produce a fresh CA cert (different serial / public key)")
}

func TestGenerateCAAndServerCert_OutDirRequired(t *testing.T) {
	_, err := GenerateCAAndServerCert(Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OutDir")
}

func TestGenerateCAAndServerCert_CreatesMissingDir(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "nested", "tls")
	_, err := GenerateCAAndServerCert(Options{
		OutDir:   target,
		ValidFor: time.Hour,
		KeyBits:  2048,
	})
	require.NoError(t, err)
	st, err := os.Stat(target)
	require.NoError(t, err)
	assert.True(t, st.IsDir())
}

func TestDefaultOutDir_ContainsDbounceTLS(t *testing.T) {
	got := DefaultOutDir()
	if got == "" {
		t.Skip("no HOME on this runner")
	}
	assert.Contains(t, got, ".dbounce")
	assert.Contains(t, got, "tls")
}

// Package tlsmat issues the self-signed CA + server cert (+ optional
// client cert) dbounce uses for its TLS listeners. D-Slice 4.
//
// The shape mirrors kbounce's internal/tlsmat package so cross-product
// agent-parity ([[cross-product-agent-parity]]) holds: same file names
// (ca.crt / server.crt / server.key / client.crt / client.key), same
// permissions (keys 0600, certs 0644), same atomic-write semantics.
// An operator who has used `kbounce init-tls` will recognize the
// `dbounce init-tls` output verbatim.
//
// What this package does NOT do:
//
//   - It does NOT contact a CA — everything is self-signed for local
//     development. Operators who need a real PKI either point dbounce
//     at certs their own pipeline produced (via the run-time flags) or
//     wire their own issuer outside the dbounce binary. Same posture as
//     kbounce + ibounce.
//   - It does NOT overwrite existing material without OverwriteExisting.
//     A stray re-run of `init-tls` against a populated directory aborts
//     with a clear error rather than silently rotating the keys clients
//     have already trusted.
//   - It does NOT load the generated material at issuance time — caller
//     paths supply the file paths to `crypto/tls.LoadX509KeyPair` (or
//     equivalent) when the listener actually starts. Separation keeps
//     `init-tls` runnable offline on a machine that will never bind
//     the listener.
//
// Per [[creates-never-mutates]]: tlsmat only CREATES files under the
// caller-supplied out-dir; it never modifies pre-existing material
// elsewhere on the filesystem.
package tlsmat

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// File names produced by GenerateCAAndServerCert. Exported so callers
// (CLI banner, integration tests, downstream tooling) can refer to
// them by symbolic name rather than re-typing the strings.
const (
	FileCACert     = "ca.crt"
	FileServerCert = "server.crt"
	FileServerKey  = "server.key"
	FileClientCert = "client.crt"
	FileClientKey  = "client.key"
)

// Permissions applied to the generated files. Keys hold private
// material — 0600. Certs are public and may be read by tooling running
// under a different uid (e.g. health checkers) — 0644.
const (
	keyFilePerm  os.FileMode = 0o600
	certFilePerm os.FileMode = 0o644
	dirPerm      os.FileMode = 0o700
)

// Options carries the inputs GenerateCAAndServerCert consumes. Built
// as a struct so future fields (CommonName overrides, SAN list, key
// size) can land without breaking the API.
type Options struct {
	// OutDir is where the cert + key files land. Created with 0700 if
	// missing. Required.
	OutDir string

	// WithClientCert, when true, additionally issues a client cert/key
	// pair signed by the same CA. Used for the optional mTLS path.
	WithClientCert bool

	// OverwriteExisting, when true, allows GenerateCAAndServerCert to
	// replace any pre-existing files. Default false makes a re-run
	// against a populated directory fail loudly rather than silently
	// rotating the trust anchor.
	OverwriteExisting bool

	// ValidFor caps the cert lifetime. Zero defaults to 365 days. Tests
	// use a short value to exercise the chain without polluting the
	// validity window of the dev environment.
	ValidFor time.Duration

	// KeyBits sizes the RSA private keys. Zero defaults to 2048 (RSA
	// keeps the kbounce parity surface; ECDSA may land as a separate
	// option later).
	KeyBits int

	// Hostnames + IPAddresses populate the server cert's SAN list. Empty
	// defaults to {"localhost"} + {127.0.0.1, ::1} — the loopback-only
	// posture dbounce enforces at bind time (see CRIT-32-02 in
	// internal/cli/cli.go).
	Hostnames   []string
	IPAddresses []net.IP
}

// Result names the files GenerateCAAndServerCert wrote. Returned so
// the CLI banner can print absolute paths without re-deriving them.
type Result struct {
	OutDir         string
	CACertPath     string
	ServerCertPath string
	ServerKeyPath  string
	// ClientCertPath / ClientKeyPath are empty unless WithClientCert
	// was true.
	ClientCertPath string
	ClientKeyPath  string
}

// GenerateCAAndServerCert is the high-level entry point. It produces:
//
//   - a self-signed CA in ca.crt
//   - a server cert in server.crt + RSA key in server.key, signed by the CA
//   - (when WithClientCert) a client cert in client.crt + RSA key in
//     client.key, signed by the same CA, for mTLS callers
//
// File layout under opts.OutDir matches kbounce/internal/tlsmat exactly:
//
//	ca.crt        — PEM-encoded CA cert (0644)
//	server.crt    — PEM-encoded server cert (0644)
//	server.key    — PEM-encoded RSA private key (0600)
//	client.crt    — optional, PEM-encoded client cert (0644)
//	client.key    — optional, PEM-encoded RSA private key (0600)
//
// The function is atomic per-file: each file is written to a temp
// neighbor + renamed into place. A crash mid-issuance leaves either
// the old file or the new file — never a half-written one.
func GenerateCAAndServerCert(opts Options) (*Result, error) {
	if opts.OutDir == "" {
		return nil, errors.New("tlsmat: OutDir is required")
	}
	if opts.ValidFor <= 0 {
		opts.ValidFor = 365 * 24 * time.Hour
	}
	if opts.KeyBits == 0 {
		opts.KeyBits = 2048
	}
	if len(opts.Hostnames) == 0 {
		opts.Hostnames = []string{"localhost"}
	}
	if len(opts.IPAddresses) == 0 {
		opts.IPAddresses = []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		}
	}

	if err := os.MkdirAll(opts.OutDir, dirPerm); err != nil {
		return nil, fmt.Errorf("tlsmat: mkdir %q: %w", opts.OutDir, err)
	}

	res := &Result{
		OutDir:         opts.OutDir,
		CACertPath:     filepath.Join(opts.OutDir, FileCACert),
		ServerCertPath: filepath.Join(opts.OutDir, FileServerCert),
		ServerKeyPath:  filepath.Join(opts.OutDir, FileServerKey),
	}

	// Pre-flight overwrite check. We do this BEFORE any key generation
	// so the operator's `dbounce init-tls` doesn't spend CPU on RSA-2048
	// just to error out at write time.
	if !opts.OverwriteExisting {
		for _, p := range []string{
			res.CACertPath, res.ServerCertPath, res.ServerKeyPath,
		} {
			if _, err := os.Stat(p); err == nil {
				return nil, fmt.Errorf(
					"tlsmat: refusing to overwrite existing %s "+
						"(pass OverwriteExisting=true / `--force` to rotate)", p)
			}
		}
		if opts.WithClientCert {
			for _, p := range []string{
				filepath.Join(opts.OutDir, FileClientCert),
				filepath.Join(opts.OutDir, FileClientKey),
			} {
				if _, err := os.Stat(p); err == nil {
					return nil, fmt.Errorf(
						"tlsmat: refusing to overwrite existing %s "+
							"(pass OverwriteExisting=true / `--force` to rotate)", p)
				}
			}
		}
	}

	// CA. CommonName intentionally distinguishes dbounce's CA from
	// kbounce's / ibounce's in the same operator's trust store.
	caKey, err := rsa.GenerateKey(rand.Reader, opts.KeyBits)
	if err != nil {
		return nil, fmt.Errorf("tlsmat: generate CA key: %w", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			CommonName:   "dbounce-local-ca",
			Organization: []string{"dbounce"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(opts.ValidFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("tlsmat: sign CA cert: %w", err)
	}
	caParsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("tlsmat: parse CA cert: %w", err)
	}
	if err := writePEMAtomic(res.CACertPath, "CERTIFICATE", caDER, certFilePerm); err != nil {
		return nil, err
	}

	// Server cert.
	srvKey, err := rsa.GenerateKey(rand.Reader, opts.KeyBits)
	if err != nil {
		return nil, fmt.Errorf("tlsmat: generate server key: %w", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			CommonName:   "dbounce-local-server",
			Organization: []string{"dbounce"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(opts.ValidFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              opts.Hostnames,
		IPAddresses:           opts.IPAddresses,
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caParsed, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("tlsmat: sign server cert: %w", err)
	}
	if err := writePEMAtomic(res.ServerCertPath, "CERTIFICATE", srvDER, certFilePerm); err != nil {
		return nil, err
	}
	if err := writePEMAtomic(res.ServerKeyPath, "RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(srvKey), keyFilePerm); err != nil {
		return nil, err
	}

	// Optional client cert for mTLS.
	if opts.WithClientCert {
		res.ClientCertPath = filepath.Join(opts.OutDir, FileClientCert)
		res.ClientKeyPath = filepath.Join(opts.OutDir, FileClientKey)
		cliKey, err := rsa.GenerateKey(rand.Reader, opts.KeyBits)
		if err != nil {
			return nil, fmt.Errorf("tlsmat: generate client key: %w", err)
		}
		cliTmpl := &x509.Certificate{
			SerialNumber: newSerial(),
			Subject: pkix.Name{
				CommonName:   "dbounce-local-client",
				Organization: []string{"dbounce"},
			},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(opts.ValidFor),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}
		cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caParsed, &cliKey.PublicKey, caKey)
		if err != nil {
			return nil, fmt.Errorf("tlsmat: sign client cert: %w", err)
		}
		if err := writePEMAtomic(res.ClientCertPath, "CERTIFICATE", cliDER, certFilePerm); err != nil {
			return nil, err
		}
		if err := writePEMAtomic(res.ClientKeyPath, "RSA PRIVATE KEY",
			x509.MarshalPKCS1PrivateKey(cliKey), keyFilePerm); err != nil {
			return nil, err
		}
	}

	return res, nil
}

// writePEMAtomic encodes der as a PEM block of the given type + writes
// it to path via a temp neighbor + rename. The perm is applied to the
// temp file BEFORE rename so the final file never appears with a
// looser mode (e.g. 0644 then chmod 0600 races).
func writePEMAtomic(path, blockType string, der []byte, perm os.FileMode) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if pemBytes == nil {
		return fmt.Errorf("tlsmat: pem-encode %s failed", filepath.Base(path))
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("tlsmat: create tmp for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if _, err := os.Stat(tmpName); err == nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("tlsmat: chmod tmp %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(pemBytes); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("tlsmat: write tmp %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("tlsmat: fsync tmp %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("tlsmat: close tmp %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("tlsmat: rename %s -> %s: %w", tmpName, path, err)
	}
	return nil
}

// newSerial returns a fresh random serial number (positive, 128-bit).
// Reusing serial numbers across certs signed by the same CA breaks
// some clients' chain validation; randomizing avoids that landmine.
func newSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		// Fall back to time-based. rand.Reader failures during cert
		// issuance are basically unheard of; this branch exists so
		// init-tls never panics in pathological CI environments.
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

// DefaultOutDir resolves the operator's home-relative default
// ~/.dbounce/tls. Empty home returns the empty string; the CLI surfaces
// that as a clear error rather than silently writing to the current
// working directory.
func DefaultOutDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".dbounce", "tls")
}

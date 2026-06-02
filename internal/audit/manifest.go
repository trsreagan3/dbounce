// Ed25519-signed chain-checkpoint manifests — ADOPT-10 / #734 / #624.
// Port of the Python ManifestSigner (manifest.py). The hash chain
// detects in-place edits / reordering / mid-chain deletion; manifests
// add detection of TAIL TRUNCATION by recording the chain head's
// (seq, hash) in an externally-shippable Ed25519-signed document.
//
// Wire format is BYTE-IDENTICAL to the Python format AND across the
// three Go bouncers:
//
//   - signing payload = canonical({schema_version, seq_start, seq_end,
//     head_hash, generated_at_iso, bouncer_product, log_dir}) — the
//     same key-sorted compact JSON the chain uses.
//   - signature + public key are URL-safe base64, no padding
//     (base64.RawURLEncoding == Python urlsafe_b64encode().rstrip("=")).
//   - public key is the raw 32-byte Ed25519 key.
//   - the manifest JSON file is indent=2, key-sorted, trailing newline
//     (matches Python json.dumps(indent=2, sort_keys=True) + "\n").
//
// Ed25519 signatures are deterministic, so a given (key, message) signs
// identically in Go's crypto/ed25519 and Python's cryptography lib —
// verified by the cross-impl vector test (manifest_vectors_test.go).
//
// Key handling: load_or_generate writes the keypair under the bouncer
// state dir as PEM (PKCS8 private 0o600, SPKI public 0o644) so openssl
// / ssh-keygen / the Python verifier all interoperate. The private key
// is NEVER logged or committed.
package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// DefaultKeypairName is the basename of the keypair files under the
	// keypair dir.
	DefaultKeypairName = "manifest-ed25519"
	PrivateKeySuffix   = ".priv"
	PublicKeySuffix    = ".pub"

	// DefaultManifestIntervalEvents emits a manifest every N events.
	// Matches the Python default (1000).
	DefaultManifestIntervalEvents = 1000

	// ManifestDirName is where manifests land inside the audit log dir.
	ManifestDirName = "manifests"

	// ManifestSchemaVersion stamps the signed payload. Verifiers reject
	// unknown versions (downgrade-attack defence). Matches Python.
	ManifestSchemaVersion = 1

	manifestOCSFActivityName = "audit_chain_checkpoint"
	manifestOCSFTypeName     = "API Activity: audit_chain_checkpoint"
)

// Manifest is an emitted (signed) chain-checkpoint manifest. Field
// names + JSON tags match the Python Manifest.to_dict() exactly.
type Manifest struct {
	SchemaVersion  int    `json:"schema_version"`
	SeqStart       int64  `json:"seq_start"`
	SeqEnd         int64  `json:"seq_end"`
	HeadHash       string `json:"head_hash"`
	GeneratedAtISO string `json:"generated_at_iso"`
	BouncerProduct string `json:"bouncer_product"`
	LogDir         string `json:"log_dir"`
	SignatureB64   string `json:"signature_b64"`
	PublicKeyB64   string `json:"public_key_b64"`
}

// signingPayload re-derives the exact bytes the signature covers:
// canonical JSON over every field except the two base64 fields. Must
// match Python Manifest.signing_payload().
func (m Manifest) signingPayload() ([]byte, error) {
	d := map[string]any{
		"schema_version":   m.SchemaVersion,
		"seq_start":        m.SeqStart,
		"seq_end":          m.SeqEnd,
		"head_hash":        m.HeadHash,
		"generated_at_iso": m.GeneratedAtISO,
		"bouncer_product":  m.BouncerProduct,
		"log_dir":          m.LogDir,
	}
	return canonicalJSON(d)
}

func b64u(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64uDecode(s string) ([]byte, error) {
	// RawURLEncoding has no padding; tolerate either form.
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

// LoadOrGenerateKeypair loads the bouncer's manifest-signing keypair,
// generating it on first call. The dir is created 0o700 if absent; the
// private key file is 0o600, public 0o644. PEM (PKCS8 / SPKI) so the
// Python verifier + openssl interoperate. The private key is never
// logged.
func LoadOrGenerateKeypair(dir, name string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if name == "" {
		name = DefaultKeypairName
	}
	dir = expandHome(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	// Best-effort tighten in case MkdirAll honored a looser umask.
	_ = os.Chmod(dir, 0o700)
	privPath := filepath.Join(dir, name+PrivateKeySuffix)
	pubPath := filepath.Join(dir, name+PublicKeySuffix)

	if raw, err := os.ReadFile(privPath); err == nil {
		blk, _ := pem.Decode(raw)
		if blk == nil {
			return nil, nil, fmt.Errorf("audit manifest: key at %s is not PEM", privPath)
		}
		key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("audit manifest: parse key at %s: %w", privPath, err)
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("audit manifest: key at %s is not Ed25519 — move it aside to regenerate", privPath)
		}
		return priv, priv.Public().(ed25519.PublicKey), nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// ManifestSigner is a stateful manifest emitter wired into the audit
// writer. Emit failures are counted (ManifestsFailed) but never block
// the chain.
type ManifestSigner struct {
	logDir         string
	bouncerProduct string
	interval       int64
	priv           ed25519.PrivateKey
	pubB64         string
	manifestDir    string

	LastEmittedSeq   *int64
	ManifestsEmitted int64
	ManifestsFailed  int64
}

// NewManifestSigner constructs a signer, loading/generating its
// keypair from keypairDir.
func NewManifestSigner(logDir, bouncerProduct string, interval int64, keypairDir, keypairName string) (*ManifestSigner, error) {
	if interval < 1 {
		interval = 1
	}
	priv, pub, err := LoadOrGenerateKeypair(keypairDir, keypairName)
	if err != nil {
		return nil, err
	}
	return &ManifestSigner{
		logDir:         logDir,
		bouncerProduct: bouncerProduct,
		interval:       interval,
		priv:           priv,
		pubB64:         b64u(pub),
		manifestDir:    filepath.Join(logDir, ManifestDirName),
	}, nil
}

// ShouldEmit reports whether the chain head has advanced interval
// events past the last emitted manifest. Matches Python should_emit.
func (s *ManifestSigner) ShouldEmit(state *ChainState) bool {
	head := state.HeadSeq()
	if head < 0 {
		return false
	}
	if s.LastEmittedSeq == nil {
		return head+1 >= s.interval
	}
	return (head - *s.LastEmittedSeq) >= s.interval
}

// Emit signs + persists a manifest covering the current chain head.
// Returns the emitted manifest, or nil on failure (counted in
// ManifestsFailed). Matches Python emit().
func (s *ManifestSigner) Emit(state *ChainState) (*Manifest, error) {
	head := state.HeadSeq()
	headHash := state.HeadHash()
	if head < 0 || headHash == "" {
		return nil, nil
	}
	var seqStart int64
	if s.LastEmittedSeq != nil {
		seqStart = *s.LastEmittedSeq + 1
	}
	seqEnd := head
	if seqStart > seqEnd {
		seqStart = seqEnd
	}
	generatedAt := time.Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")

	m := Manifest{
		SchemaVersion:  ManifestSchemaVersion,
		SeqStart:       seqStart,
		SeqEnd:         seqEnd,
		HeadHash:       headHash,
		GeneratedAtISO: generatedAt,
		BouncerProduct: s.bouncerProduct,
		LogDir:         s.logDir,
		PublicKeyB64:   s.pubB64,
	}
	payload, err := m.signingPayload()
	if err != nil {
		s.ManifestsFailed++
		return nil, err
	}
	sig := ed25519.Sign(s.priv, payload)
	m.SignatureB64 = b64u(sig)

	if err := s.persist(m, generatedAt); err != nil {
		s.ManifestsFailed++
		return nil, err
	}
	s.ManifestsEmitted++
	se := seqEnd
	s.LastEmittedSeq = &se
	return &m, nil
}

func (s *ManifestSigner) persist(m Manifest, generatedAt string) error {
	if err := os.MkdirAll(s.manifestDir, 0o755); err != nil {
		return err
	}
	tsForName := strings.NewReplacer(":", "", "-", "").Replace(generatedAt)
	name := fmt.Sprintf("manifest-%012d-%012d-%s.json", m.SeqStart, m.SeqEnd, tsForName)
	out := filepath.Join(s.manifestDir, name)
	// indent=2, sort_keys, trailing newline — matches Python.
	body, err := json.MarshalIndent(manifestSortedMap(m), "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, out)
}

// manifestSortedMap returns the manifest as a map so MarshalIndent
// sorts keys (matching Python sort_keys=True). A struct would emit in
// field-declaration order.
func manifestSortedMap(m Manifest) map[string]any {
	return map[string]any{
		"schema_version":   m.SchemaVersion,
		"seq_start":        m.SeqStart,
		"seq_end":          m.SeqEnd,
		"head_hash":        m.HeadHash,
		"generated_at_iso": m.GeneratedAtISO,
		"bouncer_product":  m.BouncerProduct,
		"log_dir":          m.LogDir,
		"signature_b64":    m.SignatureB64,
		"public_key_b64":   m.PublicKeyB64,
	}
}

// PublicKeyB64 returns the URL-safe base64 (no padding) public key.
func (s *ManifestSigner) PublicKeyB64() string { return s.pubB64 }

// ManifestDir returns the manifest output directory.
func (s *ManifestSigner) ManifestDir() string { return s.manifestDir }

// LoadManifestFile reads + parses a manifest. Does NOT verify the
// signature (see VerifyManifest). Rejects unknown schema versions.
func LoadManifestFile(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.SchemaVersion != ManifestSchemaVersion {
		return nil, fmt.Errorf("manifest %s has unknown schema_version %d; expected %d (refusing — downgrade attack could strip safety fields)", path, m.SchemaVersion, ManifestSchemaVersion)
	}
	return &m, nil
}

// VerifyManifest verifies the Ed25519 signature. By default uses the
// embedded public key; pass a non-empty override (pinned out-of-band)
// to ignore it. Returns (ok, reason); reason is "" on success. Matches
// Python verify_manifest.
func VerifyManifest(m *Manifest, publicKeyOverrideB64 string) (bool, string) {
	pubB64 := m.PublicKeyB64
	if publicKeyOverrideB64 != "" {
		pubB64 = publicKeyOverrideB64
	}
	pubBytes, err := b64uDecode(pubB64)
	if err != nil {
		return false, fmt.Sprintf("public key base64 decode failed: %v", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return false, fmt.Sprintf("public key length %d != 32 (Ed25519 raw key must be exactly 32 bytes)", len(pubBytes))
	}
	sig, err := b64uDecode(m.SignatureB64)
	if err != nil {
		return false, fmt.Sprintf("signature base64 decode failed: %v", err)
	}
	payload, err := m.signingPayload()
	if err != nil {
		return false, fmt.Sprintf("signing payload re-derive failed: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), payload, sig) {
		return false, "signature does not match payload — manifest was tampered with or signed by a different key"
	}
	return true, ""
}

// ListManifests returns all manifest files under logDir/manifests/
// sorted by name (== seq_start order). Empty when the dir is missing.
func ListManifests(logDir string) []string {
	dir := filepath.Join(logDir, ManifestDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "manifest-") && strings.HasSuffix(n, ".json") {
			out = append(out, filepath.Join(dir, n))
		}
	}
	sort.Strings(out)
	return out
}

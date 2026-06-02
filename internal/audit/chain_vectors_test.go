package audit

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// pythonEventJSON is the exact OCSF event the Python reference impl
// stamped to produce the known-good vectors below. Field order here is
// irrelevant — canonicalization sorts keys — but it matches the Python
// test fixture for clarity.
const pythonEventJSON = `{"metadata":{"version":"1.1.0","product":{"name":"gbounce"}},"class_uid":6003,"activity_name":"Read","time":1700000000000,"unmapped":{"iam_jit":{"verdict":"ALLOW","i":0}}}`

// pythonChainHashes are the chain hashes the Python implementation
// (src/iam_jit/bouncer/audit_export/chain.py + audit.py:_hash_event)
// produced for a 3-event chain where event i has time=1700000000000+i
// and unmapped.iam_jit.i=i. Computed offline from the canonical Python
// impl; hardcoded so any Go-vs-Python wire divergence fails CI.
var pythonChainHashes = []string{
	"38d80141a2274459b2486b307f945848d0b317e49d2eb33573cd13241e8111a8",
	"56a9c6b434fb32d72afbc24e168045ddd53b440d491db2a3a9bab7687d7a814d",
	"dde6274dba53027f803174717927cbd3d3259a1b85728f68206015d076897618",
}

// pythonManifest* are the Ed25519 signature + raw public key the Python
// impl produced for a manifest over the 3-event chain head, signed with
// the deterministic seed key bytes(range(32)). Ed25519 is deterministic
// so Go's crypto/ed25519 MUST produce byte-identical output.
const (
	pythonManifestSigB64 = "SXSRGbaGz9UIHdfoUopvUaegfzYkDqm174e35hsQhtQzmyRJBxWjsmWU42bkKQ0NGLYLoj6jub8P3nPGJa5bCQ"
	pythonManifestPubB64 = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
)

// TestCrossImpl_ChainHashMatchesPython is the load-bearing
// cross-implementation assertion: stamping the SAME event with the Go
// chain MUST produce the SAME hash the Python impl produced. A
// divergence in canonicalization (key order, separators, HTML escaping,
// ensure_ascii, int-vs-float) fails here, which fails CI.
func TestCrossImpl_ChainHashMatchesPython(t *testing.T) {
	st := &ChainState{saveEveryN: DefaultSaveEveryNEvents}
	for i := 0; i < 3; i++ {
		ev := map[string]any{
			"metadata":     map[string]any{"version": "1.1.0", "product": map[string]any{"name": "gbounce"}},
			"class_uid":    6003,
			"activity_name": "Read",
			"time":         1700000000000 + i,
			"unmapped":     map[string]any{"iam_jit": map[string]any{"verdict": "ALLOW", "i": i}},
		}
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		stamped, err := st.StampJSON(raw)
		if err != nil {
			t.Fatalf("stamp %d: %v", i, err)
		}
		var out map[string]any
		dec := json.NewDecoder(bytes.NewReader(stamped))
		dec.UseNumber()
		if err := dec.Decode(&out); err != nil {
			t.Fatal(err)
		}
		block := out["unmapped"].(map[string]any)["iam_jit"].(map[string]any)[ChainField].(map[string]any)
		got := block[ChainHashField].(string)
		if got != pythonChainHashes[i] {
			t.Fatalf("event %d hash mismatch:\n  go     = %s\n  python = %s", i, got, pythonChainHashes[i])
		}
	}
}

// TestCrossImpl_SingleEventCanonicalHash asserts the genesis hash for a
// single event matches the documented preimage vector — a minimal
// regression guard independent of the multi-event stamping above.
func TestCrossImpl_SingleEventCanonicalHash(t *testing.T) {
	tree, err := decodeJSONNumber([]byte(pythonEventJSON))
	if err != nil {
		t.Fatal(err)
	}
	h, err := hashEvent(nil, 0, tree)
	if err != nil {
		t.Fatal(err)
	}
	if h != pythonChainHashes[0] {
		t.Fatalf("genesis hash mismatch:\n  go     = %s\n  python = %s", h, pythonChainHashes[0])
	}
}

// TestCrossImpl_CanonicalJSONEscaping locks in the two Python-divergent
// behaviors: HTML chars (< > &) are NOT escaped, and non-ASCII is
// escaped to \uXXXX (surrogate pairs for astral chars) — matching
// json.dumps(ensure_ascii=True, separators=(",",":")).
func TestCrossImpl_CanonicalJSONEscaping(t *testing.T) {
	tree, _ := decodeJSONNumber([]byte(`{"u":"café 日本 😀 emoji","a":"<script> & \"q\""}`))
	got, err := canonicalJSON(tree)
	if err != nil {
		t.Fatal(err)
	}
	// Python json.dumps(ensure_ascii=True) output: non-ASCII escaped to
	// \uXXXX, astral chars (😀 = U+1F600) as surrogate pairs
	// (😀), HTML chars (< > &) NOT escaped. The backslashes
	// below are literal backslash-u sequences in the JSON, hence the
	// backtick raw string with doubled meaning avoided via explicit \\.
	want := "{\"a\":\"<script> & \\\"q\\\"\",\"u\":\"caf\\u00e9 \\u65e5\\u672c \\ud83d\\ude00 emoji\"}"
	if string(got) != want {
		t.Fatalf("canonical mismatch:\n  go   = %s\n  want = %s", got, want)
	}
}

// TestCrossImpl_ManifestSignatureMatchesPython verifies that signing the
// same manifest payload with the same Ed25519 seed key produces the
// byte-identical signature + public key the Python impl produced. This
// proves the manifest wire format (signing-payload canonicalization +
// base64url-no-pad encoding) is cross-compatible.
func TestCrossImpl_ManifestSignatureMatchesPython(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	m := Manifest{
		SchemaVersion:  ManifestSchemaVersion,
		SeqStart:       0,
		SeqEnd:         2,
		HeadHash:       pythonChainHashes[2],
		GeneratedAtISO: "2026-06-02T12:00:00Z",
		BouncerProduct: "gbounce",
		LogDir:         "/tmp/logs",
	}
	payload, err := m.signingPayload()
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, payload)
	gotSig := b64u(sig)
	if gotSig != pythonManifestSigB64 {
		t.Fatalf("signature mismatch:\n  go     = %s\n  python = %s", gotSig, pythonManifestSigB64)
	}
	gotPub := b64u(priv.Public().(ed25519.PublicKey))
	if gotPub != pythonManifestPubB64 {
		t.Fatalf("pubkey mismatch:\n  go     = %s\n  python = %s", gotPub, pythonManifestPubB64)
	}
	// And the manifest verifies against the embedded (Python-format) key.
	m.SignatureB64 = pythonManifestSigB64
	m.PublicKeyB64 = pythonManifestPubB64
	ok, reason := VerifyManifest(&m, "")
	if !ok {
		t.Fatalf("Python-signed manifest failed Go verification: %s", reason)
	}
}

// helper: gzip-write a slice of pre-stamped JSONL lines to an archive.
func writeGzArchive(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	for _, l := range lines {
		_, _ = gw.Write(append(append([]byte(nil), l...), '\n'))
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeLines(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func stampN(t *testing.T, st *ChainState, n int) [][]byte {
	t.Helper()
	var lines [][]byte
	for i := 0; i < n; i++ {
		ev := map[string]any{
			"class_uid":     6003,
			"activity_name": "Read",
			"time":          1700000000000 + i,
			"unmapped":      map[string]any{"iam_jit": map[string]any{"i": i}},
		}
		raw, _ := json.Marshal(ev)
		s, err := st.StampJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, s)
	}
	return lines
}

func tmpLogDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	return filepath.Join(d)
}

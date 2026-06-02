package audit

import (
	"crypto/ed25519"
	"testing"
)

// TestCrossImpl_ManifestSignatureForThisProduct is the per-repo
// product-string parity vector (LOW finding). The shared
// chain_vectors_test.go asserts the manifest signature for the literal
// product string "gbounce" in every repo, which does NOT prove THIS
// repo's own product string round-trips against Python. This vector
// signs a manifest carrying THIS repo's product string
// ("dbounce") with the deterministic seed bytes(range(32)) and asserts
// the signature matches the value computed offline from the reference
// Python cryptography lib — proving this repo's product-string
// canonicalization is byte-identical to Python.
func TestCrossImpl_ManifestSignatureForThisProduct(t *testing.T) {
	const thisProduct = "dbounce"
	// Computed offline from the Python reference impl with seed
	// bytes(range(32)) over a manifest with bouncer_product=thisProduct.
	const wantSigB64 = "U7hylEzGOHJMAlV7RDnvtlsQBT43D07SKGy3kWgAQ03Zv9_9DJPwwTdhUIAnYJBWL9YL5s7qdn4ztC9SqXnnAw"

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
		BouncerProduct: thisProduct,
		LogDir:         "/tmp/logs",
	}
	payload, err := m.signingPayload()
	if err != nil {
		t.Fatal(err)
	}
	gotSig := b64u(ed25519.Sign(priv, payload))
	if gotSig != wantSigB64 {
		t.Fatalf("manifest signature for product %q diverged from Python:\n  go     = %s\n  python = %s",
			thisProduct, gotSig, wantSigB64)
	}

	// And the manifest verifies end-to-end with the embedded key.
	m.SignatureB64 = gotSig
	m.PublicKeyB64 = pythonManifestPubB64
	if ok, reason := VerifyManifest(&m, ""); !ok {
		t.Fatalf("product-%q manifest failed verification: %s", thisProduct, reason)
	}
}

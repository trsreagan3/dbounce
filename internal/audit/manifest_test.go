package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestManifest_EmitAndVerify(t *testing.T) {
	dir := tmpLogDir(t)
	keys := filepath.Join(dir, "keys")
	st := LoadChainState(dir, 0)
	_ = stampN(t, st, 1)

	signer, err := NewManifestSigner(dir, "gbounce", 1, keys, DefaultKeypairName)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.ShouldEmit(st) {
		t.Fatal("should emit after interval=1 with 1 event")
	}
	m, err := signer.Emit(st)
	if err != nil || m == nil {
		t.Fatalf("emit: m=%v err=%v", m, err)
	}
	ok, reason := VerifyManifest(m, "")
	if !ok {
		t.Fatalf("fresh manifest failed to verify: %s", reason)
	}
	files := ListManifests(dir)
	if len(files) != 1 {
		t.Fatalf("expected 1 manifest file, got %d", len(files))
	}
	// Re-load from disk + verify.
	loaded, err := LoadManifestFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := VerifyManifest(loaded, ""); !ok {
		t.Fatalf("loaded manifest failed to verify: %s", reason)
	}
}

func TestManifest_TamperFailsVerify(t *testing.T) {
	dir := tmpLogDir(t)
	keys := filepath.Join(dir, "keys")
	st := LoadChainState(dir, 0)
	_ = stampN(t, st, 1)
	signer, err := NewManifestSigner(dir, "gbounce", 1, keys, DefaultKeypairName)
	if err != nil {
		t.Fatal(err)
	}
	m, err := signer.Emit(st)
	if err != nil || m == nil {
		t.Fatalf("emit: %v", err)
	}
	// Tamper the seq_end after signing.
	m.SeqEnd += 99
	if ok, _ := VerifyManifest(m, ""); ok {
		t.Fatal("expected tampered manifest to fail verification")
	}
}

func TestManifest_TamperedFileOnDiskFails(t *testing.T) {
	dir := tmpLogDir(t)
	keys := filepath.Join(dir, "keys")
	st := LoadChainState(dir, 0)
	_ = stampN(t, st, 1)
	signer, _ := NewManifestSigner(dir, "gbounce", 1, keys, DefaultKeypairName)
	if _, err := signer.Emit(st); err != nil {
		t.Fatal(err)
	}
	mfile := ListManifests(dir)[0]
	raw, _ := os.ReadFile(mfile)
	var obj map[string]any
	_ = json.Unmarshal(raw, &obj)
	obj["seq_end"] = 999
	out, _ := json.MarshalIndent(obj, "", "  ")
	_ = os.WriteFile(mfile, out, 0o644)

	loaded, err := LoadManifestFile(mfile)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyManifest(loaded, ""); ok {
		t.Fatal("expected on-disk-tampered manifest to fail verification")
	}
}

func TestManifest_KeypairPerms(t *testing.T) {
	dir := tmpLogDir(t)
	keys := filepath.Join(dir, "keys")
	if _, err := NewManifestSigner(dir, "gbounce", 1, keys, DefaultKeypairName); err != nil {
		t.Fatal(err)
	}
	priv := filepath.Join(keys, DefaultKeypairName+PrivateKeySuffix)
	fi, err := os.Stat(priv)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key perms = %o, want 600", fi.Mode().Perm())
	}
	// Loading again returns the SAME key (stable identity).
	s2, _ := NewManifestSigner(dir, "gbounce", 1, keys, DefaultKeypairName)
	st := LoadChainState(dir, 0)
	_ = stampN(t, st, 1)
	s1, _ := NewManifestSigner(dir, "gbounce", 1, keys, DefaultKeypairName)
	if s1.PublicKeyB64() != s2.PublicKeyB64() {
		t.Fatal("keypair not stable across loads")
	}
}

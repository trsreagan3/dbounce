package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLogWriter_ChainStampsAndVerifies — ADOPT-10 / #734 — events
// written through the LogWriter worker with a chain configured must
// land chained on disk + verify clean, and the writer must surface
// honest chain + manifest state via its accessors.
func TestLogWriter_ChainStampsAndVerifies(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	chain := LoadChainState(dir, 0)
	signer, err := NewManifestSigner(dir, "dbounce", 1, filepath.Join(dir, "keys"), DefaultKeypairName)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewLogWriter(LogOptions{
		Path:   logPath,
		Fsync:  true,
		Chain:  chain,
		Signer: signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_ = w.Write(context.Background(), Event{})
	}
	// Drain.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && w.Stats().Written < 3 {
		time.Sleep(20 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = w.Shutdown(ctx)

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("audit log empty")
	}

	res, err := VerifyChain(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("chain failed verification: %+v", res.Inconsistencies)
	}
	if res.EventsChecked != 3 {
		t.Fatalf("events_checked = %d, want 3", res.EventsChecked)
	}

	if !w.ChainEnabled() {
		t.Fatal("ChainEnabled = false; want true")
	}
	if w.ChainHeadSeq() != 2 {
		t.Fatalf("ChainHeadSeq = %d, want 2", w.ChainHeadSeq())
	}
	if w.ChainHeadHash() == "" {
		t.Fatal("ChainHeadHash empty")
	}

	files := ListManifests(dir)
	if len(files) == 0 {
		t.Fatal("expected at least one manifest emitted")
	}
	m, err := LoadManifestFile(files[len(files)-1])
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := VerifyManifest(m, ""); !ok {
		t.Fatalf("emitted manifest failed verify: %s", reason)
	}
}

package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestChain_CleanVerify(t *testing.T) {
	dir := tmpLogDir(t)
	st := LoadChainState(dir, 0)
	lines := stampN(t, st, 5)
	writeLines(t, filepath.Join(dir, "audit.jsonl"), lines)

	res, err := VerifyChain(dir, st.StateFileAbsent())
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("expected clean chain, got: %+v", res.Inconsistencies)
	}
	if res.EventsChecked != 5 {
		t.Fatalf("events_checked = %d, want 5", res.EventsChecked)
	}
	if res.HeadSeq == nil || *res.HeadSeq != 4 {
		t.Fatalf("head_seq = %v, want 4", res.HeadSeq)
	}
}

func TestChain_TamperMiddleEventFailsVerify(t *testing.T) {
	dir := tmpLogDir(t)
	st := LoadChainState(dir, 0)
	lines := stampN(t, st, 5)

	// Tamper a field in the MIDDLE event (index 2) without recomputing
	// its hash — exactly what a quiet log editor would do.
	var ev map[string]any
	dec := json.NewDecoder(bytes.NewReader(lines[2]))
	dec.UseNumber()
	if err := dec.Decode(&ev); err != nil {
		t.Fatal(err)
	}
	ev["unmapped"].(map[string]any)["iam_jit"].(map[string]any)["verdict"] = "DENY"
	tampered, _ := json.Marshal(ev)
	lines[2] = tampered
	writeLines(t, filepath.Join(dir, "audit.jsonl"), lines)

	res, err := VerifyChain(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("expected tamper to be detected, chain verified clean")
	}
	var sawHashMismatch bool
	for _, inc := range res.Inconsistencies {
		if inc.Reason == ReasonHashMismatch && inc.Seq != nil && *inc.Seq == 2 {
			sawHashMismatch = true
		}
	}
	if !sawHashMismatch {
		t.Fatalf("expected hash-mismatch finding at seq 2, got: %+v", res.Inconsistencies)
	}
}

func TestChain_DeletedRowFailsVerify(t *testing.T) {
	dir := tmpLogDir(t)
	st := LoadChainState(dir, 0)
	lines := stampN(t, st, 5)
	// Delete the middle row.
	kept := append(append([][]byte{}, lines[:2]...), lines[3:]...)
	writeLines(t, filepath.Join(dir, "audit.jsonl"), kept)

	res, _ := VerifyChain(dir, false)
	if res.OK() {
		t.Fatal("expected deletion to be detected")
	}
	var sawGap, sawPrev bool
	for _, inc := range res.Inconsistencies {
		switch inc.Reason {
		case ReasonSeqGap:
			sawGap = true
		case ReasonPrevHashMismatch:
			sawPrev = true
		}
	}
	if !sawGap || !sawPrev {
		t.Fatalf("expected seq-gap + prev-hash-mismatch, got: %+v", res.Inconsistencies)
	}
}

func TestChain_StatePersistsAcrossReload(t *testing.T) {
	dir := tmpLogDir(t)
	st := LoadChainState(dir, 0)
	_ = stampN(t, st, 3)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	st2 := LoadChainState(dir, 0)
	if st2.StateFileAbsent() {
		t.Fatal("state should not be absent after Save")
	}
	if st2.NextSeq() != 3 {
		t.Fatalf("reloaded next_seq = %d, want 3", st2.NextSeq())
	}
	if st2.HeadHash() != st.HeadHash() {
		t.Fatalf("reloaded head hash mismatch: %s vs %s", st2.HeadHash(), st.HeadHash())
	}
}

func TestChain_StateFilePerms(t *testing.T) {
	dir := tmpLogDir(t)
	st := LoadChainState(dir, 0)
	_ = stampN(t, st, 1)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(StatePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("chain state perms = %o, want 600", fi.Mode().Perm())
	}
}

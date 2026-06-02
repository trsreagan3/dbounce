// Package cli — verify-chain (ADOPT-10/#734) tamper-detection tests.
//
// MED-2 closure: the `dbounce logs verify-chain` operator subcommand is the
// reachable entrypoint for the tamper-evident hash-chain verifier. These
// tests prove a clean chain reports OK (zero exit) and a tampered chain
// reports the break + a non-zero exit — the property an incident-response
// runbook depends on per [[ibounce-honest-positioning]].

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trsreagan3/dbounce/internal/audit"
)

// stampChainToFile builds an N-event hash-chain via the audit package's
// StampJSON (the same code path the live writer uses) and writes the
// canonical rows to audit.jsonl in dir. Returns the file path.
func stampChainToFile(t *testing.T, dir string, n int) string {
	t.Helper()
	chain := audit.LoadChainState(dir, 0)
	var buf bytes.Buffer
	for i := 0; i < n; i++ {
		ev := map[string]any{
			"class_uid":     6003,
			"activity_name": "Read",
			"time":          1700000000000 + i,
			"unmapped":      map[string]any{"iam_jit": map[string]any{"i": i}},
		}
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		stamped, err := chain.StampJSON(raw)
		if err != nil {
			t.Fatalf("stamp %d: %v", i, err)
		}
		buf.Write(stamped)
		buf.WriteByte('\n')
	}
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLogsVerifyChain_Clean asserts the verify-chain command reports a
// clean chain (zero exit, "chain OK") for an untampered log.
func TestLogsVerifyChain_Clean(t *testing.T) {
	dir := t.TempDir()
	path := stampChainToFile(t, dir, 4)

	root := newRootCmd()
	root.SetArgs([]string{"logs", "verify-chain", "--audit-log", path})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	if err := root.Execute(); err != nil {
		t.Fatalf("verify-chain on a clean log must succeed; got err=%v out=%q", err, buf.String())
	}
	if !strings.Contains(buf.String(), "chain OK:") {
		t.Errorf("expected 'chain OK:' summary; got: %q", buf.String())
	}
}

// TestLogsVerifyChain_TamperDetected is the load-bearing tamper test:
// edit one row's payload in place, then assert the command reports a
// hash-mismatch break AND exits non-zero — the property an
// incident-response runbook depends on per [[ibounce-honest-positioning]].
func TestLogsVerifyChain_TamperDetected(t *testing.T) {
	dir := t.TempDir()
	path := stampChainToFile(t, dir, 4)

	// Tamper: flip a value inside the middle row's payload WITHOUT
	// recomputing its chain hash. The stored hash no longer matches the
	// recomputed hash over the edited payload.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected 4 rows, got %d", len(lines))
	}
	// Row index 2 (seq=2): change activity_name Read -> Delete.
	tampered := strings.Replace(lines[2], `"activity_name":"Read"`, `"activity_name":"Delete"`, 1)
	if tampered == lines[2] {
		t.Fatalf("tamper substitution did not change the row; row=%q", lines[2])
	}
	lines[2] = tampered
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := newRootCmd()
	root.SetArgs([]string{"logs", "verify-chain", "--audit-log", path})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	err = root.Execute()
	if err == nil {
		t.Fatalf("verify-chain MUST return a non-zero (error) result on a tampered log; got out=%q", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "TAMPER DETECTED") {
		t.Errorf("expected 'TAMPER DETECTED' in output; got: %q", out)
	}
	if !strings.Contains(out, "hash mismatch") {
		t.Errorf("expected the hash-mismatch reason naming the edited row; got: %q", out)
	}
	if !strings.Contains(out, "seq=2") {
		t.Errorf("expected the break to be reported at seq=2 (the edited row); got: %q", out)
	}
}

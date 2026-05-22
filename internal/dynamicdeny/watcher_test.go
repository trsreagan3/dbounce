// watcher_test.go — #324c watcher regression suite.
//
// Covers:
//   - file-creation event triggers reload + emits ReasonFileCreated /
//     ReasonFileModified (fsevents-timing-tolerant).
//   - file-modification event triggers reload.
//   - rapid sequential writes are debounced (<=2 emits).
//   - parse error retains the previous snapshot + emits ReasonParseError
//     (fail-CLOSED).
//   - dbounce-specific instance transition events fire when a reload
//     causes the instance's denied state to flip (now_denied / now_allowed).

package dynamicdeny

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// validYAMLPayload builds a single-rule YAML payload using the given
// rule id + a DB-shaped target (so the loader filter retains it).
func validYAMLPayload(ruleID, target string) string {
	added := time.Now().UTC().Format(time.RFC3339)
	return strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + ruleID,
		`    targets: ["` + target + `"]`,
		`    reason: "test"`,
		`    duration: "1h"`,
		`    added_by: "u@h"`,
		`    added_at: "` + added + `"`,
		`    applied_to: [dbounce]`,
	}, "\n")
}

type capturedEmit struct {
	reason ReloadReason
	count  int
	err    string
}

type emitRecorder struct {
	mu       sync.Mutex
	captured []capturedEmit
}

func (er *emitRecorder) Emit(reason ReloadReason, rs *RuleSet, err error) {
	er.mu.Lock()
	defer er.mu.Unlock()
	c := capturedEmit{reason: reason}
	if rs != nil {
		c.count = len(rs.Rules)
	}
	if err != nil {
		c.err = err.Error()
	}
	er.captured = append(er.captured, c)
}

func (er *emitRecorder) Snapshot() []capturedEmit {
	er.mu.Lock()
	defer er.mu.Unlock()
	out := make([]capturedEmit, len(er.captured))
	copy(out, er.captured)
	return out
}

// waitForEmit polls the recorder until at least n events of the given
// reason show up OR the timeout elapses.
func waitForEmit(er *emitRecorder, reason ReloadReason, n int, timeout time.Duration) []capturedEmit {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var match []capturedEmit
		for _, c := range er.Snapshot() {
			if reason == "" || c.reason == reason {
				match = append(match, c)
			}
		}
		if len(match) >= n {
			return match
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func TestWatcher_DetectsFileCreation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	er := &emitRecorder{}
	w, err := NewWatcher(p, er.Emit)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	w.SetDebouncePeriod(20 * time.Millisecond)
	var stderr bytes.Buffer
	w.SetStderr(&stderr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()
	if got := len(w.Snapshot().Rules); got != 0 {
		t.Errorf("initial snapshot should be empty; got %d", got)
	}
	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID, "payments-db.example.com")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	matches := waitForEmit(er, "", 1, 2*time.Second)
	if len(matches) == 0 {
		t.Fatalf("no emit captured after file creation; stderr=%q", stderr.String())
	}
	got := matches[len(matches)-1].reason
	if got != ReasonFileCreated && got != ReasonFileModified {
		t.Errorf("emit reason = %q; want file_created or file_modified", got)
	}
	snap := w.Snapshot()
	if len(snap.Rules) != 1 {
		t.Errorf("post-create snapshot = %d rule(s); want 1", len(snap.Rules))
	}
}

func TestWatcher_DetectsFileModification(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID, "payments-db.example.com")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	er := &emitRecorder{}
	w, err := NewWatcher(p, er.Emit)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	w.SetDebouncePeriod(20 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()
	if got := len(w.Snapshot().Rules); got != 1 {
		t.Fatalf("initial snapshot should have 1 rule; got %d", got)
	}
	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID2, "other-db.example.com")), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	matches := waitForEmit(er, "", 1, 2*time.Second)
	if len(matches) == 0 {
		t.Fatal("no emit captured after modify")
	}
	snap := w.Snapshot()
	if len(snap.Rules) != 1 || snap.Rules[0].ID != validRuleID2 {
		t.Errorf("post-modify snapshot = %v; want one rule with id %q", snap.Rules, validRuleID2)
	}
}

func TestWatcher_Debounces100ms(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID, "payments-db.example.com")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	er := &emitRecorder{}
	w, err := NewWatcher(p, er.Emit)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	// Long debounce so all the rapid writes coalesce.
	w.SetDebouncePeriod(150 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()

	for i := 0; i < 5; i++ {
		body := validYAMLPayload(validRuleID2, "other-db.example.com")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		time.Sleep(15 * time.Millisecond)
	}
	// Wait for debounce settle.
	time.Sleep(250 * time.Millisecond)

	snap := er.Snapshot()
	if len(snap) == 0 {
		t.Fatal("no emit captured")
	}
	if len(snap) > 2 {
		t.Errorf("rapid 5-write storm produced %d emits; want <=2 (debounce working)", len(snap))
	}
}

func TestWatcher_RetainsRulesOnParseError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID, "payments-db.example.com")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	er := &emitRecorder{}
	w, err := NewWatcher(p, er.Emit)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	w.SetDebouncePeriod(20 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()
	if got := len(w.Snapshot().Rules); got != 1 {
		t.Fatalf("initial snapshot should have 1 rule; got %d", got)
	}
	if err := os.WriteFile(p, []byte("schema_version: \"1.0\"\ndenies: not-a-list\n"), 0o600); err != nil {
		t.Fatalf("rewrite garbage: %v", err)
	}
	matches := waitForEmit(er, ReasonParseError, 1, 2*time.Second)
	if len(matches) == 0 {
		t.Fatal("no parse_error emit captured")
	}
	snap := w.Snapshot()
	if len(snap.Rules) != 1 || snap.Rules[0].ID != validRuleID {
		t.Errorf("post-parse-error snapshot = %v; want previous rule retained", snap.Rules)
	}
	if w.TotalParseErrors() == 0 {
		t.Error("TotalParseErrors should be incremented")
	}
}

func TestWatcher_FiresInstanceDeniedEventOnReload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	er := &emitRecorder{}
	w, err := NewWatcher(p, er.Emit)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	w.SetDebouncePeriod(20 * time.Millisecond)
	w.SetInstanceUpstream("payments-db.example.com", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()
	if w.InstanceDenied() {
		t.Fatal("instance should not be denied at startup with empty file")
	}
	// Write a rule whose target matches the upstream.
	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID, "payments-db.example.com")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	matches := waitForEmit(er, ReasonInstanceNowDenied, 1, 2*time.Second)
	if len(matches) == 0 {
		t.Fatalf("no instance_now_denied emit captured; got %+v", er.Snapshot())
	}
	if !w.InstanceDenied() {
		t.Error("InstanceDenied() = false; want true")
	}
	id, reason := w.DenyingRule()
	if id != validRuleID || reason != "test" {
		t.Errorf("DenyingRule = (%q, %q); want (%q, %q)", id, reason, validRuleID, "test")
	}
}

func TestWatcher_FiresInstanceAllowedEventOnRuleRemoval(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	// Start with a matching rule already in place.
	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID, "payments-db.example.com")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	er := &emitRecorder{}
	w, err := NewWatcher(p, er.Emit)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	w.SetDebouncePeriod(20 * time.Millisecond)
	w.SetInstanceUpstream("payments-db.example.com", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()
	if !w.InstanceDenied() {
		t.Fatal("instance should already be denied at startup (matching rule present)")
	}
	// Overwrite with an empty denies list.
	empty := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies: []`,
	}, "\n")
	if err := os.WriteFile(p, []byte(empty), 0o600); err != nil {
		t.Fatalf("rewrite empty: %v", err)
	}
	matches := waitForEmit(er, ReasonInstanceNowAllowed, 1, 2*time.Second)
	if len(matches) == 0 {
		t.Fatalf("no instance_now_allowed emit captured; got %+v", er.Snapshot())
	}
	if w.InstanceDenied() {
		t.Error("InstanceDenied() = true; want false after rule removal")
	}
}

func TestWatcher_ReloadNow(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	if err := os.WriteFile(p, []byte(validYAMLPayload(validRuleID, "payments-db.example.com")), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var calls atomic.Int64
	emit := func(reason ReloadReason, rs *RuleSet, err error) {
		calls.Add(1)
	}
	w, err := NewWatcher(p, emit)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer w.Stop()
	rs, err := w.ReloadNow(ReasonReloadRequested)
	if err != nil {
		t.Fatalf("ReloadNow: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Errorf("rules after manual reload = %d; want 1", len(rs.Rules))
	}
	if calls.Load() == 0 {
		t.Error("emit callback should have fired on manual reload")
	}
}

func TestWatcher_NoPathStartIsNoOp(t *testing.T) {
	w, err := NewWatcher("", nil)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	if err := w.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	w.Stop()
	if got := len(w.Snapshot().Rules); got != 0 {
		t.Errorf("empty-path snapshot = %d; want 0", got)
	}
}

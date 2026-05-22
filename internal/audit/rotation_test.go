// Tests for #311 / §A10 — audit-log rotation, retention, recovery.
// Cross-product parity with iam-roles/tests/bouncer/test_audit_export_rotation.py.

package audit

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withTimeout returns a context that auto-cancels after d. Used to
// bound Shutdown calls in the rotation integration tests.
func withTimeout(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), d)
}

func TestRotation_ShouldRotateBySize(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), 2*1024*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ShouldRotateBySize(p, 1) {
		t.Fatal("expected rotation trigger at 2MB > 1MB")
	}
	if ShouldRotateBySize(p, 0) {
		t.Fatal("maxMB=0 must disable")
	}
}

func TestRotation_ShouldRotateByAge(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	_ = os.WriteFile(p, []byte("{}\n"), 0o600)
	old := time.Now().Add(-10 * 24 * time.Hour)
	_ = os.Chtimes(p, old, old)
	if !ShouldRotateByAge(p, 7, time.Now()) {
		t.Fatal("expected rotation at 10d > 7d")
	}
}

func TestRotation_MovesAndGzips(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	original := []byte(`{"id":1}` + "\n" + `{"id":2}` + "\n")
	_ = os.WriteFile(p, original, 0o600)
	archive, err := Rotate(p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if archive == "" {
		t.Fatal("expected archive")
	}
	if !strings.HasSuffix(archive, ".jsonl.gz") {
		t.Fatalf("expected .jsonl.gz: %s", archive)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("active file should be gone")
	}
	f, _ := os.Open(archive)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(gz)
	if !bytes.Equal(body, original) {
		t.Fatalf("content mismatch: %q", body)
	}
}

func TestRotation_NoopOnMissing(t *testing.T) {
	a, err := Rotate(filepath.Join(t.TempDir(), "missing.jsonl"), time.Now())
	if err != nil || a != "" {
		t.Fatalf("unexpected: arc=%s err=%v", a, err)
	}
}

func TestRotation_RecoverPartialTail_Clean(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	_ = os.WriteFile(p, []byte(`{"id":1}`+"\n"+`{"id":2}`+"\n"), 0o600)
	n, err := RecoverPartialTail(p)
	if err != nil || n != 0 {
		t.Fatalf("clean file expected 0 trimmed; got n=%d err=%v", n, err)
	}
}

func TestRotation_RecoverPartialTail_TruncatesCorrupt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	_ = os.WriteFile(p, []byte(`{"id":1}`+"\n"+`{"id":2}`+"\n"+`{"id":3`), 0o600)
	n, err := RecoverPartialTail(p)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(`{"id":3`)) {
		t.Fatalf("got %d trimmed", n)
	}
	after, _ := os.ReadFile(p)
	if string(after) != `{"id":1}`+"\n"+`{"id":2}`+"\n" {
		t.Fatalf("unexpected body: %q", after)
	}
}

func TestRotation_PurgeLogsOlderThan(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "audit-2026-01-01-000000.jsonl.gz")
	_ = os.WriteFile(archive, []byte("fake"), 0o600)
	old := time.Now().Add(-30 * 24 * time.Hour)
	_ = os.Chtimes(archive, old, old)
	active := filepath.Join(dir, "audit.jsonl")
	_ = os.WriteFile(active, []byte("{}\n"), 0o600)
	_ = os.Chtimes(active, old, old)
	removed, err := PurgeLogsOlderThan(dir, 7, 30, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != archive {
		t.Fatalf("expected just the archive, got %v", removed)
	}
	if _, err := os.Stat(active); err != nil {
		t.Fatal("active file should never be purged")
	}
}

func TestRotation_DiskClassify(t *testing.T) {
	if s := ClassifyDiskStatusForTest(50, 85, 95, "/tmp"); s.Status != "ok" {
		t.Fatalf("expected ok, got %s", s.Status)
	}
	if s := ClassifyDiskStatusForTest(90, 85, 95, "/tmp"); s.Status != "degraded" {
		t.Fatalf("expected degraded, got %s", s.Status)
	}
	if s := ClassifyDiskStatusForTest(98, 85, 95, "/tmp"); s.Status != "critical" {
		t.Fatalf("expected critical, got %s", s.Status)
	}
}

func TestRotation_VerifyIntegrity(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte(`{"id":1}`+"\n"), 0o600)
	gp := filepath.Join(dir, "audit-2026-01-01-000000.jsonl.gz")
	gf, _ := os.OpenFile(gp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	gz := gzip.NewWriter(gf)
	_, _ = gz.Write([]byte(`{"id":2}` + "\n"))
	gz.Close()
	gf.Close()
	res, err := VerifyIntegrity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.FilesChecked != 2 {
		t.Fatalf("expected ok with 2 files; got %+v", res)
	}
	// Now corrupt the archive.
	_ = os.WriteFile(gp, []byte("not gzip"), 0o600)
	res, _ = VerifyIntegrity(dir)
	if res.OK {
		t.Fatal("expected failure on corrupt gzip")
	}
}

func TestRotation_ArchiveLogs(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte(`{"id":1}`+"\n"), 0o600)
	gp := filepath.Join(dir, "audit-2026-01-01-000000.jsonl.gz")
	gf, _ := os.OpenFile(gp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	gz := gzip.NewWriter(gf)
	_, _ = gz.Write([]byte(`{}` + "\n"))
	gz.Close()
	gf.Close()
	_ = os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("x"), 0o600)
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := ArchiveLogs(dir, out, true); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(out)
	defer f.Close()
	gz2, _ := gzip.NewReader(f)
	defer gz2.Close()
	tr := tar.NewReader(gz2)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
	}
	hasAudit, hasArchive, hasOther := false, false, false
	for _, n := range names {
		if n == "audit.jsonl" {
			hasAudit = true
		}
		if n == "audit-2026-01-01-000000.jsonl.gz" {
			hasArchive = true
		}
		if n == "unrelated.txt" {
			hasOther = true
		}
	}
	if !hasAudit || !hasArchive || hasOther {
		t.Fatalf("unexpected bundle contents: %v", names)
	}
}

func TestRotation_ParseLogDuration(t *testing.T) {
	for _, c := range []struct {
		in   string
		want time.Duration
	}{
		{"7d", 7 * 24 * time.Hour},
		{"24h", 24 * time.Hour},
		{"30m", 30 * time.Minute},
		{"3", 3 * 24 * time.Hour},
	} {
		got, err := ParseLogDuration(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("%s: got %s want %s", c.in, got, c.want)
		}
	}
}

func TestRotation_LogWriterRotatesOnSizeOverflow(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	rotated := make(chan string, 4)
	w, err := NewLogWriter(LogOptions{
		Path:       p,
		QueueSize:  2000,
		MaxSizeMB:  1,
		OnRotation: func(arc string) { rotated <- arc },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := withTimeout(t, 2*time.Second)
		defer cancel()
		_ = w.Shutdown(ctx)
	}()
	big := strings.Repeat("y", 4096)
	for i := 0; i < 400; i++ {
		_ = w.Write(nil, Event{Time: time.Now().Unix(), StatusDetail: big})
		if i%50 == 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	deadline := time.After(5 * time.Second)
	for w.Stats().Rotations == 0 {
		select {
		case <-deadline:
			t.Fatalf("rotation did not fire; %+v", w.Stats())
		case <-time.After(20 * time.Millisecond):
		}
	}
	select {
	case arc := <-rotated:
		if !strings.HasSuffix(arc, ".jsonl.gz") {
			t.Fatalf("got %s", arc)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("rotation callback did not fire")
	}
}

func TestRotation_LogWriterRecoversPartialTailOnStart(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	_ = os.WriteFile(p, []byte(`{"id":1}`+"\n"+`{"partial`), 0o600)
	recovered := make(chan int64, 1)
	w, err := NewLogWriter(LogOptions{
		Path:       p,
		QueueSize:  10,
		OnRecovery: func(n int64) { recovered <- n },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := withTimeout(t, 2*time.Second)
		defer cancel()
		_ = w.Shutdown(ctx)
	}()
	select {
	case n := <-recovered:
		if n != int64(len(`{"partial`)) {
			t.Fatalf("expected %d, got %d", len(`{"partial`), n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recovery callback did not fire")
	}
	if w.Stats().PartialBytesRecovered == 0 {
		t.Fatal("Stats().PartialBytesRecovered must be non-zero post-recovery")
	}
}

func TestRotation_RecoverThenAppend(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	_ = os.WriteFile(p, []byte(`{"id":1}`+"\n"+`{"partial`), 0o600)
	if _, err := RecoverPartialTail(p); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.Write([]byte(`{"id":2}` + "\n"))
	f.Close()
	body, _ := os.ReadFile(p)
	for _, line := range bytes.Split(bytes.TrimSpace(body), []byte("\n")) {
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("invalid JSON after recovery: %q", line)
		}
	}
}

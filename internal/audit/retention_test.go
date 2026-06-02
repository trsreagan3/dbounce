package audit

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetention_FrameworkDefaultsMatchPython(t *testing.T) {
	cases := []struct {
		fw                     string
		hot, warm, cold, purge int
		gdpr                   bool
	}{
		{FrameworkPCI, 30, 120, 365, -1, false},
		{FrameworkHIPAA, 30, 210, 2190, 2190, false},
		{FrameworkSOX, 30, 395, 2555, -1, false},
		{FrameworkGDPR, 30, 120, 365, -1, true},
		{FrameworkCustom, 30, 120, 365, -1, false},
	}
	for _, c := range cases {
		p, err := PolicyForFramework(c.fw, nil, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.fw, err)
		}
		if p.HotDays != c.hot || p.WarmDays != c.warm || p.ColdDays != c.cold || p.PurgeAfterDays != c.purge || p.GDPRPIIPurge != c.gdpr {
			t.Fatalf("%s defaults = %+v, want hot=%d warm=%d cold=%d purge=%d gdpr=%v",
				c.fw, p, c.hot, c.warm, c.cold, c.purge, c.gdpr)
		}
	}
}

func TestRetention_UnknownFrameworkErrors(t *testing.T) {
	if _, err := PolicyForFramework("soc2", nil, nil, nil, nil, nil); err == nil {
		t.Fatal("expected error for unknown framework")
	}
}

func TestRetention_InvalidPurgeOrderingErrors(t *testing.T) {
	bad := 10
	cold := 365
	if _, err := PolicyForFramework(FrameworkCustom, nil, nil, &cold, &bad, nil); err == nil {
		t.Fatal("expected error: purge_after < cold")
	}
}

func mkArchive(t *testing.T, dir, name string, ageDays float64) string {
	t.Helper()
	path := filepath.Join(dir, name)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte(`{"unmapped":{"iam_jit":{"i":0}}}` + "\n"))
	_ = gw.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(-time.Duration(ageDays*86400) * time.Second)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRetention_HotToWarmTransition(t *testing.T) {
	dir := t.TempDir()
	// PCI: hot<=30, warm 30-120. A 60-day-old hot archive → warm.
	mkArchive(t, dir, "audit-2026.jsonl.gz", 60)
	p, _ := PolicyForFramework(FrameworkPCI, nil, nil, nil, nil, nil)
	res, err := ApplyRetention(dir, p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Transitions) != 1 || res.Transitions[0].ToTier != TierWarm {
		t.Fatalf("expected 1 hot→warm transition, got %+v", res.Transitions)
	}
	if _, err := os.Stat(filepath.Join(dir, "warm-2026.jsonl.gz")); err != nil {
		t.Fatalf("warm archive not created: %v", err)
	}
}

func TestRetention_HotToColdSinglePass(t *testing.T) {
	dir := t.TempDir()
	// 400 days old, past cold threshold (365) → directly hot→cold.
	mkArchive(t, dir, "audit-2025.jsonl.gz", 400)
	p, _ := PolicyForFramework(FrameworkPCI, nil, nil, nil, nil, nil)
	res, _ := ApplyRetention(dir, p, time.Now())
	if len(res.Transitions) != 1 || res.Transitions[0].ToTier != TierCold {
		t.Fatalf("expected 1 hot→cold transition, got %+v", res.Transitions)
	}
	if len(res.ColdEligible) != 1 {
		t.Fatalf("expected 1 cold-eligible, got %v", res.ColdEligible)
	}
}

func TestRetention_PurgeTwoKeySafety(t *testing.T) {
	dir := t.TempDir()
	// HIPAA purges at 2190. A 3000-day-old archive should be purged.
	old := mkArchive(t, dir, "cold-2018.jsonl.gz", 3000)
	p, _ := PolicyForFramework(FrameworkHIPAA, nil, nil, nil, nil, nil)
	res, _ := ApplyRetention(dir, p, time.Now())
	if len(res.Purged) != 1 {
		t.Fatalf("expected 1 purge, got %v", res.Purged)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("purged file should be gone")
	}
}

func TestRetention_NoPurgeWhenPolicyNone(t *testing.T) {
	dir := t.TempDir()
	// PCI has no purge (purge_after = none); a very old cold file stays.
	mkArchive(t, dir, "cold-2010.jsonl.gz", 9000)
	p, _ := PolicyForFramework(FrameworkPCI, nil, nil, nil, nil, nil)
	res, _ := ApplyRetention(dir, p, time.Now())
	if len(res.Purged) != 0 {
		t.Fatalf("PCI must never purge, got %v", res.Purged)
	}
	if len(res.ColdEligible) != 1 {
		t.Fatalf("expected old cold file to be cold-eligible, got %v", res.ColdEligible)
	}
}

func TestRetention_GDPRPIIScrub(t *testing.T) {
	dir := t.TempDir()
	// GDPR scrubs PII on the hot→warm transition. Write a hot archive
	// (60d old) containing an email + AWS key, then apply.
	path := filepath.Join(dir, "audit-gdpr.jsonl.gz")
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte(`{"unmapped":{"iam_jit":{"note":"contact alice@example.com key AKIAIOSFODNN7EXAMPLE"}}}` + "\n"))
	_ = gw.Close()
	_ = os.WriteFile(path, buf.Bytes(), 0o600)
	mt := time.Now().Add(-60 * 24 * time.Hour)
	_ = os.Chtimes(path, mt, mt)

	p, _ := PolicyForFramework(FrameworkGDPR, nil, nil, nil, nil, nil)
	if _, err := ApplyRetention(dir, p, time.Now()); err != nil {
		t.Fatal(err)
	}
	warm := filepath.Join(dir, "warm-gdpr.jsonl.gz")
	f, err := os.Open(warm)
	if err != nil {
		t.Fatalf("warm archive missing: %v", err)
	}
	defer f.Close()
	gr, _ := gzip.NewReader(f)
	out := new(bytes.Buffer)
	_, _ = out.ReadFrom(gr)
	s := out.String()
	if bytes.Contains([]byte(s), []byte("alice@example.com")) {
		t.Fatalf("email not redacted: %s", s)
	}
	if bytes.Contains([]byte(s), []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatalf("AWS key not redacted: %s", s)
	}
	if !bytes.Contains([]byte(s), []byte("[REDACTED:email]")) {
		t.Fatalf("expected redaction placeholder, got: %s", s)
	}
}

// TestRetention_AWSSecretKeyRedacted pins HIGH-1: the 40-char AWS
// secret-access-key pattern (Python's \b[A-Za-z0-9/+]{40}\b) MUST be
// redacted under a GDPR policy. RE2 has no \b, so the Go port uses a
// boundary-preserving capture-group form; this test proves a real
// 40-char secret IS scrubbed while ordinary prose is NOT over-redacted.
func TestRetention_AWSSecretKeyRedacted(t *testing.T) {
	p, _ := PolicyForFramework(FrameworkGDPR, nil, nil, nil, nil, nil)

	// A canonical AWS secret access key is exactly 40 base64-ish chars.
	const secret40 = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE1" // 40 chars
	if len(secret40) != 40 {
		t.Fatalf("test fixture must be exactly 40 chars; got %d", len(secret40))
	}

	ev := map[string]any{
		"unmapped": map[string]any{"iam_jit": map[string]any{
			"creds": "aws_secret_access_key=" + secret40,
		}},
	}
	RedactEventPII(ev, p)
	got := ev["unmapped"].(map[string]any)["iam_jit"].(map[string]any)["creds"].(string)
	if strings.Contains(got, secret40) {
		t.Fatalf("40-char AWS secret key was NOT redacted: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:aws_secret_access_key]") {
		t.Fatalf("expected [REDACTED:aws_secret_access_key] placeholder; got: %q", got)
	}
	// The '=' boundary char preceding the secret must be preserved (the
	// capture-group replacement only swaps the 40-char run).
	if !strings.Contains(got, "aws_secret_access_key=") {
		t.Fatalf("boundary context was clobbered; got: %q", got)
	}

	// False-positive guard: realistic prose with short words + a long
	// sentence (but no single 40-char [A-Za-z0-9/+] run) must NOT be
	// redacted. Spaces break the run, so this is safe.
	ev2 := map[string]any{
		"unmapped": map[string]any{"iam_jit": map[string]any{
			"note": "The quick brown fox jumps over the lazy sleeping dog today",
		}},
	}
	RedactEventPII(ev2, p)
	note := ev2["unmapped"].(map[string]any)["iam_jit"].(map[string]any)["note"].(string)
	if strings.Contains(note, "[REDACTED") {
		t.Fatalf("ordinary prose was over-redacted: %q", note)
	}
}

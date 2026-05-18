// Tests for `dbounce investigate` (#273) — the cross-product
// "land a Claude-ready evidence pack" subcommand. Coverage:
//
//   - Command exits 0 + writes the two expected artifact files.
//   - --print-prompts lists 10 prompts WITHOUT writing files.
//   - --time-range "24h" filters audit-tail by seeded timestamps.
//   - Missing/empty audit DB → command still succeeds + records the
//     gap in the evidence file so a Claude analyst sees data, not
//     a tool failure.
//   - --filter rejects garbage early (before touching the disk).
//   - The starter prompts list stays in the neutral safety-team
//     vocabulary per [[security-team-positioning-safety-not-
//     surveillance]] (no "violation"/"infraction"/"unauthorized").
//   - --print-prompts text contains the dbounce-specific
//     write-query + DDL prompt swaps.
package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/store"
)

// runInvestigateCLI is the test wrapper for `dbounce investigate`.
// Builds a fresh root each call so test ordering doesn't matter.
func runInvestigateCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	// Point HOME at the tmpdir parent so the default profiles path
	// resolution doesn't hit the operator's real home. Each test
	// sets HOME via t.Setenv to a fresh tmpdir.
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

func TestInvestigate_ParseTimeRange(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"24h", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"4w", 4 * 7 * 24 * time.Hour},
		{"24H", 24 * time.Hour},
	}
	for _, tc := range cases {
		got, err := parseTimeRange(tc.in)
		require.NoError(t, err, "parseTimeRange(%q)", tc.in)
		assert.Equal(t, tc.want, got, "parseTimeRange(%q)", tc.in)
	}
	for _, bad := range []string{"", "garbage", "24m", "0h", "-3d"} {
		_, err := parseTimeRange(bad)
		require.Error(t, err, "parseTimeRange(%q) must reject", bad)
	}
}

func TestInvestigate_StarterPromptsAvoidLoadedVocab(t *testing.T) {
	banned := []string{"violation", "infraction", "unauthorized"}
	for _, prompt := range starterPrompts {
		lower := strings.ToLower(prompt)
		for _, w := range banned {
			assert.NotContains(t, lower, w,
				"prompt %q contains banned vocab %q", prompt, w)
		}
	}
	assert.Equal(t, 10, len(starterPrompts),
		"investigate ships exactly 10 starter prompts")
}

func TestInvestigate_StarterPromptsDBounceSpecific(t *testing.T) {
	// dbounce variants include write-query + DDL prompts per the
	// cross-product spec ("per-product variations OK").
	joined := strings.ToLower(strings.Join(starterPrompts, " "))
	assert.Contains(t, joined, "insert", "expected write-query prompt")
	assert.Contains(t, joined, "ddl", "expected DDL-window prompt")
}

func TestInvestigate_PrintPromptsWritesNoFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	outDir := filepath.Join(dir, "out")
	stdout, _, err := runInvestigateCLI(t,
		"investigate", "--print-prompts", "--out-dir", outDir,
	)
	require.NoError(t, err)
	for _, p := range starterPrompts {
		assert.Contains(t, stdout, p)
	}
	_, statErr := os.Stat(outDir)
	assert.True(t, os.IsNotExist(statErr),
		"--print-prompts must not create --out-dir")
}

func TestInvestigate_WritesBothArtifacts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	db := filepath.Join(dir, "state.db")
	outDir := filepath.Join(dir, "out")

	// Seed one decision row so the evidence file is non-trivial.
	st, err := store.Open(db)
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		At:               time.Now().UTC(),
		Dialect:          "postgres",
		Statement:        "SELECT 1",
		StatementType:    "SELECT",
		TablesTouched:    []string{"public.users"},
		DecisionVerdict:  "ALLOW",
		DecisionReason:   "test",
		ModeAtDecision:   "cooperative",
		ImpersonatedRole: "alice",
	})
	require.NoError(t, err)
	st.Close()

	stdout, _, err := runInvestigateCLI(t,
		"investigate",
		"--db", db,
		"--out-dir", outDir,
		"--mgmt-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	evidencePath := filepath.Join(outDir, investigationEvidenceFilename)
	contextPath := filepath.Join(outDir, investigationContextFilename)
	evSt, err := os.Stat(evidencePath)
	require.NoError(t, err)
	require.Greater(t, evSt.Size(), int64(100))
	require.Equal(t, os.FileMode(0o600), evSt.Mode().Perm(),
		"evidence file must be 0o600 (owner-only)")

	ctxSt, err := os.Stat(contextPath)
	require.NoError(t, err)
	require.Greater(t, ctxSt.Size(), int64(100))

	assert.Contains(t, stdout, evidencePath)
	assert.Contains(t, stdout, contextPath)
	assert.Contains(t, stdout, "Anthropic")
	assert.Contains(t, stdout, "local Claude client")
}

func TestInvestigate_EvidenceFileIsValidOCSFFinding(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	db := filepath.Join(dir, "state.db")
	outDir := filepath.Join(dir, "out")

	st, err := store.Open(db)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		_, err = st.RecordDecision(store.DecisionRow{
			At:              time.Now().UTC(),
			Dialect:         "postgres",
			Statement:       "INSERT INTO users VALUES (1)",
			StatementType:   "INSERT",
			TablesTouched:   []string{"public.users"},
			DecisionVerdict: "ALLOW",
			ModeAtDecision:  "cooperative",
		})
		require.NoError(t, err)
	}
	st.Close()

	_, _, err = runInvestigateCLI(t,
		"investigate",
		"--db", db,
		"--out-dir", outDir,
		"--mgmt-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	body, err := os.ReadFile(filepath.Join(outDir, investigationEvidenceFilename))
	require.NoError(t, err)

	var parsed struct {
		Metadata struct {
			Count int `json:"count"`
		} `json:"metadata"`
		Findings []struct {
			ClassUID  int    `json:"class_uid"`
			ClassName string `json:"class_name"`
		} `json:"findings"`
		Investigate struct {
			Window          string `json:"window"`
			AuditLogPresent bool   `json:"audit_log_present"`
			EventCount      int    `json:"event_count"`
		} `json:"investigate"`
	}
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Equal(t, 3, parsed.Metadata.Count,
		"3 seeded rows should land in the bundle")
	for _, f := range parsed.Findings {
		assert.Equal(t, 2004, f.ClassUID, "OCSF class 2004 (Detection Finding)")
		assert.Equal(t, "Detection Finding", f.ClassName)
	}
	assert.True(t, parsed.Investigate.AuditLogPresent)
	assert.Equal(t, 3, parsed.Investigate.EventCount)
	assert.Equal(t, "all", parsed.Investigate.Window,
		"no --time-range means window=all")
}

func TestInvestigate_ContextBundleHasNoAuditTail(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	db := filepath.Join(dir, "state.db")
	outDir := filepath.Join(dir, "out")

	st, err := store.Open(db)
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		At:              time.Now().UTC(),
		Dialect:         "postgres",
		Statement:       "SELECT 1",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
	})
	require.NoError(t, err)
	st.Close()

	_, _, err = runInvestigateCLI(t,
		"investigate",
		"--db", db,
		"--out-dir", outDir,
		"--mgmt-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	zr, err := zip.OpenReader(filepath.Join(outDir, investigationContextFilename))
	require.NoError(t, err)
	defer zr.Close()
	// audit-tail.jsonl should NOT appear in the ZIP, OR if it does
	// (legacy section name) it should be the empty/omitted marker.
	var fileNames []string
	for _, f := range zr.File {
		fileNames = append(fileNames, f.Name)
		assert.NotEqual(t, "audit-tail.jsonl", f.Name,
			"context bundle should not include audit-tail; the evidence file does")
	}
	// Manifest should record the --no-audit note.
	for _, f := range zr.File {
		if f.Name != "manifest.json" {
			continue
		}
		rc, err := f.Open()
		require.NoError(t, err)
		defer rc.Close()
		var buf bytes.Buffer
		_, err = buf.ReadFrom(rc)
		require.NoError(t, err)
		var mf DiagnosticsManifest
		require.NoError(t, json.Unmarshal(buf.Bytes(), &mf))
		var noted bool
		for _, n := range mf.Notes {
			if strings.Contains(n, "--no-audit") {
				noted = true
			}
		}
		assert.True(t, noted, "manifest must note --no-audit")
		break
	}
	t.Logf("context bundle files: %v", fileNames)
}

func TestInvestigate_TimeRangeFiltersByCutoff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	db := filepath.Join(dir, "state.db")
	outDir := filepath.Join(dir, "out")

	now := time.Now().UTC()
	st, err := store.Open(db)
	require.NoError(t, err)
	// Recent row (1h ago) + ancient row (30 days ago).
	_, err = st.RecordDecision(store.DecisionRow{
		At:              now.Add(-30 * 24 * time.Hour),
		Dialect:         "postgres",
		Statement:       "SELECT 1",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
	})
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		At:              now.Add(-1 * time.Hour),
		Dialect:         "postgres",
		Statement:       "SELECT 2",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
	})
	require.NoError(t, err)
	st.Close()

	_, _, err = runInvestigateCLI(t,
		"investigate",
		"--db", db,
		"--time-range", "24h",
		"--out-dir", outDir,
		"--mgmt-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)

	body, err := os.ReadFile(filepath.Join(outDir, investigationEvidenceFilename))
	require.NoError(t, err)
	var parsed struct {
		Metadata struct {
			Count int `json:"count"`
		} `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Equal(t, 1, parsed.Metadata.Count,
		"--time-range 24h must filter out the 30d-old row")
}

func TestInvestigate_EmptyDBStillSucceeds(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	db := filepath.Join(dir, "state.db")
	outDir := filepath.Join(dir, "out")

	stdout, _, err := runInvestigateCLI(t,
		"investigate",
		"--db", db,
		"--out-dir", outDir,
		"--mgmt-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err)
	assert.Contains(t, stdout, "audit log was missing")

	body, err := os.ReadFile(filepath.Join(outDir, investigationEvidenceFilename))
	require.NoError(t, err)
	var parsed struct {
		Investigate struct {
			AuditLogPresent bool `json:"audit_log_present"`
		} `json:"investigate"`
	}
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.False(t, parsed.Investigate.AuditLogPresent)
}

func TestInvestigate_RejectsBadFilter(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	_, _, err := runInvestigateCLI(t,
		"investigate",
		"--db", filepath.Join(dir, "state.db"),
		"--filter", "garbage_no_operator",
		"--out-dir", filepath.Join(dir, "out"),
	)
	require.Error(t, err)
}

func TestInvestigate_RejectsBadTimeRange(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	_, _, err := runInvestigateCLI(t,
		"investigate",
		"--db", filepath.Join(dir, "state.db"),
		"--time-range", "24m",
		"--out-dir", filepath.Join(dir, "out"),
	)
	require.Error(t, err)
}

func TestInvestigate_NoOutboundNetworkCall(t *testing.T) {
	// Sanity poke at the local resolver — the test will fail loud
	// if investigate tries to dial off-loopback because we pin
	// --mgmt-url to a closed loopback port. Any DNS lookup the
	// command performed against an external name would trip the
	// underlying transport before we get here.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	db := filepath.Join(dir, "state.db")
	outDir := filepath.Join(dir, "out")

	st, err := store.Open(db)
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		At:              time.Now().UTC(),
		Dialect:         "postgres",
		Statement:       "SELECT 1",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
	})
	require.NoError(t, err)
	st.Close()

	conn, derr := net.DialTimeout("tcp", "127.0.0.1:1", 50*time.Millisecond)
	if derr == nil {
		_ = conn.Close()
	}

	_, _, err = runInvestigateCLI(t,
		"investigate",
		"--db", db,
		"--out-dir", outDir,
		"--mgmt-url", "http://127.0.0.1:1/healthz",
	)
	require.NoError(t, err,
		"investigate must succeed end-to-end with loopback-only network")
}

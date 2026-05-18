// Tests for `dbounce session list / show / export / purge` (#285).
//
// The subcommand surface is read-only over per-session NDJSON files
// written by the proxy. These tests seed a temp recordings dir via the
// audit.SessionRecorder helpers (the same path the proxy uses) and
// exercise each subcommand end-to-end.
//
// Cross-product parity: same test names + same flag shape as the
// kbouncer + ibounce session test files per
// [[cross-product-agent-parity]] so regressions in any one product
// surface against the same checklist.

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/audit"
)

const (
	sessionIDA = "01956c44-c5c1-7c31-9bca-7c0aaa000001"
	sessionIDB = "01956c44-c5c1-7c31-9bca-7c0aaa000099"
)

// seedSessionsDir writes two completed recordings into a fresh temp
// dir and returns its path. Each session carries a single select-shape
// event so the test can assert on event_count.
func seedSessionsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	r, err := audit.NewSessionRecorder(audit.SessionRecorderOptions{
		Dir:            dir,
		BouncerProduct: "dbounce",
	})
	require.NoError(t, err)
	require.NoError(t, r.Start())
	r.Record(audit.Event{
		Time:         time.Now().UnixMilli(),
		ClassUID:     6003,
		ClassName:    "API Activity",
		ActivityID:   1,
		ActivityName: "select",
		Unmapped: &audit.Unmapped{
			IAMJIT: audit.IAMJITExt{
				Verdict: "allow",
				Profile: "safe-default",
				Agent: &audit.Agent{
					Name:         "claude-code",
					SessionID:    sessionIDA,
					DetectedFrom: "mcp_clientinfo",
				},
			},
		},
	})
	r.Record(audit.Event{
		Time:         time.Now().UnixMilli(),
		ClassUID:     6003,
		ClassName:    "API Activity",
		ActivityID:   1,
		ActivityName: "select",
		Unmapped: &audit.Unmapped{
			IAMJIT: audit.IAMJITExt{
				Verdict: "allow",
				Profile: "safe-default",
				Agent: &audit.Agent{
					Name:         "cursor",
					SessionID:    sessionIDB,
					DetectedFrom: "mcp_clientinfo",
				},
			},
		},
	})
	r.Stop()
	return dir
}

func TestSessionList_ShowsSeededSessions(t *testing.T) {
	dir := seedSessionsDir(t)
	cmd := newSessionCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"list", "--dir", dir})
	require.NoError(t, cmd.Execute())
	out := buf.String()
	assert.Contains(t, out, sessionIDA)
	assert.Contains(t, out, sessionIDB)
	assert.Contains(t, out, "claude-code")
	assert.Contains(t, out, "cursor")
	assert.Contains(t, out, "EVENTS")
}

func TestSessionList_EmptyDir_ShowsNothing(t *testing.T) {
	dir := t.TempDir()
	cmd := newSessionCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"list", "--dir", dir})
	require.NoError(t, cmd.Execute())
	out := buf.String()
	assert.Contains(t, out, "no recordings in")
	assert.NotContains(t, out, sessionIDA)
}

func TestSessionShow_BadID_CleanError(t *testing.T) {
	dir := t.TempDir()
	cmd := newSessionCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"show", "../../etc/passwd", "--dir", dir})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session_id")
}

func TestSessionShow_PrintsSummary(t *testing.T) {
	dir := seedSessionsDir(t)
	cmd := newSessionCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"show", sessionIDA, "--dir", dir})
	require.NoError(t, cmd.Execute())
	out := buf.String()
	assert.Contains(t, out, sessionIDA)
	assert.Contains(t, out, "claude-code")
	assert.Contains(t, out, "dbounce")
	assert.Contains(t, out, "select")
}

func TestSessionExport_ProducesOCSFDetectionFinding(t *testing.T) {
	dir := seedSessionsDir(t)
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "finding.json")
	cmd := newSessionCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"export", sessionIDA, "--dir", dir, "--out", outPath})
	require.NoError(t, cmd.Execute())

	// File exists + mode 0o600.
	info, err := os.Stat(outPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"OCSF export file must be 0o600 (owner-read-only)")

	// File parses as JSON + carries the session id.
	raw, err := os.ReadFile(outPath)
	require.NoError(t, err)
	var finding map[string]any
	require.NoError(t, json.Unmarshal(raw, &finding))
	encoded, _ := json.Marshal(finding)
	assert.Contains(t, string(encoded), sessionIDA)
}

func TestSessionExport_RequiresOut(t *testing.T) {
	dir := seedSessionsDir(t)
	cmd := newSessionCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"export", sessionIDA, "--dir", dir})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--out is required")
}

func TestSessionPurge_OlderThanRemovesOnlyOld(t *testing.T) {
	dir := seedSessionsDir(t)

	// Backdate session A's mtime well past the threshold; leave B fresh.
	oldPath := filepath.Join(dir, sessionIDA+".ndjson")
	freshPath := filepath.Join(dir, sessionIDB+".ndjson")
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(oldPath, old, old))

	cmd := newSessionCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"purge", "--dir", dir, "--older-than", "1h"})
	require.NoError(t, cmd.Execute())
	out := buf.String()
	assert.Contains(t, out, "removed 1 recording")

	_, err := os.Stat(oldPath)
	assert.True(t, os.IsNotExist(err), "old recording must be gone")
	_, err = os.Stat(freshPath)
	assert.NoError(t, err, "fresh recording must survive")
}

func TestSessionPurge_DryRunListsWithoutDeleting(t *testing.T) {
	dir := seedSessionsDir(t)
	oldPath := filepath.Join(dir, sessionIDA+".ndjson")
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(oldPath, old, old))

	cmd := newSessionCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"purge", "--dir", dir, "--older-than", "1h", "--dry-run"})
	require.NoError(t, cmd.Execute())
	out := buf.String()
	assert.Contains(t, out, "would remove 1 recording")
	assert.Contains(t, out, sessionIDA)

	_, err := os.Stat(oldPath)
	assert.NoError(t, err, "--dry-run must not delete anything")
}

func TestSessionPurge_RequiresOlderThan(t *testing.T) {
	dir := t.TempDir()
	cmd := newSessionCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"purge", "--dir", dir})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--older-than is required")
}

func TestParseRetention_AcceptsSMHD(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"30s", 30 * time.Second},
		{"15m", 15 * time.Minute},
		{"2h", 2 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
	}
	for _, c := range cases {
		got, err := parseRetention(c.in)
		require.NoError(t, err, c.in)
		assert.Equal(t, c.want, got, c.in)
	}
}

func TestParseRetention_RejectsBadInput(t *testing.T) {
	bad := []string{"", "30", "abc", "0d", "-1h", "30x"}
	for _, b := range bad {
		_, err := parseRetention(b)
		assert.Error(t, err, b)
	}
}

func TestSessionRecordingsFileMode_IsOwnerOnly(t *testing.T) {
	dir := seedSessionsDir(t)
	// Every .ndjson file emitted by the recorder must be 0o600.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	count := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".ndjson") {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
			"recording file %s must be 0o600", e.Name())
		count++
	}
	assert.GreaterOrEqual(t, count, 2, "seedSessionsDir should produce two recordings")
}

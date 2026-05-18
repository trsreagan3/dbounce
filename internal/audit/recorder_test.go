// Tests for the per-session recorder (#285). Mirrors the iam-roles
// Python + kbouncer Go tests so cross-product regressions surface in CI.

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testSIDA = "01956c44-c5c1-7c31-9bca-7c0aaa000001"
	testSIDB = "01956c44-c5c1-7c31-9bca-7c0aaa000099"
)

func makeTestEvent(sid, op, agent string) Event {
	return Event{
		Time:         time.Now().UnixMilli(),
		ClassUID:     6003,
		ClassName:    "API Activity",
		ActivityID:   1,
		ActivityName: op,
		Unmapped: &Unmapped{
			IAMJIT: IAMJITExt{
				Verdict: "allow",
				Profile: "safe-default",
				Agent: &Agent{
					Name:         agent,
					SessionID:    sid,
					DetectedFrom: "mcp_clientinfo",
				},
			},
		},
	}
}

func TestIsValidSessionID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{testSIDA, true},
		{"../../etc/passwd", false},
		{"a/b", false},
		{"", false},
		{strings.Repeat("a", 129), false},
	}
	for _, c := range cases {
		if got := IsValidSessionID(c.in); got != c.want {
			t.Errorf("IsValidSessionID(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestExtractSessionID(t *testing.T) {
	ev := makeTestEvent(testSIDA, "select", "claude-code")
	if got := ExtractSessionID(ev); got != testSIDA {
		t.Errorf("ExtractSessionID = %q want %q", got, testSIDA)
	}
	ev.Unmapped.IAMJIT.Agent = nil
	if got := ExtractSessionID(ev); got != "" {
		t.Errorf("ExtractSessionID with no agent = %q want empty", got)
	}
}

func TestRecorderMultipleSessions(t *testing.T) {
	dir := t.TempDir()
	r, err := NewSessionRecorder(SessionRecorderOptions{Dir: dir, BouncerProduct: "dbounce"})
	if err != nil {
		t.Fatalf("NewSessionRecorder: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	r.Record(makeTestEvent(testSIDA, "select", "claude-code"))
	r.Record(makeTestEvent(testSIDB, "select", "cursor"))
	r.Stop()
	for _, sid := range []string{testSIDA, testSIDB} {
		if _, err := os.Stat(filepath.Join(dir, sid+".ndjson")); err != nil {
			t.Errorf("expected %s.ndjson: %v", sid, err)
		}
	}
}

func TestRecorderMetaHeader(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{Dir: dir, BouncerProduct: "dbounce"})
	_ = r.Start()
	r.Record(makeTestEvent(testSIDA, "select", "claude-code"))
	r.Stop()
	data, _ := os.ReadFile(filepath.Join(dir, testSIDA+".ndjson"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var h recordingMetaWrapper
	if err := json.Unmarshal([]byte(lines[0]), &h); err != nil {
		t.Fatalf("header unmarshal: %v", err)
	}
	if h.Meta.BouncerProduct != "dbounce" {
		t.Errorf("bouncer_product = %q want dbounce", h.Meta.BouncerProduct)
	}
	if h.Meta.RecordingSchemaVersion != RecordingSchemaVersion {
		t.Errorf("schema_version = %q", h.Meta.RecordingSchemaVersion)
	}
}

func TestRecorderFileMode(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{Dir: dir, BouncerProduct: "dbounce"})
	_ = r.Start()
	r.Record(makeTestEvent(testSIDA, "select", "claude-code"))
	r.Stop()
	info, _ := os.Stat(filepath.Join(dir, testSIDA+".ndjson"))
	if got := info.Mode().Perm(); got != RecordingFileMode {
		t.Errorf("file mode = %o want %o", got, RecordingFileMode)
	}
}

func TestRecorderDropsEventWithoutSessionID(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{Dir: dir, BouncerProduct: "dbounce"})
	_ = r.Start()
	ev := makeTestEvent(testSIDA, "select", "claude-code")
	ev.Unmapped.IAMJIT.Agent = nil
	r.Record(ev)
	r.Stop()
	if r.Status().DroppedEvents != 1 {
		t.Errorf("dropped = %d want 1", r.Status().DroppedEvents)
	}
}

func TestRecorderNoCrossSessionLeakage(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{Dir: dir, BouncerProduct: "dbounce"})
	_ = r.Start()
	evA := makeTestEvent(testSIDA, "select", "claude-code")
	evA.StatusDetail = "sentinel-AAA-only-in-A"
	r.Record(evA)
	evB := makeTestEvent(testSIDB, "select", "cursor")
	evB.StatusDetail = "sentinel-BBB-only-in-B"
	r.Record(evB)
	r.Stop()
	a, _ := os.ReadFile(filepath.Join(dir, testSIDA+".ndjson"))
	b, _ := os.ReadFile(filepath.Join(dir, testSIDB+".ndjson"))
	if !strings.Contains(string(a), "sentinel-AAA-only-in-A") ||
		strings.Contains(string(a), "sentinel-BBB-only-in-B") {
		t.Error("session A leakage")
	}
	if !strings.Contains(string(b), "sentinel-BBB-only-in-B") ||
		strings.Contains(string(b), "sentinel-AAA-only-in-A") {
		t.Error("session B leakage")
	}
}

func TestRecorderSentinelGrep(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{Dir: dir, BouncerProduct: "dbounce"})
	_ = r.Start()
	ev := makeTestEvent(testSIDA, "select", "claude-code")
	ev.Resources = []Resource{{UID: "table:sentinel-XYZ"}}
	r.Record(ev)
	r.Stop()
	data, _ := os.ReadFile(filepath.Join(dir, testSIDA+".ndjson"))
	if !strings.Contains(string(data), "sentinel-XYZ") {
		t.Error("sentinel-XYZ should appear in recording")
	}
}

func TestRecorderPartialBeforeStop(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{Dir: dir, BouncerProduct: "dbounce"})
	_ = r.Start()
	r.Record(makeTestEvent(testSIDA, "select", "claude-code"))
	if _, err := os.Stat(filepath.Join(dir, testSIDA+".ndjson.partial")); err != nil {
		t.Errorf("expected .partial: %v", err)
	}
	r.Stop()
	if _, err := os.Stat(filepath.Join(dir, testSIDA+".ndjson.partial")); !os.IsNotExist(err) {
		t.Errorf(".partial should be renamed; err=%v", err)
	}
}

func TestRecorderFinaliseIdle(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{
		Dir: dir, BouncerProduct: "dbounce", HeartbeatTimeout: time.Minute,
	})
	_ = r.Start()
	r.Record(makeTestEvent(testSIDA, "select", "claude-code"))
	stale := r.FinaliseIdle(time.Now().Add(2 * time.Minute))
	if len(stale) != 1 {
		t.Errorf("FinaliseIdle = %v", stale)
	}
	r.Stop()
}

func TestListSessionsEmpty(t *testing.T) {
	rows, err := ListSessions(t.TempDir())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 rows; got %d", len(rows))
	}
}

func TestListSessionsCountsEvents(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{Dir: dir, BouncerProduct: "dbounce"})
	_ = r.Start()
	for i := 0; i < 3; i++ {
		r.Record(makeTestEvent(testSIDA, "select", "claude-code"))
	}
	r.Record(makeTestEvent(testSIDB, "select", "cursor"))
	r.Stop()
	rows, _ := ListSessions(dir)
	counts := map[string]int64{}
	for _, r := range rows {
		counts[r.SessionID] = r.EventCount
	}
	if counts[testSIDA] != 3 || counts[testSIDB] != 1 {
		t.Errorf("counts wrong: %v", counts)
	}
}

func TestReadSessionRoundTrips(t *testing.T) {
	dir := t.TempDir()
	r, _ := NewSessionRecorder(SessionRecorderOptions{Dir: dir, BouncerProduct: "dbounce"})
	_ = r.Start()
	r.Record(makeTestEvent(testSIDA, "select", "claude-code"))
	r.Record(makeTestEvent(testSIDA, "insert", "claude-code"))
	r.Stop()
	meta, events, err := ReadSession(dir, testSIDA)
	if err != nil {
		t.Fatalf("ReadSession: %v", err)
	}
	if meta.SessionID != testSIDA {
		t.Errorf("session_id = %q", meta.SessionID)
	}
	if len(events) != 2 {
		t.Errorf("events = %d want 2", len(events))
	}
}

func TestReadSessionRejectsTraversal(t *testing.T) {
	if _, _, err := ReadSession(t.TempDir(), "../etc/passwd"); err == nil {
		t.Error("expected error on traversal")
	}
}

func TestDetectionFindingFromSession(t *testing.T) {
	events := []Event{
		{Time: 1_700_000_000_000, ActivityName: "select"},
		{Time: 1_700_000_010_000, ActivityName: "insert"},
	}
	meta := RecordingMeta{
		SessionID:      testSIDA,
		AgentName:      "claude-code",
		BouncerProduct: "dbounce",
	}
	f := DetectionFindingFromSession(meta, events)
	if f.ClassUID != 2004 {
		t.Errorf("class_uid = %d", f.ClassUID)
	}
	if f.Unmapped.IAMJIT.Session.SessionID != testSIDA {
		t.Errorf("session_id wrong")
	}
}

func TestPurgeOlderThanRemovesOnlyOld(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, testSIDA+".ndjson")
	new_ := filepath.Join(dir, testSIDB+".ndjson")
	_ = os.WriteFile(old, []byte("{}\n"), 0o600)
	_ = os.WriteFile(new_, []byte("{}\n"), 0o600)
	oldTime := time.Now().Add(-40 * 24 * time.Hour)
	_ = os.Chtimes(old, oldTime, oldTime)
	removed, _ := PurgeOlderThan(dir, 30*24*time.Hour, time.Now())
	if len(removed) != 1 || removed[0] != old {
		t.Errorf("removed = %v", removed)
	}
}

func TestPurgeSkipsPartialFiles(t *testing.T) {
	dir := t.TempDir()
	partial := filepath.Join(dir, testSIDA+".ndjson.partial")
	_ = os.WriteFile(partial, []byte("{}\n"), 0o600)
	old := time.Now().Add(-90 * 24 * time.Hour)
	_ = os.Chtimes(partial, old, old)
	removed, _ := PurgeOlderThan(dir, 30*24*time.Hour, time.Now())
	if len(removed) != 0 {
		t.Errorf("expected .partial to be skipped; got %v", removed)
	}
}

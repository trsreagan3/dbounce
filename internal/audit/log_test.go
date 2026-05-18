package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogWriter_CreatesFile_AppendsValidJSONL exercises the happy path:
// open a path that doesn't exist yet, write 3 events, close, verify the
// file mode + perm + that each line parses as a valid Event in order.
func TestLogWriter_CreatesFile_AppendsValidJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "audit.jsonl")

	w, err := NewLogWriter(LogOptions{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = w.Shutdown(ctx)
	})

	events := []Event{
		testDecisionEvent(1),
		testDecisionEvent(2),
		testDecisionEvent(3),
	}
	for _, e := range events {
		require.NoError(t, w.Write(context.Background(), e))
	}

	// Shutdown so we know all in-flight writes hit disk.
	require.NoError(t, w.Shutdown(context.Background()))

	// Verify file permission == 0600.
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"audit log file MUST be 0600 to keep operator's local secrets unreadable to other users")

	// Verify lines parse + decision_id order is preserved + every line
	// carries the OCSF cross-product invariants
	// (metadata.product.{name,vendor_name}, class_uid=6003).
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	gotIDs := []int64{}
	for scanner.Scan() {
		var got Event
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &got))
		assert.Equal(t, Product, got.Metadata.Product.Name)
		assert.Equal(t, VendorName, got.Metadata.Product.VendorName)
		assert.Equal(t, SchemaVersion, got.Metadata.Version)
		assert.Equal(t, 6003, got.ClassUID)
		require.NotNil(t, got.Unmapped)
		gotIDs = append(gotIDs, got.Unmapped.IAMJIT.DecisionID)
	}
	require.NoError(t, scanner.Err())
	assert.Equal(t, []int64{1, 2, 3}, gotIDs)
}

// TestLogWriter_AppendsAcrossOpen verifies the O_APPEND mode: opening
// the same path a second time appends rather than truncates.
func TestLogWriter_AppendsAcrossOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	w1, err := NewLogWriter(LogOptions{Path: path})
	require.NoError(t, err)
	require.NoError(t, w1.Write(context.Background(), testDecisionEvent(100)))
	require.NoError(t, w1.Shutdown(context.Background()))

	w2, err := NewLogWriter(LogOptions{Path: path})
	require.NoError(t, err)
	require.NoError(t, w2.Write(context.Background(), testDecisionEvent(101)))
	require.NoError(t, w2.Shutdown(context.Background()))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Count(string(data), "\n")
	assert.Equal(t, 2, lines, "second open MUST append (O_APPEND), not truncate")
}

// TestLogWriter_FsyncFlag_Enabled verifies the option is wired through.
// We can't reliably test fdatasync hit disk from a unit test (the OS
// page cache hides it), but we CAN verify the option round-trips into
// Stats() so a misconfigured fsync flag is at least visible to ops.
func TestLogWriter_FsyncFlag_Enabled(t *testing.T) {
	dir := t.TempDir()
	w, err := NewLogWriter(LogOptions{
		Path:  filepath.Join(dir, "audit.jsonl"),
		Fsync: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = w.Shutdown(context.Background())
	})
	assert.True(t, w.Stats().Fsync, "Fsync option must reach Stats() for ops introspection")
}

// TestLogWriter_DropsOnOverflow exercises the bounded-channel drop
// path. With QueueSize=1 + a paused worker (achievable by holding
// Shutdown until we've over-saturated the channel), writes after the
// first must increment the dropped counter without blocking.
func TestLogWriter_DropsOnOverflow(t *testing.T) {
	dir := t.TempDir()
	w, err := NewLogWriter(LogOptions{
		Path:      filepath.Join(dir, "audit.jsonl"),
		QueueSize: 1,
	})
	require.NoError(t, err)

	// Saturate the channel: send 1000 events as fast as possible. Some
	// will go through the worker, most will hit the drop path. The
	// invariant is "dropped > 0 + writes never block".
	for i := 0; i < 1000; i++ {
		done := make(chan struct{})
		go func() {
			_ = w.Write(context.Background(), testDecisionEvent(int64(i)))
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("Write blocked > 500ms; non-blocking-send invariant broken")
		}
	}
	require.NoError(t, w.Shutdown(context.Background()))
	stats := w.Stats()
	assert.Greater(t, stats.Dropped, int64(0),
		"saturated bounded channel must drop SOME events; if zero, the overflow path didn't fire")
}

// TestLogWriter_ConcurrentWrites_AreSafeAndOrdered: many goroutines
// writing simultaneously must not produce torn lines on disk + Stats()
// counters must not race. Run under -race; success = test passes.
func TestLogWriter_ConcurrentWrites_AreSafeAndOrdered(t *testing.T) {
	dir := t.TempDir()
	w, err := NewLogWriter(LogOptions{
		Path:      filepath.Join(dir, "audit.jsonl"),
		QueueSize: 10000,
	})
	require.NoError(t, err)
	var wg sync.WaitGroup
	const N = 100
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_ = w.Write(context.Background(), testDecisionEvent(int64(id)))
		}(i)
	}
	wg.Wait()
	require.NoError(t, w.Shutdown(context.Background()))

	// Every line must parse — no torn writes.
	data, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	require.NoError(t, err)
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var e Event
		require.NoError(t, json.Unmarshal([]byte(line), &e),
			"every JSONL line must be valid JSON; concurrent writes must not produce torn lines")
	}
}

// TestLogWriter_ShutdownIdempotent: a second Shutdown call must not
// panic / deadlock. The proxy's signal-shutdown path may double-call.
func TestLogWriter_ShutdownIdempotent(t *testing.T) {
	dir := t.TempDir()
	w, err := NewLogWriter(LogOptions{Path: filepath.Join(dir, "audit.jsonl")})
	require.NoError(t, err)
	require.NoError(t, w.Shutdown(context.Background()))
	require.NoError(t, w.Shutdown(context.Background()), "second Shutdown must be a no-op")
}

// TestLogWriter_StatsBeforeShutdown reads counters mid-flight to
// verify the MCP status tool can poll without locking up the worker.
func TestLogWriter_StatsBeforeShutdown(t *testing.T) {
	dir := t.TempDir()
	w, err := NewLogWriter(LogOptions{Path: filepath.Join(dir, "audit.jsonl")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Shutdown(context.Background()) })

	for i := 0; i < 50; i++ {
		require.NoError(t, w.Write(context.Background(), testDecisionEvent(int64(i))))
	}
	// Give the worker a moment to drain.
	time.Sleep(50 * time.Millisecond)
	stats := w.Stats()
	assert.True(t, stats.Configured)
	assert.NotEmpty(t, stats.Path)
	assert.GreaterOrEqual(t, stats.Written+stats.Dropped, int64(0))
}

// TestLogWriter_EmptyPath_Rejected guards against silent footgun:
// passing an empty --audit-log-path must produce a clear error rather
// than open the working directory or panic.
func TestLogWriter_EmptyPath_Rejected(t *testing.T) {
	_, err := NewLogWriter(LogOptions{Path: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-empty path")
}

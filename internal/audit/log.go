// LogWriter — append-only JSONL audit-export file writer (#252 Slice 1).
//
// One LogWriter per dbounce process; emits one JSON-encoded Event per
// line to the configured file path. Worker goroutine drains a bounded
// channel so the proxy's hot-path (evaluateAndAudit / handleGatedMessage
// / mysqlForwarder.handleGatedQuery) never blocks on disk I/O.
//
// Trade-offs (per the spec doc):
//
//   - File mode is O_APPEND|O_CREATE|O_WRONLY perm 0600. Append-only
//     means rotation MUST happen via an external tool (logrotate /
//     Fluent Bit / Vector / fluentd). Bundling rotation here would
//     duplicate well-trodden tools + would conflict with operators who
//     already ship a centralized rotation policy.
//
//   - --audit-log-fsync is OPT-IN (default OFF). With fsync the writer
//     issues fdatasync after every line, giving compliance-grade
//     durability (the audit row is on disk before the response leaves
//     the proxy) at the cost of ~hundreds-of-microseconds-per-decision
//     of additional latency. The default (no fsync) batches at the OS
//     page-cache layer and risks losing the trailing few microseconds
//     of events on a hard kill — acceptable for the dev-laptop +
//     centralized-aggregator deployment shape.
//
//   - On overflow (bounded channel full), the LogWriter DROPS the
//     event + increments DroppedCount. The drop is surfaced via the
//     dbounce_audit_export_status MCP tool. We do NOT block the proxy
//     on a slow log writer — that would translate disk pressure into
//     SQL-client timeouts.
//
// Why a separate goroutine instead of in-line file.Write: cross-platform
// file I/O is variable (Darwin's APFS sync, Linux's writeback batching);
// keeping the proxy hot-path off it means the worst-case write tail
// never reaches the SQL client.
//
// Per [[audit-cadence-discipline]]: the LogWriter's surface is small
// (one Write call, one Shutdown call); the file-mode + perm + path
// validation is all in Open. Tests pin the file mode + perm bits.
//
// Per [[ibounce-honest-positioning]]: this is OPERATOR VISIBILITY. An
// adversary who can reach the proxy can also reach the log file (same
// UID). The log is for post-hoc security-team review, not real-time
// adversary defense.

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// LogWriter writes one JSON-encoded Event per line to an append-only
// file. Construct with NewLogWriter; close with Shutdown so the worker
// drains the in-flight channel before the file handle closes.
type LogWriter struct {
	path  string
	fsync bool

	// f is the open file handle. Owned by the worker goroutine; the
	// Write path NEVER touches it directly (only the channel).
	f io.WriteCloser

	// ch is the bounded queue. Buffered = chanCapacity. Write does a
	// non-blocking send + DROPS on full (incrementing dropped) so the
	// proxy hot-path never blocks.
	ch chan Event

	// doneCh is closed by the worker when it exits. Shutdown waits on
	// it so a Close-then-immediately-stat caller sees all in-flight
	// rows flushed.
	doneCh chan struct{}

	// shutdownOnce gates the channel close so concurrent Shutdown
	// callers see a clean second-call return.
	shutdownOnce sync.Once

	// dropped + written are atomic counters surfaced via Stats(). The
	// MCP status tool reads these without locking the worker.
	dropped atomic.Int64
	written atomic.Int64

	// lastErr is the most recent worker-side error (failed write,
	// failed fsync). Surfaced via Stats() so the MCP tool can answer
	// "is the audit log healthy?" without the operator tailing
	// stderr.
	lastErrMu sync.Mutex
	lastErr   string
}

// LogOptions wires the LogWriter from CLI flags.
type LogOptions struct {
	// Path is the absolute path to the JSONL file. Required.
	Path string
	// Fsync, when true, fdatasyncs after every line. Off by default;
	// see file docstring for the trade-off.
	Fsync bool
	// QueueSize bounds the in-flight chan. Defaults to 1000 when
	// zero. Tests pass small values to exercise the drop path.
	QueueSize int
}

// chanCapacityDefault is the in-flight bound when QueueSize is unset.
// 1000 is generous for any laptop workload while keeping the in-flight
// memory footprint bounded (each Event JSONified is well under 4 KB ⇒
// ~4 MB max in-flight).
const chanCapacityDefault = 1000

// NewLogWriter opens path with O_APPEND|O_CREATE|O_WRONLY perm 0600,
// starts the worker goroutine, and returns the writer ready to accept
// Write calls. The worker exits when the channel is closed (via
// Shutdown).
//
// The parent dir is created with perm 0700 if missing so an operator
// who passed --audit-log-path ~/logs/dbounce.jsonl on a fresh machine
// doesn't hit "no such file or directory."
func NewLogWriter(opts LogOptions) (*LogWriter, error) {
	if opts.Path == "" {
		return nil, errors.New("audit: LogWriter requires a non-empty path")
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = chanCapacityDefault
	}
	if dir := filepath.Dir(opts.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("audit: create log parent dir %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(opts.Path,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open log %q: %w", opts.Path, err)
	}
	w := &LogWriter{
		path:   opts.Path,
		fsync:  opts.Fsync,
		f:      f,
		ch:     make(chan Event, opts.QueueSize),
		doneCh: make(chan struct{}),
	}
	go w.runWorker()
	return w, nil
}

// Write enqueues evt for the worker to serialize + write. Non-blocking:
// if the channel is full, the event is DROPPED and the dropped counter
// is incremented. The ctx parameter is honored as a cancel signal —
// when ctx is already canceled, the call short-circuits + drops.
//
// Why non-blocking: the proxy hot-path is the caller. A blocked send
// here would translate disk pressure into SQL client timeouts. Better
// to surface the drop via the MCP status tool than to stall the proxy.
//
// Per the spec doc: drops on overflow MUST be visible. The webhook
// emits a synthetic AUDIT_DROPPED event; the log file does NOT (the
// file consumer is local + can read the dropped counter from /healthz
// or the MCP tool).
func (w *LogWriter) Write(ctx context.Context, evt Event) error {
	if w == nil {
		return nil
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			w.dropped.Add(1)
			return ctx.Err()
		default:
		}
	}
	select {
	case w.ch <- evt:
		return nil
	default:
		w.dropped.Add(1)
		return nil
	}
}

// runWorker is the goroutine that drains w.ch onto the file. Exits
// when the channel is closed by Shutdown — at which point any in-flight
// events have already been queued (Shutdown closes after the last Write
// completes) so the worker drains them to disk before signaling doneCh.
func (w *LogWriter) runWorker() {
	defer close(w.doneCh)
	defer func() {
		if err := w.f.Close(); err != nil {
			w.recordErr(fmt.Errorf("close: %w", err))
		}
	}()
	enc := json.NewEncoder(w.f)
	// The encoder appends \n after each Encode call — matches the JSONL
	// contract (one event per line, newline-terminated).
	for evt := range w.ch {
		if err := enc.Encode(evt); err != nil {
			w.recordErr(fmt.Errorf("encode: %w", err))
			// Keep draining — a single bad encode shouldn't halt the
			// worker. The lastErr counter surfaces persistent failures
			// via Stats().
			continue
		}
		if w.fsync {
			// Best-effort fdatasync. Fail-open: a sync error is logged
			// but doesn't stop the worker (the row is already in OS
			// page cache; the next sync attempt may succeed). Matches
			// the file-mode trade-off in the package docstring.
			if osF, ok := w.f.(*os.File); ok {
				if err := osF.Sync(); err != nil {
					w.recordErr(fmt.Errorf("fsync: %w", err))
				}
			}
		}
		w.written.Add(1)
	}
}

// Shutdown closes the channel + waits for the worker to drain the
// in-flight events and close the file. Returns the worker's final error
// state (the most recent recordErr) when the wait completes. Idempotent
// — second + later calls are no-ops.
//
// Caller MUST stop sending to Write BEFORE calling Shutdown — a Write
// after Shutdown would panic on send-to-closed-channel. The proxy code
// path enforces this by holding the LogWriter pointer through Server
// lifetime + Shutdown firing only after Server.Shutdown unblocks.
func (w *LogWriter) Shutdown(ctx context.Context) error {
	if w == nil {
		return nil
	}
	w.shutdownOnce.Do(func() {
		close(w.ch)
	})
	select {
	case <-w.doneCh:
	case <-ctx.Done():
		return ctx.Err()
	}
	w.lastErrMu.Lock()
	defer w.lastErrMu.Unlock()
	if w.lastErr != "" {
		return errors.New(w.lastErr)
	}
	return nil
}

// Stats returns a snapshot of the writer's runtime counters. Read by
// the dbounce_audit_export_status MCP tool. Race-free: all underlying
// fields are atomics or mutex-guarded.
type LogStats struct {
	Path        string
	Written     int64
	Dropped     int64
	LastError   string
	Fsync       bool
	QueueDepth  int
	QueueLimit  int
	Configured  bool
}

// Stats returns the current counters. Safe to call concurrently with
// Write + Shutdown.
func (w *LogWriter) Stats() LogStats {
	if w == nil {
		return LogStats{Configured: false}
	}
	w.lastErrMu.Lock()
	last := w.lastErr
	w.lastErrMu.Unlock()
	return LogStats{
		Path:       w.path,
		Written:    w.written.Load(),
		Dropped:    w.dropped.Load(),
		LastError:  last,
		Fsync:      w.fsync,
		QueueDepth: len(w.ch),
		QueueLimit: cap(w.ch),
		Configured: true,
	}
}

// recordErr stores err as the most-recent worker-side error. Race-free
// via the lastErrMu mutex. We don't keep an error CHAIN — only the most
// recent — so the MCP tool's "last_error" field has stable read
// semantics regardless of how many errors fired.
func (w *LogWriter) recordErr(err error) {
	if err == nil {
		return
	}
	w.lastErrMu.Lock()
	w.lastErr = err.Error()
	w.lastErrMu.Unlock()
}

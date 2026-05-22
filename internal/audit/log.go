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
	"time"
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

	// lastErrAtUnixNano is the wall-clock at the most-recent recordErr
	// call. Atomic so /healthz + the audit-export health CLI can read
	// it without a lock. Per [[audit-export-failure-visibility]] F4/F5/
	// F6: a stale "last write failed at HH:MM but we've had no recent
	// failure" surface is the operator's signal that the log path is
	// transiently broken — fold into log_writes_ok logic below.
	lastErrAtUnixNano atomic.Int64

	// lastWriteAtUnixNano is the wall-clock of the most-recent
	// successful enc.Encode return. Atomic. Together with
	// lastErrAtUnixNano this lets the health-monitor compute
	// "log_writes_ok = (no recent error) OR (a successful write
	// landed since the last error)". A LogWriter that was unhealthy
	// at startup but is now writing fine reads as ok again, exactly
	// like the webhook recovery semantics.
	lastWriteAtUnixNano atomic.Int64

	// #311 / §A10 rotation knobs + telemetry. maxSizeMB / maxAgeDays
	// gate the rotation trigger; rotations / rotationFailures /
	// partialBytesRecovered are surfaced by Stats() so operators
	// can confirm rotation cadence without grepping admin-actions.
	maxSizeMB              int64
	maxAgeDays             int
	rotations              atomic.Int64
	rotationFailures       atomic.Int64
	lastRotationUnixNano   atomic.Int64
	lastRotationPath       atomic.Value // string
	partialBytesRecovered  atomic.Int64
	onRotation             func(archive string)
	onRotationFailure      func(reason string)
	onRecovery             func(bytes int64)
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
	// #311 / §A10 rotation thresholds. Zero disables the respective
	// trigger; the writer never destroys data on its own.
	MaxSizeMB  int64
	MaxAgeDays int
	// Optional lifecycle callbacks for the admin-action audit
	// channel. Fire off the worker goroutine; callers MUST NOT
	// block on the audit pipeline (would deadlock the worker).
	OnRotation        func(archive string)
	OnRotationFailure func(reason string)
	OnRecovery        func(bytes int64)
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
	// #311 / §A10 — crash recovery before opening for append.
	recovered, _ := RecoverPartialTail(opts.Path)
	f, err := os.OpenFile(opts.Path,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open log %q: %w", opts.Path, err)
	}
	w := &LogWriter{
		path:              opts.Path,
		fsync:             opts.Fsync,
		f:                 f,
		ch:                make(chan Event, opts.QueueSize),
		doneCh:            make(chan struct{}),
		maxSizeMB:         opts.MaxSizeMB,
		maxAgeDays:        opts.MaxAgeDays,
		onRotation:        opts.OnRotation,
		onRotationFailure: opts.OnRotationFailure,
		onRecovery:        opts.OnRecovery,
	}
	w.lastRotationPath.Store("")
	if recovered > 0 {
		w.partialBytesRecovered.Add(recovered)
		if opts.OnRecovery != nil {
			go opts.OnRecovery(recovered)
		}
	}
	go w.runWorker()
	return w, nil
}

// maybeRotate runs the size + age check; on a trigger it swaps the
// file handle. Called from runWorker on the writer goroutine so the
// mutation of w.f is single-threaded. A rotation failure does not
// abort the worker — the active log keeps growing until the
// operator intervenes (signal: rotation_failed admin-action).
func (w *LogWriter) maybeRotate() {
	if !ShouldRotateBySize(w.path, w.maxSizeMB) &&
		!ShouldRotateByAge(w.path, w.maxAgeDays, time.Now()) {
		return
	}
	if osF, ok := w.f.(*os.File); ok {
		_ = osF.Sync()
		_ = osF.Close()
	}
	archive, rotErr := Rotate(w.path, time.Now())
	if rotErr != nil {
		w.rotationFailures.Add(1)
		w.recordErr(fmt.Errorf("rotate: %w", rotErr))
		if w.onRotationFailure != nil {
			go w.onRotationFailure(rotErr.Error())
		}
	}
	newF, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		w.recordErr(fmt.Errorf("reopen after rotate: %w", err))
		return
	}
	w.f = newF
	if archive != "" {
		w.rotations.Add(1)
		w.lastRotationUnixNano.Store(time.Now().UnixNano())
		w.lastRotationPath.Store(archive)
		if w.onRotation != nil {
			go w.onRotation(archive)
		}
	}
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
//
// Per [[audit-export-failure-visibility]] F6: every Nth write also runs
// a stat() on the path to detect "log file deleted/moved while bouncer
// running" — the OS keeps the fd valid + writes succeed into the
// unlinked inode (silently invisible to operators tailing the path).
// On detection, the worker records an error AND re-opens the file at
// the same path so subsequent events land where the operator expects.
// N=64 balances "catch the deletion within a small event window" with
// "don't add a per-event syscall." A 64-event window at 100 events/s
// = ~640ms recovery; well within the [[audit-cadence-discipline]] BB
// audit tolerance.
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
	var sinceStat int
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
		w.lastWriteAtUnixNano.Store(time.Now().UnixNano())
		sinceStat++
		if sinceStat >= logStatCheckInterval {
			sinceStat = 0
			if newEnc := w.checkFilePresence(enc); newEnc != nil {
				enc = newEnc
			}
		}
		// #311 / §A10 — rotation guard. Cheap when no trigger fires
		// (a single Stat); on rotation we swap w.f and rebuild enc.
		if w.maxSizeMB > 0 || w.maxAgeDays > 0 {
			prevPath := w.lastRotationPath.Load()
			w.maybeRotate()
			if w.lastRotationPath.Load() != prevPath {
				enc = json.NewEncoder(w.f)
			}
		}
	}
}

// logStatCheckInterval is the per-N-events cadence for F6 (file
// deleted/moved). 64 is small enough that an operator who deletes the
// file mid-run sees the recovery within ~half a second on a 100 ev/s
// stream + large enough that the syscall overhead is in the noise (a
// stat() is ~5-10us on a warm cache; per-event would be ~10% overhead
// at high throughput, per-64-events is ~0.2%).
const logStatCheckInterval = 64

// checkFilePresence stats the log path; if the file is gone OR the
// inode no longer matches the open fd, records an error + re-opens at
// the same path. Returns a new json.Encoder bound to the re-opened
// handle (or nil when no re-open was needed). Worker-only.
//
// Per [[audit-export-failure-visibility]] F6 + [[deliberate-feature-
// completion]] the recovery is BOTH halves: detect (record error so
// /healthz flips degraded + the SIEM alert fires) AND re-open (so
// subsequent events land at the path the operator expects). A "detect
// but don't recover" implementation would silently lose events for the
// rest of the process lifetime; a "recover but don't surface" would
// hide the operator's mis-action from the audit channel.
func (w *LogWriter) checkFilePresence(enc *json.Encoder) *json.Encoder {
	if w == nil || w.f == nil {
		return nil
	}
	osF, ok := w.f.(*os.File)
	if !ok {
		return nil
	}
	pathStat, pathErr := os.Stat(w.path)
	if pathErr != nil {
		// File at the path no longer exists (or is unreadable). Try to
		// re-open at the same path. If THAT also fails (perm-denied
		// parent dir, disk-full), record both errors + keep writing to
		// the old fd; the WritesOK signal will stay false until the
		// operator fixes the path.
		w.recordErr(fmt.Errorf("file vanished at %q: %w", w.path, pathErr))
		return w.tryReopen()
	}
	fdStat, fdErr := osF.Stat()
	if fdErr != nil {
		w.recordErr(fmt.Errorf("fstat open fd: %w", fdErr))
		return nil
	}
	if !os.SameFile(pathStat, fdStat) {
		// Same path; different inode — the operator (or logrotate)
		// renamed-then-touched a new file. Re-open so subsequent
		// events land in the new inode. Per the docstring this is
		// surfaced as an error so /healthz can flip — silent
		// re-opens would hide rotation misconfiguration.
		w.recordErr(fmt.Errorf(
			"file inode changed at %q (logrotate misconfigured?)", w.path))
		return w.tryReopen()
	}
	return nil
}

// tryReopen attempts to re-OpenFile(w.path) + swap w.f. On success,
// returns a fresh json.Encoder bound to the new fd; on failure,
// records the failure + returns nil (caller keeps using the old fd).
// Worker-only — w.f mutation here is safe because the worker is the
// only goroutine that touches it.
func (w *LogWriter) tryReopen() *json.Encoder {
	f, err := os.OpenFile(w.path,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0o600)
	if err != nil {
		w.recordErr(fmt.Errorf("reopen %q: %w", w.path, err))
		return nil
	}
	// Best-effort close of the previous fd. A failed close on the
	// unlinked inode is expected (Linux deletes the inode when the
	// last fd closes; the failure mode here would be ENOSPC on close,
	// which we surface but don't act on — the new fd is already live).
	if old, ok := w.f.(io.Closer); ok {
		_ = old.Close()
	}
	w.f = f
	// The recovery write itself is the "we're back" signal — no
	// separate event; the next decision will land cleanly in the new
	// inode + the LastWriteAt timestamp will bump past the LastErrorAt
	// timestamp, which clears WritesOK back to true.
	return json.NewEncoder(f)
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
//
// Per [[audit-export-failure-visibility]]: WritesOK + LastErrorAt +
// LastWriteAt are surfaced so /healthz + `dbounce audit-export health`
// can answer "is the log writer healthy right now?" without re-
// inspecting the file. F4/F5/F6 (perm-denied / disk-full / file
// deleted) all flow through these fields via recordErr.
type LogStats struct {
	Path        string
	Written     int64
	Dropped     int64
	LastError   string
	Fsync       bool
	QueueDepth  int
	QueueLimit  int
	Configured  bool
	WritesOK    bool
	LastErrorAt int64
	LastWriteAt int64
	// #311 / §A10 rotation telemetry.
	MaxSizeMB             int64
	MaxAgeDays            int
	Rotations             int64
	RotationFailures      int64
	LastRotationAt        int64
	LastRotationPath      string
	PartialBytesRecovered int64
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
	lastRotPath, _ := w.lastRotationPath.Load().(string)
	return LogStats{
		Path:                  w.path,
		Written:               w.written.Load(),
		Dropped:               w.dropped.Load(),
		LastError:             last,
		Fsync:                 w.fsync,
		QueueDepth:            len(w.ch),
		QueueLimit:            cap(w.ch),
		Configured:            true,
		WritesOK:              w.WritesOK(),
		LastErrorAt:           w.lastErrAtUnixNano.Load(),
		LastWriteAt:           w.lastWriteAtUnixNano.Load(),
		MaxSizeMB:             w.maxSizeMB,
		MaxAgeDays:            w.maxAgeDays,
		Rotations:             w.rotations.Load(),
		RotationFailures:      w.rotationFailures.Load(),
		LastRotationAt:        w.lastRotationUnixNano.Load(),
		LastRotationPath:      lastRotPath,
		PartialBytesRecovered: w.partialBytesRecovered.Load(),
	}
}

// RecordErrForTest is the exported test-only entry point to recordErr.
// Lets the proxy package's /healthz test drive the LogWriter into a
// degraded posture without simulating an ENOSPC / EPERM that depends
// on filesystem state. Production code MUST NOT call this; the
// recordErr-from-the-worker path is the only legitimate driver in
// production builds.
func (w *LogWriter) RecordErrForTest(msg string) {
	w.recordErr(errors.New(msg))
}

// recordErr stores err as the most-recent worker-side error. Race-free
// via the lastErrMu mutex. We don't keep an error CHAIN — only the most
// recent — so the MCP tool's "last_error" field has stable read
// semantics regardless of how many errors fired.
//
// Per [[audit-export-failure-visibility]] F4/F5/F6: also stamps the
// wall-clock so /healthz + the audit-export health CLI can answer
// "how recently did writes start failing?" The atomic store is
// race-clean against concurrent Stats() reads.
func (w *LogWriter) recordErr(err error) {
	if err == nil {
		return
	}
	w.lastErrMu.Lock()
	w.lastErr = err.Error()
	w.lastErrMu.Unlock()
	w.lastErrAtUnixNano.Store(time.Now().UnixNano())
}

// LastErrorAtUnixNano returns the wall-clock of the most-recent
// recordErr. Zero when no error has been recorded. Atomic-only read so
// the health-monitor + /healthz can poll without locking.
func (w *LogWriter) LastErrorAtUnixNano() int64 {
	if w == nil {
		return 0
	}
	return w.lastErrAtUnixNano.Load()
}

// LastWriteAtUnixNano returns the wall-clock of the most-recent
// successful enc.Encode return. Zero when nothing has been written
// (e.g. an open writer that hasn't received any events yet). Atomic-
// only read.
func (w *LogWriter) LastWriteAtUnixNano() int64 {
	if w == nil {
		return 0
	}
	return w.lastWriteAtUnixNano.Load()
}

// WritesOK reports whether the most-recent observation of the log
// path is healthy. Definition: no error recorded, OR a successful
// write landed AFTER the last error (recovery). The health-monitor
// reads this to drive log_writes_ok in the /healthz block.
//
// Per [[audit-export-failure-visibility]]: a permission-denied parent
// dir, a disk-full event, or a deleted-mid-run log file all surface
// here as false until a subsequent write succeeds. Operators who pre-
// check the log path via `dbounce audit-export health` get an exit-1
// signal before the bouncer starts emitting decisions.
func (w *LogWriter) WritesOK() bool {
	if w == nil {
		return true
	}
	lastErr := w.lastErrAtUnixNano.Load()
	if lastErr == 0 {
		return true
	}
	lastWrite := w.lastWriteAtUnixNano.Load()
	return lastWrite > lastErr
}

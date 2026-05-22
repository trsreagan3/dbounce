// watcher.go — fsnotify-driven hot reload of
// `~/.iam-jit/dynamic-denies.yaml`.
//
// macOS uses fsevents; Linux uses inotify; the fsnotify library
// transparently routes to the right backend. On Windows
// ReadDirectoryChangesW is wired but dbounce is not advertised as a
// Windows product.
//
// Design notes
// ------------
//
// fsnotify watches a single PATH — directory OR file. We watch the
// PARENT DIRECTORY because operators often atomic-rename their config
// updates (write to tmp; rename onto the live path) — watching the file
// inode directly misses the rename. The directory watch produces an
// event for every entry; we filter to the file we care about.
//
// Debouncing: rapid sequential writes (e.g. the `iam-jit deny add` CLI
// writing the file as it appends a rule) can produce multiple fsnotify
// events in quick succession. We debounce with a 100ms quiet-period
// timer — every event resets the timer; only when the timer elapses
// without a new event do we actually reload. This avoids reloading the
// file mid-write (which would surface a parse error against a partial
// file).
//
// Failure semantics:
//   - File created / removed / modified -> reload, swap in new ruleset
//     atomically, emit `dynamic_deny.reloaded` admin-action event.
//   - Parse error on reload -> retain previous in-memory snapshot, emit
//     `dynamic_deny.parse_error` admin-action event with the offending
//     error string. fail-CLOSED per [[ibounce-honest-positioning]].
//
// INSTANCE-LEVEL TRANSITION DETECTION (dbounce-specific)
// ------------------------------------------------------
// In addition to the standard reload events, the dbounce watcher
// computes "did the in-memory denied state of THIS instance change?"
// across each reload + emits an `instance_now_denied` /
// `instance_now_allowed` reason when it did. The proxy uses these
// transitions to log loudly + flip its connection-accept gate.

package dynamicdeny

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ReloadReason is the canonical enum surfaced on admin-action events.
// Operators query SIEMs for `unmapped.iam_jit.ext.dynamic_deny_reload_reason`
// per the cross-product design doc.
type ReloadReason string

const (
	// ReasonFileCreated — the file was created (e.g. operator's first
	// `iam-jit deny add` invocation, or the file was previously absent
	// and an admin just installed it).
	ReasonFileCreated ReloadReason = "file_created"
	// ReasonFileModified — the file was modified in place (the common
	// shape: `iam-jit deny add` appends a rule).
	ReasonFileModified ReloadReason = "file_modified"
	// ReasonFileRemoved — the file was removed; the watcher resets the
	// active rule set to empty + waits for the file to reappear.
	ReasonFileRemoved ReloadReason = "file_removed"
	// ReasonParseError — a reload attempt failed parse/schema
	// validation. The previous snapshot is retained.
	ReasonParseError ReloadReason = "parse_error"
	// ReasonReloadRequested — the operator (or a cross-bouncer fan-out
	// CLI) hit POST /admin/dynamic-denies/reload. Distinguished from
	// the fsnotify-driven reasons so a SIEM can isolate "operator
	// pushed" vs "filesystem detected" reloads.
	ReasonReloadRequested ReloadReason = "reload_requested"
	// ReasonInstanceNowDenied — dbounce-specific: a reload caused this
	// instance's denied state to flip from false -> true (a new rule
	// matches the upstream). Emitted IN ADDITION to the underlying
	// reload reason so a SIEM consumer can pivot directly on
	// "instance newly denied" without computing the diff.
	ReasonInstanceNowDenied ReloadReason = "instance_now_denied"
	// ReasonInstanceNowAllowed — dbounce-specific: a reload caused this
	// instance's denied state to flip from true -> false (a previously
	// matching rule was removed / expired / no longer matches).
	ReasonInstanceNowAllowed ReloadReason = "instance_now_allowed"
)

// debounceQuietPeriod is the timer interval between the last fsnotify
// event and the actual reload attempt. 100ms balances "react fast
// enough that an operator sees the rule apply right after they ran
// `iam-jit deny add`" against "don't reload mid-write."
const debounceQuietPeriod = 100 * time.Millisecond

// EmitFunc is the callback the watcher invokes whenever a reload (or
// reload attempt) lands. Implementations typically build an OCSF
// admin-action event + tee it into the audit-log sink + bump a
// /healthz counter. nil EmitFunc → emissions are silently dropped (the
// reload still applies; the watcher just doesn't surface it through
// the admin-action channel).
//
// Decoupled from the audit package so this package stays free of
// audit-package dependencies (avoids an import cycle once #324f wires
// the recommender side).
type EmitFunc func(reason ReloadReason, rs *RuleSet, parseErr error)

// Watcher hot-reloads the dynamic-deny YAML file on disk changes.
//
// Constructed with NewWatcher; Start spins the background goroutine;
// Stop (or ctx-cancel) shuts it down. Snapshot returns the most
// recently committed RuleSet under an RWMutex so concurrent proxy hot-
// path readers see a consistent view.
type Watcher struct {
	path string

	emit EmitFunc

	// Stderr is where parse-error / startup warnings land. nil routes
	// to os.Stderr. Test seam.
	stderr io.Writer

	// rs holds the active RuleSet pointer. Replaced atomically on
	// successful reload. Reads use Snapshot which takes the RLock.
	mu sync.RWMutex
	rs *RuleSet

	// counters surface through /healthz so an operator sees reload
	// activity without grepping the audit log.
	totalReloads     atomic.Int64
	totalParseErrors atomic.Int64

	// debounceQuietPeriod is configurable for tests so a debounce-
	// regression test doesn't have to sleep 100ms on every assert.
	// Zero → debounceQuietPeriod constant above.
	debounce time.Duration

	// instanceUpstream + instanceRDSARN are the upstream identity the
	// watcher matches each reload against to compute the instance-
	// denied transition. Empty values disable the matching.
	instanceUpstream string
	instanceRDSARN   string

	// instanceDenied tracks the most-recently-computed denied state of
	// this dbounce instance. Compared against the post-reload state to
	// emit instance_now_denied / instance_now_allowed transitions.
	instanceDeniedFlag atomic.Bool
	// instanceDenyingRule stores the id + reason of the rule that
	// produced the current denied state (empty when not denied).
	denyingMu        sync.RWMutex
	denyingRuleID   string
	denyingReason   string

	// cancel + done coordinate shutdown. Set by Start; Stop calls
	// cancel + waits on done.
	cancel context.CancelFunc
	done   chan struct{}
}

// NewWatcher constructs a Watcher rooted at path. The initial snapshot
// is loaded synchronously from disk so the proxy's startup banner sees
// the actual count + the proxy doesn't briefly accept connections
// before the watcher catches up. emit may be nil.
func NewWatcher(path string, emit EmitFunc) (*Watcher, error) {
	w := &Watcher{
		path:     path,
		emit:     emit,
		debounce: debounceQuietPeriod,
		done:     make(chan struct{}),
	}
	rs, err := LoadFile(path)
	if err != nil {
		// Initial load failed — surface the error to the caller so the
		// startup banner can announce "0 rules loaded (parse error:
		// ...)". The watcher still starts with an empty ruleset.
		w.rs = Empty()
		w.rs.SourcePath = path
		w.totalParseErrors.Add(1)
		return w, err
	}
	w.rs = rs
	return w, nil
}

// SetStderr lets the caller redirect the watcher's stderr emissions.
// Used by tests + by operators who route dbounce's stderr through a
// custom sink.
func (w *Watcher) SetStderr(s io.Writer) { w.stderr = s }

// SetEmitFunc installs (or replaces) the admin-action emit callback.
// Used by the CLI layer to wire the watcher's reload notifications
// into the audit-log sink AFTER NewWatcher has already returned a
// snapshot the proxy can read. nil disables the channel.
func (w *Watcher) SetEmitFunc(emit EmitFunc) { w.emit = emit }

// SetDebouncePeriod overrides the debounce quiet-period for tests that
// need a shorter wait. NewWatcher defaults to 100ms.
func (w *Watcher) SetDebouncePeriod(d time.Duration) {
	if d > 0 {
		w.debounce = d
	}
}

// SetInstanceUpstream wires the upstream identity the watcher matches
// each reload against to compute the instance-denied transition.
// upstreamHost is the dbounce instance's configured upstream hostname
// (parsed from `--upstream` at startup); rdsARN is the optional
// operator-supplied `--upstream-rds-arn`. Empty values disable the
// matching (no instance-denied transitions will be reported).
//
// Called once at startup BEFORE Start. Also recomputes the initial
// denied state so /healthz + the startup banner reflect it.
func (w *Watcher) SetInstanceUpstream(upstreamHost, rdsARN string) {
	w.instanceUpstream = upstreamHost
	w.instanceRDSARN = rdsARN
	w.recomputeInstanceDenied(w.Snapshot())
}

// Snapshot returns the current ruleset. Safe for concurrent use.
func (w *Watcher) Snapshot() *RuleSet {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.rs
}

// InstanceDenied reports whether this dbounce instance is currently
// denied by ANY active dynamic-deny rule. Computed against the upstream
// identity wired via SetInstanceUpstream + the most recently committed
// rule set. Safe for concurrent use; cheap (atomic load).
func (w *Watcher) InstanceDenied() bool {
	if w == nil {
		return false
	}
	return w.instanceDeniedFlag.Load()
}

// DenyingRule returns the (rule_id, reason) of the rule producing the
// current denied state. Empty strings when InstanceDenied()==false.
func (w *Watcher) DenyingRule() (string, string) {
	if w == nil {
		return "", ""
	}
	w.denyingMu.RLock()
	defer w.denyingMu.RUnlock()
	return w.denyingRuleID, w.denyingReason
}

// TotalReloads returns the count of successful reloads since
// construction (does not count the initial load).
func (w *Watcher) TotalReloads() int64 { return w.totalReloads.Load() }

// TotalParseErrors returns the count of failed reloads (parse / schema
// errors) since construction. Includes the initial load when it failed.
func (w *Watcher) TotalParseErrors() int64 { return w.totalParseErrors.Load() }

// Path returns the file path the watcher watches.
func (w *Watcher) Path() string { return w.path }

// Start launches the fsnotify goroutine. Returns immediately. Stop or
// ctx-cancel ends it.
func (w *Watcher) Start(ctx context.Context) error {
	if w.path == "" {
		// No path configured → nothing to watch. The watcher behaves
		// like a no-op (Snapshot returns an empty RuleSet).
		close(w.done)
		return nil
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("dynamic-denies: fsnotify: %w", err)
	}
	// We watch the PARENT directory so atomic-rename writes
	// (write-tmp + rename) are caught — fsnotify on a file inode loses
	// the watch when the inode is replaced.
	dir := filepath.Dir(w.path)
	if dir == "" {
		dir = "."
	}
	// Ensure the directory exists so the watcher attaches cleanly. If
	// it doesn't exist, the file can't exist either; walk up to find
	// an existing ancestor.
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		ancestor := dir
		for ancestor != "/" && ancestor != "." {
			ancestor = filepath.Dir(ancestor)
			if _, err := os.Stat(ancestor); err == nil {
				dir = ancestor
				break
			}
		}
	}
	if err := fsw.Add(dir); err != nil {
		_ = fsw.Close()
		return fmt.Errorf("dynamic-denies: watch %q: %w", dir, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel

	go w.loop(ctx, fsw)
	return nil
}

// Stop signals the watcher to shut down + waits up to 2s for the
// goroutine to drain. Safe to call multiple times.
func (w *Watcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
	}
}

// ReloadNow triggers an immediate reload from disk (skipping the
// debounce). Used by the POST /admin/dynamic-denies/reload mgmt-port
// endpoint. The reason flows into the admin-action event so a SIEM
// can distinguish operator-driven reloads from filesystem-triggered
// ones.
func (w *Watcher) ReloadNow(reason ReloadReason) (*RuleSet, error) {
	rs, err := LoadFile(w.path)
	if err != nil {
		w.totalParseErrors.Add(1)
		if w.emit != nil {
			w.emit(ReasonParseError, w.Snapshot(), err)
		}
		w.warnf("dynamic-denies: reload (%s) failed: %v\n", reason, err)
		return w.Snapshot(), err
	}
	w.commitAndDetectTransition(rs, reason)
	return rs, nil
}

// loop is the fsnotify event loop. Filters for events targeting w.path,
// debounces rapid sequential events, applies the resulting reload to
// the in-memory snapshot.
func (w *Watcher) loop(ctx context.Context, fsw *fsnotify.Watcher) {
	defer close(w.done)
	defer fsw.Close()

	var (
		pending      ReloadReason
		pendingTimer *time.Timer
	)
	resetTimer := func(reason ReloadReason) {
		pending = reason
		if pendingTimer != nil {
			pendingTimer.Stop()
		}
		pendingTimer = time.NewTimer(w.debounce)
	}
	timerC := func() <-chan time.Time {
		if pendingTimer == nil {
			return nil
		}
		return pendingTimer.C
	}

	for {
		select {
		case <-ctx.Done():
			if pendingTimer != nil {
				pendingTimer.Stop()
			}
			return
		case err, ok := <-fsw.Errors:
			if !ok {
				return
			}
			w.warnf("dynamic-denies: fsnotify error: %v\n", err)
		case ev, ok := <-fsw.Events:
			if !ok {
				return
			}
			if !w.matchesPath(ev.Name) {
				continue
			}
			reason := classifyEvent(ev)
			if reason == "" {
				continue
			}
			resetTimer(reason)
		case <-timerC():
			pendingTimer = nil
			r := pending
			pending = ""
			w.applyReload(r)
		}
	}
}

// matchesPath reports whether an fsnotify event targets the watched
// file.
func (w *Watcher) matchesPath(p string) bool {
	cleanA := filepath.Clean(p)
	cleanB := filepath.Clean(w.path)
	if cleanA == cleanB {
		return true
	}
	return filepath.Base(cleanA) == filepath.Base(cleanB) &&
		filepath.Dir(cleanA) == filepath.Dir(cleanB)
}

// classifyEvent maps an fsnotify event into a ReloadReason. Returns ""
// for events the watcher doesn't act on (Chmod, etc).
func classifyEvent(ev fsnotify.Event) ReloadReason {
	switch {
	case ev.Op&fsnotify.Create != 0:
		return ReasonFileCreated
	case ev.Op&fsnotify.Write != 0:
		return ReasonFileModified
	case ev.Op&fsnotify.Remove != 0:
		return ReasonFileRemoved
	case ev.Op&fsnotify.Rename != 0:
		return ReasonFileModified
	}
	return ""
}

// applyReload runs a single reload pass + emits the resulting
// admin-action event. Called from the debounce timer goroutine.
func (w *Watcher) applyReload(reason ReloadReason) {
	if reason == ReasonFileRemoved {
		empty := Empty()
		empty.SourcePath = w.path
		empty.LoadedAt = time.Now().UTC()
		w.commitAndDetectTransition(empty, reason)
		return
	}
	rs, err := LoadFile(w.path)
	if err != nil {
		w.totalParseErrors.Add(1)
		if w.emit != nil {
			w.emit(ReasonParseError, w.Snapshot(), err)
		}
		w.warnf("dynamic-denies: %s reload failed (retaining previous %d rule(s)): %v\n",
			reason, len(w.Snapshot().Rules), err)
		return
	}
	w.commitAndDetectTransition(rs, reason)
}

// commitAndDetectTransition is the load-bearing path that swaps in the
// new ruleset + computes the dbounce-specific instance-denied
// transition + emits the standard reload event followed by the
// instance-transition event (when applicable).
//
// Emit order: the standard event ALWAYS fires first (so a SIEM sees
// the underlying reload-reason regardless of whether the transition
// fired). The instance-transition event, when present, fires SECOND
// so an operator filtering for `instance_now_denied` sees both the
// trigger + the resulting state.
func (w *Watcher) commitAndDetectTransition(rs *RuleSet, reason ReloadReason) {
	prevDenied := w.instanceDeniedFlag.Load()
	w.commit(rs)
	w.recomputeInstanceDenied(rs)
	w.totalReloads.Add(1)
	if w.emit != nil {
		w.emit(reason, rs, nil)
	}
	nowDenied := w.instanceDeniedFlag.Load()
	if prevDenied != nowDenied {
		transition := ReasonInstanceNowAllowed
		if nowDenied {
			transition = ReasonInstanceNowDenied
		}
		ruleID, denyReason := w.DenyingRule()
		w.warnf("dynamic-denies: instance transition -> %s (rule_id=%q reason=%q)\n",
			transition, ruleID, denyReason)
		if w.emit != nil {
			w.emit(transition, rs, nil)
		}
	}
}

// commit atomically swaps in the new ruleset.
func (w *Watcher) commit(rs *RuleSet) {
	w.mu.Lock()
	w.rs = rs
	w.mu.Unlock()
}

// recomputeInstanceDenied refreshes the instance-denied flag against
// the given ruleset + the configured upstream identity. Cheap; runs
// O(rules x targets).
func (w *Watcher) recomputeInstanceDenied(rs *RuleSet) {
	if w.instanceUpstream == "" && w.instanceRDSARN == "" {
		// No upstream configured (observation-only) → never denied.
		w.instanceDeniedFlag.Store(false)
		w.denyingMu.Lock()
		w.denyingRuleID = ""
		w.denyingReason = ""
		w.denyingMu.Unlock()
		return
	}
	match := rs.MatchingRule(w.instanceUpstream, w.instanceRDSARN)
	if match == nil {
		w.instanceDeniedFlag.Store(false)
		w.denyingMu.Lock()
		w.denyingRuleID = ""
		w.denyingReason = ""
		w.denyingMu.Unlock()
		return
	}
	w.instanceDeniedFlag.Store(true)
	w.denyingMu.Lock()
	w.denyingRuleID = match.ID
	w.denyingReason = match.Reason
	w.denyingMu.Unlock()
}

// warnf writes a stderr warning. Uses w.stderr when set; falls back to
// os.Stderr otherwise.
func (w *Watcher) warnf(format string, args ...any) {
	target := w.stderr
	if target == nil {
		target = os.Stderr
	}
	fmt.Fprintf(target, format, args...)
}

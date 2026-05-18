// Burst-prompt detector + active-rule sweeper goroutine for
// [[bulk-prompt-answer-ux]].
//
// Closes the "block-happy = uninstalled" failure mode per
// [[safety-mode-lean-permissive]]: when many pending prompts pile up
// in a short window, the operator gets a one-shot affordance to
// resolve the burst en masse (switch profile / time-bounded blanket
// allow / leave one-by-one) rather than facing a wall of per-call
// prompts and bypassing the proxy entirely.
//
// Two responsibilities live here:
//
//  1. BurstDetector — counts pending-prompt enqueues in a sliding
//     window; reports + arms when the threshold trips; re-arms after
//     the operator answers OR after a cool-down. sync.Mutex protected
//     because the proxy's per-conn goroutines all call Record from
//     different threads.
//
//  2. burstSweeper — long-lived background goroutine the Server starts
//     in Serve(); ticks every sweepInterval; calls
//     store.SweepExpiredRules (reaps expired bulk-allow rules) +
//     consumes store.GetProfileOverride (applies hot-swap signals
//     posted by `dbounce prompts bulk-answer --decision profile` via
//     the cross-process SQLite signal). Joined via Server.connWG +
//     ordered AFTER Server.listener.Close() in Shutdown, mirroring
//     the heartbeater shutdown ordering closed in 276298f.
//
// Per [[scorer-is-ground-truth]]: no LLM here. The detector is a
// strict O(window-events) sliding-window counter. The sweeper is a
// fixed-interval ticker.
//
// Per [[creates-never-mutates]]: the sweeper DELETES expired
// dbounce-CREATED time-bounded rules. The audit chain is preserved
// via decisions.matched_rule_id (a column that records the rule id at
// decision time — when the rule is later swept, the audit row's
// matched_rule_id still points at the (now-deleted) numeric id; the
// audit reviewer can still see "decision X matched the bulk-allow
// rule for tuple Y at time T" because the decision row's full reason
// + pattern were stamped at the time the decision was made).

package proxy

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/dbounce/internal/profile"
)

// BurstDetectorDefaults mirror the cross-product defaults in
// [[bulk-prompt-answer-ux]]. N=5 prompts within T=60s arms the
// burst; the operator's next interaction surfaces the bulk-answer
// affordance. Both tunable via Server config.
const (
	DefaultBurstThreshold = 5
	DefaultBurstWindow    = 60 * time.Second
	DefaultBurstCooldown  = 5 * time.Minute
)

// BurstDetector is the proxy-side sliding-window pending-prompt counter.
//
// Concurrency: Record + Snapshot are mutex-guarded so the per-conn
// goroutines in evaluateAndAuditWithAgent can call Record from
// arbitrary threads without coordinating. Snapshot is read-only.
type BurstDetector struct {
	mu           sync.Mutex
	timestamps   []time.Time
	threshold    int
	window       time.Duration
	cooldown     time.Duration
	lastArmed    time.Time
	armedNow     bool
}

// NewBurstDetector constructs a detector with the given threshold +
// window + cooldown. Zero values fall back to the cross-product
// defaults. Returns nil iff threshold <= 0 (caller disabled the burst
// detector explicitly).
func NewBurstDetector(threshold int, window, cooldown time.Duration) *BurstDetector {
	if threshold < 0 {
		return nil
	}
	if threshold == 0 {
		threshold = DefaultBurstThreshold
	}
	if window <= 0 {
		window = DefaultBurstWindow
	}
	if cooldown <= 0 {
		cooldown = DefaultBurstCooldown
	}
	return &BurstDetector{
		threshold: threshold,
		window:    window,
		cooldown:  cooldown,
	}
}

// Record appends a pending-prompt enqueue timestamp + trims any older
// than (now - window). Returns true when the threshold was JUST
// crossed (the caller should fire the BURST_DETECTED event); false
// when below threshold OR the detector is in cool-down. Re-arms after
// cool-down expires.
//
// Per the spec ("one-shot; re-arms after the operator answers OR
// after 5min cool-down"): the cool-down side is the floor. The
// operator-answer side is wired via Reset, called by
// `dbounce prompts bulk-answer` after a successful bulk-resolve.
func (b *BurstDetector) Record(at time.Time) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := at.Add(-b.window)
	// Trim old entries. Slice is small (bounded by threshold + the
	// rate at which prompts arrive within window); linear scan is
	// fine.
	keep := b.timestamps[:0]
	for _, t := range b.timestamps {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	b.timestamps = append(keep, at)
	if b.armedNow {
		// Already armed; no second fire until Reset or cool-down.
		return false
	}
	if !b.lastArmed.IsZero() && at.Sub(b.lastArmed) < b.cooldown {
		// Still in cool-down from the last arming.
		return false
	}
	if len(b.timestamps) >= b.threshold {
		b.armedNow = true
		b.lastArmed = at
		return true
	}
	return false
}

// Snapshot returns the (count-in-window, armed) tuple without
// mutating state. Used by CLI / MCP to render the bulk-answer
// affordance.
func (b *BurstDetector) Snapshot() (int, bool) {
	if b == nil {
		return 0, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.timestamps), b.armedNow
}

// Armed returns true iff the burst detector has fired + the operator
// has not yet acknowledged via Reset. Used by the proxy hot-path to
// decorate the next interactive response with the bulk-answer prompt.
func (b *BurstDetector) Armed() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.armedNow
}

// Reset clears the armed flag + the sliding window. Called by
// `dbounce prompts bulk-answer` after the operator has resolved a
// burst. Idempotent.
func (b *BurstDetector) Reset() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.armedNow = false
	b.timestamps = b.timestamps[:0]
}

// sweepInterval is the burst sweeper's tick cadence. Short enough
// that a hot-swap signal posted by the CLI/MCP gets picked up
// promptly (operator sees the swap within ~5s of running bulk-answer);
// long enough that the goroutine doesn't burn CPU when nothing is
// happening. Not configurable in v1.0 — the audit-cadence discipline
// says ship sane defaults first + add knobs when an operator reports
// the default is wrong.
const sweepInterval = 5 * time.Second

// burstSweeper is the Server's long-lived background goroutine that:
//
//  - reaps expired bulk-allow rules from the rules table
//    (SweepExpiredRules — preserves the audit chain via the
//    decisions.matched_rule_id column)
//  - consumes profile_overrides hot-swap signals + calls SwapProfile
//    to swap the active profile WITHOUT a restart (cross-process
//    signal via SQLite per [[bulk-prompt-answer-ux]])
//
// Lifecycle:
//
//  - Started by Server.Serve via go s.runBurstSweeper(ctx).
//  - Context cancellation is the stop signal. Server.Shutdown
//    cancels the context BEFORE waiting on connWG so the sweeper
//    drains its final tick promptly (matches the heartbeater
//    shutdown-ordering pattern closed in 276298f).
//  - Joins via the same connWG the per-conn handlers use so
//    Shutdown's existing drain semantics naturally cover us.
func (s *Server) runBurstSweeper(ctx context.Context) {
	s.connWG.Add(1)
	defer s.connWG.Done()
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.sweepExpiredRulesOnce(now)
			s.applyProfileOverrideOnce()
		}
	}
}

// sweepExpiredRulesOnce reaps expired rules. Logged at debug to keep
// the production log quiet when no rules are expiring.
func (s *Server) sweepExpiredRulesOnce(_ time.Time) {
	if s.store == nil {
		return
	}
	n, err := s.store.SweepExpiredRules()
	if err != nil {
		BumpLookupErrors()
		log.Warn().Err(err).Msg("dbounce: sweep expired rules failed")
		return
	}
	if n > 0 {
		log.Info().Int64("reaped", n).
			Msg("dbounce: burst sweeper reaped expired bulk-allow rules")
	}
}

// applyProfileOverrideOnce consumes the profile_overrides table. When
// non-empty + the named profile loads cleanly, calls Server.SwapProfile
// + clears the override row. Errors are logged + the override row is
// LEFT IN PLACE so the operator can debug rather than silently
// dropping the request.
func (s *Server) applyProfileOverrideOnce() {
	if s.store == nil {
		return
	}
	pending, err := s.store.GetProfileOverride()
	if err != nil {
		BumpLookupErrors()
		log.Warn().Err(err).Msg("dbounce: read profile override failed")
		return
	}
	if pending == nil {
		return
	}
	// Already on the requested profile? Clear the signal + no-op.
	current := s.ActiveProfileName()
	if current == pending.ProfileName {
		if cerr := s.store.ClearProfileOverride(); cerr != nil {
			log.Warn().Err(cerr).Msg("dbounce: clear profile override (no-op swap) failed")
		}
		return
	}
	// Resolve the requested profile from the profiles file the proxy
	// was started with. The Server holds onto its profiles path so the
	// hot-swap loads from the SAME source the operator started with
	// (not a different profiles.yaml that a parallel CLI invocation
	// might be pointing at).
	profilesPath := s.profilesPath
	profiles, perr := profile.LoadProfiles(profilesPath)
	if perr != nil {
		log.Warn().Err(perr).Str("path", profilesPath).
			Msg("dbounce: load profiles for hot-swap failed (leaving override pending)")
		return
	}
	newProfile, aerr := profiles.Active(pending.ProfileName)
	if aerr != nil || newProfile == nil {
		log.Warn().Err(aerr).Str("profile", pending.ProfileName).
			Msg("dbounce: requested profile not found (leaving override pending)")
		return
	}
	s.SwapProfile(newProfile)
	log.Info().Str("from", current).Str("to", newProfile.Name).
		Str("by", pending.SetBy).Str("reason", pending.Reason).
		Msg("dbounce: hot-swapped active profile via bulk-answer override")
	if cerr := s.store.ClearProfileOverride(); cerr != nil {
		log.Warn().Err(cerr).Msg("dbounce: clear profile override after swap failed")
	}
}

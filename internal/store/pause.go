// Pause-window helpers for D-Slice 8.
//
// The pause_events table was scaffolded in store.go's migrate() at
// D-Slice 1 time. This file adds the Go-API around it.
//
// Mirrors kbounce's + ibounce's pause shape: a single active window
// per machine (any second active-start auto-ends the first one with
// end_kind="superseded"), wall-clock expiry handled in GetActivePause
// (idempotent: every call GCs expired rows), and a history list that
// answers "what pauses fired recently and why?" without leaking the
// underlying SQLite shape.
//
// Composition with the decision pipeline (see internal/proxy/decide.go):
//   - IsPaused() returns true ⇒ proxy.decide() demotes any transparent-
//     mode DENY to an ALLOW with audit-row pause_id set + Enforced=false.
//   - The audit row keeps the original DecisionVerdict the rule engine
//     produced so post-incident review can answer "what would have been
//     blocked had the pause not been active?"
//
// Per [[safety-mode-lean-permissive]] this pause primitive IS the
// emergency escape hatch: an admin doing live demos / oncall debugging
// can flip the gate off for a bounded window without redeploying, and
// every action that happened during the window is still in the audit
// log.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// StartPause inserts a new pause window. When a previous pause is
// still active the previous row is closed out with end_kind="superseded"
// BEFORE the new row lands — the invariant is "at most one active
// pause." Caller passes ttl (must be > 0); the wall-clock end is
// computed now + ttl.
//
// Returns the new row's id + the wall-clock end timestamp the row was
// stamped with.
func (s *Store) StartPause(reason, startedBy string, ttl time.Duration) (int64, time.Time, error) {
	if ttl <= 0 {
		return 0, time.Time{}, fmt.Errorf("dbounce: StartPause: ttl must be > 0 (got %v)", ttl)
	}
	if startedBy == "" {
		return 0, time.Time{}, fmt.Errorf("dbounce: StartPause: started_by is required")
	}
	now := time.Now().UTC()
	ends := now.Add(ttl)
	startStr := now.Format("2006-01-02T15:04:05Z")
	endStr := ends.Format("2006-01-02T15:04:05Z")

	// Close out any active row first. end_kind="superseded" so
	// reviewers can distinguish "operator started a fresh pause while
	// one was running" from "operator ran stop". SELECT-first so we
	// know which rows we're about to supersede + can enqueue the
	// matching ADMIN_FALLBACK_END synthetic events (best-effort:
	// enqueue failure does NOT block the new-pause path because the
	// synthetic is observability metadata, not a gating signal).
	prior, perr := s.db.Query(
		`SELECT id, COALESCE(reason, ''), started_by
		 FROM pause_events
		 WHERE ended_at_actual IS NULL`,
	)
	if perr != nil {
		return 0, time.Time{}, fmt.Errorf("dbounce: supersede active pause: select: %w", perr)
	}
	type priorRow struct {
		id        int64
		reason    string
		startedBy string
	}
	var supersededRows []priorRow
	for prior.Next() {
		var r priorRow
		if err := prior.Scan(&r.id, &r.reason, &r.startedBy); err != nil {
			_ = prior.Close()
			return 0, time.Time{}, fmt.Errorf("dbounce: supersede active pause: scan: %w", err)
		}
		supersededRows = append(supersededRows, r)
	}
	if err := prior.Err(); err != nil {
		_ = prior.Close()
		return 0, time.Time{}, fmt.Errorf("dbounce: supersede active pause: iterate: %w", err)
	}
	_ = prior.Close()

	if _, err := s.db.Exec(
		`UPDATE pause_events SET ended_at_actual = ?, end_kind = 'superseded'
		 WHERE ended_at_actual IS NULL`,
		startStr,
	); err != nil {
		return 0, time.Time{}, fmt.Errorf("dbounce: supersede active pause: %w", err)
	}
	for _, r := range supersededRows {
		payload := buildAdminFallbackEndPayload(r.id, r.startedBy, r.reason, "superseded")
		_, _ = s.AddPendingAuditEvent(
			PendingAuditEventAdminFallbackEnd, payload)
	}

	res, err := s.db.Exec(
		`INSERT INTO pause_events(started_at, ends_at, reason, started_by)
		 VALUES (?, ?, ?, ?)`,
		startStr, endStr, reason, startedBy,
	)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("dbounce: insert pause: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("dbounce: pause last insert id: %w", err)
	}
	return id, ends, nil
}

// StopPause ends the currently-active pause window (if any). Returns
// the pause id that was ended, or (0, nil) when no pause was active.
//
// end_kind="manual" so reviewers can distinguish from "expired" (TTL
// ran out) and "superseded" (a fresh pause overwrote it).
//
// Side effect per [[security-team-audit-export]]: enqueues an
// ADMIN_FALLBACK_END pending audit event so the run-process's drain
// loop picks it up + emits through the wired Exporter / RuleEngine.
// `dbounce pause stop` runs in a separate process from `dbounce run`
// — the SQLite queue is the cross-process channel. Best-effort:
// enqueue failure does NOT block the user-facing pause-stop because
// the synthetic is observability metadata, not a gating signal.
// endedBy is recorded in the payload's started_by field for symmetry
// with the open-event; future schema work may add an ended_by field.
func (s *Store) StopPause(endedBy string) (int64, error) {
	active, err := s.GetActivePause()
	if err != nil {
		return 0, err
	}
	if active == nil {
		return 0, nil
	}
	endStr := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if _, err := s.db.Exec(
		`UPDATE pause_events SET ended_at_actual = ?, end_kind = 'manual'
		 WHERE id = ? AND ended_at_actual IS NULL`,
		endStr, active.ID,
	); err != nil {
		return 0, fmt.Errorf("dbounce: stop pause: %w", err)
	}
	payload := buildAdminFallbackEndPayload(
		active.ID, active.StartedBy, active.Reason, "manual")
	_, _ = s.AddPendingAuditEvent(
		PendingAuditEventAdminFallbackEnd, payload)
	_ = endedBy // recorded in pause history via the row already; reserved
	return active.ID, nil
}

// IsPaused returns (paused, pauseID, error). When paused == true,
// pauseID is the id of the active pause for the audit-row pause_id
// column. Composes the GC + lookup that GetActivePause already does.
//
// Used by the proxy's decide() loop on every statement; keep cheap.
// The query is a single indexed lookup (idx_pause_events_ends_at).
func (s *Store) IsPaused() (bool, int64, error) {
	active, err := s.GetActivePause()
	if err != nil {
		return false, 0, err
	}
	if active == nil {
		return false, 0, nil
	}
	return true, active.ID, nil
}

// PauseHistoryEntry is one row in PauseHistory's return value.
type PauseHistoryEntry struct {
	ID            int64
	StartedAt     string
	EndsAt        string
	Reason        string
	StartedBy     string
	EndedAtActual string
	EndKind       string
}

// PauseHistory returns the most recent N pause windows (active + ended)
// newest-first. limit <= 0 defaults to 20; capped at 200.
func (s *Store) PauseHistory(limit int) ([]PauseHistoryEntry, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	// GC expired rows so the history view doesn't show stale "active"
	// pauses. Mirrors GetActivePause.
	nowStr := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if _, err := s.db.Exec(
		`UPDATE pause_events SET ended_at_actual = ends_at, end_kind = 'expired'
		 WHERE ended_at_actual IS NULL AND ends_at <= ?`,
		nowStr,
	); err != nil {
		return nil, fmt.Errorf("dbounce: gc expired pauses: %w", err)
	}
	rows, err := s.db.Query(
		`SELECT id, started_at, ends_at, reason, started_by,
		        COALESCE(ended_at_actual, ''), COALESCE(end_kind, '')
		 FROM pause_events ORDER BY id DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("dbounce: pause history query: %w", err)
	}
	defer rows.Close()
	out := make([]PauseHistoryEntry, 0, limit)
	for rows.Next() {
		var e PauseHistoryEntry
		if err := rows.Scan(&e.ID, &e.StartedAt, &e.EndsAt, &e.Reason,
			&e.StartedBy, &e.EndedAtActual, &e.EndKind); err != nil {
			return nil, fmt.Errorf("dbounce: pause history scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dbounce: pause history iterate: %w", err)
	}
	return out, nil
}

// ErrNoActivePause is returned by StopPause callers that want to
// distinguish "no-op" from real errors. (StopPause itself returns
// (0, nil) — this constant is for higher-level wrappers that want to
// surface a typed error.)
var ErrNoActivePause = errors.New("dbounce: no active pause")

// Silence the unused-import linter when sql isn't otherwise needed at
// package scope (it's needed by other files in the package, but the
// build picks per-file).
var _ = sql.ErrNoRows

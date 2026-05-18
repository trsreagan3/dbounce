// Cross-process audit-event queue helpers per
// [[security-team-audit-export]] Slice 2 wiring.
//
// `dbounce pause stop` and `dbounce profile install` run in separate
// processes from `dbounce run`. The synthetic ADMIN_FALLBACK_END /
// PROFILE_INSTALLED events those commands originate cannot be emitted
// directly through the run-process's Exporter / RuleEngine (the
// CLI process has neither wired). Instead each CLI APPENDS a row to
// `pending_audit_events` here, and the run-process's burst-sweeper
// goroutine drains the table on its sweep tick + emits each row
// through its in-process Exporter / RuleEngine.
//
// Why a SQLite queue rather than a fresh per-process exporter:
//
//   1. Single emit path. The run-process is the only writer to the
//      operator's configured audit-log file + the only client of the
//      webhook URL. A second exporter in the CLI would double-write
//      to the log (or worse, double-POST to the webhook with
//      ordering ambiguity).
//
//   2. Matches the existing cross-process pattern. The
//      `profile_overrides` table + the burst-sweeper's
//      applyProfileOverrideOnce already use this exact shape (CLI
//      writes, run-process polls every 5s + drains). The audit-event
//      poll runs at a faster cadence (1s) because the rows are
//      operator-facing lifecycle signals that the SIEM expects
//      promptly + bounded queue depth is naturally tiny.
//
//   3. Zero new third-party deps. Pure SQL on the existing
//      modernc.org/sqlite driver, same connection pool, same
//      synchronous=FULL durability guarantee.
//
// Per [[scorer-is-ground-truth]]: this queue NEVER carries decision
// rows. Decisions go directly through the run-process's Exporter on
// the proxy hot-path. This queue is for cross-process LIFECYCLE
// events only.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PendingAuditEventKind names the synthetic-event kind a CLI process
// enqueued. Sibling agents in ibounce + kbounce ship the same kind
// strings under the same payload shape so the run-process drain code
// in all three products reads identically.
type PendingAuditEventKind string

const (
	// PendingAuditEventAdminFallbackEnd corresponds to
	// audit.EventTypeAdminFallbackEnd. Emitted by `dbounce pause stop`
	// after StopPause + by the GetActivePause expiry-GC path (whichever
	// process triggers the GC). payload_json carries
	// {pause_id, started_by, reason, end_kind} so the drain side can
	// rebuild the audit.AdminFallbackInfo without a JOIN against
	// pause_events.
	PendingAuditEventAdminFallbackEnd PendingAuditEventKind = "admin_fallback_end"

	// PendingAuditEventProfileInstalled corresponds to
	// audit.EventTypeProfileInstalled. Emitted by `dbounce profile
	// install --from URL` after a successful install. payload_json
	// carries {source_url, profile_names, sha256, sha256_verified,
	// profiles_path, installed_by, dialects} so the drain side can
	// rebuild the audit.ProfileInstalledInfo AND fire the Slice 2
	// RuleEngine.ObserveProfileInstall hook (non-org-source alert).
	PendingAuditEventProfileInstalled PendingAuditEventKind = "profile_installed"
)

// PendingAuditEvent is one queued row. The CLI side constructs +
// AddPendingAuditEvent; the run-process drains via
// DrainPendingAuditEvents + emits per Kind.
type PendingAuditEvent struct {
	ID          int64
	CreatedAt   time.Time
	Kind        PendingAuditEventKind
	PayloadJSON string
}

// AddPendingAuditEvent appends a row to the cross-process queue.
// payloadJSON MUST be a well-formed JSON object string the run-process
// side knows how to parse for this Kind. Returns the new row id.
//
// CLI callers are encouraged to log a debug line on a non-nil error
// rather than fail the user-facing operation — a missing audit row is
// strictly less harmful than blocking a `pause stop` / `profile
// install` the operator expects to succeed.
func (s *Store) AddPendingAuditEvent(kind PendingAuditEventKind, payloadJSON string) (int64, error) {
	if kind == "" {
		return 0, errors.New("dbounce: AddPendingAuditEvent: kind required")
	}
	if payloadJSON == "" {
		payloadJSON = "{}"
	}
	createdAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	res, err := s.db.Exec(
		`INSERT INTO pending_audit_events(created_at, kind, payload_json)
		 VALUES (?, ?, ?)`,
		createdAt, string(kind), payloadJSON,
	)
	if err != nil {
		return 0, fmt.Errorf("dbounce: insert pending audit event: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("dbounce: pending audit event last insert id: %w", err)
	}
	return id, nil
}

// DrainPendingAuditEvents reads up to maxBatch rows in id-ascending
// order + DELETEs them in the same transaction so a race against a
// second drainer never double-emits. limit <= 0 defaults to 256 (a
// generous ceiling — typical depth is 0 or 1; the cap defends against
// runaway growth in a degraded state where the drain loop fell
// behind).
//
// Returns the drained rows. The run-process caller iterates + emits
// through its Exporter / RuleEngine.
//
// Idempotency note: the DELETE happens BEFORE we return the rows, so a
// crash between the SELECT and the actual emit loses those events.
// This is the right trade-off vs. "DELETE after emit" (which would
// re-emit on restart, multiplying alert noise). The CLI side persists
// the row durably (synchronous=FULL via the DSN); a crash window
// during drain is the only loss surface + that window is small (a
// single SQLite txn).
func (s *Store) DrainPendingAuditEvents(maxBatch int) ([]PendingAuditEvent, error) {
	if maxBatch <= 0 {
		maxBatch = 256
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("dbounce: drain pending audit events: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.Query(
		`SELECT id, created_at, kind, payload_json
		 FROM pending_audit_events
		 ORDER BY id ASC
		 LIMIT ?`, maxBatch,
	)
	if err != nil {
		return nil, fmt.Errorf("dbounce: drain pending audit events: query: %w", err)
	}
	out := make([]PendingAuditEvent, 0, 8)
	var ids []int64
	for rows.Next() {
		var (
			id        int64
			createdAt string
			kind      string
			payload   string
		)
		if err := rows.Scan(&id, &createdAt, &kind, &payload); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("dbounce: drain pending audit events: scan: %w", err)
		}
		t, _ := time.Parse("2006-01-02T15:04:05Z", createdAt)
		out = append(out, PendingAuditEvent{
			ID:          id,
			CreatedAt:   t,
			Kind:        PendingAuditEventKind(kind),
			PayloadJSON: payload,
		})
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("dbounce: drain pending audit events: iterate: %w", err)
	}
	_ = rows.Close()
	if len(ids) == 0 {
		// Nothing to delete — commit the empty txn + return.
		if cerr := tx.Commit(); cerr != nil {
			return nil, fmt.Errorf("dbounce: drain pending audit events: commit empty: %w", cerr)
		}
		return nil, nil
	}
	// Build the DELETE statement with one placeholder per drained id.
	// SQLite caps to ~999 by default — we already cap maxBatch at 256
	// above so we are well clear of the limit.
	placeholders := make([]byte, 0, 2*len(ids))
	args := make([]any, 0, len(ids))
	for i, id := range ids {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		args = append(args, id)
	}
	delQuery := `DELETE FROM pending_audit_events WHERE id IN (` + string(placeholders) + `)`
	if _, err := tx.Exec(delQuery, args...); err != nil {
		return nil, fmt.Errorf("dbounce: drain pending audit events: delete: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("dbounce: drain pending audit events: commit: %w", err)
	}
	return out, nil
}

// PendingAuditEventDepth returns the current queue depth. Surfaced for
// the burst-sweeper's debug logging + tests that want to assert the
// drain behavior without scraping output. Read-only — does not GC.
func (s *Store) PendingAuditEventDepth() (int, error) {
	row := s.db.QueryRow(`SELECT COUNT(*) FROM pending_audit_events`)
	var n int
	if err := row.Scan(&n); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("dbounce: pending audit event depth: %w", err)
	}
	return n, nil
}

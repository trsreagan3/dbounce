// Bulk-prompt-answer UX store helpers per [[bulk-prompt-answer-ux]].
//
// Cross-product (ibounce / kbounce / dbounce) feature that closes the
// "block-happy = uninstalled" failure mode per
// [[safety-mode-lean-permissive]]. When N pending prompts accumulate
// in a short window, the operator can opt into:
//
//   - --decision profile --profile NAME     hot-swap to a broader profile
//   - --decision 10min                      time-bounded blanket allow
//   - --decision 3h                         longer time-bounded allow
//   - --decision session                    until proxy restart / 60min idle
//   - --decision none                       no-op (existing one-by-one flow)
//
// This file owns the persistence shape: pending-prompt aggregation
// across (dialect, statement_type, table) for the rule-synthesis step,
// the profile_overrides single-row table for cross-process hot-swap,
// and a small `ListPendingPromptsWithDialect` join helper so the CLI /
// MCP tool can build per-dialect bulk-allow rules.
//
// Per [[scorer-is-ground-truth]]: this file ONLY persists state; the
// composition + scoring side runs in the proxy + CLI. No LLM, no
// inference: the burst snapshot is a deterministic JOIN.
//
// Per [[creates-never-mutates]]: bulk-answer CREATES new time-bounded
// rules + answers existing pending prompts. It NEVER modifies historical
// audit rows; the decisions table remains append-only.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// BulkPromptKey groups pending prompts by the tuple the rule
// synthesizer will use. Per the spec: "(service, action, optional
// resource glob)" — adapted to SQL as (dialect, statement_type, table).
// Per-dialect grouping is load-bearing — a PG burst's bulk-allow rule
// MUST NOT spill into MySQL traffic and vice versa, because the
// statement-type vocab differs subtly across dialects.
type BulkPromptKey struct {
	// Dialect is the wire dialect of the decision the prompt was
	// enqueued from ("postgres" / "mysql"). Comes from the JOIN
	// against decisions.dialect.
	Dialect string
	// StatementType is the parser classifier output (SELECT / INSERT /
	// UPDATE / DELETE / DDL / CALL / ...). Per the cross-product
	// design, the rule-synthesizer keys on this so the resulting rule
	// is a tight allow for "what was being denied" rather than a broad
	// MUTATING:* shape.
	StatementType string
	// Table is the schema-qualified table identifier the statement
	// touched, or "*" when the statement touched no tables (e.g. DO
	// blocks, SET ROLE). Per spec: "covers each dialect's matching
	// patterns separately."
	Table string
}

// BulkPendingEntry is one entry of the burst summary: a tuple +
// the pending-prompt IDs that match it. The rule-synthesizer creates
// ONE rule per BulkPendingEntry; the bulk-answer marks every PromptID
// in the entry as answered with answer_kind="bulk-{decision}".
type BulkPendingEntry struct {
	Key       BulkPromptKey
	PromptIDs []int64
	// SampleReason carries the first deny_reason in the bucket so the
	// CLI's pre-answer summary can show "what was blocked" without
	// emitting all of them. Capped at 200 chars upstream of the caller.
	SampleReason string
}

// BulkPendingSummary is the full burst view: every pending prompt
// grouped into (dialect, statement_type, table) buckets, sorted by
// dialect then statement_type then table for stable presentation.
type BulkPendingSummary struct {
	// Entries is the per-tuple grouping. Stable order.
	Entries []BulkPendingEntry
	// TotalPrompts is the count of pending prompts in the burst window
	// (sum of len(entry.PromptIDs) across all entries).
	TotalPrompts int
	// Dialects is the deduplicated set of dialects represented in this
	// burst. When > 1, the rule-synthesizer emits per-dialect rules
	// rather than a single dialect-agnostic rule. Sorted.
	Dialects []string
}

// ListBulkPendingPrompts returns a snapshot of all currently-pending
// prompts joined against decisions.dialect, grouped by
// (dialect, statement_type, table). One pending prompt contributes to
// each of its touched-tables (or once with table="*" when no tables).
// Used by `dbounce prompts bulk-answer` + the dbounce_prompts_bulk_pending
// MCP tool to build the burst summary.
//
// "Pending" = status='pending' AND (sync_wait_id IS NULL OR the
// waiter is still live in the registry — but we surface ALL pending
// rows here; the bulk-answer path will WakeSyncPendingPrompt for any
// rows that have a registered sync waiter).
//
// Bounded at 500 rows (same cap as ListPendingPrompts) so a runaway
// burst can't materialize a multi-MB result set in process memory.
func (s *Store) ListBulkPendingPrompts() (*BulkPendingSummary, error) {
	rows, err := s.db.Query(
		`SELECT p.id, p.statement_type, p.tables_json, p.deny_reason,
		        COALESCE(d.dialect, '')
		 FROM pending_prompts p
		 LEFT JOIN decisions d ON p.decision_id = d.id
		 WHERE p.status = 'pending'
		 ORDER BY p.id DESC
		 LIMIT 500`)
	if err != nil {
		return nil, fmt.Errorf("dbounce: list bulk pending prompts: %w", err)
	}
	defer rows.Close()
	buckets := make(map[BulkPromptKey]*BulkPendingEntry)
	dialectSet := make(map[string]struct{})
	total := 0
	for rows.Next() {
		var (
			id         int64
			stmtType   string
			tablesJSON string
			reason     string
			dialect    string
		)
		if err := rows.Scan(&id, &stmtType, &tablesJSON, &reason, &dialect); err != nil {
			return nil, fmt.Errorf("dbounce: list bulk pending prompts scan: %w", err)
		}
		total++
		tables := unmarshalStrings(tablesJSON)
		if len(tables) == 0 {
			tables = []string{"*"}
		}
		// Normalize empty statement_type to "*" so the resulting rule
		// is a permissive (*:table) pattern rather than an invalid one.
		stmt := stmtType
		if stmt == "" {
			stmt = "*"
		}
		// Normalize empty dialect to "postgres" (the v1.0 default + the
		// most-common case). A missing dialect can only happen when the
		// FK-joined decisions row is gone (impossible today given
		// MED-D8-07's append-only trigger + MED-D8-08's FK enforcement);
		// the default keeps the rule synthesizable rather than dropping
		// the prompt on the floor.
		dl := dialect
		if dl == "" {
			dl = "postgres"
		}
		dialectSet[dl] = struct{}{}
		for _, tbl := range tables {
			key := BulkPromptKey{
				Dialect:       dl,
				StatementType: stmt,
				Table:         tbl,
			}
			entry := buckets[key]
			if entry == nil {
				entry = &BulkPendingEntry{
					Key:          key,
					SampleReason: truncateReason(reason),
				}
				buckets[key] = entry
			}
			// Dedup by promptID — a prompt that touches the same table
			// twice should only count once per (dialect, stmt, table)
			// bucket.
			already := false
			for _, existing := range entry.PromptIDs {
				if existing == id {
					already = true
					break
				}
			}
			if !already {
				entry.PromptIDs = append(entry.PromptIDs, id)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dbounce: list bulk pending prompts iterate: %w", err)
	}
	entries := make([]BulkPendingEntry, 0, len(buckets))
	for _, e := range buckets {
		entries = append(entries, *e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Key.Dialect != entries[j].Key.Dialect {
			return entries[i].Key.Dialect < entries[j].Key.Dialect
		}
		if entries[i].Key.StatementType != entries[j].Key.StatementType {
			return entries[i].Key.StatementType < entries[j].Key.StatementType
		}
		return entries[i].Key.Table < entries[j].Key.Table
	})
	dialects := make([]string, 0, len(dialectSet))
	for d := range dialectSet {
		dialects = append(dialects, d)
	}
	sort.Strings(dialects)
	return &BulkPendingSummary{
		Entries:      entries,
		TotalPrompts: total,
		Dialects:     dialects,
	}, nil
}

// AnswerPendingPromptsBulk stamps every promptID with the given
// answer_kind / answer_target / answered_by atomically (one
// transaction). Returns the number of rows actually updated (some IDs
// may already have been answered by a concurrent CLI session — the
// caller should treat that as a no-op for those IDs, not an error).
//
// Sync waiters: this function does NOT WakeSyncPendingPrompt — the
// caller (CLI / MCP tool) owns the wakeup loop so the answer-kind →
// PromptDecision mapping stays in one place (matching the existing
// per-prompt answer flow in cli/prompts.go).
func (s *Store) AnswerPendingPromptsBulk(promptIDs []int64, kind, target, by string) (int64, error) {
	if len(promptIDs) == 0 {
		return 0, nil
	}
	if kind == "" {
		return 0, errors.New("dbounce: AnswerPendingPromptsBulk: kind required")
	}
	status := string(PromptAnswered)
	if kind == "ignore" || kind == "bulk-ignore" {
		status = string(PromptIgnored)
	}
	answeredAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("dbounce: bulk-answer begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(
		`UPDATE pending_prompts
		 SET status = ?, answer_kind = ?, answer_target = ?,
		     answered_by = ?, answered_at = ?
		 WHERE id = ? AND status = 'pending'`)
	if err != nil {
		return 0, fmt.Errorf("dbounce: bulk-answer prepare: %w", err)
	}
	defer stmt.Close()
	var updated int64
	for _, id := range promptIDs {
		res, eerr := stmt.Exec(status, kind, target, by, answeredAt, id)
		if eerr != nil {
			return 0, fmt.Errorf("dbounce: bulk-answer exec (id=%d): %w", id, eerr)
		}
		n, _ := res.RowsAffected()
		updated += n
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("dbounce: bulk-answer commit: %w", err)
	}
	return updated, nil
}

// SyncWaitIDsForPromptIDs returns the (promptID → sync_wait_id) map
// for the given prompt IDs, omitting any IDs whose row is missing or
// whose sync_wait_id is NULL. Used by the CLI / MCP bulk-answer path
// to fire WakeSyncPendingPrompt on each sync-blocked waiter after the
// bulk UPDATE has persisted.
//
// Bounded at 500 IDs (matches ListBulkPendingPrompts row cap). Larger
// inputs are truncated rather than rejected — the bulk-answer call
// already wrote the answer to disk; this is the optional wakeup side.
func (s *Store) SyncWaitIDsForPromptIDs(promptIDs []int64) (map[int64]string, error) {
	if len(promptIDs) == 0 {
		return nil, nil
	}
	if len(promptIDs) > 500 {
		promptIDs = promptIDs[:500]
	}
	placeholders := make([]string, 0, len(promptIDs))
	params := make([]any, 0, len(promptIDs))
	for _, id := range promptIDs {
		placeholders = append(placeholders, "?")
		params = append(params, id)
	}
	query := `SELECT id, COALESCE(sync_wait_id, '')
	          FROM pending_prompts
	          WHERE id IN (` + strings.Join(placeholders, ",") + `)`
	rows, err := s.db.Query(query, params...)
	if err != nil {
		return nil, fmt.Errorf("dbounce: sync-wait IDs query: %w", err)
	}
	defer rows.Close()
	out := make(map[int64]string)
	for rows.Next() {
		var (
			id      int64
			waitID  string
		)
		if err := rows.Scan(&id, &waitID); err != nil {
			return nil, fmt.Errorf("dbounce: sync-wait IDs scan: %w", err)
		}
		if waitID != "" {
			out[id] = waitID
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dbounce: sync-wait IDs iterate: %w", err)
	}
	return out, nil
}

// ProfileOverride is the single-row hot-swap signal per
// [[bulk-prompt-answer-ux]]. When SetProfileOverride writes a row, the
// running proxy's burst-sweeper goroutine sees it on its next tick,
// re-loads the profiles.yaml, and calls Server.SwapProfile to take the
// override live. On successful swap the sweeper calls
// ClearProfileOverride so a stale override row can't pin the next
// process.
//
// Cross-process correct: every dbounce process consults the same
// SQLite DB (the CLI + MCP server + the running proxy share state.db).
// The proxy is the only writer to "applied"; the CLI / MCP server are
// the writers to "pending."
type ProfileOverride struct {
	ProfileName string
	SetAt       time.Time
	SetBy       string
	Reason      string
}

// SetProfileOverride writes the hot-swap signal. UPSERT: the override
// row's id is always 1; a second SetProfileOverride atomically
// overwrites the previous. The proxy picks it up on its next sweeper
// tick (default 5s — fast enough for an operator who just answered to
// see the change without restarting; slow enough that the sweeper
// goroutine doesn't burn CPU).
func (s *Store) SetProfileOverride(profileName, by, reason string) error {
	if profileName == "" {
		return errors.New("dbounce: SetProfileOverride: profile_name required")
	}
	setAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	_, err := s.db.Exec(
		`INSERT INTO profile_overrides(id, profile_name, set_at, set_by, reason)
		 VALUES (1, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   profile_name = excluded.profile_name,
		   set_at       = excluded.set_at,
		   set_by       = excluded.set_by,
		   reason       = excluded.reason`,
		profileName, setAt, by, reason)
	if err != nil {
		return fmt.Errorf("dbounce: set profile override: %w", err)
	}
	return nil
}

// GetProfileOverride returns the pending hot-swap signal, or (nil, nil)
// when none is set. Read by the proxy's burst-sweeper goroutine on
// every tick.
func (s *Store) GetProfileOverride() (*ProfileOverride, error) {
	row := s.db.QueryRow(
		`SELECT profile_name, set_at, set_by, reason
		 FROM profile_overrides WHERE id = 1`)
	var (
		profileName string
		setAtStr    string
		setBy       string
		reason      string
	)
	if err := row.Scan(&profileName, &setAtStr, &setBy, &reason); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("dbounce: get profile override: %w", err)
	}
	setAt, _ := time.Parse("2006-01-02T15:04:05Z", setAtStr)
	return &ProfileOverride{
		ProfileName: profileName,
		SetAt:       setAt,
		SetBy:       setBy,
		Reason:      reason,
	}, nil
}

// ClearProfileOverride removes the hot-swap signal. Called by the
// proxy after it has applied the override. Idempotent: clearing an
// already-empty table is a no-op.
func (s *Store) ClearProfileOverride() error {
	_, err := s.db.Exec(`DELETE FROM profile_overrides WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("dbounce: clear profile override: %w", err)
	}
	return nil
}

func truncateReason(reason string) string {
	if len(reason) <= 200 {
		return reason
	}
	return reason[:197] + "..."
}

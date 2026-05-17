// Pending-prompts helpers for D-Slice 8.
//
// The pending_prompts table was scaffolded in store.go's migrate() at
// D-Slice 1 time. This file adds the Go-API around it.
//
// Mirrors kbounce's + ibounce's async-prompt UX: when a transparent
// DENY happens with --prompt-on-deny enabled, the proxy enqueues a row
// here (instead of blocking the wire-protocol call waiting for an
// operator answer; the SQL client times out on the wire long before
// the human gets to the terminal). The operator runs
// `dbounce prompts list` later to drain the queue and answer each one
// with `dbounce prompts answer ID --kind {ignore|always|profile}`.
//
// answer_kind values + their semantics:
//
//   "ignore"  — record the operator's decision; no rule/profile change.
//                The decision-source label tells future audits "this
//                was reviewed and intentionally not acted on."
//   "always"  — append a global ALLOW rule for the same statement_type
//                + table pattern (so future requests of this shape
//                won't enqueue another prompt). Equivalent to the
//                operator running `dbounce rules add`.
//   "profile" — synthesize a profile from the prompt context. Caller
//                injects a ProfileWriter at command-construction time
//                (the actual profile package lives in D-Slice 7; this
//                file keeps no dependency on it).
//
// Per [[creates-never-mutates]]: this package PERSISTS prompt state +
// answers; the proxy NEVER blocks a wire-protocol call waiting on a
// human, and the proxy NEVER modifies the customer's database. Prompts
// are an out-of-band review channel.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// PromptDecision is the wakeup signal a sync-prompt-blocked request
// goroutine receives from `dbounce prompts answer`. Drives the proxy's
// "forward to upstream OR return SQL error" branch on the unblock.
//
// #203 (synchronous deny-prompt v1.1) — three values:
//
//   - PromptDecisionAllow  — answer was 'always' or 'profile' (the
//     operator approved); proxy forwards the original SQL bytes to
//     the upstream + relays the response.
//   - PromptDecisionDeny   — answer was 'ignore' (the operator chose
//     not to allow); proxy emits the original deny ErrorResponse.
//   - PromptDecisionTimeout — no answer arrived inside the timeout;
//     proxy applies --sync-prompt-default (allow|deny). Distinct from
//     Deny so audit-log analytics can ask "how often does timeout
//     fire?" without parsing reason text.
type PromptDecision string

const (
	PromptDecisionAllow   PromptDecision = "allow"
	PromptDecisionDeny    PromptDecision = "deny"
	PromptDecisionTimeout PromptDecision = "timeout"
)

// syncWaiters is the in-memory map from sync_wait_id UUID → wakeup
// channel. Populated by AddSyncPendingPrompt; drained by
// WakeSyncPendingPrompt. Lost on process restart — the request
// goroutine that owned the channel is also dead, so the loss is
// symmetric (no orphan channels, no zombie waiters). Mutex-guarded so
// the answer path can safely race the request path.
type syncWaiter struct {
	ch        chan PromptDecision
	promptID  int64
	createdAt time.Time
}

// syncWaiterRegistry is per-Store so multiple Open() calls in the same
// process (rare; tests use it) don't share runtime state.
type syncWaiterRegistry struct {
	mu       sync.Mutex
	waiters  map[string]*syncWaiter
}

func newSyncWaiterRegistry() *syncWaiterRegistry {
	return &syncWaiterRegistry{waiters: make(map[string]*syncWaiter)}
}

func (r *syncWaiterRegistry) add(waitID string, w *syncWaiter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.waiters[waitID] = w
}

func (r *syncWaiterRegistry) remove(waitID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.waiters, waitID)
}

// take atomically retrieves + removes a waiter. Returns nil when the
// id is unknown (already removed by timeout/cancel, or never existed).
func (r *syncWaiterRegistry) take(waitID string) *syncWaiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	w := r.waiters[waitID]
	if w != nil {
		delete(r.waiters, waitID)
	}
	return w
}

// snapshotIDs returns the currently-waiting wait IDs. Used by the MCP
// tool `dbounce_pending_sync_prompts` to JOIN against pending_prompts.
func (r *syncWaiterRegistry) snapshotIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.waiters))
	for id := range r.waiters {
		out = append(out, id)
	}
	return out
}

// randomSyncWaitID returns a hex-encoded 16-byte random id. Good enough
// for in-flight correlation; not a security token (the registry is
// process-local + the id never traverses the wire — operators look up
// prompts by their integer id, not by sync_wait_id).
func randomSyncWaitID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// PromptStatus is the lifecycle state of a pending_prompts row.
type PromptStatus string

const (
	// PromptPending — enqueued; awaiting operator answer.
	PromptPending PromptStatus = "pending"
	// PromptAnswered — operator has answered (kind/target stamped).
	PromptAnswered PromptStatus = "answered"
	// PromptIgnored — the operator answered "ignore"; an alias for
	// PromptAnswered with answer_kind="ignore", surfaced as a distinct
	// status so list views can filter cleanly.
	PromptIgnored PromptStatus = "ignored"
)

// PendingPrompt is the Go-side shape of one pending_prompts row.
type PendingPrompt struct {
	ID            int64
	CreatedAt     string
	DecisionID    int64
	StatementType string
	TablesTouched []string
	FunctionsCalled []string
	DenyReason    string
	Status        PromptStatus
	AnswerKind    string
	AnswerTarget  string
	AnsweredBy    string
	AnsweredAt    string
	// SyncWaitID, when non-empty, names the in-memory wakeup channel a
	// proxy request goroutine is blocked on, waiting for an operator
	// answer. Set by AddSyncPendingPrompt; nil for legacy async
	// prompts (existing --prompt-on-deny behavior). #203 (synchronous
	// deny-prompt v1.1).
	SyncWaitID string
}

// AddPendingPrompt enqueues a prompt referencing the decision row that
// produced the DENY. Caller is responsible for having already inserted
// the decision row (via RecordDecision) and passing its id.
func (s *Store) AddPendingPrompt(p PendingPrompt) (int64, error) {
	if p.DecisionID <= 0 {
		return 0, fmt.Errorf("dbounce: AddPendingPrompt: decision_id required")
	}
	createdAt := p.CreatedAt
	if createdAt == "" {
		createdAt = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	tablesJSON, err := marshalStrings(p.TablesTouched)
	if err != nil {
		return 0, fmt.Errorf("dbounce: marshal prompt tables: %w", err)
	}
	funcsJSON, err := marshalStrings(p.FunctionsCalled)
	if err != nil {
		return 0, fmt.Errorf("dbounce: marshal prompt functions: %w", err)
	}
	res, err := s.db.Exec(
		`INSERT INTO pending_prompts(
			created_at, decision_id, statement_type,
			tables_json, functions_json, deny_reason, status
		) VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
		createdAt, p.DecisionID, p.StatementType,
		tablesJSON, funcsJSON, p.DenyReason,
	)
	if err != nil {
		return 0, fmt.Errorf("dbounce: insert prompt: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("dbounce: prompt last insert id: %w", err)
	}
	return id, nil
}

// ListPendingPrompts returns prompts ordered newest-first. status ""
// returns ALL statuses. limit <= 0 defaults to 50; capped at 500.
func (s *Store) ListPendingPrompts(status PromptStatus, limit int) ([]PendingPrompt, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	var (
		query  string
		params []any
	)
	base := `SELECT id, created_at, decision_id, statement_type,
	                tables_json, functions_json, deny_reason, status,
	                COALESCE(answer_kind, ''), COALESCE(answer_target, ''),
	                COALESCE(answered_by, ''), COALESCE(answered_at, ''),
	                COALESCE(sync_wait_id, '')
	         FROM pending_prompts`
	if status != "" {
		query = base + ` WHERE status = ? ORDER BY id DESC LIMIT ?`
		params = []any{string(status), limit}
	} else {
		query = base + ` ORDER BY id DESC LIMIT ?`
		params = []any{limit}
	}
	rows, err := s.db.Query(query, params...)
	if err != nil {
		return nil, fmt.Errorf("dbounce: list prompts: %w", err)
	}
	defer rows.Close()
	out := make([]PendingPrompt, 0, limit)
	for rows.Next() {
		p, err := scanPromptRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dbounce: list prompts iterate: %w", err)
	}
	return out, nil
}

// GetPendingPrompt fetches one prompt by id. (nil, nil) when missing.
func (s *Store) GetPendingPrompt(id int64) (*PendingPrompt, error) {
	row := s.db.QueryRow(
		`SELECT id, created_at, decision_id, statement_type,
		        tables_json, functions_json, deny_reason, status,
		        COALESCE(answer_kind, ''), COALESCE(answer_target, ''),
		        COALESCE(answered_by, ''), COALESCE(answered_at, ''),
		        COALESCE(sync_wait_id, '')
		 FROM pending_prompts WHERE id = ?`, id)
	p, err := scanPromptRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dbounce: get prompt: %w", err)
	}
	return &p, nil
}

// AnswerPendingPrompt stamps a prompt as answered. Returns true when
// the row was updated, false when no such prompt was pending. answer
// kinds are not validated here (the CLI layer enforces the enum) —
// keeping the store agnostic lets future kinds land without a schema
// touch.
func (s *Store) AnswerPendingPrompt(id int64, kind, target, by string) (bool, error) {
	if id <= 0 {
		return false, fmt.Errorf("dbounce: AnswerPendingPrompt: invalid id %d", id)
	}
	if kind == "" {
		return false, fmt.Errorf("dbounce: AnswerPendingPrompt: kind required")
	}
	answeredAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	status := string(PromptAnswered)
	if kind == "ignore" {
		status = string(PromptIgnored)
	}
	res, err := s.db.Exec(
		`UPDATE pending_prompts
		 SET status = ?, answer_kind = ?, answer_target = ?, answered_by = ?, answered_at = ?
		 WHERE id = ? AND status = 'pending'`,
		status, kind, target, by, answeredAt, id,
	)
	if err != nil {
		return false, fmt.Errorf("dbounce: answer prompt: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("dbounce: answer prompt rows affected: %w", err)
	}
	return n > 0, nil
}

// scanPromptRow mirrors scanTaskRow's shape: works for *sql.Row +
// *sql.Rows so list + get paths can share scanning logic.
func scanPromptRow(sc scanner) (PendingPrompt, error) {
	var (
		p          PendingPrompt
		tablesJSON string
		funcsJSON  string
		status     string
	)
	if err := sc.Scan(&p.ID, &p.CreatedAt, &p.DecisionID, &p.StatementType,
		&tablesJSON, &funcsJSON, &p.DenyReason, &status,
		&p.AnswerKind, &p.AnswerTarget, &p.AnsweredBy, &p.AnsweredAt,
		&p.SyncWaitID); err != nil {
		return PendingPrompt{}, err
	}
	p.Status = PromptStatus(status)
	p.TablesTouched = unmarshalStrings(tablesJSON)
	p.FunctionsCalled = unmarshalStrings(funcsJSON)
	return p, nil
}

// AddSyncPendingPrompt enqueues a SYNCHRONOUS deny-prompt (#203 — the
// v1.1 follow-up to D-Slice 8's async --prompt-on-deny). The returned
// channel fires exactly once when an operator answers via
// `dbounce prompts answer` (or the caller cancels via
// CancelSyncPendingPrompt — the proxy timeout path does this).
//
// Lifecycle:
//
//  1. Caller (proxy request goroutine) calls AddSyncPendingPrompt;
//     receives (promptID, waitID, ch, err).
//  2. Caller `select`s on ch + a timeout + ctx.Done().
//  3. When the operator runs `dbounce prompts answer ID --kind X`, the
//     answer handler calls WakeSyncPendingPrompt(waitID, decision).
//     That send-on-channel + close fires the caller's select.
//  4. The caller MUST call CancelSyncPendingPrompt(waitID) when its
//     select fires on timeout / ctx.Done() — otherwise the registry
//     map leaks the channel (best-effort; the process restarting
//     also clears it).
//
// Returned channel is buffered size 1 so WakeSyncPendingPrompt never
// blocks even when the caller has already moved on.
//
// Crash-safety: the channel is in-memory only; on restart the proxy
// goroutine that owned this channel is also dead, so the wakeup
// signal would have nowhere to go anyway. The DB row survives the
// restart so `dbounce prompts list` still surfaces the prompt — the
// operator can answer it, the wakeup will no-op (registry empty),
// and the row's status stamps as answered. The originally-blocked
// SQL client received its connection-close (or upstream timeout) at
// the same instant the proxy crashed, so there's no "ghost waiter."
func (s *Store) AddSyncPendingPrompt(p PendingPrompt) (int64, string, <-chan PromptDecision, error) {
	if p.DecisionID <= 0 {
		return 0, "", nil, fmt.Errorf("dbounce: AddSyncPendingPrompt: decision_id required")
	}
	waitID, err := randomSyncWaitID()
	if err != nil {
		return 0, "", nil, fmt.Errorf("dbounce: generate sync_wait_id: %w", err)
	}
	createdAt := p.CreatedAt
	if createdAt == "" {
		createdAt = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	tablesJSON, err := marshalStrings(p.TablesTouched)
	if err != nil {
		return 0, "", nil, fmt.Errorf("dbounce: marshal prompt tables: %w", err)
	}
	funcsJSON, err := marshalStrings(p.FunctionsCalled)
	if err != nil {
		return 0, "", nil, fmt.Errorf("dbounce: marshal prompt functions: %w", err)
	}
	res, err := s.db.Exec(
		`INSERT INTO pending_prompts(
			created_at, decision_id, statement_type,
			tables_json, functions_json, deny_reason, status, sync_wait_id
		) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
		createdAt, p.DecisionID, p.StatementType,
		tablesJSON, funcsJSON, p.DenyReason, waitID,
	)
	if err != nil {
		return 0, "", nil, fmt.Errorf("dbounce: insert sync prompt: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, "", nil, fmt.Errorf("dbounce: sync prompt last insert id: %w", err)
	}
	ch := make(chan PromptDecision, 1)
	s.syncReg.add(waitID, &syncWaiter{
		ch:        ch,
		promptID:  id,
		createdAt: time.Now(),
	})
	return id, waitID, ch, nil
}

// WakeSyncPendingPrompt delivers a decision to the goroutine blocked
// on the wakeup channel for waitID. Returns (true, nil) when a waiter
// was woken; (false, nil) when no waiter exists for waitID (timed-out,
// canceled, or never existed — all equivalent at this layer).
//
// Non-blocking: the channel is buffered size 1 + we take ownership of
// the waiter atomically before sending, so this never blocks even if
// the answer side races the timeout side.
func (s *Store) WakeSyncPendingPrompt(waitID string, decision PromptDecision) (bool, error) {
	if waitID == "" {
		return false, fmt.Errorf("dbounce: WakeSyncPendingPrompt: waitID required")
	}
	w := s.syncReg.take(waitID)
	if w == nil {
		return false, nil
	}
	// Buffered chan + we just removed the waiter, so send-then-close
	// is race-free even if the caller already gave up (closing a
	// non-empty buffered channel is legal in Go).
	w.ch <- decision
	close(w.ch)
	return true, nil
}

// CancelSyncPendingPrompt removes a waiter from the in-memory registry
// without sending a decision. Called by the proxy goroutine when its
// select fires on timeout / ctx.Done() so the registry doesn't leak
// the channel. Idempotent (no-op when waitID is unknown).
func (s *Store) CancelSyncPendingPrompt(waitID string) {
	if waitID == "" {
		return
	}
	s.syncReg.remove(waitID)
}

// ListWaitingSyncPrompts returns the pending_prompts rows whose
// sync_wait_id corresponds to a currently-in-memory waiter. Used by
// the MCP tool `dbounce_pending_sync_prompts` so an agent can answer
// "which sync prompts are blocking a request RIGHT NOW?" without
// surfacing answered/timed-out historical rows.
//
// DETERMINISTIC: SQL JOIN of pending_prompts against the in-memory
// registry snapshot. No LLM call, no advisory inference.
func (s *Store) ListWaitingSyncPrompts() ([]PendingPrompt, error) {
	waitIDs := s.syncReg.snapshotIDs()
	if len(waitIDs) == 0 {
		return nil, nil
	}
	// Build an IN-clause with one parameter per id. Bound the slice
	// at a generous 500 so a runaway map can't generate a multi-MB
	// query; in practice the registry stays small (one entry per
	// in-flight blocked request).
	if len(waitIDs) > 500 {
		waitIDs = waitIDs[:500]
	}
	placeholders := make([]byte, 0, len(waitIDs)*2)
	params := make([]any, 0, len(waitIDs))
	for i, id := range waitIDs {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		params = append(params, id)
	}
	query := `SELECT id, created_at, decision_id, statement_type,
	                 tables_json, functions_json, deny_reason, status,
	                 COALESCE(answer_kind, ''), COALESCE(answer_target, ''),
	                 COALESCE(answered_by, ''), COALESCE(answered_at, ''),
	                 COALESCE(sync_wait_id, '')
	          FROM pending_prompts
	          WHERE sync_wait_id IN (` + string(placeholders) + `)
	          ORDER BY id DESC`
	rows, err := s.db.Query(query, params...)
	if err != nil {
		return nil, fmt.Errorf("dbounce: list waiting sync prompts: %w", err)
	}
	defer rows.Close()
	out := make([]PendingPrompt, 0, len(waitIDs))
	for rows.Next() {
		p, err := scanPromptRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dbounce: list waiting sync prompts iterate: %w", err)
	}
	return out, nil
}

// Silence unused-import diagnostics for json when no other prompts.go
// path needs it; json is used transitively via marshalStrings.
var _ = json.Marshal

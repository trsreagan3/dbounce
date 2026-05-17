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
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

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
	                COALESCE(answered_by, ''), COALESCE(answered_at, '')
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
		        COALESCE(answered_by, ''), COALESCE(answered_at, '')
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
		&p.AnswerKind, &p.AnswerTarget, &p.AnsweredBy, &p.AnsweredAt); err != nil {
		return PendingPrompt{}, err
	}
	p.Status = PromptStatus(status)
	p.TablesTouched = unmarshalStrings(tablesJSON)
	p.FunctionsCalled = unmarshalStrings(funcsJSON)
	return p, nil
}

// Silence unused-import diagnostics for json when no other prompts.go
// path needs it; json is used transitively via marshalStrings.
var _ = json.Marshal

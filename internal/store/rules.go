// Rules + tasks persistence layer for D-Slice 3.
//
// Kept in a separate file from store.go so the D-Slice 1 file stays
// focused on the foundation + so a parallel D-Slice 2 agent touching
// store.go for forwarding stats doesn't merge-conflict with this work.
//
// The rules + tasks tables themselves were scaffolded in D-Slice 1's
// migrate(); this file adds the Go-API around them.
//
// Cross-product parity: shapes intentionally mirror kbouncer's
// internal/store/rules.go (the K8s sibling). Where kbouncer stores
// namespace_scope / resource_scope / verb_scope, dbounce stores
// schema_scope / table_scope / function_scope — the SQL-specific
// equivalents. Field names diverge, semantics are identical.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/tasks"
)

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

// ErrInvalidRule is returned by AddRule when the rule's pattern fails
// validation. Mirrors the Python InvalidRuleError + kbounce
// ErrInvalidRule so a typo'd pattern surfaces at insert time, NOT at
// decision time (where a never-matching rule would silently confuse
// the operator).
var ErrInvalidRule = errors.New("dbounce: invalid rule")

// AddRule persists a rule + returns its row id. Rejects malformed
// patterns / effects via ErrInvalidRule wrapping.
func (s *Store) AddRule(r rules.ProxyRule) (rules.ID, error) {
	if _, _, err := rules.ParsePattern(r.Pattern); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	if r.Effect == "" {
		r.Effect = rules.EffectAllow
	}
	if !r.Effect.IsValid() {
		return 0, fmt.Errorf("%w: effect must be allow or deny (got %q)",
			ErrInvalidRule, r.Effect)
	}
	if r.Origin == "" {
		r.Origin = rules.OriginUser
	}
	res, err := s.db.Exec(
		`INSERT INTO rules(pattern, effect, schema_scope, table_scope,
		                   function_scope, note, origin, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Pattern, string(r.Effect),
		nullableString(r.SchemaScope), nullableString(r.TableScope),
		nullableString(r.FunctionScope), nullableString(r.Note),
		r.Origin,
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	)
	if err != nil {
		return 0, fmt.Errorf("dbounce: add rule: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("dbounce: add rule last insert id: %w", err)
	}
	return rules.ID(id), nil
}

// ListRules returns every rule in insertion order. Rules with a
// malformed effect column (e.g. corrupted via direct DB edit) are
// skipped with a logged warning rather than crashing the listing —
// same fix kbounce closed in WB23 MED-23-01.
func (s *Store) ListRules() ([]rules.StoredRule, error) {
	rs, err := s.db.Query(
		`SELECT id, pattern, effect,
		        COALESCE(schema_scope, ''), COALESCE(table_scope, ''),
		        COALESCE(function_scope, ''), COALESCE(note, ''),
		        COALESCE(origin, 'user')
		 FROM rules ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("dbounce: list rules: %w", err)
	}
	defer rs.Close()
	out := make([]rules.StoredRule, 0, 16)
	for rs.Next() {
		var (
			id     int64
			effect string
			r      rules.ProxyRule
		)
		if err := rs.Scan(&id, &r.Pattern, &effect, &r.SchemaScope,
			&r.TableScope, &r.FunctionScope, &r.Note, &r.Origin); err != nil {
			return nil, fmt.Errorf("dbounce: list rules scan: %w", err)
		}
		eff := rules.Effect(effect)
		if !eff.IsValid() {
			// Skip malformed rows rather than crash the listing — same
			// behavior as the Python store + kbounce.
			continue
		}
		r.Effect = eff
		out = append(out, rules.StoredRule{ID: rules.ID(id), Rule: r})
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("dbounce: list rules iterate: %w", err)
	}
	return out, nil
}

// GetRule fetches one rule by id; returns (nil, nil) when missing.
func (s *Store) GetRule(id rules.ID) (*rules.ProxyRule, error) {
	var (
		effect string
		r      rules.ProxyRule
	)
	row := s.db.QueryRow(
		`SELECT pattern, effect,
		        COALESCE(schema_scope, ''), COALESCE(table_scope, ''),
		        COALESCE(function_scope, ''), COALESCE(note, ''),
		        COALESCE(origin, 'user')
		 FROM rules WHERE id = ?`, int64(id))
	err := row.Scan(&r.Pattern, &effect, &r.SchemaScope, &r.TableScope,
		&r.FunctionScope, &r.Note, &r.Origin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dbounce: get rule: %w", err)
	}
	r.Effect = rules.Effect(effect)
	return &r, nil
}

// RemoveRule deletes a rule by id. Returns true when a row was
// removed, false when no such rule existed.
func (s *Store) RemoveRule(id rules.ID) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM rules WHERE id = ?`, int64(id))
	if err != nil {
		return false, fmt.Errorf("dbounce: remove rule: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("dbounce: remove rule rows affected: %w", err)
	}
	return n > 0, nil
}

// LoadRuleSet snapshots the full rules table into a *rules.RuleSet for
// the proxy's evaluator. Called once per decision in D-Slice 3 — the
// table is small (a few hundred rules in realistic deployments) so
// reading on every request keeps the implementation simple. If the
// table grows we'll add an in-memory cache invalidated via a config
// event hook.
func (s *Store) LoadRuleSet() (*rules.RuleSet, error) {
	stored, err := s.ListRules()
	if err != nil {
		return nil, err
	}
	flat := make([]rules.ProxyRule, 0, len(stored))
	for _, sr := range stored {
		flat = append(flat, sr.Rule)
	}
	return rules.NewRuleSet(flat), nil
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

// ErrActiveTaskExists is returned by AddTask when another task is
// already active for the same owner. Caller decides whether to end the
// existing task first or surface the conflict to the agent. Mirrors
// the Python ActiveTaskExistsError + kbounce ErrActiveTaskExists.
var ErrActiveTaskExists = errors.New("dbounce: another task is already active")

// AddTask persists a new task scope as ACTIVE. Enforces the single-
// active-per-owner invariant: a same-owner active task causes
// ErrActiveTaskExists. owner="" means the default-owner slot
// (single-active for the laptop / single-session case).
func (s *Store) AddTask(sc *tasks.Scope) error {
	if sc == nil {
		return errors.New("dbounce: AddTask: nil scope")
	}
	if sc.TaskID == "" || sc.Description == "" {
		return errors.New("dbounce: AddTask: scope missing required fields")
	}
	// Check single-active-per-owner.
	var existing string
	q := `SELECT task_id FROM tasks WHERE status = 'active' AND ` +
		`(owner = ? OR (owner IS NULL AND ? = '')) LIMIT 1`
	err := s.db.QueryRow(q, sc.Owner, sc.Owner).Scan(&existing)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// OK; proceed.
	case err != nil:
		return fmt.Errorf("dbounce: active-task check: %w", err)
	default:
		return fmt.Errorf("%w: %s (owner=%q)", ErrActiveTaskExists, existing, sc.Owner)
	}

	allowJSON, err := rulesToJSON(sc.AllowRules)
	if err != nil {
		return fmt.Errorf("dbounce: encode allow rules: %w", err)
	}
	denyJSON, err := rulesToJSON(sc.DenyRules)
	if err != nil {
		return fmt.Errorf("dbounce: encode deny rules: %w", err)
	}

	_, err = s.db.Exec(
		`INSERT INTO tasks(
			task_id, description, allow_rules_json, deny_rules_json,
			started_at, expires_at, started_by, status,
			ended_at, ended_by, end_reason, owner
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sc.TaskID, sc.Description, allowJSON, denyJSON,
		sc.StartedAt, sc.ExpiresAt, sc.StartedBy, string(sc.Status),
		nullableString(sc.EndedAt), nullableString(sc.EndedBy),
		nullableString(sc.EndReason), nullableString(sc.Owner),
	)
	if err != nil {
		return fmt.Errorf("dbounce: insert task: %w", err)
	}
	return nil
}

// GetActiveTask returns the active task for the given owner ("" =
// default-owner slot), or (nil, nil) when none is active. Auto-
// expires tasks whose wall-clock expiry has passed.
func (s *Store) GetActiveTask(owner string) (*tasks.Scope, error) {
	var (
		query  string
		params []any
	)
	if owner == "" {
		query = `SELECT task_id, description, allow_rules_json, deny_rules_json,
		                started_at, expires_at, started_by, status,
		                COALESCE(ended_at, ''), COALESCE(ended_by, ''),
		                COALESCE(end_reason, ''), COALESCE(owner, '')
		         FROM tasks WHERE status = 'active' AND owner IS NULL
		         ORDER BY started_at DESC, rowid DESC LIMIT 1`
	} else {
		query = `SELECT task_id, description, allow_rules_json, deny_rules_json,
		                started_at, expires_at, started_by, status,
		                COALESCE(ended_at, ''), COALESCE(ended_by, ''),
		                COALESCE(end_reason, ''), COALESCE(owner, '')
		         FROM tasks WHERE status = 'active' AND owner = ?
		         ORDER BY started_at DESC, rowid DESC LIMIT 1`
		params = append(params, owner)
	}
	row := s.db.QueryRow(query, params...)
	sc, err := scanTaskRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dbounce: get active task: %w", err)
	}
	if sc.IsExpired(time.Now().UTC()) {
		// Auto-expire + log; return nil to the caller.
		if _, eerr := s.EndTask(sc.TaskID, "auto-expire", "timeout", tasks.StatusExpired); eerr != nil {
			// Best-effort: a transient write failure shouldn't break
			// the read path. Same policy as kbounce.
			return nil, nil
		}
		return nil, nil
	}
	return sc, nil
}

// GetTask returns the named task or (nil, nil) when missing.
func (s *Store) GetTask(taskID string) (*tasks.Scope, error) {
	row := s.db.QueryRow(
		`SELECT task_id, description, allow_rules_json, deny_rules_json,
		        started_at, expires_at, started_by, status,
		        COALESCE(ended_at, ''), COALESCE(ended_by, ''),
		        COALESCE(end_reason, ''), COALESCE(owner, '')
		 FROM tasks WHERE task_id = ?`, taskID)
	sc, err := scanTaskRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dbounce: get task: %w", err)
	}
	return sc, nil
}

// ListTasks returns tasks newest-first with optional status filter.
// limit <= 0 defaults to 50, capped at 1000.
func (s *Store) ListTasks(statusFilter string, limit int) ([]*tasks.Scope, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	query := `SELECT task_id, description, allow_rules_json, deny_rules_json,
	                 started_at, expires_at, started_by, status,
	                 COALESCE(ended_at, ''), COALESCE(ended_by, ''),
	                 COALESCE(end_reason, ''), COALESCE(owner, '')
	          FROM tasks`
	var params []any
	if statusFilter != "" {
		query += ` WHERE status = ?`
		params = append(params, statusFilter)
	}
	query += ` ORDER BY started_at DESC, rowid DESC LIMIT ?`
	params = append(params, limit)

	rs, err := s.db.Query(query, params...)
	if err != nil {
		return nil, fmt.Errorf("dbounce: list tasks: %w", err)
	}
	defer rs.Close()
	out := make([]*tasks.Scope, 0, limit)
	for rs.Next() {
		sc, err := scanTaskRow(rs)
		if err != nil {
			return nil, fmt.Errorf("dbounce: list tasks scan: %w", err)
		}
		out = append(out, sc)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("dbounce: list tasks iterate: %w", err)
	}
	return out, nil
}

// EndTask marks the task ended with the given status. Returns true
// when a row was updated, false when the task didn't exist or was
// already non-active.
func (s *Store) EndTask(taskID, actor, endReason string, status tasks.Status) (bool, error) {
	if !status.IsValid() || status == tasks.StatusActive {
		return false, fmt.Errorf("dbounce: EndTask: invalid status %q", status)
	}
	endedAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	res, err := s.db.Exec(
		`UPDATE tasks SET status = ?, ended_at = ?, ended_by = ?, end_reason = ?
		 WHERE task_id = ? AND status = 'active'`,
		string(status), endedAt, actor, endReason, taskID,
	)
	if err != nil {
		return false, fmt.Errorf("dbounce: end task: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("dbounce: end task rows affected: %w", err)
	}
	return n > 0, nil
}

// TaskReview is the post-task review summary mirroring the Python
// task_review_summary + kbounce TaskReview. Used by `dbounce tasks
// review TASK_ID`.
//
// MED-D8-10 (AUDIT-WB-DSLICES-1-8.md) closure: pause-window demotions
// (transparent DENY → ALLOW + pause_id, recorded with the reason
// "pause-window demoted: rule engine wanted DENY (...)") are persisted
// with decision_verdict='ALLOW'. The naive switch on verdict
// double-counted those rows as plain allows, hiding the pause-demote
// signal in the post-task review. We now scan pause_id directly +
// surface the count separately so a reviewer running `dbounce tasks
// review TASK_ID` sees the three categories: allow / deny /
// pause-demoted-allow.
type TaskReview struct {
	TaskID             string
	Description        string
	Status             string
	StartedAt          string
	ExpiresAt          string
	EndedAt            string
	EndReason          string
	Owner              string
	DecisionCount      int
	AllowCount         int
	DenyCount          int
	// PauseDemotedCount is the number of ALLOW rows whose pause_id is
	// non-null — these are decisions the rule engine wanted to DENY
	// but the operator's pause window demoted to ALLOW. Always >= 0.
	// Subset of AllowCount: pause-demoted rows are also counted there
	// because the persisted verdict IS allow + they did pass through
	// the proxy. This field makes the pause-demote subset visible.
	// MED-D8-10 closure.
	PauseDemotedCount  int
	FirstDecisionAt    string
	LastDecisionAt     string
	DeniedCalls        []TaskDeniedCall
	// PauseDemotedCalls lists the pause-demoted rows so reviewers see
	// "what would have been blocked while task X ran had the pause not
	// been active?" Capped at 1000 like DeniedCalls.
	PauseDemotedCalls  []TaskDeniedCall
}

// TaskDeniedCall is one denied statement recorded during the task
// window. SQL-specific shape — captures statement_type + tables +
// reason for the post-incident "what was blocked while task X ran"
// query.
type TaskDeniedCall struct {
	At            string
	StatementType string
	Tables        []string
	Reason        string
}

// TaskReviewSummary aggregates the decisions made during a task.
// Returns (nil, nil) when the task doesn't exist.
func (s *Store) TaskReviewSummary(taskID string) (*TaskReview, error) {
	sc, err := s.GetTask(taskID)
	if err != nil {
		return nil, err
	}
	if sc == nil {
		return nil, nil
	}
	// MED-D8-10 (AUDIT-WB-DSLICES-1-8.md): pull pause_id alongside the
	// verdict so we can split out pause-demoted ALLOW rows from regular
	// ALLOW rows. The proxy persists pause-demote with
	// decision_verdict='ALLOW' + pause_id set; without inspecting
	// pause_id the reviewer would see them as plain allows.
	rs, err := s.db.Query(
		`SELECT at, decision_verdict, statement_type, tables_json,
		        decision_reason, pause_id
		 FROM decisions WHERE task_id = ? ORDER BY id`, taskID)
	if err != nil {
		return nil, fmt.Errorf("dbounce: task review decisions: %w", err)
	}
	defer rs.Close()
	out := &TaskReview{
		TaskID:      sc.TaskID,
		Description: sc.Description,
		Status:      string(sc.Status),
		StartedAt:   sc.StartedAt,
		ExpiresAt:   sc.ExpiresAt,
		EndedAt:     sc.EndedAt,
		EndReason:   sc.EndReason,
		Owner:       sc.Owner,
	}
	denied := make([]TaskDeniedCall, 0, 8)
	pauseDemoted := make([]TaskDeniedCall, 0, 4)
	for rs.Next() {
		var (
			at, verdict, stmtType, tablesJSON, reason string
			pauseID                                   sql.NullInt64
		)
		if err := rs.Scan(&at, &verdict, &stmtType, &tablesJSON, &reason, &pauseID); err != nil {
			return nil, fmt.Errorf("dbounce: task review scan: %w", err)
		}
		out.DecisionCount++
		if out.FirstDecisionAt == "" {
			out.FirstDecisionAt = at
		}
		out.LastDecisionAt = at
		switch verdict {
		case "ALLOW":
			out.AllowCount++
			// MED-D8-10: a non-null pause_id on an ALLOW row means the
			// rule engine wanted DENY but the operator's pause window
			// demoted it. Surface separately so the reviewer sees the
			// "what slipped through while paused?" set distinctly.
			if pauseID.Valid {
				out.PauseDemotedCount++
				pauseDemoted = append(pauseDemoted, TaskDeniedCall{
					At:            at,
					StatementType: stmtType,
					Tables:        unmarshalStrings(tablesJSON),
					Reason:        reason,
				})
			}
		case "DENY":
			out.DenyCount++
			denied = append(denied, TaskDeniedCall{
				At:            at,
				StatementType: stmtType,
				Tables:        unmarshalStrings(tablesJSON),
				Reason:        reason,
			})
		}
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("dbounce: task review iterate: %w", err)
	}
	// Cap at 1000 entries per the Python WB27 MED-27-01 bound (mirrored
	// by kbounce). Prevents an unbounded result from a long-running task
	// with thousands of denied calls. The pause-demoted list applies
	// the same cap for the same reason.
	if len(denied) > 1000 {
		denied = denied[:1000]
	}
	if len(pauseDemoted) > 1000 {
		pauseDemoted = pauseDemoted[:1000]
	}
	out.DeniedCalls = denied
	out.PauseDemotedCalls = pauseDemoted
	return out, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// scanner abstracts *sql.Row + *sql.Rows so scanTaskRow works for both.
type scanner interface {
	Scan(dest ...any) error
}

func scanTaskRow(sc scanner) (*tasks.Scope, error) {
	var (
		taskID, description, allowJSON, denyJSON string
		startedAt, expiresAt, startedBy, status  string
		endedAt, endedBy, endReason, owner       string
	)
	if err := sc.Scan(&taskID, &description, &allowJSON, &denyJSON,
		&startedAt, &expiresAt, &startedBy, &status,
		&endedAt, &endedBy, &endReason, &owner); err != nil {
		return nil, err
	}
	allow, derr := jsonToRules(allowJSON, rules.EffectAllow)
	if derr != nil {
		return nil, fmt.Errorf("dbounce: decode allow rules: %w", derr)
	}
	deny, derr := jsonToRules(denyJSON, rules.EffectDeny)
	if derr != nil {
		return nil, fmt.Errorf("dbounce: decode deny rules: %w", derr)
	}
	return &tasks.Scope{
		TaskID:      taskID,
		Description: description,
		AllowRules:  allow,
		DenyRules:   deny,
		StartedAt:   startedAt,
		ExpiresAt:   expiresAt,
		StartedBy:   startedBy,
		Status:      tasks.Status(status),
		EndedAt:     endedAt,
		EndedBy:     endedBy,
		EndReason:   endReason,
		Owner:       owner,
	}, nil
}

func rulesToJSON(rs []rules.ProxyRule) (string, error) {
	if len(rs) == 0 {
		return "[]", nil
	}
	maps := make([]map[string]any, 0, len(rs))
	for _, r := range rs {
		maps = append(maps, r.ToMap())
	}
	b, err := json.Marshal(maps)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func jsonToRules(blob string, effect rules.Effect) ([]rules.ProxyRule, error) {
	if blob == "" || blob == "[]" {
		return nil, nil
	}
	var raw []map[string]any
	if err := json.Unmarshal([]byte(blob), &raw); err != nil {
		// Corrupt JSON → empty list; same conservative behavior as
		// the Python store + kbounce.
		return nil, nil
	}
	out := make([]rules.ProxyRule, 0, len(raw))
	for _, m := range raw {
		r := rules.ProxyRule{
			Pattern:       stringFrom(m, "pattern"),
			Effect:        effect,
			SchemaScope:   stringFrom(m, "schema_scope"),
			TableScope:    stringFrom(m, "table_scope"),
			FunctionScope: stringFrom(m, "function_scope"),
			Note:          stringFrom(m, "note"),
			Origin:        stringFromOr(m, "origin", rules.OriginTask),
		}
		out = append(out, r)
	}
	return out, nil
}

func stringFrom(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func stringFromOr(m map[string]any, key, fallback string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return fallback
}

// Package store wraps a local SQLite database used by dbounce for
// decision audit logging plus the scaffolded rule / task / pause /
// prompt tables that D-Slices 3+ populate.
//
// The schema is intentionally parallel to kbounce's + ibounce's store
// so future tooling (cross-product audit-log scrapers, joint review
// UIs) can join across all three databases without translation. Where
// kbounce's decisions row records verb/group/resource/namespace and
// ibounce's records service/action, dbounce records the SQL-specific
// equivalents: statement_type, tables (JSON), functions (JSON), and
// the boolean flags that the parser surfaces (is_dml, is_ddl,
// has_mutating_node, is_explain_analyze).
//
// D-Slice 1 ships:
//
//   - decisions table: one row per parsed statement
//   - rules table: empty in D-Slice 1, scaffolded for D-Slice 3
//   - tasks table: empty in D-Slice 1, scaffolded for D-Slice 3
//   - pause_events table: empty in D-Slice 1, scaffolded for D-Slice 8
//   - pending_prompts table: empty in D-Slice 1, scaffolded for D-Slice 8
//   - schema_version table: monotonic migration tracker
//
// Driver: modernc.org/sqlite (pure Go; no CGO). A single binary builds
// cleanly for every platform — critical because dbounce is shipped as
// a one-file install on the user's laptop or as a sidecar in CI.
//
// Path: defaults to ~/.dbounce/state.db. Override with DBOUNCE_DB env
// var or by passing an explicit path to Open. Distinct from kbounce's
// ~/.kbouncer/state.db and ibounce's ~/.iam-jit/bouncer/state.db so
// the three products don't share file locks.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// SchemaVersion is bumped whenever the on-disk schema changes.
// Migrations are additive only (CREATE TABLE IF NOT EXISTS + ALTER
// TABLE ADD COLUMN); no destructive changes once we ship v1.
//
// Version log:
//
//	1 — D-Slice 1 initial: decisions + rules + tasks + pause_events +
//	    pending_prompts tables, all the D-Slice 7 + D-Slice 8 columns
//	    materialized up-front so the schema doesn't churn across
//	    slices.
const SchemaVersion = 1

// DefaultDBPath returns the path the store opens when no explicit path
// is supplied. Honors DBOUNCE_DB for tests and CI sandboxes that want
// a scratch location.
func DefaultDBPath() (string, error) {
	if override := os.Getenv("DBOUNCE_DB"); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("dbounce: resolve home dir: %w", err)
	}
	return filepath.Join(home, ".dbounce", "state.db"), nil
}

// Store wraps a sql.DB plus migration state. Safe for concurrent use
// from multiple goroutines (sql.DB handles its own pooling).
type Store struct {
	db   *sql.DB
	path string
}

// Open initializes (creating if needed) the SQLite database at path.
// If path is "", DefaultDBPath() is consulted. Parent directories are
// created with 0o700 to keep the audit log private to the user
// (mirrors kbounce + ibounce).
func Open(path string) (*Store, error) {
	if path == "" {
		p, err := DefaultDBPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("dbounce: mkdir %q: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("dbounce: sql.Open: %w", err)
	}
	db.SetMaxOpenConns(4)

	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the on-disk path of the SQLite file, useful for log
// messages and tests.
func (s *Store) Path() string { return s.path }

// migrate runs the additive schema for SchemaVersion. Safe to call on
// an existing database; CREATE TABLE IF NOT EXISTS makes it
// idempotent.
//
// Decisions: the row shape includes everything D-Slices 3+ need so
// the schema doesn't churn. statement_type + tables + functions are
// the SQL-specific equivalents of kbounce's verb/resource/namespace
// and ibounce's service/action — the cross-product audit-log scraper
// can SELECT a consistent superset across all three databases.
func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY
		)`,
		// Decisions: one row per parsed statement. statement_type is the
		// classifier output (SELECT, INSERT, UPDATE, DELETE, DDL, CALL,
		// DO, EXECUTE, WITH-WRITE, EXPLAIN, EXPLAIN-ANALYZE, etc).
		// tables_json + functions_json are the AST walker's output as
		// JSON arrays so downstream tools can JSON-extract without
		// re-parsing the SQL. has_mutating_node is the layer-2 backstop
		// signal: AST walker found a mutating node anywhere in the tree
		// (catches CTE-wrapped writes that look like SELECT at the top).
		// decision_source is the D-Slice 7 column naming the rule layer
		// that produced the verdict ("profile" / "task" / "global" /
		// "default" / "unclassifiable"); empty for D-Slice 1 (no rule
		// engine yet). is_stream + stream_kind track long-lived stream
		// shapes (PG COPY, MySQL streaming result sets); D-Slice 1 never
		// sets is_stream true but the columns are present so D-Slice 2's
		// forwarding doesn't need a schema bump.
		`CREATE TABLE IF NOT EXISTS decisions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			at TEXT NOT NULL,
			dialect TEXT NOT NULL,
			statement TEXT NOT NULL,
			statement_type TEXT NOT NULL,
			tables_json TEXT NOT NULL DEFAULT '[]',
			functions_json TEXT NOT NULL DEFAULT '[]',
			is_dml INTEGER NOT NULL DEFAULT 0,
			is_ddl INTEGER NOT NULL DEFAULT 0,
			has_mutating_node INTEGER NOT NULL DEFAULT 0,
			mutating_node_type TEXT NOT NULL DEFAULT '',
			is_explain INTEGER NOT NULL DEFAULT 0,
			is_explain_analyze INTEGER NOT NULL DEFAULT 0,
			impersonated_role TEXT NOT NULL DEFAULT '',
			parse_errors_json TEXT NOT NULL DEFAULT '[]',
			decision_verdict TEXT NOT NULL,
			decision_reason TEXT NOT NULL,
			mode_at_decision TEXT NOT NULL,
			enforced INTEGER NOT NULL DEFAULT 0,
			decision_source TEXT NOT NULL DEFAULT '',
			profile_name TEXT,
			matched_rule_id INTEGER,
			task_id TEXT,
			pause_id INTEGER,
			is_stream INTEGER NOT NULL DEFAULT 0,
			stream_kind TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_at ON decisions(at)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_verdict ON decisions(decision_verdict)`,
		`CREATE INDEX IF NOT EXISTS idx_decisions_pause_id ON decisions(pause_id)`,
		// Rules: scaffolded for D-Slice 3. Pattern shape will be
		// "statement_type:table_glob" (e.g. "DELETE:public.*",
		// "*:secrets_*"). Empty in D-Slice 1.
		`CREATE TABLE IF NOT EXISTS rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pattern TEXT NOT NULL,
			effect TEXT NOT NULL,
			schema_scope TEXT,
			table_scope TEXT,
			function_scope TEXT,
			note TEXT,
			origin TEXT NOT NULL DEFAULT 'user',
			created_at TEXT NOT NULL
		)`,
		// Tasks: scaffolded for D-Slice 3 (per-task scope composition).
		`CREATE TABLE IF NOT EXISTS tasks (
			task_id TEXT PRIMARY KEY,
			description TEXT NOT NULL,
			allow_rules_json TEXT NOT NULL,
			deny_rules_json TEXT NOT NULL,
			started_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			started_by TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			ended_at TEXT,
			ended_by TEXT,
			end_reason TEXT,
			owner TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)`,
		// pause_events: scaffolded for D-Slice 8 timed escape hatch.
		`CREATE TABLE IF NOT EXISTS pause_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			started_at TEXT NOT NULL,
			ends_at TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			started_by TEXT NOT NULL,
			ended_at_actual TEXT,
			end_kind TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pause_events_ends_at ON pause_events(ends_at)`,
		// pending_prompts: scaffolded for D-Slice 8 async deny-prompt UX.
		`CREATE TABLE IF NOT EXISTS pending_prompts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			created_at TEXT NOT NULL,
			decision_id INTEGER NOT NULL,
			statement_type TEXT NOT NULL DEFAULT '',
			tables_json TEXT NOT NULL DEFAULT '[]',
			functions_json TEXT NOT NULL DEFAULT '[]',
			deny_reason TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			answer_kind TEXT,
			answer_target TEXT,
			answered_by TEXT,
			answered_at TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_prompts_status ON pending_prompts(status)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_prompts_created_at ON pending_prompts(created_at)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("dbounce: migrate: %w (stmt=%q)", err, q)
		}
	}

	// Stamp / bump schema_version.
	var ver int
	row := s.db.QueryRow(`SELECT version FROM schema_version LIMIT 1`)
	switch err := row.Scan(&ver); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := s.db.Exec(`INSERT INTO schema_version(version) VALUES (?)`, SchemaVersion); err != nil {
			return fmt.Errorf("dbounce: stamp schema_version: %w", err)
		}
	case err != nil:
		return fmt.Errorf("dbounce: read schema_version: %w", err)
	default:
		if ver < SchemaVersion {
			if _, err := s.db.Exec(`UPDATE schema_version SET version = ?`, SchemaVersion); err != nil {
				return fmt.Errorf("dbounce: bump schema_version: %w", err)
			}
		}
	}
	return nil
}

// addColumnIfMissing is the idempotent ALTER TABLE ADD COLUMN helper
// kbounce + ibounce use. Reserved for future additive migrations
// (D-Slice 2-8 already ship their columns up-front in the SchemaVersion
// 1 baseline, but the helper is here ready for whatever the post-launch
// adversarial-loop process uncovers).
func (s *Store) addColumnIfMissing(table, column, decl string) error {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return fmt.Errorf("dbounce: pragma table_info(%s): %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("dbounce: scan table_info: %w", err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("dbounce: rows.Err: %w", err)
	}
	stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, decl)
	if _, err := s.db.Exec(stmt); err != nil {
		return fmt.Errorf("dbounce: add column %s.%s: %w", table, column, err)
	}
	return nil
}

// DecisionRow is the input to RecordDecision + the output of
// RecentDecisions. Mirrors the parser's ParsedStatement plus the
// gating verdict + audit context.
type DecisionRow struct {
	At               time.Time
	Dialect          string
	Statement        string
	StatementType    string
	TablesTouched    []string
	FunctionsCalled  []string
	IsDML            bool
	IsDDL            bool
	HasMutatingNode  bool
	MutatingNodeType string
	IsExplain        bool
	IsExplainAnalyze bool
	ImpersonatedRole string
	ParseErrors      []string
	DecisionVerdict  string
	DecisionReason   string
	ModeAtDecision   string
	Enforced         bool
	// DecisionSource names the rule layer that produced the verdict
	// ("profile" / "task" / "global" / "default" / "unclassifiable").
	// Empty in D-Slice 1; populated by D-Slices 3 + 7.
	DecisionSource string
	// ProfileName is the active profile at decision time. Empty when no
	// profile is active (D-Slice 1 always empty; D-Slice 7 wires it).
	ProfileName string
	// MatchedRuleID is set when a D-Slice 3 rule produced the verdict.
	MatchedRuleID *int64
	// TaskID is set when a D-Slice 3 task scope produced the verdict.
	TaskID string
	// PauseID is set when a D-Slice 8 pause window was active at
	// decision time. Lets reviewers ask "what calls happened inside
	// pause N?" with a single JOIN.
	PauseID *int64
	// IsStream marks streaming statements (PG COPY, MySQL streaming
	// result sets). Always false in D-Slice 1; D-Slice 2 forwarding +
	// D-Slice 5 MySQL will set it.
	IsStream bool
	// StreamKind: "copy", "result-set-stream", "" (not streaming).
	StreamKind string
}

// RecordDecision appends one row to the decisions audit log and
// returns the assigned row id. Failures bubble to the caller; the
// proxy logs them and keeps serving — audit-write failure must not
// crash the listener (same policy as kbounce + ibounce).
func (s *Store) RecordDecision(d DecisionRow) (int64, error) {
	atStr := d.At.UTC().Format("2006-01-02T15:04:05Z")
	if d.At.IsZero() {
		atStr = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	tablesJSON, err := marshalStrings(d.TablesTouched)
	if err != nil {
		return 0, fmt.Errorf("dbounce: marshal tables: %w", err)
	}
	functionsJSON, err := marshalStrings(d.FunctionsCalled)
	if err != nil {
		return 0, fmt.Errorf("dbounce: marshal functions: %w", err)
	}
	parseErrJSON, err := marshalStrings(d.ParseErrors)
	if err != nil {
		return 0, fmt.Errorf("dbounce: marshal parse errors: %w", err)
	}
	res, err := s.db.Exec(
		`INSERT INTO decisions(
			at, dialect, statement, statement_type,
			tables_json, functions_json,
			is_dml, is_ddl, has_mutating_node, mutating_node_type,
			is_explain, is_explain_analyze,
			impersonated_role, parse_errors_json,
			decision_verdict, decision_reason, mode_at_decision, enforced,
			decision_source, profile_name,
			matched_rule_id, task_id, pause_id,
			is_stream, stream_kind
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		atStr, d.Dialect, d.Statement, d.StatementType,
		tablesJSON, functionsJSON,
		boolToInt(d.IsDML), boolToInt(d.IsDDL), boolToInt(d.HasMutatingNode), d.MutatingNodeType,
		boolToInt(d.IsExplain), boolToInt(d.IsExplainAnalyze),
		d.ImpersonatedRole, parseErrJSON,
		d.DecisionVerdict, d.DecisionReason, d.ModeAtDecision, boolToInt(d.Enforced),
		d.DecisionSource, nullableString(d.ProfileName),
		nullableInt(d.MatchedRuleID), nullableString(d.TaskID), nullableInt(d.PauseID),
		boolToInt(d.IsStream), d.StreamKind,
	)
	if err != nil {
		return 0, fmt.Errorf("dbounce: record decision: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("dbounce: last insert id: %w", err)
	}
	return id, nil
}

// CountDecisions returns the total decision rows recorded so far.
// Surfaced via /healthz so liveness probes can use it as a smoke
// signal.
func (s *Store) CountDecisions() (int64, error) {
	var n int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM decisions`).Scan(&n); err != nil {
		return 0, fmt.Errorf("dbounce: count decisions: %w", err)
	}
	return n, nil
}

// RecentDecisions returns the N most recently recorded decisions,
// newest first. Used by `dbounce audit tail`. Pass 0 / negative for
// the implicit default of 50; capped at 1000.
func (s *Store) RecentDecisions(limit int) ([]DecisionRow, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.Query(`SELECT
		at, dialect, statement, statement_type,
		tables_json, functions_json,
		is_dml, is_ddl, has_mutating_node, mutating_node_type,
		is_explain, is_explain_analyze,
		impersonated_role, parse_errors_json,
		decision_verdict, decision_reason, mode_at_decision, enforced,
		decision_source, profile_name,
		matched_rule_id, task_id, pause_id,
		is_stream, stream_kind
		FROM decisions
		ORDER BY id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("dbounce: recent decisions query: %w", err)
	}
	defer rows.Close()
	out := make([]DecisionRow, 0, limit)
	for rows.Next() {
		var (
			d                DecisionRow
			atStr            string
			tablesJSON       string
			functionsJSON    string
			parseErrJSON     string
			isDML            int
			isDDL            int
			hasMut           int
			isExplain        int
			isExplainAnalyze int
			enforced         int
			profileName      sql.NullString
			ruleID           sql.NullInt64
			taskID           sql.NullString
			pauseID          sql.NullInt64
			isStream         int
		)
		if err := rows.Scan(
			&atStr, &d.Dialect, &d.Statement, &d.StatementType,
			&tablesJSON, &functionsJSON,
			&isDML, &isDDL, &hasMut, &d.MutatingNodeType,
			&isExplain, &isExplainAnalyze,
			&d.ImpersonatedRole, &parseErrJSON,
			&d.DecisionVerdict, &d.DecisionReason, &d.ModeAtDecision, &enforced,
			&d.DecisionSource, &profileName,
			&ruleID, &taskID, &pauseID,
			&isStream, &d.StreamKind,
		); err != nil {
			return nil, fmt.Errorf("dbounce: recent decisions scan: %w", err)
		}
		if t, perr := time.Parse("2006-01-02T15:04:05Z", atStr); perr == nil {
			d.At = t
		}
		d.TablesTouched = unmarshalStrings(tablesJSON)
		d.FunctionsCalled = unmarshalStrings(functionsJSON)
		d.ParseErrors = unmarshalStrings(parseErrJSON)
		d.IsDML = isDML != 0
		d.IsDDL = isDDL != 0
		d.HasMutatingNode = hasMut != 0
		d.IsExplain = isExplain != 0
		d.IsExplainAnalyze = isExplainAnalyze != 0
		d.Enforced = enforced != 0
		if profileName.Valid {
			d.ProfileName = profileName.String
		}
		if ruleID.Valid {
			rid := ruleID.Int64
			d.MatchedRuleID = &rid
		}
		if taskID.Valid {
			d.TaskID = taskID.String
		}
		if pauseID.Valid {
			pid := pauseID.Int64
			d.PauseID = &pid
		}
		d.IsStream = isStream != 0
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dbounce: recent decisions iterate: %w", err)
	}
	return out, nil
}

// GetActivePause returns the currently-active pause window, or nil
// when none. D-Slice 1 scaffolding: always returns nil because no code
// path inserts into pause_events yet. Defined here so /healthz can
// already gracefully include the pause field in its JSON shape and
// D-Slice 8 doesn't need to change /healthz signatures.
func (s *Store) GetActivePause() (*PauseRow, error) {
	nowStr := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if _, err := s.db.Exec(
		`UPDATE pause_events SET ended_at_actual = ends_at, end_kind = 'expired'
		 WHERE ended_at_actual IS NULL AND ends_at <= ?`,
		nowStr,
	); err != nil {
		return nil, fmt.Errorf("dbounce: gc expired pauses: %w", err)
	}
	row := s.db.QueryRow(
		`SELECT id, started_at, ends_at, reason, started_by,
		        COALESCE(ended_at_actual, ''), COALESCE(end_kind, '')
		 FROM pause_events WHERE ended_at_actual IS NULL
		 ORDER BY id DESC LIMIT 1`,
	)
	var p PauseRow
	err := row.Scan(&p.ID, &p.StartedAt, &p.EndsAt, &p.Reason, &p.StartedBy, &p.EndedAtActual, &p.EndKind)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("dbounce: get active pause: %w", err)
	}
	return &p, nil
}

// PauseRow is the shape of an active pause window. Defined here so the
// /healthz handler can reference it without importing the D-Slice 8
// pause package (which doesn't exist yet).
type PauseRow struct {
	ID            int64
	StartedAt     string
	EndsAt        string
	Reason        string
	StartedBy     string
	EndedAtActual string
	EndKind       string
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullableInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func marshalStrings(xs []string) (string, error) {
	if len(xs) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(xs)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func unmarshalStrings(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var xs []string
	if err := json.Unmarshal([]byte(s), &xs); err != nil {
		return nil
	}
	return xs
}

// silence unused-helper lint while the rest of the migration helpers
// land in later D-Slices.
var _ = (*Store)(nil).addColumnIfMissing

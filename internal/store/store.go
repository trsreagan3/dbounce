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
//	2 — D-Slice 2 forwarding: decisions table gains forwarded /
//	    upstream_status / upstream_response_summary so audit reviewers
//	    can distinguish forwarded vs not-forwarded vs upstream-errored
//	    decisions without parsing the reason text.
//	3 — MED-D8-09 (AUDIT-WB-DSLICES-1-8.md): decisions table gains
//	    statement_redacted boolean so audit consumers know when the
//	    stored SQL had its quoted string literals swapped for
//	    [REDACTED] before persistence — they MUST NOT trust the row's
//	    SQL for replay when this column is true.
//	4 — #203 synchronous deny-prompt v1.1: pending_prompts table gains
//	    sync_wait_id TEXT column (nullable; UNIQUE when set) so the
//	    proxy can correlate an in-flight blocked request with the
//	    operator's eventual `dbounce prompts answer ID` call. The
//	    wakeup channel itself is in-memory (lost on restart — the
//	    blocked request goroutine is dead too); the UUID is the
//	    persistence-side handle. Crash-safe: a restart returns the
//	    blocked client an SQL error via TCP-close, and the prompt row
//	    survives so the operator still sees it in `prompts list`.
const SchemaVersion = 4

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
	db       *sql.DB
	path     string
	// syncReg is the #203 in-memory registry of sync-prompt wakeup
	// channels keyed by sync_wait_id UUID. Populated by
	// AddSyncPendingPrompt; drained by WakeSyncPendingPrompt /
	// CancelSyncPendingPrompt. Lost on process restart by design —
	// the request goroutine that owned the channel is also dead.
	syncReg *syncWaiterRegistry
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

	// DSN-level busy_timeout makes EVERY connection in the pool wait +
	// retry for up to N ms when a competing connection holds a lock,
	// rather than failing immediately with SQLITE_BUSY. Necessary
	// because we keep MaxOpenConns > 1 — concurrent forwarder-audit-
	// write + healthz-count-read race against each other otherwise.
	// 5s is generous for our workload (per-statement audit writes +
	// healthz polls) and matches kbounce's setting.
	//
	// modernc.org/sqlite parses `_pragma=<name>(<value>)` in the DSN +
	// applies it on every new connection — this is per-connection so
	// passing it via DSN is the only correct shape for a pool.
	// MED-D8-08 (AUDIT-WB-DSLICES-1-8.md) closure: enable
	// `foreign_keys` so the FK declaration on `pending_prompts.
	// decision_id` (added in the migrate stmts) is actually enforced.
	// SQLite ships with FK enforcement OFF by default for historical-
	// compatibility reasons; per-connection PRAGMA via the DSN ensures
	// every pool connection has it enabled. Same-UID attacker can
	// disable via PRAGMA (defense-in-depth, not cryptographic), but
	// this closes the casual-write integrity gap.
	//
	// LOW-D8-12 (AUDIT-WB-DSLICES-1-8.md) closure: pin
	// `synchronous=FULL` explicitly. FULL is SQLite's default in
	// rollback-journal mode (and the modernc.org/sqlite driver doesn't
	// switch us to WAL by default), so this is largely defense-in-depth
	// — but the audit log's value depends on durability across power
	// loss, and a future driver/config change that quietly flips us to
	// `synchronous=NORMAL` (the WAL default) or worse `OFF` could lose
	// the last committed audit row. Pinning it on every connection
	// makes the durability story explicit + survives driver upgrades.
	// Trade-off documented: FULL adds an fsync per commit; for
	// dbounce's per-statement audit writes this is the right side of
	// the latency/durability trade — every decision MUST be on disk
	// before the wire-protocol path moves on, otherwise a crash erases
	// evidence the audit reviewer might be the only source of.
	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("dbounce: sql.Open: %w", err)
	}
	db.SetMaxOpenConns(4)

	s := &Store{db: db, path: path, syncReg: newSyncWaiterRegistry()}
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
			stream_kind TEXT NOT NULL DEFAULT '',
			forwarded INTEGER NOT NULL DEFAULT 0,
			upstream_status TEXT NOT NULL DEFAULT '',
			upstream_response_summary TEXT NOT NULL DEFAULT '',
			statement_redacted INTEGER NOT NULL DEFAULT 0
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
		// MED-D8-08: decision_id carries a FOREIGN KEY REFERENCES
		// decisions(id) so a delete-+-reuse attack against decisions
		// (impossible today given the append-only triggers from
		// MED-D8-07, but defense-in-depth) can't leave dangling /
		// re-pointed prompts. FK enforcement is enabled at connection
		// open via the foreign_keys pragma on the DSN.
		// Existing pre-MED-D8-08 databases retain the pre-FK table
		// shape (SQLite can't ALTER TABLE to add an FK); fresh
		// installations (the v1.0 launch case) get the constraint.
		// #203 (synchronous deny-prompt v1.1): sync_wait_id is a
		// nullable TEXT column carrying the UUID the proxy goroutine
		// uses to find its wakeup channel when an operator answers a
		// prompt via `dbounce prompts answer`. NULL = async-style
		// prompt (existing D-Slice 8 --prompt-on-deny behavior — fire-
		// and-forget). Non-NULL = a request goroutine is currently
		// blocked on the wakeup. The UNIQUE constraint applies only
		// when populated (partial index below) so multiple async
		// prompts with NULL sync_wait_id coexist.
		`CREATE TABLE IF NOT EXISTS pending_prompts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			created_at TEXT NOT NULL,
			decision_id INTEGER NOT NULL REFERENCES decisions(id),
			statement_type TEXT NOT NULL DEFAULT '',
			tables_json TEXT NOT NULL DEFAULT '[]',
			functions_json TEXT NOT NULL DEFAULT '[]',
			deny_reason TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			answer_kind TEXT,
			answer_target TEXT,
			answered_by TEXT,
			answered_at TEXT,
			sync_wait_id TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_prompts_status ON pending_prompts(status)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_prompts_created_at ON pending_prompts(created_at)`,
		// #203: partial UNIQUE index on sync_wait_id (only when populated).
		// SQLite supports partial indexes — this enforces uniqueness on
		// the in-flight sync prompts without disturbing the existing
		// async prompts (which leave sync_wait_id NULL).
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_prompts_sync_wait_id
			ON pending_prompts(sync_wait_id) WHERE sync_wait_id IS NOT NULL`,
		// MED-D8-07 (AUDIT-WB-DSLICES-1-8.md) closure: enforce append-only
		// semantics on `decisions` via BEFORE UPDATE / BEFORE DELETE
		// triggers. The audit log is dbounce's gating invariant — a
		// caller with sqlite write access can still bypass via PRAGMA
		// (same-UID attacker has equivalent reach), so this is defense-
		// in-depth, not cryptographic tamper-evidence. A rolling hash
		// chain across rows is the post-launch full-tamper-evidence
		// path; these triggers close the "honest log" gap.
		`CREATE TRIGGER IF NOT EXISTS decisions_no_update
			BEFORE UPDATE ON decisions
			BEGIN SELECT RAISE(ABORT, 'dbounce: decisions is append-only (MED-D8-07)'); END`,
		`CREATE TRIGGER IF NOT EXISTS decisions_no_delete
			BEFORE DELETE ON decisions
			BEGIN SELECT RAISE(ABORT, 'dbounce: decisions is append-only (MED-D8-07)'); END`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("dbounce: migrate: %w (stmt=%q)", err, q)
		}
	}

	// D-Slice 2 additive migration for databases stamped at v1: add the
	// forwarding-audit columns if they aren't already present. The
	// CREATE TABLE above declares them so fresh databases get them
	// inline; addColumnIfMissing handles upgrade-in-place for
	// pre-existing v1 databases.
	for _, col := range []struct{ name, decl string }{
		{"forwarded", "INTEGER NOT NULL DEFAULT 0"},
		{"upstream_status", "TEXT NOT NULL DEFAULT ''"},
		{"upstream_response_summary", "TEXT NOT NULL DEFAULT ''"},
		// MED-D8-09 (AUDIT-WB-DSLICES-1-8.md): in-place upgrade for
		// pre-v3 databases. Existing rows default to 0 (not redacted).
		{"statement_redacted", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := s.addColumnIfMissing("decisions", col.name, col.decl); err != nil {
			return err
		}
	}

	// #203 additive migration for pre-v4 databases: add sync_wait_id
	// column to pending_prompts (NULL = legacy async-style prompt; no
	// in-flight blocked goroutine waiting on a wakeup).
	if err := s.addColumnIfMissing("pending_prompts", "sync_wait_id", "TEXT"); err != nil {
		return err
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
	// Forwarded is true when D-Slice 2's forwarder actually proxied the
	// message to the upstream. False when (a) no upstream is configured
	// (observation-only), or (b) transparent-mode DENY refused without
	// forwarding. Lets audit reviewers ask "which decisions touched the
	// real database?" with a single column.
	Forwarded bool
	// UpstreamStatus names the outcome of the upstream call: "ok" /
	// "error" / "not_forwarded". Empty in D-Slice 1.
	UpstreamStatus string
	// UpstreamResponseSummary is a short human-readable description of
	// the upstream's reply ("23 rows returned", "upstream error:
	// relation 'foo' does not exist") for the audit reviewer. Bounded
	// at ~256 chars by the writer.
	UpstreamResponseSummary string
	// StatementRedacted is true when the persisted Statement field has
	// had its quoted string literals swapped for [REDACTED] (per
	// MED-D8-09's --redact-literals flag). Audit consumers MUST NOT
	// trust the SQL for replay when this is true — see RedactLiterals
	// in the parser package.
	StatementRedacted bool
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
	// Bound the upstream-response summary at 256 chars so a chatty
	// upstream error (a stack trace, a multi-line plpgsql NOTICE) can't
	// bloat individual SQLite rows.
	upstreamSummary := d.UpstreamResponseSummary
	if len(upstreamSummary) > 256 {
		upstreamSummary = upstreamSummary[:253] + "..."
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
			is_stream, stream_kind,
			forwarded, upstream_status, upstream_response_summary,
			statement_redacted
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		atStr, d.Dialect, d.Statement, d.StatementType,
		tablesJSON, functionsJSON,
		boolToInt(d.IsDML), boolToInt(d.IsDDL), boolToInt(d.HasMutatingNode), d.MutatingNodeType,
		boolToInt(d.IsExplain), boolToInt(d.IsExplainAnalyze),
		d.ImpersonatedRole, parseErrJSON,
		d.DecisionVerdict, d.DecisionReason, d.ModeAtDecision, boolToInt(d.Enforced),
		d.DecisionSource, nullableString(d.ProfileName),
		nullableInt(d.MatchedRuleID), nullableString(d.TaskID), nullableInt(d.PauseID),
		boolToInt(d.IsStream), d.StreamKind,
		boolToInt(d.Forwarded), d.UpstreamStatus, upstreamSummary,
		boolToInt(d.StatementRedacted),
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
		is_stream, stream_kind,
		forwarded, upstream_status, upstream_response_summary,
		statement_redacted
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
			forwarded        int
			stmtRedacted     int
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
			&forwarded, &d.UpstreamStatus, &d.UpstreamResponseSummary,
			&stmtRedacted,
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
		d.Forwarded = forwarded != 0
		d.StatementRedacted = stmtRedacted != 0
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

// D-Slice 2 actively uses addColumnIfMissing for the forwarding-audit
// column migration. Future slices reuse it for their own column adds.

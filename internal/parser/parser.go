// Package parser turns a raw SQL string into a ParsedStatement —
// dbounce's normalized handle for "what does this statement want to
// do?" Every downstream layer (audit log, rule engine, profile
// evaluator, /healthz counter) consumes ParsedStatement, not raw SQL.
//
// Dialects:
//
//   - postgres — pg_query_go v6 (libpg_query / PostgreSQL 16 grammar).
//     See postgres.go.
//   - mysql    — xwb1989/sqlparser (a standalone fork of Vitess's
//     sqlparser, single-package, no transitive bloat). See mysql.go.
//
// D-Slice 6 will add snowflake + bigquery via the JDBC-driver-shim
// path; the dialect dispatcher below is the only file those slices
// need to touch.
//
// Cross-dialect invariant: every audit row carries the same
// ParsedStatement shape regardless of dialect, so the recommender +
// live-action-tail UI compose against rows already on disk without
// per-dialect special-cases. Per [[cross-product-agent-parity]]:
// statement_type / tables_touched / functions_called / is_dml /
// is_ddl / has_mutating_node form the audit-log spine.
//
// Per [[creates-never-mutates]]: this package PARSES. It never
// executes SQL, never connects to a DB, never holds credentials.
// Pure analysis.
package parser

import "fmt"

// Dialect names a SQL wire-protocol family. Stored on each
// ParsedStatement so the audit row records which parser produced the
// classification.
const (
	// DialectPostgres routes Parse() through libpg_query.
	DialectPostgres = "postgres"
	// DialectMySQL routes Parse() through xwb1989/sqlparser (D-Slice 5).
	DialectMySQL = "mysql"
	// DialectSnowflake routes Parse() through the xwb1989/sqlparser-based
	// Snowflake parser (D-Slice 6). Best-effort: Snowflake's grammar
	// extends MySQL-ish SQL with VARIANT / OBJECT_INSERT / STAGE /
	// WAREHOUSE / COPY INTO / PUT verbs. Per [[scorer-is-ground-truth]]:
	// the Snowflake rule pack ships calibration_status: experimental.
	DialectSnowflake = "snowflake"
	// DialectBigQuery routes Parse() through the xwb1989/sqlparser-based
	// BigQuery parser (D-Slice 6). Best-effort: BigQuery's grammar
	// extends SQL with CREATE MODEL / EXPORT DATA / FOR SYSTEM_TIME AS OF
	// + the __TABLES__ enumeration shape. Per [[scorer-is-ground-truth]]:
	// the BigQuery rule pack ships calibration_status: experimental.
	DialectBigQuery = "bigquery"
)

// Statement-type constants. Surfaced into ParsedStatement.StatementType
// + into the audit-log decisions.statement_type column.
//
// Shared across dialects so the rule engine + audit log key off one
// vocabulary. Dialect-specific statement shapes (MySQL LOAD DATA
// INFILE, MySQL SET GLOBAL) reuse the closest applicable constant +
// surface the dialect-specific verb in MutatingNodeType so a
// MySQL-aware rule pack can match on it.
const (
	StmtSelect         = "SELECT"
	StmtInsert         = "INSERT"
	StmtUpdate         = "UPDATE"
	StmtDelete         = "DELETE"
	StmtMerge          = "MERGE"
	StmtWithWrite      = "WITH-WRITE" // CTE whose body contains UPDATE/INSERT/DELETE
	StmtDDL            = "DDL"        // CREATE / ALTER / DROP / TRUNCATE / COMMENT / RENAME
	StmtTruncate       = "TRUNCATE"
	StmtCall           = "CALL"
	StmtDo             = "DO"      // DO $$ ... $$ (PG) — also any anonymous block on other dialects
	StmtExecute        = "EXECUTE" // EXECUTE 'sql_string' / PREPARE-EXECUTE
	StmtExplain        = "EXPLAIN"
	StmtExplainAnalyze = "EXPLAIN-ANALYZE"
	StmtSet            = "SET" // SET ROLE / SET search_path / SET TIME ZONE / SET GLOBAL
	StmtTransaction    = "TRANSACTION"
	StmtCopy           = "COPY" // PG COPY (streaming)
	StmtLoad           = "LOAD" // MySQL LOAD DATA INFILE / LOAD XML — exfil-shape verb
	StmtVacuum         = "VACUUM"
	StmtComment        = "COMMENT"
	StmtShow           = "SHOW" // MySQL SHOW TABLES / SHOW VARIABLES (informational read)
	StmtUse            = "USE"  // MySQL USE <db>
	// DCL (Data Control Language) — privilege management. Per task #302
	// + KNOWN-CAVEATS §A5: before this slice, `GRANT ALL PRIVILEGES ...
	// TO PUBLIC` classified as UNKNOWN and slipped past safe-default. The
	// parser now surfaces three explicit DCL operations + the
	// `dcl_targets_public` predicate so the profile evaluator can refuse
	// PUBLIC-targeting grants outright.
	StmtGrant            = "GRANT"            // GRANT ... ON ... TO ... (object privileges + role-grants)
	StmtRevoke           = "REVOKE"           // REVOKE ... ON ... FROM ... (cleanup is safe by default)
	StmtAlterPrivileges  = "ALTER_PRIVILEGES" // ALTER DEFAULT PRIVILEGES ... GRANT/REVOKE ...
	StmtUnknown          = "UNKNOWN"          // parse succeeded but classifier didn't match
	StmtUnparseable      = "UNPARSEABLE"
)

// ParsedStatement is dbounce's normalized handle on an inbound SQL
// statement. Every audit-log decision row materializes from one of
// these.
//
// Shape is the cross-dialect invariant. Adding fields is allowed;
// removing or renaming is a breaking change to the audit-row schema.
type ParsedStatement struct {
	// Raw is the original SQL text the client sent (verbatim, including
	// trailing semicolons + whitespace). Stored for audit reconstruction;
	// never re-executed.
	Raw string
	// Dialect names which wire protocol parsed the bytes
	// (DialectPostgres / DialectMySQL).
	Dialect string
	// StatementType is the classifier output. One of the Stmt* constants.
	StatementType string
	// TablesTouched is the set of schema-qualified table identifiers the
	// statement references. Deduped + sorted for stable JSON encoding.
	// Empty when the statement has no table references.
	TablesTouched []string
	// FunctionsCalled is the set of function names invoked by the
	// statement.
	FunctionsCalled []string
	// IsDML is true for INSERT / UPDATE / DELETE / MERGE (+ MySQL
	// REPLACE which the MySQL classifier surfaces as INSERT).
	IsDML bool
	// IsDDL is true for CREATE / ALTER / DROP / TRUNCATE / COMMENT /
	// RENAME.
	IsDDL bool
	// IsDCL is true for GRANT / REVOKE / ALTER DEFAULT PRIVILEGES — the
	// privilege-management family. Surfaced as a first-class predicate
	// so profiles can reason about privilege escalation without keyword-
	// sniffing the raw SQL. Per task #302 / KNOWN-CAVEATS §A5: before
	// this field existed the parser returned StatementType=UNKNOWN for
	// these statements and the safe-default profile let `GRANT ALL ...
	// TO PUBLIC` slip through.
	IsDCL bool
	// DCLTargetsPublic is true when the statement's grantee list includes
	// the special PG `PUBLIC` pseudo-role — i.e., a GRANT that fans out
	// to every database role. The safe-default profile treats this as a
	// hard deny (privilege escalation to all sessions). Also true for
	// `ALTER DEFAULT PRIVILEGES ... GRANT ... TO PUBLIC`.
	//
	// Always false for REVOKE — revoking from PUBLIC is a cleanup
	// operation and stays advisory under safe-default.
	DCLTargetsPublic bool
	// HasMutatingNode is the Layer-2 backstop: AST walker found at least
	// one mutating node anywhere in the tree, regardless of nesting
	// depth. Catches CTE-wrapped writes whose top-level keyword is WITH
	// (PG) plus MySQL multi-statement batches whose first statement is
	// a SELECT but whose second is an UPDATE.
	HasMutatingNode bool
	// MutatingNodeType names the first mutating node the walker
	// surfaced, for audit-row reasoning ("UpdateStmt inside CTE",
	// "LOAD-DATA-INFILE", "SET-GLOBAL").
	MutatingNodeType string
	// IsExplain is true for EXPLAIN. EXPLAIN alone does NOT execute the
	// inner statement — informational only.
	IsExplain bool
	// IsExplainAnalyze is true for EXPLAIN ANALYZE on a mutating inner
	// statement. The inner statement DOES execute, so the verdict must
	// honor the inner statement's mutating shape.
	IsExplainAnalyze bool
	// ImpersonatedRole is the role name from a `SET ROLE` (PG) or the
	// MySQL `SET ROLE` equivalent. Empty when the statement is not a
	// SET ROLE.
	ImpersonatedRole string
	// ParseErrors is non-empty when the dialect parser rejected the SQL.
	// The classifier still returns a ParsedStatement (with
	// StatementType = StmtUnparseable) so the audit log keeps a record
	// of what the client tried.
	ParseErrors []string
}

// Parse dispatches a raw SQL string to the dialect-appropriate parser
// implementation. The dialect string is normally one of the Dialect*
// constants; unknown dialects return a ParsedStatement with
// StatementType = StmtUnparseable + a single ParseError naming the
// unknown dialect (so the audit log still gets a row).
//
// Empty dialect defaults to DialectPostgres — preserves D-Slice 1
// behavior + lets older callers that still invoke Parse without an
// explicit dialect continue to work.
func Parse(dialect, raw string) *ParsedStatement {
	switch dialect {
	case "", DialectPostgres:
		return parsePostgres(raw)
	case DialectMySQL:
		return parseMySQL(raw)
	case DialectSnowflake:
		return parseSnowflake(raw)
	case DialectBigQuery:
		return parseBigQuery(raw)
	default:
		return &ParsedStatement{
			Raw:           raw,
			Dialect:       dialect,
			StatementType: StmtUnparseable,
			ParseErrors: []string{fmt.Sprintf(
				"dbounce parser: unknown dialect %q (want postgres, mysql, snowflake, or bigquery)",
				dialect)},
		}
	}
}

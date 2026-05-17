// BigQuery parser implementation (D-Slice 6).
//
// IMPORTANT: dbounce does NOT ship a wire-protocol proxy for BigQuery
// in v1.0. BigQuery's "wire protocol" is the google-cloud-bigquery
// REST/gRPC API; the pragmatic v1.0 shape is the JDBC-driver-shim per
// [[dbounce-build-plan]] §D-Slice 6. The customer wraps their
// google-cloud-bigquery client / JDBC driver so dbounce receives the
// raw SQL string (via `dbounce decide` or the dbounce_decide MCP tool),
// parses + gates it, then forwards. See docs/SHIM-INTEGRATION.md for
// the honest trade-offs.
//
// Parser substrate: a thin wrapper around xwb1989/sqlparser (already a
// dep from D-Slice 5) with a BigQuery-specific keyword pre-check layer
// in front. BigQuery has no canonical Go parser; xwb1989's MySQL-shaped
// grammar covers SELECT / INSERT / UPDATE / DELETE / CREATE / DROP /
// ALTER but does NOT recognize BigQuery-only verbs like CREATE MODEL,
// EXPORT DATA, FOR SYSTEM_TIME AS OF, the `_PARTITIONTIME` pseudo-
// column, or the `__TABLES__` enumeration view. Per
// [[scorer-is-ground-truth]]: we surface what we can confidently
// classify; the rule pack carries calibration_status: experimental.
//
// LOAD-BEARING dialect-shape notes:
//
//   - CREATE MODEL / CREATE OR REPLACE MODEL — BigQuery ML model
//     creation. Mutating + billing-affecting. Pre-check: classify as
//     StmtDDL + MutatingNodeType = "CREATE-MODEL". Rule pack denies by
//     default in non-ML profiles.
//
//   - EXPORT DATA — bulk export to GCS. The canonical BigQuery exfil
//     shape. Pre-check: classify as StmtCopy + MutatingNodeType =
//     "EXPORT-DATA" + IsDML = true (semantically a write to GCS).
//
//   - LOAD DATA — bulk import from GCS into a table. Pre-check:
//     classify as StmtLoad + MutatingNodeType = "LOAD-DATA-GCS".
//
//   - SELECT * FROM `project.dataset.__TABLES__` — enumeration of
//     every table in a dataset. The rule pack denies via table_scope
//     pattern (not the parser); listed here for documentation.
//
//   - SELECT * FROM dataset.tbl FOR SYSTEM_TIME AS OF ... — BigQuery's
//     time-travel read. Read-only (no mutation), but a rule pack that
//     wants to flag historical reads can match on the SQL text.
//
//   - ASSERT — runtime data-quality check. Read-only; xwb1989 doesn't
//     recognize the verb, so we surface it as StmtUnknown by design
//     (the audit row still records the SQL).
//
// Per [[creates-never-mutates]]: this file PARSES. No execution, no
// connection, no credentials.

package parser

import (
	"strings"

	"github.com/xwb1989/sqlparser"
)

// bigquery mutating-node-type labels. Kept as package consts so the
// rule pack + recommender can match on a stable vocabulary across the
// audit log.
const (
	bigqueryMutatingCreateModel = "CREATE-MODEL"
	bigqueryMutatingDropModel   = "DROP-MODEL"
	bigqueryMutatingExportData  = "EXPORT-DATA"
	bigqueryMutatingLoadData    = "LOAD-DATA-GCS"
	bigqueryMutatingMergeInto   = "MERGE-INTO"
)

// parseBigQuery turns a raw BigQuery statement into a ParsedStatement.
// Same contract as parsePostgres / parseMySQL / parseSnowflake: never
// returns nil, surfaces StmtUnparseable + ParseErrors when the parser
// rejects the SQL. Best-effort by design.
func parseBigQuery(raw string) *ParsedStatement {
	out := &ParsedStatement{
		Raw:     raw,
		Dialect: DialectBigQuery,
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		out.StatementType = StmtUnknown
		return out
	}

	// CRIT-D8-02 closure: strip SQL comments BEFORE the prefix test.
	// `/* */ EXPORT DATA OPTIONS(...) AS SELECT ...` is the canonical
	// BigQuery exfil shape BigQuery accepts; the bare HasPrefix scan
	// misses it because the byte at position 0 is `/`, not the verb.
	// See stripcomments.go + AUDIT-WB-DSLICES-1-8.md. The stripped
	// form is used for both the upper-case prefix test AND the per-
	// extension extractors (so an `INTO fake` hidden inside a comment
	// can't fool them).
	stripped := strings.TrimSpace(stripSQLComments(trimmed))
	upper := strings.ToUpper(stripped)

	// BigQuery-specific keyword pre-checks. These run BEFORE we hand
	// bytes to xwb1989 because xwb1989's grammar doesn't recognize
	// these as top-level statements. Order matters: more-specific
	// prefixes first.
	if handled := classifyBigQueryExtension(upper, stripped, out); handled {
		return out
	}

	// Fall through to xwb1989 for SELECT / INSERT / UPDATE / DELETE /
	// CREATE TABLE / DROP TABLE / TRUNCATE / transactions. We reuse the
	// MySQL walker because the AST shape is identical for these
	// constructs.
	tokenizer := sqlparser.NewStringTokenizer(raw)
	stmts := []sqlparser.Statement{}
	for {
		stmt, err := sqlparser.ParseNext(tokenizer)
		if err != nil {
			if len(stmts) == 0 {
				out.StatementType = StmtUnparseable
				out.ParseErrors = []string{err.Error()}
				return out
			}
			break
		}
		if stmt == nil {
			break
		}
		stmts = append(stmts, stmt)
		if len(stmts) >= 64 {
			break
		}
	}

	if len(stmts) == 0 {
		out.StatementType = StmtUnknown
		return out
	}

	out.StatementType = classifyMySQLTopLevel(stmts[0])

	tableSet := map[string]struct{}{}
	functionSet := map[string]struct{}{}
	aliasSet := map[string]struct{}{}
	for i, stmt := range stmts {
		_ = sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
			if ate, ok := node.(*sqlparser.AliasedTableExpr); ok && ate != nil && !ate.As.IsEmpty() {
				aliasSet[strings.ToLower(ate.As.String())] = struct{}{}
			}
			return true, nil
		}, stmt)
		mysqlWalk(stmt, &mysqlWalkCtx{
			parsed:        out,
			tables:        tableSet,
			functions:     functionSet,
			aliases:       aliasSet,
			canReclassify: i == 0,
		})
	}
	out.TablesTouched = sortedKeys(tableSet)
	out.FunctionsCalled = sortedKeys(functionSet)

	switch out.StatementType {
	case StmtInsert, StmtUpdate, StmtDelete, StmtMerge:
		out.IsDML = true
	case StmtDDL, StmtTruncate, StmtComment:
		out.IsDDL = true
	}
	return out
}

// classifyBigQueryExtension detects BigQuery-specific verbs the
// xwb1989 grammar doesn't recognize. Returns true when one of the
// extensions matched + the ParsedStatement was populated.
func classifyBigQueryExtension(upper, raw string, out *ParsedStatement) bool {
	switch {
	case strings.HasPrefix(upper, "CREATE MODEL") ||
		strings.HasPrefix(upper, "CREATE OR REPLACE MODEL"):
		out.StatementType = StmtDDL
		out.IsDDL = true
		out.HasMutatingNode = true
		out.MutatingNodeType = bigqueryMutatingCreateModel
		out.TablesTouched = bigqueryExtractCreateModelTarget(raw)
		return true
	case strings.HasPrefix(upper, "DROP MODEL"):
		out.StatementType = StmtDDL
		out.IsDDL = true
		out.HasMutatingNode = true
		out.MutatingNodeType = bigqueryMutatingDropModel
		return true
	case strings.HasPrefix(upper, "EXPORT DATA"):
		// EXPORT DATA OPTIONS(...) AS SELECT ... — the canonical
		// BigQuery exfil shape. Tag as both COPY (semantically the
		// closest existing classification) + MutatingNodeType so the
		// rule pack can deny EXPORT-DATA specifically.
		out.StatementType = StmtCopy
		out.IsDML = true
		out.HasMutatingNode = true
		out.MutatingNodeType = bigqueryMutatingExportData
		return true
	case strings.HasPrefix(upper, "LOAD DATA"):
		// LOAD DATA INTO <table> FROM FILES (...) — bulk import.
		out.StatementType = StmtLoad
		out.IsDML = true
		out.HasMutatingNode = true
		out.MutatingNodeType = bigqueryMutatingLoadData
		out.TablesTouched = bigqueryExtractLoadDataTarget(raw)
		return true
	case strings.HasPrefix(upper, "MERGE INTO ") || strings.HasPrefix(upper, "MERGE "):
		// MERGE — BigQuery DML. xwb1989 doesn't model MERGE; surface as
		// StmtMerge + MutatingNodeType so MERGE:* rule patterns fire.
		out.StatementType = StmtMerge
		out.IsDML = true
		out.HasMutatingNode = true
		out.MutatingNodeType = bigqueryMutatingMergeInto
		out.TablesTouched = bigqueryExtractMergeTarget(raw)
		return true
	}
	return false
}

// bigqueryExtractCreateModelTarget pulls the model identifier out of
// `CREATE MODEL <project.dataset.model> ...` or
// `CREATE OR REPLACE MODEL ...`. Best-effort.
func bigqueryExtractCreateModelTarget(sql string) []string {
	upper := strings.ToUpper(sql)
	idx := strings.Index(upper, "MODEL ")
	if idx < 0 {
		return nil
	}
	rest := strings.TrimSpace(sql[idx+len("MODEL "):])
	// IF NOT EXISTS clause — skip.
	upRest := strings.ToUpper(rest)
	if strings.HasPrefix(upRest, "IF NOT EXISTS ") {
		rest = strings.TrimSpace(rest[len("IF NOT EXISTS "):])
	}
	end := len(rest)
	for i, ch := range rest {
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '(' || ch == ',' {
			end = i
			break
		}
	}
	tok := strings.Trim(rest[:end], "`\"'")
	tok = strings.ToLower(tok)
	if tok == "" {
		return nil
	}
	return []string{tok}
}

// bigqueryExtractLoadDataTarget pulls the destination table out of a
// `LOAD DATA [OVERWRITE] INTO <table> FROM FILES (...)` statement.
func bigqueryExtractLoadDataTarget(sql string) []string {
	upper := strings.ToUpper(sql)
	idx := strings.Index(upper, "INTO ")
	if idx < 0 {
		return nil
	}
	rest := strings.TrimSpace(sql[idx+len("INTO "):])
	end := len(rest)
	for i, ch := range rest {
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '(' || ch == ',' {
			end = i
			break
		}
	}
	tok := strings.Trim(rest[:end], "`\"'")
	tok = strings.ToLower(tok)
	if tok == "" {
		return nil
	}
	return []string{tok}
}

// bigqueryExtractMergeTarget pulls the target table out of a
// `MERGE [INTO] <table> USING ...` statement.
func bigqueryExtractMergeTarget(sql string) []string {
	upper := strings.ToUpper(sql)
	var idx int
	switch {
	case strings.HasPrefix(upper, "MERGE INTO "):
		idx = len("MERGE INTO ")
	case strings.HasPrefix(upper, "MERGE "):
		idx = len("MERGE ")
	default:
		return nil
	}
	rest := strings.TrimSpace(sql[idx:])
	end := len(rest)
	for i, ch := range rest {
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '(' || ch == ',' {
			end = i
			break
		}
	}
	tok := strings.Trim(rest[:end], "`\"'")
	tok = strings.ToLower(tok)
	if tok == "" {
		return nil
	}
	return []string{tok}
}

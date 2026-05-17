// Snowflake parser implementation (D-Slice 6).
//
// IMPORTANT: dbounce does NOT ship a wire-protocol proxy for Snowflake
// in v1.0. Snowflake's wire protocol is HTTPS-based + closed-spec; the
// pragmatic v1.0 shape is the JDBC-driver-shim per the
// [[dbounce-build-plan]] §D-Slice 6 decision. The customer wraps their
// Snowflake driver connection so dbounce receives the raw SQL string
// (via `dbounce decide` or the dbounce_decide MCP tool), parses + gates
// it, then forwards to the real driver. The parser below is what the
// shim-side `decide` call invokes. See docs/SHIM-INTEGRATION.md for the
// honest trade-offs vs the PG/MySQL native wire-protocol path.
//
// Parser substrate: a thin wrapper around xwb1989/sqlparser (already a
// dep from D-Slice 5) with a Snowflake-specific keyword pre-check
// layer in front. Snowflake has no canonical Go parser; xwb1989's
// MySQL-shaped grammar covers the common SELECT / INSERT / UPDATE /
// DELETE / CREATE / DROP shapes but does NOT recognize Snowflake-only
// verbs like COPY INTO, PUT, GET, UNDROP, USE SECONDARY ROLES, SET TAG,
// CREATE WAREHOUSE, etc. Per [[scorer-is-ground-truth]]: we surface
// what we can confidently classify; what we can't reaches the rule
// engine as StmtUnparseable + the audit row still gets written.
//
// LOAD-BEARING dialect-shape notes:
//
//   - COPY INTO <table> FROM @stage — Snowflake's bulk-load shape (the
//     ingest direction). Pre-check: trimmed lead "COPY INTO" → StmtCopy
//     + MutatingNodeType = "COPY-INTO-TABLE" + IsDML = true. Best-
//     effort destination-table extraction parallels the MySQL LOAD
//     DATA INFILE pre-check.
//
//   - COPY INTO @stage FROM <table_or_query> — Snowflake's bulk-export
//     shape. Same StmtCopy + MutatingNodeType = "COPY-INTO-STAGE" so a
//     rule pack can deny export shapes specifically (the exfil
//     direction the audit pack flags hardest).
//
//   - PUT file://... @stage / GET @stage file://... — local-file
//     transfer verbs the JDBC shim should NEVER let through. Pre-check:
//     classify as StmtCopy + MutatingNodeType = "PUT" / "GET".
//
//   - UNDROP TABLE / UNDROP SCHEMA / UNDROP DATABASE — Snowflake-only
//     time-travel verb that restores a dropped object. Mutating; rule
//     pack denies by default.
//
//   - USE SECONDARY ROLES { ALL | NONE | <role-name> } — privilege
//     escalation shape. Classify as StmtUse + MutatingNodeType =
//     "USE-SECONDARY-ROLES" so the deny is precise.
//
//   - SET TAG / UNSET TAG — Snowflake metadata mutation; classify as
//     StmtSet + MutatingNodeType = "SET-TAG" / "UNSET-TAG".
//
//   - GRANT / REVOKE — privilege management; classify as StmtDDL +
//     MutatingNodeType = "GRANT" / "REVOKE". (xwb1989 doesn't model
//     these as their own node type; the pre-check is the only path.)
//
//   - CREATE WAREHOUSE / ALTER WAREHOUSE / DROP WAREHOUSE — billing-
//     affecting shapes; classify as StmtDDL + MutatingNodeType =
//     "WAREHOUSE-MUTATION".
//
//   - SELECT ... FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY — the
//     audit-infra exfil shape the rule pack denies by default. Detected
//     by the rule pack's pattern matcher (table_scope), not the parser;
//     listed here for documentation.
//
// Per [[creates-never-mutates]]: this file PARSES. No execution, no
// connection, no credentials. Same invariant as parsePostgres /
// parseMySQL.

package parser

import (
	"strings"

	"github.com/xwb1989/sqlparser"
)

// snowflake mutating-node-type labels. Kept as package consts so the
// rule pack + recommender can match on a stable vocabulary across the
// audit log.
const (
	snowflakeMutatingCopyIntoTable = "COPY-INTO-TABLE"
	snowflakeMutatingCopyIntoStage = "COPY-INTO-STAGE"
	snowflakeMutatingPut           = "PUT"
	snowflakeMutatingGet           = "GET"
	snowflakeMutatingUndrop        = "UNDROP"
	snowflakeMutatingUseSecondary  = "USE-SECONDARY-ROLES"
	snowflakeMutatingSetTag        = "SET-TAG"
	snowflakeMutatingUnsetTag      = "UNSET-TAG"
	snowflakeMutatingGrant         = "GRANT"
	snowflakeMutatingRevoke        = "REVOKE"
	snowflakeMutatingWarehouseMut  = "WAREHOUSE-MUTATION"
)

// parseSnowflake turns a raw Snowflake statement into a ParsedStatement.
// Same contract as parsePostgres / parseMySQL: never returns nil,
// surfaces StmtUnparseable + ParseErrors when the parser rejects the
// SQL. Best-effort by design — see file header for the trade-off
// rationale.
func parseSnowflake(raw string) *ParsedStatement {
	out := &ParsedStatement{
		Raw:     raw,
		Dialect: DialectSnowflake,
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		out.StatementType = StmtUnknown
		return out
	}
	upper := strings.ToUpper(trimmed)

	// Snowflake-specific keyword pre-checks. These run BEFORE we hand
	// bytes to xwb1989 because xwb1989's grammar doesn't recognize
	// these as top-level statements. Order matters: more-specific
	// prefixes first.
	if handled := classifySnowflakeExtension(upper, trimmed, out); handled {
		return out
	}

	// Fall through to xwb1989 for SELECT / INSERT / UPDATE / DELETE /
	// CREATE TABLE / DROP TABLE / ALTER TABLE / TRUNCATE / SHOW / USE /
	// transactions / SET (session variables). We reuse the MySQL walker
	// because the AST shape is identical for these constructs.
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

	// Snowflake-specific function-name surfacing. xwb1989's walker
	// collects FuncExpr nodes generically; OBJECT_INSERT / OBJECT_KEYS
	// / VARIANT-shaped functions surface naturally via that path. We do
	// NOT inject Snowflake-only functions here — the rule pack matches
	// on functions_called via pattern, and the walker has already done
	// the right thing.
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

// classifySnowflakeExtension detects Snowflake-specific verbs the
// xwb1989 grammar doesn't recognize. Returns true when one of the
// extensions matched + the ParsedStatement was populated; the caller
// then skips the xwb1989 path entirely.
//
// `upper` is the trimmed + upper-cased SQL; `raw` is the trimmed
// original (preserved case, for table-name extraction). `out` is
// mutated in place when a match is found.
func classifySnowflakeExtension(upper, raw string, out *ParsedStatement) bool {
	switch {
	case strings.HasPrefix(upper, "COPY INTO @"):
		// COPY INTO @stage FROM <table_or_query> — the EXPORT direction.
		out.StatementType = StmtCopy
		out.IsDML = true
		out.HasMutatingNode = true
		out.MutatingNodeType = snowflakeMutatingCopyIntoStage
		out.TablesTouched = snowflakeCopyExtractFromTable(raw)
		return true
	case strings.HasPrefix(upper, "COPY INTO "):
		// COPY INTO <table> FROM @stage — the INGEST direction.
		out.StatementType = StmtCopy
		out.IsDML = true
		out.HasMutatingNode = true
		out.MutatingNodeType = snowflakeMutatingCopyIntoTable
		out.TablesTouched = snowflakeCopyExtractIntoTable(raw)
		return true
	case strings.HasPrefix(upper, "PUT "):
		// PUT file://... @stage — local-file → stage upload.
		out.StatementType = StmtCopy
		out.IsDML = true
		out.HasMutatingNode = true
		out.MutatingNodeType = snowflakeMutatingPut
		return true
	case strings.HasPrefix(upper, "GET @"):
		// GET @stage file://... — stage → local-file download.
		out.StatementType = StmtCopy
		out.IsDML = true
		out.HasMutatingNode = true
		out.MutatingNodeType = snowflakeMutatingGet
		return true
	case strings.HasPrefix(upper, "UNDROP "):
		// UNDROP TABLE/SCHEMA/DATABASE — time-travel restore. Mutating.
		out.StatementType = StmtDDL
		out.IsDDL = true
		out.HasMutatingNode = true
		out.MutatingNodeType = snowflakeMutatingUndrop
		return true
	case strings.HasPrefix(upper, "USE SECONDARY ROLES"):
		// Privilege escalation shape.
		out.StatementType = StmtUse
		out.HasMutatingNode = true
		out.MutatingNodeType = snowflakeMutatingUseSecondary
		return true
	case strings.HasPrefix(upper, "SET TAG "):
		out.StatementType = StmtSet
		out.HasMutatingNode = true
		out.MutatingNodeType = snowflakeMutatingSetTag
		return true
	case strings.HasPrefix(upper, "UNSET TAG "):
		out.StatementType = StmtSet
		out.HasMutatingNode = true
		out.MutatingNodeType = snowflakeMutatingUnsetTag
		return true
	case strings.HasPrefix(upper, "GRANT "):
		out.StatementType = StmtDDL
		out.IsDDL = true
		out.HasMutatingNode = true
		out.MutatingNodeType = snowflakeMutatingGrant
		return true
	case strings.HasPrefix(upper, "REVOKE "):
		out.StatementType = StmtDDL
		out.IsDDL = true
		out.HasMutatingNode = true
		out.MutatingNodeType = snowflakeMutatingRevoke
		return true
	case strings.HasPrefix(upper, "CREATE WAREHOUSE") ||
		strings.HasPrefix(upper, "CREATE OR REPLACE WAREHOUSE") ||
		strings.HasPrefix(upper, "ALTER WAREHOUSE") ||
		strings.HasPrefix(upper, "DROP WAREHOUSE"):
		// Billing-affecting verb — Snowflake charges by warehouse uptime.
		out.StatementType = StmtDDL
		out.IsDDL = true
		out.HasMutatingNode = true
		out.MutatingNodeType = snowflakeMutatingWarehouseMut
		return true
	}
	return false
}

// snowflakeCopyExtractIntoTable pulls the destination table out of a
// `COPY INTO <table> FROM @stage ...` statement. Best-effort: returns
// nil when the shape doesn't match (the rule pack still gates via the
// COPY-INTO-TABLE MutatingNodeType).
func snowflakeCopyExtractIntoTable(sql string) []string {
	// After "COPY INTO " the first identifier-like token is the
	// destination table. Stop at whitespace / paren / FROM.
	upper := strings.ToUpper(sql)
	idx := strings.Index(upper, "COPY INTO ")
	if idx < 0 {
		return nil
	}
	rest := strings.TrimSpace(sql[idx+len("COPY INTO "):])
	end := len(rest)
	for i, ch := range rest {
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '(' || ch == ',' {
			end = i
			break
		}
	}
	tok := strings.Trim(rest[:end], "`\"'")
	tok = strings.ToLower(tok)
	if tok == "" || strings.HasPrefix(tok, "@") {
		return nil
	}
	return []string{tok}
}

// snowflakeCopyExtractFromTable pulls the source table out of a
// `COPY INTO @stage FROM <table> ...` statement (the export shape).
// Best-effort: returns nil when the FROM clause holds a subquery or
// when the shape doesn't match.
func snowflakeCopyExtractFromTable(sql string) []string {
	upper := strings.ToUpper(sql)
	fromIdx := strings.Index(upper, " FROM ")
	if fromIdx < 0 {
		return nil
	}
	rest := strings.TrimSpace(sql[fromIdx+len(" FROM "):])
	// If the FROM clause is a subquery `(SELECT ...)`, skip — the
	// walker doesn't reach here because xwb1989 isn't invoked. Honest:
	// we don't capture the inner table.
	if strings.HasPrefix(rest, "(") {
		return nil
	}
	end := len(rest)
	for i, ch := range rest {
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == ';' ||
			ch == '(' || ch == ',' {
			end = i
			break
		}
	}
	tok := strings.Trim(rest[:end], "`\"'")
	tok = strings.ToLower(tok)
	if tok == "" || strings.HasPrefix(tok, "@") {
		return nil
	}
	return []string{tok}
}

// Package parser turns a raw SQL string into a ParsedStatement —
// dbounce's normalized handle for "what does this statement want to
// do?" Every downstream layer (audit log, rule engine, profile evaluator,
// /healthz counter) consumes ParsedStatement, not raw SQL.
//
// D-Slice 1 supports PostgreSQL only, via github.com/pganalyze/pg_query_go/v6
// (pure-Go bindings to libpg_query; tracks the PostgreSQL 16 grammar).
// D-Slice 5 adds MySQL via Vitess sqlparser; D-Slice 6 adds Snowflake +
// BigQuery via the JDBC-driver-shim path.
//
// The walker IS the Layer-2 backstop per [[structured-classifier-backstop-
// pattern]]: keyword-only classification ("does the SQL start with SELECT?")
// misses CTE-wrapped writes (`WITH foo AS (UPDATE ... RETURNING ...)
// SELECT ...`), so we walk every node looking for mutating shapes and
// surface them via HasMutatingNode + MutatingNodeType regardless of where
// they sit in the tree.
//
// Per [[creates-never-mutates]]: this package PARSES. It never executes
// SQL, never connects to a DB, never holds credentials. Pure analysis.
package parser

import (
	"fmt"
	"sort"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// DialectPostgres is the only dialect supported in D-Slice 1.
const DialectPostgres = "postgres"

// Statement-type constants. Surfaced into ParsedStatement.StatementType
// + into the audit-log decisions.statement_type column.
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
	StmtDo             = "DO"      // DO $$ ... $$
	StmtExecute        = "EXECUTE" // EXECUTE 'sql_string' / PREPARE-EXECUTE
	StmtExplain        = "EXPLAIN"
	StmtExplainAnalyze = "EXPLAIN-ANALYZE"
	StmtSet            = "SET" // SET ROLE / SET search_path / SET TIME ZONE
	StmtTransaction    = "TRANSACTION"
	StmtCopy           = "COPY"
	StmtVacuum         = "VACUUM"
	StmtComment        = "COMMENT"
	StmtUnknown        = "UNKNOWN" // parse succeeded but classifier didn't match
	StmtUnparseable    = "UNPARSEABLE"
)

// ParsedStatement is dbounce's normalized handle on an inbound SQL
// statement. Every audit-log decision row materializes from one of
// these.
type ParsedStatement struct {
	// Raw is the original SQL text the client sent (verbatim, including
	// trailing semicolons + whitespace). Stored for audit reconstruction;
	// never re-executed.
	Raw string
	// Dialect names which wire protocol parsed the bytes. "postgres" in
	// D-Slice 1.
	Dialect string
	// StatementType is the classifier output. One of the Stmt* constants.
	StatementType string
	// TablesTouched is the set of schema-qualified table identifiers the
	// statement references. Deduped + sorted for stable JSON encoding.
	// Empty when the statement has no table references (e.g. DO blocks,
	// SET ROLE).
	TablesTouched []string
	// FunctionsCalled is the set of function names invoked by the
	// statement. Includes volatile-function calls (`SELECT pg_sleep(60)`),
	// CALL targets, and aggregates surfaced by the AST walker.
	FunctionsCalled []string
	// IsDML is true for INSERT / UPDATE / DELETE / MERGE.
	IsDML bool
	// IsDDL is true for CREATE / ALTER / DROP / TRUNCATE / COMMENT /
	// RENAME.
	IsDDL bool
	// HasMutatingNode is the Layer-2 backstop: AST walker found at least
	// one mutating node anywhere in the tree, regardless of nesting
	// depth. Catches CTE-wrapped writes whose top-level keyword is WITH.
	HasMutatingNode bool
	// MutatingNodeType names the first mutating node the walker
	// surfaced, for audit-row reasoning ("UpdateStmt inside CTE").
	MutatingNodeType string
	// IsExplain is true for EXPLAIN. EXPLAIN alone does NOT execute the
	// inner statement — informational only.
	IsExplain bool
	// IsExplainAnalyze is true for EXPLAIN ANALYZE on a mutating inner
	// statement. The inner statement DOES execute, so the verdict must
	// honor the inner statement's mutating shape.
	IsExplainAnalyze bool
	// ImpersonatedRole is the role name from a `SET ROLE`. D-Slice 1
	// captures only; D-Slice 3 uses it to scope per-task evaluation.
	// Empty when the statement is not a SET ROLE.
	ImpersonatedRole string
	// ParseErrors is non-empty when libpg_query rejected the SQL. The
	// classifier still returns a ParsedStatement (with StatementType =
	// StmtUnparseable) so the audit log keeps a record of what the
	// client tried.
	ParseErrors []string
}

// Parse turns a raw PostgreSQL statement into a ParsedStatement.
// Always returns a ParsedStatement: when libpg_query rejects the SQL,
// the returned struct has StatementType = StmtUnparseable + ParseErrors
// populated. dbounce never throws away the audit record of "client
// sent something we couldn't parse" — the audit trail is the gating
// invariant.
//
// Never panics on malformed input. The libpg_query bindings return
// errors for syntactically-broken SQL; we capture + classify.
func Parse(raw string) *ParsedStatement {
	out := &ParsedStatement{
		Raw:     raw,
		Dialect: DialectPostgres,
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		out.StatementType = StmtUnknown
		return out
	}

	tree, err := pg_query.Parse(raw)
	if err != nil {
		out.StatementType = StmtUnparseable
		out.ParseErrors = []string{err.Error()}
		return out
	}
	if tree == nil || len(tree.Stmts) == 0 {
		out.StatementType = StmtUnknown
		return out
	}

	// Walk every top-level statement in the batch. In practice the PG
	// wire-protocol `Query` message can contain multiple statements
	// separated by ';'; libpg_query returns each as a RawStmt. We
	// classify the FIRST statement (its type drives the verdict for the
	// batch), but we walk ALL of them when collecting tables / functions
	// / mutating-node signals so a multi-statement batch like
	// `SELECT 1; UPDATE secrets SET x = 1` still surfaces the UPDATE.
	first := tree.Stmts[0]
	if first == nil || first.Stmt == nil {
		out.StatementType = StmtUnknown
		return out
	}
	out.StatementType = classifyTopLevel(first.Stmt)

	tableSet := map[string]struct{}{}
	functionSet := map[string]struct{}{}
	for i, rs := range tree.Stmts {
		if rs == nil || rs.Stmt == nil {
			continue
		}
		walkNode(rs.Stmt, &walkCtx{
			parsed:      out,
			tables:      tableSet,
			functions:   functionSet,
			depth:       0,
			insideExpl:  false,
			insideCTE:   false,
			insideAnExpl: false,
			// Only the FIRST statement's walk is allowed to reclassify
			// StatementType (e.g. SELECT -> WITH-WRITE for a CTE-wrapped
			// write). Subsequent statements in a multi-statement batch
			// still contribute tables / functions / HasMutatingNode for
			// the audit row but they don't overwrite the top-level
			// classification — the first statement's keyword drives the
			// audit row's statement_type.
			canReclassify: i == 0,
		})
	}
	out.TablesTouched = sortedKeys(tableSet)
	out.FunctionsCalled = sortedKeys(functionSet)

	// Final post-processing.
	switch out.StatementType {
	case StmtSelect, StmtInsert, StmtUpdate, StmtDelete, StmtMerge:
		// fine
	case StmtWithWrite:
		out.HasMutatingNode = true
		if out.MutatingNodeType == "" {
			out.MutatingNodeType = "WITH-WRITE"
		}
	}
	// IsDML / IsDDL derivation from StatementType + walker findings.
	switch out.StatementType {
	case StmtInsert, StmtUpdate, StmtDelete, StmtMerge:
		out.IsDML = true
	case StmtDDL, StmtTruncate, StmtComment:
		out.IsDDL = true
	}
	return out
}

// classifyTopLevel returns the StatementType for the top-level AST
// node. The walker handles deeper-nested mutating shapes; this just
// picks the StatementType the audit row will display.
func classifyTopLevel(n *pg_query.Node) string {
	if n == nil {
		return StmtUnknown
	}
	switch v := n.Node.(type) {
	case *pg_query.Node_SelectStmt:
		// SELECT might still wrap a write via FROM-clause subselects;
		// the walker will set HasMutatingNode if so. Top-level
		// StatementType stays SELECT.
		_ = v
		return StmtSelect
	case *pg_query.Node_InsertStmt:
		return StmtInsert
	case *pg_query.Node_UpdateStmt:
		return StmtUpdate
	case *pg_query.Node_DeleteStmt:
		return StmtDelete
	case *pg_query.Node_MergeStmt:
		return StmtMerge
	case *pg_query.Node_CallStmt:
		return StmtCall
	case *pg_query.Node_DoStmt:
		return StmtDo
	case *pg_query.Node_ExecuteStmt:
		return StmtExecute
	case *pg_query.Node_PrepareStmt:
		return StmtExecute
	case *pg_query.Node_ExplainStmt:
		if explainAnalyze(v.ExplainStmt) {
			return StmtExplainAnalyze
		}
		return StmtExplain
	case *pg_query.Node_VariableSetStmt:
		// SET ROLE / SET search_path / SET TIME ZONE / etc.
		return StmtSet
	case *pg_query.Node_TransactionStmt:
		return StmtTransaction
	case *pg_query.Node_CopyStmt:
		return StmtCopy
	case *pg_query.Node_VacuumStmt:
		return StmtVacuum
	case *pg_query.Node_TruncateStmt:
		return StmtTruncate
	case *pg_query.Node_CommentStmt:
		return StmtComment
	case *pg_query.Node_CreateStmt,
		*pg_query.Node_CreateSchemaStmt,
		*pg_query.Node_CreateRoleStmt,
		*pg_query.Node_CreateFunctionStmt,
		*pg_query.Node_CreateExtensionStmt,
		*pg_query.Node_CreateTableAsStmt,
		*pg_query.Node_CreateSeqStmt,
		*pg_query.Node_CreateTrigStmt,
		*pg_query.Node_CreatePolicyStmt,
		*pg_query.Node_AlterTableStmt,
		*pg_query.Node_AlterRoleStmt,
		*pg_query.Node_AlterDatabaseStmt,
		*pg_query.Node_AlterSeqStmt,
		*pg_query.Node_AlterPolicyStmt,
		*pg_query.Node_DropStmt,
		*pg_query.Node_DropRoleStmt,
		*pg_query.Node_DropdbStmt,
		*pg_query.Node_RenameStmt,
		*pg_query.Node_IndexStmt:
		return StmtDDL
	}
	// CTE-style queries arrive as SelectStmt wrappers around the inner
	// node; classifyTopLevel doesn't see them as WITH-WRITE — the
	// walker reclassifies during traversal if it finds a write under a
	// CTE.
	return StmtUnknown
}

// explainAnalyze returns true when an EXPLAIN's options include
// ANALYZE = true (which actually executes the inner statement).
func explainAnalyze(e *pg_query.ExplainStmt) bool {
	if e == nil {
		return false
	}
	for _, opt := range e.Options {
		if opt == nil {
			continue
		}
		def, ok := opt.Node.(*pg_query.Node_DefElem)
		if !ok || def.DefElem == nil {
			continue
		}
		if strings.EqualFold(def.DefElem.Defname, "analyze") {
			return true
		}
	}
	return false
}

type walkCtx struct {
	parsed        *ParsedStatement
	tables        map[string]struct{}
	functions     map[string]struct{}
	depth         int
	insideExpl    bool
	insideCTE     bool
	insideAnExpl  bool // EXPLAIN ANALYZE specifically — inner WILL execute
	canReclassify bool // only the first stmt in a batch may overwrite StatementType
}

// walkNode visits every reachable child of n collecting:
//
//   - schema-qualified table names (TablesTouched)
//   - function-call references (FunctionsCalled)
//   - mutating-node signals (HasMutatingNode + MutatingNodeType)
//   - SET ROLE targets (ImpersonatedRole)
//   - CTE-wrapped writes (re-classifies StatementType to WITH-WRITE)
//
// Bounded recursion. The PG AST is finite for any single statement;
// libpg_query rejects pathological infinite-grammar cases before we
// get here. Tracks depth defensively (cap at 256) so a future
// grammar quirk can't blow our stack.
//
// Stored-procedure note: when we hit a CallStmt or DoStmt, we record
// the call site itself but do NOT recursively analyze the procedure
// body. Per [[dbounce-build-plan]] §"Don't recursively analyze
// stored-procedure bodies": v1.0 treats CALL as opaque + denies unless
// allowlisted (the gating decision lives in D-Slices 3 + 7). D-Slice 1
// just captures the call signature.
func walkNode(n *pg_query.Node, ctx *walkCtx) {
	if n == nil || ctx == nil {
		return
	}
	if ctx.depth > 256 {
		return
	}
	ctx.depth++
	defer func() { ctx.depth-- }()

	switch v := n.Node.(type) {
	case *pg_query.Node_RangeVar:
		if v.RangeVar != nil {
			ctx.tables[qualify(v.RangeVar)] = struct{}{}
		}
	case *pg_query.Node_FuncCall:
		if v.FuncCall != nil {
			name := funcCallName(v.FuncCall)
			if name != "" {
				ctx.functions[name] = struct{}{}
			}
			for _, arg := range v.FuncCall.Args {
				walkNode(arg, ctx)
			}
		}
	case *pg_query.Node_SelectStmt:
		if v.SelectStmt == nil {
			return
		}
		// CTE detection. WithClause non-nil means a SELECT/INSERT/UPDATE/
		// DELETE prefixed with WITH; per [[structured-classifier-backstop-
		// pattern]] the walker MUST surface mutating CTE bodies even when
		// the top-level keyword is SELECT.
		if v.SelectStmt.WithClause != nil {
			ctx.insideCTE = true
			for _, cte := range v.SelectStmt.WithClause.Ctes {
				walkNode(cte, ctx)
			}
		}
		for _, f := range v.SelectStmt.FromClause {
			walkNode(f, ctx)
		}
		for _, t := range v.SelectStmt.TargetList {
			walkNode(t, ctx)
		}
		walkNode(v.SelectStmt.WhereClause, ctx)
		walkNode(v.SelectStmt.HavingClause, ctx)
		// UNION / INTERSECT / EXCEPT branches. Larg / Rarg are typed
		// *SelectStmt rather than *Node, so we manually wrap before
		// recursing through walkNode (which switches on Node.Node).
		if v.SelectStmt.Larg != nil {
			walkNode(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: v.SelectStmt.Larg}}, ctx)
		}
		if v.SelectStmt.Rarg != nil {
			walkNode(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: v.SelectStmt.Rarg}}, ctx)
		}
	case *pg_query.Node_CommonTableExpr:
		if v.CommonTableExpr != nil {
			walkNode(v.CommonTableExpr.Ctequery, ctx)
		}
	case *pg_query.Node_InsertStmt:
		flagMutating(ctx, "INSERT")
		if v.InsertStmt != nil {
			if v.InsertStmt.Relation != nil {
				ctx.tables[qualify(v.InsertStmt.Relation)] = struct{}{}
			}
			walkNode(v.InsertStmt.SelectStmt, ctx)
			if v.InsertStmt.OnConflictClause != nil {
				walkNode(v.InsertStmt.OnConflictClause.WhereClause, ctx)
			}
		}
	case *pg_query.Node_UpdateStmt:
		flagMutating(ctx, "UPDATE")
		if v.UpdateStmt != nil {
			if v.UpdateStmt.Relation != nil {
				ctx.tables[qualify(v.UpdateStmt.Relation)] = struct{}{}
			}
			for _, t := range v.UpdateStmt.TargetList {
				walkNode(t, ctx)
			}
			walkNode(v.UpdateStmt.WhereClause, ctx)
			for _, f := range v.UpdateStmt.FromClause {
				walkNode(f, ctx)
			}
		}
	case *pg_query.Node_DeleteStmt:
		flagMutating(ctx, "DELETE")
		if v.DeleteStmt != nil {
			if v.DeleteStmt.Relation != nil {
				ctx.tables[qualify(v.DeleteStmt.Relation)] = struct{}{}
			}
			walkNode(v.DeleteStmt.WhereClause, ctx)
		}
	case *pg_query.Node_MergeStmt:
		flagMutating(ctx, "MERGE")
		if v.MergeStmt != nil {
			if v.MergeStmt.Relation != nil {
				ctx.tables[qualify(v.MergeStmt.Relation)] = struct{}{}
			}
		}
	case *pg_query.Node_TruncateStmt:
		flagMutating(ctx, "TRUNCATE")
		if v.TruncateStmt != nil {
			for _, r := range v.TruncateStmt.Relations {
				if rng, ok := r.Node.(*pg_query.Node_RangeVar); ok && rng.RangeVar != nil {
					ctx.tables[qualify(rng.RangeVar)] = struct{}{}
				}
			}
		}
	case *pg_query.Node_CallStmt:
		// Record the procedure invocation. v1.0 will deny by default
		// unless allowlisted; D-Slice 1 just captures.
		if v.CallStmt != nil && v.CallStmt.Funccall != nil {
			name := funcCallName(v.CallStmt.Funccall)
			if name != "" {
				ctx.functions[name] = struct{}{}
			}
		}
	case *pg_query.Node_DoStmt:
		// Anonymous block (`DO $$ ... $$`). Per
		// [[dbounce-build-plan]] no recursive body analysis; we just
		// mark mutating shape because anonymous blocks commonly mutate
		// and a deny-unless-allowlisted policy is the v1.0 stance.
		flagMutating(ctx, "DO")
	case *pg_query.Node_ExecuteStmt:
		// EXECUTE 'sql_string' — dynamic SQL. Same stance as CALL/DO:
		// gate it via allowlist, not recursive analysis (we couldn't
		// recurse anyway; the inner SQL is data not AST until runtime).
		flagMutating(ctx, "EXECUTE")
	case *pg_query.Node_PrepareStmt:
		// PREPARE statements declare a prepared name; the execute path
		// is the one that runs SQL. We don't flagMutating because
		// PREPARE alone doesn't execute, but we DO walk the inner
		// Query so the audit row surfaces the tables/functions the
		// prepared statement will touch — operators want to know what
		// a PREPARE'd statement is going to do at EXECUTE time.
		if v.PrepareStmt != nil {
			walkNode(v.PrepareStmt.Query, ctx)
		}
	case *pg_query.Node_VariableSetStmt:
		if v.VariableSetStmt != nil && strings.EqualFold(v.VariableSetStmt.Name, "role") {
			// SET ROLE 'newrole' — surface the impersonation target so
			// D-Slice 3's session evaluator can pick it up. The role
			// name lives in the Args (A_Const string).
			ctx.parsed.ImpersonatedRole = firstAConstString(v.VariableSetStmt.Args)
		}
	case *pg_query.Node_ExplainStmt:
		ctx.insideExpl = true
		ctx.insideAnExpl = explainAnalyze(v.ExplainStmt)
		if v.ExplainStmt != nil {
			walkNode(v.ExplainStmt.Query, ctx)
		}
		if ctx.insideAnExpl {
			ctx.parsed.IsExplainAnalyze = true
		} else {
			ctx.parsed.IsExplain = true
		}
	case *pg_query.Node_JoinExpr:
		if v.JoinExpr != nil {
			walkNode(v.JoinExpr.Larg, ctx)
			walkNode(v.JoinExpr.Rarg, ctx)
			walkNode(v.JoinExpr.Quals, ctx)
		}
	case *pg_query.Node_SubLink:
		if v.SubLink != nil {
			walkNode(v.SubLink.Subselect, ctx)
		}
	case *pg_query.Node_RangeSubselect:
		if v.RangeSubselect != nil {
			walkNode(v.RangeSubselect.Subquery, ctx)
		}
	case *pg_query.Node_RangeFunction:
		if v.RangeFunction != nil {
			for _, fn := range v.RangeFunction.Functions {
				walkNode(fn, ctx)
			}
		}
	case *pg_query.Node_ResTarget:
		if v.ResTarget != nil {
			walkNode(v.ResTarget.Val, ctx)
		}
	case *pg_query.Node_List:
		if v.List != nil {
			for _, item := range v.List.Items {
				walkNode(item, ctx)
			}
		}
	case *pg_query.Node_RawStmt:
		if v.RawStmt != nil {
			walkNode(v.RawStmt.Stmt, ctx)
		}
	}
}

// flagMutating records that a mutating node was found during the walk.
// If the top-level classifier didn't already pick INSERT/UPDATE/DELETE/
// MERGE (which means we're inside a CTE or a SELECT subquery), and the
// current walk is allowed to reclassify (first stmt of a batch only),
// upgrade StatementType to WITH-WRITE so the gating layer sees this is
// a write under a SELECT/WITH wrapper.
func flagMutating(ctx *walkCtx, kind string) {
	ctx.parsed.HasMutatingNode = true
	if ctx.parsed.MutatingNodeType == "" {
		ctx.parsed.MutatingNodeType = kind
	}
	if !ctx.canReclassify {
		return
	}
	switch ctx.parsed.StatementType {
	case StmtInsert, StmtUpdate, StmtDelete, StmtMerge, StmtTruncate, StmtDDL:
		// Top-level already records the mutation; nothing to upgrade.
	case StmtSelect:
		// SELECT wrapping a write — almost always a CTE-wrapped write.
		ctx.parsed.StatementType = StmtWithWrite
	}
}

// qualify renders a PG RangeVar as "schema.table" (or just "table"
// when no schema is set). dbounce always normalizes to lowercase so
// matchers don't have to.
func qualify(rv *pg_query.RangeVar) string {
	if rv == nil {
		return ""
	}
	schema := strings.ToLower(rv.Schemaname)
	rel := strings.ToLower(rv.Relname)
	if schema == "" {
		return rel
	}
	return fmt.Sprintf("%s.%s", schema, rel)
}

// funcCallName renders a FuncCall node as "schema.fn" (or just "fn")
// in lowercase. Returns empty string when no name parts are present.
func funcCallName(fc *pg_query.FuncCall) string {
	if fc == nil || len(fc.Funcname) == 0 {
		return ""
	}
	parts := make([]string, 0, len(fc.Funcname))
	for _, n := range fc.Funcname {
		if n == nil {
			continue
		}
		str, ok := n.Node.(*pg_query.Node_String_)
		if !ok || str.String_ == nil {
			continue
		}
		parts = append(parts, strings.ToLower(str.String_.Sval))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ".")
}

// firstAConstString returns the first string-typed constant inside a
// list of nodes. Used to extract `SET ROLE 'foo'`'s 'foo'.
func firstAConstString(args []*pg_query.Node) string {
	for _, a := range args {
		if a == nil {
			continue
		}
		c, ok := a.Node.(*pg_query.Node_AConst)
		if !ok || c.AConst == nil {
			continue
		}
		if sv, ok := c.AConst.Val.(*pg_query.A_Const_Sval); ok && sv.Sval != nil {
			return sv.Sval.Sval
		}
	}
	return ""
}

// sortedKeys returns the keys of a string-set as a sorted slice. We
// always sort because the JSON-serialized form goes into the audit log
// + a stable sort lets unit tests assert exact equality.
func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

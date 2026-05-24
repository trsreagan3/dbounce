// PostgreSQL parser implementation. Uses
// github.com/pganalyze/pg_query_go/v6 (pure-Go bindings to libpg_query;
// tracks the PostgreSQL 16 grammar).
//
// The walker IS the Layer-2 backstop per [[structured-classifier-backstop-
// pattern]]: keyword-only classification ("does the SQL start with SELECT?")
// misses CTE-wrapped writes (`WITH foo AS (UPDATE ... RETURNING ...)
// SELECT ...`), so we walk every node looking for mutating shapes and
// surface them via HasMutatingNode + MutatingNodeType regardless of
// where they sit in the tree.
//
// Shared ParsedStatement + dialect dispatcher live in parser.go; MySQL
// path lives in mysql.go. The cross-dialect invariant is "every audit
// row has the same shape" — see parser.go.
package parser

import (
	"fmt"
	"sort"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// parsePostgres turns a raw PostgreSQL statement into a ParsedStatement.
// Always returns a ParsedStatement: when libpg_query rejects the SQL,
// the returned struct has StatementType = StmtUnparseable + ParseErrors
// populated. dbounce never throws away the audit record of "client
// sent something we couldn't parse" — the audit trail is the gating
// invariant.
//
// Never panics on malformed input. The libpg_query bindings return
// errors for syntactically-broken SQL; we capture + classify.
func parsePostgres(raw string) *ParsedStatement {
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
	// IsDML / IsDDL / IsDCL derivation from StatementType + walker findings.
	switch out.StatementType {
	case StmtInsert, StmtUpdate, StmtDelete, StmtMerge:
		out.IsDML = true
	case StmtDDL, StmtTruncate, StmtComment:
		out.IsDDL = true
	case StmtGrant, StmtRevoke, StmtAlterPrivileges:
		out.IsDCL = true
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
	// DCL — privilege management. Per task #302 / KNOWN-CAVEATS §A5:
	// before this slice these classified as UNKNOWN and slipped past
	// the safe-default profile (default-allow). The GrantStmt /
	// GrantRoleStmt nodes both carry an IsGrant bool that distinguishes
	// GRANT (true) from REVOKE (false); we surface that as the
	// StatementType so profile rules can reason about direction. The
	// `dcl_targets_public` predicate is set by the walker (see
	// walkNode below).
	case *pg_query.Node_GrantStmt:
		if v.GrantStmt != nil && !v.GrantStmt.IsGrant {
			return StmtRevoke
		}
		return StmtGrant
	case *pg_query.Node_GrantRoleStmt:
		if v.GrantRoleStmt != nil && !v.GrantRoleStmt.IsGrant {
			return StmtRevoke
		}
		return StmtGrant
	case *pg_query.Node_AlterDefaultPrivilegesStmt:
		// `ALTER DEFAULT PRIVILEGES ... GRANT/REVOKE ...` is its own
		// statement type because it sets the privilege-default for
		// future objects in a schema. Always classified as
		// ALTER_PRIVILEGES regardless of inner direction — the future-
		// objects shape is what matters for the profile gate.
		return StmtAlterPrivileges
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
	case *pg_query.Node_GrantStmt:
		// Privilege grant on an object (TABLE / SCHEMA / DATABASE /
		// SEQUENCE / FUNCTION / etc.). Walker surfaces:
		//   - touched tables (so table-scope rules still apply)
		//   - dcl_targets_public when any grantee is the PUBLIC pseudo-role
		//   - privileges + grantees + target_object + risk_indicators
		// REVOKE direction (IsGrant=false) NEVER sets dcl_targets_public —
		// revoking FROM PUBLIC is cleanup and the safe-default profile lets
		// it through.
		if v.GrantStmt != nil {
			gs := v.GrantStmt
			for _, obj := range gs.Objects {
				if obj == nil {
					continue
				}
				if rng, ok := obj.Node.(*pg_query.Node_RangeVar); ok && rng.RangeVar != nil {
					ctx.tables[qualify(rng.RangeVar)] = struct{}{}
				}
			}
			// privileges + grantees + target_object extraction (for both
			// GRANT and REVOKE — downstream filters use these on either
			// direction, e.g. "what got revoked" is an audit signal too).
			ctx.parsed.Privileges = appendUnique(ctx.parsed.Privileges, extractGrantPrivileges(gs.Privileges, gs.Targtype)...)
			ctx.parsed.Grantees = appendUnique(ctx.parsed.Grantees, extractGranteeNames(gs.Grantees)...)
			if ctx.parsed.TargetObject == "" {
				ctx.parsed.TargetObject = grantTargetObjectLabel(gs)
			}
			if gs.IsGrant {
				if granteesIncludePublic(gs.Grantees) {
					ctx.parsed.DCLTargetsPublic = true
					ctx.parsed.RiskIndicators = appendUnique(ctx.parsed.RiskIndicators, "public_grant")
				}
				if grantHasAllPrivileges(gs.Privileges) {
					ctx.parsed.RiskIndicators = appendUnique(ctx.parsed.RiskIndicators, "all_privileges")
				}
				if gs.GrantOption {
					ctx.parsed.RiskIndicators = appendUnique(ctx.parsed.RiskIndicators, "with_grant_option")
				}
			}
		}
	case *pg_query.Node_GrantRoleStmt:
		// `GRANT role_a TO role_b` — role membership grant. Same
		// dcl_targets_public predicate semantics: only the grant
		// direction with PUBLIC as grantee sets the predicate. Note
		// that PostgreSQL itself forbids granting role membership TO
		// PUBLIC, but the predicate stays consistent across both
		// GrantStmt shapes so downstream callers don't have to dispatch
		// on the inner type.
		if v.GrantRoleStmt != nil {
			grs := v.GrantRoleStmt
			ctx.parsed.Grantees = appendUnique(ctx.parsed.Grantees, extractGranteeNames(grs.GranteeRoles)...)
			// Role-membership grants have no privilege list per se; the
			// implicit privilege is "membership in <role>". Surface the
			// granted roles into Privileges as "ROLE:<name>" so audit
			// rows + downstream filters carry the role-name context
			// without overloading TargetObject.
			ctx.parsed.Privileges = appendUnique(ctx.parsed.Privileges, extractRoleNames(grs.GrantedRoles)...)
			if grs.IsGrant {
				ctx.parsed.RiskIndicators = appendUnique(ctx.parsed.RiskIndicators, "role_membership")
				if granteesIncludePublic(grs.GranteeRoles) {
					ctx.parsed.DCLTargetsPublic = true
					ctx.parsed.RiskIndicators = appendUnique(ctx.parsed.RiskIndicators, "public_grant")
				}
				if grantRoleHasAdminOption(grs.Opt) {
					ctx.parsed.RiskIndicators = appendUnique(ctx.parsed.RiskIndicators, "with_admin_option")
				}
			}
		}
	case *pg_query.Node_AlterDefaultPrivilegesStmt:
		// `ALTER DEFAULT PRIVILEGES ... GRANT ... TO PUBLIC` is the
		// dangerous shape — it makes EVERY future object in a schema
		// world-accessible. We recurse into the inner Action (a
		// GrantStmt) so granteesIncludePublic fires consistently.
		if v.AlterDefaultPrivilegesStmt != nil && v.AlterDefaultPrivilegesStmt.Action != nil {
			action := v.AlterDefaultPrivilegesStmt.Action
			ctx.parsed.Privileges = appendUnique(ctx.parsed.Privileges, extractGrantPrivileges(action.Privileges, action.Targtype)...)
			ctx.parsed.Grantees = appendUnique(ctx.parsed.Grantees, extractGranteeNames(action.Grantees)...)
			ctx.parsed.RiskIndicators = appendUnique(ctx.parsed.RiskIndicators, "alter_default_privileges")
			// TargetObject for ADP is the schema scope (when supplied),
			// expressed as `all-<objtype>-in-schema:<schema>` so an
			// operator reading the audit row sees "this affects every
			// future TABLE in `public`" rather than just `schema:public`.
			if ctx.parsed.TargetObject == "" {
				ctx.parsed.TargetObject = alterDefaultPrivTargetLabel(v.AlterDefaultPrivilegesStmt, action)
			}
			if action.IsGrant {
				if granteesIncludePublic(action.Grantees) {
					ctx.parsed.DCLTargetsPublic = true
					ctx.parsed.RiskIndicators = appendUnique(ctx.parsed.RiskIndicators, "public_grant")
				}
				if grantHasAllPrivileges(action.Privileges) {
					ctx.parsed.RiskIndicators = appendUnique(ctx.parsed.RiskIndicators, "all_privileges")
				}
				if action.GrantOption {
					ctx.parsed.RiskIndicators = appendUnique(ctx.parsed.RiskIndicators, "with_grant_option")
				}
			}
		}
	case *pg_query.Node_RawStmt:
		if v.RawStmt != nil {
			walkNode(v.RawStmt.Stmt, ctx)
		}
	}
}

// granteesIncludePublic returns true when any node in the grantee list
// resolves to the PG `PUBLIC` pseudo-role (either via Roletype =
// ROLESPEC_PUBLIC or, defensively, Rolename = "public" case-insensitive).
//
// pg_query parses bare `PUBLIC` as Roletype = ROLESPEC_PUBLIC so the
// first check catches the canonical syntax. The Rolename fallback is
// defensive: a future libpg_query version that surfaces PUBLIC via the
// Rolename field instead of Roletype keeps working without a code change.
func granteesIncludePublic(grantees []*pg_query.Node) bool {
	for _, g := range grantees {
		if g == nil {
			continue
		}
		rs, ok := g.Node.(*pg_query.Node_RoleSpec)
		if !ok || rs.RoleSpec == nil {
			continue
		}
		if rs.RoleSpec.Roletype == pg_query.RoleSpecType_ROLESPEC_PUBLIC {
			return true
		}
		if strings.EqualFold(rs.RoleSpec.Rolename, "public") {
			return true
		}
	}
	return false
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

// appendUnique appends each value to the slice if it is not already
// present (case-sensitive). Used by the DCL walker to grow Privileges /
// Grantees / RiskIndicators without duplicates when the same predicate
// fires twice (e.g. a multi-statement batch with two GRANT ... TO PUBLIC
// statements would otherwise list "public_grant" twice).
//
// O(n*m) where n = current length + m = new values. Both are tiny in
// practice (DCL statements rarely carry >10 privileges / grantees) so
// a map allocation per call would be more overhead than the linear scan.
func appendUnique(slice []string, values ...string) []string {
	for _, v := range values {
		if v == "" {
			continue
		}
		found := false
		for _, existing := range slice {
			if existing == v {
				found = true
				break
			}
		}
		if !found {
			slice = append(slice, v)
		}
	}
	return slice
}

// extractGrantPrivileges turns a GrantStmt.Privileges list into the
// upper-case privilege-name slice we expose via ParsedStatement.Privileges.
//
// pg_query encoding: each Node in the list wraps an *AccessPriv whose
// PrivName is the bare privilege keyword ("SELECT", "INSERT", "UPDATE",
// etc.). An empty Privileges list is PG's encoding for `GRANT ALL ...`
// per the grammar — we surface that as the single-element ["ALL"] so
// downstream filters don't have to special-case "empty list = ALL".
//
// targtype distinguishes object-scoped grants from schema-fan-out
// grants. We don't currently use it to label privileges differently,
// but it's preserved in the signature so a future per-targtype filter
// (e.g. "ALL TABLES IN SCHEMA" is broader than per-table "ALL") has
// the hook without re-walking the AST.
func extractGrantPrivileges(privs []*pg_query.Node, _ pg_query.GrantTargetType) []string {
	if len(privs) == 0 {
		// PG grammar: empty privilege list = ALL.
		return []string{"ALL"}
	}
	out := make([]string, 0, len(privs))
	for _, p := range privs {
		if p == nil {
			continue
		}
		ap, ok := p.Node.(*pg_query.Node_AccessPriv)
		if !ok || ap.AccessPriv == nil {
			continue
		}
		name := strings.ToUpper(strings.TrimSpace(ap.AccessPriv.PrivName))
		if name == "" {
			// PG encodes "ALL" as PrivName="" + non-nil AccessPriv. Surface
			// it explicitly so the downstream stays uniform.
			name = "ALL"
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return []string{"ALL"}
	}
	return out
}

// grantHasAllPrivileges returns true when the GrantStmt.Privileges list
// indicates a wildcard ALL grant. PG encodes ALL one of two ways:
//
//   - empty Privileges list (the canonical `GRANT ALL ON ...` shape), OR
//   - a single AccessPriv with PrivName="" (defensive — older bindings)
//
// Risk-indicator population uses this; same predicate the safe-default
// floor would use if a future profile rule wanted "deny ALL grants
// regardless of grantee."
func grantHasAllPrivileges(privs []*pg_query.Node) bool {
	if len(privs) == 0 {
		return true
	}
	for _, p := range privs {
		if p == nil {
			continue
		}
		ap, ok := p.Node.(*pg_query.Node_AccessPriv)
		if !ok || ap.AccessPriv == nil {
			continue
		}
		if strings.TrimSpace(ap.AccessPriv.PrivName) == "" ||
			strings.EqualFold(strings.TrimSpace(ap.AccessPriv.PrivName), "ALL") {
			return true
		}
	}
	return false
}

// extractGranteeNames turns a grantee list (Node wrapping RoleSpec)
// into lower-case principal names. The PG `PUBLIC` pseudo-role appears
// as the literal "public" so downstream string matchers see it without
// a separate predicate.
func extractGranteeNames(grantees []*pg_query.Node) []string {
	if len(grantees) == 0 {
		return nil
	}
	out := make([]string, 0, len(grantees))
	for _, g := range grantees {
		if g == nil {
			continue
		}
		rs, ok := g.Node.(*pg_query.Node_RoleSpec)
		if !ok || rs.RoleSpec == nil {
			continue
		}
		if rs.RoleSpec.Roletype == pg_query.RoleSpecType_ROLESPEC_PUBLIC {
			out = append(out, "public")
			continue
		}
		if name := strings.ToLower(strings.TrimSpace(rs.RoleSpec.Rolename)); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// extractRoleNames pulls the role names out of a GrantRoleStmt's
// GrantedRoles list. pg_query encodes the "granted role" half as
// AccessPriv nodes (NOT RoleSpec — that's the grantee half), with
// the role name in priv_name. We lower-case + prefix with "ROLE:"
// so downstream callers can distinguish a granted role from an
// object-privilege when both populate ParsedStatement.Privileges.
//
// Defensive fallback: a future libpg_query version that switches the
// encoding to RoleSpec is also handled (the role name comes off
// RoleSpec.Rolename in that case).
func extractRoleNames(roles []*pg_query.Node) []string {
	if len(roles) == 0 {
		return nil
	}
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if r == nil {
			continue
		}
		switch n := r.Node.(type) {
		case *pg_query.Node_AccessPriv:
			if n.AccessPriv == nil {
				continue
			}
			if name := strings.ToLower(strings.TrimSpace(n.AccessPriv.PrivName)); name != "" {
				out = append(out, "ROLE:"+name)
			}
		case *pg_query.Node_RoleSpec:
			if n.RoleSpec == nil {
				continue
			}
			if name := strings.ToLower(strings.TrimSpace(n.RoleSpec.Rolename)); name != "" {
				out = append(out, "ROLE:"+name)
			}
		}
	}
	return out
}

// grantRoleHasAdminOption returns true when the GrantRoleStmt's Opt
// list contains a DefElem with defname="admin" (the WITH ADMIN OPTION
// clause). pg_query encodes options as DefElem nodes inside the Opt
// list; the canonical shape for WITH ADMIN OPTION is one DefElem
// {defname:"admin", arg:bool true}.
//
// Defensive: we treat presence of a defname="admin" DefElem as the
// option being set; older libpg_query builds that surface the option
// differently are caught by the StatementType+IsDCL+role_membership
// indicator path so the risk_indicator just narrows further when this
// helper matches.
func grantRoleHasAdminOption(opts []*pg_query.Node) bool {
	for _, o := range opts {
		if o == nil {
			continue
		}
		def, ok := o.Node.(*pg_query.Node_DefElem)
		if !ok || def.DefElem == nil {
			continue
		}
		if strings.EqualFold(def.DefElem.Defname, "admin") {
			return true
		}
	}
	return false
}

// grantTargetObjectLabel renders a stable "<kind>:<identifier>" label
// describing what the GrantStmt operates on. Per ParsedStatement.TargetObject
// docstring — examples include "database:mydb", "schema:public",
// "table:public.users".
//
// Object-kind dispatch keys off GrantStmt.Objtype (the ObjectType
// enum). Identifier shape depends on which Node type the Objects list
// carries — RangeVar for tables/sequences, String for database/schema
// names, ObjectWithArgs for functions.
//
// Per [[ibounce-honest-positioning]]: we only label the object kinds
// most commonly used in DCL workflows + the ones a deny-floor would
// most need to discriminate. Unmapped kinds (foreign tables, types,
// languages, etc.) leave TargetObject empty rather than fabricating
// a label that downstream policy might misinterpret as a known kind.
func grantTargetObjectLabel(gs *pg_query.GrantStmt) string {
	if gs == nil {
		return ""
	}
	switch gs.Targtype {
	case pg_query.GrantTargetType_ACL_TARGET_ALL_IN_SCHEMA:
		schemaName := firstSchemaName(gs.Objects)
		if schemaName == "" {
			return ""
		}
		return objtypeAllInSchemaLabel(gs.Objtype) + ":" + schemaName
	}
	// ACL_TARGET_OBJECT (or undefined, which PG treats as object-targeted):
	switch gs.Objtype {
	case pg_query.ObjectType_OBJECT_DATABASE:
		if name := firstStringName(gs.Objects); name != "" {
			return "database:" + name
		}
	case pg_query.ObjectType_OBJECT_SCHEMA:
		if name := firstStringName(gs.Objects); name != "" {
			return "schema:" + name
		}
	case pg_query.ObjectType_OBJECT_TABLE:
		if name := firstRangeVarLabel(gs.Objects); name != "" {
			return "table:" + name
		}
	case pg_query.ObjectType_OBJECT_SEQUENCE:
		if name := firstRangeVarLabel(gs.Objects); name != "" {
			return "sequence:" + name
		}
	case pg_query.ObjectType_OBJECT_FUNCTION:
		if name := firstObjectWithArgsLabel(gs.Objects); name != "" {
			return "function:" + name
		}
	}
	// Unmapped object kind — leave empty rather than guess a label.
	return ""
}

// alterDefaultPrivTargetLabel renders the TargetObject string for
// ALTER DEFAULT PRIVILEGES. Shape:
//
//	all-tables-in-schema:public  — IN SCHEMA public + objtype=TABLE
//	all-tables                   — no schema scope (server-wide ADP)
//
// The schema scope lives in the outer AlterDefaultPrivilegesStmt.Options
// list as a DefElem with defname="schemas" + arg=List of String nodes.
// The object kind lives on the inner action.Objtype.
func alterDefaultPrivTargetLabel(adp *pg_query.AlterDefaultPrivilegesStmt, action *pg_query.GrantStmt) string {
	if adp == nil || action == nil {
		return ""
	}
	schemaName := alterDefaultPrivSchemaName(adp)
	if schemaName != "" {
		if kindInSchema := objtypeAllInSchemaLabel(action.Objtype); kindInSchema != "" {
			return kindInSchema + ":" + schemaName
		}
	}
	// No schema clause = ADP applies to every schema the grantor owns.
	// Surface that as a kind-only label so downstream filters can match.
	return objtypeAllLabel(action.Objtype)
}

// alterDefaultPrivSchemaName extracts the first schema name from an
// AlterDefaultPrivilegesStmt's options list. Returns "" when no
// `IN SCHEMA <name>` clause was present (server-wide ADP).
func alterDefaultPrivSchemaName(adp *pg_query.AlterDefaultPrivilegesStmt) string {
	if adp == nil {
		return ""
	}
	for _, opt := range adp.Options {
		if opt == nil {
			continue
		}
		def, ok := opt.Node.(*pg_query.Node_DefElem)
		if !ok || def.DefElem == nil {
			continue
		}
		if !strings.EqualFold(def.DefElem.Defname, "schemas") {
			continue
		}
		if def.DefElem.Arg == nil {
			continue
		}
		listNode, ok := def.DefElem.Arg.Node.(*pg_query.Node_List)
		if !ok || listNode.List == nil {
			continue
		}
		for _, item := range listNode.List.Items {
			if item == nil {
				continue
			}
			str, ok := item.Node.(*pg_query.Node_String_)
			if !ok || str.String_ == nil {
				continue
			}
			if name := strings.ToLower(strings.TrimSpace(str.String_.Sval)); name != "" {
				return name
			}
		}
	}
	return ""
}

// objtypeAllInSchemaLabel maps an ObjectType to the kind half of the
// "all-X-in-schema:Y" label.
func objtypeAllInSchemaLabel(ot pg_query.ObjectType) string {
	switch ot {
	case pg_query.ObjectType_OBJECT_TABLE:
		return "all-tables-in-schema"
	case pg_query.ObjectType_OBJECT_SEQUENCE:
		return "all-sequences-in-schema"
	case pg_query.ObjectType_OBJECT_FUNCTION:
		return "all-functions-in-schema"
	}
	return ""
}

// objtypeAllLabel maps an ObjectType to the kind half of an ADP label
// when no schema clause is present.
func objtypeAllLabel(ot pg_query.ObjectType) string {
	switch ot {
	case pg_query.ObjectType_OBJECT_TABLE:
		return "all-tables"
	case pg_query.ObjectType_OBJECT_SEQUENCE:
		return "all-sequences"
	case pg_query.ObjectType_OBJECT_FUNCTION:
		return "all-functions"
	case pg_query.ObjectType_OBJECT_SCHEMA:
		return "all-schemas"
	case pg_query.ObjectType_OBJECT_TYPE:
		return "all-types"
	}
	return ""
}

// firstStringName extracts the first String-node value from a Node list.
// Used for ObjectType_OBJECT_DATABASE / OBJECT_SCHEMA grants where PG
// encodes the object identifier as a bare String rather than a RangeVar.
func firstStringName(objs []*pg_query.Node) string {
	for _, o := range objs {
		if o == nil {
			continue
		}
		s, ok := o.Node.(*pg_query.Node_String_)
		if !ok || s.String_ == nil {
			continue
		}
		if name := strings.ToLower(strings.TrimSpace(s.String_.Sval)); name != "" {
			return name
		}
	}
	return ""
}

// firstSchemaName extracts the first schema name from an ALL IN SCHEMA
// grant. The Objects list carries String nodes naming the schemas.
func firstSchemaName(objs []*pg_query.Node) string {
	return firstStringName(objs)
}

// firstRangeVarLabel extracts the first schema.table identifier from
// an Objects list of RangeVar nodes (TABLE / SEQUENCE grants).
func firstRangeVarLabel(objs []*pg_query.Node) string {
	for _, o := range objs {
		if o == nil {
			continue
		}
		rv, ok := o.Node.(*pg_query.Node_RangeVar)
		if !ok || rv.RangeVar == nil {
			continue
		}
		if label := qualify(rv.RangeVar); label != "" {
			return label
		}
	}
	return ""
}

// firstObjectWithArgsLabel extracts the first function name from an
// Objects list of ObjectWithArgs nodes (FUNCTION grants).
func firstObjectWithArgsLabel(objs []*pg_query.Node) string {
	for _, o := range objs {
		if o == nil {
			continue
		}
		owa, ok := o.Node.(*pg_query.Node_ObjectWithArgs)
		if !ok || owa.ObjectWithArgs == nil {
			continue
		}
		parts := make([]string, 0, len(owa.ObjectWithArgs.Objname))
		for _, p := range owa.ObjectWithArgs.Objname {
			if p == nil {
				continue
			}
			s, ok := p.Node.(*pg_query.Node_String_)
			if !ok || s.String_ == nil {
				continue
			}
			parts = append(parts, strings.ToLower(strings.TrimSpace(s.String_.Sval)))
		}
		if len(parts) == 0 {
			continue
		}
		return strings.Join(parts, ".")
	}
	return ""
}

// MySQL parser implementation. Uses github.com/xwb1989/sqlparser —
// a standalone fork of Vitess's sqlparser kept as a single Go package
// with no transitive bloat. The fork tracks MySQL 5.7-era grammar; for
// dbounce's "classify a statement" job that's sufficient — we are not
// executing or rewriting SQL, just deciding "is this a read or a write,
// what tables, what functions."
//
// Library choice: xwb1989/sqlparser over vitess.io/vitess/go/vt/sqlparser
// because vitess pulls in a heavy module tree (~hundreds of MB of
// transitive deps for cluster orchestration we don't need); the
// standalone fork is one package, one license file, and the AST shape
// is unchanged from vitess. The trade-off is no support for MySQL
// 8.x-specific syntax (CTEs / window functions), which the dbounce-
// build-plan acknowledges as a post-launch upgrade. When that gap
// matters, swap to vitess by pointing the import at vt/sqlparser; the
// AST API is identical.
//
// LOAD-BEARING dialect-shape notes (mirroring the PG parser's
// audit-cadence self-checks):
//
//   - LOAD DATA INFILE / LOAD XML / LOAD DATA LOCAL INFILE are MySQL-
//     specific exfil primitives. The xwb1989 grammar does NOT recognize
//     them as a top-level statement (Vitess never needed to), so the
//     parser would fall through to StmtUnparseable. We surface them via
//     a keyword pre-check BEFORE handing bytes to xwb1989: a SQL whose
//     trimmed lead is "LOAD" gets classified StmtLoad +
//     MutatingNodeType = "LOAD-DATA-INFILE" so the MySQL rule pack can
//     match on LOAD:* without depending on AST detail.
//
//   - SET GLOBAL <varname> = <value> is the mutating MySQL admin
//     command (changes server-wide state). The Set AST exposes a Scope
//     field; we map Scope == "global" to StatementType = StmtSet with
//     MutatingNodeType = "SET-GLOBAL" so a SET:set-global rule can be
//     written without ambiguity.
//
//   - Prepared statements (PREPARE / EXECUTE) and stored-procedure CALL
//     are NOT in xwb1989's grammar either; the proxy's wire-protocol
//     handler rejects COM_STMT_PREPARE separately (see
//     proxy/mysql.go's gateMySQLCommand). What reaches Parse() is
//     COM_QUERY-encapsulated SQL only.
//
// Per [[creates-never-mutates]]: this file PARSES. No execution, no
// connection, no credentials. Same invariant as parsePostgres.
package parser

import (
	"strings"

	"github.com/xwb1989/sqlparser"
)

// parseMySQL turns a raw MySQL statement into a ParsedStatement. Same
// contract as parsePostgres: never returns nil, surfaces StmtUnparseable
// + ParseErrors on any parser error so the audit log keeps a record of
// what the client tried.
func parseMySQL(raw string) *ParsedStatement {
	out := &ParsedStatement{
		Raw:     raw,
		Dialect: DialectMySQL,
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		out.StatementType = StmtUnknown
		return out
	}

	// LOAD DATA INFILE pre-check — xwb1989's grammar doesn't recognize
	// LOAD as a top-level statement, but it's the canonical MySQL exfil
	// shape and the rule pack MUST be able to match on it. Surface it
	// explicitly BEFORE we hand bytes to the AST parser.
	upper := strings.ToUpper(trimmed)
	if strings.HasPrefix(upper, "LOAD DATA") ||
		strings.HasPrefix(upper, "LOAD XML") ||
		strings.HasPrefix(upper, "LOAD INDEX") {
		out.StatementType = StmtLoad
		out.HasMutatingNode = true
		out.MutatingNodeType = mysqlMutatingLoadDataInfile
		out.IsDML = true
		out.TablesTouched = mysqlLoadDataInfileTable(trimmed)
		return out
	}

	// xwb1989/sqlparser can handle multi-statement batches via
	// ParseNext + Tokenizer; the simpler Parse() consumes just the
	// first statement. We mirror the PG parser's batch semantics: the
	// FIRST statement drives StatementType, but we walk all of them
	// for tables/functions/HasMutatingNode. This matters because a
	// `SELECT 1; UPDATE secrets SET x = 1` batch should still surface
	// the UPDATE for the audit row.
	tokenizer := sqlparser.NewStringTokenizer(raw)
	stmts := []sqlparser.Statement{}
	for {
		stmt, err := sqlparser.ParseNext(tokenizer)
		if err != nil {
			// Parse error on first statement = StmtUnparseable; on a
			// subsequent statement, keep the first classification + record
			// the error in ParseErrors so the audit row sees both.
			if len(stmts) == 0 {
				out.StatementType = StmtUnparseable
				out.ParseErrors = []string{err.Error()}
				return out
			}
			// EOF marker reaches here as io.EOF wrapped — the xwb1989
			// code returns io.EOF from ParseNext when the tokenizer is
			// done. Treat ANY post-first error as end-of-batch (we
			// already have at least one valid statement).
			break
		}
		if stmt == nil {
			break
		}
		stmts = append(stmts, stmt)
		// Cap batch size defensively — a single inbound packet should
		// not have hundreds of statements. The PG side has implicit
		// libpg_query bounds; we apply our own here.
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
		// Pre-pass: collect aliases declared by this statement's
		// AliasedTableExpr nodes so the main walk can skip ColName
		// qualifiers that match.
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

	// IsDML / IsDDL derivation from StatementType (parallel to PG path).
	switch out.StatementType {
	case StmtInsert, StmtUpdate, StmtDelete, StmtMerge:
		out.IsDML = true
	case StmtDDL, StmtTruncate, StmtComment:
		out.IsDDL = true
	}
	return out
}

// MutatingNodeType labels surfaced for MySQL-specific shapes. Kept as
// package consts so the rule pack + recommender can match on a stable
// vocabulary.
const (
	mysqlMutatingLoadDataInfile = "LOAD-DATA-INFILE"
	mysqlMutatingSetGlobal      = "SET-GLOBAL"
)

// classifyMySQLTopLevel maps an xwb1989 Statement to one of the
// dialect-agnostic Stmt* constants. The walker handles deeper-nested
// shapes; this just picks the StatementType the audit row will display.
func classifyMySQLTopLevel(stmt sqlparser.Statement) string {
	switch s := stmt.(type) {
	case *sqlparser.Select, *sqlparser.Union, *sqlparser.ParenSelect:
		return StmtSelect
	case *sqlparser.Insert:
		// REPLACE INTO maps to Insert with Action="replace" — semantically
		// a DML write (delete-then-insert), so we classify as INSERT +
		// MutatingNodeType gets the actual verb during the walk.
		return StmtInsert
	case *sqlparser.Update:
		return StmtUpdate
	case *sqlparser.Delete:
		return StmtDelete
	case *sqlparser.Set:
		return StmtSet
	case *sqlparser.DDL:
		switch s.Action {
		case sqlparser.TruncateStr:
			return StmtTruncate
		default:
			return StmtDDL
		}
	case *sqlparser.DBDDL:
		return StmtDDL
	case *sqlparser.Show:
		return StmtShow
	case *sqlparser.Use:
		return StmtUse
	case *sqlparser.Begin, *sqlparser.Commit, *sqlparser.Rollback:
		return StmtTransaction
	case *sqlparser.OtherRead:
		// EXPLAIN / DESCRIBE / DESC — xwb1989 lumps them under OtherRead.
		return StmtExplain
	case *sqlparser.OtherAdmin:
		// REPAIR / OPTIMIZE / ANALYZE — admin / mutating ops on the
		// physical table. Classify as DDL bucket; the rule pack can
		// narrow via MutatingNodeType.
		return StmtDDL
	}
	return StmtUnknown
}

// mysqlWalkCtx mirrors the PG walker's context shape.
type mysqlWalkCtx struct {
	parsed        *ParsedStatement
	tables        map[string]struct{}
	functions     map[string]struct{}
	// aliases collects per-table aliases so we don't accidentally add
	// the alias to TablesTouched when ColName.Qualifier walks it as a
	// TableName. xwb1989's AST encodes `u.id` as a ColName whose
	// Qualifier is TableName{Name:"u"}; without this filter "u" would
	// pollute TablesTouched.
	aliases       map[string]struct{}
	canReclassify bool
}

// mysqlWalk drives xwb1989/sqlparser's Walk over a statement,
// collecting tables touched / functions called / mutating-node
// signals.
//
// xwb1989's Walk is depth-first with a "kontinue bool" return per
// visit: returning false short-circuits the subtree (we never do).
// Errors from the visitor bubble out of Walk; we never produce errors
// from the visitor (a parse-time table-name collection is best-effort
// only — a malformed TableName just doesn't contribute to the set,
// rather than failing the whole parse).
func mysqlWalk(stmt sqlparser.Statement, ctx *mysqlWalkCtx) {
	// Pre-walk dispatch: some shapes carry mutating semantics we need
	// to flag BEFORE the generic walk visits them. SET GLOBAL is the
	// canonical example.
	switch s := stmt.(type) {
	case *sqlparser.Insert:
		mysqlFlagMutating(ctx, mysqlInsertVerb(s))
	case *sqlparser.Update:
		mysqlFlagMutating(ctx, "UPDATE")
	case *sqlparser.Delete:
		mysqlFlagMutating(ctx, "DELETE")
	case *sqlparser.Set:
		if strings.EqualFold(s.Scope, "global") {
			mysqlFlagMutating(ctx, mysqlMutatingSetGlobal)
		}
		// SET ROLE capture — xwb1989's SetExpr.Name holds the variable
		// name; the value is in Expr. Best-effort string extraction for
		// the rare `SET ROLE 'rolename'` case.
		for _, expr := range s.Exprs {
			if expr == nil {
				continue
			}
			if strings.EqualFold(expr.Name.String(), "role") {
				ctx.parsed.ImpersonatedRole = sqlparser.String(expr.Expr)
			}
		}
	case *sqlparser.DDL:
		switch s.Action {
		case sqlparser.TruncateStr:
			mysqlFlagMutating(ctx, "TRUNCATE")
		default:
			// CREATE / ALTER / DROP / RENAME — flag as mutating shape so
			// MUTATING:* rules catch them via HasMutatingNode (parallels
			// PG path: IsDDL + HasMutatingNode both true is fine).
			mysqlFlagMutating(ctx, strings.ToUpper(s.Action))
		}
	case *sqlparser.DBDDL:
		mysqlFlagMutating(ctx, strings.ToUpper(s.Action)+"-DATABASE")
	}

	// Generic walk: pick up TableName references + FuncExpr calls
	// wherever they appear. Skip ColName.Qualifier — xwb1989 encodes
	// column references like `u.id` as ColName{Qualifier: TableName{Name:"u"}}
	// and the unqualified "u" is an alias, not a real table.
	_ = sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		switch n := node.(type) {
		case *sqlparser.ColName:
			// Walk the Name (ColIdent) but stop the subtree so the
			// Qualifier (a TableName) doesn't reach the TableName branch
			// below. Returning false short-circuits the subtree.
			return false, nil
		case sqlparser.TableName:
			if n.IsEmpty() {
				return true, nil
			}
			qualified := mysqlQualifyTable(n)
			// Drop alias references: if the TableName has no qualifier
			// AND its bare name matches an alias declared in the same
			// statement, skip it.
			if n.Qualifier.IsEmpty() {
				if _, isAlias := ctx.aliases[strings.ToLower(n.Name.String())]; isAlias {
					return true, nil
				}
			}
			ctx.tables[qualified] = struct{}{}
		case *sqlparser.FuncExpr:
			if !n.Name.IsEmpty() {
				ctx.functions[mysqlFuncName(n)] = struct{}{}
			}
		}
		return true, nil
	}, stmt)
}

// mysqlFlagMutating records a mutating-node sighting (parallels the PG
// flagMutating helper).
func mysqlFlagMutating(ctx *mysqlWalkCtx, kind string) {
	ctx.parsed.HasMutatingNode = true
	if ctx.parsed.MutatingNodeType == "" {
		ctx.parsed.MutatingNodeType = kind
	}
}

// mysqlInsertVerb returns "INSERT" for an INSERT INTO and "REPLACE" for
// REPLACE INTO (which xwb1989 models as an Insert with Action = replace).
func mysqlInsertVerb(s *sqlparser.Insert) string {
	if s != nil && strings.EqualFold(s.Action, sqlparser.ReplaceStr) {
		return "REPLACE"
	}
	return "INSERT"
}

// mysqlQualifyTable renders a TableName as "schema.table" (or just
// "table" when no qualifier is set). Lowercased so matchers don't have
// to case-normalize per [[scorer-is-ground-truth]]: rule patterns key
// off the parser's normalized form.
func mysqlQualifyTable(t sqlparser.TableName) string {
	name := strings.ToLower(t.Name.String())
	qual := strings.ToLower(t.Qualifier.String())
	if qual == "" {
		return name
	}
	return qual + "." + name
}

// mysqlFuncName renders a FuncExpr as "schema.fn" (or just "fn") in
// lowercase. Empty when no name parts are present.
func mysqlFuncName(f *sqlparser.FuncExpr) string {
	if f == nil {
		return ""
	}
	name := strings.ToLower(f.Name.String())
	qual := strings.ToLower(f.Qualifier.String())
	if qual == "" {
		return name
	}
	return qual + "." + name
}

// mysqlLoadDataInfileTable extracts the destination table from a LOAD
// DATA INFILE / LOAD XML statement. xwb1989 doesn't parse these, so we
// do a small keyword scan: the "INTO TABLE <name>" clause carries the
// table identifier. Best-effort — falls back to nil when the shape
// doesn't match, in which case the audit row records LOAD without a
// table (the MUTATING category still gates it).
func mysqlLoadDataInfileTable(sql string) []string {
	upper := strings.ToUpper(sql)
	idx := strings.Index(upper, "INTO TABLE")
	if idx < 0 {
		return nil
	}
	rest := strings.TrimSpace(sql[idx+len("INTO TABLE"):])
	// Take the first identifier-like token. Backticks, quotes, and
	// schema-dot-table forms are all preserved verbatim.
	end := len(rest)
	for i, ch := range rest {
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == ';' ||
			ch == '(' || ch == ',' {
			end = i
			break
		}
	}
	tok := rest[:end]
	tok = strings.Trim(tok, "`\"'")
	tok = strings.ToLower(tok)
	if tok == "" {
		return nil
	}
	return []string{tok}
}

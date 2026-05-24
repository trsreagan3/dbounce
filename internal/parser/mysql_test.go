package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MySQL parser tests cover the same audit-row-relevant fields the PG
// tests do (StatementType, TablesTouched, FunctionsCalled,
// HasMutatingNode, MutatingNodeType) so the cross-product audit-log
// scraper has consistent shape across all rows.
//
// Coverage:
//
//   - SELECT (simple, joins, subqueries, schema-qualified, UNION)
//   - INSERT / UPDATE / DELETE / REPLACE INTO (REPLACE classified as INSERT
//     with MutatingNodeType=REPLACE for rule-pack distinction)
//   - INSERT ... ON DUPLICATE KEY UPDATE
//   - DDL: CREATE / ALTER / DROP / TRUNCATE / RENAME
//   - SHOW TABLES / SHOW VARIABLES (informational reads)
//   - USE <db> (session-state change)
//   - SET GLOBAL <var> = <value> (mutating admin command — load-bearing)
//   - SET session-scope (NOT mutating)
//   - LOAD DATA INFILE (MySQL exfil primitive — load-bearing pre-check)
//   - LOAD XML / LOAD DATA LOCAL INFILE variants
//   - Multi-statement batches
//   - Malformed / empty SQL — never panics; surfaces UNPARSEABLE
//   - Function-call detection (volatile / aggregate)

func myParse(raw string) *ParsedStatement {
	return Parse(DialectMySQL, raw)
}

func TestMySQL_SimpleSelect(t *testing.T) {
	ps := myParse("SELECT id, name FROM users WHERE id = 1")
	require.NotNil(t, ps)
	assert.Equal(t, DialectMySQL, ps.Dialect)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Equal(t, []string{"users"}, ps.TablesTouched)
	assert.False(t, ps.IsDML)
	assert.False(t, ps.HasMutatingNode)
	assert.Empty(t, ps.ParseErrors)
}

func TestMySQL_SchemaQualifiedTable(t *testing.T) {
	ps := myParse("SELECT * FROM mydb.orders")
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Equal(t, []string{"mydb.orders"}, ps.TablesTouched)
}

func TestMySQL_SelectWithJoin(t *testing.T) {
	ps := myParse(`SELECT u.id, o.total FROM users u JOIN orders o ON o.user_id = u.id WHERE u.id = 1`)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.ElementsMatch(t, []string{"users", "orders"}, ps.TablesTouched)
}

func TestMySQL_SelectSubquery(t *testing.T) {
	ps := myParse(`SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 100)`)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.ElementsMatch(t, []string{"users", "orders"}, ps.TablesTouched)
}

func TestMySQL_SelectUnion(t *testing.T) {
	ps := myParse(`SELECT id FROM users UNION SELECT id FROM admins`)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.ElementsMatch(t, []string{"users", "admins"}, ps.TablesTouched)
}

func TestMySQL_SelectVolatileFunction(t *testing.T) {
	ps := myParse("SELECT SLEEP(60)")
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Contains(t, ps.FunctionsCalled, "sleep")
}

func TestMySQL_SelectAggregate(t *testing.T) {
	// xwb1989 treats count/max as special funcs (FuncExpr) — should
	// still surface in FunctionsCalled.
	ps := myParse("SELECT MAX(price) FROM products")
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Contains(t, ps.FunctionsCalled, "max")
}

func TestMySQL_Insert(t *testing.T) {
	ps := myParse(`INSERT INTO users (id, name) VALUES (1, 'alice')`)
	assert.Equal(t, StmtInsert, ps.StatementType)
	assert.Equal(t, []string{"users"}, ps.TablesTouched)
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "INSERT", ps.MutatingNodeType)
}

func TestMySQL_Replace(t *testing.T) {
	// REPLACE INTO is MySQL-specific. xwb1989 models it as an Insert
	// with Action="replace"; we surface it as INSERT (StatementType) +
	// REPLACE (MutatingNodeType) so a rule pack can deny "REPLACE only"
	// without losing INSERT denies.
	ps := myParse(`REPLACE INTO users (id, name) VALUES (1, 'alice')`)
	assert.Equal(t, StmtInsert, ps.StatementType,
		"REPLACE INTO classifies as INSERT (semantically a write)")
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "REPLACE", ps.MutatingNodeType,
		"MutatingNodeType MUST distinguish REPLACE from INSERT for rule-pack precision")
}

func TestMySQL_InsertOnDuplicateKey(t *testing.T) {
	ps := myParse(`INSERT INTO users (id, name) VALUES (1, 'alice') ON DUPLICATE KEY UPDATE name = VALUES(name)`)
	assert.Equal(t, StmtInsert, ps.StatementType)
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, []string{"users"}, ps.TablesTouched)
}

func TestMySQL_Update(t *testing.T) {
	ps := myParse(`UPDATE users SET name = 'bob' WHERE id = 1`)
	assert.Equal(t, StmtUpdate, ps.StatementType)
	assert.Equal(t, []string{"users"}, ps.TablesTouched)
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "UPDATE", ps.MutatingNodeType)
}

func TestMySQL_UpdateJoin(t *testing.T) {
	ps := myParse(`UPDATE orders o JOIN payments p ON o.id = p.order_id SET o.status = 'paid'`)
	assert.Equal(t, StmtUpdate, ps.StatementType)
	assert.ElementsMatch(t, []string{"orders", "payments"}, ps.TablesTouched)
}

func TestMySQL_Delete(t *testing.T) {
	ps := myParse(`DELETE FROM sessions WHERE expired_at < NOW()`)
	assert.Equal(t, StmtDelete, ps.StatementType)
	assert.Equal(t, []string{"sessions"}, ps.TablesTouched)
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
}

// DDL coverage.

func TestMySQL_CreateTable(t *testing.T) {
	ps := myParse(`CREATE TABLE foo (id INT)`)
	assert.Equal(t, StmtDDL, ps.StatementType)
	assert.True(t, ps.IsDDL)
}

func TestMySQL_AlterTable(t *testing.T) {
	ps := myParse(`ALTER TABLE users ADD COLUMN email VARCHAR(255)`)
	assert.Equal(t, StmtDDL, ps.StatementType)
}

func TestMySQL_DropTable(t *testing.T) {
	ps := myParse(`DROP TABLE users`)
	assert.Equal(t, StmtDDL, ps.StatementType)
}

func TestMySQL_Truncate(t *testing.T) {
	ps := myParse(`TRUNCATE TABLE audit_log`)
	assert.Equal(t, StmtTruncate, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
}

func TestMySQL_CreateIndex(t *testing.T) {
	ps := myParse(`CREATE INDEX idx_users_email ON users(email)`)
	assert.Equal(t, StmtDDL, ps.StatementType)
}

// MySQL-specific informational + admin shapes.

func TestMySQL_ShowTables(t *testing.T) {
	ps := myParse(`SHOW TABLES`)
	assert.Equal(t, StmtShow, ps.StatementType)
	assert.False(t, ps.HasMutatingNode, "SHOW is informational only")
}

func TestMySQL_ShowVariables(t *testing.T) {
	ps := myParse(`SHOW VARIABLES LIKE 'max_%'`)
	assert.Equal(t, StmtShow, ps.StatementType)
	assert.False(t, ps.HasMutatingNode)
}

func TestMySQL_UseDatabase(t *testing.T) {
	ps := myParse(`USE production`)
	assert.Equal(t, StmtUse, ps.StatementType)
	assert.False(t, ps.HasMutatingNode)
}

// SET GLOBAL — load-bearing: this changes server-wide state and the
// rule pack MUST be able to gate it specifically.
func TestMySQL_SetGlobal(t *testing.T) {
	ps := myParse(`SET GLOBAL max_connections = 500`)
	assert.Equal(t, StmtSet, ps.StatementType)
	assert.True(t, ps.HasMutatingNode,
		"SET GLOBAL changes server-wide state — MUST flag as mutating")
	assert.Equal(t, mysqlMutatingSetGlobal, ps.MutatingNodeType)
}

func TestMySQL_SetSession_NotMutating(t *testing.T) {
	// SET @@SESSION.var = val (or just SET var=val) is session-scoped
	// and not mutating server state. We don't mark it mutating.
	ps := myParse(`SET sql_mode = 'STRICT_ALL_TABLES'`)
	assert.Equal(t, StmtSet, ps.StatementType)
	assert.False(t, ps.HasMutatingNode,
		"session-scoped SET does NOT change server-wide state — must NOT be flagged mutating")
}

// LOAD DATA INFILE — the canonical MySQL exfil primitive. Load-bearing:
// the rule pack relies on the StmtLoad classification + MutatingNodeType.
func TestMySQL_LoadDataInfile(t *testing.T) {
	ps := myParse(`LOAD DATA INFILE '/tmp/users.csv' INTO TABLE users`)
	assert.Equal(t, StmtLoad, ps.StatementType,
		"LOAD DATA INFILE MUST classify as StmtLoad for rule-pack matching")
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, mysqlMutatingLoadDataInfile, ps.MutatingNodeType)
	assert.True(t, ps.IsDML)
	assert.Contains(t, ps.TablesTouched, "users")
}

func TestMySQL_LoadDataLocalInfile(t *testing.T) {
	// The LOCAL variant — same exfil shape, must classify identically.
	ps := myParse(`LOAD DATA LOCAL INFILE '/tmp/x.csv' INTO TABLE staging.imports`)
	assert.Equal(t, StmtLoad, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, mysqlMutatingLoadDataInfile, ps.MutatingNodeType)
	assert.Contains(t, ps.TablesTouched, "staging.imports")
}

func TestMySQL_LoadXML(t *testing.T) {
	ps := myParse(`LOAD XML INFILE '/tmp/data.xml' INTO TABLE products`)
	assert.Equal(t, StmtLoad, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
	assert.Contains(t, ps.TablesTouched, "products")
}

// CRIT-D8-01 regression — comment-prefix bypass. Every shape below was
// exploitable before stripcomments.go landed: the trimmed prefix on raw
// bytes missed because the byte at position 0 was `/` or `-` not `L`.
// AUDIT-WB-DSLICES-1-8.md §CRIT-D8-01 has the full reproduction.

func TestMySQL_LoadDataInfile_BlockCommentPrefix(t *testing.T) {
	ps := myParse(`/* */ LOAD DATA INFILE '/tmp/x' INTO TABLE secrets`)
	assert.Equal(t, StmtLoad, ps.StatementType,
		"leading /* */ block comment MUST NOT hide LOAD DATA from the prefix check")
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, mysqlMutatingLoadDataInfile, ps.MutatingNodeType)
	assert.Contains(t, ps.TablesTouched, "secrets")
}

func TestMySQL_LoadDataInfile_LineCommentPrefix(t *testing.T) {
	ps := myParse("-- attacker injected\nLOAD DATA INFILE '/tmp/x' INTO TABLE secrets")
	assert.Equal(t, StmtLoad, ps.StatementType,
		"leading -- comment MUST NOT hide LOAD DATA from the prefix check")
	assert.True(t, ps.HasMutatingNode)
	assert.Contains(t, ps.TablesTouched, "secrets")
}

func TestMySQL_LoadDataInfile_NestedBlockCommentPrefix(t *testing.T) {
	ps := myParse(`/*outer /*inner*/ outer*/ LOAD DATA INFILE '/tmp/x' INTO TABLE u`)
	assert.Equal(t, StmtLoad, ps.StatementType,
		"nested block comments MUST be stripped fully before the prefix check")
	assert.True(t, ps.HasMutatingNode)
}

func TestMySQL_LoadDataInfile_CaseInsensitivePrefix(t *testing.T) {
	ps := myParse(`/* x */ lOaD DaTa InFiLe '/tmp/x' INTO TABLE u`)
	assert.Equal(t, StmtLoad, ps.StatementType,
		"case-insensitive prefix MUST match after comment-strip + ToUpper")
	assert.True(t, ps.HasMutatingNode)
}

func TestMySQL_LiteralLooksLikeCommentNotStripped(t *testing.T) {
	// String literal CONTAINING a comment-shaped substring MUST NOT be
	// confused with an actual comment. This SELECT must classify as
	// SELECT, not get falsely flagged as a LOAD.
	ps := myParse(`SELECT '/* not a comment */ LOAD DATA' FROM t`)
	assert.Equal(t, StmtSelect, ps.StatementType,
		"comment markers inside a string literal MUST NOT trigger the LOAD prefix")
}

// Transactions.

func TestMySQL_Begin(t *testing.T) {
	ps := myParse(`BEGIN`)
	assert.Equal(t, StmtTransaction, ps.StatementType)
}

func TestMySQL_Commit(t *testing.T) {
	ps := myParse(`COMMIT`)
	assert.Equal(t, StmtTransaction, ps.StatementType)
}

func TestMySQL_Rollback(t *testing.T) {
	ps := myParse(`ROLLBACK`)
	assert.Equal(t, StmtTransaction, ps.StatementType)
}

// Multi-statement batches: first statement drives StatementType, but
// TablesTouched + HasMutatingNode aggregate across all.
func TestMySQL_MultiStatementBatch(t *testing.T) {
	ps := myParse(`SELECT 1; UPDATE secrets SET val = 'oops'`)
	// First statement is SELECT.
	assert.Equal(t, StmtSelect, ps.StatementType)
	// The walker MUST have surfaced the UPDATE.
	assert.True(t, ps.HasMutatingNode,
		"multi-statement batch's mutating shape MUST surface for audit")
	assert.Contains(t, ps.TablesTouched, "secrets")
}

// Malformed / pathological — must NEVER panic.

func TestMySQL_Empty(t *testing.T) {
	ps := myParse("")
	require.NotNil(t, ps)
	assert.Equal(t, StmtUnknown, ps.StatementType)
}

func TestMySQL_OnlyWhitespace(t *testing.T) {
	ps := myParse("   \n\t  ")
	assert.Equal(t, StmtUnknown, ps.StatementType)
}

func TestMySQL_Garbage(t *testing.T) {
	ps := myParse("zxcvbnm asdfghjkl !@#$%^&*()")
	assert.Equal(t, StmtUnparseable, ps.StatementType)
	assert.NotEmpty(t, ps.ParseErrors)
}

func TestMySQL_PartialStatement(t *testing.T) {
	ps := myParse("SELECT * FROM")
	assert.Equal(t, StmtUnparseable, ps.StatementType)
	assert.NotEmpty(t, ps.ParseErrors)
}

// Raw text must round-trip verbatim.
func TestMySQL_RawPreserved(t *testing.T) {
	in := "  SELECT 1;  \n"
	ps := myParse(in)
	assert.Equal(t, in, ps.Raw)
}

// Table identifier normalization — matchers operate on lowercase.
func TestMySQL_TableNormalization(t *testing.T) {
	ps := myParse(`SELECT * FROM MyDB.Users`)
	assert.Equal(t, []string{"mydb.users"}, ps.TablesTouched)
}

func TestMySQL_FunctionLowercase(t *testing.T) {
	ps := myParse(`SELECT SLEEP(60)`)
	assert.Contains(t, ps.FunctionsCalled, "sleep")
}

// Dispatcher coverage — unknown dialect surfaces UNPARSEABLE with a
// helpful error, no panic. Snowflake + BigQuery are recognized as of
// D-Slice 6; use a clearly-fake dialect here.
func TestParse_UnknownDialect(t *testing.T) {
	ps := Parse("teradata-fake", "SELECT 1")
	require.NotNil(t, ps)
	assert.Equal(t, StmtUnparseable, ps.StatementType)
	assert.NotEmpty(t, ps.ParseErrors)
	assert.Contains(t, ps.ParseErrors[0], "teradata-fake")
}

func TestParse_EmptyDialectDefaultsToPostgres(t *testing.T) {
	// Backward-compat: empty dialect → postgres. Lets legacy callers
	// keep working through the dispatcher.
	ps := Parse("", "SELECT 1")
	require.NotNil(t, ps)
	assert.Equal(t, DialectPostgres, ps.Dialect)
	assert.Equal(t, StmtSelect, ps.StatementType)
}

// ---------------------------------------------------------------------------
// MySQL DCL parity tests — per #556 follow-up from UC-34. Before this slice
// the MySQL classifier had ZERO DCL handling (xwb1989 doesn't model
// GRANT/REVOKE/CREATE USER/etc.), so the proxy.decide() Step 5.5
// admin-tight floor NEVER fired on MySQL upstreams. Every test below
// asserts:
//   - StatementType (drives the floor's isAdminGrantShape predicate)
//   - IsDCL=true (drives the floor's first-half check)
//   - MutatingNodeType (cross-product rule-pack vocabulary)
//   - Operation-relevant field population (Privileges/Grantees/etc.)
//   - RiskIndicators (SIEM-filter vocabulary parity w/ PG path)
//
// Per [[ibounce-honest-positioning]]: the MySQL DCL parser is
// keyword-based (xwb1989 doesn't have an AST for these statements), so
// edge cases that the PG AST parser handles via tree-walking may be
// less precisely captured here. Mirroring the PG path's risk-indicator
// vocabulary keeps the cross-dialect audit experience consistent.
// ---------------------------------------------------------------------------

func TestGrantAllOnTableToPublicMySQL(t *testing.T) {
	// The canonical UC-34 hostile shape ported to MySQL: GRANT ALL ON
	// foo.* TO PUBLIC. MUST classify as StmtGrant + IsDCL=true so the
	// admin-tight floor in proxy.decide() Step 5.5 refuses it.
	// risk_indicators MUST include "public_grant" + "all_privileges"
	// for SIEM filter parity with the PG path's UC-34 audit row.
	ps := myParse(`GRANT ALL ON foo.* TO PUBLIC`)
	assert.Equal(t, StmtGrant, ps.StatementType,
		"GRANT MUST classify as StmtGrant so admin-tight floor fires")
	assert.True(t, ps.IsDCL, "MySQL GRANT MUST set IsDCL=true")
	assert.Equal(t, mysqlDCLOpGrant, ps.MutatingNodeType,
		"MutatingNodeType MUST surface mysqlDCLOpGrant for rule-pack matching")
	assert.Equal(t, []string{"ALL"}, ps.Privileges)
	assert.Equal(t, []string{"public"}, ps.Grantees)
	assert.Equal(t, "schema:foo.*", ps.TargetObject)
	assert.Contains(t, ps.RiskIndicators, "public_grant",
		"GRANT ... TO PUBLIC MUST flag public_grant indicator")
	assert.Contains(t, ps.RiskIndicators, "all_privileges",
		"GRANT ALL ... MUST flag all_privileges indicator")
	// DCL is not DML — HasMutatingNode stays false (matches PG semantics).
	assert.False(t, ps.IsDML, "DCL MUST NOT set IsDML")
	assert.False(t, ps.IsDDL, "DCL MUST NOT set IsDDL")
}

func TestGrantSelectToUserMySQL(t *testing.T) {
	// Non-PUBLIC, non-ALL: still admin-grant (StmtGrant + IsDCL=true)
	// but with neither public_grant NOR all_privileges flagged. The
	// wildcard_host indicator DOES fire because grantee is 'bob'@'%'
	// (any-host grant) — distinct from a public_grant but still worth
	// audit attention.
	ps := myParse(`GRANT SELECT ON foo.bar TO 'bob'@'%'`)
	assert.Equal(t, StmtGrant, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.Equal(t, []string{"SELECT"}, ps.Privileges)
	assert.Equal(t, []string{"'bob'@'%'"}, ps.Grantees)
	assert.Equal(t, "table:foo.bar", ps.TargetObject)
	assert.NotContains(t, ps.RiskIndicators, "public_grant",
		"specific user is NOT PUBLIC; public_grant must NOT fire")
	assert.NotContains(t, ps.RiskIndicators, "all_privileges")
	assert.Contains(t, ps.RiskIndicators, "wildcard_host",
		"'bob'@'%' is any-host; wildcard_host indicator MUST fire")
}

func TestGrantWithGrantOptionMySQL(t *testing.T) {
	// WITH GRANT OPTION — grantee can re-grant the privilege. Always
	// flagged. Matches PG path's with_grant_option indicator semantics.
	ps := myParse(`GRANT SELECT ON foo.* TO 'bob'@'%' WITH GRANT OPTION`)
	assert.Equal(t, StmtGrant, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.Contains(t, ps.RiskIndicators, "with_grant_option",
		"WITH GRANT OPTION MUST flag with_grant_option indicator")
}

func TestRevokeMySQL(t *testing.T) {
	// REVOKE — cleanup direction. MUST classify as StmtRevoke + IsDCL.
	// The admin-tight floor (proxy decide Step 5.5) does NOT fire on
	// StmtRevoke (only StmtGrant + StmtAlterPrivileges), so REVOKE
	// remains advisory under default-policy=allow even with no rules.
	// Privileges + grantees + target still extracted (audit signal).
	ps := myParse(`REVOKE SELECT ON foo.* FROM 'bob'@'%'`)
	assert.Equal(t, StmtRevoke, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.Equal(t, mysqlDCLOpRevoke, ps.MutatingNodeType)
	assert.Equal(t, []string{"SELECT"}, ps.Privileges)
	assert.Equal(t, []string{"'bob'@'%'"}, ps.Grantees)
	assert.Equal(t, "schema:foo.*", ps.TargetObject)
	// REVOKE never flags public_grant / all_privileges (cleanup, not
	// escalation).
	assert.NotContains(t, ps.RiskIndicators, "public_grant")
	assert.NotContains(t, ps.RiskIndicators, "all_privileges")
}

func TestCreateUserMySQL(t *testing.T) {
	// CREATE USER ... IDENTIFIED BY '...'. Classified as StmtGrant
	// (creating a user IS an admin-grant — they exist solely to be the
	// target of subsequent GRANTs). Two risk_indicators MUST fire:
	// "create_user" (the shape itself) + "identified_by_password" (the
	// password literal is now in the audit row's Statement column).
	ps := myParse(`CREATE USER 'newuser'@'%' IDENTIFIED BY 'secret'`)
	assert.Equal(t, StmtGrant, ps.StatementType,
		"CREATE USER classifies as StmtGrant so admin-tight floor fires")
	assert.True(t, ps.IsDCL)
	assert.Equal(t, mysqlDCLOpCreateUser, ps.MutatingNodeType)
	assert.Contains(t, ps.RiskIndicators, "create_user",
		"CREATE USER MUST flag create_user indicator")
	assert.Contains(t, ps.RiskIndicators, "identified_by_password",
		"IDENTIFIED BY '...' MUST flag identified_by_password indicator")
	assert.Contains(t, ps.RiskIndicators, "wildcard_host",
		"'newuser'@'%' MUST flag wildcard_host indicator")
	assert.Contains(t, ps.Grantees, "'newuser'@'%'",
		"CREATE USER grantee list MUST include the new account")
	assert.Equal(t, []string{"CREATE USER"}, ps.Privileges)
}

func TestDropUserMySQL(t *testing.T) {
	// DROP USER — cleanup direction. Classified as StmtRevoke so the
	// admin-tight floor does NOT refuse it (paralleling REVOKE
	// semantics). Operators who want DROP USER gated add an explicit
	// MUTATING:* or DROP-USER MutatingNodeType deny.
	ps := myParse(`DROP USER 'olduser'@'%'`)
	assert.Equal(t, StmtRevoke, ps.StatementType,
		"DROP USER classifies as StmtRevoke (cleanup direction)")
	assert.True(t, ps.IsDCL)
	assert.Equal(t, mysqlDCLOpDropUser, ps.MutatingNodeType)
	assert.Contains(t, ps.Grantees, "'olduser'@'%'")
	assert.Equal(t, []string{"DROP USER"}, ps.Privileges)
}

func TestGrantWildcardHostMySQL(t *testing.T) {
	// GRANT ALL ON *.* TO 'admin'@'%' — the canonical
	// "give-admin-everything-from-anywhere" shape. Three indicators
	// MUST fire: all_privileges + wildcard_host + (NOT public_grant
	// because 'admin'@'%' is not PUBLIC).
	ps := myParse(`GRANT ALL ON *.* TO 'admin'@'%'`)
	assert.Equal(t, StmtGrant, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.Contains(t, ps.RiskIndicators, "all_privileges")
	assert.Contains(t, ps.RiskIndicators, "wildcard_host")
	assert.NotContains(t, ps.RiskIndicators, "public_grant",
		"'admin'@'%' is wildcard-host but NOT PUBLIC; public_grant must NOT fire")
	assert.Equal(t, "global:*.*", ps.TargetObject,
		"*.* MUST surface as global:*.* TargetObject")
	assert.Equal(t, []string{"'admin'@'%'"}, ps.Grantees)
}

func TestRenameUserMySQL(t *testing.T) {
	// RENAME USER — silently invalidates downstream allow_rules pinned
	// to the old name. Classified as StmtAlterPrivileges so admin-tight
	// floor fires.
	ps := myParse(`RENAME USER 'old'@'%' TO 'new'@'%'`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType,
		"RENAME USER classifies as StmtAlterPrivileges (admin-tight class)")
	assert.True(t, ps.IsDCL)
	assert.Equal(t, mysqlDCLOpRenameUser, ps.MutatingNodeType)
}

func TestSetPasswordMySQL(t *testing.T) {
	// SET PASSWORD FOR <user> = ... — credential mutation. Classified
	// as StmtAlterPrivileges (admin-tight floor fires) +
	// identified_by_password risk_indicator (the literal IS in the
	// audit row).
	ps := myParse(`SET PASSWORD FOR 'bob'@'%' = 'newpass'`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType,
		"SET PASSWORD classifies as StmtAlterPrivileges (admin-tight class)")
	assert.True(t, ps.IsDCL)
	assert.Equal(t, mysqlDCLOpSetPwd, ps.MutatingNodeType)
	assert.Contains(t, ps.RiskIndicators, "identified_by_password")
}

func TestGrantMultiplePrivilegesMySQL(t *testing.T) {
	// Multi-privilege grant: every privilege surfaces in upper-case +
	// order. Parallels TestParse_GrantMultiplePrivileges on the PG side.
	ps := myParse(`GRANT SELECT, INSERT, UPDATE ON foo.bar TO 'bob'@'%'`)
	assert.Equal(t, []string{"SELECT", "INSERT", "UPDATE"}, ps.Privileges)
	assert.Equal(t, []string{"'bob'@'%'"}, ps.Grantees)
	assert.Equal(t, "table:foo.bar", ps.TargetObject)
}

func TestGrantAllPrivilegesNormalizationMySQL(t *testing.T) {
	// "ALL PRIVILEGES" (full keyword) should normalize to "ALL" so the
	// all_privileges indicator's predicate stays simple.
	ps := myParse(`GRANT ALL PRIVILEGES ON foo.* TO 'bob'@'%'`)
	assert.Equal(t, []string{"ALL"}, ps.Privileges,
		`"ALL PRIVILEGES" MUST normalize to single-element ["ALL"]`)
	assert.Contains(t, ps.RiskIndicators, "all_privileges")
}

func TestCreateUserIfNotExistsMySQL(t *testing.T) {
	// IF NOT EXISTS clause — optional in MySQL 5.7+ / mandatory-ish in
	// idempotent migrations. MUST still classify as StmtGrant with
	// create_user indicator (the IF NOT EXISTS doesn't change the
	// shape's risk profile — the user still exists after).
	ps := myParse(`CREATE USER IF NOT EXISTS 'newuser'@'localhost' IDENTIFIED BY 'pw'`)
	assert.Equal(t, StmtGrant, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.Contains(t, ps.RiskIndicators, "create_user")
	assert.Contains(t, ps.RiskIndicators, "identified_by_password")
	assert.Contains(t, ps.Grantees, "'newuser'@'localhost'")
}

func TestNonDCLStatementHasEmptyDCLFieldsMySQL(t *testing.T) {
	// Regression: plain SELECT MUST NOT populate Privileges / Grantees
	// / TargetObject / RiskIndicators. These are DCL-only fields;
	// bleeding into non-DCL parsing confuses downstream filters.
	// Parallels the PG TestParse_NonDCLStatementHasEmptyDCLFields test.
	ps := myParse(`SELECT * FROM foo`)
	assert.Nil(t, ps.Privileges)
	assert.Nil(t, ps.Grantees)
	assert.Empty(t, ps.TargetObject)
	assert.Nil(t, ps.RiskIndicators)
	assert.False(t, ps.IsDCL)
}

func TestRevokeAllGlobalMySQL(t *testing.T) {
	// REVOKE ALL PRIVILEGES, GRANT OPTION FROM <user> — the global
	// revoke shape. No "ON <obj>" clause; the parser must handle that
	// branch + still classify as StmtRevoke + IsDCL.
	ps := myParse(`REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'bob'@'%'`)
	assert.Equal(t, StmtRevoke, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.Contains(t, ps.Grantees, "'bob'@'%'")
}

func TestGrantOnGlobalShapeMySQL(t *testing.T) {
	// GRANT SELECT ON *.* TO ... — global scope, all schemas. TargetObject
	// MUST read "global:*.*" so a downstream filter can match "grants
	// on the global scope" without re-parsing.
	ps := myParse(`GRANT SELECT ON *.* TO 'monitor'@'localhost'`)
	assert.Equal(t, "global:*.*", ps.TargetObject)
	assert.Equal(t, []string{"SELECT"}, ps.Privileges)
}

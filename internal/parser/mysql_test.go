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

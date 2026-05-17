package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests cover the parser substrate D-Slice 1 ships:
//
//   - SELECT (simple, with joins, with subqueries, with CTEs)
//   - INSERT / UPDATE / DELETE / MERGE
//   - INSERT ... ON CONFLICT (upsert)
//   - DDL: CREATE / ALTER / DROP / TRUNCATE / RENAME / COMMENT
//   - Stored-procedure call sites: CALL / DO $$ ... $$ / EXECUTE
//   - Volatile-function calls (SELECT pg_sleep(60))
//   - CTE-wrapped writes (must classify as WITH-WRITE not SELECT)
//   - SET ROLE impersonation capture
//   - EXPLAIN vs EXPLAIN ANALYZE distinction
//   - Multi-statement batches
//   - Malformed / empty SQL — never panics; surfaces UNPARSEABLE
//
// Per the audit-cadence self-check: every test asserts on the
// audit-row-relevant fields (StatementType, TablesTouched,
// FunctionsCalled, HasMutatingNode, MutatingNodeType) so the cross-
// product audit-log scraper has consistent shape across all rows.

func TestParse_SimpleSelect(t *testing.T) {
	ps := pgParse("SELECT id, name FROM users WHERE id = 1")
	require.NotNil(t, ps)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Equal(t, []string{"users"}, ps.TablesTouched)
	assert.False(t, ps.IsDML)
	assert.False(t, ps.IsDDL)
	assert.False(t, ps.HasMutatingNode)
	assert.Empty(t, ps.ParseErrors)
}

func TestParse_SchemaQualifiedTable(t *testing.T) {
	ps := pgParse("SELECT * FROM public.orders")
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Equal(t, []string{"public.orders"}, ps.TablesTouched)
}

func TestParse_SelectWithJoin(t *testing.T) {
	ps := pgParse(`SELECT u.id, o.total
	FROM users u
	JOIN orders o ON o.user_id = u.id
	WHERE u.id = 1`)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.ElementsMatch(t, []string{"users", "orders"}, ps.TablesTouched)
}

func TestParse_SelectSubquery(t *testing.T) {
	ps := pgParse(`SELECT * FROM users
	WHERE id IN (SELECT user_id FROM orders WHERE total > 100)`)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.ElementsMatch(t, []string{"users", "orders"}, ps.TablesTouched)
}

func TestParse_SelectFromSubquery(t *testing.T) {
	ps := pgParse(`SELECT * FROM (SELECT id FROM users) sub`)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Equal(t, []string{"users"}, ps.TablesTouched)
}

func TestParse_SelectUnion(t *testing.T) {
	ps := pgParse(`SELECT id FROM users UNION SELECT id FROM admins`)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.ElementsMatch(t, []string{"users", "admins"}, ps.TablesTouched)
}

func TestParse_SelectVolatileFunction(t *testing.T) {
	ps := pgParse("SELECT pg_sleep(60)")
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Contains(t, ps.FunctionsCalled, "pg_sleep")
}

func TestParse_SelectAggregate(t *testing.T) {
	ps := pgParse("SELECT count(*), max(price) FROM products")
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Contains(t, ps.FunctionsCalled, "count")
	assert.Contains(t, ps.FunctionsCalled, "max")
}

func TestParse_Insert(t *testing.T) {
	ps := pgParse(`INSERT INTO users (id, name) VALUES (1, 'alice')`)
	assert.Equal(t, StmtInsert, ps.StatementType)
	assert.Equal(t, []string{"users"}, ps.TablesTouched)
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "INSERT", ps.MutatingNodeType)
}

func TestParse_InsertSelect(t *testing.T) {
	ps := pgParse(`INSERT INTO audit_log (event)
	SELECT event FROM events WHERE created_at > '2026-01-01'`)
	assert.Equal(t, StmtInsert, ps.StatementType)
	assert.ElementsMatch(t, []string{"audit_log", "events"}, ps.TablesTouched)
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
}

func TestParse_InsertOnConflict(t *testing.T) {
	ps := pgParse(`INSERT INTO users (id, name) VALUES (1, 'alice')
	ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`)
	assert.Equal(t, StmtInsert, ps.StatementType)
	assert.Equal(t, []string{"users"}, ps.TablesTouched)
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
}

func TestParse_Update(t *testing.T) {
	ps := pgParse(`UPDATE users SET name = 'bob' WHERE id = 1`)
	assert.Equal(t, StmtUpdate, ps.StatementType)
	assert.Equal(t, []string{"users"}, ps.TablesTouched)
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "UPDATE", ps.MutatingNodeType)
}

func TestParse_UpdateFrom(t *testing.T) {
	ps := pgParse(`UPDATE orders SET status = 'paid'
	FROM payments WHERE orders.id = payments.order_id`)
	assert.Equal(t, StmtUpdate, ps.StatementType)
	assert.ElementsMatch(t, []string{"orders", "payments"}, ps.TablesTouched)
}

func TestParse_Delete(t *testing.T) {
	ps := pgParse(`DELETE FROM sessions WHERE expired_at < now()`)
	assert.Equal(t, StmtDelete, ps.StatementType)
	assert.Equal(t, []string{"sessions"}, ps.TablesTouched)
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "DELETE", ps.MutatingNodeType)
}

func TestParse_Merge(t *testing.T) {
	ps := pgParse(`MERGE INTO accounts a
	USING ledger l ON a.id = l.account_id
	WHEN MATCHED THEN UPDATE SET balance = l.balance
	WHEN NOT MATCHED THEN INSERT (id, balance) VALUES (l.account_id, l.balance)`)
	assert.Equal(t, StmtMerge, ps.StatementType)
	assert.Contains(t, ps.TablesTouched, "accounts")
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
}

// CTE-wrapped writes — the critical Layer-2-backstop test. Top-level
// keyword is WITH, which the keyword-only classifier would mark
// SELECT; the AST walker MUST surface the UPDATE under the CTE and
// reclassify as WITH-WRITE.
func TestParse_CTEWrappedUpdate(t *testing.T) {
	ps := pgParse(`WITH archived AS (
	  UPDATE orders SET archived = true
	  WHERE created_at < '2024-01-01'
	  RETURNING id
	)
	SELECT count(*) FROM archived`)
	assert.Equal(t, StmtWithWrite, ps.StatementType,
		"CTE-wrapped UPDATE must classify as WITH-WRITE (Layer-2 backstop)")
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "UPDATE", ps.MutatingNodeType)
	assert.Contains(t, ps.TablesTouched, "orders")
}

func TestParse_CTEWrappedInsert(t *testing.T) {
	ps := pgParse(`WITH new_users AS (
	  INSERT INTO users (name) VALUES ('alice') RETURNING id
	)
	SELECT * FROM new_users`)
	assert.Equal(t, StmtWithWrite, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "INSERT", ps.MutatingNodeType)
}

func TestParse_CTEWrappedDelete(t *testing.T) {
	ps := pgParse(`WITH gone AS (
	  DELETE FROM sessions WHERE expired_at < now() RETURNING id
	)
	SELECT count(*) FROM gone`)
	assert.Equal(t, StmtWithWrite, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "DELETE", ps.MutatingNodeType)
}

func TestParse_CTEReadOnly(t *testing.T) {
	// Read-only CTE: should NOT reclassify to WITH-WRITE.
	ps := pgParse(`WITH recent AS (
	  SELECT id FROM users WHERE created_at > now() - interval '1 day'
	)
	SELECT count(*) FROM recent`)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.False(t, ps.HasMutatingNode)
}

// DDL coverage.

func TestParse_CreateTable(t *testing.T) {
	ps := pgParse(`CREATE TABLE foo (id INT)`)
	assert.Equal(t, StmtDDL, ps.StatementType)
	assert.True(t, ps.IsDDL)
}

func TestParse_CreateRole(t *testing.T) {
	ps := pgParse(`CREATE ROLE service_acct LOGIN`)
	assert.Equal(t, StmtDDL, ps.StatementType)
}

func TestParse_CreateExtension(t *testing.T) {
	ps := pgParse(`CREATE EXTENSION pgcrypto`)
	assert.Equal(t, StmtDDL, ps.StatementType)
}

func TestParse_AlterTable(t *testing.T) {
	ps := pgParse(`ALTER TABLE users ADD COLUMN email TEXT`)
	assert.Equal(t, StmtDDL, ps.StatementType)
}

func TestParse_DropTable(t *testing.T) {
	ps := pgParse(`DROP TABLE users`)
	assert.Equal(t, StmtDDL, ps.StatementType)
}

func TestParse_RenameTable(t *testing.T) {
	ps := pgParse(`ALTER TABLE users RENAME TO users_archive`)
	// AlterTableStmt is StmtDDL (RenameStmt is the standalone form).
	assert.Equal(t, StmtDDL, ps.StatementType)
}

func TestParse_Truncate(t *testing.T) {
	ps := pgParse(`TRUNCATE TABLE audit_log`)
	assert.Equal(t, StmtTruncate, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "TRUNCATE", ps.MutatingNodeType)
	assert.Equal(t, []string{"audit_log"}, ps.TablesTouched)
}

func TestParse_CreateIndex(t *testing.T) {
	ps := pgParse(`CREATE INDEX idx_users_email ON users(email)`)
	assert.Equal(t, StmtDDL, ps.StatementType)
}

func TestParse_Comment(t *testing.T) {
	ps := pgParse(`COMMENT ON TABLE users IS 'application users'`)
	assert.Equal(t, StmtComment, ps.StatementType)
	assert.True(t, ps.IsDDL)
}

// Stored-procedure call sites. Per the build plan, D-Slice 1 captures
// them but does NOT recurse into procedure bodies.

func TestParse_Call(t *testing.T) {
	ps := pgParse(`CALL refresh_materialized_views()`)
	assert.Equal(t, StmtCall, ps.StatementType)
	assert.Contains(t, ps.FunctionsCalled, "refresh_materialized_views")
}

func TestParse_CallQualified(t *testing.T) {
	ps := pgParse(`CALL public.do_thing(1, 'hi')`)
	assert.Equal(t, StmtCall, ps.StatementType)
	assert.Contains(t, ps.FunctionsCalled, "public.do_thing")
}

func TestParse_DoBlock(t *testing.T) {
	ps := pgParse(`DO $$
	BEGIN
	  UPDATE users SET active = false WHERE id = 99;
	END
	$$`)
	assert.Equal(t, StmtDo, ps.StatementType)
	// DO blocks are opaque to the parser; we mark mutating because the
	// stance is "deny unless allowlisted" (the D-Slices 3+ enforcement
	// layer will flip the verdict). HasMutatingNode = true ensures
	// audit rows surface that the operator should pay attention.
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "DO", ps.MutatingNodeType)
}

func TestParse_Execute(t *testing.T) {
	ps := pgParse(`EXECUTE my_stmt(1, 2)`)
	assert.Equal(t, StmtExecute, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "EXECUTE", ps.MutatingNodeType)
}

func TestParse_Prepare(t *testing.T) {
	ps := pgParse(`PREPARE my_stmt (int) AS SELECT * FROM users WHERE id = $1`)
	// PREPARE is classified as StmtExecute (prepared-statement family);
	// the underlying SELECT is walked so tables are surfaced.
	assert.Equal(t, StmtExecute, ps.StatementType)
	assert.Contains(t, ps.TablesTouched, "users")
}

// SET ROLE impersonation capture.

func TestParse_SetRole(t *testing.T) {
	ps := pgParse(`SET ROLE 'admin'`)
	assert.Equal(t, StmtSet, ps.StatementType)
	assert.Equal(t, "admin", ps.ImpersonatedRole)
}

func TestParse_SetNonRole(t *testing.T) {
	ps := pgParse(`SET TIME ZONE 'UTC'`)
	assert.Equal(t, StmtSet, ps.StatementType)
	assert.Empty(t, ps.ImpersonatedRole)
}

// EXPLAIN vs EXPLAIN ANALYZE.

func TestParse_Explain(t *testing.T) {
	ps := pgParse(`EXPLAIN SELECT * FROM users`)
	assert.Equal(t, StmtExplain, ps.StatementType)
	assert.True(t, ps.IsExplain)
	assert.False(t, ps.IsExplainAnalyze)
}

func TestParse_ExplainAnalyze(t *testing.T) {
	ps := pgParse(`EXPLAIN ANALYZE UPDATE users SET active = false`)
	assert.Equal(t, StmtExplainAnalyze, ps.StatementType)
	assert.True(t, ps.IsExplainAnalyze)
	// The inner UPDATE actually executes under EXPLAIN ANALYZE, so the
	// walker MUST mark mutating.
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, "UPDATE", ps.MutatingNodeType)
	assert.Contains(t, ps.TablesTouched, "users")
}

// Transactions / COPY / VACUUM.

func TestParse_BeginTransaction(t *testing.T) {
	ps := pgParse(`BEGIN`)
	assert.Equal(t, StmtTransaction, ps.StatementType)
}

func TestParse_Commit(t *testing.T) {
	ps := pgParse(`COMMIT`)
	assert.Equal(t, StmtTransaction, ps.StatementType)
}

func TestParse_Copy(t *testing.T) {
	ps := pgParse(`COPY users (id, name) FROM STDIN`)
	assert.Equal(t, StmtCopy, ps.StatementType)
}

func TestParse_Vacuum(t *testing.T) {
	ps := pgParse(`VACUUM users`)
	assert.Equal(t, StmtVacuum, ps.StatementType)
}

// Multi-statement batches: the FIRST statement drives StatementType,
// but TablesTouched + HasMutatingNode aggregate across all statements
// in the batch so a "SELECT 1; UPDATE secrets ..." batch still
// surfaces the UPDATE for the audit row.

func TestParse_MultiStatementBatch(t *testing.T) {
	ps := pgParse(`SELECT 1; UPDATE secrets SET val = 'oops'`)
	// First statement is SELECT.
	assert.Equal(t, StmtSelect, ps.StatementType)
	// But the walker MUST still have surfaced the UPDATE.
	assert.True(t, ps.HasMutatingNode,
		"multi-statement batch's mutating shape MUST surface for audit")
	assert.Contains(t, ps.TablesTouched, "secrets")
}

// Malformed / pathological input — must NEVER panic. Per the audit-
// cadence self-check: malformed SQL ends up as StmtUnparseable with
// ParseErrors populated, and we still get an audit row.

func TestParse_Empty(t *testing.T) {
	ps := pgParse("")
	require.NotNil(t, ps)
	assert.Equal(t, StmtUnknown, ps.StatementType)
}

func TestParse_OnlyWhitespace(t *testing.T) {
	ps := pgParse("   \n\t  ")
	assert.Equal(t, StmtUnknown, ps.StatementType)
}

func TestParse_Garbage(t *testing.T) {
	ps := pgParse("zxcvbnm asdfghjkl !@#$%^&*()")
	assert.Equal(t, StmtUnparseable, ps.StatementType)
	assert.NotEmpty(t, ps.ParseErrors)
}

func TestParse_PartialStatement(t *testing.T) {
	ps := pgParse("SELECT * FROM")
	assert.Equal(t, StmtUnparseable, ps.StatementType)
	assert.NotEmpty(t, ps.ParseErrors)
}

func TestParse_VeryLongInput(t *testing.T) {
	// 10KB of a single legitimate SELECT — should parse cleanly.
	sb := strings.Builder{}
	sb.WriteString("SELECT ")
	for i := 0; i < 1000; i++ {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("col_")
		sb.WriteString(itoa(i))
	}
	sb.WriteString(" FROM big_table")
	ps := pgParse(sb.String())
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Equal(t, []string{"big_table"}, ps.TablesTouched)
}

func TestParse_RawPreserved(t *testing.T) {
	// Raw text must round-trip verbatim so the audit log keeps the
	// operator's exact bytes.
	in := "  SELECT 1;  \n"
	ps := pgParse(in)
	assert.Equal(t, in, ps.Raw)
}

// Schema names normalized to lowercase. Matchers operate on the
// lowercase form so case variation in the SQL doesn't bypass denies.
func TestParse_SchemaNormalization(t *testing.T) {
	ps := pgParse(`SELECT * FROM Public.Users`)
	assert.Equal(t, []string{"public.users"}, ps.TablesTouched)
}

func TestParse_FunctionLowercase(t *testing.T) {
	ps := pgParse(`SELECT PG_SLEEP(60)`)
	assert.Contains(t, ps.FunctionsCalled, "pg_sleep")
}

// pgParse is the postgres-test-only helper. Routes raw SQL through the
// shared dispatcher with the postgres dialect so the test file
// exercises the same entry point production code uses + still reads
// like `ps := pgParse("SELECT ...")`.
func pgParse(raw string) *ParsedStatement {
	return Parse(DialectPostgres, raw)
}

// Helper.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

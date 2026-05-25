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

// TestParse_CreateRole pins the #586 reclassification: CREATE ROLE is
// admin-grant DCL (not DDL), so the AdminTightFloor fires by default
// under --default-policy=allow. Per [[scorer-is-ground-truth]]: this
// statement IS privilege management; classifying it as DDL let
// `CREATE ROLE attacker SUPERUSER` slip through default-allow on
// PostgreSQL (UAT-C 2026-05-25). The MySQL classifier already covers
// CREATE USER via populateMySQLCreateUser; #586 closes the PG parity gap.
func TestParse_CreateRole(t *testing.T) {
	ps := pgParse(`CREATE ROLE service_acct LOGIN`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType,
		"CREATE ROLE MUST classify as StmtAlterPrivileges so the admin-tight floor fires (#586)")
	assert.True(t, ps.IsDCL,
		"CREATE ROLE MUST set IsDCL=true so downstream policy can reason about privilege management (#586)")
	assert.False(t, ps.IsDDL,
		"CREATE ROLE MUST NOT be IsDDL — it's DCL, not DDL (#586 classifier correction)")
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

// DCL (Data Control Language) classification — privilege management.
// Per task #302 / KNOWN-CAVEATS §A5: before this slice, GRANT/REVOKE/
// ALTER DEFAULT PRIVILEGES classified as StmtUnknown and the safe-default
// profile let `GRANT ALL PRIVILEGES ... TO PUBLIC` slip through.
// These tests pin the classifier + the DCLTargetsPublic predicate.

func TestParse_GrantAllPrivilegesToPublic(t *testing.T) {
	// The canonical hostile shape per UAT Variant A + Variant C: a
	// GRANT that fans privilege out to every database role. Parser MUST
	// surface StmtGrant + IsDCL=true + DCLTargetsPublic=true so the
	// safe-default profile's deny_dcl_targets_public floor can refuse
	// it. Before #302 fix: classified as UNKNOWN, default-allow.
	ps := pgParse(`GRANT ALL PRIVILEGES ON DATABASE mydb TO PUBLIC`)
	assert.Equal(t, StmtGrant, ps.StatementType)
	assert.True(t, ps.IsDCL, "GRANT must set IsDCL=true")
	assert.True(t, ps.DCLTargetsPublic, "GRANT ... TO PUBLIC must set DCLTargetsPublic=true")
	assert.False(t, ps.IsDML)
	assert.False(t, ps.IsDDL)
	assert.False(t, ps.HasMutatingNode, "DCL is not a DML mutation; HasMutatingNode stays false")
}

func TestParse_GrantSelectOnTableToSpecificUser(t *testing.T) {
	// Non-PUBLIC grantee: still DCL, but DCLTargetsPublic=false so the
	// safe-default DCL floor abstains and downstream policy decides.
	ps := pgParse(`GRANT SELECT ON TABLE public.users TO specific_user`)
	assert.Equal(t, StmtGrant, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.False(t, ps.DCLTargetsPublic,
		"specific user is not PUBLIC; DCLTargetsPublic must stay false")
	assert.Contains(t, ps.TablesTouched, "public.users")
}

func TestParse_GrantCaseInsensitivePublic(t *testing.T) {
	// pg_query parses bare PUBLIC via Roletype = ROLESPEC_PUBLIC; the
	// case shouldn't matter. Defensive: lowercase + mixed-case still
	// surface DCLTargetsPublic=true.
	for _, sql := range []string{
		`GRANT SELECT ON TABLE t TO public`,
		`GRANT SELECT ON TABLE t TO Public`,
		`GRANT SELECT ON TABLE t TO PUBLIC`,
	} {
		ps := pgParse(sql)
		assert.True(t, ps.DCLTargetsPublic, "%q must set DCLTargetsPublic", sql)
	}
}

func TestParse_RevokeFromPublic(t *testing.T) {
	// REVOKE direction MUST NOT set DCLTargetsPublic. Revoking FROM
	// PUBLIC is a cleanup operation and the safe-default profile lets
	// it through — denying the cleanup would be a worse failure than
	// allowing the original grant. Per task #302 spec.
	ps := pgParse(`REVOKE ALL PRIVILEGES ON DATABASE mydb FROM PUBLIC`)
	assert.Equal(t, StmtRevoke, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.False(t, ps.DCLTargetsPublic,
		"REVOKE ... FROM PUBLIC is cleanup; DCLTargetsPublic MUST stay false")
}

func TestParse_RevokeFromSpecificUser(t *testing.T) {
	ps := pgParse(`REVOKE INSERT ON TABLE public.orders FROM specific_user`)
	assert.Equal(t, StmtRevoke, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.False(t, ps.DCLTargetsPublic)
}

func TestParse_AlterDefaultPrivilegesGrantToPublic(t *testing.T) {
	// The other dangerous shape: ALTER DEFAULT PRIVILEGES ... GRANT ...
	// TO PUBLIC makes EVERY FUTURE object in the schema world-accessible.
	// StatementType is StmtAlterPrivileges, IsDCL=true, and the walker
	// must recurse into the inner action to see PUBLIC in the grantees.
	ps := pgParse(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO PUBLIC`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.True(t, ps.DCLTargetsPublic,
		"ALTER DEFAULT PRIVILEGES ... GRANT ... TO PUBLIC must set DCLTargetsPublic")
}

func TestParse_AlterDefaultPrivilegesGrantToSpecificUser(t *testing.T) {
	ps := pgParse(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO specific_user`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.False(t, ps.DCLTargetsPublic)
}

func TestParse_GrantRoleToUser(t *testing.T) {
	// `GRANT role_a TO role_b` — role-membership grant (GrantRoleStmt
	// node, distinct from object GrantStmt). Classified as StmtGrant
	// + IsDCL=true.
	ps := pgParse(`GRANT manager_role TO alice`)
	assert.Equal(t, StmtGrant, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.False(t, ps.DCLTargetsPublic)
}

func TestParse_GrantMultipleGranteesIncludesPublic(t *testing.T) {
	// Mixed grantee list including PUBLIC — must set DCLTargetsPublic
	// (a grant to PUBLIC anywhere in the list is just as dangerous as
	// a grant to PUBLIC alone).
	ps := pgParse(`GRANT SELECT ON TABLE t TO alice, PUBLIC, bob`)
	assert.True(t, ps.DCLTargetsPublic,
		"PUBLIC mixed into a grantee list still triggers the floor")
}

// DCL field-extraction tests — per UC-34 spec: privileges + grantees +
// target_object + risk_indicators must populate so downstream policy +
// audit can reason about the privilege shape without re-parsing the
// raw SQL.

func TestParse_GrantAllToPublicPopulatesFields(t *testing.T) {
	// The canonical UC-34 shape: GRANT ALL ON TABLE foo TO PUBLIC.
	// Must surface:
	//   operation=GRANT (StatementType)
	//   grantees=["public"]
	//   privileges=["ALL"]  (PG encodes empty privilege list as ALL;
	//                        parser surfaces explicitly)
	//   target_object="table:foo"
	//   risk_indicators contains "public_grant" AND "all_privileges"
	ps := pgParse(`GRANT ALL ON TABLE foo TO PUBLIC`)
	assert.Equal(t, StmtGrant, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.Equal(t, []string{"public"}, ps.Grantees)
	assert.Equal(t, []string{"ALL"}, ps.Privileges)
	assert.Equal(t, "table:foo", ps.TargetObject)
	assert.Contains(t, ps.RiskIndicators, "public_grant",
		"GRANT ... TO PUBLIC MUST flag public_grant")
	assert.Contains(t, ps.RiskIndicators, "all_privileges",
		"GRANT ALL ... MUST flag all_privileges")
}

func TestParse_GrantSelectToUserPopulatesFields(t *testing.T) {
	// Non-PUBLIC, non-ALL grant: still classified as admin-grant
	// (StmtGrant + IsDCL) but with NEITHER public_grant NOR
	// all_privileges flagged — risk_indicators may be empty for the
	// "boring" case.
	ps := pgParse(`GRANT SELECT ON TABLE foo TO bob`)
	assert.Equal(t, StmtGrant, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.Equal(t, []string{"bob"}, ps.Grantees)
	assert.Equal(t, []string{"SELECT"}, ps.Privileges)
	assert.Equal(t, "table:foo", ps.TargetObject)
	assert.NotContains(t, ps.RiskIndicators, "public_grant")
	assert.NotContains(t, ps.RiskIndicators, "all_privileges")
	assert.NotContains(t, ps.RiskIndicators, "with_grant_option")
}

func TestParse_GrantWithGrantOptionFlagged(t *testing.T) {
	// WITH GRANT OPTION — grantee can re-grant the privilege. Always
	// flagged as a risk_indicator regardless of who the grantee is.
	ps := pgParse(`GRANT SELECT ON foo TO bob WITH GRANT OPTION`)
	assert.Equal(t, StmtGrant, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.Contains(t, ps.RiskIndicators, "with_grant_option",
		"WITH GRANT OPTION MUST flag with_grant_option indicator")
}

func TestParse_GrantMultiplePrivileges(t *testing.T) {
	// Multi-privilege grant: every privilege surfaces in upper-case,
	// in declared order, with no dedup needed (PG doesn't allow
	// duplicate privileges in the same GRANT).
	ps := pgParse(`GRANT SELECT, INSERT, UPDATE ON TABLE foo TO bob`)
	assert.Equal(t, []string{"SELECT", "INSERT", "UPDATE"}, ps.Privileges)
	assert.Equal(t, []string{"bob"}, ps.Grantees)
}

func TestParse_GrantOnDatabasePopulatesTarget(t *testing.T) {
	// The MRR-1 audit's literal shape: GRANT ALL PRIVILEGES ON DATABASE
	// mydb TO PUBLIC. TargetObject must read "database:mydb" so a
	// downstream filter can match "grants on prod-account databases"
	// without re-parsing.
	ps := pgParse(`GRANT ALL PRIVILEGES ON DATABASE mydb TO PUBLIC`)
	assert.Equal(t, "database:mydb", ps.TargetObject)
	assert.Equal(t, []string{"public"}, ps.Grantees)
	assert.Equal(t, []string{"ALL"}, ps.Privileges)
	assert.Contains(t, ps.RiskIndicators, "public_grant")
	assert.Contains(t, ps.RiskIndicators, "all_privileges")
}

func TestParse_GrantOnSchemaPopulatesTarget(t *testing.T) {
	ps := pgParse(`GRANT USAGE ON SCHEMA public TO bob`)
	assert.Equal(t, "schema:public", ps.TargetObject)
	assert.Equal(t, []string{"USAGE"}, ps.Privileges)
	assert.Equal(t, []string{"bob"}, ps.Grantees)
}

func TestParse_RevokeClassifiedAsAdminRevoke(t *testing.T) {
	// REVOKE direction (IsGrant=false on the AST). Per UC-34 spec test
	// #4: classified as admin-revoke (StmtRevoke). Privileges +
	// grantees still extracted (audit signal — operators want to know
	// what got revoked from whom). risk_indicators stay empty for
	// REVOKE — revoking IS cleanup; no escalation shape applies.
	ps := pgParse(`REVOKE SELECT ON foo FROM bob`)
	assert.Equal(t, StmtRevoke, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.Equal(t, []string{"SELECT"}, ps.Privileges)
	assert.Equal(t, []string{"bob"}, ps.Grantees)
	assert.Equal(t, "table:foo", ps.TargetObject)
	assert.NotContains(t, ps.RiskIndicators, "public_grant")
	assert.NotContains(t, ps.RiskIndicators, "all_privileges")
}

func TestParse_AlterDefaultPrivilegesFlaggedAsAlteringFutureObjects(t *testing.T) {
	// ALTER DEFAULT PRIVILEGES affects EVERY FUTURE object created in
	// the schema — a dangerous escalation shape distinct from a
	// one-time GRANT. risk_indicators MUST include
	// "alter_default_privileges" so audit + SIEM can prioritize.
	ps := pgParse(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO bob`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.Contains(t, ps.RiskIndicators, "alter_default_privileges",
		"ALTER DEFAULT PRIVILEGES MUST flag alter_default_privileges indicator")
	assert.Equal(t, "all-tables-in-schema:public", ps.TargetObject)
	assert.Equal(t, []string{"SELECT"}, ps.Privileges)
	assert.Equal(t, []string{"bob"}, ps.Grantees)
}

func TestParse_AlterDefaultPrivilegesAllToPublicMultipleIndicators(t *testing.T) {
	// The dangerous combo: ALTER DEFAULT PRIVILEGES ... GRANT ALL ... TO
	// PUBLIC. Three risk_indicators MUST fire:
	//   alter_default_privileges + all_privileges + public_grant
	ps := pgParse(`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO PUBLIC`)
	assert.Contains(t, ps.RiskIndicators, "alter_default_privileges")
	assert.Contains(t, ps.RiskIndicators, "all_privileges")
	assert.Contains(t, ps.RiskIndicators, "public_grant")
	assert.True(t, ps.DCLTargetsPublic)
}

func TestParse_GrantRoleMembershipFlagged(t *testing.T) {
	// `GRANT role_a TO bob` — role-membership grant (GrantRoleStmt
	// node). Must flag role_membership indicator + surface the granted
	// role as ROLE:role_a in Privileges so the audit row carries the
	// role-name context.
	ps := pgParse(`GRANT manager_role TO bob`)
	assert.Equal(t, StmtGrant, ps.StatementType)
	assert.True(t, ps.IsDCL)
	assert.Contains(t, ps.RiskIndicators, "role_membership")
	assert.Contains(t, ps.Privileges, "ROLE:manager_role")
	assert.Equal(t, []string{"bob"}, ps.Grantees)
}

func TestParse_GrantRoleWithAdminOptionFlagged(t *testing.T) {
	// WITH ADMIN OPTION on a role-membership grant = bob can grant
	// manager_role to others. Risk indicator with_admin_option.
	ps := pgParse(`GRANT manager_role TO bob WITH ADMIN OPTION`)
	assert.Contains(t, ps.RiskIndicators, "with_admin_option",
		"WITH ADMIN OPTION MUST flag with_admin_option indicator")
}

func TestParse_NonDCLStatementHasEmptyDCLFields(t *testing.T) {
	// Regression: a plain SELECT must NOT populate Privileges / Grantees /
	// TargetObject / RiskIndicators. These are DCL-only fields; bleeding
	// into non-DCL parsing would confuse downstream filters.
	ps := pgParse(`SELECT * FROM foo`)
	assert.Nil(t, ps.Privileges)
	assert.Nil(t, ps.Grantees)
	assert.Empty(t, ps.TargetObject)
	assert.Nil(t, ps.RiskIndicators)
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

// =============================================================================
// #586 — PG role/user management classifier tests.
// =============================================================================
//
// UAT-C 2026-05-25 found that PostgreSQL user-management DDL bypassed the
// admin-tight floor entirely under --default-policy=allow. Same UC-34
// bypass class. Per [[scorer-is-ground-truth]]: fix the underlying
// classifier (these statements ARE privilege management) — don't add
// special-case handling downstream of the floor.
//
// Each test asserts observable state: StatementType + IsDCL + (not) IsDDL
// so the admin-tight floor's isAdminGrantShape predicate evaluates true.
// Per CONTRIBUTING.md: state assertions, not implementation internals.

// TestClassifier_CreateRoleSuperuser_IsDCL pins the CREATE ROLE
// admin-grant classification. SUPERUSER is the highest-privilege
// attribute; missing the floor on this statement = catastrophic
// privilege escalation under default-allow.
func TestClassifier_CreateRoleSuperuser_IsDCL(t *testing.T) {
	ps := pgParse(`CREATE ROLE attacker SUPERUSER`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType,
		"CREATE ROLE SUPERUSER MUST classify as admin-grant DCL (#586)")
	assert.True(t, ps.IsDCL, "CREATE ROLE MUST set IsDCL=true")
	assert.False(t, ps.IsDDL, "CREATE ROLE is DCL not DDL after #586")
}

// TestClassifier_AlterUserSuperuser_IsDCL pins the ALTER USER -> SUPERUSER
// reclassification. PG aliases USER to ROLE; both keywords parse to
// Node_AlterRoleStmt.
func TestClassifier_AlterUserSuperuser_IsDCL(t *testing.T) {
	ps := pgParse(`ALTER USER bob SUPERUSER`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType,
		"ALTER USER SUPERUSER MUST classify as admin-grant DCL (#586)")
	assert.True(t, ps.IsDCL)
	assert.False(t, ps.IsDDL)
}

// TestClassifier_AlterRoleCreatedb_IsDCL pins ALTER ROLE with CREATEDB
// attribute — also a privilege expansion (lets the role create new
// databases).
func TestClassifier_AlterRoleCreatedb_IsDCL(t *testing.T) {
	ps := pgParse(`ALTER ROLE bob WITH CREATEDB`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType)
	assert.True(t, ps.IsDCL)
}

// TestClassifier_CreateUserWithPassword_IsDCL pins the CREATE USER
// shape (PG's alias for CREATE ROLE ... LOGIN) with embedded password
// + SUPERUSER. Same node type as CREATE ROLE.
func TestClassifier_CreateUserWithPassword_IsDCL(t *testing.T) {
	ps := pgParse(`CREATE USER attacker WITH SUPERUSER PASSWORD 'pw'`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType,
		"CREATE USER WITH SUPERUSER PASSWORD MUST classify as admin-grant DCL (#586)")
	assert.True(t, ps.IsDCL)
}

// TestClassifier_DropRoleSingle_IsDCL pins DROP ROLE. Note: dropping a
// role IS a privilege-management operation (removes the principal +
// orphans its grants). Even though it's "destruction" rather than
// "grant," it's the same admin-tight class as CREATE.
func TestClassifier_DropRoleSingle_IsDCL(t *testing.T) {
	ps := pgParse(`DROP ROLE bob`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType,
		"DROP ROLE MUST classify as admin-grant DCL (#586)")
	assert.True(t, ps.IsDCL)
}

// TestClassifier_DropUserSingle_IsDCL pins DROP USER (PG alias for
// DROP ROLE; same node type).
func TestClassifier_DropUserSingle_IsDCL(t *testing.T) {
	ps := pgParse(`DROP USER bob`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType)
	assert.True(t, ps.IsDCL)
}

// TestClassifier_DropRoleMultiple_IsDCL pins multi-grantee DROP ROLE.
// pg_query packs the role list inside one DropRoleStmt; the classifier
// must still recognize the node type.
func TestClassifier_DropRoleMultiple_IsDCL(t *testing.T) {
	ps := pgParse(`DROP ROLE bob, eve, alice`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType,
		"multi-grantee DROP ROLE MUST classify as admin-grant DCL (#586)")
	assert.True(t, ps.IsDCL)
}

// TestClassifier_DropUserIfExists_IsDCL pins the IF EXISTS variant.
// The conditional-existence clause does not change the node type or
// the classification.
func TestClassifier_DropUserIfExists_IsDCL(t *testing.T) {
	ps := pgParse(`DROP USER IF EXISTS bob`)
	assert.Equal(t, StmtAlterPrivileges, ps.StatementType)
	assert.True(t, ps.IsDCL)
}

// TestClassifier_AlterRoleSet_NotAdminGrant pins the carve-out: ALTER
// ROLE/USER SET <var> = <val> is SESSION-VAR configuration (search_path,
// timezone, etc.), NOT a privilege-attribute change. PG parses it as
// Node_AlterRoleSetStmt — a different node type than the privilege-
// attribute AlterRoleStmt. Per [[safety-mode-lean-permissive]] (block
// rarely): the admin-tight floor stays OUT of benign session config so
// search_path / timezone tweaks don't get denied. Currently classifies
// as StmtUnknown (pre-#586 behavior; whatever it is, it's NOT IsDCL).
func TestClassifier_AlterRoleSet_NotAdminGrant(t *testing.T) {
	ps := pgParse(`ALTER ROLE bob SET search_path = 'a'`)
	assert.NotEqual(t, StmtAlterPrivileges, ps.StatementType,
		"ALTER ROLE SET <var> is session-config (not privilege mgmt); "+
			"MUST NOT trigger admin-tight floor per [[safety-mode-lean-permissive]] (#586 carve-out)")
	assert.False(t, ps.IsDCL,
		"AlterRoleSetStmt MUST NOT be IsDCL — admin-tight floor stays out of benign session config")
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

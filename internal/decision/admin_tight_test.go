package decision

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/parser"
	"github.com/trsreagan3/dbounce/internal/profile"
)

// State-verification tests per CONTRIBUTING.md: every assertion checks
// observable state (deny/applicable verdicts + reason strings), not
// implementation internals. Per #559: the shared helper IS the single
// source of truth for proxy.decide + cli.evalDecide; these tests pin
// the contract both call sites depend on.

// parsePG is a test helper that parses raw SQL through the PG dialect
// dispatcher.
func parsePG(t *testing.T, sql string) *parser.ParsedStatement {
	t.Helper()
	ps := parser.Parse(parser.DialectPostgres, sql)
	require.NotNil(t, ps)
	return ps
}

// parseMySQL is a test helper that parses raw SQL through the MySQL
// dialect dispatcher.
func parseMySQL(t *testing.T, sql string) *parser.ParsedStatement {
	t.Helper()
	ps := parser.Parse(parser.DialectMySQL, sql)
	require.NotNil(t, ps)
	return ps
}

// TestAdminTightFloor_PostgresGrantAllToPublic_Denies pins the UC-34
// regression: PG GRANT ALL ON TABLE foo TO PUBLIC with empty profile +
// default-policy=allow → deny=true + applicable=true + reason includes
// "admin-tight" and "GRANT" and the default-policy clause. The exact
// reason string MUST mirror proxy.decide() Step 5.5 so SIEM filters
// keying on the substring stay green.
func TestAdminTightFloor_PostgresGrantAllToPublic_Denies(t *testing.T) {
	ps := parsePG(t, "GRANT ALL ON TABLE foo TO PUBLIC")
	require.True(t, ps.IsDCL, "PG parser MUST set IsDCL=true for GRANT (UC-34 invariant)")
	require.Equal(t, parser.StmtGrant, ps.StatementType)

	deny, reason, applicable := AdminTightFloor(ps, nil, "allow")
	assert.True(t, applicable, "PG GRANT MUST trigger the admin-tight floor (applicable=true)")
	assert.True(t, deny, "PG GRANT under no profile MUST deny via admin-tight floor")
	assert.Contains(t, reason, "admin-tight floor",
		"reason MUST name the admin-tight floor (SIEM filters key on this string)")
	assert.Contains(t, reason, "GRANT",
		"reason MUST name the statement type so audit reviewers see WHAT fired the floor")
	assert.Contains(t, reason, "default-policy=allow",
		"reason MUST surface the default-policy that the floor superseded so reviewers see "+
			"'this would have allowed under default-allow but the floor refused'")
}

// TestAdminTightFloor_PostgresGrantWithAllowRule_Allows pins the
// override path: a profile allow_rule matching the GRANT statement
// flips the floor from "deny" to "applicable + overridden." Reason
// names the matched pattern + profile so audit reviewers can trace
// WHICH rule overrode the floor.
func TestAdminTightFloor_PostgresGrantWithAllowRule_Allows(t *testing.T) {
	ps := parsePG(t, "GRANT SELECT ON TABLE foo TO bob")
	prof := &profile.Profile{
		Name: "test-profile",
		AllowRules: []profile.ProfileAllowRule{
			{Pattern: "GRANT:*"},
		},
	}
	deny, reason, applicable := AdminTightFloor(ps, prof, "allow")
	assert.True(t, applicable, "DCL statement MUST trigger the floor evaluation (applicable=true)")
	assert.False(t, deny, "profile allow_rule matching the GRANT MUST override the floor")
	assert.Contains(t, reason, "overridden",
		"reason MUST surface that the floor was overridden so audit reviewers see WHY this passed")
	assert.Contains(t, reason, "test-profile",
		"reason MUST name the profile so reviewers can trace the override source")
	assert.Contains(t, reason, "GRANT:*",
		"reason MUST name the matched allow_rule pattern")
}

// TestAdminTightFloor_MySQLGrant_Denies pins the #556 MySQL parity:
// MySQL GRANT classifies as StmtGrant + IsDCL=true → SAME floor fires
// as PG (cross-dialect parity per [[scorer-is-ground-truth]]).
func TestAdminTightFloor_MySQLGrant_Denies(t *testing.T) {
	ps := parseMySQL(t, "GRANT ALL ON foo.* TO 'bob'@'%'")
	require.True(t, ps.IsDCL, "MySQL parser MUST set IsDCL=true for GRANT (#556 invariant)")
	require.Equal(t, parser.StmtGrant, ps.StatementType)

	deny, reason, applicable := AdminTightFloor(ps, nil, "allow")
	assert.True(t, applicable, "MySQL GRANT MUST trigger the floor (cross-dialect parity)")
	assert.True(t, deny, "MySQL GRANT under no profile MUST deny via admin-tight floor (#556)")
	assert.Contains(t, reason, "admin-tight floor")
	assert.Contains(t, reason, "GRANT")
}

// TestAdminTightFloor_MySQLCreateUser_Denies pins the #556 CREATE USER
// classification: MySQL CREATE USER maps to StmtGrant + IsDCL=true
// (creating a user IS a grant — the new user is a privilege target).
// Defense-in-depth: creating users requires explicit approval.
func TestAdminTightFloor_MySQLCreateUser_Denies(t *testing.T) {
	ps := parseMySQL(t, "CREATE USER 'newuser'@'%' IDENTIFIED BY 'secret'")
	require.True(t, ps.IsDCL, "MySQL parser MUST set IsDCL=true for CREATE USER (#556)")
	require.Equal(t, parser.StmtGrant, ps.StatementType,
		"MySQL CREATE USER MUST classify as StmtGrant so it shares the admin-tight floor with GRANT")

	deny, reason, applicable := AdminTightFloor(ps, nil, "allow")
	assert.True(t, applicable, "MySQL CREATE USER MUST trigger the floor")
	assert.True(t, deny, "MySQL CREATE USER MUST default-deny via admin-tight floor (#556)")
	assert.Contains(t, reason, "admin-tight floor")
}

// TestAdminTightFloor_NonDCL_NotApplicable pins the negative case: a
// SELECT statement is NOT DCL and MUST NOT trigger the floor at all
// (applicable=false). The caller falls through to its default-policy
// evaluation untouched.
func TestAdminTightFloor_NonDCL_NotApplicable(t *testing.T) {
	ps := parsePG(t, "SELECT 1")
	require.False(t, ps.IsDCL, "SELECT MUST NOT be classified as DCL")

	deny, reason, applicable := AdminTightFloor(ps, nil, "allow")
	assert.False(t, applicable,
		"SELECT MUST NOT trigger the admin-tight floor (applicable=false)")
	assert.False(t, deny, "applicable=false MUST imply deny=false")
	assert.Empty(t, reason, "applicable=false MUST return empty reason")
}

// TestAdminTightFloor_RevokeNotCaught pins the cleanup-direction
// invariant: REVOKE is IsDCL=true but is NOT an admin-grant shape,
// so the floor returns applicable=false. Per UC-34 + #556: refusing
// REVOKE would refuse the safer half of every GRANT/REVOKE pair.
func TestAdminTightFloor_RevokeNotCaught(t *testing.T) {
	ps := parsePG(t, "REVOKE SELECT ON foo FROM bob")
	require.True(t, ps.IsDCL, "REVOKE MUST be classified as DCL (parser invariant)")
	require.Equal(t, parser.StmtRevoke, ps.StatementType,
		"REVOKE MUST classify as StmtRevoke (NOT StmtGrant) so the floor short-circuits")

	deny, reason, applicable := AdminTightFloor(ps, nil, "allow")
	assert.False(t, applicable,
		"REVOKE is cleanup direction; admin-tight floor MUST NOT engage "+
			"(applicable=false so caller defers to default-policy)")
	assert.False(t, deny, "applicable=false MUST imply deny=false")
	assert.Empty(t, reason)
}

// TestAdminTightFloor_PostgresAlterDefaultPrivileges_Denies pins the
// ALTER DEFAULT PRIVILEGES handling: it affects every FUTURE object so
// it's the same admin-tight class as GRANT — floor MUST fire.
func TestAdminTightFloor_PostgresAlterDefaultPrivileges_Denies(t *testing.T) {
	ps := parsePG(t,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO bob")
	require.True(t, ps.IsDCL)
	require.Equal(t, parser.StmtAlterPrivileges, ps.StatementType)

	deny, reason, applicable := AdminTightFloor(ps, nil, "allow")
	assert.True(t, applicable)
	assert.True(t, deny,
		"ALTER DEFAULT PRIVILEGES MUST default-deny via admin-tight floor")
	assert.Contains(t, reason, "admin-tight floor")
	assert.Contains(t, reason, parser.StmtAlterPrivileges)
}

// TestAdminTightFloor_NilStmt_NotApplicable pins the nil-safety
// invariant: callers can hand a nil ParsedStatement without crashing
// (e.g. a parser failure path that returns nil + a defensive caller
// invoking the floor anyway). applicable=false.
func TestAdminTightFloor_NilStmt_NotApplicable(t *testing.T) {
	deny, reason, applicable := AdminTightFloor(nil, nil, "allow")
	assert.False(t, applicable, "nil stmt MUST return applicable=false (no crash)")
	assert.False(t, deny)
	assert.Empty(t, reason)
}

// TestAdminTightFloor_EmptyDefaultPolicy_ReasonElidesClause pins the
// empty-default-policy reason shape: when defaultPolicy="" the reason
// omits the "default-policy=X is bypassed" clause but still names the
// floor + the statement type. Callers that don't have a default-policy
// concept (future shapes) get a clean reason.
func TestAdminTightFloor_EmptyDefaultPolicy_ReasonElidesClause(t *testing.T) {
	ps := parsePG(t, "GRANT ALL ON foo TO PUBLIC")
	deny, reason, applicable := AdminTightFloor(ps, nil, "")
	assert.True(t, applicable)
	assert.True(t, deny)
	assert.Contains(t, reason, "admin-tight floor")
	assert.Contains(t, reason, "GRANT")
	assert.NotContains(t, reason, "default-policy=",
		"empty default-policy MUST elide the default-policy clause from the reason")
}

// =============================================================================
// #586 — PostgreSQL role/user management floor tests.
// =============================================================================
//
// UAT-C 2026-05-25 confirmed PG CREATE/ALTER/DROP ROLE+USER bypassed the
// admin-tight floor entirely under --default-policy=allow. Same UC-34
// bypass class. Per [[scorer-is-ground-truth]]: the fix lives in the
// classifier (internal/parser/postgres.go) which now classifies these
// nodes as StmtAlterPrivileges + IsDCL=true; the floor fires naturally
// via isAdminGrantShape. These tests pin the END-TO-END behavior:
// observable deny verdicts from real SQL strings — proxy.decide() and
// cli.evalDecide() both invoke this exact entry point.

// TestAdminTightFloor_PGCreateRole_Denies pins the #586 CRIT regression:
// CREATE ROLE attacker SUPERUSER under no profile + default-policy=allow
// MUST deny via the admin-tight floor. Pre-fix this returned
// applicable=false (StatementType was StmtDDL, which isAdminGrantShape
// rejects) and the caller fell through to default-allow.
func TestAdminTightFloor_PGCreateRole_Denies(t *testing.T) {
	ps := parsePG(t, "CREATE ROLE attacker SUPERUSER")
	require.True(t, ps.IsDCL,
		"PG CREATE ROLE MUST set IsDCL=true (#586 classifier fix)")

	deny, reason, applicable := AdminTightFloor(ps, nil, "allow")
	assert.True(t, applicable,
		"PG CREATE ROLE MUST trigger the admin-tight floor (#586)")
	assert.True(t, deny,
		"PG CREATE ROLE under no profile MUST default-deny via admin-tight floor (#586)")
	assert.Contains(t, reason, "admin-tight floor",
		"reason MUST name the admin-tight floor so SIEM filters key on the canonical string")
	assert.Contains(t, reason, "default-policy=allow",
		"reason MUST surface that default-allow was bypassed by the floor")
}

// TestAdminTightFloor_PGCreateRoleWithAllowRule_Allows pins the override
// path on the new shape: a profile allow_rule matching admin-grant DCL
// overrides the floor. Operators with legitimate role-provisioning
// workflows add an allow_rule and get the expected verdict.
func TestAdminTightFloor_PGCreateRoleWithAllowRule_Allows(t *testing.T) {
	ps := parsePG(t, "CREATE ROLE service_acct LOGIN")
	prof := &profile.Profile{
		Name: "ops-provisioning",
		AllowRules: []profile.ProfileAllowRule{
			{Pattern: "ALTER_PRIVILEGES:*"},
		},
	}
	deny, reason, applicable := AdminTightFloor(ps, prof, "allow")
	assert.True(t, applicable,
		"PG CREATE ROLE MUST trigger floor evaluation (so override path is considered)")
	assert.False(t, deny,
		"profile allow_rule matching ALTER_PRIVILEGES:* MUST override the floor for CREATE ROLE")
	assert.Contains(t, reason, "overridden",
		"reason MUST surface override so audit reviewers see WHY this passed")
	assert.Contains(t, reason, "ops-provisioning",
		"reason MUST name the overriding profile")
}

// TestAdminTightFloor_PGAlterUser_Denies pins ALTER USER bob SUPERUSER —
// the second concrete UAT-C bypass example. Same node type as ALTER ROLE.
func TestAdminTightFloor_PGAlterUser_Denies(t *testing.T) {
	ps := parsePG(t, "ALTER USER bob SUPERUSER")
	require.True(t, ps.IsDCL)

	deny, _, applicable := AdminTightFloor(ps, nil, "allow")
	assert.True(t, applicable,
		"PG ALTER USER SUPERUSER MUST trigger admin-tight floor (#586)")
	assert.True(t, deny,
		"PG ALTER USER SUPERUSER under no profile MUST default-deny via admin-tight floor (#586)")
}

// TestAdminTightFloor_PGDropUser_Denies pins DROP USER bob. Per the task
// scope: even though dropping is "destruction" rather than "grant," it's
// privilege management — the principal is gone, its grants are orphaned.
// Same admin-tight class as CREATE.
func TestAdminTightFloor_PGDropUser_Denies(t *testing.T) {
	ps := parsePG(t, "DROP USER bob")
	require.True(t, ps.IsDCL)

	deny, _, applicable := AdminTightFloor(ps, nil, "allow")
	assert.True(t, applicable,
		"PG DROP USER MUST trigger admin-tight floor (#586)")
	assert.True(t, deny,
		"PG DROP USER under no profile MUST default-deny via admin-tight floor (#586)")
}

// TestAdminTightFloor_PGAlterDefaultPrivileges_StillDenies is a
// regression check for UC-34: ALTER DEFAULT PRIVILEGES still denies
// after the #586 reclassification of CREATE/ALTER/DROP ROLE+USER. The
// classifier change touched the StmtDDL switch case; this test makes
// sure ALTER DEFAULT PRIVILEGES (a different node type entirely) still
// flows through the StmtAlterPrivileges path.
func TestAdminTightFloor_PGAlterDefaultPrivileges_StillDenies(t *testing.T) {
	ps := parsePG(t,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO bob")
	require.True(t, ps.IsDCL, "UC-34 regression: ALTER DEFAULT PRIVILEGES MUST stay IsDCL")
	require.Equal(t, parser.StmtAlterPrivileges, ps.StatementType,
		"UC-34 regression: ALTER DEFAULT PRIVILEGES MUST stay StmtAlterPrivileges")

	deny, reason, applicable := AdminTightFloor(ps, nil, "allow")
	assert.True(t, applicable, "UC-34 regression: floor MUST still fire on ALTER DEFAULT PRIVILEGES")
	assert.True(t, deny, "UC-34 regression: ALTER DEFAULT PRIVILEGES MUST still default-deny")
	assert.Contains(t, reason, "admin-tight floor")
}

// TestAdminTightFloor_CrossDialectUserMgmtParity_BothDeny pins the
// cross-dialect parity invariant: equivalent user-management operations
// in PG + MySQL must both DENY under no profile + default-policy=allow.
// Per [[scorer-is-ground-truth]]: the calibration vocabulary stays
// uniform across dialects so SIEM filters + audit reviewers see the
// same shape on either upstream. Pre-#586 the parity was BROKEN in the
// wrong direction (MySQL covered, PG missed); #588 closed the residual
// MySQL DROP USER gap so the matrix is now fully symmetric.
func TestAdminTightFloor_CrossDialectUserMgmtParity_BothDeny(t *testing.T) {
	// Parametrized: same conceptual operation on each dialect.
	cases := []struct {
		name     string
		dialect  string
		sql      string
		parsedFn func(t *testing.T, sql string) *parser.ParsedStatement
	}{
		{"PG-CreateUserWithSuperuser",
			"postgres", "CREATE USER attacker WITH SUPERUSER PASSWORD 'pw'", parsePG},
		{"MySQL-CreateUser",
			"mysql", "CREATE USER 'attacker'@'%' IDENTIFIED BY 'pw'", parseMySQL},
		{"PG-DropUser",
			"postgres", "DROP USER bob", parsePG},
		// #588 — MySQL DROP USER now denies too (was the residual gap;
		// pre-#588 it classified as StmtRevoke + bypassed the floor).
		// The classifier fix in mysql_dcl.go promotes it to
		// StmtAlterPrivileges per populateMySQLDropUser. See
		// TestAdminTightFloor_CrossDialectDropUser_BothDeny below for
		// the dedicated parity-pin.
		{"MySQL-DropUser",
			"mysql", "DROP USER 'bob'@'%'", parseMySQL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := tc.parsedFn(t, tc.sql)
			require.True(t, ps.IsDCL,
				"%s parser MUST set IsDCL=true for user-mgmt statement (cross-dialect parity)",
				tc.dialect)
			deny, reason, applicable := AdminTightFloor(ps, nil, "allow")
			assert.True(t, applicable,
				"%s user-mgmt MUST trigger admin-tight floor (cross-dialect parity)", tc.dialect)
			assert.True(t, deny,
				"%s user-mgmt under no profile MUST default-deny via admin-tight floor "+
					"(cross-dialect parity; #586 closed PG gap; #588 closed MySQL DROP USER gap)",
				tc.dialect)
			assert.Contains(t, reason, "admin-tight floor",
				"%s reason MUST name the admin-tight floor (SIEM filter parity)", tc.dialect)
		})
	}
}

// =============================================================================
// #588 — MySQL DROP USER / DROP ROLE admin-tight floor closure.
// =============================================================================
//
// UAT-C 2026-05-25 confirmed: MySQL `DROP USER 'bob'@'%'` was classified
// as StmtRevoke (cleanup verb) and bypassed admin-tight floor even with
// `--profile safe-default --default-policy allow`. Same classifier-gap
// shape as #586 (just fixed for PG); cross-dialect inconsistency in
// MySQL where CREATE USER + RENAME USER + SET PASSWORD already routed
// through the admin-tight class. Per [[scorer-is-ground-truth]]: the
// fix lives in internal/parser/mysql_dcl.go which now classifies
// populateMySQLDropUser + populateMySQLDropRole as StmtAlterPrivileges
// + IsDCL=true; the floor fires naturally via isAdminGrantShape. These
// tests pin the END-TO-END floor behavior on real SQL strings.

// TestAdminTightFloor_MySQLDropUser_Denies pins the #588 regression:
// MySQL `DROP USER 'bob'@'%'` under no profile + default-policy=allow
// MUST deny via the admin-tight floor. Pre-#588 this returned
// applicable=false (StatementType was StmtRevoke, which isAdminGrantShape
// rejects) and the caller fell through to default-allow.
func TestAdminTightFloor_MySQLDropUser_Denies(t *testing.T) {
	ps := parseMySQL(t, "DROP USER 'bob'@'%'")
	require.True(t, ps.IsDCL,
		"MySQL DROP USER MUST set IsDCL=true (#588 classifier fix)")

	deny, reason, applicable := AdminTightFloor(ps, nil, "allow")
	assert.True(t, applicable,
		"MySQL DROP USER MUST trigger the admin-tight floor (#588)")
	assert.True(t, deny,
		"MySQL DROP USER under no profile MUST default-deny via admin-tight floor (#588)")
	assert.Contains(t, reason, "admin-tight floor",
		"reason MUST name the admin-tight floor so SIEM filters key on the canonical string")
	assert.Contains(t, reason, "default-policy=allow",
		"reason MUST surface that default-allow was bypassed by the floor")
}

// TestAdminTightFloor_MySQLDropUserWithAllowRule_Allows pins the
// override path on the new shape: a profile allow_rule matching
// ALTER_PRIVILEGES:* lets DROP USER through. Operators with legitimate
// user-rotation workflows get the expected verdict — parity with the
// #586 PG path's override behavior.
func TestAdminTightFloor_MySQLDropUserWithAllowRule_Allows(t *testing.T) {
	ps := parseMySQL(t, "DROP USER 'bob'@'%'")
	prof := &profile.Profile{
		Name: "ops-user-rotation",
		AllowRules: []profile.ProfileAllowRule{
			{Pattern: "ALTER_PRIVILEGES:*"},
		},
	}
	deny, reason, applicable := AdminTightFloor(ps, prof, "allow")
	assert.True(t, applicable,
		"MySQL DROP USER MUST trigger floor evaluation (so override path is considered)")
	assert.False(t, deny,
		"profile allow_rule matching ALTER_PRIVILEGES:* MUST override the floor for DROP USER (#588)")
	assert.Contains(t, reason, "overridden",
		"reason MUST surface override so audit reviewers see WHY this passed")
	assert.Contains(t, reason, "ops-user-rotation",
		"reason MUST name the overriding profile")
}

// TestAdminTightFloor_MySQLDropUserIfExists_Denies pins the idempotent
// variant: `DROP USER IF EXISTS 'bob'@'%'` MUST deny identically.
// IF EXISTS doesn't change the operation's privilege-management shape.
func TestAdminTightFloor_MySQLDropUserIfExists_Denies(t *testing.T) {
	ps := parseMySQL(t, "DROP USER IF EXISTS 'bob'@'%'")
	require.True(t, ps.IsDCL)

	deny, _, applicable := AdminTightFloor(ps, nil, "allow")
	assert.True(t, applicable,
		"MySQL DROP USER IF EXISTS MUST trigger admin-tight floor (#588)")
	assert.True(t, deny,
		"MySQL DROP USER IF EXISTS under no profile MUST default-deny via admin-tight floor (#588)")
}

// TestAdminTightFloor_MySQLDropUserMultiple_Denies pins the
// multi-grantee variant: `DROP USER 'a'@'%', 'b'@'%'` MUST deny
// identically — bulk destruction is the adversarial shape that
// MOST needs the floor to fire.
func TestAdminTightFloor_MySQLDropUserMultiple_Denies(t *testing.T) {
	ps := parseMySQL(t, "DROP USER 'a'@'%', 'b'@'%'")
	require.True(t, ps.IsDCL)

	deny, _, applicable := AdminTightFloor(ps, nil, "allow")
	assert.True(t, applicable,
		"MySQL multi-grantee DROP USER MUST trigger admin-tight floor (#588)")
	assert.True(t, deny,
		"MySQL multi-grantee DROP USER under no profile MUST default-deny "+
			"(bulk destruction is the adversarial shape; #588)")
}

// TestAdminTightFloor_CrossDialectDropUser_BothDeny pins the dedicated
// cross-dialect DROP USER parity assertion: equivalent DROP USER (PG
// post-#586 + MySQL post-#588) must BOTH DENY under no profile +
// default-policy=allow. This is the parity-pin that proves the residual
// MySQL gap is closed — pre-#588 the matrix was asymmetric in the
// wrong direction (PG covered, MySQL missed).
func TestAdminTightFloor_CrossDialectDropUser_BothDeny(t *testing.T) {
	cases := []struct {
		name     string
		dialect  string
		sql      string
		parsedFn func(t *testing.T, sql string) *parser.ParsedStatement
	}{
		{"PG-DropUser-Post586",
			"postgres", "DROP USER bob", parsePG},
		{"MySQL-DropUser-Post588",
			"mysql", "DROP USER 'bob'@'%'", parseMySQL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := tc.parsedFn(t, tc.sql)
			require.True(t, ps.IsDCL,
				"%s DROP USER MUST set IsDCL=true (cross-dialect parity invariant)",
				tc.dialect)
			deny, reason, applicable := AdminTightFloor(ps, nil, "allow")
			assert.True(t, applicable,
				"%s DROP USER MUST trigger admin-tight floor "+
					"(cross-dialect parity; #586 PG + #588 MySQL closures)",
				tc.dialect)
			assert.True(t, deny,
				"%s DROP USER under no profile MUST default-deny via admin-tight floor "+
					"(cross-dialect parity; pre-#588 MySQL silently allowed)", tc.dialect)
			assert.Contains(t, reason, "admin-tight floor",
				"%s reason MUST name the floor (SIEM filter contract)", tc.dialect)
		})
	}
}

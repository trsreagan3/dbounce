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

// Package decision houses cross-call-site decision primitives that
// MUST stay identical between dbounce's wire-protocol hot path
// (proxy.decide) and the CLI dry-run path (cli/decide.go's
// evalDecide). Per [[ibounce-honest-positioning]]: CLI dry-run that
// diverges from production gating is a calibration-drift bug class —
// operators rely on `dbounce decide --dialect X 'sql'` matching what
// the running proxy would do, byte-for-byte.
//
// Per #559: this package was extracted after #556 surfaced a missing
// admin-tight floor in the CLI path. UC-34 (commit e442f9e) wired the
// floor on the PG hot path; #556 (commit 1f78729) wired MySQL parity;
// both edited proxy.decide() INLINE. The CLI path was parallel + got
// missed both times. Single-source-of-truth here closes that gap.
package decision

import (
	"fmt"

	"github.com/trsreagan3/dbounce/internal/parser"
	"github.com/trsreagan3/dbounce/internal/profile"
)

// AdminTightFloor reports whether the admin-tight floor (UC-34 + #556)
// would deny the given DCL statement under the given active profile.
//
// Returns (deny, reason, applicable):
//
//   - applicable=false when stmt is nil OR stmt.IsDCL=false OR stmt is
//     not an admin-grant shape (StmtGrant / StmtAlterPrivileges). The
//     caller MUST treat this as "the floor doesn't apply; defer to the
//     surrounding default-policy / rule engine." deny is always false
//     when applicable=false.
//
//   - applicable=true + deny=false when stmt IS an admin-grant DCL AND
//     the active profile has an allow_rule matching the statement. The
//     caller MUST treat this as "the floor was overridden by an
//     explicit operator allow." reason carries the matched pattern for
//     audit visibility.
//
//   - applicable=true + deny=true when stmt IS an admin-grant DCL AND
//     no profile allow_rule matched. The caller MUST emit DENY with
//     reason carrying the floor explanation + the default-policy that
//     would otherwise have applied (for "your default-allow was
//     bypassed by the floor" audit visibility).
//
// defaultPolicy is interpolated into the deny reason so audit reviewers
// see WHICH default-policy the floor superseded. Empty string is
// allowed (reason elides the default-policy clause).
//
// Per UC-34 (proxy.decide() Step 5.5): REVOKE is NOT in the admin-grant
// shape set — revoking is the cleanup direction and admin-tight denying
// it would refuse the safer half of every GRANT/REVOKE pair. Per
// [[safety-mode-lean-permissive]]: block rarely; the floor exists to
// catch privilege escalation that would otherwise slip through
// default-policy=allow.
//
// Per [[scorer-is-ground-truth]]: this function is pure (no I/O, no
// mutation). The caller (proxy or CLI) owns the audit-write side.
func AdminTightFloor(
	stmt *parser.ParsedStatement,
	prof *profile.Profile,
	defaultPolicy string,
) (deny bool, reason string, applicable bool) {
	if stmt == nil || !stmt.IsDCL || !isAdminGrantShape(stmt.StatementType) {
		return false, "", false
	}
	// Override path: profile allow_rule. The proxy's hot path also has
	// task-allow + global-allow override layers ABOVE this floor (see
	// proxy.decide Step 4 + 5); when those layers fire the caller
	// returns BEFORE invoking AdminTightFloor, so they're naturally
	// honored. The profile allow_rule check here is defense-in-depth
	// + matches the documented "override path" on proxy.decide Step 5.5
	// for the CLI dry-run path (where the profile allow path was
	// already evaluated via Profile.Evaluate's Allowed=true short-
	// circuit upstream of this call — but a future call site that
	// bypassed Profile.Evaluate would still see the override).
	if prof != nil {
		profileView := &profile.ParsedStatement{
			StatementType:    stmt.StatementType,
			TablesTouched:    stmt.TablesTouched,
			FunctionsCalled:  stmt.FunctionsCalled,
			IsDML:            stmt.IsDML,
			IsDDL:            stmt.IsDDL,
			IsDCL:            stmt.IsDCL,
			DCLTargetsPublic: stmt.DCLTargetsPublic,
			HasMutatingNode:  stmt.HasMutatingNode,
			IsExplain:        stmt.IsExplain,
			IsExplainAnalyze: stmt.IsExplainAnalyze,
		}
		if matched, pattern := prof.MatchAllowRule(profileView); matched {
			return false, fmt.Sprintf(
				"admin-tight floor overridden by profile %q allow_rule pattern %q",
				prof.Name, pattern), true
		}
	}
	// Floor fires: no override matched + the statement is an admin-grant
	// DCL. Reason mirrors proxy.decide Step 5.5 byte-for-byte (audit
	// log scrapers + SIEM dashboards key on this string).
	//
	// #590: use the MutatingNodeType when it carries a more specific
	// operation name than StatementType. MySQL DCL shapes like CREATE
	// USER, DROP USER, RENAME USER, and SET PASSWORD all classify as
	// StmtGrant / StmtAlterPrivileges for the admin-tight floor check,
	// but their MutatingNodeType carries the exact verb (CREATE-USER,
	// DROP-USER, etc.). The reason string MUST name the actual command
	// so operators and SIEM dashboards see "CREATE USER requires..." not
	// "GRANT requires..." for a CREATE USER statement.
	opName := verbForReason(stmt)
	if defaultPolicy == "" {
		return true, fmt.Sprintf(
			"admin-tight floor: %s requires an explicit allow_rule "+
				"(profile or global) — DCL operations are default-deny "+
				"per [[safety-mode-lean-permissive]]",
			opName), true
	}
	return true, fmt.Sprintf(
		"admin-tight floor: %s requires an explicit allow_rule "+
			"(profile or global) — DCL operations are default-deny "+
			"per [[safety-mode-lean-permissive]]; default-policy=%s "+
			"is bypassed for privilege management",
		opName, defaultPolicy), true
}

// verbForReason returns the most specific operation name for the deny
// reason string. When MutatingNodeType carries a value (MySQL DCL shapes
// use it to record the exact verb like CREATE-USER, DROP-USER, etc.) it
// is preferred over StatementType because it is more informative to
// operators ("CREATE USER requires..." vs "GRANT requires...").
//
// Per #590: before this helper the reason always used StatementType,
// which for MySQL CREATE USER is StmtGrant = "GRANT" — misleading in
// the admin-tight deny message. MutatingNodeType carries the actual
// command verb for all MySQL DCL shapes (mysqlDCLOpCreateUser =
// "CREATE-USER", mysqlDCLOpDropUser = "DROP-USER", etc.).
func verbForReason(stmt *parser.ParsedStatement) string {
	if stmt.MutatingNodeType != "" {
		return stmt.MutatingNodeType
	}
	return stmt.StatementType
}

// isAdminGrantShape returns true when the parsed statement type is one
// of the privilege-granting DCL shapes that get default-deny treatment
// per the UC-34 admin-tight floor. StmtRevoke is NOT in the set —
// revoking is cleanup; the floor would refuse the safer direction of
// every GRANT/REVOKE pair. Per [[safety-mode-lean-permissive]].
//
// Kept package-private — external callers should invoke AdminTightFloor
// which composes this with the IsDCL check + override path.
func isAdminGrantShape(stmtType string) bool {
	switch stmtType {
	case parser.StmtGrant, parser.StmtAlterPrivileges:
		return true
	}
	return false
}

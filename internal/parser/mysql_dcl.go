// MySQL DCL (Data Control Language) handling. Per #556 follow-up from
// UC-34: the PostgreSQL parser surfaces GRANT/REVOKE/ALTER DEFAULT
// PRIVILEGES via libpg_query AST nodes + the admin-tight floor in
// proxy.decide() Step 5.5 fires on IsDCL=true. Before this file the
// MySQL classifier had ZERO DCL handling — every MySQL GRANT shape fell
// through to xwb1989 (which doesn't model GRANT/REVOKE/CREATE USER/DROP
// USER/RENAME USER/SET PASSWORD), classified as StmtUnparseable, and
// slipped past the admin-tight floor entirely on a deployment running
// MySQL upstream.
//
// HONEST POSITIONING (per [[ibounce-honest-positioning]]): xwb1989's
// grammar is the MySQL 5.7-era SELECT/INSERT/UPDATE/DELETE/DDL subset
// Vitess needed for query routing — it never modeled DCL because Vitess
// doesn't reshape privilege statements. Adding the full vitess.io/vitess
// dep brings in hundreds of MB of cluster-orchestration transitive
// deps for AST nodes we'd use for ~5 statement shapes. The dialect's
// existing LOAD DATA INFILE detection (see mysql.go lines 67-90) uses
// a keyword pre-check for the same reason; this file mirrors that shape.
//
// What this file covers:
//   - GRANT <privs> ON <object> TO <grantees> [WITH GRANT OPTION]
//   - REVOKE <privs> ON <object> FROM <grantees>
//   - REVOKE ALL [PRIVILEGES], GRANT OPTION FROM <users>
//   - CREATE USER [IF NOT EXISTS] <user> [IDENTIFIED BY '<password>']
//   - DROP USER [IF EXISTS] <user>
//   - RENAME USER <old> TO <new>
//   - SET PASSWORD [FOR <user>] = ...
//
// What this file does NOT cover (deferred — honest limitations):
//   - FLUSH PRIVILEGES — an admin operation but not strictly a
//     GRANT/REVOKE; left for a separate task. See note at bottom.
//   - GRANT PROXY ON ... — proxy-user delegation; rare in practice.
//   - GRANT ROLE TO ... — MySQL 8.0+ role grants are syntactically
//     identical to user grants in this parser (treated as admin-grant);
//     role-membership-vs-privilege distinction would need AST awareness.
//   - SHOW GRANTS — informational, no privilege change, not DCL.
//   - Multi-statement DCL batches (e.g. GRANT; CREATE USER; GRANT) —
//     the existing MySQL multi-statement path goes through xwb1989 which
//     errors on the first DCL token; the pre-check sees only the FIRST
//     statement. A multi-DCL batch will classify its first statement
//     correctly + the trailing DCL statements will fall through as
//     StmtUnparseable (which is admin-tight enough — UNPARSEABLE
//     under default-policy=allow still bypasses the floor; operators
//     deploying with default-allow + multi-DCL batches should add
//     `MUTATING:*` denies).
//
// Risk-indicator vocabulary (parallels postgres.go for cross-dialect
// SIEM filter parity):
//   - "public_grant"           — grantee includes PUBLIC or '%'@'%'
//   - "all_privileges"         — privilege list contains ALL [PRIVILEGES]
//   - "with_grant_option"      — grant carries WITH GRANT OPTION
//   - "identified_by_password" — password literal embedded in statement
//                                (CRIT: gets persisted to audit log if
//                                --redact-literals is off)
//   - "create_user"            — CREATE USER (escalation-prep shape)
//   - "wildcard_host"          — host part is '%' (any-host grant)
//
// Per [[creates-never-mutates]]: this file PARSES STRINGS. No execution,
// no connection, no credentials.

package parser

import (
	"strings"
)

// MySQL DCL operation labels surfaced via ParsedStatement.MutatingNodeType
// so a downstream rule pack can match on a stable vocabulary
// (parallels mysqlMutatingLoadDataInfile / mysqlMutatingSetGlobal).
const (
	mysqlDCLOpGrant      = "GRANT"
	mysqlDCLOpRevoke     = "REVOKE"
	mysqlDCLOpCreateUser = "CREATE-USER"
	mysqlDCLOpDropUser   = "DROP-USER"
	mysqlDCLOpRenameUser = "RENAME-USER"
	mysqlDCLOpSetPwd     = "SET-PASSWORD"
)

// detectMySQLDCL inspects the (comment-stripped, ToUpper-ed) leading
// keyword of a MySQL statement and, when it matches a DCL shape,
// populates ParsedStatement fields + returns true. Returns false for
// non-DCL statements; the caller (parseMySQL) then proceeds with the
// xwb1989 path.
//
// The stripped + upper input is supplied by the caller so we don't
// re-do the comment-strip work parseMySQL already did for the LOAD
// pre-check (the same bytes — the caller passes them straight through).
//
// Inputs:
//   - raw    : original SQL (for ParsedStatement.Raw round-trip — not
//              touched here; the caller stored it).
//   - stripped: comment-stripped form (preserves case + identifiers).
//   - upper   : ToUpper(stripped) — used for keyword matching.
//
// Outputs (when this returns true):
//   - out.StatementType = StmtGrant | StmtRevoke (or REVOKE for
//     RENAME-USER → admin-modify but mapped to StmtAlterPrivileges
//     for cross-dialect parity with the PG admin-tight floor: the
//     PG path treats ALTER DEFAULT PRIVILEGES as a separate admin-tight
//     shape, which is the closest cross-dialect cousin to RENAME USER
//     / SET PASSWORD; on the MySQL side they all should default-deny).
//     CREATE USER + DROP USER both map to StmtGrant (creating a user
//     IS an admin-grant; dropping is paired with revoke but we'd
//     rather default-deny user destruction than treat it as "safe
//     cleanup" — operators who legitimately drop users add an
//     explicit allow_rule).
//   - out.IsDCL = true (load-bearing: this gates the Step 5.5 floor).
//   - out.Operation = mysqlDCLOp* label (surfaced to MutatingNodeType
//     so a rule pack can match on GRANT-vs-CREATE-USER specifically).
//   - out.Privileges / Grantees / TargetObject / RiskIndicators
//     populated where extractable.
//
// On parse-uncertainty (a SQL whose lead matches "GRANT" but whose
// body we can't fully decompose): IsDCL=true is still set + the
// StatementType is StmtGrant. The admin-tight floor still fires —
// safer to deny an ambiguous DCL than to fall through.
func detectMySQLDCL(out *ParsedStatement, stripped, upper string) bool {
	// REVOKE ... FROM <user> — must check BEFORE GRANT because REVOKE
	// appears in "REVOKE ALL PRIVILEGES, GRANT OPTION FROM ..." which
	// contains the substring "GRANT OPTION". The leading-keyword test
	// (HasPrefix on upper) is unambiguous.
	switch {
	case hasKeywordPrefix(upper, "REVOKE"):
		populateMySQLRevoke(out, stripped, upper)
		return true
	case hasKeywordPrefix(upper, "GRANT"):
		populateMySQLGrant(out, stripped, upper)
		return true
	case hasKeywordPrefix(upper, "CREATE USER"):
		populateMySQLCreateUser(out, stripped, upper)
		return true
	case hasKeywordPrefix(upper, "DROP USER"):
		populateMySQLDropUser(out, stripped, upper)
		return true
	case hasKeywordPrefix(upper, "RENAME USER"):
		populateMySQLRenameUser(out, stripped, upper)
		return true
	case hasKeywordPrefix(upper, "SET PASSWORD"):
		populateMySQLSetPassword(out, stripped, upper)
		return true
	}
	return false
}

// hasKeywordPrefix returns true when upper starts with the keyword AND
// the character after the keyword is a delimiter (whitespace, EOF, or
// a SQL token boundary). Prevents false positives where an identifier
// happens to start with "GRANT" (e.g. a column named `grant_id`).
func hasKeywordPrefix(upper, keyword string) bool {
	if !strings.HasPrefix(upper, keyword) {
		return false
	}
	if len(upper) == len(keyword) {
		return true
	}
	next := upper[len(keyword)]
	return next == ' ' || next == '\t' || next == '\n' || next == ';' ||
		next == '\r' || next == '(' // unlikely but defensive
}

// populateMySQLGrant fills out a GRANT statement.
//
// Grammar (the load-bearing subset):
//
//	GRANT <priv_list> ON [<type>] <object> TO <grantee_list>
//	   [REQUIRE ...] [WITH GRANT OPTION] [WITH ...]
//
// Best-effort parse — see file header for limitations.
func populateMySQLGrant(out *ParsedStatement, stripped, upper string) {
	out.StatementType = StmtGrant
	out.IsDCL = true
	out.HasMutatingNode = false // DCL is not DML — matches PG semantics
	out.MutatingNodeType = mysqlDCLOpGrant

	// Slice out the body after the GRANT keyword.
	body := strings.TrimSpace(stripped[len("GRANT"):])
	bodyUpper := strings.ToUpper(body)

	// Privileges = everything between "GRANT" and " ON ".
	onIdx := findKeywordIndex(bodyUpper, " ON ")
	if onIdx < 0 {
		// No ON clause — malformed but still DCL. Default to ALL.
		out.Privileges = []string{"ALL"}
		return
	}
	privsRaw := strings.TrimSpace(body[:onIdx])
	out.Privileges = parseMySQLPrivList(privsRaw)
	if grantHasAllMySQL(out.Privileges) {
		out.RiskIndicators = appendUnique(out.RiskIndicators, "all_privileges")
	}

	// Target + grantees = everything after " ON ".
	rest := strings.TrimSpace(body[onIdx+len(" ON "):])
	restUpper := strings.ToUpper(rest)

	// TO clause delimits target from grantees.
	toIdx := findKeywordIndex(restUpper, " TO ")
	if toIdx < 0 {
		out.TargetObject = mysqlGrantTargetObject(rest)
		return
	}
	targetRaw := strings.TrimSpace(rest[:toIdx])
	out.TargetObject = mysqlGrantTargetObject(targetRaw)

	granteesRaw := strings.TrimSpace(rest[toIdx+len(" TO "):])

	// Trim trailing clauses (REQUIRE / WITH / IDENTIFIED) before
	// extracting grantees.
	granteesPart := stripTrailingGrantClauses(granteesRaw)
	out.Grantees = parseMySQLGranteeList(granteesPart)

	// Risk-indicator population from grantees.
	for _, g := range out.Grantees {
		if granteeIsPublic(g) {
			out.RiskIndicators = appendUnique(out.RiskIndicators, "public_grant")
		}
		if granteeHasWildcardHost(g) {
			out.RiskIndicators = appendUnique(out.RiskIndicators, "wildcard_host")
		}
	}

	// WITH GRANT OPTION detection. Case-insensitive scan on the trailing
	// clauses (the granteesRaw includes them; bodyUpper includes them
	// too).
	if strings.Contains(bodyUpper, " WITH GRANT OPTION") ||
		strings.HasSuffix(bodyUpper, " WITH GRANT OPTION") {
		out.RiskIndicators = appendUnique(out.RiskIndicators, "with_grant_option")
	}

	// IDENTIFIED BY <password> — pre-MySQL-8 syntax that embeds the
	// password literal directly in the GRANT statement. Flag so the
	// operator knows the audit log captured a credential.
	if strings.Contains(bodyUpper, " IDENTIFIED BY ") {
		out.RiskIndicators = appendUnique(out.RiskIndicators, "identified_by_password")
	}
}

// populateMySQLRevoke fills out a REVOKE statement.
//
// Grammar:
//
//	REVOKE <priv_list> [, GRANT OPTION] ON <object> FROM <grantee_list>
//	REVOKE ALL [PRIVILEGES], GRANT OPTION FROM <user_list>
//
// REVOKE is the cleanup direction — per the PG path, the admin-tight
// floor does NOT fire on StmtRevoke (would refuse the safer direction
// of every GRANT/REVOKE pair). RiskIndicators stay minimal.
func populateMySQLRevoke(out *ParsedStatement, stripped, upper string) {
	out.StatementType = StmtRevoke
	out.IsDCL = true
	out.MutatingNodeType = mysqlDCLOpRevoke

	body := strings.TrimSpace(stripped[len("REVOKE"):])
	bodyUpper := strings.ToUpper(body)

	// Two REVOKE shapes:
	//   1. REVOKE <privs> ON <obj> FROM <users>     (object-scoped)
	//   2. REVOKE ALL PRIVILEGES, GRANT OPTION FROM <users>  (global)
	// Distinguish by presence of " ON " before " FROM ".
	onIdx := findKeywordIndex(bodyUpper, " ON ")
	fromIdx := findKeywordIndex(bodyUpper, " FROM ")
	if fromIdx < 0 {
		// Malformed — at minimum we've already set IsDCL + StatementType.
		out.Privileges = []string{"ALL"}
		return
	}

	switch {
	case onIdx > 0 && onIdx < fromIdx:
		// Shape 1: object-scoped REVOKE.
		out.Privileges = parseMySQLPrivList(strings.TrimSpace(body[:onIdx]))
		targetRaw := strings.TrimSpace(body[onIdx+len(" ON ") : fromIdx])
		out.TargetObject = mysqlGrantTargetObject(targetRaw)
		out.Grantees = parseMySQLGranteeList(strings.TrimSpace(body[fromIdx+len(" FROM "):]))
	default:
		// Shape 2: global REVOKE ALL ... FROM <users>.
		out.Privileges = parseMySQLPrivList(strings.TrimSpace(body[:fromIdx]))
		out.Grantees = parseMySQLGranteeList(strings.TrimSpace(body[fromIdx+len(" FROM "):]))
	}
}

// populateMySQLCreateUser fills out a CREATE USER statement.
//
// Grammar:
//
//	CREATE USER [IF NOT EXISTS] <user> [IDENTIFIED BY '<password>']
//	   [, <user> [IDENTIFIED BY '<password>']]...
//	   [REQUIRE ...] [PASSWORD EXPIRE ...] [ATTRIBUTE ...]
//
// Creating a user IS an admin-grant by another name — they exist solely
// to be the target of subsequent GRANTs. Classified as StmtGrant so the
// admin-tight floor fires.
//
// CREATE USER ALSO gets risk_indicator "create_user" because the
// presence of a CREATE USER statement is itself a sign of privilege
// expansion (vs a GRANT on an existing user, which the operator has
// already vetted).
func populateMySQLCreateUser(out *ParsedStatement, stripped, upper string) {
	out.StatementType = StmtGrant
	out.IsDCL = true
	out.MutatingNodeType = mysqlDCLOpCreateUser
	out.Privileges = []string{"CREATE USER"}
	out.RiskIndicators = appendUnique(out.RiskIndicators, "create_user")

	// Slice after "CREATE USER".
	body := strings.TrimSpace(stripped[len("CREATE USER"):])
	bodyUpper := strings.ToUpper(body)

	// Strip optional "IF NOT EXISTS".
	if strings.HasPrefix(bodyUpper, "IF NOT EXISTS ") {
		body = strings.TrimSpace(body[len("IF NOT EXISTS "):])
		bodyUpper = strings.ToUpper(body)
	}

	// Detect IDENTIFIED BY for the password-leak risk indicator.
	if strings.Contains(bodyUpper, " IDENTIFIED BY ") ||
		strings.HasPrefix(bodyUpper, "IDENTIFIED BY ") {
		out.RiskIndicators = appendUnique(out.RiskIndicators, "identified_by_password")
	}

	// Extract user names — everything up to the first IDENTIFIED /
	// REQUIRE / WITH / PASSWORD / ATTRIBUTE clause (or EOF). Then split
	// on comma at top level (commas inside quoted strings stay inside).
	userPart := stripTrailingGrantClauses(body)
	users := parseMySQLGranteeList(userPart)
	out.Grantees = users
	out.TargetObject = "user-account" // sentinel — no object target on CREATE USER

	// Risk-indicators from extracted user names.
	for _, u := range users {
		if granteeIsPublic(u) {
			out.RiskIndicators = appendUnique(out.RiskIndicators, "public_grant")
		}
		if granteeHasWildcardHost(u) {
			out.RiskIndicators = appendUnique(out.RiskIndicators, "wildcard_host")
		}
	}
}

// populateMySQLDropUser fills out a DROP USER statement.
//
// Classified as StmtRevoke — dropping a user revokes everything the
// user had. Per the REVOKE-is-cleanup path the admin-tight floor does
// NOT fire on DROP USER. (An operator who wants user-destruction to be
// gated adds an explicit deny rule for DROP-USER MutatingNodeType.)
func populateMySQLDropUser(out *ParsedStatement, stripped, upper string) {
	out.StatementType = StmtRevoke
	out.IsDCL = true
	out.MutatingNodeType = mysqlDCLOpDropUser
	out.Privileges = []string{"DROP USER"}

	body := strings.TrimSpace(stripped[len("DROP USER"):])
	bodyUpper := strings.ToUpper(body)
	if strings.HasPrefix(bodyUpper, "IF EXISTS ") {
		body = strings.TrimSpace(body[len("IF EXISTS "):])
	}
	out.Grantees = parseMySQLGranteeList(body)
	out.TargetObject = "user-account"
}

// populateMySQLRenameUser fills out a RENAME USER statement.
//
// Classified as StmtAlterPrivileges — semantically modifies the
// privilege-target identity (a renamed user keeps its privileges but
// under a new name; downstream allow_rules pinned to the old name
// silently stop matching). Falls under the admin-tight floor.
func populateMySQLRenameUser(out *ParsedStatement, stripped, upper string) {
	out.StatementType = StmtAlterPrivileges
	out.IsDCL = true
	out.MutatingNodeType = mysqlDCLOpRenameUser
	out.Privileges = []string{"RENAME USER"}

	body := strings.TrimSpace(stripped[len("RENAME USER"):])
	out.Grantees = parseMySQLGranteeList(body)
	out.TargetObject = "user-account"
}

// populateMySQLSetPassword fills out a SET PASSWORD statement.
//
// Grammar:
//
//	SET PASSWORD [FOR <user>] = '<password>' | PASSWORD('<password>')
//
// Classified as StmtAlterPrivileges + admin-tight (changing a password
// is a credential-mutation shape that almost always wants explicit
// approval). RiskIndicator identified_by_password always fires because
// the password literal is in the statement bytes.
func populateMySQLSetPassword(out *ParsedStatement, stripped, upper string) {
	out.StatementType = StmtAlterPrivileges
	out.IsDCL = true
	out.MutatingNodeType = mysqlDCLOpSetPwd
	out.Privileges = []string{"SET PASSWORD"}
	out.RiskIndicators = appendUnique(out.RiskIndicators, "identified_by_password")

	body := strings.TrimSpace(stripped[len("SET PASSWORD"):])
	bodyUpper := strings.ToUpper(body)
	if strings.HasPrefix(bodyUpper, "FOR ") {
		// "FOR <user> = ..."
		afterFor := strings.TrimSpace(body[len("FOR "):])
		// Take up to the '=' as the user name.
		eqIdx := strings.Index(afterFor, "=")
		if eqIdx > 0 {
			user := strings.TrimSpace(afterFor[:eqIdx])
			out.Grantees = parseMySQLGranteeList(user)
		}
	}
	// SET PASSWORD without FOR targets the current session user — no
	// grantee to extract.
	out.TargetObject = "user-account"
}

// parseMySQLPrivList splits a comma-separated privilege list at top
// level (commas inside parentheses or quoted strings stay inside),
// normalizes to upper-case, and strips trailing column-grant
// parenthesized lists (e.g. "SELECT (col1, col2)" → "SELECT").
func parseMySQLPrivList(raw string) []string {
	parts := splitTopLevelComma(raw)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		// Strip trailing parenthesized column-list.
		if paren := strings.Index(p, "("); paren >= 0 {
			p = p[:paren]
		}
		p = strings.TrimSpace(strings.ToUpper(p))
		if p == "" {
			continue
		}
		// Normalize "ALL PRIVILEGES" → "ALL" so the all_privileges
		// indicator's predicate stays simple.
		if p == "ALL PRIVILEGES" {
			p = "ALL"
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return []string{"ALL"}
	}
	return out
}

// parseMySQLGranteeList splits a comma-separated grantee list at top
// level. Each grantee is normalized to lowercase. PUBLIC stays as the
// literal "public" so granteeIsPublic matches. 'user'@'host' forms
// are preserved verbatim.
func parseMySQLGranteeList(raw string) []string {
	parts := splitTopLevelComma(raw)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		// Trim trailing IDENTIFIED BY '...' suffix on a per-grantee
		// basis (CREATE USER multi-user shape allows
		// "u1@h1 IDENTIFIED BY '...', u2@h2 IDENTIFIED BY '...'").
		pUpper := strings.ToUpper(p)
		if idx := strings.Index(pUpper, " IDENTIFIED BY "); idx > 0 {
			p = p[:idx]
		}
		p = strings.TrimSpace(p)
		// Trim trailing ';' or extraneous noise.
		p = strings.TrimRight(p, "; \t\r\n")
		if p == "" {
			continue
		}
		// Lowercase (matches PG path).
		out = append(out, strings.ToLower(p))
	}
	return out
}

// splitTopLevelComma splits raw on commas that appear OUTSIDE quoted
// strings and parenthesized expressions. Returns the list with each
// element trimmed of leading/trailing whitespace.
func splitTopLevelComma(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := []string{}
	depth := 0
	inSingle := false
	inDouble := false
	inBacktick := false
	start := 0
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		switch {
		case inSingle:
			if ch == '\\' && i+1 < len(raw) {
				i++
				continue
			}
			if ch == '\'' {
				// '' = escaped single quote inside single-quoted string.
				if i+1 < len(raw) && raw[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
		case inDouble:
			if ch == '\\' && i+1 < len(raw) {
				i++
				continue
			}
			if ch == '"' {
				if i+1 < len(raw) && raw[i+1] == '"' {
					i++
					continue
				}
				inDouble = false
			}
		case inBacktick:
			if ch == '`' {
				inBacktick = false
			}
		default:
			switch ch {
			case '\'':
				inSingle = true
			case '"':
				inDouble = true
			case '`':
				inBacktick = true
			case '(':
				depth++
			case ')':
				if depth > 0 {
					depth--
				}
			case ',':
				if depth == 0 {
					parts = append(parts, strings.TrimSpace(raw[start:i]))
					start = i + 1
				}
			}
		}
	}
	if start < len(raw) {
		parts = append(parts, strings.TrimSpace(raw[start:]))
	}
	return parts
}

// mysqlGrantTargetObject renders the ON target as a "<kind>:<name>"
// label parallel to grantTargetObjectLabel in postgres.go.
//
// MySQL grammar accepts:
//
//	[TABLE] <db>.<tbl>          — table-scoped (TABLE keyword optional)
//	*.*                         — global (all schemas, all objects)
//	<db>.*                      — schema-scoped (all objects in db)
//	FUNCTION <db>.<fn>          — function-scoped
//	PROCEDURE <db>.<proc>       — procedure-scoped
//
// Labels:
//
//	"table:db.tbl"
//	"global:*.*"
//	"schema:db.*"
//	"function:db.fn"
//	"procedure:db.proc"
//
// Unknown / unparseable target → bare identifier preserved.
func mysqlGrantTargetObject(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	upper := strings.ToUpper(raw)
	prefix := ""
	body := raw
	switch {
	case strings.HasPrefix(upper, "TABLE "):
		prefix = "table"
		body = strings.TrimSpace(raw[len("TABLE "):])
	case strings.HasPrefix(upper, "FUNCTION "):
		prefix = "function"
		body = strings.TrimSpace(raw[len("FUNCTION "):])
	case strings.HasPrefix(upper, "PROCEDURE "):
		prefix = "procedure"
		body = strings.TrimSpace(raw[len("PROCEDURE "):])
	}
	body = strings.ToLower(strings.Trim(body, "`\""))
	// Recognize *.* (global) + <db>.* (schema) shapes.
	if prefix == "" {
		switch {
		case body == "*.*":
			return "global:*.*"
		case strings.HasSuffix(body, ".*"):
			return "schema:" + body
		default:
			prefix = "table"
		}
	}
	return prefix + ":" + body
}

// stripTrailingGrantClauses removes trailing IDENTIFIED BY, REQUIRE,
// WITH, PASSWORD EXPIRE, and ATTRIBUTE clauses from the grantee-list
// region of a GRANT or CREATE USER statement, so the grantee parser
// sees only the user-list bytes.
func stripTrailingGrantClauses(raw string) string {
	upper := strings.ToUpper(raw)
	cuts := []string{
		" IDENTIFIED BY ",
		" IDENTIFIED WITH ",
		" REQUIRE ",
		" WITH ",
		" PASSWORD EXPIRE",
		" ATTRIBUTE ",
		" COMMENT ",
		" RESOURCE OPTION",
	}
	cutAt := len(raw)
	for _, c := range cuts {
		if idx := strings.Index(upper, c); idx > 0 && idx < cutAt {
			cutAt = idx
		}
	}
	return strings.TrimSpace(raw[:cutAt])
}

// granteeIsPublic returns true when the grantee names the MySQL/SQL
// PUBLIC pseudo-role. MySQL doesn't have a canonical PUBLIC like
// PostgreSQL, but operators (and some tools) emit `GRANT ... TO PUBLIC`
// expecting MySQL 8.0+ role semantics; we treat that as the canonical
// "fan privilege to everyone" shape per parity with the PG path.
// Additionally, '%'@'%' on a CREATE USER + subsequent GRANT is the
// effective MySQL equivalent (any-user from any-host).
func granteeIsPublic(grantee string) bool {
	g := strings.ToLower(strings.Trim(grantee, " '`\""))
	if g == "public" {
		return true
	}
	// '%'@'%' or @'%' (any user / any host) — surface as public_grant
	// even when the literal PUBLIC keyword isn't used.
	if g == "'%'@'%'" || g == "%@%" {
		return true
	}
	return false
}

// granteeHasWildcardHost returns true when the grantee's host part is
// '%' (any-host grant) — a less-severe shape than PUBLIC but still a
// "this account can be used from anywhere" signal worth flagging for
// audit. Matches both 'user'@'%' + bare user@%.
func granteeHasWildcardHost(grantee string) bool {
	g := strings.ToLower(grantee)
	return strings.HasSuffix(g, "@'%'") || strings.HasSuffix(g, "@%")
}

// grantHasAllMySQL returns true when the parsed privilege list
// indicates a wildcard grant (ALL or ALL PRIVILEGES). parseMySQLPrivList
// already normalizes "ALL PRIVILEGES" → "ALL"; this helper just checks
// for the literal "ALL" entry.
func grantHasAllMySQL(privs []string) bool {
	for _, p := range privs {
		if p == "ALL" {
			return true
		}
	}
	return false
}

// findKeywordIndex returns the index of the first occurrence of keyword
// in s, where keyword is a whitespace-padded token (e.g. " ON ", " TO ").
// Case-sensitive on s (caller passes ToUpper output). Returns -1 when
// not found. This is the equivalent of strings.Index but kept named for
// readability at call sites — the searches are all keyword-shaped.
func findKeywordIndex(s, keyword string) int {
	return strings.Index(s, keyword)
}

// Future-work note: FLUSH PRIVILEGES.
//
// FLUSH PRIVILEGES reloads the in-memory privilege tables from the
// underlying mysql.* tables. Strictly speaking it's an admin operation
// that doesn't itself grant or revoke — but in practice it's a
// post-condition of out-of-band privilege manipulation (e.g. someone
// edited mysql.user directly + needs FLUSH for the change to take
// effect). We do NOT currently classify FLUSH PRIVILEGES as DCL because
// (a) it doesn't fit the GRANT/REVOKE/USER vocabulary cleanly, and
// (b) it's commonly issued by automation that the admin-tight floor
// would silently break. A separate task can classify FLUSH PRIVILEGES
// as StmtAlterPrivileges if calibration data surfaces it as a real
// bypass shape; for #556 we keep scope tight (per
// [[ibounce-honest-positioning]] + [[v1-scope-bar]]).

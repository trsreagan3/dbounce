// Rule engine — #252 Slice 2 suspicious-activity alerts for dbounce.
//
// Sits ON TOP of the Slice 1 audit-export transport: the proxy emits
// every decision via Exporter.EmitDecision (Slice 1); AFTER that emit
// the proxy invokes RuleEngine.ObserveDecision, which pattern-matches
// against the OCSF event + emits a SECURITY_ALERT event back through
// the SAME exporter when a rule fires. One SIEM ingest sees both the
// decision stream + the alert stream.
//
// Architecture per the [[security-team-audit-export]] memo:
//
//   - ZERO HOT-PATH WORK on no-match. The matchers are simple verb /
//     dialect set lookups + a couple of substring checks; well under a
//     microsecond per decision. We deliberately do NOT run regex passes
//     on every audit row — the dialect-aware path uses the parser's
//     pre-computed unmapped.iam_jit.ext fields (statement_type, dialect,
//     tables_touched, is_dml, mutating_node_type) so we never re-parse.
//
//   - REACTS, DOES NOT GATE. ObserveDecision is fire-and-forget: it
//     observes an already-recorded decision + may emit an alert; it
//     CANNOT change the proxy's verdict. Per the spec memo:
//     "rule engine reacts to observed events; doesn't gate." This keeps
//     the safety-critical decide() path independent of the alerting
//     surface — a bug in alerts.go cannot mis-deny a SQL statement.
//
//   - SAME OCSF SCHEMA. Alerts are class 6003 events with activity_id=99
//     + activity_name=<rule_id> + severity_id>=3 + event_type=
//     SECURITY_ALERT. The Slice 1 transports + presets handle them
//     transparently — datadog's `status` overlay sees severity Medium
//     and renders the row at "notice" priority; sentinel signs the same
//     way; splunk-hec wraps the same way. No per-transport branching
//     needed.
//
//   - RACE-CLEAN. The engine holds NO mutable shared state on the hot
//     path — every Observe* call reads only immutable rule configuration
//     + writes nothing the next call needs to see. The
//     observed/triggered counters are atomic. dbounce has extra
//     concurrency-sensitive features (sync-prompt poll, listener port
//     race fix) per [[deliberate-feature-completion]] — alerts.go MUST
//     pass `go test -race -count=10` per the spec.
//
//   - NEUTRAL LANGUAGE. Per [[security-team-positioning-safety-not-
//     surveillance]] the alert detail + suggestion text NAMES the
//     pattern + SUGGESTS the operator distribute a narrower profile; it
//     never accuses the user of a "violation" / "attack" / "abuse." The
//     security team interprets context.
//
// Per [[scorer-is-ground-truth]] this package NEVER re-scores the
// decision — the decision verdict + reason already exist on the event;
// the alert is metadata around the observation.

package audit

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// RuleEngineOptions wires the RuleEngine from CLI flags / Server
// construction. All fields are optional: an empty options struct yields
// an engine that fires the two default rules with the bundled defaults
// (the most-common shape — operators who don't think about alerts get
// reasonable defaults; operators who do think about them tune via
// these knobs).
type RuleEngineOptions struct {
	// Disabled, when true, makes the engine a no-op at every observe
	// call site. Lets the CLI ship the engine wired into the proxy
	// + still give operators a kill-switch (--no-audit-alerts) that
	// short-circuits BEFORE any matcher runs. Per the spec: behavior
	// MUST default to ON in v1.0 (else the safety-floor of the alerts
	// vanishes for operators who didn't know about the flag).
	Disabled bool

	// OrgProfileSourceAllowlist names the URL prefixes that count as
	// "org-curated" for the non_org_profile_install rule. Per the
	// memo + [[enterprise-profile-distribution]] the typical operator
	// configures `--audit-alert-org-source-prefix https://internal.example`
	// and any profile install from a DIFFERENT https:// source fires
	// the alert. Empty means "alert on EVERY install" (the safe
	// default for solo operators who installed no org-curated profile).
	// Matching is case-insensitive prefix-match.
	OrgProfileSourceAllowlist []string

	// SensitiveSchemas names the schema names whose tables, when
	// touched by a DML statement, fire the unusual_high_risk_action
	// alert. Per the memo + [[security-team-positioning-safety-not-
	// surveillance]] the operator tunes this per-deployment (the
	// default is empty — operators who don't configure it only get
	// dialect-verb-pattern alerts; configuring "prod" / "billing" /
	// "audit_log" adds the schema-scoped DML check on top). Matching
	// is case-insensitive prefix-match against the schema component
	// of each ext.tables_touched entry.
	SensitiveSchemas []string

	// CallAllowlist names the stored-procedure / function names that
	// the unusual_high_risk_action rule should NOT fire on. Per the
	// SQL-specific spec: "Stored procs (CALL) not in allowlist" are
	// flagged; allowlisted ones pass silently. Empty = every CALL/
	// EXECUTE fires the alert (the safe default for solo operators).
	// Matching is case-insensitive exact-match against the function
	// name extracted from ext.functions.
	CallAllowlist []string

	// Host stamps src_endpoint.hostname on every emitted alert event
	// so the SIEM consumer can correlate alerts with the listener
	// they were observed on. Same value the Exporter holds — the CLI
	// passes the proxy's listener "host:port".
	Host string

	// emit is the alert-event sink. Production callers leave it nil
	// and SetExporter wires it to the live Exporter. Tests pass a
	// captured-slice stub to assert per-rule emit contents without
	// spinning up the full transport plumbing.
	//
	// emit is mutex-protected (setEmitMu) so SetExporter is race-clean
	// with concurrent ObserveDecision / ObserveProfileInstall calls.
	emit func(ctx context.Context, evt Event) error
}

// RuleEngine is the per-server alert engine. Construct via
// NewRuleEngine; wire to an Exporter via SetExporter; observe events
// via ObserveDecision (per audit row) + ObserveProfileInstall (per
// install command). Race-clean by construction: hot-path callers only
// read immutable rule config + write to atomic counters.
type RuleEngine struct {
	opts RuleEngineOptions

	// pre-computed lowercased prefix sets for case-insensitive prefix
	// match. Built once at construction; never mutated.
	orgPrefixesLower []string
	sensSchemasLower []string
	callAllowLower   map[string]struct{}

	// emit + emitMu protect the dynamic exporter pointer. SetExporter
	// can be called concurrently with ObserveDecision in theory (the
	// CLI sets it once at startup, but tests + future hot-reload
	// hooks may set it mid-flight); the mutex keeps the read race-
	// clean. The mutex is taken ONLY when we have a fired rule —
	// no-match decisions never touch it.
	emitMu sync.RWMutex
	emit   func(ctx context.Context, evt Event) error

	// Counters for the dbounce_audit_export_status MCP tool +
	// /healthz. observedDecisions = every ObserveDecision call;
	// firedByRule = per-rule fire count.
	observedDecisions atomic.Int64
	observedInstalls  atomic.Int64
	firedNonOrgProf   atomic.Int64
	firedHighRisk     atomic.Int64
}

// NewRuleEngine constructs a RuleEngine with the supplied options.
// Always safe to call; nil-returns + no-op behavior on misconfiguration
// are NEVER used here — the engine MUST exist (even if disabled) so
// proxy.evaluateAndAudit can call ObserveDecision unconditionally.
func NewRuleEngine(opts RuleEngineOptions) *RuleEngine {
	e := &RuleEngine{opts: opts}
	e.orgPrefixesLower = make([]string, 0, len(opts.OrgProfileSourceAllowlist))
	for _, p := range opts.OrgProfileSourceAllowlist {
		if s := strings.ToLower(strings.TrimSpace(p)); s != "" {
			e.orgPrefixesLower = append(e.orgPrefixesLower, s)
		}
	}
	e.sensSchemasLower = make([]string, 0, len(opts.SensitiveSchemas))
	for _, s := range opts.SensitiveSchemas {
		if v := strings.ToLower(strings.TrimSpace(s)); v != "" {
			e.sensSchemasLower = append(e.sensSchemasLower, v)
		}
	}
	e.callAllowLower = make(map[string]struct{}, len(opts.CallAllowlist))
	for _, n := range opts.CallAllowlist {
		if v := strings.ToLower(strings.TrimSpace(n)); v != "" {
			e.callAllowLower[v] = struct{}{}
		}
	}
	e.emit = opts.emit
	return e
}

// SetExporter wires the engine's alert emit channel to an *Exporter.
// Safe to call concurrently with Observe* (the emit field is mutex-
// protected). Pass nil to detach (e.g. during Shutdown so a late
// observation doesn't try to enqueue after the transports are closed).
//
// Per the spec: alerts MUST flow through the same Exporter as
// decisions so a SIEM that consumes one endpoint sees both streams in
// chronological order.
func (e *RuleEngine) SetExporter(exp *Exporter) {
	if e == nil {
		return
	}
	e.emitMu.Lock()
	defer e.emitMu.Unlock()
	if exp == nil {
		e.emit = nil
		return
	}
	e.emit = func(ctx context.Context, evt Event) error {
		return exp.Emit(ctx, evt)
	}
}

// Enabled reports whether the engine will do non-trivial work for
// future Observe calls. False = disabled-by-flag OR no emit sink wired
// yet. The proxy's hot-path can read this to skip projection work
// when the alert pipeline is dormant, mirroring the Exporter.Enabled
// short-circuit.
func (e *RuleEngine) Enabled() bool {
	if e == nil || e.opts.Disabled {
		return false
	}
	e.emitMu.RLock()
	defer e.emitMu.RUnlock()
	return e.emit != nil
}

// ObserveDecision is the proxy-hot-path hook. Called AFTER
// Exporter.EmitDecision so the decision is already in flight + the
// engine reacts to the OBSERVED projection (not the underlying row).
//
// Per the spec: this MUST NOT block the proxy hot-path. The emit
// callback is the same non-blocking enqueue as Exporter.EmitDecision
// (bounded queue + drop-on-overflow). Errors are intentionally
// ignored — a failed alert MUST NOT take down the proxy + a slow
// downstream is already counted via the transport's drop counter.
//
// Per [[scorer-is-ground-truth]]: pattern-matches against the OCSF
// event's already-recorded fields; NEVER re-scores. The decision
// verdict is the row's ground truth.
func (e *RuleEngine) ObserveDecision(ctx context.Context, evt Event) {
	if !e.Enabled() {
		return
	}
	e.observedDecisions.Add(1)
	if hit, detail, ext := e.matchHighRiskAction(evt); hit {
		e.firedHighRisk.Add(1)
		alert := NewSecurityAlertEvent(
			AlertRuleUnusualHighRiskAction,
			AlertSeverityMedium,
			e.opts.Host,
			detail,
			ext,
		)
		e.emitLocked(ctx, alert)
	}
}

// ObserveProfileInstall is the CLI-side hook called from
// `dbounce profile install --from URL` AFTER a successful install. The
// install command builds an InstallObservation describing what was
// installed (source URL, profile names, sha256, verified flag) and
// hands it to this method; the engine pattern-matches against the
// OrgProfileSourceAllowlist + emits a non_org_profile_install alert
// when the source isn't on the allowlist.
//
// Per the spec: sibling agents in ibounce + kbounce ship the SAME
// observation shape so a downstream SIEM rule keyed on rule_id +
// product can fan-out per-product without per-product semantics.
//
// The CLI MUST wire this even when the engine is Disabled — the
// engine's Disabled gate short-circuits internally. Defense-in-depth:
// the install observer + the disabled gate are independent so a
// future feature can flip one without untangling the other.
func (e *RuleEngine) ObserveProfileInstall(ctx context.Context, obs InstallObservation) {
	if !e.Enabled() {
		return
	}
	e.observedInstalls.Add(1)
	if e.isOrgSource(obs.SourceURL) {
		return
	}
	e.firedNonOrgProf.Add(1)
	ext := map[string]any{
		"source_url":     obs.SourceURL,
		"profile_names":  append([]string(nil), obs.ProfileNames...),
		"sha256":         obs.SHA256,
		"sha256_verified": obs.SHA256Verified,
	}
	if len(e.orgPrefixesLower) > 0 {
		ext["org_source_allowlist"] = append([]string(nil), e.orgPrefixesLower...)
	}
	detail := buildNonOrgInstallDetail(obs, len(e.orgPrefixesLower) > 0)
	alert := NewSecurityAlertEvent(
		AlertRuleNonOrgProfileInstall,
		AlertSeverityMedium,
		e.opts.Host,
		detail,
		ext,
	)
	e.emitLocked(ctx, alert)
}

// InstallObservation is the value the CLI install command hands to
// ObserveProfileInstall. Mirrors the profile.InstallResult fields the
// engine needs without requiring this package to import the profile
// package (which would create an import cycle via the CLI).
type InstallObservation struct {
	// SourceURL is the exact URL the install fetched from. Stamped
	// into the alert's ext.source_url so a security reviewer can
	// answer "where did this profile come from?" without a JOIN.
	SourceURL string
	// ProfileNames are the names of the profiles installed in this
	// invocation (one install can carry multiple profiles). The
	// alert ext.profile_names mirrors.
	ProfileNames []string
	// SHA256 is the hex-encoded SHA-256 of the fetched bytes. Always
	// computed by the install path; mirrored to the alert so a
	// downstream reviewer can pin-compare without re-fetching.
	SHA256 string
	// SHA256Verified is true when the install was launched with
	// --sha256 + the hash matched. Mirrored to the alert so a
	// reviewer can answer "did the operator pin this?" — a non-org
	// install WITH a pin is a different posture than one without.
	SHA256Verified bool
}

// emitLocked sends evt through the wired emit callback under the read
// lock. The lock is taken ONLY when we have a fired rule (every
// no-match observe call avoids it — Enabled() already took the lock
// once to check). Errors are dropped per the spec; the transport's
// drop counter is the visibility channel.
func (e *RuleEngine) emitLocked(ctx context.Context, evt Event) {
	e.emitMu.RLock()
	emit := e.emit
	e.emitMu.RUnlock()
	if emit == nil {
		return
	}
	_ = emit(ctx, evt)
}

// isOrgSource reports whether the install source URL matches any
// configured org-prefix. Case-insensitive prefix match. Empty prefix
// set means EVERY install is non-org → the alert fires on every
// install (solo-operator default; safe).
func (e *RuleEngine) isOrgSource(sourceURL string) bool {
	if len(e.orgPrefixesLower) == 0 {
		return false
	}
	src := strings.ToLower(strings.TrimSpace(sourceURL))
	if src == "" {
		return false
	}
	for _, p := range e.orgPrefixesLower {
		if strings.HasPrefix(src, p) {
			return true
		}
	}
	return false
}

// highRiskByDialect is the per-dialect verb set the
// unusual_high_risk_action rule fires on. Per the spec memo:
//
//	postgres / mysql      DROP TABLE, TRUNCATE TABLE, ALTER TABLE,
//	                      DELETE FROM <sensitive schema>, GRANT,
//	                      un-allowlisted CALL/EXECUTE
//
//	snowflake / bigquery  + EXPORT_DATA, + COPY INTO @stage / COPY_INTO,
//	                      + UNDROP
//
// Each entry is the UPPER-CASED statement_type the parser already
// emits. We branch by dialect because UNDROP / EXPORT_DATA exist only
// in Snowflake/BigQuery + would surface as parse errors on PG/MySQL.
//
// Per [[scorer-is-ground-truth]]: this table is a HEURISTIC for
// alerting only — it never gates decide(). The decide() composition
// already determined whether the statement is ALLOW / DENY using the
// profile + task + global rules; the rule engine adds a visibility
// signal on top.
var highRiskByDialect = map[string]map[string]struct{}{
	"postgres": {
		"DROP":     {},
		"TRUNCATE": {},
		"ALTER":    {},
		"GRANT":    {},
		"REVOKE":   {},
		"CALL":     {},
		"EXECUTE":  {},
	},
	"mysql": {
		"DROP":     {},
		"TRUNCATE": {},
		"ALTER":    {},
		"GRANT":    {},
		"REVOKE":   {},
		"CALL":     {},
		"EXECUTE":  {},
	},
	"snowflake": {
		"DROP":        {},
		"TRUNCATE":    {},
		"ALTER":       {},
		"GRANT":       {},
		"REVOKE":      {},
		"UNDROP":      {},
		"EXPORT_DATA": {},
		"COPY_INTO":   {},
		"CALL":        {},
		"EXECUTE":     {},
	},
	"bigquery": {
		"DROP":        {},
		"TRUNCATE":    {},
		"ALTER":       {},
		"GRANT":       {},
		"REVOKE":      {},
		"EXPORT_DATA": {},
		"COPY_INTO":   {},
		"CALL":        {},
		"EXECUTE":     {},
	},
}

// HighRiskVerbsForDialect returns the sorted upper-cased verb set the
// rule engine fires on for the given dialect. Exported for the report-
// back doc + the alerts_test.go cross-dialect table test. Returns nil
// for unknown dialects.
func HighRiskVerbsForDialect(dialect string) []string {
	d := strings.ToLower(strings.TrimSpace(dialect))
	set, ok := highRiskByDialect[d]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// matchHighRiskAction is the per-decision matcher for the
// unusual_high_risk_action rule. Reads ONLY the OCSF event's already-
// computed ext fields (dialect, tables_touched, is_dml,
// mutating_node_type, functions, statement_type) — never re-parses
// SQL, never touches the underlying DecisionRow.
//
// Returns (true, detail, ext) when the event matches. Detail is the
// neutral suggestion text; ext is the rule-specific payload that
// joins the OCSF envelope's unmapped.iam_jit.ext on emit.
//
// Per the spec: SQL-specific suggestion text is
// "consider distributing a profile that allows the specific tables
// your task needs" — NOT "the user committed a violation."
func (e *RuleEngine) matchHighRiskAction(evt Event) (bool, string, map[string]any) {
	// Synthetics (AUDIT_DROPPED / SECURITY_ALERT) never trigger rules
	// — they aren't decisions. Short-circuit before any field read
	// so the engine can't recurse on its own alerts.
	if evt.Unmapped != nil {
		etype := evt.Unmapped.IAMJIT.EventType
		if etype == string(EventTypeAuditDropped) ||
			etype == string(EventTypeSecurityAlert) {
			return false, "", nil
		}
	}

	dialect, stmtType, tablesAny, functionsAny := extractMatchFields(evt)
	if dialect == "" || stmtType == "" {
		return false, "", nil
	}

	dialectLower := strings.ToLower(dialect)
	verbSet, ok := highRiskByDialect[dialectLower]
	if !ok {
		return false, "", nil
	}

	tables := normalizeStringSlice(tablesAny)
	functions := normalizeStringSlice(functionsAny)
	stmtUpper := strings.ToUpper(stmtType)

	// 1) Per-dialect verb match. CALL/EXECUTE are suppressed when
	// every named function is on the operator's allowlist (per the
	// spec: "Stored procs (CALL) not in allowlist" are flagged).
	// A suppressed-on-verb CALL still falls through to the
	// sensitive-schema DML check in case it touched a sensitive table.
	if _, hit := verbSet[stmtUpper]; hit {
		isCallVerb := stmtUpper == "CALL" || stmtUpper == "EXECUTE"
		if !isCallVerb || !e.allCallsAllowlisted(functions) {
			detail := buildHighRiskDetail(dialectLower, stmtUpper, tables, "verb")
			ext := buildHighRiskExt(dialectLower, stmtUpper, tables, functions, "verb")
			return true, detail, ext
		}
	}

	// 2) Sensitive-schema DML: when the operator configured a
	// SensitiveSchemas list, fire on any DML statement that touched a
	// table whose schema component matches.
	if len(e.sensSchemasLower) == 0 || !isDMLStatement(evt, stmtUpper) {
		return false, "", nil
	}
	matched := matchSensitiveSchemas(tables, e.sensSchemasLower)
	if len(matched) == 0 {
		return false, "", nil
	}
	detail := buildHighRiskDetail(dialectLower, stmtUpper, matched, "sensitive_schema")
	ext := buildHighRiskExt(dialectLower, stmtUpper, matched, functions, "sensitive_schema")
	ext["sensitive_schemas"] = append([]string(nil), e.sensSchemasLower...)
	return true, detail, ext
}

// allCallsAllowlisted reports whether every function name in the
// CALL/EXECUTE row is on the allowlist. Empty allowlist + non-empty
// functions returns false (the safe-default — "no allowlist set" means
// "fire on every un-classified CALL"). Empty functions returns false
// too (we can't verify a CALL with no function names against the
// allowlist).
func (e *RuleEngine) allCallsAllowlisted(functions []string) bool {
	if len(e.callAllowLower) == 0 {
		return false
	}
	if len(functions) == 0 {
		return false
	}
	for _, f := range functions {
		k := strings.ToLower(strings.TrimSpace(f))
		if _, ok := e.callAllowLower[k]; !ok {
			return false
		}
	}
	return true
}

// isDMLStatement reports whether the OCSF event represents a DML
// statement that touched data (INSERT/UPDATE/DELETE/MERGE + the ext
// is_dml flag). The flag is the canonical source; the verb fallback
// covers events where the parser didn't tag is_dml (e.g. older
// schema rows replayed through the rule engine).
func isDMLStatement(evt Event, stmtUpper string) bool {
	if evt.Unmapped != nil && evt.Unmapped.IAMJIT.Ext != nil {
		if v, ok := evt.Unmapped.IAMJIT.Ext["is_dml"].(bool); ok && v {
			return true
		}
	}
	switch stmtUpper {
	case "INSERT", "UPDATE", "DELETE", "MERGE":
		return true
	}
	return false
}

// matchSensitiveSchemas returns the tables whose schema-component
// matches any configured sensitive schema. Case-insensitive prefix
// match against the schema prefix of each "schema.table" or
// "db.schema.table" string. Tables with no dot are treated as having
// no schema (no match) — the spec is "schema.table" shape; a bare
// table name doesn't carry the schema signal.
func matchSensitiveSchemas(tables, sensitive []string) []string {
	if len(tables) == 0 || len(sensitive) == 0 {
		return nil
	}
	out := make([]string, 0, len(tables))
	for _, t := range tables {
		schema := schemaPart(t)
		if schema == "" {
			continue
		}
		sl := strings.ToLower(schema)
		for _, s := range sensitive {
			if strings.HasPrefix(sl, s) {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// schemaPart extracts the schema component of a qualified table name.
// "schema.table" → "schema"; "db.schema.table" → "schema";
// "table" → "". Quoted identifiers are stripped (Postgres + Snowflake
// allow double-quoted names — we strip a leading + trailing quote so
// "public"."users" matches the "public" prefix).
func schemaPart(qualified string) string {
	q := strings.TrimSpace(qualified)
	if q == "" {
		return ""
	}
	parts := strings.Split(q, ".")
	switch len(parts) {
	case 1:
		return ""
	case 2:
		return stripQuotes(parts[0])
	default:
		// db.schema.table — middle component is the schema.
		return stripQuotes(parts[len(parts)-2])
	}
}

func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '`' && s[len(s)-1] == '`' {
		return s[1 : len(s)-1]
	}
	return s
}

// extractMatchFields pulls the matcher-relevant fields off the OCSF
// event. Reads from unmapped.iam_jit.ext (the canonical source per
// [[ocsf-audit-schema]]); falls back to the top-level OCSF fields
// (api.service.name → dialect, activity_name → stmt_type) when ext is
// missing — relevant for events that transited JSON round-trip in
// tests where the ext map's typed slices became []any.
func extractMatchFields(evt Event) (dialect, stmtType string, tables, functions any) {
	if evt.Unmapped != nil && evt.Unmapped.IAMJIT.Ext != nil {
		ext := evt.Unmapped.IAMJIT.Ext
		if d, ok := ext["dialect"].(string); ok {
			dialect = d
		}
		tables = ext["tables_touched"]
		functions = ext["functions"]
	}
	if dialect == "" {
		dialect = evt.API.Service.Name
	}
	stmtType = evt.API.Operation
	if stmtType == "" {
		stmtType = strings.ToUpper(evt.ActivityName)
	}
	return dialect, stmtType, tables, functions
}

// normalizeStringSlice unwraps either []string or []any (post-JSON-
// round-trip) into a []string. Returns nil on unknown shape so the
// caller can short-circuit cleanly.
func normalizeStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return append([]string(nil), t...)
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// buildHighRiskDetail builds the neutral SECURITY_ALERT detail string.
// Per the SQL-specific spec language:
//
//	"<dialect>: high-risk <verb> on <table[, more]>; consider
//	distributing a profile that allows the specific tables your
//	task needs"
//
// The "consider distributing a profile" phrasing matches kbounce +
// ibounce sibling-agent conventions so a cross-product SIEM dashboard
// reads consistently. Callers pre-normalize dialect (lower) + verb
// (upper) — the matcher already did this work via the map-key + the
// stmtUpper conversion.
func buildHighRiskDetail(dialect, verb string, tables []string, reason string) string {
	var tablePart string
	switch len(tables) {
	case 0:
		tablePart = ""
	case 1:
		tablePart = " on " + tables[0]
	default:
		tablePart = " on " + tables[0] + " +" + strconv.Itoa(len(tables)-1) + " more"
	}
	prefix := "high-risk " + verb + " observed"
	if reason == "sensitive_schema" {
		prefix = "DML against sensitive-schema table observed (" + verb + ")"
	}
	return dialect + ": " + prefix + tablePart +
		"; consider distributing a profile that allows the specific tables your task needs"
}

// buildHighRiskExt builds the unusual_high_risk_action ext payload.
// Sibling agents in ibounce + kbounce ship the SAME field names so a
// SIEM filter keyed on rule_id + reason works cross-product. Callers
// pre-normalize dialect + verb (see buildHighRiskDetail's contract).
func buildHighRiskExt(dialect, verb string, tables, functions []string, reason string) map[string]any {
	ext := map[string]any{
		"dialect":        dialect,
		"statement_type": verb,
		"matched_reason": reason,
		"matched_tables": append([]string(nil), tables...),
	}
	if len(functions) > 0 {
		ext["functions"] = append([]string(nil), functions...)
	}
	return ext
}

// buildNonOrgInstallDetail builds the neutral SECURITY_ALERT detail
// string for the non_org_profile_install rule. Per [[security-team-
// positioning-safety-not-surveillance]]: the language NAMES the
// observation + SUGGESTS the operator distribute via org channels;
// never accuses the operator.
func buildNonOrgInstallDetail(obs InstallObservation, hasAllowlist bool) string {
	suffix := "; consider distributing org-curated profiles via " +
		"--audit-alert-org-source-prefix"
	if !hasAllowlist {
		suffix = "; configure --audit-alert-org-source-prefix to mark " +
			"your IT distribution endpoint as the org source"
	}
	prefix := "profile install from non-org source observed"
	src := strings.TrimSpace(obs.SourceURL)
	if src != "" {
		prefix += " (" + src + ")"
	}
	if len(obs.ProfileNames) > 0 {
		prefix += " — profiles: " + strings.Join(obs.ProfileNames, ", ")
	}
	return prefix + suffix
}

// RuleEngineStats is the snapshot the
// dbounce_audit_export_status MCP tool reads for the alert engine.
// Race-free: all underlying counters are atomic.
type RuleEngineStats struct {
	Configured         bool   `json:"configured"`
	Disabled           bool   `json:"disabled"`
	ObservedDecisions  int64  `json:"observed_decisions"`
	ObservedInstalls   int64  `json:"observed_installs"`
	FiredNonOrgInstall int64  `json:"fired_non_org_profile_install"`
	FiredHighRisk      int64  `json:"fired_unusual_high_risk_action"`
	OrgPrefixCount     int    `json:"org_prefix_count"`
	SensitiveSchemas   int    `json:"sensitive_schema_count"`
	CallAllowlistSize  int    `json:"call_allowlist_size"`
	Host               string `json:"host,omitempty"`
}

// Stats returns the current counters. Safe to call concurrently.
func (e *RuleEngine) Stats() RuleEngineStats {
	if e == nil {
		return RuleEngineStats{Configured: false}
	}
	return RuleEngineStats{
		Configured:         true,
		Disabled:           e.opts.Disabled,
		ObservedDecisions:  e.observedDecisions.Load(),
		ObservedInstalls:   e.observedInstalls.Load(),
		FiredNonOrgInstall: e.firedNonOrgProf.Load(),
		FiredHighRisk:      e.firedHighRisk.Load(),
		OrgPrefixCount:     len(e.orgPrefixesLower),
		SensitiveSchemas:   len(e.sensSchemasLower),
		CallAllowlistSize:  len(e.callAllowLower),
		Host:               e.opts.Host,
	}
}


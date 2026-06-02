// anomaly_wire.go is the THIN, protocol-specific glue between
// dbounce's SQL-proxy decision path and the byte-identical
// internal/anomaly core (#718 ADOPT-4 / Phase H).
//
// Per [[config-export-wire-divergence]] the cross-repo core (config /
// baseline / detector / hook) is identical across gbounce / kbouncer /
// dbounce; ONLY this file (signal extraction + audit-emitter
// adaptation + healthz surface) differs per product. For dbounce the
// protocol signals are:
//
//   - action        = a privacy-safe composite of the SQL statement
//     type + mutating-node type + leading verb keyword
//     (SELECT / "DDL DROP" / TRUNCATE / ...) — verb SHAPES
//     only, never literals/values or the raw statement.
//   - resource      = the first table touched (or the dialect when no
//     table parsed) — canonicalised by the core into a
//     privacy-safe sql:<env> bucket.
//   - agentIdentity = the resolved agent name from the session
//     registry (or "anonymous").
//
// PRIVACY: we deliberately pass only the statement TYPE + table NAME
// to the core — never the statement text or any literal values — so
// the SQL-redaction concern ([[dbounce-sql-redaction-gaps]]) does not
// reach the baseline DB. The core canonicaliser is lossy on top.
//
// DEFAULT = ALERT, NOT BLOCK per [[safety-mode-lean-permissive]].
package proxy

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/trsreagan3/dbounce/internal/anomaly"
	"github.com/trsreagan3/dbounce/internal/store"
)

// SetAnomalyDetector wires the Phase H behavioral-deviation detector.
// nil disables the channel. The CLI calls this at startup when
// anomaly_detection is enabled.
func (s *Server) SetAnomalyDetector(d *anomaly.Detector) {
	s.anomalyDetector = d
}

// sqlAnomalyAgent resolves the agent name for a session id via the
// per-process registry (best-effort; "anonymous" on a miss). Kept here
// so the tap call stays a one-liner in the hot path.
func sqlAnomalyAgent(s *Server, sessionID string) string {
	if sessionID == "" || s.agentRegistry == nil {
		return "anonymous"
	}
	if a, ok := s.agentRegistry.Lookup(sessionID); ok && a.Name != "" {
		return a.Name
	}
	return "anonymous"
}

// sqlAnomalySignals extracts (action, resource) for the anomaly core
// from a decision row. resource = first table touched (or dialect when
// none parsed).
//
// action is a privacy-safe COMPOSITE of structural verb shapes so the
// cold-start adversarial backstop ("drop ", "truncate", "delete from",
// "grant all", ...) can actually fire (#718 finding MEDIUM). dbounce's
// parser buckets CREATE / ALTER / DROP under StatementType="DDL" (a
// bucket the backstop catalog cannot match on), with the concrete verb
// living in MutatingNodeType ("DROP" / "TRUNCATE" / "GRANT" / ...) on
// the MySQL/Snowflake/BigQuery paths — but EMPTY for a PostgreSQL bare
// DROP (its walker only flags DML nodes). So we fold in BOTH the
// MutatingNodeType AND the leading SQL keyword token (verb only — never
// literals/values/identifiers, preserving the
// [[dbounce-sql-redaction-gaps]] privacy invariant) so DROP / TRUNCATE /
// DELETE / DROP DATABASE reach the backstop on every dialect.
func sqlAnomalySignals(row store.DecisionRow) (string, string) {
	parts := make([]string, 0, 3)
	if st := strings.TrimSpace(row.StatementType); st != "" {
		parts = append(parts, st)
	}
	if mn := strings.TrimSpace(row.MutatingNodeType); mn != "" {
		parts = append(parts, mn)
	}
	if verb := leadingSQLVerb(row.Statement); verb != "" {
		parts = append(parts, verb)
	}
	action := strings.Join(parts, " ")
	if action == "" {
		action = "STATEMENT"
	}

	resource := ""
	if len(row.TablesTouched) > 0 {
		resource = row.TablesTouched[0]
	} else if row.Dialect != "" {
		resource = row.Dialect
	}
	return action, resource
}

// leadingSQLVerb returns the leading SQL keyword token of a statement,
// uppercased — and ONLY when it is one of a small allowlist of
// structural operation verbs. Returning a keyword from the allowlist
// (never an arbitrary token, literal, identifier, or value) keeps the
// signal privacy-safe: it is the operation SHAPE, not the data. Empty
// when the statement is blank or the leading token is not an allowlisted
// verb.
func leadingSQLVerb(statement string) string {
	s := strings.TrimSpace(statement)
	if s == "" {
		return ""
	}
	// First whitespace/paren-delimited token.
	idx := strings.IndexFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '(' || r == ';'
	})
	tok := s
	if idx >= 0 {
		tok = s[:idx]
	}
	tok = strings.ToUpper(tok)
	switch tok {
	case "DROP", "TRUNCATE", "DELETE", "GRANT", "REVOKE", "CREATE", "ALTER", "RENAME":
		return tok
	}
	return ""
}

// anomalyDenySource is the canonical DecisionSource stamped on a
// decision when mode=block tightens an anomalous statement (iam-jit#59).
const anomalyDenySource = "anomaly_block"

// anomalyDetectorWired reports whether an enabled detector is installed.
func (s *Server) anomalyDetectorWired() bool {
	return s.anomalyDetector != nil && s.anomalyDetector.Enabled()
}

// decideAnomalyTighten is the PRE-DECISION enforcement check (iam-jit#59)
// for dbounce. Consulted in the live forwarder ONLY on a non-deny floor
// verdict, BEFORE the statement is forwarded to the upstream DB. In
// mode=block an anomalous statement-shape / table / volume deviation
// TIGHTENS allow->deny: it returns true (the high-severity OCSF event
// having already been emitted by the core Decide via the bound emitter),
// and the caller routes the statement through the enforced-deny path.
//
// The signals are extracted IDENTICALLY to observeAnomaly's
// sqlAnomalySignals (statement-type + mutating-node + leading verb shape;
// first table touched) so the pre-decision score + the post-decision
// observe share the same per-agent baseline key. Privacy preserved: only
// structural verb shapes + table name, never statement text/literals.
//
// TIGHTEN-ONLY: the core Detector.Decide refuses to loosen a deny floor
// and only mode=block (not detection-only) tightens. FAIL-SOFT: a
// nil/disabled detector returns false; the core never panics; a scoring
// hiccup degrades to the floor (allow) so this can never spuriously deny
// or break the connection.
func (s *Server) decideAnomalyTighten(row store.DecisionRow, agentIdentity string) bool {
	if !s.anomalyDetectorWired() {
		return false
	}
	action, resource := sqlAnomalySignals(row)
	out := s.anomalyDetector.Decide(anomaly.DecideInput{
		Action:        action,
		AgentIdentity: agentIdentity,
		Resource:      resource,
		FloorDecision: "allow", // only consulted on the non-deny branch
	})
	return out.Tightened && out.Decision == "deny"
}

// observeAnomaly observes one decision into the behavioral baseline +
// scores it. Fail-soft + no-op when the detector is unwired/disabled.
func (s *Server) observeAnomaly(agentIdentity string, row store.DecisionRow) {
	if s.anomalyDetector == nil || !s.anomalyDetector.Enabled() {
		return
	}
	action, resource := sqlAnomalySignals(row)
	floor := "allow"
	if row.DecisionVerdict == "DENY" || row.DecisionVerdict == "deny" {
		floor = "deny"
	}
	// FEED THE REAL DEVIATION SIGNALS (#718 finding HIGH): derive the
	// current hour-of-day from the clock and the recent-window observed
	// action rate for this (agent, action, resource_pattern) from the
	// baseline store, so the hour_of_day + action_frequency dimensions
	// actually contribute. Computed BEFORE Run records this event so the
	// rate reflects the burst arriving so far; Run adds the current one.
	// Privacy preserved: we pass only structural shapes + counts.
	observedHour := time.Now().UTC().Hour()
	observedRate := s.anomalyDetector.Store().RecentRate(agentIdentity, action, resource, 0)
	s.anomalyDetector.Run(anomaly.RunInput{
		Action:              action,
		AgentIdentity:       agentIdentity,
		Resource:            resource,
		ObservedHour:        observedHour,
		ObservedActionCount: observedRate,
		FloorDecision:       floor,
		RecordObservation:   true,
	})
}

// NewAnomalyDetector constructs a Detector wired to surface neutral
// OCSF anomaly events into the in-memory recent ring (exposed on
// /healthz + the query surface). Returns a disabled no-op detector
// when cfg.Enabled is false.
func (s *Server) NewAnomalyDetector(cfg anomaly.Config) *anomaly.Detector {
	anomaly.SetProduct("dbounce")
	if !cfg.Enabled {
		return anomaly.NewDetector(cfg, nil, false)
	}
	return anomaly.NewDetector(cfg, s.anomalyEventSink, false)
}

// anomalyEventSink lands an emitted neutral OCSF anomaly event into the
// bounded recent ring.
func (s *Server) anomalyEventSink(event map[string]any) {
	s.anomalyMu.Lock()
	s.anomalyRecent = append(s.anomalyRecent, event)
	if len(s.anomalyRecent) > anomalyRecentCap {
		s.anomalyRecent = s.anomalyRecent[len(s.anomalyRecent)-anomalyRecentCap:]
	}
	s.anomalyMu.Unlock()
}

const anomalyRecentCap = 50

// anomalyHealthz returns the /healthz + query-surface block. Always a
// map (enabled:false when unwired) so the composite monitor key set
// stays stable per [[cross-product-agent-parity]].
func (s *Server) anomalyHealthz() map[string]any {
	if s.anomalyDetector == nil {
		return map[string]any{"enabled": false}
	}
	st := s.anomalyDetector.Status()
	s.anomalyMu.Lock()
	st["recent_count"] = len(s.anomalyRecent)
	s.anomalyMu.Unlock()
	return st
}

// AnomalyConfigFromEnv builds the Phase H detector config from
// environment variables (frictionless opt-in per
// [[lightweight-frictionless-principle]]). Same env names across the
// suite per [[cross-product-agent-parity]]:
//
//	IAM_JIT_ANOMALY_DETECTION    = "1" / "true" to enable (default off)
//	IAM_JIT_ANOMALY_MODE         = "alert" (default) | "block"
//	IAM_JIT_ANOMALY_SENSITIVITY  = "low" | "medium" (default) | "high"
//	IAM_JIT_ANOMALY_MIN_ACTIONS  = integer baseline floor (default 50)
func AnomalyConfigFromEnv() (anomaly.Config, error) {
	enable := os.Getenv("IAM_JIT_ANOMALY_DETECTION")
	if enable != "1" && enable != "true" && enable != "TRUE" {
		return anomaly.DefaultConfig(), nil
	}
	block := map[string]any{"enabled": true}
	if v := os.Getenv("IAM_JIT_ANOMALY_MODE"); v != "" {
		block["mode"] = v
	}
	if v := os.Getenv("IAM_JIT_ANOMALY_SENSITIVITY"); v != "" {
		block["sensitivity"] = v
	}
	if v := os.Getenv("IAM_JIT_ANOMALY_MIN_ACTIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			block["min_actions_for_baseline"] = n
		}
	}
	return anomaly.LoadConfig(block)
}

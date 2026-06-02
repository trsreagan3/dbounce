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
//   - action        = the SQL statement type (SELECT / INSERT /
//                     DELETE / DROP / ...) — the privacy-safe verb shape,
//                     never the raw statement text.
//   - resource      = the first table touched (or the dialect when no
//                     table parsed) — canonicalised by the core into a
//                     privacy-safe sql:<env> bucket.
//   - agentIdentity = the resolved agent name from the session
//                     registry (or "anonymous").
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
// from a decision row. action = statement type; resource = first table
// touched (or dialect when none parsed).
func sqlAnomalySignals(row store.DecisionRow) (string, string) {
	action := row.StatementType
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
	s.anomalyDetector.Run(anomaly.RunInput{
		Action:              action,
		AgentIdentity:       agentIdentity,
		Resource:            resource,
		ObservedHour:        -1,
		ObservedActionCount: -1,
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

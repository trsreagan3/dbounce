// anomaly_wire_test.go covers the dbounce-specific Phase H wiring
// (#718 ADOPT-4): env config, SQL signal extraction, the
// observe-and-alert tap, and the /healthz + query status surface.
package proxy

import (
	"testing"

	"github.com/trsreagan3/dbounce/internal/anomaly"
	"github.com/trsreagan3/dbounce/internal/store"
)

func TestAnomalyConfigFromEnvDisabledByDefault(t *testing.T) {
	t.Setenv("IAM_JIT_ANOMALY_DETECTION", "")
	c, err := AnomalyConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Enabled {
		t.Fatalf("anomaly detection must be DISABLED by default")
	}
}

func TestAnomalyConfigFromEnvEnable(t *testing.T) {
	t.Setenv("IAM_JIT_ANOMALY_DETECTION", "1")
	t.Setenv("IAM_JIT_ANOMALY_MODE", "block")
	t.Setenv("IAM_JIT_ANOMALY_SENSITIVITY", "high")
	t.Setenv("IAM_JIT_ANOMALY_MIN_ACTIONS", "7")
	c, err := AnomalyConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.Enabled || c.Mode != "block" || c.Sensitivity != "high" || c.MinActionsForBaseline != 7 {
		t.Fatalf("env not honored: %+v", c)
	}
}

func TestSQLAnomalySignals(t *testing.T) {
	action, res := sqlAnomalySignals(store.DecisionRow{
		StatementType: "DELETE",
		TablesTouched: []string{"prod_orders", "audit_log"},
	})
	if action != "DELETE" {
		t.Fatalf("expected statement type action, got %q", action)
	}
	if res != "prod_orders" {
		t.Fatalf("expected first table touched, got %q", res)
	}
	// No table parsed → fall back to dialect.
	action, res = sqlAnomalySignals(store.DecisionRow{StatementType: "", Dialect: "postgres"})
	if action != "STATEMENT" || res != "postgres" {
		t.Fatalf("fallback wrong: %q / %q", action, res)
	}
}

func TestAnomalyHealthzUnwired(t *testing.T) {
	s := &Server{}
	h := s.anomalyHealthz()
	if h["enabled"].(bool) != false {
		t.Fatalf("unwired detector must report enabled:false")
	}
}

// TestObserveAnomalyEmitsThroughWire is the GENUINE wire test (#718
// finding LOW): it drives a volume-spike burst entirely THROUGH
// observeAnomaly (never d.Run directly) and asserts a neutral event is
// emitted. This FAILS against the old sentinel wire (ObservedHour=-1,
// ObservedActionCount=-1 meant no deviation dimension ever contributed,
// so behavioral detection was dead) and PASSES once observeAnomaly
// feeds the real hour-of-day + recent-window rate.
func TestObserveAnomalyEmitsThroughWire(t *testing.T) {
	cfg := anomaly.DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "alert"
	cfg.MinActionsForBaseline = 5
	s := &Server{}
	d := s.NewAnomalyDetector(cfg)
	s.SetAnomalyDetector(d)

	// A sharp burst for one (agent, statement, table): the recent-window
	// rate climbs far above the learned per-hour baseline mean, so the
	// action_frequency dimension trips — all THROUGH observeAnomaly.
	row := store.DecisionRow{StatementType: "SELECT", Statement: "SELECT 1", TablesTouched: []string{"prod_orders"}, DecisionVerdict: "ALLOW"}
	for i := 0; i < 200; i++ {
		s.observeAnomaly("agent-d", row)
	}
	if got := d.Status()["alerts_emitted"].(int64); got < 1 {
		t.Fatalf("expected the wire to flag the volume spike (alerts_emitted=%d); "+
			"behavioral detection is dead if this is 0", got)
	}
	if scored := d.Status()["events_scored"].(int64); scored < 1 {
		t.Fatalf("expected the wire to score events through observeAnomaly; got %d", scored)
	}
	h := s.anomalyHealthz()
	if h["enabled"].(bool) != true {
		t.Fatalf("healthz should report enabled detector")
	}
	if h["recent_count"].(int) < 1 {
		t.Fatalf("expected recent ring to hold the emitted event")
	}
}

// TestObserveAnomalyDropReachesBackstopThroughWire asserts the #718
// finding MEDIUM fix: a DROP statement (bucketed StatementType="DDL")
// reaches the cold-start adversarial backstop and is flagged THROUGH
// observeAnomaly even with no baseline. Before the fix the wire passed
// only StatementType="DDL", which the backstop catalog could never
// match, so destructive DROP/TRUNCATE went unseen on cold start.
func TestObserveAnomalyDropReachesBackstopThroughWire(t *testing.T) {
	cfg := anomaly.DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "alert"
	cfg.MinActionsForBaseline = 50 // force cold-start so only the backstop can fire
	s := &Server{}
	d := s.NewAnomalyDetector(cfg)
	s.SetAnomalyDetector(d)

	// DROP TABLE as the parser produces it on the PostgreSQL path:
	// StatementType="DDL" (the blind bucket) + empty MutatingNodeType.
	// The leading-verb derivation must surface "DROP" so the backstop
	// catalog ("drop ") fires.
	row := store.DecisionRow{
		StatementType:   "DDL",
		Statement:       "DROP TABLE prod_orders",
		IsDDL:           true,
		TablesTouched:   nil,
		Dialect:         "postgres",
		DecisionVerdict: "ALLOW",
	}
	s.observeAnomaly("agent-drop", row)

	if got := d.Status()["alerts_emitted"].(int64); got < 1 {
		t.Fatalf("expected DROP to reach the cold-start backstop + flag (alerts_emitted=%d)", got)
	}

	// Sanity: a benign cold-start SELECT must NOT flag (no false alarm).
	benign := store.DecisionRow{StatementType: "SELECT", Statement: "SELECT 1", TablesTouched: []string{"prod_orders"}, DecisionVerdict: "ALLOW"}
	before := d.Status()["alerts_emitted"].(int64)
	s.observeAnomaly("agent-benign", benign)
	if d.Status()["alerts_emitted"].(int64) != before {
		t.Fatalf("a benign cold-start SELECT must not be flagged")
	}
}

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

// TestObserveAnomalyEmitsAfterBaseline asserts the detector surfaces a
// neutral event on a spike but never changes the decision in alert mode.
func TestObserveAnomalyEmitsAfterBaseline(t *testing.T) {
	cfg := anomaly.DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "alert"
	cfg.MinActionsForBaseline = 5
	s := &Server{}
	d := s.NewAnomalyDetector(cfg)
	s.SetAnomalyDetector(d)

	row := store.DecisionRow{StatementType: "SELECT", TablesTouched: []string{"prod_orders"}, DecisionVerdict: "ALLOW"}
	for i := 0; i < 40; i++ {
		s.observeAnomaly("agent-d", row)
	}
	before := d.Status()["alerts_emitted"].(int64)
	out := d.Run(anomaly.RunInput{
		Action:              "SELECT",
		AgentIdentity:       "agent-d",
		Resource:            "prod_orders",
		ObservedHour:        -1,
		ObservedActionCount: 100000,
		FloorDecision:       "allow",
		RecordObservation:   true,
	})
	if out.Decision != "allow" {
		t.Fatalf("alert mode must not block; got %q", out.Decision)
	}
	after := d.Status()["alerts_emitted"].(int64)
	if after <= before {
		t.Fatalf("expected an alert emitted on the spike (before=%d after=%d)", before, after)
	}
	h := s.anomalyHealthz()
	if h["enabled"].(bool) != true {
		t.Fatalf("healthz should report enabled detector")
	}
}

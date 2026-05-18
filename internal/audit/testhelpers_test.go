package audit

import (
	"github.com/trsreagan3/dbounce/internal/store"
)

// testDecisionEvent constructs a minimal valid OCSF class-6003 Event
// via the real FromDecisionRow projection. Used by transport-level
// tests (LogWriter, WebhookPusher) that want a known-shape event
// without re-stating the OCSF envelope at every call-site.
//
// Caller passes a decision id; the rest is a stable fixture (postgres,
// SELECT, ALLOW, cooperative-mode) so individual transport tests
// don't accidentally vary projection-level fields they don't care
// about.
func testDecisionEvent(decisionID int64) Event {
	return FromDecisionRow(store.DecisionRow{
		Dialect:         "postgres",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
	}, decisionID, "", "")
}

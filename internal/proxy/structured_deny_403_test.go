// Tests for the dbounce structured-deny wire-suffix (#459 / §A57b).
// dbounce returns deny verdicts as PG ErrorResponse + MySQL ErrPacket
// — not HTTP 403s — so the parity test exercises the in-band wire
// suffix the bouncer appends to the legacy "dbounce: denied: ..."
// message text. Per [[cross-product-agent-parity]] the embedded JSON
// MUST match the field names ibounce + kbouncer + gbounce ship.
//
// Test names match the cross-bouncer convention (StructuredDeny403_*)
// so the parity expectation is greppable across all four bouncers,
// even though the dbounce wire shape is a string suffix rather than a
// JSON 403 body.
package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/structureddeny"
)

// TestStructuredDeny403_IncludesCaughtByBouncer asserts the
// caught_by_bouncer field rides in the in-band suffix per
// [[ambient-value-prop-and-friction-framing]].
func TestStructuredDeny403_IncludesCaughtByBouncer(t *testing.T) {
	parsed := splitDbounceDenyMessage(t, sampleDbounceDenyRow("DROP", "public.users"), "postgres")
	if got, _ := parsed["caught_by_bouncer"].(string); got != "dbounce" {
		t.Fatalf("caught_by_bouncer = %v; want \"dbounce\"", parsed["caught_by_bouncer"])
	}
}

func TestStructuredDeny403_IncludesClassifierField(t *testing.T) {
	parsed := splitDbounceDenyMessage(t, sampleDbounceDenyRow("DROP", "public.users"), "postgres")
	if got, _ := parsed["classifier_hook"].(string); got != structureddeny.ClassifierHookGoHeuristic {
		t.Fatalf("classifier_hook = %v; want %q",
			parsed["classifier_hook"], structureddeny.ClassifierHookGoHeuristic)
	}
}

func TestStructuredDeny403_IncludesSuggestedAllowCommand(t *testing.T) {
	parsed := splitDbounceDenyMessage(t, sampleDbounceDenyRow("SELECT", "public.users"), "postgres")
	got, ok := parsed["suggested_allow_command"].(string)
	if !ok || got == "" {
		t.Fatalf("suggested_allow_command missing or empty: %v", parsed["suggested_allow_command"])
	}
	for _, want := range []string{"dbounce profile allow", "--target public.users", "--action SELECT"} {
		if !strings.Contains(got, want) {
			t.Errorf("suggested_allow_command = %q; missing %q", got, want)
		}
	}
}

func TestStructuredDeny403_IncludesRecommendedAction(t *testing.T) {
	parsed := splitDbounceDenyMessage(t, sampleDbounceDenyRow("DROP", "public.users"), "postgres")
	got, _ := parsed["recommended_action"].(string)
	if got != structureddeny.RecommendedActionHaltEscalate {
		t.Fatalf("DROP recommended_action = %v; want %q (destructive verb)",
			got, structureddeny.RecommendedActionHaltEscalate)
	}
}

// TestStructuredDeny403_PreservesLegacyKeys asserts the legacy
// "dbounce: denied: ..." prefix is preserved per
// [[creates-never-mutates]] so old grep-on-"denied:" tooling keeps
// working.
func TestStructuredDeny403_PreservesLegacyKeys(t *testing.T) {
	legacy := "dbounce: denied: testing legacy prefix"
	full := dbounceDenyMessageWithStructured(legacy, sampleDbounceDenyRow("SELECT", "public.users"), "postgres")
	if !strings.HasPrefix(full, legacy) {
		t.Errorf("structured-deny wire prefix changed; got %q; want prefix %q", full, legacy)
	}
	if !strings.Contains(full, structureddeny.WireMarker) {
		t.Errorf("structured-deny wire missing marker %q; got %q",
			structureddeny.WireMarker, full)
	}
}

// TestStructuredDeny403_HeuristicClassifierAdversarialBackstop asserts
// the Go-local heuristic mirrors KNOWN_ADVERSARIAL_PATTERNS for the
// dbounce action shape <STMT_TYPE>:<dialect>.
func TestStructuredDeny403_HeuristicClassifierAdversarialBackstop(t *testing.T) {
	parsed := splitDbounceDenyMessage(t, sampleDbounceDenyRow("DROP", "public.users"), "postgres")
	if got, _ := parsed["is_likely_injection_classification"].(string); got != structureddeny.InjectionAppearsAdversarial {
		t.Errorf("classification for DROP = %v; want %q",
			got, structureddeny.InjectionAppearsAdversarial)
	}
	// Non-destructive SELECT → ambiguous.
	parsed2 := splitDbounceDenyMessage(t, sampleDbounceDenyRow("SELECT", "public.users"), "postgres")
	if got, _ := parsed2["is_likely_injection_classification"].(string); got != structureddeny.InjectionAmbiguous {
		t.Errorf("classification for SELECT = %v; want %q",
			got, structureddeny.InjectionAmbiguous)
	}
}

func TestStructuredDeny403_SchemaVersionFieldPresent(t *testing.T) {
	parsed := splitDbounceDenyMessage(t, sampleDbounceDenyRow("SELECT", "public.users"), "postgres")
	if got, _ := parsed["structured_deny_schema_version"].(string); got != structureddeny.SchemaVersion {
		t.Fatalf("structured_deny_schema_version = %v; want %q",
			parsed["structured_deny_schema_version"], structureddeny.SchemaVersion)
	}
}

func TestStructuredDeny403_DenyEventIDFieldPresent(t *testing.T) {
	parsed := splitDbounceDenyMessage(t, sampleDbounceDenyRow("SELECT", "public.users"), "postgres")
	got, _ := parsed["deny_event_id"].(string)
	if !strings.HasPrefix(got, "evt_dbounce_") {
		t.Fatalf("deny_event_id = %q; want evt_dbounce_ prefix", got)
	}
}

// sampleDbounceDenyRow builds a minimal DecisionRow that exercises
// dbounce's action shape <STMT_TYPE>:<dialect>. dialect is supplied
// separately to mirror the runtime config-driven dialect lookup.
func sampleDbounceDenyRow(stmtType, table string) store.DecisionRow {
	return store.DecisionRow{
		Dialect:         "postgres",
		StatementType:   stmtType,
		TablesTouched:   []string{table},
		DecisionVerdict: "deny",
		DecisionReason:  "dbounce test deny on " + stmtType,
		DecisionSource:  "profile",
	}
}

// splitDbounceDenyMessage builds the structured-deny suffix via the
// production helper + splits the JSON payload off the marker.
func splitDbounceDenyMessage(t *testing.T, row store.DecisionRow, dialect string) map[string]any {
	t.Helper()
	legacy := "dbounce: denied: " + row.DecisionReason
	full := dbounceDenyMessageWithStructured(legacy, row, dialect)
	idx := strings.Index(full, structureddeny.WireMarker)
	if idx < 0 {
		t.Fatalf("marker not found in deny message: %q", full)
	}
	jsonPart := full[idx+len(structureddeny.WireMarker):]
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonPart), &parsed); err != nil {
		t.Fatalf("unmarshal structured-deny JSON: %v\njson=%s", err, jsonPart)
	}
	return parsed
}

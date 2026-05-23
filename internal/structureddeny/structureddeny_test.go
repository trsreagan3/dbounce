package structureddeny

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestStructuredDeny_IncludesCaughtByBouncer asserts the lead-with-
// caught_by_bouncer framing per
// [[ambient-value-prop-and-friction-framing]].
func TestStructuredDeny_IncludesCaughtByBouncer(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "dbounce"})
	if sd.CaughtByBouncer != "dbounce" {
		t.Fatalf("CaughtByBouncer = %q; want %q", sd.CaughtByBouncer, "dbounce")
	}
	if _, ok := sd.AsMap()["caught_by_bouncer"]; !ok {
		t.Fatalf("AsMap missing caught_by_bouncer key")
	}
}

func TestStructuredDeny_IncludesClassifierField(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "dbounce", Action: "SELECT:postgres"})
	if sd.ClassifierHook != ClassifierHookGoHeuristic {
		t.Fatalf("ClassifierHook = %q; want %q", sd.ClassifierHook, ClassifierHookGoHeuristic)
	}
}

func TestStructuredDeny_IncludesSuggestedAllowCommand(t *testing.T) {
	cmd := "dbounce profile allow --target public.users --action SELECT --reason ..."
	sd := Build(BuildOptions{
		Bouncer:               "dbounce",
		Action:                "SELECT:postgres",
		Resource:              "public.users",
		SuggestedAllowCommand: cmd,
	})
	if sd.SuggestedAllowCommand != cmd {
		t.Fatalf("SuggestedAllowCommand = %q; want %q", sd.SuggestedAllowCommand, cmd)
	}
}

func TestStructuredDeny_IncludesRecommendedAction(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "dbounce", Action: "SELECT:postgres"})
	switch sd.RecommendedAction {
	case RecommendedActionEasyAllow, RecommendedActionHaltEscalate, RecommendedActionRephraseRetry:
	default:
		t.Fatalf("RecommendedAction = %q; want one of the canonical three", sd.RecommendedAction)
	}
}

// TestStructuredDeny_HeuristicClassifierAdversarialBackstop verifies
// the KNOWN_ADVERSARIAL_PATTERNS work against dbounce's action shape
// <STMT_TYPE>:<dialect>.
func TestStructuredDeny_HeuristicClassifierAdversarialBackstop(t *testing.T) {
	cases := []struct {
		action string
		want   string
	}{
		{"DROP:postgres", InjectionAppearsAdversarial},
		{"DELETE:mysql", InjectionAppearsAdversarial},
		{"TRUNCATE:postgres", InjectionAppearsAdversarial},
		{"GRANT:postgres", InjectionAppearsAdversarial},
		{"SELECT:postgres", InjectionAmbiguous},
		{"INSERT:mysql", InjectionAmbiguous},
		{"UPDATE:postgres", InjectionAmbiguous},
	}
	for _, c := range cases {
		t.Run(c.action, func(t *testing.T) {
			sd := Build(BuildOptions{Bouncer: "dbounce", Action: c.action})
			if sd.IsLikelyInjectionClassification != c.want {
				t.Fatalf("classification for %q = %q; want %q",
					c.action, sd.IsLikelyInjectionClassification, c.want)
			}
		})
	}
}

func TestStructuredDeny_SchemaVersionFieldPresent(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "dbounce"})
	if sd.StructuredDenySchemaVersion != SchemaVersion {
		t.Fatalf("StructuredDenySchemaVersion = %q; want %q",
			sd.StructuredDenySchemaVersion, SchemaVersion)
	}
}

func TestStructuredDeny_DenyEventIDDeterministic(t *testing.T) {
	opts := BuildOptions{
		Bouncer: "dbounce", Action: "DROP:postgres",
		Resource: "public.users", When: "2026-05-23T12:00:00Z",
	}
	a := Build(opts)
	b := Build(opts)
	if a.DenyEventID != b.DenyEventID {
		t.Fatalf("DenyEventID not deterministic: %q vs %q", a.DenyEventID, b.DenyEventID)
	}
	if !strings.HasPrefix(a.DenyEventID, "evt_dbounce_") {
		t.Fatalf("DenyEventID = %q; want evt_dbounce_ prefix", a.DenyEventID)
	}
}

func TestStructuredDeny_DynamicDenyMeansRephraseRetry(t *testing.T) {
	sd := Build(BuildOptions{
		Bouncer:    "dbounce",
		Action:     "SELECT:postgres",
		DenySource: "dynamic_deny",
	})
	if sd.RecommendedAction != RecommendedActionRephraseRetry {
		t.Fatalf("dynamic_deny recommended=%q; want %q",
			sd.RecommendedAction, RecommendedActionRephraseRetry)
	}
}

func TestStructuredDeny_AsMapMatchesWireSchema(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "dbounce"})
	m := sd.AsMap()
	wantKeys := []string{
		"caught_by_bouncer",
		"is_likely_injection_classification",
		"suggested_allow_command",
		"recommended_action",
		"deny_event_id",
		"classifier_hook",
		"deny_source_classified",
		"structured_deny_schema_version",
	}
	for _, k := range wantKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("AsMap missing wire-schema key %q", k)
		}
	}
}

func TestStructuredDeny_JSONRoundTripsCanonicalShape(t *testing.T) {
	sd := Build(BuildOptions{Bouncer: "dbounce"})
	b, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	out := string(b)
	for _, want := range []string{
		`"caught_by_bouncer":"dbounce"`,
		`"structured_deny_schema_version":"1.0"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON output missing %q; got %s", want, out)
		}
	}
}

// TestStructuredDeny_AppendToMessage asserts the in-band wire shape
// "<legacy msg> | iam-jit-structured-deny: <json>" — the cross-protocol
// way to carry structured fields through PG ErrorResponse + MySQL
// ErrPacket without touching the protocol bytes.
func TestStructuredDeny_AppendToMessage(t *testing.T) {
	sd := Build(BuildOptions{
		Bouncer: "dbounce", Action: "DROP:postgres", Resource: "public.users",
	})
	out := sd.AppendToMessage("dbounce: denied: table users blocked by profile")
	if !strings.Contains(out, "dbounce: denied: table users blocked by profile") {
		t.Errorf("AppendToMessage dropped legacy prefix; got %q", out)
	}
	if !strings.Contains(out, WireMarker) {
		t.Errorf("AppendToMessage missing marker %q; got %q", WireMarker, out)
	}
	// Split-on-marker round-trip: confirm an agent reading the wire can
	// parse the structured fields back out.
	idx := strings.Index(out, WireMarker)
	if idx < 0 {
		t.Fatalf("marker not found in %q", out)
	}
	jsonPart := out[idx+len(WireMarker):]
	var parsed StructuredDeny
	if err := json.Unmarshal([]byte(jsonPart), &parsed); err != nil {
		t.Fatalf("unmarshal embedded JSON failed: %v\njson=%s", err, jsonPart)
	}
	if parsed.CaughtByBouncer != "dbounce" {
		t.Errorf("embedded caught_by_bouncer = %q; want %q", parsed.CaughtByBouncer, "dbounce")
	}
	if parsed.StructuredDenySchemaVersion != SchemaVersion {
		t.Errorf("embedded schema version = %q; want %q",
			parsed.StructuredDenySchemaVersion, SchemaVersion)
	}
}

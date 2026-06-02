// events_filter_test.go executes the live audit-UI row filter the same
// way the browser does, so a broken filter fails CI instead of shipping
// silently (the gap that let the server-side-only filter regress: the
// old tests only string-matched the HTML and never ran the JS).
//
// Two layers:
//
//  1. Behavioural — the exact auditFilterMatchJS source is run under a
//     JS engine (goja) and its verdict is asserted across the whole
//     filter grammar. This is the single source of truth for "does the
//     filter actually filter".
//  2. Contract — the rendered page is asserted to wire that matcher to
//     the DOM live (input event + applied on every append) and to NOT
//     pin filtering to the server poll, guarding against a regression
//     to the old broken shape.
package proxy

import (
	"strings"
	"testing"

	"github.com/dop251/goja"
)

// newFilterMatcher compiles the production filter JS into a callable
// Go closure: match(fields, query) -> bool.
func newFilterMatcher(t *testing.T) func(map[string]any, string) bool {
	t.Helper()
	vm := goja.New()
	if _, err := vm.RunString(auditFilterMatchJS); err != nil {
		t.Fatalf("auditFilterMatchJS failed to parse/run: %v", err)
	}
	fn, ok := goja.AssertFunction(vm.Get("auditFilterMatch"))
	if !ok {
		t.Fatal("auditFilterMatch is not defined as a function")
	}
	return func(fields map[string]any, query string) bool {
		res, err := fn(goja.Undefined(), vm.ToValue(fields), vm.ToValue(query))
		if err != nil {
			t.Fatalf("auditFilterMatch(%v, %q) threw: %v", fields, query, err)
		}
		return res.ToBoolean()
	}
}

func denyRow() map[string]any {
	return map[string]any{
		"time":     "2026-06-02 12:00:00",
		"severity": "High",
		"type":     "PROXY_DECISION",
		"actor":    "claude-code",
		"op":       "GET /repos/foo",
		"verdict":  "DENIED",
	}
}

func allowRow() map[string]any {
	return map[string]any{
		"time":     "2026-06-02 12:00:01",
		"severity": "Info",
		"type":     "PROXY_DECISION",
		"actor":    "anonymous",
		"op":       "POST /v1/messages",
		"verdict":  "ALLOWED",
	}
}

func TestAuditFilterMatch_Grammar(t *testing.T) {
	match := newFilterMatcher(t)
	deny := denyRow()
	allow := allowRow()

	cases := []struct {
		name  string
		row   map[string]any
		query string
		want  bool
	}{
		// Empty filter matches everything (this is the live default;
		// a broken filter that hides rows by default would fail here).
		{"empty matches deny", deny, "", true},
		{"empty matches allow", allow, "", true},
		{"whitespace-only matches", deny, "   ", true},

		// Plain substring across all columns, case-insensitive.
		{"plain text hits verdict", deny, "denied", true},
		{"plain text hits actor", deny, "claude", true},
		{"plain text case-insensitive", deny, "CLAUDE-CODE", true},
		{"plain text miss", allow, "claude", false},
		{"plain text path", allow, "/v1/messages", true},

		// field=value -> substring on that column only.
		{"verdict= matches deny", deny, "verdict=denied", true},
		{"verdict= rejects allow", allow, "verdict=denied", false},
		{"actor= matches", deny, "actor=claude", true},
		{"actor= rejects", allow, "actor=claude", false},
		{"severity alias sev=", deny, "sev=high", true},
		{"type alias et=", deny, "et=proxy_decision", true},
		{"op alias operation=", deny, "operation=GET", true},
		{"verdict alias v=", allow, "v=allow", true},
		{"field= is case-insensitive", deny, "VERDICT=DENIED", true},
		{"field= scoped, no cross-column bleed", deny, "actor=DENIED", false},

		// field~regex -> regex on that column, case-insensitive.
		{"op~ anchored regex hit", deny, "op~^GET", true},
		{"op~ anchored regex miss", allow, "op~^GET", false},
		{"verdict~ alternation", allow, "verdict~allow|denied", true},
		{"invalid regex never throws, returns false", deny, "op~[", false},

		// Unknown field name falls back to whole-string substring so a
		// typo never blanks the table.
		{"unknown field falls back to substring", deny, "nope=claude", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := match(tc.row, tc.query); got != tc.want {
				t.Errorf("auditFilterMatch(row, %q) = %v; want %v", tc.query, got, tc.want)
			}
		})
	}
}

// TestAuditFilterMatch_FiltersAVisibleSet proves the matcher narrows a
// concrete set the way the UI renders it — the end-to-end "typing a
// filter shows fewer rows" guarantee, evaluated row by row.
func TestAuditFilterMatch_FiltersAVisibleSet(t *testing.T) {
	match := newFilterMatcher(t)
	rows := []map[string]any{denyRow(), allowRow(), denyRow()}

	count := func(q string) int {
		n := 0
		for _, r := range rows {
			if match(r, q) {
				n++
			}
		}
		return n
	}
	if n := count(""); n != 3 {
		t.Errorf("no filter: %d visible; want all 3", n)
	}
	if n := count("verdict=denied"); n != 2 {
		t.Errorf("verdict=denied: %d visible; want 2", n)
	}
	if n := count("verdict=allowed"); n != 1 {
		t.Errorf("verdict=allowed: %d visible; want 1", n)
	}
	if n := count("zzz-no-match"); n != 0 {
		t.Errorf("non-matching filter: %d visible; want 0", n)
	}
}

// TestAuditEventsUI_FilterWiredLive guards the DOM wiring that connects
// the matcher to the page. Each assertion pins a specific thing that
// was broken before this fix, so a regression to the old server-only
// behaviour fails the test.
func TestAuditEventsUI_FilterWiredLive(t *testing.T) {
	body := renderAuditEventsUI(bouncerNameDbounce)

	// The {{FILTER_JS}} token must be substituted (matcher present).
	if strings.Contains(body, "{{FILTER_JS}}") {
		t.Error("FILTER_JS token left unsubstituted in rendered page")
	}
	if !strings.Contains(body, "function auditFilterMatch(") {
		t.Error("rendered page is missing the auditFilterMatch function")
	}

	// Filter must be live (input event), not the old change-only bind.
	if !strings.Contains(body, `elFilter.addEventListener("input"`) {
		t.Error("filter input is not bound to the live \"input\" event")
	}

	// The matcher must be applied to rendered rows on each append.
	if !strings.Contains(body, "applyFilter()") {
		t.Error("applyFilter is never invoked from the render/append path")
	}
	if !strings.Contains(body, "auditFilterMatch(tr._fields") {
		t.Error("applyFilter does not evaluate rows through auditFilterMatch")
	}

	// Regression guard: the UI filter must NOT be pushed to the server
	// poll. That was the root cause — filtering only the next fetch
	// left stale rows on screen. If this string ever comes back, the
	// live filter has likely been undermined.
	if strings.Contains(body, "filter=") {
		t.Error("rendered page pushes filter= to the server poll; " +
			"filtering must be client-side (regression to old bug)")
	}
}

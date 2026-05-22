// loader_test.go — #324c loader regression suite.
//
// Covers:
//   - happy-path YAML load + filter to dbounce-applicable entries
//   - schema-violation rejection (missing required fields, bad rule-id
//     shape, bad duration shape, bad applied_to bouncer, duplicate id,
//     misrouted product magic)
//   - filter: ARN-but-not-rds targets + k8s-namespace targets are
//     skipped; rds:* ARN targets + DB-shaped hostnames are retained.
//   - operator-explicit `applied_to: [dbounce]` ALWAYS wins (overrides
//     heuristic).
//   - hostname-heuristic matches (*-db*, *postgres*, *mysql*, *-rds*).
//   - expired rules dropped at load time.
//   - instance-level matcher: AppliesToInstance / MatchingRule.

package dynamicdeny

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validRuleID is a stable rule id used across the suite. ULID body
// "01HZ8VKJ6Y2BJTPVZ3PNX97A2C" matches the schema's Crockford base32
// shape (rejects I/L/O/U).
const validRuleID = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"
const validRuleID2 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2D"
const validRuleID3 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2E"
const validRuleID4 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2F"
const validRuleID5 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2G"
const validRuleID6 = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2H"

// goldenYAML builds a single-rule YAML payload targeting dbounce
// explicitly via applied_to.
func goldenYAML() string {
	added := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(3 * time.Hour).Format(time.RFC3339)
	return strings.Join([]string{
		`schema_version: "1.0"`,
		`product: iam-jit-dynamic-denies`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets:`,
		`      - "payments-db-prod.us-east-1.rds.amazonaws.com"`,
		`    reason: "operator: lockout payments db for 3h"`,
		`    duration: "3h"`,
		`    added_by: "operator@org.com"`,
		`    added_at: "` + added + `"`,
		`    expires_at: "` + expires + `"`,
		`    applied_to:`,
		`      - dbounce`,
		`    applies_to_recommender: false`,
		`    source: "cli"`,
	}, "\n")
}

func TestLoader_LoadsValidYAML(t *testing.T) {
	rs, err := LoadBytes([]byte(goldenYAML()), "test.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if rs == nil || len(rs.Rules) != 1 {
		t.Fatalf("Rules = %v; want 1", rs)
	}
	r := rs.Rules[0]
	if r.ID != validRuleID {
		t.Errorf("ID = %q; want %q", r.ID, validRuleID)
	}
	if len(r.Targets) != 1 || r.Targets[0] != "payments-db-prod.us-east-1.rds.amazonaws.com" {
		t.Errorf("Targets = %v; unexpected", r.Targets)
	}
	if r.Duration != "3h" {
		t.Errorf("Duration = %q; want 3h", r.Duration)
	}
	if rs.SourcePath != "test.yaml" {
		t.Errorf("SourcePath = %q; want test.yaml", rs.SourcePath)
	}
}

func TestLoader_LoadFile_MissingFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	rs, err := LoadFile(filepath.Join(dir, "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("LoadFile on missing path should not error; got %v", err)
	}
	if rs == nil || len(rs.Rules) != 0 {
		t.Errorf("Rules = %v; want empty", rs)
	}
}

func TestLoader_LoadFile_RealFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dd.yaml")
	if err := os.WriteFile(p, []byte(goldenYAML()), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rs, err := LoadFile(p)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Errorf("Rules = %d; want 1", len(rs.Rules))
	}
}

func TestLoader_RejectsSchemaViolation(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantSub  string
	}{
		{
			name: "missing schema_version",
			body: strings.Join([]string{
				`denies:`,
				`  - id: ` + validRuleID,
				`    targets: [payments-db.example.com]`,
				`    reason: "test"`,
				`    duration: "3h"`,
				`    added_by: "u@h"`,
				`    added_at: "2026-05-22T16:13:48Z"`,
				`    applied_to: [dbounce]`,
			}, "\n"),
			wantSub: "schema_version",
		},
		{
			name: "bad rule id shape",
			body: strings.Join([]string{
				`schema_version: "1.0"`,
				`denies:`,
				`  - id: not-a-valid-id`,
				`    targets: [payments-db.example.com]`,
				`    reason: "test"`,
				`    duration: "3h"`,
				`    added_by: "u@h"`,
				`    added_at: "2026-05-22T16:13:48Z"`,
				`    applied_to: [dbounce]`,
			}, "\n"),
			wantSub: "dd_",
		},
		{
			name: "bad duration shape",
			body: strings.Join([]string{
				`schema_version: "1.0"`,
				`denies:`,
				`  - id: ` + validRuleID,
				`    targets: [payments-db.example.com]`,
				`    reason: "test"`,
				`    duration: "not-a-duration"`,
				`    added_by: "u@h"`,
				`    added_at: "2026-05-22T16:13:48Z"`,
				`    applied_to: [dbounce]`,
			}, "\n"),
			wantSub: "duration",
		},
		{
			name: "unknown bouncer name",
			body: strings.Join([]string{
				`schema_version: "1.0"`,
				`denies:`,
				`  - id: ` + validRuleID,
				`    targets: [payments-db.example.com]`,
				`    reason: "test"`,
				`    duration: "3h"`,
				`    added_by: "u@h"`,
				`    added_at: "2026-05-22T16:13:48Z"`,
				`    applied_to: [made-up-bouncer]`,
			}, "\n"),
			wantSub: "made-up-bouncer",
		},
		{
			name: "duplicate rule id",
			body: strings.Join([]string{
				`schema_version: "1.0"`,
				`denies:`,
				`  - id: ` + validRuleID,
				`    targets: [payments-db.example.com]`,
				`    reason: "test"`,
				`    duration: "3h"`,
				`    added_by: "u@h"`,
				`    added_at: "2026-05-22T16:13:48Z"`,
				`    applied_to: [dbounce]`,
				`  - id: ` + validRuleID,
				`    targets: [other-db.example.com]`,
				`    reason: "dup"`,
				`    duration: "1h"`,
				`    added_by: "u@h"`,
				`    added_at: "2026-05-22T16:13:48Z"`,
				`    applied_to: [dbounce]`,
			}, "\n"),
			wantSub: "duplicate",
		},
		{
			name: "bad product magic",
			body: strings.Join([]string{
				`schema_version: "1.0"`,
				`product: dbounce-config`,
				`denies: []`,
			}, "\n"),
			wantSub: "product",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadBytes([]byte(tc.body), "x.yaml")
			if err == nil {
				t.Fatal("expected rejection; got no error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q should contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestLoader_FiltersNonDbounceTargets(t *testing.T) {
	// 6 rules — only the DB-shaped (rds:* ARN + RDS-endpoint hostname +
	// explicit-dbounce applied_to) land. The S3 ARN, k8s namespace,
	// generic non-DB hostname rules get filtered out.
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		// 1 — rds:* ARN, no explicit applied_to-dbounce, ibounce-routed
		//    in the YAML; should land via the rds:* heuristic.
		`  - id: ` + validRuleID,
		`    targets: ["arn:aws:rds:us-east-1:123:db:payments-*"]`,
		`    reason: "rds ARN -> dbounce via heuristic"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [ibounce]`,
		// 2 — s3 ARN, ibounce-routed; should NOT land.
		`  - id: ` + validRuleID2,
		`    targets: ["arn:aws:s3:::prod-*"]`,
		`    reason: "s3 ARN -> ibounce only"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [ibounce]`,
		// 3 — k8s namespace, kbouncer-routed; should NOT land.
		`  - id: ` + validRuleID3,
		`    targets: ["kube-system"]`,
		`    reason: "k8s namespace -> kbouncer only"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [kbouncer]`,
		// 4 — RDS endpoint hostname, dbounce+gbounce both via resolver.
		`  - id: ` + validRuleID4,
		`    targets: ["payments-db-prod.us-east-1.rds.amazonaws.com"]`,
		`    reason: "RDS endpoint -> dbounce + gbounce"`,
		`    duration: "45m"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [dbounce, gbounce]`,
		// 5 — generic api hostname, gbounce-routed; should NOT land
		//    (no DB-shape heuristic match).
		`  - id: ` + validRuleID5,
		`    targets: ["api.openai.com"]`,
		`    reason: "generic api -> gbounce only"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [gbounce]`,
		// 6 — *postgres* hostname pattern, gbounce-routed in YAML;
		//    should land via the hostname heuristic.
		`  - id: ` + validRuleID6,
		`    targets: ["prod-postgres-replica-7.internal"]`,
		`    reason: "postgres hostname -> dbounce via heuristic"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [gbounce]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	// rules 1, 4, 6 should survive (rds-arn, explicit dbounce, postgres heuristic).
	if len(rs.Rules) != 3 {
		t.Fatalf("Rules = %d; want 3; got %+v", len(rs.Rules), rs.Rules)
	}
	keptIDs := map[string]bool{}
	for _, r := range rs.Rules {
		keptIDs[r.ID] = true
	}
	for _, want := range []string{validRuleID, validRuleID4, validRuleID6} {
		if !keptIDs[want] {
			t.Errorf("rule %q should have been kept", want)
		}
	}
	for _, drop := range []string{validRuleID2, validRuleID3, validRuleID5} {
		if keptIDs[drop] {
			t.Errorf("rule %q should have been filtered out", drop)
		}
	}
}

func TestLoader_HostnameHeuristicsMatch(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		expect bool
	}{
		{"prod-db endpoint", "prod-db.example.com", true},
		{"postgres hostname", "my-postgres-1.internal", true},
		{"mysql hostname", "mysql-replica.local", true},
		{"rds endpoint", "anything-rds-prod.example.com", true},
		{"unrelated hostname", "api.openai.com", false},
		{"k8s-like name", "kube-system", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Rule{
				ID:        validRuleID,
				Targets:   []string{tc.host},
				Reason:    "x",
				Duration:  "1h",
				AddedBy:   "u@h",
				AddedAt:   time.Now().UTC(),
				AppliedTo: []string{"gbounce"}, // intentionally NOT dbounce
			}
			got := appliesToDbounce(r)
			if got != tc.expect {
				t.Errorf("appliesToDbounce(%q) = %v; want %v", tc.host, got, tc.expect)
			}
		})
	}
}

func TestLoader_ExplicitBouncerAnnotationOverrides(t *testing.T) {
	// Target shape is "*.openai.com" — would NOT match the heuristic;
	// but applied_to: [dbounce] is explicit and ALWAYS wins.
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: ["api.openai.com"]`,
		`    reason: "operator override -> dbounce"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [dbounce]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(rs.Rules) != 1 || rs.Rules[0].ID != validRuleID {
		t.Errorf("explicit applied_to: [dbounce] should land regardless of target shape; got %+v", rs.Rules)
	}
}

func TestLoader_RDSARNMatches(t *testing.T) {
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: ["arn:aws:rds:us-east-1:123456789012:db:payments-prod"]`,
		`    reason: "rds arn target"`,
		`    duration: "3h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    applied_to: [ibounce]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("Rules = %d; want 1 (rds arn -> dbounce via heuristic)", len(rs.Rules))
	}
	// AppliesToInstance against the matching ARN should fire.
	if !rs.AppliesToInstance("", "arn:aws:rds:us-east-1:123456789012:db:payments-prod") {
		t.Errorf("AppliesToInstance(rds-arn) = false; want true")
	}
	// Against a non-matching ARN should NOT fire.
	if rs.AppliesToInstance("", "arn:aws:rds:us-east-1:123456789012:db:other-db") {
		t.Errorf("AppliesToInstance(non-matching-arn) = true; want false")
	}
}

func TestLoader_ExpiredRulesFiltered(t *testing.T) {
	expired := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	body := strings.Join([]string{
		`schema_version: "1.0"`,
		`denies:`,
		`  - id: ` + validRuleID,
		`    targets: ["payments-db.example.com"]`,
		`    reason: "already expired"`,
		`    duration: "1h"`,
		`    added_by: "u@h"`,
		`    added_at: "2026-05-22T16:13:48Z"`,
		`    expires_at: "` + expired + `"`,
		`    applied_to: [dbounce]`,
	}, "\n")
	rs, err := LoadBytes([]byte(body), "x.yaml")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(rs.Rules) != 0 {
		t.Errorf("expired rule should be skipped; got %d rule(s)", len(rs.Rules))
	}
}

func TestLoader_ResolveDefaultPath(t *testing.T) {
	t.Setenv(DefaultPathEnv, "/tmp/iam-jit-test-override.yaml")
	got := ResolveDefaultPath()
	if got != "/tmp/iam-jit-test-override.yaml" {
		t.Errorf("ResolveDefaultPath = %q; want override", got)
	}
}

func TestRuleSet_MatchingRule_HostnameGlob(t *testing.T) {
	rs := &RuleSet{
		Rules: []Rule{
			{
				ID:        validRuleID,
				Targets:   []string{"*.us-east-1.rds.amazonaws.com"},
				Reason:    "lockout us-east-1 RDS",
				AppliedTo: []string{"dbounce"},
			},
		},
	}
	if !rs.AppliesToInstance("payments-db-prod.us-east-1.rds.amazonaws.com", "") {
		t.Errorf("glob hostname target should match")
	}
	if rs.AppliesToInstance("payments-db-prod.us-west-2.rds.amazonaws.com", "") {
		t.Errorf("glob hostname target should NOT match different region")
	}
	if rs.AppliesToInstance("", "") {
		t.Errorf("empty upstream should never match")
	}
}

func TestRuleSet_MatchingRule_ReturnsFirstMatch(t *testing.T) {
	rs := &RuleSet{
		Rules: []Rule{
			{
				ID:        validRuleID,
				Targets:   []string{"prod-db.example.com"},
				Reason:    "first rule",
				AppliedTo: []string{"dbounce"},
			},
			{
				ID:        validRuleID2,
				Targets:   []string{"prod-db.example.com"},
				Reason:    "second rule",
				AppliedTo: []string{"dbounce"},
			},
		},
	}
	m := rs.MatchingRule("prod-db.example.com", "")
	if m == nil || m.ID != validRuleID {
		t.Errorf("MatchingRule should return the FIRST matching rule; got %+v", m)
	}
}

func TestGlobMatch_BasicShapes(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"*.example.com", "host.example.com", true},
		{"*.example.com", "deeply.nested.example.com", true},
		{"*.example.com", "example.com", false},
		{"*-db*", "prod-db.example.com", true},
		{"*-db*", "api.example.com", false},
		{"prod-db.example.com", "prod-db.example.com", true},
		{"prod-db.example.com", "other-db.example.com", false},
		{"*", "anything", true},
	}
	for _, tc := range cases {
		if got := globMatch(tc.pat, tc.s); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v; want %v", tc.pat, tc.s, got, tc.want)
		}
	}
}

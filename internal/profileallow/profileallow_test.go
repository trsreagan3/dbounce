// profileallow_test.go — #387 / §A25 Phase 2 test suite.

package profileallow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/trsreagan3/dbounce/internal/profile"
)

func writeProfilesYAML(t *testing.T, dir, name, source string) string {
	t.Helper()
	path := filepath.Join(dir, "profiles.yaml")
	body := map[string]any{
		"profiles": map[string]any{
			name: map[string]any{"description": "test"},
		},
	}
	if source != "" {
		body["profiles"].(map[string]any)[name].(map[string]any)["source"] = source
	}
	raw, err := yaml.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func setupQueuePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	qp := filepath.Join(dir, "pending.jsonl")
	t.Setenv(PendingApprovalsPathEnv, qp)
	return qp
}

func TestProfileAllow_AppendsRule(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")

	emitted := 0
	res, err := AddProfileAllowRule(Options{
		Target:       "*.staging.internal",
		Actions:      []string{"SELECT:public.users"},
		Reason:       "agent reads staging users",
		ProfileName:  "full-user",
		ProfilesPath: path,
		Source:       SourceCLI,
		Actor:        "test-actor",
		EmitAudit: func(AuditEvent) {
			emitted++
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "applied" {
		t.Fatalf("status: got %q", res.Status)
	}
	if emitted == 0 {
		t.Errorf("expected emit callback to fire")
	}

	ps, _ := profile.LoadProfiles(path)
	p, _ := ps.Active("full-user")
	if len(p.AllowRules) != 1 {
		t.Fatalf("on-disk allow rules: got %d", len(p.AllowRules))
	}
	rule := p.AllowRules[0]
	if !strings.Contains(rule.Note, EasyAllowOriginTag) {
		t.Errorf("note missing tag: %q", rule.Note)
	}
	if !strings.Contains(rule.Note, "by=test-actor") {
		t.Errorf("note missing actor: %q", rule.Note)
	}
}

func TestProfileAllow_RefusesWildcardTarget(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")
	_, err := AddProfileAllowRule(Options{
		Target:       "*",
		Actions:      []string{"SELECT:public.users"},
		Reason:       "broad",
		ProfilesPath: path,
		ProfileName:  "full-user",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if perr, ok := err.(*Error); !ok || perr.Code != "target_too_broad" {
		t.Fatalf("error code: %v", err)
	}
}

func TestProfileAllow_RefusesActionWithoutColon(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")
	_, err := AddProfileAllowRule(Options{
		Target:       "*.staging.internal",
		Actions:      []string{"BadAction"},
		Reason:       "wrong",
		ProfileName:  "full-user",
		ProfilesPath: path,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if perr, ok := err.(*Error); !ok || perr.Code != "bad_action" {
		t.Fatalf("error code: %v", err)
	}
}

func TestProfileAllow_RefusesOrgDistributedProfile(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "org-floor", "https://corp.example.com/profiles.yaml")
	_, err := AddProfileAllowRule(Options{
		Target:       "*.staging.internal",
		Actions:      []string{"SELECT:public.users"},
		Reason:       "agent",
		ProfileName:  "org-floor",
		ProfilesPath: path,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if perr, ok := err.(*Error); !ok || perr.Code != "org_distributed" {
		t.Fatalf("error code: %v", err)
	}
}

func TestProfileAllow_EmitsAdminActionAuditEvent(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")
	var captured *AuditEvent
	_, err := AddProfileAllowRule(Options{
		Target:       "*.staging.internal",
		Actions:      []string{"SELECT:public.users"},
		Reason:       "agent",
		ProfileName:  "full-user",
		ProfilesPath: path,
		EmitAudit: func(ev AuditEvent) {
			c := ev
			captured = &c
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if captured == nil {
		t.Fatal("expected audit event captured")
	}
	if captured.Action != AdminActionProfileAllowAdded {
		t.Errorf("action: got %q", captured.Action)
	}
	if captured.EntityName != "full-user" {
		t.Errorf("entity_name: got %q", captured.EntityName)
	}
}

func TestProfileAllow_AgentSelfGrantDefaultOff_QueuesPending(t *testing.T) {
	qp := setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")

	res, err := AddProfileAllowRule(Options{
		Target:       "*.staging.internal",
		Actions:      []string{"SELECT:public.users"},
		Reason:       "agent suggests",
		ProfileName:  "full-user",
		ProfilesPath: path,
		Source:       SourceMCP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending_approval" {
		t.Fatalf("status: got %q", res.Status)
	}

	raw, _ := os.ReadFile(qp)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("pending lines: got %d", len(lines))
	}
	var entry map[string]any
	if jerr := json.Unmarshal([]byte(lines[0]), &entry); jerr != nil {
		t.Fatal(jerr)
	}
	if id, _ := entry["id"].(string); !strings.HasPrefix(id, "pa_") {
		t.Errorf("missing pa_ prefix: %q", id)
	}
	if b, _ := entry["bouncer"].(string); b != "dbounce" {
		t.Errorf("bouncer: got %q", b)
	}
}

func TestProfileAllow_AgentSelfGrantOptIn_AppliesImmediately(t *testing.T) {
	setupQueuePath(t)
	dir := t.TempDir()
	path := writeProfilesYAML(t, dir, "full-user", "")
	trueVal := true
	res, err := AddProfileAllowRule(Options{
		Target:              "*.staging.internal",
		Actions:             []string{"SELECT:public.users"},
		Reason:              "opt-in",
		ProfileName:         "full-user",
		ProfilesPath:        path,
		Source:              SourceMCP,
		AllowAgentSelfGrant: &trueVal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "applied" {
		t.Fatalf("status: got %q", res.Status)
	}
}

func TestClassifyDenySource(t *testing.T) {
	cases := []struct {
		reason string
		want   string
	}{
		{"matched dynamic deny: dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C", DenySourceDynamicDeny},
		{"profile 'safe-default': verb in deny_verbs", DenySourceSafeDefault},
		{"no idea", DenySourceUnknown},
	}
	for _, tc := range cases {
		got, _ := ClassifyDenySource(tc.reason)
		if got != tc.want {
			t.Errorf("%q: got %q want %q", tc.reason, got, tc.want)
		}
	}
}

func TestSynthSuggestedAllowCommand_Includes_dbounce(t *testing.T) {
	out := SynthSuggestedAllowCommand("public.users", "SELECT:postgres", DenySourceSafeDefault)
	if !strings.Contains(out, "dbounce profile allow") {
		t.Errorf("expected dbounce profile allow, got %q", out)
	}
}

func TestPendingQueueIDFormat(t *testing.T) {
	id := newPendingID()
	if !strings.HasPrefix(id, "pa_") {
		t.Errorf("missing pa_: %q", id)
	}
	if len(id) != 29 {
		t.Errorf("length: got %d", len(id))
	}
}

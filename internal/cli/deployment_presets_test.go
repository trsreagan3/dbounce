// Tests for #254 — `dbounce run --preset security-observe`.
//
// dbounce variant: same preset NAME + same HARD/SOFT override
// semantics as ibounce/kbounce/gbounce per [[cross-product-agent-
// parity]]. dbounce ships heartbeat + audit-export-health-interval
// but NOT a rule-engine alert framework, so the preset's canonical
// settings differ slightly:
//   - HARD: --mode (transparent)
//   - SOFT: --default-policy, --audit-log-path, --heartbeat-interval,
//     --audit-export-health-interval
//   - NOT included: --alert-rules (dbounce never registered the flag)

package cli

import (
	"strings"
	"testing"
)

func TestSecurityObserve_ActivatesCanonicalSettings(t *testing.T) {
	preset := GetPreset("security-observe", "dbounce")
	if preset == nil {
		t.Fatal("expected non-nil preset")
	}
	want := map[string]string{
		"mode":                         "transparent",
		"default-policy":               "allow",
		"audit-log-path":               DefaultAuditLogPath("dbounce"),
		"heartbeat-interval":           "30s",
		"audit-export-health-interval": "30s",
	}
	for k, v := range want {
		got, ok := preset.Values[k]
		if !ok {
			t.Errorf("preset missing key %q", k)
			continue
		}
		if got.Value != v {
			t.Errorf("preset[%q] = %q; want %q", k, got.Value, v)
		}
	}
}

func TestSecurityObserve_HardOverridesModeOnly(t *testing.T) {
	preset := GetPreset("security-observe", "dbounce")
	hard := []string{}
	for k, v := range preset.Values {
		if v.Policy == PresetHard {
			hard = append(hard, k)
		}
	}
	if len(hard) != 1 || hard[0] != "mode" {
		t.Errorf("expected exactly one HARD key (mode); got %v", hard)
	}
}

func TestApplyPreset_HardOverrideErrors(t *testing.T) {
	preset := GetPreset("security-observe", "dbounce")
	_, err := ApplyPreset(
		preset,
		map[string]bool{"mode": true},
		map[string]string{
			"mode":                         "cooperative",
			"default-policy":               "deny",
			"audit-log-path":               "",
			"heartbeat-interval":           "0",
			"audit-export-health-interval": "0",
		},
		nil,
	)
	if err == nil {
		t.Fatal("expected HARD-override error")
	}
	msg := err.Error()
	for _, want := range []string{"security-observe", "mode", "HARD", "drop the --preset", "drop the explicit"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}
}

func TestApplyPreset_SoftOverrideAllowed(t *testing.T) {
	preset := GetPreset("security-observe", "dbounce")
	res, err := ApplyPreset(
		preset,
		map[string]bool{"audit-log-path": true},
		map[string]string{
			"mode":                         "cooperative",
			"default-policy":               "deny",
			"audit-log-path":               "/custom/siem.jsonl",
			"heartbeat-interval":           "0",
			"audit-export-health-interval": "0",
		},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, k := range res.OverriddenKeys {
		if k == "audit-log-path" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected audit-log-path in OverriddenKeys; got %v", res.OverriddenKeys)
	}
}

func TestFormatBanner_ShowsPresetAndDerivedKeys(t *testing.T) {
	preset := GetPreset("security-observe", "dbounce")
	res, err := ApplyPreset(preset, nil, map[string]string{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := FormatBanner(preset, res)
	if !strings.Contains(lines[0], "deployment preset: security-observe") {
		t.Errorf("first line should name preset: %q", lines[0])
	}
	joined := strings.Join(lines, "\n")
	for _, key := range []string{"mode", "audit-log-path", "heartbeat-interval", "audit-export-health-interval", "default-policy"} {
		if !strings.Contains(joined, "--"+key) {
			t.Errorf("banner missing --%s: %s", key, joined)
		}
	}
}

func TestSecurityObserve_NeutralLanguageNoViolationTerms(t *testing.T) {
	preset := GetPreset("security-observe", "dbounce")
	blob := strings.ToLower(preset.Description)
	for _, forbidden := range []string{"violation", "infraction", "unauthorized"} {
		if strings.Contains(blob, forbidden) {
			t.Errorf("preset description leaks %q: %s", forbidden, preset.Description)
		}
	}
}

func TestSecurityObserve_NoPhoneHome(t *testing.T) {
	preset := GetPreset("security-observe", "dbounce")
	if _, ok := preset.Values["audit-webhook-url"]; ok {
		t.Error("preset must NOT set audit-webhook-url")
	}
}

func TestUnknownPreset_ReturnsNil(t *testing.T) {
	if GetPreset("does-not-exist", "dbounce") != nil {
		t.Error("expected nil for unknown preset")
	}
}

func TestListPresetNames_OnlySecurityObserve(t *testing.T) {
	names := ListPresetNames()
	if len(names) != 1 || names[0] != "security-observe" {
		t.Errorf("v1.0 should ship exactly security-observe; got %v", names)
	}
}

// Integration test: actual `dbounce run --preset security-observe
// --mode cooperative` cobra invocation. The HARD-override error
// fires BEFORE any listener bind.
func TestRunCmd_HardOverrideErrorsBeforeBind(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{
		"run",
		"--preset", "security-observe",
		"--mode", "cooperative",
		"--db", t.TempDir() + "/db.db",
		"--port", "0",
		"--mgmt-port", "0",
	})
	root.SetOut(devNull{})
	root.SetErr(devNull{})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected HARD-override error")
	}
	msg := err.Error()
	for _, want := range []string{"security-observe", "mode", "HARD"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q: %s", want, msg)
		}
	}
}

type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }

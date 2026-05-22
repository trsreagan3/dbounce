// Tests for `dbounce profile doctor` (task #321 / KNOWN-CAVEATS §A19).
//
// Mirrors the cross-product spec in the task brief: fresh profile is
// silent, missing safety-floor warns loudly + with category, --apply
// merges additively + backs up, --acknowledge silences until version
// bump, convenience misses don't trigger the startup banner.

package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// freshProfilesPath writes the embedded defaults to a temp file and
// returns the path. Mirrors `dbounce run`'s first-launch shape.
func freshProfilesPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	if _, err := EnsureDefaultProfilesFile(path); err != nil {
		t.Fatalf("seed defaults: %v", err)
	}
	return path
}

// stripFieldFromProfile removes one field from a profile in the on-
// disk YAML so we can simulate "operator installed pre-#302."
func stripFieldFromProfile(t *testing.T, path, profileName, field string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	profilesObj := tree["profiles"].(map[string]any)
	body := profilesObj[profileName].(map[string]any)
	delete(body, field)
	profilesObj[profileName] = body
	out, err := yaml.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestDoctor_FreshProfile_NoWarnings(t *testing.T) {
	path := freshProfilesPath(t)
	rep, err := Check(path)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(rep.MissingFields) != 0 {
		t.Fatalf("expected zero missing fields on fresh profile; got %d: %+v",
			len(rep.MissingFields), rep.MissingFields)
	}
	if rep.HasSafetyFloorGap() {
		t.Fatalf("fresh profile should not report a safety-floor gap")
	}
	if line := StartupBannerLine("dbounce", path); line != "" {
		t.Fatalf("fresh profile should not emit a startup banner; got %q", line)
	}
}

func TestDoctor_MissingSafetyFloor_WarnsLoudly(t *testing.T) {
	path := freshProfilesPath(t)
	stripFieldFromProfile(t, path, "safe-default", "deny_dcl_targets_public")

	rep, err := Check(path)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(rep.MissingFields) == 0 {
		t.Fatalf("expected at least one missing field after strip")
	}
	var found *FieldGap
	for i := range rep.MissingFields {
		g := rep.MissingFields[i]
		if g.ProfileName == "safe-default" && g.Field == "deny_dcl_targets_public" {
			found = &rep.MissingFields[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected deny_dcl_targets_public in missing list; got %+v",
			rep.MissingFields)
	}
	if found.Category != CategorySafetyFloor {
		t.Fatalf("expected category safety-floor; got %q", found.Category)
	}
	if !strings.Contains(found.WhyMatters, "PUBLIC") {
		t.Fatalf("expected why-matters to mention PUBLIC grant; got %q", found.WhyMatters)
	}
	if !rep.HasSafetyFloorGap() {
		t.Fatalf("HasSafetyFloorGap should report true")
	}
	line := StartupBannerLine("dbounce", path)
	if line == "" {
		t.Fatalf("startup banner should fire on safety-floor gap")
	}
	if !strings.Contains(line, "§A19") {
		t.Fatalf("startup banner should reference KNOWN-CAVEATS §A19; got %q", line)
	}
	if !strings.Contains(line, "dbounce profile doctor") {
		t.Fatalf("startup banner should name the doctor command; got %q", line)
	}
}

func TestDoctor_MissingConvenience_NoStartupWarn_ButShowsInDoctor(t *testing.T) {
	// We don't currently have a CategoryConvenience entry in the
	// catalog (every shipped default is safety-floor in v1.0); inject
	// a temporary one so the test enforces the contract for when
	// future entries land.
	original := shippedDefaultsCatalog
	t.Cleanup(func() { shippedDefaultsCatalog = original })
	shippedDefaultsCatalog = append([]FieldGap{
		{
			ProfileName: "safe-default",
			Field:       "_test_convenience_field",
			Category:    CategoryConvenience,
			WhyMatters:  "test-only convenience field",
			AddedIn:     "test fixture",
			DefaultValue: "test",
		},
	}, original...)

	path := freshProfilesPath(t)
	// The temp catalog entry isn't in the embedded YAML, so the
	// fresh profile is automatically "missing" it from the doctor's
	// POV. That's the exact shape we need for this test.
	rep, err := Check(path)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	var sawConvenience, sawSafetyFloor bool
	for _, g := range rep.MissingFields {
		if g.Category == CategoryConvenience {
			sawConvenience = true
		}
		if g.Category == CategorySafetyFloor {
			sawSafetyFloor = true
		}
	}
	if !sawConvenience {
		t.Fatalf("expected at least one convenience gap; got %+v", rep.MissingFields)
	}
	if sawSafetyFloor {
		t.Fatalf("fresh profile should not have safety-floor gap (none stripped)")
	}
	if rep.HasSafetyFloorGap() {
		t.Fatalf("HasSafetyFloorGap should return false")
	}
	if line := StartupBannerLine("dbounce", path); line != "" {
		t.Fatalf("startup banner must NOT fire on convenience-only gaps; got %q", line)
	}
	// But `profile doctor` (the explicit command) should still show
	// it — FormatReport renders it.
	rendered := FormatReport("dbounce", rep)
	if !strings.Contains(rendered, "_test_convenience_field") {
		t.Fatalf("explicit doctor output should list convenience field; got %q", rendered)
	}
}

func TestDoctor_Apply_MergesAdditively(t *testing.T) {
	path := freshProfilesPath(t)
	stripFieldFromProfile(t, path, "safe-default", "deny_dcl_targets_public")
	// Add an operator-customized field that --apply MUST NOT touch.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	body := tree["profiles"].(map[string]any)["safe-default"].(map[string]any)
	body["exempt_resources"] = []any{"public.my_custom_audit_table"}
	out, err := yaml.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	result, err := Apply(path, ApplyOptions{Now: now})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(result.AppliedFields) == 0 {
		t.Fatalf("expected at least one applied field")
	}

	// Reload + verify additivity.
	mergedRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reread: %v", err)
	}
	var mergedTree map[string]any
	if err := yaml.Unmarshal(mergedRaw, &mergedTree); err != nil {
		t.Fatalf("unmarshal merged: %v", err)
	}
	mergedBody := mergedTree["profiles"].(map[string]any)["safe-default"].(map[string]any)
	if mergedBody["deny_dcl_targets_public"] != true {
		t.Fatalf("expected deny_dcl_targets_public=true after apply; got %v",
			mergedBody["deny_dcl_targets_public"])
	}
	exemptRaw, ok := mergedBody["exempt_resources"]
	if !ok {
		t.Fatalf("operator-customized exempt_resources was lost during apply")
	}
	exempt, _ := exemptRaw.([]any)
	if len(exempt) != 1 || exempt[0] != "public.my_custom_audit_table" {
		t.Fatalf("operator-customized exempt_resources mutated; got %v", exempt)
	}

	// After apply, doctor should report current.
	rep, err := Check(path)
	if err != nil {
		t.Fatalf("post-apply Check: %v", err)
	}
	if rep.HasSafetyFloorGap() {
		t.Fatalf("post-apply HasSafetyFloorGap should be false; got %+v", rep.MissingFields)
	}
}

func TestDoctor_Apply_BacksUp(t *testing.T) {
	path := freshProfilesPath(t)
	stripFieldFromProfile(t, path, "safe-default", "deny_dcl_targets_public")

	priorBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	now := time.Date(2026, 5, 22, 12, 34, 56, 0, time.UTC)
	result, err := Apply(path, ApplyOptions{Now: now})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.BackupPath == "" {
		t.Fatalf("expected non-empty backup path")
	}
	if !strings.HasSuffix(result.BackupPath, ".bak-20260522-123456") {
		t.Fatalf("backup path missing UTC timestamp suffix; got %q", result.BackupPath)
	}
	backupBytes, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backupBytes) != string(priorBytes) {
		t.Fatalf("backup contents differ from prior profile state")
	}
}

func TestDoctor_Acknowledge_SilencesUntilNewVersion(t *testing.T) {
	path := freshProfilesPath(t)
	stripFieldFromProfile(t, path, "safe-default", "deny_dcl_targets_public")
	if StartupBannerLine("dbounce", path) == "" {
		t.Fatalf("pre-ack: banner should fire")
	}
	if _, err := Acknowledge(path); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if line := StartupBannerLine("dbounce", path); line != "" {
		t.Fatalf("post-ack: banner should be silent; got %q", line)
	}
	// Simulate a version bump.
	ack := AcknowledgedVersionPath(path)
	if err := os.WriteFile(ack, []byte("OLDER-VERSION-STAMP\n"), 0o600); err != nil {
		t.Fatalf("write older ack: %v", err)
	}
	if line := StartupBannerLine("dbounce", path); line == "" {
		t.Fatalf("after version-bump simulation, banner should re-arm")
	}
}

func TestDoctor_CatalogCoversEmbeddedDefaults(t *testing.T) {
	// Defensive: every shippedDefaultsCatalog entry must reference a
	// profile that exists in the embedded defaults YAML. A typo here
	// would silently make the doctor skip the field (Check() returns
	// no gap when the profile is absent — that's the "operator deleted
	// the profile" path).
	var pf profileFile
	if err := yaml.Unmarshal(DefaultProfilesYAML(), &pf); err != nil {
		t.Fatalf("parse embedded defaults: %v", err)
	}
	for _, gap := range shippedDefaultsCatalog {
		if _, ok := pf.Profiles[gap.ProfileName]; !ok {
			t.Fatalf("catalog references profile %q absent from embedded defaults",
				gap.ProfileName)
		}
	}
}

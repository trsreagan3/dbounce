// Package profile — doctor.go
//
// `dbounce profile doctor` — diff-checks the operator's installed
// profile YAML against the embedded shipped defaults and reports
// missing fields without touching the file.
//
// Context: this exists because dbounce NEVER overwrites
// ~/.dbounce/profiles.yaml once it's been written (operator edits
// must survive). That's the right default for operator-customized
// state, but it silently turns into UPGRADE-BLINDNESS when a new
// safety floor (e.g. `deny_dcl_targets_public`, shipped in #302) is
// added to embedded defaults AFTER the operator's local file was
// written. The operator runs without the floor + has no breadcrumb
// that they should know about.
//
// Per task #321 / KNOWN-CAVEATS §A19 — the role-effectiveness eval
// 2026-05-22 surfaced this as a launch-blocker: an operator who
// installed dbounce pre-#302 was running WITHOUT the DCL floor
// because their profiles.yaml predated the embedded default that
// added it.
//
// Architecture (cross-product symmetric with kbouncer + ibounce +
// gbounce):
//
//   - Check() — compare installed profile YAML against embedded
//     defaults; return MissingFields[] + category for each.
//   - Apply() — additively merge missing fields into the on-disk
//     profile; back up the prior file BEFORE write. NEVER overwrites
//     operator-customized field VALUES (only adds absent KEYS).
//   - Acknowledge() — write ~/.dbounce/profiles/.acknowledged-version
//     tracking the operator's last-acknowledged shipped-defaults
//     version; future runs skip the warning until a new version
//     ships.
//   - HasSafetyFloorGap() — fast predicate used by the `dbounce run`
//     startup banner to decide whether to emit the one-line caveat.
//
// Field categories (load-bearing):
//
//   - "safety-floor" — denies that ENFORCE the safe-default
//     guarantees. Missing one = the safety claim is silently false.
//     EXAMPLES: deny_dcl_targets_public, deny_ast_mutating_nodes.
//     The startup banner fires ONLY for missing safety-floor fields.
//   - "detection" — observation features (burst detection, prompt-
//     injection sniffers). Operator may want to know but the
//     baseline still constrains the agent.
//   - "audit" — telemetry-shape changes (audit preset versions,
//     decision_source fields). Affects SIEM dashboards, not safety.
//   - "convenience" — defaults / naming / TTL. Pure-UX.
//
// Per [[creates-never-mutates]]: Apply() is additive only. Per
// [[security-team-positioning-safety-not-surveillance]]: framed as
// "your profile is behind" not "you are non-compliant."

package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FieldCategory classifies the urgency of a missing default field.
type FieldCategory string

const (
	// CategorySafetyFloor — denies that ENFORCE the safety guarantees.
	// Missing = the safety claim is silently false. Startup banner
	// fires for these.
	CategorySafetyFloor FieldCategory = "safety-floor"
	// CategoryDetection — observation features (burst detection, etc).
	CategoryDetection FieldCategory = "detection"
	// CategoryAudit — telemetry / decision_source shape.
	CategoryAudit FieldCategory = "audit"
	// CategoryConvenience — UX (TTLs, default names, etc).
	CategoryConvenience FieldCategory = "convenience"
)

// FieldGap describes one missing or behind-default field in the
// operator's installed profile relative to the embedded defaults.
type FieldGap struct {
	// ProfileName is the YAML profile the field lives on (e.g.
	// "safe-default").
	ProfileName string
	// Field is the YAML field name within that profile (e.g.
	// "deny_dcl_targets_public").
	Field string
	// Category is the urgency classification.
	Category FieldCategory
	// WhyMatters is the operator-readable rationale.
	WhyMatters string
	// AddedIn is the human-readable version + task ref ("dbounce
	// 0.7.0 (#302, 2026-05-22)").
	AddedIn string
	// DefaultValue is the YAML-marshaled default that Apply() would
	// add (so the operator can read what `--apply` would write).
	DefaultValue any
}

// Report is the output of Check().
type Report struct {
	// MissingFields is the list of FieldGap entries discovered.
	MissingFields []FieldGap
	// InstalledPath is the path to the on-disk profile file that was
	// checked. Empty when the operator hasn't materialized one yet
	// (every field still in embedded defaults — no gap to report).
	InstalledPath string
	// ShippedDefaultsVersion is the version tag stamped on the
	// embedded defaults at build time. Operators acknowledge a
	// SPECIFIC version; bumping it re-arms the warning.
	ShippedDefaultsVersion string
}

// HasSafetyFloorGap returns true when at least one MissingFields
// entry is CategorySafetyFloor. The startup banner uses this to
// decide whether to emit the one-line caveat.
func (r *Report) HasSafetyFloorGap() bool {
	if r == nil {
		return false
	}
	for _, g := range r.MissingFields {
		if g.Category == CategorySafetyFloor {
			return true
		}
	}
	return false
}

// shippedDefaultsCatalog is the source-of-truth list of default
// fields the doctor knows about. Adding a new safety floor to
// embedded defaults.yaml REQUIRES adding a row here; the test
// `TestDoctor_CatalogCoversEmbeddedDefaults` enforces this so an
// engineer can't ship a new floor without wiring the upgrade
// notification path.
//
// Stable order: by category (safety-floor first), then alphabetical
// by (ProfileName, Field). The fixed order makes test goldens
// deterministic + the operator-facing output predictable.
var shippedDefaultsCatalog = []FieldGap{
	{
		ProfileName: "safe-default",
		Field:       "deny_dcl_targets_public",
		Category:    CategorySafetyFloor,
		WhyMatters: "Prevents `GRANT * TO PUBLIC` and equivalent " +
			"privilege escalation — without this floor, parser " +
			"classified DCL as UNKNOWN and `GRANT ALL PRIVILEGES " +
			"ON DATABASE x TO PUBLIC` slipped through.",
		AddedIn:      "dbounce 0.7.0 (#302, 2026-05-22)",
		DefaultValue: true,
	},
	{
		ProfileName: "safe-default",
		Field:       "deny_ast_mutating_nodes",
		Category:    CategorySafetyFloor,
		WhyMatters: "AST-walk Layer 2 backstop — catches CTE-wrapped " +
			"writes whose top-level keyword is WITH/SELECT but the " +
			"tree contains an UPDATE/DELETE/INSERT node. Without " +
			"this, a CTE-wrapped DELETE looks like a SELECT to the " +
			"top-level keyword classifier.",
		AddedIn:      "dbounce 0.5.0 (D-Slice 7, 2026-05-17)",
		DefaultValue: true,
	},
	{
		ProfileName: "safe-default",
		Field:       "allow_baseline",
		Category:    CategorySafetyFloor,
		WhyMatters: "Names the built-in pure-SELECT classifier. " +
			"Without it, only deny_actions + deny_keywords run — " +
			"any statement type the deny list doesn't enumerate " +
			"passes by default.",
		AddedIn:      "dbounce 0.5.0 (D-Slice 7, 2026-05-17)",
		DefaultValue: "sql_read_only",
	},
}

// ShippedDefaultsVersion is the version stamp baked into the
// embedded defaults. Bump this whenever defaults.yaml changes in a
// way operators should re-acknowledge. The doctor stores this
// alongside `--acknowledge` so the next bump re-arms the warning.
const ShippedDefaultsVersion = "2026-05-22-321"

// Check inspects the installed profile YAML at path against the
// shippedDefaultsCatalog. Returns a Report with zero MissingFields
// when the operator's file is current.
//
// When path is empty or the file doesn't exist, Check returns a
// zero-length Report — there's nothing installed to be behind.
// `dbounce run`'s first-run path writes embedded defaults to disk
// (EnsureDefaultProfilesFile), so subsequent invocations DO have a
// file to check; the empty-path case is for fresh installs only.
func Check(path string) (*Report, error) {
	r := &Report{
		InstalledPath:          path,
		ShippedDefaultsVersion: ShippedDefaultsVersion,
	}
	if path == "" {
		return r, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return r, nil
		}
		return nil, fmt.Errorf("dbounce: read profiles %q: %w", path, err)
	}
	var pf profileFile
	if err := yaml.Unmarshal(raw, &pf); err != nil {
		return nil, fmt.Errorf("dbounce: parse profiles yaml: %w", err)
	}
	// We need the raw map (not the parsed Profile struct) so absent
	// keys are distinguishable from explicit-false / explicit-empty
	// values an operator may have written.
	var rawTree map[string]any
	if err := yaml.Unmarshal(raw, &rawTree); err != nil {
		return nil, fmt.Errorf("dbounce: parse profiles tree: %w", err)
	}
	profilesObj, _ := rawTree["profiles"].(map[string]any)

	for _, want := range shippedDefaultsCatalog {
		profileBody, _ := profilesObj[want.ProfileName].(map[string]any)
		// If the operator removed the profile entirely we treat
		// every default field as present (the profile being absent
		// is its own intentional act — surfacing every catalog row
		// for a deleted profile would be misleading noise).
		if profileBody == nil {
			continue
		}
		if _, present := profileBody[want.Field]; present {
			continue
		}
		r.MissingFields = append(r.MissingFields, want)
	}
	// Sort: safety-floor first (within stable catalog order),
	// then other categories. The catalog already sorts within
	// category; this is the secondary sort by category.
	sort.SliceStable(r.MissingFields, func(i, j int) bool {
		return categoryRank(r.MissingFields[i].Category) <
			categoryRank(r.MissingFields[j].Category)
	})
	return r, nil
}

func categoryRank(c FieldCategory) int {
	switch c {
	case CategorySafetyFloor:
		return 0
	case CategoryDetection:
		return 1
	case CategoryAudit:
		return 2
	case CategoryConvenience:
		return 3
	}
	return 9
}

// ApplyOptions tunes Apply().
type ApplyOptions struct {
	// Now is injected for testable backup-filename timestamps.
	// Zero value → time.Now().
	Now time.Time
}

// ApplyResult describes what Apply() did.
type ApplyResult struct {
	// BackupPath is the path the prior profiles.yaml was copied to
	// before merge (~/.dbounce/profiles.yaml.bak-YYYYMMDD-HHMMSS).
	BackupPath string
	// AppliedFields is the subset of Report.MissingFields that
	// Apply() actually added.
	AppliedFields []FieldGap
}

// Apply additively merges missing default fields from the catalog
// into the profile YAML at path. NEVER overwrites a field the
// operator explicitly set (the merge skips any field the parsed
// profile already has under any key). Backs up the prior file
// before writing.
//
// Per [[creates-never-mutates]]: ADDITIVE only. If the operator set
// `deny_dcl_targets_public: false` deliberately, the field is
// PRESENT in the YAML map → Apply() skips it. The doctor cannot
// override an operator's explicit choice.
func Apply(path string, opts ApplyOptions) (*ApplyResult, error) {
	if path == "" {
		return nil, errors.New("dbounce: Apply requires a profiles.yaml path")
	}
	rep, err := Check(path)
	if err != nil {
		return nil, err
	}
	if len(rep.MissingFields) == 0 {
		return &ApplyResult{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dbounce: read profiles %q: %w", path, err)
	}
	var rawTree map[string]any
	if err := yaml.Unmarshal(raw, &rawTree); err != nil {
		return nil, fmt.Errorf("dbounce: parse profiles tree: %w", err)
	}
	profilesObj, _ := rawTree["profiles"].(map[string]any)
	if profilesObj == nil {
		profilesObj = map[string]any{}
		rawTree["profiles"] = profilesObj
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	backupPath := backupPathFor(path, now)
	if err := os.WriteFile(backupPath, raw, 0o600); err != nil {
		return nil, fmt.Errorf("dbounce: write backup %q: %w", backupPath, err)
	}

	applied := make([]FieldGap, 0, len(rep.MissingFields))
	for _, gap := range rep.MissingFields {
		profileBody, _ := profilesObj[gap.ProfileName].(map[string]any)
		if profileBody == nil {
			// Operator deleted the profile entry — don't recreate it
			// implicitly (Check() already skipped these; defensive).
			continue
		}
		if _, present := profileBody[gap.Field]; present {
			continue
		}
		profileBody[gap.Field] = gap.DefaultValue
		profilesObj[gap.ProfileName] = profileBody
		applied = append(applied, gap)
	}

	out, err := yaml.Marshal(rawTree)
	if err != nil {
		return nil, fmt.Errorf("dbounce: encode profiles yaml: %w", err)
	}
	// Atomic write — same posture as writeInstalledProfiles.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".profiles-*.yaml.tmp")
	if err != nil {
		return nil, fmt.Errorf("dbounce: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("dbounce: write temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("dbounce: chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("dbounce: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, fmt.Errorf("dbounce: rename into place: %w", err)
	}
	return &ApplyResult{BackupPath: backupPath, AppliedFields: applied}, nil
}

func backupPathFor(path string, now time.Time) string {
	stamp := now.UTC().Format("20060102-150405")
	return path + ".bak-" + stamp
}

// AcknowledgedVersionPath returns the path to the per-operator
// acknowledged-version file. Lives next to profiles.yaml so a fresh
// install's empty home dir doesn't accidentally carry over an old
// acknowledgement from a previous machine.
func AcknowledgedVersionPath(profilesPath string) string {
	if profilesPath == "" {
		return ""
	}
	dir := filepath.Dir(profilesPath)
	return filepath.Join(dir, ".profiles-acknowledged-version")
}

// Acknowledge writes the current ShippedDefaultsVersion to the
// acknowledged-version file. Future Check() runs read this; the
// startup banner skips warning until a new version bumps the stamp.
func Acknowledge(profilesPath string) (string, error) {
	ack := AcknowledgedVersionPath(profilesPath)
	if ack == "" {
		return "", errors.New("dbounce: Acknowledge requires a profiles.yaml path")
	}
	if dir := filepath.Dir(ack); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("dbounce: mkdir %q: %w", dir, err)
		}
	}
	if err := os.WriteFile(ack, []byte(ShippedDefaultsVersion+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("dbounce: write acknowledgement: %w", err)
	}
	return ack, nil
}

// IsAcknowledged returns true when the on-disk acknowledged-version
// matches the current ShippedDefaultsVersion. Used by `dbounce run`
// startup-banner suppression.
func IsAcknowledged(profilesPath string) bool {
	ack := AcknowledgedVersionPath(profilesPath)
	if ack == "" {
		return false
	}
	raw, err := os.ReadFile(ack)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(raw)) == ShippedDefaultsVersion
}

// FormatReport renders a Report as the multi-line text shown by
// `dbounce profile doctor`. Stable shape for test goldens.
func FormatReport(product string, r *Report) string {
	if r == nil || len(r.MissingFields) == 0 {
		return fmt.Sprintf(
			"%s: profile doctor — installed profile matches shipped defaults (version %s).\n",
			product, ShippedDefaultsVersion)
	}
	var b strings.Builder
	fmt.Fprintf(&b,
		"%s: profile doctor — your installed profile is missing %d field(s) "+
			"that ship in this version (defaults version %s):\n\n",
		product, len(r.MissingFields), ShippedDefaultsVersion)
	for _, gap := range r.MissingFields {
		fmt.Fprintf(&b, "  - profile=%s field=%s\n", gap.ProfileName, gap.Field)
		fmt.Fprintf(&b, "    category:   %s\n", gap.Category)
		fmt.Fprintf(&b, "    why:        %s\n", gap.WhyMatters)
		fmt.Fprintf(&b, "    added in:   %s\n", gap.AddedIn)
		fmt.Fprintf(&b, "    default:    %v\n\n", gap.DefaultValue)
	}
	fmt.Fprintf(&b, "To accept the new defaults: %s profile doctor --apply\n", product)
	fmt.Fprintf(&b, "To suppress this warning:   %s profile doctor --acknowledge\n", product)
	return b.String()
}

// StartupBannerLine returns the one-line caveat the bouncer's `run`
// command emits at startup when the installed profile is missing a
// safety-floor field AND the operator hasn't acknowledged the
// current shipped-defaults version. Returns "" when no banner
// should fire.
//
// Framing per [[security-team-positioning-safety-not-surveillance]]:
// "your profile is behind" — NOT "you are non-compliant."
func StartupBannerLine(product string, profilesPath string) string {
	if profilesPath == "" {
		return ""
	}
	if IsAcknowledged(profilesPath) {
		return ""
	}
	rep, err := Check(profilesPath)
	if err != nil {
		return ""
	}
	if !rep.HasSafetyFloorGap() {
		return ""
	}
	return fmt.Sprintf(
		"caveat: your safe-default profile is missing fields shipped in "+
			"this version — run `%s profile doctor` for details "+
			"(KNOWN-CAVEATS §A19)",
		product)
}

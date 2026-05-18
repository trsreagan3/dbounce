// Tests for `dbounce config export | import` per
// [[basic-app-hygiene-features]] TIER 1 #1.
//
// Three layers under test:
//
//  1. buildConfigBundle: end-to-end read of state.db + profiles.yaml
//     into the export shape. Verifies the per-dialect rule pack
//     reference, per-rule + per-profile dialect inference, and the
//     synthesized full-user passthrough exclusion.
//
//  2. validateBundle: format magic, format_version ceiling,
//     schema_version ceiling, dialect-mismatch refusal, and --force
//     override.
//
//  3. End-to-end CLI surface: `config export -o FILE` then `config
//     import -i FILE` round-trips rules + local profiles, skips
//     same-named profiles by default, and emits exactly ONE
//     ADMIN_ACTION row per subcommand invocation (per the existing
//     admin-action contract).
//
// Per-dialect handling is asserted explicitly in the export JSON
// assertions — rule patterns carrying a dialect prefix surface in
// Dialects; the runtime_config.dialect lands in the ADMIN_ACTION
// row's Dialects field for SIEM filtering.

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

func TestConfigCmd_TreeWired(t *testing.T) {
	c := newConfigCmd()
	assert.Equal(t, "config", c.Name())
	subs := map[string]bool{}
	for _, s := range c.Commands() {
		subs[s.Name()] = true
	}
	for _, sub := range []string{"export", "import"} {
		assert.True(t, subs[sub], "config must wire %s subcommand", sub)
	}
}

func TestBuildConfigBundle_EmptyFreshDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")

	bundle, err := buildConfigBundle(buildBundleParams{
		DBPath:       dbPath,
		ProfilesPath: profilesPath,
		Dialect:      proxy.DialectPostgres,
		ExportedBy:   "tester",
	})
	require.NoError(t, err)
	require.NotNil(t, bundle)
	assert.Equal(t, configBundleFormat, bundle.Format)
	assert.Equal(t, configBundleFormatVersion, bundle.FormatVersion)
	assert.Equal(t, store.SchemaVersion, bundle.SchemaVersion)
	assert.Equal(t, "postgres", bundle.RuntimeConfig.Dialect)
	assert.Equal(t, "tester", bundle.ExportedBy)
	assert.Empty(t, bundle.Rules,
		"fresh DB exports zero rules")
	// safe-default ships in the embedded defaults (full-user is the
	// synthesized passthrough + intentionally excluded).
	require.NotNil(t, bundle.Profiles.Items)
	names := map[string]bool{}
	for _, p := range bundle.Profiles.Items {
		names[p.Name] = true
	}
	assert.False(t, names[profile.FullUserProfileName],
		"export MUST exclude the synthesized full-user sentinel")
	require.NotNil(t, bundle.RulePack)
	assert.Equal(t, "postgres", bundle.RulePack.Name)
	assert.True(t, bundle.RulePack.Embedded)
	assert.Nil(t, bundle.Pause,
		"fresh DB has no active pause")
}

func TestBuildConfigBundle_RuleDialectInference(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")

	// Seed three rules with different dialect signal.
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	for _, r := range []dbrules.ProxyRule{
		{Pattern: "SELECT:*", Effect: dbrules.EffectAllow, Origin: dbrules.OriginUser, Note: "agnostic"},
		{Pattern: "SELECT:snowflake.public.*", Effect: dbrules.EffectAllow, Origin: dbrules.OriginUser, Note: "snowflake"},
		{Pattern: "DELETE:pg.audit.*", Effect: dbrules.EffectDeny, Origin: dbrules.OriginUser, Note: "postgres"},
	} {
		_, err := st.AddRule(r)
		require.NoError(t, err)
	}
	require.NoError(t, st.Close())

	bundle, err := buildConfigBundle(buildBundleParams{
		DBPath:       dbPath,
		ProfilesPath: profilesPath,
		Dialect:      proxy.DialectSnowflake,
	})
	require.NoError(t, err)
	require.Len(t, bundle.Rules, 3)

	byPattern := map[string]ConfigRule{}
	for _, r := range bundle.Rules {
		byPattern[r.Pattern] = r
	}
	assert.Nil(t, byPattern["SELECT:*"].Dialects,
		"glob-only pattern carries no dialect signal")
	assert.Equal(t, []string{"snowflake"}, byPattern["SELECT:snowflake.public.*"].Dialects)
	assert.Equal(t, []string{"postgres"}, byPattern["DELETE:pg.audit.*"].Dialects)

	// Per-dialect rule pack reference reflects the export-time dialect
	// choice, regardless of which dialects individual rules touch.
	require.NotNil(t, bundle.RulePack)
	assert.Equal(t, "snowflake", bundle.RulePack.Name)
	assert.Equal(t, "experimental", bundle.RulePack.CalibrationStatus)
	assert.NotEmpty(t, bundle.RulePack.Version)
}

func TestValidateBundle_RejectsWrongFormat(t *testing.T) {
	b := &ConfigBundle{Format: "kbounce.config", FormatVersion: 1, SchemaVersion: 1, RuntimeConfig: RuntimeConfigBlock{Dialect: "postgres"}}
	err := validateBundle(b, proxy.DialectPostgres, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "format")
}

func TestValidateBundle_RejectsFutureFormatVersion(t *testing.T) {
	b := &ConfigBundle{Format: configBundleFormat, FormatVersion: configBundleFormatVersion + 1, SchemaVersion: 1, RuntimeConfig: RuntimeConfigBlock{Dialect: "postgres"}}
	err := validateBundle(b, proxy.DialectPostgres, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "newer than this binary supports")
}

func TestValidateBundle_RejectsFutureSchemaVersion(t *testing.T) {
	b := &ConfigBundle{Format: configBundleFormat, FormatVersion: 1, SchemaVersion: store.SchemaVersion + 5, RuntimeConfig: RuntimeConfigBlock{Dialect: "postgres"}}
	err := validateBundle(b, proxy.DialectPostgres, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema_version")
}

func TestValidateBundle_RejectsDialectMismatch(t *testing.T) {
	b := &ConfigBundle{Format: configBundleFormat, FormatVersion: 1, SchemaVersion: 1, RuntimeConfig: RuntimeConfigBlock{Dialect: "mysql"}}
	err := validateBundle(b, proxy.DialectPostgres, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dialect")
	assert.Contains(t, err.Error(), "force")
}

func TestValidateBundle_ForceOverridesDialectMismatch(t *testing.T) {
	b := &ConfigBundle{Format: configBundleFormat, FormatVersion: 1, SchemaVersion: 1, RuntimeConfig: RuntimeConfigBlock{Dialect: "mysql"}}
	err := validateBundle(b, proxy.DialectPostgres, true)
	require.NoError(t, err)
}

func TestValidateBundle_RequiresDialect(t *testing.T) {
	b := &ConfigBundle{Format: configBundleFormat, FormatVersion: 1, SchemaVersion: 1, RuntimeConfig: RuntimeConfigBlock{Dialect: ""}}
	err := validateBundle(b, proxy.DialectPostgres, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dialect")
}

func TestConfigExportCmd_WritesBundleAndEnqueuesAdminAction(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	outPath := filepath.Join(dir, "bundle.json")

	// Seed one rule so the export isn't empty.
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	_, err = st.AddRule(dbrules.ProxyRule{
		Pattern: "SELECT:mysql.app.*", Effect: dbrules.EffectAllow,
		Origin: dbrules.OriginUser, Note: "seed",
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	cmd := newConfigExportCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--profiles-path", profilesPath,
		"--dialect", "mysql",
		"--output", outPath,
		"--actor", "tester",
	})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "wrote dbounce config bundle")

	// File on disk parses + carries the seeded rule.
	raw, err := os.ReadFile(outPath)
	require.NoError(t, err)
	var bundle ConfigBundle
	require.NoError(t, json.Unmarshal(raw, &bundle))
	assert.Equal(t, "mysql", bundle.RuntimeConfig.Dialect)
	require.Len(t, bundle.Rules, 1)
	assert.Equal(t, "SELECT:mysql.app.*", bundle.Rules[0].Pattern)
	assert.Equal(t, []string{"mysql"}, bundle.Rules[0].Dialects)
	require.NotNil(t, bundle.RulePack)
	assert.Equal(t, "mysql", bundle.RulePack.Name)

	// File perms are 0600 (matches profiles.yaml + state.db convention).
	fi, err := os.Stat(outPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	// ADMIN_ACTION row landed in the queue with the dialect stamped.
	got := drainOneAdminAction(t, dbPath)
	assert.Equal(t, "config.export", got["action"])
	assert.Equal(t, "tester", got["actor"])
	assert.Equal(t, "config", got["resource_type"])
	assert.Equal(t, "mysql", got["resource_id"])
	// dialects is a one-element array carrying the runtime dialect.
	dialects, ok := got["dialects"].([]any)
	require.True(t, ok, "dialects must be a JSON array")
	require.Len(t, dialects, 1)
	assert.Equal(t, "mysql", dialects[0])
}

func TestConfigExportCmd_StdoutMode(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")

	cmd := newConfigExportCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--profiles-path", profilesPath,
		"--dialect", "postgres",
		"--output", "-",
		"--actor", "tester",
	})
	require.NoError(t, cmd.Execute())

	var bundle ConfigBundle
	require.NoError(t, json.Unmarshal(out.Bytes(), &bundle))
	assert.Equal(t, configBundleFormat, bundle.Format)
	assert.Equal(t, "postgres", bundle.RuntimeConfig.Dialect)
}

func TestConfigImportCmd_AppendsRulesAndSkipsExisting(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	bundlePath := filepath.Join(dir, "bundle.json")

	// Build a bundle with two rules — one new + one duplicate of an
	// already-present rule.
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	_, err = st.AddRule(dbrules.ProxyRule{
		Pattern: "SELECT:*", Effect: dbrules.EffectAllow, Origin: dbrules.OriginUser,
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	bundle := &ConfigBundle{
		Format:        configBundleFormat,
		FormatVersion: 1,
		SchemaVersion: store.SchemaVersion,
		ExportedAt:    "2026-05-18T00:00:00Z",
		RuntimeConfig: RuntimeConfigBlock{Dialect: "postgres"},
		Rules: []ConfigRule{
			{Pattern: "SELECT:*", Effect: "allow", Origin: "user"},                   // duplicate
			{Pattern: "DELETE:public.audit_log", Effect: "deny", Origin: "user"},     // new
		},
		Profiles: ProfilesBlock{},
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bundlePath, raw, 0o600))

	cmd := newConfigImportCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--profiles-path", profilesPath,
		"--dialect", "postgres",
		"--input", bundlePath,
		"--actor", "tester",
	})
	require.NoError(t, cmd.Execute())
	s := out.String()
	assert.Contains(t, s, "rules:    1 added, 1 skipped")

	// Verify the duplicate was NOT inserted twice + the new rule landed.
	st, err = store.Open(dbPath)
	require.NoError(t, err)
	rs, err := st.ListRules()
	require.NoError(t, err)
	require.NoError(t, st.Close())
	patterns := map[string]int{}
	for _, r := range rs {
		patterns[r.Rule.Pattern]++
	}
	assert.Equal(t, 1, patterns["SELECT:*"], "duplicate rule MUST be deduped on import")
	assert.Equal(t, 1, patterns["DELETE:public.audit_log"], "new rule MUST be inserted")

	// ADMIN_ACTION row landed with action=config.import + dialect=postgres.
	got := drainOneAdminAction(t, dbPath)
	assert.Equal(t, "config.import", got["action"])
	assert.Equal(t, "postgres", got["resource_id"])
	dialects, _ := got["dialects"].([]any)
	require.Len(t, dialects, 1)
	assert.Equal(t, "postgres", dialects[0])
}

func TestConfigImportCmd_DryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	bundlePath := filepath.Join(dir, "bundle.json")

	bundle := &ConfigBundle{
		Format:        configBundleFormat,
		FormatVersion: 1,
		SchemaVersion: store.SchemaVersion,
		ExportedAt:    "2026-05-18T00:00:00Z",
		RuntimeConfig: RuntimeConfigBlock{Dialect: "postgres"},
		Rules: []ConfigRule{
			{Pattern: "SELECT:*", Effect: "allow"},
		},
		Profiles: ProfilesBlock{},
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bundlePath, raw, 0o600))

	cmd := newConfigImportCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--profiles-path", profilesPath,
		"--dialect", "postgres",
		"--input", bundlePath,
		"--dry-run",
		"--actor", "tester",
	})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "DRY-RUN:")

	// Nothing landed in the rules table.
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	rs, err := st.ListRules()
	require.NoError(t, err)
	st.Close()
	assert.Empty(t, rs, "dry-run MUST NOT write any rules")

	// ADMIN_ACTION row STILL fires — Result=noop so a SIEM can filter
	// planning activity from apply activity.
	got := drainOneAdminAction(t, dbPath)
	assert.Equal(t, "config.import", got["action"])
	assert.Equal(t, "noop", got["result"])
	details, _ := got["details"].(map[string]any)
	require.NotNil(t, details)
	assert.Equal(t, true, details["dry_run"])
}

func TestConfigImportCmd_DialectMismatchRefused(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	bundlePath := filepath.Join(dir, "bundle.json")

	bundle := &ConfigBundle{
		Format:        configBundleFormat,
		FormatVersion: 1,
		SchemaVersion: store.SchemaVersion,
		ExportedAt:    "2026-05-18T00:00:00Z",
		RuntimeConfig: RuntimeConfigBlock{Dialect: "snowflake"},
		Profiles:      ProfilesBlock{},
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bundlePath, raw, 0o600))

	cmd := newConfigImportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--dialect", "postgres",
		"--input", bundlePath,
	})
	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dialect")
	// --force overrides.
	cmd2 := newConfigImportCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{
		"--db", dbPath,
		"--dialect", "postgres",
		"--input", bundlePath,
		"--force",
	})
	require.NoError(t, cmd2.Execute())
}

func TestConfigRoundTrip_RulesAndProfilesPreserved(t *testing.T) {
	dir := t.TempDir()
	srcDB := filepath.Join(dir, "src.db")
	srcProfiles := filepath.Join(dir, "src-profiles.yaml")
	bundlePath := filepath.Join(dir, "bundle.json")
	dstDB := filepath.Join(dir, "dst.db")
	dstProfiles := filepath.Join(dir, "dst-profiles.yaml")

	// SOURCE: seed two rules + one local profile.
	st, err := store.Open(srcDB)
	require.NoError(t, err)
	_, err = st.AddRule(dbrules.ProxyRule{
		Pattern: "SELECT:public.*", Effect: dbrules.EffectAllow, Origin: dbrules.OriginUser,
		Note: "round-trip seed",
	})
	require.NoError(t, err)
	_, err = st.AddRule(dbrules.ProxyRule{
		Pattern: "DELETE:postgres.audit.*", Effect: dbrules.EffectDeny, Origin: dbrules.OriginUser,
	})
	require.NoError(t, err)
	st.Close()

	// Seed a local profile via the writer adapter (same path the
	// `presets apply` + `rules recommend --save-as-profile` surfaces
	// use).
	profiles, err := profile.LoadProfiles(srcProfiles)
	require.NoError(t, err)
	require.NoError(t, profiles.AddLocalProfile(srcProfiles, &profile.Profile{
		Name:                 "round-trip-pg",
		Description:          "round-trip test profile",
		AllowBaseline:        profile.BaselineSQLReadOnly,
		DenyASTMutatingNodes: true,
		DenyKeywords:         []string{"prod"},
	}))

	// EXPORT.
	exp := newConfigExportCmd()
	expOut := &bytes.Buffer{}
	exp.SetOut(expOut)
	exp.SetErr(&bytes.Buffer{})
	exp.SetArgs([]string{
		"--db", srcDB,
		"--profiles-path", srcProfiles,
		"--dialect", "postgres",
		"--output", bundlePath,
		"--actor", "tester",
	})
	require.NoError(t, exp.Execute())

	// Drain the source-side ADMIN_ACTION row so the dst-side import
	// drain assertion sees only the import event.
	_ = drainOneAdminAction(t, srcDB)

	// IMPORT into the destination DB + profiles.yaml.
	imp := newConfigImportCmd()
	impOut := &bytes.Buffer{}
	imp.SetOut(impOut)
	imp.SetErr(&bytes.Buffer{})
	imp.SetArgs([]string{
		"--db", dstDB,
		"--profiles-path", dstProfiles,
		"--dialect", "postgres",
		"--input", bundlePath,
		"--actor", "tester",
	})
	require.NoError(t, imp.Execute())
	assert.Contains(t, impOut.String(), "rules:    2 added")
	assert.Contains(t, impOut.String(), "profiles: 1 added")

	// Verify rules landed.
	st, err = store.Open(dstDB)
	require.NoError(t, err)
	rs, err := st.ListRules()
	require.NoError(t, err)
	st.Close()
	require.Len(t, rs, 2)

	// Verify profile landed.
	dstP, err := profile.LoadProfiles(dstProfiles)
	require.NoError(t, err)
	assert.Contains(t, dstP.All, "round-trip-pg")
	pr := dstP.All["round-trip-pg"]
	assert.Equal(t, "round-trip test profile", pr.Description)
	assert.Equal(t, profile.BaselineSQLReadOnly, pr.AllowBaseline)
	assert.True(t, pr.DenyASTMutatingNodes)
	assert.Equal(t, []string{"prod"}, pr.DenyKeywords)
}

func TestConfigImportCmd_NonLocalProfileSkipped(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	bundlePath := filepath.Join(dir, "bundle.json")

	bundle := &ConfigBundle{
		Format:        configBundleFormat,
		FormatVersion: 1,
		SchemaVersion: store.SchemaVersion,
		ExportedAt:    "2026-05-18T00:00:00Z",
		RuntimeConfig: RuntimeConfigBlock{Dialect: "postgres"},
		Profiles: ProfilesBlock{
			Items: []ConfigProfile{
				{
					Name:   "from-url",
					Source: "https://example.invalid/profiles.yaml",
				},
			},
		},
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bundlePath, raw, 0o600))

	cmd := newConfigImportCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--profiles-path", profilesPath,
		"--dialect", "postgres",
		"--input", bundlePath,
		"--actor", "tester",
	})
	require.NoError(t, cmd.Execute())
	s := out.String()
	assert.Contains(t, s, "profiles: 0 added, 1 skipped")
	assert.Contains(t, s, "non-local source")

	// Verify nothing landed in profiles.yaml.
	ps, err := profile.LoadProfiles(profilesPath)
	require.NoError(t, err)
	assert.NotContains(t, ps.All, "from-url")
}

func TestRuleFingerprint_StableAcrossNoteAndOrigin(t *testing.T) {
	a := dbrules.ProxyRule{Pattern: "SELECT:*", Effect: dbrules.EffectAllow, Origin: dbrules.OriginUser, Note: "first"}
	b := dbrules.ProxyRule{Pattern: "SELECT:*", Effect: dbrules.EffectAllow, Origin: dbrules.OriginPreset, Note: "second"}
	assert.Equal(t, ruleFingerprint(a), ruleFingerprint(b),
		"fingerprint MUST ignore documentation fields so a re-imported rule with a tweaked note still dedupes")
}

func TestRuleFingerprint_ChangesWithGatingSemantics(t *testing.T) {
	base := dbrules.ProxyRule{Pattern: "SELECT:*", Effect: dbrules.EffectAllow, SchemaScope: "public"}
	// Different scope → different fingerprint.
	scoped := base
	scoped.SchemaScope = "reports"
	assert.NotEqual(t, ruleFingerprint(base), ruleFingerprint(scoped))
	// Different effect → different fingerprint.
	denied := base
	denied.Effect = dbrules.EffectDeny
	assert.NotEqual(t, ruleFingerprint(base), ruleFingerprint(denied))
}

// TestConfigExport_DialectPackVersions verifies each supported dialect
// resolves to a non-empty pack reference. Per-dialect handling
// invariant: every dialect the bundle records MUST round-trip a
// readable pack name so a downstream reviewer can pin the gating
// surface.
func TestConfigExport_DialectPackVersions(t *testing.T) {
	for _, d := range []proxy.Dialect{
		proxy.DialectPostgres, proxy.DialectMySQL,
		proxy.DialectSnowflake, proxy.DialectBigQuery,
	} {
		ref := rulePackFor(d)
		require.NotNil(t, ref, "dialect %q must have a pack reference", d)
		assert.Equal(t, string(d), ref.Name)
		assert.True(t, ref.Embedded)
		if d == proxy.DialectMySQL || d == proxy.DialectSnowflake || d == proxy.DialectBigQuery {
			assert.NotEmpty(t, ref.Version, "dialect %q must carry pack version", d)
			assert.NotEmpty(t, ref.CalibrationStatus, "dialect %q must carry calibration status", d)
		}
	}
}

func TestWriteBundleAtomic_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "b.json")
	require.NoError(t, writeBundleAtomic(p, []byte("first")))
	require.NoError(t, writeBundleAtomic(p, []byte("second")))
	got, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "second", string(got))
	fi, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestConfigImportCmd_RequiresInput(t *testing.T) {
	cmd := newConfigImportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--dialect", "postgres"})
	err := cmd.Execute()
	require.Error(t, err)
	// cobra surfaces "required flag(s) \"input\" not set" — message
	// shape stable across cobra v1.x.
	assert.True(t,
		strings.Contains(err.Error(), "input") ||
			strings.Contains(err.Error(), "required"),
		"expected the missing --input flag to be surfaced; got %q", err.Error())
}

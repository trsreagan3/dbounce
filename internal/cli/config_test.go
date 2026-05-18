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
	assert.Equal(t, ConfigProduct, bundle.Product,
		"post-#288: product is the cross-product magic; was `format` pre-reconciliation")
	assert.Equal(t, ConfigSchemaVersion, bundle.SchemaVersion,
		"post-#288: schema_version is string semver \"1.0\"; was int `format_version: 1` pre-reconciliation")
	assert.Equal(t, store.SchemaVersion, bundle.StoreSchemaVersion,
		"post-#288: store-schema version is `store_schema_version`; was `schema_version` (int) pre-reconciliation")
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

// canonBundle returns the post-#288 minimal valid bundle. Tests use it
// as a base + override the fields they're exercising. Replaces the
// pre-#288 `Format`/`FormatVersion`/int-`SchemaVersion` literal sets.
func canonBundle() *ConfigBundle {
	return &ConfigBundle{
		SchemaVersion:      ConfigSchemaVersion,
		Product:            ConfigProduct,
		StoreSchemaVersion: 1,
		RuntimeConfig:      RuntimeConfigBlock{Dialect: "postgres"},
	}
}

func TestValidateBundle_RejectsWrongProduct(t *testing.T) {
	b := canonBundle()
	b.Product = "kbounce"
	err := validateBundle(b, proxy.DialectPostgres, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "product",
		"post-#288: cross-product reject keys on `product` not `format`")
}

func TestValidateBundle_RejectsFutureSchemaVersion(t *testing.T) {
	b := canonBundle()
	b.SchemaVersion = "2.0"
	err := validateBundle(b, proxy.DialectPostgres, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema_version",
		"post-#288: wire-format-version mismatch surfaces on `schema_version`")
}

func TestValidateBundle_RejectsFutureStoreSchemaVersion(t *testing.T) {
	b := canonBundle()
	b.StoreSchemaVersion = store.SchemaVersion + 5
	err := validateBundle(b, proxy.DialectPostgres, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store_schema_version",
		"post-#288: store-version mismatch surfaces on `store_schema_version` "+
			"(renamed from pre-#288 `schema_version` to break field-name collision)")
}

func TestValidateBundle_RejectsDialectMismatch(t *testing.T) {
	b := canonBundle()
	b.RuntimeConfig.Dialect = "mysql"
	err := validateBundle(b, proxy.DialectPostgres, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dialect")
	assert.Contains(t, err.Error(), "force")
}

func TestValidateBundle_ForceOverridesDialectMismatch(t *testing.T) {
	b := canonBundle()
	b.RuntimeConfig.Dialect = "mysql"
	err := validateBundle(b, proxy.DialectPostgres, true)
	require.NoError(t, err)
}

func TestValidateBundle_RequiresDialect(t *testing.T) {
	b := canonBundle()
	b.RuntimeConfig.Dialect = ""
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
	assert.Equal(t, ConfigProduct, bundle.Product,
		"post-#288: cross-product magic is `product` (was `format`)")
	assert.Equal(t, ConfigSchemaVersion, bundle.SchemaVersion,
		"post-#288: wire-format version is string semver \"1.0\" (was int `format_version: 1`)")
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
		SchemaVersion:      ConfigSchemaVersion,
		Product:            ConfigProduct,
		StoreSchemaVersion: store.SchemaVersion,
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
		"--in", bundlePath,
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
		SchemaVersion:      ConfigSchemaVersion,
		Product:            ConfigProduct,
		StoreSchemaVersion: store.SchemaVersion,
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
		"--in", bundlePath,
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
		SchemaVersion:      ConfigSchemaVersion,
		Product:            ConfigProduct,
		StoreSchemaVersion: store.SchemaVersion,
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
		"--in", bundlePath,
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
		"--in", bundlePath,
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
		"--in", bundlePath,
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
		SchemaVersion:      ConfigSchemaVersion,
		Product:            ConfigProduct,
		StoreSchemaVersion: store.SchemaVersion,
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
		"--in", bundlePath,
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

func TestConfigImportCmd_RequiresIn(t *testing.T) {
	cmd := newConfigImportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--dialect", "postgres"})
	err := cmd.Execute()
	require.Error(t, err)
	// Post-#288: the RunE rather than cobra's required-flag mechanism
	// surfaces "--in PATH is required" (because --in and --input are
	// aliases — neither being individually required by cobra; the RunE
	// rejects when both are unset). Accept either form to ride a
	// future cobra phrasing change.
	assert.True(t,
		strings.Contains(err.Error(), "--in") ||
			strings.Contains(err.Error(), "required"),
		"expected the missing --in flag to be surfaced; got %q", err.Error())
}

// TestConfigImportCmd_DeprecatedInputAliasStillWorks asserts that the
// pre-#288 `--input PATH` form (and its `-i` shorthand) still works.
// A deprecation warning lands on stderr so the operator knows to
// update the script before a future major version drops the alias.
func TestConfigImportCmd_DeprecatedInputAliasStillWorks(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	bundlePath := filepath.Join(dir, "bundle.json")

	bundle := &ConfigBundle{
		SchemaVersion:      ConfigSchemaVersion,
		Product:            ConfigProduct,
		StoreSchemaVersion: store.SchemaVersion,
		ExportedAt:         "2026-05-18T00:00:00Z",
		RuntimeConfig:      RuntimeConfigBlock{Dialect: "postgres"},
		Profiles:           ProfilesBlock{},
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bundlePath, raw, 0o600))

	for _, args := range [][]string{
		{"--input", bundlePath},
		{"-i", bundlePath},
	} {
		cmd := newConfigImportCmd()
		out := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		cmd.SetOut(out)
		cmd.SetErr(stderr)
		cmd.SetArgs(append([]string{
			"--db", dbPath,
			"--profiles-path", profilesPath,
			"--dialect", "postgres",
		}, args...))
		require.NoError(t, cmd.Execute(),
			"deprecated alias %v must still work", args)
		assert.Contains(t, stderr.String(), "deprecation",
			"deprecated alias %v must print a stderr deprecation warning",
			args)
		assert.Contains(t, stderr.String(), "--in",
			"deprecation warning must name the new flag")
	}
}

// TestConfigImportCmd_InAndInputMutuallyExclusive — passing both
// flags simultaneously must be rejected with a clear message. An
// operator half-completing a flag rename should get an explicit error
// rather than silent precedence.
func TestConfigImportCmd_InAndInputMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := &ConfigBundle{
		SchemaVersion: ConfigSchemaVersion,
		Product:       ConfigProduct,
		RuntimeConfig: RuntimeConfigBlock{Dialect: "postgres"},
		Profiles:      ProfilesBlock{},
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bundlePath, raw, 0o600))

	cmd := newConfigImportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--dialect", "postgres",
		"--in", bundlePath,
		"--input", bundlePath,
	})
	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aliases",
		"--in + --input together must be rejected with an `aliases` message")
}

// TestConfig_Import_LegacyWireShape asserts that a pre-#288 export
// (`format: "dbounce.config"` + `format_version: 1` + int
// `schema_version` naming the store-schema version) imports cleanly
// into the new binary. The importer rewrites the legacy fields onto
// the canonical shape + prints a stderr deprecation warning. Loadbearing
// compat invariant for old exports on disk per the #288 memo.
func TestConfig_Import_LegacyWireShape(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	bundlePath := filepath.Join(dir, "legacy.json")

	// Hand-craft a pre-#288 export shape: `format` + `format_version`
	// + int `schema_version` naming the store version.
	legacy := map[string]any{
		"format":         "dbounce.config",
		"format_version": 1,
		"schema_version": store.SchemaVersion, // int — pre-#288 store version
		"exported_at":    "2026-05-17T00:00:00Z",
		"runtime_config": map[string]any{"dialect": "postgres"},
		"rules": []any{
			map[string]any{"pattern": "SELECT:public.*", "effect": "allow"},
		},
		"profiles": map[string]any{"items": []any{}},
	}
	raw, err := json.Marshal(legacy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bundlePath, raw, 0o600))

	cmd := newConfigImportCmd()
	out := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--profiles-path", profilesPath,
		"--dialect", "postgres",
		"--in", bundlePath,
	})
	require.NoError(t, cmd.Execute(),
		"pre-#288 wire-shape bundles MUST import cleanly into the new binary")
	assert.Contains(t, stderr.String(), "deprecation",
		"legacy wire shape MUST trigger a stderr deprecation warning")
	assert.Contains(t, stderr.String(), "format",
		"deprecation warning must name the legacy fields")

	// The imported rule landed.
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	rs, err := st.ListRules()
	require.NoError(t, err)
	require.NoError(t, st.Close())
	require.Len(t, rs, 1, "legacy bundle's rule MUST land in the store")
	assert.Equal(t, "SELECT:public.*", rs[0].Rule.Pattern)
}

// TestConfig_Import_LegacyTestdataFile pins the
// `testdata/legacy-pre-288-wire-shape.json` golden file as a
// regression watchdog. The file lives in the repo so a future
// shape-normalizer change cannot silently drop legacy compat without
// the test surfacing the regression.
func TestConfig_Import_LegacyTestdataFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")

	src, err := os.ReadFile("testdata/legacy-pre-288-wire-shape.json")
	require.NoError(t, err,
		"testdata fixture must exist; the legacy compat invariant is load-bearing")
	bundlePath := filepath.Join(dir, "legacy.json")
	require.NoError(t, os.WriteFile(bundlePath, src, 0o600))

	cmd := newConfigImportCmd()
	stderr := &bytes.Buffer{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--profiles-path", profilesPath,
		"--dialect", "postgres",
		"--in", bundlePath,
	})
	require.NoError(t, cmd.Execute(),
		"the testdata legacy fixture MUST keep importing across binary upgrades")
	assert.Contains(t, stderr.String(), "deprecation")
}

// TestConfig_Import_LegacyWrongProductRefused — a pre-#288 bundle whose
// `format` magic names a different product MUST be refused before the
// rewrite step succeeds (preserving the cross-product reject
// semantic).
func TestConfig_Import_LegacyWrongProductRefused(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	bundlePath := filepath.Join(dir, "wrong.json")

	wrong := map[string]any{
		"format":         "kbounce.config", // wrong product
		"format_version": 1,
		"schema_version": 1,
		"exported_at":    "2026-05-17T00:00:00Z",
		"runtime_config": map[string]any{"dialect": "postgres"},
		"rules":          []any{},
		"profiles":       map[string]any{"items": []any{}},
	}
	raw, err := json.Marshal(wrong)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bundlePath, raw, 0o600))

	cmd := newConfigImportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--dialect", "postgres",
		"--in", bundlePath,
	})
	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kbounce.config",
		"legacy wrong-product refusal must name the offending format")
}

// TestConfig_Roundtrip_OldExportImportsCleanly — the load-bearing
// cross-version round-trip: an old-shape export imports into the new
// binary + can be RE-exported in the new canonical shape. Compat is
// one-way (new binaries read old; new binaries always write new).
func TestConfig_Roundtrip_OldExportImportsCleanly(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	profilesPath := filepath.Join(dir, "profiles.yaml")
	bundlePath := filepath.Join(dir, "legacy.json")
	reExportPath := filepath.Join(dir, "re-export.json")

	legacy := map[string]any{
		"format":         "dbounce.config",
		"format_version": 1,
		"schema_version": store.SchemaVersion,
		"exported_at":    "2026-05-17T00:00:00Z",
		"runtime_config": map[string]any{"dialect": "postgres"},
		"rules":          []any{},
		"profiles":       map[string]any{"items": []any{}},
	}
	raw, err := json.Marshal(legacy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(bundlePath, raw, 0o600))

	// Import the legacy file into the new binary.
	imp := newConfigImportCmd()
	imp.SetOut(&bytes.Buffer{})
	imp.SetErr(&bytes.Buffer{})
	imp.SetArgs([]string{
		"--db", dbPath,
		"--profiles-path", profilesPath,
		"--dialect", "postgres",
		"--in", bundlePath,
	})
	require.NoError(t, imp.Execute())

	// Re-export. The new export MUST carry the canonical shape.
	exp := newConfigExportCmd()
	exp.SetOut(&bytes.Buffer{})
	exp.SetErr(&bytes.Buffer{})
	exp.SetArgs([]string{
		"--db", dbPath,
		"--profiles-path", profilesPath,
		"--dialect", "postgres",
		"--output", reExportPath,
		"--actor", "tester",
	})
	require.NoError(t, exp.Execute())
	reRaw, err := os.ReadFile(reExportPath)
	require.NoError(t, err)
	var re ConfigBundle
	require.NoError(t, json.Unmarshal(reRaw, &re))
	assert.Equal(t, ConfigSchemaVersion, re.SchemaVersion,
		"re-export MUST canonicalize to string \"1.0\"")
	assert.Equal(t, ConfigProduct, re.Product,
		"re-export MUST carry the `product` field")

	// The new export MUST NOT carry the pre-#288 deprecated field
	// names; the wire converged on the new shape.
	assert.NotContains(t, string(reRaw), `"format":`,
		"new exports MUST NOT carry the pre-#288 `format` field")
	assert.NotContains(t, string(reRaw), `"format_version":`,
		"new exports MUST NOT carry the pre-#288 `format_version` field")
}

// TestConfig_NormalizeLegacyBundleShape_NewShapePassthrough —
// the normalizer must be a no-op on already-canonical bundles. A
// post-#288 export round-trips through the normalizer unchanged.
func TestConfig_NormalizeLegacyBundleShape_NewShapePassthrough(t *testing.T) {
	canon := map[string]any{
		"schema_version":       "1.0",
		"product":              "dbounce",
		"exported_at":          "2026-05-18T00:00:00Z",
		"store_schema_version": store.SchemaVersion,
		"runtime_config":       map[string]any{"dialect": "postgres"},
		"rules":                []any{},
		"profiles":              map[string]any{"items": []any{}},
	}
	raw, err := json.Marshal(canon)
	require.NoError(t, err)
	stderr := &bytes.Buffer{}
	out, legacy, err := normalizeLegacyBundleShape(raw, stderr)
	require.NoError(t, err)
	assert.False(t, legacy, "canonical bundles MUST NOT be flagged legacy")
	assert.Equal(t, "", stderr.String(),
		"canonical bundles MUST NOT trigger a deprecation warning")
	// Re-decode the output and confirm it carries the same fields.
	var back map[string]any
	require.NoError(t, json.Unmarshal(out, &back))
	assert.Equal(t, "1.0", back["schema_version"])
	assert.Equal(t, "dbounce", back["product"])
}

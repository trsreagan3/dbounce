package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/profile"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

// CLI smoke tests: assert that the command tree is wired correctly,
// that --version surfaces the stamped strings, that `audit tail`
// reads from the store, and that the --limit bound is enforced at
// parse time (mirror UAT-K2 HIGH-K2-03).

func TestVersionString_Format(t *testing.T) {
	s := versionString()
	assert.Contains(t, s, "dbounce")
	assert.Contains(t, s, "commit")
	assert.Contains(t, s, "built")
}

func TestRootCmd_HasVersionAndSubcommands(t *testing.T) {
	cmd := newRootCmd()
	assert.NotEmpty(t, cmd.Version)
	names := map[string]bool{}
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	assert.True(t, names["run"], "run subcommand must be wired")
	assert.True(t, names["audit"], "audit subcommand must be wired")
}

func TestRunCmd_Help(t *testing.T) {
	cmd := newRunCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--help"})
	require.NoError(t, cmd.Execute())
	help := out.String()
	assert.Contains(t, help, "--port")
	assert.Contains(t, help, "--mode")
	assert.Contains(t, help, "--upstream")
	assert.Contains(t, help, "--i-know-this-binds-externally")
	assert.Contains(t, help, "--dialect")
	assert.Contains(t, help, "--mgmt-port")
	// D-Slice 4 flags
	assert.Contains(t, help, "--listener-tls-cert")
	assert.Contains(t, help, "--listener-tls-key")
	assert.Contains(t, help, "--require-client-cert")
	assert.Contains(t, help, "--management-tls-cert")
	assert.Contains(t, help, "--management-tls-key")
	// D-Slice 8 flag
	assert.Contains(t, help, "--prompt-on-deny")
}

func TestRootCmd_HasDSlice8Subcommands(t *testing.T) {
	cmd := newRootCmd()
	names := map[string]bool{}
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	for _, sub := range []string{"pause", "prompts", "presets", "rules"} {
		assert.True(t, names[sub], "D-Slice 8 must wire %s subcommand", sub)
	}
}

func TestRunCmd_MySQLRejectsListenerTLS(t *testing.T) {
	// D-Slice 5 → 4 cross-slice guard: MySQL listener TLS not shipped.
	// CLI must fail-fast rather than silently accept TLS flags that the
	// MySQL handler won't honor.
	cases := []struct {
		name string
		args []string
	}{
		{"tls-cert", []string{"--dialect=mysql", "--listener-tls-cert=/tmp/x.pem"}},
		{"tls-key", []string{"--dialect=mysql", "--listener-tls-key=/tmp/x.key"}},
		{"require-client-cert", []string{"--dialect=mysql", "--require-client-cert"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newRunCmd()
			out := &bytes.Buffer{}
			cmd.SetOut(out)
			cmd.SetErr(out)
			cmd.SilenceUsage = true
			cmd.SetArgs(append(tc.args,
				"--db", t.TempDir()+"/x.db",
				"--port", "0", "--mgmt-port", "0",
				"--host", "127.0.0.1",
			))
			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "MySQL")
		})
	}
}

// HIGH-D8-04 regression — management listener loopback guard. The
// wire-protocol listener already guards against external binds; the
// management listener (default 127.0.0.1) lacked the parallel guard,
// so `--mgmt-host 0.0.0.0` would silently expose /healthz (which
// discloses operator-controlled pause.reason text + deployment
// fingerprint). AUDIT-WB-DSLICES-1-8.md §HIGH-D8-04 has the full
// reproduction.

func TestRunCmd_MgmtHostRequiresAcknowledgementWhenExternal(t *testing.T) {
	cmd := newRunCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{
		"--mgmt-host", "0.0.0.0",
		"--host", "127.0.0.1",
		"--db", t.TempDir() + "/x.db",
		"--port", "0", "--mgmt-port", "0",
	})
	err := cmd.Execute()
	require.Error(t, err,
		"--mgmt-host 0.0.0.0 without acknowledgement MUST be rejected")
	assert.Contains(t, err.Error(), "HIGH-D8-04",
		"error must reference the audit ID")
	assert.Contains(t, err.Error(), "--i-know-mgmt-binds-externally",
		"error must name the escape-hatch flag")
}

func TestRunCmd_MgmtHostGuardLoopbackMembership(t *testing.T) {
	// Directly verify the loopbackHosts map matches the wire-listener's
	// definition so the mgmt guard is symmetric (the audit's "asymmetry
	// footgun" is closed by sharing the same allowlist). We don't run
	// the listener in test — that would block on Ctrl+C; the guard's
	// correctness lives in the map membership + the conditional that
	// uses it (covered by the rejection test above + by reading the
	// source). Sanity that all expected entries are present:
	for _, h := range []string{"127.0.0.1", "::1", "localhost", "ip6-localhost", "ip6-loopback"} {
		_, ok := loopbackHosts[h]
		assert.True(t, ok, "loopbackHosts map MUST contain %q so mgmt guard accepts it", h)
	}
	// And confirm a clear external-looking host is NOT a member.
	for _, h := range []string{"0.0.0.0", "::", "1.2.3.4"} {
		_, ok := loopbackHosts[h]
		assert.False(t, ok, "loopbackHosts map MUST NOT contain %q", h)
	}
}

func TestRunCmd_Help_MentionsMgmtBindAcknowledgement(t *testing.T) {
	cmd := newRunCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--help"})
	require.NoError(t, cmd.Execute())
	help := out.String()
	assert.Contains(t, help, "--i-know-mgmt-binds-externally",
		"--help MUST surface the new acknowledgement flag")
}

func TestRootCmd_HasInitTLSSubcommand(t *testing.T) {
	cmd := newRootCmd()
	names := map[string]bool{}
	for _, c := range cmd.Commands() {
		names[c.Name()] = true
	}
	assert.True(t, names["init-tls"], "init-tls subcommand must be wired")
}

func TestInitTLSCmd_WritesCertMaterial(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "tls")

	cmd := newInitTLSCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--out", out})
	require.NoError(t, cmd.Execute())

	for _, name := range []string{"ca.crt", "server.crt", "server.key"} {
		p := filepath.Join(out, name)
		_, err := os.Stat(p)
		require.NoError(t, err, "init-tls must write %s", name)
	}
	text := buf.String()
	assert.Contains(t, text, "ca.crt")
	assert.Contains(t, text, "server.crt")
	assert.Contains(t, text, "server.key")
}

func TestInitTLSCmd_WithClientCertWritesClientPair(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "tls")

	cmd := newInitTLSCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--out", out, "--with-client-cert"})
	require.NoError(t, cmd.Execute())

	for _, name := range []string{"ca.crt", "server.crt", "server.key", "client.crt", "client.key"} {
		p := filepath.Join(out, name)
		_, err := os.Stat(p)
		require.NoError(t, err, "init-tls --with-client-cert must write %s", name)
	}
}

func TestInitTLSCmd_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "tls")

	cmd := newInitTLSCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--out", out})
	require.NoError(t, cmd.Execute())

	cmd2 := newInitTLSCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--out", out})
	err := cmd2.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to overwrite")
}

func TestInitTLSCmd_ForceAllowsOverwrite(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "tls")

	cmd := newInitTLSCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--out", out})
	require.NoError(t, cmd.Execute())

	cmd2 := newInitTLSCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--out", out, "--force"})
	require.NoError(t, cmd2.Execute())
}

func TestAuditTail_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--limit", "10"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "no decisions recorded")
}

func TestAuditTail_WithRows(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	st, err := store.Open(dbPath)
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		Dialect:         "postgres",
		Statement:       "SELECT * FROM users",
		StatementType:   "SELECT",
		TablesTouched:   []string{"users"},
		DecisionVerdict: "ALLOW",
		DecisionReason:  "observation-only",
		ModeAtDecision:  "cooperative",
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--limit", "10"})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "SELECT")
	assert.Contains(t, text, "ALLOW")
	assert.Contains(t, text, "users")
}

func TestAuditTail_JSON(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")

	st, err := store.Open(dbPath)
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		Dialect:         "postgres",
		Statement:       "DELETE FROM sessions",
		StatementType:   "DELETE",
		TablesTouched:   []string{"sessions"},
		IsDML:           true,
		HasMutatingNode: true,
		MutatingNodeType: "DELETE",
		DecisionVerdict: "ALLOW",
		DecisionReason:  "observation-only",
		ModeAtDecision:  "cooperative",
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--json", "--limit", "10"})
	require.NoError(t, cmd.Execute())
	text := out.String()
	// One JSON object per line, newest first.
	assert.True(t, strings.HasPrefix(text, "{"), "JSON output must start with {")
	assert.Contains(t, text, `"statement_type":"DELETE"`)
	assert.Contains(t, text, `"has_mutating_node":true`)
}

func TestAuditTail_LimitOutOfRange_Rejected(t *testing.T) {
	// UAT-K2 HIGH-K2-03 parity: --limit must be in 1-1000.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--limit", "0"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1-1000")

	cmd2 := newAuditCmd()
	out2 := &bytes.Buffer{}
	cmd2.SetOut(out2)
	cmd2.SetErr(out2)
	cmd2.SetArgs([]string{"tail", "--db", dbPath, "--limit", "5000"})
	err = cmd2.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1-1000")
}

func TestAuditCmd_RequiresSubcommand(t *testing.T) {
	// Calling `dbounce audit unknown-thing` should exit with a clear
	// error pointing the operator at --help. Mirrors UAT-K2 BLOCKER-K2-02.
	// We can't directly assert on os.Exit(1) from this test, but we
	// CAN assert that the help text + subcommand wiring is in place.
	cmd := newAuditCmd()
	assert.Equal(t, "audit", cmd.Name())
	subs := map[string]bool{}
	for _, c := range cmd.Commands() {
		subs[c.Name()] = true
	}
	assert.True(t, subs["tail"], "audit tail must be wired")
}

// withProfilesPath sets DBOUNCE_PROFILES_PATH to a tempdir-local
// profiles.yaml for the duration of the test + returns the path. Used
// by the e2e tests below so the profileWriterAdapter inside
// newRootCmd() writes to a controlled location rather than the
// developer's real ~/.dbounce/profiles.yaml.
func withProfilesPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "profiles.yaml")
	prev := os.Getenv("DBOUNCE_PROFILES_PATH")
	require.NoError(t, os.Setenv("DBOUNCE_PROFILES_PATH", p))
	t.Cleanup(func() {
		if prev == "" {
			_ = os.Unsetenv("DBOUNCE_PROFILES_PATH")
		} else {
			_ = os.Setenv("DBOUNCE_PROFILES_PATH", prev)
		}
	})
	return p
}

// TestRootCmd_ProfileWriterWired_PromptsAnswerProfile drives the
// `dbounce prompts answer ID --kind profile --target NAME` flow end-
// to-end via newRootCmd() so the profileWriterAdapter wiring is what
// gets exercised — not the prompts-answer-with-test-double pattern
// used by prompts_test.go. Confirms the merge-time TODO from
// commit 3396bd1 is closed.
func TestRootCmd_ProfileWriterWired_PromptsAnswerProfile(t *testing.T) {
	profilesPath := withProfilesPath(t)
	dbPath := dbAt(t)
	// DBOUNCE_DB is set by the package's TestMain; override for this
	// test so each subcommand opens the same tempdir-scoped store.
	prevDB := os.Getenv("DBOUNCE_DB")
	require.NoError(t, os.Setenv("DBOUNCE_DB", dbPath))
	t.Cleanup(func() { _ = os.Setenv("DBOUNCE_DB", prevDB) })

	id := enqueueTestPrompt(t, dbPath)
	target := "e2e-prompt-profile"

	root := newRootCmd()
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{
		"prompts", "answer", fmt.Sprintf("%d", id),
		"--kind", "profile",
		"--target=" + target,
		"--db", dbPath,
		"--actor", "e2e-test",
	})
	require.NoError(t, root.Execute(), "root execute failed: %s", out.String())
	assert.Contains(t, out.String(), target,
		"output must mention the created profile name")

	// Verify the profile landed in the on-disk YAML.
	ps, err := profile.LoadProfiles(profilesPath)
	require.NoError(t, err)
	got, present := ps.All[target]
	require.True(t, present, "profile %q must exist in %s", target, profilesPath)
	assert.Equal(t, "local", got.Source,
		"adapter must force source=local on operator-created profiles")
	require.NotEmpty(t, got.AllowRules,
		"prompt-derived profile must carry at least one allow_rule")
	assert.Contains(t, got.AllowRules[0].Pattern, "SELECT",
		"allow_rule pattern must reflect the prompt's statement_type")
}

// TestRootCmd_ProfileWriterWired_PresetsApply drives the
// `dbounce presets apply NAME --target NAME` flow end-to-end via
// newRootCmd() — confirms that presets apply now creates profiles
// instead of erroring with the stub message.
func TestRootCmd_ProfileWriterWired_PresetsApply(t *testing.T) {
	profilesPath := withProfilesPath(t)
	target := "e2e-preset-profile"

	root := newRootCmd()
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{
		"presets", "apply", "analytics-engineer",
		"--target=" + target,
	})
	require.NoError(t, root.Execute(), "root execute failed: %s", out.String())
	text := out.String()
	assert.Contains(t, text, target)
	assert.Contains(t, text, "analytics-engineer",
		"output must reference the source preset id")

	ps, err := profile.LoadProfiles(profilesPath)
	require.NoError(t, err)
	got, present := ps.All[target]
	require.True(t, present, "preset-derived profile must land in %s", profilesPath)
	assert.NotEmpty(t, got.AllowRules,
		"analytics-engineer carries allow_rules that must round-trip")
	assert.NotEmpty(t, got.DenyActions,
		"analytics-engineer carries deny_rules (MUTATING:*) — adapter "+
			"must extract the statement_type into DenyActions")
}

// TestRootCmd_ProfileWriterWired_RulesRecommendSaveAsProfile drives
// the `dbounce rules recommend --save-as-profile NAME` flow end-to-
// end. Seeds the audit log with enough repeat decisions for the
// recommender to surface a pattern, then verifies the resulting
// profile lands in the YAML.
func TestRootCmd_ProfileWriterWired_RulesRecommendSaveAsProfile(t *testing.T) {
	profilesPath := withProfilesPath(t)
	dbPath := dbAt(t)
	prevDB := os.Getenv("DBOUNCE_DB")
	require.NoError(t, os.Setenv("DBOUNCE_DB", dbPath))
	t.Cleanup(func() { _ = os.Setenv("DBOUNCE_DB", prevDB) })

	// Seed enough decisions so the recommender surfaces a pattern.
	// Default --min-count is 3 so we record 5 identical SELECT rows.
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			Dialect:         "postgres",
			Statement:       "SELECT * FROM public.metrics",
			StatementType:   "SELECT",
			TablesTouched:   []string{"public.metrics"},
			DecisionVerdict: "ALLOW",
			DecisionReason:  "observation-only",
			ModeAtDecision:  "cooperative",
		})
		require.NoError(t, err)
	}
	require.NoError(t, st.Close())

	target := "e2e-recommend-profile"
	root := newRootCmd()
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{
		"rules", "recommend",
		"--db", dbPath,
		"--save-as-profile=" + target,
	})
	require.NoError(t, root.Execute(), "root execute failed: %s", out.String())
	assert.Contains(t, out.String(), target)

	ps, err := profile.LoadProfiles(profilesPath)
	require.NoError(t, err)
	got, present := ps.All[target]
	require.True(t, present,
		"recommender-derived profile must land in %s", profilesPath)
	require.NotEmpty(t, got.AllowRules,
		"rules recommend --save-as-profile must produce allow_rules")
	// The recommender pattern is "SELECT:<table-glob>" — assert the
	// allow_rule round-tripped the statement type.
	assert.True(t,
		strings.HasPrefix(got.AllowRules[0].Pattern, "SELECT:"),
		"recommended allow_rule must carry SELECT: prefix, got %q",
		got.AllowRules[0].Pattern)
}

// TestProfileWriterAdapter_CollisionReturnsErrProfileExists exercises
// the adapter directly (rather than via a CLI subcommand) to confirm
// the ErrProfileExists backstop fires. The CLI subcommands use
// naming.AvoidCollision to auto-bump duplicate names BEFORE calling
// CreateProfile, so the adapter's ErrProfileExists is a defense-in-
// depth check that fires only on a TOCTOU race or a caller that
// bypasses AvoidCollision. Per [[creates-never-mutates]] the adapter
// must NEVER overwrite an existing profile.
func TestProfileWriterAdapter_CollisionReturnsErrProfileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	require.NoError(t, os.WriteFile(path, []byte(
		"profiles:\n  collision-target:\n    description: pre-existing\n",
	), 0o600))

	adapter := newCLIProfileWriter(path)
	err := adapter.CreateProfile(
		"collision-target", "tried to overwrite",
		nil, nil)
	require.Error(t, err, "adapter must surface collision as an error")
	assert.ErrorIs(t, err, profile.ErrProfileExists,
		"must wrap profile.ErrProfileExists for ErrorIs identification")
	assert.Contains(t, err.Error(), path,
		"adapter's wrap should name the profiles file the operator edits")

	// Confirm the existing profile was NOT modified.
	ps, err := profile.LoadProfiles(path)
	require.NoError(t, err)
	got, present := ps.All["collision-target"]
	require.True(t, present)
	assert.Equal(t, "pre-existing", got.Description,
		"adapter must never overwrite an existing profile (creates-never-mutates)")
}

// HIGH-D8-03 regression — profileWriterAdapter.CreateProfile must
// fail-fast when an allow rule carries SchemaScope / TableScope /
// FunctionScope (which profile.ProfileAllowRule would silently drop,
// widening the persisted rule). AUDIT-WB-DSLICES-1-8.md §HIGH-D8-03
// has the full reproduction. Per [[creates-never-mutates]] +
// [[scorer-is-ground-truth]], silent widening is the worst failure
// mode for a security gate; explicit error is the correct stop-gap
// until profile.ProfileAllowRule grows the scope fields in v1.1.

func TestProfileWriterAdapter_RejectsAllowRuleWithSchemaScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	adapter := newCLIProfileWriter(path)

	scoped := []dbrules.ProxyRule{
		{Pattern: "SELECT:*", SchemaScope: "reporting"},
	}
	err := adapter.CreateProfile("scoped-allow", "would widen", scoped, nil)
	require.Error(t, err, "scoped allow rule MUST be rejected to prevent silent widening")
	assert.Contains(t, err.Error(), "HIGH-D8-03",
		"error must reference the audit ID so the operator can find context")
	assert.Contains(t, err.Error(), "schema_scope",
		"error must surface which axis was offending")

	// Confirm no profile was written (fail-fast = no partial state).
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr),
		"profiles.yaml MUST NOT be created when the guard fires")
}

func TestProfileWriterAdapter_RejectsAllowRuleWithTableScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	adapter := newCLIProfileWriter(path)

	scoped := []dbrules.ProxyRule{
		{Pattern: "SELECT:*", TableScope: "public.metrics"},
	}
	err := adapter.CreateProfile("scoped-allow", "would widen", scoped, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "table_scope")
}

func TestProfileWriterAdapter_RejectsAllowRuleWithFunctionScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	adapter := newCLIProfileWriter(path)

	scoped := []dbrules.ProxyRule{
		{Pattern: "CALL:*", FunctionScope: "audit_*"},
	}
	err := adapter.CreateProfile("scoped-allow", "would widen", scoped, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "function_scope")
}

func TestProfileWriterAdapter_AllowsUnscopedRule(t *testing.T) {
	// Sanity: an allow rule with NO scope fields persists successfully
	// (the guard must not fire when there's nothing to drop).
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	adapter := newCLIProfileWriter(path)

	unscoped := []dbrules.ProxyRule{
		{Pattern: "SELECT:public.metrics", Note: "ok"},
	}
	require.NoError(t, adapter.CreateProfile("unscoped-allow",
		"no scope to drop", unscoped, nil),
		"unscoped allow rule MUST persist successfully")

	ps, err := profile.LoadProfiles(path)
	require.NoError(t, err)
	got, present := ps.All["unscoped-allow"]
	require.True(t, present)
	require.Len(t, got.AllowRules, 1)
	assert.Equal(t, "SELECT:public.metrics", got.AllowRules[0].Pattern)
}

func TestProfileWriterAdapter_RejectsMultipleScopedRulesNamesAll(t *testing.T) {
	// Error message must list ALL offending rules so the operator can
	// fix them in one round-trip (not just the first offender).
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	adapter := newCLIProfileWriter(path)

	scoped := []dbrules.ProxyRule{
		{Pattern: "SELECT:*", SchemaScope: "reporting"},
		{Pattern: "INSERT:*", TableScope: "staging.*"},
		{Pattern: "OK:*"}, // no scope — fine in isolation
	}
	err := adapter.CreateProfile("multi-scoped", "would widen all", scoped, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `pattern="SELECT:*"`)
	assert.Contains(t, err.Error(), `pattern="INSERT:*"`)
	assert.NotContains(t, err.Error(), `pattern="OK:*"`,
		"unscoped rule MUST NOT be named as offending")
}

func TestMain(m *testing.M) {
	// Don't litter the user's home directory if a test accidentally
	// triggers DefaultDBPath().
	tmp, err := os.MkdirTemp("", "dbounce-cli-test-*")
	if err == nil {
		_ = os.Setenv("DBOUNCE_DB", filepath.Join(tmp, "state.db"))
		defer os.RemoveAll(tmp)
	}
	os.Exit(m.Run())
}

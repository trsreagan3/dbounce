// Tests for the [[basic-app-hygiene-features]] TIER 1 #4 +
// [[security-team-audit-export]] admin-action wiring.
//
// Three layers under test here:
//
//   1. The shared enqueueAdminAction helper writes a well-shaped
//      pending_audit_events row + tolerates expected failure modes
//      (missing dbPath, missing action) without breaking the caller.
//
//   2. The per-action dialect-inference helpers
//      (inferDialectsFromRulePattern + inferDialectsFromPresetID)
//      pick up dialect signal when present, return nil otherwise.
//      Empty/nil drives the audit event's "ext.config_change.dialects
//      MUST be omitted when dialect-agnostic" contract.
//
//   3. The per-subcommand wiring (rules add / rules remove / rules
//      recommend --save-as-profile / pause start / presets apply)
//      enqueues exactly one ADMIN_ACTION row each — payload carries
//      the cross-product config_change fields.
//
// The poller / cross-process drain itself is covered in
// internal/proxy/audit_events_wiring_test.go; this file's scope is
// the CLI-side enqueue contract.

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

// drainOneAdminAction opens the store at dbPath, drains the queue,
// asserts exactly one ADMIN_ACTION row landed, decodes its payload,
// and returns the decoded map for further assertions. Centralizes
// the boilerplate every per-subcommand test repeats.
func drainOneAdminAction(t *testing.T, dbPath string) map[string]any {
	t.Helper()
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()
	rows, err := st.DrainPendingAuditEvents(0)
	require.NoError(t, err)
	require.Len(t, rows, 1,
		"admin subcommand MUST enqueue exactly one ADMIN_ACTION row")
	assert.Equal(t, store.PendingAuditEventAdminAction, rows[0].Kind)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(rows[0].PayloadJSON), &got))
	return got
}

func TestInferDialectsFromRulePattern(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    []string
	}{
		{"empty", "", nil},
		{"glob-only-star", "SELECT:*", nil},
		{"no-colon", "SELECTpublic.users", nil},
		{"no-dialect-prefix", "SELECT:public.users", nil},
		{"postgres-shorthand", "SELECT:pg.public.users", []string{"postgres"}},
		{"postgres-long", "SELECT:postgres.public.users", []string{"postgres"}},
		{"mysql", "INSERT:mysql.app_db.events", []string{"mysql"}},
		{"snowflake-shorthand", "SELECT:sf.analytics.*", []string{"snowflake"}},
		{"snowflake-long", "SELECT:snowflake.public.*", []string{"snowflake"}},
		{"bigquery-shorthand", "SELECT:bq.proj.events", []string{"bigquery"}},
		{"case-insensitive", "SELECT:MySQL.app_db.*", []string{"mysql"}},
		{"glob-only", "SELECT:public.*", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inferDialectsFromRulePattern(tc.pattern)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestInferDialectsFromPresetID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want []string
	}{
		{"empty", "", nil},
		{"agnostic", "analytics-engineer", nil},
		{"mysql-suffix", "readonly-mysql", []string{"mysql"}},
		{"snowflake-shorthand", "sf-analyst", []string{"snowflake"}},
		{"multi", "snowflake-and-bigquery-export", []string{"bigquery", "snowflake"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inferDialectsFromPresetID(tc.id)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestEnqueueAdminAction_WritesRow(t *testing.T) {
	db := dbAt(t)
	errOut := &bytes.Buffer{}
	enqueueAdminAction(errOut, db, adminActionEnqueueParams{
		Action:       "rules.add",
		Actor:        "alice",
		ResourceType: "rule",
		ResourceID:   "42",
		Dialects:     []string{"mysql"},
		Details: map[string]any{
			"pattern": "SELECT:mysql.app_db.*",
		},
	})
	assert.Empty(t, errOut.String(),
		"happy path MUST NOT write to stderr")
	got := drainOneAdminAction(t, db)
	assert.Equal(t, "rules.add", got["action"])
	assert.Equal(t, "alice", got["actor"])
	assert.Equal(t, "rule", got["resource_type"])
	assert.Equal(t, "42", got["resource_id"])
	assert.Equal(t, "success", got["result"],
		"empty Result defaults to 'success'")
	dialects, ok := got["dialects"].([]any)
	require.True(t, ok)
	require.Len(t, dialects, 1)
	assert.Equal(t, "mysql", dialects[0])
	details, ok := got["details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "SELECT:mysql.app_db.*", details["pattern"])
}

func TestEnqueueAdminAction_MissingActionWarnsButNoEnqueue(t *testing.T) {
	db := dbAt(t)
	errOut := &bytes.Buffer{}
	enqueueAdminAction(errOut, db, adminActionEnqueueParams{
		// Action deliberately empty.
		Actor: "alice",
	})
	assert.Contains(t, errOut.String(), "action id missing",
		"missing action MUST surface loudly on stderr (caller bug)")
	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	depth, err := st.PendingAuditEventDepth()
	require.NoError(t, err)
	assert.Equal(t, 0, depth,
		"missing action MUST NOT produce an unattributable audit row")
}

func TestEnqueueAdminAction_EmptyActorDefaultsToUnknown(t *testing.T) {
	db := dbAt(t)
	enqueueAdminAction(&bytes.Buffer{}, db, adminActionEnqueueParams{
		Action: "pause.start",
		// Actor deliberately empty.
	})
	got := drainOneAdminAction(t, db)
	assert.Equal(t, "unknown", got["actor"],
		"empty Actor MUST default to 'unknown' so the audit row is always "+
			"attributable to some identity")
}

func TestRulesAdd_EnqueuesAdminAction(t *testing.T) {
	db := dbAt(t)
	cmd := newRulesAddCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--db", db,
		"--pattern", "SELECT:mysql.app_db.*",
		"--effect", "allow",
		"--actor", "alice",
		"--note", "test rule",
	})
	require.NoError(t, cmd.Execute())

	got := drainOneAdminAction(t, db)
	assert.Equal(t, "rules.add", got["action"])
	assert.Equal(t, "alice", got["actor"])
	assert.Equal(t, "rule", got["resource_type"])
	// rule id is the first row → "1"
	assert.Equal(t, "1", got["resource_id"])
	dialects, ok := got["dialects"].([]any)
	require.True(t, ok,
		"per-dialect inference must surface MySQL from the rule pattern's "+
			"table-glob prefix")
	require.Len(t, dialects, 1)
	assert.Equal(t, "mysql", dialects[0])
	details, ok := got["details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "SELECT:mysql.app_db.*", details["pattern"])
	assert.Equal(t, "allow", details["effect"])
	assert.Equal(t, "test rule", details["note"])
}

func TestRulesAdd_CrossDialectPatternOmitsDialects(t *testing.T) {
	db := dbAt(t)
	cmd := newRulesAddCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--db", db,
		"--pattern", "SELECT:public.users", // no dialect prefix
		"--effect", "allow",
		"--actor", "alice",
	})
	require.NoError(t, cmd.Execute())

	got := drainOneAdminAction(t, db)
	_, hasDialects := got["dialects"]
	assert.False(t, hasDialects,
		"cross-dialect rule pattern MUST omit dialects field — per-dialect "+
			"contract: empty/omitted when no dialect signal is present")
}

func TestRulesRemove_EnqueuesAdminAction(t *testing.T) {
	db := dbAt(t)
	// Seed a rule directly.
	st, err := store.Open(db)
	require.NoError(t, err)
	id, err := st.AddRule(dbrules.ProxyRule{
		Pattern: "SELECT:*", Effect: dbrules.EffectAllow,
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	cmd := newRulesRemoveCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", db, "--actor", "bob", intStr(int64(id))})
	require.NoError(t, cmd.Execute())

	got := drainOneAdminAction(t, db)
	assert.Equal(t, "rules.remove", got["action"])
	assert.Equal(t, "bob", got["actor"])
	assert.Equal(t, "rule", got["resource_type"])
	assert.Equal(t, intStr(int64(id)), got["resource_id"])
}

func TestPauseStart_EnqueuesAdminAction(t *testing.T) {
	db := dbAt(t)
	cmd := newPauseStartCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--db", db,
		"--for", "30m",
		"--reason", "live demo",
		"--actor", "carol",
	})
	require.NoError(t, cmd.Execute())

	got := drainOneAdminAction(t, db)
	assert.Equal(t, "pause.start", got["action"])
	assert.Equal(t, "carol", got["actor"])
	assert.Equal(t, "pause", got["resource_type"])
	// First pause → id 1.
	assert.Equal(t, "1", got["resource_id"])
	_, hasDialects := got["dialects"]
	assert.False(t, hasDialects,
		"pause windows are dialect-agnostic; the audit event MUST omit dialects")
	details, ok := got["details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "live demo", details["reason"])
	// TTL round-trips as a float64 in JSON (1800s).
	ttl, ok := details["ttl_seconds"].(float64)
	require.True(t, ok)
	assert.InDelta(t, (30 * time.Minute).Seconds(), ttl, 0.01)
}

func TestPresetsApply_EnqueuesAdminAction(t *testing.T) {
	db := dbAt(t)
	rw := &recordingProfileWriter{}
	cmd := newPresetsApplyCmd(rw)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--db", db,
		"--target=my-analytics",
		"--actor", "dave",
		"analytics-engineer",
	})
	require.NoError(t, cmd.Execute())
	require.Len(t, rw.created, 1, "preset apply should have created the profile")

	got := drainOneAdminAction(t, db)
	assert.Equal(t, "presets.apply", got["action"])
	assert.Equal(t, "dave", got["actor"])
	assert.Equal(t, "profile", got["resource_type"])
	assert.Equal(t, "my-analytics", got["resource_id"],
		"resource_id is the RESOLVED profile name (per [[creates-never-mutates]] "+
			"the apply creates a fresh profile)")
	details, ok := got["details"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "analytics-engineer", details["preset_id"])
}

func TestRulesRecommend_SaveAsProfile_EnqueuesAdminAction(t *testing.T) {
	db := dbAt(t)
	// Seed decisions so the recommender has something to surface.
	st, err := store.Open(db)
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			At:              time.Now().UTC(),
			Dialect:         "postgres",
			Statement:       "SELECT 1",
			StatementType:   "SELECT",
			TablesTouched:   []string{"public.users"},
			DecisionVerdict: "ALLOW",
			ModeAtDecision:  "cooperative",
		})
		require.NoError(t, err)
	}
	require.NoError(t, st.Close())

	rw := &recordingProfileWriter{}
	cmd := newRulesRecommendCmd(rw)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--db", db,
		"--min-count", "2",
		"--save-as-profile=recommend-test",
		"--actor", "eve",
	})
	require.NoError(t, cmd.Execute())

	got := drainOneAdminAction(t, db)
	assert.Equal(t, "rules.recommend", got["action"])
	assert.Equal(t, "eve", got["actor"])
	assert.Equal(t, "profile", got["resource_type"])
	assert.Equal(t, "recommend-test", got["resource_id"])
	details, ok := got["details"].(map[string]any)
	require.True(t, ok)
	// JSON numbers decode as float64; assert via type-tolerant compare.
	count, ok := details["allow_rule_count"].(float64)
	require.True(t, ok)
	assert.Greater(t, count, 0.0,
		"recommend MUST report the allow-rule count it materialized")
}

// TestUnionStringSlices spot-checks the presets-apply helper that
// unions per-preset + per-target-profile dialect inferences. Empty +
// empty → nil so the audit event omits the dialects field; non-empty
// inputs union, dedup, and sort deterministically.
func TestUnionStringSlices(t *testing.T) {
	assert.Nil(t, unionStringSlices(nil, nil))
	assert.Equal(t, []string{"mysql"},
		unionStringSlices([]string{"mysql"}, nil))
	assert.Equal(t, []string{"bigquery", "mysql", "snowflake"},
		unionStringSlices(
			[]string{"snowflake", "mysql"},
			[]string{"mysql", "bigquery"}))
	// Idempotent: union(x, x) == x.
	in := []string{"postgres", "mysql"}
	got := unionStringSlices(in, in)
	assert.Equal(t, []string{"mysql", "postgres"}, got)
	// Silence unused-import linter if strings winds up unused via
	// surface refactor.
	_ = strings.Join(got, ",")
}

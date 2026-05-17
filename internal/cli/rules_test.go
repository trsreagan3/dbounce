package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

// INFO-D8-14: newRulesCmd + newRulesRecommendCmd MUST panic on nil
// ProfileWriter so a regression that drops the wiring fails loudly
// at construction time.
func TestRulesCmd_NilWriter_Panics(t *testing.T) {
	assert.Panics(t, func() { _ = newRulesCmd(nil) },
		"newRulesCmd MUST panic on nil ProfileWriter (INFO-D8-14)")
}

func TestRulesRecommendCmd_NilWriter_Panics(t *testing.T) {
	assert.Panics(t, func() { _ = newRulesRecommendCmd(nil) },
		"newRulesRecommendCmd MUST panic on nil ProfileWriter (INFO-D8-14)")
}

func TestRulesCmd_TreeWired(t *testing.T) {
	c := newRulesCmd(&recordingProfileWriter{})
	assert.Equal(t, "rules", c.Name())
	subs := map[string]bool{}
	for _, s := range c.Commands() {
		subs[s.Name()] = true
	}
	for _, sub := range []string{"add", "list", "remove", "recommend"} {
		assert.True(t, subs[sub], "rules must wire %s subcommand", sub)
	}
}

func TestRulesAdd_RoundTripsToList(t *testing.T) {
	db := dbAt(t)
	add := newRulesAddCmd()
	out := &bytes.Buffer{}
	add.SetOut(out)
	add.SetErr(out)
	add.SetArgs([]string{"--db", db, "--pattern", "SELECT:public.*", "--effect", "allow"})
	require.NoError(t, add.Execute())
	assert.Contains(t, out.String(), "added rule")

	list := newRulesListCmd()
	out2 := &bytes.Buffer{}
	list.SetOut(out2)
	list.SetErr(out2)
	list.SetArgs([]string{"--db", db})
	require.NoError(t, list.Execute())
	assert.Contains(t, out2.String(), "SELECT:public.*")
}

func TestRulesAdd_RejectsBadEffect(t *testing.T) {
	db := dbAt(t)
	cmd := newRulesAddCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", db, "--pattern", "SELECT:*", "--effect", "bogus"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allow|deny")
}

func TestRulesRemove_ExistingAndMissing(t *testing.T) {
	db := dbAt(t)
	st, err := store.Open(db)
	require.NoError(t, err)
	id, err := st.AddRule(dbrules.ProxyRule{Pattern: "SELECT:*", Effect: dbrules.EffectAllow})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	cmd := newRulesRemoveCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db, intStr(int64(id))})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "removed rule")

	cmd2 := newRulesRemoveCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--db", db, "9999"})
	err = cmd2.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rule")
}

func TestRecommendFromDecisions_AggregatesPatterns(t *testing.T) {
	// Pure-function test for the recommender core. Three SELECTs on
	// the same table should aggregate; one DELETE on something else
	// should NOT meet min-count=2.
	rows := []store.DecisionRow{
		{StatementType: "SELECT", TablesTouched: []string{"public.users"}, DecisionVerdict: "ALLOW"},
		{StatementType: "SELECT", TablesTouched: []string{"public.users"}, DecisionVerdict: "ALLOW"},
		{StatementType: "SELECT", TablesTouched: []string{"public.users"}, DecisionVerdict: "DENY"},
		{StatementType: "DELETE", TablesTouched: []string{"public.cache"}, DecisionVerdict: "ALLOW"},
	}
	recs := recommendFromDecisions(rows, 2)
	require.Len(t, recs, 1)
	assert.Equal(t, "SELECT", recs[0].StatementType)
	assert.Equal(t, "public.users", recs[0].TableGlob)
	assert.Equal(t, 3, recs[0].Count)
	assert.Equal(t, 2, recs[0].AllowCount)
	assert.Equal(t, 1, recs[0].DenyCount)
}

func TestRecommendFromDecisions_GeneralizesGlob(t *testing.T) {
	// Rows touching multiple tables in the same schema should
	// generalize to schema.*; mixed schemas → "*".
	rows := []store.DecisionRow{
		{StatementType: "SELECT", TablesTouched: []string{"reports.a", "reports.b"}, DecisionVerdict: "ALLOW"},
		{StatementType: "SELECT", TablesTouched: []string{"reports.c", "reports.d"}, DecisionVerdict: "ALLOW"},
	}
	recs := recommendFromDecisions(rows, 2)
	require.Len(t, recs, 1)
	assert.Equal(t, "reports.*", recs[0].TableGlob)

	rows2 := []store.DecisionRow{
		{StatementType: "SELECT", TablesTouched: []string{"a.x", "b.y"}, DecisionVerdict: "ALLOW"},
		{StatementType: "SELECT", TablesTouched: []string{"a.x", "b.y"}, DecisionVerdict: "ALLOW"},
	}
	recs2 := recommendFromDecisions(rows2, 2)
	require.Len(t, recs2, 1)
	assert.Equal(t, "*", recs2[0].TableGlob)
}

func TestRecommendFromDecisions_DeterministicOrdering(t *testing.T) {
	// Two patterns with same count should sort by stmt then glob so
	// repeated runs produce identical output (important for any
	// downstream snapshot tooling).
	rows := []store.DecisionRow{
		{StatementType: "UPDATE", TablesTouched: []string{"a.x"}, DecisionVerdict: "ALLOW"},
		{StatementType: "UPDATE", TablesTouched: []string{"a.x"}, DecisionVerdict: "ALLOW"},
		{StatementType: "SELECT", TablesTouched: []string{"a.x"}, DecisionVerdict: "ALLOW"},
		{StatementType: "SELECT", TablesTouched: []string{"a.x"}, DecisionVerdict: "ALLOW"},
	}
	recs := recommendFromDecisions(rows, 2)
	require.Len(t, recs, 2)
	// Both have count=2; SELECT comes before UPDATE alphabetically.
	assert.Equal(t, "SELECT", recs[0].StatementType)
	assert.Equal(t, "UPDATE", recs[1].StatementType)
}

func TestRulesRecommend_CLIEndToEnd(t *testing.T) {
	db := dbAt(t)
	st, err := store.Open(db)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
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

	cmd := newRulesRecommendCmd(&recordingProfileWriter{})
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db, "--min-count", "2"})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "SELECT")
	assert.Contains(t, text, "public.users")
}

func TestRulesRecommend_SaveAsProfile_AutoName(t *testing.T) {
	db := dbAt(t)
	st, err := store.Open(db)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
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
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db, "--min-count", "2", "--save-as-profile"})
	require.NoError(t, cmd.Execute())
	require.Len(t, rw.created, 1)
	p := rw.created[0]
	assert.True(t, strings.HasPrefix(p.Name, "auto-"))
	assert.Contains(t, p.Name, "recommend")
	require.Len(t, p.Allow, 1)
	assert.Equal(t, "SELECT:public.users", p.Allow[0].Pattern)
}

func TestRulesRecommend_SaveAsProfile_ExplicitName(t *testing.T) {
	db := dbAt(t)
	st, err := store.Open(filepath.Join(db))
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			Dialect: "postgres", Statement: "SELECT 1",
			StatementType: "SELECT", TablesTouched: []string{"public.users"},
			DecisionVerdict: "ALLOW", ModeAtDecision: "cooperative",
		})
		require.NoError(t, err)
	}
	require.NoError(t, st.Close())

	rw := &recordingProfileWriter{}
	cmd := newRulesRecommendCmd(rw)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", db, "--min-count", "2",
		"--save-as-profile=my-recommendation", "--description", "smoke test"})
	require.NoError(t, cmd.Execute())
	require.Len(t, rw.created, 1)
	assert.Equal(t, "my-recommendation", rw.created[0].Name)
	assert.Equal(t, "smoke test", rw.created[0].Description)
}

func TestRulesRecommend_SaveAsProfile_NoRecsErrors(t *testing.T) {
	// Empty decisions table + --save-as-profile should surface a
	// clear error rather than silently create an empty profile.
	db := dbAt(t)
	rw := &recordingProfileWriter{}
	cmd := newRulesRecommendCmd(rw)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", db, "--save-as-profile"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no recommendations")
}

func TestRulesRecommend_RejectsBadScan(t *testing.T) {
	db := dbAt(t)
	cmd := newRulesRecommendCmd(&recordingProfileWriter{})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", db, "--scan", "0"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1-10000")
}

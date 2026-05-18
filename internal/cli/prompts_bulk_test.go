package cli

import (
	"bytes"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"

	"github.com/trsreagan3/dbounce/internal/store"
)

func openRawSQLite(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path)
}

// Tests for `dbounce prompts bulk-pending` + `dbounce prompts
// bulk-answer` per [[bulk-prompt-answer-ux]].

func enqueueDialectPrompt(t *testing.T, db, dialect, stmtType string, tables []string) int64 {
	t.Helper()
	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	decID, err := st.RecordDecision(store.DecisionRow{
		Dialect:         dialect,
		Statement:       "stmt",
		StatementType:   stmtType,
		TablesTouched:   tables,
		DecisionVerdict: "DENY",
		DecisionReason:  "out-of-scope",
		ModeAtDecision:  "transparent",
	})
	require.NoError(t, err)
	id, err := st.AddPendingPrompt(store.PendingPrompt{
		DecisionID:    decID,
		StatementType: stmtType,
		TablesTouched: tables,
		DenyReason:    "out-of-scope",
	})
	require.NoError(t, err)
	return id
}

func TestBulkPending_EmptyAndPopulated(t *testing.T) {
	db := dbAt(t)
	cmd := newPromptsBulkPendingCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "(no pending prompts)")

	_ = enqueueDialectPrompt(t, db, "postgres", "SELECT", []string{"public.users"})
	_ = enqueueDialectPrompt(t, db, "postgres", "SELECT", []string{"public.users"})
	_ = enqueueDialectPrompt(t, db, "mysql", "UPDATE", []string{"mydb.orders"})

	cmd2 := newPromptsBulkPendingCmd()
	out2 := &bytes.Buffer{}
	cmd2.SetOut(out2)
	cmd2.SetErr(out2)
	cmd2.SetArgs([]string{"--db", db})
	require.NoError(t, cmd2.Execute())
	text := out2.String()
	assert.Contains(t, text, "3 pending prompt(s)")
	assert.Contains(t, text, "mysql")
	assert.Contains(t, text, "postgres")
	assert.Contains(t, text, "mydb.orders")
	assert.Contains(t, text, "public.users")
}

func TestBulkAnswer_RejectsUnknownDecision(t *testing.T) {
	cmd := newPromptsBulkAnswerCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", dbAt(t), "--decision", "forever"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "profile|session|3h|10min|none")
}

func TestBulkAnswer_ProfileRequiresProfileFlag(t *testing.T) {
	cmd := newPromptsBulkAnswerCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", dbAt(t), "--decision", "profile"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--profile NAME")
}

func TestBulkAnswer_NoPendingShortCircuits(t *testing.T) {
	cmd := newPromptsBulkAnswerCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", dbAt(t), "--decision", "10min", "--yes"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "no pending prompts")
}

func TestBulkAnswer_NoneIsNoOp(t *testing.T) {
	db := dbAt(t)
	id := enqueueDialectPrompt(t, db, "postgres", "SELECT", []string{"public.users"})
	cmd := newPromptsBulkAnswerCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db, "--decision", "none", "--yes"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "no changes made")
	// Prompt remains pending.
	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	p, err := st.GetPendingPrompt(id)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, store.PromptPending, p.Status)
}

func TestBulkAnswer_TimeBoundedCreatesPerDialectRules(t *testing.T) {
	// Mixed PG + MySQL burst — bulk-answer 10min must create ONE rule
	// PER (dialect, stmt, table) entry so PG rules don't spill into
	// MySQL traffic.
	db := dbAt(t)
	_ = enqueueDialectPrompt(t, db, "postgres", "SELECT", []string{"public.users"})
	_ = enqueueDialectPrompt(t, db, "postgres", "SELECT", []string{"public.users"})
	_ = enqueueDialectPrompt(t, db, "postgres", "DELETE", []string{"public.audit"})
	_ = enqueueDialectPrompt(t, db, "mysql", "UPDATE", []string{"mydb.orders"})

	cmd := newPromptsBulkAnswerCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db, "--decision", "10min", "--yes",
		"--actor", "alice"})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "ALLOW rule")

	// Verify the rules table now holds exactly 3 entries (one per
	// dialect-aware bucket), each with expires_at set, and the
	// per-dialect note is correctly stamped.
	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	listed, err := st.ListRules()
	require.NoError(t, err)
	require.Len(t, listed, 3, "one rule per (dialect, stmt, table) bucket")

	dialectsSeen := map[string]int{}
	for _, sr := range listed {
		assert.Contains(t, sr.Rule.Note, "dialect=", "rule note must record dialect")
		assert.Contains(t, sr.Rule.Note, "expires_at=")
		if strings.Contains(sr.Rule.Note, "dialect=postgres") {
			dialectsSeen["postgres"]++
		}
		if strings.Contains(sr.Rule.Note, "dialect=mysql") {
			dialectsSeen["mysql"]++
		}
	}
	assert.Equal(t, 2, dialectsSeen["postgres"], "2 PG buckets")
	assert.Equal(t, 1, dialectsSeen["mysql"], "1 MySQL bucket")

	// Verify prompts are marked answered.
	for _, status := range []store.PromptStatus{store.PromptAnswered} {
		rows, err := st.ListPendingPrompts(status, 100)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(rows), 4)
		for _, r := range rows {
			assert.True(t, strings.HasPrefix(r.AnswerKind, "bulk-allow-"),
				"answer_kind must be bulk-allow-{decision}, got %q", r.AnswerKind)
			assert.Equal(t, "alice", r.AnsweredBy)
		}
	}
}

func TestBulkAnswer_ProfileSwapPostsOverride(t *testing.T) {
	db := dbAt(t)
	_ = enqueueDialectPrompt(t, db, "postgres", "SELECT", []string{"public.users"})

	cmd := newPromptsBulkAnswerCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db, "--decision", "profile",
		"--profile", "dev-only", "--yes", "--actor", "alice"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "hot-swap to profile")

	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	override, err := st.GetProfileOverride()
	require.NoError(t, err)
	require.NotNil(t, override)
	assert.Equal(t, "dev-only", override.ProfileName)
	assert.Equal(t, "alice", override.SetBy)

	rows, err := st.ListPendingPrompts(store.PromptAnswered, 100)
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	assert.Equal(t, "bulk-profile-swap", rows[0].AnswerKind)
	assert.Equal(t, "dev-only", rows[0].AnswerTarget)
}

func TestBulkAnswer_TimeBoundedRulesExpireAndFilter(t *testing.T) {
	// End-to-end: time-bounded rule synthesized; manually push the
	// clock by setting expiry to a past value; ListRules + LoadRuleSet
	// MUST stop seeing it.
	db := dbAt(t)
	_ = enqueueDialectPrompt(t, db, "postgres", "SELECT", []string{"public.x"})
	cmd := newPromptsBulkAnswerCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", db, "--decision", "10min", "--yes"})
	require.NoError(t, cmd.Execute())

	// Verify the rule exists right now.
	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	listed, err := st.ListRules()
	require.NoError(t, err)
	require.Len(t, listed, 1)
	// Sweeper now would not reap (TTL is 10min — not expired).
	n, err := st.SweepExpiredRules()
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)

	// Hack: directly update the rule's expires_at to a past timestamp
	// to simulate expiry. (Real-world this is just time passing.)
	// Re-open the DB at the raw sql.DB layer to issue a one-off
	// UPDATE — the store API intentionally doesn't expose an
	// "update expires_at" mutation (rules are append-only-ish at the
	// API surface; only Add + Sweep mutate the table).
	pastStr := time.Now().UTC().Add(-1 * time.Hour).Format("2006-01-02T15:04:05Z")
	rawDB, err := openRawSQLite(db)
	require.NoError(t, err)
	defer rawDB.Close()
	_, err = rawDB.Exec(`UPDATE rules SET expires_at = ? WHERE id = ?`,
		pastStr, int64(listed[0].ID))
	require.NoError(t, err)
	// ListRules filters expired.
	listed2, err := st.ListRules()
	require.NoError(t, err)
	assert.Empty(t, listed2, "expired rule must not appear in ListRules")
	// Sweep cleans it up.
	n, err = st.SweepExpiredRules()
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
}

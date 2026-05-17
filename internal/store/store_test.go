package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scratchStore returns an Open store on a temp file so tests don't
// touch ~/.dbounce/state.db.
func scratchStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpen_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "deep", "deeper", "state.db")
	s, err := Open(nested)
	require.NoError(t, err)
	defer s.Close()
	info, err := os.Stat(filepath.Dir(nested))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	// Parent dir should be 0o700 (private to user) per the kbounce
	// pattern.
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
}

func TestRecordDecision_RoundTrip(t *testing.T) {
	s := scratchStore(t)

	row := DecisionRow{
		At:               time.Now().UTC().Truncate(time.Second),
		Dialect:          "postgres",
		Statement:        "SELECT 1",
		StatementType:    "SELECT",
		TablesTouched:    []string{"public.users", "public.orders"},
		FunctionsCalled:  []string{"count", "pg_sleep"},
		IsDML:            false,
		IsDDL:            false,
		HasMutatingNode:  false,
		MutatingNodeType: "",
		IsExplain:        false,
		IsExplainAnalyze: false,
		ImpersonatedRole: "",
		ParseErrors:      nil,
		DecisionVerdict:  "ALLOW",
		DecisionReason:   "observation-only",
		ModeAtDecision:   "cooperative",
		Enforced:         false,
		DecisionSource:   "d-slice-1-observation-only",
		ProfileName:      "",
	}
	id, err := s.RecordDecision(row)
	require.NoError(t, err)
	assert.Greater(t, id, int64(0))

	rows, err := s.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	got := rows[0]
	assert.Equal(t, row.At.Unix(), got.At.Unix())
	assert.Equal(t, row.Dialect, got.Dialect)
	assert.Equal(t, row.Statement, got.Statement)
	assert.Equal(t, row.StatementType, got.StatementType)
	assert.Equal(t, row.TablesTouched, got.TablesTouched)
	assert.Equal(t, row.FunctionsCalled, got.FunctionsCalled)
	assert.Equal(t, row.DecisionVerdict, got.DecisionVerdict)
	assert.Equal(t, row.DecisionReason, got.DecisionReason)
	assert.Equal(t, row.ModeAtDecision, got.ModeAtDecision)
	assert.Equal(t, row.DecisionSource, got.DecisionSource)
}

func TestRecordDecision_FlagBag(t *testing.T) {
	// Mutating, DDL, EXPLAIN ANALYZE flags must round-trip cleanly so
	// the rule engine + recommender can filter on them without
	// re-parsing the SQL.
	s := scratchStore(t)
	row := DecisionRow{
		Dialect:          "postgres",
		Statement:        "EXPLAIN ANALYZE UPDATE users SET active = false",
		StatementType:    "EXPLAIN-ANALYZE",
		TablesTouched:    []string{"users"},
		IsDML:            true,
		IsDDL:            false,
		HasMutatingNode:  true,
		MutatingNodeType: "UPDATE",
		IsExplain:        false,
		IsExplainAnalyze: true,
		DecisionVerdict:  "ALLOW",
		DecisionReason:   "observation-only",
		ModeAtDecision:   "cooperative",
	}
	_, err := s.RecordDecision(row)
	require.NoError(t, err)

	rows, err := s.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.True(t, rows[0].IsDML)
	assert.False(t, rows[0].IsDDL)
	assert.True(t, rows[0].HasMutatingNode)
	assert.Equal(t, "UPDATE", rows[0].MutatingNodeType)
	assert.True(t, rows[0].IsExplainAnalyze)
}

func TestRecordDecision_ParseErrorsPreserved(t *testing.T) {
	s := scratchStore(t)
	row := DecisionRow{
		Dialect:         "postgres",
		Statement:       "SELECT * FROM",
		StatementType:   "UNPARSEABLE",
		ParseErrors:     []string{"syntax error at end of input"},
		DecisionVerdict: "ALLOW",
		DecisionReason:  "observation-only",
		ModeAtDecision:  "cooperative",
	}
	_, err := s.RecordDecision(row)
	require.NoError(t, err)
	rows, err := s.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, []string{"syntax error at end of input"}, rows[0].ParseErrors)
}

func TestRecentDecisions_Order(t *testing.T) {
	s := scratchStore(t)
	for i := 0; i < 5; i++ {
		_, err := s.RecordDecision(DecisionRow{
			Dialect:         "postgres",
			Statement:       "SELECT 1",
			StatementType:   "SELECT",
			DecisionVerdict: "ALLOW",
			DecisionReason:  "test",
			ModeAtDecision:  "cooperative",
		})
		require.NoError(t, err)
	}
	rows, err := s.RecentDecisions(3)
	require.NoError(t, err)
	require.Len(t, rows, 3, "limit must cap result set")
}

func TestRecentDecisions_DefaultsAndCaps(t *testing.T) {
	s := scratchStore(t)
	// Negative limit → default 50.
	rows, err := s.RecentDecisions(-1)
	require.NoError(t, err)
	assert.Empty(t, rows)
	// Limit > 1000 should still succeed (gets clamped).
	rows, err = s.RecentDecisions(5000)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestCountDecisions(t *testing.T) {
	s := scratchStore(t)
	n, err := s.CountDecisions()
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
	for i := 0; i < 3; i++ {
		_, err := s.RecordDecision(DecisionRow{
			Dialect:         "postgres",
			Statement:       "SELECT 1",
			StatementType:   "SELECT",
			DecisionVerdict: "ALLOW",
			DecisionReason:  "test",
			ModeAtDecision:  "cooperative",
		})
		require.NoError(t, err)
	}
	n, err = s.CountDecisions()
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
}

func TestSchema_Idempotent(t *testing.T) {
	// Opening the same DB twice must not error or duplicate-create
	// tables.
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s1, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, s1.Close())
	s2, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, s2.Close())
}

func TestGetActivePause_NoneActive(t *testing.T) {
	// D-Slice 1 doesn't insert pauses; this is the scaffolding path
	// /healthz uses. Must return nil + nil error on a fresh DB.
	s := scratchStore(t)
	p, err := s.GetActivePause()
	require.NoError(t, err)
	assert.Nil(t, p)
}

func TestDefaultDBPath_EnvOverride(t *testing.T) {
	t.Setenv("DBOUNCE_DB", "/tmp/dbounce-test-override.db")
	p, err := DefaultDBPath()
	require.NoError(t, err)
	assert.Equal(t, "/tmp/dbounce-test-override.db", p)
}

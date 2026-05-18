package store

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/rules"
)

// Tests for the bulk-prompt-answer UX store layer per
// [[bulk-prompt-answer-ux]]: time-bounded rules, bulk pending
// aggregation across multiple dialects, profile-override
// hot-swap signal.

func seedPGDeniedPrompt(t *testing.T, s *Store, stmtType string, tables []string) int64 {
	t.Helper()
	decID, err := s.RecordDecision(DecisionRow{
		Dialect:         "postgres",
		Statement:       "SELECT * FROM " + tables[0],
		StatementType:   stmtType,
		TablesTouched:   tables,
		DecisionVerdict: "DENY",
		DecisionReason:  "out-of-scope",
		ModeAtDecision:  "transparent",
	})
	require.NoError(t, err)
	promptID, err := s.AddPendingPrompt(PendingPrompt{
		DecisionID:    decID,
		StatementType: stmtType,
		TablesTouched: tables,
		DenyReason:    "out-of-scope",
	})
	require.NoError(t, err)
	return promptID
}

func seedMySQLDeniedPrompt(t *testing.T, s *Store, stmtType string, tables []string) int64 {
	t.Helper()
	decID, err := s.RecordDecision(DecisionRow{
		Dialect:         "mysql",
		Statement:       "UPDATE " + tables[0] + " SET x=1",
		StatementType:   stmtType,
		TablesTouched:   tables,
		DecisionVerdict: "DENY",
		DecisionReason:  "out-of-scope",
		ModeAtDecision:  "transparent",
	})
	require.NoError(t, err)
	promptID, err := s.AddPendingPrompt(PendingPrompt{
		DecisionID:    decID,
		StatementType: stmtType,
		TablesTouched: tables,
		DenyReason:    "out-of-scope",
	})
	require.NoError(t, err)
	return promptID
}

func TestAddRuleWithExpiry_FiltersExpired(t *testing.T) {
	s := scratchStore(t)
	// Add one permanent rule.
	permID, err := s.AddRule(rules.ProxyRule{
		Pattern: "SELECT:public.users", Effect: rules.EffectAllow,
	})
	require.NoError(t, err)
	// Add a future-expiring rule (visible).
	futureID, err := s.AddRuleWithExpiry(
		rules.ProxyRule{Pattern: "INSERT:public.users", Effect: rules.EffectAllow},
		time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	// Add an already-expired rule (filtered).
	expiredID, err := s.AddRuleWithExpiry(
		rules.ProxyRule{Pattern: "DELETE:public.users", Effect: rules.EffectAllow},
		time.Now().Add(-1*time.Hour))
	require.NoError(t, err)

	listed, err := s.ListRules()
	require.NoError(t, err)
	gotIDs := map[rules.ID]struct{}{}
	for _, r := range listed {
		gotIDs[r.ID] = struct{}{}
	}
	assert.Contains(t, gotIDs, permID, "permanent rule must be listed")
	assert.Contains(t, gotIDs, futureID, "non-expired time-bounded rule must be listed")
	assert.NotContains(t, gotIDs, expiredID, "expired rule MUST be filtered out of ListRules")

	// LoadRuleSet inherits the filter (it calls ListRules).
	rs, err := s.LoadRuleSet()
	require.NoError(t, err)
	for _, r := range rs.Rules() {
		assert.NotEqual(t, "DELETE:public.users", r.Pattern,
			"expired rule MUST NOT appear in LoadRuleSet snapshot")
	}
}

func TestSweepExpiredRules_DeletesOnlyExpired(t *testing.T) {
	s := scratchStore(t)
	permID, err := s.AddRule(rules.ProxyRule{
		Pattern: "SELECT:public.audit", Effect: rules.EffectAllow,
	})
	require.NoError(t, err)
	futureID, err := s.AddRuleWithExpiry(
		rules.ProxyRule{Pattern: "INSERT:public.audit", Effect: rules.EffectAllow},
		time.Now().Add(1*time.Hour))
	require.NoError(t, err)
	_, err = s.AddRuleWithExpiry(
		rules.ProxyRule{Pattern: "DELETE:public.audit", Effect: rules.EffectAllow},
		time.Now().Add(-1*time.Hour))
	require.NoError(t, err)

	n, err := s.SweepExpiredRules()
	require.NoError(t, err)
	assert.EqualValues(t, 1, n, "exactly one row should have been deleted")

	r, err := s.GetRule(permID)
	require.NoError(t, err)
	assert.NotNil(t, r, "permanent rule must survive sweep")
	r2, err := s.GetRule(futureID)
	require.NoError(t, err)
	assert.NotNil(t, r2, "future-expiring rule must survive sweep")
}

func TestListBulkPendingPrompts_GroupsByDialectStatementTable(t *testing.T) {
	s := scratchStore(t)
	// Burst: 3 PG SELECTs on public.users, 2 PG DELETEs on public.audit,
	// 4 MySQL UPDATEs on mydb.orders. Mixed-dialect burst.
	for i := 0; i < 3; i++ {
		_ = seedPGDeniedPrompt(t, s, "SELECT", []string{"public.users"})
	}
	for i := 0; i < 2; i++ {
		_ = seedPGDeniedPrompt(t, s, "DELETE", []string{"public.audit"})
	}
	for i := 0; i < 4; i++ {
		_ = seedMySQLDeniedPrompt(t, s, "UPDATE", []string{"mydb.orders"})
	}

	summary, err := s.ListBulkPendingPrompts()
	require.NoError(t, err)
	require.NotNil(t, summary)
	assert.Equal(t, 3+2+4, summary.TotalPrompts)
	assert.Equal(t, 3, len(summary.Entries),
		"three (dialect,stmt,table) buckets expected")
	// Dialects must be sorted + deduplicated.
	assert.Equal(t, []string{"mysql", "postgres"}, summary.Dialects)

	// Entries are sorted stable for presentation: dialect → stmt → table.
	want := []struct {
		dialect, stmt, table string
		count                int
	}{
		{"mysql", "UPDATE", "mydb.orders", 4},
		{"postgres", "DELETE", "public.audit", 2},
		{"postgres", "SELECT", "public.users", 3},
	}
	require.Len(t, summary.Entries, len(want))
	for i, e := range summary.Entries {
		assert.Equal(t, want[i].dialect, e.Key.Dialect, "entry %d dialect", i)
		assert.Equal(t, want[i].stmt, e.Key.StatementType, "entry %d stmt", i)
		assert.Equal(t, want[i].table, e.Key.Table, "entry %d table", i)
		assert.Equal(t, want[i].count, len(e.PromptIDs), "entry %d count", i)
	}
}

func TestListBulkPendingPrompts_NoTablesNormalizesToWildcard(t *testing.T) {
	s := scratchStore(t)
	// A DO block + a SET ROLE — both touch no tables. Persist with
	// tables_json="[]" so unmarshalStrings returns nil → bucketed
	// under table="*" per the spec.
	decID, err := s.RecordDecision(DecisionRow{
		Dialect:         "postgres",
		Statement:       "DO $$ BEGIN PERFORM 1; END $$;",
		StatementType:   "DO",
		TablesTouched:   nil,
		DecisionVerdict: "DENY",
		DecisionReason:  "DO not allowed",
		ModeAtDecision:  "transparent",
	})
	require.NoError(t, err)
	_, err = s.AddPendingPrompt(PendingPrompt{
		DecisionID:    decID,
		StatementType: "DO",
		TablesTouched: nil,
		DenyReason:    "DO not allowed",
	})
	require.NoError(t, err)

	summary, err := s.ListBulkPendingPrompts()
	require.NoError(t, err)
	require.Len(t, summary.Entries, 1)
	assert.Equal(t, "*", summary.Entries[0].Key.Table,
		"tableless statements must bucket under '*'")
}

func TestAnswerPendingPromptsBulk_MarksAllAtomically(t *testing.T) {
	s := scratchStore(t)
	id1 := seedPGDeniedPrompt(t, s, "SELECT", []string{"public.users"})
	id2 := seedPGDeniedPrompt(t, s, "SELECT", []string{"public.users"})
	id3 := seedPGDeniedPrompt(t, s, "DELETE", []string{"public.audit"})

	updated, err := s.AnswerPendingPromptsBulk(
		[]int64{id1, id2, id3}, "bulk-allow-10min", "", "alice")
	require.NoError(t, err)
	assert.EqualValues(t, 3, updated)

	for _, id := range []int64{id1, id2, id3} {
		p, err := s.GetPendingPrompt(id)
		require.NoError(t, err)
		require.NotNil(t, p)
		assert.Equal(t, PromptAnswered, p.Status, "prompt %d should be answered", id)
		assert.Equal(t, "bulk-allow-10min", p.AnswerKind)
		assert.Equal(t, "alice", p.AnsweredBy)
	}
}

func TestAnswerPendingPromptsBulk_IdempotentOnSecondCall(t *testing.T) {
	s := scratchStore(t)
	id := seedPGDeniedPrompt(t, s, "SELECT", []string{"public.users"})
	_, err := s.AnswerPendingPromptsBulk([]int64{id}, "bulk-allow-10min", "", "alice")
	require.NoError(t, err)
	// Second call must be a no-op for already-answered rows.
	updated, err := s.AnswerPendingPromptsBulk([]int64{id}, "bulk-allow-10min", "", "bob")
	require.NoError(t, err)
	assert.EqualValues(t, 0, updated, "already-answered row must be skipped")
}

func TestSyncWaitIDsForPromptIDs_OnlyReturnsSyncRows(t *testing.T) {
	s := scratchStore(t)
	// One async prompt.
	asyncID := seedPGDeniedPrompt(t, s, "SELECT", []string{"public.x"})
	// One sync prompt.
	decID := seedDecision(t, s)
	syncID, waitID, _, err := s.AddSyncPendingPrompt(PendingPrompt{
		DecisionID:    decID,
		StatementType: "INSERT",
		TablesTouched: []string{"public.y"},
		DenyReason:    "blocked",
	})
	require.NoError(t, err)

	waiters, err := s.SyncWaitIDsForPromptIDs([]int64{asyncID, syncID})
	require.NoError(t, err)
	assert.NotContains(t, waiters, asyncID, "async prompt has no sync_wait_id")
	require.Contains(t, waiters, syncID, "sync prompt must be present")
	assert.Equal(t, waitID, waiters[syncID])
}

func TestProfileOverride_RoundTrip(t *testing.T) {
	s := scratchStore(t)
	// Empty by default.
	got, err := s.GetProfileOverride()
	require.NoError(t, err)
	assert.Nil(t, got)
	// Set + read back.
	require.NoError(t, s.SetProfileOverride("dev-only", "alice", "bulk-answer"))
	got, err = s.GetProfileOverride()
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "dev-only", got.ProfileName)
	assert.Equal(t, "alice", got.SetBy)
	assert.Equal(t, "bulk-answer", got.Reason)
	// Overwrite.
	require.NoError(t, s.SetProfileOverride("incident-response", "bob", "page"))
	got, err = s.GetProfileOverride()
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "incident-response", got.ProfileName)
	assert.Equal(t, "bob", got.SetBy)
	// Clear.
	require.NoError(t, s.ClearProfileOverride())
	got, err = s.GetProfileOverride()
	require.NoError(t, err)
	assert.Nil(t, got, "cleared override should read as nil")
	// Clear again is a no-op.
	require.NoError(t, s.ClearProfileOverride())
}

func TestProfileOverride_RequiresName(t *testing.T) {
	s := scratchStore(t)
	err := s.SetProfileOverride("", "alice", "test")
	require.Error(t, err)
}

func TestListBulkPendingPrompts_PromptsTouchingMultipleTables(t *testing.T) {
	// A single prompt with multiple tables contributes to each
	// bucket but is only counted once total.
	s := scratchStore(t)
	id := seedPGDeniedPrompt(t, s, "SELECT", []string{"public.a", "public.b"})

	summary, err := s.ListBulkPendingPrompts()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalPrompts, "one prompt counted once")
	require.Len(t, summary.Entries, 2, "prompt with 2 tables → 2 entries")
	// Each bucket contains the prompt id exactly once (not double-counted).
	tables := []string{}
	for _, e := range summary.Entries {
		assert.Equal(t, []int64{id}, e.PromptIDs)
		tables = append(tables, e.Key.Table)
	}
	sort.Strings(tables)
	assert.Equal(t, []string{"public.a", "public.b"}, tables)
}

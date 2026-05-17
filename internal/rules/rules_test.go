package rules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePattern_Valid(t *testing.T) {
	cases := []struct {
		input         string
		wantStmtType  string
		wantTableGlob string
	}{
		{"SELECT:*", "SELECT", "*"},
		{"select:*", "SELECT", "*"},
		{"DELETE:public.users", "DELETE", "public.users"},
		{"DML:reports_*", "DML", "reports_*"},
		{"MUTATING:*", "MUTATING", "*"},
		{"READ:*", "READ", "*"},
		{"CALL:*", "CALL", "*"},
		{"*:public.audit_log", "*", "public.audit_log"},
		{"*", "*", "*"},
		{"WITH-WRITE:*", "WITH-WRITE", "*"},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			st, tg, err := ParsePattern(c.input)
			require.NoError(t, err)
			assert.Equal(t, c.wantStmtType, st)
			assert.Equal(t, c.wantTableGlob, tg)
		})
	}
}

func TestParsePattern_Invalid(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"SELECT",        // no colon
		"SELECT::table", // empty halves
		":table",        // empty stmt type
		"SELECT:",       // empty table
		"SE*:*",         // partial wildcard at stmt type
		"SELECT *",      // whitespace
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			_, _, err := ParsePattern(c)
			require.Error(t, err)
			var bad *ErrInvalidPattern
			assert.ErrorAs(t, err, &bad)
		})
	}
}

func TestProxyRule_Matches_PatternAndTableGlob(t *testing.T) {
	r := ProxyRule{Pattern: "SELECT:public.*", Effect: EffectAllow}
	ps := &ParsedStatement{
		StatementType: "SELECT",
		TablesTouched: []string{"public.users"},
	}
	assert.True(t, r.Matches(ps))

	ps2 := &ParsedStatement{
		StatementType: "SELECT",
		TablesTouched: []string{"reporting.users"},
	}
	assert.False(t, r.Matches(ps2))

	ps3 := &ParsedStatement{
		StatementType: "INSERT",
		TablesTouched: []string{"public.users"},
	}
	assert.False(t, r.Matches(ps3))
}

func TestProxyRule_Matches_SchemaScope(t *testing.T) {
	r := ProxyRule{Pattern: "DML:*", SchemaScope: "reports", Effect: EffectAllow}
	psHit := &ParsedStatement{
		StatementType: "INSERT",
		IsDML:         true,
		TablesTouched: []string{"reports.monthly"},
	}
	assert.True(t, r.Matches(psHit))

	psMiss := &ParsedStatement{
		StatementType: "INSERT",
		IsDML:         true,
		TablesTouched: []string{"public.monthly"},
	}
	assert.False(t, r.Matches(psMiss))

	// Statement with no tables and a non-wildcard schema scope: no match.
	psNoTables := &ParsedStatement{
		StatementType: "DO",
		TablesTouched: nil,
	}
	rNoMatch := ProxyRule{Pattern: "*", SchemaScope: "public", Effect: EffectAllow}
	assert.False(t, rNoMatch.Matches(psNoTables))
}

func TestProxyRule_Matches_TableScope(t *testing.T) {
	r := ProxyRule{Pattern: "*", TableScope: "*.users", Effect: EffectDeny}
	ps := &ParsedStatement{
		StatementType: "SELECT",
		TablesTouched: []string{"public.users", "public.orders"},
	}
	assert.True(t, r.Matches(ps), "ANY-table-matches must hit when one of N tables matches the glob")

	psNoHit := &ParsedStatement{
		StatementType: "SELECT",
		TablesTouched: []string{"public.orders"},
	}
	assert.False(t, r.Matches(psNoHit))
}

func TestProxyRule_Matches_FunctionScope_CallProc(t *testing.T) {
	// `CALL:*#approved_proc` style — narrowing stored-proc calls.
	r := ProxyRule{
		Pattern:       "CALL:*",
		FunctionScope: "approved_proc",
		Effect:        EffectAllow,
	}
	psHit := &ParsedStatement{
		StatementType:   "CALL",
		FunctionsCalled: []string{"approved_proc"},
	}
	assert.True(t, r.Matches(psHit))

	psMiss := &ParsedStatement{
		StatementType:   "CALL",
		FunctionsCalled: []string{"sketchy_proc"},
	}
	assert.False(t, r.Matches(psMiss))
}

func TestProxyRule_Matches_MutatingCategory_CatchesCTEHiddenWrite(t *testing.T) {
	// LOAD-BEARING per dbounce-build-plan §"CTE-hidden writes": a SELECT
	// that wraps a write in a CTE has top-level StatementType=SELECT
	// (or WITH-WRITE if the walker reclassified). Either way,
	// HasMutatingNode=true, and a MUTATING:* rule must hit.
	r := ProxyRule{Pattern: "MUTATING:*", Effect: EffectDeny}

	// Case 1: top-level SELECT with HasMutatingNode=true (walker
	// detected a write but didn't reclassify because the operator
	// crafted it past the reclassify path).
	psSelect := &ParsedStatement{
		StatementType:   "SELECT",
		TablesTouched:   []string{"public.users"},
		HasMutatingNode: true,
	}
	assert.True(t, r.Matches(psSelect),
		"MUTATING:* MUST catch CTE-hidden writes via HasMutatingNode even when top-level type is SELECT")

	// Case 2: top-level WITH-WRITE (walker reclassified).
	psWithWrite := &ParsedStatement{
		StatementType:   "WITH-WRITE",
		TablesTouched:   []string{"public.users"},
		HasMutatingNode: true,
		IsDML:           false, // walker didn't set IsDML
	}
	assert.True(t, r.Matches(psWithWrite))

	// Case 3: plain SELECT, NO mutating node → MUTATING:* must NOT hit.
	psPlainSelect := &ParsedStatement{
		StatementType:   "SELECT",
		TablesTouched:   []string{"public.users"},
		HasMutatingNode: false,
	}
	assert.False(t, r.Matches(psPlainSelect))
}

func TestProxyRule_Matches_DMLCategory(t *testing.T) {
	r := ProxyRule{Pattern: "DML:public.*", Effect: EffectDeny}
	psInsert := &ParsedStatement{
		StatementType: "INSERT",
		IsDML:         true,
		TablesTouched: []string{"public.audit"},
	}
	assert.True(t, r.Matches(psInsert))

	// SELECT is not DML — no match even on public.* table.
	psSelect := &ParsedStatement{
		StatementType: "SELECT",
		TablesTouched: []string{"public.audit"},
	}
	assert.False(t, r.Matches(psSelect))

	// WITH-WRITE counts as DML (it IS a write).
	psWithWrite := &ParsedStatement{
		StatementType:   "WITH-WRITE",
		TablesTouched:   []string{"public.audit"},
		HasMutatingNode: true,
	}
	assert.True(t, r.Matches(psWithWrite))
}

func TestProxyRule_Matches_ReadCategory(t *testing.T) {
	rAllow := ProxyRule{Pattern: "READ:*", Effect: EffectAllow}
	psSelect := &ParsedStatement{StatementType: "SELECT"}
	assert.True(t, rAllow.Matches(psSelect))

	psExplain := &ParsedStatement{StatementType: "EXPLAIN", IsExplain: true}
	assert.True(t, rAllow.Matches(psExplain))

	// EXPLAIN ANALYZE is NOT a read — it executes the inner statement.
	psExplainAnalyze := &ParsedStatement{
		StatementType:    "EXPLAIN-ANALYZE",
		IsExplainAnalyze: true,
	}
	assert.False(t, rAllow.Matches(psExplainAnalyze))

	// DELETE is not a read.
	psDelete := &ParsedStatement{StatementType: "DELETE", IsDML: true}
	assert.False(t, rAllow.Matches(psDelete))
}

func TestProxyRule_Matches_DDLCategory(t *testing.T) {
	r := ProxyRule{Pattern: "DDL:*", Effect: EffectDeny}
	psDrop := &ParsedStatement{StatementType: "DDL", IsDDL: true}
	assert.True(t, r.Matches(psDrop))

	psSelect := &ParsedStatement{StatementType: "SELECT"}
	assert.False(t, r.Matches(psSelect))
}

func TestRuleSet_Evaluate_DenyBeatsAllow(t *testing.T) {
	rs := NewRuleSet([]ProxyRule{
		{Pattern: "SELECT:*", Effect: EffectAllow},
		{Pattern: "*:public.secrets", Effect: EffectDeny},
	})
	ps := &ParsedStatement{
		StatementType: "SELECT",
		TablesTouched: []string{"public.secrets"},
	}
	got := rs.Evaluate(ps)
	require.NotNil(t, got)
	assert.Equal(t, EffectDeny, got.Effect,
		"deny must beat allow even when allow appears first in the rule list")
}

func TestRuleSet_Evaluate_FirstMatchWithinAllow(t *testing.T) {
	rs := NewRuleSet([]ProxyRule{
		{Pattern: "SELECT:public.*", Effect: EffectAllow, Note: "A"},
		{Pattern: "SELECT:*", Effect: EffectAllow, Note: "B"},
	})
	ps := &ParsedStatement{
		StatementType: "SELECT",
		TablesTouched: []string{"public.users"},
	}
	got := rs.Evaluate(ps)
	require.NotNil(t, got)
	assert.Equal(t, EffectAllow, got.Effect)
	assert.Equal(t, "A", got.Rule.Note, "first-match within a class wins")
}

func TestRuleSet_Evaluate_NoMatch(t *testing.T) {
	rs := NewRuleSet([]ProxyRule{
		{Pattern: "SELECT:reports.*", Effect: EffectAllow},
	})
	ps := &ParsedStatement{
		StatementType: "INSERT",
		TablesTouched: []string{"public.users"},
	}
	assert.Nil(t, rs.Evaluate(ps), "no match -> nil so caller falls through")
}

func TestRuleSet_Add_RejectsBadEffect(t *testing.T) {
	rs := NewRuleSet(nil)
	err := rs.Add(ProxyRule{Pattern: "SELECT:*", Effect: Effect("maybe")})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "invalid rule effect"))
}

func TestProxyRule_ToMap_RoundTripFields(t *testing.T) {
	r := ProxyRule{
		Pattern:       "DML:public.*",
		Effect:        EffectDeny,
		SchemaScope:   "public",
		TableScope:    "users",
		FunctionScope: "*",
		Note:          "no writes to public",
		Origin:        OriginUser,
	}
	m := r.ToMap()
	assert.Equal(t, "DML:public.*", m["pattern"])
	assert.Equal(t, "deny", m["effect"])
	assert.Equal(t, "public", m["schema_scope"])
	assert.Equal(t, "users", m["table_scope"])
	assert.Equal(t, "*", m["function_scope"])
	assert.Equal(t, "no writes to public", m["note"])
	assert.Equal(t, OriginUser, m["origin"])
}

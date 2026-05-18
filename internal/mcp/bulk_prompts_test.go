package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/proxy"
	"github.com/trsreagan3/dbounce/internal/store"
)

// MCP-layer tests for the bulk-prompt-answer UX per
// [[bulk-prompt-answer-ux]]. Mirror the shape of the existing
// MCP-tool tests.

func seedPendingPromptOnStore(t *testing.T, st *store.Store, dialect, stmt string, tables []string) int64 {
	t.Helper()
	decID, err := st.RecordDecision(store.DecisionRow{
		Dialect:         dialect,
		Statement:       "stmt",
		StatementType:   stmt,
		TablesTouched:   tables,
		DecisionVerdict: "DENY",
		DecisionReason:  "out-of-scope",
		ModeAtDecision:  "transparent",
	})
	require.NoError(t, err)
	id, err := st.AddPendingPrompt(store.PendingPrompt{
		DecisionID:    decID,
		StatementType: stmt,
		TablesTouched: tables,
		DenyReason:    "out-of-scope",
	})
	require.NoError(t, err)
	return id
}

func newMCPWithToken(t *testing.T, token string) (*Server, *store.Store) {
	t.Helper()
	srv, st := newTestServer(t, nil)
	srv.cfg.BulkAnswerToken = token
	srv.cfg.Mode = proxy.ModeCooperative
	srv.cfg.Dialect = proxy.DialectPostgres
	return srv, st
}

func TestMCP_BulkPending_GroupsByDialect(t *testing.T) {
	srv, st := newMCPWithToken(t, "")
	_ = seedPendingPromptOnStore(t, st, "postgres", "SELECT", []string{"public.users"})
	_ = seedPendingPromptOnStore(t, st, "postgres", "SELECT", []string{"public.users"})
	_ = seedPendingPromptOnStore(t, st, "mysql", "UPDATE", []string{"mydb.orders"})

	sc := rpcCallTool(t, srv, "dbounce_prompts_bulk_pending", nil)
	assert.EqualValues(t, 3, sc["total_prompts"])
	dialects := sc["dialects"].([]any)
	assert.ElementsMatch(t, []any{"mysql", "postgres"}, dialects)
	entries := sc["entries"].([]any)
	assert.Len(t, entries, 2)
}

func TestMCP_BulkAnswer_DefaultDisabled(t *testing.T) {
	srv, st := newMCPWithToken(t, "") // no token configured
	_ = seedPendingPromptOnStore(t, st, "postgres", "SELECT", []string{"public.users"})
	sc := rpcCallTool(t, srv, "dbounce_prompts_bulk_answer", map[string]any{
		"decision": "10min", "token": "anything",
	})
	assert.Equal(t, "disabled", sc["error"],
		"bulk-answer MUST be disabled by default — no operator-set token")
}

func TestMCP_BulkAnswer_RejectsWrongToken(t *testing.T) {
	srv, st := newMCPWithToken(t, "correct-token")
	_ = seedPendingPromptOnStore(t, st, "postgres", "SELECT", []string{"public.users"})
	sc := rpcCallTool(t, srv, "dbounce_prompts_bulk_answer", map[string]any{
		"decision": "10min", "token": "wrong-token",
	})
	assert.Equal(t, "invalid_token", sc["error"])
}

func TestMCP_BulkAnswer_RejectsEmptyToken(t *testing.T) {
	srv, st := newMCPWithToken(t, "correct-token")
	_ = seedPendingPromptOnStore(t, st, "postgres", "SELECT", []string{"public.users"})
	sc := rpcCallTool(t, srv, "dbounce_prompts_bulk_answer", map[string]any{
		"decision": "10min", "token": "",
	})
	assert.Equal(t, "invalid_token", sc["error"])
}

func TestMCP_BulkAnswer_TimeBoundedCreatesPerDialectRules(t *testing.T) {
	srv, st := newMCPWithToken(t, "the-token")
	_ = seedPendingPromptOnStore(t, st, "postgres", "SELECT", []string{"public.users"})
	_ = seedPendingPromptOnStore(t, st, "mysql", "UPDATE", []string{"mydb.orders"})
	sc := rpcCallTool(t, srv, "dbounce_prompts_bulk_answer", map[string]any{
		"decision": "10min", "token": "the-token",
	})
	assert.Equal(t, "10min", sc["applied"])
	assert.EqualValues(t, 2, sc["rules_created"], "one rule per dialect")
	listed, err := st.ListRules()
	require.NoError(t, err)
	assert.Len(t, listed, 2)
}

func TestMCP_BulkAnswer_ProfileSwapPostsOverride(t *testing.T) {
	srv, st := newMCPWithToken(t, "the-token")
	_ = seedPendingPromptOnStore(t, st, "postgres", "SELECT", []string{"public.users"})
	sc := rpcCallTool(t, srv, "dbounce_prompts_bulk_answer", map[string]any{
		"decision": "profile", "token": "the-token", "profile_name": "dev-only",
	})
	assert.Equal(t, "profile", sc["applied"])
	assert.Equal(t, true, sc["hot_swap_pending"])
	override, err := st.GetProfileOverride()
	require.NoError(t, err)
	require.NotNil(t, override)
	assert.Equal(t, "dev-only", override.ProfileName)
}

func TestMCP_BulkAnswer_NoneIsNoOp(t *testing.T) {
	srv, st := newMCPWithToken(t, "the-token")
	id := seedPendingPromptOnStore(t, st, "postgres", "SELECT", []string{"public.users"})
	sc := rpcCallTool(t, srv, "dbounce_prompts_bulk_answer", map[string]any{
		"decision": "none", "token": "the-token",
	})
	assert.Equal(t, "none", sc["applied"])
	p, err := st.GetPendingPrompt(id)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, store.PromptPending, p.Status, "no-op must leave prompt pending")
}

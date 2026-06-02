// parity_tools_test.go — MCP tool tests for the 4 tools added in #7
// to bring dbounce to agent-parity with kbounce/ibounce:
//
//   - dbounce_recommend_rules     (SQL-domain equivalent of kbounce_recommend_rules)
//   - dbounce_apply_preset        (SQL-domain equivalent of kbounce_apply_preset)
//   - dbounce_task_review         (SQL-domain equivalent of kbounce_task_review)
//   - dbounce_scope_self_for_task (SQL-domain equivalent of kbounce_scope_self_for_task)
//
// Also covers the supporting dbounce_end_task + dbounce_list_presets
// tools that are part of the same parity surface.
//
// Per [[tests-and-independent-uat-required]]: each tool is covered by
// at least one BB (registered + dispatches) + one WB (returns sane
// output) scenario. Per [[cross-product-agent-parity]]: tool names
// + arg shapes are verified to match the kbounce surface (SQL-domain
// adapted).
package mcp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/store"
)

// ---------------------------------------------------------------------------
// dbounce_recommend_rules
// ---------------------------------------------------------------------------

func TestMCP_RecommendRules_ReturnsSQLRecommendations(t *testing.T) {
	srv, st := newTestServer(t, nil)
	// Seed 4 ALLOW decisions for SELECT on public.users so they clear
	// the default min_support=3 gate.
	for i := 0; i < 4; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			Dialect:         "postgres",
			StatementType:   "SELECT",
			TablesTouched:   []string{"public.users"},
			DecisionVerdict: "ALLOW",
		})
		require.NoError(t, err)
	}

	sc := rpcCallTool(t, srv, "dbounce_recommend_rules", map[string]any{
		"min_support": 3,
	})
	require.NotNil(t, sc)
	count, _ := sc["count"].(float64)
	assert.GreaterOrEqual(t, int(count), 1, "at least one recommendation expected")
	recs, ok := sc["recommendations"].([]any)
	require.True(t, ok, "recommendations must be a list")
	require.GreaterOrEqual(t, len(recs), 1)

	// Verify proposed_rule has SQL-domain fields.
	first := recs[0].(map[string]any)
	proposed, ok := first["proposed_rule"].(map[string]any)
	require.True(t, ok, "proposed_rule must be a map")
	assert.Contains(t, proposed["pattern"].(string), "SELECT",
		"pattern must contain the SQL statement type")
	assert.Equal(t, "allow", proposed["effect"])
}

func TestMCP_RecommendRules_ReadOnly_DoesNotApply(t *testing.T) {
	srv, st := newTestServer(t, nil)
	// Seed enough ALLOWs to get a recommendation.
	for i := 0; i < 4; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			StatementType:   "DELETE",
			TablesTouched:   []string{"public.logs"},
			DecisionVerdict: "ALLOW",
		})
		require.NoError(t, err)
	}

	before, err := st.ListRules()
	require.NoError(t, err)

	_ = rpcCallTool(t, srv, "dbounce_recommend_rules", map[string]any{})

	after, err := st.ListRules()
	require.NoError(t, err)
	assert.Equal(t, len(before), len(after),
		"dbounce_recommend_rules must be read-only; rule count must not change")
}

func TestMCP_RecommendRules_BelowMinSupport_NoRecs(t *testing.T) {
	srv, st := newTestServer(t, nil)
	// Only 2 decisions; min_support=3 → no recommendations.
	for i := 0; i < 2; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			StatementType:   "SELECT",
			TablesTouched:   []string{"public.foo"},
			DecisionVerdict: "ALLOW",
		})
		require.NoError(t, err)
	}
	sc := rpcCallTool(t, srv, "dbounce_recommend_rules", map[string]any{
		"min_support": 3,
	})
	count, _ := sc["count"].(float64)
	assert.Equal(t, float64(0), count,
		"no recommendations when support < min_support")
}

func TestMCP_RecommendRules_DenyDecisions_NotRecommended(t *testing.T) {
	// CRIT-28-01: DENY decisions must NOT drive recommendations.
	srv, st := newTestServer(t, nil)
	for i := 0; i < 5; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			StatementType:   "DROP",
			TablesTouched:   []string{"public.sensitive"},
			DecisionVerdict: "DENY",
		})
		require.NoError(t, err)
	}
	sc := rpcCallTool(t, srv, "dbounce_recommend_rules", map[string]any{
		"min_support": 3,
	})
	count, _ := sc["count"].(float64)
	assert.Equal(t, float64(0), count,
		"DENY decisions must never produce recommendations (CRIT-28-01)")
}

func TestMCP_RecommendRules_NoStore(t *testing.T) {
	srv := NewServer(Config{})
	sc := rpcCallTool(t, srv, "dbounce_recommend_rules", nil)
	assert.Contains(t, sc["error"].(string), "store not configured")
}

func TestMCP_RecommendRules_RegisteredInToolsList(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := rpcCall(t, srv, "tools/list", nil)
	result := resp["result"].(map[string]any)
	toolsAny := result["tools"].([]any)
	found := false
	for _, ti := range toolsAny {
		if m := ti.(map[string]any); m["name"] == "dbounce_recommend_rules" {
			found = true
		}
	}
	assert.True(t, found, "dbounce_recommend_rules must appear in tools/list")
}

// ---------------------------------------------------------------------------
// dbounce_apply_preset + dbounce_list_presets
// ---------------------------------------------------------------------------

func TestMCP_ListPresets_ReturnsSQLCatalog(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sc := rpcCallTool(t, srv, "dbounce_list_presets", nil)
	count, _ := sc["count"].(float64)
	assert.GreaterOrEqual(t, int(count), 1, "must surface at least one SQL preset")
	presets, ok := sc["presets"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, presets)
	// Each entry must have id, name, title, description, rule_count.
	// name == id so agents can pass list_presets → apply_preset(name=...) without mapping.
	first := presets[0].(map[string]any)
	assert.NotEmpty(t, first["id"], "preset must have id")
	assert.NotEmpty(t, first["name"], "preset must have name (kbounce parity for apply_preset arg)")
	assert.Equal(t, first["id"], first["name"], "name must equal id")
	assert.NotEmpty(t, first["title"], "preset must have title")
	rc, _ := first["rule_count"].(float64)
	assert.Greater(t, int(rc), 0, "preset must have at least one rule")
}

func TestMCP_ApplyPreset_AddsRulesToStore(t *testing.T) {
	srv, st := newTestServer(t, nil)

	before, err := st.ListRules()
	require.NoError(t, err)

	// Use the "analytics-engineer" preset which is known to exist.
	sc := rpcCallTool(t, srv, "dbounce_apply_preset", map[string]any{
		"name": "analytics-engineer",
	})
	require.Nil(t, sc["error"], "apply_preset must not return an error, got: %v", sc["error"])
	assert.Equal(t, "analytics-engineer", sc["preset"])
	applied, _ := sc["applied"].(float64)
	assert.Greater(t, int(applied), 0, "at least one rule must be applied")

	after, err := st.ListRules()
	require.NoError(t, err)
	assert.Greater(t, len(after), len(before),
		"rule count must grow after apply_preset")

	ids, ok := sc["rule_ids"].([]any)
	require.True(t, ok, "rule_ids must be a list")
	assert.Len(t, ids, int(applied), "rule_ids length must match applied count")
}

func TestMCP_ApplyPreset_UnknownPreset_ReturnsError(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sc := rpcCallTool(t, srv, "dbounce_apply_preset", map[string]any{
		"name": "this-preset-does-not-exist",
	})
	assert.Contains(t, sc["error"].(string), "not found")
}

func TestMCP_ApplyPreset_NoStore_ReturnsError(t *testing.T) {
	srv := NewServer(Config{})
	sc := rpcCallTool(t, srv, "dbounce_apply_preset", map[string]any{
		"name": "analytics-engineer",
	})
	assert.Contains(t, sc["error"].(string), "store not configured")
}

func TestMCP_ApplyPreset_RegisteredInToolsList(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := rpcCall(t, srv, "tools/list", nil)
	result := resp["result"].(map[string]any)
	toolsAny := result["tools"].([]any)
	found := false
	for _, ti := range toolsAny {
		if m := ti.(map[string]any); m["name"] == "dbounce_apply_preset" {
			found = true
		}
	}
	assert.True(t, found, "dbounce_apply_preset must appear in tools/list")
}

// ---------------------------------------------------------------------------
// dbounce_scope_self_for_task + dbounce_end_task + dbounce_task_review
// ---------------------------------------------------------------------------

func TestMCP_ScopeSelfForTask_CreatesTaskAndReturnsID(t *testing.T) {
	srv, st := newTestServer(t, nil)

	sc := rpcCallTool(t, srv, "dbounce_scope_self_for_task", map[string]any{
		"description":     "Read-only reporting task on public.orders",
		"statement_types": []any{"SELECT"},
		"tables":          []any{"public.orders"},
		"duration_minutes": float64(15),
	})
	require.Nil(t, sc["error"], "scope_self_for_task must not error, got: %v", sc["error"])

	taskID, _ := sc["task_id"].(string)
	require.NotEmpty(t, taskID, "task_id must be returned")
	expiresAt, _ := sc["expires_at"].(string)
	assert.NotEmpty(t, expiresAt)
	allowN, _ := sc["allow_rule_n"].(float64)
	assert.Equal(t, float64(1), allowN, "one statement_type × one table = 1 allow rule")

	// Confirm the task is now active in the store.
	active, err := st.GetActiveTask("")
	require.NoError(t, err)
	require.NotNil(t, active, "task must be active after scope_self_for_task")
	assert.Equal(t, taskID, active.TaskID)
}

func TestMCP_ScopeSelfForTask_MultipleStatementTypesAndTables(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	sc := rpcCallTool(t, srv, "dbounce_scope_self_for_task", map[string]any{
		"description":     "analytics task",
		"statement_types": []any{"SELECT", "EXPLAIN"},
		"tables":          []any{"public.events", "public.users"},
	})
	require.Nil(t, sc["error"])
	allowN, _ := sc["allow_rule_n"].(float64)
	// 2 statement types × 2 tables = 4 allow rules.
	assert.Equal(t, float64(4), allowN)
}

func TestMCP_ScopeSelfForTask_WithDenyTypes(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	sc := rpcCallTool(t, srv, "dbounce_scope_self_for_task", map[string]any{
		"description":          "safe migration",
		"statement_types":      []any{"SELECT"},
		"tables":               []any{"*"},
		"deny_statement_types": []any{"DROP", "TRUNCATE"},
	})
	require.Nil(t, sc["error"])
	denyN, _ := sc["deny_rule_n"].(float64)
	assert.Equal(t, float64(2), denyN, "two deny_statement_types → two deny rules")
}

func TestMCP_ScopeSelfForTask_MissingRequiredArgs_ReturnsError(t *testing.T) {
	srv, _ := newTestServer(t, nil)

	// Missing tables.
	sc := rpcCallTool(t, srv, "dbounce_scope_self_for_task", map[string]any{
		"description":     "incomplete",
		"statement_types": []any{"SELECT"},
		// tables intentionally omitted
	})
	assert.NotNil(t, sc["error"], "missing tables must return an error")

	// Missing statement_types.
	sc2 := rpcCallTool(t, srv, "dbounce_scope_self_for_task", map[string]any{
		"description": "incomplete",
		"tables":      []any{"public.foo"},
	})
	assert.NotNil(t, sc2["error"], "missing statement_types must return an error")
}

func TestMCP_ScopeSelfForTask_RegisteredInToolsList(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := rpcCall(t, srv, "tools/list", nil)
	result := resp["result"].(map[string]any)
	toolsAny := result["tools"].([]any)
	found := false
	for _, ti := range toolsAny {
		if m := ti.(map[string]any); m["name"] == "dbounce_scope_self_for_task" {
			found = true
		}
	}
	assert.True(t, found, "dbounce_scope_self_for_task must appear in tools/list")
}

func TestMCP_EndTask_NoActiveTask(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sc := rpcCallTool(t, srv, "dbounce_end_task", map[string]any{
		"reason": "test",
	})
	require.Nil(t, sc["error"])
	assert.Equal(t, false, sc["ended"], "ended must be false when no active task")
}

func TestMCP_EndTask_EndsActiveTask(t *testing.T) {
	srv, st := newTestServer(t, nil)

	// Open a task first.
	openSC := rpcCallTool(t, srv, "dbounce_scope_self_for_task", map[string]any{
		"description":     "task to end",
		"statement_types": []any{"SELECT"},
		"tables":          []any{"public.x"},
	})
	require.Nil(t, openSC["error"])
	taskID, _ := openSC["task_id"].(string)

	// Confirm active.
	active, err := st.GetActiveTask("")
	require.NoError(t, err)
	require.NotNil(t, active)

	// End it via MCP.
	endSC := rpcCallTool(t, srv, "dbounce_end_task", map[string]any{
		"reason": "finished reporting",
	})
	require.Nil(t, endSC["error"])
	assert.Equal(t, true, endSC["ended"])
	assert.Equal(t, taskID, endSC["task_id"])

	// Should now be gone.
	active2, err := st.GetActiveTask("")
	require.NoError(t, err)
	assert.Nil(t, active2, "task must no longer be active after end_task")
}

// ---------------------------------------------------------------------------
// dbounce_task_review
// ---------------------------------------------------------------------------

func TestMCP_TaskReview_SummarizesDecisions(t *testing.T) {
	srv, st := newTestServer(t, nil)

	// Open a task via the MCP tool — this gives us a real task_id.
	openSC := rpcCallTool(t, srv, "dbounce_scope_self_for_task", map[string]any{
		"description":      "review test task",
		"statement_types":  []any{"SELECT"},
		"tables":           []any{"public.orders"},
		"duration_minutes": float64(30),
	})
	require.Nil(t, openSC["error"])
	taskID, _ := openSC["task_id"].(string)

	// Seed two ALLOW + one DENY decision referencing the task_id.
	for i := 0; i < 2; i++ {
		_, err := st.RecordDecision(store.DecisionRow{
			StatementType:   "SELECT",
			TablesTouched:   []string{"public.orders"},
			DecisionVerdict: "ALLOW",
			TaskID:          taskID,
		})
		require.NoError(t, err)
	}
	_, err := st.RecordDecision(store.DecisionRow{
		StatementType:   "DELETE",
		TablesTouched:   []string{"public.orders"},
		DecisionVerdict: "DENY",
		DecisionReason:  "out-of-task-scope",
		TaskID:          taskID,
	})
	require.NoError(t, err)

	// End the task so review can load it.
	endSC := rpcCallTool(t, srv, "dbounce_end_task", map[string]any{
		"reason": "done",
	})
	require.Nil(t, endSC["error"])

	// Now review.
	sc := rpcCallTool(t, srv, "dbounce_task_review", map[string]any{
		"task_id": taskID,
	})
	require.Nil(t, sc["error"], "task_review must not error, got: %v", sc["error"])
	assert.Equal(t, taskID, sc["task_id"])
	assert.Equal(t, float64(3), sc["decision_count"])
	assert.Equal(t, float64(2), sc["allow_count"])
	assert.Equal(t, float64(1), sc["deny_count"])
	assert.Equal(t, float64(1), sc["denied_calls_n"])
}

func TestMCP_TaskReview_MissingTaskID_ReturnsError(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sc := rpcCallTool(t, srv, "dbounce_task_review", map[string]any{})
	assert.Contains(t, sc["error"].(string), "task_id required")
}

func TestMCP_TaskReview_UnknownTaskID_ReturnsError(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sc := rpcCallTool(t, srv, "dbounce_task_review", map[string]any{
		"task_id": "nonexistent-id-abc123",
	})
	assert.NotNil(t, sc["error"])
	assert.Contains(t, sc["error"].(string), "nonexistent-id-abc123")
}

func TestMCP_TaskReview_RegisteredInToolsList(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := rpcCall(t, srv, "tools/list", nil)
	result := resp["result"].(map[string]any)
	toolsAny := result["tools"].([]any)
	found := false
	for _, ti := range toolsAny {
		if m := ti.(map[string]any); m["name"] == "dbounce_task_review" {
			found = true
		}
	}
	assert.True(t, found, "dbounce_task_review must appear in tools/list")
}

// ---------------------------------------------------------------------------
// tools/list parity check — all 4 parity tools must appear
// ---------------------------------------------------------------------------

func TestMCP_ParityTools_AllPresentInToolsList(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := rpcCall(t, srv, "tools/list", nil)
	result := resp["result"].(map[string]any)
	toolsAny := result["tools"].([]any)
	names := map[string]bool{}
	for _, ti := range toolsAny {
		m := ti.(map[string]any)
		names[m["name"].(string)] = true
	}
	parityTools := []string{
		"dbounce_recommend_rules",
		"dbounce_apply_preset",
		"dbounce_task_review",
		"dbounce_scope_self_for_task",
		// Support tools that come with the parity set:
		"dbounce_end_task",
		"dbounce_list_presets",
	}
	for _, tool := range parityTools {
		assert.True(t, names[tool],
			"parity tool %q must be present in tools/list", tool)
	}
}

// ---------------------------------------------------------------------------
// parseSinceArg — unit tests for the shared time-window parser
// (mirrors kbouncer's equivalent coverage)
// ---------------------------------------------------------------------------

func TestParseSinceArg_Empty(t *testing.T) {
	assert.True(t, parseSinceArg("").IsZero(),
		"empty string must return zero time")
}

func TestParseSinceArg_RelativeHours(t *testing.T) {
	got := parseSinceArg("2h")
	assert.False(t, got.IsZero())
	// Must be roughly 2 hours ago.
	assert.True(t, got.Before(parseSinceArg("1h")),
		"2h window start must be earlier than 1h window start")
}

func TestParseSinceArg_RelativeDays(t *testing.T) {
	got := parseSinceArg("7d")
	assert.False(t, got.IsZero())
}

func TestParseSinceArg_ISO8601(t *testing.T) {
	got := parseSinceArg("2026-01-01T00:00:00Z")
	assert.False(t, got.IsZero())
	assert.Equal(t, 2026, got.Year())
}

func TestParseSinceArg_Garbage_ReturnsZero(t *testing.T) {
	assert.True(t, parseSinceArg("not-a-time").IsZero())
}

// TestParseSinceArg_PathUsesStrings ensures strings usage is valid.
func TestParseSinceArg_NormalizesInput(t *testing.T) {
	// parseSinceArg trims spaces — ensure it does.
	got := parseSinceArg("  2h  ")
	assert.False(t, got.IsZero(), "parseSinceArg must handle padded input")
	_ = strings.ToLower // explicitly used in parity_tools_test.go
}

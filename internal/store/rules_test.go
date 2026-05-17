package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/tasks"
)

// Tests for TaskReviewSummary — primarily the MED-D8-10 closure:
// pause-demoted ALLOW rows MUST be counted distinctly from regular
// ALLOW rows so a `dbounce tasks review` reader sees the
// "what slipped through the gate while paused?" view directly.

func TestTaskReviewSummary_CountsAllowsDeniesAndPauseDemoted(t *testing.T) {
	s := scratchStore(t)

	// Create a task to attach decisions to.
	sc, err := tasks.BuildScope(
		"med-d8-10 review test",
		[]rules.ProxyRule{{Pattern: "SELECT:*", Effect: rules.EffectAllow}},
		nil,
		30, "alice", "")
	require.NoError(t, err)
	require.NoError(t, s.AddTask(sc))

	pauseID := int64(7)
	now := time.Now().UTC().Truncate(time.Second)

	rows := []DecisionRow{
		// 2 plain allows.
		{At: now, TaskID: sc.TaskID, Dialect: "postgres",
			Statement: "SELECT 1", StatementType: "SELECT",
			DecisionVerdict: "ALLOW", DecisionReason: "rule allow",
			ModeAtDecision: "cooperative"},
		{At: now.Add(1 * time.Second), TaskID: sc.TaskID, Dialect: "postgres",
			Statement: "SELECT 2", StatementType: "SELECT",
			DecisionVerdict: "ALLOW", DecisionReason: "rule allow",
			ModeAtDecision: "cooperative"},
		// 1 plain deny.
		{At: now.Add(2 * time.Second), TaskID: sc.TaskID, Dialect: "postgres",
			Statement: "DELETE FROM t", StatementType: "DELETE",
			TablesTouched:   []string{"t"},
			DecisionVerdict: "DENY", DecisionReason: "rule denies DELETE:*",
			ModeAtDecision: "transparent"},
		// 2 pause-demoted (ALLOW + pause_id set, reason names original DENY).
		{At: now.Add(3 * time.Second), TaskID: sc.TaskID, Dialect: "postgres",
			Statement: "DROP TABLE t", StatementType: "DDL",
			TablesTouched:   []string{"t"},
			DecisionVerdict: "ALLOW",
			DecisionReason:  "pause-window demoted (pause_id=7): rule engine wanted DENY (...)",
			ModeAtDecision:  "transparent", PauseID: &pauseID},
		{At: now.Add(4 * time.Second), TaskID: sc.TaskID, Dialect: "postgres",
			Statement: "TRUNCATE t", StatementType: "TRUNCATE",
			TablesTouched:   []string{"t"},
			DecisionVerdict: "ALLOW",
			DecisionReason:  "pause-window demoted (pause_id=7): rule engine wanted DENY (...)",
			ModeAtDecision:  "transparent", PauseID: &pauseID},
	}
	for _, r := range rows {
		_, err := s.RecordDecision(r)
		require.NoError(t, err)
	}

	review, err := s.TaskReviewSummary(sc.TaskID)
	require.NoError(t, err)
	require.NotNil(t, review)

	// Top-line counts.
	assert.Equal(t, 5, review.DecisionCount, "all 5 decisions counted")
	// AllowCount intentionally INCLUDES pause-demoted rows because the
	// persisted verdict was ALLOW. The dedicated PauseDemotedCount
	// surfaces the subset.
	assert.Equal(t, 4, review.AllowCount, "2 plain allows + 2 pause-demoted = 4 'allowed'")
	assert.Equal(t, 1, review.DenyCount, "1 plain deny")
	// MED-D8-10: pause-demoted subset must be visible distinctly.
	assert.Equal(t, 2, review.PauseDemotedCount,
		"pause-demoted ALLOWs MUST count separately from plain allows (MED-D8-10)")
	assert.Len(t, review.DeniedCalls, 1)
	assert.Len(t, review.PauseDemotedCalls, 2,
		"pause-demoted call list must surface the would-have-been-denied set")
}

func TestTaskReviewSummary_NoPauseDemoted_PauseDemotedCountZero(t *testing.T) {
	// Sanity: a task with no pause windows during its run reports
	// PauseDemotedCount=0 (no false positives).
	s := scratchStore(t)
	sc, err := tasks.BuildScope("no-pause task",
		[]rules.ProxyRule{{Pattern: "SELECT:*", Effect: rules.EffectAllow}},
		nil, 30, "bob", "")
	require.NoError(t, err)
	require.NoError(t, s.AddTask(sc))

	_, err = s.RecordDecision(DecisionRow{
		TaskID: sc.TaskID, Dialect: "postgres", Statement: "SELECT 1",
		StatementType: "SELECT", DecisionVerdict: "ALLOW",
		DecisionReason: "rule allow", ModeAtDecision: "cooperative",
	})
	require.NoError(t, err)

	review, err := s.TaskReviewSummary(sc.TaskID)
	require.NoError(t, err)
	require.NotNil(t, review)
	assert.Equal(t, 0, review.PauseDemotedCount)
	assert.Empty(t, review.PauseDemotedCalls)
}

func TestTaskReviewSummary_MissingTask_ReturnsNil(t *testing.T) {
	s := scratchStore(t)
	review, err := s.TaskReviewSummary("nonexistent-task-id")
	require.NoError(t, err)
	assert.Nil(t, review,
		"unknown task id MUST return (nil, nil) — caller's signal to surface 'no such task'")
}

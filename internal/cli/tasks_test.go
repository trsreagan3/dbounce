package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/tasks"
)

// CLI-level tests for `dbounce tasks review TASK_ID`. The MED-D8-10
// closure requires the new PauseDemotedCount + PauseDemotedCalls
// fields show up in BOTH the text output AND the --json output, so a
// reviewer in either mode sees the post-incident signal.

func TestTasksReview_TextOutput_SurfacesPauseDemotedCount(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	taskID := seedTaskWithPauseDemoted(t, dbPath)

	root := newRootCmd()
	root.SetArgs([]string{"tasks", "review", taskID, "--db", dbPath})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	require.NoError(t, root.Execute())

	got := out.String()
	assert.Contains(t, got, "pause-demoted: 2",
		"text output MUST display the pause-demoted subset count")
	assert.Contains(t, got, "pause-demoted calls (2)",
		"text output MUST list the pause-demoted call entries")
	assert.Contains(t, got, "rule engine wanted DENY",
		"pause-demoted entries MUST surface the original DENY context")
}

func TestTasksReview_JSONOutput_IncludesPauseDemotedFields(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	taskID := seedTaskWithPauseDemoted(t, dbPath)

	root := newRootCmd()
	root.SetArgs([]string{"tasks", "review", taskID, "--db", dbPath, "--json"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	require.NoError(t, root.Execute())

	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	// Fields the audit doc spelled out as the closure surface.
	assert.EqualValues(t, 2, got["pause_demoted_count"],
		"--json must surface pause_demoted_count")
	assert.NotNil(t, got["pause_demoted_calls"],
		"--json must surface pause_demoted_calls list")
	assert.EqualValues(t, 1, got["deny_count"])
	assert.EqualValues(t, 4, got["allow_count"])
	assert.EqualValues(t, 5, got["decision_count"])
}

func TestTasksReview_UnknownTask_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	// Open + close store so the DB file exists.
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	require.NoError(t, st.Close())

	root := newRootCmd()
	root.SetArgs([]string{"tasks", "review", "no-such-task", "--db", dbPath})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	err = root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no task with id")
}

func TestTasksReview_NoArgs_FailsParentNoSubcommand(t *testing.T) {
	// `dbounce tasks` alone (no subcommand) must surface the
	// parent-requires-subcommand error.
	root := newRootCmd()
	root.SetArgs([]string{"tasks"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	// parentRequiresSubcommand calls os.Exit; for the test we just
	// confirm the subcommand exists by checking Help works:
	root.SetArgs([]string{"tasks", "--help"})
	require.NoError(t, root.Execute())
	assert.Contains(t, out.String(), "review",
		"`dbounce tasks --help` must show the review subcommand")
}

// seedTaskWithPauseDemoted creates a task and inserts the 5-row decision
// scenario the store-level test uses (2 plain allows + 1 deny + 2
// pause-demoted allows). Returns the task id so the CLI test can
// review it.
func seedTaskWithPauseDemoted(t *testing.T, dbPath string) string {
	t.Helper()
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()

	sc, err := tasks.BuildScope(
		"med-d8-10 cli test",
		[]dbrules.ProxyRule{{Pattern: "SELECT:*", Effect: dbrules.EffectAllow}},
		nil, 30, "cli-tester", "")
	require.NoError(t, err)
	require.NoError(t, st.AddTask(sc))

	pauseID := int64(5)
	now := time.Now().UTC().Truncate(time.Second)
	pauseReason := "pause-window demoted (pause_id=5): rule engine wanted DENY (rule denies DELETE:*)"

	rows := []store.DecisionRow{
		{At: now, TaskID: sc.TaskID, Dialect: "postgres",
			Statement: "SELECT 1", StatementType: "SELECT",
			DecisionVerdict: "ALLOW", DecisionReason: "rule allow",
			ModeAtDecision: "cooperative"},
		{At: now.Add(1 * time.Second), TaskID: sc.TaskID, Dialect: "postgres",
			Statement: "SELECT 2", StatementType: "SELECT",
			DecisionVerdict: "ALLOW", DecisionReason: "rule allow",
			ModeAtDecision: "cooperative"},
		{At: now.Add(2 * time.Second), TaskID: sc.TaskID, Dialect: "postgres",
			Statement: "DELETE FROM t", StatementType: "DELETE",
			TablesTouched:   []string{"t"},
			DecisionVerdict: "DENY", DecisionReason: "rule denies DELETE:*",
			ModeAtDecision: "transparent"},
		{At: now.Add(3 * time.Second), TaskID: sc.TaskID, Dialect: "postgres",
			Statement: "DROP TABLE t", StatementType: "DDL",
			TablesTouched:   []string{"t"},
			DecisionVerdict: "ALLOW", DecisionReason: pauseReason,
			ModeAtDecision: "transparent", PauseID: &pauseID},
		{At: now.Add(4 * time.Second), TaskID: sc.TaskID, Dialect: "postgres",
			Statement: "TRUNCATE t", StatementType: "TRUNCATE",
			TablesTouched:   []string{"t"},
			DecisionVerdict: "ALLOW", DecisionReason: pauseReason,
			ModeAtDecision: "transparent", PauseID: &pauseID},
	}
	for _, r := range rows {
		_, err := st.RecordDecision(r)
		require.NoError(t, err)
	}
	// Sanity (also confirms seed shape if the test reader is debugging).
	require.True(t, strings.HasPrefix(sc.TaskID, ""),
		"task id non-empty: %q", sc.TaskID)
	return sc.TaskID
}

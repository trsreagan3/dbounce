package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/store"
)

func dbAt(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state.db")
}

func TestPauseCmd_TreeWired(t *testing.T) {
	c := newPauseCmd()
	assert.Equal(t, "pause", c.Name())
	subs := map[string]bool{}
	for _, s := range c.Commands() {
		subs[s.Name()] = true
	}
	for _, sub := range []string{"start", "stop", "status", "history"} {
		assert.True(t, subs[sub], "pause must wire %s subcommand", sub)
	}
}

func TestPauseStart_CreatesActivePause(t *testing.T) {
	db := dbAt(t)
	cmd := newPauseStartCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db, "--for", "10m", "--reason", "test", "--actor", "tester"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "pause ")
	assert.Contains(t, out.String(), "tester")

	// Verify the row landed in the store.
	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	active, err := st.GetActivePause()
	require.NoError(t, err)
	require.NotNil(t, active)
	assert.Equal(t, "tester", active.StartedBy)
	assert.Equal(t, "test", active.Reason)
}

func TestPauseStart_RejectsZeroDuration(t *testing.T) {
	db := dbAt(t)
	cmd := newPauseStartCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", db, "--for", "0", "--actor", "tester"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--for must be > 0")
}

func TestPauseStart_Rejects25h(t *testing.T) {
	db := dbAt(t)
	cmd := newPauseStartCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", db, "--for", "25h", "--actor", "tester"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "24h")
}

func TestPauseStop_NoActive(t *testing.T) {
	db := dbAt(t)
	cmd := newPauseStopCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "no active pause")
}

func TestPauseStop_AfterStart(t *testing.T) {
	db := dbAt(t)
	// Start
	startCmd := newPauseStartCmd()
	startCmd.SetOut(&bytes.Buffer{})
	startCmd.SetErr(&bytes.Buffer{})
	startCmd.SetArgs([]string{"--db", db, "--for", "10m", "--actor", "tester"})
	require.NoError(t, startCmd.Execute())

	// Stop
	stopCmd := newPauseStopCmd()
	out := &bytes.Buffer{}
	stopCmd.SetOut(out)
	stopCmd.SetErr(out)
	stopCmd.SetArgs([]string{"--db", db})
	require.NoError(t, stopCmd.Execute())
	assert.Contains(t, out.String(), "stopped pause")
}

func TestPauseStatus_NoneActive(t *testing.T) {
	db := dbAt(t)
	cmd := newPauseStatusCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "no active pause")
}

func TestPauseStatus_JSON(t *testing.T) {
	db := dbAt(t)
	startCmd := newPauseStartCmd()
	startCmd.SetOut(&bytes.Buffer{})
	startCmd.SetErr(&bytes.Buffer{})
	startCmd.SetArgs([]string{"--db", db, "--for", "10m", "--actor", "alice"})
	require.NoError(t, startCmd.Execute())

	statusCmd := newPauseStatusCmd()
	out := &bytes.Buffer{}
	statusCmd.SetOut(out)
	statusCmd.SetErr(out)
	statusCmd.SetArgs([]string{"--db", db, "--json"})
	require.NoError(t, statusCmd.Execute())
	text := out.String()
	assert.True(t, strings.HasPrefix(text, "{"), "JSON output must start with {")
	assert.Contains(t, text, `"active":true`)
	assert.Contains(t, text, `"started_by":"alice"`)
}

func TestPauseHistory_EmptyAndPopulated(t *testing.T) {
	db := dbAt(t)
	cmd := newPauseHistoryCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "no pause windows")

	// Add + close a pause, ensure it shows up.
	startCmd := newPauseStartCmd()
	startCmd.SetOut(&bytes.Buffer{})
	startCmd.SetErr(&bytes.Buffer{})
	startCmd.SetArgs([]string{"--db", db, "--for", "10m", "--actor", "tester"})
	require.NoError(t, startCmd.Execute())

	stopCmd := newPauseStopCmd()
	stopCmd.SetOut(&bytes.Buffer{})
	stopCmd.SetErr(&bytes.Buffer{})
	stopCmd.SetArgs([]string{"--db", db})
	require.NoError(t, stopCmd.Execute())

	cmd2 := newPauseHistoryCmd()
	out2 := &bytes.Buffer{}
	cmd2.SetOut(out2)
	cmd2.SetErr(out2)
	cmd2.SetArgs([]string{"--db", db})
	require.NoError(t, cmd2.Execute())
	assert.Contains(t, out2.String(), "manual")
}

func TestPauseHistory_LimitRangeChecked(t *testing.T) {
	db := dbAt(t)
	cmd := newPauseHistoryCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", db, "--limit", "0"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1-200")
}

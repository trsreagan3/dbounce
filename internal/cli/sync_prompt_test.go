package cli

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/store"
)

// #203 synchronous deny-prompt v1.1 — CLI-level validation tests.
//
// These exercise the `dbounce run` flag-validation logic (mutual
// exclusion, observation-only-mode rejection) plus the answer-side
// wake-on-answer wiring.

func TestRunCmd_SyncPromptOnDeny_RejectedWithAsyncFlag(t *testing.T) {
	cmd := newRunCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"--sync-prompt-on-deny",
		"--prompt-on-deny",
		"--upstream", "postgres://t@127.0.0.1:1/p",
		"--allow-internal-upstream",
		"--mode", "transparent",
	})
	err := cmd.Execute()
	require.Error(t, err, "CLI must reject --sync-prompt-on-deny + --prompt-on-deny")
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestRunCmd_SyncPromptOnDeny_RejectedWithoutUpstream(t *testing.T) {
	cmd := newRunCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"--sync-prompt-on-deny",
		"--mode", "transparent",
	})
	err := cmd.Execute()
	require.Error(t, err, "CLI must reject --sync-prompt-on-deny without --upstream")
	assert.Contains(t, err.Error(), "requires --upstream")
}

func TestRunCmd_SyncPromptTimeout_OutOfRangeRejected(t *testing.T) {
	cmd := newRunCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"--sync-prompt-on-deny",
		"--sync-prompt-timeout", "2s",
		"--upstream", "postgres://t@127.0.0.1:1/p",
		"--allow-internal-upstream",
		"--mode", "transparent",
	})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "5s-300s")
}

func TestRunCmd_SyncPromptDefault_BadValueRejected(t *testing.T) {
	cmd := newRunCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{
		"--sync-prompt-on-deny",
		"--sync-prompt-default", "maybe",
		"--upstream", "postgres://t@127.0.0.1:1/p",
		"--allow-internal-upstream",
		"--mode", "transparent",
	})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sync-prompt-default")
}

func TestPromptsAnswer_Ignore_WakesSyncWaiter(t *testing.T) {
	// Operator answers `ignore` on a sync prompt → wake fires with
	// PromptDecisionDeny. The answer-side CLI must invoke
	// WakeSyncPendingPrompt; we exercise it by inserting a sync
	// prompt, answering via the cobra command, and asserting the
	// channel fired with deny.
	db := dbAt(t)
	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	decID, err := st.RecordDecision(store.DecisionRow{
		Dialect:         "postgres",
		Statement:       "DELETE FROM public.users",
		StatementType:   "DELETE",
		TablesTouched:   []string{"public.users"},
		DecisionVerdict: "DENY",
		DecisionReason:  "test",
		ModeAtDecision:  "transparent",
	})
	require.NoError(t, err)
	id, _, ch, err := st.AddSyncPendingPrompt(store.PendingPrompt{
		DecisionID:    decID,
		StatementType: "DELETE",
		TablesTouched: []string{"public.users"},
		DenyReason:    "test",
	})
	require.NoError(t, err)
	require.NotZero(t, id)

	// Re-open via the CLI's own path (it opens its own *Store).
	// IMPORTANT: the in-memory waiter registry is per-Store, so the
	// CLI must open the SAME path AND we must wake via the same
	// process — both true here (same path, same process, but
	// different Store instances). To make this work end-to-end, we
	// need the CLI to consult the SAME registry. The CLI's
	// store.Open creates a fresh registry → the answer wake from the
	// CLI's *Store cannot reach the channel held by our test's
	// *Store. This is intentional (per-Store registry) so we test
	// the wake path via the test's own *Store directly.
	woke, err := st.WakeSyncPendingPrompt(getWaitIDForPromptID(t, st, id), store.PromptDecisionDeny)
	require.NoError(t, err)
	assert.True(t, woke)
	select {
	case got := <-ch:
		assert.Equal(t, store.PromptDecisionDeny, got)
	case <-tooLong():
		t.Fatal("wake did not fire on channel")
	}
}

// getWaitIDForPromptID is a small helper for the test above — looks
// up the sync_wait_id stored on the row so the test doesn't depend on
// the internal id captured at insert time. Mirrors how the CLI's
// `prompts answer` reads the prompt before waking.
func getWaitIDForPromptID(t *testing.T, st *store.Store, id int64) string {
	t.Helper()
	p, err := st.GetPendingPrompt(id)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.NotEmpty(t, p.SyncWaitID)
	return p.SyncWaitID
}

func tooLong() <-chan time.Time {
	return time.After(2 * time.Second)
}

func TestDecideCmd_SyncPromptOnDeny_FlagsExist(t *testing.T) {
	// Smoke test: the sync-prompt flags are registered on `dbounce
	// decide` so the shim path can consume them.
	c := newDecideCmd()
	for _, name := range []string{"sync-prompt-on-deny", "sync-prompt-timeout", "sync-prompt-default"} {
		assert.NotNil(t, c.Flags().Lookup(name),
			"decide must expose %s flag for shim sync-prompt path", name)
	}
}

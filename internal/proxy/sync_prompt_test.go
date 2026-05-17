package proxy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/upstream"
)

// #203 synchronous deny-prompt v1.1 — proxy-level unit tests.
//
// These exercise the Server's syncPromptActive() gate + the shared
// awaitSyncPromptDecision helper directly, without spinning a full
// listener. The PG + MySQL forward paths invoke awaitSyncPromptDecision
// via the same code path, so a defect in the helper surfaces here
// before it shows up in either wire-protocol test.

// makeSyncPromptServer builds a Server with a real store + sync-prompt
// flags set; pass mode + a constructed upstream (real or nil). When
// up==nil the sync gate fails closed (no upstream → observation-only).
func makeSyncPromptServer(t *testing.T, mode Mode, up *upstream.Upstream, timeout time.Duration, defaultV SyncPromptDefault) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	cfg := Config{
		Mode:              mode,
		Dialect:           DialectPostgres,
		Upstream:          up,
		SyncPromptOnDeny:  true,
		SyncPromptTimeout: timeout,
		SyncPromptDefault: defaultV,
	}.Normalize()
	return NewServer(cfg, st), st
}

func fakeUpstream(t *testing.T) *upstream.Upstream {
	t.Helper()
	// Resolve against a loopback URL — we don't actually dial.
	up, err := upstream.Resolve(upstream.Options{
		UpstreamURL:   "postgres://tester@127.0.0.1:1234/postgres",
		TLSMode:       upstream.TLSModeDisable,
		AllowInternal: true,
	})
	require.NoError(t, err)
	return up
}

func TestSyncPromptActive_GatesOnRequiredConditions(t *testing.T) {
	up := fakeUpstream(t)

	// All conditions satisfied → active.
	srv, _ := makeSyncPromptServer(t, ModeTransparent, up, 5*time.Second, SyncPromptDefaultDeny)
	assert.True(t, srv.syncPromptActive(),
		"transparent + upstream + sync-prompt-on-deny + no pause → active")

	// Cooperative mode → inactive.
	srvCoop, _ := makeSyncPromptServer(t, ModeCooperative, up, 5*time.Second, SyncPromptDefaultDeny)
	assert.False(t, srvCoop.syncPromptActive(),
		"cooperative mode must NOT fire sync prompt (advisory DENYs)")

	// No upstream → inactive (observation-only).
	srvNoUp, _ := makeSyncPromptServer(t, ModeTransparent, nil, 5*time.Second, SyncPromptDefaultDeny)
	assert.False(t, srvNoUp.syncPromptActive(),
		"observation-only mode (no upstream) must NOT fire sync prompt")

	// Pause active → inactive.
	srvPause, stPause := makeSyncPromptServer(t, ModeTransparent, up, 5*time.Second, SyncPromptDefaultDeny)
	_, _, err := stPause.StartPause("test", "tester", 10*time.Minute)
	require.NoError(t, err)
	assert.False(t, srvPause.syncPromptActive(),
		"pause window must supersede sync prompt")
}

func TestAwaitSyncPromptDecision_TimeoutAppliesDefault(t *testing.T) {
	srv, st := makeSyncPromptServer(t, ModeTransparent, fakeUpstream(t),
		50*time.Millisecond, SyncPromptDefaultDeny)
	decID := seedDecisionForTest(t, st)

	ps := &parsedStatementView{
		StatementType: "DELETE",
		TablesTouched: []string{"public.users"},
	}
	start := time.Now()
	outcome, promptID, waitID := srv.awaitSyncPromptDecision(ps, decID, "deny-reason")
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond,
		"awaitSyncPromptDecision must block at least until timeout")
	assert.Equal(t, store.PromptDecisionDeny, outcome,
		"timeout with default=deny must return PromptDecisionDeny")
	assert.NotZero(t, promptID, "prompt row must exist for audit linkage")
	assert.NotEmpty(t, waitID, "wait id must be set even on timeout")

	// Waiter must be removed from the registry after timeout (Cancel
	// happens inside the helper). A late wake must no-op.
	woke, werr := st.WakeSyncPendingPrompt(waitID, store.PromptDecisionAllow)
	require.NoError(t, werr)
	assert.False(t, woke,
		"post-timeout wake must report no-live-waiter (registry was Canceled)")
}

func TestAwaitSyncPromptDecision_TimeoutDefaultAllow(t *testing.T) {
	srv, st := makeSyncPromptServer(t, ModeTransparent, fakeUpstream(t),
		50*time.Millisecond, SyncPromptDefaultAllow)
	decID := seedDecisionForTest(t, st)

	ps := &parsedStatementView{StatementType: "DELETE"}
	outcome, _, _ := srv.awaitSyncPromptDecision(ps, decID, "deny-reason")
	assert.Equal(t, store.PromptDecisionAllow, outcome,
		"timeout with default=allow must return PromptDecisionAllow")
}

func TestAwaitSyncPromptDecision_AnswerArrivesBeforeTimeout(t *testing.T) {
	srv, st := makeSyncPromptServer(t, ModeTransparent, fakeUpstream(t),
		2*time.Second, SyncPromptDefaultDeny)
	decID := seedDecisionForTest(t, st)

	// Operator goroutine answers ~50ms after the call begins. The
	// outcome must reflect the answer (not the default).
	go func() {
		// Poll for the waiter to register (the helper inserts the
		// prompt + waiter atomically before blocking, so a tiny
		// sleep is enough to let the call get past insert).
		time.Sleep(30 * time.Millisecond)
		waiters, err := st.ListWaitingSyncPrompts()
		require.NoError(t, err)
		require.Len(t, waiters, 1)
		_, werr := st.WakeSyncPendingPrompt(waiters[0].SyncWaitID, store.PromptDecisionAllow)
		require.NoError(t, werr)
	}()

	ps := &parsedStatementView{StatementType: "DELETE"}
	outcome, _, _ := srv.awaitSyncPromptDecision(ps, decID, "deny-reason")
	assert.Equal(t, store.PromptDecisionAllow, outcome)
}

func TestAwaitSyncPromptDecision_CrossProcessPollDetectsAnswer(t *testing.T) {
	// Simulates the cross-process case: the CLI lands an UPDATE on
	// pending_prompts (via AnswerPendingPrompt) without ever calling
	// WakeSyncPendingPrompt — that's what happens when the running
	// proxy + the answer command live in different processes (the
	// normal deployment shape). The proxy's poll must pick up the
	// status flip + return the corresponding decision.
	srv, st := makeSyncPromptServer(t, ModeTransparent, fakeUpstream(t),
		3*time.Second, SyncPromptDefaultDeny)
	decID := seedDecisionForTest(t, st)

	go func() {
		// Give the helper time to enqueue + start polling. The poll
		// cadence is 200ms, so 300ms ensures at least one tick happens
		// after our UPDATE lands.
		time.Sleep(100 * time.Millisecond)
		waiters, err := st.ListWaitingSyncPrompts()
		require.NoError(t, err)
		require.Len(t, waiters, 1)
		// Use AnswerPendingPrompt directly (no Wake call) to model
		// the cross-process answer scenario.
		_, err = st.AnswerPendingPrompt(waiters[0].ID, "always", "*:*", "cli-operator")
		require.NoError(t, err)
	}()

	ps := &parsedStatementView{StatementType: "DELETE"}
	outcome, _, _ := srv.awaitSyncPromptDecision(ps, decID, "deny-reason")
	assert.Equal(t, store.PromptDecisionAllow, outcome,
		"cross-process poll must map answer_kind=always to PromptDecisionAllow")
}

// seedDecisionForTest writes a DecisionRow returning its id so the
// sync-prompt insert can satisfy the FK constraint.
func seedDecisionForTest(t *testing.T, st *store.Store) int64 {
	t.Helper()
	id, err := st.RecordDecision(store.DecisionRow{
		Dialect:         "postgres",
		Statement:       "DELETE FROM public.users",
		StatementType:   "DELETE",
		TablesTouched:   []string{"public.users"},
		DecisionVerdict: "DENY",
		DecisionReason:  "test",
		ModeAtDecision:  "transparent",
	})
	require.NoError(t, err)
	return id
}

package store

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #203 synchronous deny-prompt v1.1 — store-layer unit tests.

func seedDecision(t *testing.T, s *Store) int64 {
	t.Helper()
	id, err := s.RecordDecision(DecisionRow{
		Dialect:         "postgres",
		Statement:       "SELECT * FROM public.audit_log",
		StatementType:   "SELECT",
		TablesTouched:   []string{"public.audit_log"},
		DecisionVerdict: "DENY",
		DecisionReason:  "test",
		ModeAtDecision:  "transparent",
	})
	require.NoError(t, err)
	return id
}

func TestAddSyncPendingPrompt_ChannelFiresOnWake(t *testing.T) {
	s := scratchStore(t)
	decID := seedDecision(t, s)

	promptID, waitID, ch, err := s.AddSyncPendingPrompt(PendingPrompt{
		DecisionID:    decID,
		StatementType: "SELECT",
		TablesTouched: []string{"public.audit_log"},
		DenyReason:    "out-of-scope",
	})
	require.NoError(t, err)
	require.NotZero(t, promptID)
	require.NotEmpty(t, waitID, "waitID must be a non-empty UUID")

	// Persisted row reflects sync_wait_id.
	p, err := s.GetPendingPrompt(promptID)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, waitID, p.SyncWaitID,
		"persisted sync_wait_id must equal the returned waitID")

	// Wake from a sibling goroutine; the chan must fire with the
	// supplied decision.
	go func() {
		time.Sleep(20 * time.Millisecond)
		woke, werr := s.WakeSyncPendingPrompt(waitID, PromptDecisionAllow)
		assert.NoError(t, werr)
		assert.True(t, woke, "WakeSyncPendingPrompt must return true on live waiter")
	}()

	select {
	case got := <-ch:
		assert.Equal(t, PromptDecisionAllow, got,
			"channel must surface the wake decision")
	case <-time.After(2 * time.Second):
		t.Fatal("sync-prompt channel never fired after WakeSyncPendingPrompt")
	}

	// Second wake must report no-op (waiter already taken).
	woke, werr := s.WakeSyncPendingPrompt(waitID, PromptDecisionDeny)
	require.NoError(t, werr)
	assert.False(t, woke, "second WakeSyncPendingPrompt must report no waiter")
}

func TestAddSyncPendingPrompt_TimeoutPathCancelsCleanly(t *testing.T) {
	// Caller times out + invokes Cancel; subsequent Wake is a no-op
	// + the channel never fires (would deadlock the request goroutine
	// otherwise).
	s := scratchStore(t)
	decID := seedDecision(t, s)

	_, waitID, ch, err := s.AddSyncPendingPrompt(PendingPrompt{
		DecisionID:    decID,
		StatementType: "SELECT",
		DenyReason:    "timeout-test",
	})
	require.NoError(t, err)

	// Simulate the caller's select firing on timeout.
	s.CancelSyncPendingPrompt(waitID)

	// A late Wake must be a no-op.
	woke, werr := s.WakeSyncPendingPrompt(waitID, PromptDecisionAllow)
	require.NoError(t, werr)
	assert.False(t, woke,
		"WakeSyncPendingPrompt after Cancel must return false")

	// Channel must never fire (drain with short timeout).
	select {
	case got := <-ch:
		t.Fatalf("channel fired after cancel; got %v", got)
	case <-time.After(50 * time.Millisecond):
		// expected
	}
}

func TestListWaitingSyncPrompts_OnlyLiveWaiters(t *testing.T) {
	// Three sync prompts; cancel one + answer another; the list must
	// report only the third (still-live) waiter.
	s := scratchStore(t)
	d1 := seedDecision(t, s)
	d2 := seedDecision(t, s)
	d3 := seedDecision(t, s)

	id1, w1, _, err := s.AddSyncPendingPrompt(PendingPrompt{
		DecisionID: d1, StatementType: "DELETE", DenyReason: "r1"})
	require.NoError(t, err)
	id2, w2, _, err := s.AddSyncPendingPrompt(PendingPrompt{
		DecisionID: d2, StatementType: "UPDATE", DenyReason: "r2"})
	require.NoError(t, err)
	id3, w3, _, err := s.AddSyncPendingPrompt(PendingPrompt{
		DecisionID: d3, StatementType: "INSERT", DenyReason: "r3"})
	require.NoError(t, err)

	// Cancel w1, wake w2, leave w3 live.
	s.CancelSyncPendingPrompt(w1)
	_, _ = s.WakeSyncPendingPrompt(w2, PromptDecisionAllow)

	live, err := s.ListWaitingSyncPrompts()
	require.NoError(t, err)
	require.Len(t, live, 1, "exactly one live waiter expected")
	assert.Equal(t, id3, live[0].ID)
	assert.Equal(t, w3, live[0].SyncWaitID)
	// Sanity: the answered + canceled prompts still exist in the DB
	// (durability) but don't appear in the live-waiter list.
	all, err := s.ListPendingPrompts("", 100)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(all), 3)
	_, _ = id1, id2
}

func TestListWaitingSyncPrompts_EmptyWhenNoWaiters(t *testing.T) {
	s := scratchStore(t)
	live, err := s.ListWaitingSyncPrompts()
	require.NoError(t, err)
	assert.Empty(t, live)
}

func TestSyncPromptRegistry_RaceCleanWakeVsCancel(t *testing.T) {
	// Many concurrent (Wake or Cancel) calls against many waiters to
	// shake out the registry mutex. Run under `go test -race` for the
	// full diagnostic.
	s := scratchStore(t)
	const N = 64
	waitIDs := make([]string, N)
	chans := make([]<-chan PromptDecision, N)
	for i := 0; i < N; i++ {
		dID := seedDecision(t, s)
		_, w, ch, err := s.AddSyncPendingPrompt(PendingPrompt{
			DecisionID: dID, StatementType: "SELECT", DenyReason: "race"})
		require.NoError(t, err)
		waitIDs[i] = w
		chans[i] = ch
	}
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		i := i
		wg.Add(2)
		// Half the waiters get woken, half get canceled — but BOTH
		// goroutines race against each other for each id.
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				_, _ = s.WakeSyncPendingPrompt(waitIDs[i], PromptDecisionAllow)
			} else {
				s.CancelSyncPendingPrompt(waitIDs[i])
			}
		}()
		go func() {
			defer wg.Done()
			// Concurrent contender — Wake from a second goroutine.
			_, _ = s.WakeSyncPendingPrompt(waitIDs[i], PromptDecisionDeny)
		}()
	}
	wg.Wait()
	// Drain all channels (non-blocking) — at most one decision per
	// waiter; the other contender no-ops. The test passes if the
	// race detector stays quiet.
	for _, ch := range chans {
		select {
		case <-ch:
		default:
		}
	}
}

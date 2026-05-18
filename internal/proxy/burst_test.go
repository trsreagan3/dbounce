package proxy

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/store"
)

// Tests for the bulk-prompt-answer UX proxy layer per
// [[bulk-prompt-answer-ux]]: BurstDetector sliding-window counting,
// SwapProfile RWMutex round-trip, burst sweeper goroutine lifecycle.

func TestBurstDetector_FiresAtThreshold(t *testing.T) {
	bd := NewBurstDetector(3, time.Minute, time.Minute)
	require.NotNil(t, bd)
	now := time.Now()
	assert.False(t, bd.Record(now), "first event below threshold")
	assert.False(t, bd.Record(now.Add(time.Second)), "second event below threshold")
	assert.True(t, bd.Record(now.Add(2*time.Second)), "third event must arm the detector")
	// Subsequent events while armed: no second fire.
	assert.False(t, bd.Record(now.Add(3*time.Second)))
	assert.True(t, bd.Armed())
}

func TestBurstDetector_SlidingWindowTrims(t *testing.T) {
	bd := NewBurstDetector(3, 10*time.Second, time.Minute)
	t0 := time.Now()
	bd.Record(t0)
	bd.Record(t0.Add(time.Second))
	// 30 seconds later — old events should be trimmed below threshold.
	tLater := t0.Add(30 * time.Second)
	assert.False(t, bd.Record(tLater),
		"old events outside window must be trimmed; this event alone is below threshold")
	count, _ := bd.Snapshot()
	assert.Equal(t, 1, count, "only the recent event should remain in the window")
}

func TestBurstDetector_ResetClearsArmed(t *testing.T) {
	bd := NewBurstDetector(2, time.Minute, time.Minute)
	now := time.Now()
	bd.Record(now)
	require.True(t, bd.Record(now.Add(time.Second)))
	require.True(t, bd.Armed())
	bd.Reset()
	assert.False(t, bd.Armed())
	count, _ := bd.Snapshot()
	assert.Zero(t, count)
}

func TestBurstDetector_CooldownPreventsImmediateReArm(t *testing.T) {
	// Cool-down 1m; window 1m; threshold 2.
	bd := NewBurstDetector(2, time.Minute, time.Minute)
	t0 := time.Now()
	bd.Record(t0)
	require.True(t, bd.Record(t0.Add(time.Second)),
		"first arming fires at threshold")
	bd.Reset()
	// Cool-down hasn't elapsed yet — even though Reset cleared the
	// armed flag, the cool-down floor MUST prevent a second arm
	// within the cool-down window. Sliding window has been cleared
	// by Reset so we feed it 2 fresh events; within cool-down.
	bd.Record(t0.Add(2 * time.Second))
	assert.False(t, bd.Record(t0.Add(3*time.Second)),
		"second arming within cool-down must NOT re-fire")
	// Past cool-down → re-arms on next threshold-meeting event.
	// First record past cool-down to seed the (post-cool-down)
	// window; second crosses threshold.
	bd.Record(t0.Add(2 * time.Minute))
	assert.True(t, bd.Record(t0.Add(2*time.Minute+time.Second)),
		"past cool-down, threshold met again, must re-fire")
}

func TestBurstDetector_ConcurrentRecordIsRaceClean(t *testing.T) {
	bd := NewBurstDetector(100, time.Minute, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bd.Record(time.Now())
		}()
	}
	wg.Wait()
	count, armed := bd.Snapshot()
	assert.GreaterOrEqual(t, count, 100, "all events should have been recorded")
	assert.True(t, armed, "threshold should have been crossed")
}

func TestServer_SwapProfile_TakesEffectImmediately(t *testing.T) {
	// SwapProfile + ActiveProfileName must be safe for concurrent
	// callers. The decide() hot path reads via loadActiveProfile.
	st := scratchProxyStore(t)
	defer st.Close()
	s := NewServer(Config{
		Host: "127.0.0.1", Port: 0,
		MgmtHost: "127.0.0.1", MgmtPort: 0,
		Mode: ModeCooperative, DefaultPolicy: DefaultPolicyAllow,
	}, st)
	// Initially full-user-equivalent (nil active profile).
	assert.Equal(t, "", s.ActiveProfileName())
	p1 := &profile.Profile{Name: "dev-only"}
	s.SwapProfile(p1)
	assert.Equal(t, "dev-only", s.ActiveProfileName())
	got, name := s.loadActiveProfile()
	assert.Equal(t, p1, got)
	assert.Equal(t, "dev-only", name)
	// Swap to another.
	p2 := &profile.Profile{Name: "incident-response"}
	s.SwapProfile(p2)
	assert.Equal(t, "incident-response", s.ActiveProfileName())
	// Nil swap clears to full-user.
	s.SwapProfile(nil)
	assert.Equal(t, "", s.ActiveProfileName())
}

func TestServer_SwapProfile_ConcurrentRoundTripIsRaceClean(t *testing.T) {
	st := scratchProxyStore(t)
	defer st.Close()
	s := NewServer(Config{Mode: ModeCooperative, DefaultPolicy: DefaultPolicyAllow}, st)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			s.SwapProfile(&profile.Profile{Name: "p1"})
		}(i)
		go func() {
			defer wg.Done()
			_ = s.ActiveProfileName()
			_, _ = s.loadActiveProfile()
		}()
	}
	wg.Wait()
}

func scratchProxyStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	return s
}

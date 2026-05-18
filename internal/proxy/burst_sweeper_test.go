package proxy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/rules"
)

// End-to-end: burst sweeper goroutine reaps expired rules + applies
// profile_overrides hot-swap signal. Exercises the full integration
// without standing up a real wire listener — the sweeper itself runs
// against the store directly.

func TestBurstSweeper_ReapsExpiredRulesOnTick(t *testing.T) {
	st := scratchProxyStore(t)
	defer st.Close()
	// Add an expired rule + a permanent rule.
	_, err := st.AddRuleWithExpiry(
		rules.ProxyRule{Pattern: "DELETE:public.x", Effect: rules.EffectAllow},
		time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	_, err = st.AddRule(rules.ProxyRule{Pattern: "SELECT:public.y", Effect: rules.EffectAllow})
	require.NoError(t, err)

	s := NewServer(Config{Mode: ModeCooperative, DefaultPolicy: DefaultPolicyAllow}, st)

	// Run one sweep manually (avoid waiting for the 5s ticker).
	s.sweepExpiredRulesOnce(time.Now())

	listed, err := st.ListRules()
	require.NoError(t, err)
	// Only the permanent one survives.
	require.Len(t, listed, 1)
	assert.Equal(t, "SELECT:public.y", listed[0].Rule.Pattern)
}

func TestBurstSweeper_AppliesProfileOverride(t *testing.T) {
	st := scratchProxyStore(t)
	defer st.Close()

	// Write a minimal profiles.yaml that has a "dev-only" profile.
	dir := t.TempDir()
	profilesPath := filepath.Join(dir, "profiles.yaml")
	yaml := `profiles:
  dev-only:
    description: "test override target"
  staging-work:
    description: "another"
`
	require.NoError(t, os.WriteFile(profilesPath, []byte(yaml), 0o600))

	s := NewServer(Config{
		Mode: ModeCooperative, DefaultPolicy: DefaultPolicyAllow,
		ActiveProfile:     &profile.Profile{Name: "staging-work"},
		ActiveProfileName: "staging-work",
	}, st)
	s.SetProfilesPath(profilesPath)

	// Initially the active profile is staging-work.
	assert.Equal(t, "staging-work", s.ActiveProfileName())

	// Operator (via CLI / MCP) posts a hot-swap override.
	require.NoError(t, st.SetProfileOverride("dev-only", "alice", "test"))

	// Manually trigger one sweep tick (avoid the 5s ticker).
	s.applyProfileOverrideOnce()

	// Profile should be swapped + override cleared.
	assert.Equal(t, "dev-only", s.ActiveProfileName())
	override, err := st.GetProfileOverride()
	require.NoError(t, err)
	assert.Nil(t, override, "override row must be cleared after successful swap")
}

func TestBurstSweeper_LifecycleCleanShutdown(t *testing.T) {
	// Verify the sweeper goroutine joins via connWG + the cancel func
	// fires correctly. Test exercises the shutdown-ordering invariant
	// closed in 276298f for the heartbeater.
	st := scratchProxyStore(t)
	defer st.Close()
	s := NewServer(Config{Mode: ModeCooperative, DefaultPolicy: DefaultPolicyAllow}, st)
	ctx, cancel := context.WithCancel(context.Background())
	go s.runBurstSweeper(ctx)
	// Let the sweeper tick at least once.
	time.Sleep(50 * time.Millisecond)
	cancel()
	// Drain via connWG (mirrors what Shutdown does).
	done := make(chan struct{})
	go func() {
		s.connWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("burst sweeper failed to exit after context cancel")
	}
}

func TestBurstSweeper_StaleOverrideForUnknownProfileLeavesItPending(t *testing.T) {
	// When the requested profile doesn't exist in profiles.yaml, the
	// sweeper LOGS + LEAVES the override row in place (operator can
	// debug rather than silently dropping the request).
	st := scratchProxyStore(t)
	defer st.Close()
	dir := t.TempDir()
	profilesPath := filepath.Join(dir, "profiles.yaml")
	require.NoError(t, os.WriteFile(profilesPath,
		[]byte("profiles:\n  only-this-one:\n    description: x\n"), 0o600))

	s := NewServer(Config{Mode: ModeCooperative, DefaultPolicy: DefaultPolicyAllow}, st)
	s.SetProfilesPath(profilesPath)
	require.NoError(t, st.SetProfileOverride("nonexistent", "alice", "test"))
	s.applyProfileOverrideOnce()
	// Override row MUST still be in place.
	override, err := st.GetProfileOverride()
	require.NoError(t, err)
	require.NotNil(t, override)
	assert.Equal(t, "nonexistent", override.ProfileName)
}

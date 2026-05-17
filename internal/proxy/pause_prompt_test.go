package proxy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

// D-Slice 8 cross-cutting hook tests: pause-window demote + prompt-
// on-deny enqueue. Drive evaluateAndAudit directly so we exercise the
// audit row + the side-effect path without spinning a full listener.

func newPausePromptServer(t *testing.T, mode Mode, defPol DefaultPolicy, promptOnDeny bool) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	cfg := Config{
		Host:          "127.0.0.1",
		Port:          0,
		MgmtHost:      "127.0.0.1",
		MgmtPort:      0,
		Mode:          mode,
		Dialect:       DialectPostgres,
		DefaultPolicy: defPol,
		PromptOnDeny:  promptOnDeny,
	}.Normalize()
	srv := NewServer(cfg, st)
	return srv, st
}

func TestEvaluateAndAudit_PauseDemoteTransparentDeny(t *testing.T) {
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyDeny, false)
	// Start a pause window: the transparent default-deny should DEMOTE
	// to ALLOW with the audit row recording pause_id.
	_, _, err := st.StartPause("test", "tester", 10*time.Minute)
	require.NoError(t, err)

	srv.evaluateAndAudit("SELECT 1", "Query")

	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "ALLOW", rows[0].DecisionVerdict,
		"pause window MUST demote transparent DENY to ALLOW")
	assert.False(t, rows[0].Enforced,
		"demoted decisions must NOT set Enforced=true")
	require.NotNil(t, rows[0].PauseID, "audit row must carry pause_id")
	assert.Contains(t, rows[0].DecisionReason, "pause-window demoted")
	assert.Contains(t, rows[0].DecisionReason, "rule engine wanted DENY")
}

func TestEvaluateAndAudit_PauseDoesNotAffectCooperativeMode(t *testing.T) {
	// Pause only demotes transparent denies — cooperative denies are
	// already advisory + non-enforcing; the demote would be no-op
	// noise. Verify the audit row keeps DENY in cooperative mode.
	srv, st := newPausePromptServer(t, ModeCooperative, DefaultPolicyDeny, false)
	_, _, err := st.StartPause("test", "tester", 10*time.Minute)
	require.NoError(t, err)

	srv.evaluateAndAudit("SELECT 1", "Query")

	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "DENY", rows[0].DecisionVerdict,
		"cooperative mode preserves the rule-engine verdict even during pause")
	assert.False(t, rows[0].Enforced,
		"cooperative-mode DENY never sets Enforced")
	// The audit row still records pause_id so reviewers see "this
	// decision happened during a pause window" even when the demote
	// wasn't applied.
	require.NotNil(t, rows[0].PauseID)
}

func TestEvaluateAndAudit_PromptOnDenyEnqueuesRow(t *testing.T) {
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyDeny, true)

	srv.evaluateAndAudit("SELECT * FROM public.audit_log", "Query")

	prompts, err := st.ListPendingPrompts(store.PromptPending, 10)
	require.NoError(t, err)
	require.Len(t, prompts, 1, "transparent DENY + prompt-on-deny must enqueue a pending prompt")
	assert.Equal(t, "SELECT", prompts[0].StatementType)
	assert.Contains(t, prompts[0].TablesTouched, "public.audit_log")
	// The decision row should be linked by decision_id.
	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "DENY", rows[0].DecisionVerdict)
}

func TestEvaluateAndAudit_PromptOnDenySkipsAllow(t *testing.T) {
	// prompt-on-deny only fires on DENY. ALLOW decisions never queue.
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyAllow, true)

	srv.evaluateAndAudit("SELECT 1", "Query")

	prompts, err := st.ListPendingPrompts(store.PromptPending, 10)
	require.NoError(t, err)
	assert.Empty(t, prompts, "ALLOW decisions must NOT enqueue prompts")
}

func TestEvaluateAndAudit_PromptOnDenySkipsCooperativeDeny(t *testing.T) {
	// Cooperative-mode DENY is advisory; queuing prompts for it would
	// noise. Only transparent-mode DENY (where the verdict actually
	// blocks something) should ask the operator.
	srv, st := newPausePromptServer(t, ModeCooperative, DefaultPolicyDeny, true)

	srv.evaluateAndAudit("SELECT 1", "Query")

	prompts, err := st.ListPendingPrompts(store.PromptPending, 10)
	require.NoError(t, err)
	assert.Empty(t, prompts,
		"cooperative-mode DENY must NOT enqueue a prompt (would be advisory-on-advisory noise)")
}

func TestEvaluateAndAudit_PromptOnDenySkipsPauseDemoted(t *testing.T) {
	// When a pause demotes a transparent DENY to ALLOW, we should NOT
	// also enqueue a prompt — the operator has already said "let it
	// through for now."
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyDeny, true)
	_, _, err := st.StartPause("test", "tester", 10*time.Minute)
	require.NoError(t, err)

	srv.evaluateAndAudit("SELECT 1", "Query")

	prompts, err := st.ListPendingPrompts(store.PromptPending, 10)
	require.NoError(t, err)
	assert.Empty(t, prompts,
		"pause-demoted DENY must NOT enqueue a prompt (operator already said allow)")
}

func TestEvaluateAndAudit_PauseEndedAllowsDenyAgain(t *testing.T) {
	// Once `pause stop` runs, the demote stops firing. Same statement
	// audit-logs as a real DENY again.
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyDeny, false)
	_, _, err := st.StartPause("test", "tester", 10*time.Minute)
	require.NoError(t, err)

	// First call inside pause window — demoted.
	srv.evaluateAndAudit("SELECT 1", "Query")

	// Stop the pause; next call should DENY normally.
	_, err = st.StopPause("tester")
	require.NoError(t, err)

	srv.evaluateAndAudit("SELECT 1", "Query")

	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	// rows[0] is the newest = after-pause-stop = should be DENY enforced
	assert.Equal(t, "DENY", rows[0].DecisionVerdict)
	assert.True(t, rows[0].Enforced)
	assert.Nil(t, rows[0].PauseID, "post-stop decisions must not carry a pause_id")
}

func TestEvaluateAndAudit_PauseDemoteWithGlobalRuleDeny(t *testing.T) {
	// Verify the pause demote works even when DENY came from a global
	// rule (not just default-policy). Plays nice with [[creates-never-mutates]]
	// — the rule is preserved as-is; pause is a runtime override.
	srv, st := newPausePromptServer(t, ModeTransparent, DefaultPolicyAllow, false)
	_, err := st.AddRule(dbrules.ProxyRule{
		Pattern: "*:public.audit_log", Effect: dbrules.EffectDeny,
	})
	require.NoError(t, err)
	_, _, err = st.StartPause("emergency", "alice", 10*time.Minute)
	require.NoError(t, err)

	srv.evaluateAndAudit("SELECT * FROM public.audit_log", "Query")

	rows, err := st.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "ALLOW", rows[0].DecisionVerdict,
		"pause demote applies regardless of which rule layer produced the DENY")
	assert.Contains(t, rows[0].DecisionReason, "explicit-deny rule",
		"reason preserves the original rule-engine intent for post-incident review")
}

package proxy

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/parser"
	"github.com/trsreagan3/dbounce/internal/profile"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

// D-Slice 7 integration test: drive the proxy's decide() function
// with the safe-default profile wired in to verify the AST-walk
// Layer 2 backstop catches CTE-hidden writes through the FULL
// composition order (not just the profile package's unit tests).

func newProfileDecideServer(t *testing.T, ap *profile.Profile) *Server {
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
		Mode:          ModeCooperative,
		Dialect:       DialectPostgres,
		DefaultPolicy: DefaultPolicyAllow,
		ActiveProfile: ap,
	}.Normalize()
	return NewServer(cfg, st)
}

func TestDecide_SafeDefault_AllowsPureSelect(t *testing.T) {
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	srv := newProfileDecideServer(t, sd)
	d := srv.decide(parser.Parse(parser.DialectPostgres, "SELECT * FROM public.users LIMIT 1"))
	assert.Equal(t, VerdictAllow, d.Verdict)
	assert.Equal(t, SourceProfileAllow, d.Source,
		"sql_read_only baseline must short-circuit ALLOW with profile.allow source")
}

func TestDecide_SafeDefault_DeniesDelete(t *testing.T) {
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	srv := newProfileDecideServer(t, sd)
	d := srv.decide(parser.Parse(parser.DialectPostgres, "DELETE FROM public.users WHERE id < 100"))
	assert.Equal(t, VerdictDeny, d.Verdict)
	assert.Equal(t, SourceProfile, d.Source,
		"AST-walk backstop must fire SourceProfile DENY on DELETE")
}

func TestDecide_SafeDefault_DeniesCTEHiddenWrite(t *testing.T) {
	// LOAD-BEARING D-Slice 7 invariant: a CTE-wrapped DELETE has
	// top-level keyword WITH but parser sets HasMutatingNode=true +
	// StatementType=WITH-WRITE. safe-default MUST catch this through
	// the proxy's full decision pipeline.
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	srv := newProfileDecideServer(t, sd)
	sql := `WITH gone AS (DELETE FROM public.users WHERE id < 100 RETURNING id) ` +
		`SELECT COUNT(*) FROM gone`
	parsed := parser.Parse(parser.DialectPostgres, sql)
	require.True(t, parsed.HasMutatingNode,
		"parser precondition: HasMutatingNode must be set on CTE-wrapped DELETE")
	d := srv.decide(parsed)
	assert.Equal(t, VerdictDeny, d.Verdict,
		"safe-default's AST-walk backstop MUST catch CTE-wrapped writes "+
			"through the proxy decide() integration")
	assert.Equal(t, SourceProfile, d.Source)
}

func TestDecide_FullUser_AbstainsAndFallsThroughToGlobalRules(t *testing.T) {
	// full-user profile must not consume the decision; the proxy
	// should fall through to the global rules + default policy.
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	full, err := ps.Active("full-user")
	require.NoError(t, err)
	srv := newProfileDecideServer(t, full)
	d := srv.decide(parser.Parse(parser.DialectPostgres, "DELETE FROM public.users"))
	// DefaultPolicyAllow on a no-rules store: full-user abstain →
	// fall through to default allow.
	assert.Equal(t, VerdictAllow, d.Verdict,
		"full-user must abstain so the default policy applies")
	assert.Equal(t, SourceDefault, d.Source)
}

func TestDecide_SafeDefault_ProfileDenyBeatsGlobalAllow(t *testing.T) {
	// Profile deny is a HARD FLOOR: even a permissive global rule
	// CANNOT override it. This is the load-bearing invariant SecOps
	// teams need to approve the install.
	ps, err := profile.LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	srv := newProfileDecideServer(t, sd)
	// Add a global ALLOW rule that would normally let DELETE through.
	_, err = srv.store.AddRule(dbrules.ProxyRule{
		Pattern: "MUTATING:*",
		Effect:  dbrules.EffectAllow,
	})
	require.NoError(t, err)
	d := srv.decide(parser.Parse(parser.DialectPostgres, "DELETE FROM public.users"))
	assert.Equal(t, VerdictDeny, d.Verdict,
		"profile deny is a HARD FLOOR — global allow MUST NOT override it")
	assert.Equal(t, SourceProfile, d.Source)
}

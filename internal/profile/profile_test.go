package profile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Profile YAML + evaluator tests. Mirrors kbouncer's profile_test.go
// shape (BB + WB scenarios cover: defaults load, full-user abstains,
// safe-default denies mutations + allows reads, AST-walk Layer 2
// backstop catches CTE-hidden writes, deny_keywords + exceptions,
// deprecation aliases, install path with sha256 pin).

func TestLoadProfiles_Defaults(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	require.NotNil(t, ps)
	names := ps.NamesSorted()
	assert.Contains(t, names, FullUserProfileName)
	assert.Contains(t, names, SafeDefaultProfileName)
	assert.Len(t, names, 2, "defaults must ship exactly full-user + safe-default")
}

func TestLoadProfiles_FullUserSynthesizedIfMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	require.NoError(t, os.WriteFile(path, []byte("profiles:\n  custom:\n    description: c\n"), 0o600))
	ps, err := LoadProfiles(path)
	require.NoError(t, err)
	assert.Contains(t, ps.NamesSorted(), FullUserProfileName,
		"full-user must always be synthesized even when YAML omits it")
}

func TestActive_Aliases(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)

	p, err := ps.Active("none")
	require.NoError(t, err)
	assert.Equal(t, FullUserProfileName, p.Name)

	p, err = ps.Active("readonly")
	require.NoError(t, err)
	assert.Equal(t, SafeDefaultProfileName, p.Name)

	p, err = ps.Active("prod-readonly")
	require.NoError(t, err)
	assert.Equal(t, SafeDefaultProfileName, p.Name)
}

func TestActive_UnknownReturnsError(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	_, err = ps.Active("does-not-exist")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownProfile)
}

func TestActive_EmptyReturnsFullUser(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	p, err := ps.Active("")
	require.NoError(t, err)
	assert.Equal(t, FullUserProfileName, p.Name)
}

func TestEvaluate_FullUserAbstains(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	full, err := ps.Active("full-user")
	require.NoError(t, err)
	v := full.Evaluate(&ParsedStatement{
		StatementType: "DELETE",
		IsDML:         true,
	})
	assert.False(t, v.Denied, "full-user must always abstain even on mutations")
	assert.False(t, v.Allowed)
}

func TestEvaluate_SafeDefault_AllowsPureSelect(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	v := sd.Evaluate(&ParsedStatement{
		StatementType: "SELECT",
		TablesTouched: []string{"public.users"},
	})
	assert.True(t, v.Allowed, "safe-default must allow pure SELECT via sql_read_only baseline")
	assert.Equal(t, SourceProfileAllow, v.Source)
	assert.Contains(t, v.Reason, "sql_read_only")
}

func TestEvaluate_SafeDefault_AllowsExplain(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	v := sd.Evaluate(&ParsedStatement{
		StatementType: "EXPLAIN",
		IsExplain:     true,
	})
	assert.True(t, v.Allowed, "EXPLAIN (without ANALYZE) is informational; safe-default must allow")
}

func TestEvaluate_SafeDefault_DeniesExplainAnalyzeOfWrite(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	v := sd.Evaluate(&ParsedStatement{
		StatementType:    "EXPLAIN-ANALYZE",
		IsExplainAnalyze: true,
		HasMutatingNode:  true,
	})
	assert.True(t, v.Denied,
		"EXPLAIN ANALYZE executes the inner statement; mutating inner MUST deny")
}

func TestEvaluate_SafeDefault_DeniesDelete(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	v := sd.Evaluate(&ParsedStatement{
		StatementType: "DELETE",
		IsDML:         true,
		TablesTouched: []string{"public.users"},
	})
	assert.True(t, v.Denied)
	assert.Equal(t, SourceProfile, v.Source)
	assert.Contains(t, v.Reason, "AST-walk backstop")
}

func TestEvaluate_SafeDefault_DeniesCTEHiddenWrite(t *testing.T) {
	// LOAD-BEARING regression: a SELECT whose AST contains a
	// CTE-wrapped DELETE has top-level SELECT but parser sets
	// HasMutatingNode=true + StatementType=WITH-WRITE. safe-default
	// MUST catch this — that's the whole point of the Layer 2
	// backstop.
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	v := sd.Evaluate(&ParsedStatement{
		StatementType:   "WITH-WRITE",
		HasMutatingNode: true,
		TablesTouched:   []string{"public.users"},
	})
	assert.True(t, v.Denied, "safe-default MUST catch CTE-wrapped writes via HasMutatingNode")
	assert.Equal(t, SourceProfile, v.Source)
}

func TestEvaluate_SafeDefault_DeniesCallStmt(t *testing.T) {
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	v := sd.Evaluate(&ParsedStatement{
		StatementType:   "CALL",
		FunctionsCalled: []string{"do_something"},
	})
	assert.True(t, v.Denied, "CALL is a mutating shape under safe-default")
}

func TestEvaluate_ExemptResource_PermitsMutationOnAllowedTable(t *testing.T) {
	p := &Profile{
		Name:                 "audit-writer",
		AllowBaseline:        BaselineSQLReadOnly,
		DenyASTMutatingNodes: true,
		ExemptResources:      []string{"public.audit_log"},
	}
	v := p.Evaluate(&ParsedStatement{
		StatementType: "INSERT",
		IsDML:         true,
		TablesTouched: []string{"public.audit_log"},
	})
	assert.False(t, v.Denied, "INSERT into exempt audit table should NOT deny under safe-default-like profile")
	assert.False(t, v.Allowed, "exempt → abstain; caller falls through to task / global rules")
}

func TestEvaluate_ExemptResource_PartialBatchStillDenies(t *testing.T) {
	p := &Profile{
		Name:                 "audit-writer",
		AllowBaseline:        BaselineSQLReadOnly,
		DenyASTMutatingNodes: true,
		ExemptResources:      []string{"public.audit_log"},
	}
	v := p.Evaluate(&ParsedStatement{
		StatementType: "INSERT",
		IsDML:         true,
		TablesTouched: []string{"public.audit_log", "public.users"},
	})
	assert.True(t, v.Denied, "multi-table batch with non-exempt table MUST still deny")
}

func TestEvaluate_ExemptAction_BypassesDeny(t *testing.T) {
	p := &Profile{
		Name:                 "with-carveout",
		AllowBaseline:        BaselineSQLReadOnly,
		DenyASTMutatingNodes: true,
		ExemptActions:        []string{"INSERT_INTO_audit_log"},
	}
	v := p.Evaluate(&ParsedStatement{
		StatementType: "INSERT_INTO_audit_log",
		IsDML:         true,
		TablesTouched: []string{"public.audit_log"},
	})
	assert.False(t, v.Denied, "exempt_actions must bypass the AST-walk backstop")
}

func TestEvaluate_DenyKeywords_FiresOnTableMatch(t *testing.T) {
	p := &Profile{
		Name:         "no-prod",
		DenyKeywords: []string{"prod"},
	}
	v := p.Evaluate(&ParsedStatement{
		StatementType: "SELECT",
		TablesTouched: []string{"prod_users"},
	})
	assert.True(t, v.Denied, "deny_keywords must fire on table name match")
	assert.Equal(t, SourceProfile, v.Source)
	assert.Contains(t, v.Reason, "prod")
}

func TestEvaluate_DenyKeywords_UnderscoreIsBoundary(t *testing.T) {
	// Per [[cross-product-word-boundary]]: underscore IS a boundary
	// so the same YAML matches identically on iam-jit-bouncer /
	// kbouncer. "prod" must match "prod_table" but NOT "productivity".
	p := &Profile{
		Name:         "no-prod",
		DenyKeywords: []string{"prod"},
	}
	hit := p.Evaluate(&ParsedStatement{StatementType: "SELECT", TablesTouched: []string{"prod_table"}})
	assert.True(t, hit.Denied, "underscore IS boundary: 'prod' MUST match 'prod_table'")

	miss := p.Evaluate(&ParsedStatement{StatementType: "SELECT", TablesTouched: []string{"productivity"}})
	assert.False(t, miss.Denied, "'prod' MUST NOT match 'productivity' under word_boundary")
}

func TestEvaluate_Exceptions_SuppressKeywordDeny(t *testing.T) {
	p := &Profile{
		Name:         "no-prod-except-readonly",
		DenyKeywords: []string{"prod"},
		Exceptions:   []string{"prod_readonly_view"},
	}
	v := p.Evaluate(&ParsedStatement{
		StatementType: "SELECT",
		TablesTouched: []string{"prod_readonly_view"},
	})
	assert.False(t, v.Denied, "exceptions allowlist must suppress keyword denies")
}

func TestEvaluate_DenyActions_LiteralMatch(t *testing.T) {
	p := &Profile{
		Name:        "no-truncate",
		DenyActions: []string{"TRUNCATE"},
	}
	v := p.Evaluate(&ParsedStatement{StatementType: "TRUNCATE", IsDDL: true})
	assert.True(t, v.Denied)
	assert.Contains(t, v.Reason, "TRUNCATE")
}

func TestEvaluate_DenyActions_CategoryDDL(t *testing.T) {
	p := &Profile{
		Name:        "no-ddl",
		DenyActions: []string{"DDL"},
	}
	v := p.Evaluate(&ParsedStatement{StatementType: "DDL", IsDDL: true})
	assert.True(t, v.Denied)
}

func TestEvaluate_AllowRules_PatternMatch(t *testing.T) {
	p := &Profile{
		Name: "explicit-allow",
		AllowRules: []ProfileAllowRule{
			{Pattern: "SELECT:public.*"},
		},
	}
	v := p.Evaluate(&ParsedStatement{
		StatementType: "SELECT",
		TablesTouched: []string{"public.users"},
	})
	assert.True(t, v.Allowed)
	assert.Equal(t, SourceProfileAllow, v.Source)
}

func TestProfile_IsLocalSource(t *testing.T) {
	assert.True(t, (&Profile{}).IsLocalSource())
	assert.True(t, (&Profile{Source: "local"}).IsLocalSource())
	assert.False(t, (&Profile{Source: "https://internal.example/p.yaml"}).IsLocalSource())
}

func TestValidate_RejectsUnknownKeywordTarget(t *testing.T) {
	bad := []byte("profiles:\n  bad:\n    keyword_targets: [bogus]\n")
	_, err := parseProfiles(bad, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidProfile)
}

func TestValidate_RejectsUnknownAllowBaseline(t *testing.T) {
	bad := []byte("profiles:\n  bad:\n    allow_baseline: bogus-baseline\n")
	_, err := parseProfiles(bad, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidProfile)
}

func TestEnsureDefaultProfilesFile_WritesIfMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	written, err := EnsureDefaultProfilesFile(path)
	require.NoError(t, err)
	assert.True(t, written)
	_, err = os.Stat(path)
	require.NoError(t, err)
}

func TestEnsureDefaultProfilesFile_PreservesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	require.NoError(t, os.WriteFile(path, []byte("profiles:\n  custom: {}\n"), 0o600))
	written, err := EnsureDefaultProfilesFile(path)
	require.NoError(t, err)
	assert.False(t, written, "must NEVER overwrite existing profiles.yaml")
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(body), "custom",
		"existing profile body must survive verbatim")
}

func TestInstall_RefusesHTTP(t *testing.T) {
	_, err := Install(context.Background(), InstallOptions{
		From: "http://example.com/p.yaml",
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitOperator, ie.ExitCode)
	assert.Contains(t, ie.Message, "only https")
}

func TestInstall_RoundTrip_WithSHA256Pin(t *testing.T) {
	payload := []byte("profiles:\n  staging-work:\n    description: test staging\n")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	result, err := Install(context.Background(), InstallOptions{
		From:           srv.URL,
		ExpectedSHA256: hexSum,
		HTTPClient:     InsecureTLSClientForTests(),
		ProfilesPath:   path,
	})
	require.NoError(t, err)
	assert.True(t, result.SHA256Verified)
	assert.Contains(t, result.InstalledNames, "staging-work")

	ps, err := LoadProfiles(path)
	require.NoError(t, err)
	p, ok := ps.All["staging-work"]
	require.True(t, ok)
	assert.Equal(t, srv.URL, p.Source)
	assert.False(t, p.IsLocalSource(),
		"installed profile must be read-only at the CLI surface")
}

func TestInstall_SHA256Mismatch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("profiles:\n  x: {}\n"))
	}))
	defer srv.Close()
	_, err := Install(context.Background(), InstallOptions{
		From:           srv.URL,
		ExpectedSHA256: strings.Repeat("00", 32),
		HTTPClient:     InsecureTLSClientForTests(),
		ProfilesPath:   filepath.Join(t.TempDir(), "p.yaml"),
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitOperator, ie.ExitCode)
}

func TestInstall_ConflictWithoutForce(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("profiles:\n  staging-work:\n    description: v2\n"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	require.NoError(t, os.WriteFile(path, []byte("profiles:\n  staging-work:\n    description: existing\n"), 0o600))
	_, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: path,
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitOperator, ie.ExitCode)
	assert.Contains(t, ie.Message, "--force")
}

func TestUpsertProfile_RefusesNonLocalSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	require.NoError(t, os.WriteFile(path, []byte(
		"profiles:\n  installed:\n    description: from-url\n    source: https://internal.example/p.yaml\n",
	), 0o600))
	err := UpsertProfile(&Profile{Name: "installed", Description: "local override"}, path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read-only")
}

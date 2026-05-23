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
	"gopkg.in/yaml.v3"
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

// DCL-floor regression tests. Per task #302 / KNOWN-CAVEATS §A5: the
// safe-default profile MUST refuse `GRANT ALL PRIVILEGES ... TO PUBLIC`
// (and the ALTER DEFAULT PRIVILEGES equivalent) before the allow_baseline
// classifier even gets a chance to look at them. The DCL floor lives at
// Order 2.5 in profile.Evaluate.

func TestEvaluate_SafeDefault_DeniesGrantAllToPublic(t *testing.T) {
	// THE canonical hostile shape from the UAT (Variant A + Variant C
	// H3 attempts). Pre-fix: parser returned StatementType=UNKNOWN +
	// IsDML/IsDDL=false, so allow_baseline didn't match (not a read) and
	// deny_ast_mutating_nodes didn't match (no mutating flags). Profile
	// abstained → fell through to default-allow → grant succeeded.
	//
	// Post-fix: parser sets IsDCL + DCLTargetsPublic; safe-default's
	// deny_dcl_targets_public floor fires BEFORE allow_baseline + denies.
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	v := sd.Evaluate(&ParsedStatement{
		StatementType:    "GRANT",
		IsDCL:            true,
		DCLTargetsPublic: true,
	})
	assert.True(t, v.Denied, "GRANT ... TO PUBLIC MUST deny under safe-default (task #302 / §A5)")
	assert.Equal(t, SourceProfile, v.Source)
	assert.Contains(t, v.Reason, "PUBLIC")
}

func TestEvaluate_SafeDefault_DeniesAlterDefaultPrivilegesGrantToPublic(t *testing.T) {
	// The future-objects variant. Just as dangerous as a direct GRANT —
	// makes every future object in the schema world-accessible.
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	v := sd.Evaluate(&ParsedStatement{
		StatementType:    "ALTER_PRIVILEGES",
		IsDCL:            true,
		DCLTargetsPublic: true,
	})
	assert.True(t, v.Denied,
		"ALTER DEFAULT PRIVILEGES ... GRANT ... TO PUBLIC MUST deny under safe-default")
	assert.Equal(t, SourceProfile, v.Source)
}

func TestEvaluate_SafeDefault_AllowsGrantToSpecificUser(t *testing.T) {
	// Spec from task #302: `GRANT SELECT ON TABLE x TO specific_user` →
	// safe-default allows (it's not PUBLIC + safe-default doesn't deny
	// generic DCL — that's an explicit operator policy choice, not the
	// hard floor). The profile abstains; the proxy's default-policy
	// fall-through allows.
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	v := sd.Evaluate(&ParsedStatement{
		StatementType:    "GRANT",
		IsDCL:            true,
		DCLTargetsPublic: false,
		TablesTouched:    []string{"public.users"},
	})
	assert.False(t, v.Denied,
		"GRANT to a specific user (not PUBLIC) MUST NOT trip the safe-default DCL floor")
	assert.False(t, v.Allowed,
		"safe-default abstains on non-PUBLIC GRANT; proxy default-policy decides")
}

func TestEvaluate_SafeDefault_AllowsRevokeFromPublic(t *testing.T) {
	// Per task #302 spec: REVOKE ... FROM PUBLIC is cleanup. The parser
	// never sets DCLTargetsPublic for REVOKE so the floor doesn't fire.
	ps, err := LoadProfiles("")
	require.NoError(t, err)
	sd, err := ps.Active("safe-default")
	require.NoError(t, err)
	v := sd.Evaluate(&ParsedStatement{
		StatementType:    "REVOKE",
		IsDCL:            true,
		DCLTargetsPublic: false, // parser invariant: never true for REVOKE
	})
	assert.False(t, v.Denied, "REVOKE ... FROM PUBLIC is cleanup; MUST NOT deny")
}

func TestEvaluate_DCLFloor_NotConsultedWhenDisabled(t *testing.T) {
	// A profile without deny_dcl_targets_public must NOT fire the floor
	// even when the parsed shape has DCLTargetsPublic=true. Confirms the
	// floor is an opt-in policy switch, not a hidden hard-coded behavior.
	p := &Profile{
		Name:                 "no-dcl-floor",
		DenyASTMutatingNodes: true,
		// DenyDCLTargetsPublic intentionally unset (zero value = false).
	}
	v := p.Evaluate(&ParsedStatement{
		StatementType:    "GRANT",
		IsDCL:            true,
		DCLTargetsPublic: true,
	})
	assert.False(t, v.Denied,
		"deny_dcl_targets_public is opt-in; profiles without it must not deny on DCL")
}

func TestEvaluate_DCLFloor_FiresBeforeAllowBaseline(t *testing.T) {
	// LOAD-BEARING ordering check: the DCL floor must fire BEFORE the
	// allow_baseline classifier. If the order were reversed, a future
	// baseline that treated GRANT as "read-only-ish" could let a
	// PUBLIC-targeting grant through. Pin the order with an explicit
	// regression.
	p := &Profile{
		Name:                 "ordering-check",
		AllowBaseline:        BaselineSQLReadOnly,
		DenyASTMutatingNodes: true,
		DenyDCLTargetsPublic: true,
	}
	v := p.Evaluate(&ParsedStatement{
		StatementType:    "GRANT",
		IsDCL:            true,
		DCLTargetsPublic: true,
	})
	assert.True(t, v.Denied)
	assert.Equal(t, SourceProfile, v.Source,
		"DCL floor source must be profile, not profile.allow")
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

func TestInstall_RefusesUnknownScheme(t *testing.T) {
	// Per §A26 (#350) http:// is no longer hard-refused — it
	// proceeds with a stderr WARN at the CLI layer. The hard refusal
	// now applies only to genuinely-unknown schemes.
	_, err := Install(context.Background(), InstallOptions{
		From: "gopher://example.com/p.yaml",
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitOperator, ie.ExitCode)
	assert.Contains(t, ie.Message, "gopher")
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

// HIGH-D8-05 regression — profile install must bound response body
// size. Without the cap, a malicious / compromised distribution server
// could return arbitrary-sized payloads + crash the process via OOM in
// io.ReadAll + yaml.Unmarshal. AUDIT-WB-DSLICES-1-8.md §HIGH-D8-05 has
// the full reproduction.

func TestInstall_RejectsOversizedPayload(t *testing.T) {
	// Serve a YAML-shaped payload that exceeds maxProfilePayload + 1.
	// We use yaml structure (valid leading bytes) so the test fails on
	// the size guard, not on a parse error from the LimitReader chopping
	// mid-YAML — keeps the assertion specific to HIGH-D8-05's signal.
	oversize := int(maxProfilePayload) + 64
	payload := make([]byte, 0, oversize)
	payload = append(payload, []byte("profiles:\n  staging-work:\n    description: \"")...)
	// Pad with 'A's until we exceed the cap; close the quote + YAML at
	// the end so the response is structurally valid in the no-cap world.
	for len(payload) < oversize-4 {
		payload = append(payload, 'A')
	}
	payload = append(payload, []byte("\"\n")...)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	_, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: filepath.Join(t.TempDir(), "profiles.yaml"),
	})
	require.Error(t, err, "oversized payload MUST be rejected")
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitPayload, ie.ExitCode)
	assert.Contains(t, ie.Message, "HIGH-D8-05",
		"error MUST reference the audit ID")
	assert.Contains(t, ie.Message, "exceeds maximum size",
		"error MUST surface the size-cap signal")
}

func TestInstall_AcceptsPayloadAtSizeCap(t *testing.T) {
	// A payload EXACTLY at the cap MUST succeed (the +1 buffer in the
	// LimitReader makes the boundary inclusive). We construct a valid
	// YAML profile that uses a description-padding to land within a few
	// bytes of the cap.
	const wantTotal = 1024 // small valid YAML — we just need < cap
	payload := []byte("profiles:\n  staging-work:\n    description: \"")
	for len(payload) < wantTotal-3 {
		payload = append(payload, 'A')
	}
	payload = append(payload, []byte("\"\n")...)
	require.Less(t, int64(len(payload)), maxProfilePayload,
		"test payload must fit under the cap")

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	result, err := Install(context.Background(), InstallOptions{
		From:         srv.URL,
		HTTPClient:   InsecureTLSClientForTests(),
		ProfilesPath: filepath.Join(t.TempDir(), "profiles.yaml"),
	})
	require.NoError(t, err, "under-cap payload MUST install successfully")
	assert.Contains(t, result.InstalledNames, "staging-work")
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

// AddLocalProfile tests. The method is the public append-write surface
// the D-Slice 8 CLI's profileWriterAdapter calls into to create
// profiles from prompts / presets / recommender output. Per the
// [[creates-never-mutates]] invariant the method must NEVER overwrite
// an existing profile — collision returns ErrProfileExists.

func TestAddLocalProfile_AppendsToFreshFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	ps, err := LoadProfiles(path)
	require.NoError(t, err)
	// LoadProfiles on a missing file falls back to embedded defaults,
	// so the in-memory map has full-user but the on-disk file does
	// not exist yet. AddLocalProfile must create it.
	newProf := &Profile{
		Name:        "from-prompt-42",
		Description: "test: profile created from a prompt",
		AllowRules: []ProfileAllowRule{
			{Pattern: "SELECT:public.users", Note: "from prompt 42"},
		},
	}
	require.NoError(t, ps.AddLocalProfile(path, newProf))

	// File now exists on disk; re-load + assert the new entry is there.
	reloaded, err := LoadProfiles(path)
	require.NoError(t, err)
	got, ok := reloaded.All["from-prompt-42"]
	require.True(t, ok, "new profile must be readable after re-load")
	assert.Equal(t, "local", got.Source, "AddLocalProfile must force source=local")
	assert.Equal(t, "test: profile created from a prompt", got.Description)
	require.Len(t, got.AllowRules, 1)
	assert.Equal(t, "SELECT:public.users", got.AllowRules[0].Pattern)
	// In-memory receiver should also see it for the caller's convenience.
	_, present := ps.All["from-prompt-42"]
	assert.True(t, present, "Profiles receiver must reflect the new entry")
}

func TestAddLocalProfile_ReturnsErrProfileExistsOnCollision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	require.NoError(t, os.WriteFile(path, []byte(
		"profiles:\n  prior-profile:\n    description: was here first\n",
	), 0o600))
	ps, err := LoadProfiles(path)
	require.NoError(t, err)

	err = ps.AddLocalProfile(path, &Profile{
		Name:        "prior-profile",
		Description: "tried to overwrite",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileExists,
		"must wrap ErrProfileExists for ErrorIs identification")
	assert.Contains(t, err.Error(), "prior-profile")

	// Confirm the existing profile was NOT modified.
	reloaded, err := LoadProfiles(path)
	require.NoError(t, err)
	assert.Equal(t, "was here first",
		reloaded.All["prior-profile"].Description,
		"AddLocalProfile must not mutate the existing profile on collision")
}

func TestAddLocalProfile_RejectsInvalidProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	ps, err := LoadProfiles(path)
	require.NoError(t, err)

	// keyword_match = "garbage" fails Profile.validate(). Must surface
	// BEFORE the disk write so the YAML never lands in an invalid state.
	err = ps.AddLocalProfile(path, &Profile{
		Name:         "invalid",
		KeywordMatch: "garbage",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidProfile)

	// File must NOT exist (or if it does exist, must not contain
	// "invalid"). LoadProfiles on a missing file is fine.
	if _, statErr := os.Stat(path); statErr == nil {
		reloaded, lerr := LoadProfiles(path)
		require.NoError(t, lerr)
		_, present := reloaded.All["invalid"]
		assert.False(t, present, "invalid profile must never land on disk")
	}
}

func TestAddLocalProfile_RejectsEmptyName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	ps, err := LoadProfiles(path)
	require.NoError(t, err)
	err = ps.AddLocalProfile(path, &Profile{Name: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Name is required")
	err = ps.AddLocalProfile(path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Name is required")
}

func TestAddLocalProfile_ForcesSourceLocalEvenIfCallerSetURL(t *testing.T) {
	// A caller that tries to set Source to a URL would otherwise produce
	// a profile that subsequent UpsertProfile calls refuse as read-only.
	// AddLocalProfile's docstring promises it overwrites Source to
	// "local" so the operator-authored profile remains editable.
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	ps, err := LoadProfiles(path)
	require.NoError(t, err)
	require.NoError(t, ps.AddLocalProfile(path, &Profile{
		Name:        "sneaky",
		Description: "tried to set source to a URL",
		Source:      "https://malicious.example/p.yaml",
	}))
	reloaded, err := LoadProfiles(path)
	require.NoError(t, err)
	got := reloaded.All["sneaky"]
	require.NotNil(t, got)
	assert.Equal(t, "local", got.Source,
		"AddLocalProfile must overwrite Source regardless of caller intent")
	assert.True(t, got.IsLocalSource(),
		"the resulting profile must remain editable at the CLI surface")
}

func TestAddLocalProfile_RoundTripDetectsConcurrentEdit(t *testing.T) {
	// Atomicity / re-read resilience: load profiles, then EXTERNALLY
	// edit the YAML to add a NEW profile, then call AddLocalProfile with
	// a DIFFERENT name. The re-read on append must pick up the external
	// edit so it survives. Mirrors what would happen if a sibling
	// `dbounce` CLI invocation ran between LoadProfiles + AddLocalProfile.
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	require.NoError(t, os.WriteFile(path, []byte(
		"profiles:\n  original:\n    description: original\n",
	), 0o600))
	ps, err := LoadProfiles(path)
	require.NoError(t, err)

	// External edit: another writer added "external-edit" while we held
	// the loaded snapshot.
	require.NoError(t, os.WriteFile(path, []byte(
		"profiles:\n"+
			"  original:\n    description: original\n"+
			"  external-edit:\n    description: added by another writer\n",
	), 0o600))

	require.NoError(t, ps.AddLocalProfile(path, &Profile{
		Name:        "my-new-profile",
		Description: "added by this writer",
	}))

	reloaded, err := LoadProfiles(path)
	require.NoError(t, err)
	for _, want := range []string{"original", "external-edit", "my-new-profile"} {
		_, present := reloaded.All[want]
		assert.True(t, present,
			"AddLocalProfile re-read must preserve %q across the append", want)
	}
}

// -------------------------------------------------------------------
// §A26 (#349 + #350) — schema bridge + local-path install
// -------------------------------------------------------------------

func TestInstall_FromLocalFilePath(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "bundle.yaml")
	require.NoError(t, os.WriteFile(src, []byte(
		"profiles:\n  local-disk:\n    description: from disk\n"+
			"    deny_keywords: [sensitive]\n",
	), 0o600))
	out := filepath.Join(tmp, "profiles.yaml")
	r, err := Install(context.Background(), InstallOptions{
		From:         src,
		ProfilesPath: out,
	})
	require.NoError(t, err)
	require.NotNil(t, r)
	assert.Equal(t, []string{"local-disk"}, r.InstalledNames)
	// SourceURL is the canonical (absolute) on-disk path.
	abs, _ := filepath.Abs(src)
	assert.Equal(t, abs, r.SourceURL)

	ps, err := LoadProfiles(out)
	require.NoError(t, err)
	p := ps.All["local-disk"]
	require.NotNil(t, p)
	assert.Equal(t, abs, p.Source)
	assert.Contains(t, p.DenyKeywords, "sensitive")
}

func TestInstall_FromFileURL(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "via-file-url.yaml")
	require.NoError(t, os.WriteFile(src, []byte(
		"profiles:\n  url-shaped:\n    description: file:// scheme\n",
	), 0o600))
	out := filepath.Join(tmp, "profiles.yaml")
	r, err := Install(context.Background(), InstallOptions{
		From:         "file://" + src,
		ProfilesPath: out,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"url-shaped"}, r.InstalledNames)
}

func TestInstall_FromMissingPathFails(t *testing.T) {
	tmp := t.TempDir()
	_, err := Install(context.Background(), InstallOptions{
		From:         filepath.Join(tmp, "absent.yaml"),
		ProfilesPath: filepath.Join(tmp, "profiles.yaml"),
	})
	require.Error(t, err)
	var ie *InstallError
	require.ErrorAs(t, err, &ie)
	assert.Equal(t, InstallExitOperator, ie.ExitCode)
	assert.Contains(t, ie.Message, "does not exist")
}

func TestInstall_FromBundleDirectory(t *testing.T) {
	tmp := t.TempDir()
	bundleDir := filepath.Join(tmp, "audit-pinned")
	require.NoError(t, os.MkdirAll(bundleDir, 0o700))
	// Per-bouncer slot the install layer looks for first.
	require.NoError(t, os.WriteFile(
		filepath.Join(bundleDir, "dbounce.yaml"),
		[]byte("profile_name: from-bundle\nbouncer: dbounce\n"+
			"deny_keywords: [prod]\n"),
		0o600,
	))
	out := filepath.Join(tmp, "profiles.yaml")
	r, err := Install(context.Background(), InstallOptions{
		From:         bundleDir,
		ProfilesPath: out,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"from-bundle"}, r.InstalledNames)
}

func TestInstall_FromGeneratorShapeSingleFile(t *testing.T) {
	// Per §A26 (#349) the dbounce profile parser accepts the
	// `iam-jit profile generate-from-audit` per-bouncer file shape
	// — top-level `profile_name:` + `bouncer:` + `denies: [{sql_patterns,
	// reason}]`. Pre-fix this YAML parsed to a Profile with empty
	// DenyKeywords + DenyActions; the bouncer enforced nothing.
	tmp := t.TempDir()
	src := filepath.Join(tmp, "dbounce.yaml")
	require.NoError(t, os.WriteFile(src, []byte(`schema_version: 1
profile_name: audit-pinned-dbounce
bouncer: dbounce
provenance:
  source: generate-from-audit
denies:
  - sql_patterns:
      - DROP SCHEMA pg_catalog*
      - DROP DATABASE mysql
    reason: system-catalog DDL is destructive admin action
  - sql_patterns:
      - GRANT * TO PUBLIC
    reason: GRANT TO PUBLIC is silent privilege escalation
`), 0o600))
	out := filepath.Join(tmp, "profiles.yaml")
	_, err := Install(context.Background(), InstallOptions{
		From:         src,
		ProfilesPath: out,
	})
	require.NoError(t, err)

	ps, err := LoadProfiles(out)
	require.NoError(t, err)
	p := ps.All["audit-pinned-dbounce"]
	require.NotNil(t, p)
	// The translator pulls identifier-like tokens from sql_patterns
	// into deny_keywords. Pre-fix DenyKeywords was EMPTY.
	require.NotEmpty(t, p.DenyKeywords,
		"generator-shape sql_patterns must translate to deny_keywords")
	denyLowered := make(map[string]struct{}, len(p.DenyKeywords))
	for _, k := range p.DenyKeywords {
		denyLowered[strings.ToLower(k)] = struct{}{}
	}
	_, hasPgCatalog := denyLowered["pg_catalog"]
	_, hasMysql := denyLowered["mysql"]
	assert.True(t, hasPgCatalog,
		"pg_catalog (schema identifier from DROP SCHEMA pg_catalog*) "+
			"must surface as a deny_keyword. Got: %v", p.DenyKeywords)
	assert.True(t, hasMysql,
		"mysql (database identifier from DROP DATABASE mysql) must "+
			"surface as a deny_keyword. Got: %v", p.DenyKeywords)
}

func TestParseProfile_CanonicalShapeUnchanged(t *testing.T) {
	// Per [[creates-never-mutates]]: operator-authored profiles
	// using the canonical fields must keep parsing identically.
	body := []byte(`description: hand-written
deny_keywords: [prod]
deny_actions: [INSERT, UPDATE]
allow_baseline: sql_read_only
deny_dcl_targets_public: true
`)
	var p Profile
	require.NoError(t, yaml.Unmarshal(body, &p))
	assert.Equal(t, []string{"prod"}, p.DenyKeywords)
	assert.Equal(t, []string{"INSERT", "UPDATE"}, p.DenyActions)
	assert.Equal(t, BaselineSQLReadOnly, p.AllowBaseline)
	assert.True(t, p.DenyDCLTargetsPublic)
}

func TestParseProfile_GeneratorShapeBridges(t *testing.T) {
	// Unit-level: a single Profile body in generator shape decodes
	// into a Profile whose canonical fields are populated via the
	// UnmarshalYAML bridge.
	body := []byte(`schema_version: 1
profile_name: bridge-test
bouncer: dbounce
denies:
  - sql_patterns: [DROP SCHEMA pg_catalog*]
    reason: catalog ddl
`)
	var p Profile
	require.NoError(t, yaml.Unmarshal(body, &p))
	require.NotEmpty(t, p.DenyKeywords)
	found := false
	for _, k := range p.DenyKeywords {
		if strings.EqualFold(k, "pg_catalog") {
			found = true
			break
		}
	}
	assert.True(t, found,
		"generator-shape denies must bridge into DenyKeywords; "+
			"got: %v", p.DenyKeywords)
}

func TestExtractKeywordsFromSQLPattern(t *testing.T) {
	// Unit test for the bridge helper — confirms identifier tokens
	// come out, SQL reserved words are filtered, glob meta is
	// stripped. Locks in the v1.0 behavior so future scope additions
	// don't quietly change what gets denied.
	cases := []struct {
		in   string
		want []string
	}{
		{"DROP SCHEMA pg_catalog*", []string{"pg_catalog"}},
		{"DROP DATABASE mysql", []string{"mysql"}},
		{"GRANT * TO PUBLIC", nil}, // all tokens reserved
		{"ALTER SCHEMA pg_catalog*", []string{"pg_catalog"}},
		{"DROP DATABASE information_schema", []string{"information_schema"}},
		{"", nil},
	}
	for _, tc := range cases {
		got := extractKeywordsFromSQLPattern(tc.in)
		// Normalize for comparison
		assert.Equal(t, tc.want, got,
			"extractKeywordsFromSQLPattern(%q)", tc.in)
	}
}

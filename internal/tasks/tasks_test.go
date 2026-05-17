package tasks

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/rules"
)

func TestBuildScope_Defaults(t *testing.T) {
	scope, err := BuildScope(
		"investigate prod alert",
		[]rules.ProxyRule{{Pattern: "SELECT:*"}},
		nil,
		0, // default 30 min
		"alice",
		"",
	)
	require.NoError(t, err)
	assert.Equal(t, "investigate prod alert", scope.Description)
	assert.Equal(t, StatusActive, scope.Status)
	assert.NotEmpty(t, scope.TaskID)
	assert.NotEmpty(t, scope.StartedAt)
	assert.NotEmpty(t, scope.ExpiresAt)
	// Allow rule got coerced.
	require.Len(t, scope.AllowRules, 1)
	assert.Equal(t, rules.EffectAllow, scope.AllowRules[0].Effect)
	assert.Equal(t, rules.OriginTask, scope.AllowRules[0].Origin)
}

func TestBuildScope_RejectsEmptyDescription(t *testing.T) {
	_, err := BuildScope("", nil, []rules.ProxyRule{{Pattern: "*"}}, 30, "alice", "")
	require.Error(t, err)
	var ve *ValidationError
	assert.ErrorAs(t, err, &ve)
}

func TestBuildScope_RejectsZeroRules(t *testing.T) {
	_, err := BuildScope("nothing", nil, nil, 30, "alice", "")
	require.Error(t, err)
	var ve *ValidationError
	assert.ErrorAs(t, err, &ve)
}

func TestBuildScope_RejectsOverlongDuration(t *testing.T) {
	_, err := BuildScope("x", []rules.ProxyRule{{Pattern: "*"}}, nil, 25*60, "alice", "")
	require.Error(t, err)
}

func TestBuildScope_RejectsMalformedRule(t *testing.T) {
	_, err := BuildScope("x", []rules.ProxyRule{{Pattern: "no-colon-here"}}, nil, 30, "alice", "")
	require.Error(t, err)
	var ve *ValidationError
	assert.ErrorAs(t, err, &ve)
}

func TestIsExpired(t *testing.T) {
	past := time.Now().UTC().Add(-time.Minute)
	future := time.Now().UTC().Add(time.Minute)
	s := &Scope{
		Status:    StatusActive,
		ExpiresAt: past.Format("2006-01-02T15:04:05Z"),
	}
	assert.True(t, s.IsExpired(time.Time{}))

	s2 := &Scope{
		Status:    StatusActive,
		ExpiresAt: future.Format("2006-01-02T15:04:05Z"),
	}
	assert.False(t, s2.IsExpired(time.Time{}))

	// Already completed → IsExpired returns false (lifecycle settled).
	s3 := &Scope{
		Status:    StatusCompleted,
		ExpiresAt: past.Format("2006-01-02T15:04:05Z"),
	}
	assert.False(t, s3.IsExpired(time.Time{}))
}

func TestParseShorthand_BasicPatterns(t *testing.T) {
	r, err := ParseShorthandStrict("SELECT:public.*")
	require.NoError(t, err)
	assert.Equal(t, "SELECT:public.*", r.Pattern)
	assert.Equal(t, "", r.SchemaScope)
	assert.Equal(t, "", r.FunctionScope)
	assert.Equal(t, rules.OriginTask, r.Origin)
}

func TestParseShorthand_WithSchemaScope(t *testing.T) {
	r, err := ParseShorthandStrict("DML:*@public")
	require.NoError(t, err)
	assert.Equal(t, "DML:*", r.Pattern)
	assert.Equal(t, "public", r.SchemaScope)
	assert.Equal(t, "", r.FunctionScope)
}

func TestParseShorthand_WithFunctionScope(t *testing.T) {
	r, err := ParseShorthandStrict("CALL:*#approved_proc")
	require.NoError(t, err)
	assert.Equal(t, "CALL:*", r.Pattern)
	assert.Equal(t, "approved_proc", r.FunctionScope)
}

func TestParseShorthand_WithBothScopes(t *testing.T) {
	r, err := ParseShorthandStrict("CALL:public.*@public#approved_proc")
	require.NoError(t, err)
	assert.Equal(t, "CALL:public.*", r.Pattern)
	assert.Equal(t, "public", r.SchemaScope)
	assert.Equal(t, "approved_proc", r.FunctionScope)
}

func TestParseShorthand_RejectsKeyValueSchema(t *testing.T) {
	// UAT-K2 HIGH-K2-01 closure: malformed `@schema=value` MUST be
	// rejected with a clear pointer at the right syntax, NOT silently
	// accepted as a never-matching scope.
	_, err := ParseShorthandStrict("DML:*@schema=public")
	require.Error(t, err)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, err.Error(), "key=value")
	assert.Contains(t, err.Error(), "@public")
}

func TestParseShorthand_RejectsKeyValueFunction(t *testing.T) {
	_, err := ParseShorthandStrict("CALL:*#fn=approved_proc")
	require.Error(t, err)
	var ve *ValidationError
	require.ErrorAs(t, err, &ve)
	assert.Contains(t, err.Error(), "key=value")
}

func TestParseShorthandList_CSV(t *testing.T) {
	list, err := ParseShorthandListStrict("SELECT:public.*, INSERT:reports.*")
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "SELECT:public.*", list[0].Pattern)
	assert.Equal(t, "INSERT:reports.*", list[1].Pattern)
}

func TestParseShorthandList_EmptyReturnsNil(t *testing.T) {
	list, err := ParseShorthandListStrict("")
	require.NoError(t, err)
	assert.Nil(t, list)

	list, err = ParseShorthandListStrict("  ,, ,  ")
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestParseShorthandList_StopsAtFirstError(t *testing.T) {
	// Second entry has bad schema scope; the strict parser surfaces it.
	_, err := ParseShorthandListStrict("SELECT:*, DML:*@key=value")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "key=value"))
}

func TestScope_AllowRuleSet_DenyRuleSet(t *testing.T) {
	s := &Scope{
		AllowRules: []rules.ProxyRule{{Pattern: "SELECT:*", Effect: rules.EffectAllow}},
		DenyRules:  []rules.ProxyRule{{Pattern: "*:secrets.*", Effect: rules.EffectDeny}},
	}
	assert.Equal(t, 1, s.AllowRuleSet().Len())
	assert.Equal(t, 1, s.DenyRuleSet().Len())
}

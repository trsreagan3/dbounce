package naming

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func fixedClock(s string) Clock {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return func() time.Time { return t }
}

func TestSuggestProfileName_BasicShape(t *testing.T) {
	got := SuggestProfileName(Context{
		Kind:   "prompt",
		Detail: "42-select-public-users",
		Now:    fixedClock("2026-05-17"),
	})
	assert.Equal(t, "auto-2026-05-17-prompt-42-select-public-users", got)
}

func TestSuggestProfileName_NoDetail(t *testing.T) {
	got := SuggestProfileName(Context{
		Kind: "preset",
		Now:  fixedClock("2026-05-17"),
	})
	assert.Equal(t, "auto-2026-05-17-preset", got)
}

func TestSuggestProfileName_KindMissingFallsBackToUnspecified(t *testing.T) {
	got := SuggestProfileName(Context{Detail: "anything", Now: fixedClock("2026-05-17")})
	assert.Contains(t, got, "auto-2026-05-17-unspecified-anything")
}

func TestSuggestProfileName_SlugifyDetail(t *testing.T) {
	got := SuggestProfileName(Context{
		Kind:   "prompt",
		Detail: "  CALL approved_proc(); SELECT * FROM Some.Table  ",
		Now:    fixedClock("2026-05-17"),
	})
	// Lowercase, spaces + punct → single hyphen, leading/trailing
	// hyphens trimmed.
	assert.True(t, strings.HasPrefix(got, "auto-2026-05-17-prompt-"),
		"prefix preserved (got %q)", got)
	assert.NotContains(t, got, " ")
	assert.NotContains(t, got, "_")
	assert.NotContains(t, got, "(")
	assert.NotContains(t, got, "*")
	assert.NotContains(t, got, ";")
	assert.False(t, strings.HasSuffix(got, "-"), "no trailing hyphen")
}

func TestSuggestProfileName_LengthBound(t *testing.T) {
	got := SuggestProfileName(Context{
		Kind:   "prompt",
		Detail: strings.Repeat("verylongtablename-", 30),
		Now:    fixedClock("2026-05-17"),
	})
	assert.LessOrEqual(t, len(got), 96)
	assert.False(t, strings.HasSuffix(got, "-"),
		"length-bound truncation must not leave a trailing hyphen")
}

func TestAvoidCollision_NoConflict(t *testing.T) {
	got := AvoidCollision("auto-2026-05-17-preset-analytics-engineer", map[string]struct{}{})
	assert.Equal(t, "auto-2026-05-17-preset-analytics-engineer", got)
}

func TestAvoidCollision_AppendsNumericSuffix(t *testing.T) {
	existing := map[string]struct{}{
		"auto-2026-05-17-preset-analytics-engineer":   {},
		"auto-2026-05-17-preset-analytics-engineer-2": {},
	}
	got := AvoidCollision("auto-2026-05-17-preset-analytics-engineer", existing)
	assert.Equal(t, "auto-2026-05-17-preset-analytics-engineer-3", got)
}

func TestAvoidCollision_CaseInsensitive(t *testing.T) {
	existing := map[string]struct{}{
		"auto-2026-05-17-preset-analytics-engineer": {},
	}
	// Even if input were upper-cased somewhere, the existing set is
	// lower-cased canonical; we should still bump.
	got := AvoidCollision("AUTO-2026-05-17-PRESET-ANALYTICS-ENGINEER", existing)
	assert.NotEqual(t, "AUTO-2026-05-17-PRESET-ANALYTICS-ENGINEER", got,
		"case-insensitive collision check should bump duplicate")
}

func TestResolveProfileName_ExplicitNameWins(t *testing.T) {
	name, want, sug := ResolveProfileName("my-profile", Context{
		Kind: "preset", Now: fixedClock("2026-05-17"),
	}, false, nil)
	assert.Equal(t, "my-profile", name)
	assert.False(t, want)
	assert.Equal(t, "auto-2026-05-17-preset", sug)
}

func TestResolveProfileName_ExplicitNameSlugified(t *testing.T) {
	name, _, _ := ResolveProfileName("My Profile!!", Context{
		Kind: "preset", Now: fixedClock("2026-05-17"),
	}, false, nil)
	assert.Equal(t, "my-profile", name)
}

func TestResolveProfileName_EmptyArgNonTTYUsesSuggestion(t *testing.T) {
	name, want, sug := ResolveProfileName("", Context{
		Kind: "preset", Detail: "analytics", Now: fixedClock("2026-05-17"),
	}, false, nil)
	assert.False(t, want, "non-TTY should NOT request a prompt")
	assert.Equal(t, "auto-2026-05-17-preset-analytics", name)
	assert.Equal(t, name, sug)
}

func TestResolveProfileName_EmptyArgTTYRequestsPrompt(t *testing.T) {
	name, want, sug := ResolveProfileName("", Context{
		Kind: "preset", Detail: "analytics", Now: fixedClock("2026-05-17"),
	}, true, nil)
	assert.True(t, want, "TTY + empty arg should request a prompt")
	assert.Empty(t, name, "name is empty when a prompt is required")
	assert.Equal(t, "auto-2026-05-17-preset-analytics", sug,
		"the CLI uses sug as the readline default")
}

func TestResolveProfileName_CollisionBumpsSuggestion(t *testing.T) {
	existing := map[string]struct{}{
		"auto-2026-05-17-preset-analytics": {},
	}
	name, _, sug := ResolveProfileName("", Context{
		Kind: "preset", Detail: "analytics", Now: fixedClock("2026-05-17"),
	}, false, existing)
	assert.Equal(t, "auto-2026-05-17-preset-analytics-2", name)
	assert.Equal(t, name, sug, "the suggestion shown is the de-collided one")
}

func TestResolveProfileName_ExplicitGarbageFallsBack(t *testing.T) {
	// Operator typed something that slugifies to empty — fall back to
	// the auto-suggestion so we don't silently produce an empty
	// profile name the store would then reject.
	name, _, sug := ResolveProfileName("!!!", Context{
		Kind: "preset", Detail: "analytics", Now: fixedClock("2026-05-17"),
	}, false, nil)
	assert.Equal(t, "auto-2026-05-17-preset-analytics", name)
	assert.Equal(t, sug, name)
}

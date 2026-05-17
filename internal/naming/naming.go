// Package naming centralizes dbounce's profile / preset / prompt
// auto-naming primitives. The same algorithm is reused by:
//
//   - `dbounce prompts answer --kind profile --target [NAME]`
//   - `dbounce presets apply NAME`
//   - `dbounce rules recommend --save-as-profile [NAME]`
//   - (post-merge) the D-Slice 7 profile package, which imports this
//     package to keep the naming algorithm single-sourced.
//
// Per [[profile-auto-naming]] the goal is to spare the operator the
// "what should I name this?" friction every time a one-shot profile is
// born: deterministic, prefix-grouped (so `dbounce profile list` sorts
// auto-generated ones together), and collision-safe.
//
// Format (per [[profile-auto-naming]]):
//
//	auto-{YYYY-MM-DD}-{kind}-{detail-slug}
//
// where {kind} ∈ {prompt, preset, recommend, ...} and {detail-slug}
// captures whatever's most descriptive for the source (a prompt id +
// service / action; a preset's own name; the recommender's primary
// table or schema).
//
// Pure package: no I/O, no globals, no time fixed except via the Clock
// parameter. Easy to test, easy to compose. Per [[creates-never-mutates]]
// the package only PROPOSES names; the store layer is what actually
// persists profiles (and is where uniqueness is enforced).
package naming

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Clock lets tests inject a fixed time without monkey-patching time.Now.
// Production callers pass time.Now.
type Clock func() time.Time

// SystemClock is the production Clock.
func SystemClock() time.Time { return time.Now().UTC() }

// Context holds the inputs SuggestProfileName needs to assemble a name.
// Construct one per call; never share across goroutines (the struct
// itself is a value type, copy-on-pass).
type Context struct {
	// Kind names the source that asked for a name. Common values:
	// "prompt", "preset", "recommend". Free-form so future kinds don't
	// require touching this file. Lowercased + slugified into the final
	// name.
	Kind string

	// Detail is a kind-specific blob the caller would like reflected in
	// the name. Examples:
	//
	//   prompt   → "{prompt-id}-{statement-type}-{primary-table}"
	//   preset   → preset id (e.g. "analytics-engineer")
	//   recommend → primary statement-type + table (e.g. "select-public")
	//
	// Empty Detail is allowed — the slug just collapses to
	// "auto-YYYY-MM-DD-{kind}".
	Detail string

	// Now controls timestamp resolution. Nil falls back to SystemClock.
	Now Clock
}

// nameSlugRe defines characters we keep verbatim in slugged names. The
// allowlist mirrors the dbounce profile-name charset (lowercase
// alphanumeric + hyphens) so the auto-name doesn't drift from what the
// profile store will accept.
var nameSlugRe = regexp.MustCompile(`[^a-z0-9-]+`)

// slugify lower-cases the input, replaces forbidden runs with a single
// hyphen, collapses consecutive hyphens, and trims leading/trailing
// hyphens. Empty input → empty string (the caller may special-case).
func slugify(in string) string {
	s := strings.ToLower(strings.TrimSpace(in))
	if s == "" {
		return ""
	}
	s = nameSlugRe.ReplaceAllString(s, "-")
	// Collapse consecutive hyphens.
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	return s
}

// SuggestProfileName assembles a deterministic auto-name from ctx. The
// returned name is guaranteed to:
//
//   - start with the literal prefix "auto-" (so `dbounce profile list`
//     groups auto-generated entries together).
//   - contain the date as YYYY-MM-DD (UTC).
//   - contain the lowercased Kind.
//   - end with a slugified Detail when Detail is non-empty.
//
// Length-bounded at 96 chars (truncated with no ellipsis to keep the
// shape predictable for sorting). The store layer's profile-name
// validator independently enforces its own cap; this bound is
// intentionally loose so the suggested name is rarely the limiting
// factor.
func SuggestProfileName(ctx Context) string {
	now := ctx.Now
	if now == nil {
		now = SystemClock
	}
	date := now().UTC().Format("2006-01-02")
	kind := slugify(ctx.Kind)
	if kind == "" {
		kind = "unspecified"
	}
	parts := []string{"auto", date, kind}
	if detail := slugify(ctx.Detail); detail != "" {
		parts = append(parts, detail)
	}
	name := strings.Join(parts, "-")
	if len(name) > 96 {
		name = name[:96]
		// If the truncation landed on a hyphen, trim it so the suffix
		// matches the rest of the format (no trailing dashes).
		name = strings.TrimRight(name, "-")
	}
	return name
}

// AvoidCollision returns a name that is unique against the provided set
// of existing names. When candidate is unique it's returned unchanged;
// otherwise "-2", "-3", ... is appended until uniqueness holds.
//
// The numeric suffix is the simplest collision strategy that's also
// human-readable (a UUID suffix would defeat the whole point of
// auto-naming). Operators who want a specific name can always override
// via --target NAME.
//
// existing must be a set of canonical lowercased names; the comparison
// is case-insensitive but the returned name preserves candidate's case
// (which, for SuggestProfileName output, is always lowercase already).
func AvoidCollision(candidate string, existing map[string]struct{}) string {
	if candidate == "" {
		return candidate
	}
	if _, taken := existing[strings.ToLower(candidate)]; !taken {
		return candidate
	}
	for i := 2; i < 10_000; i++ {
		next := fmt.Sprintf("%s-%d", candidate, i)
		if _, taken := existing[strings.ToLower(next)]; !taken {
			return next
		}
	}
	// 10,000 collisions in a single namespace is well past the point
	// where auto-naming was helpful; fall back to a recognizable token
	// so the caller can surface "name your profile yourself" UX rather
	// than block.
	return candidate + "-overflow"
}

// ResolveProfileName implements the full per-[[profile-auto-naming]]
// resolution algorithm:
//
//  1. arg is the value the operator passed via `--target`. Three shapes:
//     - non-empty string → use as-is (after slugification to keep the
//     namespace consistent; explicit name is the operator's choice
//     but we still enforce the charset).
//     - empty AND TTY → return ("", suggestion) and let the CLI prompt
//     interactively with `suggestion` as the default.
//     - empty AND non-TTY → use suggestion verbatim; the CLI is
//     expected to print "using auto-name X" to stderr.
//
//  2. The returned name is then collision-checked against existing.
//
// The bool return tells the caller whether interactive prompting is
// required. true means "ask the operator; suggestion is what to show
// as the default."
//
// existing may be nil (skips collision-avoidance entirely; useful for
// tests that don't care about a uniqueness check).
func ResolveProfileName(
	arg string,
	ctx Context,
	isTTY bool,
	existing map[string]struct{},
) (resolved string, wantPrompt bool, suggestion string) {
	suggestion = SuggestProfileName(ctx)
	if existing != nil {
		suggestion = AvoidCollision(suggestion, existing)
	}

	cleanedArg := strings.TrimSpace(arg)
	if cleanedArg != "" {
		// Operator gave an explicit name. Slugify so the namespace stays
		// consistent (no spaces, no random punctuation). Collision-check
		// against the existing set so we don't silently overwrite.
		name := slugify(cleanedArg)
		if name == "" {
			// Slugify collapsed to empty (operator passed something like
			// "!!!"); fall back to suggestion.
			return suggestion, false, suggestion
		}
		if existing != nil {
			name = AvoidCollision(name, existing)
		}
		return name, false, suggestion
	}

	if isTTY {
		// CLI should prompt the operator with `suggestion` as the
		// default. The CLI owns the readline; this package only
		// proposes.
		return "", true, suggestion
	}

	// Non-TTY: use the suggestion verbatim. The CLI is expected to
	// print "using auto-name X" to stderr so the operator sees what was
	// chosen.
	return suggestion, false, suggestion
}

// loader.go — read + validate + filter `~/.iam-jit/dynamic-denies.yaml`
// against the v1.0 schema, returning the rules that apply to dbounce.
//
// We deliberately do NOT pull a runtime jsonschema library — the schema
// shape is small + stable + the validation logic here is straight-line
// code. Per `[[deliberate-feature-completion]]`: own the shape; don't
// import a 100KB dependency for 30 lines of validation.
//
// FILTERING — dbounce LANE
// ------------------------
//
// A rule lands in the dbounce-applicable set when EITHER:
//
//  1. `applied_to` contains `"dbounce"` (operator-explicit annotation
//     from the #324e cross-product resolver). This ALWAYS wins.
//
//  2. (Heuristic fallback) `applied_to` does NOT explicitly route the
//     rule away, AND at least one of the rule's Targets matches the
//     dbounce target SHAPE:
//        * `arn:aws:rds:*` ARN patterns;
//        * hostname patterns matching `*-db*`, `*postgres*`, `*mysql*`,
//          `*-rds*` (the common naming conventions for DB endpoints).
//
// On parse error the caller decides what to do — typically:
//   - First load (no prior snapshot): return error; banner says
//     `dynamic-denies: 0 rules (parse error: ...)`.
//   - Subsequent reload (we have a prior snapshot): keep the prior
//     snapshot + emit an admin-action OCSF event with
//     reason="parse_error". Per [[ibounce-honest-positioning]] we
//     fail-CLOSED here — never silently dropping rules.

package dynamicdeny

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPathEnv is the env-var name that overrides the default file
// path. Mirrors the iam-jit-wide IAM_JIT_* env-var convention from
// `[[enterprise-profile-distribution]]`.
const DefaultPathEnv = "IAM_JIT_DYNAMIC_DENIES_PATH"

// DefaultRelPath is the default path under the operator's home dir.
// `~` is resolved at lookup time via os.UserHomeDir.
const DefaultRelPath = ".iam-jit/dynamic-denies.yaml"

// BouncerName is the value the loader matches in each rule's
// `applied_to` list. Pinned here so a typo in the rest of the package
// shows up as a compile error.
const BouncerName = "dbounce"

// SchemaVersion is the on-disk schema version this loader accepts.
// A future bump migrates here per the cross-product convention.
const SchemaVersion = "1.0"

// ProductMagic is the on-disk `product` discriminator. Matches
// `docs/schemas/dynamic-denies-v1.json::product.const`.
const ProductMagic = "iam-jit-dynamic-denies"

// ruleIDPattern matches the on-disk `dd_<ULID>` shape. ULIDs are 26
// chars of Crockford base32 (rejects I/L/O/U to avoid digit confusion).
var ruleIDPattern = regexp.MustCompile(`^dd_[0-9A-HJKMNP-TV-Z]{26}$`)

// durationPattern matches `permanent` OR `N{s,m,h,d,w}` (one or more
// digits + a single unit suffix).
var durationPattern = regexp.MustCompile(`^(permanent|[0-9]+(s|m|h|d|w))$`)

// validBouncers is the set of strings allowed inside a rule's
// `applied_to` list.
var validBouncers = map[string]struct{}{
	"ibounce":  {},
	"kbounce":  {},
	"dbounce":  {},
	"gbounce":  {},
	"kbouncer": {},
}

// hostnameHeuristics names the glob shapes that signal "this target is
// probably a DB endpoint" — used by the heuristic fallback when the
// rule doesn't explicitly list dbounce in `applied_to`. Mirrors the
// canonical design doc's cross-protocol resolver table.
var hostnameHeuristics = []string{
	"*-db*",
	"*postgres*",
	"*mysql*",
	"*-rds*",
}

// ResolveDefaultPath returns the loader's default file path, honoring
// the IAM_JIT_DYNAMIC_DENIES_PATH env var. Returns an empty string
// when the home dir cannot be resolved (the caller surfaces the error
// + falls back to "no dynamic-denies file configured").
func ResolveDefaultPath() string {
	if env := strings.TrimSpace(os.Getenv(DefaultPathEnv)); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, DefaultRelPath)
}

// LoadFile reads + validates + filters the file at `path`. Returns:
//
//   - On a missing file: returns (Empty(), nil). The watcher waits for
//     the file to appear; this is NOT an error condition (an operator
//     who hasn't installed any dynamic denies still wants the proxy to
//     start cleanly).
//   - On a parse / schema / structural error: returns (Empty(), err).
//     Caller policy is "fail-closed; retain previous snapshot."
//   - On success: returns (RuleSet, nil) with the rules filtered to
//     those that apply to dbounce + that haven't already expired at
//     the wall-clock the loader runs at.
func LoadFile(path string) (*RuleSet, error) {
	if path == "" {
		return Empty(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Honest no-file shape — the watcher waits for the file to
			// appear; the proxy starts up with zero dynamic rules.
			rs := Empty()
			rs.SourcePath = path
			rs.LoadedAt = time.Now().UTC()
			return rs, nil
		}
		return Empty(), fmt.Errorf("dynamic-denies: read %q: %w", path, err)
	}
	return parseAndFilter(raw, path)
}

// LoadBytes is the test-time entry point. Same shape as LoadFile but
// reads from an in-memory byte slice — handy for the unit tests that
// don't want a real on-disk file.
func LoadBytes(raw []byte, path string) (*RuleSet, error) {
	return parseAndFilter(raw, path)
}

// parseAndFilter is the shared implementation behind LoadFile +
// LoadBytes. Validates the file shape against the v1.0 schema; returns
// a filtered RuleSet on success.
func parseAndFilter(raw []byte, path string) (*RuleSet, error) {
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return Empty(), fmt.Errorf("dynamic-denies: parse %q: %w", path, err)
	}
	if err := validateFile(&f); err != nil {
		return Empty(), fmt.Errorf("dynamic-denies: validate %q: %w", path, err)
	}

	now := time.Now().UTC()
	out := &RuleSet{
		SourcePath: path,
		LoadedAt:   now,
	}
	for _, r := range f.Denies {
		if !appliesToDbounce(r) {
			continue
		}
		// Drop already-expired rules at load time so the matcher never
		// sees them. The watcher schedules a reload at expiry time for
		// not-yet-expired rules (TODO in #324e/f — for now the watcher
		// only reacts to file changes).
		if r.ExpiresAt != nil && !r.ExpiresAt.IsZero() && r.ExpiresAt.Before(now) {
			continue
		}
		out.Rules = append(out.Rules, r)
	}
	return out, nil
}

// validateFile runs the shape checks the cross-product schema declares.
// Returned errors name the offending field + value so an operator
// debugging a parse rejection sees exactly what to fix.
func validateFile(f *File) error {
	if f.SchemaVersion == "" {
		return errors.New("missing required field `schema_version`")
	}
	if f.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q (this dbounce build accepts %q only)", f.SchemaVersion, SchemaVersion)
	}
	// product field is optional in the schema (no `required`), but if
	// present it must match the magic discriminator so a misrouted
	// dbounce-config.yaml gets refused.
	if f.Product != "" && f.Product != ProductMagic {
		return fmt.Errorf("unexpected `product` value %q (this loader accepts %q only)", f.Product, ProductMagic)
	}
	if f.Denies == nil {
		// Schema requires `denies`; treat nil as missing so an operator
		// with an empty list writes `denies: []` explicitly.
		return errors.New("missing required field `denies`")
	}
	seen := map[string]struct{}{}
	for i, r := range f.Denies {
		if err := validateRule(i, &r); err != nil {
			return err
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("rule[%d]: duplicate id %q", i, r.ID)
		}
		seen[r.ID] = struct{}{}
	}
	return nil
}

func validateRule(idx int, r *Rule) error {
	if r.ID == "" {
		return fmt.Errorf("rule[%d]: missing required field `id`", idx)
	}
	if !ruleIDPattern.MatchString(r.ID) {
		return fmt.Errorf("rule[%d]: id %q does not match required `dd_<ULID>` shape", idx, r.ID)
	}
	if len(r.Targets) == 0 {
		return fmt.Errorf("rule[%d] %q: targets is required + must have >=1 entry", idx, r.ID)
	}
	for j, t := range r.Targets {
		if strings.TrimSpace(t) == "" {
			return fmt.Errorf("rule[%d] %q: targets[%d] is empty", idx, r.ID, j)
		}
	}
	if r.Reason == "" {
		return fmt.Errorf("rule[%d] %q: reason is required + must be non-empty", idx, r.ID)
	}
	if r.Duration == "" {
		return fmt.Errorf("rule[%d] %q: duration is required", idx, r.ID)
	}
	if !durationPattern.MatchString(r.Duration) {
		return fmt.Errorf("rule[%d] %q: duration %q does not match `permanent` or `N{s|m|h|d|w}`", idx, r.ID, r.Duration)
	}
	if r.AddedBy == "" {
		return fmt.Errorf("rule[%d] %q: added_by is required", idx, r.ID)
	}
	if r.AddedAt.IsZero() {
		return fmt.Errorf("rule[%d] %q: added_at is required", idx, r.ID)
	}
	if len(r.AppliedTo) == 0 {
		return fmt.Errorf("rule[%d] %q: applied_to is required + must have >=1 entry", idx, r.ID)
	}
	for j, b := range r.AppliedTo {
		if _, ok := validBouncers[b]; !ok {
			return fmt.Errorf("rule[%d] %q: applied_to[%d] %q is not a recognized bouncer name (expected one of ibounce/kbounce/dbounce/gbounce/kbouncer)", idx, r.ID, j, b)
		}
	}
	if r.Source != "" {
		switch r.Source {
		case "cli", "mcp", "org-distributed", "imported":
			// ok
		default:
			return fmt.Errorf("rule[%d] %q: source %q is not a recognized provenance (expected one of cli/mcp/org-distributed/imported)", idx, r.ID, r.Source)
		}
	}
	return nil
}

// appliesToDbounce reports whether a rule should land in the dbounce
// lane. Operator-explicit `applied_to: [dbounce]` always wins; otherwise
// the hostname/RDS-ARN heuristic fires when at least one target matches
// the DB-endpoint shape.
func appliesToDbounce(r Rule) bool {
	// 1. Explicit annotation always wins.
	for _, b := range r.AppliedTo {
		if b == BouncerName {
			return true
		}
	}
	// 2. Heuristic fallback: pattern shape match on any target.
	for _, t := range r.Targets {
		if isARNPattern(t) {
			// rds:* ARN patterns land on dbounce. Other ARN families
			// (s3, secretsmanager, ...) are ibounce's lane.
			if isRDSArn(t) {
				return true
			}
			continue
		}
		// Hostname-shaped target — apply the heuristic glob list.
		for _, h := range hostnameHeuristics {
			if globMatch(h, t) {
				return true
			}
		}
	}
	return false
}

// isARNPattern reports whether s looks like an AWS ARN (or a glob
// thereof). Cheap prefix check — the resolver in #324e is the source
// of truth; this is only a shape classifier.
func isARNPattern(s string) bool {
	return strings.HasPrefix(s, "arn:aws:") || strings.HasPrefix(s, "arn:*")
}

// isRDSArn reports whether s is an `arn:aws:rds:*` pattern. Used by
// the heuristic fallback to decide whether an ARN-shaped target lands
// on dbounce (vs ibounce).
func isRDSArn(s string) bool {
	return strings.HasPrefix(s, "arn:aws:rds:")
}

// globMatch reports whether the glob pattern (with `*` as any-run
// wildcard) matches s. Case-insensitive — DB hostnames are commonly
// lowercased but the operator's typed glob may not be. Linear time
// in pattern len * s len; bounded by the small fixed inputs here.
func globMatch(pattern, s string) bool {
	pattern = strings.ToLower(pattern)
	s = strings.ToLower(s)
	return globMatchCS(pattern, s)
}

// globMatchCS is the case-sensitive glob matcher. Two-pointer scan
// with backtracking on `*`. No regexp dependency.
func globMatchCS(pattern, s string) bool {
	pi, si := 0, 0
	starIdx, matchIdx := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			starIdx = pi
			matchIdx = si
			pi++
		case starIdx != -1:
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

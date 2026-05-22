// Package caveats surfaces relevant §B entries from the canonical
// KNOWN-CAVEATS.md doc at three discoverability surfaces:
//
//   - `dbounce run` startup banner (one-line hint when a triggering
//     config is detected)
//   - `dbounce doctor caveats` (full §B explanation per applicable
//     entry, plus link to canonical doc)
//   - MCP tool descriptions (so an agent reading `tools/list` sees
//     the caveat embedded in the description)
//
// The canonical caveat content lives in
// https://github.com/trsreagan3/iam-jit/blob/main/docs/KNOWN-CAVEATS.md.
// THIS package does NOT duplicate the full content — only the short
// summary + the anchor — because:
//   - the canonical doc is owned by the iam-roles repo (concurrent
//     edit hazard if we copy verbatim across four repos);
//   - the one-line banner + the doctor's short blurb is enough to
//     point an operator at the linked anchor for the full read.
package caveats

import "fmt"

const canonicalDocURL = "https://github.com/trsreagan3/iam-jit/blob/main/docs/KNOWN-CAVEATS.md"

// Entry describes one row from KNOWN-CAVEATS §B that dbounce surfaces.
type Entry struct {
	ID          string
	Anchor      string
	BannerLine  string
	DoctorBlurb string
}

// URL returns the full GitHub URL pointing at this entry's anchor.
func (e Entry) URL() string { return canonicalDocURL + "#" + e.Anchor }

// All dbounce-relevant §B entries. Per task #304:
//   - product-specific: B6 (per-statement gating, not per-result),
//     B7 (literal-redaction is heuristic — numerics not redacted)
//   - cross-product: B13, B14, B15
var All = []Entry{
	{
		ID:     "B6",
		Anchor: "b6-dbounce-per-statement-gating-not-per-result-design",
		BannerLine: "  caveat: dbounce gates per-statement; a SELECT returning 1M " +
			"rows is one DECISION event, not 1M (see KNOWN-CAVEATS §B6)",
		DoctorBlurb: "dbounce evaluates per-statement, not per-result-row. " +
			"A SELECT that returns 1M rows is ONE decision event in the " +
			"audit log — not 1M. This is the deliberate per-statement " +
			"shape; a future slice could add per-result-row gating but " +
			"that's a different product.",
	},
	{
		ID:     "B7",
		Anchor: "b7-dbounce-literal-redaction-is-heuristic-design--partial",
		BannerLine: "  caveat: dbounce redacts string literals in WHERE; " +
			"numeric literals are NOT redacted (see KNOWN-CAVEATS §B7)",
		DoctorBlurb: "dbounce's literal-redaction is heuristic + partial. " +
			"String literals in `WHERE` get redacted to '?'; numeric " +
			"literals do NOT. If you store PII as numeric columns " +
			"(SSNs / IDs / phone numbers stored as integers), pair " +
			"with `--redact-numerics` (post-v1.0 flag). Per " +
			"[[dbounce-sql-redaction-gaps]].",
	},
	{
		ID:     "B13",
		Anchor: "b13-cross-product-1-3-concurrent-terminals-in-v10-gap--v11-raises-to-20",
		DoctorBlurb: "dbounce shares the cross-product 1-3 concurrent " +
			"terminal limit with ibounce + kbounce + gbounce. v1.1 task " +
			"#296 raises this to 20.",
	},
	{
		ID:     "B14",
		Anchor: "b14-cross-product-defense-in-depth--unified-product-design-per-four-products-one-brand",
		DoctorBlurb: "dbounce is one of four Bounce products under one " +
			"brand — NOT a unified suite. ~10% of decisions show TRUE " +
			"multi-layer composition per UAT. The honest framing per " +
			"[[ibounce-honest-positioning]]: complementary products.",
	},
	{
		ID:     "B15",
		Anchor: "b15-cross-product-no-unified-deny-prompt-ui-in-v10-gap--v11",
		DoctorBlurb: "Each bouncer prompts independently in v1.0. " +
			"v1.1 brings a unified prompt-inbox UI across the suite.",
	},
}

// ByID returns the Entry with the given ID, or nil if no match.
func ByID(id string) *Entry {
	for i := range All {
		if All[i].ID == id {
			return &All[i]
		}
	}
	return nil
}

// LinkSuffix returns " (see KNOWN-CAVEATS §<ID>: <URL>)" for the
// entry with the given ID, or empty string when the ID isn't known.
func LinkSuffix(id string) string {
	e := ByID(id)
	if e == nil {
		return ""
	}
	return fmt.Sprintf(" (see KNOWN-CAVEATS §%s: %s)", e.ID, e.URL())
}

// CanonicalDocURL returns the base URL operators can read.
func CanonicalDocURL() string { return canonicalDocURL }

// Trigger captures the runtime conditions that determine which §B
// entries the startup banner emits.
type Trigger struct {
	// SafeDefaultProfile is true when the active profile is
	// "safe-default" (the deny-floor baseline). v1.0 emits both B6
	// and B7 banner lines when safe-default is active because those
	// are the literal shapes operators most need to know.
	SafeDefaultProfile bool
	// RedactNumericsEnabled is true when the operator passed
	// --redact-numerics; suppresses the B7 banner line.
	RedactNumericsEnabled bool
}

// BannerLines returns the per-line banner output for the matched
// caveats. B6 always fires (per-statement gating is structural).
// B7 fires unless --redact-numerics was passed.
func BannerLines(t Trigger) []string {
	var out []string
	if e := ByID("B6"); e != nil && e.BannerLine != "" {
		out = append(out, e.BannerLine)
	}
	if !t.RedactNumericsEnabled {
		if e := ByID("B7"); e != nil && e.BannerLine != "" {
			out = append(out, e.BannerLine)
		}
	}
	return out
}

// DoctorEntries returns the entries `dbounce doctor caveats` prints.
func DoctorEntries() []Entry { return All }

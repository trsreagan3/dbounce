// Tests for the caveats discoverability surfaces.
package caveats

import (
	"strings"
	"testing"
)

func TestAllEntriesHaveURLs(t *testing.T) {
	for _, e := range All {
		if e.ID == "" {
			t.Errorf("entry without ID: %+v", e)
		}
		if e.Anchor == "" {
			t.Errorf("entry %s without anchor", e.ID)
		}
		u := e.URL()
		if !strings.HasPrefix(u, "https://github.com/") {
			t.Errorf("entry %s URL does not look like GitHub: %s", e.ID, u)
		}
		if !strings.Contains(u, e.Anchor) {
			t.Errorf("entry %s URL %s does not contain its anchor %s", e.ID, u, e.Anchor)
		}
		if e.DoctorBlurb == "" {
			t.Errorf("entry %s missing DoctorBlurb", e.ID)
		}
	}
}

func TestByID(t *testing.T) {
	for _, id := range []string{"B6", "B7", "B13", "B14", "B15"} {
		if ByID(id) == nil {
			t.Errorf("ByID(%s) returned nil", id)
		}
	}
	if ByID("BNONE") != nil {
		t.Error("ByID(BNONE) should be nil")
	}
}

func TestBannerLinesDefault(t *testing.T) {
	// Default: B6 + B7 both fire.
	lines := BannerLines(Trigger{})
	if len(lines) != 2 {
		t.Fatalf("expected 2 banner lines, got %d: %v", len(lines), lines)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "§B6") {
		t.Errorf("banner missing §B6: %v", lines)
	}
	if !strings.Contains(joined, "§B7") {
		t.Errorf("banner missing §B7: %v", lines)
	}
}

func TestBannerLinesRedactNumericsSuppressesB7(t *testing.T) {
	lines := BannerLines(Trigger{RedactNumericsEnabled: true})
	if len(lines) != 1 {
		t.Fatalf("expected 1 banner line, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "§B6") {
		t.Errorf("banner should still emit §B6: %v", lines)
	}
	if strings.Contains(lines[0], "§B7") {
		t.Errorf("banner should suppress §B7 when --redact-numerics is on: %v", lines)
	}
}

func TestLinkSuffix(t *testing.T) {
	got := LinkSuffix("B7")
	if !strings.Contains(got, "§B7:") {
		t.Errorf("LinkSuffix missing §B7: %q", got)
	}
}

func TestDoctorEntriesCoversCrossProduct(t *testing.T) {
	ids := map[string]bool{}
	for _, e := range DoctorEntries() {
		ids[e.ID] = true
	}
	for _, must := range []string{"B6", "B7", "B13", "B14", "B15"} {
		if !ids[must] {
			t.Errorf("doctor entries missing %s", must)
		}
	}
}

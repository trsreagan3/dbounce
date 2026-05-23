// constant_time_compare_test.go — §A99 regression tests.
//
// Pre-§A99 the bearer-token gate on the 4 management endpoints
// (/audit/events, GET /, /admin/profile/reload, /admin/dynamic-
// denies/reload) compared the supplied token to the configured
// token with the `!=` operator. That's a wall-clock-string compare
// that short-circuits on the first mismatching byte, leaking the
// configured token byte-by-byte to an attacker over enough
// requests.
//
// Post-§A99 every gate routes through `crypto/subtle.ConstantTime
// Compare` (the stdlib's constant-time primitive). These tests
// verify the OBSERVABLE STATE per CONTRIBUTING.md: the source files
// MUST use `subtle.ConstantTimeCompare` and MUST NOT contain the
// pre-§A99 `tok != requireBearer` pattern.

package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var guardedFiles = []string{
	"audit_events.go",
	"events_ui.go",
	"profile_reload.go",
	"dynamic_deny_reload.go",
}

func TestBearerComparisonUsesConstantTimeCompare(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for _, name := range guardedFiles {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(wd, name)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			src := string(b)

			if !strings.Contains(src, "subtle.ConstantTimeCompare") {
				t.Errorf(
					"§A99 regression: %s no longer uses subtle."+
						"ConstantTimeCompare for the bearer compare. "+
						"See the audit finding in iam-roles repo "+
						"(#484 BB+WB).",
					name,
				)
			}
			if strings.Contains(src, "tok != requireBearer") {
				t.Errorf(
					"§A99 regression: %s reintroduced "+
						"`tok != requireBearer` (non-constant-time). "+
						"Use subtle.ConstantTimeCompare instead.",
					name,
				)
			}
			if !strings.Contains(src, `"crypto/subtle"`) {
				t.Errorf(
					"§A99 regression: %s dropped the "+
						"`crypto/subtle` import.",
					name,
				)
			}
		})
	}
}

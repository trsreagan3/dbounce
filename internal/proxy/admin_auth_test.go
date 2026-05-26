// admin_auth_test.go — #524 BB-3 state-verification tests for the
// mgmt-port admin-endpoint auth middleware (requireMgmtAuth).
//
// Test corpus mirrors the shape filed against gbounce + kbouncer per
// [[cross-product-agent-parity]] so every Bounce gets the same
// fail-closed admin gate and the same well-formed loopback
// recognition.

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAdminHandler is the no-op handler the middleware wraps in the
// tests below. Returns 200 "ok" so a test that exercises the auth
// gate can distinguish "request reached the handler" from "auth
// middleware rejected the request".
func fakeAdminHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// TestRequireMgmtAuth_LoopbackNoTokenAllows — BB-3 §1: loopback bind
// + no token configured → request passes through (preserves existing
// UX for default-deploy operators on loopback).
func TestRequireMgmtAuth_LoopbackNoTokenAllows(t *testing.T) {
	h := requireMgmtAuth(fakeAdminHandler, "", "127.0.0.1")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/dynamic-denies/reload", nil)
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("loopback + no token: status = %d body = %q; want 200", rec.Code, rec.Body.String())
	}
}

// TestRequireMgmtAuth_ExternalNoTokenRefuses — BB-3 §2: external bind
// + no token configured → 503 with operator-actionable hint.
func TestRequireMgmtAuth_ExternalNoTokenRefuses(t *testing.T) {
	h := requireMgmtAuth(fakeAdminHandler, "", "0.0.0.0")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/dynamic-denies/reload", nil)
	h(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("external + no token: status = %d; want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "--audit-events-token") {
		t.Errorf("external + no token: body lacks operator hint: %q", rec.Body.String())
	}
}

// TestRequireMgmtAuth_ExternalCorrectTokenAllows — BB-3 §3: external
// bind + token set + correct Bearer → request passes through.
func TestRequireMgmtAuth_ExternalCorrectTokenAllows(t *testing.T) {
	const token = "s3cret-token-#524-BB3"
	h := requireMgmtAuth(fakeAdminHandler, token, "0.0.0.0")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/dynamic-denies/reload", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("external + correct token: status = %d body = %q; want 200", rec.Code, rec.Body.String())
	}
}

// TestRequireMgmtAuth_ExternalWrongTokenRefuses — BB-3 §4: external
// bind + token set + wrong Bearer → 401.
func TestRequireMgmtAuth_ExternalWrongTokenRefuses(t *testing.T) {
	const token = "s3cret-token-#524-BB3"
	h := requireMgmtAuth(fakeAdminHandler, token, "0.0.0.0")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/dynamic-denies/reload", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("external + wrong token: status = %d; want 401", rec.Code)
	}
}

// TestRequireMgmtAuth_ExternalMissingHeaderRefuses — BB-3 §4 variant:
// external bind + token set + NO Authorization header → 401.
func TestRequireMgmtAuth_ExternalMissingHeaderRefuses(t *testing.T) {
	const token = "s3cret-token-#524-BB3"
	h := requireMgmtAuth(fakeAdminHandler, token, "0.0.0.0")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/dynamic-denies/reload", nil)
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("external + missing header: status = %d; want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Bearer") {
		t.Errorf("external + missing header: body lacks Bearer hint: %q", rec.Body.String())
	}
}

// TestRequireMgmtAuth_LoopbackTokenSetEnforced — BB-3 belt-and-
// suspenders: even on loopback, if a token is configured the gate
// enforces it. Matches the handler-internal bearer check the
// reload-handlers already do, so the middleware is a strict SUPERSET
// — never weaker than the handler-internal check.
func TestRequireMgmtAuth_LoopbackTokenSetEnforced(t *testing.T) {
	const token = "loopback-still-needs-token"
	h := requireMgmtAuth(fakeAdminHandler, token, "127.0.0.1")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/profile/reload", nil)
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("loopback + token set + no header: status = %d; want 401", rec.Code)
	}
}

// TestRequireMgmtAuth_ConstantTimeCompareUsed — BB-3 §5: behavioral
// baseline against accidental regressions where someone swapped
// subtle.ConstantTimeCompare for ==. The existing
// TestBearerComparisonUsesConstantTimeCompare in constant_time_compare
// _test.go walks every .go file in the package — admin_auth.go is
// caught by that test too.
func TestRequireMgmtAuth_ConstantTimeCompareUsed(t *testing.T) {
	const token = "match-prefix-then-diverge-at-the-very-end-1"
	const near = "match-prefix-then-diverge-at-the-very-end-2"
	h := requireMgmtAuth(fakeAdminHandler, token, "0.0.0.0")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/dynamic-denies/reload", nil)
	req.Header.Set("Authorization", "Bearer "+near)
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("near-match token: status = %d; want 401", rec.Code)
	}
}

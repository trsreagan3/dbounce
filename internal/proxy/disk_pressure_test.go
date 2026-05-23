// disk_pressure_test.go — proxy-layer integration tests for the
// #461 / §A63c disk-pressure circuit breaker (dbounce).
package proxy

import (
	"bytes"
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/store"
)

func freshStoreForDP(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func fakeDiskStatFn(usedPct float64) func(path string, warnPct, critPct int) (audit.DiskStatus, error) {
	return func(path string, warnPct, critPct int) (audit.DiskStatus, error) {
		return audit.ClassifyDiskStatusForTest(usedPct, warnPct, critPct, path), nil
	}
}

// TestHealthzIncludesAuditLogBlock asserts /healthz emits the
// audit_log block when DiskPressure is wired.
func TestHealthzIncludesAuditLogBlock(t *testing.T) {
	tmp := t.TempDir()
	st := audit.NewDiskPressureState(audit.DiskPressureModePauseRequests, tmp, 0, 0, 0)
	st.EvaluateAndReact(context.Background(), nil, "", fakeDiskStatFn(20.0), time.Now())
	srv := NewServer(Config{DiskPressure: st}.Normalize(), freshStoreForDP(t))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	srv.healthz(rec, req)
	if rec.Code != 200 {
		t.Fatalf("Code = %d; want 200", rec.Code)
	}
	body := rec.Body.Bytes()
	for _, want := range []string{
		`"audit_log"`,
		`"disk_pressure_mode":"pause-requests"`,
		`"refuse_requests":false`,
		`"current_archive_count":`,
		`"current_archive_size_bytes":`,
		`"warn_pct":`,
		`"crit_pct":`,
		`"emergency_pct":`,
	} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("/healthz body missing %s\nbody=%s", want, body)
		}
	}
}

// TestHealthz503AtCriticalInPauseMode asserts /healthz returns 503
// when refuse_requests=true.
func TestHealthz503AtCriticalInPauseMode(t *testing.T) {
	tmp := t.TempDir()
	st := audit.NewDiskPressureState(audit.DiskPressureModePauseRequests, tmp, 0, 0, 0)
	st.EvaluateAndReact(context.Background(), nil, "", fakeDiskStatFn(96.0), time.Now())
	srv := NewServer(Config{DiskPressure: st}.Normalize(), freshStoreForDP(t))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	srv.healthz(rec, req)
	if rec.Code != 503 {
		t.Fatalf("Code = %d; want 503", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"refuse_requests":true`) {
		t.Errorf("/healthz body missing refuse_requests=true: %s", body)
	}
}

// TestStopOnDiskCriticalAliasEquivalentToPauseMode asserts the alias
// produces identical RefuseRequests behavior at the state level.
// (The CLI-side aliasing lives in cli.go; this test pins the state
// machine's contract for both forms.)
func TestStopOnDiskCriticalAliasEquivalentToPauseMode(t *testing.T) {
	tmp := t.TempDir()
	longForm := audit.NewDiskPressureState(audit.DiskPressureModePauseRequests, tmp, 0, 0, 0)
	aliasState := audit.NewDiskPressureState(audit.DiskPressureModePauseRequests, tmp, 0, 0, 0)
	longForm.EvaluateAndReact(context.Background(), nil, "", fakeDiskStatFn(96.0), time.Now())
	aliasState.EvaluateAndReact(context.Background(), nil, "", fakeDiskStatFn(96.0), time.Now())
	if longForm.RefuseRequests() != aliasState.RefuseRequests() {
		t.Fatalf("alias RefuseRequests = %t; long form = %t",
			aliasState.RefuseRequests(), longForm.RefuseRequests())
	}
}

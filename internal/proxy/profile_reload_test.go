// profile_reload_test.go — #387 / §A25 Phase 2 admin endpoint tests.

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/store"
)

func newReloadTestServer(t *testing.T, active *profile.Profile) *Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	cfg := Config{
		Host:          "127.0.0.1",
		Port:          0,
		Dialect:       DialectPostgres,
		Mode:          ModeCooperative,
		DefaultPolicy: DefaultPolicyAllow,
		ActiveProfile: active,
	}.Normalize()
	if active != nil {
		cfg.ActiveProfileName = active.Name
	}
	return NewServer(cfg, st)
}

func writeReloadProfilesYAML(t *testing.T, dir, name string, allowRules int) string {
	t.Helper()
	body := "profiles:\n  " + name + ":\n    description: test\n"
	if allowRules > 0 {
		body += "    allow_rules:\n"
		for i := 0; i < allowRules; i++ {
			body += "    - pattern: SELECT:public.users\n      arn_scope: '*.staging.internal'\n"
		}
	}
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAdminProfileReload_HotSwapsActiveProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DBOUNCE_PROFILES_PATH", filepath.Join(dir, "profiles.yaml"))
	path := writeReloadProfilesYAML(t, dir, "work", 0)
	ps, err := profile.LoadProfiles(path)
	require.NoError(t, err)
	active, _ := ps.Active("work")
	srv := newReloadTestServer(t, active)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/profile/reload", nil)
	srv.profileReloadHandler("", path)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body=%q", rec.Body.String())

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.True(t, body["reloaded"].(bool))
	require.Equal(t, float64(0), body["rules_in_active_profile"])

	// Mutate file + reload again.
	_ = writeReloadProfilesYAML(t, dir, "work", 2)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/admin/profile/reload", nil)
	srv.profileReloadHandler("", path)(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body=%q", rec.Body.String())
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.Equal(t, float64(2), body["rules_in_active_profile"])

	// Hot-swap visible via loadActiveProfile.
	got, _ := srv.loadActiveProfile()
	require.NotNil(t, got)
	require.Equal(t, 2, len(got.AllowRules))
}

func TestAdminProfileReload_RejectsNonPOST(t *testing.T) {
	srv := newReloadTestServer(t, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/profile/reload", nil)
	srv.profileReloadHandler("", "")(rec, req)
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAdminProfileReload_NoActiveProfileNoOp(t *testing.T) {
	srv := newReloadTestServer(t, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/profile/reload", nil)
	srv.profileReloadHandler("", "")(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	require.True(t, body["reloaded"].(bool))
	require.True(t, body["no_active_profile"].(bool))
}

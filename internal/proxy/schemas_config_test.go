package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSchemasConfigEndpointServesEmbeddedSchema confirms
// `GET /schemas/config` returns the same bytes that ship in
// schemas/dbounce-config.schema.json.
func TestSchemasConfigEndpointServesEmbeddedSchema(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/schemas/config", nil)
	rec := httptest.NewRecorder()
	schemasConfigHandler(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t,
		strings.HasPrefix(resp.Header.Get("Content-Type"), "application/schema+json"),
		"unexpected content type: %q", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	wantPath := repoSchemaPath(t)
	want, err := os.ReadFile(wantPath)
	require.NoError(t, err)
	assert.Equal(t, want, body,
		"served schema diverged from %s — re-copy the published "+
			"schema into internal/proxy/schemas_config.json",
		wantPath)
}

// TestSchemasConfigEndpointReturnsValidJSONSchema: parses + post-#288
// wire-shape (string semver schema_version).
func TestSchemasConfigEndpointReturnsValidJSONSchema(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/schemas/config", nil)
	rec := httptest.NewRecorder()
	schemasConfigHandler(rec, req)

	body, err := io.ReadAll(rec.Result().Body)
	require.NoError(t, err)

	var schema map[string]any
	require.NoError(t, json.Unmarshal(body, &schema))
	props, _ := schema["properties"].(map[string]any)
	require.NotNil(t, props)
	sv, _ := props["schema_version"].(map[string]any)
	require.NotNil(t, sv)
	assert.Equal(t, "string", sv["type"])
	enumVals, ok := sv["enum"].([]any)
	require.True(t, ok)
	require.Len(t, enumVals, 1)
	assert.Equal(t, "1.0", enumVals[0])

	prod, _ := props["product"].(map[string]any)
	require.NotNil(t, prod)
	prodEnum, _ := prod["enum"].([]any)
	require.Len(t, prodEnum, 1)
	assert.Equal(t, "dbounce", prodEnum[0])
}

// TestSchemasConfigEndpointRejectsNonGet: PUT / POST / DELETE return
// 405 — the schema is READ-only metadata.
func TestSchemasConfigEndpointRejectsNonGet(t *testing.T) {
	for _, method := range []string{
		http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch,
	} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/schemas/config", nil)
			rec := httptest.NewRecorder()
			schemasConfigHandler(rec, req)
			resp := rec.Result()
			defer resp.Body.Close()
			assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
			assert.Equal(t, "GET, HEAD", resp.Header.Get("Allow"))
		})
	}
}

// repoSchemaPath returns the absolute path to the published
// dbounce-config schema file (the in-repo source of truth).
func repoSchemaPath(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	root := filepath.Dir(filepath.Dir(filepath.Dir(here)))
	return filepath.Join(root, "schemas", "dbounce-config.schema.json")
}

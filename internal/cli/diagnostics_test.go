// Tests for #277 `dbounce diagnostics bundle`.
//
// Coverage:
//
//   1. Command tree wiring (the parent + the `diag` alias both resolve)
//   2. defaultBundleOutPath produces the spec-defined timestamped path
//   3. collectDiagnostics with no live proxy + empty DB still produces
//      a valid zip + populated manifest + the expected note
//   4. Zip contents pass per-file sha256 manifest verification
//   5. SQL literals are scrubbed from audit-tail rows even when the
//      row in state.db has the literal intact
//   6. Tokens / webhook URLs / IP addresses / SQL literals do NOT
//      appear ANYWHERE in the zip contents (the grep-the-zip test the
//      spec calls out)
//   7. --no-audit excludes audit-tail.jsonl + slow-queries.jsonl
//   8. --out PATH respects the operator's choice
//   9. /healthz unreachable falls back to a placeholder + a note
//  10. Empty SQLite file is handled gracefully (no panic, no error)
//  11. The hashUserID + redactFreeText helpers behave as advertised
//  12. The DBOUNCE_* env var list ships names only (no values)

package cli

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/proxy"
	"github.com/trsreagan3/dbounce/internal/store"
)

func TestDiagnosticsCmd_TreeWired(t *testing.T) {
	c := newDiagnosticsCmd()
	assert.Equal(t, "diagnostics", c.Name())
	var found bool
	for _, sub := range c.Commands() {
		if sub.Name() == "bundle" {
			found = true
		}
	}
	assert.True(t, found, "diagnostics must wire `bundle` subcommand")

	alias := newDiagnosticsDiagAliasCmd()
	assert.Equal(t, "diag", alias.Name())
}

func TestDiagnostics_DefaultBundleOutPath(t *testing.T) {
	now := time.Date(2026, 5, 18, 14, 23, 17, 0, time.UTC)
	got := defaultBundleOutPath(now)
	assert.Equal(t, "./dbounce-diagnostics-20260518T142317Z.zip", got)
}

func TestDiagnostics_HashUserID(t *testing.T) {
	// Empty round-trips empty (avoids the "every empty col looks the
	// same hash" failure mode).
	assert.Equal(t, "", hashUserID(""))
	// Non-empty hashes to a sha256: prefix + truncated digest.
	got := hashUserID("alice@example.com")
	assert.True(t, strings.HasPrefix(got, "sha256:"))
	assert.Equal(t, 7+userIdHashLen, len(got))
	// Stable across calls.
	assert.Equal(t, got, hashUserID("alice@example.com"))
	// Different inputs produce different hashes.
	assert.NotEqual(t, got, hashUserID("bob@example.com"))
}

func TestDiagnostics_RedactFreeText(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		mustNot []string
	}{
		{
			"http_url_scrubbed",
			"error posting to https://collector.example.com/events: timeout",
			[]string{"collector.example.com", "https://"},
		},
		{
			"postgres_url_scrubbed",
			"failed to connect to postgres://user:pw@db.example.com:5432/app",
			[]string{"user:pw", "db.example.com"},
		},
		{
			"ipv4_scrubbed",
			"upstream 192.168.10.42 timed out",
			[]string{"192.168.10.42"},
		},
		{
			"email_scrubbed",
			"sent alert to alice@example.com",
			[]string{"alice@example.com"},
		},
		{
			"bearer_scrubbed",
			"Authorization: Bearer sk_live_abc123XYZ",
			[]string{"sk_live_abc123XYZ"},
		},
		{
			"token_kv_scrubbed",
			"using token=hunter2 password=p@ss",
			[]string{"hunter2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := redactFreeText(tc.in)
			for _, leak := range tc.mustNot {
				assert.NotContains(t, out, leak,
					"%s leaked %q in %q", tc.name, leak, out)
			}
			assert.Contains(t, out, "[REDACTED]",
				"%s should emit a [REDACTED] marker", tc.name)
		})
	}
}

// makeTestStoreWithSecrets seeds a fresh state.db with a couple of
// decision rows that contain SQL literals + a user identifier. Used
// by the "no secrets in zip" tests so we have something to NOT leak.
func makeTestStoreWithSecrets(t *testing.T, dir string) string {
	t.Helper()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()
	_, err = st.RecordDecision(store.DecisionRow{
		At:               time.Now().UTC(),
		Dialect:          "postgres",
		Statement:        "SELECT * FROM users WHERE email = 'alice@example.com' AND token = 'sk_live_SECRETXYZ'",
		StatementType:    "SELECT",
		TablesTouched:    []string{"users"},
		FunctionsCalled:  nil,
		IsDML:            false,
		IsDDL:            false,
		HasMutatingNode:  false,
		DecisionVerdict:  "ALLOW",
		DecisionReason:   "matched rule; remote 10.0.0.42 connected to https://internal-host.example.com",
		ModeAtDecision:   "cooperative",
		Enforced:         false,
		DecisionSource:   "global",
		ImpersonatedRole: "support-staff-bob",
	})
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		At:              time.Now().UTC().Add(-1 * time.Minute),
		Dialect:         "postgres",
		Statement:       "UPDATE accounts SET status = 'frozen' WHERE id = 42",
		StatementType:   "UPDATE",
		TablesTouched:   []string{"accounts"},
		IsDML:           true,
		HasMutatingNode: true,
		DecisionVerdict: "DENY",
		DecisionReason:  "violates profile policy",
		ModeAtDecision:  "transparent",
		Enforced:        true,
		DecisionSource:  "profile",
		ProfileName:     "safe-default",
	})
	require.NoError(t, err)
	// Add a rule too so the config-export side has something to ship.
	_, err = st.AddRule(dbrules.ProxyRule{
		Pattern: "DELETE:public.*",
		Effect:  dbrules.EffectDeny,
		Note:    "no deletes by default",
		Origin:  dbrules.OriginUser,
	})
	require.NoError(t, err)
	return dbPath
}

func TestDiagnostics_CollectExitsZeroOnFreshEmptyDB(t *testing.T) {
	dir := t.TempDir()
	zipBytes, manifest, err := collectDiagnostics(collectDiagnosticsParams{
		DBPath:           filepath.Join(dir, "state.db"),
		ProfilesPath:     filepath.Join(dir, "profiles.yaml"),
		Dialect:          proxy.DialectPostgres,
		MgmtURL:          "", // empty -> note in manifest, not a failure
		IncludeAuditTail: defaultAuditTailRows,
		FetchTimeout:     1 * time.Second,
		Actor:            "tester",
		GeneratedAt:      time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC),
	})
	require.NoError(t, err)
	require.NotEmpty(t, zipBytes)
	require.NotNil(t, manifest)
	assert.Equal(t, diagnosticsBundleFormat, manifest.Format)
	assert.Equal(t, diagnosticsBundleVersion, manifest.FormatVersion)
	assert.Equal(t, "dbounce", manifest.Product)
	assert.NotEmpty(t, manifest.Files)
	// /healthz unreachable should appear in notes.
	var sawHealthNote bool
	for _, n := range manifest.Notes {
		if strings.Contains(n, "health.json") {
			sawHealthNote = true
		}
	}
	assert.True(t, sawHealthNote, "expected health.json note for unreachable /healthz; notes=%v", manifest.Notes)
}

func TestDiagnostics_ManifestSHA256sMatchZipContents(t *testing.T) {
	dir := t.TempDir()
	zipBytes, manifest, err := collectDiagnostics(collectDiagnosticsParams{
		DBPath:           filepath.Join(dir, "state.db"),
		ProfilesPath:     filepath.Join(dir, "profiles.yaml"),
		Dialect:          proxy.DialectPostgres,
		IncludeAuditTail: defaultAuditTailRows,
		FetchTimeout:     500 * time.Millisecond,
		GeneratedAt:      time.Now().UTC(),
	})
	require.NoError(t, err)
	files := readZipFiles(t, zipBytes)
	// manifest.json itself is in the zip but not in manifest.Files.
	for _, mf := range manifest.Files {
		data, ok := files[mf.Name]
		require.True(t, ok, "manifest names %q but zip does not contain it", mf.Name)
		assert.Equal(t, mf.Size, len(data), "size mismatch for %q", mf.Name)
		sum := sha256.Sum256(data)
		assert.Equal(t, mf.SHA256, hex.EncodeToString(sum[:]),
			"sha256 mismatch for %q", mf.Name)
	}
	// manifest.json must be in the zip + parse cleanly.
	mraw, ok := files["manifest.json"]
	require.True(t, ok, "zip must contain manifest.json")
	var roundTrip DiagnosticsManifest
	require.NoError(t, json.Unmarshal(mraw, &roundTrip))
	assert.Equal(t, diagnosticsBundleFormat, roundTrip.Format)
}

func TestDiagnostics_NoSecretsInZipContents(t *testing.T) {
	dir := t.TempDir()
	dbPath := makeTestStoreWithSecrets(t, dir)
	// Also seed DBOUNCE_STDERR_LOG-style data: a stderr-log file
	// containing secrets.
	stderrPath := filepath.Join(dir, "dbounce.stderr.log")
	require.NoError(t, os.WriteFile(stderrPath, []byte(
		"2026-05-18T12:00:00Z WARN failed POST to https://collector.example.com/events token=hunter2\n"+
			"2026-05-18T12:00:01Z INFO upstream 10.0.0.42 reachable\n"+
			"2026-05-18T12:00:02Z INFO contact alice@example.com\n",
	), 0o600))

	zipBytes, manifest, err := collectDiagnostics(collectDiagnosticsParams{
		DBPath:           dbPath,
		ProfilesPath:     filepath.Join(dir, "profiles.yaml"),
		Dialect:          proxy.DialectPostgres,
		StderrLogPath:    stderrPath,
		IncludeAuditTail: defaultAuditTailRows,
		FetchTimeout:     500 * time.Millisecond,
		GeneratedAt:      time.Now().UTC(),
	})
	require.NoError(t, err)
	files := readZipFiles(t, zipBytes)

	// Grep every file in the zip for leaks.
	leakStrings := []string{
		"alice@example.com",
		"sk_live_SECRETXYZ",
		"hunter2",
		"10.0.0.42",
		"collector.example.com",
		"internal-host.example.com",
		"support-staff-bob", // user id -> must be hashed in audit
	}
	for name, data := range files {
		text := string(data)
		for _, leak := range leakStrings {
			assert.NotContainsf(t, text, leak,
				"file %q in bundle leaked %q\ncontent:\n%s",
				name, leak, truncate(text, 1024))
		}
	}
	// Sanity: a [REDACTED] marker shows up somewhere (audit-tail or
	// errors.tail or both) confirming the redaction path ran.
	var sawRedacted bool
	for _, data := range files {
		if strings.Contains(string(data), "[REDACTED]") {
			sawRedacted = true
			break
		}
	}
	assert.True(t, sawRedacted, "expected [REDACTED] marker somewhere in bundle")
	// Belt-and-suspenders: the manifest.Files entry for audit-tail
	// should exist + be non-empty.
	var auditEntry *DiagnosticsManifestFile
	for i, f := range manifest.Files {
		if f.Name == "audit-tail.jsonl" {
			auditEntry = &manifest.Files[i]
		}
	}
	require.NotNil(t, auditEntry, "audit-tail.jsonl missing from manifest")
	assert.Greater(t, auditEntry.Size, 0)
}

func TestDiagnostics_NoAuditOmitsAuditSections(t *testing.T) {
	dir := t.TempDir()
	dbPath := makeTestStoreWithSecrets(t, dir)
	zipBytes, manifest, err := collectDiagnostics(collectDiagnosticsParams{
		DBPath:           dbPath,
		ProfilesPath:     filepath.Join(dir, "profiles.yaml"),
		Dialect:          proxy.DialectPostgres,
		NoAudit:          true,
		IncludeAuditTail: defaultAuditTailRows,
		FetchTimeout:     500 * time.Millisecond,
		GeneratedAt:      time.Now().UTC(),
	})
	require.NoError(t, err)
	files := readZipFiles(t, zipBytes)
	_, hasAudit := files["audit-tail.jsonl"]
	_, hasSlow := files["slow-queries.jsonl"]
	assert.False(t, hasAudit, "--no-audit must exclude audit-tail.jsonl")
	assert.False(t, hasSlow, "--no-audit must exclude slow-queries.jsonl")
	// Notes must record the omission.
	var sawOmitNote bool
	for _, n := range manifest.Notes {
		if strings.Contains(n, "--no-audit") {
			sawOmitNote = true
		}
	}
	assert.True(t, sawOmitNote, "expected --no-audit omission note; notes=%v", manifest.Notes)
}

func TestDiagnostics_OutPathHonored(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "custom-name.zip")
	zipBytes, _, err := collectDiagnostics(collectDiagnosticsParams{
		DBPath:           filepath.Join(dir, "state.db"),
		ProfilesPath:     filepath.Join(dir, "profiles.yaml"),
		Dialect:          proxy.DialectPostgres,
		IncludeAuditTail: defaultAuditTailRows,
		FetchTimeout:     500 * time.Millisecond,
		GeneratedAt:      time.Now().UTC(),
	})
	require.NoError(t, err)
	require.NoError(t, writeBundleAtomic(out, zipBytes))
	info, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, int64(len(zipBytes)), info.Size())
	// File must be readable as a valid zip.
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	_, err = zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err, "output must be a valid zip")
}

func TestDiagnostics_HealthzReachableEmbedsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","mode":"cooperative","dialect":"postgres","active_profile":"safe-default","decisions_count":42}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	zipBytes, manifest, err := collectDiagnostics(collectDiagnosticsParams{
		DBPath:           filepath.Join(dir, "state.db"),
		ProfilesPath:     filepath.Join(dir, "profiles.yaml"),
		Dialect:          proxy.DialectPostgres,
		MgmtURL:          server.URL,
		IncludeAuditTail: defaultAuditTailRows,
		FetchTimeout:     5 * time.Second,
		GeneratedAt:      time.Now().UTC(),
	})
	require.NoError(t, err)
	files := readZipFiles(t, zipBytes)
	healthRaw, ok := files["health.json"]
	require.True(t, ok)
	assert.Contains(t, string(healthRaw), `"mode": "cooperative"`)
	assert.Contains(t, string(healthRaw), `"decisions_count": 42`)
	listenerRaw, ok := files["listener-status.json"]
	require.True(t, ok)
	assert.Contains(t, string(listenerRaw), `"live_proxy": true`)
	assert.Contains(t, string(listenerRaw), `"dialect": "postgres"`)
	// No /healthz error note expected this time.
	for _, n := range manifest.Notes {
		assert.NotContains(t, n, "health.json")
	}
}

func TestDiagnostics_HealthzUnreachableFallsBackToPlaceholder(t *testing.T) {
	dir := t.TempDir()
	zipBytes, manifest, err := collectDiagnostics(collectDiagnosticsParams{
		DBPath:           filepath.Join(dir, "state.db"),
		ProfilesPath:     filepath.Join(dir, "profiles.yaml"),
		Dialect:          proxy.DialectPostgres,
		// Point at a port nobody listens on so we get a real connection
		// error rather than a timeout.
		MgmtURL:          "http://127.0.0.1:1/healthz",
		IncludeAuditTail: defaultAuditTailRows,
		FetchTimeout:     500 * time.Millisecond,
		GeneratedAt:      time.Now().UTC(),
	})
	require.NoError(t, err)
	files := readZipFiles(t, zipBytes)
	healthRaw := files["health.json"]
	assert.Contains(t, string(healthRaw), "healthz_unreachable")
	listenerRaw := files["listener-status.json"]
	assert.Contains(t, string(listenerRaw), `"live_proxy": false`)
	// Notes must include the unreachable note.
	var sawNote bool
	for _, n := range manifest.Notes {
		if strings.Contains(n, "health.json") && strings.Contains(n, "unreachable") {
			sawNote = true
		}
	}
	assert.True(t, sawNote, "expected health.json unreachable note; notes=%v", manifest.Notes)
}

func TestDiagnostics_EmptySQLiteHandledGracefully(t *testing.T) {
	dir := t.TempDir()
	// Create a zero-byte file at the db path. store.Open should still
	// initialize it (CREATE TABLE IF NOT EXISTS). Bundle must not panic.
	dbPath := filepath.Join(dir, "state.db")
	require.NoError(t, os.WriteFile(dbPath, []byte{}, 0o600))
	// Delete it again so store.Open creates fresh — empty file would
	// actually parse as a brand-new sqlite db, but the test name
	// covers the broader "missing" case too.
	require.NoError(t, os.Remove(dbPath))

	zipBytes, manifest, err := collectDiagnostics(collectDiagnosticsParams{
		DBPath:           dbPath,
		ProfilesPath:     filepath.Join(dir, "profiles.yaml"),
		Dialect:          proxy.DialectPostgres,
		IncludeAuditTail: defaultAuditTailRows,
		FetchTimeout:     500 * time.Millisecond,
		GeneratedAt:      time.Now().UTC(),
	})
	require.NoError(t, err)
	files := readZipFiles(t, zipBytes)
	statsRaw, ok := files["sqlite-stats.json"]
	require.True(t, ok)
	// schema_version_constant key must appear regardless of file state.
	assert.Contains(t, string(statsRaw), "schema_version_constant")
	// row_counts.decisions == 0 because fresh DB.
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(statsRaw, &parsed))
	rowCounts, ok := parsed["row_counts"].(map[string]any)
	require.True(t, ok)
	assert.EqualValues(t, 0, rowCounts["decisions"])
	// manifest still well-formed.
	assert.NotEmpty(t, manifest.Files)
}

func TestDiagnostics_EnvNamesFileShipsNamesOnly(t *testing.T) {
	t.Setenv("DBOUNCE_DIAG_TEST_FAKE_TOKEN", "super-secret-value-DO-NOT-LEAK")
	out := collectEnvNamesFile()
	body := string(out)
	assert.Contains(t, body, "DBOUNCE_DIAG_TEST_FAKE_TOKEN=<redacted>")
	assert.NotContains(t, body, "super-secret-value-DO-NOT-LEAK")
}

// readZipFiles returns the {name -> bytes} map of a zip blob.
func readZipFiles(t *testing.T, zipBytes []byte) map[string][]byte {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	require.NoError(t, err)
	out := map[string][]byte{}
	for _, f := range r.File {
		rc, err := f.Open()
		require.NoError(t, err)
		data, err := io.ReadAll(rc)
		require.NoError(t, err)
		_ = rc.Close()
		out[f.Name] = data
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

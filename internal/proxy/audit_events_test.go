// audit_events_test.go covers GET /audit/events shipped in #271.
// Same shape as the gbounce + kbounce + ibounce sibling tests; see
// docs/QUERYING-AUDIT-LOGS.md for the wire spec.

package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trsreagan3/dbounce/internal/store"
)

func seedAuditEventsStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	base := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	rows := []store.DecisionRow{
		{
			At:              base,
			Dialect:         "postgres",
			Statement:       "SELECT * FROM users",
			StatementType:   "SELECT",
			TablesTouched:   []string{"users"},
			IsDML:           true,
			DecisionVerdict: "ALLOW",
			DecisionReason:  "select is read-only",
			ModeAtDecision:  "cooperative",
		},
		{
			At:               base.Add(10 * time.Second),
			Dialect:          "postgres",
			Statement:        "DELETE FROM users",
			StatementType:    "DELETE",
			TablesTouched:    []string{"users"},
			HasMutatingNode:  true,
			MutatingNodeType: "DELETE",
			IsDML:            true,
			DecisionVerdict:  "DENY",
			DecisionReason:   "deletion-not-permitted",
			ModeAtDecision:   "transparent",
			Enforced:         true,
		},
		{
			At:              base.Add(20 * time.Second),
			Dialect:         "mysql",
			Statement:       "INSERT INTO orders VALUES (1)",
			StatementType:   "INSERT",
			TablesTouched:   []string{"orders"},
			IsDML:           true,
			DecisionVerdict: "ALLOW",
			ModeAtDecision:  "cooperative",
		},
	}
	for _, r := range rows {
		if _, err := st.RecordDecision(r); err != nil {
			t.Fatalf("RecordDecision: %v", err)
		}
	}
	return st
}

func newAuditEventsTestServer(t *testing.T, requireToken string) (*httptest.Server, *store.Store) {
	t.Helper()
	st := seedAuditEventsStore(t)
	srv := httptest.NewServer(auditEventsHandler(st, requireToken))
	t.Cleanup(srv.Close)
	return srv, st
}

func TestAuditEvents_GetReturnsJSONL(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?limit=10")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("content-type = %q; want application/x-ndjson", ct)
	}
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Errorf("line %d: invalid JSON: %v", n+1, err)
		}
		n++
	}
	if n != 3 {
		t.Errorf("got %d events; want 3", n)
	}
}

func TestAuditEvents_FilterByDialectMatches(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	u, _ := url.Parse(srv.URL)
	q := u.Query()
	q.Set("limit", "10")
	q.Add("filter", "api.service.name=mysql")
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		n++
	}
	if n != 1 {
		t.Errorf("got %d events; want 1 (filtered to mysql)", n)
	}
}

func TestAuditEvents_FilterByExtFieldMatches(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	// mutating_node_type is a dbounce-specific ext-map field set
	// when the parser detects a mutating AST node.
	u, _ := url.Parse(srv.URL)
	q := u.Query()
	q.Set("limit", "10")
	q.Add("filter", "unmapped.iam_jit.ext.mutating_node_type=DELETE")
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		n++
	}
	if n != 1 {
		t.Errorf("got %d events; want 1 (filtered to mutating_node_type=DELETE)", n)
	}
}

func TestAuditEvents_BadFilterReturns400(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	u, _ := url.Parse(srv.URL)
	q := u.Query()
	q.Add("filter", "no_operator_here")
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d (want 400)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var payload map[string]string
	_ = json.Unmarshal(body, &payload)
	if !strings.Contains(payload["error"], "filter") {
		t.Errorf("error body = %q; want filter-mentioning", payload["error"])
	}
}

func TestAuditEvents_LimitCapsResults(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?limit=1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		n++
	}
	if n != 1 {
		t.Errorf("got %d events; want 1 (limit)", n)
	}
}

func TestAuditEvents_LimitOverMaxRejected(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(fmt.Sprintf("%s?limit=%d", srv.URL, AuditEventsMaxLimit+1))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d (want 400)", resp.StatusCode)
	}
}

func TestAuditEvents_SinceUntilBoundsWork(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	noneURL := fmt.Sprintf("%s?since=%s",
		srv.URL,
		url.QueryEscape(time.Now().UTC().Add(-30*time.Minute).Format(time.RFC3339)),
	)
	resp, err := http.Get(noneURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	scanner := bufio.NewScanner(resp.Body)
	n := 0
	for scanner.Scan() {
		n++
	}
	resp.Body.Close()
	if n != 0 {
		t.Errorf("since=30min-ago: got %d events; want 0", n)
	}
	allURL := fmt.Sprintf("%s?since=%s",
		srv.URL,
		url.QueryEscape(time.Now().UTC().Add(-2*time.Hour).Format(time.RFC3339)),
	)
	resp2, err := http.Get(allURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp2.Body.Close()
	scanner2 := bufio.NewScanner(resp2.Body)
	n2 := 0
	for scanner2.Scan() {
		n2++
	}
	if n2 != 3 {
		t.Errorf("since=2h-ago: got %d events; want 3", n2)
	}
}

func TestAuditEvents_BadTimeBoundReturns400(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?since=not-a-time")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d (want 400)", resp.StatusCode)
	}
}

func TestAuditEvents_OCSFBundleFormat(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?format=ocsf-bundle&limit=10")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (want 200)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var bundle map[string]any
	if err := json.Unmarshal(body, &bundle); err != nil {
		t.Fatalf("decode bundle: %v\n%s", err, body)
	}
	if cl, _ := bundle["class_uid"].(float64); cl != 2004 {
		t.Errorf("class_uid = %v; want 2004", bundle["class_uid"])
	}
	events, ok := bundle["events"].([]any)
	if !ok {
		t.Fatalf("events not an array; got %T", bundle["events"])
	}
	if len(events) != 3 {
		t.Errorf("bundle events len = %d; want 3", len(events))
	}
}

func TestAuditEvents_UnknownFormatReturns400(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	resp, err := http.Get(srv.URL + "?format=wat")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d (want 400)", resp.StatusCode)
	}
}

func TestAuditEvents_AuthTokenMissingReturns401(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "secret-token")
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d (want 401)", resp.StatusCode)
	}
}

func TestAuditEvents_AuthTokenWrongReturns403(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "secret-token")
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d (want 403)", resp.StatusCode)
	}
}

func TestAuditEvents_AuthTokenCorrectReturns200(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "secret-token")
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d (want 200)", resp.StatusCode)
	}
}

func TestAuditEvents_NonGETMethodRejected(t *testing.T) {
	srv, _ := newAuditEventsTestServer(t, "")
	req, _ := http.NewRequest("POST", srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d (want 405)", resp.StatusCode)
	}
}

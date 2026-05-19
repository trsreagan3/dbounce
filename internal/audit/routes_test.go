package audit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Test-secret literals the leak-prevention test greps for. If ANY of
// these appears in a status snapshot or stringified destination, the
// leak test fails.
const (
	testSOCToken      = "lit_soc_splunk_hec_secret_no_leak_xyz"
	testDevToken      = "lit_dev_datadog_secret_no_leak_xyz"
	testPDKey         = "lit_pagerduty_integration_no_leak_xyz"
	testSlackURL      = "https://hooks.slack.com/services/T123/B456/litSlackNoLeakXyz"
	testArchiveToken  = "lit_central_archive_secret_no_leak_xyz"
)

func setSecretEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SOC_SPLUNK_HEC_TOKEN", testSOCToken)
	t.Setenv("DEV_DATADOG_API_KEY", testDevToken)
	t.Setenv("PD_INTEGRATION_KEY", testPDKey)
	t.Setenv("SLACK_ONCALL_WEBHOOK", testSlackURL)
	t.Setenv("CENTRAL_ARCHIVE_TOKEN", testArchiveToken)
}

func writeMemoRoutesYAML(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.yaml")
	body := `
routes:
  - name: soc-high-severity
    match:
      severity_id: { gte: 3 }
    destinations:
      - webhook:
          url: https://splunk-soc.example.com/services/collector/event
          token: ${SOC_SPLUNK_HEC_TOKEN}
          preset: splunk-hec
          allow_internal: true
  - name: dev-team-own-events
    match:
      actor.user.attribute.team: dev
    destinations:
      - webhook:
          url: https://datadog-dev.example.com/api/v2/logs
          token: ${DEV_DATADOG_API_KEY}
          preset: datadog
          allow_internal: true
  - name: on-call-critical
    match:
      severity_id: 5
    destinations:
      - pagerduty:
          integration_key: ${PD_INTEGRATION_KEY}
      - slack:
          webhook_url: ${SLACK_ONCALL_WEBHOOK}
  - name: central-archive
    match: {}
    destinations:
      - webhook:
          url: https://archive-collector.example.com/api/v1/audit
          token: ${CENTRAL_ARCHIVE_TOKEN}
          preset: generic
          allow_internal: true
    on_match: continue
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func sampleEventMap() map[string]any {
	return map[string]any{
		"metadata": map[string]any{
			"version": "1.1.0",
			"product": map[string]any{"name": "dbounce", "vendor_name": "iam-jit"},
		},
		"category_uid": 6,
		"class_uid":    6003,
		"activity_id":  1,
		"severity_id":  3,
		"severity":     "Medium",
		"status_id":    1,
		"status":       "Success",
		"time":         int64(1717000000000),
		"api": map[string]any{
			"operation": "iam:CreateRole",
		},
		"actor": map[string]any{
			"user": map[string]any{
				"name":      "alice@example.com",
				"attribute": map[string]any{"team": "dev"},
			},
		},
		"resources": []any{
			map[string]any{"uid": "role/example", "type": "Role"},
		},
		"src_endpoint": map[string]any{
			"ip":       "10.0.0.5",
			"hostname": "dev-laptop",
		},
		"unmapped": map[string]any{
			"iam_jit": map[string]any{"verdict": "ALLOW", "mode": "cooperative"},
		},
	}
}

func TestLoadRoutesConfig_HappyPath(t *testing.T) {
	setSecretEnv(t)
	path := writeMemoRoutesYAML(t)
	cfg, err := LoadRoutesConfig(path)
	if err != nil {
		t.Fatalf("LoadRoutesConfig: %v", err)
	}
	if got, want := len(cfg.Routes), 4; got != want {
		t.Fatalf("route count: got %d want %d", got, want)
	}
	want := []string{
		"soc-high-severity", "dev-team-own-events",
		"on-call-critical", "central-archive",
	}
	for i, w := range want {
		if cfg.Routes[i].Name != w {
			t.Errorf("route[%d].Name: got %q want %q",
				i, cfg.Routes[i].Name, w)
		}
	}
	if cfg.Routes[3].OnMatch != "continue" {
		t.Errorf("central-archive on_match: got %q want continue",
			cfg.Routes[3].OnMatch)
	}
	for i := 0; i < 3; i++ {
		if cfg.Routes[i].OnMatch != "stop" {
			t.Errorf("route[%d] on_match default: got %q want stop",
				i, cfg.Routes[i].OnMatch)
		}
	}
}

func TestLoadRoutesConfig_BareLiteralTokenRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	body := `
routes:
  - name: bad
    match: {}
    destinations:
      - webhook:
          url: https://x.example
          token: literal_token_should_be_refused
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRoutesConfig(path)
	if err == nil || !strings.Contains(err.Error(), "env-var interpolation") {
		t.Fatalf("expected env-var-interpolation error; got %v", err)
	}
}

func TestLoadRoutesConfig_MissingEnvVar(t *testing.T) {
	os.Unsetenv("NEVER_SET_FOR_THIS_TEST")
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	body := `
routes:
  - name: bad
    match: {}
    destinations:
      - webhook:
          url: https://x.example
          token: ${NEVER_SET_FOR_THIS_TEST}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRoutesConfig(path)
	if err == nil || !strings.Contains(err.Error(), "not set") {
		t.Fatalf("expected env-not-set error; got %v", err)
	}
}

func TestLoadRoutesConfig_UnknownDestinationType(t *testing.T) {
	setSecretEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	body := `
routes:
  - name: bad
    match: {}
    destinations:
      - email:
          to: ops@example.com
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRoutesConfig(path)
	if err == nil || !strings.Contains(err.Error(), "unknown destination") {
		t.Fatalf("expected unknown-destination error; got %v", err)
	}
}

func TestLoadRoutesConfig_InvalidOnMatch(t *testing.T) {
	setSecretEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	body := `
routes:
  - name: bad
    match: {}
    on_match: garbage
    destinations:
      - webhook:
          url: https://x.example
          token: ${SOC_SPLUNK_HEC_TOKEN}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRoutesConfig(path)
	if err == nil || !strings.Contains(err.Error(), "on_match") {
		t.Fatalf("expected on_match error; got %v", err)
	}
}

func TestLoadRoutesConfig_DuplicateRouteName(t *testing.T) {
	setSecretEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	body := `
routes:
  - name: dup
    match: {}
    destinations:
      - webhook:
          url: https://x.example
          token: ${SOC_SPLUNK_HEC_TOKEN}
  - name: dup
    match: {}
    destinations:
      - webhook:
          url: https://y.example
          token: ${SOC_SPLUNK_HEC_TOKEN}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRoutesConfig(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error; got %v", err)
	}
}

func TestLoadRoutesConfig_UnknownMatchOperator(t *testing.T) {
	setSecretEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	body := `
routes:
  - name: bad
    match:
      severity_id: { startswith: foo }
    destinations:
      - webhook:
          url: https://x.example
          token: ${SOC_SPLUNK_HEC_TOKEN}
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRoutesConfig(path)
	if err == nil || !strings.Contains(err.Error(), "unknown operator") {
		t.Fatalf("expected unknown-operator error; got %v", err)
	}
}

func TestEvaluateMatch_EqualsDefault(t *testing.T) {
	ev := sampleEventMap()
	if !EvaluateMatch(ev, map[string]any{"severity_id": 3}) {
		t.Error("equals 3 should match")
	}
	if EvaluateMatch(ev, map[string]any{"severity_id": 5}) {
		t.Error("equals 5 should NOT match")
	}
}

func TestEvaluateMatch_GteLteGtLt(t *testing.T) {
	ev := sampleEventMap()
	cases := []struct {
		match  map[string]any
		expect bool
	}{
		{map[string]any{"severity_id": map[string]any{"gte": 3}}, true},
		{map[string]any{"severity_id": map[string]any{"gte": 4}}, false},
		{map[string]any{"severity_id": map[string]any{"lte": 3}}, true},
		{map[string]any{"severity_id": map[string]any{"lte": 2}}, false},
		{map[string]any{"severity_id": map[string]any{"gt": 2}}, true},
		{map[string]any{"severity_id": map[string]any{"gt": 3}}, false},
		{map[string]any{"severity_id": map[string]any{"lt": 4}}, true},
		{map[string]any{"severity_id": map[string]any{"lt": 3}}, false},
	}
	for i, c := range cases {
		if got := EvaluateMatch(ev, c.match); got != c.expect {
			t.Errorf("case %d match=%v: got %v want %v",
				i, c.match, got, c.expect)
		}
	}
}

func TestEvaluateMatch_In(t *testing.T) {
	ev := sampleEventMap()
	yes := map[string]any{"severity_id": map[string]any{"in": []any{3, 4, 5}}}
	no := map[string]any{"severity_id": map[string]any{"in": []any{4, 5}}}
	if !EvaluateMatch(ev, yes) {
		t.Error("in [3,4,5] should match severity_id=3")
	}
	if EvaluateMatch(ev, no) {
		t.Error("in [4,5] should NOT match severity_id=3")
	}
}

func TestEvaluateMatch_Regex(t *testing.T) {
	ev := sampleEventMap()
	yes := map[string]any{
		"api.operation": map[string]any{"match": `iam:Create.*`},
	}
	no := map[string]any{
		"api.operation": map[string]any{"match": `s3:.*`},
	}
	if !EvaluateMatch(ev, yes) {
		t.Error("regex iam:Create.* should match iam:CreateRole")
	}
	if EvaluateMatch(ev, no) {
		t.Error("regex s3:.* should NOT match iam:CreateRole")
	}
}

func TestEvaluateMatch_GlobCaseInsensitive(t *testing.T) {
	ev := sampleEventMap()
	m := map[string]any{
		"api.operation": map[string]any{"glob": "iam:create*"},
	}
	if !EvaluateMatch(ev, m) {
		t.Error("glob iam:create* (icase) should match iam:CreateRole")
	}
}

func TestEvaluateMatch_ListWalkResources(t *testing.T) {
	ev := sampleEventMap()
	yes := map[string]any{
		"resources[].uid": map[string]any{"glob": "role/*"},
	}
	no := map[string]any{
		"resources[].uid": map[string]any{"glob": "bucket/*"},
	}
	if !EvaluateMatch(ev, yes) {
		t.Error("glob role/* should match resources[].uid=role/example")
	}
	if EvaluateMatch(ev, no) {
		t.Error("glob bucket/* should NOT match resources[].uid=role/example")
	}
}

func TestEvaluateMatch_MissingFieldIsNotMatch(t *testing.T) {
	ev := sampleEventMap()
	if EvaluateMatch(ev, map[string]any{"this.does.not.exist": "x"}) {
		t.Error("missing field should NOT match")
	}
}

func TestEvaluateMatch_AndWithinRoute(t *testing.T) {
	ev := sampleEventMap()
	yes := map[string]any{
		"severity_id":   map[string]any{"gte": 3},
		"api.operation": map[string]any{"match": "iam:Create.*"},
	}
	no := map[string]any{
		"severity_id":   map[string]any{"gte": 3},
		"api.operation": map[string]any{"match": "s3:.*"},
	}
	if !EvaluateMatch(ev, yes) {
		t.Error("AND both true should match")
	}
	if EvaluateMatch(ev, no) {
		t.Error("AND second false should NOT match")
	}
}

func TestEvaluateMatch_EmptyBlockMatchesEverything(t *testing.T) {
	ev := sampleEventMap()
	if !EvaluateMatch(ev, map[string]any{}) {
		t.Error("empty match block should match every event")
	}
}

func TestEvaluateMatch_NestedDottedPath(t *testing.T) {
	ev := sampleEventMap()
	if !EvaluateMatch(ev, map[string]any{"actor.user.attribute.team": "dev"}) {
		t.Error("nested dotted path should match")
	}
}

func TestEvaluateMatch_BoolNotInt(t *testing.T) {
	ev := sampleEventMap()
	ev["severity_id"] = true
	m := map[string]any{"severity_id": map[string]any{"gte": 0}}
	if EvaluateMatch(ev, m) {
		t.Error("bool value must NOT compare as int")
	}
}

func TestSelectRoutes_StopShortCircuits(t *testing.T) {
	setSecretEnv(t)
	path := writeMemoRoutesYAML(t)
	cfg, err := LoadRoutesConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	hits := SelectRoutes(sampleEventMap(), cfg.Routes)
	if len(hits) != 1 || hits[0].Name != "soc-high-severity" {
		t.Errorf("got %d routes (names=%v), want [soc-high-severity]",
			len(hits), routeNames(hits))
	}
}

func TestSelectRoutes_ContinueEvaluatesSubsequent(t *testing.T) {
	setSecretEnv(t)
	path := writeMemoRoutesYAML(t)
	cfg, err := LoadRoutesConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	reordered := []Route{cfg.Routes[3], cfg.Routes[0]}
	hits := SelectRoutes(sampleEventMap(), reordered)
	if len(hits) != 2 ||
		hits[0].Name != "central-archive" ||
		hits[1].Name != "soc-high-severity" {
		t.Errorf("got names=%v, want [central-archive soc-high-severity]",
			routeNames(hits))
	}
}

func TestSelectRoutes_NoMatch(t *testing.T) {
	setSecretEnv(t)
	path := writeMemoRoutesYAML(t)
	cfg, err := LoadRoutesConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ev := map[string]any{"severity_id": 1, "metadata": map[string]any{}}
	hits := SelectRoutes(ev, cfg.Routes)
	if len(hits) != 1 || hits[0].Name != "central-archive" {
		t.Errorf("got names=%v, want [central-archive]", routeNames(hits))
	}
}

func TestSelectRoutes_OrViaMultipleRoutes(t *testing.T) {
	setSecretEnv(t)
	path := writeMemoRoutesYAML(t)
	cfg, err := LoadRoutesConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	devContinue := cfg.Routes[1]
	devContinue.OnMatch = "continue"
	reordered := []Route{devContinue, cfg.Routes[0]}
	hits := SelectRoutes(sampleEventMap(), reordered)
	if len(hits) != 2 ||
		hits[0].Name != "dev-team-own-events" ||
		hits[1].Name != "soc-high-severity" {
		t.Errorf("got names=%v want [dev-team-own-events soc-high-severity]",
			routeNames(hits))
	}
}

func routeNames(rs []Route) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}

type recordedPost struct {
	URL     string
	Headers http.Header
	Body    []byte
}

func startCapturingServer(
	t *testing.T, statusFor func(string) int,
) (*httptest.Server, func() []recordedPost) {
	t.Helper()
	var mu = struct {
		atomic.Pointer[[]recordedPost]
	}{}
	empty := []recordedPost{}
	mu.Store(&empty)
	ts := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			cur := *mu.Load()
			next := append(cur, recordedPost{
				URL:     r.URL.String(),
				Headers: r.Header.Clone(),
				Body:    body,
			})
			mu.Store(&next)
			status := statusFor(r.URL.Path)
			w.WriteHeader(status)
		}))
	t.Cleanup(ts.Close)
	return ts, func() []recordedPost {
		return *mu.Load()
	}
}

func TestEngine_DispatchesWebhookForSOCRoute(t *testing.T) {
	setSecretEnv(t)
	ts, captured := startCapturingServer(t, func(p string) int { return 200 })
	cfg := &RoutesConfig{
		Routes: []Route{
			{
				Name:  "soc-high-severity",
				Match: map[string]any{"severity_id": map[string]any{"gte": 3}},
				Destinations: []Destination{
					{
						Kind:                 DestinationWebhook,
						WebhookURL:           ts.URL + "/splunk",
						WebhookToken:         "supersecret-soc",
						WebhookPreset:        PresetSplunkHEC,
						WebhookAllowInternal: true,
						WebhookSentinelTable: DefaultSentinelTable,
					},
				},
				OnMatch: "stop",
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine, err := NewRoutesEngine(ctx, RoutesEngineOptions{
		Cfg: cfg, HTTPClient: ts.Client(), Product: "dbounce",
	})
	if err != nil {
		t.Fatal(err)
	}
	engine.Push(ctx, eventFromMap(t, sampleEventMap()))
	waitForPosts(t, captured, 1)
	engine.Close()
	posts := captured()
	if len(posts) != 1 {
		t.Fatalf("got %d posts, want 1", len(posts))
	}
	if !strings.HasPrefix(posts[0].Headers.Get("Authorization"), "Splunk ") {
		t.Errorf("expected Splunk auth header, got %q",
			posts[0].Headers.Get("Authorization"))
	}
}

func TestEngine_DispatchesPagerDutyAndSlackForCritical(t *testing.T) {
	setSecretEnv(t)
	ts, captured := startCapturingServer(t, func(p string) int { return 200 })
	cfg := &RoutesConfig{
		Routes: []Route{
			{
				Name:  "on-call-critical",
				Match: map[string]any{"severity_id": 5},
				Destinations: []Destination{
					{
						Kind:                    DestinationPagerDuty,
						PagerDutyIntegrationKey: "pd-key-123",
						PagerDutySeverity:       "critical",
					},
					{
						Kind:            DestinationSlack,
						SlackWebhookURL: ts.URL + "/slack/hooks/T1/B2/secrettoken",
					},
				},
				OnMatch: "stop",
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientToTS := &http.Client{
		Transport: &rewriteTransport{
			base:       ts.Client().Transport,
			redirectTo: ts.URL,
		},
	}
	engine, err := NewRoutesEngine(ctx, RoutesEngineOptions{
		Cfg: cfg, HTTPClient: clientToTS, Product: "dbounce",
	})
	if err != nil {
		t.Fatal(err)
	}
	critEv := map[string]any{
		"severity_id": 5,
		"api":         map[string]any{"operation": "iam:DeleteRole"},
		"metadata": map[string]any{
			"product": map[string]any{"name": "dbounce", "vendor_name": "iam-jit"},
		},
		"unmapped": map[string]any{
			"iam_jit": map[string]any{"verdict": "DENY", "event_type": "DECISION"},
		},
	}
	engine.Push(ctx, eventFromMap(t, critEv))
	waitForPosts(t, captured, 2)
	engine.Close()
	posts := captured()
	if len(posts) != 2 {
		t.Fatalf("got %d posts, want 2: %+v", len(posts), posts)
	}
	var pdSeen, slackSeen bool
	for _, p := range posts {
		if strings.Contains(p.URL, "v2/enqueue") {
			pdSeen = true
			var body map[string]any
			if err := json.Unmarshal(p.Body, &body); err != nil {
				t.Errorf("pagerduty body not JSON: %v", err)
			}
			if body["event_action"] != "trigger" {
				t.Errorf("event_action: got %v want trigger", body["event_action"])
			}
		}
		if strings.Contains(p.URL, "/slack/hooks/") {
			slackSeen = true
			var body map[string]any
			if err := json.Unmarshal(p.Body, &body); err != nil {
				t.Errorf("slack body not JSON: %v", err)
			}
			text, _ := body["text"].(string)
			for _, forbidden := range []string{
				"violation", "infraction", "unauthorized",
			} {
				if strings.Contains(strings.ToLower(text), forbidden) {
					t.Errorf("slack text contains forbidden word %q: %q",
						forbidden, text)
				}
			}
		}
	}
	if !pdSeen {
		t.Error("expected a pagerduty POST")
	}
	if !slackSeen {
		t.Error("expected a slack POST")
	}
}

type rewriteTransport struct {
	base       http.RoundTripper
	redirectTo string
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	dst, err := req.URL.Parse(rt.redirectTo)
	if err != nil {
		return nil, err
	}
	req2 := req.Clone(req.Context())
	req2.URL.Scheme = dst.Scheme
	req2.URL.Host = dst.Host
	return rt.base.RoundTrip(req2)
}

func TestEngine_FailureIsolation(t *testing.T) {
	setSecretEnv(t)
	ts, captured := startCapturingServer(t, func(p string) int {
		if strings.Contains(p, "v2/enqueue") {
			return 500
		}
		return 200
	})
	cfg := &RoutesConfig{
		Routes: []Route{
			{
				Name:  "on-call-critical",
				Match: map[string]any{"severity_id": 5},
				Destinations: []Destination{
					{
						Kind:                    DestinationPagerDuty,
						PagerDutyIntegrationKey: "pd-key-123",
						PagerDutySeverity:       "critical",
					},
					{
						Kind:            DestinationSlack,
						SlackWebhookURL: ts.URL + "/slack/hooks/T1/B2/secrettoken",
					},
				},
				OnMatch: "stop",
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientToTS := &http.Client{
		Transport: &rewriteTransport{
			base:       ts.Client().Transport,
			redirectTo: ts.URL,
		},
	}
	engine, err := NewRoutesEngine(ctx, RoutesEngineOptions{
		Cfg: cfg, HTTPClient: clientToTS, Product: "dbounce",
	})
	if err != nil {
		t.Fatal(err)
	}
	critEv := map[string]any{
		"severity_id": 5,
		"api":         map[string]any{"operation": "iam:DeleteRole"},
		"unmapped":    map[string]any{"iam_jit": map[string]any{"verdict": "DENY"}},
	}
	engine.Push(ctx, eventFromMap(t, critEv))
	waitForPosts(t, captured, 2)
	engine.Close()
	posts := captured()
	if len(posts) != 2 {
		t.Fatalf("expected 2 posts (failure isolation); got %d", len(posts))
	}
	status := engine.Status()
	var pdStats map[string]any
	for _, r := range status.Routes {
		if r.Name == "on-call-critical" {
			pdStats = r.DestinationStats[0]
		}
	}
	failed, _ := pdStats["total_failed"].(int64)
	if failed < 1 {
		t.Errorf("expected total_failed >= 1 on pagerduty destination; got %v",
			pdStats["total_failed"])
	}
}

func TestEngine_SecretsNeverAppearInStatus(t *testing.T) {
	setSecretEnv(t)
	cfg := &RoutesConfig{
		Routes: []Route{
			{
				Name:  "soc",
				Match: map[string]any{},
				Destinations: []Destination{
					{
						Kind:                 DestinationWebhook,
						WebhookURL:           "https://splunk-soc.example.com/x",
						WebhookToken:         testSOCToken,
						WebhookPreset:        PresetSplunkHEC,
						WebhookAllowInternal: true,
						secretOrigins: map[string]string{
							"webhook_token": "SOC_SPLUNK_HEC_TOKEN",
						},
					},
				},
			},
			{
				Name:  "pd",
				Match: map[string]any{},
				Destinations: []Destination{
					{
						Kind:                    DestinationPagerDuty,
						PagerDutyIntegrationKey: testPDKey,
						PagerDutySeverity:       "warning",
						secretOrigins: map[string]string{
							"pagerduty_integration_key": "PD_INTEGRATION_KEY",
						},
					},
				},
			},
			{
				Name:  "slack",
				Match: map[string]any{},
				Destinations: []Destination{
					{
						Kind:            DestinationSlack,
						SlackWebhookURL: testSlackURL,
						secretOrigins: map[string]string{
							"slack_webhook_url": "SLACK_ONCALL_WEBHOOK",
						},
					},
				},
			},
		},
	}
	ctx := context.Background()
	engine, err := NewRoutesEngine(ctx, RoutesEngineOptions{
		Cfg: cfg, Product: "dbounce",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	status := engine.Status()
	rendered, _ := json.Marshal(status)
	for _, secret := range []string{
		testSOCToken, testPDKey, testSlackURL,
	} {
		if strings.Contains(string(rendered), secret) {
			t.Errorf("plaintext secret leaked into status: %q", secret)
		}
	}
	for _, kv := range cfg.SecretsUsed() {
		if strings.Contains(kv[1], testSOCToken) ||
			strings.Contains(kv[1], testPDKey) ||
			kv[1] == testSlackURL {
			t.Errorf("secretsUsed leak in %s: %s", kv[0], kv[1])
		}
		if !strings.HasSuffix(kv[1], "***") {
			t.Errorf("secretsUsed mask should end in ***: %s -> %s",
				kv[0], kv[1])
		}
	}
}

func TestEngine_RejectsBadSchemeForWebhook(t *testing.T) {
	cfg := &RoutesConfig{
		Routes: []Route{
			{
				Name: "bad", Match: map[string]any{},
				Destinations: []Destination{{
					Kind: DestinationWebhook, WebhookURL: "ftp://x.example",
					WebhookToken: "x", WebhookPreset: PresetGeneric,
					WebhookAllowInternal: true,
				}},
			},
		},
	}
	_, err := NewRoutesEngine(context.Background(), RoutesEngineOptions{Cfg: cfg})
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("expected scheme error; got %v", err)
	}
}

func TestErrRoutesLicenseRequired(t *testing.T) {
	if ErrRoutesLicenseRequired == nil {
		t.Fatal("ErrRoutesLicenseRequired must be a non-nil sentinel error")
	}
	msg := ErrRoutesLicenseRequired.Error()
	if !strings.Contains(msg, "Enterprise") {
		t.Errorf("error message should mention Enterprise; got %q", msg)
	}
	if !strings.Contains(msg, "--alert-routes") {
		t.Errorf("error message should reference --alert-routes flag; got %q",
			msg)
	}
	if !strings.Contains(msg, "#235") {
		t.Errorf("error message should point at #235 tracking issue; got %q",
			msg)
	}
}

func eventFromMap(t *testing.T, m map[string]any) Event {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var ev Event
	if err := json.Unmarshal(b, &ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

func waitForPosts(t *testing.T, captured func() []recordedPost, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(captured()) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

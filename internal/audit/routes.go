// Package audit — per-org notification routing engine (#280).
//
// Per [[per-org-notification-routing]]: the single --audit-webhook-url
// shape works for one team / one collector. At org scale customers
// want multi-destination routing with severity / team / product
// filters. This file ships the deterministic routes engine that does
// that.
//
// One YAML file describes routes; each route has a match block, a
// list of destinations, and an on_match mode (stop default; continue
// for fan-out). Secrets live in env vars via ${ENV} interpolation;
// the YAML never carries plaintext tokens.
//
// Per [[enterprise-self-host-only]]: this is Enterprise-tier; the
// license gate mirrors the existing licensedForAuditWebhook
// placeholder pattern (returns ErrRoutesLicenseRequired until #235
// license-file plumbing lands).
//
// Per [[security-team-positioning-safety-not-surveillance]]: route +
// destination strings use NEUTRAL language. Match conditions are
// SHIPPING filters, not GATING rules.
//
// Per [[creates-never-mutates]]: routes are ADDITIVE; the engine
// never modifies the event it dispatches.
//
// Per [[no-hosted-saas]] + [[self-host-zero-billing-dependency]]:
// every destination is operator-configured; iam-jit-the-company never
// receives the routed traffic.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/dbounce/internal/upstream"
)

// ErrRoutesLicenseRequired is returned when --alert-routes is passed
// without an Enterprise license. Placeholder until #235 license-file
// plumbing lands.
var ErrRoutesLicenseRequired = errors.New(
	"--alert-routes requires an Enterprise license (placeholder: " +
		"dbounce's license-file plumbing has not yet landed — tracked " +
		"as #235). The single-destination --audit-webhook-url channel " +
		"is available on every tier and the JSONL log writer ships " +
		"everywhere.")

// Destination kinds shipped in v1.0 per [[per-org-notification-routing]].
const (
	DestinationWebhook   = "webhook"
	DestinationPagerDuty = "pagerduty"
	DestinationSlack     = "slack"
)

// PagerDutyEventsAPIV2URL is the documented enqueue endpoint. Raw
// HTTP POST (no SDK dep).
const PagerDutyEventsAPIV2URL = "https://events.pagerduty.com/v2/enqueue"

var envVarRE = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// RoutesConfig is the parsed --alert-routes YAML file.
type RoutesConfig struct {
	Routes []Route
}

// Route is one routing decision. Match conditions AND within the
// block; OR across routes. OnMatch is "stop" (default; first-match-
// wins) or "continue" (fan-out tail).
type Route struct {
	Name         string
	Match        map[string]any
	Destinations []Destination
	OnMatch      string
}

// Destination is one (kind, body) pair plus the resolved secrets.
type Destination struct {
	Kind string

	// Webhook fields.
	WebhookURL           string
	WebhookToken         string
	WebhookPreset        Preset
	WebhookAllowInternal bool
	WebhookTags          string
	WebhookSentinelTable string

	// PagerDuty fields.
	PagerDutyIntegrationKey string
	PagerDutySeverity       string

	// Slack fields.
	SlackWebhookURL string

	// secretOrigins records the env-var that supplied each secret
	// field so the startup banner can mask the resolved value while
	// still telling the operator which env var was read. Internal.
	secretOrigins map[string]string
}

// Masked returns a JSON-friendly view of the destination with every
// secret-bearing field replaced by an 8-char-prefix mask. NEVER
// includes raw token / key / Slack-url values.
func (d Destination) Masked() map[string]any {
	switch d.Kind {
	case DestinationWebhook:
		return map[string]any{
			"type":           "webhook",
			"url":            maskWebhookURLForRoutes(d.WebhookURL),
			"token":          maskTokenShort(d.WebhookToken),
			"preset":         string(d.WebhookPreset),
			"allow_internal": d.WebhookAllowInternal,
		}
	case DestinationPagerDuty:
		return map[string]any{
			"type":            "pagerduty",
			"integration_key": maskTokenShort(d.PagerDutyIntegrationKey),
			"severity":        d.PagerDutySeverity,
		}
	case DestinationSlack:
		host := ""
		if u, err := url.Parse(d.SlackWebhookURL); err == nil {
			host = u.Hostname()
		}
		return map[string]any{
			"type":        "slack",
			"webhook_url": fmt.Sprintf("https://%s/***", host),
		}
	}
	return map[string]any{"type": d.Kind}
}

// maskWebhookURLForRoutes strips userinfo + query from a URL. The
// existing WebhookPusher has RedactedURL() for the configured single-
// webhook; we keep this routes-local to avoid coupling the engine to
// the pusher's internal state.
func maskWebhookURLForRoutes(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}

func maskTokenShort(s string) string {
	if s == "" {
		return "***"
	}
	if len(s) <= 8 {
		return s + "***"
	}
	return s[:8] + "***"
}

// SecretsUsed returns sorted (env_var_name, masked_value_prefix)
// pairs for the startup banner. Dedupes by env-var name.
func (c RoutesConfig) SecretsUsed() [][2]string {
	seen := make(map[string]string)
	for _, r := range c.Routes {
		for _, d := range r.Destinations {
			for field, env := range d.secretOrigins {
				if env == "" {
					continue
				}
				if _, ok := seen[env]; ok {
					continue
				}
				switch field {
				case "webhook_token":
					seen[env] = maskTokenShort(d.WebhookToken)
				case "pagerduty_integration_key":
					seen[env] = maskTokenShort(d.PagerDutyIntegrationKey)
				case "slack_webhook_url":
					seen[env] = maskTokenShort(d.SlackWebhookURL)
				default:
					seen[env] = "***"
				}
			}
		}
	}
	out := make([][2]string, 0, len(seen))
	for k, v := range seen {
		out = append(out, [2]string{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// LoadRoutesConfig reads + validates an --alert-routes YAML file.
func LoadRoutesConfig(path string) (*RoutesConfig, error) {
	clean := filepath.Clean(path)
	// #G304 read-only path; operator passes the path explicitly.
	raw, err := os.ReadFile(clean) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf(
			"audit: could not read --alert-routes file %q: %w", clean, err)
	}
	var top struct {
		Routes []rawRoute `yaml:"routes"`
	}
	if err := yaml.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf(
			"audit: --alert-routes YAML at %q: %w", clean, err)
	}
	if top.Routes == nil {
		return nil, fmt.Errorf(
			"audit: --alert-routes YAML at %q: top-level 'routes' key " +
				"is required (a list of route definitions)", clean)
	}
	if len(top.Routes) == 0 {
		return nil, fmt.Errorf(
			"audit: --alert-routes YAML at %q: 'routes' must be non-empty",
			clean)
	}
	cfg := &RoutesConfig{Routes: make([]Route, 0, len(top.Routes))}
	seen := make(map[string]struct{})
	for i, rr := range top.Routes {
		route, err := rr.normalize(i)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[route.Name]; dup {
			return nil, fmt.Errorf(
				"audit: --alert-routes YAML at %q: duplicate route name %q",
				clean, route.Name)
		}
		seen[route.Name] = struct{}{}
		cfg.Routes = append(cfg.Routes, route)
	}
	return cfg, nil
}

type rawRoute struct {
	Name         string           `yaml:"name"`
	Match        map[string]any   `yaml:"match"`
	Destinations []map[string]any `yaml:"destinations"`
	OnMatch      string           `yaml:"on_match"`
}

func (rr rawRoute) normalize(idx int) (Route, error) {
	if rr.Name == "" {
		return Route{}, fmt.Errorf(
			"audit: routes[%d].name must be a non-empty string", idx)
	}
	if rr.Match == nil {
		rr.Match = map[string]any{}
	}
	if err := validateMatchBlock(rr.Name, rr.Match); err != nil {
		return Route{}, err
	}
	if len(rr.Destinations) == 0 {
		return Route{}, fmt.Errorf(
			"audit: route %q: 'destinations' must be a non-empty list",
			rr.Name)
	}
	onMatch := strings.ToLower(rr.OnMatch)
	if onMatch == "" {
		onMatch = "stop"
	}
	if onMatch != "stop" && onMatch != "continue" {
		return Route{}, fmt.Errorf(
			"audit: route %q: on_match must be 'stop' (default) or " +
				"'continue'; got %q", rr.Name, rr.OnMatch)
	}
	dests := make([]Destination, 0, len(rr.Destinations))
	for di, raw := range rr.Destinations {
		dest, err := loadDestination(rr.Name, di, raw)
		if err != nil {
			return Route{}, err
		}
		dests = append(dests, dest)
	}
	return Route{
		Name: rr.Name, Match: rr.Match,
		Destinations: dests, OnMatch: onMatch,
	}, nil
}

var validMatchOperators = map[string]struct{}{
	"equals": {}, "gte": {}, "lte": {}, "gt": {}, "lt": {},
	"in": {}, "match": {}, "glob": {},
}

func validateMatchBlock(routeName string, match map[string]any) error {
	for k, v := range match {
		if k == "" {
			return fmt.Errorf(
				"audit: route %q: match keys must be non-empty strings",
				routeName)
		}
		cond, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for op := range cond {
			if _, ok := validMatchOperators[op]; !ok {
				return fmt.Errorf(
					"audit: route %q: unknown operator %q on field %q. " +
						"Supported: equals / gte / lte / gt / lt / in / match / glob",
					routeName, op, k)
			}
		}
	}
	return nil
}

func loadDestination(routeName string, idx int, raw map[string]any) (Destination, error) {
	if len(raw) != 1 {
		return Destination{}, fmt.Errorf(
			"audit: route %q: destination[%d] must be a single-key " +
				"mapping like '{webhook: {...}}'", routeName, idx)
	}
	var kind string
	var body any
	for k, v := range raw {
		kind, body = k, v
	}
	bodyMap, ok := body.(map[string]any)
	if !ok {
		return Destination{}, fmt.Errorf(
			"audit: route %q: destination[%d] body must be a mapping",
			routeName, idx)
	}
	switch kind {
	case DestinationWebhook:
		return loadWebhookDestination(routeName, idx, bodyMap)
	case DestinationPagerDuty:
		return loadPagerDutyDestination(routeName, idx, bodyMap)
	case DestinationSlack:
		return loadSlackDestination(routeName, idx, bodyMap)
	}
	return Destination{}, fmt.Errorf(
		"audit: route %q: unknown destination type %q; supported: %s",
		routeName, kind,
		strings.Join([]string{
			DestinationWebhook, DestinationPagerDuty, DestinationSlack,
		}, ", "))
}

func loadWebhookDestination(routeName string, idx int, body map[string]any) (Destination, error) {
	urlVal, _ := body["url"].(string)
	if urlVal == "" {
		return Destination{}, fmt.Errorf(
			"audit: route %q: webhook destination requires a 'url'",
			routeName)
	}
	resolvedURL, _, err := resolveOptionalString(
		urlVal,
		fmt.Sprintf("route %q.destinations[%d].webhook.url", routeName, idx))
	if err != nil {
		return Destination{}, err
	}
	tokenRaw, ok := body["token"]
	if !ok {
		return Destination{}, fmt.Errorf(
			"audit: route %q: webhook destination requires a 'token' " +
				"(env-var interpolation: token: ${ENV_NAME})", routeName)
	}
	tokenStr, tokenOk := tokenRaw.(string)
	if !tokenOk {
		return Destination{}, fmt.Errorf(
			"audit: route %q: webhook destination 'token' must be a " +
				"string of the form '${ENV_NAME}'", routeName)
	}
	token, envName, err := resolveSecret(
		tokenStr,
		fmt.Sprintf("route %q.destinations[%d].webhook.token", routeName, idx))
	if err != nil {
		return Destination{}, err
	}
	presetStr, _ := body["preset"].(string)
	if presetStr == "" {
		presetStr = string(PresetGeneric)
	}
	preset, err := ParsePreset(presetStr)
	if err != nil {
		return Destination{}, fmt.Errorf(
			"audit: route %q: %w", routeName, err)
	}
	allowInternal, _ := body["allow_internal"].(bool)
	tags, _ := body["tags"].(string)
	sentinelTable, _ := body["sentinel_table"].(string)
	if sentinelTable == "" {
		sentinelTable = DefaultSentinelTable
	}
	return Destination{
		Kind:                 DestinationWebhook,
		WebhookURL:           resolvedURL,
		WebhookToken:         token,
		WebhookPreset:        preset,
		WebhookAllowInternal: allowInternal,
		WebhookTags:          tags,
		WebhookSentinelTable: sentinelTable,
		secretOrigins:        map[string]string{"webhook_token": envName},
	}, nil
}

func loadPagerDutyDestination(routeName string, idx int, body map[string]any) (Destination, error) {
	keyRaw, ok := body["integration_key"]
	if !ok {
		return Destination{}, fmt.Errorf(
			"audit: route %q: pagerduty destination requires an " +
				"'integration_key' (env-var interpolation: " +
				"integration_key: ${ENV_NAME})", routeName)
	}
	keyStr, okStr := keyRaw.(string)
	if !okStr {
		return Destination{}, fmt.Errorf(
			"audit: route %q: pagerduty destination 'integration_key' " +
				"must be a string of the form '${ENV_NAME}'", routeName)
	}
	key, envName, err := resolveSecret(
		keyStr,
		fmt.Sprintf(
			"route %q.destinations[%d].pagerduty.integration_key",
			routeName, idx))
	if err != nil {
		return Destination{}, err
	}
	severity, _ := body["severity"].(string)
	if severity == "" {
		severity = "warning"
	}
	severity = strings.ToLower(severity)
	switch severity {
	case "info", "warning", "error", "critical":
	default:
		return Destination{}, fmt.Errorf(
			"audit: route %q: pagerduty severity must be one of " +
				"info / warning / error / critical; got %q",
			routeName, severity)
	}
	return Destination{
		Kind:                    DestinationPagerDuty,
		PagerDutyIntegrationKey: key,
		PagerDutySeverity:       severity,
		secretOrigins: map[string]string{
			"pagerduty_integration_key": envName,
		},
	}, nil
}

func loadSlackDestination(routeName string, idx int, body map[string]any) (Destination, error) {
	urlRaw, ok := body["webhook_url"]
	if !ok {
		return Destination{}, fmt.Errorf(
			"audit: route %q: slack destination requires a 'webhook_url' " +
				"(env-var interpolation: webhook_url: ${ENV_NAME})",
			routeName)
	}
	urlStr, okStr := urlRaw.(string)
	if !okStr {
		return Destination{}, fmt.Errorf(
			"audit: route %q: slack destination 'webhook_url' must be a " +
				"string of the form '${ENV_NAME}'", routeName)
	}
	u, envName, err := resolveSecret(
		urlStr,
		fmt.Sprintf(
			"route %q.destinations[%d].slack.webhook_url", routeName, idx))
	if err != nil {
		return Destination{}, err
	}
	return Destination{
		Kind:            DestinationSlack,
		SlackWebhookURL: u,
		secretOrigins:   map[string]string{"slack_webhook_url": envName},
	}, nil
}

func resolveSecret(value, fieldPath string) (string, string, error) {
	m := envVarRE.FindStringSubmatch(value)
	if m == nil {
		return "", "", fmt.Errorf(
			"audit: %s: secrets must be passed as '${ENV_NAME}' " +
				"(env-var interpolation only). Bare literal tokens are " +
				"refused — keep secrets out of the YAML file", fieldPath)
	}
	env := m[1]
	resolved := os.Getenv(env)
	if resolved == "" {
		return "", "", fmt.Errorf(
			"audit: %s: env-var %q is not set in the environment " +
				"(referenced as '${%s}'). Export it before starting the " +
				"proxy", fieldPath, env, env)
	}
	return resolved, env, nil
}

func resolveOptionalString(value, fieldPath string) (string, string, error) {
	m := envVarRE.FindStringSubmatch(value)
	if m == nil {
		return value, "", nil
	}
	env := m[1]
	resolved, ok := os.LookupEnv(env)
	if !ok {
		return "", "", fmt.Errorf(
			"audit: %s: env-var %q is not set (referenced as " +
				"'${%s}'). Export it before starting the proxy",
			fieldPath, env, env)
	}
	return resolved, env, nil
}

// ============================================================================
// Match-condition evaluator
// ============================================================================

// EvaluateMatch returns true when every (path, condition) pair in
// match holds for ev. Empty match block matches everything (the
// fallback-route shape). Pure function.
func EvaluateMatch(ev map[string]any, match map[string]any) bool {
	if len(match) == 0 {
		return true
	}
	for path, cond := range match {
		if !fieldMatches(ev, path, cond) {
			return false
		}
	}
	return true
}

func fieldMatches(ev map[string]any, path string, cond any) bool {
	values := walkPath(ev, path)
	if len(values) == 0 {
		return false
	}
	for _, v := range values {
		if matchOne(v, cond) {
			return true
		}
	}
	return false
}

func walkPath(ev map[string]any, path string) []any {
	parts := strings.Split(path, ".")
	stack := []any{ev}
	for _, p := range parts {
		next := make([]any, 0, len(stack))
		listWalk := strings.HasSuffix(p, "[]")
		if listWalk {
			p = strings.TrimSuffix(p, "[]")
		}
		for _, cur := range stack {
			m, ok := cur.(map[string]any)
			if !ok {
				continue
			}
			val, ok := m[p]
			if !ok {
				continue
			}
			if listWalk {
				if arr, ok := val.([]any); ok {
					next = append(next, arr...)
					continue
				}
				continue
			}
			next = append(next, val)
		}
		stack = next
		if len(stack) == 0 {
			return nil
		}
	}
	return stack
}

func matchOne(value, cond any) bool {
	condMap, ok := cond.(map[string]any)
	if !ok {
		return equalsAny(value, cond)
	}
	if len(condMap) == 0 {
		return true
	}
	for op, target := range condMap {
		if !applyOperator(value, op, target) {
			return false
		}
	}
	return true
}

func applyOperator(value any, op string, target any) bool {
	switch op {
	case "equals":
		return equalsAny(value, target)
	case "gte", "lte", "gt", "lt":
		vi, vok := coerceInt(value)
		ti, tok := coerceInt(target)
		if !vok || !tok {
			return false
		}
		switch op {
		case "gte":
			return vi >= ti
		case "lte":
			return vi <= ti
		case "gt":
			return vi > ti
		case "lt":
			return vi < ti
		}
	case "in":
		arr, ok := target.([]any)
		if !ok {
			return false
		}
		for _, t := range arr {
			if equalsAny(value, t) {
				return true
			}
		}
		return false
	case "match":
		s, sok := value.(string)
		ts, tsok := target.(string)
		if !sok || !tsok {
			return false
		}
		re, err := regexp.Compile("^" + ts + "$")
		if err != nil {
			return false
		}
		return re.MatchString(s)
	case "glob":
		s, sok := value.(string)
		ts, tsok := target.(string)
		if !sok || !tsok {
			return false
		}
		return globMatch(strings.ToLower(ts), strings.ToLower(s))
	}
	return false
}

func equalsAny(a, b any) bool {
	if ai, aok := coerceInt(a); aok {
		if bi, bok := coerceInt(b); bok {
			return ai == bi
		}
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func coerceInt(v any) (int64, bool) {
	switch x := v.(type) {
	case bool:
		return 0, false
	case int:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case float32:
		return int64(x), true
	case float64:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func globMatch(pattern, value string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	if parts[0] != "" {
		if !strings.HasPrefix(value, parts[0]) {
			return false
		}
		pos = len(parts[0])
	}
	for _, seg := range parts[1 : len(parts)-1] {
		if seg == "" {
			continue
		}
		idx := strings.Index(value[pos:], seg)
		if idx < 0 {
			return false
		}
		pos += idx + len(seg)
	}
	if last := parts[len(parts)-1]; last != "" {
		if !strings.HasSuffix(value, last) {
			return false
		}
		if len(value)-len(last) < pos {
			return false
		}
	}
	return true
}

// SelectRoutes returns the ordered list of matched routes honoring
// on_match. Pure function; exposed for the dry-run + tests.
func SelectRoutes(ev map[string]any, routes []Route) []Route {
	out := make([]Route, 0, len(routes))
	for _, r := range routes {
		if EvaluateMatch(ev, r.Match) {
			out = append(out, r)
			if r.OnMatch == "stop" {
				break
			}
		}
	}
	return out
}

// ============================================================================
// Runtime engine
// ============================================================================

// RoutesEngine is the runtime that the audit Exporter hands events to
// when --alert-routes is configured. Failure-isolated per destination:
// one dest's 500 does NOT stop the next.
type RoutesEngine struct {
	cfg     *RoutesConfig
	client  *http.Client
	product string

	queue chan map[string]any
	done  chan struct{}
	wg    sync.WaitGroup

	closeOnce sync.Once

	totalDropped atomic.Int64

	stats   map[string]*destStats
	statsMu sync.RWMutex
}

type destStats struct {
	TotalSent       atomic.Int64
	TotalFailed     atomic.Int64
	LastErr         atomic.Value // string
	LastStatus      atomic.Int64
	LastAttemptUnix atomic.Int64
	LastSuccessUnix atomic.Int64
}

// RoutesEngineOptions configures a RoutesEngine.
type RoutesEngineOptions struct {
	Cfg        *RoutesConfig
	HTTPClient *http.Client
	QueueDepth int
	Product    string
	// LookupHost lets tests inject a stub for the SSRF gate.
	LookupHost func(string) ([]string, error)
}

// DefaultRoutesQueueDepth is the same default as the single-webhook
// pusher (chanCapacityDefault); kept routes-local to avoid sharing
// the constant across the file.
const DefaultRoutesQueueDepth = 1000

// NewRoutesEngine constructs + starts a routes engine. Runs the SSRF
// gate on every webhook destination upfront so a misconfigured URL
// surfaces at startup.
func NewRoutesEngine(ctx context.Context, opts RoutesEngineOptions) (*RoutesEngine, error) {
	if opts.Cfg == nil {
		return nil, errors.New("audit: routes engine requires a non-nil config")
	}
	depth := opts.QueueDepth
	if depth <= 0 {
		depth = DefaultRoutesQueueDepth
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	prod := opts.Product
	if prod == "" {
		prod = "dbounce"
	}
	for _, r := range opts.Cfg.Routes {
		for _, d := range r.Destinations {
			if d.Kind != DestinationWebhook {
				continue
			}
			parsed, err := url.Parse(d.WebhookURL)
			if err != nil {
				return nil, fmt.Errorf(
					"audit: route %q: webhook URL parse: %w", r.Name, err)
			}
			scheme := parsed.Scheme
			if scheme != "https" && scheme != "http" {
				return nil, fmt.Errorf(
					"audit: route %q: webhook URL must use http:// or " +
						"https:// scheme", r.Name)
			}
			if d.WebhookAllowInternal {
				continue
			}
			// Reuse the same SSRF gate the single-webhook pusher uses;
			// GuardKindWebhook points the operator at the right flag.
			if err := upstream.GuardInternalHost(
				parsed.Hostname(), opts.LookupHost, upstream.GuardKindWebhook,
			); err != nil {
				return nil, fmt.Errorf(
					"audit: route %q: webhook URL refused: %w", r.Name, err)
			}
		}
	}
	eng := &RoutesEngine{
		cfg:     opts.Cfg,
		client:  client,
		product: prod,
		queue:   make(chan map[string]any, depth),
		done:    make(chan struct{}),
		stats:   make(map[string]*destStats),
	}
	for _, r := range opts.Cfg.Routes {
		for di := range r.Destinations {
			key := destStatsKey(r.Name, di)
			s := &destStats{}
			s.LastErr.Store("")
			eng.stats[key] = s
		}
	}
	eng.wg.Add(1)
	go eng.run(ctx)
	return eng, nil
}

func destStatsKey(routeName string, idx int) string {
	return fmt.Sprintf("%s#%d", routeName, idx)
}

// Push enqueues one event. Non-blocking; drops on overflow.
func (e *RoutesEngine) Push(_ context.Context, ev Event) {
	if e == nil {
		return
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return
	}
	select {
	case e.queue <- m:
	default:
		e.totalDropped.Add(1)
	}
}

// Close drains the engine. Idempotent.
func (e *RoutesEngine) Close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		close(e.done)
	})
	e.wg.Wait()
}

func (e *RoutesEngine) run(ctx context.Context) {
	defer e.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.done:
			return
		case ev := <-e.queue:
			e.dispatch(ctx, ev)
		}
	}
}

func (e *RoutesEngine) dispatch(ctx context.Context, ev map[string]any) {
	hits := SelectRoutes(ev, e.cfg.Routes)
	for _, route := range hits {
		for di, dest := range route.Destinations {
			func(routeName string, dIdx int, d Destination) {
				defer func() {
					if r := recover(); r != nil {
						log.Warn().
							Str("route", routeName).
							Int("dest_idx", dIdx).
							Interface("recover", r).
							Msg("routes engine dispatch panic")
					}
				}()
				err := e.dispatchOne(ctx, route, dIdx, d, ev)
				if err != nil {
					stats := e.statsFor(routeName, dIdx)
					stats.TotalFailed.Add(1)
					stats.LastErr.Store(maskSecretsInError(err.Error()))
					log.Warn().
						Str("route", routeName).
						Int("dest_idx", dIdx).
						Str("kind", d.Kind).
						Str("error", maskSecretsInError(err.Error())).
						Msg("routes engine dispatch failed")
				}
			}(route.Name, di, dest)
		}
	}
}

func (e *RoutesEngine) statsFor(routeName string, idx int) *destStats {
	e.statsMu.RLock()
	s, ok := e.stats[destStatsKey(routeName, idx)]
	e.statsMu.RUnlock()
	if ok {
		return s
	}
	e.statsMu.Lock()
	defer e.statsMu.Unlock()
	s = &destStats{}
	s.LastErr.Store("")
	e.stats[destStatsKey(routeName, idx)] = s
	return s
}

func (e *RoutesEngine) dispatchOne(
	ctx context.Context, route Route, idx int, d Destination, ev map[string]any,
) error {
	stats := e.statsFor(route.Name, idx)
	stats.LastAttemptUnix.Store(time.Now().Unix())
	switch d.Kind {
	case DestinationWebhook:
		return e.postWebhook(ctx, d, ev, stats)
	case DestinationPagerDuty:
		return e.postPagerDuty(ctx, d, ev, stats)
	case DestinationSlack:
		return e.postSlack(ctx, d, ev, stats)
	}
	return fmt.Errorf("unknown destination kind %q", d.Kind)
}

func (e *RoutesEngine) postWebhook(
	ctx context.Context, d Destination, ev map[string]any, stats *destStats,
) error {
	typedEv, err := mapToEvent(ev)
	if err != nil {
		return fmt.Errorf("preset build round-trip: %w", err)
	}
	cfg := PresetConfig{
		Preset:        d.WebhookPreset,
		URL:           d.WebhookURL,
		Token:         d.WebhookToken,
		ExtraTags:     d.WebhookTags,
		SentinelTable: d.WebhookSentinelTable,
		Product:       e.product,
	}
	if err := cfg.Normalize(); err != nil {
		return err
	}
	rp, err := BuildRequest(cfg, []Event{typedEv})
	if err != nil {
		return err
	}
	return e.doPost(ctx, rp.URL, rp.Headers, rp.Body, stats)
}

func (e *RoutesEngine) postPagerDuty(
	ctx context.Context, d Destination, ev map[string]any, stats *destStats,
) error {
	payload := pagerDutyPayload(ev, d, e.product)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	headers := map[string]string{
		"Content-Type": "application/json",
		"User-Agent":   fmt.Sprintf("%s-audit-export/1.0", e.product),
	}
	return e.doPost(ctx, PagerDutyEventsAPIV2URL, headers, body, stats)
}

func (e *RoutesEngine) postSlack(
	ctx context.Context, d Destination, ev map[string]any, stats *destStats,
) error {
	payload := slackPayload(ev, e.product)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	headers := map[string]string{
		"Content-Type": "application/json",
		"User-Agent":   fmt.Sprintf("%s-audit-export/1.0", e.product),
	}
	return e.doPost(ctx, d.SlackWebhookURL, headers, body, stats)
}

func (e *RoutesEngine) doPost(
	ctx context.Context, targetURL string, headers map[string]string,
	body []byte, stats *destStats,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	stats.LastStatus.Store(int64(resp.StatusCode))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		stats.TotalSent.Add(1)
		stats.LastSuccessUnix.Store(time.Now().Unix())
		return nil
	}
	return fmt.Errorf(
		"upstream HTTP %d from %s", resp.StatusCode,
		maskWebhookURLForRoutes(targetURL))
}

func pagerDutyPayload(ev map[string]any, d Destination, product string) map[string]any {
	op := nestedString(ev, "api.operation")
	evtType := nestedString(ev, "unmapped.iam_jit.event_type")
	summary := fmt.Sprintf("iam-jit %s", product)
	if evtType != "" {
		summary += " — " + evtType
	}
	if op != "" {
		summary += " — " + op
	}
	if len(summary) > 1024 {
		summary = summary[:1024]
	}
	return map[string]any{
		"routing_key":  d.PagerDutyIntegrationKey,
		"event_action": "trigger",
		"payload": map[string]any{
			"summary":        summary,
			"source":         fmt.Sprintf("iam-jit/%s", product),
			"severity":       d.PagerDutySeverity,
			"custom_details": ev,
		},
	}
}

func slackPayload(ev map[string]any, product string) map[string]any {
	op := nestedString(ev, "api.operation")
	evtType := nestedString(ev, "unmapped.iam_jit.event_type")
	actor := nestedString(ev, "actor.user.name")
	parts := []string{fmt.Sprintf("iam-jit %s", product)}
	if evtType != "" {
		parts = append(parts, evtType)
	}
	if op != "" {
		parts = append(parts, op)
	}
	if actor != "" {
		parts = append(parts, "actor="+actor)
	}
	return map[string]any{"text": strings.Join(parts, " — ")}
}

func nestedString(ev map[string]any, path string) string {
	values := walkPath(ev, path)
	if len(values) == 0 {
		return ""
	}
	if s, ok := values[0].(string); ok {
		return s
	}
	return ""
}

func mapToEvent(m map[string]any) (Event, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return Event{}, err
	}
	var ev Event
	if err := json.Unmarshal(b, &ev); err != nil {
		return Event{}, err
	}
	return ev, nil
}

var secretLikeRE = regexp.MustCompile(`[A-Za-z0-9_\-]{16,}`)

func maskSecretsInError(s string) string {
	return secretLikeRE.ReplaceAllString(s, "<masked>")
}

// RoutesEngineStatus is the snapshot read by the MCP status tool +
// the startup banner. NEVER includes any secret value.
type RoutesEngineStatus struct {
	Configured    bool                      `json:"configured"`
	RouteCount    int                       `json:"route_count"`
	EngineDropped int64                     `json:"engine_dropped"`
	QueueDepth    int                       `json:"queue_depth"`
	Routes        []RoutesEngineRouteStatus `json:"routes"`
}

type RoutesEngineRouteStatus struct {
	Name             string           `json:"name"`
	OnMatch          string           `json:"on_match"`
	Destinations     []map[string]any `json:"destinations"`
	DestinationStats []map[string]any `json:"destination_stats"`
}

func (e *RoutesEngine) Status() RoutesEngineStatus {
	if e == nil {
		return RoutesEngineStatus{}
	}
	rs := make([]RoutesEngineRouteStatus, 0, len(e.cfg.Routes))
	for _, r := range e.cfg.Routes {
		dests := make([]map[string]any, 0, len(r.Destinations))
		dstats := make([]map[string]any, 0, len(r.Destinations))
		for di, d := range r.Destinations {
			dests = append(dests, d.Masked())
			s := e.statsFor(r.Name, di)
			lastErr, _ := s.LastErr.Load().(string)
			dstats = append(dstats, map[string]any{
				"total_sent":        s.TotalSent.Load(),
				"total_failed":      s.TotalFailed.Load(),
				"last_error":        lastErr,
				"last_status_code":  s.LastStatus.Load(),
				"last_attempt_unix": s.LastAttemptUnix.Load(),
				"last_success_unix": s.LastSuccessUnix.Load(),
			})
		}
		rs = append(rs, RoutesEngineRouteStatus{
			Name:             r.Name,
			OnMatch:          r.OnMatch,
			Destinations:     dests,
			DestinationStats: dstats,
		})
	}
	return RoutesEngineStatus{
		Configured:    true,
		RouteCount:    len(e.cfg.Routes),
		EngineDropped: e.totalDropped.Load(),
		QueueDepth:    len(e.queue),
		Routes:        rs,
	}
}

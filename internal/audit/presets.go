// Webhook presets — vendor-native body + header shapes for the
// audit-export webhook transport. Per the [[audit-webhook-presets]]
// memo, this file is a PURE TRANSFORMATION layer: it takes the
// canonical OCSF v1.1.0 class-6003 Event (per [[ocsf-audit-schema]])
// + a PresetConfig and returns (target_url, headers, body_bytes). The
// OCSF event written to the JSONL log file via internal/audit/log.go
// is UNCHANGED — only the webhook body picks up the vendor overlay
// at send-time.
//
// Slice scope per the memo:
//
//	generic     — backward-compat default. Authorization: Bearer + JSON
//	              array of OCSF events. Byte-identical to the pre-preset
//	              wire shape (regression-tested).
//	datadog     — DD-API-KEY header + ddsource/service/ddtags/status/
//	              message overlay. The `message` summary uses the
//	              per-dialect ext fields (dialect, tables_touched,
//	              is_dml, mutating_node_type) so DD's full-text search
//	              surfaces a readable line, e.g.
//	              "DENY UPDATE on public.users (1 table, mysql)".
//	splunk-hec  — `Splunk <token>` auth + event-wrapped NDJSON.
//	sentinel    — Microsoft Sentinel Log Analytics Workspace ingest;
//	              HMAC-SHA256-signed SharedKey Authorization computed
//	              per request (signature includes content_length +
//	              x-ms-date so it CANNOT be precomputed).
//
// Per [[security-team-positioning-safety-not-surveillance]] the
// vendor-side overlay language is NEUTRAL: per-dialect summaries say
// "DENY UPDATE on public.users" not "unauthorized" / "violation"
// /etc. The framing matches the rest of the audit-export surface.
//
// Per [[scorer-is-ground-truth]]: this layer NEVER re-scores, mutates,
// or LLM-enriches the OCSF event. It is a deterministic mapping.
//
// Per [[deliberate-feature-completion]]: the four presets ship in one
// atomic commit with per-preset adapter tests + a generic-preset byte-
// identity regression + a Sentinel-HMAC-matches-Microsoft-vector test.
//
// AWS Security Lake is a SEPARATE slice (S3 + parquet, different
// transport; out-of-scope here).

package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Preset is the operator-selectable vendor adapter. Matches the
// `--audit-webhook-preset` CLI flag values. Per the memo: same set
// of names across all three Bounce products for
// [[cross-product-agent-parity]].
type Preset string

const (
	PresetGeneric    Preset = "generic"
	PresetDatadog    Preset = "datadog"
	PresetSplunkHEC  Preset = "splunk-hec"
	PresetSentinel   Preset = "sentinel"
)

// DefaultSentinelTable is the Log Analytics custom-table name when
// the operator doesn't override via --audit-webhook-sentinel-table.
// Per the memo: one custom table across all three Bounce products
// (operators can split per-product by overriding this value per
// deployment).
const DefaultSentinelTable = "IamJitBouncer"

// ParsePreset normalizes operator-supplied preset names + returns an
// error naming the valid set. Empty string defaults to generic so an
// operator who upgrades from the pre-preset webhook gets the same
// wire shape they had before.
func ParsePreset(s string) (Preset, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "generic":
		return PresetGeneric, nil
	case "datadog", "dd":
		return PresetDatadog, nil
	case "splunk-hec", "splunk_hec", "splunkhec", "splunk":
		return PresetSplunkHEC, nil
	case "sentinel", "azure-sentinel", "azure_sentinel":
		return PresetSentinel, nil
	default:
		return "", fmt.Errorf(
			"unknown --audit-webhook-preset %q (valid: generic, datadog, splunk-hec, sentinel)",
			s)
	}
}

// PresetConfig is the per-deployment adapter input. The WebhookPusher
// constructs one from WebhookOptions at startup + passes it (along
// with the per-batch Event slice) to BuildRequest on every delivery
// attempt.
type PresetConfig struct {
	// Preset names which adapter to dispatch to.
	Preset Preset

	// URL is the operator-configured webhook endpoint as parsed at
	// startup. Adapters use it as-is for generic / datadog /
	// splunk-hec; Sentinel uses it but ALSO requires the path to be
	// "/api/logs" for the HMAC signature.
	URL string

	// Token is the vendor's auth credential. Mapped to the correct
	// header per preset: Bearer for generic, DD-API-KEY for datadog,
	// `Splunk <token>` for splunk-hec, base64-decoded HMAC key for
	// sentinel. NEVER logged.
	Token string

	// Product is stamped into vendor-overlay fields that name the
	// originating product (datadog service / ddtags, splunk-hec
	// sourcetype). Defaults to the package-level Product const
	// ("dbounce") when empty.
	Product string

	// ExtraTags is the free-form --audit-webhook-tags value appended
	// to datadog's ddtags. Format: "k1:v1,k2:v2" (comma-separated;
	// validated downstream by DD's parser — we don't pre-validate per
	// the memo's "don't pre-validate the vendor's tokens/tags" rule).
	// Ignored by other presets but stored at construction so a future
	// preset can read it without a config-shape change.
	ExtraTags string

	// SentinelTable is the Log Analytics custom-table name (passed via
	// Log-Type header). Defaults to DefaultSentinelTable when empty.
	// Sentinel-only; ignored by other presets.
	SentinelTable string

	// SentinelWorkspaceID is the Log Analytics workspace ID — the
	// "<workspace-id>" part of the SharedKey Authorization header.
	// Derived at startup from URL host's leftmost label (workspace
	// IDs are GUIDs serving as Azure subdomain prefixes); operators
	// who use a CNAME-rewriting proxy can override via the
	// SentinelWorkspaceID field directly.
	SentinelWorkspaceID string

	// now is overridable for HMAC test fixtures so a deterministic
	// x-ms-date can be compared to Microsoft's published example.
	// Production callers leave nil → time.Now.UTC().
	now func() time.Time
}

// Normalize fills in defaults + parses derived fields. Returns an
// error when a required field for the chosen preset is missing or
// malformed. Called once at WebhookPusher construction so per-request
// BuildRequest calls can assume the config is valid.
func (c *PresetConfig) Normalize() error {
	if c.Preset == "" {
		c.Preset = PresetGeneric
	}
	if c.Product == "" {
		c.Product = Product
	}
	if c.SentinelTable == "" {
		c.SentinelTable = DefaultSentinelTable
	}
	if c.Preset == PresetSentinel {
		// Derive workspace ID from the URL host's leftmost label
		// unless explicitly set. Sentinel's host shape is
		// "<workspace-id>.ods.opinsights.azure.com" (or .us / .cn /
		// .de government clouds). The HMAC Authorization header
		// requires the workspace ID; failing to derive it at startup
		// would silently sign with the wrong identity.
		if c.SentinelWorkspaceID == "" {
			host := c.URL
			if idx := strings.Index(host, "://"); idx >= 0 {
				host = host[idx+3:]
			}
			if idx := strings.IndexAny(host, "/?#"); idx >= 0 {
				host = host[:idx]
			}
			if idx := strings.Index(host, ":"); idx >= 0 {
				host = host[:idx]
			}
			label := host
			if idx := strings.Index(host, "."); idx >= 0 {
				label = host[:idx]
			}
			if label == "" {
				return fmt.Errorf(
					"audit: --audit-webhook-preset=sentinel requires the URL to "+
						"include a workspace-id subdomain (got %q); typical "+
						"shape: https://<workspace-id>.ods.opinsights.azure.com"+
						"/api/logs?api-version=2016-04-01", c.URL)
			}
			c.SentinelWorkspaceID = label
		}
		// Sentinel signing requires the shared key to be valid base64.
		// Validate at startup so a typo'd token fails fast with a
		// clear error instead of producing silently-broken signatures
		// the operator has to triage via Sentinel's 403 responses.
		if _, err := base64.StdEncoding.DecodeString(c.Token); err != nil {
			return fmt.Errorf(
				"audit: --audit-webhook-preset=sentinel: --audit-webhook-token "+
					"must be the workspace shared key (base64-encoded); decode "+
					"failed: %w", err)
		}
	}
	return nil
}

// RequestParts is the (url, headers, body) tuple every adapter
// returns. The WebhookPusher copies headers onto the http.Request +
// uses url as the POST target + body as the request body. Adapter
// is pure — no IO, no logging, no goroutines.
type RequestParts struct {
	URL     string
	Headers map[string]string
	Body    []byte
}

// BuildRequest dispatches to the per-preset adapter for the
// configured Preset. Called once per delivery attempt (Sentinel's
// signature depends on x-ms-date so we can't precompute across
// retries). On error the deliver loop logs + drops per the existing
// non-2xx path; the adapter NEVER reaches the network itself.
func BuildRequest(cfg PresetConfig, batch []Event) (RequestParts, error) {
	switch cfg.Preset {
	case PresetGeneric, "":
		return buildGenericRequest(cfg, batch)
	case PresetDatadog:
		return buildDatadogRequest(cfg, batch)
	case PresetSplunkHEC:
		return buildSplunkHECRequest(cfg, batch)
	case PresetSentinel:
		return buildSentinelRequest(cfg, batch)
	default:
		return RequestParts{}, fmt.Errorf("audit: unknown preset %q", cfg.Preset)
	}
}

// buildGenericRequest preserves the pre-preset wire shape:
//
//	URL:     cfg.URL as-is
//	Headers: Authorization: Bearer <token>
//	         Content-Type:  application/x-ndjson
//	Body:    one OCSF event per line (NDJSON; same as the JSONL log
//	         file format)
//
// This adapter is byte-identical to the pre-preset webhook output —
// the generic-preset regression test in presets_test.go asserts that
// invariant.
func buildGenericRequest(cfg PresetConfig, batch []Event) (RequestParts, error) {
	body, err := encodeNDJSON(batch)
	if err != nil {
		return RequestParts{}, err
	}
	return RequestParts{
		URL: cfg.URL,
		Headers: map[string]string{
			"Content-Type":  "application/x-ndjson",
			"Authorization": "Bearer " + cfg.Token,
		},
		Body: body,
	}, nil
}

// buildDatadogRequest emits a JSON array of objects; each object is
// the OCSF event with the DD-native overlay fields added at the top
// level so DD's pipelines + dashboards auto-categorize.
//
// Overlay fields per the memo:
//
//	ddsource = "iam-jit"
//	service  = cfg.Product (dbounce / kbounce / ibounce)
//	ddtags   = "product:iam-jit,bouncer:<product>"[ + ExtraTags]
//	host     = OCSF src_endpoint.hostname/ip
//	status   = OCSF status_id → "info" | "error" | "notice"
//	message  = per-dialect readable summary (DD's searchable text)
//
// Per the memo: when an overlay field collides with an OCSF field
// (e.g. `status`), the OVERLAY value wins for DD's categorization +
// the OCSF value is preserved under ocsf.<original_field>.
func buildDatadogRequest(cfg PresetConfig, batch []Event) (RequestParts, error) {
	overlay := make([]map[string]any, 0, len(batch))
	for _, e := range batch {
		obj := eventToMap(e)
		// Preserve OCSF's `status` under ocsf.status before overlay
		// overwrites it. ocsf.* namespace per the memo's
		// field-overlap-conflict rule.
		ocsf := map[string]any{}
		if v, ok := obj["status"]; ok {
			ocsf["status"] = v
		}
		if v, ok := obj["status_id"]; ok {
			ocsf["status_id"] = v
		}
		if len(ocsf) > 0 {
			obj["ocsf"] = ocsf
		}
		obj["ddsource"] = "iam-jit"
		obj["service"] = cfg.Product
		obj["ddtags"] = ddTags(cfg)
		if host := eventHost(e); host != "" {
			obj["host"] = host
		}
		obj["status"] = datadogStatus(e.StatusID)
		obj["message"] = datadogMessage(e)
		overlay = append(overlay, obj)
	}
	body, err := json.Marshal(overlay)
	if err != nil {
		return RequestParts{}, fmt.Errorf("datadog: marshal batch: %w", err)
	}
	return RequestParts{
		URL: cfg.URL,
		Headers: map[string]string{
			"Content-Type": "application/json",
			"DD-API-KEY":   cfg.Token,
		},
		Body: body,
	}, nil
}

// buildSplunkHECRequest emits newline-delimited HEC events. Each line
// is an object wrapping the full OCSF event under `event` so Splunk's
// auto-extraction picks up `event.*` fields without per-field
// configuration.
//
//	sourcetype = "iam_jit:bouncer:<product>"  (per the spec memo)
//	source     = "iam-jit"
//	host       = OCSF src_endpoint.hostname/ip
//	time       = epoch seconds derived from OCSF time (ms → s)
//	event      = full OCSF event
func buildSplunkHECRequest(cfg PresetConfig, batch []Event) (RequestParts, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range batch {
		wrapped := map[string]any{
			"event":      e,
			"sourcetype": "iam_jit:bouncer:" + cfg.Product,
			"source":     "iam-jit",
			// Splunk's HEC `time` field is epoch SECONDS (with optional
			// fractional ms). OCSF Event.Time is epoch MILLISECONDS.
			// Convert here so Splunk doesn't interpret a ms timestamp
			// as a year-55000 future date.
			"time": float64(e.Time) / 1000.0,
		}
		if host := eventHost(e); host != "" {
			wrapped["host"] = host
		}
		if err := enc.Encode(wrapped); err != nil {
			return RequestParts{}, fmt.Errorf("splunk-hec: encode: %w", err)
		}
	}
	return RequestParts{
		URL: cfg.URL,
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Splunk " + cfg.Token,
		},
		Body: buf.Bytes(),
	}, nil
}

// buildSentinelRequest emits a JSON array of OCSF events + the
// HMAC-SHA256-signed Authorization header per Microsoft's Log
// Analytics Workspace HTTP Data Collector API spec:
//
//	StringToSign = METHOD + "\n" + content_length + "\n" +
//	               application/json + "\n" + x-ms-date:<date> + "\n" +
//	               /api/logs
//	signature    = base64(HMAC-SHA256(decode_base64(shared_key),
//	                                  StringToSign))
//	Authorization: SharedKey <workspace-id>:<signature>
//
// Reference (Microsoft Learn, "Send log data to Azure Monitor by using
// the HTTP Data Collector API"):
//
//	https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
//
// The Microsoft-published example uses workspace-id
// "xx-workspace-id-xx" + shared-key "<a base64 value>"; the
// presets_test.go fixtures match those constants against the example
// signature so a regression in our HMAC implementation surfaces at
// test time, not in customer Sentinel pipelines.
func buildSentinelRequest(cfg PresetConfig, batch []Event) (RequestParts, error) {
	body, err := json.Marshal(batch)
	if err != nil {
		return RequestParts{}, fmt.Errorf("sentinel: marshal batch: %w", err)
	}
	nowFn := cfg.now
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	// RFC1123 per Microsoft's spec — note Go's http.TimeFormat is
	// RFC1123 with GMT (NOT the locale-sensitive time.RFC1123). The
	// "GMT" suffix is required by Sentinel's parser.
	xmsDate := nowFn().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	sig, err := sentinelSignature(cfg.Token, len(body), xmsDate, "/api/logs")
	if err != nil {
		return RequestParts{}, err
	}
	return RequestParts{
		URL: cfg.URL,
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "SharedKey " + cfg.SentinelWorkspaceID + ":" + sig,
			"Log-Type":      cfg.SentinelTable,
			"x-ms-date":     xmsDate,
			// "time-generated-field" is the OCSF field Sentinel uses
			// for the row's TimeGenerated column. Without it Sentinel
			// stamps ingestion time, which obscures the actual event
			// time when audit-export catches up after a backlog.
			"time-generated-field": "time",
		},
		Body: body,
	}, nil
}

// sentinelSignature computes the SharedKey HMAC per the Microsoft
// spec. The signed string includes the HTTP method (always POST for
// our ingest), the content_length (Sentinel REJECTS requests where
// header content-length disagrees), the content-type, the
// x-ms-date header, and the /api/logs URL path. base64-decoded
// shared key is the HMAC key.
//
// Returned signature is base64 of the HMAC bytes.
func sentinelSignature(sharedKeyBase64 string, contentLength int, xmsDate, resource string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(sharedKeyBase64)
	if err != nil {
		// Should be unreachable in production (Normalize already
		// validated) but we re-check here so direct callers from tests
		// get a clear error rather than a panic in hmac.New.
		return "", fmt.Errorf("sentinel: shared-key base64 decode: %w", err)
	}
	stringToSign := strings.Join([]string{
		"POST",
		strconv.Itoa(contentLength),
		"application/json",
		"x-ms-date:" + xmsDate,
		resource,
	}, "\n")
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// ddTags assembles the DD `ddtags` string. Always carries
// product:iam-jit + bouncer:<product> so DD pipelines can fan-out
// per-product without a sourcetype rule. ExtraTags appends as-is (we
// don't pre-validate DD's tag syntax per the memo's "vendor's parser
// rejects malformed tokens" rule).
func ddTags(cfg PresetConfig) string {
	base := "product:iam-jit,bouncer:" + cfg.Product
	if cfg.ExtraTags != "" {
		return base + "," + cfg.ExtraTags
	}
	return base
}

// datadogStatus maps OCSF status_id to DD's `status` enum per the
// memo. DD's status drives row coloring + alert correlation in DD's
// Log Explorer UI.
//
//	1 (Success) → "info"
//	2 (Failure) → "error"
//	99 (Other)  → "notice"
//	(else)      → "info"   conservative default; treat unknowns as
//	                       informational so a future OCSF status_id
//	                       addition doesn't silently page on-call.
func datadogStatus(statusID int) string {
	switch statusID {
	case StatusIDSuccess:
		return "info"
	case StatusIDFailure:
		return "error"
	case StatusIDOther:
		return "notice"
	default:
		return "info"
	}
}

// datadogMessage builds the per-dialect human-readable summary that
// DD uses as the row's searchable text. Reads from
// unmapped.iam_jit.ext (dialect / tables_touched / mutating_node_type)
// which the OCSF refactor (#255) already populates per [[ocsf-audit-
// schema]] so we don't have to re-derive these from the underlying
// store row.
//
// Format:
//
//	"<VERDICT> <activity> on <table[, more]> (N tables, <dialect>)"
//
// Examples:
//
//	"ALLOW SELECT on public.users (1 table, postgres)"
//	"DENY UPDATE on app.orders (1 table, mysql)"
//	"DENY EXPORT_DATA on analytics.events (1 table, snowflake) (advisory)"
//	"audit_dropped (5 events)"
//
// Per [[security-team-positioning-safety-not-surveillance]] the
// language is NEUTRAL: it names what happened, not whether it was a
// "violation" or "unauthorized" — the security team interprets the
// verdict in context.
func datadogMessage(e Event) string {
	// AUDIT_DROPPED synthetic gets its own format — it has no
	// verdict / no tables / no dialect.
	if e.Unmapped != nil && e.Unmapped.IAMJIT.EventType == string(EventTypeAuditDropped) {
		return fmt.Sprintf("audit_dropped (%d events)", e.Unmapped.IAMJIT.DroppedCount)
	}
	verdict := ""
	if e.Unmapped != nil {
		verdict = e.Unmapped.IAMJIT.Verdict
	}
	activity := strings.ToUpper(strings.TrimSpace(e.ActivityName))
	// Prefer the per-dialect statement-type from ext.mutating_node_type
	// when present (it's the specific verb for CALL/EXECUTE/WITH-WRITE
	// rows where activity_name is just "other"). Falls back to
	// activity_name's upper-cased form.
	if e.Unmapped != nil && e.Unmapped.IAMJIT.Ext != nil {
		if mut, ok := e.Unmapped.IAMJIT.Ext["mutating_node_type"].(string); ok && mut != "" {
			activity = strings.ToUpper(mut)
		}
	}
	if activity == "" {
		activity = "UNKNOWN"
	}
	tablesPart := ""
	tableCount := 0
	dialect := ""
	if e.Unmapped != nil && e.Unmapped.IAMJIT.Ext != nil {
		if d, ok := e.Unmapped.IAMJIT.Ext["dialect"].(string); ok {
			dialect = d
		}
		// tables_touched can be either []string (when buildExt copied
		// from store.DecisionRow) OR []any (after json round-trip).
		// Handle both so this function is safe regardless of whether
		// the caller passes a freshly-projected Event or one that
		// transited through JSON.
		switch tt := e.Unmapped.IAMJIT.Ext["tables_touched"].(type) {
		case []string:
			tableCount = len(tt)
			if len(tt) > 0 {
				tablesPart = " on " + tt[0]
				if len(tt) > 1 {
					tablesPart = " on " + tt[0] + " +" + strconv.Itoa(len(tt)-1) + " more"
				}
			}
		case []any:
			tableCount = len(tt)
			if len(tt) > 0 {
				if first, ok := tt[0].(string); ok {
					tablesPart = " on " + first
					if len(tt) > 1 {
						tablesPart = " on " + first + " +" + strconv.Itoa(len(tt)-1) + " more"
					}
				}
			}
		}
	}
	// Fall back to OCSF resources when ext didn't carry tables (paths
	// where buildExt skipped tables — empty TablesTouched).
	if tableCount == 0 && len(e.Resources) > 0 {
		tableCount = len(e.Resources)
		tablesPart = " on " + e.Resources[0].Name
		if len(e.Resources) > 1 {
			tablesPart = " on " + e.Resources[0].Name + " +" + strconv.Itoa(len(e.Resources)-1) + " more"
		}
	}

	suffix := ""
	if tableCount > 0 || dialect != "" {
		parts := []string{}
		if tableCount > 0 {
			parts = append(parts, fmt.Sprintf("%d table%s", tableCount, plural(tableCount)))
		}
		if dialect != "" {
			parts = append(parts, dialect)
		}
		suffix = " (" + strings.Join(parts, ", ") + ")"
	}

	// Cooperative-advisory DENYs get a trailing "(advisory)" so
	// security teams reading the DD line know the upstream call still
	// went through (per the verdictToStatus semantics — enforced=false
	// DENY maps to OCSF Success). This matters because DD's
	// status="info" alongside verdict=DENY would otherwise be
	// confusing without context.
	advisorySuffix := ""
	if verdict == "DENY" && e.Unmapped != nil && !e.Unmapped.IAMJIT.Enforced {
		advisorySuffix = " (advisory)"
	}

	if verdict != "" {
		return verdict + " " + activity + tablesPart + suffix + advisorySuffix
	}
	return activity + tablesPart + suffix
}

// eventHost returns the host string for the vendor-overlay `host`
// field. Prefers OCSF src_endpoint.hostname; falls back to .ip; empty
// when neither is set so callers can omit the field via map-delete /
// omitempty rather than emitting "host":"".
func eventHost(e Event) string {
	if e.SrcEndpoint == nil {
		return ""
	}
	if e.SrcEndpoint.Hostname != "" {
		return e.SrcEndpoint.Hostname
	}
	return e.SrcEndpoint.IP
}

// eventToMap converts an Event to a generic map so vendor adapters
// can OVERLAY top-level keys without per-field unmarshal. The
// round-trip is JSON-based to guarantee the map keys EXACTLY match
// the JSON tags on the Event struct — overlays would otherwise
// shadow nothing if the map key shape disagreed (e.g.
// "status_id" vs "StatusID").
//
// This is the only allocation hot path in the adapter; the
// alternative (per-event manual map construction) is fragile to
// schema changes — every new OCSF field would need a hand-mirrored
// map entry. The JSON round-trip stays correct under any additive
// schema change.
func eventToMap(e Event) map[string]any {
	raw, _ := json.Marshal(e)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// encodeNDJSON writes one JSON object per line. Same shape as the
// JSONL log file + the pre-preset generic webhook body.
func encodeNDJSON(batch []Event) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range batch {
		if err := enc.Encode(e); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// plural is the most boring helper in the file. Centralized so the
// per-dialect summary line ("1 table" vs "2 tables") doesn't have a
// per-call-site copy.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// SortedHeaders returns the RequestParts headers in deterministic
// order. Used by tests that want stable assertion targets; production
// http.Request.Header is a map (Go's iteration is randomized) so the
// wire order may differ — that's fine, HTTP header order is not
// significant.
func (rp RequestParts) SortedHeaders() []string {
	keys := make([]string, 0, len(rp.Headers))
	for k := range rp.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+": "+rp.Headers[k])
	}
	return out
}

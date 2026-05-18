// audit_events.go ships the GET /audit/events HTTP endpoint that lives
// on the management port alongside /healthz (#271).
//
// This is the "headless" sibling of `dbounce audit tail --filter ...
// --export jsonl` (#268): same filter language (audit.ParseFilter),
// same supported field catalog (cross-product OCSF + dbounce-specific
// unmapped.iam_jit.ext.* fields), same OCSF v1.1.0 wire shape. The
// cross-bouncer `iam-jit audit query` CLI calls this endpoint on
// each reachable bouncer in parallel + merges results.
//
// Wire shape:
//
//	GET /audit/events?since=ISO8601&until=ISO8601
//	                 &filter=field=value&filter=...
//	                 &limit=N&format=jsonl|ocsf-bundle
//
// Defaults: limit=100 (max 1000), format=jsonl.
//
// Auth model:
//   - Loopback mgmt-host (default): no Authorization header required.
//   - External mgmt-host: requires Authorization: Bearer
//     <AuditEventsToken>. The CLI refuses to start in external-bind
//     mode without --audit-events-token TOKEN.
//
// Per [[cross-product-agent-parity]] the same endpoint ships on every
// bouncer in the suite. Per [[creates-never-mutates]] read-only.
// Per [[self-host-zero-billing-dependency]] no phone-home; the
// endpoint only ever talks to the operator-controlled mgmt port.

package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/store"
)

// AuditEventsDefaultLimit is the response cap when ?limit= is unset.
const AuditEventsDefaultLimit = 100

// AuditEventsMaxLimit caps ?limit= so a runaway query can't return an
// unbounded payload.
const AuditEventsMaxLimit = 1000

// AuditEventsFormatJSONL is the default response format: one
// JSON-encoded OCSF event per line.
const AuditEventsFormatJSONL = "jsonl"

// AuditEventsFormatOCSFBundle wraps the response in a single OCSF v1.1.0
// class 2004 Detection Finding for SIEM batch import.
const AuditEventsFormatOCSFBundle = "ocsf-bundle"

// auditEventsHandler builds the http.HandlerFunc for /audit/events.
// requireBearer == "" allows unauthenticated requests (loopback mode);
// non-empty requires "Authorization: Bearer <requireBearer>".
func auditEventsHandler(st *store.Store, requireBearer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeAuditEventsError(w, http.StatusMethodNotAllowed,
				"only GET is supported")
			return
		}
		if requireBearer != "" {
			ah := r.Header.Get("Authorization")
			if ah == "" {
				writeAuditEventsError(w, http.StatusUnauthorized,
					"Authorization: Bearer <token> required")
				return
			}
			tok, ok := parseBearerHeader(ah)
			if !ok || tok != requireBearer {
				writeAuditEventsError(w, http.StatusForbidden,
					"bearer token rejected")
				return
			}
		}

		q := r.URL.Query()
		opts, err := parseAuditEventsQuery(q)
		if err != nil {
			writeAuditEventsError(w, http.StatusBadRequest, err.Error())
			return
		}

		if st == nil {
			writeAuditEventsError(w, http.StatusServiceUnavailable,
				"audit store not initialized")
			return
		}
		rows, err := st.RecentDecisions(opts.fetchLimit)
		if err != nil {
			writeAuditEventsError(w, http.StatusInternalServerError,
				fmt.Sprintf("store read: %v", err))
			return
		}
		events := decisionRowsToAuditEvents(rows)
		events = filterAuditEventsByTime(events, opts.since, opts.until)
		if len(opts.filters) > 0 {
			kept := make([]audit.Event, 0, len(events))
			for _, ev := range events {
				if audit.MatchAll(ev, opts.filters) {
					kept = append(kept, ev)
				}
			}
			events = kept
		}
		if len(events) > opts.limit {
			events = events[:opts.limit]
		}

		switch opts.format {
		case AuditEventsFormatJSONL:
			w.Header().Set("Content-Type", "application/x-ndjson")
			enc := json.NewEncoder(w)
			for _, ev := range events {
				if err := enc.Encode(ev); err != nil {
					return
				}
			}
		case AuditEventsFormatOCSFBundle:
			w.Header().Set("Content-Type", "application/json")
			bundle := buildAuditEventsBundle(events)
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(bundle)
		}
	}
}

type auditEventsOpts struct {
	limit      int
	fetchLimit int
	format     string
	since      *time.Time
	until      *time.Time
	filters    []audit.Filter
}

func parseAuditEventsQuery(q url.Values) (auditEventsOpts, error) {
	opts := auditEventsOpts{
		limit:      AuditEventsDefaultLimit,
		fetchLimit: AuditEventsMaxLimit,
		format:     AuditEventsFormatJSONL,
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return opts, fmt.Errorf("limit=%q: must be a positive integer", v)
		}
		if n > AuditEventsMaxLimit {
			return opts, fmt.Errorf("limit=%d exceeds max %d", n, AuditEventsMaxLimit)
		}
		opts.limit = n
	}
	if v := q.Get("format"); v != "" {
		switch v {
		case AuditEventsFormatJSONL, AuditEventsFormatOCSFBundle:
			opts.format = v
		default:
			return opts, fmt.Errorf(
				"format=%q: want one of: %s, %s",
				v, AuditEventsFormatJSONL, AuditEventsFormatOCSFBundle)
		}
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return opts, fmt.Errorf("since=%q: want RFC3339 / ISO 8601", v)
		}
		opts.since = &t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return opts, fmt.Errorf("until=%q: want RFC3339 / ISO 8601", v)
		}
		opts.until = &t
	}
	if opts.since != nil && opts.until != nil && opts.since.After(*opts.until) {
		return opts, errors.New("since must be <= until")
	}
	for _, raw := range q["filter"] {
		f, err := audit.ParseFilter(raw)
		if err != nil {
			return opts, fmt.Errorf("filter %q: %v", raw, err)
		}
		opts.filters = append(opts.filters, f)
	}
	return opts, nil
}

func filterAuditEventsByTime(events []audit.Event, since, until *time.Time) []audit.Event {
	if since == nil && until == nil {
		return events
	}
	kept := make([]audit.Event, 0, len(events))
	for _, ev := range events {
		t := time.UnixMilli(ev.Time).UTC()
		if since != nil && t.Before(*since) {
			continue
		}
		if until != nil && t.After(*until) {
			continue
		}
		kept = append(kept, ev)
	}
	return kept
}

// decisionRowsToAuditEvents wraps SQLite DecisionRows as OCSF Events
// via the canonical FromDecisionRow builder so the resulting events
// match what the JSONL log / webhook pipeline emits.
func decisionRowsToAuditEvents(rows []store.DecisionRow) []audit.Event {
	out := make([]audit.Event, 0, len(rows))
	for _, r := range rows {
		out = append(out, audit.FromDecisionRow(r, 0, "", ""))
	}
	return out
}

// auditEventsBundle is the on-wire shape for ?format=ocsf-bundle.
type auditEventsBundle struct {
	Metadata     map[string]any `json:"metadata"`
	Time         int64          `json:"time"`
	ClassUID     int            `json:"class_uid"`
	ClassName    string         `json:"class_name"`
	CategoryUID  int            `json:"category_uid"`
	CategoryName string         `json:"category_name"`
	ActivityID   int            `json:"activity_id"`
	ActivityName string         `json:"activity_name"`
	TypeUID      int            `json:"type_uid"`
	TypeName     string         `json:"type_name"`
	SeverityID   int            `json:"severity_id"`
	Severity     string         `json:"severity"`
	StatusID     int            `json:"status_id"`
	Status       string         `json:"status"`
	FindingInfo  map[string]any `json:"finding_info"`
	Events       []audit.Event  `json:"events"`
}

func buildAuditEventsBundle(events []audit.Event) auditEventsBundle {
	now := time.Now().UTC()
	return auditEventsBundle{
		Metadata: map[string]any{
			"version": audit.SchemaVersion,
			"product": map[string]any{
				"name":        audit.Product,
				"vendor_name": audit.VendorName,
			},
		},
		Time:         now.UnixMilli(),
		ClassUID:     2004,
		ClassName:    "Detection Finding",
		CategoryUID:  2,
		CategoryName: "Findings",
		ActivityID:   1,
		ActivityName: "Create",
		TypeUID:      2004*100 + 1,
		TypeName:     "Detection Finding: Create",
		SeverityID:   1,
		Severity:     "Informational",
		StatusID:     99,
		Status:       "Other",
		FindingInfo: map[string]any{
			"uid":          fmt.Sprintf("dbounce-audit-events-%d", now.UnixNano()),
			"title":        "dbounce audit-events query",
			"desc":         fmt.Sprintf("HTTP /audit/events query returned %d event(s).", len(events)),
			"created_time": now.UnixMilli(),
		},
		Events: events,
	}
}

func writeAuditEventsError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func parseBearerHeader(header string) (string, bool) {
	const prefix = "bearer "
	if len(header) <= len(prefix) {
		return "", false
	}
	if !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(header[len(prefix):]), true
}

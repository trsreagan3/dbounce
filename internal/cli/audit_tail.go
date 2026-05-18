// Package cli — `dbounce audit tail` enhancements (#268).
//
// The base `audit tail` (cli.go::newAuditTailCmd) prints a snapshot of
// the most recent decisions in a human table or as JSON. #268 extends
// that surface with four operator workflows shared cross-product with
// ibounce + kbounce (per [[cross-product-agent-parity]]):
//
//   --follow                                 live tail (poll loop, SIGINT-aware)
//   --filter EXPR (repeatable)               AND-combined field predicates
//   --summary                                count-summary across groupings
//   --export {jsonl,csv,ocsf-bundle} --out   bulk export for SIEM ingest
//
// The flags compose: --filter narrows what --follow / --summary / --export
// see. --follow + --summary clash (live-tail vs one-shot aggregation) and
// the parser rejects the combination at invocation time with a clear
// error.
//
// SQL-literal redaction (dbounce-specific care):
//
// Per the spec, every CSV and ocsf-bundle export defensively pipes any
// SQL text through parser.RedactLiterals BEFORE writing — even when the
// audit row was persisted without --redact-literals at run time. The
// `dbounce audit tail` plaintext + --json paths preserve the stored
// shape for operator visibility (the SQLite DB is local to the
// operator's user account), but bulk-exporting raw literals to a SIEM
// is the surface that ships customer PII to third-party storage. We
// fail closed: redact on export, surface `--include-literals` only when
// a future ticket adds an explicit override (not in scope for #268).
//
// Cross-product parity: the flag set + summary groupings + supported
// filter fields match the ibounce + kbounce surface. See
// docs/QUERYING-AUDIT-LOGS.md for the full schema.
//
// Per [[creates-never-mutates]]: this file reads the SQLite audit DB +
// writes to operator-provided paths. No proxy / DB / network mutation.
//
// Per [[self-host-zero-billing-dependency]]: zero network calls. Export
// formats are written to local files only.

package cli

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/parser"
	"github.com/trsreagan3/dbounce/internal/store"
)

// followPollIntervalDefault is the SQLite poll cadence for --follow.
// 500ms balances responsiveness (operator sees new rows within half a
// second of the proxy committing them) against query pressure on the
// shared SQLite db (each poll is one indexed SELECT WHERE id > ?).
// Override via --poll-interval for slow-disk smoke tests.
const followPollIntervalDefault = 500 * time.Millisecond

// followBatchLimit caps the per-poll batch so a sudden burst (e.g. a
// data-import dumping thousands of statements) doesn't allocate
// unbounded memory inside the follow goroutine. When the underlying
// table grew faster than the print loop drained, the NEXT poll picks up
// where this one stopped — the watermark advances regardless of the
// caller's print speed.
const followBatchLimit = 500

// exportFormatJSONL emits one OCSF-projected Event per line. Mirrors
// the JSONL file transport so an operator can replay an export through
// the same downstream pipelines without per-shape translation.
const exportFormatJSONL = "jsonl"

// exportFormatCSV emits a header row + one CSV line per event. Columns
// default to the operator-readable set; override via --csv-columns.
const exportFormatCSV = "csv"

// exportFormatOCSFBundle emits a single JSON object wrapping every
// matched row as an OCSF Detection Finding (class_uid=2004). SIEM batch
// import surface — Splunk / Sentinel / Datadog can ingest the bundle
// in one HTTP POST instead of N JSONL lines.
const exportFormatOCSFBundle = "ocsf-bundle"

// defaultCSVColumns names the columns in the CSV export header when
// --csv-columns is not passed. Documented in docs/QUERYING-AUDIT-LOGS.md.
var defaultCSVColumns = []string{
	"timestamp",
	"severity",
	"event_type",
	"actor",
	"operation",
	"verdict",
	"agent.name",
	"agent.session_id",
}

// ocsfDetectionFindingClassUID is the OCSF class id for class 2004
// (Detection Finding). The audit-tail --export ocsf-bundle bundles
// every matched event as a Detection Finding object so a SIEM batch
// ingestor recognizes the shape without per-product wiring.
const ocsfDetectionFindingClassUID = 2004

// ocsfDetectionFindingClassName is the human-readable display name for
// class 2004.
const ocsfDetectionFindingClassName = "Detection Finding"

// ocsfDetectionFindingCategoryUID is the OCSF category for Findings
// (category 2).
const ocsfDetectionFindingCategoryUID = 2

// ocsfDetectionFindingCategoryName is the display name for the
// Findings category.
const ocsfDetectionFindingCategoryName = "Findings"

// auditTailOpts groups the new flag values for the enhanced tail. Held
// in a struct so the cobra RunE can pass them to helpers without a
// telephone-game of positional args.
type auditTailOpts struct {
	limit          int
	dbPath         string
	asJSON         bool
	follow         bool
	pollInterval   time.Duration
	filters        []string
	summary        bool
	exportFormat   string
	exportOutPath  string
	csvColumnsArg  string
}

// registerAuditTailFlags wires the enhanced flag set onto the existing
// tail subcommand. Called from newAuditTailCmd so the cobra surface
// stays in one place.
func registerAuditTailFlags(cmd *cobra.Command, o *auditTailOpts) {
	cmd.Flags().IntVar(&o.limit, "limit", 50,
		"Max rows to return (1-1000). Default 50. Ignored under --follow "+
			"(follow streams all matching rows).")
	cmd.Flags().StringVar(&o.dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().BoolVar(&o.asJSON, "json", false,
		"Emit one JSON object per decision row, newest first. Mirrors "+
			"kbounce + ibounce's `audit tail --json` for cross-product "+
			"agent parity.")
	cmd.Flags().BoolVar(&o.follow, "follow", false,
		"Live tail: poll the SQLite audit DB at --poll-interval + print "+
			"new rows as they appear. Exit on SIGINT (Ctrl-C). Mirrors "+
			"kbounce + ibounce's `audit tail --follow` for cross-product "+
			"agent parity (#268).")
	cmd.Flags().DurationVar(&o.pollInterval, "poll-interval", followPollIntervalDefault,
		"Poll cadence for --follow. Lower values reduce time-to-print "+
			"at the cost of more SELECT pressure; higher values batch "+
			"more rows per poll. Default 500ms.")
	cmd.Flags().StringSliceVar(&o.filters, "filter", nil,
		"Repeatable field predicate (AND-combined). Forms:\n"+
			"  field=value        string equality\n"+
			"  field~regex        regex match (RE2 syntax)\n"+
			"  field>=N           numeric ≥\n"+
			"  field<=N           numeric ≤\n"+
			"Fields: severity_id, activity_id, status_id, actor.user.name, "+
			"api.operation, unmapped.iam_jit.event_type, "+
			"unmapped.iam_jit.agent.name, unmapped.iam_jit.agent.session_id, "+
			"unmapped.iam_jit.ext.is_dml, unmapped.iam_jit.ext.is_ddl, "+
			"unmapped.iam_jit.ext.tables_touched (dbounce-specific).")
	cmd.Flags().BoolVar(&o.summary, "summary", false,
		"Count-summary mode: print row counts grouped by event_type, "+
			"severity_id, actor.user.name, api.operation. Honors --filter. "+
			"Conflicts with --follow.")
	cmd.Flags().StringVar(&o.exportFormat, "export", "",
		"Bulk-export format. One of: jsonl, csv, ocsf-bundle. Requires --out.")
	cmd.Flags().StringVar(&o.exportOutPath, "out", "",
		"Output file path for --export. Required when --export is set. "+
			"Refuses to overwrite an existing file unless the operator "+
			"passes a fresh path.")
	cmd.Flags().StringVar(&o.csvColumnsArg, "csv-columns", "",
		"Override the default CSV column set with a comma-separated list. "+
			"Only used when --export csv. Defaults: timestamp,severity,"+
			"event_type,actor,operation,verdict,agent.name,agent.session_id.")
}

// runAuditTail dispatches the enhanced tail. The base table / JSON path
// (no --follow / --summary / --export) is delegated to the legacy
// snapshot rendered by emitTailSnapshot.
func runAuditTail(cmd *cobra.Command, o *auditTailOpts) error {
	// Compose-validity gates first so the operator gets a clear error
	// before we touch the DB.
	if o.follow && o.summary {
		return errors.New(
			"dbounce: --follow and --summary are mutually exclusive " +
				"(--summary is a one-shot aggregation; --follow is a live " +
				"stream)")
	}
	if o.exportFormat != "" {
		if o.exportOutPath == "" {
			return errors.New(
				"dbounce: --export requires --out PATH (refusing to write " +
					"binary export to stdout)")
		}
		switch o.exportFormat {
		case exportFormatJSONL, exportFormatCSV, exportFormatOCSFBundle:
		default:
			return fmt.Errorf(
				"dbounce: unsupported --export format %q (allowed: jsonl, csv, ocsf-bundle)",
				o.exportFormat)
		}
	}
	if o.limit < 1 || o.limit > 1000 {
		return fmt.Errorf("--limit must be in 1-1000 (got %d)", o.limit)
	}
	predicates, err := parseFilterExprs(o.filters)
	if err != nil {
		return err
	}

	st, err := store.Open(o.dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	switch {
	case o.follow:
		return runAuditTailFollow(cmd, st, predicates, o)
	case o.summary:
		return runAuditTailSummary(cmd, st, predicates, o)
	case o.exportFormat != "":
		return runAuditTailExport(st, predicates, o)
	default:
		return emitTailSnapshot(cmd, st, predicates, o)
	}
}

// emitTailSnapshot is the historical `dbounce audit tail` behavior:
// pull RecentDecisions, apply optional filters, render as table or
// JSON. Centralized here so the legacy + new code paths share the
// filter pass.
func emitTailSnapshot(cmd *cobra.Command, st *store.Store, predicates []filterPredicate, o *auditTailOpts) error {
	rows, err := st.RecentDecisions(o.limit)
	if err != nil {
		return err
	}
	rows = applyFiltersToRows(rows, predicates)
	if o.asJSON {
		return writeRowsAsJSON(cmd.OutOrStdout(), rows)
	}
	writeRowsAsTable(cmd.OutOrStdout(), rows)
	return nil
}

// runAuditTailFollow streams new rows as they appear. Watermarks via
// row id so a duplicate row at the same `at` second can't slip past +
// can't be re-printed. Polls until SIGINT.
func runAuditTailFollow(cmd *cobra.Command, st *store.Store, predicates []filterPredicate, o *auditTailOpts) error {
	pollInterval := o.pollInterval
	if pollInterval <= 0 {
		pollInterval = followPollIntervalDefault
	}
	// Seed the watermark at MAX(id) so we don't replay historical rows;
	// `tail -f` semantics — only NEW rows after the operator invoked
	// follow.
	watermark, err := st.MaxDecisionID()
	if err != nil {
		return err
	}

	// SIGINT-aware context so the operator's Ctrl-C exits cleanly +
	// returns control to the shell without leaving a partial line on
	// stdout. We use a context (rather than a raw signal channel) so a
	// future test harness can pass a deadline-bound context to the same
	// loop.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runAuditTailFollowLoop(ctx, cmd.OutOrStdout(), st, predicates, o, watermark, pollInterval)
}

// runAuditTailFollowLoop is the loop body extracted so a test harness
// can drive it with a deadline-bound context (the real command uses a
// SIGINT-derived context — that's hard to fire from a Go test).
func runAuditTailFollowLoop(ctx context.Context, w io.Writer, st *store.Store, predicates []filterPredicate, o *auditTailOpts, watermark int64, pollInterval time.Duration) error {
	header := true
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			batch, err := st.RecentDecisionsAfterID(watermark, followBatchLimit)
			if err != nil {
				return err
			}
			if len(batch) == 0 {
				continue
			}
			// Apply predicates per-row + advance the watermark to the
			// max id regardless of whether the row passed the filter
			// (otherwise a filtered-out row would re-appear on every
			// subsequent poll).
			rows := make([]store.DecisionRow, 0, len(batch))
			for _, b := range batch {
				if b.ID > watermark {
					watermark = b.ID
				}
				if applyFiltersToRow(b.Row, predicates) {
					rows = append(rows, b.Row)
				}
			}
			if len(rows) == 0 {
				continue
			}
			if o.asJSON {
				if err := writeRowsAsJSON(w, rows); err != nil {
					return err
				}
			} else {
				writeRowsAsTableStreaming(w, rows, header)
				header = false
			}
		}
	}
}

// runAuditTailSummary renders count-summary tables across the spec's
// four groupings (event_type, severity_id, actor.user.name,
// api.operation). Honors --filter so an operator can ask "summary for
// just claude-code sessions" with one command.
func runAuditTailSummary(cmd *cobra.Command, st *store.Store, predicates []filterPredicate, o *auditTailOpts) error {
	rows, err := st.RecentDecisions(o.limit)
	if err != nil {
		return err
	}
	rows = applyFiltersToRows(rows, predicates)
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "total: %d\n\n", len(rows))
	// Empty audit log → still print the section headers + zero counts so
	// an automated consumer always sees the same shape.
	emitSummarySection(w, "by event_type", summarizeBy(rows, eventTypeKey))
	emitSummarySection(w, "by severity_id", summarizeBy(rows, severityIDKey))
	emitSummarySection(w, "by actor.user.name", summarizeBy(rows, actorUserNameKey))
	emitSummarySection(w, "by api.operation", summarizeBy(rows, apiOperationKey))
	return nil
}

// emitSummarySection prints one labeled grouping (sorted descending by
// count for operator readability; ties broken alphabetically).
func emitSummarySection(w io.Writer, label string, counts map[string]int) {
	fmt.Fprintln(w, label+":")
	if len(counts) == 0 {
		fmt.Fprintln(w, "  (none)")
		fmt.Fprintln(w)
		return
	}
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(counts))
	for k, v := range counts {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	for _, p := range pairs {
		fmt.Fprintf(w, "  %6d  %s\n", p.v, p.k)
	}
	fmt.Fprintln(w)
}

// summarizeBy buckets rows by a key extractor + returns a count map.
func summarizeBy(rows []store.DecisionRow, key func(store.DecisionRow) string) map[string]int {
	out := make(map[string]int)
	for _, r := range rows {
		out[key(r)]++
	}
	return out
}

func eventTypeKey(r store.DecisionRow) string {
	// All DECISION rows from the SQLite audit log carry event_type
	// "DECISION" in the OCSF projection; the synthetics (HEARTBEAT,
	// SECURITY_ALERT, ADMIN_ACTION, SESSION_ENDED, ...) never persist
	// to the decisions table — they're emitted directly through the
	// Exporter. So the per-row event_type for the summary view is
	// always "DECISION" for the rows we read here. Surface it
	// explicitly so the operator sees the grouping even when the
	// underlying value is constant.
	return string(audit.EventTypeDecision)
}

func severityIDKey(r store.DecisionRow) string {
	// Every decision row maps to OCSF severity_id=1 (Informational) per
	// [[security-team-positioning-safety-not-surveillance]]. Surface as
	// "1" (string) so the summary table format stays uniform across
	// numeric + string keys.
	return "1"
}

func actorUserNameKey(r store.DecisionRow) string {
	if r.ImpersonatedRole != "" {
		return r.ImpersonatedRole
	}
	return "(unset)"
}

func apiOperationKey(r store.DecisionRow) string {
	if r.StatementType == "" {
		return "(unknown)"
	}
	return r.StatementType
}

// runAuditTailExport opens --out, projects each filtered row to OCSF,
// writes per-format, defensively redacts SQL literals on the CSV /
// ocsf-bundle paths.
func runAuditTailExport(st *store.Store, predicates []filterPredicate, o *auditTailOpts) error {
	rows, err := st.RecentDecisions(o.limit)
	if err != nil {
		return err
	}
	rows = applyFiltersToRows(rows, predicates)
	if err := refuseOverwrite(o.exportOutPath); err != nil {
		return err
	}
	f, err := os.OpenFile(o.exportOutPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("dbounce: open export --out %s: %w", o.exportOutPath, err)
	}
	defer f.Close()
	switch o.exportFormat {
	case exportFormatJSONL:
		return exportJSONL(f, rows)
	case exportFormatCSV:
		return exportCSV(f, rows, o.csvColumnsArg)
	case exportFormatOCSFBundle:
		return exportOCSFBundle(f, rows)
	}
	return fmt.Errorf("dbounce: unsupported --export format %q", o.exportFormat)
}

// refuseOverwrite returns an error if path already exists. The export
// path is operator-owned; clobbering an existing file (which may itself
// be the SIEM-ingest archive) is the kind of mistake we want to surface
// loudly.
func refuseOverwrite(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("dbounce: refusing to overwrite existing file %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("dbounce: stat export --out %s: %w", path, err)
	}
	return nil
}

// exportJSONL writes one OCSF-projected event per line. Empty rows are
// fine (operator gets an empty file rather than an error so a wrapper
// script can always assert "file exists").
func exportJSONL(w io.Writer, rows []store.DecisionRow) error {
	enc := json.NewEncoder(w)
	for _, r := range rows {
		evt := audit.FromDecisionRow(r, 0, "", "")
		if err := enc.Encode(evt); err != nil {
			return fmt.Errorf("dbounce: jsonl encode: %w", err)
		}
	}
	return nil
}

// exportCSV writes header row + one CSV row per event. SQL-bearing
// columns are redacted via parser.RedactLiterals BEFORE the write.
// Per the spec's load-bearing sentinel test: a row whose stored
// statement contains 'sentinel-literal-XYZ' MUST not have that string
// in any CSV cell.
func exportCSV(w io.Writer, rows []store.DecisionRow, columnsArg string) error {
	columns := defaultCSVColumns
	if columnsArg != "" {
		parts := strings.Split(columnsArg, ",")
		columns = make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				columns = append(columns, p)
			}
		}
		if len(columns) == 0 {
			return errors.New(
				"dbounce: --csv-columns parsed to an empty list (pass a " +
					"comma-separated list of column names)")
		}
	}
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write(columns); err != nil {
		return fmt.Errorf("dbounce: csv header: %w", err)
	}
	for _, r := range rows {
		redacted := redactRowForExport(r)
		evt := audit.FromDecisionRow(redacted, 0, "", "")
		record := make([]string, len(columns))
		for i, col := range columns {
			record[i] = csvValueFor(col, evt, redacted)
		}
		if err := cw.Write(record); err != nil {
			return fmt.Errorf("dbounce: csv row: %w", err)
		}
	}
	return nil
}

// csvValueFor maps a column name to a string-formatted value. The
// column names are the operator-facing surface — they cover the
// default set + a small list of common nested OCSF paths.
func csvValueFor(col string, evt audit.Event, row store.DecisionRow) string {
	switch col {
	case "timestamp":
		// Emit the RFC3339 UTC timestamp so operators can sort / pivot
		// without re-parsing the OCSF unix-ms shape.
		return time.UnixMilli(evt.Time).UTC().Format(time.RFC3339)
	case "severity":
		return evt.Severity
	case "severity_id":
		return strconv.Itoa(evt.SeverityID)
	case "event_type":
		return eventTypeFromEvent(evt)
	case "actor":
		if evt.Actor != nil && evt.Actor.User != nil && evt.Actor.User.Name != "" {
			return evt.Actor.User.Name
		}
		return ""
	case "operation":
		return evt.API.Operation
	case "verdict":
		if evt.Unmapped != nil {
			return evt.Unmapped.IAMJIT.Verdict
		}
		return ""
	case "agent.name":
		if evt.Unmapped != nil && evt.Unmapped.IAMJIT.Agent != nil {
			return evt.Unmapped.IAMJIT.Agent.Name
		}
		return ""
	case "agent.session_id":
		if evt.Unmapped != nil && evt.Unmapped.IAMJIT.Agent != nil {
			return evt.Unmapped.IAMJIT.Agent.SessionID
		}
		return ""
	case "dialect":
		return row.Dialect
	case "statement":
		// SQL text — already redacted by redactRowForExport upstream.
		return row.Statement
	case "tables":
		return strings.Join(row.TablesTouched, "|")
	case "mode":
		return row.ModeAtDecision
	}
	// Unknown column name — fall back to a JSON-pointer-style lookup
	// against the projected event so an operator can ask for any nested
	// OCSF field without us having to enumerate. Empty string when the
	// path doesn't resolve.
	if v, ok := lookupNestedString(evt, col); ok {
		return v
	}
	return ""
}

// eventTypeFromEvent returns the dbounce native EventType when the
// projection carries it under unmapped.iam_jit.event_type; otherwise
// "DECISION" (the implicit type for rows in the decisions table).
func eventTypeFromEvent(evt audit.Event) string {
	if evt.Unmapped != nil && evt.Unmapped.IAMJIT.EventType != "" {
		return evt.Unmapped.IAMJIT.EventType
	}
	return string(audit.EventTypeDecision)
}

// redactRowForExport returns a copy of row with Statement passed
// through parser.RedactLiterals + StatementRedacted=true. The original
// row is left untouched so the in-memory audit-tail snapshot rendering
// stays operator-faithful; only the export path gets the redacted
// view. Per the spec: defensive redaction on read for the export
// surface.
//
// We also redact every entry of ParseErrors + UpstreamResponseSummary —
// the proxy can include raw SQL snippets in those (a syntax error
// message embeds the offending fragment; the upstream's failure reply
// can echo the literal). Per the SQL-PII story, anywhere the proxy
// touched a literal is a potential leak.
func redactRowForExport(row store.DecisionRow) store.DecisionRow {
	out := row
	if out.Statement != "" {
		out.Statement = parser.RedactLiterals(out.Statement)
	}
	out.StatementRedacted = true
	if out.DecisionReason != "" {
		out.DecisionReason = parser.RedactLiterals(out.DecisionReason)
	}
	if out.UpstreamResponseSummary != "" {
		out.UpstreamResponseSummary = parser.RedactLiterals(out.UpstreamResponseSummary)
	}
	if len(out.ParseErrors) > 0 {
		redactedErrs := make([]string, len(out.ParseErrors))
		for i, e := range out.ParseErrors {
			redactedErrs[i] = parser.RedactLiterals(e)
		}
		out.ParseErrors = redactedErrs
	}
	return out
}

// detectionFindingBundle is the JSON wrapper for the OCSF Detection
// Finding ocsf-bundle export. SIEM batch ingestors expect either a
// JSON array of findings or an object with a `findings` key — we ship
// the object form so a future addition (bundle metadata: producer +
// emitted_at) doesn't break the on-disk shape.
type detectionFindingBundle struct {
	Metadata bundleMetadata    `json:"metadata"`
	Findings []detectionFinding `json:"findings"`
}

type bundleMetadata struct {
	Product       audit.Product_ `json:"product"`
	SchemaVersion string         `json:"schema_version"`
	EmittedAt     int64          `json:"emitted_at_unix_ms"`
	Count         int            `json:"count"`
}

// detectionFinding is the OCSF v1.1.0 class-2004 envelope. We share the
// same Metadata + Actor + Resource + Endpoint sub-objects as the
// API-Activity event (re-use audit package types). The finding
// .observables array carries the original API Activity event under a
// JSON observable so the downstream consumer doesn't lose any context
// the decision row carried.
type detectionFinding struct {
	Metadata    audit.Metadata    `json:"metadata"`
	Time        int64             `json:"time"`
	ClassUID    int               `json:"class_uid"`
	ClassName   string            `json:"class_name"`
	CategoryUID int               `json:"category_uid"`
	CategoryName string           `json:"category_name"`
	ActivityID  int               `json:"activity_id"`
	ActivityName string           `json:"activity_name"`
	TypeUID     int               `json:"type_uid"`
	TypeName    string            `json:"type_name"`
	SeverityID  int               `json:"severity_id"`
	Severity    string            `json:"severity"`
	StatusID    int               `json:"status_id"`
	Status      string            `json:"status"`
	Message     string            `json:"message"`
	FindingInfo findingInfo       `json:"finding_info"`
	Observables []observable      `json:"observables,omitempty"`
	Unmapped    *audit.Unmapped   `json:"unmapped,omitempty"`
}

type findingInfo struct {
	UID         string `json:"uid"`
	Title       string `json:"title"`
	CreatedTime int64  `json:"created_time"`
}

type observable struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value any    `json:"value,omitempty"`
}

// exportOCSFBundle wraps the filtered + redacted rows as Detection
// Findings + writes the whole bundle as one JSON object. Bulk-ingest
// path. Per the spec: literals also redacted (we pass through
// redactRowForExport before constructing the Finding).
func exportOCSFBundle(w io.Writer, rows []store.DecisionRow) error {
	now := time.Now().UTC().UnixMilli()
	findings := make([]detectionFinding, 0, len(rows))
	for i, r := range rows {
		redacted := redactRowForExport(r)
		evt := audit.FromDecisionRow(redacted, int64(i+1), "", "")
		findings = append(findings, detectionFinding{
			Metadata: audit.Metadata{
				Version: audit.SchemaVersion,
				Product: audit.Product_{
					Name:       audit.Product,
					VendorName: audit.VendorName,
					Version:    audit.BuildVersion,
				},
			},
			Time:        evt.Time,
			ClassUID:    ocsfDetectionFindingClassUID,
			ClassName:   ocsfDetectionFindingClassName,
			CategoryUID: ocsfDetectionFindingCategoryUID,
			CategoryName: ocsfDetectionFindingCategoryName,
			ActivityID:  1, // Create — a new finding is recorded
			ActivityName: "create",
			TypeUID:     ocsfDetectionFindingClassUID*100 + 1,
			TypeName:    "Detection Finding: Create",
			SeverityID:  evt.SeverityID,
			Severity:    evt.Severity,
			StatusID:    evt.StatusID,
			Status:      evt.Status,
			Message: fmt.Sprintf("dbounce decision: %s %s verdict=%s",
				redacted.Dialect, redacted.StatementType, redacted.DecisionVerdict),
			FindingInfo: findingInfo{
				UID:         fmt.Sprintf("dbounce-decision-%d", i+1),
				Title:       "dbounce decision",
				CreatedTime: evt.Time,
			},
			Observables: []observable{
				{Name: "api_activity_event", Type: "json", Value: evt},
			},
			Unmapped: evt.Unmapped,
		})
	}
	bundle := detectionFindingBundle{
		Metadata: bundleMetadata{
			Product: audit.Product_{
				Name:       audit.Product,
				VendorName: audit.VendorName,
				Version:    audit.BuildVersion,
			},
			SchemaVersion: audit.SchemaVersion,
			EmittedAt:     now,
			Count:         len(findings),
		},
		Findings: findings,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bundle)
}

// writeRowsAsJSON emits one JSON object per row, matching the legacy
// `--json` shape. Extracted so --follow + --json reuses the same line
// shape an operator's downstream tooling already parses.
func writeRowsAsJSON(w io.Writer, rows []store.DecisionRow) error {
	enc := json.NewEncoder(w)
	for _, r := range rows {
		rec := map[string]any{
			"at":                 r.At.UTC().Format(time.RFC3339),
			"dialect":            r.Dialect,
			"statement":          r.Statement,
			"statement_type":     r.StatementType,
			"tables":             r.TablesTouched,
			"functions":          r.FunctionsCalled,
			"is_dml":             r.IsDML,
			"is_ddl":             r.IsDDL,
			"has_mutating_node":  r.HasMutatingNode,
			"mutating_node_type": r.MutatingNodeType,
			"is_explain":         r.IsExplain,
			"is_explain_analyze": r.IsExplainAnalyze,
			"impersonated_role":  r.ImpersonatedRole,
			"parse_errors":       r.ParseErrors,
			"decision_verdict":   r.DecisionVerdict,
			"decision_reason":    r.DecisionReason,
			"mode_at_decision":   r.ModeAtDecision,
			"enforced":           r.Enforced,
			"decision_source":    r.DecisionSource,
			"profile_name":       r.ProfileName,
			"task_id":            r.TaskID,
			"is_stream":          r.IsStream,
			"stream_kind":        r.StreamKind,
			"statement_redacted": r.StatementRedacted,
		}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

// writeRowsAsTable is the legacy table renderer for the snapshot path.
func writeRowsAsTable(w io.Writer, rows []store.DecisionRow) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "(no decisions recorded yet)")
		return
	}
	fmt.Fprintf(w, "%-20s  %-6s  %-7s  %-12s  %s\n",
		"AT (UTC)", "MODE", "VERDICT", "STMT-TYPE", "STATEMENT")
	for _, r := range rows {
		printTableRow(w, r)
	}
}

// writeRowsAsTableStreaming is the --follow renderer. Header prints on
// the FIRST call only so the live tail looks like one continuous table
// rather than a re-header per tick.
func writeRowsAsTableStreaming(w io.Writer, rows []store.DecisionRow, includeHeader bool) {
	if includeHeader {
		fmt.Fprintf(w, "%-20s  %-6s  %-7s  %-12s  %s\n",
			"AT (UTC)", "MODE", "VERDICT", "STMT-TYPE", "STATEMENT")
	}
	for _, r := range rows {
		printTableRow(w, r)
	}
}

// printTableRow centralizes the legacy formatting so the --follow path +
// the snapshot path can't drift.
func printTableRow(w io.Writer, r store.DecisionRow) {
	at := r.At.UTC().Format("2006-01-02 15:04:05")
	stmt := r.Statement
	if len(stmt) > 60 {
		stmt = stmt[:57] + "..."
	}
	fmt.Fprintf(w, "%-20s  %-6s  %-7s  %-12s  %s\n",
		at, r.ModeAtDecision, r.DecisionVerdict, r.StatementType, stmt)
	if r.DecisionReason != "" {
		reason := r.DecisionReason
		if len(reason) > 80 {
			reason = reason[:77] + "..."
		}
		fmt.Fprintf(w, "%52s  %s\n", "↳", reason)
	}
}

// --- filter expression parser ------------------------------------------

// filterOp names the predicate's comparison operator.
type filterOp int

const (
	opEq filterOp = iota
	opRegex
	opGE
	opLE
)

// filterPredicate is one parsed `--filter` expression. The Field is a
// canonical OCSF path (or one of the legacy field names parseField
// accepts) and the comparison value is interpreted per Op.
type filterPredicate struct {
	Field  string
	Op     filterOp
	Value  string
	Number float64 // populated for opGE / opLE
	Regex  *regexp.Regexp
}

// parseFilterExprs parses every --filter EXPR + returns the AND-combined
// predicate slice. Empty input → nil (no filtering).
func parseFilterExprs(exprs []string) ([]filterPredicate, error) {
	if len(exprs) == 0 {
		return nil, nil
	}
	out := make([]filterPredicate, 0, len(exprs))
	for _, e := range exprs {
		p, err := parseOneFilterExpr(e)
		if err != nil {
			return nil, fmt.Errorf("dbounce: invalid --filter %q: %w", e, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// parseOneFilterExpr parses a single expression. The grammar is
// permissive about operator detection — we try in this order:
//
//   field>=N    numeric ≥
//   field<=N    numeric ≤
//   field=val   string equality
//   field~re    regex
//
// `>=` + `<=` are checked BEFORE `=` so `severity_id>=3` doesn't
// silently parse as field="severity_id>" + value="=3".
func parseOneFilterExpr(expr string) (filterPredicate, error) {
	for _, op := range []struct {
		token string
		kind  filterOp
	}{
		{">=", opGE},
		{"<=", opLE},
	} {
		if idx := strings.Index(expr, op.token); idx > 0 {
			field := strings.TrimSpace(expr[:idx])
			val := strings.TrimSpace(expr[idx+len(op.token):])
			if field == "" || val == "" {
				return filterPredicate{}, fmt.Errorf("missing field or value around %q", op.token)
			}
			n, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return filterPredicate{}, fmt.Errorf(
					"numeric value required for %q (got %q)", op.token, val)
			}
			return filterPredicate{Field: field, Op: op.kind, Value: val, Number: n}, nil
		}
	}
	if idx := strings.Index(expr, "~"); idx > 0 {
		field := strings.TrimSpace(expr[:idx])
		val := expr[idx+1:]
		if field == "" || val == "" {
			return filterPredicate{}, errors.New("missing field or value around \"~\"")
		}
		re, err := regexp.Compile(val)
		if err != nil {
			return filterPredicate{}, fmt.Errorf("invalid regex %q: %w", val, err)
		}
		return filterPredicate{Field: field, Op: opRegex, Value: val, Regex: re}, nil
	}
	if idx := strings.Index(expr, "="); idx > 0 {
		field := strings.TrimSpace(expr[:idx])
		val := expr[idx+1:]
		if field == "" {
			return filterPredicate{}, errors.New("missing field around \"=\"")
		}
		return filterPredicate{Field: field, Op: opEq, Value: val}, nil
	}
	return filterPredicate{}, errors.New(
		"expected field=value, field~regex, field>=N, or field<=N")
}

// applyFiltersToRows returns the subset of rows that pass EVERY
// predicate (AND semantics). nil predicates → unchanged slice.
func applyFiltersToRows(rows []store.DecisionRow, predicates []filterPredicate) []store.DecisionRow {
	if len(predicates) == 0 {
		return rows
	}
	out := make([]store.DecisionRow, 0, len(rows))
	for _, r := range rows {
		if applyFiltersToRow(r, predicates) {
			out = append(out, r)
		}
	}
	return out
}

// applyFiltersToRow projects the row to its OCSF Event + evaluates
// every predicate. Empty predicate list → true.
func applyFiltersToRow(row store.DecisionRow, predicates []filterPredicate) bool {
	if len(predicates) == 0 {
		return true
	}
	evt := audit.FromDecisionRow(row, 0, "", "")
	for _, p := range predicates {
		if !predicateMatchesEvent(p, evt, row) {
			return false
		}
	}
	return true
}

// predicateMatchesEvent evaluates one predicate against the projected
// event + the original row (for non-OCSF fields like statement_type
// the operator might want to filter on).
func predicateMatchesEvent(p filterPredicate, evt audit.Event, row store.DecisionRow) bool {
	switch p.Op {
	case opEq:
		v, ok := lookupNestedString(evt, p.Field)
		if !ok {
			// Fallbacks for OCSF-named numeric fields stored on the
			// Event as ints (severity_id, activity_id, status_id).
			if n, nok := lookupNestedNumber(evt, p.Field); nok {
				return strconv.Itoa(int(n)) == p.Value
			}
			return false
		}
		return v == p.Value
	case opRegex:
		v, ok := lookupNestedString(evt, p.Field)
		if !ok {
			if n, nok := lookupNestedNumber(evt, p.Field); nok {
				return p.Regex.MatchString(strconv.Itoa(int(n)))
			}
			return false
		}
		return p.Regex.MatchString(v)
	case opGE:
		n, ok := lookupNestedNumber(evt, p.Field)
		if !ok {
			return false
		}
		return n >= p.Number
	case opLE:
		n, ok := lookupNestedNumber(evt, p.Field)
		if !ok {
			return false
		}
		return n <= p.Number
	}
	return false
}

// lookupNestedString resolves a dotted OCSF path against the projected
// event + returns its string value. Returns (value, true) when found,
// ("", false) when the path doesn't resolve to a string (the caller
// can fall back to lookupNestedNumber).
//
// We hand-resolve the well-known paths from the spec rather than
// re-marshal+walk-JSON per row — projection-then-walk would dominate
// the follow-loop's per-row cost. The fall-through goes through the
// JSON walk so an operator can ask for any other OCSF field with the
// expected key path.
func lookupNestedString(evt audit.Event, path string) (string, bool) {
	switch path {
	case "severity":
		return evt.Severity, true
	case "status":
		return evt.Status, true
	case "status_detail":
		return evt.StatusDetail, true
	case "activity_name":
		return evt.ActivityName, true
	case "class_name":
		return evt.ClassName, true
	case "api.operation":
		return evt.API.Operation, true
	case "api.service.name":
		return evt.API.Service.Name, true
	case "api.request.uid":
		if evt.API.Request != nil {
			return evt.API.Request.UID, true
		}
		return "", true
	case "actor.user.name":
		if evt.Actor != nil && evt.Actor.User != nil {
			return evt.Actor.User.Name, true
		}
		return "", true
	case "actor.user.uid":
		if evt.Actor != nil && evt.Actor.User != nil {
			return evt.Actor.User.UID, true
		}
		return "", true
	case "actor.session.uid":
		if evt.Actor != nil && evt.Actor.Session != nil {
			return evt.Actor.Session.UID, true
		}
		return "", true
	case "src_endpoint.hostname":
		if evt.SrcEndpoint != nil {
			return evt.SrcEndpoint.Hostname, true
		}
		return "", true
	case "dst_endpoint.hostname":
		if evt.DstEndpoint != nil {
			return evt.DstEndpoint.Hostname, true
		}
		return "", true
	case "unmapped.iam_jit.event_type":
		if evt.Unmapped != nil {
			return evt.Unmapped.IAMJIT.EventType, true
		}
		return "", true
	case "unmapped.iam_jit.verdict":
		if evt.Unmapped != nil {
			return evt.Unmapped.IAMJIT.Verdict, true
		}
		return "", true
	case "unmapped.iam_jit.mode":
		if evt.Unmapped != nil {
			return evt.Unmapped.IAMJIT.Mode, true
		}
		return "", true
	case "unmapped.iam_jit.profile":
		if evt.Unmapped != nil {
			return evt.Unmapped.IAMJIT.Profile, true
		}
		return "", true
	case "unmapped.iam_jit.agent.name":
		if evt.Unmapped != nil && evt.Unmapped.IAMJIT.Agent != nil {
			return evt.Unmapped.IAMJIT.Agent.Name, true
		}
		return "", true
	case "unmapped.iam_jit.agent.version":
		if evt.Unmapped != nil && evt.Unmapped.IAMJIT.Agent != nil {
			return evt.Unmapped.IAMJIT.Agent.Version, true
		}
		return "", true
	case "unmapped.iam_jit.agent.session_id":
		if evt.Unmapped != nil && evt.Unmapped.IAMJIT.Agent != nil {
			return evt.Unmapped.IAMJIT.Agent.SessionID, true
		}
		return "", true
	case "unmapped.iam_jit.agent.detected_from":
		if evt.Unmapped != nil && evt.Unmapped.IAMJIT.Agent != nil {
			return string(evt.Unmapped.IAMJIT.Agent.DetectedFrom), true
		}
		return "", true
	}
	// Fallback: walk into unmapped.iam_jit.ext.* for the dbounce-specific
	// SQL-shaped fields (tables_touched, mutating_node_type, dialect,
	// etc.). Operators use these to filter "all events touching the
	// 'finance' schema" or "all events with mutating_node_type=DELETE".
	const extPrefix = "unmapped.iam_jit.ext."
	if strings.HasPrefix(path, extPrefix) && evt.Unmapped != nil {
		key := strings.TrimPrefix(path, extPrefix)
		if v, ok := evt.Unmapped.IAMJIT.Ext[key]; ok {
			switch tv := v.(type) {
			case string:
				return tv, true
			case []string:
				return strings.Join(tv, ","), true
			case bool:
				if tv {
					return "true", true
				}
				return "false", true
			case float64:
				return strconv.FormatFloat(tv, 'g', -1, 64), true
			case int:
				return strconv.Itoa(tv), true
			case int64:
				return strconv.FormatInt(tv, 10), true
			}
		}
	}
	return "", false
}

// lookupNestedNumber resolves a dotted path to a numeric field. Used
// for the >= / <= operators on severity_id / activity_id / status_id +
// for fallback equality when an OCSF numeric field is asked for as a
// string-equality predicate.
func lookupNestedNumber(evt audit.Event, path string) (float64, bool) {
	switch path {
	case "severity_id":
		return float64(evt.SeverityID), true
	case "activity_id":
		return float64(evt.ActivityID), true
	case "status_id":
		return float64(evt.StatusID), true
	case "class_uid":
		return float64(evt.ClassUID), true
	case "category_uid":
		return float64(evt.CategoryUID), true
	case "type_uid":
		return float64(evt.TypeUID), true
	case "time":
		return float64(evt.Time), true
	case "src_endpoint.port":
		if evt.SrcEndpoint != nil {
			return float64(evt.SrcEndpoint.Port), true
		}
		return 0, false
	case "dst_endpoint.port":
		if evt.DstEndpoint != nil {
			return float64(evt.DstEndpoint.Port), true
		}
		return 0, false
	}
	const extPrefix = "unmapped.iam_jit.ext."
	if strings.HasPrefix(path, extPrefix) && evt.Unmapped != nil {
		key := strings.TrimPrefix(path, extPrefix)
		if v, ok := evt.Unmapped.IAMJIT.Ext[key]; ok {
			switch tv := v.(type) {
			case float64:
				return tv, true
			case int:
				return float64(tv), true
			case int64:
				return float64(tv), true
			}
		}
	}
	return 0, false
}

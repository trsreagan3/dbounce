// `dbounce diagnostics bundle` per #277 (dbounce diagnostics bundle).
//
// Produces a ZIP bundle a support engineer (or the operator themselves
// per [[basic-app-hygiene-features]]) can attach to a bug report
// without leaking secrets. Mirrors the sibling kbounce + ibounce
// implementations of the same feature so cross-product UX is uniform
// per [[cross-product-agent-parity]]:
//
//   - subcommand:    dbounce diagnostics bundle
//   - alias:         dbounce diag
//   - default out:   ./dbounce-diagnostics-{timestamp}.zip
//   - flags:         --out PATH, --include-audit-tail N, --no-audit
//
// What ships in the bundle (each as a separate file inside the zip):
//
//   1.  version.txt                — `dbounce --version` output + Go +
//                                    OS/ARCH from runtime
//   2.  config.json                — REDACTED ConfigBundle (reuses #275
//                                    export path; no credentials by
//                                    construction)
//   3.  profile.txt                — active profile name + sha256 of
//                                    profiles.yaml + loaded-at timestamp
//   4.  audit-tail.jsonl           — last N decisions, with EVERY
//                                    statement scrubbed via
//                                    parser.RedactLiterals + user
//                                    identifiers (impersonated_role,
//                                    profile_name) replaced with a
//                                    stable sha256-truncated hash
//                                    (omitted entirely when --no-audit)
//   5.  health.json                — /healthz response (best-effort;
//                                    when unreachable, a placeholder
//                                    with the reason is written instead)
//   6.  errors.tail.txt            — last 200 lines of an operator-
//                                    configured stderr capture file
//                                    (DBOUNCE_STDERR_LOG env var or
//                                    --stderr-log flag). Skipped + a
//                                    note appended to NOTES when no
//                                    file is configured.
//   7.  sqlite-stats.json          — SQLite file size, schema_version,
//                                    per-table row counts (NO row
//                                    contents)
//   8.  listener-status.json       — wire-port, mgmt-port, dialect,
//                                    current connections count (NOT
//                                    remote IPs). Sourced from /healthz
//                                    + best-effort.
//   9.  slow-queries.jsonl         — last N=20 audit rows ordered by
//                                    decision verdict + statement type
//                                    (no per-row duration on D-Slice 1;
//                                    we ship statement_type + table
//                                    list + row sequence as a
//                                    best-effort proxy)
//  10.  queue-depth.json           — pending_audit_events + pending_
//                                    prompts row counts (per #277 the
//                                    natural-section addition the spec
//                                    flagged as expected)
//  11.  env.txt                    — names of DBOUNCE_* env vars
//                                    (values REDACTED)
//  12.  notes.txt                  — non-fatal collection issues
//                                    encountered while building the
//                                    bundle (a /healthz timeout +
//                                    a missing stderr-log file show
//                                    up here)
//  13.  manifest.json              — file list + per-file sha256 +
//                                    bundle version + generated-at
//                                    timestamp
//
// What MUST be redacted (per #277):
//
//   - tokens, webhook URLs, alert-route destinations
//   - hostnames / IPs / database connection strings
//   - user identifiers (replaced with stable sha256-truncated hash)
//   - SQL literals (parser.RedactLiterals reused — dbounce is uniquely
//     exposed here because audit rows carry the raw SQL)
//   - environment variable VALUES (names only)
//   - certs / keys
//
// The redaction is BELT + SUSPENDERS:
//
//   - the config.json reuses #275's existing export which by
//     construction omits webhook URLs, credentials, hostnames, etc.
//   - SQL literals are scrubbed at OUR write site via
//     parser.RedactLiterals even when the operator has
//     --redact-literals=false on the running proxy (the audit row's
//     raw form might still be replayable; we re-redact defensively)
//   - URL/IP/secret patterns are stripped from any stderr line that
//     escapes the basic capture
//
// Per [[creates-never-mutates]]: this command is read-only. It opens
// state.db read-only, hits /healthz over HTTP GET, never mutates
// anything. Per [[self-host-zero-billing-dependency]]: no network call
// to any address other than the operator-supplied --mgmt-url (a
// loopback /healthz by default).
//
// Cross-process: this command runs in the CLI process. The running
// `dbounce run` process is NOT required — the bundle is still useful
// without it (config + audit tail + SQLite stats + version all come
// from on-disk state). Sections that need a live proxy (health.json,
// listener-status.json) gracefully fall back to a placeholder + the
// notes file records why.

package cli

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/parser"
	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
	"github.com/trsreagan3/dbounce/internal/store"
)

// diagnosticsBundleVersion is bumped when the bundle SHAPE changes (a
// new section, a renamed file). Additive section additions don't bump
// because consumers tolerate unknown files via the manifest.
const diagnosticsBundleVersion = 1

// diagnosticsBundleFormat is the magic string in the manifest so a
// support engineer can tell at a glance which product produced the
// bundle. Sibling agents in kbounce + ibounce use their own product-
// namespaced strings.
const diagnosticsBundleFormat = "dbounce.diagnostics"

// defaultAuditTailRows is the audit-tail row cap when --include-audit-
// tail is not passed. Matches the #277 spec ("last 200").
const defaultAuditTailRows = 200

// slowQueriesRows is the row cap for the slow-queries.jsonl section.
// D-Slice 1 has no per-row duration; this is a best-effort proxy on
// statement_type + table count. The cap matches the #277 spec.
const slowQueriesRows = 20

// userIdHashLen is the truncation length for stable user-id hashes.
// Same truncation length kbounce + ibounce use so a cross-product
// reviewer recognizes the shape.
const userIdHashLen = 12

// newDiagnosticsCmd implements `dbounce diagnostics ...`. The
// `bundle` subcommand is the v1.0 surface; an alias `dbounce diag` is
// wired at the root level so the spec's shorthand still resolves.
func newDiagnosticsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diagnostics",
		Short: "Produce a redacted ZIP bundle for support / self-debug",
		Long: `dbounce diagnostics produces a ZIP bundle a support engineer
(or the operator themselves) can attach to a bug report WITHOUT
leaking secrets. The bundle contains version + redacted config +
profile fingerprint + redacted audit tail + health snapshot + SQLite
stats + listener status + queue depth + env var names + a manifest.

What MUST be redacted (defensively, even when the running proxy was
not configured for redaction):

  - tokens, webhook URLs, alert-route destinations
  - hostnames / IPs / database connection strings
  - user identifiers (replaced with a stable truncated hash)
  - SQL literals (the dbounce-specific PII risk — see the
    --redact-literals flag's docstring on dbounce run for the
    deeper rationale)
  - environment variable VALUES (only the names ship)
  - certs / keys

The bundle is the operator's to share. Review notes.txt + manifest.json
before forwarding to a third party.

Sibling agents in kbounce + ibounce ship the same subcommand shape +
flag names per the cross-product-agent-parity contract.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("diagnostics", cmd)
	cmd.AddCommand(newDiagnosticsBundleCmd())
	return cmd
}

// newDiagnosticsDiagAliasCmd is the `dbounce diag` shorthand wired at
// the root level. Forwards to `diagnostics bundle` so the cross-product
// muscle-memory works (`kbounce diag` / `ibounce diag` resolve the
// same way per [[cross-product-agent-parity]]).
func newDiagnosticsDiagAliasCmd() *cobra.Command {
	cmd := newDiagnosticsBundleCmd()
	cmd.Use = "diag"
	cmd.Short = "Alias for `dbounce diagnostics bundle`"
	return cmd
}

// newDiagnosticsBundleCmd is the workhorse. All flag handling +
// collection logic lives here.
func newDiagnosticsBundleCmd() *cobra.Command {
	var (
		outPath          string
		includeAuditTail int
		noAudit          bool
		dbPath           string
		profilesPath     string
		dialectStr       string
		mgmtURL          string
		stderrLog        string
		actor            string
		insecureTLS      bool
		fetchTimeout     time.Duration
	)
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Write a redacted diagnostics ZIP to ./dbounce-diagnostics-{timestamp}.zip",
		Long: `Collects version + redacted config + profile fingerprint +
redacted audit tail + health snapshot + SQLite stats + listener
status + queue depth + env var names into a single ZIP bundle.

The default output path is ./dbounce-diagnostics-{UTC-timestamp}.zip
in the current working directory. Override with --out.

The bundle is read-only (per [[creates-never-mutates]]) and makes ONE
HTTP GET to the supplied --mgmt-url (loopback /healthz by default,
per [[self-host-zero-billing-dependency]]).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dialect, err := proxy.ParseDialect(dialectStr)
			if err != nil {
				return err
			}
			if includeAuditTail < 0 {
				return fmt.Errorf("--include-audit-tail must be >= 0 (got %d)", includeAuditTail)
			}
			if includeAuditTail == 0 {
				includeAuditTail = defaultAuditTailRows
			}
			if outPath == "" {
				outPath = defaultBundleOutPath(time.Now().UTC())
			}

			params := collectDiagnosticsParams{
				DBPath:           dbPath,
				ProfilesPath:     profilesPath,
				Dialect:          dialect,
				MgmtURL:          mgmtURL,
				StderrLogPath:    resolveStderrLogPath(stderrLog),
				IncludeAuditTail: includeAuditTail,
				NoAudit:          noAudit,
				FetchTimeout:     fetchTimeout,
				InsecureTLS:      insecureTLS,
				Actor:            resolveActor(actor),
				GeneratedAt:      time.Now().UTC(),
			}
			zipBytes, manifest, cerr := collectDiagnostics(params)
			if cerr != nil {
				return cerr
			}
			if werr := writeBundleAtomic(outPath, zipBytes); werr != nil {
				return werr
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"wrote dbounce diagnostics bundle to %s (%d files, %d bytes).\n",
				outPath, len(manifest.Files), len(zipBytes))
			for _, n := range manifest.Notes {
				fmt.Fprintf(cmd.OutOrStdout(), "  note: %s\n", n)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "",
		"Output ZIP path. Default: ./dbounce-diagnostics-{UTC-timestamp}.zip.")
	cmd.Flags().IntVar(&includeAuditTail, "include-audit-tail", defaultAuditTailRows,
		"Number of audit rows to include (REDACTED). 0 means use the default (200). Ignored when --no-audit.")
	cmd.Flags().BoolVar(&noAudit, "no-audit", false,
		"Exclude the audit-tail section entirely.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"profiles.yaml path (default: ~/.dbounce/profiles.yaml, or DBOUNCE_PROFILES_PATH env).")
	cmd.Flags().StringVar(&dialectStr, "dialect", "postgres",
		"Runtime dialect of the deployment being diagnosed (postgres|mysql|snowflake|bigquery).")
	cmd.Flags().StringVar(&mgmtURL, "mgmt-url", "http://127.0.0.1:8768/healthz",
		"URL of the running proxy's /healthz endpoint. Best-effort; unreachable = placeholder.")
	cmd.Flags().StringVar(&stderrLog, "stderr-log", "",
		"Path to an operator-managed stderr capture file. Last 200 lines included (redacted). "+
			"Defaults to DBOUNCE_STDERR_LOG env var when unset.")
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id stamped on the bundle's manifest. Defaults to $USER then 'unknown'.")
	cmd.Flags().BoolVar(&insecureTLS, "insecure-tls", false,
		"Skip TLS verification on the /healthz fetch (only for self-signed cert deployments).")
	cmd.Flags().DurationVar(&fetchTimeout, "fetch-timeout", 5*time.Second,
		"HTTP timeout for the /healthz fetch.")
	return cmd
}

// collectDiagnosticsParams bundles the inputs to collectDiagnostics
// so the signature stays small + a future flag addition (e.g.
// --include-pcap) lands without reshuffling.
type collectDiagnosticsParams struct {
	DBPath           string
	ProfilesPath     string
	Dialect          proxy.Dialect
	MgmtURL          string
	StderrLogPath    string
	IncludeAuditTail int
	NoAudit          bool
	FetchTimeout     time.Duration
	InsecureTLS      bool
	Actor            string
	GeneratedAt      time.Time
}

// DiagnosticsManifest is what manifest.json carries. Exported so tests
// can unmarshal + assert the file listing without re-parsing the zip.
type DiagnosticsManifest struct {
	Format        string                `json:"format"`
	FormatVersion int                   `json:"format_version"`
	GeneratedAt   string                `json:"generated_at"`
	GeneratedBy   string                `json:"generated_by"`
	Product       string                `json:"product"`
	Version       string                `json:"version"`
	Dialect       string                `json:"dialect"`
	Files         []DiagnosticsManifestFile `json:"files"`
	Notes         []string              `json:"notes,omitempty"`
}

// DiagnosticsManifestFile names one file inside the zip + its sha256.
// The sha256 is the hex digest of the file's raw bytes BEFORE zip
// compression (so a downstream consumer can verify integrity without
// having to interpret the zip's per-entry checksum).
type DiagnosticsManifestFile struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

// collectDiagnostics is the pure-data assembly path: assembles every
// file as a (name, bytes) pair, builds the manifest, writes the zip
// in-memory, returns the zip bytes + parsed manifest. Tests use this
// directly to assert per-file contents WITHOUT having to touch disk.
//
// Best-effort posture: any individual section that fails populates a
// notes entry but does NOT abort the whole bundle. The bundle is
// useful even when /healthz is unreachable + when stderr-log is
// missing. A FAIL in section X must not cause section Y to drop.
func collectDiagnostics(p collectDiagnosticsParams) ([]byte, *DiagnosticsManifest, error) {
	manifest := &DiagnosticsManifest{
		Format:        diagnosticsBundleFormat,
		FormatVersion: diagnosticsBundleVersion,
		GeneratedAt:   p.GeneratedAt.Format(time.RFC3339),
		GeneratedBy:   p.Actor,
		Product:       "dbounce",
		Version:       versionString(),
		Dialect:       string(p.Dialect),
	}

	// Ordered list so manifest entries + zip entries are deterministic
	// (important for test assertions + reproducibility on a per-second
	// re-run).
	type file struct {
		name string
		data []byte
	}
	var files []file
	addFile := func(name string, data []byte) {
		files = append(files, file{name: name, data: data})
	}
	addNote := func(format string, args ...any) {
		manifest.Notes = append(manifest.Notes, fmt.Sprintf(format, args...))
	}

	// 1. version.txt
	addFile("version.txt", collectVersionFile())

	// 2. config.json (reuses #275 export path — no creds by construction)
	if data, err := collectConfigFile(p); err != nil {
		addNote("config.json: %v", err)
		addFile("config.json", placeholderJSON("config_collection_failed", err.Error()))
	} else {
		addFile("config.json", data)
	}

	// 3. profile.txt
	addFile("profile.txt", collectProfileFile(p))

	// 4. audit-tail.jsonl (skipped on --no-audit)
	if p.NoAudit {
		addNote("audit-tail.jsonl: omitted (--no-audit)")
	} else {
		data, err := collectAuditTailFile(p)
		if err != nil {
			addNote("audit-tail.jsonl: %v", err)
			addFile("audit-tail.jsonl", []byte(""))
		} else {
			addFile("audit-tail.jsonl", data)
		}
	}

	// 5. health.json (best-effort /healthz fetch)
	health, healthErr := fetchHealthz(p.MgmtURL, p.FetchTimeout, p.InsecureTLS)
	if healthErr != nil {
		addNote("health.json: /healthz unreachable: %v", healthErr)
		addFile("health.json", placeholderJSON("healthz_unreachable", healthErr.Error()))
	} else {
		addFile("health.json", health)
	}

	// 6. errors.tail.txt (operator-managed stderr capture file)
	if p.StderrLogPath == "" {
		addNote("errors.tail.txt: no stderr-log configured (--stderr-log or DBOUNCE_STDERR_LOG)")
		addFile("errors.tail.txt", []byte("(no stderr-log configured)\n"))
	} else {
		data, err := collectStderrTail(p.StderrLogPath)
		if err != nil {
			addNote("errors.tail.txt: %v", err)
			addFile("errors.tail.txt", []byte(fmt.Sprintf("(stderr-log read failed: %v)\n", err)))
		} else {
			addFile("errors.tail.txt", data)
		}
	}

	// 7. sqlite-stats.json
	if data, err := collectSQLiteStats(p); err != nil {
		addNote("sqlite-stats.json: %v", err)
		addFile("sqlite-stats.json", placeholderJSON("sqlite_stats_failed", err.Error()))
	} else {
		addFile("sqlite-stats.json", data)
	}

	// 8. listener-status.json (sourced from /healthz; reuses fetch above)
	listenerData := collectListenerStatusFromHealthz(health, healthErr, p)
	addFile("listener-status.json", listenerData)

	// 9. slow-queries.jsonl (skipped on --no-audit)
	if p.NoAudit {
		addNote("slow-queries.jsonl: omitted (--no-audit)")
	} else {
		data, err := collectSlowQueriesFile(p)
		if err != nil {
			addNote("slow-queries.jsonl: %v", err)
			addFile("slow-queries.jsonl", []byte(""))
		} else {
			addFile("slow-queries.jsonl", data)
		}
	}

	// 10. queue-depth.json (the natural-section addition #277 flagged)
	if data, err := collectQueueDepthFile(p); err != nil {
		addNote("queue-depth.json: %v", err)
		addFile("queue-depth.json", placeholderJSON("queue_depth_failed", err.Error()))
	} else {
		addFile("queue-depth.json", data)
	}

	// 11. env.txt (names only — never values)
	addFile("env.txt", collectEnvNamesFile())

	// 12. notes.txt (rendered from manifest.Notes — operator-visible
	// summary without having to read the manifest JSON). Written
	// LATE so it includes everything accumulated above.
	addFile("notes.txt", renderNotesFile(manifest.Notes))

	// 13. manifest.json — built LAST so it sees every other file.
	for _, f := range files {
		sum := sha256.Sum256(f.data)
		manifest.Files = append(manifest.Files, DiagnosticsManifestFile{
			Name:   f.name,
			Size:   len(f.data),
			SHA256: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(manifest.Files, func(i, j int) bool {
		return manifest.Files[i].Name < manifest.Files[j].Name
	})
	manifestJSON, merr := json.MarshalIndent(manifest, "", "  ")
	if merr != nil {
		return nil, nil, fmt.Errorf("encode manifest: %w", merr)
	}
	manifestJSON = append(manifestJSON, '\n')

	// Assemble zip in memory.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Write the data files in sorted name order so a re-run on the
	// same inputs produces a bit-identical bundle (sha-able for tests).
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	for _, f := range files {
		header := &zip.FileHeader{
			Name:     f.name,
			Method:   zip.Deflate,
			Modified: p.GeneratedAt,
		}
		w, err := zw.CreateHeader(header)
		if err != nil {
			_ = zw.Close()
			return nil, nil, fmt.Errorf("zip create %q: %w", f.name, err)
		}
		if _, err := w.Write(f.data); err != nil {
			_ = zw.Close()
			return nil, nil, fmt.Errorf("zip write %q: %w", f.name, err)
		}
	}
	// Manifest last so an unzip listing shows it at the bottom (the
	// natural place a reviewer looks for a TOC).
	mh := &zip.FileHeader{
		Name:     "manifest.json",
		Method:   zip.Deflate,
		Modified: p.GeneratedAt,
	}
	mw, err := zw.CreateHeader(mh)
	if err != nil {
		_ = zw.Close()
		return nil, nil, fmt.Errorf("zip create manifest: %w", err)
	}
	if _, err := mw.Write(manifestJSON); err != nil {
		_ = zw.Close()
		return nil, nil, fmt.Errorf("zip write manifest: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, nil, fmt.Errorf("zip close: %w", err)
	}
	return buf.Bytes(), manifest, nil
}

// defaultBundleOutPath returns the spec-defined default output path
// for the bundle: ./dbounce-diagnostics-{UTC-timestamp}.zip.
func defaultBundleOutPath(now time.Time) string {
	return fmt.Sprintf("./dbounce-diagnostics-%s.zip",
		now.Format("20060102T150405Z"))
}

// resolveStderrLogPath returns the explicit flag value when non-empty,
// otherwise the DBOUNCE_STDERR_LOG env var.
func resolveStderrLogPath(flag string) string {
	if flag != "" {
		return flag
	}
	return os.Getenv("DBOUNCE_STDERR_LOG")
}

// placeholderJSON returns a small JSON document recording a section
// failure. Written in place of the real section so the consumer's
// JSON-parser doesn't choke on an empty file.
func placeholderJSON(reason, detail string) []byte {
	b, _ := json.MarshalIndent(map[string]any{
		"placeholder": true,
		"reason":      reason,
		"detail":      detail,
	}, "", "  ")
	return append(b, '\n')
}

// collectVersionFile writes version + commit + build time + Go +
// OS/ARCH so a support engineer sees the binary's full identity at a
// glance.
func collectVersionFile() []byte {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", versionString())
	fmt.Fprintf(&sb, "go=%s\n", runtime.Version())
	fmt.Fprintf(&sb, "os=%s\n", runtime.GOOS)
	fmt.Fprintf(&sb, "arch=%s\n", runtime.GOARCH)
	return []byte(sb.String())
}

// collectConfigFile reuses the #275 ConfigBundle export path. The
// resulting JSON by construction omits credentials, hostnames, and
// webhook URLs (the export ships the gating SURFACE — patterns +
// profile shapes — not the transport configuration).
func collectConfigFile(p collectDiagnosticsParams) ([]byte, error) {
	bundle, err := buildConfigBundle(buildBundleParams{
		DBPath:       p.DBPath,
		ProfilesPath: p.ProfilesPath,
		Dialect:      p.Dialect,
		ExportedBy:   p.Actor,
	})
	if err != nil {
		return nil, err
	}
	// Zero the path field defensively: the existing export keeps the
	// profiles.yaml path for change-management context, but for a
	// support bundle the absolute path on the operator's laptop is a
	// hostname-shaped leak. Replace with a stable marker.
	if bundle.Profiles.Path != "" {
		bundle.Profiles.Path = "<redacted>"
	}
	b, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal config bundle: %w", err)
	}
	return append(b, '\n'), nil
}

// collectProfileFile records the active profile name + the sha256 of
// the profiles.yaml file + the file's mtime ("loaded-at" proxy). The
// name is NOT a secret — it's the operator-chosen string the running
// proxy is using. The sha256 lets a support engineer verify a
// reported profile matches the one in the bundle.
func collectProfileFile(p collectDiagnosticsParams) []byte {
	var sb strings.Builder
	activeName := os.Getenv(envProfileVar)
	fmt.Fprintf(&sb, "active_profile_env=%s\n", activeName)
	pp := p.ProfilesPath
	if pp == "" {
		if rp, err := profile.DefaultProfilesPath(); err == nil {
			pp = rp
		}
	}
	// Record HASH only, not the path itself.
	if pp == "" {
		fmt.Fprintln(&sb, "profiles_yaml=<not_resolved>")
		return []byte(sb.String())
	}
	info, err := os.Stat(pp)
	if err != nil {
		fmt.Fprintf(&sb, "profiles_yaml=<missing> (%v)\n", err)
		return []byte(sb.String())
	}
	data, err := os.ReadFile(pp)
	if err != nil {
		fmt.Fprintf(&sb, "profiles_yaml=<read_error> (%v)\n", err)
		return []byte(sb.String())
	}
	sum := sha256.Sum256(data)
	fmt.Fprintf(&sb, "profiles_yaml_sha256=%s\n", hex.EncodeToString(sum[:]))
	fmt.Fprintf(&sb, "profiles_yaml_size_bytes=%d\n", info.Size())
	fmt.Fprintf(&sb, "profiles_yaml_loaded_at=%s\n", info.ModTime().UTC().Format(time.RFC3339))
	return []byte(sb.String())
}

// collectAuditTailFile writes JSONL of the last N decisions. Every
// row is REDACTED:
//
//   - Statement passed through parser.RedactLiterals (defensive — even
//     when the running proxy had --redact-literals=false)
//   - DecisionReason scrubbed of any URL / IP / email pattern
//   - ImpersonatedRole + ProfileName + TaskID replaced with a stable
//     truncated sha256 hash so a reviewer can correlate rows without
//     learning the cleartext identity
func collectAuditTailFile(p collectDiagnosticsParams) ([]byte, error) {
	st, err := store.Open(p.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	rows, err := st.RecentDecisions(p.IncludeAuditTail)
	if err != nil {
		return nil, fmt.Errorf("recent decisions: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range rows {
		rec := map[string]any{
			"at":                 r.At.UTC().Format(time.RFC3339),
			"dialect":            r.Dialect,
			"statement":          parser.RedactLiterals(r.Statement),
			"statement_type":     r.StatementType,
			"tables":             r.TablesTouched,
			"functions":          r.FunctionsCalled,
			"is_dml":             r.IsDML,
			"is_ddl":             r.IsDDL,
			"has_mutating_node":  r.HasMutatingNode,
			"mutating_node_type": r.MutatingNodeType,
			"is_explain":         r.IsExplain,
			"is_explain_analyze": r.IsExplainAnalyze,
			"impersonated_role":  hashUserID(r.ImpersonatedRole),
			"parse_errors":       r.ParseErrors,
			"decision_verdict":   r.DecisionVerdict,
			"decision_reason":    redactFreeText(r.DecisionReason),
			"mode_at_decision":   r.ModeAtDecision,
			"enforced":           r.Enforced,
			"decision_source":    r.DecisionSource,
			"profile_name":       hashUserID(r.ProfileName),
			"task_id":            hashUserID(r.TaskID),
			"is_stream":          r.IsStream,
			"stream_kind":        r.StreamKind,
			"statement_redacted": true, // we re-redacted defensively
		}
		if err := enc.Encode(rec); err != nil {
			return nil, fmt.Errorf("encode audit row: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// fetchHealthz performs the one outbound HTTP GET the bundle needs.
// Returns the raw body so it round-trips into health.json verbatim
// (operators frequently care about field-level details the bundle
// builder doesn't enumerate). Best-effort: any error becomes a notes
// entry + a placeholder file.
func fetchHealthz(rawURL string, timeout time.Duration, insecureTLS bool) ([]byte, error) {
	if rawURL == "" {
		return nil, errors.New("--mgmt-url empty")
	}
	if _, err := url.Parse(rawURL); err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	transport := &http.Transport{}
	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 — opt-in via --insecure-tls
	}
	client := &http.Client{Timeout: timeout, Transport: transport}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	// Validate it's JSON; if not, wrap as a string so consumers can
	// still see what came back.
	var probe map[string]any
	if jerr := json.Unmarshal(body, &probe); jerr != nil {
		wrapped, _ := json.MarshalIndent(map[string]any{
			"raw_body":    string(body),
			"status_code": resp.StatusCode,
			"warning":     "/healthz did not return JSON",
		}, "", "  ")
		return append(wrapped, '\n'), nil
	}
	// Re-marshal indented so the bundle is human-readable. Also add
	// the http_status_code field so a reviewer doesn't have to guess.
	probe["http_status_code"] = resp.StatusCode
	pretty, err := json.MarshalIndent(probe, "", "  ")
	if err != nil {
		return body, nil
	}
	return append(pretty, '\n'), nil
}

// collectListenerStatusFromHealthz derives the listener-status.json
// content from the /healthz fetch we already did. Avoids a second HTTP
// roundtrip + keeps the "no live proxy" fallback uniform across both
// sections.
func collectListenerStatusFromHealthz(healthRaw []byte, healthErr error, p collectDiagnosticsParams) []byte {
	out := map[string]any{
		"requested_dialect": string(p.Dialect),
	}
	if healthErr != nil {
		out["live_proxy"] = false
		out["reason"] = healthErr.Error()
		b, _ := json.MarshalIndent(out, "", "  ")
		return append(b, '\n')
	}
	var probe map[string]any
	if err := json.Unmarshal(healthRaw, &probe); err == nil {
		// Surface the per-listener fields /healthz exposes. We
		// EXCLUDE any remote IPs / connection-string-shaped fields.
		copyIfPresent(out, probe, "mode")
		copyIfPresent(out, probe, "default_policy")
		copyIfPresent(out, probe, "dialect")
		copyIfPresent(out, probe, "active_profile")
		copyIfPresent(out, probe, "status")
		out["live_proxy"] = true
	} else {
		out["live_proxy"] = false
		out["reason"] = "could not parse /healthz body"
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return append(b, '\n')
}

func copyIfPresent(dst, src map[string]any, key string) {
	if v, ok := src[key]; ok {
		dst[key] = v
	}
}

// collectStderrTail reads the last 200 lines of the operator-managed
// stderr-capture file, scrubbing any URL / IP / email pattern. Bounded
// at 64 KiB of raw read so a huge file doesn't bloat the bundle.
func collectStderrTail(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	const maxRead = 64 * 1024
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var offset int64
	if info.Size() > maxRead {
		offset = info.Size() - maxRead
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	// Drop the first (possibly partial) line when we did NOT start at
	// the beginning of the file — it's almost certainly mid-line.
	if offset > 0 && len(lines) > 1 {
		lines = lines[1:]
	}
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	var out bytes.Buffer
	for _, line := range lines {
		out.WriteString(redactFreeText(line))
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

// collectSQLiteStats reports the file size, schema version, and per-
// table row counts. NO row contents leave the database. The shape
// matches the #277 spec.
func collectSQLiteStats(p collectDiagnosticsParams) ([]byte, error) {
	resolvedPath := p.DBPath
	if resolvedPath == "" {
		rp, err := store.DefaultDBPath()
		if err != nil {
			return nil, fmt.Errorf("resolve db path: %w", err)
		}
		resolvedPath = rp
	}
	out := map[string]any{
		// Intentionally do NOT include the resolved file system path —
		// would leak the operator's home directory layout.
		"schema_version_constant": store.SchemaVersion,
	}
	if info, err := os.Stat(resolvedPath); err == nil {
		out["file_size_bytes"] = info.Size()
	} else {
		out["file_size_bytes"] = 0
		out["file_missing"] = true
	}
	st, err := store.Open(p.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	// Closed table allow-list: only tables we have public store
	// counters for. Tables without a counter would show as -1 + add
	// noise; better to enumerate what we can actually measure.
	tables := []string{
		"decisions",
		"rules",
		"pending_audit_events",
		"pending_prompts",
	}
	counts := map[string]int64{}
	for _, t := range tables {
		n, cerr := countTable(st, t)
		if cerr != nil {
			counts[t] = -1
			continue
		}
		counts[t] = n
	}
	out["row_counts"] = counts
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// countTable returns SELECT COUNT(*) FROM <table> via the store's
// public counters. Returns -1 when no counter is available (the table
// is in the allow-list but the store doesn't yet ship a public
// Count* helper — currently true only for the seldom-changing tables
// `rules` / `tasks` / `pause_events` / `profile_overrides` /
// `schema_version`). Treating unknown as -1 (rather than 0) keeps the
// JSON visibly honest about which counts were actually observed.
func countTable(st *store.Store, table string) (int64, error) {
	switch table {
	case "decisions":
		return st.CountDecisions()
	case "pending_audit_events":
		return st.CountPendingAuditEvents()
	case "pending_prompts":
		return st.CountPendingPrompts()
	case "rules":
		rows, err := st.ListRules()
		if err != nil {
			return -1, err
		}
		return int64(len(rows)), nil
	default:
		return -1, nil
	}
}

// collectSlowQueriesFile writes a best-effort slow-queries JSONL.
// D-Slice 1 doesn't measure per-row duration; we ship the SHAPE
// signal the spec asked for (verb + tables + parse_errors length as
// a proxy for cost). Every row is redacted same as audit-tail.jsonl.
func collectSlowQueriesFile(p collectDiagnosticsParams) ([]byte, error) {
	st, err := store.Open(p.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	// Pull a wider tail then rank by a synthetic cost so the bundle
	// reflects "broad statements with many tables" first.
	rows, err := st.RecentDecisions(slowQueriesRows * 5)
	if err != nil {
		return nil, fmt.Errorf("recent decisions: %w", err)
	}
	// Sort by (tables-touched count desc, statement length desc) as a
	// best-effort proxy for cost. Stable on equal keys so the row order
	// is deterministic.
	sort.SliceStable(rows, func(i, j int) bool {
		ai, aj := len(rows[i].TablesTouched), len(rows[j].TablesTouched)
		if ai != aj {
			return ai > aj
		}
		return len(rows[i].Statement) > len(rows[j].Statement)
	})
	if len(rows) > slowQueriesRows {
		rows = rows[:slowQueriesRows]
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range rows {
		rec := map[string]any{
			"at":                 r.At.UTC().Format(time.RFC3339),
			"statement_verb":     r.StatementType,
			"tables":             r.TablesTouched,
			"table_count":        len(r.TablesTouched),
			"statement_length":   len(r.Statement),
			"redacted_statement": parser.RedactLiterals(r.Statement),
			// Per #277 the spec asks for duration; D-Slice 1 hasn't
			// measured it yet. Surface explicitly so a consumer doesn't
			// silently assume zero.
			"duration_ms":        nil,
			"duration_available": false,
		}
		if err := enc.Encode(rec); err != nil {
			return nil, fmt.Errorf("encode slow query row: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// collectQueueDepthFile reports the pending_audit_events +
// pending_prompts row counts. This is the natural-section addition
// the #277 spec hinted at ("e.g. pending audit-event queue depth from
// the SQLite Option-A queue").
func collectQueueDepthFile(p collectDiagnosticsParams) ([]byte, error) {
	st, err := store.Open(p.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	queues := map[string]int64{
		"pending_audit_events": -1,
		"pending_prompts":      -1,
	}
	if n, cerr := st.CountPendingAuditEvents(); cerr == nil {
		queues["pending_audit_events"] = n
	}
	if n, cerr := st.CountPendingPrompts(); cerr == nil {
		queues["pending_prompts"] = n
	}
	out := map[string]any{
		"queue_row_counts": queues,
		"notes": "pending_audit_events drains every 1s from the running proxy. " +
			"pending_prompts is the deny-prompt UX queue. A persistent non-zero " +
			"pending_audit_events count means the run-process is not draining.",
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// collectEnvNamesFile lists DBOUNCE_* env var NAMES (never values).
// Sibling agents in kbounce + ibounce ship the equivalent prefix
// filter so the cross-product bundle shape is uniform.
func collectEnvNamesFile() []byte {
	var names []string
	for _, kv := range os.Environ() {
		eq := strings.Index(kv, "=")
		if eq < 0 {
			continue
		}
		name := kv[:eq]
		if strings.HasPrefix(name, "DBOUNCE_") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		fmt.Fprintf(&sb, "%s=<redacted>\n", n)
	}
	if len(names) == 0 {
		sb.WriteString("(no DBOUNCE_* env vars set)\n")
	}
	return []byte(sb.String())
}

// renderNotesFile produces the human-readable summary of any
// collection issues. The same notes appear in manifest.json under
// "notes"; this file is the convenience copy for the reviewer who
// unzips + reads top-down.
func renderNotesFile(notes []string) []byte {
	if len(notes) == 0 {
		return []byte("(no collection issues)\n")
	}
	var sb strings.Builder
	for _, n := range notes {
		fmt.Fprintf(&sb, "- %s\n", n)
	}
	return []byte(sb.String())
}

// hashUserID returns a stable truncated sha256 hex digest of the
// cleartext id, suitable for cross-row correlation without leaking
// the cleartext. Empty input round-trips to empty (so an unpopulated
// optional column doesn't render as a hash of "").
func hashUserID(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])[:userIdHashLen]
}

// redactionPatterns names the secret-shaped patterns we scrub from
// free-text fields (decision_reason, stderr lines). The intent is
// defense-in-depth: the bundle should not contain secrets even when
// the underlying source unexpectedly does.
//
// Patterns:
//   - HTTP/HTTPS URLs (catches webhook URLs that escaped to a log)
//   - IPv4 addresses (catches remote-IP leaks)
//   - bare hostnames after the postgres:// / mysql:// scheme prefix
//   - email addresses
//   - "Bearer <token>" and "token=..." substrings
//   - base64-looking 32+ byte sequences (catches stray keys)
var redactionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`https?://[^\s'"]+`),
	regexp.MustCompile(`(postgres|postgresql|mysql|snowflake|bigquery)://[^\s'"]+`),
	regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
	regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]+`),
	regexp.MustCompile(`(?i)(token|secret|api_-?key|password)=\S+`),
	regexp.MustCompile(`\b[A-Za-z0-9+/]{32,}={0,2}\b`),
}

// redactFreeText runs every redactionPattern against s, replacing
// each match with the literal string [REDACTED]. Idempotent.
func redactFreeText(s string) string {
	out := s
	for _, re := range redactionPatterns {
		out = re.ReplaceAllString(out, "[REDACTED]")
	}
	return out
}


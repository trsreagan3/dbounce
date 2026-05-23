// Package cli is dbounce's cobra command tree. Both the cmd/dbounce
// binary and any future packaging shims delegate to cli.Main so the
// command surface has a single source of truth.
//
// D-Slice 1 commands:
//
//	dbounce run           start the SQL-wire-protocol listener
//	dbounce audit tail    show recent decisions from the audit log
//	dbounce --version     print version + commit + build time
//
// Profile / rules / tasks / pause / prompts / presets / mcp / init-tls
// land in D-Slices 3-8 respectively. The cobra parent commands aren't
// scaffolded here because cobra would print them in --help and mislead
// the operator into thinking they're partially-implemented; better to
// add them at the same time the underlying subcommands ship.
package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/caveats"
	"github.com/trsreagan3/dbounce/internal/dynamicdeny"
	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/upstream"
)

// licensedForAuditWebhook is the #252 Slice 1 placeholder license
// gate. The audit-webhook transport is an Enterprise-tier feature per
// the [[security-team-audit-export]] memo + [[enterprise-self-host-
// only]]. dbounce does NOT yet have license-file plumbing (tracked as
// issue #235); until that lands, --audit-webhook-url is rejected at
// CLI parse time with an actionable error pointing the operator at
// the JSONL log path (the FREE-tier transport that ships now) +
// the future license-file path.
//
// When #235 lands, this function reads the Ed25519-signed license
// file + returns nil iff the license includes the
// "audit-export-webhook" entitlement. Until then, it always returns a
// not-licensed error. The function is exported via a package-level
// var so tests can override it without depending on a real license
// file on disk.
var licensedForAuditWebhook = func() error {
	return errors.New(
		"--audit-webhook-url requires an Enterprise license " +
			"(placeholder: dbounce's license-file plumbing has not yet " +
			"landed — tracked as #235). The JSONL log file transport " +
			"--audit-log-path PATH is the FREE-tier audit-export channel " +
			"and is available on all tiers. Ship the JSONL file to your " +
			"collector via Fluent Bit / Vector / logrotate until the " +
			"webhook gate unlocks. See [[security-team-audit-export]] " +
			"for the full transport-tier matrix.")
}

// loopbackHosts mirrors kbounce + ibounce's CRIT-32-02 closure:
// dbounce will hold inbound client SCRAM challenges + bearer tokens
// once D-Slice 2 lands; binding externally exposes that surface to
// anyone on the network. Refuse non-loopback bindings unless the
// operator passed --i-know-this-binds-externally to acknowledge they
// read the threat model.
var loopbackHosts = map[string]struct{}{
	"127.0.0.1":     {},
	"::1":           {},
	"localhost":     {},
	"ip6-localhost": {},
	"ip6-loopback":  {},
}

// envProfileVar is the env-var name used to select the active profile
// when --profile is not passed. The DBOUNCE_ prefix is preserved
// (rather than DB_) so the three-product `*BOUNCE_PROFILE` env-var
// pattern stays consistent across iam-jit-bouncer / kbouncer /
// dbounce.
const envProfileVar = "DBOUNCE_PROFILE"

// version is overridden at build time via -ldflags
// "-X github.com/trsreagan3/dbounce/internal/cli.version=...". Unstamped
// builds report "dev".
var version = "dev"

// commit is the git SHA the binary was built from. Set via -ldflags
// "-X github.com/trsreagan3/dbounce/internal/cli.commit=...". Unset →
// "none".
var commit = "none"

// buildTime is the ISO-8601 UTC timestamp the binary was built at.
// Set via -ldflags
// "-X github.com/trsreagan3/dbounce/internal/cli.buildTime=...". Unset
// → "unknown".
var buildTime = "unknown"

// Main is the package's exported entry point so any binary that wraps
// dbounce (homebrew shim, distro packager, downstream fork) runs the
// same code path.
func Main() {
	proxy.EnsureLogger()
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// versionString returns the human-readable version surfaced via
// `dbounce --version`. Format: `dbounce <version> (commit X, built Y)`.
// Mirrors kbounce + ibounce's UAT-K2 HIGH-K2-06 closure pattern.
func versionString() string {
	return fmt.Sprintf("dbounce %s (commit %s, built %s)", version, commit, buildTime)
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "dbounce",
		Short:         "Local SQL gating proxy",
		Long:          rootLongHelp,
		Version:       versionString(),
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.AddCommand(newRunCmd())
	root.AddCommand(newAuditCmd())
	// [[audit-export-failure-visibility]] Part 2: explicit operator
	// health check for the audit-export pipeline. Non-zero exit when
	// degraded so an operator can chain it in a startup script:
	//   `dbounce audit-export health || alert-on-call`
	// Reads the live /healthz endpoint of a running proxy — this
	// avoids re-opening the audit log / hitting the webhook a second
	// time (which would inflate counters + spam the collector). See
	// the cross-product "audit-export health" pattern shared with
	// ibounce + kbounce.
	root.AddCommand(newAuditExportCmd())
	// `dbounce audit-webhook presets list` (#259) — operator-facing
	// CLI to enumerate the webhook preset shapes the binary speaks.
	// Sibling to `audit-export health`; cross-product parity with
	// ibounce + kbounce per [[cross-product-agent-parity]].
	root.AddCommand(newAuditWebhookCmd())
	// [[basic-app-hygiene-features]] TIER 1 #1: `dbounce config
	// export | import` ships a portable JSON bundle of the runtime
	// configuration so an operator can back up, move, or change-
	// manage a deployment without scraping state.db by hand. Sibling
	// agents in ibounce + kbounce ship the same parent.
	root.AddCommand(newConfigCmd())
	root.AddCommand(newInitTLSCmd())
	// D-Slice 7: environment profile + MCP server subcommand trees.
	root.AddCommand(newProfileCmd())
	// #387 / §A25 Phase 2 — `dbounce denies recent` cross-bouncer
	// deny-visibility surface (the symmetric flip of dynamic-deny
	// rules).
	root.AddCommand(newDeniesCmd())
	root.AddCommand(newMCPCmd())
	// D-Slice 8: pause + prompts + presets + rules subcommands.
	// ProfileWriter wiring bridges D-Slice 7's internal/profile package
	// (the writer) to D-Slice 8's CLI surface (the consumer). The
	// adapter loads profiles.yaml lazily on the first writer call so
	// that root-cmd construction stays cheap + the whole CLI doesn't
	// hard-fail at startup if profiles.yaml is missing — `dbounce
	// audit tail` should keep working even without a profiles file.
	writer := newCLIProfileWriter("")
	root.AddCommand(newPauseCmd())
	root.AddCommand(newPromptsCmd(writer))
	root.AddCommand(newPresetsCmd(writer))
	root.AddCommand(newRulesCmd(writer))
	// MED-D8-10 (AUDIT-WB-DSLICES-1-8.md) closure: wire the
	// TaskReviewSummary helper into a CLI surface. Without this command
	// the new PauseDemotedCount + PauseDemotedCalls fields aren't
	// reachable; per [[deliberate-feature-completion]] both halves of
	// the fix ship together.
	root.AddCommand(newTasksCmd())
	// D-Slice 6: dry-run SQL through the rule engine without starting
	// a wire-protocol listener. The supported invocation path for
	// Snowflake + BigQuery (which ship via the JDBC-driver-shim per
	// [[dbounce-build-plan]] §D-Slice 6); also works for postgres +
	// mysql so the shim pattern is dialect-uniform.
	root.AddCommand(newDecideCmd())
	// #277 diagnostics bundle (per [[basic-app-hygiene-features]] +
	// [[cross-product-agent-parity]]). Two surface paths: the canonical
	// `dbounce diagnostics bundle` parent + the `dbounce diag` alias
	// that sibling agents in kbounce + ibounce also wire so a single
	// muscle-memory shortcut works across all three products.
	root.AddCommand(newDiagnosticsCmd())
	root.AddCommand(newDiagnosticsDiagAliasCmd())
	// #304 — `dbounce doctor caveats` surfaces the §B entries from
	// KNOWN-CAVEATS.md that apply to dbounce. Sibling Bounce products
	// ship the same shape per [[cross-product-agent-parity]].
	root.AddCommand(newDoctorCmd())
	// #273 investigate-with-Claude workflow. Composes #268
	// audit-tail OCSF export + #277 diagnostics bundle into a single
	// subcommand that lands a Claude-ready evidence pack on disk.
	// Cross-product parity with ibounce / kbounce / gbounce per
	// [[cross-product-agent-parity]].
	root.AddCommand(newInvestigateCmd())
	// #279 SQLite backup/restore. Top-level subcommands (NOT under
	// `dbounce config`) — see internal/cli/backup.go for the verb-
	// choice rationale + the cross-product alignment with kbounce +
	// ibounce.
	root.AddCommand(newBackupCmd())
	root.AddCommand(newRestoreCmd())
	// #285 — `dbounce session list / show / export / purge`. Reads the
	// per-session NDJSON recordings written when the proxy runs with
	// `--record-sessions-dir`. Subcommand + flag names match ibounce +
	// kbounce + gbounce exactly per [[cross-product-agent-parity]] so
	// orchestrators (and the cross-product `iam-jit session replay
	// <FILE>` CLI) consume any product's recordings uniformly.
	root.AddCommand(newSessionCmd())
	// #311 / §A10 — `dbounce logs {purge,archive,verify}` audit-log
	// retention surface. Ships in lockstep with the sibling products
	// (ibounce / kbounce / gbounce); the cross-product runbook at
	// iam-roles/docs/LOG-RETENTION.md applies to all.
	root.AddCommand(newLogsCmd())
	// #365 / §A34 — `dbounce version-check`. Opt-in GitHub-Releases
	// poll; mirrors kbouncer + ibounce siblings per
	// [[cross-product-agent-parity]]. Privacy posture: zero telemetry,
	// generic User-Agent, kill-switch env var; see internal/cli/
	// version_check.go for the full design.
	root.AddCommand(newVersionCheckCmd())
	// #383 / §A42 — `dbounce posture` per-bouncer posture surface.
	// Cross-product parity per [[cross-product-agent-parity]]; for
	// the cross-product roll-up use `iam-jit posture` from iam-roles.
	root.AddCommand(newPostureCmd())
	return root
}

// profileWriterAdapter implements the cli.ProfileWriter interface
// using D-Slice 7's internal/profile package. The adapter is the
// merge-time bridge promised by the prompts.go ProfileWriter
// docstring: it lets the D-Slice 8 CLI surfaces (prompts answer
// --kind profile / presets apply / rules recommend --save-as-profile)
// create real profiles on disk via Profiles.AddLocalProfile.
//
// Lazy load: profilesPath / loaded.Profiles are populated on the
// first CreateProfile or ExistingProfileNames call. Two reasons:
//
//  1. Root-cmd construction runs for every dbounce invocation
//     including `dbounce --help` and `dbounce audit tail`. A
//     hard-fail here on a missing profiles.yaml would break those
//     unrelated workflows. Lazy means the error only surfaces when
//     the operator actually asks to write a profile.
//
//  2. The --profiles-path flag (D-Slice 7 run command) lets the
//     operator override the default path. Lazy + the optional
//     path argument to CreateProfile/AddLocalProfile mean we can
//     extend the adapter to honor the flag later without breaking
//     the current callers.
//
// Conversion note: cli.ProfileWriter.CreateProfile takes []ProxyRule
// for both allow + deny, but profile.Profile uses ProfileAllowRule
// for allows and []string DenyActions for denies. The Pattern + Note
// fields round-trip; rules.ProxyRule's SchemaScope / TableScope /
// FunctionScope / Origin / Effect are DROPPED on the allow side
// (ProfileAllowRule's ArnScope / RegionScope are AWS-shaped and not
// the same axis). For deny rules we extract the Pattern's statement
// type and append to DenyActions — table-half of the pattern is
// dropped because DenyActions is a category-or-type list, not a
// pattern list. Both lossy conversions are documented inline.
type profileWriterAdapter struct {
	// configuredPath is the path the adapter was constructed with.
	// Empty means "use profile.DefaultProfilesPath() on first call."
	configuredPath string

	mu             sync.Mutex
	loaded         *profile.Profiles
	resolvedPath   string
}

func newCLIProfileWriter(path string) *profileWriterAdapter {
	return &profileWriterAdapter{configuredPath: path}
}

// ensureLoaded resolves the on-disk path + loads the current profile
// set. Idempotent; the first call wins. Safe for concurrent callers.
func (a *profileWriterAdapter) ensureLoaded() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loaded != nil {
		return nil
	}
	path := a.configuredPath
	if path == "" {
		p, err := profile.DefaultProfilesPath()
		if err != nil {
			return fmt.Errorf("dbounce: resolve profiles path: %w", err)
		}
		path = p
	}
	ps, err := profile.LoadProfiles(path)
	if err != nil {
		return fmt.Errorf("dbounce: load profiles for writer: %w", err)
	}
	// LoadProfiles falls back to embedded defaults when the file is
	// missing + leaves Path = "". Override so AddLocalProfile lands the
	// new profile on the disk path the operator expects (rather than
	// silently creating profiles.yaml at a nondeterministic default
	// resolved inside AddLocalProfile).
	if ps.Path == "" {
		ps.Path = path
	}
	a.loaded = ps
	a.resolvedPath = path
	return nil
}

// CreateProfile satisfies cli.ProfileWriter. Converts the wire-shape
// []ProxyRule into the on-disk profile.Profile shape + persists via
// AddLocalProfile. See type docstring for the lossy-conversion notes.
//
// HIGH-D8-03 (AUDIT-WB-DSLICES-1-8.md) closure: an allow rule that
// carries SchemaScope / TableScope / FunctionScope WOULD be silently
// widened on persistence because profile.ProfileAllowRule has no
// corresponding fields. Silent widening is the worst possible failure
// for a security gate — "allow SELECT scoped to reporting schema"
// becomes "allow SELECT on any schema" with no operator-visible
// signal. Per [[creates-never-mutates]] + [[scorer-is-ground-truth]],
// we fail-fast on this case with an explicit error rather than persist
// a more-permissive rule than the operator described. Extending
// profile.ProfileAllowRule to carry the scope axes is a v1.1 schema
// change (additive YAML fields, backwards-compatible) — tracked as the
// long-term fix in the audit doc; this commit ships the immediate
// safety guard.
func (a *profileWriterAdapter) CreateProfile(name, description string,
	allow []dbrules.ProxyRule, deny []dbrules.ProxyRule) error {
	if err := a.ensureLoaded(); err != nil {
		return err
	}
	// HIGH-D8-03 guard: reject any allow rule whose scope fields would
	// be silently dropped on persistence. Iterate ALL rules first so the
	// error names every offender, not just the first one (operator can
	// fix the whole batch in one round-trip).
	var scoped []string
	for _, r := range allow {
		if r.SchemaScope != "" || r.TableScope != "" || r.FunctionScope != "" {
			scoped = append(scoped, fmt.Sprintf(
				"  - pattern=%q schema_scope=%q table_scope=%q function_scope=%q",
				r.Pattern, r.SchemaScope, r.TableScope, r.FunctionScope))
		}
	}
	if len(scoped) > 0 {
		return fmt.Errorf(
			"dbounce: profile save rejected — allow rule(s) carry "+
				"schema/table/function scope that profile.ProfileAllowRule "+
				"would silently drop, widening the gate. HIGH-D8-03 "+
				"(AUDIT-WB-DSLICES-1-8.md): either rewrite the rule(s) "+
				"with no scope, or extend profile.ProfileAllowRule to "+
				"carry the axes (v1.1).\n\noffending rule(s):\n%s",
			strings.Join(scoped, "\n"))
	}
	p := &profile.Profile{
		Name:        name,
		Description: description,
	}
	for _, r := range allow {
		// Pattern + Note round-trip. SchemaScope / TableScope /
		// FunctionScope / Origin / Effect are dropped — ProfileAllowRule
		// does not carry those axes. Origin is captured implicitly via
		// the Description ("from preset X" / "from prompt N" /
		// "auto-generated by rules recommend"). The pre-loop guard above
		// rejects rules whose scope fields are set (HIGH-D8-03), so
		// reaching this loop means all three scope fields are empty;
		// the drop is no-op rather than silent widening.
		p.AllowRules = append(p.AllowRules, profile.ProfileAllowRule{
			Pattern: r.Pattern,
			Note:    r.Note,
		})
	}
	for _, r := range deny {
		// DenyActions is a statement-type / category list, not a pattern
		// list. Pull the statement_type half from the pattern; if the
		// pattern is malformed, skip it (caller has bigger problems than
		// a profile write) rather than reject the whole CreateProfile
		// call. The table-glob half is DROPPED — profile.Profile has no
		// per-deny-action table scope (the keyword-target denies live on
		// a separate field). For pattern "DELETE:public.users" we deny
		// the whole DELETE statement type under this profile.
		stmtType, _, err := dbrules.ParsePattern(r.Pattern)
		if err != nil || stmtType == "" {
			continue
		}
		p.DenyActions = append(p.DenyActions, stmtType)
	}
	if err := a.loaded.AddLocalProfile(a.resolvedPath, p); err != nil {
		// Re-wrap ErrProfileExists with a friendlier message that names
		// the file the operator will need to edit, but preserve the
		// sentinel via errors.Is for callers that test for it.
		if errors.Is(err, profile.ErrProfileExists) {
			return fmt.Errorf(
				"%w (profiles file: %s — pick a different name or "+
					"delete the existing entry)",
				err, a.resolvedPath)
		}
		return err
	}
	return nil
}

// ExistingProfileNames satisfies cli.ProfileWriter. Returns a set so
// naming.ResolveProfileName can do membership tests in O(1).
func (a *profileWriterAdapter) ExistingProfileNames() (map[string]struct{}, error) {
	if err := a.ensureLoaded(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	names := a.loaded.NamesSorted()
	a.mu.Unlock()
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		// strings.TrimSpace defends against a hand-edited YAML with
		// trailing whitespace in a profile name — the collision check
		// should still fire.
		out[strings.TrimSpace(n)] = struct{}{}
	}
	return out, nil
}

const rootLongHelp = `dbounce is a local proxy that sits between a SQL client (psql /
a coding agent / an analytics tool / a CI job) and the real database.
It parses every statement, records the decision in an audit log, and
(in later slices, transparent mode) can deny statements that don't
match its rule set.

Two operating modes (mirroring kbounce + ibounce):

  cooperative   parse + log every statement (D-Slice 1 default).
                D-Slice 1 NEVER forwards or blocks — observation only.
  transparent   DENY verdicts return a SQL error to the client.
                Real upstream forwarding lands in D-Slice 2.

D-Slice 1 ships:
  - PostgreSQL wire-protocol listener (observation-only)
  - AST-aware statement parser (pg_query_go v6)
  - Decision audit log (~/.dbounce/state.db)
  - dbounce run, dbounce audit tail, dbounce --version, /healthz

Read-vs-write framing: D-Slice 1 records statement_type (SELECT vs
INSERT/UPDATE/DELETE/MERGE/DDL/CALL/DO/EXECUTE/WITH-WRITE) for every
row + flags HasMutatingNode so the D-Slice 7 safe-default profile
can default to "reads are fine; writes get layered checks" out of
the gate.`

func newRunCmd() *cobra.Command {
	var (
		port              int
		host              string
		mgmtHost          string
		mgmtPort          int
		modeStr           string
		defaultPolStr     string
		dialectStr        string
		upstreamURL         string
		upstreamCACert      string
		upstreamTLSStr      string
		allowInternalUpstream bool
		dbPath                string
		forceExternalBind     bool
		forceExternalMgmtBind bool
		// D-Slice 4: TLS flags. All optional; empty preserves D-Slice
		// 1+2's plaintext behavior.
		listenerTLSCert     string
		listenerTLSKey      string
		listenerTLSClientCA string
		requireClientCert   bool
		mgmtTLSCert         string
		mgmtTLSKey          string
		// D-Slice 7: environment profile + profiles.yaml path.
		profileName  string
		profilesPath string
		// D-Slice 8: async deny-prompt UX. When true, transparent DENY
		// decisions enqueue a pending_prompts row for `dbounce prompts
		// answer` to drain. Default false preserves D-Slice 3 behavior.
		promptOnDeny bool
		// #203 synchronous deny-prompt v1.1: opt-in companion to
		// --prompt-on-deny. Blocks the SQL request goroutine for up to
		// --sync-prompt-timeout waiting for an operator answer; on
		// allow the proxy forwards + returns the real result. Mutually
		// exclusive with --prompt-on-deny (different UX shape; running
		// both creates per-request ambiguity).
		syncPromptOnDeny     bool
		syncPromptTimeoutStr string
		syncPromptDefaultStr string
		// MED-D8-09 (AUDIT-WB-DSLICES-1-8.md): when true, the audit
		// row's persisted Statement field has quoted string literals
		// swapped for [REDACTED] before insertion. Default false
		// preserves the full-fidelity audit-reconstruction behavior.
		redactLiterals bool
		// LOW-D8-13 (AUDIT-WB-DSLICES-1-8.md): when true, the startup
		// banner is reduced to listener address + dialect only — the
		// fingerprint-sensitive fields (mode, default-policy, profile,
		// upstream URL/TLS, audit db path) are suppressed. The full
		// configuration remains available via /healthz for operators
		// who want introspection through the management endpoint.
		quietBanner bool
		// #252 Slice 1 audit-export transport flags. See
		// [[security-team-audit-export]] memo for the full design.
		// auditLogPath enables the FREE-tier JSONL transport.
		auditLogPath  string
		auditLogFsync bool
		// #311 / §A10 — rotation thresholds. Sentinel -1 = "operator
		// didn't pass the flag → use the audit-package default
		// (matches iam-roles/docs/LOG-RETENTION.md)." 0 = "explicitly
		// disabled." Same names across all four Bounce products per
		// [[cross-product-agent-parity]]; env-var counterparts share the
		// DBOUNCE_AUDIT_LOG_MAX_SIZE_MB / _MAX_AGE_DAYS /
		// _DB_RETENTION_DAYS shape.
		auditLogMaxSizeMB    int64
		auditLogMaxAgeDays   int
		auditDBRetentionDays int
		// auditWebhookURL + Token enable the Enterprise webhook
		// transport. License-gated (placeholder until #235 lands the
		// real license-file plumbing). batchSize defaults to 1 (one
		// event per POST). allowInternalWebhook mirrors
		// --allow-internal-upstream — same SSRF gate, separate opt-in
		// so an operator who needs intranet upstream connectivity
		// doesn't accidentally relax the webhook surface (or vice
		// versa).
		auditWebhookURL       string
		auditWebhookToken     string
		auditWebhookBatchSize int
		allowInternalWebhook  bool
		// #257 webhook presets: vendor-native body/header shapes
		// applied at send-time. The canonical OCSF event in the
		// JSONL log file is unchanged; only the webhook body
		// picks up the vendor overlay. Per [[audit-webhook-presets]]
		// + [[cross-product-agent-parity]] the same flag names ship
		// across kbounce / dbounce / ibounce.
		auditWebhookPreset        string
		auditWebhookTags          string
		auditWebhookSentinelTable string
		// #280 — per-org notification routing engine. YAML config path;
		// empty disables the engine (the single --audit-webhook-url
		// path stays available). Enterprise-tier (license-gated;
		// placeholder error until #235 license-file plumbing lands).
		auditAlertRoutesPath string
		// Heartbeat — periodic OCSF liveness event + in-process gap
		// watchdog per [[prompt-injection-disable-bouncer-threat]].
		// Default OFF (heartbeatInterval == 0). Sibling agents in
		// ibounce + kbounce ship the SAME flag names so a single
		// cross-product SIEM rule keyed on activity_name=heartbeat
		// works for all three.
		heartbeatIntervalStr     string
		heartbeatGapThresholdStr string
		// [[audit-export-failure-visibility]] Part 3: periodic
		// audit_export_degraded alert + /healthz 503 flip. Default
		// OFF (operator opt-in); any non-zero positive value enables
		// the in-process poll goroutine that fires the alert when
		// the export pipeline is degraded. Sibling agents in
		// ibounce + kbounce ship the SAME flag name so cross-product
		// SIEM alerting cadence is uniform.
		auditExportHealthIntervalStr string
		// #271 — bearer token for GET /audit/events when the mgmt port
		// is bound off-loopback. Empty = loopback-only (no auth gate).
		auditEventsToken string
		// #254 — deployment preset. Single-flag shortcut for a common
		// deployment shape (only `security-observe` in v1.0). Resolved
		// BEFORE downstream validation so license / SSRF / loopback
		// gates see the preset-resolved values.
		deploymentPreset string
		// #285 — per-session NDJSON recordings directory. Empty disables
		// the channel. Replayable via `iam-jit session replay <FILE>`.
		recordSessionsDir string
		// #258 — AWS Security Lake adapter. All four fields off by
		// default. Per [[no-hosted-saas]] + [[self-host-zero-billing-
		// dependency]] the bucket lives in the operator's AWS account;
		// iam-jit-the-company never receives the data.
		securityLakeBucket          string
		securityLakeRegion          string
		securityLakeRoleARN         string
		securityLakeRotationSeconds int
		// #317 — cloud-neutral S3-compatible NDJSON object-storage
		// sink. All fields OFF by default. Per [[self-host-zero-
		// billing-dependency]] the bucket is operator-owned.
		auditObjectStorageEndpoint        string
		auditObjectStorageBucket          string
		auditObjectStoragePrefix          string
		auditObjectStorageRegion          string
		auditObjectStorageCredentialsFile string
		auditObjectStorageRotationMinutes int
		auditObjectStorageMaxSizeMB       int
		auditObjectStorageInstanceID      string
		// #324c — dynamic-deny YAML path + disable + RDS-ARN match input.
		// Default path is `~/.iam-jit/dynamic-denies.yaml` resolved via
		// dynamicdeny.ResolveDefaultPath (honors $IAM_JIT_DYNAMIC_DENIES_PATH).
		dynamicDeniesPath    string
		disableDynamicDenies bool
		upstreamRDSARN       string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the SQL wire-protocol listener",
		Long: `Start the dbounce SQL wire-protocol listener.

The wire-protocol listener binds to 127.0.0.1:5433 by default
(loopback only — dbounce will hold SCRAM challenges + bearer tokens
once D-Slice 2's real forwarding lands; binding externally exposes
that surface). The management HTTP listener for /healthz binds to
127.0.0.1:8768 (distinct from kbounce's 8766 and ibounce's 8767).

D-Slice 1 is OBSERVATION-ONLY: each inbound statement is parsed +
audit-logged, then a synthetic ReadyForQuery is sent to the client.
NOTHING ACTUALLY EXECUTES against any upstream. D-Slice 2 lands real
forwarding.

Ctrl+C exits cleanly (graceful shutdown).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// #254 — deployment preset resolution. Runs BEFORE any
			// downstream parsing / validation so the preset-resolved
			// values flow through everything that follows. HARD-
			// override conflicts (e.g. --preset security-observe
			// --mode cooperative) fail-fast here with a "drop one OR
			// the other" message. SOFT overrides flow through. The
			// preset BANNER lines are stashed for printing alongside
			// the existing startup banner.
			var presetBannerLines []string
			if deploymentPreset != "" {
				preset := GetPreset(deploymentPreset, "dbounce")
				if preset == nil {
					return fmt.Errorf(
						"dbounce: unknown --preset %q; available: security-observe",
						deploymentPreset)
				}
				operatorChanged := map[string]bool{
					"mode":                         cmd.Flags().Changed("mode"),
					"default-policy":               cmd.Flags().Changed("default-policy"),
					"audit-log-path":               cmd.Flags().Changed("audit-log-path"),
					"heartbeat-interval":           cmd.Flags().Changed("heartbeat-interval"),
					"audit-export-health-interval": cmd.Flags().Changed("audit-export-health-interval"),
				}
				currentValues := map[string]string{
					"mode":                         modeStr,
					"default-policy":               defaultPolStr,
					"audit-log-path":               auditLogPath,
					"heartbeat-interval":           heartbeatIntervalStr,
					"audit-export-health-interval": auditExportHealthIntervalStr,
				}
				res, err := ApplyPreset(preset, operatorChanged, currentValues, nil)
				if err != nil {
					return err
				}
				// Rebind the locals from the preset where the operator
				// did not override.
				for _, key := range res.DerivedKeys {
					pv := preset.Values[key]
					switch key {
					case "mode":
						modeStr = pv.Value
					case "default-policy":
						defaultPolStr = pv.Value
					case "audit-log-path":
						auditLogPath = pv.Value
						if d := filepath.Dir(auditLogPath); d != "" {
							_ = os.MkdirAll(d, 0o700)
						}
					case "heartbeat-interval":
						heartbeatIntervalStr = pv.Value
					case "audit-export-health-interval":
						auditExportHealthIntervalStr = pv.Value
					}
				}
				presetBannerLines = FormatBanner(preset, res)
			}

			mode, err := proxy.ParseMode(modeStr)
			if err != nil {
				return err
			}
			defaultPol, err := proxy.ParseDefaultPolicy(defaultPolStr)
			if err != nil {
				return err
			}
			dialect, err := proxy.ParseDialect(dialectStr)
			if err != nil {
				return err
			}

			// D-Slice 6 guard: snowflake + bigquery ship via the JDBC-
			// driver-shim, NOT via a wire-protocol proxy. `dbounce run`
			// binds a TCP listener that speaks PG or MySQL wire protocol;
			// there is no such listener for Snowflake/BigQuery in v1.0
			// because their wire protocols are HTTPS-based + closed-spec
			// per [[dbounce-build-plan]] §D-Slice 6 + [[v1-scope-bar]].
			// Fail fast here pointing the operator at the supported
			// invocation path (`dbounce decide` + the dbounce_decide MCP
			// tool) so we don't silently start a TCP listener that the
			// customer's Snowflake driver will never connect to.
			if dialect == proxy.DialectSnowflake || dialect == proxy.DialectBigQuery {
				return fmt.Errorf(
					"dbounce run --dialect %s is not supported (no wire-protocol "+
						"proxy for these dialects in v1.0; use the JDBC-shim "+
						"approach — see docs/SHIM-INTEGRATION.md). The supported "+
						"invocation path is `dbounce decide --dialect %s` (or the "+
						"dbounce_decide MCP tool) called from a shim wrapper.",
					dialect, dialect)
			}

			// D-Slice 5 → 4 cross-slice guard: MySQL listener TLS not
			// shipped yet (per dbounce-build-plan §D-Slice 5). Fail-fast
			// here rather than silently accepting flags that won't take
			// effect on the MySQL handler. Revisit when MySQL TLS lands.
			if dialect == proxy.DialectMySQL &&
				(listenerTLSCert != "" || listenerTLSKey != "" || requireClientCert) {
				return fmt.Errorf(
					"--dialect=mysql does not yet support listener TLS " +
						"(--listener-tls-cert / --listener-tls-key / " +
						"--require-client-cert). MySQL listener TLS is " +
						"post-launch; use --dialect=postgres for now.")
			}

			// CRIT-32-02 (mirrored from kbounce + ibounce): refuse to
			// bind externally without explicit operator acknowledgement.
			if _, ok := loopbackHosts[host]; !ok && !forceExternalBind {
				fmt.Fprintf(os.Stderr,
					"refusing to bind to %q: this exposes dbounce's "+
						"credential-handling surface to the network.\n\n"+
						"If you genuinely need to bind externally (test VM "+
						"with no real DB credentials, network-segmented dev "+
						"box), re-run with --i-know-this-binds-externally.\n",
					host)
				os.Exit(2)
			}

			// HIGH-D8-04 (AUDIT-WB-DSLICES-1-8.md) closure: the same
			// loopback guard MUST also apply to the management listener.
			// /healthz discloses mode, dialect, active_profile, decision
			// counters, AND pause.reason (operator-supplied free-text).
			// The wire-listener-only guard was a footgun: operators who
			// saw the wire-protocol message could reasonably assume mgmt
			// shared the same default protection, but it didn't. Symmetric
			// guard + parallel escape hatch closes the asymmetry. Returns
			// an error (rather than os.Exit) so the guard is testable
			// without the binary-level Exit semantics of the older guard.
			if _, ok := loopbackHosts[mgmtHost]; !ok && !forceExternalMgmtBind {
				return fmt.Errorf(
					"refusing to bind the management listener to %q: "+
						"/healthz exposes operator-configured fields including "+
						"the active pause.reason free-text (HIGH-D8-04 from "+
						"AUDIT-WB-DSLICES-1-8.md).\n\nIf you genuinely need to "+
						"bind externally (test VM, network-segmented dev box, "+
						"intentional read-only health endpoint behind a "+
						"trusted reverse proxy), re-run with "+
						"--i-know-mgmt-binds-externally.",
					mgmtHost)
			}
			// #271 — GET /audit/events lives on the same mgmt port; an
			// external bind without a bearer token would expose recent
			// audit events (statement_type, table names) without auth.
			// Refuse to start in that shape.
			if _, ok := loopbackHosts[mgmtHost]; !ok && auditEventsToken == "" {
				return fmt.Errorf(
					"dbounce: --audit-events-token TOKEN is required when --mgmt-host %q is non-loopback "+
						"(GET /audit/events would otherwise be exposed without auth)",
					mgmtHost)
			}

			// #203 sync-prompt validation — fail-fast at parse before
			// any listeners bind:
			//
			//   - --sync-prompt-on-deny + --prompt-on-deny on the
			//     same invocation: rejected (mutually exclusive UX).
			//   - --sync-prompt-on-deny without --upstream: rejected
			//     (observation-only mode has nowhere to forward an
			//     allow answer to; the block would always resolve
			//     to its default).
			//   - --sync-prompt-on-deny + --mode cooperative: warn
			//     (cooperative DENYs are advisory; sync-blocking on
			//     them would block a request the proxy was about to
			//     forward anyway). Treated as a no-op at runtime.
			//   - --sync-prompt-timeout outside 5s-300s: rejected
			//     (5s = minimum credible operator-reaction window;
			//     300s = beyond any sane SQL client timeout).
			//   - --sync-prompt-default must be allow|deny.
			var syncPromptTimeout time.Duration
			var syncPromptDefault proxy.SyncPromptDefault
			if syncPromptOnDeny {
				if promptOnDeny {
					return fmt.Errorf(
						"dbounce: --sync-prompt-on-deny and --prompt-on-deny " +
							"are mutually exclusive (different UX shapes — " +
							"sync blocks the request goroutine; async returns " +
							"a SQL error immediately + queues for review). " +
							"Pick one.")
				}
				if upstreamURL == "" {
					return fmt.Errorf(
						"dbounce: --sync-prompt-on-deny requires --upstream " +
							"(observation-only mode has nowhere to forward an " +
							"'allow' answer to). Set --upstream or drop the " +
							"flag.")
				}
				d, err := time.ParseDuration(syncPromptTimeoutStr)
				if err != nil {
					return fmt.Errorf(
						"dbounce: --sync-prompt-timeout: parse %q: %w",
						syncPromptTimeoutStr, err)
				}
				if d < 5*time.Second || d > 300*time.Second {
					return fmt.Errorf(
						"dbounce: --sync-prompt-timeout must be in 5s-300s "+
							"(got %s). 5s is the minimum credible operator-"+
							"reaction window; 300s is beyond any sane SQL "+
							"client timeout.", d)
				}
				syncPromptTimeout = d
				sd, err := proxy.ParseSyncPromptDefault(syncPromptDefaultStr)
				if err != nil {
					return err
				}
				syncPromptDefault = sd
				if mode == proxy.ModeCooperative {
					// Warning, not error. The flag is harmless in
					// cooperative mode because the deny is advisory
					// (no block applied), but operators who set it
					// expecting a block should know the gate didn't
					// fire.
					fmt.Fprintln(os.Stderr,
						"dbounce: --sync-prompt-on-deny has no effect in "+
							"cooperative mode (advisory DENYs are not "+
							"blocked); the flag is being ignored at runtime.")
				}
			}

			// D-Slice 2: resolve the upstream forwarding target. Empty
			// --upstream preserves D-Slice 1 observation-only mode.
			var resolvedUpstream *upstream.Upstream
			if upstreamURL != "" {
				tlsMode, err := upstream.ParseTLSMode(upstreamTLSStr)
				if err != nil {
					return err
				}
				up, err := upstream.Resolve(upstream.Options{
					UpstreamURL:   upstreamURL,
					CACertPath:    upstreamCACert,
					TLSMode:       tlsMode,
					AllowInternal: allowInternalUpstream,
				})
				if err != nil {
					return fmt.Errorf("resolve upstream: %w", err)
				}
				resolvedUpstream = up
			}

			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			// D-Slice 4: optional listener-side TLS. When both
			// --listener-tls-cert + --listener-tls-key are set, the
			// listener answers SSLRequest with 'S' + performs the TLS
			// handshake before the StartupMessage parser fires.
			var listenerTLSCfg *proxy.ListenerTLS
			if listenerTLSCert != "" || listenerTLSKey != "" || requireClientCert {
				lcfg, err := proxy.LoadListenerTLS(
					listenerTLSCert, listenerTLSKey, listenerTLSClientCA, requireClientCert)
				if err != nil {
					return err
				}
				listenerTLSCfg = lcfg
			}

			// D-Slice 4: /healthz over HTTPS sanity check. Either both
			// management-tls flags are set, or neither. A half-set pair
			// is an operator typo we should surface loudly.
			if (mgmtTLSCert == "") != (mgmtTLSKey == "") {
				return fmt.Errorf(
					"dbounce: --management-tls-cert and --management-tls-key " +
						"must both be set or both empty")
			}

			// D-Slice 7: profile resolution. Precedence: --profile flag >
			// DBOUNCE_PROFILE env var. Env-var fallback intentionally
			// only fires when the flag is unset so a shell-wide default
			// can be overridden per-invocation without unsetting the env
			// var. profiles.yaml is auto-created from embedded defaults
			// on first run; existing files are NEVER overwritten.
			profileFromFlag := profileName != ""
			if profileName == "" {
				profileName = os.Getenv(envProfileVar)
			}
			resolvedProfilesPath := profilesPath
			if resolvedProfilesPath == "" {
				resolvedProfilesPath, err = profile.DefaultProfilesPath()
				if err != nil {
					return fmt.Errorf("resolve profiles path: %w", err)
				}
			}
			if written, ferr := profile.EnsureDefaultProfilesFile(resolvedProfilesPath); ferr != nil {
				log.Warn().Err(ferr).Str("path", resolvedProfilesPath).
					Msg("dbounce: could not write default profiles.yaml; using embedded defaults")
			} else if written {
				fmt.Fprintf(os.Stderr,
					"dbounce: wrote default profiles to %s\n", resolvedProfilesPath)
			}
			profiles, err := profile.LoadProfiles(resolvedProfilesPath)
			if err != nil {
				return fmt.Errorf("load profiles: %w", err)
			}
			activeProfile, err := profiles.Active(profileName)
			if err != nil {
				return fmt.Errorf("select profile: %w", err)
			}

			// #324c — dynamic-deny watcher. Constructed BEFORE
			// proxy.NewServer so the watcher's initial in-memory
			// snapshot is the one the proxy sees on its first request.
			// Default path is `~/.iam-jit/dynamic-denies.yaml`; the
			// `--dynamic-denies-path PATH` flag overrides; the
			// `--disable-dynamic-denies` flag turns the channel off
			// entirely. SetInstanceUpstream is called with the resolved
			// upstream's hostname (parsed from `--upstream`) + the
			// operator-supplied --upstream-rds-arn so the watcher can
			// compute the instance-denied flag on the initial snapshot
			// + every subsequent reload.
			var ddWatcher *dynamicdeny.Watcher
			var ddBannerLine string
			if !disableDynamicDenies {
				ddPath := dynamicDeniesPath
				if ddPath == "" {
					ddPath = dynamicdeny.ResolveDefaultPath()
				}
				if ddPath != "" {
					// emitFunc is wired AFTER NewServer below so we can
					// reference the Server's counter-bump methods +
					// audit-log sink. For now construct with nil; the
					// post-NewServer step reassigns.
					w, loadErr := dynamicdeny.NewWatcher(ddPath, nil)
					if loadErr != nil {
						fmt.Fprintf(cmd.ErrOrStderr(),
							"dbounce: dynamic-denies: initial load of %q failed: %v\n",
							ddPath, loadErr)
					}
					if w != nil {
						upstreamHost := ""
						if resolvedUpstream != nil {
							upstreamHost = resolvedUpstream.HostnameOnly()
						}
						w.SetInstanceUpstream(upstreamHost, upstreamRDSARN)
					}
					ddWatcher = w
				}
			}

			cfg := proxy.Config{
				Host:               host,
				Port:               port,
				MgmtHost:           mgmtHost,
				MgmtPort:           mgmtPort,
				Mode:               mode,
				DefaultPolicy:      defaultPol,
				Dialect:            dialect,
				UpstreamURL:        upstreamURL,
				Upstream:           resolvedUpstream,
				ListenerTLS:        listenerTLSCfg,
				MgmtTLSCertFile:    mgmtTLSCert,
				MgmtTLSKeyFile:     mgmtTLSKey,
				ActiveProfile:      activeProfile,
				ActiveProfileName:  activeProfile.Name,
				PromptOnDeny:       promptOnDeny,
				SyncPromptOnDeny:   syncPromptOnDeny,
				SyncPromptTimeout:  syncPromptTimeout,
				SyncPromptDefault:  syncPromptDefault,
				RedactLiterals:     redactLiterals,
				AuditEventsToken:   auditEventsToken,
				DynamicDenyWatcher: ddWatcher,
				UpstreamRDSARN:     upstreamRDSARN,
			}.Normalize()

			// Heartbeat — parse + validate BEFORE the exporter build so a
			// malformed flag fails fast. Per
			// [[prompt-injection-disable-bouncer-threat]]: default OFF;
			// any non-zero positive Interval turns on both the periodic
			// tick + the in-process gap watchdog.
			heartbeatInterval, err := time.ParseDuration(heartbeatIntervalStr)
			if err != nil {
				return fmt.Errorf(
					"dbounce: --heartbeat-interval: parse %q: %w",
					heartbeatIntervalStr, err)
			}
			if heartbeatInterval < 0 {
				return fmt.Errorf(
					"dbounce: --heartbeat-interval must be >= 0 (got %s); "+
						"0 disables", heartbeatInterval)
			}
			if heartbeatInterval > 0 &&
				(heartbeatInterval < time.Second || heartbeatInterval > time.Hour) {
				return fmt.Errorf(
					"dbounce: --heartbeat-interval must be in 1s-1h when "+
						"non-zero (got %s); 1s is the minimum credible cadence "+
						"and 1h is beyond any usable SIEM-absence window",
					heartbeatInterval)
			}
			heartbeatGap, err := time.ParseDuration(heartbeatGapThresholdStr)
			if err != nil {
				return fmt.Errorf(
					"dbounce: --heartbeat-gap-threshold: parse %q: %w",
					heartbeatGapThresholdStr, err)
			}
			if heartbeatGap < 0 {
				return fmt.Errorf(
					"dbounce: --heartbeat-gap-threshold must be >= 0 (got %s); "+
						"0 resolves to 2.5x --heartbeat-interval",
					heartbeatGap)
			}

			// [[audit-export-failure-visibility]] interval parse +
			// validation. Default 0 = no periodic poll. Range 5s-1h
			// when non-zero — narrower than the heartbeat range
			// (poll cadence has no SIEM-absence semantics; 5s is the
			// floor at which the alert is timely without burning CPU).
			auditExportHealthInterval, err := time.ParseDuration(auditExportHealthIntervalStr)
			if err != nil {
				return fmt.Errorf(
					"dbounce: --audit-export-health-interval: parse %q: %w",
					auditExportHealthIntervalStr, err)
			}
			if auditExportHealthInterval < 0 {
				return fmt.Errorf(
					"dbounce: --audit-export-health-interval must be >= 0 (got %s); "+
						"0 disables", auditExportHealthInterval)
			}
			if auditExportHealthInterval > 0 &&
				(auditExportHealthInterval < 5*time.Second || auditExportHealthInterval > time.Hour) {
				return fmt.Errorf(
					"dbounce: --audit-export-health-interval must be in 5s-1h when "+
						"non-zero (got %s); narrower than --heartbeat-interval "+
						"because the audit_export_degraded alert is local-state "+
						"+ doesn't need sub-5s precision",
					auditExportHealthInterval)
			}

			s := proxy.NewServer(cfg, st)
			// [[bulk-prompt-answer-ux]] hot-swap: the burst sweeper
			// loads the profiles file when applying a profile-swap
			// override. Record the path the operator started with so
			// the swap loads from the SAME source.
			s.SetProfilesPath(resolvedProfilesPath)

			// #252 Slice 1: build the audit-export fan-out from the
			// transport flags. License gate fires BEFORE any IO so the
			// operator's license-rejected case never opens a webhook
			// connection / log file. Both transports are optional;
			// neither configured = no audit-export (FREE-tier default).
			//
			// #257 webhook presets: vendor-native body/header overlays
			// are passed through to the WebhookPusher; the preset
			// adapter dispatches per-batch at send-time.
			//
			// Heartbeat is layered on the same exporter — its periodic
			// HEARTBEAT events + heartbeat_gap SECURITY_ALERTs flow
			// through whichever transports are configured. When no
			// transport is wired AND heartbeat is enabled, the
			// heartbeater still runs (stderr line + /healthz degraded
			// flag are useful on their own); the OCSF events are simply
			// dropped on the floor because there's nowhere to send them.
			// #311 / §A10 — env-var fallback for the rotation trio. CLI
			// flag wins when explicitly set; otherwise the matching
			// $DBOUNCE_AUDIT_LOG_MAX_SIZE_MB / _MAX_AGE_DAYS /
			// _DB_RETENTION_DAYS env var is consulted; otherwise the
			// audit-package default (matches LOG-RETENTION.md) wins.
			resolveInt64EnvDB := func(flagName string, flagVal int64, envName string) int64 {
				if cmd.Flags().Changed(flagName) {
					return flagVal
				}
				if v := os.Getenv(envName); v != "" {
					if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
						return parsed
					}
				}
				return flagVal
			}
			resolveIntEnvDB := func(flagName string, flagVal int, envName string) int {
				if cmd.Flags().Changed(flagName) {
					return flagVal
				}
				if v := os.Getenv(envName); v != "" {
					if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
						return parsed
					}
				}
				return flagVal
			}
			effAuditLogMaxSizeMB := resolveInt64EnvDB("audit-log-max-size-mb", auditLogMaxSizeMB, "DBOUNCE_AUDIT_LOG_MAX_SIZE_MB")
			effAuditLogMaxAgeDays := resolveIntEnvDB("audit-log-max-age-days", auditLogMaxAgeDays, "DBOUNCE_AUDIT_LOG_MAX_AGE_DAYS")
			effAuditDBRetentionDays := resolveIntEnvDB("audit-db-retention-days", auditDBRetentionDays, "DBOUNCE_AUDIT_DB_RETENTION_DAYS")
			auditExporter, exporterErr := buildAuditExporter(
				auditLogPath, auditLogFsync,
				effAuditLogMaxSizeMB, effAuditLogMaxAgeDays, effAuditDBRetentionDays,
				auditWebhookURL, auditWebhookToken,
				auditWebhookBatchSize, allowInternalWebhook,
				auditWebhookPreset, auditWebhookTags, auditWebhookSentinelTable,
				auditAlertRoutesPath,
				heartbeatInterval, heartbeatGap,
				auditExportHealthInterval,
				fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
				upstreamURL,
				recordSessionsDir,
				securityLakeBucket, securityLakeRegion, securityLakeRoleARN,
				securityLakeRotationSeconds,
				auditObjectStorageEndpoint, auditObjectStorageBucket,
				auditObjectStoragePrefix, auditObjectStorageRegion,
				auditObjectStorageCredentialsFile,
				auditObjectStorageRotationMinutes,
				auditObjectStorageMaxSizeMB,
				auditObjectStorageInstanceID,
			)
			if exporterErr != nil {
				return exporterErr
			}
			if auditExporter != nil {
				s.SetAuditExporter(auditExporter)
				// Close the exporter AFTER the proxy shuts down so any
				// in-flight final-decision events get drained to disk +
				// flushed to webhook. 5s is the same shutdown budget the
				// proxy uses for its other transports. Exporter.Shutdown
				// stops the heartbeater FIRST (see exporter.go) so its
				// in-flight final tick drains before transports close.
				defer func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = auditExporter.Shutdown(ctx)
				}()
			}

			// #324c — wire the dynamic-deny watcher's emit callback now
			// that the Server + audit exporter exist. Each reload bumps
			// the matching counter on the Server + emits a synthetic
			// ADMIN_ACTION OCSF event through the wired exporter so a
			// SIEM dashboard sees activity. Instance-level transitions
			// (now_denied / now_allowed) emit dbounce-specific actions
			// distinct from the cross-product `dynamic_deny.reloaded` /
			// `dynamic_deny.parse_error` shapes.
			if ddWatcher != nil {
				ddWatcher.SetStderr(cmd.ErrOrStderr())
				listenerHost := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
				emit := func(reason dynamicdeny.ReloadReason, rs *dynamicdeny.RuleSet, parseErr error) {
					switch reason {
					case dynamicdeny.ReasonParseError:
						s.BumpDynamicDenyParseError()
					default:
						s.BumpDynamicDenyReload()
					}
					var action audit.AdminActionKind
					switch reason {
					case dynamicdeny.ReasonParseError:
						action = audit.AdminActionKindDynamicDenyParseError
					case dynamicdeny.ReasonInstanceNowDenied:
						action = audit.AdminActionKindDynamicDenyInstanceNowDenied
					case dynamicdeny.ReasonInstanceNowAllowed:
						action = audit.AdminActionKindDynamicDenyInstanceNowAllowed
					default:
						action = audit.AdminActionKindDynamicDenyReloaded
					}
					details := map[string]any{
						"dynamic_deny_reload_reason": string(reason),
					}
					if rs != nil {
						details["dynamic_denies_count"] = len(rs.Rules)
						details["dynamic_denies_path"] = rs.SourcePath
					}
					if parseErr != nil {
						details["dynamic_deny_parse_error"] = parseErr.Error()
					}
					// Surface the denying rule id alongside the
					// transition action so a SIEM consumer joining
					// `dynamic_deny.instance_now_denied` ->
					// `dynamic_deny.connection_refused` on rule_id
					// sees both keyed identically.
					if reason == dynamicdeny.ReasonInstanceNowDenied {
						if id, r := ddWatcher.DenyingRule(); id != "" {
							details["dynamic_deny_rule_id"] = id
							details["dynamic_deny_reason_detail"] = r
						}
					}
					if auditExporter != nil && auditExporter.Enabled() {
						evt := audit.NewAdminActionEvent(listenerHost,
							audit.AdminActionInfo{
								Action:       action,
								Actor:        "dbounce-dynamic-deny-watcher",
								ResourceType: "dynamic_denies_file",
								ResourceID:   ddWatcher.Path(),
								Result:       "success",
								Details:      details,
							})
						_ = auditExporter.Emit(context.Background(), evt)
					}
				}
				ddWatcher.SetEmitFunc(emit)
				if startErr := ddWatcher.Start(cmd.Context()); startErr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"dbounce: dynamic-denies: watcher failed to start: %v\n",
						startErr)
				}
				snap := ddWatcher.Snapshot()
				ruleCount := 0
				if snap != nil {
					ruleCount = len(snap.Rules)
				}
				denied := ddWatcher.InstanceDenied()
				denyingID, denyingReason := ddWatcher.DenyingRule()
				deniedSuffix := "false"
				if denied {
					deniedSuffix = fmt.Sprintf("true (rule_id=%s; %s)", denyingID, denyingReason)
				}
				ddBannerLine = fmt.Sprintf(
					"dynamic-denies: %d rules loaded from %s (%d applied to dbounce upstream; watching for changes)\nupstream-denied: %s",
					ruleCount, ddWatcher.Path(), ruleCount, deniedSuffix)
			} else if !disableDynamicDenies {
				ddBannerLine = "dynamic-denies: disabled (no path resolved)"
			} else {
				ddBannerLine = "dynamic-denies: disabled (--disable-dynamic-denies)"
			}

			// Banner per the agent-parity requirement + the read-write
			// framing the safe-default profile (D-Slice 7) will hook
			// into. Goes to stderr so stdout stays clean.
			//
			// LOW-D8-13 (AUDIT-WB-DSLICES-1-8.md): when --quiet-banner
			// is set, emit ONLY the listener address + dialect.
			writeStartupBanner(os.Stderr, bannerOpts{
				Cfg:                  cfg,
				StoredAuditDBPath:    st.Path(),
				UpstreamURL:          upstreamURL,
				UpstreamCACert:       upstreamCACert,
				ResolvedUpstream:     resolvedUpstream,
				ActiveProfileName:    activeProfile.Name,
				ResolvedProfilesPath: resolvedProfilesPath,
				ProfileFromFlag:      profileFromFlag,
				ProfileEnvSet:        os.Getenv(envProfileVar) != "",
				Quiet:                quietBanner,
				AuditExporter:        auditExporter,
			})
			// #324c — dynamic-denies banner line. One line (with optional
			// upstream-denied second line) per [[cross-product-agent-
			// parity]]; suppressed by --quiet-banner like the rest of the
			// banner.
			if !quietBanner && ddBannerLine != "" {
				fmt.Fprintln(os.Stderr, ddBannerLine)
			}
			// #254 — preset-derivation banner sits AFTER the standard
			// startup banner so the operator sees which settings came
			// from the preset (vs. their own flags / env). Suppressed
			// when --quiet-banner is set, mirroring the LOW-D8-13 quiet
			// posture for the rest of the banner. Same format across
			// all four Bounce products per [[cross-product-agent-
			// parity]].
			if !quietBanner {
				for _, line := range presetBannerLines {
					fmt.Fprintln(os.Stderr, line)
				}
				// #304 / §A17 (F-304-2) — known-caveats banner. Emits one
				// line per §B entry whose triggering config is detected.
				// Quiet when no triggering config applies, per the
				// founder direction "the signal should be useful, not
				// noise." Full doc: `dbounce doctor caveats`. Sibling
				// products (ibounce / kbounce / gbounce) ship the same
				// startup hook per [[cross-product-agent-parity]].
				//
				// Trigger inputs:
				//   - SafeDefaultProfile: active profile is the cross-
				//     product safe-default deny-floor (kicks B6 + B7).
				//   - RedactNumericsEnabled: --redact-numerics is a
				//     post-v1.0 flag (see KNOWN-CAVEATS §B7); always
				//     false here until the flag ships.
				safeDefault := false
				if activeProfile != nil && activeProfile.Name == "safe-default" {
					safeDefault = true
				}
				for _, line := range caveats.BannerLines(caveats.Trigger{
					SafeDefaultProfile:    safeDefault,
					RedactNumericsEnabled: false,
				}) {
					fmt.Fprintln(os.Stderr, line)
				}
				// §A19 profile-upgrade-blindness banner (#321). Only
				// fires when the operator's installed profile is
				// missing a safety-floor field AND they haven't
				// acknowledged the current shipped-defaults version.
				// Convenience / detection / audit misses don't trigger
				// the startup line — operators see those on explicit
				// `dbounce profile doctor` invocation.
				if line := profile.StartupBannerLine("dbounce", resolvedProfilesPath); line != "" {
					fmt.Fprintln(os.Stderr, line)
				}
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			serveErr := make(chan error, 1)
			go func() {
				err := s.Serve()
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					serveErr <- err
					return
				}
				serveErr <- nil
			}()

			select {
			case <-ctx.Done():
				log.Info().Msg("dbounce received shutdown signal")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := s.Shutdown(shutdownCtx); err != nil {
					return fmt.Errorf("shutdown: %w", err)
				}
				if err := <-serveErr; err != nil {
					return err
				}
				fmt.Fprintln(os.Stderr, "dbounce stopped.")
				return nil
			case err := <-serveErr:
				return err
			}
		},
	}
	cmd.Flags().IntVar(&port, "port", 5433,
		"TCP port for the SQL wire-protocol listener (loopback only by default).")
	cmd.Flags().StringVar(&host, "host", "127.0.0.1",
		"Interface to bind the wire-protocol listener. Anything other than "+
			"127.0.0.1 / ::1 / localhost requires --i-know-this-binds-externally.")
	cmd.Flags().StringVar(&mgmtHost, "mgmt-host", "127.0.0.1",
		"Interface to bind the management HTTP listener (/healthz). Loopback by default.")
	cmd.Flags().IntVar(&mgmtPort, "mgmt-port", 8768,
		"TCP port for the management HTTP listener (/healthz). Distinct from "+
			"kbounce's 8766 and ibounce's 8767 so all three products coexist.")
	cmd.Flags().StringVar(&modeStr, "mode", "cooperative",
		"cooperative | transparent. cooperative = parse + log + advisory. "+
			"transparent = DENY verdicts return a SQL error (D-Slice 2+).")
	cmd.Flags().StringVar(&defaultPolStr, "default-policy", "deny",
		"allow | deny. What transparent mode does when no rule matches. "+
			"Scaffolding for D-Slice 3 (no rule engine yet).")
	cmd.Flags().StringVar(&dialectStr, "dialect", "postgres",
		"SQL wire-protocol dialect: postgres (default) | mysql | snowflake | bigquery. "+
			"postgres + mysql ship native wire-protocol proxies; snowflake + "+
			"bigquery ship as JDBC-driver-shim only (no wire-protocol proxy "+
			"in v1.0 — `dbounce run --dialect snowflake|bigquery` fails fast "+
			"pointing at docs/SHIM-INTEGRATION.md, which describes the "+
			"shim-wrapping pattern that delivers `dbounce decide` calls to "+
			"the parser + rule engine for these dialects).")
	cmd.Flags().StringVar(&upstreamURL, "upstream", "",
		"Upstream DB URL (e.g. postgres://user@host:5432/db). When set, "+
			"dbounce dials this on every inbound session + forwards SCRAM "+
			"auth verbatim + proxies ALLOW verdicts. When empty, dbounce "+
			"runs in observation-only mode (D-Slice 1 behavior).")
	cmd.Flags().StringVar(&upstreamCACert, "upstream-ca-cert", "",
		"Optional CA bundle (PEM) for outbound TLS validation. Empty = "+
			"system trust store. Has no effect when --upstream-tls=skip "+
			"or --upstream-tls=disable.")
	cmd.Flags().StringVar(&upstreamTLSStr, "upstream-tls", "verify",
		"Outbound TLS mode: verify | skip | disable. verify (default) "+
			"validates the upstream's cert against the system trust + any "+
			"--upstream-ca-cert. skip disables verification (self-signed "+
			"dev clusters; never production). disable refuses TLS even "+
			"when the upstream offers it.")
	cmd.Flags().BoolVar(&allowInternalUpstream, "allow-internal-upstream", false,
		"Opt-in: permit --upstream hosts that resolve to internal IP "+
			"ranges (127.0.0.0/8, 169.254.0.0/16 incl. AWS/GCP/Azure "+
			"metadata, 10/8, 172.16/12, 192.168/16, ::1, fe80::/10, "+
			"fc00::/7) or .internal / .local TLDs. Default false rejects "+
			"these to defend against SSRF-shaped abuse of operator-"+
			"influenced upstream URLs (MED-D8-06 from "+
			"AUDIT-WB-DSLICES-1-8.md). Pass only when the upstream is a "+
			"legitimate intranet DB.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite audit DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().BoolVar(&forceExternalBind, "i-know-this-binds-externally", false,
		"Required acknowledgement when --host is anything other than 127.0.0.1 "+
			"/ ::1 / localhost. Binding externally exposes dbounce's "+
			"credential-handling surface (once D-Slice 2 lands SCRAM "+
			"pass-through). Don't pass without a specific reason.")
	cmd.Flags().BoolVar(&forceExternalMgmtBind, "i-know-mgmt-binds-externally", false,
		"Required acknowledgement when --mgmt-host is anything other than "+
			"127.0.0.1 / ::1 / localhost. /healthz exposes operator-configured "+
			"fields including the pause.reason free-text. HIGH-D8-04 from "+
			"AUDIT-WB-DSLICES-1-8.md. Don't pass without a specific reason.")

	// D-Slice 4: listener-side TLS for the SQL wire-protocol port.
	cmd.Flags().StringVar(&listenerTLSCert, "listener-tls-cert", "",
		"PEM cert for the SQL wire-protocol listener. Pair with "+
			"--listener-tls-key. When both are set, dbounce answers PG SSLRequest "+
			"with 'S' + performs the TLS handshake before the StartupMessage "+
			"parser fires. Generate via `dbounce init-tls`.")
	cmd.Flags().StringVar(&listenerTLSKey, "listener-tls-key", "",
		"PEM private key for the SQL wire-protocol listener (matches --listener-tls-cert).")
	cmd.Flags().StringVar(&listenerTLSClientCA, "listener-tls-client-ca", "",
		"PEM CA bundle clients' certs are verified against when "+
			"--require-client-cert is set. Required for mTLS.")
	cmd.Flags().BoolVar(&requireClientCert, "require-client-cert", false,
		"Reject TLS clients that don't present a cert signed by --listener-tls-client-ca. "+
			"Opt-in mTLS. Has no effect when --listener-tls-cert is unset.")

	// D-Slice 4: management-listener TLS for /healthz.
	cmd.Flags().StringVar(&mgmtTLSCert, "management-tls-cert", "",
		"PEM cert for the management HTTP listener. Pair with "+
			"--management-tls-key. When both are set, /healthz is served over HTTPS. "+
			"Generate via `dbounce init-tls`.")
	cmd.Flags().StringVar(&mgmtTLSKey, "management-tls-key", "",
		"PEM private key for the management HTTP listener (matches --management-tls-cert).")

	// D-Slice 7: environment profile flags.
	cmd.Flags().StringVar(&profileName, "profile", "",
		"Active environment profile. Built-in: 'full-user' (passthrough, "+
			"default) and 'safe-default' (sql_read_only baseline + "+
			"AST-walk Layer 2 backstop for mutations). Community "+
			"profiles install via `dbounce profile install --from URL`. "+
			"Falls back to "+envProfileVar+" env var; defaults to "+
			"'full-user' if neither is set. Profile denies are a HARD "+
			"FLOOR — a permissive task scope CANNOT override them. "+
			"Legacy aliases ('readonly', 'prod-readonly', 'none') "+
			"resolve in v1.0 and are removed in v1.1.")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.dbounce/profiles.yaml). "+
			"Honors DBOUNCE_PROFILES_PATH env var if --profiles-path unset.")
	// D-Slice 8: async deny-prompt UX.
	cmd.Flags().BoolVar(&promptOnDeny, "prompt-on-deny", false,
		"When in transparent mode, every DENY enqueues a row in "+
			"pending_prompts. Drain the queue with `dbounce prompts list` "+
			"+ `dbounce prompts answer ID --kind {ignore|always|profile}`. "+
			"Has no effect in cooperative mode (advisory verdicts aren't "+
			"prompted) or during an active pause window (operator already "+
			"said allow).")
	// #203 synchronous deny-prompt v1.1.
	cmd.Flags().BoolVar(&syncPromptOnDeny, "sync-prompt-on-deny", false,
		"Synchronous companion to --prompt-on-deny (mutually exclusive). "+
			"In transparent mode, every DENY BLOCKS the SQL request for up "+
			"to --sync-prompt-timeout waiting for an operator answer via "+
			"`dbounce prompts answer ID --kind {ignore|always|profile}`. "+
			"Answer kind=always/profile → forwards the original SQL to "+
			"--upstream + returns the actual upstream result rows. Answer "+
			"kind=ignore (or timeout with --sync-prompt-default=deny) → "+
			"returns the DENY SQL error. Requires --upstream "+
			"(observation-only mode has nowhere to forward to). Pause "+
			"window supersedes. Per [[ibounce-honest-positioning]]: this "+
			"is a deterrent UX for legitimate human-in-loop, not "+
			"adversarial defense.")
	cmd.Flags().StringVar(&syncPromptTimeoutStr, "sync-prompt-timeout", "30s",
		"How long --sync-prompt-on-deny blocks waiting for an operator "+
			"answer before applying --sync-prompt-default. Range 5s-300s; "+
			"default 30s.")
	cmd.Flags().StringVar(&syncPromptDefaultStr, "sync-prompt-default", "deny",
		"Verdict --sync-prompt-on-deny applies on timeout: allow | deny. "+
			"Default deny matches the operator's likely posture ('if I'm "+
			"not here to approve, refuse'); allow suits the rarer 'fail-"+
			"open if I'm asleep' stance.")
	cmd.Flags().BoolVar(&quietBanner, "quiet-banner", false,
		"Reduce the startup banner to listener address + dialect only. "+
			"Suppresses the mode / default-policy / profile / upstream / "+
			"audit-db-path fields whose combination fingerprints the "+
			"deployment when the banner is forwarded to centralized "+
			"observability. Full configuration remains available via "+
			"/healthz on the management endpoint. Recommended for "+
			"production deployments where stderr is shipped to a shared "+
			"log aggregator. LOW-D8-13 from AUDIT-WB-DSLICES-1-8.md.")
	cmd.Flags().BoolVar(&redactLiterals, "redact-literals", false,
		"When true, the audit row's recorded SQL has its quoted string "+
			"literals swapped for [REDACTED] before persistence (numeric "+
			"literals + identifiers preserved). The row's "+
			"statement_redacted column is also set so audit consumers "+
			"know the SQL is not replayable. Recommended for deployments "+
			"where audit data is exposed to MCP-connected agents or "+
			"centralized observability — keeps secret-shaped string "+
			"literals (passwords, API keys, PII) out of the log. Default "+
			"false preserves full audit-reconstruction fidelity. "+
			"MED-D8-09 from AUDIT-WB-DSLICES-1-8.md.")
	// #252 Slice 1 audit-export flags. See
	// [[security-team-audit-export]] memo for the full design + cross-
	// product schema.
	cmd.Flags().StringVar(&auditLogPath, "audit-log-path", "",
		"Path to a JSONL audit-export file. When set, every decision is "+
			"appended (O_APPEND|O_CREAT|O_WRONLY perm 0600) for security-"+
			"team consumption. Append-only; rotation via logrotate / "+
			"Fluent Bit / Vector / fluentd (NOT built in — bundling "+
			"rotation here would duplicate well-trodden tools). FREE tier "+
			"(all license tiers). Pairs with --audit-log-fsync for "+
			"compliance-grade durability. #252 Slice 1.")
	cmd.Flags().BoolVar(&auditLogFsync, "audit-log-fsync", false,
		"Opt-in: fdatasync the audit log after every line. Default false "+
			"batches at OS page-cache for throughput (risks losing the "+
			"trailing few microseconds of events on a hard kill). True "+
			"flushes per-line for compliance-grade durability at ~hundreds "+
			"of microseconds of additional latency per decision. Has no "+
			"effect when --audit-log-path is unset.")
	// #311 / §A10 — rotation thresholds. Sentinel -1 = "use audit-pkg
	// default (matches LOG-RETENTION.md)." 0 = "operator explicitly
	// disabled this trigger." Same names across all four Bounce
	// products per [[cross-product-agent-parity]].
	cmd.Flags().Int64Var(&auditLogMaxSizeMB, "audit-log-max-size-mb", -1,
		"#311 — rotate the JSONL audit log when its size exceeds N MB. "+
			"0 disables size-triggered rotation. Default 100 (matches the "+
			"cross-product LOG-RETENTION.md spec). Rotated files are gzip'd "+
			"in-place and live until `dbounce logs purge` reaps them (per "+
			"[[creates-never-mutates]] the active log is never destroyed "+
			"automatically). Honors $DBOUNCE_AUDIT_LOG_MAX_SIZE_MB for "+
			"non-flag overrides.")
	cmd.Flags().IntVar(&auditLogMaxAgeDays, "audit-log-max-age-days", -1,
		"#311 — rotate the JSONL audit log when its mtime is older than N "+
			"days. 0 disables age-triggered rotation. Default 7 (matches "+
			"the cross-product LOG-RETENTION.md spec). Pairs with --audit-"+
			"log-max-size-mb; whichever fires first wins. Honors "+
			"$DBOUNCE_AUDIT_LOG_MAX_AGE_DAYS for non-flag overrides.")
	cmd.Flags().IntVar(&auditDBRetentionDays, "audit-db-retention-days", -1,
		"#311 — purge rotated audit DB archives older than N days. 0 "+
			"disables DB retention. Default 30 (matches the cross-product "+
			"LOG-RETENTION.md spec). Active audit DB is NEVER deleted by "+
			"this path; only rotated archives are eligible. Honors "+
			"$DBOUNCE_AUDIT_DB_RETENTION_DAYS for non-flag overrides.")
	cmd.Flags().StringVar(&auditWebhookURL, "audit-webhook-url", "",
		"HTTPS webhook URL to POST audit-export events to. ENTERPRISE tier "+
			"(license-gated; #235 will land the license-file plumbing — "+
			"until then the flag fails at parse with the FREE-tier "+
			"JSONL fallback documented). Bounded queue + exponential "+
			"backoff retry + drop-on-overflow with synthetic AUDIT_DROPPED "+
			"events. SSRF gate REUSES the --upstream SSRF closure (MED-D8-"+
			"06) — internal-range hosts rejected unless "+
			"--allow-internal-webhook is set. Pair with --audit-webhook-"+
			"token for the Bearer credential.")
	cmd.Flags().StringVar(&auditWebhookToken, "audit-webhook-token", "",
		"Bearer credential the webhook POST sends as Authorization. "+
			"Required when --audit-webhook-url is set. NEVER appears in "+
			"the startup banner, /healthz, audit log file, retry-failure "+
			"messages, or the MCP status tool — masked at every emission "+
			"point. Prefer reading from a file via $(cat /path/to/token) "+
			"on launch rather than echoing into shell history.")
	cmd.Flags().IntVar(&auditWebhookBatchSize, "audit-webhook-batch-size", 1,
		"How many decisions fit in one webhook POST body (newline-delimited "+
			"JSON). Default 1 emits every decision. ≥2 reduces request "+
			"overhead for high-throughput orgs at the cost of retry "+
			"granularity (one failed batch loses N events). Max 1000.")
	cmd.Flags().BoolVar(&allowInternalWebhook, "allow-internal-webhook", false,
		"Opt-in: permit --audit-webhook-url hosts that resolve to internal "+
			"IP ranges (127.0.0.0/8, 169.254.0.0/16 incl. AWS/GCP/Azure "+
			"metadata, 10/8, 172.16/12, 192.168/16, ::1, fe80::/10, "+
			"fc00::/7) or .internal / .local TLDs. Default false rejects "+
			"these to defend against SSRF-shaped abuse of operator-"+
			"influenced webhook URLs (same gate as MED-D8-06 closure on "+
			"--upstream). Pass only when the webhook collector is a "+
			"legitimate intranet endpoint.")
	// #257 webhook presets — vendor-native body/header overlays applied
	// at send-time. The canonical OCSF event in the JSONL log file is
	// UNCHANGED — these flags ONLY affect the webhook wire shape. Per
	// [[cross-product-agent-parity]] the same names ship in kbounce +
	// ibounce.
	cmd.Flags().StringVar(&auditWebhookPreset, "audit-webhook-preset", "generic",
		"Webhook body/header shape: generic | datadog | splunk-hec | sentinel. "+
			"generic (default) = backward-compat Bearer auth + NDJSON OCSF body. "+
			"datadog = DD-API-KEY header + ddsource/service/ddtags/status/message "+
			"overlay onto the OCSF event. splunk-hec = `Splunk <token>` auth + "+
			"HEC event-wrapped NDJSON with sourcetype=iam_jit:bouncer:dbounce. "+
			"sentinel = Microsoft Sentinel Log Analytics workspace HMAC-SHA256-"+
			"signed SharedKey auth (URL must be the workspace's "+
			"<workspace-id>.ods.opinsights.azure.com/api/logs endpoint + "+
			"--audit-webhook-token must be the workspace shared key). #257.")
	cmd.Flags().StringVar(&auditWebhookTags, "audit-webhook-tags", "",
		"Free-form tags appended to the datadog preset's ddtags (format "+
			"k1:v1,k2:v2). Ignored by other presets. Vendor-side parsing applies "+
			"— dbounce does NOT pre-validate the tag syntax (a malformed tag "+
			"surfaces as a Datadog API 400 + retry-failure visible via the "+
			"dbounce_audit_export_status MCP tool).")
	cmd.Flags().StringVar(&auditWebhookSentinelTable, "audit-webhook-sentinel-table",
		"IamJitBouncer",
		"Log Analytics custom-table name (Log-Type header) for the sentinel "+
			"preset. Default IamJitBouncer is the shared cross-product table "+
			"per [[audit-webhook-presets]] — one custom-log table holds "+
			"dbounce + kbounce + ibounce rows; operators who prefer per-product "+
			"tables override this per-deployment. Sentinel custom-log tables "+
			"have a max name length of 100 chars + must match [A-Za-z0-9_]+.")
	cmd.Flags().StringVar(&auditAlertRoutesPath, "alert-routes", "",
		"#280 (ENTERPRISE tier — license-gated) — YAML file describing "+
			"per-org notification routing. When set, the multi-destination "+
			"routing engine activates: each event is matched against the "+
			"configured routes' match blocks + dispatched to the route's "+
			"destinations (webhook / pagerduty / slack). When unset, the "+
			"existing single-webhook --audit-webhook-url path stays exactly "+
			"as today (zero regression). Secrets must use ${ENV_VAR} "+
			"interpolation; literal tokens in the YAML are refused. Use "+
			"`dbounce config preview-routes` to dry-run a sample event "+
			"against the file before deploying. Setting BOTH --alert-routes "+
			"and --audit-webhook-url ignores the latter (with a warning).")
	// Heartbeat — periodic OCSF liveness event + in-process gap
	// watchdog per [[prompt-injection-disable-bouncer-threat]]. Default
	// OFF preserves the safety-not-surveillance posture; opt-in via
	// --heartbeat-interval. Sibling agents in ibounce + kbounce ship
	// the SAME flag names so a single cross-product SIEM absence rule
	// keyed on activity_name=heartbeat works for all three.
	cmd.Flags().StringVar(&heartbeatIntervalStr, "heartbeat-interval", "0",
		"Emit a periodic HEARTBEAT OCSF event at this cadence so a SIEM "+
			"consumer can alert on ABSENCE (the bouncer was killed / "+
			"paused / suspended). Default 0 disables. Practical range 1s "+
			"to 1h; recommended 30s for high-fidelity deployments / 5m for "+
			"low-overhead production. Pairs with --heartbeat-gap-threshold "+
			"for the in-process gap watchdog (defaults to 2.5x interval). "+
			"Per [[prompt-injection-disable-bouncer-threat]].")
	cmd.Flags().StringVar(&heartbeatGapThresholdStr, "heartbeat-gap-threshold", "0",
		"How far past --heartbeat-interval the in-process watchdog waits "+
			"before firing a heartbeat_gap SECURITY_ALERT (also writes to "+
			"stderr + flips /healthz status to 'degraded'). Default 0 "+
			"resolves to 2.5x --heartbeat-interval. Has no effect when "+
			"--heartbeat-interval is 0.")

	// [[audit-export-failure-visibility]] Part 3: periodic
	// audit_export_degraded alert when the export pipeline itself is
	// failing (log perm-denied / disk full / webhook unreachable /
	// webhook auth failed). Default 0 disables — operator opt-in. The
	// /healthz audit_export_health block + the `dbounce audit-export
	// health` CLI command remain available regardless of this flag;
	// this flag controls only the periodic OCSF alert + stderr line.
	// Sibling agents in ibounce + kbounce ship the SAME flag name so
	// a cross-product SIEM rule keyed on rule_id="audit_export_
	// degraded" works for all three.
	cmd.Flags().StringVar(&auditExportHealthIntervalStr, "audit-export-health-interval", "0",
		"Poll the audit-export pipeline at this cadence + fire the "+
			"audit_export_degraded OCSF SECURITY_ALERT when degraded "+
			"(log writes failing, webhook unreachable, webhook auth "+
			"failed). Default 0 disables. Practical range 5s-1h; "+
			"recommended 30s. Independent of --heartbeat-interval. "+
			"Per [[audit-export-failure-visibility]]: silent audit "+
			"failures are a stealth bypass; making them loud is the fix.")
	cmd.Flags().StringVar(&auditEventsToken, "audit-events-token", "",
		"Bearer token required for GET /audit/events (#271) when the "+
			"mgmt port is bound externally. Empty + loopback mgmt-host = "+
			"no auth (the loopback bind is the trust anchor). Empty + "+
			"external mgmt-host = dbounce refuses to start.")
	cmd.Flags().StringVar(&recordSessionsDir, "record-sessions-dir", "",
		"#285 — per-session NDJSON recording directory. When set, every "+
			"audit event is also written to {dir}/{agent.session_id}.ndjson "+
			"(one file per agent session). Replayable via `iam-jit session "+
			"replay <FILE>`. File mode 0o600. Default off; the recorder "+
			"captures agent identity + operation details so it ships opt-in.")
	// #258 — AWS Security Lake audit-export adapter. Per [[no-hosted-
	// saas]] + [[self-host-zero-billing-dependency]] the bucket lives
	// in the operator's AWS account; iam-jit-the-company never
	// receives the data.
	cmd.Flags().StringVar(&securityLakeBucket, "security-lake-bucket", "",
		"#258 — name of the operator-owned S3 bucket that AWS Security "+
			"Lake auto-ingests from. When set, every OCSF event is also "+
			"written as a parquet file at `s3://<bucket>/region=<r>/"+
			"eventday=<YYYYMMDD>/eventhour=<HH>/api_activity-<unix-ms>."+
			"parquet`. Requires --security-lake-region; honours "+
			"--security-lake-role-arn if set otherwise uses the default "+
			"AWS credential chain.")
	cmd.Flags().StringVar(&securityLakeRegion, "security-lake-region", "",
		"#258 — AWS region the Security Lake bucket lives in. Required "+
			"when --security-lake-bucket is set. Becomes the `region=<r>` "+
			"partition key on every parquet file.")
	cmd.Flags().StringVar(&securityLakeRoleARN, "security-lake-role-arn", "",
		"#258 — optional IAM role to assume for Security Lake writes "+
			"(STS AssumeRole). When unset the default AWS credential chain "+
			"is used. Recommended for cross-account deployments where the "+
			"bucket lives in a dedicated security account.")
	cmd.Flags().IntVar(&securityLakeRotationSeconds,
		"security-lake-rotation-seconds", audit.SecurityLakeDefaultRotationSeconds,
		"#258 — how often the in-memory parquet batch flushes to S3. "+
			"Default 300 (5 minutes) matches the Security Lake custom-"+
			"source ingest cadence. A 10 MiB size cap also forces a flush, "+
			"whichever fires first.")
	// #317 — cloud-neutral S3-compatible NDJSON object-storage sink.
	// All fields OFF by default. Per [[self-host-zero-billing-
	// dependency]] the bucket is operator-owned. Per [[don't-tailor-
	// to-lighthouse]]: generic S3-compat. Per [[cross-product-agent-
	// parity]] the flag shape is identical to ibounce + kbounce +
	// gbounce.
	cmd.Flags().StringVar(&auditObjectStorageEndpoint,
		"audit-object-storage-endpoint", "",
		"#317 — S3 API endpoint URL. Required when "+
			"--audit-object-storage-bucket is set. Examples: "+
			"https://s3.us-east-1.amazonaws.com (AWS S3); "+
			"https://<accountid>.r2.cloudflarestorage.com (Cloudflare R2); "+
			"https://minio.internal:9000 (MinIO); "+
			"https://storage.googleapis.com (GCS interop); "+
			"https://s3.us-west-002.backblazeb2.com (Backblaze B2); "+
			"https://nyc3.digitaloceanspaces.com (DigitalOcean Spaces).")
	cmd.Flags().StringVar(&auditObjectStorageBucket,
		"audit-object-storage-bucket", "",
		"#317 — name of the operator-owned bucket the writer appends "+
			"NDJSON files into. Operator creates the bucket; dbounce "+
			"NEVER creates buckets. When set, every OCSF event is also "+
			"written as a gzip-compressed NDJSON line into "+
			"`{prefix}/year=YYYY/month=MM/day=DD/hour=HH/"+
			"dbounce-{instance_id}-{timestamp}.jsonl.gz`. Hive-style "+
			"partitioning lets Athena / BigQuery / Spark / Trino query "+
			"the bucket directly.")
	cmd.Flags().StringVar(&auditObjectStoragePrefix,
		"audit-object-storage-prefix", "",
		"#317 — key prefix inside the bucket (e.g. `bounce-audit/prod`). "+
			"Empty = bucket root.")
	cmd.Flags().StringVar(&auditObjectStorageRegion,
		"audit-object-storage-region", audit.ObjectStorageDefaultRegion,
		"#317 — region for the SigV4 signature. AWS S3: real region. "+
			"Cloudflare R2: `auto`. Vendor-specific otherwise.")
	cmd.Flags().StringVar(&auditObjectStorageCredentialsFile,
		"audit-object-storage-credentials-file", "",
		"#317 — optional explicit credentials file (YAML or INI). "+
			"Overrides AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env "+
			"vars when set.")
	cmd.Flags().IntVar(&auditObjectStorageRotationMinutes,
		"audit-object-storage-rotation-minutes",
		audit.ObjectStorageDefaultRotationMinutes,
		"#317 — rotate the active NDJSON file when N minutes elapse OR "+
			"--audit-object-storage-max-size-mb fires.")
	cmd.Flags().IntVar(&auditObjectStorageMaxSizeMB,
		"audit-object-storage-max-size-mb",
		audit.ObjectStorageDefaultMaxSizeMB,
		"#317 — rotate the active NDJSON file when its in-memory size "+
			"estimate crosses N megabytes.")
	cmd.Flags().StringVar(&auditObjectStorageInstanceID,
		"audit-object-storage-instance-id", "",
		"#317 — override the auto-generated instance identifier "+
			"(hostname-pid) used in the object key.")
	// #324c — dynamic-deny YAML path. Default ~/.iam-jit/dynamic-denies.yaml
	// (resolved via os.UserHomeDir; honors IAM_JIT_DYNAMIC_DENIES_PATH
	// env var). Per [[cross-product-agent-parity]] the flag name +
	// default is identical on the other Bounce products. When the file
	// is absent at startup the watcher waits for it to appear — startup
	// is NOT an error condition (an operator who hasn't installed any
	// dynamic denies still wants the proxy to start cleanly).
	cmd.Flags().StringVar(&dynamicDeniesPath, "dynamic-denies-path", "",
		"#324c — path to the dynamic-deny YAML file. Default "+
			"~/.iam-jit/dynamic-denies.yaml (honors "+
			"$IAM_JIT_DYNAMIC_DENIES_PATH). The file is watched via "+
			"fsnotify (fsevents on macOS, inotify on Linux); rules apply "+
			"to dbounce immediately on file change. Rules that don't "+
			"target dbounce (per the rule's `applied_to` list OR the "+
			"hostname / rds:* heuristic) are silently skipped — a "+
			"single shared file fans out across the Bounce suite. POST "+
			"/admin/dynamic-denies/reload on the mgmt port triggers an "+
			"immediate reload for cross-bouncer fan-out orchestration "+
			"(#324e). Parse errors retain the previous in-memory "+
			"snapshot + emit an admin-action OCSF event. When ANY "+
			"matching rule applies to this dbounce instance, NEW "+
			"connections are refused at PG StartupMessage with SQLSTATE "+
			"42501; existing connections continue normally.")
	cmd.Flags().BoolVar(&disableDynamicDenies, "disable-dynamic-denies", false,
		"#324c — turn the dynamic-deny watcher off entirely. The proxy "+
			"falls back to the pre-#324c behavior (no instance-level "+
			"deny gate). Useful for environments where the operator "+
			"hasn't installed the cross-product CLI yet + the watcher's "+
			"stat()ing of an absent file is undesirable.")
	cmd.Flags().StringVar(&upstreamRDSARN, "upstream-rds-arn", "",
		"#324c — optional RDS ARN identifying the upstream database "+
			"(e.g. arn:aws:rds:us-east-1:123456789012:db:payments-prod). "+
			"When set, dynamic-deny rules whose targets are `arn:aws:rds:*` "+
			"patterns are matched against this ARN in addition to the "+
			"hostname axis. Leave empty to match by hostname only.")
	// #254 — deployment preset. Single-flag shortcut for a common
	// deployment shape. v1.0 ships only `security-observe` per
	// [[deliberate-feature-completion]]; the framework supports more
	// (see docs/DEPLOYMENT-PRESETS.md for the roadmap).
	cmd.Flags().StringVar(&deploymentPreset, "preset", "",
		"#254 — single-flag shortcut for a common deployment shape. "+
			"security-observe = transparent mode + JSONL audit + 30s "+
			"heartbeat + 30s audit-export health poll. Designed for the "+
			"security-team 'gather data first; author profile second' "+
			"starting shape per [[bouncer-mode-selection-for-agents]]. "+
			"Some preset values are HARD (e.g. --mode for security-observe "+
			"— the entire point of the preset is transparent); passing "+
			"them with a different value is an error. Others are SOFT "+
			"(e.g. --audit-log-path); the operator's value wins. Startup "+
			"banner shows which settings are derived from the preset.")
	return cmd
}

// buildAuditExporter constructs the #252 Slice 1 audit-export fan-out
// from CLI flags. Returns nil + nil err when no transports are
// configured AND heartbeat is disabled (FREE-tier default). License
// gate fires BEFORE any IO so a rejected license never opens a webhook
// connection / creates a log file.
//
// listenerHost is the proxy listener "host:port" the exporter stamps
// onto Event.Host; upstreamURL is the upstream's "host:port" stamped
// onto Event.Upstream (or empty when observation-only).
//
// heartbeatInterval > 0 turns on the Heartbeater (periodic OCSF
// liveness events + in-process gap watchdog per
// [[prompt-injection-disable-bouncer-threat]]); heartbeatGap defaults
// inside the heartbeater when 0. The heartbeater is wired to the same
// Exporter as decisions + alerts so a SIEM consumes all three streams
// on one channel.
func buildAuditExporter(
	logPath string, logFsync bool,
	logMaxSizeMB int64, logMaxAgeDays int, dbRetentionDays int,
	webhookURL, webhookToken string, webhookBatchSize int,
	allowInternalWebhook bool,
	webhookPreset, webhookTags, webhookSentinelTable string,
	alertRoutesPath string,
	heartbeatInterval, heartbeatGap time.Duration,
	auditExportHealthInterval time.Duration,
	listenerHost, upstreamURL string,
	recordSessionsDir string,
	securityLakeBucket, securityLakeRegion, securityLakeRoleARN string,
	securityLakeRotationSeconds int,
	auditObjectStorageEndpoint, auditObjectStorageBucket,
	auditObjectStoragePrefix, auditObjectStorageRegion,
	auditObjectStorageCredentialsFile string,
	auditObjectStorageRotationMinutes int,
	auditObjectStorageMaxSizeMB int,
	auditObjectStorageInstanceID string,
) (*audit.Exporter, error) {
	// #258 — Security Lake parse-time validation. Bucket without
	// region (or vice versa) is a misconfiguration; fail-fast so the
	// operator fixes it once rather than seeing a credential probe
	// failure deep in startup.
	if securityLakeBucket != "" && securityLakeRegion == "" {
		return nil, errors.New(
			"dbounce: --security-lake-bucket requires --security-lake-region " +
				"(the region becomes the `region=<r>` partition key on every " +
				"parquet file)")
	}
	if securityLakeRegion != "" && securityLakeBucket == "" {
		return nil, errors.New(
			"dbounce: --security-lake-region requires --security-lake-bucket " +
				"(passing region without a target bucket has no effect)")
	}
	// #317 — object-storage parse-time validation. Bucket without
	// endpoint (or vice versa) is a misconfiguration; fail-fast.
	if auditObjectStorageBucket != "" && auditObjectStorageEndpoint == "" {
		return nil, errors.New(
			"dbounce: --audit-object-storage-bucket requires " +
				"--audit-object-storage-endpoint (the S3 API endpoint URL " +
				"for the operator's cloud provider — examples: " +
				"https://s3.us-east-1.amazonaws.com for AWS S3; " +
				"https://<accountid>.r2.cloudflarestorage.com for " +
				"Cloudflare R2; https://storage.googleapis.com for GCS " +
				"interop)")
	}
	if auditObjectStorageEndpoint != "" && auditObjectStorageBucket == "" {
		return nil, errors.New(
			"dbounce: --audit-object-storage-endpoint requires " +
				"--audit-object-storage-bucket (passing an endpoint " +
				"without a target bucket has no effect)")
	}
	// #280 — per-org routing engine license gate. Same placeholder
	// shape as licensedForAuditWebhook; both wait on #235. The
	// alternative-with-routes-engine path can't fail without going
	// through this gate, so we surface the error before any IO.
	if alertRoutesPath != "" {
		return nil, audit.ErrRoutesLicenseRequired
	}
	var logWriter *audit.LogWriter
	if logPath != "" {
		// #311 / §A10 — sentinel -1 = "use audit-pkg default"; 0 = "operator
		// disabled the trigger." Same resolution pattern across all four
		// Bounce products per [[cross-product-agent-parity]].
		effSize := logMaxSizeMB
		if effSize < 0 {
			effSize = audit.DefaultMaxSizeMB
		}
		effAge := logMaxAgeDays
		if effAge < 0 {
			effAge = audit.DefaultMaxAgeDays
		}
		// dbRetentionDays is consumed by the on-demand `dbounce logs
		// purge` subcommand; the live writer doesn't sweep the DB
		// itself. Surfaced at the run-cmd layer so the operator sees
		// the resolved value on startup.
		_ = dbRetentionDays
		w, err := audit.NewLogWriter(audit.LogOptions{
			Path:       logPath,
			Fsync:      logFsync,
			MaxSizeMB:  effSize,
			MaxAgeDays: effAge,
		})
		if err != nil {
			return nil, fmt.Errorf("audit-log writer: %w", err)
		}
		logWriter = w
	}

	var webhookPusher *audit.WebhookPusher
	if webhookURL != "" {
		// License gate FIRST — before any URL parsing / SSRF check /
		// IO. Per [[deliberate-feature-completion]]: the operator
		// gets a single clear error pointing at the FREE-tier
		// alternative + the future-fix issue, not a stack of
		// validation errors that mask the actual gate.
		if err := licensedForAuditWebhook(); err != nil {
			// Close the log writer if one was opened above so we
			// don't leak a partial-init goroutine on the rejection
			// path.
			if logWriter != nil {
				_ = logWriter.Shutdown(context.Background())
			}
			return nil, err
		}
		// #257 preset selection — parsed here so an unknown name fails
		// at CLI parse with the valid-set error rather than as an
		// opaque WebhookPusher construction error.
		preset, err := audit.ParsePreset(webhookPreset)
		if err != nil {
			if logWriter != nil {
				_ = logWriter.Shutdown(context.Background())
			}
			return nil, err
		}
		p, err := audit.NewWebhookPusher(audit.WebhookOptions{
			URL:                 webhookURL,
			Token:               webhookToken,
			BatchSize:           webhookBatchSize,
			Host:                listenerHost,
			AllowInternal:       allowInternalWebhook,
			Preset:              preset,
			PresetExtraTags:     webhookTags,
			PresetSentinelTable: webhookSentinelTable,
		})
		if err != nil {
			if logWriter != nil {
				_ = logWriter.Shutdown(context.Background())
			}
			return nil, fmt.Errorf("audit-webhook pusher: %w", err)
		}
		webhookPusher = p
	} else if webhookToken != "" {
		// Token without a URL is almost certainly a typo / forgotten
		// --audit-webhook-url. Fail-fast rather than silently ignore.
		if logWriter != nil {
			_ = logWriter.Shutdown(context.Background())
		}
		return nil, errors.New(
			"--audit-webhook-token set but --audit-webhook-url is empty; " +
				"either pair them or drop both flags")
	}

	// Heartbeat / health-monitor can run on their own (stderr line +
	// /healthz degraded flag are useful even without an export
	// transport); when no transport AND no heartbeat AND no
	// audit-export-health monitor is configured, the exporter is a
	// no-op (FREE-tier default).
	if logWriter == nil && webhookPusher == nil &&
		alertRoutesPath == "" &&
		heartbeatInterval == 0 && auditExportHealthInterval == 0 &&
		recordSessionsDir == "" && securityLakeBucket == "" &&
		auditObjectStorageBucket == "" {
		return nil, nil
	}
	upstreamHost := ""
	if upstreamURL != "" {
		// Best-effort: pull the host out for the Event.Upstream stamp.
		// Parsing failure here is non-fatal because upstream.Resolve
		// already validated; the worst case is an empty Upstream field
		// in the emitted events.
		if u, err := url.Parse(upstreamURL); err == nil {
			upstreamHost = u.Host
		}
	}
	// #285 — per-session NDJSON recorder. Default off; only constructed
	// when the operator passed --record-sessions-dir. Start() creates
	// the dir + recovers any stale .partial files. Fatal on failure so
	// an unwritable dir surfaces immediately (mirrors the LogWriter
	// fail-fast above; if the recording sink can't be opened the
	// operator wants to know).
	var sessRecorder *audit.SessionRecorder
	if recordSessionsDir != "" {
		sr, err := audit.NewSessionRecorder(audit.SessionRecorderOptions{
			Dir:            recordSessionsDir,
			BouncerProduct: "dbounce",
		})
		if err != nil {
			if logWriter != nil {
				_ = logWriter.Shutdown(context.Background())
			}
			if webhookPusher != nil {
				_ = webhookPusher.Shutdown(context.Background())
			}
			return nil, fmt.Errorf("session recorder: %w", err)
		}
		if err := sr.Start(); err != nil {
			if logWriter != nil {
				_ = logWriter.Shutdown(context.Background())
			}
			if webhookPusher != nil {
				_ = webhookPusher.Shutdown(context.Background())
			}
			return nil, fmt.Errorf("session recorder: %w", err)
		}
		sessRecorder = sr
	}
	// #258 — Security Lake parquet writer. Default OFF; only
	// constructed when --security-lake-bucket is set. Start() probes
	// credentials (default chain OR AssumeRole when --security-lake-
	// role-arn is set) and refuses to start with a clear error if
	// none are reachable. Per [[no-hosted-saas]] + [[self-host-zero-
	// billing-dependency]] the bucket lives in the operator's AWS
	// account; iam-jit-the-company never receives the data.
	var securityLakeWriter *audit.SecurityLakeWriter
	if securityLakeBucket != "" {
		slw, err := audit.NewSecurityLakeWriter(audit.SecurityLakeWriterOptions{
			Bucket:          securityLakeBucket,
			Region:          securityLakeRegion,
			RoleARN:         securityLakeRoleARN,
			RotationSeconds: securityLakeRotationSeconds,
		})
		if err != nil {
			if logWriter != nil {
				_ = logWriter.Shutdown(context.Background())
			}
			if webhookPusher != nil {
				_ = webhookPusher.Shutdown(context.Background())
			}
			if sessRecorder != nil {
				sessRecorder.Stop()
			}
			return nil, err
		}
		if err := slw.Start(context.Background()); err != nil {
			if logWriter != nil {
				_ = logWriter.Shutdown(context.Background())
			}
			if webhookPusher != nil {
				_ = webhookPusher.Shutdown(context.Background())
			}
			if sessRecorder != nil {
				sessRecorder.Stop()
			}
			return nil, fmt.Errorf(
				"dbounce: Security Lake writer failed to start: %w", err)
		}
		securityLakeWriter = slw
	}
	// #317 — cloud-neutral S3-compat NDJSON object-storage writer.
	// Default OFF; only constructed when --audit-object-storage-bucket
	// is set. Start() probes the bucket so credential / endpoint /
	// bucket-name misconfigurations surface immediately rather than at
	// first flush. Per [[self-host-zero-billing-dependency]] the
	// bucket is operator-owned (operator creates; dbounce never
	// creates).
	var objectStorageWriter *audit.ObjectStorageWriter
	if auditObjectStorageBucket != "" {
		osCreds, err := audit.LoadObjectStorageCredentials(
			auditObjectStorageCredentialsFile)
		if err != nil {
			if logWriter != nil {
				_ = logWriter.Shutdown(context.Background())
			}
			if webhookPusher != nil {
				_ = webhookPusher.Shutdown(context.Background())
			}
			if sessRecorder != nil {
				sessRecorder.Stop()
			}
			if securityLakeWriter != nil {
				securityLakeWriter.Close()
			}
			return nil, err
		}
		osw, err := audit.NewObjectStorageWriter(audit.ObjectStorageWriterOptions{
			EndpointURL:     auditObjectStorageEndpoint,
			Bucket:          auditObjectStorageBucket,
			Prefix:          auditObjectStoragePrefix,
			Region:          auditObjectStorageRegion,
			Credentials:     osCreds,
			Product:         "dbounce",
			InstanceID:      auditObjectStorageInstanceID,
			RotationMinutes: auditObjectStorageRotationMinutes,
			MaxSizeMB:       auditObjectStorageMaxSizeMB,
		})
		if err != nil {
			if logWriter != nil {
				_ = logWriter.Shutdown(context.Background())
			}
			if webhookPusher != nil {
				_ = webhookPusher.Shutdown(context.Background())
			}
			if sessRecorder != nil {
				sessRecorder.Stop()
			}
			if securityLakeWriter != nil {
				securityLakeWriter.Close()
			}
			return nil, err
		}
		if err := osw.Start(context.Background()); err != nil {
			if logWriter != nil {
				_ = logWriter.Shutdown(context.Background())
			}
			if webhookPusher != nil {
				_ = webhookPusher.Shutdown(context.Background())
			}
			if sessRecorder != nil {
				sessRecorder.Stop()
			}
			if securityLakeWriter != nil {
				securityLakeWriter.Close()
			}
			return nil, fmt.Errorf(
				"dbounce: object-storage writer failed to start: %w", err)
		}
		objectStorageWriter = osw
	}
	exp := audit.NewExporter(logWriter, webhookPusher, listenerHost, upstreamHost)
	exp.Recorder = sessRecorder
	exp.SecurityLake = securityLakeWriter
	exp.ObjectStorage = objectStorageWriter
	if heartbeatInterval > 0 {
		hb := audit.NewHeartbeater(audit.HeartbeatOptions{
			Interval:     heartbeatInterval,
			GapThreshold: heartbeatGap,
			Host:         listenerHost,
			Stderr:       os.Stderr,
		})
		hb.SetExporter(exp)
		exp.Heartbeat = hb
		// Start immediately so the first HEARTBEAT lands while the
		// proxy is still binding listeners — earliest possible
		// "alive" signal to the SIEM.
		hb.Start()
	}
	// [[audit-export-failure-visibility]] Part 3: wire the periodic
	// audit_export_degraded alert monitor. Independent of heartbeat
	// — operators may want the audit-export health alert WITHOUT the
	// heartbeat (e.g. they're already tracking absence externally via
	// the JSONL log file size). Same shutdown-ordering invariant: the
	// monitor stops FIRST in Exporter.Shutdown so its in-flight Emit
	// drains before transports close.
	if auditExportHealthInterval > 0 {
		mon := audit.NewExportHealthMonitor(audit.ExportHealthMonitorOptions{
			Exporter: exp,
			Interval: auditExportHealthInterval,
			Stderr:   os.Stderr,
			Host:     listenerHost,
		})
		exp.HealthMonitor = mon
		mon.Start()
	}
	return exp, nil
}

// newAuditCmd implements `dbounce audit ...`. D-Slice 1 ships `tail`
// only — the highest-leverage operator workflow ("show me what just
// went through the proxy"). Later slices may add `search`, `export`,
// and diff-against-baseline.
func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Inspect the dbounce decision audit log",
		Long: `dbounce records every parsed statement in a local SQLite audit
log at ~/.dbounce/state.db. ` + "`dbounce audit tail`" + ` is the
fastest way to see what a SQL client just sent through the proxy +
what verdict each statement got.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("audit", cmd)
	cmd.AddCommand(newAuditTailCmd())
	return cmd
}

// parentRequiresSubcommand returns a RunE that prints a clear error +
// returns exit 1 when a cobra parent command is invoked without a
// known sub-subcommand. Mirrors kbounce's UAT-K2 BLOCKER-K2-02
// closure pattern.
func parentRequiresSubcommand(parent string, _ *cobra.Command) func(*cobra.Command, []string) error {
	return func(c *cobra.Command, args []string) error {
		if len(args) == 0 {
			fmt.Fprintf(c.ErrOrStderr(),
				"dbounce: missing subcommand for %q; see `dbounce %s --help` for valid subs\n",
				parent, parent)
			os.Exit(1)
		}
		fmt.Fprintf(c.ErrOrStderr(),
			"dbounce: unknown subcommand %q for %q; see `dbounce %s --help` for valid subs\n",
			args[0], parent, parent)
		os.Exit(1)
		return nil
	}
}

// newAuditTailCmd builds the `dbounce audit tail` subcommand. The flag
// surface + dispatch live in audit_tail.go (#268 added --follow, --filter,
// --summary, and --export to the legacy snapshot + --json path); this
// constructor stays here so the cobra command tree definition is in one
// place.
func newAuditTailCmd() *cobra.Command {
	var o auditTailOpts
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Show recent decisions (snapshot, live follow, summary, or bulk export)",
		Long: `Show the most recent decisions from the local SQLite audit log.

Default mode prints the newest --limit rows as a human-readable table.
The flag set extends with four operator workflows shared cross-product
with ibounce + kbounce (#268):

  --follow                  live tail; polls the audit DB + prints new
                            rows as they arrive. Exit on SIGINT.
  --filter EXPR             field predicate (repeatable; AND-combined).
                            Forms: field=val, field~regex, field>=N,
                            field<=N. See --filter --help for fields.
  --summary                 count-summary across event_type, severity_id,
                            actor.user.name, api.operation. Honors --filter.
  --export FORMAT --out P   bulk export. FORMAT: jsonl | csv | ocsf-bundle.
                            SQL string literals are ALWAYS redacted on the
                            csv + ocsf-bundle paths so a bulk SIEM export
                            cannot leak PII embedded in raw statements.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuditTail(cmd, &o)
		},
	}
	registerAuditTailFlags(cmd, &o)
	return cmd
}

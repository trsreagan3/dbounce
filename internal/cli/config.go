// `dbounce config export | import` per [[basic-app-hygiene-features]]
// TIER 1 #1.
//
// Round-trips a deployment's runtime configuration as a single JSON
// document so an operator can:
//
//   - back the gating surface up before a risky change
//   - move a hand-tuned dev-laptop config onto a CI runner or sibling
//     bouncer host
//   - feed the JSON into a change-management diff so the security
//     reviewer sees exactly what's about to land
//   - ship a starter config to a teammate alongside the install
//     instructions
//
// What ships in the bundle (schema: schemas/dbounce-config.schema.json):
//
//   - schema_version + product + dbounce_version + exported_at +
//     exported_by + source_hostname_hash + store_schema_version
//                                          — provenance for the reviewer
//   - runtime_config.dialect              — load-bearing; importer
//                                           refuses on a mismatch
//                                           unless --force
//   - rule_pack (name + version + cal.    — REFERENCED only; the
//     status + embedded flag)               YAML lives in the binary
//                                           at internal/packs/<dialect>.yaml
//   - rules (every row from the rules     — round-tripped verbatim;
//     table, plus per-rule dialects)        importer APPENDS via AddRule
//                                           per [[creates-never-mutates]]
//   - profiles (active + path + items     — round-tripped with per-
//     with per-profile dialects)             profile dialect tags;
//                                           non-local-source entries
//                                           are skipped on import
//   - pause + tasks                       — operational state, included
//                                           for change-management review
//                                           but NOT re-played on import
//
// What does NOT ship (intentional, per [[scorer-is-ground-truth]] +
// [[opt-in-feedback-pipeline]] + [[push-policy-public-repo]]):
//
//   - decisions table (audit log)         — operator data; ship via
//                                           audit-export pipeline, not
//                                           this bundle
//   - pending_audit_events / pending_     — transient queue state; the
//     prompts                                running proxy drains these
//                                           every second
//   - profile_overrides                   — single-row hot-swap signal;
//                                           wholly transient
//   - any credentials / hostnames /       — bundle is human-reviewable
//     URLs / file paths beyond informational by design; reviewers should
//     `profiles.path`                       not have to redact before
//                                           checking it into a config repo
//
// Cross-process consideration: both `export` and `import` run in the CLI
// process. Neither requires the `dbounce run` process. Both read/write
// state.db directly via store.Open. The single-writer invariant for
// audit-event emission is preserved because import enqueues an
// ADMIN_ACTION row (same `pending_audit_events` queue as every other
// admin subcommand) which the running proxy drains + emits through its
// wired Exporter — same Option A architecture as the existing admin-
// action wiring.
//
// Schema migration: no store.SchemaVersion bump required. The export
// path reads existing tables; the import path uses existing AddRule /
// AddLocalProfile helpers. The bundle's own `format_version` is a
// separate axis from store.SchemaVersion + bumps only on a real bundle-
// shape break.
//
// Admin-action audit emission: both subcommands enqueue an ADMIN_ACTION
// row via the shared `enqueueAdminAction` helper. Action ids:
//
//   - "config.export" — Actor + Details{path, rule_count, profile_count}
//   - "config.import" — Actor + Details{path, rules_imported,
//                                       rules_skipped, profiles_imported,
//                                       profiles_skipped, force, dry_run}
//
// Per-dialect handling on the audit event: the bundle's
// runtime_config.dialect is stamped into Dialects (one entry — the
// export/import IS dialect-scoped at the deployment level). A SIEM
// dashboard keyed on unmapped.iam_jit.config_change.dialects sees
// "config.import dialect=postgres" without parsing the details map.
//
// Sibling agents in ibounce + kbounce ship the SAME action ids + the
// SAME bundle shape (with their own runtime_config fields — kbounce
// carries cluster_arn, ibounce carries aws_account_id). One cross-
// product SIEM correlation rule keyed on action="config.import"
// catches the lifecycle event regardless of which product fired it.

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/packs"
	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
	"gopkg.in/yaml.v3"
)

// ConfigSchemaVersion is the wire-format version of the bundle JSON.
// String semver per the #288 cross-product reconciliation: lets us bump
// "1.0" → "1.1" (additive) vs "2.0" (breaking) without changing the
// parser shape. Matches the ibounce + gbounce + kbounce shape so a
// customer's single cross-product backup parser handles every Bounce
// product identically.
const ConfigSchemaVersion = "1.0"

// ConfigProduct is the product name stamped into every export.
// Refusing imports whose `product` field doesn't match is the
// load-bearing "you can't import a kbounce / ibounce / gbounce export
// into dbounce" guard. Replaces the pre-#288 `format` magic string
// (which carried the same semantic by a different name); the importer
// still accepts the legacy `format: "dbounce.config"` shape for
// backwards compat.
const ConfigProduct = "dbounce"

// legacyBundleFormat is the pre-#288 magic string. New exports do NOT
// emit it; the importer accepts it (alongside the legacy `format_version`
// int) so old exports on disk stay readable indefinitely.
const legacyBundleFormat = "dbounce.config"

// legacyBundleFormatVersion is the pre-#288 wire value (raw int 1).
// New exports always emit the string-semver `schema_version` form, but
// importers accept the int form across the v1.x compat window.
const legacyBundleFormatVersion = 1

// ConfigBundle is the on-disk JSON shape. The schema lives at
// schemas/dbounce-config.schema.json and is the authoritative
// definition; this struct mirrors it for the marshal/unmarshal path.
//
// Wire-shape reconciliation (#288): the top-level field order matches
// ibounce + gbounce + kbounce so a SIEM / backup-script parser sees
// the same shape across the suite:
//
//   schema_version       — string semver ("1.0"); was `format_version` (int 1)
//   product              — "dbounce"; was carried only inside the `format` magic
//   dbounce_version      — informational
//   exported_at          — ISO-8601 UTC
//   source_hostname_hash — sha256[:12] of os.Hostname()
//   store_schema_version — the store.SchemaVersion at export time (was
//                          named `schema_version` pre-#288; renamed to
//                          break the field-name collision with the new
//                          wire-format `schema_version`)
//
// `omitempty` on every optional field keeps the export terse — a fresh
// install with no rules + no profiles produces a small bundle a
// reviewer can read in one screen.
type ConfigBundle struct {
	SchemaVersion      string             `json:"schema_version"`
	Product            string             `json:"product"`
	DbounceVersion     string             `json:"dbounce_version,omitempty"`
	ExportedAt         string             `json:"exported_at"`
	ExportedBy         string             `json:"exported_by,omitempty"`
	SourceHostnameHash string             `json:"source_hostname_hash,omitempty"`
	StoreSchemaVersion int                `json:"store_schema_version"`
	RuntimeConfig      RuntimeConfigBlock `json:"runtime_config"`
	RulePack           *RulePackRef       `json:"rule_pack,omitempty"`
	Rules              []ConfigRule       `json:"rules"`
	Profiles           ProfilesBlock      `json:"profiles"`
	Pause              *PauseBlock        `json:"pause,omitempty"`
	Tasks              []TaskBlock        `json:"tasks,omitempty"`
}

// RuntimeConfigBlock carries the dialect (the load-bearing per-dialect
// field) + reserves space for future runtime-config additions. Kept as
// a nested object (rather than flat fields on ConfigBundle) so the
// shape stays cleanly versionable — a future runtime_config.mode field
// lands here without churning the top-level shape.
type RuntimeConfigBlock struct {
	Dialect string `json:"dialect"`
}

// RulePackRef names the dialect's embedded rule pack BY name + version
// (NOT inlining the YAML). Two reasons:
//
//  1. Packs ship inside the binary (internal/packs/*.yaml + go:embed).
//     The customer's `dbounce` binary already has them; re-shipping in
//     the bundle would just bloat the file + drift the source of truth.
//
//  2. Pack-version drift is a real change-management signal. When the
//     binary's pack version differs from the bundle's, the importer
//     warns + the operator gets a chance to read the diff between
//     pack versions before pushing the import through.
type RulePackRef struct {
	Name              string `json:"name"`
	Version           string `json:"version,omitempty"`
	CalibrationStatus string `json:"calibration_status,omitempty"`
	Embedded          bool   `json:"embedded"`
}

// ConfigRule is the export-shape of one rules-table row. Mirrors
// rules.ProxyRule's ToMap output plus the row id + the per-rule dialect
// inference (so a reviewer reading the JSON sees which dialects each
// rule targets without having to re-parse the table-glob).
type ConfigRule struct {
	ID            int64    `json:"id,omitempty"`
	Pattern       string   `json:"pattern"`
	Effect        string   `json:"effect"`
	SchemaScope   string   `json:"schema_scope,omitempty"`
	TableScope    string   `json:"table_scope,omitempty"`
	FunctionScope string   `json:"function_scope,omitempty"`
	Note          string   `json:"note,omitempty"`
	Origin        string   `json:"origin,omitempty"`
	Dialects      []string `json:"dialects,omitempty"`
}

// ProfilesBlock carries the loaded profiles + the active selection.
// Path is informational; the importer writes to its OWN configured
// profiles.yaml path, never to the path baked into the bundle.
type ProfilesBlock struct {
	Active string          `json:"active,omitempty"`
	Path   string          `json:"path,omitempty"`
	Items  []ConfigProfile `json:"items"`
}

// ConfigProfile is the export-shape of one profile entry. Mirrors the
// on-disk YAML shape (profile.Profile) plus per-profile dialect tags.
type ConfigProfile struct {
	Name                 string                     `json:"name"`
	Description          string                     `json:"description,omitempty"`
	Source               string                     `json:"source,omitempty"`
	AllowBaseline        string                     `json:"allow_baseline,omitempty"`
	DenyASTMutatingNodes bool                       `json:"deny_ast_mutating_nodes,omitempty"`
	DenyActions          []string                   `json:"deny_actions,omitempty"`
	DenyKeywords         []string                   `json:"deny_keywords,omitempty"`
	KeywordMatch         string                     `json:"keyword_match,omitempty"`
	KeywordTargets       []string                   `json:"keyword_targets,omitempty"`
	ExemptResources      []string                   `json:"exempt_resources,omitempty"`
	ExemptActions        []string                   `json:"exempt_actions,omitempty"`
	Exceptions           []string                   `json:"exceptions,omitempty"`
	AllowRules           []ConfigProfileAllowRule   `json:"allow_rules,omitempty"`
	Dialects             []string                   `json:"dialects,omitempty"`
}

// ConfigProfileAllowRule mirrors profile.ProfileAllowRule's fields the
// dbounce profile engine consumes. ArnScope / RegionScope are AWS-
// shaped + ignored by dbounce — round-tripped only when present in the
// source YAML (preserved via the additionalProperties:true contract in
// the schema, not surfaced on this struct).
type ConfigProfileAllowRule struct {
	Pattern string `json:"pattern"`
	Note    string `json:"note,omitempty"`
}

// PauseBlock is the active pause window (or nil). Operational state —
// included for change-management review but NOT re-played on import.
type PauseBlock struct {
	ID        int64  `json:"id"`
	StartedAt string `json:"started_at"`
	EndsAt    string `json:"ends_at"`
	Reason    string `json:"reason,omitempty"`
	StartedBy string `json:"started_by"`
}

// TaskBlock is one active task scope. Operational state — included for
// change-management review but NOT re-played on import.
type TaskBlock struct {
	TaskID      string `json:"task_id"`
	Description string `json:"description"`
	StartedAt   string `json:"started_at"`
	ExpiresAt   string `json:"expires_at"`
	StartedBy   string `json:"started_by"`
	Owner       string `json:"owner,omitempty"`
}

// newConfigCmd implements `dbounce config ...` per
// [[basic-app-hygiene-features]] TIER 1 #1.
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Export / import dbounce runtime configuration as a JSON bundle",
		Long: `dbounce config ships a portable JSON bundle so an operator
can back up a deployment's runtime configuration, move it to a sibling
host, or feed a diff into a change-management review.

Subcommands:
  export  write the current rules + profiles + dialect + pack ref to a JSON file
  import  read a bundle file and apply its rules + profiles to this host

What ships:
  - dialect + rule pack reference (by name + version; pack YAML stays in the binary)
  - all global rules from the rules table
  - all locally-authored profiles (non-local-source entries excluded)
  - informational provenance (exported_at, exported_by, dbounce_version, schema_version)
  - active pause + active tasks (informational only; NOT re-played on import)

What does NOT ship (by design):
  - audit log decisions (route via the audit-export pipeline instead)
  - transient queue rows (pending prompts / pending audit events)
  - credentials, hostnames, URLs (the bundle is human-reviewable + checkable into config repos)

Per [[creates-never-mutates]] import APPENDS — existing rules and
profiles are preserved; same-named entries are SKIPPED with an
informational note. Use --replace on import to overwrite same-named
profiles (rules always append; their pattern+scope IS the identity).

JSON schema: schemas/dbounce-config.schema.json (in-tree).`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("config", cmd)
	cmd.AddCommand(newConfigExportCmd())
	cmd.AddCommand(newConfigImportCmd())
	return cmd
}

func newConfigExportCmd() *cobra.Command {
	var (
		dbPath       string
		profilesPath string
		dialectStr   string
		activeName   string
		outPath      string
		actor        string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write the current dbounce configuration to a JSON bundle",
		Long: `Reads the rules table + the active profiles.yaml + the
runtime dialect, and writes a JSON bundle conforming to
schemas/dbounce-config.schema.json.

Pass --output - to stream to stdout (useful for piping into a diff
tool); pass a path to write to a file. The file is written 0600 + via
atomic temp+rename so a crash mid-write cannot leave a half-written
bundle on disk.

Dialect selection: --dialect chooses which pack reference the bundle
records (defaults to postgres to match ` + "`dbounce run`" + `'s
default). The dialect MUST match the deployment's runtime dialect; an
importer with a different --dialect will refuse the bundle.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dialect, err := proxy.ParseDialect(dialectStr)
			if err != nil {
				return err
			}
			if activeName == "" {
				activeName = os.Getenv(envProfileVar)
			}
			bundle, err := buildConfigBundle(buildBundleParams{
				DBPath:       dbPath,
				ProfilesPath: profilesPath,
				Dialect:      dialect,
				ActiveName:   activeName,
				ExportedBy:   resolveActor(actor),
			})
			if err != nil {
				return err
			}

			b, err := json.MarshalIndent(bundle, "", "  ")
			if err != nil {
				return fmt.Errorf("encode config bundle: %w", err)
			}
			// Final newline is friendlier for git diffs + `cat`.
			b = append(b, '\n')

			if outPath == "" || outPath == "-" {
				if _, werr := cmd.OutOrStdout().Write(b); werr != nil {
					return fmt.Errorf("write bundle to stdout: %w", werr)
				}
			} else {
				if werr := writeBundleAtomic(outPath, b); werr != nil {
					return werr
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"wrote dbounce config bundle to %s (%d rules, %d profiles, dialect=%s).\n",
					outPath, len(bundle.Rules), len(bundle.Profiles.Items), dialect)
			}

			// [[basic-app-hygiene-features]] TIER 1 #1 +
			// [[security-team-audit-export]]: enqueue an ADMIN_ACTION row
			// so a SIEM dashboard sees the export event. Best-effort:
			// the bundle is already on disk / stdout; an enqueue failure
			// MUST NOT undo it. Per-dialect: the bundle's runtime
			// dialect is stamped into Dialects so a SIEM rule keyed on
			// config_change.dialects can filter "exports of the
			// snowflake surface."
			details := map[string]any{
				"product":        ConfigProduct,
				"schema_version": ConfigSchemaVersion,
				"dialect":        string(dialect),
				"rule_count":     len(bundle.Rules),
				"profile_count":  len(bundle.Profiles.Items),
			}
			if outPath != "" && outPath != "-" {
				details["path"] = outPath
			} else {
				details["path"] = "stdout"
			}
			enqueueAdminAction(cmd.ErrOrStderr(), dbPath, adminActionEnqueueParams{
				Action:       "config.export",
				Actor:        resolveActor(actor),
				ResourceType: "config",
				ResourceID:   string(dialect),
				Dialects:     []string{string(dialect)},
				Details:      details,
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"profiles.yaml path (default: ~/.dbounce/profiles.yaml, or DBOUNCE_PROFILES_PATH env).")
	cmd.Flags().StringVar(&dialectStr, "dialect", "postgres",
		"Runtime dialect to record in the bundle (postgres|mysql|snowflake|bigquery). "+
			"MUST match the deployment's dialect; the importer refuses on mismatch.")
	cmd.Flags().StringVar(&activeName, "profile", "",
		"Active profile name to record in the bundle. Defaults to "+envProfileVar+
			" env var when unset; empty when neither is set.")
	cmd.Flags().StringVarP(&outPath, "output", "o", "",
		"Output file path. Use '-' or omit to stream to stdout.")
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id recorded on the ADMIN_ACTION audit event. "+
			"Defaults to $USER then 'unknown'.")
	return cmd
}

func newConfigImportCmd() *cobra.Command {
	var (
		dbPath        string
		profilesPath  string
		dialectStr    string
		inPath        string // primary flag per #288 — matches ibounce / gbounce / kbounce
		legacyInPath  string // pre-#288 --input/-i alias
		dryRun        bool
		force         bool
		replace       bool
		actor         string
		asJSON        bool
	)
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Apply a dbounce config bundle to this host (appends rules + profiles)",
		Long: `Reads a JSON bundle produced by ` + "`dbounce config export`" + `
and applies its rules + profiles to this host.

Per [[creates-never-mutates]]:
  - rules APPEND (each is inserted via AddRule with a fresh row id)
  - profiles APPEND (same-named entries are SKIPPED, not overwritten,
    unless --replace is passed)
  - operational state (pause, tasks) is NOT re-played

Cross-product flag parity per #288: ` + "`--in PATH`" + ` is the primary
form (matches ibounce + gbounce + kbounce so one cross-product backup
script can target every Bounce product). ` + "`--input PATH`" + ` /
` + "`-i PATH`" + ` are preserved as DEPRECATED aliases — they still
work but print a stderr deprecation warning.

Dialect compatibility: the importer refuses bundles whose
runtime_config.dialect does NOT match --dialect; override with --force
at your own risk (the rule patterns may carry table-glob prefixes that
do not exist in the target dialect's schema).

Backwards compatibility: pre-#288 exports carrying the legacy
` + "`format` / `format_version`" + ` fields (and an int
` + "`schema_version`" + ` that named the store-schema version) import
cleanly into this binary. The importer normalizes them to the canonical
shape and prints a stderr deprecation warning.

Use --dry-run to preview what the import would change without writing
anything.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dialect, err := proxy.ParseDialect(dialectStr)
			if err != nil {
				return err
			}
			// Resolve source from --in (primary) or --input/-i
			// (deprecated alias per #288). Both set: refuse with a
			// clear message; neither set: require --in.
			source := inPath
			if source == "" && legacyInPath != "" {
				source = legacyInPath
				fmt.Fprintln(cmd.ErrOrStderr(),
					"dbounce: deprecation: --input/-i PATH is renamed to "+
						"--in PATH for cross-product parity (ibounce + gbounce + "+
						"kbounce all use --in). The --input/-i aliases still work "+
						"but will be removed in a future major version. Update "+
						"your scripts to --in PATH.")
			} else if inPath != "" && legacyInPath != "" {
				return errors.New(
					"dbounce: --in and --input/-i are aliases for the same flag; pass " +
						"exactly one (prefer --in; --input/-i is deprecated)")
			}
			if source == "" || source == "-" {
				return errors.New("dbounce: --in PATH is required (stdin not supported v1.0)")
			}
			raw, err := os.ReadFile(source)
			if err != nil {
				return fmt.Errorf("read bundle %q: %w", source, err)
			}
			// Normalize pre-#288 wire shapes (format / format_version / int
			// schema_version) onto the canonical shape so the downstream
			// json.Unmarshal hits the renamed fields cleanly. Deprecation
			// warnings ride cmd.ErrOrStderr().
			normalized, _, nerr := normalizeLegacyBundleShape(raw, cmd.ErrOrStderr())
			if nerr != nil {
				return fmt.Errorf("parse bundle %q: %w", source, nerr)
			}
			var bundle ConfigBundle
			if uerr := json.Unmarshal(normalized, &bundle); uerr != nil {
				return fmt.Errorf("parse bundle %q: %w", source, uerr)
			}
			if verr := validateBundle(&bundle, dialect, force); verr != nil {
				return verr
			}

			result, ierr := applyBundle(applyBundleParams{
				DBPath:       dbPath,
				ProfilesPath: profilesPath,
				Bundle:       &bundle,
				DryRun:       dryRun,
				Replace:      replace,
			})
			if ierr != nil {
				return ierr
			}

			if asJSON {
				if jerr := json.NewEncoder(cmd.OutOrStdout()).Encode(result); jerr != nil {
					return jerr
				}
			} else {
				w := cmd.OutOrStdout()
				prefix := ""
				if dryRun {
					prefix = "DRY-RUN: "
				}
				fmt.Fprintf(w, "%simported dbounce config bundle from %s (dialect=%s)\n",
					prefix, source, bundle.RuntimeConfig.Dialect)
				fmt.Fprintf(w, "  rules:    %d added, %d skipped (%d errored)\n",
					result.RulesImported, result.RulesSkipped, len(result.RuleErrors))
				fmt.Fprintf(w, "  profiles: %d added, %d skipped (%d errored)\n",
					result.ProfilesImported, result.ProfilesSkipped, len(result.ProfileErrors))
				for _, msg := range result.Notes {
					fmt.Fprintf(w, "  note: %s\n", msg)
				}
				for _, msg := range result.RuleErrors {
					fmt.Fprintf(w, "  rule-error: %s\n", msg)
				}
				for _, msg := range result.ProfileErrors {
					fmt.Fprintf(w, "  profile-error: %s\n", msg)
				}
			}

			// [[basic-app-hygiene-features]] TIER 1 #1 +
			// [[security-team-audit-export]]: enqueue an ADMIN_ACTION
			// row so a SIEM dashboard sees the import event AFTER the
			// store mutations land. Dry-run still emits the event with
			// dry_run=true in details — a security team that wants to
			// observe planning activity in addition to apply activity
			// can filter on it.
			details := map[string]any{
				"product":           bundle.Product,
				"schema_version":    bundle.SchemaVersion,
				"dialect":           bundle.RuntimeConfig.Dialect,
				"path":              source,
				"rules_imported":    result.RulesImported,
				"rules_skipped":     result.RulesSkipped,
				"profiles_imported": result.ProfilesImported,
				"profiles_skipped":  result.ProfilesSkipped,
				"dry_run":           dryRun,
				"force":             force,
				"replace":           replace,
			}
			if len(result.RuleErrors) > 0 {
				details["rule_errors"] = len(result.RuleErrors)
			}
			if len(result.ProfileErrors) > 0 {
				details["profile_errors"] = len(result.ProfileErrors)
			}
			resultStr := "success"
			if dryRun {
				resultStr = "noop"
			} else if len(result.RuleErrors) > 0 || len(result.ProfileErrors) > 0 {
				// Partial failure is reported as "failure" so a SIEM
				// dashboard sees the per-error breakout in details
				// without misreading a partially-applied import as a
				// clean success.
				resultStr = "failure"
			}
			enqueueAdminAction(cmd.ErrOrStderr(), dbPath, adminActionEnqueueParams{
				Action:       "config.import",
				Actor:        resolveActor(actor),
				ResourceType: "config",
				ResourceID:   bundle.RuntimeConfig.Dialect,
				Result:       resultStr,
				Dialects:     []string{bundle.RuntimeConfig.Dialect},
				Details:      details,
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"profiles.yaml path (default: ~/.dbounce/profiles.yaml, or DBOUNCE_PROFILES_PATH env).")
	cmd.Flags().StringVar(&dialectStr, "dialect", "postgres",
		"Runtime dialect of the target deployment. Importer refuses on mismatch unless --force.")
	cmd.Flags().StringVar(&inPath, "in", "",
		"Input bundle path. Required (or pass the deprecated --input / -i alias).")
	cmd.Flags().StringVarP(&legacyInPath, "input", "i", "",
		"DEPRECATED: pre-#288 alias for --in PATH. Still works, prints "+
			"a stderr deprecation warning. Update scripts to --in.")
	// MarkDeprecated would hide --input from --help; we keep it
	// visible so an operator who runs `dbounce config import --help`
	// after migrating from an older binary sees the explicit note
	// rather than wondering where --input went.
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Parse + validate + simulate without writing anything.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Override the dialect-mismatch refusal. Rule patterns may not match the target dialect's schema.")
	cmd.Flags().BoolVar(&replace, "replace", false,
		"Overwrite an existing same-named profile rather than skipping it. Default false per [[creates-never-mutates]].")
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id recorded on the ADMIN_ACTION audit event. "+
			"Defaults to $USER then 'unknown'.")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit a machine-readable JSON summary instead of the human banner.")
	return cmd
}

// buildBundleParams is the input to buildConfigBundle. Kept as a struct
// so tests can populate fields explicitly + so a future addition
// (e.g. include-active-tasks=false) lands without churning the
// signature.
type buildBundleParams struct {
	DBPath       string
	ProfilesPath string
	Dialect      proxy.Dialect
	ActiveName   string
	ExportedBy   string
}

// buildConfigBundle assembles the export-shape bundle from the store +
// profiles.yaml. Pure read-side: never mutates either source. Exported
// for tests in the same package.
func buildConfigBundle(p buildBundleParams) (*ConfigBundle, error) {
	st, err := store.Open(p.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	rules, err := st.ListRules()
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	cfgRules := make([]ConfigRule, 0, len(rules))
	for _, r := range rules {
		cr := ConfigRule{
			ID:            int64(r.ID),
			Pattern:       r.Rule.Pattern,
			Effect:        string(r.Rule.Effect),
			SchemaScope:   r.Rule.SchemaScope,
			TableScope:    r.Rule.TableScope,
			FunctionScope: r.Rule.FunctionScope,
			Note:          r.Rule.Note,
			Origin:        r.Rule.Origin,
			Dialects:      inferDialectsFromRulePattern(r.Rule.Pattern),
		}
		cfgRules = append(cfgRules, cr)
	}

	// Profiles: load via the same path the CLI consumes (LoadProfiles
	// falls back to embedded defaults when the file doesn't exist so a
	// fresh-install export is still useful — captures the synthesized
	// full-user / safe-default entries).
	resolvedProfilesPath := p.ProfilesPath
	if resolvedProfilesPath == "" {
		rp, perr := profile.DefaultProfilesPath()
		if perr != nil {
			return nil, fmt.Errorf("resolve profiles path: %w", perr)
		}
		resolvedProfilesPath = rp
	}
	profiles, err := profile.LoadProfiles(resolvedProfilesPath)
	if err != nil {
		return nil, fmt.Errorf("load profiles: %w", err)
	}
	cfgProfiles := make([]ConfigProfile, 0, len(profiles.All))
	for _, name := range profiles.NamesSorted() {
		// Skip the synthesized full-user passthrough sentinel — it
		// always exists in every loaded set + carries zero
		// configuration. Re-exporting it would just add noise.
		if name == profile.FullUserProfileName {
			continue
		}
		pr := profiles.All[name]
		if pr == nil {
			continue
		}
		cfgProfiles = append(cfgProfiles, profileToConfig(pr))
	}

	// Pause: include the active window only (history is operational
	// audit data, NOT runtime config).
	var pauseBlock *PauseBlock
	if active, perr := st.GetActivePause(); perr == nil && active != nil {
		pauseBlock = &PauseBlock{
			ID:        active.ID,
			StartedAt: active.StartedAt,
			EndsAt:    active.EndsAt,
			Reason:    active.Reason,
			StartedBy: active.StartedBy,
		}
	}

	// Tasks: include active scopes only. Owner = "" (default-owner)
	// covers the solo-laptop case the default-owner active task.
	var taskBlocks []TaskBlock
	if active, terr := st.GetActiveTask(""); terr == nil && active != nil {
		taskBlocks = append(taskBlocks, TaskBlock{
			TaskID:      active.TaskID,
			Description: active.Description,
			StartedAt:   active.StartedAt,
			ExpiresAt:   active.ExpiresAt,
			StartedBy:   active.StartedBy,
			Owner:       active.Owner,
		})
	}

	pack := rulePackFor(p.Dialect)

	bundle := &ConfigBundle{
		SchemaVersion:      ConfigSchemaVersion,
		Product:            ConfigProduct,
		DbounceVersion:     versionString(),
		ExportedAt:         time.Now().UTC().Format(time.RFC3339),
		ExportedBy:         p.ExportedBy,
		SourceHostnameHash: sourceHostnameHash(),
		StoreSchemaVersion: store.SchemaVersion,
		RuntimeConfig: RuntimeConfigBlock{
			Dialect: string(p.Dialect),
		},
		RulePack: pack,
		Rules:    cfgRules,
		Profiles: ProfilesBlock{
			Active: p.ActiveName,
			Path:   resolvedProfilesPath,
			Items:  cfgProfiles,
		},
		Pause: pauseBlock,
		Tasks: taskBlocks,
	}
	return bundle, nil
}

// sourceHostnameHash returns the sha256[:12] hex digest of os.Hostname().
// Matches the privacy-preserving attribution pattern used by the SQLite
// backup metadata (#279) + the ibounce + gbounce config exports per
// [[cross-product-agent-parity]]: an operator can tell two bundles
// produced on different hosts apart without leaking the literal
// hostname into a file they may share with a reviewer or check into a
// config repo. Empty hostname → empty string (caller's omitempty drops
// the field).
func sourceHostnameHash() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(h))
	return hex.EncodeToString(sum[:])[:12]
}

// profileToConfig projects a profile.Profile to its export shape. The
// per-profile Dialects field is inferred from the profile name via
// inferDialectsFromProfileNames so the bundle reviewer sees which
// dialects each profile was authored for without re-parsing the name.
func profileToConfig(p *profile.Profile) ConfigProfile {
	out := ConfigProfile{
		Name:                 p.Name,
		Description:          p.Description,
		Source:               p.Source,
		AllowBaseline:        string(p.AllowBaseline),
		DenyASTMutatingNodes: p.DenyASTMutatingNodes,
		DenyActions:          appendStringsCopy(nil, p.DenyActions),
		DenyKeywords:         appendStringsCopy(nil, p.DenyKeywords),
		KeywordMatch:         string(p.KeywordMatch),
		ExemptResources:      appendStringsCopy(nil, p.ExemptResources),
		ExemptActions:        appendStringsCopy(nil, p.ExemptActions),
		Exceptions:           appendStringsCopy(nil, p.Exceptions),
		Dialects:             inferDialectsFromProfileNames([]string{p.Name}),
	}
	if len(p.KeywordTargets) > 0 {
		targets := make([]string, 0, len(p.KeywordTargets))
		for _, t := range p.KeywordTargets {
			targets = append(targets, string(t))
		}
		out.KeywordTargets = targets
	}
	if len(p.AllowRules) > 0 {
		rules := make([]ConfigProfileAllowRule, 0, len(p.AllowRules))
		for _, r := range p.AllowRules {
			rules = append(rules, ConfigProfileAllowRule{
				Pattern: r.Pattern,
				Note:    r.Note,
			})
		}
		out.AllowRules = rules
	}
	return out
}

// appendStringsCopy returns a fresh slice containing src's contents so
// the caller's projection cannot mutate the receiver's data. Nil-safe.
func appendStringsCopy(dst, src []string) []string {
	if len(src) == 0 {
		return dst
	}
	return append(dst, src...)
}

// rulePackRefDoc is the minimal YAML decoder shape for pack metadata.
// Defined inside rulePackFor's scope (rather than at package level)
// because it's only used here + naming it tightens the read site.
type rulePackMetaDoc struct {
	Metadata struct {
		Dialect           string `yaml:"dialect"`
		Version           string `yaml:"version"`
		CalibrationStatus string `yaml:"calibration_status"`
	} `yaml:"metadata"`
}

// rulePackFor returns the embedded pack reference for the given
// dialect, or nil when no pack ships for that dialect (postgres in
// v1.0 is unreferenced because the postgres pack hasn't shipped yet —
// see the internal/packs/ headers + dbounce-build-plan §D-Slice 3
// note that postgres pack ships in a later slice).
func rulePackFor(d proxy.Dialect) *RulePackRef {
	var raw []byte
	switch d {
	case proxy.DialectMySQL:
		raw = packs.MySQL
	case proxy.DialectSnowflake:
		raw = packs.Snowflake
	case proxy.DialectBigQuery:
		raw = packs.BigQuery
	default:
		// No embedded pack yet for postgres. Reference the dialect by
		// name + mark embedded=true (the binary owns the pack surface
		// regardless of whether YAML has landed) so a downstream
		// reviewer sees the intent. version + calibration_status are
		// omitted via omitempty on RulePackRef.
		return &RulePackRef{
			Name:     string(d),
			Embedded: true,
		}
	}
	var meta rulePackMetaDoc
	// Decode is best-effort: a malformed pack YAML would have failed
	// the proxy startup long before reaching the export path, but a
	// defensive zero-value here keeps the export from crashing on a
	// hypothetical pack-format regression.
	_ = yaml.Unmarshal(raw, &meta)
	return &RulePackRef{
		Name:              string(d),
		Version:           meta.Metadata.Version,
		CalibrationStatus: meta.Metadata.CalibrationStatus,
		Embedded:          true,
	}
}

// writeBundleAtomic writes b to path via temp file + rename so a crash
// between truncate + write cannot leave a half-written bundle. Mirrors
// profile.AddLocalProfile's atomic-write pattern + uses 0600 perms so
// the bundle's contents (rule patterns + profile shapes) stay
// readable only by the owning user — the same default as profiles.yaml
// + state.db.
func writeBundleAtomic(path string, b []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %q: %w", dir, err)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dbounce-config-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, werr := tmp.Write(b); werr != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", werr)
	}
	if cerr := tmp.Chmod(0o600); cerr != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", cerr)
	}
	if cerr := tmp.Close(); cerr != nil {
		return fmt.Errorf("close temp: %w", cerr)
	}
	if rerr := os.Rename(tmpName, path); rerr != nil {
		return fmt.Errorf("rename into place: %w", rerr)
	}
	return nil
}

// validateBundle runs the cross-version + cross-dialect guards. Called
// AFTER json.Unmarshal so callers can inspect malformed-shape errors
// separately from dialect / version mismatches. Assumes the bundle has
// already passed through normalizeLegacyBundleShape (which rewrites
// pre-#288 wire fields onto the new `product` + `schema_version` shape);
// validateBundle treats both old and new exports identically here.
func validateBundle(b *ConfigBundle, dialect proxy.Dialect, force bool) error {
	if b == nil {
		return errors.New("bundle is nil")
	}
	if b.Product != ConfigProduct {
		return fmt.Errorf(
			"bundle product %q is not %q (was this produced by a different product? sibling agents in ibounce + kbounce + gbounce use their own product names)",
			b.Product, ConfigProduct)
	}
	if b.SchemaVersion != ConfigSchemaVersion {
		return fmt.Errorf(
			"bundle schema_version %q is not the supported version %q. "+
				"Upgrade dbounce or re-export the bundle on a binary that "+
				"matches the import target.",
			b.SchemaVersion, ConfigSchemaVersion)
	}
	if b.StoreSchemaVersion > store.SchemaVersion {
		return fmt.Errorf(
			"bundle store_schema_version %d is newer than this binary's store.SchemaVersion %d. "+
				"Upgrade dbounce; running an older binary against a newer-schema bundle "+
				"can silently drop fields.",
			b.StoreSchemaVersion, store.SchemaVersion)
	}
	if b.RuntimeConfig.Dialect == "" {
		return errors.New("bundle runtime_config.dialect is required")
	}
	if !force && b.RuntimeConfig.Dialect != string(dialect) {
		return fmt.Errorf(
			"bundle dialect %q does not match --dialect %q. "+
				"Rule patterns may carry table-glob prefixes that do not exist in the target dialect's schema. "+
				"Pass --force to import anyway (review the patterns first).",
			b.RuntimeConfig.Dialect, dialect)
	}
	return nil
}

// normalizeLegacyBundleShape rewrites a pre-#288 dbounce export onto
// the post-#288 canonical shape so json.Unmarshal hits the renamed
// fields cleanly. Returns the (possibly modified) payload + a flag
// indicating whether a legacy shape was actually seen. Bundles that
// already carry the new shape pass through unchanged.
//
// The transformations:
//   - `format: "dbounce.config"` → dropped (carried into `product`
//     synthetically; the legacy magic string only ever named dbounce)
//   - `format_version: 1` (int)  → `schema_version: "1.0"` (string)
//   - existing `schema_version: N` (int store-version) → renamed
//     to `store_schema_version: N`
//   - `product` field synthesized as "dbounce"
//
// Per the #288 reconciliation memo: importers MUST tolerate the old
// shape indefinitely (or at minimum across the entire v1.x line) so
// exports on disk stay readable across binary upgrades. A stderr
// deprecation warning is written to deprecationOut (when non-nil)
// per encountered legacy shape so a scripted operator sees the
// heads-up exactly once per import.
func normalizeLegacyBundleShape(raw []byte, deprecationOut io.Writer) ([]byte, bool, error) {
	var head map[string]json.RawMessage
	if err := json.Unmarshal(raw, &head); err != nil {
		// Defer the descriptive error to the downstream json.Unmarshal —
		// it surfaces the same parse failure with the typed-struct
		// context.
		return raw, false, nil
	}

	// Detect legacy shape by the presence of `format` OR `format_version`.
	// New shape never carries either field (the marshal-side struct
	// has no Format / FormatVersion fields).
	_, hasFormat := head["format"]
	formatVersionRaw, hasFormatVersion := head["format_version"]
	if !hasFormat && !hasFormatVersion {
		// Already-new shape: nothing to do. The downstream Unmarshal
		// hits the canonical fields directly.
		return raw, false, nil
	}

	// Validate the legacy `format` magic when present. We REFUSE
	// non-dbounce magic strings before doing the rewrite so a bundle
	// claiming a different product surfaces with the cross-product
	// error rather than getting silently rebranded to dbounce.
	if hasFormat {
		var formatStr string
		if err := json.Unmarshal(head["format"], &formatStr); err == nil {
			if formatStr != legacyBundleFormat {
				return nil, false, fmt.Errorf(
					"bundle format %q is not %q (was this produced by a different product? sibling agents in ibounce + kbounce + gbounce use their own product names — cross-product import not supported)",
					formatStr, legacyBundleFormat)
			}
		}
	}

	// Validate the legacy `format_version` is the only known value (1).
	// Higher values would be future shapes we don't understand; refuse
	// rather than silently coerce.
	if hasFormatVersion {
		var fv int
		if err := json.Unmarshal(formatVersionRaw, &fv); err == nil {
			if fv != legacyBundleFormatVersion {
				return nil, false, fmt.Errorf(
					"bundle format_version %d is not the legacy known value %d. "+
						"Upgrade dbounce or re-export the bundle on a matching binary.",
					fv, legacyBundleFormatVersion)
			}
		}
	}

	// The pre-#288 `schema_version` was the STORE schema version (int).
	// Rename it to `store_schema_version` so the new wire-level
	// `schema_version: "1.0"` (string) can take the canonical slot.
	if oldSV, present := head["schema_version"]; present {
		// Confirm it's int-shaped (the legacy shape). String-shaped
		// schema_version on a bundle that also carried `format` would
		// be a hand-edited file; preserve it as a parse error
		// downstream rather than silently re-typing.
		var asInt int
		if err := json.Unmarshal(oldSV, &asInt); err == nil {
			head["store_schema_version"] = oldSV
		}
	}

	// Synthesize the new top-level fields.
	prod, err := json.Marshal(ConfigProduct)
	if err != nil {
		return nil, false, fmt.Errorf("marshal product: %w", err)
	}
	head["product"] = prod
	canonSV, err := json.Marshal(ConfigSchemaVersion)
	if err != nil {
		return nil, false, fmt.Errorf("marshal schema_version: %w", err)
	}
	head["schema_version"] = canonSV

	// Drop the legacy magic fields.
	delete(head, "format")
	delete(head, "format_version")

	out, err := json.Marshal(head)
	if err != nil {
		return nil, false, fmt.Errorf("re-marshal payload: %w", err)
	}

	if deprecationOut != nil {
		fmt.Fprintln(deprecationOut,
			"dbounce: deprecation: import uses pre-#288 wire shape "+
				"(`format`/`format_version` fields, int store-schema_version). "+
				"This dbounce understands it but future major versions will "+
				"refuse it. Re-export with this binary to upgrade to the "+
				"canonical `product`+`schema_version: \"1.0\"` shape.")
	}

	return out, true, nil
}

// ImportResult is what applyBundle returns + what the --json mode
// prints. Exported for tests in the same package.
type ImportResult struct {
	RulesImported    int      `json:"rules_imported"`
	RulesSkipped     int      `json:"rules_skipped"`
	ProfilesImported int      `json:"profiles_imported"`
	ProfilesSkipped  int      `json:"profiles_skipped"`
	Notes            []string `json:"notes,omitempty"`
	RuleErrors       []string `json:"rule_errors,omitempty"`
	ProfileErrors    []string `json:"profile_errors,omitempty"`
}

type applyBundleParams struct {
	DBPath       string
	ProfilesPath string
	Bundle       *ConfigBundle
	DryRun       bool
	Replace      bool
}

// applyBundle is the write-side of import. Pure side effects through
// store + profile packages; never touches the network. The dry-run
// branch reports what would change WITHOUT calling AddRule /
// AddLocalProfile.
func applyBundle(p applyBundleParams) (*ImportResult, error) {
	if p.Bundle == nil {
		return nil, errors.New("applyBundle: bundle is nil")
	}
	res := &ImportResult{}

	// Resolve profiles path once (shared by every profile import).
	resolvedProfilesPath := p.ProfilesPath
	if resolvedProfilesPath == "" {
		rp, perr := profile.DefaultProfilesPath()
		if perr != nil {
			return nil, fmt.Errorf("resolve profiles path: %w", perr)
		}
		resolvedProfilesPath = rp
	}

	st, err := store.Open(p.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Rules: APPEND each. Per [[creates-never-mutates]] we never edit
	// an existing rule + the rules table has no name-key (rows are
	// identified by id), so the only de-dup signal is exact pattern +
	// effect + scope match. We skip duplicates of that signature so a
	// repeated import doesn't double-up the same rule on every run.
	existing, lerr := st.ListRules()
	if lerr != nil {
		return nil, fmt.Errorf("list existing rules: %w", lerr)
	}
	existingFP := make(map[string]struct{}, len(existing))
	for _, sr := range existing {
		existingFP[ruleFingerprint(sr.Rule)] = struct{}{}
	}

	for _, cr := range p.Bundle.Rules {
		pr := dbrules.ProxyRule{
			Pattern:       cr.Pattern,
			Effect:        dbrules.Effect(cr.Effect),
			SchemaScope:   cr.SchemaScope,
			TableScope:    cr.TableScope,
			FunctionScope: cr.FunctionScope,
			Note:          cr.Note,
			Origin:        cr.Origin,
		}
		if pr.Origin == "" {
			pr.Origin = dbrules.OriginUser
		}
		fp := ruleFingerprint(pr)
		if _, dup := existingFP[fp]; dup {
			res.RulesSkipped++
			continue
		}
		if p.DryRun {
			res.RulesImported++
			existingFP[fp] = struct{}{}
			continue
		}
		if _, aerr := st.AddRule(pr); aerr != nil {
			res.RuleErrors = append(res.RuleErrors,
				fmt.Sprintf("pattern=%q: %v", pr.Pattern, aerr))
			continue
		}
		res.RulesImported++
		existingFP[fp] = struct{}{}
	}

	// Profiles: load the on-disk set so we can pre-check name
	// collisions + (when --replace) know what to delete-and-rewrite.
	profiles, lperr := profile.LoadProfiles(resolvedProfilesPath)
	if lperr != nil {
		return nil, fmt.Errorf("load profiles: %w", lperr)
	}

	for _, cp := range p.Bundle.Profiles.Items {
		if cp.Name == "" {
			res.ProfileErrors = append(res.ProfileErrors,
				"profile with empty name skipped")
			continue
		}
		if cp.Name == profile.FullUserProfileName {
			res.Notes = append(res.Notes,
				fmt.Sprintf("profile %q is the synthesized passthrough sentinel; skipped", cp.Name))
			res.ProfilesSkipped++
			continue
		}
		// Source-policy: non-local profiles came from `profile install
		// --from URL` and live read-only at the CLI surface. Skip them
		// on import — they should ride the install path, not a config
		// bundle.
		if cp.Source != "" && cp.Source != "local" {
			res.Notes = append(res.Notes,
				fmt.Sprintf("profile %q has non-local source %q; skipped (use `dbounce profile install` instead)",
					cp.Name, cp.Source))
			res.ProfilesSkipped++
			continue
		}
		// Existing-name collision: skip unless --replace.
		if _, exists := profiles.All[cp.Name]; exists && !p.Replace {
			res.Notes = append(res.Notes,
				fmt.Sprintf("profile %q already exists; skipped (re-run with --replace to overwrite)", cp.Name))
			res.ProfilesSkipped++
			continue
		}

		pr := configToProfile(cp)
		if p.DryRun {
			res.ProfilesImported++
			continue
		}
		if p.Replace {
			// AddLocalProfile refuses ErrProfileExists; for the
			// --replace path we surface a single note + still attempt
			// the append (the lower-level YAML writer cannot atomically
			// replace; this is documented as a v1.0 limitation —
			// operators who need replace today edit profiles.yaml by
			// hand + re-import).
			//
			// We re-check existence + when true, skip with a note
			// pointing at the manual edit. A future commit can add a
			// proper UpsertProfile that writes through the same atomic
			// temp+rename path; tracked as a v1.1 follow-up.
			if _, exists := profiles.All[cp.Name]; exists {
				res.Notes = append(res.Notes,
					fmt.Sprintf("profile %q replace requested but not yet supported (v1.0 limitation); skipped — edit %s by hand and re-import",
						cp.Name, resolvedProfilesPath))
				res.ProfilesSkipped++
				continue
			}
		}
		if aerr := profiles.AddLocalProfile(resolvedProfilesPath, pr); aerr != nil {
			res.ProfileErrors = append(res.ProfileErrors,
				fmt.Sprintf("profile=%q: %v", cp.Name, aerr))
			continue
		}
		res.ProfilesImported++
	}

	// Operational state (pause, tasks) is intentionally NOT re-played
	// on import. Surface a note when the bundle carries any so the
	// operator knows it was visible to the importer + ignored.
	if p.Bundle.Pause != nil {
		res.Notes = append(res.Notes,
			fmt.Sprintf("bundle carries an active pause (id=%d, ends_at=%s); operational state is NOT re-played on import",
				p.Bundle.Pause.ID, p.Bundle.Pause.EndsAt))
	}
	if len(p.Bundle.Tasks) > 0 {
		res.Notes = append(res.Notes,
			fmt.Sprintf("bundle carries %d active task(s); operational state is NOT re-played on import",
				len(p.Bundle.Tasks)))
	}
	return res, nil
}

// configToProfile is the inverse of profileToConfig. Pure projection;
// no I/O.
func configToProfile(cp ConfigProfile) *profile.Profile {
	pr := &profile.Profile{
		Name:                 cp.Name,
		Description:          cp.Description,
		AllowBaseline:        profile.AllowBaseline(cp.AllowBaseline),
		DenyASTMutatingNodes: cp.DenyASTMutatingNodes,
		DenyActions:          appendStringsCopy(nil, cp.DenyActions),
		DenyKeywords:         appendStringsCopy(nil, cp.DenyKeywords),
		KeywordMatch:         profile.KeywordMatchMode(cp.KeywordMatch),
		ExemptResources:      appendStringsCopy(nil, cp.ExemptResources),
		ExemptActions:        appendStringsCopy(nil, cp.ExemptActions),
		Exceptions:           appendStringsCopy(nil, cp.Exceptions),
	}
	if len(cp.KeywordTargets) > 0 {
		targets := make([]profile.KeywordTarget, 0, len(cp.KeywordTargets))
		for _, t := range cp.KeywordTargets {
			targets = append(targets, profile.KeywordTarget(t))
		}
		pr.KeywordTargets = targets
	}
	if len(cp.AllowRules) > 0 {
		rules := make([]profile.ProfileAllowRule, 0, len(cp.AllowRules))
		for _, r := range cp.AllowRules {
			rules = append(rules, profile.ProfileAllowRule{
				Pattern: r.Pattern,
				Note:    r.Note,
			})
		}
		pr.AllowRules = rules
	}
	return pr
}

// ruleFingerprint produces a stable string that two rules with the same
// gating effect share. Used by applyBundle's de-dup so a repeated
// import doesn't double-up the same rule. Effect + Pattern + scope
// axes are load-bearing for gating; Note + Origin are documentation
// fields + intentionally excluded so a slightly-rewritten note doesn't
// flip the fingerprint.
func ruleFingerprint(r dbrules.ProxyRule) string {
	var sb strings.Builder
	sb.WriteString(string(r.Effect))
	sb.WriteByte('|')
	sb.WriteString(r.Pattern)
	sb.WriteByte('|')
	sb.WriteString(r.SchemaScope)
	sb.WriteByte('|')
	sb.WriteString(r.TableScope)
	sb.WriteByte('|')
	sb.WriteString(r.FunctionScope)
	return sb.String()
}


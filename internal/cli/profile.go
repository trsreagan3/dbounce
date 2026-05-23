// Cobra `dbounce profile ...` subcommands.
//
// Mirrors kbouncer/internal/cli/profile.go shape: list / show /
// install / install-defaults. The package-level
// internal/profile.Install / UpsertProfile own all the logic so the
// CLI is a thin layer (test coverage lives next to the package
// where the algorithm lives).

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	neturl "net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/store"
)

// newProfileCmd implements `dbounce profile ...`.
func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage dbounce environment profiles",
		Long: `dbounce environment profiles add an environment-aware deny
layer that fires BEFORE per-task scopes and global rules. A profile
deny is a hard floor — a permissive task scope cannot override it.

Use ` + "`dbounce profile list`" + ` to see the available profiles
and which one would be active given the current --profile flag /
` + envProfileVar + ` env var. ` + "`dbounce profile show NAME`" + `
prints the full record for a single profile.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("profile", cmd)
	cmd.AddCommand(newProfileListCmd())
	cmd.AddCommand(newProfileShowCmd())
	cmd.AddCommand(newProfileInstallCmd())
	cmd.AddCommand(newProfileInstallDefaultsCmd())
	cmd.AddCommand(newProfileDoctorCmd())
	return cmd
}

// newProfileDoctorCmd implements `dbounce profile doctor` per task
// #321 / KNOWN-CAVEATS §A19. Diff-checks the operator's installed
// profile YAML against embedded defaults + reports missing fields
// without overwriting. Operator opts in to merging via --apply or
// silences the warning via --acknowledge.
//
// Exit codes:
//
//	0  current — installed profile matches shipped defaults OR
//	   --apply succeeded OR --acknowledge succeeded
//	1  filesystem error (cannot read profiles.yaml)
//	2  doctor found missing fields AND neither --apply nor
//	   --acknowledge was given (mirrors `git status` non-zero for
//	   "something to do") — scripts can detect "operator should
//	   review" without parsing stderr
func newProfileDoctorCmd() *cobra.Command {
	var (
		profilesPath  string
		apply         bool
		acknowledge   bool
		showDiff      bool
		checkOnly     bool
		jsonOut       bool
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diff installed profile against shipped defaults + report missing fields",
		Long: `Compare ~/.dbounce/profiles.yaml against the shipped defaults
and report any fields the operator's local file is missing. dbounce
NEVER auto-overwrites profiles.yaml — operator edits survive
upgrades — but that means a new safety floor (e.g.
deny_dcl_targets_public, shipped in #302) added to embedded defaults
AFTER your file was written goes unnoticed.

  dbounce profile doctor              # report missing fields (no write)
  dbounce profile doctor --apply      # additively merge missing fields + back up prior file
  dbounce profile doctor --acknowledge # silence the warning for this defaults version
  dbounce profile doctor --diff       # show the YAML delta that --apply would write
  dbounce profile doctor --check      # silent; exit 2 if gaps found (script-friendly)

Per [[creates-never-mutates]]: --apply is ADDITIVE only. If you set
deny_dcl_targets_public: false deliberately, the field is PRESENT in
your YAML → --apply skips it. The doctor cannot override an
explicit operator choice.

Per [[security-team-positioning-safety-not-surveillance]]: framed
as "your profile is behind" not "you are non-compliant."`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if apply && acknowledge {
				return fmt.Errorf("--apply and --acknowledge are mutually exclusive")
			}
			if profilesPath == "" {
				p, err := profile.DefaultProfilesPath()
				if err != nil {
					return err
				}
				profilesPath = p
			}
			rep, err := profile.Check(profilesPath)
			if err != nil {
				return err
			}
			if apply {
				result, aerr := profile.Apply(profilesPath, profile.ApplyOptions{})
				if aerr != nil {
					return aerr
				}
				if len(result.AppliedFields) == 0 {
					fmt.Fprintf(cmd.OutOrStdout(),
						"dbounce: profile doctor — nothing to apply; installed profile matches shipped defaults (version %s).\n",
						profile.ShippedDefaultsVersion)
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"dbounce: profile doctor --apply — added %d field(s); backup at %s\n",
					len(result.AppliedFields), result.BackupPath)
				for _, g := range result.AppliedFields {
					fmt.Fprintf(cmd.OutOrStdout(),
						"  + %s.%s = %v   [%s] %s\n",
						g.ProfileName, g.Field, g.DefaultValue, g.Category, g.AddedIn)
				}
				return nil
			}
			if acknowledge {
				path, aerr := profile.Acknowledge(profilesPath)
				if aerr != nil {
					return aerr
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"dbounce: profile doctor --acknowledge — recorded %s at %s\n",
					profile.ShippedDefaultsVersion, path)
				fmt.Fprintln(cmd.OutOrStdout(),
					"future `dbounce run` startup banners will skip the §A19 warning "+
						"until a new shipped-defaults version bumps the stamp.")
				return nil
			}
			if checkOnly {
				if len(rep.MissingFields) > 0 {
					os.Exit(2)
				}
				return nil
			}
			if jsonOut {
				type jsonGap struct {
					Profile  string `json:"profile"`
					Field    string `json:"field"`
					Category string `json:"category"`
					Why      string `json:"why"`
					AddedIn  string `json:"added_in"`
					Default  any    `json:"default"`
				}
				out := struct {
					Version       string    `json:"shipped_defaults_version"`
					InstalledPath string    `json:"installed_path"`
					Missing       []jsonGap `json:"missing"`
				}{Version: rep.ShippedDefaultsVersion, InstalledPath: rep.InstalledPath}
				for _, g := range rep.MissingFields {
					out.Missing = append(out.Missing, jsonGap{
						Profile: g.ProfileName, Field: g.Field,
						Category: string(g.Category), Why: g.WhyMatters,
						AddedIn: g.AddedIn, Default: g.DefaultValue,
					})
				}
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
				if len(rep.MissingFields) > 0 {
					os.Exit(2)
				}
				return nil
			}
			fmt.Fprint(cmd.OutOrStdout(), profile.FormatReport("dbounce", rep))
			if showDiff {
				fmt.Fprintln(cmd.OutOrStdout(), "--- YAML that --apply would add ---")
				for _, g := range rep.MissingFields {
					fmt.Fprintf(cmd.OutOrStdout(),
						"profiles.%s.%s: %v\n",
						g.ProfileName, g.Field, g.DefaultValue)
				}
			}
			if len(rep.MissingFields) > 0 {
				// script-friendly non-zero exit so CI / install scripts
				// can detect "operator should review" without parsing
				// stderr. Wrapped in os.Exit so cobra doesn't suppress.
				os.Exit(2)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.dbounce/profiles.yaml).")
	cmd.Flags().BoolVar(&apply, "apply", false,
		"Additively merge missing default fields into profiles.yaml + back up prior file. "+
			"Per [[creates-never-mutates]]: only ADDS absent fields; never overwrites "+
			"operator-customized values.")
	cmd.Flags().BoolVar(&acknowledge, "acknowledge", false,
		"Record the current shipped-defaults version as acknowledged. Future "+
			"`dbounce run` startup banners skip the §A19 warning until a new "+
			"version bumps the stamp.")
	cmd.Flags().BoolVar(&showDiff, "diff", false,
		"Print the YAML fragment that --apply would add.")
	cmd.Flags().BoolVar(&checkOnly, "check", false,
		"Silent mode: exit 0 if profile is current, exit 2 if gaps found. "+
			"For scripted use (CI / install hooks).")
	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"Emit machine-readable JSON. Exit 2 if gaps found.")
	return cmd
}

// newProfileListCmd implements `dbounce profile list`.
func newProfileListCmd() *cobra.Command {
	var (
		profileName  string
		profilesPath string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available profiles and show which is active",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if profileName == "" {
				profileName = os.Getenv(envProfileVar)
			}
			if profilesPath == "" {
				p, err := profile.DefaultProfilesPath()
				if err != nil {
					return err
				}
				profilesPath = p
			}
			profiles, err := profile.LoadProfiles(profilesPath)
			if err != nil {
				return fmt.Errorf("load profiles: %w", err)
			}
			active, _ := profiles.Active(profileName)
			source := "embedded defaults"
			if profiles.Path != "" {
				source = profiles.Path
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"dbounce profiles (source: %s)\n", source)
			if profileName != "" && active == nil {
				fmt.Fprintf(cmd.OutOrStdout(),
					"WARNING: requested profile %q is not in this file. "+
						"`dbounce run` would refuse to start.\n", profileName)
			}
			for _, name := range profiles.NamesSorted() {
				p := profiles.All[name]
				marker := "  "
				if active != nil && p.Name == active.Name && profileName != "" {
					marker = "* "
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s%-20s %s\n", marker, name, p.Description)
				if p.AllowBaseline != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "    allow_baseline:        %s\n", p.AllowBaseline)
				}
				if p.DenyASTMutatingNodes {
					fmt.Fprintf(cmd.OutOrStdout(), "    deny_ast_mutating_nodes: true\n")
				}
				if len(p.DenyKeywords) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "    deny_keywords:         %s\n", strings.Join(p.DenyKeywords, ", "))
				}
				if len(p.DenyActions) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "    deny_actions:          %s\n", strings.Join(p.DenyActions, ", "))
				}
				if len(p.ExemptResources) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "    exempt_resources:      %s\n", strings.Join(p.ExemptResources, ", "))
				}
				if len(p.ExemptActions) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "    exempt_actions:        %s\n", strings.Join(p.ExemptActions, ", "))
				}
			}
			if profileName == "" {
				fmt.Fprintln(cmd.OutOrStdout(),
					"\n(no profile selected; pass --profile NAME or set "+envProfileVar+")")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profileName, "profile", "",
		"Profile to mark as active in the listing. Falls back to "+envProfileVar+".")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.dbounce/profiles.yaml).")
	return cmd
}

// newProfileShowCmd implements `dbounce profile show NAME`.
func newProfileShowCmd() *cobra.Command {
	var profilesPath string
	cmd := &cobra.Command{
		Use:   "show NAME",
		Short: "Show full detail for a single profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if profilesPath == "" {
				p, err := profile.DefaultProfilesPath()
				if err != nil {
					return err
				}
				profilesPath = p
			}
			profiles, err := profile.LoadProfiles(profilesPath)
			if err != nil {
				return fmt.Errorf("load profiles: %w", err)
			}
			p, err := profiles.Active(name)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"dbounce: profile %q not found (loaded: %s)\n",
					name, strings.Join(profiles.NamesSorted(), ", "))
				os.Exit(1)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "name:         %s\n", p.Name)
			if p.Description != "" {
				fmt.Fprintf(w, "description:  %s\n", p.Description)
			}
			source := p.Source
			if source == "" {
				source = "local"
			}
			fmt.Fprintf(w, "source:       %s\n", source)
			if p.AllowBaseline != "" {
				fmt.Fprintf(w, "allow_baseline: %s\n", p.AllowBaseline)
			}
			if p.DenyASTMutatingNodes {
				fmt.Fprintln(w, "deny_ast_mutating_nodes: true")
			}
			if len(p.DenyKeywords) > 0 {
				fmt.Fprintf(w, "deny_keywords: %s\n", strings.Join(p.DenyKeywords, ", "))
			}
			if p.KeywordMatch != "" {
				fmt.Fprintf(w, "keyword_match: %s\n", p.KeywordMatch)
			}
			if len(p.KeywordTargets) > 0 {
				targets := make([]string, 0, len(p.KeywordTargets))
				for _, t := range p.KeywordTargets {
					targets = append(targets, string(t))
				}
				fmt.Fprintf(w, "keyword_targets: %s\n", strings.Join(targets, ", "))
			}
			if len(p.DenyActions) > 0 {
				fmt.Fprintf(w, "deny_actions: %s\n", strings.Join(p.DenyActions, ", "))
			}
			if len(p.ExemptResources) > 0 {
				fmt.Fprintf(w, "exempt_resources: %s\n", strings.Join(p.ExemptResources, ", "))
			}
			if len(p.ExemptActions) > 0 {
				fmt.Fprintf(w, "exempt_actions: %s\n", strings.Join(p.ExemptActions, ", "))
			}
			if len(p.Exceptions) > 0 {
				fmt.Fprintf(w, "exceptions: %s\n", strings.Join(p.Exceptions, ", "))
			}
			if n := len(p.AllowRules); n > 0 {
				fmt.Fprintf(w, "allow_rules: %d\n", n)
				for _, r := range p.AllowRules {
					fmt.Fprintf(w, "  - %s\n", r.Pattern)
					if r.Note != "" {
						fmt.Fprintf(w, "      # %s\n", r.Note)
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.dbounce/profiles.yaml).")
	return cmd
}

// newProfileInstallCmd implements `dbounce profile install --from URL`.
//
// Exit codes (mirror Python iam-jit-bouncer + kbouncer):
//
//	0  success
//	1  payload / fetch problem (malformed YAML, validation error,
//	   fetch failed) — usually an upstream-curator issue
//	2  operator-fixable problem (http:// URL, sha256 mismatch,
//	   conflict without --force)
func newProfileInstallCmd() *cobra.Command {
	var (
		fromURL        string
		expectedSHA256 string
		force          bool
		timeoutSecs    int
		profilesPath   string
		dbPath         string
		actor          string
	)
	cmd := &cobra.Command{
		Use:   "install --from URL_OR_PATH [--sha256 HEX] [--force] [--timeout 10]",
		Short: "Fetch + install profiles from a URL or local path",
		Long: `Install profiles from any of:

  * an HTTPS URL — preferred + recommended distribution channel
    (IT teams publish curated profiles at an internal URL, engineers
    install them on day 1).

      dbounce profile install --from https://internal.example/profiles.yaml

  * an HTTP URL — accepted for local-dev parity with the
    audit-export HTTP surface. A one-line WARN fires for non-
    loopback hosts; loopback (localhost / 127.0.0.1 / ::1) gets a
    silent pass.

  * file:///abs/path/...  or a bare local path (relative or
    absolute) — accepts a single YAML file OR a bundle directory
    produced by ` + "`iam-jit profile generate-from-audit`" + `; the
    directory form looks for ` + "`dbounce.yaml`" + ` first then
    falls back to ` + "`index.yaml`" + ` + the bouncer entry naming
    dbounce.

      dbounce profile install --from ./profiles/

The source string becomes the ` + "`source`" + ` of each installed profile.
Profiles with a non-local source are READ-ONLY at the CLI surface —
engineers cannot edit them to bypass org guardrails.

Conflict policy: if a profile of the same name already exists,
install refuses without --force.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := profile.InstallOptions{
				From:           fromURL,
				ExpectedSHA256: expectedSHA256,
				Force:          force,
				Timeout:        time.Duration(timeoutSecs) * time.Second,
				ProfilesPath:   profilesPath,
			}
			// Emit a "WARN" line for non-loopback HTTP fetches at the
			// CLI layer (the profile package keeps the source-string
			// gate pure). Loopback gets a silent pass.
			if parsed, perr := neturl.Parse(fromURL); perr == nil &&
				strings.EqualFold(parsed.Scheme, "http") {
				host := parsed.Hostname()
				isLoopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
				if !isLoopback {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"WARN: fetching %q over plaintext HTTP — a network "+
							"attacker can MITM-substitute a permissive profile. "+
							"Prefer https:// for IT-distributed profiles. This "+
							"warning does NOT block the install (per §A26 local-"+
							"dev parity with audit-export HTTP).\n", fromURL)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "loading %s ...\n", fromURL)
			result, err := profile.Install(cmd.Context(), opts)
			if err != nil {
				var ie *profile.InstallError
				if errors.As(err, &ie) {
					fmt.Fprintln(cmd.ErrOrStderr(), ie.Message)
					os.Exit(ie.ExitCode)
				}
				return err
			}

			if result.SHA256Verified {
				fmt.Fprintf(cmd.OutOrStdout(), "sha256 verified: %s\n", result.SHA256)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "sha256 (no pin given): %s\n", result.SHA256)
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"installed %d profile(s) into %s:\n",
				len(result.InstalledNames), result.ProfilesPath)
			for _, name := range result.InstalledNames {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", name)
			}
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Activate one with:")
			fmt.Fprintf(cmd.OutOrStdout(),
				"  dbounce run --profile %s\n", result.InstalledNames[0])
			fmt.Fprintln(cmd.OutOrStdout(),
				"These profiles are READ-ONLY (sourced from URL); "+
					"edit the upstream YAML + re-install to update.")

			// [[security-team-audit-export]] Slice 2: enqueue a
			// PROFILE_INSTALLED row on the cross-process audit-event
			// queue. The running `dbounce run` process polls + drains
			// the queue (proxy.runPendingAuditEventsPoller, 1s
			// cadence) + emits through its wired Exporter +
			// RuleEngine. Best-effort: an enqueue failure does NOT
			// fail the install — the install itself already succeeded
			// + the synthetic is observability metadata. We surface a
			// stderr line so an operator who's set up the audit-
			// export pipeline can see the queue write failed
			// (typically: state.db permission denied / disk full).
			enqueueProfileInstalledAuditEvent(
				cmd, dbPath, resolveActor(actor), result)
			return nil
		},
	}
	cmd.Flags().StringVar(&fromURL, "from", "",
		"HTTPS URL of a profiles.yaml fragment. Required. http:// is refused.")
	_ = cmd.MarkFlagRequired("from")
	cmd.Flags().StringVar(&expectedSHA256, "sha256", "",
		"Optional SHA-256 (hex) of the fetched bytes. Mismatch → exit 2. "+
			"Defends against a compromised distribution server swapping the file.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite existing profiles of the same name. Without --force, "+
			"install refuses on conflict.")
	cmd.Flags().IntVar(&timeoutSecs, "timeout", 10,
		"HTTPS fetch timeout in seconds.")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.dbounce/profiles.yaml). "+
			"Honors DBOUNCE_PROFILES_PATH env var if unset.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path used for the cross-process audit-event queue "+
			"(default: ~/.dbounce/state.db, or DBOUNCE_DB env). The "+
			"running `dbounce run` process drains the queue + emits "+
			"a PROFILE_INSTALLED event through its configured "+
			"audit-export transports.")
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id recorded as installed_by on the audit event. "+
			"Defaults to $USER then 'unknown'.")
	return cmd
}

// enqueueProfileInstalledAuditEvent writes the cross-process row the
// running `dbounce run` process drains on its 1s tick per
// [[security-team-audit-export]] Slice 2. Best-effort — failure is
// surfaced via stderr but does NOT fail the install (the install
// itself already succeeded + the synthetic is observability metadata).
//
// Dialect inference: dbounce profiles aren't dialect-tagged in YAML,
// but operators often distribute per-dialect bundles (pg-readonly,
// mysql-prod, snowflake-export, ...). We extract dialect tokens from
// the installed profile names so a SIEM dashboard can filter
// "profile installs that touched MySQL." Empty when no dialect token
// matches — the field is omitted from the emit per the
// audit.ProfileInstalledInfo contract.
func enqueueProfileInstalledAuditEvent(
	cmd *cobra.Command, dbPath, actor string, result *profile.InstallResult,
) {
	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"dbounce: note: open state.db for audit-event enqueue failed: %v "+
				"(install succeeded; PROFILE_INSTALLED audit event NOT emitted)\n", err)
		return
	}
	defer st.Close()

	payload := map[string]any{
		"source_url":      result.SourceURL,
		"profile_names":   result.InstalledNames,
		"sha256":          result.SHA256,
		"sha256_verified": result.SHA256Verified,
		"profiles_path":   result.ProfilesPath,
		"installed_by":    actor,
	}
	dialects := inferDialectsFromProfileNames(result.InstalledNames)
	if len(dialects) > 0 {
		payload["dialects"] = dialects
	}
	b, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"dbounce: note: marshal PROFILE_INSTALLED payload failed: %v "+
				"(install succeeded; audit event NOT emitted)\n", err)
		return
	}
	if _, err := st.AddPendingAuditEvent(
		store.PendingAuditEventProfileInstalled, string(b)); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"dbounce: note: enqueue PROFILE_INSTALLED audit event failed: %v "+
				"(install succeeded; the running `dbounce run` process "+
				"will not see this install on its next drain tick)\n", err)
	}
}

// inferDialectsFromProfileNames extracts dialect tokens from the
// installed profile names. dbounce profiles aren't dialect-tagged in
// YAML, but operators commonly include the dialect as a name prefix
// or suffix (pg-readonly, mysql-prod, snowflake-export, ...). This
// matches token-by-token against the known dialect set + returns the
// matched dialects sorted (deterministic shape for SIEM dashboards
// that group by the field value).
//
// Match is case-insensitive substring on dash-/underscore-bounded
// tokens within each profile name. Returns the deduped + sorted set;
// empty when no dialect token matches.
func inferDialectsFromProfileNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	// Token aliases per dialect — sourced from the central
	// dialectAliasMap helper (admin_action.go) so the dialect
	// vocabulary stays consistent across the install-event helper +
	// the admin-action helpers (rule-pattern + preset-id). "pg"
	// matches "postgres" because operators frequently use the
	// shorthand in profile names ("pg-readonly").
	aliases := dialectAliasMap()
	seen := map[string]struct{}{}
	for _, name := range names {
		lower := strings.ToLower(name)
		// Tokenize on dash + underscore + dot — the common separators
		// in profile naming conventions.
		tokens := strings.FieldsFunc(lower, func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		})
		for _, tok := range tokens {
			if d, ok := aliases[tok]; ok {
				seen[d] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// newProfileInstallDefaultsCmd implements `dbounce profile
// install-defaults`. Writes the embedded built-in profiles to disk
// (full-user + safe-default) iff the file doesn't already exist.
// Convenience for operators who want the file materialized on disk
// without starting the server.
func newProfileInstallDefaultsCmd() *cobra.Command {
	var (
		profilesPath string
		force        bool
	)
	cmd := &cobra.Command{
		Use:   "install-defaults",
		Short: "Materialize the built-in profiles.yaml on disk",
		Long: `Write the embedded default profiles (full-user +
safe-default) to ~/.dbounce/profiles.yaml. NEVER overwrites an
existing file unless --force is set (operator edits to community-
installed profiles must survive). Convenient when operators want to
review or edit profiles.yaml before starting the server.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if profilesPath == "" {
				p, err := profile.DefaultProfilesPath()
				if err != nil {
					return err
				}
				profilesPath = p
			}
			if force {
				// EnsureDefaultProfilesFile won't overwrite; force is the
				// only path that does. Implement explicit overwrite by
				// removing then writing.
				_ = os.Remove(profilesPath)
			}
			written, err := profile.EnsureDefaultProfilesFile(profilesPath)
			if err != nil {
				return err
			}
			if written {
				fmt.Fprintf(cmd.OutOrStdout(),
					"dbounce: wrote default profiles to %s\n", profilesPath)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(),
					"dbounce: profiles.yaml already exists at %s "+
						"(pass --force to overwrite)\n", profilesPath)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.dbounce/profiles.yaml).")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite an existing profiles.yaml at the target path.")
	return cmd
}

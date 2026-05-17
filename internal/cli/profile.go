// Cobra `dbounce profile ...` subcommands.
//
// Mirrors kbouncer/internal/cli/profile.go shape: list / show /
// install / install-defaults. The package-level
// internal/profile.Install / UpsertProfile own all the logic so the
// CLI is a thin layer (test coverage lives next to the package
// where the algorithm lives).

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/profile"
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
	)
	cmd := &cobra.Command{
		Use:   "install --from URL [--sha256 HEX] [--force] [--timeout 10]",
		Short: "Fetch + install profiles from an HTTPS URL",
		Long: `Fetch a profiles.yaml fragment from an HTTPS URL and install
the profiles it contains. Composes with the enterprise-profile-
distribution onboarding pattern: IT teams publish curated profiles
at an internal URL, and engineers install them on day 1.

  dbounce profile install --from https://internal.example/profiles.yaml

The fetched URL becomes the ` + "`source`" + ` of each installed profile.
Profiles with a non-local source are READ-ONLY at the CLI surface —
engineers cannot edit them to bypass org guardrails.

HTTPS-only: http:// URLs are refused because plaintext distribution
is MITM-substitutable. IT teams should ALSO pin --sha256 in their
onboarding docs to defend against a compromised distribution server.

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
			fmt.Fprintf(cmd.OutOrStdout(), "fetching %s ...\n", fromURL)
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
	return cmd
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

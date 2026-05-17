// `dbounce presets list | show | apply` (D-Slice 8).
//
// Browses + installs the built-in preset library (tier 1 per
// [[evolving-preset-library]]). Operators who don't yet know what
// rule set their workload needs can pick a starter preset, install
// it as a new profile, then refine.
//
// Apply semantics: NEVER mutates an existing profile (per
// [[creates-never-mutates]]). `dbounce presets apply NAME` always
// creates a fresh profile carrying the preset's rules. Auto-naming
// per [[profile-auto-naming]] applies when the operator passes
// `--target` (optional value) or omits it on non-TTY.
package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/naming"
	"github.com/trsreagan3/dbounce/internal/presets"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
)

func newPresetsCmd(profileWriter ProfileWriter) *cobra.Command {
	if profileWriter == nil {
		panic("dbounce cli: newPresetsCmd requires a non-nil ProfileWriter (INFO-D8-14)")
	}
	cmd := &cobra.Command{
		Use:   "presets",
		Short: "Browse + install the built-in preset library",
		Long: `dbounce ships a small built-in preset library (analytics-engineer,
dba-investigation, migration-runner, incident-readonly, schema-survey)
to give operators a starting point when they don't yet know exactly
what rule set their workload needs.

'dbounce presets list' shows what's available.
'dbounce presets show NAME' prints the preset's rules + description.
'dbounce presets apply NAME' creates a new profile from the preset
(auto-named per [[profile-auto-naming]] when --target is absent).

Per [[creates-never-mutates]] apply NEVER modifies an existing profile —
it always creates a fresh one. Per [[evolving-preset-library]] this is
the tier-1 (built-in) library only; org-curated + personal-recurring
presets land post-launch.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("presets", cmd)
	cmd.AddCommand(newPresetsListCmd())
	cmd.AddCommand(newPresetsShowCmd())
	cmd.AddCommand(newPresetsApplyCmd(profileWriter))
	return cmd
}

func newPresetsListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List built-in presets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			all := presets.List()
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				for _, p := range all {
					if err := enc.Encode(map[string]any{
						"id":          p.ID,
						"title":       p.Title,
						"description": p.Description,
						"allow_count": len(p.AllowRules),
						"deny_count":  len(p.DenyRules),
					}); err != nil {
						return err
					}
				}
				return nil
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-22s  %-5s  %-5s  %s\n",
				"ID", "ALLOW", "DENY", "TITLE")
			for _, p := range all {
				fmt.Fprintf(w, "%-22s  %-5d  %-5d  %s\n",
					p.ID, len(p.AllowRules), len(p.DenyRules), p.Title)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit one JSON object per preset.")
	return cmd
}

func newPresetsShowCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show NAME",
		Short: "Show the full description + rules for one preset",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			p, ok := presets.Get(id)
			if !ok {
				return fmt.Errorf("no preset named %q (try 'dbounce presets list')", id)
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"id":          p.ID,
					"title":       p.Title,
					"description": p.Description,
					"allow_rules": p.AllowRules,
					"deny_rules":  p.DenyRules,
				})
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "preset: %s\n", p.ID)
			fmt.Fprintf(w, "title : %s\n", p.Title)
			fmt.Fprintf(w, "description:\n%s\n", indent(p.Description, "  "))
			if len(p.AllowRules) > 0 {
				fmt.Fprintln(w, "allow_rules:")
				for _, r := range p.AllowRules {
					fmt.Fprintf(w, "  - %s  (note: %s)\n", r.Pattern, r.Note)
				}
			}
			if len(p.DenyRules) > 0 {
				fmt.Fprintln(w, "deny_rules:")
				for _, r := range p.DenyRules {
					fmt.Fprintf(w, "  - %s  (note: %s)\n", r.Pattern, r.Note)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit machine-readable JSON.")
	return cmd
}

func newPresetsApplyCmd(profileWriter ProfileWriter) *cobra.Command {
	if profileWriter == nil {
		panic("dbounce cli: newPresetsApplyCmd requires a non-nil ProfileWriter (INFO-D8-14)")
	}
	var (
		target string
		actor  string
	)
	cmd := &cobra.Command{
		Use:   "apply NAME",
		Short: "Install a preset as a new profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			p, ok := presets.Get(id)
			if !ok {
				return fmt.Errorf("no preset named %q (try 'dbounce presets list')", id)
			}
			allow, deny := p.ToProxyRules()
			if len(allow)+len(deny) == 0 {
				// Defensive — the presets.load validation catches this
				// at startup; assert again so a corrupt embedded YAML
				// can't silently create an empty profile.
				return fmt.Errorf("preset %q has no rules", id)
			}
			existing, err := profileWriter.ExistingProfileNames()
			if err != nil {
				return fmt.Errorf("list profile names: %w", err)
			}
			ctx := naming.Context{
				Kind:   "preset",
				Detail: p.ID,
				Now:    naming.SystemClock,
			}
			targetSet := cmd.Flags().Changed("target")
			isTTY := isatty.IsTerminal(0)
			argVal := ""
			if targetSet {
				argVal = target
				if argVal == "__AUTO__" {
					// Bare `--target` (no =VALUE) — caller asked for
					// the auto-name explicitly.
					argVal = ""
				}
			}
			resolved, wantPrompt, suggestion := naming.ResolveProfileName(argVal, ctx, isTTY && targetSet && argVal == "", existing)
			if wantPrompt {
				// CLI default-readline behavior would otherwise need a
				// stdin loop here; mirror the prompts-answer simple
				// approach: fall back to the suggestion + tell stderr.
				resolved = suggestion
				fmt.Fprintf(cmd.ErrOrStderr(),
					"using auto-name %q (TTY interactive prompt not yet wired for `presets apply`)\n",
					resolved)
			}
			if resolved == "" {
				resolved = suggestion
			}
			desc := fmt.Sprintf("from preset %s: %s", p.ID, p.Title)
			if err := profileWriter.CreateProfile(resolved, desc, allow, deny); err != nil {
				return fmt.Errorf("create profile: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"created profile %q from preset %s (%d allow rules + %d deny rules).\n",
				resolved, p.ID, len(allow), len(deny))
			_ = actor // reserved for an audit-row emission once D-Slice 7's profile package surfaces a CreatedBy field
			_ = dbrules.OriginPreset // silence unused-import if profileWriter wraps the rules transparently
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "",
		"Profile name. Use --target=NAME for an explicit name, or bare "+
			"--target (no value) for the [[profile-auto-naming]] auto-name. "+
			"The =NAME form is required when supplying a value.")
	// NoOptDefVal sentinel: bare `--target` parses to __AUTO__ which
	// RunE strips before resolving. pflag refuses empty NoOptDefVal.
	cmd.Flag("target").NoOptDefVal = "__AUTO__"
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id (reserved for future audit fields).")
	return cmd
}

// indent prefixes each line of s with prefix. Used to render the
// preset description as a nested block in the human-readable output.
func indent(s, prefix string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

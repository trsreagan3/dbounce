// `dbounce audit-webhook` — operator commands for the audit-export
// webhook channel (#259). Sibling to `audit-export` (which is about
// live status — `is the webhook healthy?`). This group is about
// configuration discovery: `what preset shapes does this binary
// speak? what flags does each one need?`
//
// Currently ships `presets list` only — read-only enumeration of
// the per-vendor adapters the binary knows about. Mirrors the
// `list_audit_webhook_presets` MCP tool + the matching `ibounce`
// + `kbounce` subcommands per [[cross-product-agent-parity]].
//
// Per [[audit-webhook-presets]]: the descriptor list is GENERIC —
// no vendor secrets, no LLM-evaluated text, no runtime introspection.
// Single source of truth is `audit.PresetDescriptors()` so both the
// CLI surface and the MCP tool import the same data.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/audit"
)

// newAuditWebhookCmd implements `dbounce audit-webhook ...`.
// Currently ships the `presets list` subcommand only.
func newAuditWebhookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit-webhook",
		Short: "Discover and inspect the audit-webhook preset framework",
		Long: `Operator commands for the audit-export webhook channel.

Sibling to ` + "`audit-export`" + ` (which is about live status — ` + "`is the " +
			"webhook healthy?`" + `). This group is about configuration discovery:
` + "`what preset shapes does this binary speak? what flags does each one " +
			"need?`" + ` Per [[audit-webhook-presets]] + [[cross-product-agent-parity]].

Subcommands:
  presets   List the per-vendor preset shapes the binary speaks`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("audit-webhook", cmd)
	cmd.AddCommand(newAuditWebhookPresetsCmd())
	return cmd
}

func newAuditWebhookPresetsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "presets",
		Short: "List / introspect available webhook preset shapes",
		Long: `Manage / introspect the available audit-webhook preset shapes.
Currently ships ` + "`list`" + ` only — read-only enumeration of the per-vendor
adapters the binary knows about.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("audit-webhook presets", cmd)
	cmd.AddCommand(newAuditWebhookPresetsListCmd())
	return cmd
}

func newAuditWebhookPresetsListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Print the available audit-webhook preset shapes + their config requirements",
		Long: `Print the available audit-webhook preset shapes. Mirrors the
` + "`list_audit_webhook_presets`" + ` MCP tool — cross-product parity per
[[cross-product-agent-parity]]; ` + "`ibounce audit-webhook presets list`" + `
+ ` + "`kbounce audit-webhook presets list`" + ` print the same JSON shape
under --json.

See docs/WEBHOOK-PRESETS.md (in the cross-product iam-roles repo) for
the full per-vendor wire shape + token-acquisition steps.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditWebhookPresetsList(cmd.OutOrStdout(), asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit the descriptor list as JSON (for agent consumption).")
	return cmd
}

// runAuditWebhookPresetsList is the testable entry point. Writes to
// stdout (passed in by the cobra command so tests can capture).
func runAuditWebhookPresetsList(stdout io.Writer, asJSON bool) error {
	descriptors := audit.PresetDescriptors()
	if asJSON {
		body, err := json.MarshalIndent(descriptors, "", "  ")
		if err != nil {
			return fmt.Errorf("dbounce: audit-webhook presets list: marshal: %w", err)
		}
		fmt.Fprintln(stdout, string(body))
		return nil
	}
	fmt.Fprintf(stdout, "%-12s  %-58s  %s\n", "NAME", "REQUIRES", "OPTIONAL")
	for _, desc := range descriptors {
		req := strings.Join(desc.RequiredFlags, ", ")
		opt := strings.Join(desc.OptionalFlags, ", ")
		if opt == "" {
			opt = "(none)"
		}
		fmt.Fprintf(stdout, "%-12s  %-58s  %s\n", desc.Name, req, opt)
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "See docs/WEBHOOK-PRESETS.md (iam-roles repo) for the full")
	fmt.Fprintln(stdout, "per-vendor wire shape + token-acquisition steps.")
	return nil
}

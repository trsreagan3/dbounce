// `dbounce doctor` — operator-friendly health + caveat surface.
//
// Per task #304: `dbounce doctor caveats` lists every §B entry that
// genuinely applies to dbounce + links to the canonical doc. Sibling
// Bounce products ship the same `*bounce doctor caveats` subcommand
// shape per [[cross-product-agent-parity]].
//
// Per [[creates-never-mutates]]: this is a strictly READ-ONLY command.
// Per [[security-team-positioning-safety-not-surveillance]]: language
// is helpful, never accusatory.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/caveats"
)

// newDoctorCmd assembles `dbounce doctor` + the `caveats` subcommand.
func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Operator-friendly health + caveat surfaces",
		Long: `Subcommands:

  caveats   Print the §B entries from KNOWN-CAVEATS.md that apply to
            dbounce (including cross-product entries shared with the
            other Bounce products).

Sibling Bounce products (ibounce / kbounce / gbounce) ship the same
` + "`{product} doctor caveats`" + ` subcommand. The full canonical doc
lives at ` + caveats.CanonicalDocURL() + `.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		return fmt.Errorf("dbounce doctor: subcommand required (try `dbounce doctor caveats`)")
	}
	cmd.AddCommand(newDoctorCaveatsCmd())
	// #311 / §A10 — audit-log integrity / freshness / disk check.
	cmd.AddCommand(newDoctorLogsCmd())
	return cmd
}

func newDoctorCaveatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "caveats",
		Short: "Print KNOWN-CAVEATS §B entries that apply to dbounce",
		Long: `Print the §B (documented limits, not launch-blocking) entries
from KNOWN-CAVEATS.md that apply to dbounce.

Full canonical doc: ` + caveats.CanonicalDocURL() + `

Per [[creates-never-mutates]]: read-only.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			fmt.Fprintln(w, "dbounce: KNOWN-CAVEATS §B entries that apply to this product")
			fmt.Fprintln(w, "Full canonical doc:", caveats.CanonicalDocURL())
			fmt.Fprintln(w)
			for _, e := range caveats.DoctorEntries() {
				fmt.Fprintf(w, "§%s\n", e.ID)
				fmt.Fprintf(w, "  %s\n", e.DoctorBlurb)
				fmt.Fprintf(w, "  link: %s\n\n", e.URL())
			}
			return nil
		},
	}
}

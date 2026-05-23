// `dbounce posture` — per-bouncer posture surface (CLI shim).
//
// Cross-product parity command per [[cross-product-agent-parity]];
// for the cross-product view use `iam-jit posture` from iam-roles.
//
// Posture-capture logic lives in internal/posture so the MCP package
// can call the same code path without an import cycle on internal/cli.
package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/posture"
)

func newPostureCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "posture",
		Short: "Report this bouncer's posture (running / mode / profile / env wiring)",
		Long: `Report dbounce's posture: is it running, what mode + profile,
and is the operator's PGHOST/PGPORT pointing at dbounce.

For the cross-product view (all 4 bouncers + iam-jit role state +
per-traffic-class effective protection), use ` + "`iam-jit posture`" + `.

Per [[ibounce-honest-positioning]]: the output is HONEST about
uncertainty + misconfig — if PGHOST points at loopback but dbounce
isn't running, the output reports "MISCONFIGURED" rather than
silently claiming intercept.

Per [[cross-product-agent-parity]]: every Bounce ships this same
shape (ibounce / kbounce / dbounce / gbounce).`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			block := posture.Capture()
			if asJSON {
				enc := json.NewEncoder(c.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(block)
			}
			w := c.OutOrStdout()
			fmt.Fprintln(w, "== dbounce posture ==")
			status := "STOPPED"
			if block.Running {
				status = "RUNNING"
			}
			fmt.Fprintf(w, "Status: %s on 127.0.0.1:%d (mgmt %d)\n",
				status, block.Port, block.MgmtPort)
			fmt.Fprintf(w, "Mode: %s\n", block.Mode)
			fmt.Fprintf(w, "Active profile: %s\n", block.ActiveProfile)
			if block.EnvVarPointingHere != "" {
				fmt.Fprintf(w, "Env wiring: %s\n", block.EnvVarPointingHere)
			}
			if block.EnvVarSetElsewhere != "" {
				fmt.Fprintf(w, "Env elsewhere: %s\n", block.EnvVarSetElsewhere)
			}
			if block.Misconfig != "" {
				fmt.Fprintf(c.ErrOrStderr(), "MISCONFIG: %s\n", block.Misconfig)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"emit structured posture snapshot as JSON (designed for agent / pipeline consumption)")
	return cmd
}

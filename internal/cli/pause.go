// `dbounce pause start | stop | status | history` (D-Slice 8).
//
// Mirrors kbounce's + ibounce's pause UX so an operator switching
// between products doesn't have to relearn the verbs:
//
//	dbounce pause start --for 30m --reason "live demo"
//	dbounce pause stop
//	dbounce pause status
//	dbounce pause history --limit 20
//
// The pause window is the [[safety-mode-lean-permissive]] escape
// hatch: a transparent-mode DENY DEMOTES to ALLOW while a pause is
// active (audit-row pause_id stamped so post-incident review can
// answer "what would have been blocked"). When `stop` runs or the TTL
// expires, the gate snaps back to its baseline.
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/store"
)

func newPauseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pause",
		Short: "Pause / resume the dbounce gate (timed escape hatch)",
		Long: `Pause the dbounce gate for a bounded window. While a pause is
active, transparent-mode DENY decisions DEMOTE to ALLOW and the audit
row records the pause id so post-incident review can answer "what
would have been blocked." Stops automatically at the configured TTL,
or explicitly via 'dbounce pause stop'.

Subcommands:
  start    open a new pause window
  stop     close the active pause early
  status   show the active pause (or "none")
  history  list recent pause windows`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("pause", cmd)
	cmd.AddCommand(newPauseStartCmd())
	cmd.AddCommand(newPauseStopCmd())
	cmd.AddCommand(newPauseStatusCmd())
	cmd.AddCommand(newPauseHistoryCmd())
	return cmd
}

func newPauseStartCmd() *cobra.Command {
	var (
		dbPath string
		forDur time.Duration
		reason string
		actor  string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Open a new pause window",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if forDur <= 0 {
				return fmt.Errorf("--for must be > 0 (got %v)", forDur)
			}
			// 24h cap mirrors tasks.MaxDurationMinutes: a multi-day
			// pause is a smell; the operator probably wants a different
			// shape (config change, profile swap).
			if forDur > 24*time.Hour {
				return fmt.Errorf("--for max is 24h (got %v); for longer windows, change the profile or default-policy instead", forDur)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			startedBy := resolveActor(actor)
			id, endsAt, err := st.StartPause(reason, startedBy, forDur)
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"pause_id":   id,
					"ends_at":    endsAt.Format(time.RFC3339),
					"reason":     reason,
					"started_by": startedBy,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"pause %d started by %s; ends at %s (in %s)\n",
				id, startedBy, endsAt.Format(time.RFC3339), forDur)
			if reason != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "reason: %s\n", reason)
			}
			fmt.Fprintln(cmd.OutOrStdout(),
				"while paused, transparent DENY decisions demote to ALLOW + audit-row pause_id is stamped.")
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().DurationVar(&forDur, "for", 30*time.Minute,
		"Pause TTL (e.g. 30m, 2h). Max 24h.")
	cmd.Flags().StringVar(&reason, "reason", "",
		"Free-form reason recorded in the audit + history (e.g. 'live demo', 'oncall debug').")
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id recorded as started_by. Defaults to $USER then 'unknown'.")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit machine-readable JSON instead of the human banner.")
	return cmd
}

func newPauseStopCmd() *cobra.Command {
	var (
		dbPath string
		actor  string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Close the active pause window early",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			_ = resolveActor(actor) // recorded by future audit-trail; for now logged via end_kind
			id, err := st.StopPause(resolveActor(actor))
			if err != nil {
				return err
			}
			if id == 0 {
				if asJSON {
					return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
						"stopped": false,
					})
				}
				fmt.Fprintln(cmd.OutOrStdout(), "no active pause to stop.")
				return nil
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"stopped":  true,
					"pause_id": id,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stopped pause %d.\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id; defaults to $USER then 'unknown'.")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit machine-readable JSON.")
	return cmd
}

func newPauseStatusCmd() *cobra.Command {
	var (
		dbPath string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the active pause window (or 'none')",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			active, err := st.GetActivePause()
			if err != nil {
				return err
			}
			if active == nil {
				if asJSON {
					return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
						"active": false,
					})
				}
				fmt.Fprintln(cmd.OutOrStdout(), "no active pause.")
				return nil
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"active":     true,
					"pause_id":   active.ID,
					"started_at": active.StartedAt,
					"ends_at":    active.EndsAt,
					"reason":     active.Reason,
					"started_by": active.StartedBy,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"active pause: id=%d started_by=%s started_at=%s ends_at=%s\n",
				active.ID, active.StartedBy, active.StartedAt, active.EndsAt)
			if active.Reason != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "reason: %s\n", active.Reason)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit machine-readable JSON.")
	return cmd
}

func newPauseHistoryCmd() *cobra.Command {
	var (
		dbPath string
		limit  int
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show recent pause windows (newest first)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 1 || limit > 200 {
				return fmt.Errorf("--limit must be in 1-200 (got %d)", limit)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			entries, err := st.PauseHistory(limit)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				for _, e := range entries {
					if err := enc.Encode(map[string]any{
						"pause_id":        e.ID,
						"started_at":      e.StartedAt,
						"ends_at":         e.EndsAt,
						"reason":          e.Reason,
						"started_by":      e.StartedBy,
						"ended_at_actual": e.EndedAtActual,
						"end_kind":        e.EndKind,
					}); err != nil {
						return err
					}
				}
				return nil
			}
			if len(entries) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no pause windows recorded)")
				return nil
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-4s  %-20s  %-20s  %-10s  %-12s  %s\n",
				"ID", "STARTED-AT", "ENDS-AT", "END-KIND", "STARTED-BY", "REASON")
			for _, e := range entries {
				endKind := e.EndKind
				if endKind == "" {
					endKind = "active"
				}
				fmt.Fprintf(w, "%-4d  %-20s  %-20s  %-10s  %-12s  %s\n",
					e.ID, e.StartedAt, e.EndsAt, endKind, e.StartedBy, e.Reason)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().IntVar(&limit, "limit", 20,
		"Max rows to return (1-200). Default 20.")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit one JSON object per pause window, newest first.")
	return cmd
}

// resolveActor mirrors kbounce's + ibounce's actor-resolution policy:
// explicit --actor wins, then $USER, then "unknown" as a last resort
// so the audit row always has SOMETHING for the started_by column.
func resolveActor(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if cu, err := user.Current(); err == nil && cu.Username != "" {
		return cu.Username
	}
	return "unknown"
}

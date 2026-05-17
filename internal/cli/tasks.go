// `dbounce tasks review TASK_ID` — post-task review of decisions
// recorded during a task window.
//
// MED-D8-10 (AUDIT-WB-DSLICES-1-8.md) closure: the store's
// TaskReviewSummary helper was implemented for D-Slice 3 but never
// wired into any CLI surface. Without a consumer, the pause-demoted-
// allow miscount the audit doc flagged stayed latent. Wiring this
// subcommand + surfacing the new PauseDemotedCount + PauseDemotedCalls
// fields lands both halves of the fix together per
// [[deliberate-feature-completion]].
//
// Subcommands:
//
//	dbounce tasks review TASK_ID         — text summary
//	dbounce tasks review TASK_ID --json  — machine-readable JSON
//
// Future subcommands (post-launch): `tasks list`, `tasks end`. Not
// shipped here because the launch story is "an agent or operator
// starts a task → runs SQL → reviews what happened" — review is the
// load-bearing surface; list/end are nice-to-haves that the MCP server
// already exposes (dbounce_list_tasks / dbounce_end_task) for the agent
// path.

package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/store"
)

func newTasksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tasks",
		Short: "Inspect dbounce per-task scopes + post-task review",
		Long: `dbounce per-task scopes layer a task-specific allow/deny set on top
of the global rules + active profile during a known work window.
` + "`dbounce tasks review TASK_ID`" + ` shows what happened inside one
task: total decisions, allows, denies, and (per MED-D8-10) the
pause-demoted-ALLOW count — decisions the rule engine wanted to DENY
but an operator pause window demoted to ALLOW.

The pause-demoted set is the post-incident "what slipped through
while I was paused?" view; reviewers should ALWAYS check it before
calling a task green.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("tasks", cmd)
	cmd.AddCommand(newTasksReviewCmd())
	return cmd
}

func newTasksReviewCmd() *cobra.Command {
	var (
		dbPath string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "review TASK_ID",
		Short: "Show the post-task review summary",
		Long: `Reports allow / deny / pause-demoted-allow counts for the named
task, plus the full lists of denied + pause-demoted calls (capped
at 1000 each). The pause-demoted list shows what the rule engine
WOULD have denied had the operator's pause window not been active —
critical for post-incident review.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			taskID := args[0]
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			review, err := st.TaskReviewSummary(taskID)
			if err != nil {
				return err
			}
			if review == nil {
				return fmt.Errorf("no task with id %q", taskID)
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(taskReviewToMap(review))
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "task %s  status=%s  owner=%q\n",
				review.TaskID, review.Status, review.Owner)
			fmt.Fprintf(w, "description : %s\n", review.Description)
			fmt.Fprintf(w, "started_at  : %s\n", review.StartedAt)
			fmt.Fprintf(w, "expires_at  : %s\n", review.ExpiresAt)
			if review.EndedAt != "" {
				fmt.Fprintf(w, "ended_at    : %s  (reason=%s)\n",
					review.EndedAt, review.EndReason)
			}
			fmt.Fprintln(w, "")
			fmt.Fprintf(w, "decisions          : %d\n", review.DecisionCount)
			fmt.Fprintf(w, "  allowed          : %d\n", review.AllowCount)
			fmt.Fprintf(w, "  denied           : %d\n", review.DenyCount)
			// MED-D8-10: surface the pause-demoted subset distinctly.
			// "of which pause-demoted: N" sits under allowed because the
			// persisted verdict was ALLOW, but the count is the
			// post-incident review signal an operator MUST read.
			fmt.Fprintf(w, "  of which pause-demoted: %d  (rule engine wanted DENY; pause window allowed)\n",
				review.PauseDemotedCount)
			if review.FirstDecisionAt != "" {
				fmt.Fprintf(w, "first_decision_at  : %s\n", review.FirstDecisionAt)
				fmt.Fprintf(w, "last_decision_at   : %s\n", review.LastDecisionAt)
			}
			if len(review.DeniedCalls) > 0 {
				fmt.Fprintln(w, "")
				fmt.Fprintf(w, "denied calls (%d):\n", len(review.DeniedCalls))
				for _, c := range review.DeniedCalls {
					fmt.Fprintf(w, "  %s  %-12s  %v  %s\n",
						c.At, c.StatementType, c.Tables, c.Reason)
				}
			}
			if len(review.PauseDemotedCalls) > 0 {
				fmt.Fprintln(w, "")
				fmt.Fprintf(w, "pause-demoted calls (%d) — rule engine wanted DENY:\n",
					len(review.PauseDemotedCalls))
				for _, c := range review.PauseDemotedCalls {
					fmt.Fprintf(w, "  %s  %-12s  %v  %s\n",
						c.At, c.StatementType, c.Tables, c.Reason)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit a single JSON object containing the full review.")
	return cmd
}

func taskReviewToMap(r *store.TaskReview) map[string]any {
	return map[string]any{
		"task_id":              r.TaskID,
		"description":          r.Description,
		"status":               r.Status,
		"started_at":           r.StartedAt,
		"expires_at":           r.ExpiresAt,
		"ended_at":             r.EndedAt,
		"end_reason":           r.EndReason,
		"owner":                r.Owner,
		"decision_count":       r.DecisionCount,
		"allow_count":          r.AllowCount,
		"deny_count":           r.DenyCount,
		"pause_demoted_count":  r.PauseDemotedCount,
		"first_decision_at":    r.FirstDecisionAt,
		"last_decision_at":     r.LastDecisionAt,
		"denied_calls":         taskDeniedCallsToMaps(r.DeniedCalls),
		"pause_demoted_calls":  taskDeniedCallsToMaps(r.PauseDemotedCalls),
	}
}

func taskDeniedCallsToMaps(cs []store.TaskDeniedCall) []map[string]any {
	out := make([]map[string]any, 0, len(cs))
	for _, c := range cs {
		out = append(out, map[string]any{
			"at":             c.At,
			"statement_type": c.StatementType,
			"tables":         c.Tables,
			"reason":         c.Reason,
		})
	}
	return out
}

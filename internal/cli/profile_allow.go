// profile_allow.go — `dbounce profile allow` + `dbounce denies recent`
// CLI commands per #387 / §A25 Phase 2.
//
// Mirrors the iam-jit Python CLI shape + the kbouncer #386 sibling
// per [[cross-product-agent-parity]]. The profile-allow command
// dispatches into internal/profileallow.AddProfileAllowRule; the
// denies-recent command dispatches into RecentDenies.

package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/profileallow"
	"github.com/trsreagan3/dbounce/internal/store"
)

// addProfileAllowCmd is invoked from newProfileCmd() to add the
// `dbounce profile allow` subcommand. Exposed as a named helper so
// the existing newProfileCmd doesn't need a long edit.
func newProfileAllowCmd() *cobra.Command {
	var (
		target       string
		actions      []string
		reason       string
		duration     string
		profileName  string
		profilesPath string
		dbPath       string
		jsonOut      bool
	)
	cmd := &cobra.Command{
		Use:   "allow",
		Short: "Add an allow rule to a dbounce profile (operator easy-allow)",
		Long: `Append a profile allow rule with provenance metadata.

  dbounce profile allow --target '*.staging.internal' \
    --action 'SELECT:public.users' \
    --reason "agent reads staging users table"

Refuses --target '*' (force operator specificity) + actions without
a ':' separator. Refuses to mutate org-distributed profiles
(operators create a local override profile to layer on top).

The provenance note format is:
  [easy_allow] <reason> -- by=<actor> via=cli [duration=... | expires=...]

Mirrors the iam-jit Python + kbouncer CLI surface 1:1 per
[[cross-product-agent-parity]].`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			emitFn := newCLIAuditEmitter(dbPath)
			res, err := profileallow.AddProfileAllowRule(profileallow.Options{
				Target:       target,
				Actions:      actions,
				Reason:       reason,
				Duration:     duration,
				ProfileName:  profileName,
				ProfilesPath: profilesPath,
				Source:       profileallow.SourceCLI,
				EmitAudit:    emitFn,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(res)
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"dbounce: %s allow rule(s) appended to profile %q (now %d rule(s))\n"+
					"  target  : %s\n"+
					"  actions : %s\n"+
					"  reason  : %s\n"+
					"  written : %s\n",
				res.Status, res.ProfileName, res.RuleCountAfter,
				res.Target, strings.Join(res.Actions, ", "),
				res.Reason, res.ProfilePath)
			if res.ExpiresAt != "" {
				fmt.Fprintf(cmd.OutOrStdout(),
					"  expires : %s (advisory metadata)\n", res.ExpiresAt)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "",
		"Target pattern to allow (e.g. '*.staging.internal'). '*' is refused.")
	cmd.Flags().StringSliceVar(&actions, "action", nil,
		"One or more 'verb:resource' strings (repeat to pass multiple).")
	cmd.Flags().StringVar(&reason, "reason", "",
		"Operator-supplied explanation.")
	cmd.Flags().StringVar(&duration, "duration", "",
		"Optional Go-style duration; empty/'permanent' = permanent.")
	cmd.Flags().StringVar(&profileName, "profile", "",
		"Profile to mutate (default: active profile).")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.dbounce/profiles.yaml).")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"Path to dbounce state.db (for the admin-action audit row).")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON.")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("action")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}

// newDeniesCmd / newDeniesRecentCmd implement
// `dbounce denies recent`.
func newDeniesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "denies",
		Short: "Inspect recent DENY decisions",
		Args:  cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("denies", cmd)
	cmd.AddCommand(newDeniesRecentCmd())
	return cmd
}

func newDeniesRecentCmd() *cobra.Command {
	var (
		dbPath         string
		since          string
		limit          int
		jsonOut        bool
		agentSessionID string
	)
	cmd := &cobra.Command{
		Use:   "recent",
		Short: "List recent DENY decisions from the local audit store",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dbPath == "" {
				p, err := store.DefaultDBPath()
				if err != nil {
					return err
				}
				dbPath = p
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("dbounce: open store at %s: %w", dbPath, err)
			}
			defer st.Close()
			lower, perr := parseSinceFlag(since)
			if perr != nil {
				return perr
			}
			rows, err := profileallow.RecentDenies(profileallow.RecentDeniesOptions{
				Store:          st,
				Since:          lower,
				AgentSessionID: agentSessionID,
				Limit:          limit,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "dbounce: no recent denies")
				return nil
			}
			for _, r := range rows {
				fmt.Fprintf(cmd.OutOrStdout(),
					"%s  action=%s  resource=%s  source=%s  reason=%s\n  suggested: %s\n",
					r.When, r.Action, r.Resource, r.DenySource, r.DenyReason, r.SuggestedAllowCommand)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"Path to dbounce SQLite store (default: ~/.dbounce/state.db).")
	cmd.Flags().StringVar(&since, "since", "5m", "Lower bound (5m / 1h / 1d / ISO).")
	cmd.Flags().IntVar(&limit, "limit", 50, "Max rows.")
	cmd.Flags().StringVar(&agentSessionID, "agent-session", "", "Filter to one MCP session.")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON.")
	return cmd
}

// newCLIAuditEmitter returns a profileallow.EmitAuditFn that
// enqueues an ADMIN_ACTION pending audit event via the dbounce
// pending_audit_events queue. Best-effort: an enqueue failure
// surfaces to stderr but doesn't fail the user-facing command
// (matches the existing enqueueAdminAction shape).
func newCLIAuditEmitter(dbPath string) profileallow.EmitAuditFn {
	return func(ev profileallow.AuditEvent) {
		enqueueAdminAction(nil /* errOut */, dbPath, adminActionEnqueueParams{
			Action:       ev.Action,
			Actor:        ev.Actor,
			ResourceType: ev.EntityKind,
			ResourceID:   ev.EntityName,
			Result:       "success",
			Details:      ev.Details,
		})
	}
}

// parseSinceFlag mirrors the kbouncer helper of the same name.
func parseSinceFlag(spec string) (time.Time, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return time.Time{}, nil
	}
	if strings.Contains(s, "T") || (len(s) >= 10 && s[4] == '-') {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}, fmt.Errorf("dbounce: --since %q: %w", spec, err)
		}
		return t, nil
	}
	if len(s) < 2 {
		return time.Time{}, fmt.Errorf("dbounce: --since %q: too short", spec)
	}
	unit := s[len(s)-1]
	qty, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return time.Time{}, fmt.Errorf("dbounce: --since %q: %w", spec, err)
	}
	var d time.Duration
	switch unit {
	case 's':
		d = time.Duration(qty) * time.Second
	case 'm':
		d = time.Duration(qty) * time.Minute
	case 'h':
		d = time.Duration(qty) * time.Hour
	case 'd':
		d = time.Duration(qty) * 24 * time.Hour
	case 'w':
		d = time.Duration(qty) * 7 * 24 * time.Hour
	default:
		return time.Time{}, fmt.Errorf("dbounce: --since %q: unknown unit %q", spec, string(unit))
	}
	return time.Now().UTC().Add(-d), nil
}

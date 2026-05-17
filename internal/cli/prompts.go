// `dbounce prompts list | show | answer` (D-Slice 8).
//
// Async deny-prompt UX: when the proxy is in transparent mode with
// --prompt-on-deny enabled, every DENY enqueues a pending_prompts row
// (without blocking the wire-protocol call — the SQL client would time
// out long before the human gets to the terminal). This subcommand
// drains the queue:
//
//	dbounce prompts list                        # what's pending?
//	dbounce prompts show ID                     # full context for one
//	dbounce prompts answer ID --kind ignore
//	dbounce prompts answer ID --kind always
//	dbounce prompts answer ID --kind profile --target [NAME]
//
// `--kind ignore` records a decision; no rule/profile change.
// `--kind always` appends a global ALLOW rule for the same shape so
// future requests don't enqueue another prompt.
// `--kind profile --target [NAME]` creates a profile from the prompt
// (auto-named per [[profile-auto-naming]] when NAME absent). The
// actual profile package lives in D-Slice 7; this file injects a
// ProfileWriter interface at command-construction time so the merge
// can land D-Slice 7's writer behind the interface without touching
// this file.
package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/naming"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

// ProfileWriter is the minimal contract `prompts answer --kind profile`
// needs from D-Slice 7's profile package. Defining it here keeps this
// branch independent of D-Slice 7's package layout; at merge time
// D-Slice 7 provides a struct that satisfies the interface and the
// CLI wiring switches from a stub to the real impl with no API change
// here.
//
// CreateProfile semantics: persist a NEW profile named `name` carrying
// the given allow/deny rules. The store layer enforces uniqueness +
// schema validation. ExistingProfileNames lists current profile names
// so the auto-naming primitive's collision-avoidance can run before
// the create attempt (avoids a round-trip on the common case).
//
// Both methods may return errors; the CLI surfaces them.
type ProfileWriter interface {
	CreateProfile(name, description string,
		allow []dbrules.ProxyRule, deny []dbrules.ProxyRule) error
	ExistingProfileNames() (map[string]struct{}, error)
}

// stubProfileWriter is the default ProfileWriter the CLI uses when no
// real writer is injected (the typical D-Slice 8 standalone test
// path). Surfaces a clear error rather than silently no-op'ing — the
// operator should know `--kind profile` requires the profile package
// (which lands in D-Slice 7).
type stubProfileWriter struct{}

func (stubProfileWriter) CreateProfile(string, string, []dbrules.ProxyRule, []dbrules.ProxyRule) error {
	return errors.New("dbounce: profile creation requires the D-Slice 7 profile package (not wired in this build)")
}
func (stubProfileWriter) ExistingProfileNames() (map[string]struct{}, error) {
	return map[string]struct{}{}, nil
}

func newPromptsCmd(profileWriter ProfileWriter) *cobra.Command {
	if profileWriter == nil {
		profileWriter = stubProfileWriter{}
	}
	cmd := &cobra.Command{
		Use:   "prompts",
		Short: "Review async deny-prompts queued by --prompt-on-deny",
		Long: `When the proxy runs with --prompt-on-deny enabled, every
transparent-mode DENY enqueues a row in pending_prompts. Run
'dbounce prompts list' to see what's waiting, 'dbounce prompts show
ID' to inspect one in detail, and 'dbounce prompts answer ID --kind
...' to record your decision.

Answer kinds:
  ignore   — record the decision; no rule/profile change.
  always   — append a global ALLOW rule covering the same shape so
              future requests of this pattern don't re-enqueue.
  profile  — create a NEW profile carrying an allow rule for the
              prompt's statement_type + tables. Auto-named per
              [[profile-auto-naming]] when --target is absent.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("prompts", cmd)
	cmd.AddCommand(newPromptsListCmd())
	cmd.AddCommand(newPromptsShowCmd())
	cmd.AddCommand(newPromptsAnswerCmd(profileWriter))
	return cmd
}

func newPromptsListCmd() *cobra.Command {
	var (
		dbPath string
		status string
		limit  int
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List pending prompts (newest first)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 1 || limit > 500 {
				return fmt.Errorf("--limit must be in 1-500 (got %d)", limit)
			}
			if status != "" && status != "pending" && status != "answered" && status != "ignored" {
				return fmt.Errorf(
					"--status must be 'pending', 'answered', 'ignored', or empty (got %q)", status)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			rows, err := st.ListPendingPrompts(store.PromptStatus(status), limit)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				for _, r := range rows {
					if err := enc.Encode(promptToMap(r)); err != nil {
						return err
					}
				}
				return nil
			}
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no prompts)")
				return nil
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-4s  %-20s  %-9s  %-12s  %-30s  %s\n",
				"ID", "CREATED-AT", "STATUS", "STMT-TYPE", "TABLES", "DENY-REASON")
			for _, r := range rows {
				tables := strings.Join(r.TablesTouched, ",")
				if len(tables) > 28 {
					tables = tables[:25] + "..."
				}
				reason := r.DenyReason
				if len(reason) > 60 {
					reason = reason[:57] + "..."
				}
				fmt.Fprintf(w, "%-4d  %-20s  %-9s  %-12s  %-30s  %s\n",
					r.ID, r.CreatedAt, r.Status, r.StatementType, tables, reason)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().StringVar(&status, "status", "pending",
		"Filter by status: pending | answered | ignored | '' (all).")
	cmd.Flags().IntVar(&limit, "limit", 50,
		"Max rows to return (1-500). Default 50.")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit one JSON object per prompt, newest first.")
	return cmd
}

func newPromptsShowCmd() *cobra.Command {
	var (
		dbPath string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "show ID",
		Short: "Show the full context of one prompt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("prompt id must be a positive integer (got %q)", args[0])
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			p, err := st.GetPendingPrompt(id)
			if err != nil {
				return err
			}
			if p == nil {
				return fmt.Errorf("no prompt with id %d", id)
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(promptToMap(*p))
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "prompt %d  status=%s  created_at=%s\n",
				p.ID, p.Status, p.CreatedAt)
			fmt.Fprintf(w, "decision_id   : %d\n", p.DecisionID)
			fmt.Fprintf(w, "statement_type: %s\n", p.StatementType)
			fmt.Fprintf(w, "tables        : %s\n", strings.Join(p.TablesTouched, ","))
			fmt.Fprintf(w, "functions     : %s\n", strings.Join(p.FunctionsCalled, ","))
			fmt.Fprintf(w, "deny_reason   : %s\n", p.DenyReason)
			if p.Status != store.PromptPending {
				fmt.Fprintf(w, "answer_kind   : %s\n", p.AnswerKind)
				fmt.Fprintf(w, "answer_target : %s\n", p.AnswerTarget)
				fmt.Fprintf(w, "answered_by   : %s\n", p.AnsweredBy)
				fmt.Fprintf(w, "answered_at   : %s\n", p.AnsweredAt)
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

func newPromptsAnswerCmd(profileWriter ProfileWriter) *cobra.Command {
	if profileWriter == nil {
		profileWriter = stubProfileWriter{}
	}
	var (
		dbPath string
		kind   string
		target string
		actor  string
		// targetSet tracks whether --target was passed at all (cobra
		// can't distinguish "absent" from "passed empty"). pflag's
		// Changed() does, but only AFTER parse — use NoOptDefVal so
		// `--target` with no value sets target=""; `--target=foo` sets
		// it to "foo". Then Changed() tells us absent-vs-present.
		_ = "force gofmt to leave the comment block intact"
	)
	cmd := &cobra.Command{
		Use:   "answer ID",
		Short: "Answer a pending prompt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("prompt id must be a positive integer (got %q)", args[0])
			}
			switch kind {
			case "ignore", "always", "profile":
				// OK
			default:
				return fmt.Errorf(
					"--kind must be one of ignore|always|profile (got %q)", kind)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			p, err := st.GetPendingPrompt(id)
			if err != nil {
				return err
			}
			if p == nil {
				return fmt.Errorf("no prompt with id %d", id)
			}
			if p.Status != store.PromptPending {
				return fmt.Errorf("prompt %d is already %s; cannot re-answer", id, p.Status)
			}

			by := resolveActor(actor)
			targetSet := cmd.Flags().Changed("target")

			switch kind {
			case "ignore":
				if _, err := st.AnswerPendingPrompt(id, "ignore", "", by); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"prompt %d ignored by %s.\n", id, by)
				return nil

			case "always":
				// Append a global ALLOW rule covering the prompt's
				// statement_type + the first touched table (broad table
				// match if none). The operator can edit the rule later
				// via `dbounce rules remove` + `rules add`.
				patternTable := "*"
				if len(p.TablesTouched) > 0 {
					patternTable = p.TablesTouched[0]
				}
				stmtType := p.StatementType
				if stmtType == "" {
					stmtType = "*"
				}
				pattern := fmt.Sprintf("%s:%s", stmtType, patternTable)
				note := fmt.Sprintf("from prompt %d", id)
				ruleID, err := st.AddRule(dbrules.ProxyRule{
					Pattern: pattern, Effect: dbrules.EffectAllow,
					Origin: dbrules.OriginUser, Note: note,
				})
				if err != nil {
					return fmt.Errorf("add rule from prompt: %w", err)
				}
				if _, err := st.AnswerPendingPrompt(id, "always", pattern, by); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"prompt %d answered with 'always'; added rule %d (pattern=%s)\n",
					id, ruleID, pattern)
				return nil

			case "profile":
				existing, perr := profileWriter.ExistingProfileNames()
				if perr != nil {
					return fmt.Errorf("list profile names: %w", perr)
				}
				detail := promptDetailSlug(*p)
				ctx := naming.Context{
					Kind:   "prompt",
					Detail: fmt.Sprintf("%d-%s", id, detail),
					Now:    naming.SystemClock,
				}
				isTTY := isatty.IsTerminal(os.Stdin.Fd())
				// targetSet=false (flag absent): use the auto-name
				// outright on non-TTY; let the prompt-loop fire on TTY.
				// targetSet=true (flag present, value possibly empty):
				// same algorithm — target=="" + TTY prompts; target=="" +
				// non-TTY uses auto-name; non-empty target wins.
				argVal := ""
				if targetSet {
					argVal = target
					if argVal == "__AUTO__" {
						// Bare `--target` (no =VALUE) — caller asked
						// for the auto-name explicitly.
						argVal = ""
					}
				}
				// TTY-prompt only when --target was passed without a
				// value (sentinel stripped to "") AND interactive.
				resolved, wantPrompt, suggestion := naming.ResolveProfileName(argVal, ctx, isTTY && targetSet && argVal == "", existing)
				if wantPrompt {
					// Interactive readline with `suggestion` as default.
					fmt.Fprintf(cmd.ErrOrStderr(),
						"name for new profile [default: %s]: ", suggestion)
					reader := bufio.NewReader(os.Stdin)
					line, _ := reader.ReadString('\n')
					line = strings.TrimSpace(line)
					if line == "" {
						resolved = suggestion
					} else {
						resolved, _, _ = naming.ResolveProfileName(line, ctx, false, existing)
					}
				}
				if resolved == "" {
					// Defensive: ResolveProfileName guarantees a value
					// unless wantPrompt is true; surface a clear error
					// rather than silently create an empty-named profile.
					return errors.New("could not resolve profile name")
				}
				if !targetSet && !isTTY {
					// Non-TTY + flag absent: be explicit about what we
					// chose so the operator sees it in CI/logs.
					fmt.Fprintf(cmd.ErrOrStderr(),
						"using auto-name %q (no --target given; non-interactive)\n", resolved)
				}
				patternTable := "*"
				if len(p.TablesTouched) > 0 {
					patternTable = p.TablesTouched[0]
				}
				stmtType := p.StatementType
				if stmtType == "" {
					stmtType = "*"
				}
				rule := dbrules.ProxyRule{
					Pattern: fmt.Sprintf("%s:%s", stmtType, patternTable),
					Effect:  dbrules.EffectAllow,
					Origin:  dbrules.OriginRecommended,
					Note:    fmt.Sprintf("from prompt %d", id),
				}
				desc := fmt.Sprintf("profile created from prompt %d (statement_type=%s, tables=%v)",
					id, p.StatementType, p.TablesTouched)
				if err := profileWriter.CreateProfile(resolved, desc,
					[]dbrules.ProxyRule{rule}, nil); err != nil {
					return fmt.Errorf("create profile: %w", err)
				}
				if _, err := st.AnswerPendingPrompt(id, "profile", resolved, by); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"prompt %d answered with 'profile'; created profile %q.\n",
					id, resolved)
				return nil
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().StringVar(&kind, "kind", "",
		"ignore | always | profile. Required.")
	cmd.Flags().StringVar(&target, "target", "",
		"For --kind profile: profile name. Use --target=NAME for an "+
			"explicit name, or bare --target (no value) for the "+
			"[[profile-auto-naming]] auto-name; on a TTY you'll be "+
			"prompted with the auto-name as the default. The =NAME form "+
			"is required because bare --target alone is the auto-name "+
			"sentinel (NoOptDefVal semantics).")
	// NoOptDefVal sentinel: bare `--target` parses to __AUTO__ which
	// RunE strips before resolving. pflag refuses empty NoOptDefVal.
	cmd.Flag("target").NoOptDefVal = "__AUTO__"
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id recorded as answered_by. Defaults to $USER then 'unknown'.")
	_ = cmd.MarkFlagRequired("kind")
	return cmd
}

func promptDetailSlug(p store.PendingPrompt) string {
	parts := []string{}
	if p.StatementType != "" {
		parts = append(parts, strings.ToLower(p.StatementType))
	}
	if len(p.TablesTouched) > 0 {
		parts = append(parts, p.TablesTouched[0])
	}
	if len(parts) == 0 {
		return "unspecified"
	}
	return strings.Join(parts, "-")
}

func promptToMap(p store.PendingPrompt) map[string]any {
	return map[string]any{
		"id":               p.ID,
		"created_at":       p.CreatedAt,
		"decision_id":      p.DecisionID,
		"statement_type":   p.StatementType,
		"tables":           p.TablesTouched,
		"functions":        p.FunctionsCalled,
		"deny_reason":      p.DenyReason,
		"status":           string(p.Status),
		"answer_kind":      p.AnswerKind,
		"answer_target":    p.AnswerTarget,
		"answered_by":      p.AnsweredBy,
		"answered_at":      p.AnsweredAt,
	}
}

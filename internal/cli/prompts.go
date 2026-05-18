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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/naming"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

// stubProfileWriter (formerly in this file) was removed per INFO-D8-14
// (AUDIT-WB-DSLICES-1-8.md). With #245's profileWriterAdapter wiring
// landed in the root command, ProfileWriter is non-nullable across all
// production code paths — the stub's error message ("not configured")
// would never reach an operator at runtime and was misleading when it
// did fire in tests. Tests now pass a real ProfileWriter (the
// recordingProfileWriter test double in prompts_test.go); newPromptsCmd
// + newPresetsCmd + newRulesCmd + newRulesRecommendCmd panic on nil so
// any future caller forgetting to wire one fails loudly at construction
// time, NOT at the next operator-visible CLI invocation.

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

func newPromptsCmd(profileWriter ProfileWriter) *cobra.Command {
	if profileWriter == nil {
		// INFO-D8-14: ProfileWriter is non-nullable. A nil writer means
		// a wiring bug at construction time — fail loudly here so the
		// regression is caught before any operator runs the binary.
		panic("dbounce cli: newPromptsCmd requires a non-nil ProfileWriter (INFO-D8-14)")
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
	cmd.AddCommand(newPromptsBulkPendingCmd())
	cmd.AddCommand(newPromptsBulkAnswerCmd())
	return cmd
}

// bulkAnswerDecision is the operator's bulk-answer choice per
// [[bulk-prompt-answer-ux]]. Mirrors the cross-product option labels
// shared with ibounce / kbounce so an operator who learned one tool
// surface understands the other.
type bulkAnswerDecision string

const (
	bulkDecisionProfile  bulkAnswerDecision = "profile"
	bulkDecisionSession  bulkAnswerDecision = "session"
	bulkDecision3h       bulkAnswerDecision = "3h"
	bulkDecision10min    bulkAnswerDecision = "10min"
	bulkDecisionNone     bulkAnswerDecision = "none"
)

// bulkDecisionTTL returns the time-bounded rule duration for the
// time-bound decisions. "session" is treated as 60 minutes per the
// memo's pragmatic definition ("session" = until proxy restart OR
// 60min of inactivity). Returns (0, ok=false) for non-time-bound
// decisions (profile + none).
func bulkDecisionTTL(d bulkAnswerDecision) (time.Duration, bool) {
	switch d {
	case bulkDecision10min:
		return 10 * time.Minute, true
	case bulkDecision3h:
		return 3 * time.Hour, true
	case bulkDecisionSession:
		// Pragmatic "session" per the memo: 60 minutes. The proxy-
		// restart half is enforced naturally — rules persist in
		// SQLite, but the in-memory burst state resets, so a new
		// process starts with a clean slate.
		return 60 * time.Minute, true
	}
	return 0, false
}

// newPromptsBulkPendingCmd implements `dbounce prompts bulk-pending`.
// Read-only: prints the burst summary (the (dialect, statement_type,
// table) tuples that would be covered by a bulk-answer) so the
// operator can preview before answering.
func newPromptsBulkPendingCmd() *cobra.Command {
	var (
		dbPath string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "bulk-pending",
		Short: "Show the burst summary: pending prompts grouped per (dialect, statement_type, table)",
		Long: `Print a one-shot summary of pending prompts grouped by
the (dialect, statement_type, table) tuple ` + "`prompts bulk-answer`" + `
would synthesize a rule for. Useful to preview which rules would be
created before running ` + "`prompts bulk-answer --decision {10min|3h|session}`" + `.

Per-dialect grouping: when a burst spans multiple dialects (e.g. an
agent that hits a PG db AND a MySQL db), the summary shows the tuple
counts per-dialect — and ` + "`bulk-answer`" + ` synthesizes one rule per
dialect to match. A bulk-allow rule for PG never spills into MySQL
traffic, and vice versa.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			summary, err := st.ListBulkPendingPrompts()
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(bulkSummaryToMap(summary))
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "burst summary: %d pending prompt(s) across %d entry/entries (%d dialect[s]: %s)\n",
				summary.TotalPrompts, len(summary.Entries), len(summary.Dialects),
				strings.Join(summary.Dialects, ","))
			if summary.TotalPrompts == 0 {
				fmt.Fprintln(w, "(no pending prompts)")
				return nil
			}
			fmt.Fprintf(w, "\n%-10s  %-14s  %-30s  %-6s  %s\n",
				"DIALECT", "STMT-TYPE", "TABLE", "COUNT", "SAMPLE-REASON")
			for _, e := range summary.Entries {
				reason := e.SampleReason
				if len(reason) > 60 {
					reason = reason[:57] + "..."
				}
				fmt.Fprintf(w, "%-10s  %-14s  %-30s  %-6d  %s\n",
					e.Key.Dialect, e.Key.StatementType, e.Key.Table,
					len(e.PromptIDs), reason)
			}
			fmt.Fprintf(w, "\nNext: `dbounce prompts bulk-answer --decision {10min|3h|session|profile|none}`\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit machine-readable JSON.")
	return cmd
}

// newPromptsBulkAnswerCmd implements `dbounce prompts bulk-answer`.
//
// Applies ONE decision across every currently-pending prompt:
//
//   --decision 10min     time-bounded ALLOW rules; expire in 10min
//   --decision 3h        time-bounded ALLOW rules; expire in 3h
//   --decision session   time-bounded ALLOW rules; ~60min pragmatic
//                        "session" definition per [[bulk-prompt-answer-ux]]
//   --decision profile   hot-swap to --profile NAME via the
//                        profile_overrides single-row table; the
//                        running proxy's burst sweeper picks it up
//                        within ~5s
//   --decision none      no-op; operator wants to drain the queue
//                        one-by-one (existing flow)
//
// Per-dialect rule synthesis: when the burst spans multiple dialects,
// one rule is created PER (dialect-aware) entry — see
// bulk-prompt-answer-ux memo, "Per-dialect scope sensitivity."
func newPromptsBulkAnswerCmd() *cobra.Command {
	var (
		dbPath      string
		decisionStr string
		profileName string
		actor       string
		assumeYes   bool
	)
	cmd := &cobra.Command{
		Use:   "bulk-answer",
		Short: "Resolve all currently-pending prompts en masse (per [[bulk-prompt-answer-ux]])",
		Long: `Resolve every currently-pending prompt with one decision.

This is the operator-friendly escape hatch from "wall of per-call
prompts" — when the agent has triggered many denies in a short window
(typically because the wrong profile is active, or the work is
exploratory), the bulk-answer surfaces lets you pick:

  --decision 10min     time-bounded ALLOW rules covering the burst;
                       expire in 10min (narrow blanket allow)
  --decision 3h        same shape; 3h TTL (typical work session)
  --decision session   ~60min pragmatic session definition; expires
                       when --decision session is set + the proxy
                       restart implicitly clears in-memory state
  --decision profile   hot-swap the running proxy's active profile
                       (pair with --profile NAME). The running proxy's
                       burst sweeper picks up the override within ~5s
                       and swaps without restart.
  --decision none      no-op — leave prompts pending so you can drain
                       them one-by-one via 'prompts answer ID'

Per-dialect rule synthesis: when the burst spans multiple SQL
dialects (a Postgres + MySQL agent), one ALLOW rule is created PER
(dialect-aware) tuple so a PG rule never spills into MySQL traffic.
See ` + "`dbounce prompts bulk-pending`" + ` to preview.

Time-bounded rules are persisted with an expires_at column; the proxy
filters them out of LoadRuleSet once expired + the burst sweeper
reaps them lazily. The decisions table preserves the full audit
chain (decisions.matched_rule_id stamps the rule id at decision
time) so a reviewer can still answer "what did the 10-min bulk-allow
let through?" after the rule has expired.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			decision := bulkAnswerDecision(strings.ToLower(strings.TrimSpace(decisionStr)))
			switch decision {
			case bulkDecisionProfile, bulkDecisionSession, bulkDecision3h, bulkDecision10min, bulkDecisionNone:
				// OK
			default:
				return fmt.Errorf("--decision must be one of "+
					"profile|session|3h|10min|none (got %q)", decisionStr)
			}
			if decision == bulkDecisionProfile && profileName == "" {
				return errors.New("--decision profile requires --profile NAME")
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			summary, err := st.ListBulkPendingPrompts()
			if err != nil {
				return err
			}
			if summary.TotalPrompts == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no pending prompts; nothing to do.")
				return nil
			}
			by := resolveActor(actor)
			w := cmd.OutOrStdout()

			if decision == bulkDecisionNone {
				fmt.Fprintf(w, "bulk-answer: leaving %d prompt(s) pending (--decision none); no changes made.\n",
					summary.TotalPrompts)
				return nil
			}

			// Preview + confirmation gate for time-bound rule synthesis.
			ttl, isTimeBound := bulkDecisionTTL(decision)
			if isTimeBound {
				fmt.Fprintf(w, "bulk-answer: will create %d ALLOW rule(s) (TTL=%s) covering %d pending prompt(s) across dialects %s:\n",
					len(summary.Entries), ttl, summary.TotalPrompts,
					strings.Join(summary.Dialects, ","))
				for _, e := range summary.Entries {
					fmt.Fprintf(w, "  - [%s] %s:%s (count=%d)\n",
						e.Key.Dialect, e.Key.StatementType, e.Key.Table, len(e.PromptIDs))
				}
			} else { // profile
				fmt.Fprintf(w, "bulk-answer: will request hot-swap to profile %q + mark %d pending prompt(s) as answered.\n",
					profileName, summary.TotalPrompts)
			}
			if !assumeYes {
				if !confirmYesNoTTY(cmd, "Proceed? [y/N]: ") {
					fmt.Fprintln(w, "aborted.")
					return nil
				}
			}

			// Apply.
			switch decision {
			case bulkDecision10min, bulkDecision3h, bulkDecisionSession:
				return applyBulkTimeBound(cmd, st, summary, ttl, decision, by)
			case bulkDecisionProfile:
				return applyBulkProfileSwap(cmd, st, summary, profileName, by)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().StringVar(&decisionStr, "decision", "",
		"profile | session | 3h | 10min | none. Required.")
	cmd.Flags().StringVar(&profileName, "profile", "",
		"For --decision profile: name of the profile to hot-swap to.")
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id recorded as answered_by + set_by. Defaults to $USER then 'unknown'.")
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false,
		"Skip the interactive confirmation prompt.")
	_ = cmd.MarkFlagRequired("decision")
	return cmd
}

// applyBulkTimeBound creates per-(dialect, statement_type, table)
// ALLOW rules with the given TTL + marks every pending prompt
// answered + wakes any sync-waiters with PromptDecisionAllow.
// Per-dialect: each entry produces its OWN rule so a PG rule never
// spills into MySQL traffic + vice versa.
func applyBulkTimeBound(cmd *cobra.Command, st *store.Store,
	summary *store.BulkPendingSummary, ttl time.Duration,
	decision bulkAnswerDecision, by string) error {

	w := cmd.OutOrStdout()
	expiresAt := time.Now().UTC().Add(ttl)
	totalPromptIDs := make([]int64, 0, summary.TotalPrompts)
	createdRules := 0
	for _, e := range summary.Entries {
		pattern := fmt.Sprintf("%s:%s", e.Key.StatementType, e.Key.Table)
		note := fmt.Sprintf("bulk-answer %s (decision=%s, dialect=%s, prompts=%d, expires_at=%s)",
			by, decision, e.Key.Dialect, len(e.PromptIDs),
			expiresAt.Format("2006-01-02T15:04:05Z"))
		// SchemaScope is unused (table_glob carries the schema half).
		// FunctionScope is unused (the burst summary buckets by
		// statement_type + table only; the operator can narrow later
		// via `dbounce rules add`).
		//
		// Per-dialect note: dbounce v1.0's rules table has NO dialect
		// column — the rule applies to any decision matching the
		// pattern regardless of dialect. Per [[bulk-prompt-answer-ux]]
		// per-dialect parity: we encode dialect into the rule's NOTE
		// so audit reviewers can answer "why does this PG-shaped rule
		// exist?" without inferring + we create ONE rule PER dialect-
		// aware bucket. A multi-dialect burst that spans PG + MySQL
		// creates separate rules with notes naming each origin. (A
		// future v1.1 dialect column would let the proxy gate
		// per-dialect; for now the table-half of the pattern serves
		// as the natural separator — PG's "public.users" is distinct
		// from MySQL's "mydb.users" so cross-dialect bleed is unlikely
		// in practice.)
		rule := dbrules.ProxyRule{
			Pattern: pattern,
			Effect:  dbrules.EffectAllow,
			Origin:  dbrules.OriginUser,
			Note:    note,
		}
		_, err := st.AddRuleWithExpiry(rule, expiresAt)
		if err != nil {
			return fmt.Errorf("add bulk-allow rule (pattern=%q): %w", pattern, err)
		}
		createdRules++
		totalPromptIDs = append(totalPromptIDs, e.PromptIDs...)
	}
	// Dedup prompt IDs (an entry may have appeared in multiple
	// buckets when a prompt touched multiple tables).
	totalPromptIDs = dedupInt64(totalPromptIDs)
	answerKind := "bulk-allow-" + string(decision)
	updated, err := st.AnswerPendingPromptsBulk(totalPromptIDs, answerKind, "", by)
	if err != nil {
		return fmt.Errorf("mark prompts answered: %w", err)
	}
	// Wake any sync-blocked waiters with PromptDecisionAllow.
	waiters, err := st.SyncWaitIDsForPromptIDs(totalPromptIDs)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"dbounce: warning: lookup sync waiters failed: %v\n", err)
	} else {
		for promptID, waitID := range waiters {
			if woke, werr := st.WakeSyncPendingPrompt(waitID, store.PromptDecisionAllow); werr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"dbounce: warning: wake sync prompt %d failed: %v\n", promptID, werr)
			} else if woke {
				fmt.Fprintf(cmd.OutOrStdout(),
					"sync-prompt waiter for prompt %d resumed with allow.\n", promptID)
			}
		}
	}
	fmt.Fprintf(w, "bulk-answer: created %d time-bounded ALLOW rule(s) (TTL=%s), answered %d prompt(s) (%d already answered concurrently).\n",
		createdRules, ttl, updated, int64(len(totalPromptIDs))-updated)
	return nil
}

// applyBulkProfileSwap posts the hot-swap signal to the
// profile_overrides table + marks every pending prompt answered with
// kind="bulk-profile-swap". The proxy's burst sweeper goroutine picks
// up the override within ~5s and calls SwapProfile to take it live.
//
// Sync waiters are woken with PromptDecisionAllow on the theory that
// "if the operator picked a broader profile, they want the existing
// blocked calls to proceed against that profile." Strict alternative
// would be PromptDecisionDeny + force the agent to retry; we pick the
// permissive side per [[safety-mode-lean-permissive]].
func applyBulkProfileSwap(cmd *cobra.Command, st *store.Store,
	summary *store.BulkPendingSummary, profileName, by string) error {

	w := cmd.OutOrStdout()
	if err := st.SetProfileOverride(profileName, by, "bulk-answer profile-swap"); err != nil {
		return fmt.Errorf("set profile override: %w", err)
	}
	totalPromptIDs := make([]int64, 0, summary.TotalPrompts)
	for _, e := range summary.Entries {
		totalPromptIDs = append(totalPromptIDs, e.PromptIDs...)
	}
	totalPromptIDs = dedupInt64(totalPromptIDs)
	answerKind := "bulk-profile-swap"
	updated, err := st.AnswerPendingPromptsBulk(totalPromptIDs, answerKind, profileName, by)
	if err != nil {
		return fmt.Errorf("mark prompts answered: %w", err)
	}
	waiters, err := st.SyncWaitIDsForPromptIDs(totalPromptIDs)
	if err == nil {
		for promptID, waitID := range waiters {
			if woke, werr := st.WakeSyncPendingPrompt(waitID, store.PromptDecisionAllow); werr == nil && woke {
				fmt.Fprintf(cmd.OutOrStdout(),
					"sync-prompt waiter for prompt %d resumed with allow.\n", promptID)
			}
		}
	}
	fmt.Fprintf(w, "bulk-answer: requested hot-swap to profile %q (running proxy picks it up within ~5s); answered %d prompt(s).\n",
		profileName, updated)
	return nil
}

// confirmYesNoTTY prints prompt to stderr and reads one line of
// stdin. Returns true iff the operator typed "y" or "yes" (case-
// insensitive). On non-TTY (CI / pipes) returns false so an
// unattended invocation can't accidentally commit — the operator must
// pass --yes explicitly in non-interactive contexts.
func confirmYesNoTTY(cmd *cobra.Command, prompt string) bool {
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"non-interactive: refusing to bulk-answer without --yes\n")
		return false
	}
	fmt.Fprint(cmd.ErrOrStderr(), prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func dedupInt64(in []int64) []int64 {
	if len(in) < 2 {
		return in
	}
	seen := make(map[int64]struct{}, len(in))
	out := make([]int64, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func bulkSummaryToMap(summary *store.BulkPendingSummary) map[string]any {
	entries := make([]map[string]any, 0, len(summary.Entries))
	for _, e := range summary.Entries {
		entries = append(entries, map[string]any{
			"dialect":        e.Key.Dialect,
			"statement_type": e.Key.StatementType,
			"table":          e.Key.Table,
			"prompt_ids":     append([]int64{}, e.PromptIDs...),
			"count":          len(e.PromptIDs),
			"sample_reason":  e.SampleReason,
		})
	}
	return map[string]any{
		"total_prompts": summary.TotalPrompts,
		"dialects":      summary.Dialects,
		"entries":       entries,
	}
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
		panic("dbounce cli: newPromptsAnswerCmd requires a non-nil ProfileWriter (INFO-D8-14)")
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

			// #203 sync-prompt wakeup helper. Closes over `p` + `st` +
			// `cmd` so each kind branch can fire it after persisting
			// the answer. Kind mapping:
			//   - "ignore"            → PromptDecisionDeny
			//   - "always" / "profile"→ PromptDecisionAllow
			// When the prompt has no SyncWaitID (legacy async-only
			// row), the wake is a no-op + nothing else changes.
			wakeSync := func(decision store.PromptDecision) {
				if p == nil || p.SyncWaitID == "" {
					return
				}
				woke, werr := st.WakeSyncPendingPrompt(p.SyncWaitID, decision)
				if werr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"dbounce: warning: WakeSyncPendingPrompt failed for "+
							"prompt %d (sync_wait_id=%s): %v\n",
						id, p.SyncWaitID, werr)
					return
				}
				if !woke {
					// Waiter already gone — timed out, the proxy
					// goroutine cancelled, or the proxy restarted.
					// The answer still persisted; the SQL client
					// already received its outcome. Informational
					// only.
					fmt.Fprintf(cmd.ErrOrStderr(),
						"dbounce: note: sync prompt %d had no live waiter "+
							"(likely timed out or the proxy restarted); "+
							"answer recorded for audit.\n", id)
					return
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"sync-prompt waiter for prompt %d resumed with %s.\n",
					id, decision)
			}

			switch kind {
			case "ignore":
				if _, err := st.AnswerPendingPrompt(id, "ignore", "", by); err != nil {
					return err
				}
				wakeSync(store.PromptDecisionDeny)
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
				wakeSync(store.PromptDecisionAllow)
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
				wakeSync(store.PromptDecisionAllow)
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

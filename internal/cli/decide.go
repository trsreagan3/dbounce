// `dbounce decide` — dry-run a single SQL statement through dbounce's
// parser + rule engine + active profile, return the verdict, never
// touch the audit log or forward upstream.
//
// D-Slice 6 lands this as the supported invocation path for Snowflake
// + BigQuery, where the wire-protocol-proxy shape isn't viable per
// [[dbounce-build-plan]] §D-Slice 6 + [[v1-scope-bar]]. The customer's
// JDBC-driver shim calls `dbounce decide --dialect snowflake|bigquery`
// (typically via a thin process exec or in-tree library wrapper)
// BEFORE forwarding the SQL to the real driver. The MCP equivalent is
// the dbounce_decide tool — same evaluation path, JSON-RPC transport.
//
// Per [[creates-never-mutates]]: this subcommand reads the on-disk
// store (rules + active task + active pause) and the profiles.yaml,
// but writes NOTHING. The audit log + pending_prompts table stay
// untouched; a deny verdict here does NOT enqueue a prompt (the
// running proxy owns the prompt-on-deny side per D-Slice 8).
//
// Per [[scorer-is-ground-truth]]: snowflake/bigquery verdicts will
// reflect the experimental calibration of those rule packs. Operators
// running these in transparent mode should review packs before relying
// on the verdict shape; the supported v1.0 deployment is cooperative
// mode + audit-log review.

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/decision"
	"github.com/trsreagan3/dbounce/internal/parser"
	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

// decideResult is the shape `dbounce decide` writes to stdout. Mirrors
// the dbounce_decide MCP tool's JSON shape so shim code can reuse the
// same parsing across the CLI + JSON-RPC paths.
//
// AgentName + AgentSessionID echo back the [[agent-identity-in-audit]]
// fields the shim passed in via --agent-name (per the memo: "the decide
// CLI is invoked with explicit --agent-name flag (operator/agent
// passes it) — fallback to 'unknown' if absent"). The shim wrapper sees
// these fields surface so it can confirm the right agent was
// fingerprinted.
type decideResult struct {
	Verdict         string   `json:"verdict"`
	DecisionSource  string   `json:"decision_source"`
	Reason          string   `json:"reason"`
	Dialect         string   `json:"dialect"`
	StatementType   string   `json:"statement_type"`
	Tables          []string `json:"tables,omitempty"`
	Functions       []string `json:"functions,omitempty"`
	IsDML           bool     `json:"is_dml"`
	IsDDL           bool     `json:"is_ddl"`
	HasMutatingNode bool     `json:"has_mutating_node"`
	// Indicators surfaces the parser's RiskIndicators for operator debugging.
	// Populated for any statement where the parser computed risk flags (DCL
	// shapes: public_grant, all_privileges, with_grant_option, etc.). Empty
	// for non-DCL statements. Per #589: operators using `dbounce decide --json`
	// for incident response now see the WHY alongside the verdict.
	Indicators []string `json:"indicators,omitempty"`
	AgentName  string   `json:"agent_name,omitempty"`
	// Kept for future use (e.g. sync-prompt correlation). Not currently
	// populated by evalDecide but reserved in the schema so shim code
	// that references the field by name doesn't break on the JSON decode.
	AgentSessionID string `json:"agent_session_id,omitempty"`
}

func newDecideCmd() *cobra.Command {
	var (
		dialectStr           string
		statement            string
		readStdin            bool
		dbPath               string
		profileName          string
		profilesPath         string
		defaultPolStr        string
		asJSON               bool
		syncPromptOnDeny     bool
		syncPromptTimeoutStr string
		syncPromptDefaultStr string
		agentName            string
		agentVersion         string
	)
	cmd := &cobra.Command{
		Use:   "decide",
		Short: "Dry-run a SQL statement through dbounce's parser + rule engine",
		Long: `Dry-run a SQL statement through dbounce's parser + rule engine and
print the verdict. Reads the on-disk store + profiles.yaml; writes
NOTHING (no audit log entry, no pending prompt).

This is the supported invocation path for Snowflake + BigQuery, which
ship as JDBC-driver-shim only in v1.0 (no wire-protocol proxy — see
docs/SHIM-INTEGRATION.md). A shim wraps the customer's driver call,
exec's ` + "`dbounce decide --dialect snowflake|bigquery`" + ` (or calls the
equivalent dbounce_decide MCP tool) with the raw SQL, and forwards
only on allow.

Statement input:
  --statement "SQL"   pass the SQL on the command line
  --stdin             read the SQL from stdin (handy for multi-line
                      / quoted SQL the shell would otherwise mangle)

Output (default human-readable lines; --json for machine-parseable):

  verdict: <allow|deny>
  source:  <profile|task|global|default|...>
  reason:  <one-line explanation>
  type:    <SELECT|INSERT|...|UNPARSEABLE>

Exit code:
  0   verdict was allow (regardless of dialect/mode/etc)
  1   verdict was deny
  2   invalid arguments / store-open failure / parse failure surfaced
      before evaluation (still prints a result row when possible)`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dialect, err := proxy.ParseDialect(dialectStr)
			if err != nil {
				return err
			}
			defaultPol, err := proxy.ParseDefaultPolicy(defaultPolStr)
			if err != nil {
				return err
			}

			// Resolve the SQL string. Both --statement and --stdin
			// supplied is an error (operator intent ambiguous);
			// neither is also an error (no input to evaluate).
			if statement != "" && readStdin {
				return fmt.Errorf("--statement and --stdin are mutually exclusive")
			}
			sql := statement
			if readStdin {
				buf, rerr := io.ReadAll(cmd.InOrStdin())
				if rerr != nil {
					return fmt.Errorf("read stdin: %w", rerr)
				}
				sql = string(buf)
			}
			if strings.TrimSpace(sql) == "" {
				return fmt.Errorf(
					"no SQL to evaluate: pass --statement \"SQL\" or --stdin " +
						"(empty input is rejected so an accidentally-empty " +
						"shim call doesn't silently allow)")
			}

			// Open the store. Read-only intent; we never write here.
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			// Resolve the active profile. Lazy + best-effort: a missing
			// profiles.yaml falls back to full-user (passthrough); the
			// rule engine still gates via the global rules + the default
			// policy.
			if profileName == "" {
				profileName = os.Getenv(envProfileVar)
			}
			resolvedProfilesPath := profilesPath
			if resolvedProfilesPath == "" {
				p, perr := profile.DefaultProfilesPath()
				if perr == nil {
					resolvedProfilesPath = p
				}
			}
			var activeProfile *profile.Profile
			if resolvedProfilesPath != "" {
				if profiles, lerr := profile.LoadProfiles(resolvedProfilesPath); lerr == nil {
					if ap, aerr := profiles.Active(profileName); aerr == nil {
						activeProfile = ap
					}
				}
			}

			res, err := evalDecide(st, activeProfile, dialect, defaultPol, sql)
			if err != nil {
				return err
			}
			// [[agent-identity-in-audit]] Feature 1: surface the
			// operator-declared --agent-name in the decideResult so the
			// JDBC-shim wrapper sees confirmation that the agent name
			// flowed through. Empty agent name normalizes to "unknown"
			// per the memo's "fallback to unknown if absent" guidance.
			if strings.TrimSpace(agentName) == "" {
				res.AgentName = "unknown"
			} else {
				res.AgentName = strings.TrimSpace(agentName)
			}

			// #203 — sync-prompt-on-deny for the JDBC-shim path.
			// `dbounce decide` is the supported invocation path for
			// Snowflake/BigQuery (no wire-protocol proxy). When the
			// operator sets --sync-prompt-on-deny + the verdict is
			// deny, BLOCK on the wakeup channel exactly as the
			// PG/MySQL forwarders do; resolved-allow flips the
			// verdict so the shim wrapper sees exit code 0 +
			// forwards to the real driver.
			if syncPromptOnDeny && res.Verdict == "deny" {
				d, perr := time.ParseDuration(syncPromptTimeoutStr)
				if perr != nil {
					return fmt.Errorf(
						"--sync-prompt-timeout: parse %q: %w",
						syncPromptTimeoutStr, perr)
				}
				if d < 5*time.Second || d > 300*time.Second {
					return fmt.Errorf(
						"--sync-prompt-timeout must be in 5s-300s (got %s)", d)
				}
				sd, perr := proxy.ParseSyncPromptDefault(syncPromptDefaultStr)
				if perr != nil {
					return perr
				}
				// Persist a real decision row so the prompt's FK is
				// valid. The decide path normally writes NOTHING; we
				// make the explicit exception here because the sync
				// prompt requires an FK-anchored pending_prompts row.
				decisionID, recErr := st.RecordDecision(store.DecisionRow{
					Dialect:         res.Dialect,
					Statement:       sql,
					StatementType:   res.StatementType,
					TablesTouched:   res.Tables,
					FunctionsCalled: res.Functions,
					IsDML:           res.IsDML,
					IsDDL:           res.IsDDL,
					HasMutatingNode: res.HasMutatingNode,
					DecisionVerdict: "DENY",
					DecisionReason: fmt.Sprintf(
						"decide-path sync-prompt block (reason: %s)",
						res.Reason),
					ModeAtDecision: "transparent",
					DecisionSource: res.DecisionSource,
				})
				if recErr != nil {
					return fmt.Errorf(
						"record sync-prompt decision: %w", recErr)
				}
				_, waitID, ch, addErr := st.AddSyncPendingPrompt(store.PendingPrompt{
					DecisionID:      decisionID,
					StatementType:   res.StatementType,
					TablesTouched:   res.Tables,
					FunctionsCalled: res.Functions,
					DenyReason:      res.Reason,
				})
				if addErr != nil {
					return fmt.Errorf(
						"enqueue sync prompt: %w", addErr)
				}
				timer := time.NewTimer(d)
				defer timer.Stop()
				var outcome store.PromptDecision
				select {
				case decision := <-ch:
					outcome = decision
				case <-timer.C:
					st.CancelSyncPendingPrompt(waitID)
					if sd == proxy.SyncPromptDefaultAllow {
						outcome = store.PromptDecisionAllow
					} else {
						outcome = store.PromptDecisionDeny
					}
				}
				if outcome == store.PromptDecisionAllow {
					res.Verdict = "allow"
					res.DecisionSource = "sync-prompt.allow"
					res.Reason = fmt.Sprintf(
						"sync-prompt-on-deny allowed (was deny: %s; sync_wait_id=%s)",
						res.Reason, waitID)
				} else {
					res.Reason = fmt.Sprintf(
						"%s (sync prompt %s; sync_wait_id=%s)",
						res.Reason, outcome, waitID)
				}
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				if eerr := enc.Encode(res); eerr != nil {
					return eerr
				}
			} else {
				w := cmd.OutOrStdout()
				fmt.Fprintf(w, "verdict: %s\n", res.Verdict)
				fmt.Fprintf(w, "source:  %s\n", res.DecisionSource)
				fmt.Fprintf(w, "reason:  %s\n", res.Reason)
				fmt.Fprintf(w, "type:    %s\n", res.StatementType)
				if len(res.Tables) > 0 {
					fmt.Fprintf(w, "tables:  %s\n", strings.Join(res.Tables, ", "))
				}
			}
			if res.Verdict == "deny" {
				// Exit code 1 = deny so shim code can branch on $? without
				// parsing the output. cobra suppresses non-zero exits from
				// RunE; we use os.Exit(1) directly here so the calling
				// shim sees the expected status. We've already flushed
				// stdout via the printer above.
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dialectStr, "dialect", "postgres",
		"SQL dialect: postgres | mysql | snowflake | bigquery. "+
			"snowflake + bigquery ship via the JDBC-shim path "+
			"(docs/SHIM-INTEGRATION.md); the parser is best-effort + "+
			"the rule packs are calibration_status: experimental.")
	cmd.Flags().StringVar(&statement, "statement", "",
		"The SQL string to evaluate. Mutually exclusive with --stdin.")
	cmd.Flags().BoolVar(&readStdin, "stdin", false,
		"Read the SQL from stdin (handy for multi-line / quoted SQL).")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite store path (default: ~/.dbounce/state.db, or DBOUNCE_DB env). "+
			"Read-only: `dbounce decide` writes NOTHING.")
	cmd.Flags().StringVar(&profileName, "profile", "",
		"Active environment profile name. Falls back to "+envProfileVar+" env "+
			"var; defaults to 'full-user' if neither is set.")
	cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
		"Path to profiles.yaml (default: ~/.dbounce/profiles.yaml).")
	cmd.Flags().StringVar(&defaultPolStr, "default-policy", "deny",
		"Fall-through policy when no rule matches: allow | deny. "+
			"Matches `dbounce run --default-policy` semantics.")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit one JSON object instead of human-readable lines. The schema "+
			"matches dbounce_decide MCP tool output so shim code can share "+
			"a parser across CLI + JSON-RPC transports.")
	// #203 synchronous deny-prompt v1.1 — JDBC-shim equivalent of the
	// wire-protocol path.
	cmd.Flags().BoolVar(&syncPromptOnDeny, "sync-prompt-on-deny", false,
		"When the verdict is deny, BLOCK for up to --sync-prompt-timeout "+
			"waiting for `dbounce prompts answer ID --kind ...`. Answer "+
			"kind=always/profile → verdict flips to allow + decide exits 0 "+
			"so the shim wrapper forwards the SQL to the real driver. "+
			"Answer kind=ignore (or timeout with --sync-prompt-default=deny) "+
			"→ verdict stays deny + decide exits 1.")
	cmd.Flags().StringVar(&syncPromptTimeoutStr, "sync-prompt-timeout", "30s",
		"How long --sync-prompt-on-deny blocks before applying "+
			"--sync-prompt-default. Range 5s-300s; default 30s.")
	cmd.Flags().StringVar(&syncPromptDefaultStr, "sync-prompt-default", "deny",
		"Verdict --sync-prompt-on-deny applies on timeout: allow | deny.")
	// [[agent-identity-in-audit]] Feature 1: --agent-name + --agent-
	// version are the JDBC-shim path's equivalent of MCP clientInfo /
	// PG application_name. The shim wrapper passes the agent name it
	// was invoked by (e.g. --agent-name claude-code --agent-version
	// 1.2.3) so the resulting decision row + sync-prompt audit event
	// carries the fingerprint in unmapped.iam_jit.agent. Per the memo:
	// "fallback to unknown if absent" — both flags are optional + the
	// result surfaces "unknown" when not passed.
	cmd.Flags().StringVar(&agentName, "agent-name", "",
		"Agent name fingerprint for the audit trail (e.g. claude-code, "+
			"cursor, devin, codex, custom). Surfaced in decideResult + "+
			"persisted to unmapped.iam_jit.agent.name when the audit-"+
			"export transport is wired. Defaults to 'unknown'.")
	cmd.Flags().StringVar(&agentVersion, "agent-version", "",
		"Agent version string accompanying --agent-name (e.g. 1.2.3). "+
			"Optional; surfaced in unmapped.iam_jit.agent.version.")
	return cmd
}

// evalDecide runs the same composition order the proxy's decide()
// uses (profile → task-deny → global → task-allow → default) but does
// NOT write an audit row + does NOT enqueue a prompt. Kept in this
// file so the CLI's dependency surface stays small (the proxy
// package's decide() is a method on *Server, which carries a lot of
// wire-protocol state we don't need here).
//
// Cross-product invariant per [[cross-product-agent-parity]]: the
// shape returned matches the dbounce_decide MCP tool's output so a
// shim wrapper can switch transports (exec vs JSON-RPC) without
// changing its result-parsing code.
func evalDecide(
	st *store.Store,
	activeProfile *profile.Profile,
	dialect proxy.Dialect,
	defaultPol proxy.DefaultPolicy,
	sql string,
) (*decideResult, error) {
	ps := parser.Parse(string(dialect), sql)
	out := &decideResult{
		Dialect:         ps.Dialect,
		StatementType:   ps.StatementType,
		Tables:          append([]string(nil), ps.TablesTouched...),
		Functions:       append([]string(nil), ps.FunctionsCalled...),
		IsDML:           ps.IsDML,
		IsDDL:           ps.IsDDL,
		HasMutatingNode: ps.HasMutatingNode,
		// #589: surface RiskIndicators so operators running
		// `dbounce decide --json` for incident response see the
		// WHY alongside the verdict.
		Indicators: append([]string(nil), ps.RiskIndicators...),
	}

	// Step 0: multi-statement admin-tight floor (#587 UAT-C CRIT).
	// Mirrors proxy.decide()'s Step 0 byte-for-byte. Fires BEFORE the
	// profile gate so an embedded GRANT/ALTER_PRIVILEGES at position
	// 2+ can't slip past a profile baseline that matched on the first
	// statement's classification. The global rules table is threaded
	// through so per-statement allow-rule matches preserve the
	// existing override semantics. Per [[ibounce-honest-positioning]]
	// + [[scorer-is-ground-truth]]: CLI dry-run + production hot path
	// produce identical verdicts on identical multi-statement inputs.
	// Single source of truth lives in
	// internal/decision/multi_statement.go.
	var step0Rules *dbrules.RuleSet
	if st != nil {
		if rs, rerr := st.LoadRuleSet(); rerr == nil {
			step0Rules = rs
		}
	}
	if mv := decision.EvaluateMultiStatement(
		ps.Dialect, ps.Raw, activeProfile,
		string(defaultPol), step0Rules); mv.Deny {
		out.Verdict = "deny"
		out.DecisionSource = "default"
		out.Reason = mv.Reason
		return out, nil
	}

	// Step 1: profile gates. Mirrors proxy.decide step 1+2.
	if activeProfile != nil && activeProfile.Name != profile.FullUserProfileName {
		profileView := &profile.ParsedStatement{
			StatementType:    ps.StatementType,
			TablesTouched:    ps.TablesTouched,
			FunctionsCalled:  ps.FunctionsCalled,
			IsDML:            ps.IsDML,
			IsDDL:            ps.IsDDL,
			HasMutatingNode:  ps.HasMutatingNode,
			IsExplain:        ps.IsExplain,
			IsExplainAnalyze: ps.IsExplainAnalyze,
		}
		pv := activeProfile.Evaluate(profileView)
		if pv.Denied {
			out.Verdict = "deny"
			out.DecisionSource = pv.Source
			out.Reason = pv.Reason
			return out, nil
		}
		if pv.Allowed {
			out.Verdict = "allow"
			out.DecisionSource = pv.Source
			out.Reason = pv.Reason
			return out, nil
		}
	}

	if st == nil {
		out.Verdict = string(defaultPol)
		out.DecisionSource = "default"
		out.Reason = fmt.Sprintf("no store configured; default policy %q applied", defaultPol)
		return out, nil
	}

	ruleSet, err := st.LoadRuleSet()
	if err != nil {
		return nil, fmt.Errorf("load ruleset: %w", err)
	}
	stmtView := &dbrules.ParsedStatement{
		StatementType:    ps.StatementType,
		TablesTouched:    ps.TablesTouched,
		FunctionsCalled:  ps.FunctionsCalled,
		IsDML:            ps.IsDML,
		IsDDL:            ps.IsDDL,
		HasMutatingNode:  ps.HasMutatingNode,
		IsExplain:        ps.IsExplain,
		IsExplainAnalyze: ps.IsExplainAnalyze,
	}
	res := ruleSet.Evaluate(stmtView)
	if res != nil {
		if res.Effect == dbrules.EffectDeny {
			out.Verdict = "deny"
			out.DecisionSource = "global.deny"
			out.Reason = fmt.Sprintf("matched deny rule pattern %q", res.Rule.Pattern)
			return out, nil
		}
		out.Verdict = "allow"
		out.DecisionSource = "global.allow"
		out.Reason = fmt.Sprintf("matched allow rule pattern %q", res.Rule.Pattern)
		return out, nil
	}

	// #559 + #587: admin-tight floor moved to Step 0 above. Pre-#587
	// the floor lived here; UAT-C 2026-05-25 surfaced that an embedded
	// DCL at position 2+ slipped past the profile gate because the
	// floor ran AFTER profile evaluation. Step 0 closes that bypass
	// for both default-allow + profile-allow shapes. Single source of
	// truth in internal/decision/multi_statement.go.

	out.Verdict = string(defaultPol)
	out.DecisionSource = "default"
	out.Reason = fmt.Sprintf("no rule matched; default policy %q applied", defaultPol)
	return out, nil
}

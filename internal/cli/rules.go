// `dbounce rules add | list | remove | recommend` (D-Slice 8 closes
// #241 by shipping the rules CLI surface area, while landing the
// observation-based recommender that the dbounce-build-plan §D-Slice
// 8 calls out).
//
// `rules recommend` is the observation-based recommender (mirror of
// kbounce + ibounce + the Python iam-jit-bouncer): scan recent
// decisions, group by statement-type + table set, surface the common
// patterns, optionally save as a profile. Auto-naming per
// [[profile-auto-naming]] when --save-as-profile is passed with an
// empty value or omitted on non-TTY.
//
// Per [[creates-never-mutates]] the recommender NEVER edits the rules
// table or any existing profile; it READS the decisions table and
// optionally CREATES a fresh profile.
package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/naming"
	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

func newRulesCmd(profileWriter ProfileWriter) *cobra.Command {
	if profileWriter == nil {
		panic("dbounce cli: newRulesCmd requires a non-nil ProfileWriter (INFO-D8-14)")
	}
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Inspect + edit global rules + run the observation-based recommender",
		Long: `Global rules layer is the first layer the decide() composition
visits AFTER profile + task scopes (see internal/proxy/proxy.go for
the full composition order). Use the rules CLI to add explicit
allow/deny rules, list what's installed, remove individual rows, and
run the observation-based recommender against recent audit-log
decisions.

The recommender scans recent decisions, groups them by statement_type
+ touched-table-set, surfaces the common patterns, and (with
--save-as-profile) creates a profile carrying allow rules for the top
patterns. The user's local agent context can then refine — per
[[agent-driven-reduction-loop]] this is the "first pass" that lets
the agent pick a starting shape instead of guessing.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("rules", cmd)
	cmd.AddCommand(newRulesAddCmd())
	cmd.AddCommand(newRulesListCmd())
	cmd.AddCommand(newRulesRemoveCmd())
	cmd.AddCommand(newRulesRecommendCmd(profileWriter))
	return cmd
}

func newRulesAddCmd() *cobra.Command {
	var (
		dbPath        string
		pattern       string
		effect        string
		schemaScope   string
		tableScope    string
		functionScope string
		note          string
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Append a global rule (closes #241 wiring)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			eff := dbrules.Effect(effect)
			if !eff.IsValid() {
				return fmt.Errorf("--effect must be allow|deny (got %q)", effect)
			}
			id, err := st.AddRule(dbrules.ProxyRule{
				Pattern:       pattern,
				Effect:        eff,
				SchemaScope:   schemaScope,
				TableScope:    tableScope,
				FunctionScope: functionScope,
				Note:          note,
				Origin:        dbrules.OriginUser,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"added rule %d: %s (effect=%s)\n", id, pattern, eff)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().StringVar(&pattern, "pattern", "",
		"Rule pattern statement_type:table_glob (e.g. 'SELECT:public.*'). Required.")
	cmd.Flags().StringVar(&effect, "effect", "allow",
		"allow | deny.")
	cmd.Flags().StringVar(&schemaScope, "schema-scope", "",
		"Glob matched against the schema half of touched tables.")
	cmd.Flags().StringVar(&tableScope, "table-scope", "",
		"Glob matched against full schema-qualified table id.")
	cmd.Flags().StringVar(&functionScope, "function-scope", "",
		"Glob matched against called function names (CALL/DO/EXECUTE).")
	cmd.Flags().StringVar(&note, "note", "",
		"Free-form description recorded with the rule.")
	_ = cmd.MarkFlagRequired("pattern")
	return cmd
}

func newRulesListCmd() *cobra.Command {
	var (
		dbPath string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all global rules in insertion order",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			rules, err := st.ListRules()
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				for _, sr := range rules {
					m := sr.Rule.ToMap()
					m["id"] = int64(sr.ID)
					if err := enc.Encode(m); err != nil {
						return err
					}
				}
				return nil
			}
			if len(rules) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no rules)")
				return nil
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-4s  %-30s  %-6s  %-10s  %s\n",
				"ID", "PATTERN", "EFFECT", "ORIGIN", "NOTE")
			for _, sr := range rules {
				fmt.Fprintf(w, "%-4d  %-30s  %-6s  %-10s  %s\n",
					int64(sr.ID), sr.Rule.Pattern, sr.Rule.Effect,
					sr.Rule.Origin, sr.Rule.Note)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit one JSON object per rule.")
	return cmd
}

func newRulesRemoveCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "remove ID",
		Short: "Remove a global rule by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			idInt, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("rule id must be a positive integer (got %q)", args[0])
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			removed, err := st.RemoveRule(dbrules.ID(idInt))
			if err != nil {
				return err
			}
			if !removed {
				return fmt.Errorf("no rule with id %d", idInt)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed rule %d.\n", idInt)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	return cmd
}

// recommendation is one row of the recommender's output: a pattern
// observed in recent decisions, the count of times it appeared, and
// the verdict distribution. Surfaced as JSON when --json is passed,
// pretty-printed otherwise.
type recommendation struct {
	StatementType string   `json:"statement_type"`
	TableGlob     string   `json:"table_glob"`
	Count         int      `json:"count"`
	AllowCount    int      `json:"allow_count"`
	DenyCount     int      `json:"deny_count"`
	SampleTables  []string `json:"sample_tables"`
}

func newRulesRecommendCmd(profileWriter ProfileWriter) *cobra.Command {
	if profileWriter == nil {
		panic("dbounce cli: newRulesRecommendCmd requires a non-nil ProfileWriter (INFO-D8-14)")
	}
	var (
		dbPath        string
		scanLimit     int
		minCount      int
		saveAsProfile string
		description   string
		actor         string
		asJSON        bool
	)
	cmd := &cobra.Command{
		Use:   "recommend",
		Short: "Scan recent decisions + propose rule shapes (optionally save as profile)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if scanLimit < 1 || scanLimit > 10_000 {
				return fmt.Errorf("--scan must be in 1-10000 (got %d)", scanLimit)
			}
			if minCount < 1 {
				return fmt.Errorf("--min-count must be >= 1 (got %d)", minCount)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()
			rows, err := st.RecentDecisions(scanLimit)
			if err != nil {
				return err
			}
			recs := recommendFromDecisions(rows, minCount)

			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				for _, r := range recs {
					if err := enc.Encode(r); err != nil {
						return err
					}
				}
			} else {
				if len(recs) == 0 {
					fmt.Fprintln(cmd.OutOrStdout(),
						"(no patterns met --min-count; try larger --scan or smaller --min-count)")
				} else {
					w := cmd.OutOrStdout()
					fmt.Fprintf(w, "%-12s  %-30s  %-6s  %-6s  %-6s  %s\n",
						"STMT-TYPE", "TABLE-GLOB", "COUNT", "ALLOW", "DENY", "SAMPLE-TABLES")
					for _, r := range recs {
						samples := strings.Join(r.SampleTables, ",")
						if len(samples) > 40 {
							samples = samples[:37] + "..."
						}
						fmt.Fprintf(w, "%-12s  %-30s  %-6d  %-6d  %-6d  %s\n",
							r.StatementType, r.TableGlob, r.Count, r.AllowCount, r.DenyCount, samples)
					}
				}
			}

			// --save-as-profile: build allow rules from the
			// recommendations + persist via the injected ProfileWriter.
			// Flag absent = no profile creation; flag present with
			// empty value = use auto-name; flag present with value =
			// use that name (slugified).
			if !cmd.Flags().Changed("save-as-profile") {
				return nil
			}
			if len(recs) == 0 {
				return fmt.Errorf("--save-as-profile passed but no recommendations meet --min-count; nothing to save")
			}
			existing, perr := profileWriter.ExistingProfileNames()
			if perr != nil {
				return fmt.Errorf("list profile names: %w", perr)
			}
			detail := recommendDetailSlug(recs)
			ctx := naming.Context{
				Kind:   "recommend",
				Detail: detail,
				Now:    naming.SystemClock,
			}
			isTTY := isatty.IsTerminal(0)
			argVal := saveAsProfile
			if argVal == "__AUTO__" {
				// Bare `--save-as-profile` (no =VALUE) — caller wants
				// auto-name. Pass empty arg so ResolveProfileName picks
				// the suggestion (with TTY-prompt when interactive).
				argVal = ""
			}
			resolved, wantPrompt, suggestion := naming.ResolveProfileName(argVal, ctx, isTTY && argVal == "", existing)
			if wantPrompt {
				resolved = suggestion
				fmt.Fprintf(cmd.ErrOrStderr(),
					"using auto-name %q (interactive prompt not yet wired for `rules recommend`)\n",
					resolved)
			}
			if resolved == "" {
				resolved = suggestion
			}
			allow := make([]dbrules.ProxyRule, 0, len(recs))
			for _, r := range recs {
				allow = append(allow, dbrules.ProxyRule{
					Pattern: fmt.Sprintf("%s:%s", r.StatementType, r.TableGlob),
					Effect:  dbrules.EffectAllow,
					Origin:  dbrules.OriginRecommended,
					Note: fmt.Sprintf("from recommender: %d observed (%d allow, %d deny)",
						r.Count, r.AllowCount, r.DenyCount),
				})
			}
			desc := description
			if desc == "" {
				desc = fmt.Sprintf("auto-generated by 'dbounce rules recommend' from %d decisions", len(rows))
			}
			if err := profileWriter.CreateProfile(resolved, desc, allow, nil); err != nil {
				return fmt.Errorf("create profile: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"created profile %q with %d allow rules (origin=recommended).\n",
				resolved, len(allow))
			_ = actor // reserved for future audit-row emission
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().IntVar(&scanLimit, "scan", 500,
		"How many recent decisions to scan (1-10000).")
	cmd.Flags().IntVar(&minCount, "min-count", 3,
		"Minimum observed count for a pattern to surface.")
	cmd.Flags().StringVar(&saveAsProfile, "save-as-profile", "",
		"Save the recommendations as a new profile. Pass without a value "+
			"(or '=NAME') to use the [[profile-auto-naming]] auto-name; pass "+
			"--save-as-profile=NAME for an explicit name.")
	// NoOptDefVal lets `--save-as-profile` (no value) parse to a sentinel
	// the RunE then interprets as "use the auto-name." pflag requires a
	// non-empty NoOptDefVal to allow the bare form; the sentinel below
	// is what RunE strips before passing to naming.ResolveProfileName.
	cmd.Flag("save-as-profile").NoOptDefVal = "__AUTO__"
	cmd.Flags().StringVar(&description, "description", "",
		"Description to seed the new profile with (used only with --save-as-profile).")
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id (reserved for future audit fields).")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit one JSON object per recommendation.")
	return cmd
}

// recommendFromDecisions is the deterministic recommender core. Pure
// function (no I/O) so tests can drive it directly without a store.
//
// Algorithm: group rows by (statement_type, generalized-table-glob),
// count, filter by min-count, sort by count descending. The
// generalized-table-glob collapses each row's TablesTouched into a
// single representative glob:
//
//   - 0 tables       → "*"
//   - 1 table        → that table verbatim
//   - >1 same schema → "{schema}.*"
//   - >1 mixed schema → "*"
//
// This is intentionally simple — the recommender is a STARTING POINT
// per [[agent-driven-reduction-loop]] (the agent then refines using
// its codebase context). A more clever generalization would mask
// real differences the agent should see.
func recommendFromDecisions(rows []store.DecisionRow, minCount int) []recommendation {
	type key struct{ stmt, glob string }
	type agg struct {
		count       int
		allow, deny int
		samples     map[string]struct{}
	}
	bucket := make(map[key]*agg)
	for _, r := range rows {
		stmt := r.StatementType
		if stmt == "" {
			stmt = "*"
		}
		glob := generalizeTableGlob(r.TablesTouched)
		k := key{stmt: stmt, glob: glob}
		a, ok := bucket[k]
		if !ok {
			a = &agg{samples: map[string]struct{}{}}
			bucket[k] = a
		}
		a.count++
		switch r.DecisionVerdict {
		case "ALLOW":
			a.allow++
		case "DENY":
			a.deny++
		}
		for _, t := range r.TablesTouched {
			if len(a.samples) < 5 {
				a.samples[t] = struct{}{}
			}
		}
	}
	out := make([]recommendation, 0, len(bucket))
	for k, a := range bucket {
		if a.count < minCount {
			continue
		}
		samples := make([]string, 0, len(a.samples))
		for s := range a.samples {
			samples = append(samples, s)
		}
		sort.Strings(samples)
		out = append(out, recommendation{
			StatementType: k.stmt,
			TableGlob:     k.glob,
			Count:         a.count,
			AllowCount:    a.allow,
			DenyCount:     a.deny,
			SampleTables:  samples,
		})
	}
	// Deterministic order: by count descending, then by (stmt, glob)
	// for tie-break so two equivalent test runs produce identical output.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].StatementType != out[j].StatementType {
			return out[i].StatementType < out[j].StatementType
		}
		return out[i].TableGlob < out[j].TableGlob
	})
	return out
}

func generalizeTableGlob(tables []string) string {
	if len(tables) == 0 {
		return "*"
	}
	if len(tables) == 1 {
		return tables[0]
	}
	// Multiple tables: keep schema-prefix only if all share one.
	schema := ""
	for i, t := range tables {
		s := ""
		if dot := strings.Index(t, "."); dot >= 0 {
			s = t[:dot]
		}
		if i == 0 {
			schema = s
			continue
		}
		if s != schema {
			return "*"
		}
	}
	if schema == "" {
		return "*"
	}
	return schema + ".*"
}

func recommendDetailSlug(recs []recommendation) string {
	if len(recs) == 0 {
		return "empty"
	}
	top := recs[0]
	parts := []string{strings.ToLower(top.StatementType)}
	// Take the schema portion of the glob for a cleaner slug.
	glob := top.TableGlob
	if dot := strings.Index(glob, "."); dot >= 0 {
		glob = glob[:dot]
	}
	if glob != "" && glob != "*" {
		parts = append(parts, glob)
	}
	return strings.Join(parts, "-")
}

// `dbounce backup` + `dbounce restore` per #279 (SQLite backup/restore).
//
// The two commands are sibling top-level subcommands (NOT nested under
// `dbounce config`) because their semantics are wholesale-file rather
// than per-bundle-merge: a `dbounce config import` overlays rules +
// profiles onto an existing deployment; a `dbounce restore` REPLACES
// the deployment's state.db with a backup file. Distinct verbs,
// distinct command names.
//
// Cross-product alignment per [[cross-product-agent-parity]]: kbounce
// + ibounce ship the same `<product> backup` + `<product> restore`
// CLI shape with the same flag names + the same refuse-without-force
// semantics + the same `{product}_backup_metadata` table format.
//
// What backup ships by default (per #279 spec):
//
//   - config_snapshots equivalent          — there's no separate
//                                            "config snapshots" table in
//                                            dbounce; the rules + profile_
//                                            overrides + tasks + pause_
//                                            events tables together carry
//                                            the equivalent state, all of
//                                            which is included by default
//   - rules                                — global allow/deny rules
//   - tasks                                — active task-scoped rule sets
//   - profile_overrides                    — hot-swap signal (transient
//                                            but harmless to back up)
//   - pause_events                         — pause history
//   - decisions                            — audit log (operator may
//                                            CHOOSE to exclude via a
//                                            future --no-decisions flag
//                                            but the default behavior is
//                                            inclusion — DR scenarios
//                                            need the audit history)
//
// What backup ships only on opt-in:
//
//   - pending_audit_events (--include-audit)   — high-volume queue
//   - pending_prompts (--include-prompts)      — bound to in-flight
//                                                proxy goroutines that
//                                                won't survive a restore
//
// Admin-action audit emission: both subcommands enqueue an
// ADMIN_ACTION row so a SIEM dashboard sees the backup / restore
// lifecycle event. Restore's enqueue happens AFTER the destructive
// copy lands; if the running dbounce process isn't up to drain the
// row, it'll pick it up on next start.

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/store"
)

// newBackupCmd implements `dbounce backup`. Top-level subcommand (NOT
// nested under `dbounce config`) per the file's doc comment.
func newBackupCmd() *cobra.Command {
	var (
		dbPath         string
		outPath        string
		includeAudit   bool
		includePrompts bool
		actor          string
		noTimestamp    bool
	)
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Write an online SQLite backup of dbounce state.db to a file",
		Long: `Creates an online backup of dbounce's SQLite state database
using SQLite's VACUUM INTO primitive. The source database is NOT
locked; concurrent writers continue uninterrupted. The destination is
a fresh SQLite file at --out (default: dbounce-backup-<timestamp>.db
in the current working directory).

Default contents:
  - rules               (global allow/deny rules)
  - profile_overrides   (hot-swap signal)
  - tasks               (active task-scoped rule sets)
  - pause_events        (pause history)
  - decisions           (audit log)
  - admin-action queue is SKIPPED by default; pass --include-audit to opt in
  - pending-prompts table is SKIPPED by default; pass --include-prompts to opt in

The backup file embeds a dbounce_backup_metadata table carrying:
  - dbounce_version
  - created_at (RFC3339)
  - source_hostname_hash (sha256[:12] of the source host's hostname)
  - schema_version
  - included_audit / included_prompts flags

` + "`dbounce restore`" + ` reads this metadata to validate cross-version +
cross-schema restores.

Per [[creates-never-mutates]]: backup is READ-ONLY against the source
database. Per [[self-host-zero-billing-dependency]]: no network calls.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if outPath == "" {
				outPath = defaultBackupFilename(noTimestamp)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			hostname, _ := os.Hostname()
			meta, err := st.Backup(outPath, store.BackupOptions{
				IncludeAudit:   includeAudit,
				IncludePrompts: includePrompts,
				DbounceVersion: version,
				Hostname:       hostname,
			})
			if err != nil {
				return err
			}

			abs, _ := filepath.Abs(outPath)
			info, statErr := os.Stat(outPath)
			var size int64
			if statErr == nil {
				size = info.Size()
			}
			counts, _ := store.CountRowsByTable(outPath)
			sum, _ := store.FileSHA256(outPath)
			fmt.Fprintf(cmd.OutOrStdout(),
				"wrote dbounce backup to %s (%d bytes, sha256=%s)\n",
				abs, size, sum)
			fmt.Fprintf(cmd.OutOrStdout(),
				"  schema_version=%d  dbounce_version=%s  created_at=%s\n",
				meta.SchemaVersion, meta.DbounceVersion,
				meta.CreatedAt.Format(time.RFC3339))
			fmt.Fprintf(cmd.OutOrStdout(),
				"  source_hostname_hash=%s  included_audit=%t  included_prompts=%t\n",
				meta.SourceHostnameHash, meta.IncludedAudit, meta.IncludedPrompts)
			if len(counts) > 0 {
				names := make([]string, 0, len(counts))
				for k := range counts {
					names = append(names, k)
				}
				sort.Strings(names)
				fmt.Fprintln(cmd.OutOrStdout(), "  tables:")
				for _, n := range names {
					fmt.Fprintf(cmd.OutOrStdout(), "    %-32s %d rows\n", n, counts[n])
				}
			}

			// ADMIN_ACTION audit-event enqueue.
			enqueueAdminAction(cmd.ErrOrStderr(), dbPath, adminActionEnqueueParams{
				Action:       "backup.create",
				Actor:        resolveActor(actor),
				ResourceType: "backup",
				ResourceID:   abs,
				Details: map[string]any{
					"path":              abs,
					"size_bytes":        size,
					"sha256":            sum,
					"schema_version":    meta.SchemaVersion,
					"dbounce_version":   meta.DbounceVersion,
					"included_audit":    meta.IncludedAudit,
					"included_prompts":  meta.IncludedPrompts,
					"source_host_hash":  meta.SourceHostnameHash,
				},
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "",
		"SQLite source DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().StringVar(&outPath, "out", "",
		"Output file path. Default: dbounce-backup-<RFC3339-timestamp>.db in cwd.")
	cmd.Flags().BoolVar(&includeAudit, "include-audit", false,
		"Include the pending_audit_events table in the backup (default: excluded).")
	cmd.Flags().BoolVar(&includePrompts, "include-prompts", false,
		"Include the pending_prompts table in the backup (default: excluded).")
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id recorded on the ADMIN_ACTION audit event. "+
			"Defaults to $USER then 'unknown'.")
	cmd.Flags().BoolVar(&noTimestamp, "no-timestamp", false,
		"Skip the RFC3339 timestamp in the default --out filename. "+
			"Use only when you're managing filenames yourself (e.g. a CI "+
			"job that uploads to S3 keyed on the job id).")
	return cmd
}

// newRestoreCmd implements `dbounce restore`. Top-level subcommand
// (NOT nested under `dbounce config`) per the file's doc comment.
func newRestoreCmd() *cobra.Command {
	var (
		dbPath    string
		inPath    string
		force     bool
		actor     string
		probeSkip bool
		probePort []int
	)
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Replace dbounce state.db with a backup file (destructive; gated)",
		Long: `Restores a ` + "`dbounce backup`" + ` file by copying it onto the
running deployment's state.db path. The destination is REPLACED — this
is a DR action, not a merge. For per-bundle merge semantics use
` + "`dbounce config import`" + ` instead.

Validation gates (all checked BEFORE the destructive copy):

  1. Schema-version match (HARD; --force does NOT override).
     Cross-schema restore is the ` + "`dbounce migrate`" + ` story,
     out-of-scope for #279.
  2. dbounce-version match (soft; --force overrides with a warning).
     Cross-version restores within the same schema_version are supported.
  3. Destination database must be empty (no rows in any user table)
     unless --force is passed.
  4. ` + "`dbounce run`" + ` must not be running (probe loopback ports
     5433 + 8768). Pass --probe-skip if the ports are held by an
     unrelated process and you've manually verified dbounce is down.

On success the command prints the per-table row counts of the restored
database + its sha256 fingerprint.

Per [[creates-never-mutates]]: restore is the one CLI surface that DOES
mutate an existing DB; the destructive verb is gated by the explicit
subcommand name + the --force semantics + the running-process probe.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if inPath == "" {
				return errors.New("--in is required (path to a `dbounce backup` file)")
			}
			if dbPath == "" {
				resolved, err := store.DefaultDBPath()
				if err != nil {
					return fmt.Errorf("resolve default DB path: %w", err)
				}
				dbPath = resolved
			}

			opts := store.RestoreOptions{
				Force:          force,
				DbounceVersion: version,
				ProbeTimeout:   200 * time.Millisecond,
			}
			if probeSkip {
				opts.ProbePorts = []store.HostPort{} // empty, not nil — skips
			} else if len(probePort) > 0 {
				targets := make([]store.HostPort, 0, len(probePort))
				for _, p := range probePort {
					targets = append(targets, store.HostPort{Host: "127.0.0.1", Port: p})
				}
				opts.ProbePorts = targets
			}

			result, warn, err := store.Restore(inPath, dbPath, opts)
			if warn != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), warn.String())
			}
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(),
				"restored dbounce state.db from %s\n", inPath)
			fmt.Fprintf(cmd.OutOrStdout(),
				"  destination: %s\n  sha256: %s\n",
				result.DstPath, result.SHA256)
			if len(result.TableNames) > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "  row counts:")
				for _, n := range result.TableNames {
					fmt.Fprintf(cmd.OutOrStdout(),
						"    %-32s %d rows\n", n, result.RowCounts[n])
				}
			}

			// ADMIN_ACTION audit-event enqueue. If `dbounce run` is
			// down right now (the spec REQUIRES it for restore), the
			// running process will drain on next start.
			enqueueAdminAction(cmd.ErrOrStderr(), dbPath, adminActionEnqueueParams{
				Action:       "backup.restore",
				Actor:        resolveActor(actor),
				ResourceType: "backup",
				ResourceID:   inPath,
				Details: map[string]any{
					"source_path":     inPath,
					"destination":     result.DstPath,
					"sha256":          result.SHA256,
					"force":           force,
					"probe_skipped":   probeSkip,
					"row_count_total": totalRowCount(result.RowCounts),
				},
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&inPath, "in", "",
		"Path to the dbounce backup file to restore. Required.")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"Destination SQLite DB path (default: ~/.dbounce/state.db, or DBOUNCE_DB env).")
	cmd.Flags().BoolVar(&force, "force", false,
		"Override the non-empty-destination refusal + the dbounce_version-mismatch warning. "+
			"Does NOT override schema_version mismatch (cross-schema migration is `dbounce migrate` territory).")
	cmd.Flags().StringVar(&actor, "actor", "",
		"Operator id recorded on the ADMIN_ACTION audit event. "+
			"Defaults to $USER then 'unknown'.")
	cmd.Flags().BoolVar(&probeSkip, "probe-skip", false,
		"Skip the running-process probe. Use only when the probe ports are "+
			"held by an unrelated process and you've manually verified dbounce is down.")
	cmd.Flags().IntSliceVar(&probePort, "probe-port", nil,
		"Override the loopback ports the running-process probe dials "+
			"(default: 5433 + 8768). Repeatable: --probe-port 5433 --probe-port 8768.")
	_ = cmd.MarkFlagRequired("in")
	return cmd
}

// defaultBackupFilename returns dbounce-backup-<RFC3339-timestamp>.db
// in the current working directory. When noTimestamp is true the
// filename is just dbounce-backup.db.
func defaultBackupFilename(noTimestamp bool) string {
	if noTimestamp {
		return "dbounce-backup.db"
	}
	// RFC3339 with `:` replaced by `-` so the filename is portable
	// across platforms that disallow `:` in filenames (Windows).
	ts := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	return "dbounce-backup-" + ts + ".db"
}

// totalRowCount sums every value in the per-table count map. Surfaced
// in the audit event payload as a single integer so a SIEM rule can
// alert on "an unusually small restore" without parsing per-table
// fields.
func totalRowCount(counts map[string]int64) int64 {
	var n int64
	for _, c := range counts {
		n += c
	}
	return n
}


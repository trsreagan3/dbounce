// `dbounce session` subcommand group — #285 session recording / playback.
//
// Lists, shows, exports, and purges per-session NDJSON recordings
// written by the proxy when run with `--record-sessions-dir`. Same
// subcommand names + flag shape across ibounce / kbouncer / dbounce /
// gbounce per [[cross-product-agent-parity]] so cross-product
// orchestration code (and the cross-product `iam-jit session replay
// <FILE>` CLI) consumes any product's recordings uniformly.
//
// Per [[creates-never-mutates]]: every subcommand here is read-only
// over the recording files. The proxy itself is the only thing that
// writes recordings.
//
// Per [[self-host-zero-billing-dependency]]: entirely local file
// system; no phone-home.
//
// File permissions on recording files are 0o600 (owner-read-only) —
// recordings carry agent identity + operation details.

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/audit"
)

// defaultSessionsDir is the standard recordings directory under the
// dbounce home. Operators override via `--dir`.
func defaultSessionsDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".dbounce", "sessions")
	}
	return filepath.Join(home, ".dbounce", "sessions")
}

func formatTSMillis(ms int64) string {
	if ms <= 0 {
		return "-"
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

// parseRetention accepts s/m/h/d suffixes for session-purge thresholds.
// Lives here (not in pause.go) because the pause parser is intentionally
// capped at 24h and rejects `d`; session retention runs in days. The
// grammar matches the Python ibounce parser + kbouncer Go parser so the
// cross-product UX is identical per [[cross-product-agent-parity]].
func parseRetention(raw string) (time.Duration, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return 0, fmt.Errorf("duration is required")
	}
	suffix := s[len(s)-1:]
	mult := map[string]time.Duration{
		"s": time.Second,
		"m": time.Minute,
		"h": time.Hour,
		"d": 24 * time.Hour,
	}
	d, ok := mult[suffix]
	if !ok {
		return 0, fmt.Errorf(
			"duration %q: must end in s/m/h/d (e.g. 30m, 2h, 90s, 7d)", raw)
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("duration %q: prefix must be a positive integer", raw)
	}
	return time.Duration(n) * d, nil
}

func newSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Per-session recording + replay (#285)",
		Long: `Per-session recording + replay (#285).

Sessions are recorded into NDJSON files (one per agent session) when
the proxy runs with --record-sessions-dir. The files are portable +
replayable via the cross-product 'iam-jit session replay <FILE>'
command.

Per [[creates-never-mutates]]: recording is additive (it tees the
existing event stream); these subcommands are read-only over the
recording files.

Per [[self-host-zero-billing-dependency]]: entirely local filesystem;
no phone-home.

File permissions on recording files are 0o600 (owner-read-only) —
recordings contain agent identity + operation details.`,
	}
	cmd.AddCommand(newSessionListCmd())
	cmd.AddCommand(newSessionShowCmd())
	cmd.AddCommand(newSessionExportCmd())
	cmd.AddCommand(newSessionPurgeCmd())
	return cmd
}

func newSessionListCmd() *cobra.Command {
	var (
		dirPath string
		asJSON  bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recorded sessions with event counts + timestamps",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dirPath == "" {
				dirPath = defaultSessionsDir()
			}
			rows, err := audit.ListSessions(dirPath)
			if err != nil {
				return err
			}
			if asJSON {
				out, _ := json.MarshalIndent(rows, "", "  ")
				cmd.OutOrStdout().Write(append(out, '\n'))
				return nil
			}
			if len(rows) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "no recordings in %s\n", dirPath)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"%-40s %-14s %7s %-22s %-22s\n",
				"SESSION_ID", "AGENT", "EVENTS", "START", "END")
			for _, r := range rows {
				sid := r.SessionID
				if r.IsPartial {
					sid += " (partial)"
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"%-40s %-14s %7d %-22s %-22s\n",
					sid, r.AgentName, r.EventCount,
					formatTSMillis(r.StartMS), formatTSMillis(r.EndMS))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dirPath, "dir", "",
		"Recordings dir. Defaults to ~/.dbounce/sessions/.")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit JSON.")
	return cmd
}

func newSessionShowCmd() *cobra.Command {
	var (
		dirPath string
		asJSON  bool
	)
	cmd := &cobra.Command{
		Use:   "show <session-id>",
		Short: "Print a summary + event-count-by-type for one recording",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]
			if dirPath == "" {
				dirPath = defaultSessionsDir()
			}
			meta, events, err := audit.ReadSession(dirPath, sessionID)
			if err != nil {
				return err
			}
			counts := audit.EventCountByType(events)
			summary := map[string]any{
				"session_id":               meta.SessionID,
				"agent_name":               meta.AgentName,
				"bouncer_product":          meta.BouncerProduct,
				"recording_schema_version": meta.RecordingSchemaVersion,
				"recording_started_at":     meta.RecordingStartedAt,
				"event_count":              len(events),
				"events_by_activity":       counts,
			}
			if asJSON {
				out, _ := json.MarshalIndent(summary, "", "  ")
				cmd.OutOrStdout().Write(append(out, '\n'))
				return nil
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "session_id:        %s\n", meta.SessionID)
			fmt.Fprintf(w, "agent_name:        %s\n", meta.AgentName)
			fmt.Fprintf(w, "bouncer_product:   %s\n", meta.BouncerProduct)
			fmt.Fprintf(w, "started_at:        %s\n", meta.RecordingStartedAt)
			fmt.Fprintf(w, "schema_version:    %s\n", meta.RecordingSchemaVersion)
			fmt.Fprintf(w, "event_count:       %d\n", len(events))
			if len(counts) > 0 {
				fmt.Fprintln(w, "events by activity:")
				for k, v := range counts {
					fmt.Fprintf(w, "  %-32s %d\n", k, v)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dirPath, "dir", "", "Recordings dir.")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit JSON.")
	return cmd
}

func newSessionExportCmd() *cobra.Command {
	var (
		dirPath string
		outPath string
	)
	cmd := &cobra.Command{
		Use:   "export <session-id>",
		Short: "Export a session as an OCSF Detection Finding JSON document",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]
			if dirPath == "" {
				dirPath = defaultSessionsDir()
			}
			if outPath == "" {
				return fmt.Errorf("--out is required")
			}
			meta, events, err := audit.ReadSession(dirPath, sessionID)
			if err != nil {
				return err
			}
			finding := audit.DetectionFindingFromSession(meta, events)
			out, err := json.MarshalIndent(finding, "", "  ")
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(outPath, out, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"exported session %s -> %s\n", sessionID, outPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&dirPath, "dir", "", "Recordings dir.")
	cmd.Flags().StringVar(&outPath, "out", "",
		"Output file. The session is wrapped in an OCSF Detection "+
			"Finding envelope (matches #273 investigate-with-claude "+
			"evidence shape).")
	return cmd
}

func newSessionPurgeCmd() *cobra.Command {
	var (
		dirPath   string
		olderThan string
		dryRun    bool
	)
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "Remove recordings older than a threshold",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if olderThan == "" {
				return fmt.Errorf("--older-than is required (e.g. 30d)")
			}
			d, err := parseRetention(olderThan)
			if err != nil {
				return err
			}
			if dirPath == "" {
				dirPath = defaultSessionsDir()
			}
			if dryRun {
				rows, _ := audit.ListSessions(dirPath)
				threshold := time.Now().Add(-d)
				toRemove := []string{}
				for _, r := range rows {
					if r.IsPartial {
						continue
					}
					info, err := os.Stat(r.Path)
					if err != nil {
						continue
					}
					if info.ModTime().Before(threshold) {
						toRemove = append(toRemove, r.Path)
					}
				}
				if len(toRemove) == 0 {
					fmt.Fprintf(cmd.OutOrStdout(),
						"no recordings older than %s in %s\n",
						olderThan, dirPath)
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"would remove %d recording(s) older than %s:\n",
					len(toRemove), olderThan)
				for _, p := range toRemove {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", p)
				}
				return nil
			}
			removed, err := audit.PurgeOlderThan(dirPath, d, time.Now())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"removed %d recording(s) from %s\n",
				len(removed), dirPath)
			for _, p := range removed {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", p)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dirPath, "dir", "", "Recordings dir.")
	cmd.Flags().StringVar(&olderThan, "older-than", "",
		"Age threshold (e.g. '30d', '7d', '12h').")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"List files that would be removed without deleting.")
	return cmd
}

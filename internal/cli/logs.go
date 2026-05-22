// Package cli — #311 / §A10 `dbounce logs` + `dbounce doctor logs`
// subcommands for audit-log retention + integrity.
//
// Mirrors the cross-product surface (ibounce, kbounce, gbounce); the
// runbook in iam-roles/docs/LOG-RETENTION.md is the source of truth.

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/audit"
)

func defaultLogDir(auditLogPath string) string {
	if auditLogPath != "" {
		abs, err := filepath.Abs(auditLogPath)
		if err == nil {
			return filepath.Dir(abs)
		}
		return filepath.Dir(auditLogPath)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".dbounce", "audit")
}

func newLogsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Manage the audit log: rotation, retention, integrity",
		Args:  cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("logs", cmd)
	cmd.AddCommand(newLogsPurgeCmd())
	cmd.AddCommand(newLogsArchiveCmd())
	cmd.AddCommand(newLogsVerifyCmd())
	return cmd
}

func newLogsPurgeCmd() *cobra.Command {
	var (
		auditLog  string
		olderThan string
		yes       bool
	)
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "Delete rotated archives older than DURATION",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := audit.ParseLogDuration(olderThan)
			if err != nil {
				return fmt.Errorf("--older-than: %w", err)
			}
			dir := defaultLogDir(auditLog)
			if !yes {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"About to purge rotated archives older than %s in %s.\n", olderThan, dir)
				fmt.Fprintln(cmd.ErrOrStderr(), "Pass --yes to confirm.")
				return fmt.Errorf("confirmation required")
			}
			days := int(d.Hours() / 24)
			if days < 1 {
				days = 1
			}
			removed, err := audit.PurgeLogsOlderThan(dir, days, days, time.Now())
			if err != nil {
				return err
			}
			if len(removed) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no archives matched)")
				return nil
			}
			for _, p := range removed {
				fmt.Fprintln(cmd.OutOrStdout(), p)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "-- removed %d file(s)\n", len(removed))
			return nil
		},
	}
	cmd.Flags().StringVar(&auditLog, "audit-log", "", "Path to the active audit.jsonl.")
	cmd.Flags().StringVar(&olderThan, "older-than", "", "Duration threshold (7d, 24h, 30m).")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip confirmation prompt.")
	_ = cmd.MarkFlagRequired("older-than")
	return cmd
}

func newLogsArchiveCmd() *cobra.Command {
	var (
		auditLog      string
		out           string
		excludeActive bool
	)
	cmd := &cobra.Command{
		Use:   "archive",
		Short: "Bundle all audit files into a tar.gz",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir := defaultLogDir(auditLog)
			if err := audit.ArchiveLogs(dir, out, !excludeActive); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), out)
			return nil
		},
	}
	cmd.Flags().StringVar(&auditLog, "audit-log", "", "Path to the active audit.jsonl.")
	cmd.Flags().StringVar(&out, "out", "", "Destination tar.gz path.")
	cmd.Flags().BoolVar(&excludeActive, "exclude-active", false, "Skip the live audit.jsonl/audit.db.")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func newLogsVerifyCmd() *cobra.Command {
	var (
		auditLog string
		asJSON   bool
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Per-file integrity check (gzip + JSONL)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir := defaultLogDir(auditLog)
			res, err := audit.VerifyIntegrity(dir)
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(res)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "checked %d file(s) in %s\n", res.FilesChecked, dir)
			if res.OK {
				fmt.Fprintln(cmd.OutOrStdout(), "OK")
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), "FAILURES:")
			for _, f := range res.Failures {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s\n", f.Path, f.Reason)
			}
			return fmt.Errorf("integrity check failed (%d failure(s))", len(res.Failures))
		},
	}
	cmd.Flags().StringVar(&auditLog, "audit-log", "", "Path to the active audit.jsonl.")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit JSON.")
	return cmd
}

// DoctorLogsReport is the cross-product JSON shape.
type DoctorLogsReport struct {
	LogDir string                 `json:"log_dir"`
	OK     bool                   `json:"ok"`
	Checks map[string]interface{} `json:"checks"`
}

func newDoctorLogsCmd() *cobra.Command {
	var (
		auditLog   string
		maxAgeDays int
		warnPct    int
		critPct    int
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Run audit-log integrity + freshness + retention + disk checks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir := defaultLogDir(auditLog)
			report := DoctorLogsReport{LogDir: dir, OK: true, Checks: map[string]interface{}{}}

			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				integ, err := audit.VerifyIntegrity(dir)
				if err != nil {
					report.OK = false
					report.Checks["integrity"] = map[string]any{"ok": false, "reason": err.Error()}
				} else {
					report.Checks["integrity"] = integ
					if !integ.OK {
						report.OK = false
					}
				}
			} else {
				report.OK = false
				report.Checks["integrity"] = map[string]any{
					"ok": false, "reason": fmt.Sprintf("audit dir %s does not exist", dir),
				}
			}

			if info, err := os.Stat(dir); err == nil && info.IsDir() {
				entries, _ := os.ReadDir(dir)
				type ageEntry struct {
					name string
					mod  time.Time
				}
				var archives []ageEntry
				var active *ageEntry
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					n := e.Name()
					inf, err := e.Info()
					if err != nil {
						continue
					}
					if n == "audit.jsonl" {
						active = &ageEntry{name: filepath.Join(dir, n), mod: inf.ModTime()}
						continue
					}
					if len(n) > 14 && n[:6] == "audit-" && len(n) > 9 &&
						n[len(n)-9:] == ".jsonl.gz" {
						archives = append(archives, ageEntry{name: filepath.Join(dir, n), mod: inf.ModTime()})
					}
				}
				sort.Slice(archives, func(i, j int) bool {
					return archives[i].mod.After(archives[j].mod)
				})
				if len(archives) > 0 {
					ageDays := time.Since(archives[0].mod).Hours() / 24
					ok := ageDays <= float64(maxAgeDays)
					report.Checks["freshness"] = map[string]any{
						"ok": ok, "most_recent": archives[0].name,
						"age_days": roundFloat(ageDays, 2), "threshold_days": maxAgeDays,
					}
					if !ok {
						report.OK = false
					}
				} else if active != nil {
					ageDays := time.Since(active.mod).Hours() / 24
					report.Checks["freshness"] = map[string]any{
						"ok": true, "most_recent": active.name,
						"age_days": roundFloat(ageDays, 2), "threshold_days": maxAgeDays,
						"note": "no rotated archives yet (active file present)",
					}
				} else {
					report.OK = false
					report.Checks["freshness"] = map[string]any{
						"ok": false, "reason": "no audit files present",
					}
				}
			}

			disk, derr := audit.GetDiskStatus(dir, warnPct, critPct)
			if derr == nil {
				report.Checks["disk"] = disk
				if disk.Status == "critical" {
					report.OK = false
				}
			} else {
				report.Checks["disk"] = map[string]any{"ok": false, "reason": derr.Error()}
				report.OK = false
			}

			if asJSON {
				_ = json.NewEncoder(cmd.OutOrStdout()).Encode(report)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "doctor logs — %s\n", dir)
				fmt.Fprintln(cmd.OutOrStdout(), "========================================")
				for _, name := range []string{"integrity", "freshness", "disk"} {
					payload, ok := report.Checks[name]
					if !ok {
						continue
					}
					b, _ := json.Marshal(payload)
					status := "OK"
					if m, isMap := payload.(map[string]any); isMap {
						if v, ok := m["ok"].(bool); ok && !v {
							status = "FAIL"
						}
					}
					if name == "disk" {
						if d, ok := payload.(audit.DiskStatus); ok {
							status = upperString(d.Status)
						}
					}
					if name == "integrity" {
						if r, ok := payload.(audit.IntegrityResult); ok && !r.OK {
							status = "FAIL"
						}
					}
					fmt.Fprintf(cmd.OutOrStdout(), "  [%8s] %s: %s\n", status, name, b)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "========================================")
				if report.OK {
					fmt.Fprintln(cmd.OutOrStdout(), "OVERALL: OK")
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "OVERALL: FAIL")
				}
			}
			if !report.OK {
				return fmt.Errorf("doctor logs failed")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&auditLog, "audit-log", "", "Path to the active audit.jsonl.")
	cmd.Flags().IntVar(&maxAgeDays, "max-age-days", 7, "Freshness threshold.")
	cmd.Flags().IntVar(&warnPct, "warn-pct", audit.DefaultDiskWarnPercent, "Disk warn threshold (%).")
	cmd.Flags().IntVar(&critPct, "crit-pct", audit.DefaultDiskCritPercent, "Disk critical threshold (%).")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit JSON.")
	return cmd
}

func upperString(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out[i] = c
	}
	return string(out)
}

func roundFloat(f float64, places int) float64 {
	pow := 1.0
	for i := 0; i < places; i++ {
		pow *= 10
	}
	return float64(int64(f*pow+0.5)) / pow
}

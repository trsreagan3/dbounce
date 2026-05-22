// Package audit — #311 / §A10 rotation, retention, and recovery.
//
// Each bouncer writes a JSONL audit log + SQLite audit DB; without
// rotation they grow unbounded and silently fill the disk. Per
// [[self-host-zero-billing-dependency]] the audit log IS the
// compliance value and cannot silently fail. This file ships the
// dbounce-side of the cross-product log-retention story; flag names
// and behaviour match the sibling products (ibounce, kbounce,
// gbounce) — the cross-product runbook in
// iam-roles/docs/LOG-RETENTION.md is the source of truth.

package audit

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Defaults match the cross-product table in
// iam-roles/docs/LOG-RETENTION.md.
const (
	DefaultMaxSizeMB        = 100
	DefaultMaxAgeDays       = 7
	DefaultDBRetentionDays  = 30
	DefaultDiskWarnPercent  = 85
	DefaultDiskCritPercent  = 95
	rotatedJSONLPattern     = "audit-%s.jsonl.gz"
	rotatedDBPattern        = "audit-%s.db.gz"
	rotationTimestampFormat = "2006-01-02-150405"
	dbDailyFormat           = "2006-01-02"
)

// DiskStatus is the /healthz payload for the audit-log subsystem.
type DiskStatus struct {
	Status  string  `json:"status"`
	Reason  string  `json:"reason"`
	UsedPct float64 `json:"used_pct"`
	Path    string  `json:"path"`
}

// IntegrityResult is the outcome of VerifyIntegrity.
type IntegrityResult struct {
	FilesChecked int                `json:"files_checked"`
	OK           bool               `json:"ok"`
	Failures     []IntegrityFailure `json:"failures"`
}

// IntegrityFailure carries a single corrupt-file finding.
type IntegrityFailure struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ShouldRotateBySize returns true iff the file exceeds maxMB MB.
func ShouldRotateBySize(path string, maxMB int64) bool {
	if maxMB <= 0 {
		return false
	}
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return st.Size() > maxMB*1024*1024
}

// ShouldRotateByAge returns true iff the mtime is older than maxDays.
func ShouldRotateByAge(path string, maxDays int, now time.Time) bool {
	if maxDays <= 0 {
		return false
	}
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	cutoff := now.Add(-time.Duration(maxDays) * 24 * time.Hour)
	return st.ModTime().Before(cutoff)
}

// Rotate atomically moves the active log + gzips the archive.
func Rotate(path string, now time.Time) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if st.Size() == 0 {
		return "", nil
	}
	dir := filepath.Dir(path)
	ts := now.UTC().Format(rotationTimestampFormat)
	archive := filepath.Join(dir, fmt.Sprintf(rotatedJSONLPattern, ts))
	rotating := path + ".rotating"
	if _, err := os.Stat(rotating); err == nil {
		_ = os.Remove(rotating)
	}
	if err := os.Rename(path, rotating); err != nil {
		return "", fmt.Errorf("rotate rename: %w", err)
	}
	if err := gzipFile(rotating, archive); err != nil {
		return "", fmt.Errorf("rotate gzip: %w", err)
	}
	_ = os.Remove(rotating)
	return archive, nil
}

func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		return err
	}
	return gz.Close()
}

// RecoverPartialTail truncates an incomplete final JSONL line.
// Returns the number of bytes trimmed.
func RecoverPartialTail(path string) (int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	if st.Size() == 0 {
		return 0, nil
	}
	const window = 64 * 1024
	tailWindow := st.Size()
	if tailWindow > window {
		tailWindow = window
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	tail := make([]byte, tailWindow)
	if _, err := f.ReadAt(tail, st.Size()-tailWindow); err != nil {
		return 0, err
	}
	nl := lastByteIndex(tail, '\n')
	if nl == -1 {
		var v any
		if json.Unmarshal(tail, &v) == nil {
			return 0, nil
		}
		return 0, nil
	}
	lastLine := tail[nl+1:]
	if len(lastLine) == 0 {
		return 0, nil
	}
	var v any
	if json.Unmarshal(lastLine, &v) == nil {
		return 0, nil
	}
	trimmed := int64(len(lastLine))
	if err := f.Truncate(st.Size() - trimmed); err != nil {
		return 0, err
	}
	return trimmed, nil
}

func lastByteIndex(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// PurgeLogsOlderThan deletes rotated archives older than the per-
// type retention threshold. Never touches the active audit.jsonl or
// audit.db. Distinct from recorder.PurgeOlderThan which targets
// per-session NDJSON files.
func PurgeLogsOlderThan(logDir string, jsonlMaxAgeDays, dbMaxAgeDays int, now time.Time) ([]string, error) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var removed []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		var maxAge int
		switch {
		case strings.HasPrefix(n, "audit-") && strings.HasSuffix(n, ".jsonl.gz"):
			maxAge = jsonlMaxAgeDays
		case strings.HasPrefix(n, "audit-") && (strings.HasSuffix(n, ".db.gz") || strings.HasSuffix(n, ".db")):
			maxAge = dbMaxAgeDays
		default:
			continue
		}
		if maxAge <= 0 {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		cutoff := now.Add(-time.Duration(maxAge) * 24 * time.Hour)
		if info.ModTime().Before(cutoff) {
			full := filepath.Join(logDir, n)
			if err := os.Remove(full); err != nil {
				continue
			}
			removed = append(removed, full)
		}
	}
	sort.Strings(removed)
	return removed, nil
}

// ArchiveLogs bundles audit files into a tar.gz at outPath.
func ArchiveLogs(logDir, outPath string, includeActive bool) error {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		isAudit := strings.HasPrefix(n, "audit") && (strings.HasSuffix(n, ".jsonl") ||
			strings.HasSuffix(n, ".jsonl.gz") ||
			strings.HasSuffix(n, ".db") ||
			strings.HasSuffix(n, ".db.gz"))
		if !isAudit {
			continue
		}
		if !includeActive && (n == "audit.jsonl" || n == "audit.db") {
			continue
		}
		if err := addTarFile(tw, filepath.Join(logDir, n), n); err != nil {
			return err
		}
	}
	return nil
}

func addTarFile(tw *tar.Writer, src, arcname string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:    arcname,
		Mode:    int64(st.Mode().Perm()),
		Size:    st.Size(),
		ModTime: st.ModTime(),
	}); err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

// VerifyIntegrity walks logDir checking gzip + JSONL.
func VerifyIntegrity(logDir string) (IntegrityResult, error) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return IntegrityResult{OK: true}, nil
		}
		return IntegrityResult{}, err
	}
	res := IntegrityResult{OK: true}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		full := filepath.Join(logDir, n)
		switch {
		case strings.HasPrefix(n, "audit-") && strings.HasSuffix(n, ".jsonl.gz"):
			res.FilesChecked++
			if err := verifyGzipJSONL(full); err != nil {
				res.OK = false
				res.Failures = append(res.Failures, IntegrityFailure{Path: full, Reason: err.Error()})
			}
		case n == "audit.jsonl":
			res.FilesChecked++
			if err := verifyActiveJSONL(full); err != nil {
				res.OK = false
				res.Failures = append(res.Failures, IntegrityFailure{Path: full, Reason: err.Error()})
			}
		}
	}
	return res, nil
}

func verifyGzipJSONL(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	dec := json.NewDecoder(gz)
	for {
		var v any
		if err := dec.Decode(&v); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func verifyActiveJSONL(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lastNl := -1
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '\n' {
			lastNl = i
			break
		}
	}
	if lastNl == -1 {
		return nil
	}
	for _, line := range splitNewlines(data[:lastNl+1]) {
		if len(line) == 0 {
			continue
		}
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			return err
		}
	}
	return nil
}

func splitNewlines(b []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			lines = append(lines, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, b[start:])
	}
	return lines
}

// GetDiskStatus inspects the filesystem hosting path.
func GetDiskStatus(path string, warnPct, critPct int) (DiskStatus, error) {
	target := path
	if _, err := os.Stat(path); err != nil {
		target = filepath.Dir(path)
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(target, &st); err != nil {
		return DiskStatus{Status: "degraded", Reason: fmt.Sprintf("statfs: %v", err), Path: target}, nil
	}
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	if total == 0 {
		return DiskStatus{Status: "degraded", Reason: "disk total is zero", Path: target}, nil
	}
	used := total - free
	usedPct := 100.0 * float64(used) / float64(total)
	return classifyDiskStatus(usedPct, warnPct, critPct, target), nil
}

func classifyDiskStatus(usedPct float64, warnPct, critPct int, path string) DiskStatus {
	if usedPct >= float64(critPct) {
		return DiskStatus{Status: "critical", Reason: fmt.Sprintf("disk usage %.1f%% >= critical threshold %d%%", usedPct, critPct), UsedPct: usedPct, Path: path}
	}
	if usedPct >= float64(warnPct) {
		return DiskStatus{Status: "degraded", Reason: fmt.Sprintf("disk usage %.1f%% >= warn threshold %d%%", usedPct, warnPct), UsedPct: usedPct, Path: path}
	}
	return DiskStatus{Status: "ok", Reason: "disk usage within thresholds", UsedPct: usedPct, Path: path}
}

// ClassifyDiskStatusForTest exposes the threshold logic to tests.
func ClassifyDiskStatusForTest(usedPct float64, warnPct, critPct int, path string) DiskStatus {
	return classifyDiskStatus(usedPct, warnPct, critPct, path)
}

// ParseLogDuration parses 7d / 24h / 30m / 60s; bare integer = days.
func ParseLogDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, errors.New("empty duration")
	}
	last := s[len(s)-1]
	switch last {
	case 'd':
		n, err := atoiSimple(s[:len(s)-1])
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	case 'h', 'm', 's':
		return time.ParseDuration(s)
	}
	n, err := atoiSimple(s)
	if err != nil {
		return 0, err
	}
	return time.Duration(n) * 24 * time.Hour, nil
}

func atoiSimple(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty integer")
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not an integer: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

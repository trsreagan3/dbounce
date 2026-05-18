// SQLite restore helpers for #279 — `dbounce restore`.
//
// Restore is intentionally a wholesale file-level replacement of the
// destination database, NOT a merge: an operator who wants merge
// semantics uses `dbounce config import`. Two reasons:
//
//   1. The decisions audit table is append-only + the SchemaVersion-
//      bound trigger refuses UPDATE / DELETE per MED-D8-07. A merge
//      flow that re-INSERTs rows from a backup would either (a) hit
//      PRIMARY-KEY collisions on the row-id columns or (b) leave the
//      destination with rewritten ids that confuse the FK from
//      pending_prompts.decision_id. A file-level replace sidesteps
//      both.
//
//   2. A restore is a DR action — the operator has accepted some loss
//      already (they wouldn't run restore otherwise) + wants the
//      backup file's state, period. File-level replace IS the
//      DR-flow's expected semantics.
//
// Validation gates the destructive copy:
//
//   - schema_version MUST match exactly. A cross-schema restore would
//     leave the destination running against tables the binary doesn't
//     know how to read. Refuse hard (--force does NOT override this —
//     cross-schema migration is the `dbounce migrate` story, out of
//     scope for #279).
//
//   - dbounce_version compared informatively; mismatch is a WARNING.
//     --force is the override for the cross-version restore case (a
//     v1.0.5 backup restored onto a v1.1.0 binary).
//
//   - destination DB must be empty OR --force must be passed. "Empty"
//     means: file does not exist, OR file exists with zero rows in
//     every user table. A fresh `dbounce` install satisfies the latter
//     so day-1 DR is friction-free.
//
//   - dbounce MUST NOT be running. A best-effort probe dials the
//     default mgmt + wire ports + refuses with an actionable message
//     when either is alive. The probe is intentionally a TCP-only
//     SYN+RST (no HTTP / no SQL handshake) so the probe itself cannot
//     accidentally write to the live DB.
//
// Per [[creates-never-mutates]]: restore is the one CLI surface in
// dbounce that DOES mutate an existing DB — the destructive verb is
// gated by an explicit subcommand name + the --force semantics + the
// running-process probe. The probe + the empty-DB check together close
// the "fat-finger restore over a populated DB" failure mode.

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// RestoreOptions controls the validation gates `Restore` applies before
// performing the destructive copy. Defaults are STRICT — the caller
// must explicitly opt into each override.
type RestoreOptions struct {
	// Force overrides the non-empty-destination refusal + the
	// dbounce_version-mismatch warning. Does NOT override the
	// schema_version-mismatch refusal (cross-schema migration is the
	// `dbounce migrate` story, out of scope for #279).
	Force bool

	// DbounceVersion is the running binary's version string. Compared
	// against the backup's dbounce_version metadata to surface the
	// cross-version restore warning. When empty, the comparison is
	// skipped (no warning).
	DbounceVersion string

	// ProbePorts is the list of (host, port) pairs the running-process
	// probe dials. Defaults to the dbounce defaults
	// (127.0.0.1:5433 + 127.0.0.1:8768) when nil. Tests use this to
	// pin the probe at a known port; production passes nil.
	ProbePorts []HostPort

	// ProbeTimeout caps each probe dial. Defaults to 200ms when zero.
	// Short enough that the probe doesn't dominate the restore latency;
	// long enough that loopback connect-times don't false-negative.
	ProbeTimeout time.Duration
}

// HostPort is one TCP probe target. Exported so the CLI layer can
// build the default list using its own port constants.
type HostPort struct {
	Host string
	Port int
}

// RestoreResult is the post-restore summary the caller surfaces to the
// operator: which tables were restored, the row counts, the destination
// file's sha256. The CLI prints this; tests assert against it.
type RestoreResult struct {
	DstPath   string
	SHA256    string
	RowCounts map[string]int64
	// TableNames is the sorted user-table list so the CLI output is
	// deterministic. Includes dbounce_backup_metadata (preserved from
	// the backup file so the restored DB carries its own provenance).
	TableNames []string
}

// ErrSchemaVersionMismatch is returned when the backup's schema_version
// does NOT match the running binary's SchemaVersion. NOT overridable
// via Force — cross-schema migration is `dbounce migrate` territory.
var ErrSchemaVersionMismatch = errors.New("dbounce: restore: schema_version mismatch (cross-schema restore refused)")

// ErrDestinationNotEmpty is returned when the destination DB exists +
// has any user-table rows + Force was not set.
var ErrDestinationNotEmpty = errors.New("dbounce: restore: destination database is not empty (pass --force to overwrite)")

// ErrDbounceRunning is returned when the probe finds a live dbounce
// process at one of the probe ports. The message includes the port the
// probe hit so the operator can `kill` the right process.
var ErrDbounceRunning = errors.New("dbounce: restore: dbounce appears to be running; stop it first")

// ErrNotABackupFile is returned when the source file is a SQLite
// database but missing the dbounce_backup_metadata table.
var ErrNotABackupFile = errors.New("dbounce: restore: source is not a dbounce backup file (missing dbounce_backup_metadata)")

// VersionMismatchWarning is the message Restore surfaces (NOT as an
// error) when the backup's dbounce_version differs from the running
// binary's. The caller (CLI) prints this to stderr.
type VersionMismatchWarning struct {
	BackupVersion  string
	RunningVersion string
}

func (w VersionMismatchWarning) String() string {
	return fmt.Sprintf(
		"dbounce: restore: WARNING dbounce_version mismatch — "+
			"backup was created by dbounce %q, running binary is %q. "+
			"Continuing under --force; this is supported but you should "+
			"verify the running binary can read the backup's row shapes.",
		w.BackupVersion, w.RunningVersion)
}

// Restore copies srcPath onto dstPath, replacing whatever was at
// dstPath. Validates per RestoreOptions BEFORE the destructive copy.
// Returns the post-restore summary on success.
//
// The Restore function deliberately does NOT take a *Store receiver —
// the destination DB may not exist yet at call time, and the running-
// process probe would itself open + lock the destination file. The
// caller-supplied dstPath is the single source of truth.
func Restore(srcPath, dstPath string, opt RestoreOptions) (*RestoreResult, *VersionMismatchWarning, error) {
	if srcPath == "" {
		return nil, nil, errors.New("dbounce: restore: source path required")
	}
	if dstPath == "" {
		return nil, nil, errors.New("dbounce: restore: destination path required")
	}
	if _, err := os.Stat(srcPath); err != nil {
		return nil, nil, fmt.Errorf("dbounce: restore: source %q not readable: %w", srcPath, err)
	}

	meta, err := ReadBackupMetadata(srcPath)
	if err != nil {
		// ReadBackupMetadata returns a friendly message for the
		// "missing metadata table" case; surface unchanged so the
		// caller can distinguish from a hard SQL error.
		return nil, nil, err
	}
	if meta == nil {
		return nil, nil, ErrNotABackupFile
	}

	// Gate 1 (HARD): schema_version match. Not overridable by Force.
	if meta.SchemaVersion != SchemaVersion {
		return nil, nil, fmt.Errorf(
			"%w: backup schema_version=%d, running binary expects schema_version=%d. "+
				"Cross-schema migration is `dbounce migrate` territory (out of scope for #279)",
			ErrSchemaVersionMismatch, meta.SchemaVersion, SchemaVersion)
	}

	// Gate 2 (soft): dbounce_version comparison surfaces a warning when
	// mismatched. Force is REQUIRED to proceed past a mismatch — same
	// posture as ibounce + kbounce's restore.
	var warn *VersionMismatchWarning
	if opt.DbounceVersion != "" && meta.DbounceVersion != "" &&
		meta.DbounceVersion != opt.DbounceVersion {
		warn = &VersionMismatchWarning{
			BackupVersion:  meta.DbounceVersion,
			RunningVersion: opt.DbounceVersion,
		}
		if !opt.Force {
			return nil, warn, fmt.Errorf(
				"dbounce: restore: dbounce_version mismatch (backup=%q, running=%q); "+
					"pass --force to proceed (cross-version restores are supported "+
					"within the same schema_version)",
				meta.DbounceVersion, opt.DbounceVersion)
		}
	}

	// Gate 3: destination must be empty OR Force.
	dstHasData, err := destinationHasData(dstPath)
	if err != nil {
		return nil, warn, err
	}
	if dstHasData && !opt.Force {
		return nil, warn, fmt.Errorf("%w: destination=%q", ErrDestinationNotEmpty, dstPath)
	}

	// Gate 4: running-process probe. Per the #279 spec: refuse if
	// dbounce is running (probe loopback wire/mgmt ports).
	probes := opt.ProbePorts
	if probes == nil {
		probes = DefaultProbePorts()
	}
	timeout := opt.ProbeTimeout
	if timeout <= 0 {
		timeout = 200 * time.Millisecond
	}
	if hp, alive := probeRunning(probes, timeout); alive {
		return nil, warn, fmt.Errorf(
			"%w (probe hit %s:%d). Stop the running `dbounce run` process + retry. "+
				"If the port is held by an unrelated process you can pass --probe-skip "+
				"to bypass this check.",
			ErrDbounceRunning, hp.Host, hp.Port)
	}

	// All gates pass — perform the destructive copy via a temp file on
	// the destination's filesystem so the rename is atomic.
	if dir := filepath.Dir(dstPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, warn, fmt.Errorf("dbounce: restore: mkdir %q: %w", dir, err)
		}
	}
	tmpPath := dstPath + ".restore.tmp"
	_ = os.Remove(tmpPath)
	if err := copyFile(srcPath, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, warn, fmt.Errorf("dbounce: restore: copy to tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return nil, warn, fmt.Errorf("dbounce: restore: chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, warn, fmt.Errorf("dbounce: restore: rename tmp to dst: %w", err)
	}

	// Post-restore: open the destination to bump the schema-version
	// stamp (if the backup was created at a lower SchemaVersion we
	// already refused; here we may need to insert the
	// schema_version row when the backup file's original stamp got
	// pruned). The Store.migrate path is idempotent + handles both
	// fresh + existing rows.
	stamped, err := Open(dstPath)
	if err != nil {
		return nil, warn, fmt.Errorf("dbounce: restore: stamp schema_version on restored db: %w", err)
	}
	_ = stamped.Close()

	counts, err := CountRowsByTable(dstPath)
	if err != nil {
		return nil, warn, err
	}
	sum, err := FileSHA256(dstPath)
	if err != nil {
		return nil, warn, err
	}
	names := make([]string, 0, len(counts))
	for k := range counts {
		names = append(names, k)
	}
	sort.Strings(names)
	return &RestoreResult{
		DstPath:    dstPath,
		SHA256:     sum,
		RowCounts:  counts,
		TableNames: names,
	}, warn, nil
}

// DefaultProbePorts is the loopback wire + mgmt port pair `dbounce run`
// binds by default. Exposed so a caller (the CLI) can extend it with a
// user-supplied --port pair without re-declaring the defaults.
func DefaultProbePorts() []HostPort {
	return []HostPort{
		{Host: "127.0.0.1", Port: 5433}, // wire-protocol listener default
		{Host: "127.0.0.1", Port: 8768}, // management /healthz default
	}
}

// destinationHasData returns true when dstPath exists + at least one
// user table has rows. A non-existent file returns false (empty DB =
// fresh install case). A file that is not a SQLite database returns
// an error.
func destinationHasData(dstPath string) (bool, error) {
	info, err := os.Stat(dstPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("dbounce: restore: stat dst: %w", err)
	}
	if info.Size() == 0 {
		// Zero-byte file is treated as empty — sqlite would refuse it
		// anyway; the restore replaces it cleanly.
		return false, nil
	}
	db, err := sql.Open("sqlite",
		"file:"+dstPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return false, fmt.Errorf("dbounce: restore: probe dst: %w", err)
	}
	defer db.Close()
	rows, err := db.Query(
		`SELECT name FROM sqlite_master WHERE type='table'
		 AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		// File exists but isn't a SQLite db; treat as data-present so
		// Force is required (we don't want to silently overwrite an
		// unrelated file at this path).
		return true, nil //nolint:nilerr // intentional: surface as not-empty
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return false, fmt.Errorf("dbounce: restore: scan dst table: %w", err)
		}
		var c int64
		if err := db.QueryRow("SELECT COUNT(*) FROM " + n).Scan(&c); err != nil {
			// Table exists in master but COUNT failed — probably a
			// schema mismatch. Treat as data-present so Force is
			// required.
			return true, nil //nolint:nilerr // intentional: conservative
		}
		if c > 0 {
			return true, nil
		}
	}
	return false, nil
}

// probeRunning dials each probe target with a short timeout. Returns
// the first target that accepted a connection + true; (zero, false)
// when none did. Closes every successful dial immediately — the probe
// is presence-only, not a handshake.
func probeRunning(targets []HostPort, timeout time.Duration) (HostPort, bool) {
	for _, hp := range targets {
		// JoinHostPort properly bracket-wraps IPv6 literals; using
		// Sprintf("%s:%d", ...) would mangle a "::1" host.
		addr := net.JoinHostPort(hp.Host, strconv.Itoa(hp.Port))
		c, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			continue
		}
		_ = c.Close()
		return hp, true
	}
	return HostPort{}, false
}

// copyFile copies src to dst byte-for-byte. We use a fresh file (not
// os.Link) so a cross-filesystem restore works + so the destination
// file is independent of the backup file's storage (the operator may
// want to delete the backup after a successful restore).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create dst: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy: %w", err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return fmt.Errorf("fsync dst: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close dst: %w", err)
	}
	return nil
}

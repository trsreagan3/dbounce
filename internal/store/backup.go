// SQLite backup helpers for #279 — `dbounce backup` + `dbounce
// restore`.
//
// Backup uses SQLite's `VACUUM INTO` statement: a one-shot atomic
// online-backup primitive that copies the live database into a new file
// at PATH while concurrent writers continue against the source. Two
// reasons for choosing VACUUM INTO over the lower-level backup API
// (sqlite3_backup_init / _step / _finish):
//
//  1. modernc.org/sqlite — dbounce's pure-Go SQLite driver — does not
//     expose the backup-API as a typed Go surface. The C-level entry
//     points exist inside the driver's libc shim but binding them
//     correctly from Go would require dropping to unsafe pointers +
//     reasoning about the driver's connection-handle lifetime. VACUUM
//     INTO is one SQL statement against the existing *sql.DB; it
//     composes cleanly with the existing pool + transaction model.
//
//  2. VACUUM INTO is atomic from the reader's perspective: the
//     destination file is created + populated inside a single
//     SQLite-side transaction. If the process dies mid-VACUUM, the
//     destination file is removed before any other connection sees it.
//     Critical for the [[creates-never-mutates]] read-only-backup
//     guarantee.
//
// Volume-table exclusion: the spec defaults to skipping the two high-
// volume tables (pending_audit_events, pending_prompts). VACUUM INTO
// can't be told to omit tables, so the flow is:
//
//   1. VACUUM INTO TMP                       — full copy
//   2. OPEN TMP                              — second handle
//   3. DELETE FROM <excluded> on TMP         — drop opt-out tables
//   4. VACUUM on TMP                         — reclaim freed pages so
//                                              the on-disk file is the
//                                              size of the kept data,
//                                              not source-size
//   5. INSERT INTO dbounce_backup_metadata   — provenance
//   6. mv TMP → PATH                         — atomic rename
//
// The dbounce_backup_metadata table is created on the destination
// (NOT the source) so the live database never grows a one-row admin
// table just because the operator ran a backup.
//
// Cross-product alignment per [[cross-product-agent-parity]]: kbounce
// + ibounce ship the same metadata-table shape (with their own table
// names — kbounce_backup_metadata / iam_jit_backup_metadata) +
// the same VACUUM INTO + delete-excluded-tables flow.

package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// backupMetadataTable is the on-disk table embedded in every dbounce
// backup file carrying the provenance fields restore validates. Named
// `dbounce_backup_metadata` per the cross-product naming convention
// (kbounce ships `kbounce_backup_metadata`, ibounce ships
// `iam_jit_backup_metadata`).
const backupMetadataTable = "dbounce_backup_metadata"

// BackupOptions controls which optional tables ship in the backup file
// + carries the version string the CLI stamps into the metadata table.
// Defaults exclude the two high-volume tables (pending_audit_events,
// pending_prompts) per the #279 spec.
type BackupOptions struct {
	// IncludeAudit ships the pending_audit_events table in the backup
	// file. Default false — the table is an ephemeral cross-process
	// queue + typically near-empty, but for DR scenarios where the
	// operator wants the in-flight events preserved across a restore
	// they can opt in.
	IncludeAudit bool

	// IncludePrompts ships the pending_prompts table in the backup
	// file. Default false — pending prompts are bound to in-flight
	// proxy goroutines that won't survive a restore anyway, so the
	// table is typically excluded.
	IncludePrompts bool

	// DbounceVersion is the version string the CLI stamps into the
	// metadata table. Captured at the CLI layer (the `version`
	// package-level var in internal/cli) + passed through here so the
	// store package stays version-free.
	DbounceVersion string

	// Hostname is the source-host identifier the metadata table
	// records — captured as the sha256[:12] of the actual hostname so
	// the backup file is auditable ("this came from production-leader-
	// 02") without leaking the literal hostname into a file the
	// operator may share for support purposes.
	Hostname string

	// Now is the timestamp the metadata table records as created_at.
	// Pluggable for deterministic tests; defaults to time.Now() when
	// zero.
	Now time.Time
}

// BackupMetadata is the in-memory shape of the dbounce_backup_metadata
// row. The Backup function returns it for caller convenience (the CLI
// prints the included flags + created_at + hostname-hash to the
// operator); Restore reads its persisted form from the source file.
type BackupMetadata struct {
	DbounceVersion     string
	CreatedAt          time.Time
	SourceHostnameHash string
	SchemaVersion      int
	IncludedAudit      bool
	IncludedPrompts    bool
}

// excludedTablesFor returns the list of tables to DELETE from the
// VACUUM-INTO output when the operator did NOT opt them in. Centralized
// here so the backup + restore paths agree on the "high volume" set.
func excludedTablesFor(opt BackupOptions) []string {
	var out []string
	if !opt.IncludeAudit {
		out = append(out, "pending_audit_events")
	}
	if !opt.IncludePrompts {
		out = append(out, "pending_prompts")
	}
	return out
}

// Backup writes an online SQLite backup of the live store to dstPath +
// returns the metadata embedded in the new file. The destination file
// is created with 0o600 (mirrors the source database's privacy
// posture) + parent directories are created with 0o700.
//
// The flow tolerates a non-empty parent directory but REFUSES to
// overwrite an existing dstPath — the CLI is expected to pick a fresh
// timestamped filename per invocation, and silently clobbering an
// older backup would defeat the point of holding multiple snapshots.
func (s *Store) Backup(dstPath string, opt BackupOptions) (*BackupMetadata, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("dbounce: backup: store not open")
	}
	if dstPath == "" {
		return nil, errors.New("dbounce: backup: destination path required")
	}
	if _, err := os.Stat(dstPath); err == nil {
		return nil, fmt.Errorf("dbounce: backup: refusing to overwrite existing file %q", dstPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("dbounce: backup: stat %q: %w", dstPath, err)
	}
	if dir := filepath.Dir(dstPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("dbounce: backup: mkdir %q: %w", dir, err)
		}
	}

	// Resolve the metadata fields up-front so a Now-stamping change
	// during the VACUUM doesn't drift the persisted value.
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	meta := BackupMetadata{
		DbounceVersion:     opt.DbounceVersion,
		CreatedAt:          opt.Now.UTC(),
		SourceHostnameHash: hashHostname(opt.Hostname),
		SchemaVersion:      SchemaVersion,
		IncludedAudit:      opt.IncludeAudit,
		IncludedPrompts:    opt.IncludePrompts,
	}

	// Step 1: VACUUM INTO a temp path in the destination directory so
	// the atomic-rename at the end is on the same filesystem (cross-
	// filesystem rename would fall back to copy+unlink + lose the
	// atomicity).
	tmpPath := dstPath + ".tmp"
	// Defensive cleanup: a previous failed run may have left tmpPath.
	_ = os.Remove(tmpPath)

	// VACUUM INTO is a SQL statement bound to a connection. Use
	// ExecContext via the pool — SQLite serializes VACUUM internally,
	// so there's no concurrency concern from the pool side.
	if _, err := s.db.Exec(`VACUUM INTO ?`, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("dbounce: backup: VACUUM INTO: %w", err)
	}

	// Step 2-5: open the freshly-vacuumed file as a second handle so we
	// can prune the opt-out tables + write the metadata table without
	// touching the source database.
	dst, err := sql.Open("sqlite",
		"file:"+tmpPath+
			"?_pragma=busy_timeout(5000)"+
			"&_pragma=foreign_keys(0)"+ // restore-side opens FKs; backup-side prunes
			"&_pragma=synchronous(FULL)")
	if err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("dbounce: backup: open destination: %w", err)
	}
	defer dst.Close()
	dst.SetMaxOpenConns(1)

	excluded := excludedTablesFor(opt)
	for _, tbl := range excluded {
		// Use raw concatenation (tbl is from a fixed allowlist, not
		// user input) — modernc.org/sqlite does not parameterize
		// table-name positions.
		if _, err := dst.Exec("DELETE FROM " + tbl); err != nil {
			// Tolerate missing tables (a backup of an older schema
			// where the table didn't exist) — but log only-via-error
			// from the Backup caller's perspective if the DELETE
			// fails for any other reason.
			if !isMissingTableErr(err) {
				_ = os.Remove(tmpPath)
				return nil, fmt.Errorf("dbounce: backup: prune %s: %w", tbl, err)
			}
		}
	}

	if err := writeBackupMetadata(dst, meta); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}

	// Step 4 (deferred to here so the metadata row gets the freed-page
	// reclamation benefit too): VACUUM to reclaim freed pages from the
	// pruned tables — without this the on-disk file is source-size
	// because SQLite marks pages free but doesn't shrink. VACUUM also
	// rebuilds the b-tree so the round-trip-byte-identical property
	// test holds.
	if _, err := dst.Exec(`VACUUM`); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("dbounce: backup: post-prune VACUUM: %w", err)
	}

	if err := dst.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("dbounce: backup: close destination: %w", err)
	}

	// Step 6: atomic rename to the final path + tighten perms.
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("dbounce: backup: rename to final: %w", err)
	}
	if err := os.Chmod(dstPath, 0o600); err != nil {
		return nil, fmt.Errorf("dbounce: backup: chmod %q: %w", dstPath, err)
	}
	return &meta, nil
}

// writeBackupMetadata creates the dbounce_backup_metadata table inside
// the destination database + inserts the single row. Schema is
// intentionally narrow so a future reader (a third-party tool or a
// sibling agent's restore code) can SELECT * without surprises.
func writeBackupMetadata(db *sql.DB, meta BackupMetadata) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS ` + backupMetadataTable + ` (
		id INTEGER PRIMARY KEY,
		dbounce_version TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		source_hostname_hash TEXT NOT NULL DEFAULT '',
		schema_version INTEGER NOT NULL,
		included_audit INTEGER NOT NULL DEFAULT 0,
		included_prompts INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		return fmt.Errorf("dbounce: backup: create metadata table: %w", err)
	}
	// Single-row design (id=1; UPSERT on conflict). Mirrors the
	// profile_overrides single-row pattern.
	if _, err := db.Exec(
		`INSERT INTO `+backupMetadataTable+`(
			id, dbounce_version, created_at, source_hostname_hash,
			schema_version, included_audit, included_prompts
		) VALUES (1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			dbounce_version=excluded.dbounce_version,
			created_at=excluded.created_at,
			source_hostname_hash=excluded.source_hostname_hash,
			schema_version=excluded.schema_version,
			included_audit=excluded.included_audit,
			included_prompts=excluded.included_prompts`,
		meta.DbounceVersion,
		meta.CreatedAt.Format(time.RFC3339),
		meta.SourceHostnameHash,
		meta.SchemaVersion,
		boolToInt(meta.IncludedAudit),
		boolToInt(meta.IncludedPrompts),
	); err != nil {
		return fmt.Errorf("dbounce: backup: write metadata row: %w", err)
	}
	return nil
}

// ReadBackupMetadata opens a backup file read-only + returns the
// embedded metadata row. Returns a wrapped sql.ErrNoRows when the file
// is a valid SQLite database but does NOT carry the metadata table —
// in which case the caller (Restore) refuses the file as "not a
// dbounce backup."
func ReadBackupMetadata(path string) (*BackupMetadata, error) {
	if path == "" {
		return nil, errors.New("dbounce: read backup metadata: path required")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("dbounce: read backup metadata: stat %q: %w", path, err)
	}
	db, err := sql.Open("sqlite",
		"file:"+path+
			"?mode=ro"+
			"&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("dbounce: read backup metadata: open %q: %w", path, err)
	}
	defer db.Close()

	// Existence check first so we can return a friendly "not a dbounce
	// backup file" error rather than a sqlite "no such table" error.
	var present int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`,
		backupMetadataTable,
	).Scan(&present); err != nil {
		return nil, fmt.Errorf("dbounce: read backup metadata: probe schema: %w", err)
	}
	if present == 0 {
		return nil, fmt.Errorf(
			"dbounce: read backup metadata: file %q is a SQLite database "+
				"but is missing the %s table — is this a dbounce backup file?",
			path, backupMetadataTable)
	}

	row := db.QueryRow(`SELECT
		dbounce_version, created_at, source_hostname_hash,
		schema_version, included_audit, included_prompts
		FROM ` + backupMetadataTable + ` WHERE id = 1`)
	var (
		meta         BackupMetadata
		createdStr   string
		includedAud  int
		includedPrm  int
	)
	if err := row.Scan(
		&meta.DbounceVersion, &createdStr, &meta.SourceHostnameHash,
		&meta.SchemaVersion, &includedAud, &includedPrm,
	); err != nil {
		return nil, fmt.Errorf("dbounce: read backup metadata: scan: %w", err)
	}
	if t, perr := time.Parse(time.RFC3339, createdStr); perr == nil {
		meta.CreatedAt = t
	}
	meta.IncludedAudit = includedAud != 0
	meta.IncludedPrompts = includedPrm != 0
	return &meta, nil
}

// CountRowsByTable returns a map of table-name → row-count for every
// user-facing table the dbounce store ships. The dbounce_backup_metadata
// table is included so a reviewer can see "yes, the backup file has its
// provenance row." Hidden SQLite tables (sqlite_*) are skipped.
//
// Used by the CLI to print the post-restore row-count summary + by the
// tests to assert exclusion semantics. Pulls table names from
// sqlite_master so a future schema-version bump doesn't require
// updating a hand-maintained allowlist here.
func CountRowsByTable(path string) (map[string]int64, error) {
	db, err := sql.Open("sqlite",
		"file:"+path+
			"?mode=ro"+
			"&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("dbounce: count rows: open %q: %w", path, err)
	}
	defer db.Close()
	rows, err := db.Query(
		`SELECT name FROM sqlite_master WHERE type='table'
		 AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("dbounce: count rows: list tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("dbounce: count rows: scan table name: %w", err)
		}
		tables = append(tables, n)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("dbounce: count rows: iterate tables: %w", err)
	}
	_ = rows.Close()

	out := make(map[string]int64, len(tables))
	for _, t := range tables {
		var n int64
		// Table name is from sqlite_master, not user input.
		if err := db.QueryRow("SELECT COUNT(*) FROM " + t).Scan(&n); err != nil {
			return nil, fmt.Errorf("dbounce: count rows: count %s: %w", t, err)
		}
		out[t] = n
	}
	return out, nil
}

// FileSHA256 returns the hex sha256 of the file at path. Used by the
// CLI to print a fingerprint of the restored database so the operator
// can pin "this is the file I want" in their change-management log.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("dbounce: sha256: open %q: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("dbounce: sha256: read %q: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashHostname returns the sha256[:12] hex digest of the input
// hostname. Per the #279 spec: source-host attribution without leaking
// the literal hostname into a file the operator may share.
func hashHostname(hostname string) string {
	if hostname == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(hostname))
	return hex.EncodeToString(sum[:])[:12]
}

// isMissingTableErr is true when err is the modernc.org/sqlite "no such
// table" error. Defensive: a backup of a pre-v6 database wouldn't have
// pending_audit_events; the prune step must tolerate that.
func isMissingTableErr(err error) bool {
	if err == nil {
		return false
	}
	// modernc.org/sqlite surfaces the error as a wrapped string;
	// substring match is the standard pattern in this codebase (see
	// store_test.go usage).
	return strings.Contains(err.Error(), "no such table")
}

// SortedTableNames returns the sorted user-table list a Backup file
// carries — useful for the CLI's verbose summary output. Pulled from
// sqlite_master so a future schema-bump table is included
// automatically.
func SortedTableNames(path string) ([]string, error) {
	counts, err := CountRowsByTable(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(counts))
	for k := range counts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

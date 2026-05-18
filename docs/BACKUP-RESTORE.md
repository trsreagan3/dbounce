# dbounce backup + restore (#279)

`dbounce backup` and `dbounce restore` ship an online SQLite backup +
gated structured restore so an operator can move dbounce state between
hosts, snapshot before a risky change, or recover from disaster.

Sibling commands `kbounce backup`/`restore` (kbouncer) and
`ibounce backup`/`restore` (iam-jit-bouncer) ship the same CLI shape +
the same metadata-table format. The product-namespaced metadata table
inside each backup file is `dbounce_backup_metadata` /
`kbounce_backup_metadata` / `iam_jit_backup_metadata` so a single shared
tooling layer can tell which product produced the file.

## Why

- **Migration.** Move a hand-tuned dev-laptop dbounce onto a CI runner
  or sibling deployment without re-applying rules / pause windows /
  task scopes by hand.
- **Disaster recovery.** Restore a deployment's state.db after a host
  loss, snapshot rotation, or accidental file deletion.
- **Audit-trail preservation.** Decisions table is included by default
  so the audit log is part of the snapshot — useful when the SIEM
  pipeline isn't your only source of truth.

For per-bundle MERGE semantics (apply some rules + profiles onto an
existing deployment) use `dbounce config import` instead — its
`[[creates-never-mutates]]` semantics APPEND. `dbounce restore` REPLACES
the destination database wholesale.

## Backup is online; restore requires the proxy stopped

`dbounce backup` uses SQLite's `VACUUM INTO` primitive: the source
database is NOT locked, concurrent writers continue uninterrupted, and
the destination file is created atomically. You can back up a running
deployment.

`dbounce restore` REPLACES the destination database file. The command
probes the loopback wire + management ports (5433 + 8768 by default)
and refuses with an actionable error if `dbounce run` is alive. Stop
the running process before restoring:

```
pkill -f 'dbounce run'   # or your service manager's stop verb
dbounce restore --in dbounce-backup-2026-05-18T14-30-00Z.db
```

If the probe ports are held by an unrelated process, pass `--probe-skip`
after manually verifying dbounce is down.

## Schema-version safety

Every backup file embeds the SchemaVersion the producing binary was
built against. `dbounce restore` refuses to restore a backup whose
`schema_version` does NOT match the running binary — even with
`--force`. Cross-schema restores require the (out-of-scope-for-#279)
`dbounce migrate` command.

dbounce-version mismatches WITHIN the same schema version are supported
as a soft gate: the restore prints a WARNING + requires `--force` to
proceed. Use this when restoring a v1.0.5 backup onto a v1.1.0 binary.

## What ships in a backup

By default the backup file contains:

- `rules` — global allow/deny rules
- `profile_overrides` — hot-swap profile selection
- `tasks` — active task-scoped rule sets
- `pause_events` — pause history (active + expired)
- `decisions` — audit log
- `schema_version` — for `dbounce restore`'s schema-version gate
- `dbounce_backup_metadata` — provenance row (dbounce_version,
  created_at, source_hostname_hash, schema_version, included_audit,
  included_prompts)

Two high-volume tables are EXCLUDED by default + opt-in via flag:

- `pending_audit_events` — opt in via `--include-audit`. Ephemeral
  cross-process queue; bound to in-flight `dbounce run` poll cycles.
- `pending_prompts` — opt in via `--include-prompts`. Bound to
  in-flight proxy goroutines that won't survive a restore anyway.

## Sample session

```
$ dbounce backup --out dbounce-backup-prod.db
wrote dbounce backup to /home/op/dbounce-backup-prod.db (102400 bytes, sha256=a3f2...)
  schema_version=6  dbounce_version=v1.0.5  created_at=2026-05-18T14:30:00Z
  source_hostname_hash=8b3c5d1f9a02  included_audit=false  included_prompts=false
  tables:
    dbounce_backup_metadata          1 rows
    decisions                        4287 rows
    pause_events                     12 rows
    pending_audit_events             0 rows
    pending_prompts                  0 rows
    profile_overrides                0 rows
    rules                            18 rows
    schema_version                   1 rows
    tasks                            3 rows
```

Restore onto a fresh host:

```
$ dbounce restore --in dbounce-backup-prod.db
restored dbounce state.db from dbounce-backup-prod.db
  destination: /home/op/.dbounce/state.db
  sha256: 4c8e91...
  row counts:
    dbounce_backup_metadata          1 rows
    decisions                        4287 rows
    pause_events                     12 rows
    ...
```

Cross-version restore (force required):

```
$ dbounce restore --in dbounce-backup-prod-v1.0.5.db --force
dbounce: restore: WARNING dbounce_version mismatch — backup was created
by dbounce "v1.0.5", running binary is "v1.1.0". Continuing under
--force; this is supported but you should verify the running binary can
read the backup's row shapes.
restored dbounce state.db from dbounce-backup-prod-v1.0.5.db
...
```

## Audit-event emission

Both subcommands enqueue an `ADMIN_ACTION` OCSF row via the same
pending-audit-events queue every other admin mutation uses:

- `backup.create` — payload carries `{path, size_bytes, sha256,
  schema_version, dbounce_version, included_audit, included_prompts,
  source_host_hash}`.
- `backup.restore` — payload carries `{source_path, destination,
  sha256, force, probe_skipped, row_count_total}`.

A SIEM dashboard keyed on `action="backup.restore"` catches the
DR-lifecycle event regardless of which product fired it. Backup events
are dialect-agnostic (the SQLite file itself is dialect-agnostic — the
runtime dialect lives in the operator's `dbounce run` flags, not the
state.db).

## Constraints

- Per [[creates-never-mutates]]: backup is read-only against the source
  database. Restore is the one CLI surface that DOES mutate an existing
  DB; the destructive verb is gated by the explicit subcommand name +
  the `--force` semantics + the running-process probe.
- Per [[self-host-zero-billing-dependency]]: no network calls. Both
  subcommands are pure file + SQLite operations.
- Per [[push-policy-public-repo]]: the metadata table records
  `source_hostname_hash` (sha256[:12] of the hostname) rather than the
  literal hostname so an operator can share a backup file for support
  purposes without leaking infra topology.

## Out of scope (for #279)

- Cross-schema-version restore (`dbounce migrate`). The
  schema_version-mismatch refusal is intentional — restoring across
  schema versions would leave the destination running against tables
  the binary doesn't know how to read.
- Encrypted backups. The destination file inherits 0o600 perms and the
  hostname hash is the only privacy primitive. Wrap in your own
  encryption layer (`gpg --symmetric` / `age` / `aws s3 cp --sse`) when
  shipping backups across trust boundaries.
- Incremental backups. Each `dbounce backup` invocation is a full
  snapshot. The state.db is small enough (rules + tasks + audit log) +
  the VACUUM INTO is fast enough that incrementals aren't worth the
  recovery complexity.

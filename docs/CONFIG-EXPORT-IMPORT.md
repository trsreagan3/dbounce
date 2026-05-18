# dbounce config export + import

`dbounce config export` and `dbounce config import` provide a portable
JSON bundle of a dbounce deployment's runtime configuration so an
operator can back up before an upgrade, mirror a hand-tuned dev-laptop
config onto a CI runner or sibling bouncer host, feed a diff into a
change-management review, or ship a starter config to a teammate
alongside the install instructions.

This document covers the wire shape, the CLI flags, the cross-product
parity contract, and the backwards-compatibility window for pre-#288
exports.

## Quick start

```bash
# Export the current config to a JSON file. Default: writes 0600 perms.
dbounce config export --output ~/backups/dbounce-2026-05-18.json

# Import on a new machine. --in PATH is the primary flag.
dbounce config import --in ~/backups/dbounce-2026-05-18.json
```

## Wire shape

The export is a single JSON document with the following top-level
fields. Schema lives in `schemas/dbounce-config.schema.json` (in-tree).

```json
{
  "schema_version": "1.0",
  "product": "dbounce",
  "dbounce_version": "v1.0.0",
  "exported_at": "2026-05-18T12:34:56Z",
  "exported_by": "tester",
  "source_hostname_hash": "a3f7b2c8d4e1",
  "store_schema_version": 6,
  "runtime_config": { "dialect": "postgres" },
  "rule_pack": { ... },
  "rules": [ ... ],
  "profiles": { ... },
  "pause": null,
  "tasks": []
}
```

Notes on the load-bearing fields:

- **`schema_version`** — string semver, currently `"1.0"`. Bumped to
  `"1.1"` on additive changes or `"2.0"` on breaking changes.
- **`product`** — always `"dbounce"`. The importer REFUSES any other
  value — you cannot import a kbounce / ibounce / gbounce export into
  dbounce.
- **`store_schema_version`** — the `store.SchemaVersion` at export
  time. The importer refuses bundles whose store-schema version is
  newer than the binary supports (older binary cannot read a
  newer-schema bundle); cross-version migration is a separate feature.
- **`source_hostname_hash`** — sha256[:12] of the export-host's
  hostname. Privacy-preserving attribution; matches the convention
  used by `dbounce backup` metadata + kbounce / ibounce / gbounce
  exports.

What does NOT ship (intentional, per
[[opt-in-feedback-pipeline]] + [[push-policy-public-repo]]):

- `decisions` table (audit log) — route via the audit-export pipeline.
- Transient queue rows (`pending_audit_events`, `pending_prompts`).
- Credentials, hostnames, URLs (other than the hashed hostname).

## CLI flags

### `dbounce config export`

```
dbounce config export [--output PATH | -o PATH] [--dialect DIALECT]
                      [--profile NAME] [--db PATH] [--profiles-path PATH]
                      [--actor NAME]
```

- `--output PATH` / `-o PATH` — write the JSON to this file. Without
  it (or with `-`), writes to stdout. The file is created `0600` via
  atomic temp+rename so a crash mid-write cannot leave a half-written
  bundle on disk.
- `--dialect DIALECT` — runtime dialect recorded in the bundle
  (`postgres` / `mysql` / `snowflake` / `bigquery`). MUST match the
  deployment's runtime dialect; the importer refuses on mismatch.
- `--profile NAME` — active profile name to record in the bundle.

### `dbounce config import`

```
dbounce config import --in PATH [--dialect DIALECT] [--dry-run]
                      [--force] [--replace] [--json]
                      [--db PATH] [--profiles-path PATH] [--actor NAME]
```

- `--in PATH` — the export JSON to import. Required. **Primary flag
  per #288 cross-product reconciliation** — ibounce, gbounce, and
  kbounce all use the same flag so one cross-product backup script
  reads identically across the suite.
- `--input PATH` / `-i PATH` — DEPRECATED aliases for `--in PATH`.
  Still work but print a stderr deprecation warning. Will be removed
  in a future major version.
- `--dialect DIALECT` — target dialect of the importing host. The
  importer refuses bundles whose `runtime_config.dialect` does not
  match. Use `--force` to override at your own risk (rule patterns may
  carry table-glob prefixes that do not exist in the target dialect's
  schema).
- `--dry-run` — parse + validate + simulate without writing anything.
- `--replace` — overwrite an existing same-named profile rather than
  skipping it. Default is to SKIP same-named profiles per
  [[creates-never-mutates]].
- `--json` — emit a machine-readable JSON summary instead of the
  human banner.

Per [[creates-never-mutates]]: rules APPEND (each is inserted via
AddRule with a fresh row id), profiles APPEND, and operational state
(pause, tasks) is NOT re-played.

## Backwards compatibility (pre-#288 exports)

The wire shape converged across the Bounce suite on 2026-05-18 as
part of issue #288. Before that, dbounce exported a pre-#288 shape:

```json
{
  "format": "dbounce.config",
  "format_version": 1,
  "schema_version": 6,
  ...
}
```

Three axes changed in the reconciliation:

1. `format: "dbounce.config"` (magic string) → REMOVED. The `product`
   field carries the same semantic with a cross-product-canonical name.
2. `format_version: 1` (int) → `schema_version: "1.0"` (string semver).
3. `schema_version: <int>` (which named the STORE schema version) →
   `store_schema_version: <int>` to break the field-name collision
   with the new wire-format `schema_version`.

The reconciled importer accepts BOTH shapes. Reading a pre-#288
export:

1. The legacy fields (`format`, `format_version`, int `schema_version`)
   are detected and rewritten in-place onto the canonical shape
   before schema validation runs.
2. A stderr deprecation warning is printed:

   ```
   dbounce: deprecation: import uses pre-#288 wire shape
   (`format`/`format_version` fields, int store-schema_version).
   This dbounce understands it but future major versions will refuse
   it. Re-export with this binary to upgrade to the canonical
   `product`+`schema_version: "1.0"` shape.
   ```

3. The import proceeds normally.

The pre-#288 `--input PATH` / `-i PATH` flags are preserved as
deprecated aliases for `--in PATH` on the same compat schedule.

This compat window stays open across the full v1.x line. Old exports
on disk are guaranteed to keep importing across binary upgrades — re-
export with a current binary at your convenience to get the canonical
shape.

## Cross-product wire-shape parity

dbounce, ibounce, gbounce, and kbounce all emit the same top-level
wire shape per #288:

- `schema_version: "1.0"` (string semver) on every product
- `product: "<product-name>"` (one of `dbounce`, `ibounce`, `gbounce`,
  `kbounce`) — the importer REFUSES any cross-product import
- `--in PATH` on every product's import command

A single cross-product backup script can target all four:

```bash
for product in dbounce ibounce gbounce kbounce; do
    $product config export --output ~/backups/$product-$(date +%F).json
done
```

For the wire-shape decisions behind #288 (string semver vs int,
`--in` over `--from`/`--input`, dropping dbounce's `format` field
in favor of `product`), see the `project_config_export_wire_divergence`
memo in the iam-jit-portable repo.

## Audit trail

Both `dbounce config export` and `dbounce config import` enqueue
ADMIN_ACTION audit events through the standard pending_audit_events
queue (drained by the running proxy + emitted through its wired
Exporter):

- `config.export` — bundle dialect, rule count, profile count land in
  `details`; the runtime dialect lands in `dialects` so a SIEM rule
  keyed on `unmapped.iam_jit.config_change.dialects` can filter by
  per-dialect export activity.
- `config.import` — source path, rules / profiles imported / skipped,
  dialect, dry_run / force / replace flags land in `details`.

Dry-run imports STILL emit the event with `result: "noop"` so a SIEM
analyst can distinguish planning activity from apply activity.

## Related

- `docs/BACKUP-RESTORE.md` — `dbounce backup` / `dbounce restore` for
  SQLite-level snapshots (different feature; backs up the full
  state.db rather than the human-reviewable config bundle).
- `docs/DIAGNOSTICS.md` — `dbounce diagnostics bundle` embeds a
  byte-identical copy of `config export` as `config.json`.
- ibounce + gbounce + kbounce docs for the cross-product equivalents.

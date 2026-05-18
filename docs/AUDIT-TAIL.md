# `dbounce audit tail` — Live tail + filtering + summary + export

`dbounce audit tail` reads the local SQLite audit log (default
`~/.dbounce/state.db`). #268 extends the base snapshot path with four
operator workflows mirrored cross-product with ibounce + kbounce per
[[cross-product-agent-parity]]:

```
dbounce audit tail [--limit N] [--json]
                   [--follow] [--poll-interval D]
                   [--filter EXPR ...] [--summary]
                   [--export {jsonl|csv|ocsf-bundle} --out PATH]
                   [--csv-columns COLS]
```

| Mode      | Trigger flag | Behaviour                                                 |
| --------- | ------------ | --------------------------------------------------------- |
| snapshot  | (default)    | newest `--limit` rows as a table; `--json` for one-per-line |
| follow    | `--follow`   | live tail; SIGINT to exit; honors `--filter`              |
| summary   | `--summary`  | count-summary by event_type / severity_id / actor / op    |
| export    | `--export`   | bulk export to `--out PATH`; honors `--filter`            |

`--follow` and `--summary` are mutually exclusive — the parser rejects
the combination with a clear error.

---

## `--follow` — live tail

```
dbounce audit tail --follow
```

Polls the SQLite audit DB at `--poll-interval` (default 500ms) and
prints new rows as they appear. Watermark is keyed on the auto-
increment row id, so duplicates within the same `at` second can't slip
past + a row can't be re-printed across poll cycles.

Semantics mirror `tail -f`: rows that existed BEFORE the operator
invoked follow are NOT replayed. Only rows inserted after invocation
appear.

Exit via Ctrl-C (SIGINT) or SIGTERM. The header prints once at the top
of the live stream.

```
$ dbounce audit tail --follow --filter 'actor.user.name=claude-code'
AT (UTC)              MODE         VERDICT  STMT-TYPE     STATEMENT
2026-05-18 14:31:02   cooperative  ALLOW    SELECT        SELECT count(*) FROM users
2026-05-18 14:31:04   cooperative  ALLOW    SELECT        SELECT id FROM users WHERE active=true
```

---

## `--filter EXPR` — field predicates

Repeatable; AND-combined. Forms:

| Form           | Meaning            | Example                                       |
| -------------- | ------------------ | --------------------------------------------- |
| `field=value`  | string equality    | `--filter 'actor.user.name=alice'`            |
| `field~regex`  | regex (RE2)        | `--filter 'api.operation~^(SELECT\|UPDATE)$'` |
| `field>=N`     | numeric ≥          | `--filter 'severity_id>=3'`                   |
| `field<=N`     | numeric ≤          | `--filter 'activity_id<=2'`                   |

Supported fields (cross-product parity with ibounce + kbounce):

- `severity_id`
- `activity_id`
- `status_id`
- `actor.user.name`
- `api.operation`
- `unmapped.iam_jit.event_type`
- `unmapped.iam_jit.verdict`
- `unmapped.iam_jit.mode`
- `unmapped.iam_jit.agent.name`
- `unmapped.iam_jit.agent.session_id`
- `unmapped.iam_jit.agent.detected_from`

dbounce-specific fields under `unmapped.iam_jit.ext.*`:

- `unmapped.iam_jit.ext.dialect`        — `postgres` / `mysql` / `snowflake` / `bigquery`
- `unmapped.iam_jit.ext.is_dml`         — bool
- `unmapped.iam_jit.ext.is_ddl`         — bool
- `unmapped.iam_jit.ext.has_mutating_node` — bool
- `unmapped.iam_jit.ext.mutating_node_type` — string (`DELETE`, `UPDATE`, `DROP`, ...)
- `unmapped.iam_jit.ext.tables_touched` — comma-joined table list
- `unmapped.iam_jit.ext.decision_source` — `profile` / `task` / `global` / `default`
- `unmapped.iam_jit.ext.forwarded`      — bool

`--filter` AND-combines:

```
$ dbounce audit tail \
    --filter 'actor.user.name=alice' \
    --filter 'activity_id>=4' \
    --filter 'unmapped.iam_jit.ext.dialect=postgres'
```

Returns only rows where the actor is `alice`, the OCSF activity is at
least `4` (Delete-class), AND the originating dialect was Postgres.

---

## `--summary` — count-summary

```
$ dbounce audit tail --summary
total: 4

by event_type:
       4  DECISION

by severity_id:
       4  1

by actor.user.name:
       2  alice
       1  bob
       1  carol

by api.operation:
       2  SELECT
       1  DELETE
       1  UPDATE
```

Honors `--filter` so you can summarize a subset:

```
$ dbounce audit tail --summary --filter 'actor.user.name=alice'
```

An empty audit log still prints the four section headers + zero
counts; automation that wraps the command sees a stable shape.

---

## `--export FORMAT --out PATH` — bulk export

Three formats — pick the one that matches your SIEM's ingestion path.

### `--export jsonl`

OCSF v1.1.0 class 6003 (API Activity) events, one per line. Same shape
the audit-export `--audit-log-path` writes during normal proxy operation
(see [docs/QUERYING-AUDIT-LOGS.md](QUERYING-AUDIT-LOGS.md)). Round-trips
through `jq`, `duckdb read_json_auto`, etc.

```
$ dbounce audit tail --export jsonl --out /tmp/dbounce-export.jsonl
$ jq '.api.operation' /tmp/dbounce-export.jsonl
```

### `--export csv`

Tabular CSV for spreadsheet / SOC-analyst review. Default columns:

```
timestamp, severity, event_type, actor, operation, verdict, agent.name, agent.session_id
```

Override with `--csv-columns COL1,COL2,...`. Supported names include
all default columns plus `severity_id`, `dialect`, `statement`,
`tables`, `mode`. Any OCSF nested path (e.g.
`unmapped.iam_jit.verdict`) is also accepted — unrecognized names
resolve to an empty cell.

### `--export ocsf-bundle`

A single JSON object wrapping every matched row as an OCSF v1.1.0 class
2004 (Detection Finding). Each finding carries the original API
Activity event as an observable so no context is lost. Useful for
batch-ingest paths (Splunk HEC, Microsoft Sentinel ingestion API,
Datadog logs intake) that accept one HTTP POST per bundle.

```
$ dbounce audit tail --export ocsf-bundle --out /tmp/dbounce-findings.json
$ jq '.findings | length' /tmp/dbounce-findings.json
4
```

### Composition

`--export` honors `--filter` so a security-team operator can ship
only the rows that match a triage query:

```
$ dbounce audit tail \
    --filter 'unmapped.iam_jit.verdict=DENY' \
    --filter 'unmapped.iam_jit.agent.name~^claude' \
    --export ocsf-bundle --out /tmp/claude-denies.json
```

### Refusing to overwrite

The export path refuses to clobber an existing `--out` file. The SIEM-
ingest archive is operator-owned; we'd rather surface "you already have
a file there" loudly than silently overwrite a previous batch.

---

## SQL-literal redaction (dbounce-specific)

**Every CSV and ocsf-bundle export defensively redacts SQL string
literals** via the MED-D8-09 redactor (`parser.RedactLiterals`),
regardless of whether the audit row was persisted with
`--redact-literals` at proxy run time.

The redactor swaps every quoted string literal for `'[REDACTED]'`:

| Input form                              | Output form                |
| --------------------------------------- | -------------------------- |
| `'alice'`                               | `'[REDACTED]'`             |
| `'foo\'bar'` (MySQL/Snowflake backslash) | `'[REDACTED]'`             |
| `'it''s a test'` (SQL-standard `''`)    | `'[REDACTED]'`             |

Identifiers (`"col-name"`, `` `col-name` ``), numeric literals, and
comments are PRESERVED — the rule packs match on them and they are not
credential candidates. See `internal/parser/redact.go` for the full
contract.

The redactor runs on every SQL-bearing column in the export pipeline:

- `Statement`
- `DecisionReason`
- `UpstreamResponseSummary`
- `ParseErrors[]`

If your SIEM uses pattern-matching on `[REDACTED]`-shaped tokens, every
exported row that had at least one string literal carries the marker.

> **Why redact on export when the proxy can also redact at write
> time?** The `dbounce run --redact-literals` flag is the operator
> opt-in for in-DB redaction. The export-path redaction is a SECOND
> layer: even if the operator didn't enable in-DB redaction (they
> wanted operator-faithful audit rows in the local SQLite DB), a bulk
> export to a third-party SIEM should default to redacted. The
> snapshot / `--json` / `--follow` paths preserve the stored shape for
> operator visibility — those land on the operator's terminal and the
> SQLite DB is local to the operator's user account; raw literals
> there have the same trust boundary as the DB file itself.

A future ticket may add `--include-literals` as an explicit
opt-out for the export path (not in scope for #268).

---

## Cross-product alignment

The flag set, summary groupings, and supported filter fields match the
`ibounce audit tail` + `kbounce audit tail` surface, so a single
muscle-memory shortcut works across all three products. The cross-
product OCSF schema (see
[docs/QUERYING-AUDIT-LOGS.md](QUERYING-AUDIT-LOGS.md)) means an export
from any one of the three ingests cleanly into any OCSF-aware SIEM
without per-product translation.

The dbounce-specific fields (`unmapped.iam_jit.ext.dialect`, `.is_dml`,
`.tables_touched`, `.mutating_node_type`, etc.) are unique to dbounce
because they describe SQL-shaped semantics that don't apply to the
AWS-IAM (ibounce) or Kubernetes (kbounce) surfaces.

---

## Examples

```
# Tail every event from one Claude Code session, formatted as JSON
dbounce audit tail \
  --follow --json \
  --filter 'unmapped.iam_jit.agent.session_id=01927e94-2d3c-7000-8000-abc1234567'

# Last 1000 DENY events as an OCSF bundle for the security team
dbounce audit tail \
  --limit 1000 \
  --filter 'unmapped.iam_jit.verdict=DENY' \
  --export ocsf-bundle --out /tmp/denies.json

# CSV review of every UPDATE/DELETE/DROP from any agent named like 'claude'
dbounce audit tail \
  --filter 'activity_id>=3' \
  --filter 'unmapped.iam_jit.agent.name~^claude' \
  --export csv --out /tmp/claude-mutations.csv \
  --csv-columns timestamp,operation,actor,verdict,statement,tables

# How many of each verdict in the last 1000 rows
dbounce audit tail --limit 1000 --summary
```

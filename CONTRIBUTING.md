# Contributing to dbounce

`dbounce` is the SQL gating bouncer in the iam-jit Bounce suite.
Same agent-friendly UX surface as `ibounce` per
`[[cross-product-agent-parity]]`, with SQL statement verbs +
schema-qualified resources underneath.

## Development setup

```bash
go install ./...
go test ./...
```

`go install` writes to `$(go env GOPATH)/bin` (defaults to `~/go/bin`).
If `dbounce --version` reports "command not found", that directory is not
on your PATH — `export PATH="$PATH:$(go env GOPATH)/bin"` once, and
persist it in `~/.bashrc` or `~/.zshrc` (closes #549 from UAT L1
2026-05-24).

Local-test infrastructure (Postgres / MySQL via Docker Compose)
lives in `compose.test.yaml` and is driven by the `Makefile`
targets.

## Adding a rule

Profile rules use the cross-product YAML shape (per
`[[cross-product-agent-parity]]`). SQL-specific verb mapping:

| Bouncer verb | SQL statement types |
|---|---|
| `select` | SELECT, EXPLAIN |
| `insert` | INSERT |
| `update` | UPDATE |
| `delete` | DELETE, TRUNCATE |
| `ddl` | CREATE, ALTER, DROP, RENAME |
| `dcl` | GRANT, REVOKE |

Submit profile contributions to the shared profile repo at
[`trsreagan3/bounce-profiles`](https://github.com/trsreagan3/bounce-profiles).

## Adding a preset

Curated preset packs ship with the binary. Each preset targets a
SQL role narrative (e.g. `analytics-engineer`, `dba-investigation`,
`migration-runner`). Add a test in `internal/...` exercising the
preset against a representative statement stream.

## Calibration corpus contributions

`dbounce` composes with the iam-jit calibration corpus when used
alongside iam-jit-issued IAM roles for the database tier (RDS,
Aurora). See [`iam-roles/docs/CONTRIBUTING.md`](https://github.com/trsreagan3/iam-jit/blob/main/docs/CONTRIBUTING.md)
for the calibration discipline + corpus contribution path.

## Supported dialects

Currently shipped (D-Slice 1): PostgreSQL, MySQL. JDBC-shim
support for Snowflake and BigQuery is queued per the dbounce
build plan in iam-roles memory.

When adding dialect support: parse with the dialect-native parser
(`pg_query_go` for PG, `vitess` parser for MySQL) — never
regex-based SQL parsing. Verb classification correctness depends
on AST-accurate parsing.

## Code style

```bash
gofmt -s -w .
go vet ./...
```

Before committing.

## Cross-product parity

Per `[[cross-product-agent-parity]]`, the dbounce MCP surface
mirrors ibounce's (only the tool prefix changes). When adding a
new MCP tool, add the equivalent surface to the other bouncers
(or file an issue noting the gap). Symmetry is the cross-product
wedge.

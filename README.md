# dbounce

**Local SQL gating proxy.** Sits between a SQL client (psql / a coding
agent / an analytics tool / a CI job) and a real database, parses every
statement, records the decision in a SQLite audit log, and (in later
slices, transparent mode) can deny statements that don't match its rule
set.

`dbounce` is the third product in the Bounce suite — the SQL-shaped
sibling of `kbounce` (Kubernetes API gating) and `ibounce` (HTTP/AWS-SDK
gating). All three products share the same vocabulary: profiles, modes,
rules, tasks, prompts, pauses. An operator who learned one understands
the others.

---

## D-Slice 1 scope (this release)

D-Slice 1 ships the observation-only foundation:

- TCP listener that speaks PostgreSQL wire protocol
- AST-aware parser for every inbound statement
  (`github.com/pganalyze/pg_query_go/v6`, pinned to libpg_query that
  tracks PostgreSQL 16)
- Decision audit log at `~/.dbounce/state.db` (SQLite, pure Go)
- `dbounce run` / `dbounce audit tail` / `dbounce --version` CLI
- `/healthz` liveness probe on a separate management HTTP port

**dbounce in D-Slice 1 does NOT forward statements upstream.** The
proxy parses + logs + returns a synthetic `ReadyForQuery` to the
client. This is "watch what your client wants to do; nothing actually
executes." D-Slice 2 adds real upstream forwarding.

Features explicitly deferred to later D-Slices:

| Slice | Feature |
| --- | --- |
| D-Slice 2 | Real upstream forwarding + SCRAM-SHA-256 auth pass-through |
| D-Slice 3 | Rule engine + tasks (`dbounce rules` / `dbounce tasks`) |
| D-Slice 4 | TLS on the inbound listener + management port |
| D-Slice 5 | MySQL wire protocol |
| D-Slice 6 | Snowflake + BigQuery (JDBC-driver-shim) |
| D-Slice 7 | Profile YAML, `safe-default` profile, MCP server |
| D-Slice 8 | Pause, prompts, presets, recommender |

## Supported dialects

| Dialect | Mode | Status |
| --- | --- | --- |
| PostgreSQL | Native wire-protocol proxy | Stable; full calibration |
| MySQL | Native wire-protocol proxy | Provisional calibration |
| Snowflake | JDBC-driver-shim only | Experimental calibration |
| BigQuery | JDBC-driver-shim only | Experimental calibration |

`postgres` and `mysql` ship a TCP listener (`dbounce run --dialect
postgres|mysql`) that speaks the native wire protocol. The client
points at dbounce; dbounce forwards to the upstream.

`snowflake` and `bigquery` ship via the JDBC-driver-shim — the
customer wraps their database driver so that every query passes
through `dbounce decide` (or the `dbounce_decide` MCP tool) before
hitting the real driver. `dbounce run --dialect snowflake|bigquery`
fails fast with a clear error pointing at
[`docs/SHIM-INTEGRATION.md`](docs/SHIM-INTEGRATION.md), which
covers the integration pattern + honest trade-offs vs the native
wire-protocol path.

---

## Quickstart

```sh
# Build (single static binary).
go build ./cmd/dbounce

# Default run: cooperative mode, observation-only.
# The proxy listens on 127.0.0.1:5433 (one above PostgreSQL's default
# 5432 so an existing local PG install isn't disturbed). The management
# HTTP port for /healthz is 127.0.0.1:8768 (distinct from kbounce's
# 8766 and ibounce's 8767 so all three products coexist on the same
# laptop).
./dbounce run --upstream postgres://user:pass@localhost:5432/mydb
```

Default audit DB: `~/.dbounce/state.db`.

---

## Operating modes

| Mode | Behavior | Use case |
| --- | --- | --- |
| `cooperative` (default) | Parse + log every statement. Always returns a synthetic `ReadyForQuery` to the client without forwarding (D-Slice 1) — D-Slice 2 will swap this for a real forward. Verdicts are advisory. | Solo dev iterating fast; previewing what transparent mode would block. |
| `transparent` | DENY verdicts return a SQL error to the client. (D-Slice 2 forwards ALLOWs to the upstream; D-Slice 1 ships only the parse + audit half.) | Locked-down environments; lower-trust agents; compliance deploys. |

Switch with `--mode cooperative` or `--mode transparent`.

---

## Subcommand reference

### `dbounce run`

Start the wire-protocol listener.

- `--port 5433` — TCP port for the SQL wire-protocol listener.
- `--host 127.0.0.1` — interface to bind. Binding to anything else
  requires `--i-know-this-binds-externally` to acknowledge the
  credential-handling threat surface.
- `--mgmt-port 8768` — management HTTP port (`/healthz` only in
  D-Slice 1).
- `--mode cooperative|transparent` — see "Operating modes".
- `--default-policy allow|deny` — what transparent mode does when no
  rule matches. D-Slice 1 has no rules; this flag is scaffolding for
  D-Slice 3.
- `--upstream postgres://...` — upstream PG URL. Captured + audit-
  logged in D-Slice 1; forwarding is wired in D-Slice 2.
- `--db PATH` — SQLite audit DB path (default
  `~/.dbounce/state.db`, override with `DBOUNCE_DB`).
- `--dialect postgres` — wire-protocol dialect. Only `postgres`
  recognized in D-Slice 1.

### `dbounce audit tail [--limit N]`

Show the most recent N decisions, newest first. `--limit` must be
1-1000 (rejected at parse time).

### `dbounce --version`

Prints `dbounce <version> (commit X, built Y)`. Set at build time via
`-ldflags "-X github.com/trsreagan3/dbounce/internal/cli.version=v0.1.0
-X github.com/trsreagan3/dbounce/internal/cli.commit=$(git rev-parse HEAD)
-X github.com/trsreagan3/dbounce/internal/cli.buildTime=$(date -u +%FT%TZ)"`.

---

## Liveness probe

`GET /healthz` (default `127.0.0.1:8768`) returns 200 with a small
JSON status payload (`status`, `mode`, `default_policy`, `dialect`,
`active_profile`, `decisions_count`, `lookup_errors_counter`, `pause`).
Never writes to the audit log; safe to poll from monit / k8s liveness
probes / systemd watchdogs.

The `lookup_errors_counter` field mirrors `kbounce`'s and `ibounce`'s
healthz shape and surfaces SQLite-class lookup failures so monitors
can flag degraded persistence without parsing logs.

---

## Test

```sh
cd dbounce
go build ./... && go vet ./... && go test ./...
```

All tests are pure-Go and use a temp-directory SQLite DB per test — no
real PostgreSQL needed for D-Slice 1.

---

## Layout

```
dbounce/
  cmd/dbounce/                 # canonical binary (calls internal/cli.Main)
  community-profiles/          # opt-in profiles installed via `dbounce profile install` (D-Slice 7)
  internal/cli/                # cobra command tree
  internal/parser/             # PG wire-protocol message parser
  internal/profile/            # environment profiles (D-Slice 7)
  internal/proxy/              # TCP listener + decision pipeline
  internal/rules/              # global rule table (D-Slice 3)
  internal/store/              # SQLite audit + rules + tasks + pauses + prompts
  go.mod
  README.md
```

`internal/...` packages are intentionally not exported — `dbounce` is
a shipped binary, not a library other Go programs link against.

---

## Position in the Bounce suite

`dbounce` is the third product in the Bounce suite — the SQL-shaped
sibling of `kbounce` (Kubernetes) and `ibounce` (HTTP / AWS-SDK).
Same brand, same audit shape, same "creates / never mutates" invariant.
Different audiences, different friction profiles, different
distribution channels — separate products so each can find its own
PMF.

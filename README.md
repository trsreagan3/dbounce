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

## Install

```sh
# Canonical install — builds the binary fresh from source into $GOPATH/bin
# (or $HOME/go/bin if GOPATH is unset). Make sure that directory is on
# your PATH.
go install github.com/trsreagan3/dbounce/cmd/dbounce@latest
```

## Quickstart

### First 60 seconds with dbounce (discovery mode default)

Per `[[discovery-first-default]]` (2026-05-22) + iam-roles KNOWN-CAVEATS
§A21 the canonical shape is **discovery mode** — observe + audit +
pass-through. Closes the D1/D2 THEATER + NEGATIVE-VALUE findings from the
role-effectiveness eval (the pre-pivot `safe-default` blocked legit
INSERT alongside adversarial DROP; reads of sensitive tables walked
through unconditionally).

```sh
# Default run: discovery mode (no profile applied; statements forwarded + audit-logged).
# The headline banner reports default_mode=discovery; full OCSF event stream operates as usual.
# Proxy listens on 127.0.0.1:5433 (one above PG's 5432). /healthz on 127.0.0.1:8768.
#
# For a loopback upstream (local PG on 127.0.0.1 / localhost / a .local hostname),
# add --allow-internal-upstream — dbounce refuses internal IP ranges by default to
# prevent SSRF when the upstream URL comes from untrusted config:
dbounce run \
  --upstream postgres://user:pass@127.0.0.1:5432/mydb \
  --allow-internal-upstream

# Opt into the safe-default profile (sql_read_only + DCL-to-PUBLIC floor):
dbounce run --profile safe-default --upstream ... --allow-internal-upstream
# Or, persistent for your shell:
export DBOUNCE_PROFILE=safe-default
```

**DCL-to-PUBLIC floor placement:** the `deny_dcl_targets_public` floor
ships TIED to `safe-default` (it doesn't auto-fire under discovery
mode). Operators who want the floor pin `--profile safe-default`. See
the CHANGELOG entry under §A21 for the rationale (judgment call:
floor + writes-block ship together by design; no partial-floor in v1.0).

### After upgrade: `dbounce profile doctor` (one-time)

dbounce never overwrites `~/.dbounce/profiles.yaml` (your edits
survive upgrades), so a new safety floor added to embedded defaults
won't land until you opt in. After upgrading the binary, run:

```sh
dbounce profile doctor          # report missing fields (no write)
dbounce profile doctor --apply  # additively merge + back up prior file
```

See [docs/PROFILE-UPGRADE.md](../iam-roles/docs/PROFILE-UPGRADE.md)
for the full runbook (task #321 / KNOWN-CAVEATS §A19).

### Local development build

If you're iterating on the source tree:

```sh
# Drops the binary into ./bin/dbounce (gitignored).
make build

# Or invoke go directly:
go build -o bin/dbounce ./cmd/dbounce
./bin/dbounce run --upstream postgres://... --allow-internal-upstream
```

`bin/` is gitignored — never commit a pre-built binary. Users pick up
fresh source via `go install ...@latest` and get an up-to-date build
every time. Closes #306 / #307 + KNOWN-CAVEATS §A8.

Default audit DB: `~/.dbounce/state.db`.

The `--allow-internal-upstream` flag is the dev-laptop opt-in; in
production you'd point `--upstream` at a routable hostname and leave
the flag off so a misconfigured value can't be coerced into hitting
loopback / link-local / RFC1918 / .local addresses. The error message
on a refused loopback URL names the flag, but the first-run snippet
above shows it inline so the local-PG case never trips silently.

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
- `--preset security-observe` — single-flag shortcut for the
  canonical security-team observation deployment shape (transparent
  mode + JSONL audit + 30s heartbeat + 30s audit-export health
  poll). See `docs/DEPLOYMENT-PRESETS.md` for the framework +
  override semantics; same preset name + same semantics across all
  four Bounce products.

### `dbounce audit tail`

Show recent decisions from the local SQLite audit log. The base path
prints a human-readable table; four flag-driven modes (#268; mirrored
in ibounce + kbounce per [[cross-product-agent-parity]]) extend the
surface for live monitoring, filtered review, summary aggregation, and
bulk SIEM export. See [docs/AUDIT-TAIL.md](docs/AUDIT-TAIL.md) for the
full reference.

```
dbounce audit tail [--limit N] [--json]
                   [--follow] [--poll-interval D]
                   [--filter EXPR ...] [--summary]
                   [--export {jsonl|csv|ocsf-bundle} --out PATH]
                   [--csv-columns COLS]
```

| Mode      | Flag        | Notes                                                    |
| --------- | ----------- | -------------------------------------------------------- |
| snapshot  | (default)   | newest N rows as a table; `--json` for JSON-per-line     |
| follow    | `--follow`  | live tail; SIGINT to exit; `--filter` narrows the stream |
| summary   | `--summary` | count-summary by event_type / severity / actor / op      |
| export    | `--export`  | jsonl / csv / ocsf-bundle to `--out PATH`                |

CSV and ocsf-bundle exports ALWAYS redact SQL string literals
(MED-D8-09 redactor applied defensively on read) so a bulk SIEM
shipment cannot leak PII embedded in raw statements.

For the full "where do my audit logs go in production" decision tree
(JSONL / webhook + presets / Security Lake / Lambda → S3 / GCP / Azure
/ CI runners / Enterprise fan-out) see the cross-product runbook in
the iam-roles repo:
[docs/PRODUCTION-LOG-STORAGE.md](https://github.com/trsreagan3/iam-roles/blob/main/docs/PRODUCTION-LOG-STORAGE.md).

### `dbounce --version`

Prints `dbounce <version> (commit X, built Y)`. Set at build time via
`-ldflags "-X github.com/trsreagan3/dbounce/internal/cli.version=v0.1.0
-X github.com/trsreagan3/dbounce/internal/cli.commit=$(git rev-parse HEAD)
-X github.com/trsreagan3/dbounce/internal/cli.buildTime=$(date -u +%FT%TZ)"`.

---

## Dynamic denies (#324c)

dbounce participates in the cross-product
`~/.iam-jit/dynamic-denies.yaml` channel — operator-authored short-
lived deny rules that fan out across the Bounce suite (ibounce /
kbounce / dbounce / gbounce). When ANY rule in that file matches the
dbounce instance's configured upstream (by hostname OR by
`--upstream-rds-arn`), NEW connections are refused at PG StartupMessage
with SQLSTATE 42501 + a structured message naming the rule id; existing
connections continue normally per the honest behavioral contract.

The full design — schema, CLI surface, MCP tools, conflict resolution,
honest caveats — lives in the canonical doc at
[`iam-roles/docs/DYNAMIC-DENY-RULES.md`](../iam-roles/docs/DYNAMIC-DENY-RULES.md).
The cross-product CLI + MCP fan-out ship in #324e; this dbounce slice
(#324c) implements the consumer side — loader, fsnotify watcher,
connection-refuse gate, mgmt-port reload endpoint, OCSF audit event.

Flags on `dbounce run`:
- `--dynamic-denies-path PATH` (default `~/.iam-jit/dynamic-denies.yaml`;
  honors `$IAM_JIT_DYNAMIC_DENIES_PATH`)
- `--disable-dynamic-denies` (default false)
- `--upstream-rds-arn ARN` (enables the RDS-ARN match axis)

Mgmt-port endpoint:
- `POST /admin/dynamic-denies/reload` — triggers an immediate reload +
  returns `{"reloaded": true, "rules_count": N,
  "rules_applied_to_dbounce": M, "instance_denied": bool,
  "denying_rule_id": "dd_..."|null}`. Same bearer-token auth model
  as `/audit/events`.

---

## Liveness probe

`GET /healthz` (default `127.0.0.1:8768`) returns 200 with a small
JSON status payload (`status`, `mode`, `default_policy`, `dialect`,
`active_profile`, `decisions_count`, `lookup_errors_counter`, `pause`,
plus the #324c `dynamic_denies_enabled` / `dynamic_denies_count` /
`upstream_denied` / `upstream_denied_rule_id` /
`total_dynamic_deny_connections_refused` /
`total_dynamic_deny_reloads` / `total_dynamic_deny_parse_errors`
fields). Never writes to the audit log; safe to poll from monit / k8s
liveness probes / systemd watchdogs.

The `lookup_errors_counter` field mirrors `kbounce`'s and `ibounce`'s
healthz shape and surfaces SQLite-class lookup failures so monitors
can flag degraded persistence without parsing logs.

---

## Docker

A multi-arch image is published to GitHub Container Registry on every
push to `main` and on every `v*` tag.

```sh
# Pull + show help (no audit DB persisted between runs).
docker run --rm ghcr.io/trsreagan3/dbounce:latest --help

# Run with the audit DB persisted to ~/.dbounce on the host. The
# distroless :nonroot user (uid 65532) needs to be able to write the
# mounted directory, so create it first + chown if it doesn't exist
# already.
mkdir -p ~/.dbounce
docker run --rm -it \
  -v ~/.dbounce:/home/nonroot/.dbounce \
  -p 127.0.0.1:5433:5433 \
  -p 127.0.0.1:8768:8768 \
  ghcr.io/trsreagan3/dbounce:latest \
  run --upstream postgres://user:pass@host.docker.internal:5432/mydb
```

The image is a packaging convenience — the binary inside is the same
one `go install github.com/trsreagan3/dbounce/cmd/dbounce@latest` would
build, with the same no-telemetry stance. Persisting `~/.dbounce` via
the bind-mount keeps the SQLite audit log, profiles, and rules across
container restarts (the runtime image has no writable filesystem of
its own).

Tags:

| Tag | Source |
| --- | --- |
| `:main` | latest push to `main` |
| `:v1.2.3` / `:1.2.3` | git tag `v1.2.3` |
| `:latest` | most recent `v*` tag |

Architectures: `linux/amd64`, `linux/arm64`.

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

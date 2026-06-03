# dbounce

**SQL gating proxy.** Sits between a SQL client (psql / a coding
agent / an analytics tool / a CI job) and a real database, parses every
statement, **forwards allowed statements verbatim to the upstream and
streams the real reply back**, records every decision in a SQLite audit
log, and — in transparent mode — **denies statements that don't match
its rule set with a real SQL error, never touching the upstream**.

`dbounce` is the third product in the Bounce suite — the SQL-shaped
sibling of `kbounce` (Kubernetes API gating) and `ibounce` (HTTP/AWS-SDK
gating). All three products share the same vocabulary: profiles, modes,
rules, tasks, prompts, pauses. An operator who learned one understands
the others.

---

## What ships today

dbounce is a real wire-protocol proxy with enforcement and an MCP
server. The following are shipped and working:

- **Real upstream forwarding.** With `--upstream` set, dbounce dials the
  real database, forwards the StartupMessage + auth flow verbatim
  (SCRAM-SHA-256 / MD5 / cleartext pass-through — dbounce never reads or
  stores the password), forwards ALLOW verdicts, and streams the
  upstream's real reply back to the client. (`internal/proxy/forward.go`.)
- **Transparent-mode enforcement.** In `--mode transparent`, an
  out-of-profile statement is denied with a PG `ErrorResponse`
  (SQLSTATE `42501`) + a structured-deny payload, and the upstream is
  **never contacted**. Cooperative mode forwards the same statements but
  records the verdict as advisory ("transparent mode would have blocked
  this").
- **AST-aware parser** for every inbound statement
  (`github.com/pganalyze/pg_query_go/v6`, pinned to libpg_query that
  tracks PostgreSQL 16). Classifies reads vs. writes, DML/DDL, CTE-wrapped
  mutations, role/DCL operations, etc.
- **Profiles + rule engine + tasks.** `safe-default` (pure-SELECT
  baseline + AST-walk mutation backstop + DCL-to-PUBLIC floor),
  `full-user`, custom profiles in `~/.dbounce/profiles.yaml`, global
  rules, and per-task scopes.
- **MCP server.** `dbounce mcp serve` exposes the `dbounce_*` tool
  family (decide / posture / active-mode / active-profile / tail /
  profile-allow / …) over JSON-RPC stdio, plus
  `dbounce mcp install-{claude-code,cursor,codex,devin}` install
  helpers. See [Add to your agent](#add-to-your-agent).
- **Decision audit log** at `~/.dbounce/state.db` (SQLite, pure Go) with
  `dbounce audit tail` (snapshot / follow / summary / export) + OCSF
  event-stream fan-out + `/healthz` liveness probe on a separate
  management HTTP port.
- **Dynamic deny rules**, **connection-scope enforcement** (per-profile
  OnlyHosts / OnlyDatabases), **sync deny-prompts**, **deployment
  presets**, and **pause windows**.

### Status by dialect surface

| Surface | Status |
| --- | --- |
| PostgreSQL native wire-protocol proxy (forward + enforce) | Shipped; full calibration |
| MySQL native wire-protocol proxy (forward + enforce) | Shipped; provisional calibration |
| Snowflake / BigQuery (JDBC-driver-shim, `dbounce decide` / `dbounce_decide`) | Shipped; experimental calibration |
| Inbound listener TLS + management-port TLS | Shipped |

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

### go install (works today — needs Go ≥ 1.25)

```sh
go install github.com/trsreagan3/dbounce/cmd/dbounce@latest
dbounce --version

# If you get "command not found": $(go env GOPATH)/bin is not on PATH.
# Stock Ubuntu (and most Linux distros) do NOT put ~/go/bin on PATH by default.
export PATH="$PATH:$(go env GOPATH)/bin"
# Persist: echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
```

**Toolchain note:** `go.mod` specifies `go 1.25.0`. `GOTOOLCHAIN=auto`
handles this automatically on most machines.

**Version stamp note:** `go install` does not carry ldflags, so
`dbounce --version` will report `commit none, built unknown`. This is
expected and does not affect functionality. Stamped binaries come from
the tagged release artifacts.

> The `go install` PATH note closes #549 (UAT L1 2026-05-24): the
> unmodified `go install` succeeds silently with the binary at
> `~/go/bin/dbounce` while the shell reports "command not found", which
> reads as "install broken" on a fresh machine.

### From source (git clone + go build)

```sh
git clone https://github.com/trsreagan3/dbounce.git
cd dbounce
go build -o bin/dbounce ./cmd/dbounce
./bin/dbounce --version
# or: make build   (drops the binary into ./bin/dbounce)
```

### Available at launch (first tagged release)

> The following paths require a tagged GitHub release with prebuilt
> artifacts. They are configured but dormant — no tag has been pushed yet.
> Note: dbounce uses CGO (pg_query_go wraps libpg_query), so prebuilt
> linux binaries are statically linked with musl; darwin builds use the
> native macOS toolchain. Windows is not supported in v1.0.

#### Homebrew (macOS / Linux)

```sh
brew install trsreagan3/tap/dbounce
```

#### Prebuilt binary (macOS / Linux)

Each [GitHub Release](https://github.com/trsreagan3/dbounce/releases)
attaches `dbounce_<version>_<os>_<arch>.tar.gz` for
`linux`/`darwin` × `amd64`/`arm64`. Download, extract, and
put `dbounce` on your `PATH`:

```sh
# Example: macOS arm64. Swap in the os/arch + version for your machine.
curl -fsSL -o dbounce.tar.gz \
  https://github.com/trsreagan3/dbounce/releases/latest/download/dbounce_<version>_darwin_arm64.tar.gz
tar -xzf dbounce.tar.gz dbounce
sudo install dbounce /usr/local/bin/dbounce
```

#### Scoop (Windows)

Not available in v1.0 (CGO dependency prevents Windows cross-compilation).
Use `go install` on Windows with a MinGW toolchain.

#### APT / RPM (Debian/Ubuntu, RHEL/Fedora)

Releases attach `.deb` + `.rpm` packages. They are **not** published to
a public APT/RPM registry yet — download the package from the release
and install it directly (installs the binary to `/usr/local/bin`):

```sh
# Debian / Ubuntu
curl -fsSL -o dbounce.deb \
  https://github.com/trsreagan3/dbounce/releases/latest/download/dbounce_<version>_linux_amd64.deb
sudo dpkg -i dbounce.deb

# RHEL / Fedora / Amazon Linux
curl -fsSL -o dbounce.rpm \
  https://github.com/trsreagan3/dbounce/releases/latest/download/dbounce_<version>_linux_amd64.rpm
sudo rpm -i dbounce.rpm
```

See [docs/INSTALL-APT.md](docs/INSTALL-APT.md) /
[docs/INSTALL-RPM.md](docs/INSTALL-RPM.md) if present for the full
package runbooks.

#### Docker

See [Docker](#docker) below for the published `ghcr.io/trsreagan3/dbounce`
image.

## Add to your agent

dbounce wires into any MCP-compatible coding agent two ways. Pick
whichever fits your setup; they compose.

### MCP mode — the agent introspects + self-scopes via `dbounce_*` tools

One command per client merges a `dbounce` entry into the agent's MCP
config (idempotent; other MCP servers are preserved):

```sh
dbounce mcp install-claude-code   # Claude Code / Claude Desktop
dbounce mcp install-cursor        # Cursor
dbounce mcp install-codex         # Codex (prints a TOML snippet to paste)
dbounce mcp install-devin         # Devin (cloud-agent recipe; see below)
```

The agent then spawns `dbounce mcp serve` and can call `dbounce_decide`
(dry-run a query's verdict), `dbounce_posture`, `dbounce_active_mode`,
`dbounce_tail_decisions`, `dbounce_profile_allow`, etc. Verify with
`dbounce mcp list-tools` (the same list the agent sees). For any other
MCP client, `dbounce mcp show-config` prints a vendor-neutral JSON/YAML
snippet.

The MCP server reads the **same** on-disk state the running proxy uses
(`--db` + `--profiles-path`); it does **not** start a proxy listener of
its own — run `dbounce run` separately for the gating + forwarding
layer.

### Connect mode — point the agent's DB client through dbounce

Run the proxy, then point your agent's (or any tool's) database
connection string at dbounce instead of the real DB:

```sh
# Proxy on 127.0.0.1:5433, forwarding to the real PG on :5432.
dbounce run \
  --dialect postgres \
  --upstream postgres://user:pass@db-host:5432/mydb \
  --mode transparent --profile safe-default
```

```
# Then in the agent / tool:
DATABASE_URL=postgres://user:pass@127.0.0.1:5433/mydb
```

Every statement the agent runs now traverses dbounce: parsed,
audit-logged, ALLOWs forwarded to the real DB, and (transparent mode)
out-of-profile writes denied with SQLSTATE `42501` before they reach
the database.

### Cloud agents (Devin) + Claude-in-container

`dbounce mcp install-devin` prints a recipe rather than editing a local
config: Devin runs in a cloud sandbox that cannot see your local
`127.0.0.1`, so the bouncer must run on a host the sandbox can reach
(`--host 0.0.0.0 --i-know-this-binds-externally`) and the agent's DB
client points at `<bouncer-host>:5433`. This is an honest limitation,
not a bug — dbounce never requires root or a transparent OS-level proxy.

For running an agent (e.g. Claude Code) inside Docker alongside the
bouncer, see the cross-product
[Claude-in-Docker integration guide](../iam-roles/docs/DOCKER-CLAUDE-INTEGRATION.md).

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
| `cooperative` (default) | Parse + log every statement, then forward it to the upstream and stream the real reply back — **including statements a profile would DENY**. The verdict is recorded as advisory (the audit row shows what transparent mode would have blocked). | Solo dev iterating fast; previewing what transparent mode would block without breaking the workflow. |
| `transparent` | ALLOW verdicts forward to the upstream and stream the real reply back. DENY verdicts return a PG `ErrorResponse` (SQLSTATE `42501`) to the client and the **upstream is never contacted** — the statement does not execute. | Locked-down environments; lower-trust agents; compliance deploys. |

Switch with `--mode cooperative` or `--mode transparent`. (With no
`--upstream` set, dbounce runs observation-only in either mode: it
parses + audit-logs + returns a synthetic `ReadyForQuery`, and nothing
executes.)

---

## Subcommand reference

### `dbounce run`

Start the wire-protocol listener.

- `--port 5433` — TCP port for the SQL wire-protocol listener.
- `--host 127.0.0.1` — interface to bind. Binding to anything else
  requires `--i-know-this-binds-externally` to acknowledge the
  credential-handling threat surface.
- `--mgmt-port 8768` — management HTTP port (`/healthz` +
  `/admin/dynamic-denies/reload`).
- `--mode cooperative|transparent` — see "Operating modes".
- `--default-policy allow|deny` — what transparent mode does when no
  profile/rule matches a statement.
- `--upstream postgres://...` — upstream DB URL. When set, dbounce
  forwards ALLOW verdicts here and streams the real reply back; in
  transparent mode DENY verdicts are blocked before this is contacted.
  With no `--upstream`, dbounce runs observation-only.
- `--allow-internal-upstream` — opt-in to a loopback / RFC1918 /
  `.local` upstream (refused by default to prevent SSRF when the
  upstream URL comes from untrusted config). Use for local-PG dev.
- `--db PATH` — SQLite audit DB path (default
  `~/.dbounce/state.db`, override with `DBOUNCE_DB`).
- `--dialect postgres|mysql|snowflake|bigquery` — wire-protocol
  dialect. `postgres` + `mysql` run as native wire-protocol proxies;
  `snowflake` + `bigquery` use the JDBC-driver-shim (`dbounce run`
  fails fast for those with a pointer to docs/SHIM-INTEGRATION.md).
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

CSV and ocsf-bundle exports ALWAYS redact single-quoted SQL string
literals (MED-D8-09 redactor applied defensively on read) so a bulk
SIEM shipment doesn't carry PII embedded in quoted-string statement
values. Coverage is limited to single-quoted string literals: numeric
literals (`WHERE id = 999887777`), comment contents (`-- token=...`),
and quoted/backtick identifiers are NOT scrubbed. Use parameterised
queries / quoted literals for anything sensitive.

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

### Bind-mounting volumes (UID 65532)

The distroless `:nonroot` base runs as **UID 65532** (non-root for
security; no shell, no package manager). When you bind-mount a host
directory into the container, that directory must be writable by UID
65532 — otherwise dbounce's first attempt to open the SQLite audit
DB will fail with a cryptic error like:

```
open store: unable to open database file
```

Two ways to fix this:

```sh
# Option A — chown the host directory once (preferred for daemons).
mkdir -p ~/.dbounce
sudo chown -R 65532:65532 ~/.dbounce
docker run --rm -it \
  -v ~/.dbounce:/home/nonroot/.dbounce \
  -p 127.0.0.1:5433:5433 \
  -p 127.0.0.1:8768:8768 \
  ghcr.io/trsreagan3/dbounce:latest \
  run --upstream postgres://user:pass@host.docker.internal:5432/mydb

# Option B — run as your host UID (preferred for short-lived dev runs
# where you don't want to leave a host directory owned by 65532).
mkdir -p ~/.dbounce
docker run --rm -it \
  --user $(id -u):$(id -g) \
  -v ~/.dbounce:/home/nonroot/.dbounce \
  -p 127.0.0.1:5433:5433 \
  -p 127.0.0.1:8768:8768 \
  ghcr.io/trsreagan3/dbounce:latest \
  run --upstream postgres://user:pass@host.docker.internal:5432/mydb
```

**macOS / colima caveat**: colima only bind-mounts `/Users/*` paths
reliably. Mounts under `/tmp`, `/var`, or `/private` silently diverge
between the host and the colima VM — files written by the container
may not appear on the host, and vice versa. Always mount paths under
`/Users/<you>/` on Mac.

### docker-compose example

```yaml
# compose.yaml — dbounce with host-owned audit dir.
services:
  dbounce:
    image: ghcr.io/trsreagan3/dbounce:latest
    user: "65532:65532"             # match the distroless :nonroot UID
    command:
      - run
      - --host
      - 0.0.0.0
      - --port
      - "5433"
      - --mgmt-host
      - 0.0.0.0
      - --mgmt-port
      - "8768"
      - --i-know-this-binds-externally
      - --i-know-mgmt-binds-externally
    ports:
      - "127.0.0.1:5433:5433"       # loopback-only on the host
      - "127.0.0.1:8768:8768"
    volumes:
      - ./dbounce-data:/home/nonroot/.dbounce
    # Before `docker compose up`, run once:
    #   mkdir -p ./dbounce-data && sudo chown 65532:65532 ./dbounce-data
```

### Common errors

| Symptom | Cause | Fix |
| --- | --- | --- |
| `open store: unable to open database file` | Bind-mounted dir not writable by UID 65532 | See **Bind-mounting volumes** above |
| `permission denied` on `/home/nonroot/.dbounce/...` | Same UID-65532 ownership issue | `chown -R 65532:65532 <hostdir>` or `--user $(id -u):$(id -g)` |
| Files written in container don't appear on host (macOS) | Mount path under `/tmp` or `/var` on colima | Move mount under `/Users/<you>/` |
| `bind: address already in use` on `:5433` | Local PostgreSQL or another dbounce on the port | `lsof -i :5433` then stop the conflicting process or change `-p 5434:5433` |

### Tags

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

Tests are pure-Go and use a temp-directory SQLite DB per test, so the
default suite needs no real database. Forwarding/enforcement is covered
by `internal/proxy/forwarding_integration_test.go` against an in-process
mock upstream; see `compose.test.yaml` for the optional real-PostgreSQL
integration harness.

---

## Layout

```
dbounce/
  cmd/dbounce/                 # canonical binary (calls internal/cli.Main)
  community-profiles/          # opt-in profiles installed via `dbounce profile install`
  internal/cli/                # cobra command tree (run / audit / mcp / profile / rules / …)
  internal/mcp/                # MCP-over-stdio server (dbounce_* tool family)
  internal/mcpinstall/         # `dbounce mcp install-*` + show-config / list-tools
  internal/parser/             # SQL wire-protocol message parser (AST-aware)
  internal/profile/            # environment profiles + safe-default
  internal/proxy/              # wire-protocol listener + forwarding + enforcement
  internal/rules/              # global rule table
  internal/store/              # SQLite audit + rules + tasks + pauses + prompts
  go.mod
  README.md
```

`internal/...` packages are intentionally not exported — `dbounce` is
a shipped binary, not a library other Go programs link against.

---

## API credits required?

**No** when an AI agent is in the loop. `dbounce` is pure
deterministic SQL rules + audit + MCP server. Your agent (Claude
Code / Cursor / Codex / Devin / any MCP-compatible client) uses its
own LLM credentials (Max / Plus / Pro / API key / Ollama / etc.).
The bouncer never makes an LLM call in this mode — `dbounce` ships
with zero LLM credentials required for local-dev.

**Yes** for standalone deployments (CI/CD / cron / daemon mode with
no agent in the loop). Opt in via `--llm-backend
anthropic|openai|bedrock|ollama` + supply credentials. This is the
minority case.

See [[bouncer-zero-llm-when-agent-in-loop]] in the iam-roles memory
for the full architecture.

---

## License

Apache-2.0 — see [LICENSE](./LICENSE).

Copyright 2026 trsreagan3.

---

## Position in the Bounce suite

`dbounce` is the third product in the Bounce suite — the SQL-shaped
sibling of `kbounce` (Kubernetes) and `ibounce` (HTTP / AWS-SDK).
Same brand, same audit shape, same "creates / never mutates" invariant.
Different audiences, different friction profiles, different
distribution channels — separate products so each can find its own
PMF.

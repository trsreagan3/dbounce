# dbounce changelog

All notable changes to `dbounce` get recorded here. Versioning follows
semver from v1.0.0 onward.

## Unreleased

### Schema endpoint + audit-webhook presets surface (#276 + #259, 2026-05-18)

Cross-product `[[cross-product-agent-parity]]` rollout matching the
ibounce + kbounce siblings:

- **`GET /schemas/config` HTTP endpoint** (#276) — dbounce's mgmt
  port serves the embedded `dbounce-config.schema.json` byte-for-byte
  at `Content-Type: application/schema+json`. Agents that want to
  validate a proposed `dbounce config import` payload against the
  LIVE bouncer's accepted shape fetch this rather than relying on a
  stale GitHub URL. READ-only (PUT/POST/DELETE return 405); no auth
  (matches `/healthz` — the schema is non-sensitive metadata). The
  served bytes are a build-time copy of `schemas/dbounce-config.schema.json`;
  a test asserts byte-equality so drift between the two fails the
  build.
- **`dbounce audit-webhook presets list`** (#259) — operator-facing
  subcommand that prints the four webhook preset shapes the binary
  speaks (`generic`, `datadog`, `splunk-hec`, `sentinel`) + each
  preset's required + optional flags + auth header + body shape.
  `--json` flag emits the structured descriptor list for agent
  consumption. Mirrors the new `list_audit_webhook_presets` MCP tool
  + the matching `ibounce` + `kbounce` subcommands. Per
  `[[audit-webhook-presets]]`.
- **`list_audit_webhook_presets` MCP tool** (#259) — agent-facing
  surface returning the same descriptor list `dbounce audit-webhook
  presets list --json` emits. Identical JSON shape across `ibounce`
  / `kbounce` / `dbounce` so cross-product orchestration code calls
  the matching tool on each bouncer and collates the results
  uniformly.
- **`audit.PresetDescriptors()` shared helper** — single source of
  truth for the preset descriptor list. Both `internal/cli/audit_webhook.go`
  + `internal/mcp/server.go` import it so the CLI surface + MCP
  surface can never drift. A test asserts every name in
  `audit.AllPresets()` shows up in the descriptor list.

### Live audit-stream web UI at `GET /` (#272, 2026-05-18)

dbounce now serves a minimal vanilla-JS web UI at `GET /` on its
mgmt port (`8768` by default) alongside `/healthz` and
`/audit/events`. The page is a single self-contained HTML+CSS+JS
file (no build step, no CDN, no Google Fonts, no analytics, no
telemetry), under 500 lines. Long-polls `/audit/events?since=
<cursor>` every two seconds and renders a colour-coded table with
top-bar event counters, filter input (same syntax as
`/audit/events?filter=`), pause + clear controls, mobile-responsive
layout.

Wire model: long-polling rather than SSE — the existing
`auditEventsHandler` doesn't ship streaming response semantics
today and the operator UX is identical at 2 s tick. A future bump
can swap the JS polling loop for `EventSource` without touching the
server contract.

Same auth model as `/audit/events`: loopback no auth; external bind
takes the bearer token through the URL `#token=...` fragment so the
HTML body never embeds the secret. Strict `Content-Security-Policy`
header. Cross-product-identical HTML shape with ibounce / kbounce
/ gbounce per `[[cross-product-agent-parity]]`.

Per `[[creates-never-mutates]]` the UI is read-only — no button
mutates dbounce state. Per `[[security-team-positioning-safety-not-
surveillance]]` event labels use "deny" / "allow", never
"violation" / "infraction" / "unauthorized". Per `[[self-host-zero-
billing-dependency]]` no CDN dependencies; everything inline.

New file: `internal/proxy/events_ui.go`. Tests:
`internal/proxy/events_ui_test.go`. Doc section in
`docs/AUDIT-TAIL.md`.

The cross-bouncer TUI sibling (`iam-jit audit stream`) merges live
streams from every reachable bouncer into one terminal table; see
`iam-roles/docs/AUDIT-STREAM-TUI.md`.

### HTTP `/audit/events` endpoint (#271, 2026-05-18)

GET `/audit/events` ships on the existing mgmt port (`8768` by
default) alongside `/healthz`. Same filter language as `dbounce
audit tail --filter`, same supported field catalog (cross-product
OCSF + dbounce-specific `unmapped.iam_jit.ext.*` fields), same OCSF
v1.1.0 wire shape. Query parameters: `since` / `until` (ISO 8601),
`filter` (repeatable; `field=value` / `field~regex` / `field>=N` /
`field<=N`), `limit` (default 100, max 1000), `format` (`jsonl`
default | `ocsf-bundle`). Loopback bind requires no auth; external
bind requires a bearer token via the new `dbounce run
--audit-events-token TOKEN` flag (refuses to start in external-bind
mode without it). Filter logic factored into the new
`internal/audit/filter.go` so both the CLI surface and the HTTP
surface call the same parser. Powers the cross-bouncer `iam-jit
audit query` CLI which queries every reachable bouncer in parallel
+ merges results. Per `[[cross-product-agent-parity]]` +
`[[creates-never-mutates]]` (read-only) + `[[self-host-zero-billing-
dependency]]` (operator-controlled port; no phone-home).

### Investigate-with-Claude workflow (#273, 2026-05-18)

`dbounce investigate` composes the existing `audit tail --export
ocsf-bundle` (#268) and `diagnostics bundle` (#277) into a single
"land a Claude-ready evidence pack" subcommand. Operator drops the
two artifacts into THEIR local Claude client (Claude Code, Cursor's
Claude integration, desktop Claude, the Anthropic console —
whichever they use) and asks an investigative prompt; dbounce never
calls Anthropic. Per `[[self-host-zero-billing-dependency]]` the
only network call is the same local /healthz GET `diagnostics
bundle` makes. Per `[[creates-never-mutates]]` it's read-only.

Cross-product alignment per `[[cross-product-agent-parity]]` —
ibounce / kbounce / gbounce ship the same subcommand shape with
the same `--out-dir` / `--time-range` / `--filter` /
`--print-prompts` flag set.

- Writes `dbounce-investigation.ndjson` (OCSF v1.1.0 class 2004
  Detection Finding bundle wrapping the filtered + redacted audit
  events) + `dbounce-investigation-context.zip` (the standard
  diagnostics bundle with `--no-audit` — the evidence file already
  carries the audit content).
- `--print-prompts` lists the 10 starter investigative prompts as a
  paste-able block without writing artifact files. dbounce variants
  include write-query bursts + DDL-outside-change-window prompts.
- `--time-range 24h|7d|4w` filters the evidence to a recent window.
- `--dialect postgres|mysql|snowflake|bigquery` labels the context
  bundle's runtime dialect for the Claude analyst.
- Per `[[don't-tailor-to-lighthouse]]` the prompts are generic — no
  specific Claude surface is named.
- Per `[[security-team-positioning-safety-not-surveillance]]` the
  prompts stay in the "denial / scope mismatch / policy mismatch"
  vocabulary; nothing reads as accusation.

Docs: `docs/INVESTIGATE-WITH-CLAUDE.md` — workflow walkthrough,
the 10 starter prompts, privacy story, and cross-bouncer parity
notes.

### Cross-product config-export wire reconciliation (#288, 2026-05-18)

Closes `[[cross-product-agent-parity]]`-#288. The `dbounce config
export/import` wire shape now matches ibounce + gbounce + kbounce
exactly so a single cross-product backup workflow targets every Bounce
product with one CLI shape.

- **`schema_version`** is now `"1.0"` (string semver) instead of int
  `format_version: 1`. Bumps to `"1.1"` (additive) or `"2.0"`
  (breaking) preserve the parser shape across version drift.
- **`format: "dbounce.config"`** magic string is DROPPED. The
  cross-product-canonical `product: "dbounce"` field carries the same
  cross-product-reject semantic with the same field name the other
  Bounce products use.
- **`schema_version: <int>` (pre-#288: STORE schema version)** renamed
  to **`store_schema_version: <int>`** to break the field-name
  collision with the new wire-format `schema_version`.
- **`--in PATH`** is the primary `config import` flag (matches
  ibounce + gbounce + kbounce). `--input PATH` / `-i PATH` stay as
  DEPRECATED aliases — still work, print a stderr deprecation warning.
- **`source_hostname_hash`** field added — sha256[:12] of os.Hostname()
  per the same privacy-preserving attribution convention used by
  `dbounce backup` metadata + the sibling Bounce products.
- **Backwards compat** — pre-#288 exports (`format` + `format_version`
  + int `schema_version`) import cleanly into the new binary. The
  importer rewrites the legacy fields onto the canonical shape before
  schema validation runs + prints a stderr deprecation warning. The
  compat window stays open across the full v1.x line.
- **Testdata fixture** —
  `internal/cli/testdata/legacy-pre-288-wire-shape.json` pins a
  pre-#288 export as a regression watchdog so a future shape-
  normalizer change cannot silently drop legacy compat.
- **Docs** — new `docs/CONFIG-EXPORT-IMPORT.md` covers the wire shape,
  CLI flags, cross-product parity contract, and backwards-compat
  window.

### SQLite backup + restore (#279, 2026-05-18)

Two new top-level subcommands ship online backup + structured restore of
the dbounce state.db for migration / DR / audit-trail preservation:

- **`dbounce backup --out PATH [--include-audit] [--include-prompts]`**
  — uses SQLite's `VACUUM INTO` for atomic online backup; the source
  database is NOT locked, concurrent writers continue. Default excludes
  the two high-volume tables (`pending_audit_events`,
  `pending_prompts`); opt in via flag. Embeds a `dbounce_backup_metadata`
  table carrying dbounce_version, created_at (RFC3339),
  source_hostname_hash (sha256[:12]), schema_version, and the included
  flags.
- **`dbounce restore --in PATH [--force]`** — wholesale file-level
  replacement of state.db. Validates schema_version (HARD; --force
  does NOT override — cross-schema migration is `dbounce migrate`
  territory), dbounce_version (soft; --force overrides with a warning),
  destination-empty (unless --force), and probes loopback ports
  5433 + 8768 to refuse if `dbounce run` is alive. Emits row counts +
  sha256 of the restored DB.
- **Cross-product alignment** per [[cross-product-agent-parity]]:
  kbounce + ibounce ship the same CLI shape + flag names + metadata-
  table format. The product-namespaced metadata-table name
  (`dbounce_backup_metadata` / `kbounce_backup_metadata` /
  `iam_jit_backup_metadata`) lets shared tooling tell which product
  produced a given backup file.
- **ADMIN_ACTION audit events**: `backup.create` + `backup.restore`
  enqueue via the same pending_audit_events queue as every other admin
  mutation.
- **Docs**: `docs/BACKUP-RESTORE.md` covers the why, the
  online-vs-stop-required contract, schema-version safety, and a sample
  session.

### Bulk-prompt-answer UX (2026-05-18)

Closes the "block-happy = uninstalled" failure mode per
[[safety-mode-lean-permissive]] + [[bulk-prompt-answer-ux]]. When the
proxy is blocking many calls in a short window (typically because the
wrong profile is active, or the work is exploratory), the operator
gets a one-shot escape hatch instead of a wall of per-call prompts:

- **Burst detector** (`internal/proxy/burst.go`) — sliding-window
  pending-prompt counter; arms at threshold (default N=5 in T=60s);
  re-arms after operator answer or 5-minute cool-down. Mutex-guarded
  for the per-conn goroutines that call Record from arbitrary threads.
- **Time-bounded rules** — rules table gains `expires_at` (schema v5);
  `LoadRuleSet` filters past-expiry rows; new `SweepExpiredRules` reaps
  lazily. Audit chain preserved via `decisions.matched_rule_id`.
- **`dbounce prompts bulk-pending`** — read-only burst summary grouped
  by (dialect, statement_type, table). Previews which rules
  `bulk-answer` would synthesize.
- **`dbounce prompts bulk-answer --decision X`** — resolves all
  pending prompts en masse. `10min` / `3h` / `session` create
  time-bounded ALLOW rules; `profile --profile NAME` posts a hot-swap
  signal (cross-process via the new `profile_overrides` table); `none`
  is a no-op. Per-dialect rule synthesis: a mixed PG+MySQL burst
  creates separate rules per dialect so PG-shaped allows never spill
  into MySQL traffic.
- **Profile hot-swap** — `Server.SwapProfile` swaps the running
  active profile under an RWMutex without a restart; the burst
  sweeper goroutine polls `profile_overrides` every ~5s and applies
  the swap.
- **Burst sweeper goroutine** — long-lived background tick that
  reaps expired rules + applies pending profile-swap signals. Joins
  via `Server.connWG`; canceled BEFORE `connWG.Wait` in `Shutdown` so
  the drain ordering matches the heartbeater pattern closed in
  276298f.
- **MCP `dbounce_prompts_bulk_pending`** — read-only burst summary
  for agents.
- **MCP `dbounce_prompts_bulk_answer`** — mutating bulk-answer tool.
  GATED behind the operator-set `--bulk-answer-mcp-token` flag;
  default empty so adversarial agents cannot bulk-allow themselves
  unsupervised per [[bulk-prompt-answer-ux]] "Don't expose the
  burst-answer affordance to the AGENT without operator opt-in."

### Audit-export failure visibility (2026-05-18)

Closes the stealth-bypass gap flagged in the Slice 1 BB+WB audit per
[[audit-export-failure-visibility]]: silently-failing log writes or
webhook posts left operators thinking they had visibility when they
had none. Five surfaces ship together per
[[deliberate-feature-completion]]:

- **`/healthz` `audit_export_health` block** — per-transport health
  (log_writes_ok, webhook_consecutive_failures,
  webhook_last_success_seconds_ago, auth_failed) plus an aggregate
  degraded flag + reason. When degraded, `/healthz` returns 503 so
  external monitors / K8s liveness probes alert.
- **`dbounce audit-export health` CLI** — operator-facing explicit
  check; reads `/healthz`; non-zero exit when degraded. `--json` mode
  for tooling.
- **`audit_export_degraded` OCSF SECURITY_ALERT** — new alert rule
  (`activity_name="audit_export_degraded"`, severity Medium). Fires
  via three lanes at once: stderr (operator-immediate), the audit-
  export channel best-effort (so a SIEM sees it via any surviving
  transport), and the `/healthz` 503 flip. Debounced at one alert per
  5min window unless the failure-mode reason shifts. Opt-in via
  `--audit-export-health-interval DURATION` (default OFF; recommended
  30s).
- **F1-F8 per-failure-mode tests** —
  `internal/audit/export_health_test.go` covers webhook unreachable
  (F1), 401/403 auth (F2), persistent 5xx (F3), log perm-denied (F4),
  disk-full (F5, folded into F4), log file deleted mid-run (F6, with
  re-open recovery via stat-check every 64 writes), queue overflow
  (F7), and the placeholder gate for license-expiry (F8, deferred
  pending #235).
- **MCP `dbounce_audit_export_status`** — now also surfaces the
  derived `audit_export_health` block + `degraded_alert_fired` /
  `degraded_alert_suppressed` counters for agents that want to
  introspect the SIEM-side alert volume.

Webhook URL masking in the health surface goes beyond Slice 1's
userinfo-strip: the URL path is also masked (`scheme://host/***`) so
Datadog / Sentinel workspace ids embedded in the path don't leak via
`/healthz`. Sibling agents in ibounce + kbounce ship the same field
names + the same `rule_id="audit_export_degraded"` so a single cross-
product SIEM rule catches all three.

### Docs

- README quickstart now shows `--allow-internal-upstream` inline for
  loopback upstreams (local PG on 127.0.0.1) so first-run users with a
  local Postgres don't hit the SSRF-gate refusal silently.

### D-Slice 1 — Foundation (2026-05-17)

First slice of dbounce. Ships the observation-only PostgreSQL wire-
protocol proxy + AST-aware statement parser + decision audit log +
minimum CLI surface (`run`, `audit tail`, `--version`, `/healthz`).

- **PostgreSQL wire-protocol listener** — TCP accept loop that parses
  inbound `Query` / `Parse` / `Bind` / `Execute` simple-protocol +
  extended-protocol messages. D-Slice 1 is observation-only: each
  inbound statement is parsed, classified, audit-logged, then a
  synthetic `ReadyForQuery` is returned to the client. **No upstream
  forwarding** — that ships in D-Slice 2.
- **AST integration** — `github.com/pganalyze/pg_query_go/v6` (pure-
  Go bindings to libpg_query; tracks the PostgreSQL 16 grammar).
  Statement classifier handles `SELECT`, `INSERT`/`UPDATE`/`DELETE`/
  `MERGE`, `INSERT ... ON CONFLICT`, DDL (`CREATE`/`ALTER`/`DROP`/
  `TRUNCATE`), CTE-wrapped writes (the AST walker surfaces the
  `UPDATE`/`INSERT`/`DELETE` node even when the top-level keyword is
  `WITH`), stored-procedure call sites (`CALL`, `DO $$ ... $$`,
  `EXECUTE 'sql_string'`), volatile function calls (`SELECT
  pg_sleep(60)`), `EXPLAIN` vs `EXPLAIN ANALYZE`, and session-state
  changes (`SET ROLE`).
- **Audit store** — SQLite at `~/.dbounce/state.db` (0o700 parent
  dir). Tables: `schema_version`, `decisions`, `rules` (scaffolded
  for D-Slice 3), `tasks` (scaffolded), `pause_events` (scaffolded
  for D-Slice 8), `pending_prompts` (scaffolded). Decisions row shape
  includes `statement`, `statement_type`, `tables`, `functions`,
  `decision_verdict`, `decision_reason`, `mode_at_decision`,
  `enforced`, `is_stream`, `stream_kind`, `decision_source`,
  `profile_name`, `task_id`, `pause_id` so D-Slices 3+ can JOIN
  without schema churn.
- **CLI** — cobra command tree: `dbounce run` (listener),
  `dbounce audit tail [--limit N]` (recent decisions),
  `dbounce --version` (built with `-ldflags -X ...commit -X
  ...buildTime`).
- **`/healthz`** — separate management HTTP port (`--mgmt-port 8768`,
  distinct from kbounce's 8766 and ibounce's 8767). Returns 200 with
  `status` / `mode` / `default_policy` / `dialect` / `active_profile`
  / `decisions_count` / `lookup_errors_counter` / `pause`. Bypasses
  the SQL-wire listener entirely; never writes audit rows.
- **External-bind guard** — `dbounce run --host 0.0.0.0` requires
  `--i-know-this-binds-externally` (mirrors kbounce + ibounce
  WB32-02 closure).
- **Banner on `dbounce run`** — surfaces cooperative-mode default,
  observation-only consequence, how to opt into transparent mode,
  and the read-vs-write framing the safe-default profile (D-Slice 7)
  will hook into.

Features explicitly NOT shipped in D-Slice 1: real upstream
forwarding (D-Slice 2), rule engine + tasks (D-Slice 3), TLS on the
inbound listener (D-Slice 4), MySQL wire protocol (D-Slice 5),
Snowflake + BigQuery (D-Slice 6), profile YAML + `safe-default` +
MCP (D-Slice 7), pause + prompts + presets + recommender (D-Slice 8).

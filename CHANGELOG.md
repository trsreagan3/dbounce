# dbounce changelog

All notable changes to `dbounce` get recorded here. Versioning follows
semver from v1.0.0 onward.

## Unreleased

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

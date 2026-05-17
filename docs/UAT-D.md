# UAT-D — Outside-context walkthrough plan for D-Slice 7 (profiles + MCP)

Companion to UAT-K2 (kbouncer) and the iam-jit-bouncer outside-context
walkthroughs. The point is the same: a reviewer who has NEVER seen the
codebase before should be able to follow each step, exercise it, and
spot rough edges the implementer was too close to see.

## Scope

D-Slice 7 ships:

1. **Environment profiles** — `internal/profile` + the two built-in
   profiles `full-user` (default; passthrough) and `safe-default`
   (sql_read_only baseline + AST-walk Layer 2 backstop for mutations).
   Profile rules are a HARD FLOOR — a permissive task scope cannot
   override a profile deny.
2. **`dbounce profile list/show/install/install-defaults` CLI** —
   mirrors kbouncer's `kbounce profile ...` shape.
3. **AST-walk Layer 2 backstop wired into the proxy** —
   `internal/proxy/proxy.go` calls `profile.Evaluate()` BEFORE the
   task / global rule engine. CTE-wrapped writes (top-level keyword
   WITH, deeper UPDATE/DELETE/INSERT) deny via `HasMutatingNode`.
4. **MCP server** — `internal/mcp` + `dbounce mcp serve` /
   `install-{claude-code,cursor,codex}` / `show-config` / `list-tools`.
   9 tools: `dbounce_active_mode`, `dbounce_active_profile`,
   `dbounce_active_task`, `dbounce_recommend_mode_for_task`
   (DETERMINISTIC), `dbounce_list_rules`, `dbounce_add_rule`,
   `dbounce_remove_rule`, `dbounce_decide`, `dbounce_tail_decisions`.
5. **Tests** — profile + AST-walk + MCP + CLI install coverage,
   `go vet ./...` clean, `go test ./... -count=1` green.

## Quick reference

- Repo: `dbounce` (Go module: `github.com/trsreagan3/dbounce`)
- Branch: `dslice-7-profiles`
- Default profile file: `~/.dbounce/profiles.yaml`
  (override: `DBOUNCE_PROFILES_PATH`)
- Default audit DB: `~/.dbounce/state.db`
  (override: `DBOUNCE_DB`)
- Default wire-protocol port: `5433` (loopback only)
- Default management port: `8768` (`/healthz`)
- Default profile env var: `DBOUNCE_PROFILE`

## Walkthrough scenarios

### Scenario 1 — fresh install: defaults land cleanly

1. From a clean clone:

   ```
   go build ./...
   go test ./... -count=1
   ```

   Expect: every package green. No `Reagan`, no `Omise`, no
   `/Users/reagan/` leak.

2. Materialize the embedded defaults on disk:

   ```
   DBOUNCE_PROFILES_PATH=/tmp/dbounce-uat-d/profiles.yaml \
     go run ./cmd/dbounce profile install-defaults
   cat /tmp/dbounce-uat-d/profiles.yaml
   ```

   Expect:
   - `full-user` + `safe-default` in the YAML
   - `allow_baseline: sql_read_only` + `deny_ast_mutating_nodes: true`
     on safe-default
   - A leading comment block explaining what each profile does
   - File mode `0600` (operator-only read)

3. Re-running `install-defaults` MUST NOT overwrite the file:

   ```
   echo '# my edit' >> /tmp/dbounce-uat-d/profiles.yaml
   DBOUNCE_PROFILES_PATH=/tmp/dbounce-uat-d/profiles.yaml \
     go run ./cmd/dbounce profile install-defaults
   tail -1 /tmp/dbounce-uat-d/profiles.yaml
   ```

   Expect: `# my edit` survives + CLI prints "already exists; pass
   --force to overwrite".

### Scenario 2 — `dbounce profile list/show` shows the right shape

1. List:

   ```
   DBOUNCE_PROFILES_PATH=/tmp/dbounce-uat-d/profiles.yaml \
     go run ./cmd/dbounce profile list --profile safe-default
   ```

   Expect: `* safe-default` (active marker) + `allow_baseline:
   sql_read_only` + `deny_ast_mutating_nodes: true` lines.

2. Show:

   ```
   DBOUNCE_PROFILES_PATH=/tmp/dbounce-uat-d/profiles.yaml \
     go run ./cmd/dbounce profile show safe-default
   ```

   Expect: the full profile record including `description`, `source:
   local`, `allow_baseline`, `deny_ast_mutating_nodes`.

3. Show unknown:

   ```
   DBOUNCE_PROFILES_PATH=/tmp/dbounce-uat-d/profiles.yaml \
     go run ./cmd/dbounce profile show nope
   ```

   Expect: exit 1 + stderr "profile 'nope' not found (loaded:
   full-user, safe-default)".

4. Deprecation alias warning:

   ```
   DBOUNCE_PROFILES_PATH=/tmp/dbounce-uat-d/profiles.yaml \
     go run ./cmd/dbounce profile show readonly
   ```

   Expect: stderr "profile name 'readonly' is deprecated; use
   'safe-default'..." + the safe-default record on stdout.

### Scenario 3 — safe-default catches CTE-hidden writes (LOAD-BEARING)

This is the load-bearing safety claim for the whole profile package.

1. With safe-default active, dry-run a pure SELECT via the MCP
   `dbounce_decide` tool:

   ```
   echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dbounce_decide","arguments":{"statement":"SELECT id FROM public.users"}}}' | \
     DBOUNCE_DB=/tmp/dbounce-uat-d/state.db \
     DBOUNCE_PROFILES_PATH=/tmp/dbounce-uat-d/profiles.yaml \
     go run ./cmd/dbounce mcp serve --profile safe-default
   ```

   Expect: `{"verdict": "allow", "decision_source": "profile.allow",
   "reason": "...sql_read_only baseline matched..."}`

2. Dry-run a top-level DELETE:

   ```
   echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dbounce_decide","arguments":{"statement":"DELETE FROM public.users WHERE id < 100"}}}' | \
     DBOUNCE_DB=/tmp/dbounce-uat-d/state.db \
     DBOUNCE_PROFILES_PATH=/tmp/dbounce-uat-d/profiles.yaml \
     go run ./cmd/dbounce mcp serve --profile safe-default
   ```

   Expect: `verdict: deny`, `decision_source: profile`, reason
   mentions "AST-walk backstop".

3. Dry-run a CTE-wrapped DELETE that looks like a SELECT at the top:

   ```
   echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dbounce_decide","arguments":{"statement":"WITH gone AS (DELETE FROM public.users WHERE id < 100 RETURNING id) SELECT COUNT(*) FROM gone"}}}' | \
     DBOUNCE_DB=/tmp/dbounce-uat-d/state.db \
     DBOUNCE_PROFILES_PATH=/tmp/dbounce-uat-d/profiles.yaml \
     go run ./cmd/dbounce mcp serve --profile safe-default
   ```

   Expect: `verdict: deny`. This is the load-bearing scenario — if it
   passes, safe-default is security theater.

### Scenario 4 — MCP server tool surface

1. List tools:

   ```
   go run ./cmd/dbounce mcp list-tools
   ```

   Expect at minimum these 9 names:
   - `dbounce_active_mode`
   - `dbounce_active_profile`
   - `dbounce_active_task`
   - `dbounce_recommend_mode_for_task`
   - `dbounce_list_rules`
   - `dbounce_add_rule`
   - `dbounce_remove_rule`
   - `dbounce_decide`
   - `dbounce_tail_decisions`

2. Show config:

   ```
   go run ./cmd/dbounce mcp show-config
   go run ./cmd/dbounce mcp show-config --shape yaml
   ```

   Expect: JSON / YAML snippets with
   `command: dbounce, args: [mcp, serve]`.

3. Install into a temp Claude Code config:

   ```
   go run ./cmd/dbounce mcp install-claude-code --path /tmp/dbounce-uat-d/claude.json
   cat /tmp/dbounce-uat-d/claude.json
   ```

   Expect: `mcpServers.dbounce.command = "dbounce"`,
   `args = ["mcp", "serve"]`.

4. Re-running into the SAME path with another server preserved:

   ```
   echo '{"mcpServers":{"other":{"command":"x","args":[],"env":{}}}}' \
     > /tmp/dbounce-uat-d/claude.json
   go run ./cmd/dbounce mcp install-claude-code --path /tmp/dbounce-uat-d/claude.json
   cat /tmp/dbounce-uat-d/claude.json | jq .mcpServers
   ```

   Expect: both `other` AND `dbounce` present.

5. Codex prints a TOML manual snippet (does NOT write the file):

   ```
   go run ./cmd/dbounce mcp install-codex --path /tmp/dbounce-uat-d/codex.toml
   test -f /tmp/dbounce-uat-d/codex.toml && echo BAD || echo OK
   ```

   Expect: `OK` (file MUST NOT exist).

### Scenario 5 — DETERMINISTIC mode recommender

Validate `dbounce_recommend_mode_for_task` is a fixed decision matrix
(no LLM call).

1. SELECT-only description:

   ```
   echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dbounce_recommend_mode_for_task","arguments":{"description":"SELECT * from public.users"}}}' | \
     go run ./cmd/dbounce mcp serve
   ```

   Expect: `{"mode": "cooperative", "deterministic": true, ...}`

2. Prod-target DELETE:

   ```
   echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dbounce_recommend_mode_for_task","arguments":{"description":"DELETE FROM users","targets_prod":true}}}' | \
     go run ./cmd/dbounce mcp serve
   ```

   Expect: `{"mode": "transparent", "deterministic": true, ...}`

3. Ambiguous description (should default to cooperative per
   safety-mode-lean-permissive):

   ```
   echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dbounce_recommend_mode_for_task","arguments":{"description":"investigate something"}}}' | \
     go run ./cmd/dbounce mcp serve
   ```

   Expect: `{"mode": "cooperative", ...}` — ambiguous never escalates
   to transparent under the SQL-shaped matrix.

### Scenario 6 — `dbounce run --profile safe-default` startup banner

1. With safe-default selected explicitly:

   ```
   DBOUNCE_DB=/tmp/dbounce-uat-d/state.db \
   DBOUNCE_PROFILES_PATH=/tmp/dbounce-uat-d/profiles.yaml \
     go run ./cmd/dbounce run --profile safe-default
   ```

   (Ctrl+C to exit.)

   Expect the startup banner to show `profile=safe-default` somewhere
   in the output. (The current banner says "no profile selected
   (safe-default profile ships in D-Slice 7)" — D-Slice 7 makes this
   accurate.)

### Scenario 7 — install profile from HTTPS URL (smoke)

Use Python or any HTTPS server to serve a profile fixture; verify the
install path completes + the resulting profile is marked read-only.

1. From the test suite:

   ```
   go test ./internal/profile/ -run TestInstall -count=1 -v
   ```

   Expect: `TestInstall_RoundTrip_WithSHA256Pin` + `TestInstall_*`
   green.

## Sign-off checklist

- [ ] `go vet ./...` clean (no warnings)
- [ ] `go test ./... -count=1` green (full suite)
- [ ] 10× `go test ./internal/proxy/... -count=1` runs all green
      (port-race regression guard)
- [ ] `git grep -i "reagan\|omise" -- ':!*.md' ':!testdata'
      ':!internal/packs'` returns nothing (internal/packs has a legit
      anti-leakage test fixture)
- [ ] `git grep "/Users/" -- ':!*.md' ':!docs'` returns nothing
- [ ] `dbounce profile list` works
- [ ] `dbounce profile show safe-default` prints `allow_baseline:
      sql_read_only` + `deny_ast_mutating_nodes: true`
- [ ] `dbounce mcp list-tools` lists 9 tools
- [ ] Scenario 3 (CTE-hidden write) MUST deny

## What's NOT in D-Slice 7

For reviewer clarity:

- The `dbounce pause` / `dbounce prompts` / `dbounce presets` /
  `dbounce recommend` subcommands ship in D-Slice 8 (parallel agent's
  branch).
- Per-account `llm_policy` and any LLM-driven tools — never in
  dbounce (per `[[scorer-is-ground-truth]]`).
- A `dbounce profile` mutation endpoint via MCP. Agents can READ the
  active profile via `dbounce_active_profile` but cannot CHANGE it;
  switching profiles is a human/admin action per
  `[[agent-friendly-not-bypassable]]`.

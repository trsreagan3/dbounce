# Investigate with Claude

`dbounce investigate` is a one-shot helper that lands a Claude-ready
evidence pack on disk. The operator drops both artifacts into THEIR
local Claude client (Claude Code / Cursor / desktop Claude / the
Anthropic console — whichever they use) and runs an investigative
prompt. **dbounce never calls Anthropic.** The audit data leaves
your host only if you choose to paste it.

The subcommand exists because the most useful thing a Claude agent
can do for a self-host operator is read their database-access audit
data and notice patterns a human would miss in a thousand-row
SQLite scroll.

## What the subcommand does

```
dbounce investigate [--out-dir DIR]
                    [--time-range 24h | 7d | 4w]
                    [--filter EXPR ...]
                    [--print-prompts]
                    [--db PATH] [--profiles-path PATH]
                    [--dialect postgres|mysql|snowflake|bigquery]
                    [--mgmt-url URL]
```

It writes two files into `--out-dir`:

- `dbounce-investigation.ndjson` — an OCSF v1.1.0 class 2004
  (Detection Finding) wrapping the filtered audit events. Statements
  + literals are redacted via the same path the `audit tail --export
  ocsf-bundle` SIEM export uses (so a Claude analyst sees `$1`/`$2`
  parameter markers, not the original values). The wrapper carries
  an `investigate` block recording the requested time window,
  whether the audit store was populated, and the event count — so
  the analyst can distinguish "quiet day" from "log was wiped".
- `dbounce-investigation-context.zip` — the standard `dbounce
  diagnostics bundle` output with `--no-audit` set (the evidence
  file already carries the audit content). Includes redacted
  config, active profile fingerprint, `/healthz` snapshot, SQLite
  stats, env-var keys, and the manifest.

Then it prints a "now what" block: three of the ten starter
prompts, a one-line privacy reminder, and a pointer to this doc.

## Step-by-step workflow

```
+------------------------------------------------------------+
|  1. Run: dbounce investigate --time-range 24h              |
|                                                             |
|     Output (truncated):                                     |
|       Artifacts written:                                    |
|         evidence  /tmp/.../dbounce-investigation.ndjson     |
|         context   /tmp/.../dbounce-investigation-context.zip|
+------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------+
|  2. Open YOUR local Claude client.                          |
|     (Claude Code, Cursor's Claude integration, the desktop  |
|      app, or the Anthropic console — operator's choice.)    |
+------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------+
|  3. Drop BOTH files into the conversation.                  |
|     (Most clients accept attachments via drag-and-drop or   |
|      a paperclip button.)                                   |
+------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------+
|  4. Ask one of the starter prompts:                         |
|       "Review the past 24h of dbounce audit data.           |
|        Anything that looks off?"                            |
+------------------------------------------------------------+
                          |
                          v
+------------------------------------------------------------+
|  5. Iterate. The starter prompts are just openers — once    |
|     Claude has the evidence + context in scope, follow up   |
|     with whatever the first answer suggests.                |
+------------------------------------------------------------+
```

## The ten starter prompts

Run `dbounce investigate --print-prompts` to get a paste-able copy
without writing artifact files. The list is also reproduced here so
operators reviewing the doc in a runbook context don't need to
shell out.

 1. Review the past 24h of dbounce audit data. Anything that looks
    off?
 2. Which agent generated the most denies? Was it consistent or a
    one-shot spike?
 3. Did the heartbeat gap ever exceed 60s? If yes, when + how
    often?
 4. Are there bursts of write queries (INSERT/UPDATE/DELETE) from
    one agent in a short window? List actor + time range + affected
    tables.
 5. Did any admin-action audit event happen outside normal working
    hours? List them with timestamps.
 6. Cross-reference the rule-trigger times against the audit-export
    channel's failures (if any). Any correlation?
 7. Did any DDL statements (CREATE/ALTER/DROP) run outside a
    planned change window? Identify the agent + statement.
 8. Which tables show up in the most denies? Does that match the
    active profile's intent?
 9. Did the same `agent.session_id` show up across multiple
    dbounce deployments or restarts? Was that expected?
10. Summarize the most common denial reasons and what they imply
    about the currently-active profile.

Per project guidance the prompts stay generic re: Claude client —
no specific surface is named, no Cursor-vs-Codex-vs-Claude-Code
preference is implied. The operator picks the client; dbounce just
lands evidence.

## Privacy and operator-side responsibilities

`dbounce investigate` itself is strictly local:

- **No network calls** except a single LOCAL `/healthz` GET on the
  loopback port (same as `dbounce diagnostics bundle`).
- **No telemetry.** dbounce does not phone home in any way.
- **No Anthropic API call.** The subcommand never sends data to
  Anthropic. That decision is yours and happens inside YOUR Claude
  session.
- **Read-only.** The subcommand never writes to the store, the
  profiles file, or the audit log. It only creates the two
  artifacts in `--out-dir`.

What the operator should think about BEFORE pasting:

- **Your Claude session is yours.** If you use a hosted Claude
  (claude.ai, the API, Claude Code with default settings), the
  audit data goes to Anthropic the moment you upload it. That may
  or may not be acceptable in your environment. Check your data-
  classification policy first.
- **Statements are redacted.** Unlike a raw SQL log, the evidence
  NDJSON carries statements with literal values replaced by `$N`
  parameter markers — same redactor as `dbounce audit tail
  --export ocsf-bundle`. Table + column names ARE present so the
  analyst can reason about the schema.
- **The context bundle IS redacted** — webhook tokens masked, user
  IDs hashed, env-var keys only without values. Safe to share more
  broadly than the evidence file.
- **For regulated environments**: use a local Claude (running
  through Ollama or similar) so no data leaves the host. The
  artifact shape is the same; only the client surface changes.

## Composability with other workflows

- The evidence NDJSON drops straight into a SIEM that indexes OCSF
  class 2004 (Splunk Enterprise Security, AWS Security Lake,
  Microsoft Sentinel). The Detection Finding shape lets the
  investigation surface in the SIEM's existing "open findings"
  queue without a custom parser.
- The context ZIP is the same artifact `dbounce diagnostics bundle`
  produces. If you already pipe support bundles to a ticketing
  system, the same pipeline works for investigation captures.
- For incident review: `dbounce investigate --time-range 7d
  --out-dir ./incident-2026-05-18` produces a stable, named
  directory you can attach to a post-mortem.

## Related docs

- `docs/AUDIT-TAIL.md` — the filter grammar `--filter` shares with
  `dbounce audit tail`.
- `docs/DIAGNOSTICS.md` — full breakdown of what the context-bundle
  ZIP contains and which fields are redacted.

## Cross-product alignment

The same `investigate` subcommand ships in `ibounce` (AWS IAM
API), `kbounce` (Kubernetes API), and `gbounce` (generic HTTP
forward proxy) with identical flags and prompt structure. An
operator running multiple bouncers learns ONE muscle-memory
pattern:

```
ibounce investigate --time-range 24h --out-dir ./ibounce-out
kbounce investigate --time-range 24h --out-dir ./kbounce-out
dbounce investigate --time-range 24h --out-dir ./dbounce-out
gbounce investigate --time-range 24h --out-dir ./gbounce-out
```

Drop all four evidence packs into one Claude session and ask
prompt 9 ("Did the same `agent.session_id` show up across multiple
products?") for cross-bouncer correlation.

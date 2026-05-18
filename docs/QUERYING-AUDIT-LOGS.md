# Querying dbounce Audit Logs

dbounce emits OCSF v1.1.0 class 6003 (API Activity) events through the
audit-export transport (#252 Slice 1) to whichever collector the
operator configured: a JSONL log file on disk, an HTTPS webhook to a
SIEM, or both. dbounce itself does NOT retain logs — your collector
owns retention.

This page lists worked queries per SIEM for the most common
post-incident question:

> _"Which agent did this — months later?"_

The queries below all key on the cross-product `unmapped.iam_jit.agent`
block per the [[agent-identity-in-audit]] memo. The same JSON path
appears in ibounce + kbounce events so a single SIEM rule can correlate
agent activity across ALL THREE products.

---

## Retention

dbounce does NOT hold customer logs — your collector handles retention.

| Collector            | Default hot retention | Notes                                                         |
| -------------------- | --------------------- | ------------------------------------------------------------- |
| Splunk               | 90 days hot          | Per index settings — operator-configurable                    |
| Datadog Logs         | 15 days              | Standard plan; extendable via archive forwarding              |
| Microsoft Sentinel   | 90 days              | Per workspace settings; Basic Logs tier extends to 7+ years   |
| AWS Security Lake    | Effectively forever  | S3 lifecycle policies — typical: 90d hot, Glacier indefinite  |
| Local JSONL file     | Until logrotate      | Operator-controlled via logrotate / Fluent Bit / Vector       |

The local SQLite audit DB (the per-decision row store) is APPEND-ONLY
since install. Operators control wipe; dbounce does not auto-rotate.

---

## Agent identity fields

Every audit event carries an OPTIONAL block under
`unmapped.iam_jit.agent`:

```json
"unmapped": {
  "iam_jit": {
    "agent": {
      "name": "claude-code" | "cursor" | "codex" | "devin" | "psql" |
              "pgcli" | "psycopg2" | "pg-jdbc" | "mysql-connector-j" |
              "libmysql" | "mysql-cli" | "unknown",
      "version": "1.2.3" | null,
      "session_id": "<UUID v7 minted per MCP connection or SQL TCP connection>",
      "detected_from": "mcp_clientinfo" | "pg_application_name" |
                       "mysql_client_attrs" | "decide_flag" | "unknown"
    }
  }
}
```

Detection sources, in confidence order:

1. **`mcp_clientinfo`** — highest confidence. The MCP `initialize`
   request's `clientInfo: {name, version}` block per the MCP spec.
2. **`pg_application_name`** — PG StartupMessage's `application_name`
   parameter. psql / pgcli / psycopg2 / PostgreSQL JDBC Driver / Claude
   Code (when invoked via psql) all set it.
3. **`mysql_client_attrs`** — MySQL HandshakeResponse41's
   `connection-attributes` block. MySQL Connector/J, libmysql, the
   mysql / mysqlsh CLIs all set `_client_name` + `_program_name`.
4. **`decide_flag`** — operator-declared via `dbounce decide
   --agent-name` for the Snowflake / BigQuery JDBC-shim path.
5. **`unknown`** — no signal available. The session id still threads
   through so the SIEM can correlate even when the name is absent.

Plus a synthetic `SESSION_ENDED` event (`unmapped.iam_jit.event_type =
"SESSION_ENDED"` + `activity_name = "session_ended"`) fires when a SQL
TCP connection or MCP stdio connection closes — so a single query can
find "every event from agent session X" bracketed by an obvious
terminator.

---

## Splunk (SPL)

```spl
# All events from a specific agent session ID
index=dbounce
  unmapped.iam_jit.agent.session_id="01927e94-2d3c-7000-8000-abc1234567"
| stats count by activity_name status

# All DENY events for snowflake EXPORT_DATA in May 2026
index=dbounce
  api.service.name="snowflake"
  api.operation="EXPORT_DATA"
  status_id=2
  _time >= "2026-05-01" _time < "2026-06-01"
| stats count by actor.user.name unmapped.iam_jit.agent.name

# All events from a Claude Code agent across PG + MySQL connections
index=dbounce
  unmapped.iam_jit.agent.name="claude-code"
| stats count by api.service.name activity_name

# All sessions in May 2026 with > 10 DENY events (suspicious bursts)
index=dbounce
  status_id=2
  _time >= "2026-05-01" _time < "2026-06-01"
| stats count by unmapped.iam_jit.agent.session_id
| where count > 10
```

## Datadog Logs

```
service:dbounce
@unmapped.iam_jit.agent.session_id:"01927e94-2d3c-7000-8000-abc1234567"
@_time:[2026-05-01T00:00:00 TO 2026-06-01T00:00:00]
```

```
service:dbounce
@api.service.name:"snowflake"
@api.operation:"EXPORT_DATA"
@status_id:2
@unmapped.iam_jit.agent.name:"claude-code"
```

## Microsoft Sentinel (KQL)

```kql
DbounceAudit
| where TimeGenerated >= datetime(2026-05-01) and TimeGenerated < datetime(2026-06-01)
| where unmapped_iam_jit.agent.session_id == "01927e94-2d3c-7000-8000-abc1234567"
| summarize count() by activity_name, status_id

// All dbounce DENY events for snowflake EXPORT_DATA in May 2026
DbounceAudit
| where TimeGenerated >= datetime(2026-05-01) and TimeGenerated < datetime(2026-06-01)
| where api.service.name == "snowflake" and api.operation == "EXPORT_DATA" and status_id == 2
| summarize count() by actor.user.name, unmapped_iam_jit.agent.name
```

## AWS Security Lake (Athena)

```sql
-- All events from a specific agent session
SELECT activity_name, status, COUNT(*) AS cnt
FROM ocsf_dbounce
WHERE eventday BETWEEN '20260501' AND '20260531'
  AND unmapped.iam_jit.agent.session_id = '01927e94-2d3c-7000-8000-abc1234567'
GROUP BY activity_name, status;

-- All DENY events for snowflake EXPORT_DATA in May 2026
SELECT activity_name, status, COUNT(*) AS cnt
FROM ocsf_dbounce
WHERE eventday BETWEEN '20260501' AND '20260531'
  AND api.service.name = 'snowflake'
  AND api.operation = 'EXPORT_DATA'
  AND status_id = 2
GROUP BY activity_name, status;
```

## Local DuckDB (no SIEM — just the JSONL file)

```bash
duckdb -c "
SELECT activity_name, COUNT(*) AS cnt
FROM read_json_auto('~/.dbounce/audit.jsonl')
WHERE json_extract_string(unmapped, '\$.iam_jit.agent.session_id') = '01927e94-2d3c-7000-8000-abc1234567'
GROUP BY activity_name
ORDER BY cnt DESC"
```

```bash
# All dbounce DENY events for snowflake EXPORT_DATA in May 2026
duckdb -c "
SELECT json_extract_string(unmapped, '\$.iam_jit.agent.name') AS agent,
       COUNT(*) AS cnt
FROM read_json_auto('~/.dbounce/audit.jsonl')
WHERE api.service.name = 'snowflake'
  AND api.operation = 'EXPORT_DATA'
  AND status_id = 2
  AND time >= 1716163200000
  AND time <  1719273600000
GROUP BY agent
ORDER BY cnt DESC"
```

```bash
# Find every event from a single agent session bracketed by its
# SESSION_ENDED terminator
duckdb -c "
SELECT to_timestamp(time/1000) AS ts,
       activity_name,
       api.operation,
       json_extract_string(unmapped, '\$.iam_jit.event_type') AS evt_type,
       json_extract_string(unmapped, '\$.iam_jit.agent.name') AS agent_name
FROM read_json_auto('~/.dbounce/audit.jsonl')
WHERE json_extract_string(unmapped, '\$.iam_jit.agent.session_id') = '01927e94-2d3c-7000-8000-abc1234567'
ORDER BY time"
```

---

## Pre-baked agent-correlation patterns

### "Which agent ran this query?"

Find the decision_id in any logging tool, then:

```bash
duckdb -c "
SELECT to_timestamp(time/1000) AS ts,
       activity_name,
       api.operation,
       json_extract_string(unmapped, '\$.iam_jit.agent.name') AS agent,
       json_extract_string(unmapped, '\$.iam_jit.agent.session_id') AS session
FROM read_json_auto('~/.dbounce/audit.jsonl')
WHERE json_extract_string(api.request, '\$.uid') = '<DECISION_ID>'"
```

### "All sessions in the last 24h that touched a sensitive schema"

```bash
duckdb -c "
SELECT DISTINCT json_extract_string(unmapped, '\$.iam_jit.agent.name') AS agent,
                json_extract_string(unmapped, '\$.iam_jit.agent.session_id') AS session
FROM read_json_auto('~/.dbounce/audit.jsonl')
WHERE time >= (strftime(now() - INTERVAL 24 HOUR, '%s%f')::BIGINT)
  AND EXISTS (
    SELECT 1 FROM UNNEST(resources) AS r
    WHERE r.name LIKE 'finance.%' OR r.name LIKE 'pii.%'
  )"
```

### "Show the full timeline for one Claude Code session"

```bash
duckdb -c "
SELECT to_timestamp(time/1000) AS ts,
       api.operation,
       activity_name,
       status,
       json_extract_string(unmapped, '\$.iam_jit.verdict') AS verdict
FROM read_json_auto('~/.dbounce/audit.jsonl')
WHERE json_extract_string(unmapped, '\$.iam_jit.agent.name') = 'claude-code'
  AND json_extract_string(unmapped, '\$.iam_jit.agent.session_id') = '<SESSION_ID>'
ORDER BY time"
```

---

## Cross-product correlation

The same `unmapped.iam_jit.agent.name` + `.session_id` shape appears in
ibounce + kbounce events. To find every iam-jit event from a single
agent across all three Bounce products (assuming all three log to the
same SIEM):

### Splunk

```spl
index=iam_jit
  unmapped.iam_jit.agent.name="claude-code"
  unmapped.iam_jit.agent.session_id="<SESSION_ID>"
| stats count by metadata.product.name activity_name
```

### Athena (Security Lake)

```sql
SELECT metadata.product.name AS product,
       activity_name,
       COUNT(*) AS cnt
FROM ocsf_iam_jit
WHERE unmapped.iam_jit.agent.name = 'claude-code'
  AND unmapped.iam_jit.agent.session_id = '<SESSION_ID>'
  AND eventday BETWEEN '20260501' AND '20260531'
GROUP BY metadata.product.name, activity_name
```

The `metadata.product.vendor_name = "iam-jit"` field is the universal
filter for "any iam-jit event regardless of product."

---

## Caveats

- **Best-effort fingerprinting.** `agent.name` is the immediate
  client's declaration, not a verified identity. An attacker who can
  reach the SQL listener can also declare any `application_name` they
  want. Per the [[agent-identity-in-audit]] memo: this is operator
  VISIBILITY, not adversary defense.
- **`"unknown"` is normal.** Honest SQL clients that don't set
  `application_name` (older drivers, custom shims) produce
  `agent.name = "unknown"`. Don't alert on it.
- **Session IDs are NOT secrets.** They appear in audit events
  intended for SIEM consumption. UUID v7 is unpredictable but not
  authenticated — a downstream system MUST NOT use a session id as a
  capability.
- **MCP and SQL sessions are separate.** A user running Claude Code +
  pgcli simultaneously will see two different `agent.session_id` values
  for the two channels. Join by user identity or by time window if you
  need to correlate across channels.

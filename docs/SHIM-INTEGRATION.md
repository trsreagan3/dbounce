# dbounce JDBC-driver-shim integration

This document describes how to integrate dbounce with a Snowflake or
BigQuery deployment using the **JDBC-driver-shim approach**.

It is the supported invocation path for those two dialects in v1.0,
and the honest trade-offs vs the PostgreSQL / MySQL native
wire-protocol path are spelled out below so operators can make
informed deployment decisions.

---

## Why a shim and not a wire-protocol proxy

dbounce ships native wire-protocol proxies for PostgreSQL and MySQL.
For those dialects:

- The client (psql, mysql, JDBC, language drivers) opens a TCP
  connection to dbounce.
- dbounce parses every inbound statement, evaluates the rule engine,
  and forwards allowed traffic to the real database.
- The customer's application code does not change; you only update
  the connection string to point at dbounce instead of the database.

Snowflake and BigQuery do not work this way:

- **Snowflake's wire protocol** is HTTPS-based (REST + chunked result
  encoding) and closed-spec. There is no openly-documented framing
  for dbounce to parse without reverse-engineering each client driver
  release.
- **BigQuery's wire protocol** is the `google-cloud-bigquery`
  REST/gRPC API. Same situation — closed-spec, vendor-specific
  framing, churns with each SDK release.

Building a native wire-protocol proxy for either is an open-ended
reverse-engineering project that ages poorly. The pragmatic v1.0
shape is to sit BEFORE the customer's driver as a SQL-string
interceptor, evaluate the SQL through the same parser + rule engine
the PostgreSQL/MySQL paths use, and let the customer's existing
driver speak the native wire protocol unchanged.

That is the JDBC-driver-shim approach.

---

## The shim contract

The customer wraps their database client so that for every query:

1. The shim captures the raw SQL string.
2. The shim calls `dbounce decide --dialect snowflake|bigquery --statement "<SQL>"`
   (or the equivalent `dbounce_decide` MCP tool) and reads the
   verdict.
3. On `verdict: allow`, the shim forwards the SQL to the real driver
   unchanged.
4. On `verdict: deny`, the shim raises an error to the caller and
   does NOT invoke the real driver.

The shim runs IN-PROCESS with the customer's application. dbounce
itself runs as a sidecar / local process exposing the `decide`
subcommand (or the MCP server on stdio).

Two transports are supported:

- **CLI exec.** The shim spawns `dbounce decide ...` and reads the
  exit code + stdout. Exit 0 = allow, exit 1 = deny.
- **MCP JSON-RPC.** The shim speaks JSON-RPC 2.0 to `dbounce mcp
  serve` over stdio, calls the `dbounce_decide` tool, and reads the
  structured response. Same evaluation path, lower per-call overhead
  for high-volume deployments.

---

## Honest trade-offs vs the PG/MySQL native path

The shim approach is not a drop-in replacement for the native
wire-protocol proxy. The following invariants change:

### The customer's app must cooperate

In the PG/MySQL path, dbounce is on the wire. Any client connecting
to dbounce gets gated, including clients the operator did not know
about.

In the shim path, only SQL that flows through the shim wrapper is
gated. An adversarial query — for example, a piece of code that
directly imports `snowflake-connector-python` and bypasses the
shim — reaches the database without being seen by dbounce.

**This means the shim approach defends against accidents, not
adversaries.** If the threat model includes a developer who actively
wants to bypass dbounce, the shim cannot stop them. The native
wire-protocol path can.

### The audit log records what the shim told it

dbounce's audit log in shim mode reflects every SQL string the shim
passed to `dbounce decide`. If the shim missed a code path, the
audit log will not show those queries. The audit log is faithful to
the shim's coverage; it is not an independent observer of what hit
the database.

For compliance scenarios that require a complete independent record
of every query, the shim approach is not sufficient. Pair it with
the database's own audit logging (Snowflake's `ACCESS_HISTORY`,
BigQuery's `INFORMATION_SCHEMA.JOBS`) and reconcile the two streams.

### Calibration is experimental

The Snowflake and BigQuery rule packs ship with
`calibration_status: experimental` (see `internal/packs/snowflake.yaml`
and `internal/packs/bigquery.yaml`). The underlying parser is a
best-effort wrapper around `xwb1989/sqlparser` plus dialect-specific
keyword pre-checks for verbs the MySQL-shaped grammar does not
recognize (COPY INTO, PUT, GET, UNDROP, USE SECONDARY ROLES, SET TAG
for Snowflake; CREATE MODEL, EXPORT DATA, LOAD DATA, MERGE for
BigQuery).

This is honest framing per `[[scorer-is-ground-truth]]`: the packs
will produce false positives and false negatives at higher rates
than the PostgreSQL pack until the calibration corpus catches up.
The recommended v1.0 deployment is **cooperative mode** with audit
review, not transparent mode with hard enforcement.

### Performance

The shim adds one process spawn (CLI exec) or one JSON-RPC roundtrip
(MCP) per query. For an OLTP workload with thousands of queries per
second per process, CLI exec is not viable; use the MCP transport.
Even with MCP, the shim adds latency proportional to dbounce's
parse + rule evaluation, which for the typical query is sub-
millisecond but is not zero.

For BI / analytics workloads where queries are large and infrequent,
the per-query overhead is negligible.

---

## Integration patterns

The snippets below show the wrapping pattern. They are
intentionally minimal — adapt them to your codebase's idioms.

### Python: snowflake-connector-python

```python
import subprocess
import snowflake.connector

class DbounceSnowflakeCursor:
    def __init__(self, real_cursor):
        self._real = real_cursor

    def execute(self, sql, *args, **kwargs):
        proc = subprocess.run(
            ["dbounce", "decide", "--dialect", "snowflake",
             "--statement", sql, "--json"],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise PermissionError(f"dbounce denied: {proc.stdout}")
        return self._real.execute(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)
```

For higher-throughput deployments, replace the `subprocess.run` with
a persistent connection to `dbounce mcp serve` over stdio and call
the `dbounce_decide` MCP tool.

### Python: google-cloud-bigquery

```python
import subprocess
from google.cloud import bigquery

class DbounceBigQueryClient:
    def __init__(self, real_client):
        self._real = real_client

    def query(self, sql, *args, **kwargs):
        proc = subprocess.run(
            ["dbounce", "decide", "--dialect", "bigquery",
             "--statement", sql, "--json"],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise PermissionError(f"dbounce denied: {proc.stdout}")
        return self._real.query(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)
```

### JDBC drivers (Java / JVM languages)

Wrap the `PreparedStatement` and `Statement` interfaces with a
delegating proxy that calls `dbounce decide` before each `execute*`
invocation. Most enterprise JDBC pools (HikariCP, c3p0) support a
custom `ConnectionWrapper` that makes this composition clean. The
contract is the same: shim sees the SQL string, calls dbounce, only
forwards on allow.

---

## What dbounce does NOT do in shim mode

To restate the invariants explicitly:

- dbounce does NOT speak Snowflake or BigQuery wire protocol.
- dbounce does NOT hold customer database credentials.
- dbounce does NOT proxy result sets.
- dbounce does NOT enforce gating against code paths that bypass the
  shim wrapper.

dbounce DOES:

- Parse the SQL string the shim hands it.
- Evaluate the rule engine + active profile + active task scope.
- Return a verdict.
- Write an audit-log row (when `dbounce_decide` is called via the
  MCP tool against a configured store, or when the shim separately
  calls `dbounce_tail_decisions`).

---

## When to switch back to the native wire-protocol path

If your Snowflake or BigQuery deployment outgrows the shim
trade-offs — typically because the threat model expands to include
adversarial bypass, or because the calibration_status: experimental
mark is no longer acceptable — that's a signal to revisit. dbounce
will track Snowflake's published query log / BigQuery's INFORMATION_SCHEMA
as alternate observability surfaces in a post-v1.0 release; the shim
approach is the pragmatic v1.0 starting point, not the terminal
deployment shape.

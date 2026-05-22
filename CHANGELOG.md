# dbounce changelog

All notable changes to `dbounce` get recorded here. Versioning follows
semver from v1.0.0 onward.

## Unreleased

### Changed

### BREAKING — §A21 / [[discovery-first-default]] — default flips to DISCOVERY MODE — Shipped 2026-05-22

Per the role-effectiveness eval at
`iam-roles/tests/dogfood/role-effectiveness-grades.md`, dbounce's v1.0
safe-default landed at 25% hit-rate against the 50% launch bar: D1
(`SELECT *` from `credit_cards`) was THEATER, D2 (legit INSERT alongside
adversarial DROP) was NEGATIVE-VALUE, and D3 (DCL floor + stale-profile
upgrade gap) shipped PARTIAL. gbounce alone hit 66.7% with operator-set
OPT-IN deny primitives — not blanket safe-defaults.

The pivot flips dbounce's runtime default to match: observe + audit +
pass-through (the `full-user` profile, which is already the default when
no `--profile` is set). Named profiles (`safe-default` with its
sql_read_only + DCL-to-PUBLIC floor, plus any custom) stay first-class
via explicit opt-in (`dbounce run --profile <name>` or
`export DBOUNCE_PROFILE=<name>`).

- **internal/cli/banner.go:** headline banner now surfaces
  `default_mode=discovery|profile` alongside dialect + mode +
  default-policy + transport. Discovery fires when the active profile
  is empty, `full-user`, or the legacy `none` alias. The "no profile
  selected" block expands to explicitly name discovery mode (the
  canonical cross-product term) + frame as audit transparency per
  `[[security-team-positioning-safety-not-surveillance]]`.
- **DCL-to-PUBLIC floor placement (judgment call per
  `[[discovery-first-default]]`):** the `deny_dcl_targets_public`
  floor stays TIED to the `safe-default` profile. Rationale: a
  DCL floor firing without an active profile would surprise operators
  who explicitly chose audit-only; the floor remains documented
  alongside its profile in KNOWN-CAVEATS §A5 + §B7 and ships with
  safe-default. Operators who want the DCL floor must pin
  `--profile safe-default` (the floor + writes-block ship together by
  design; no partial-floor mode in v1.0). v1.1 may surface the floor
  as a standalone `--deny-dcl-public` flag if operator demand
  materializes.
- **No code path lost:** safe-default profile, OCSF audit, recommender,
  agent attribution (#318/#320), pg_query AST walker all continue to
  fire when the operator pins `--profile safe-default`. PG wire-
  protocol pass-through verified.

**BREAKING-CHANGE for operators upgrading from pre-pivot v1.0 builds**
that auto-applied or framed `safe-default` as the v1.0 default. Fresh
installs + upgrades now land in discovery mode by default. To keep
pre-pivot behavior (including the DCL-to-PUBLIC floor) pin
`dbounce run --profile safe-default` or `export DBOUNCE_PROFILE=safe-default`
in your shell rc. See `iam-roles/docs/PROFILE-UPGRADE.md` + iam-roles
KNOWN-CAVEATS §A21 for the cross-product upgrade path; the re-graded
corpus lives at
`iam-roles/tests/dogfood/role-effectiveness-grades-post-pivot.md`.

### #321 / §A19 — `dbounce profile doctor` upgrade-blindness fix — Shipped 2026-05-22

Closes the D3 launch-blocker surfaced by the role-effectiveness eval
2026-05-22: an operator who installed dbounce pre-#302 was silently
running WITHOUT the `deny_dcl_targets_public` floor because
`~/.dbounce/profiles.yaml` is intentionally never overwritten
(operator may have customized). Without a fix the safety guarantee
("GRANT-to-PUBLIC blocked under safe-default") was silently false on
older installs.

- **internal/profile/doctor.go (new):** `Check()` diff-checks the
  installed profile YAML against a curated catalog of shipped default
  fields. `Apply()` additively merges missing fields into the on-disk
  YAML + backs up the prior file (`<path>.bak-YYYYMMDD-HHMMSS`)
  before writing. `Acknowledge()` writes a per-operator stamp to
  suppress the startup banner until a new `ShippedDefaultsVersion`
  re-arms it. Field categories (`safety-floor` / `detection` /
  `audit` / `convenience`) bound the startup-banner shape: only
  `safety-floor` misses trigger the run-time caveat. Per
  [[creates-never-mutates]]: additive only — operator-customized
  field values are never overwritten.
- **internal/cli/profile.go (extended):** `dbounce profile doctor`
  subcommand with `--apply` / `--acknowledge` / `--diff` / `--check`
  / `--json` flags. Same flag shape as `kbounce` / `ibounce` /
  `gbounce` per [[cross-product-agent-parity]]. Exit codes: `0`
  current; `2` gaps found (script-friendly).
- **internal/cli/cli.go (extended):** `dbounce run` startup-banner
  hook calls `profile.StartupBannerLine` after the existing caveats
  block. The one-line warning ("caveat: your safe-default profile
  is missing fields shipped in this version — run `dbounce profile
  doctor` for details (KNOWN-CAVEATS §A19)") fires only when a
  safety-floor field is missing AND the operator hasn't
  acknowledged the current shipped-defaults version. Per
  [[security-team-positioning-safety-not-surveillance]]: framed
  as "your profile is behind" not "you are non-compliant."
- **internal/profile/doctor_test.go (new):** 7 tests cover fresh
  profile / missing-safety-floor / missing-convenience / apply-
  additive / apply-backs-up / acknowledge-silences /
  catalog-covers-embedded-defaults.

### #320 / §A18 — `/audit/events` wire-shape parity fix — Shipped 2026-05-22

Closes a UAT-discovered CRIT: the HTTP `/audit/events` endpoint that
powers `iam-jit audit query` was emitting an empty agent block on
every row even when the in-memory exporter pipeline had high-fidelity
agent identity. SOC analysts pulling cross-product events by
`agent.session_id` got zero dbounce hits.

- **store/store.go:** SchemaVersion bumped to 7. Adds three additive
  columns to `decisions` via idempotent `ALTER TABLE`:
  `agent_name TEXT`, `agent_session_id TEXT`, `detected_from TEXT
  NOT NULL DEFAULT 'unknown'`. Pre-#320 rows surface NULL (or
  "unknown" for `detected_from`) so the read path drops the agent
  block — historical events keep their legacy shape per
  `[[creates-never-mutates]]`.
- **proxy/proxy.go:** `evaluateAndAuditWithAgent` looks up the agent
  registry on every decision + persists the fingerprint alongside
  the row so the SQLite-backed projection sees what the JSONL log +
  webhook stream already carry.
- **proxy/audit_events.go:** `decisionRowsToAuditEvents` now routes
  through `audit.FromDecisionRowWithAgent` with the persisted
  fields. New `agentFromDecisionRow` helper translates row → Agent.
- **audit/agent_context.go:** `Agent` struct gains a non-serialised
  `HeaderRejection` map field that propagates `application_name`
  tag-rejection breadcrumbs to every event from the rejected
  session.
- **audit/event.go:** When `Agent.HeaderRejection` is non-empty the
  projection splices it into
  `unmapped.iam_jit.ext.agent_header_rejection`.
- **audit/agent_header_rejection.go (new):** Cross-product bounded
  enum (`invalid_name_charset` / `invalid_name_length` /
  `invalid_session_id_format` / `invalid_session_id_length` /
  dbounce-only `application_name_unparseable`) + classifier
  helpers. Raw rejected value NEVER emitted; only its length, for
  safe forensics per
  `[[security-team-positioning-safety-not-surveillance]]`.
- **proxy/proxy.go:** `registerPGAgentFromBody` stamps the rejection
  breadcrumb on the registered Agent when
  `application_name=iam-jit-agent:...` fails validation, threading
  through every subsequent audit event from that connection.
- Two new regression tests in `proxy/audit_events_test.go`:
  `TestAuditEvents_320_ThreadsAgentBlockFromStore` +
  `TestAuditEvents_320_FilterByAgentSessionIDMatches`.
- Closes `[[cross-product-agent-parity]]` parity with kbouncer +
  gbounce + ibounce.

### #317 / §A15 — cloud-neutral S3-compatible NDJSON object-storage sink — Shipped 2026-05-22

Closes the headline cloud-neutrality gap surfaced by founder
direction 2026-05-22: bouncers other than ibounce are
cloud-neutral; the AWS-only Security Lake adapter (#258) alone
doesn't serve operators on GCS / Azure Blob / MinIO / R2 / B2 /
DigitalOcean Spaces. dbounce ships the new sink alongside the
existing JSONL + webhook + Security Lake transports per
[[creates-never-mutates]] (additive composition).

- **`dbounce run --audit-object-storage-endpoint URL
  --audit-object-storage-bucket NAME
  --audit-object-storage-prefix PREFIX
  --audit-object-storage-region REGION
  --audit-object-storage-credentials-file PATH
  --audit-object-storage-rotation-minutes N
  --audit-object-storage-max-size-mb N
  --audit-object-storage-instance-id ID`** — generic S3-compat
  sink. Per [[cross-product-agent-parity]] the flag shape is
  identical on ibounce + kbouncer + gbounce.
- New package symbols: `audit.ObjectStorageWriter` +
  `audit.ObjectStorageCredentials` +
  `audit.LoadObjectStorageCredentials` +
  `audit.NewObjectStorageWriter` +
  `audit.ObjectStorageStatus` +
  `audit.ObjectStorageDefaultRotationMinutes` +
  `audit.ObjectStorageDefaultMaxSizeMB` +
  `audit.ObjectStorageDefaultRegion` +
  `audit.ErrObjectStorageNoCredentials` +
  `audit.ErrObjectStorageBucketUnreachable`.
- Output layout: NDJSON (one OCSF event per line),
  gzip-compressed, Hive-partitioned at
  `{prefix}/year=YYYY/month=MM/day=DD/hour=HH/dbounce-{instance_id}-{timestamp}.jsonl.gz`.
  Athena / BigQuery / Spark / Trino auto-discover the partitions;
  SIEM collectors `LIST + GET` against the prefix.
- Additive `audit.Exporter` field
  `ObjectStorage *ObjectStorageWriter` + emit + Shutdown wiring +
  `ExporterStatus.ObjectStorage`. `Exporter.emit` fans new events
  to the writer alongside the JSONL + webhook + Security Lake +
  recorder channels.
- Per [[self-host-zero-billing-dependency]]: destination is
  operator-owned (operator creates the bucket; dbounce never
  creates buckets). Per [[don't-tailor-to-lighthouse]]: generic
  S3-compat (AWS S3 native + GCS interop + Azure Blob S3-compat
  layer + MinIO + R2 + B2 + DigitalOcean Spaces).

**Regression tests:** `internal/audit/object_storage_test.go` — 19
tests cover defaults, credentials resolution (env + YAML + INI),
partition path format, construction refusal, write/flush happy
path, status surface, size-cap synchronous flush,
drop-on-buffer-full, write-before-start no-op,
close-flushes-pending, put_object failure -> writes_ok=false, and
the rotation timer triggering a background flush.

**Task:** #317 — completed 2026-05-22.

### #319 / §A17 — UAT findings cluster: cross-product CLI parity (dbounce slice) — Fixed 2026-05-22

- **F-311-4 (HIGH)** — added `--audit-log-max-size-mb` + `--audit-log-max-age-days` + `--audit-db-retention-days` flags on `dbounce run` with matching `DBOUNCE_AUDIT_LOG_MAX_SIZE_MB` / `_MAX_AGE_DAYS` / `_DB_RETENTION_DAYS` env-var overrides. CLI flag wins when explicitly set; env var fills in otherwise; audit-package default (matches `iam-roles/docs/LOG-RETENTION.md`) wins last. Sentinel -1 = "use audit-pkg default"; 0 = "operator explicitly disabled trigger." Threaded through `buildAuditExporter` into `audit.LogOptions.{MaxSizeMB,MaxAgeDays}` so the live writer enforces both triggers. DB-retention is consumed by the on-demand `dbounce logs purge` subcommand (no writer-side DB sweep — `[[creates-never-mutates]]` keeps the live SQLite intact).
- **F-304-2 (HIGH)** — `dbounce run` now emits the `caveats.BannerLines(caveats.Trigger{...})` lines on stderr after the standard startup banner + after the preset banner, gated by `--quiet-banner`. B6 (per-statement gating is structural) + B7 (numeric-literal redaction is a post-v1.0 flag) fire when `--profile safe-default` is the active profile. Sibling products (ibounce / kbounce / gbounce) ship the same startup hook per `[[cross-product-agent-parity]]`.
- **F-311-3 / F-304-1 verified** — dbounce already ships `dbounce logs {archive,purge,verify}` + `dbounce doctor {caveats,logs}` (verified via `/tmp/dbounce --help`). The §A17 findings doc was stale on these two items; documented as such in `iam-roles/docs/KNOWN-CAVEATS.md` §A17 closure notes.

Regression coverage: new `TestRunCmdRegistersRotationFlags` in `internal/cli/security_lake_test.go`. Existing `buildAuditExporter` test callers updated to thread the new positional args.

### #318 / §A16 — cross-bouncer agent-attribution parity for SQL (2026-05-22)

Closes the SQL slice of the cross-bouncer correlation gap surfaced by
the NanoClaw integration test. dbounce sees the SQL wire protocol, not
HTTP, so the canonical agent-attribution channel is the PostgreSQL
`application_name` startup parameter rather than an `X-Agent-*` HTTP
header. The convention `application_name=iam-jit-agent:NAME:SESSIONID`
(documented at `iam-roles/docs/AGENT-ATTRIBUTION.md` §SQL) is the
wire-protocol equivalent of the HTTP path — a SIEM query on
`unmapped.iam_jit.agent.session_id=X` now resolves across dbounce
events alongside ibounce / kbouncer / gbounce ones.

- `internal/audit/agent_context.go`:
  - New `IsValidAgentName()` mirroring gbounce + ibounce + kbouncer's
    regex `^[A-Za-z0-9._-]{1,64}$` byte-for-byte. `IsValidSessionID()`
    already lived in `recorder.go` — reused for the canonical tag
    validation.
  - New `AgentAppNameTagPrefix` constant + `ParseAgentTagFromAppName()`
    helper that extracts `(name, sessionID, ok)` from the
    `iam-jit-agent:NAME:SESSIONID` shape.
  - New `ParsePGStartupAppNameWithSession()` — extended `application_name`
    parser that ALSO returns the parsed session id when the canonical
    tag was supplied, plus a `tagInvalid` bool the caller can use to
    bump a rejection counter. Existing `ParsePGStartupAppName()`
    delegates to it (backwards compatible).
  - New `AgentRegistry.MintWithSessionID()` — the cross-bouncer variant
    that registers an agent under a CALLER-SUPPLIED session id (instead
    of a fresh UUID v7), so the agent's declared session_id flows
    through to every audit event for that connection. Invalid session
    ids fall back to the existing `Mint` path so the SESSION_ENDED
    bookend still fires.
- `internal/proxy/proxy.go`:
  - `registerPGAgentFromBody` uses the new parser + `MintWithSessionID`.
    Invalid tags bump a new per-Server `totalAgentHeadersRejected`
    atomic counter + log the truncated raw value (control chars
    replaced with `?`) so a malicious application_name can't reposition
    the operator's terminal cursor. The raw value is NEVER written
    into the audit event.
  - `/healthz` payload now includes `total_agent_headers_rejected`
    (matches gbounce + ibounce + kbouncer fields of the same name).
- New tests:
  - `internal/audit/agent_headers_318_test.go` — canonical cross-product
    test names (`TestApplicationName_AgentParsing_HappyPath`,
    `TestApplicationName_NoAgentTag_FallbackToUA`,
    `TestAgentHeaders_HappyPath`,
    `TestAgentHeaders_NoHeaders_FallbackToUserAgent`,
    `TestAgentHeaders_InvalidName_Rejected`,
    `TestAgentHeaders_NameOnly_PartialDetection`,
    `TestApplicationName_AgentParsing_RejectsInvalidSessionID`,
    `TestApplicationName_AgentParsing_AcceptsUUIDv4`,
    `TestIsValidAgentName_MatchesGbounceRegex`,
    `TestAgentRegistry_MintWithSessionID_PreservesSuppliedID`,
    `TestAgentRegistry_MintWithSessionID_InvalidFallsBackToMint`).
  - `internal/proxy/agent_headers_318_test.go` — proxy-level wiring
    tests covering happy path, invalid-tag counter bump, no-tag
    fallback, and the anonymous-mint path.

`docs/AGENT-ATTRIBUTION.md` + `docs/KNOWN-CAVEATS.md` §A16 live in the
iam-roles repo (cross-product reference); they're updated alongside
this slice with the SQL `application_name` convention documented.

### #311 / §A10 — robust audit-log retention (2026-05-22)

Cross-product launch-blocker resolved. `dbounce` now rotates `audit.jsonl`
automatically at 100 MB or 7 days (whichever first), gzipping to
`audit-{YYYY-MM-DD-HHMMSS}.jsonl.gz` in the same dir. New surface:

- `dbounce logs purge --older-than 7d --yes` — retention sweep of rotated
  archives (never touches the active `audit.jsonl`)
- `dbounce logs archive --out FILE` — tar.gz bundle for SIEM hand-off
- `dbounce logs verify` — gzip + JSONL integrity check
- `dbounce doctor logs` — integrity + freshness + retention + disk checks
  (exits non-zero on any failure)
- Crash recovery: partial JSONL tail truncated on startup
- Rotation lifecycle admin-actions: `audit.log.rotated`,
  `audit.log.rotation_failed`, `audit.log.recovered_partial`
- LogOptions: `MaxSizeMB`, `MaxAgeDays`, `OnRotation`,
  `OnRotationFailure`, `OnRecovery`
- LogStats extended with rotation telemetry: `Rotations`,
  `RotationFailures`, `LastRotationAt`, `LastRotationPath`,
  `PartialBytesRecovered`
- Cross-product runbook: `iam-roles/docs/LOG-RETENTION.md`
- 12 new tests in `internal/audit/rotation_test.go`

### #304 — KNOWN-CAVEATS discoverability surfaces (2026-05-22)

Per founder direction 2026-05-22: caveats must be easily discoverable
to users + agents, not buried in `docs/KNOWN-CAVEATS.md`. This slice
ships four surfaces:

- `internal/caveats/` — new package centralizes the dbounce-relevant
  §B entries (B6 + B7 product-specific; B13 + B14 + B15 cross-product)
  + the GitHub markdown anchors. `caveats.BannerLines(Trigger)`
  returns the startup-banner lines to emit;
  `caveats.DoctorEntries()` returns the full applicable list;
  `caveats.LinkSuffix(id)` produces an inline `(see KNOWN-CAVEATS §X:
  <URL>)` suffix for error responses.
- **README "Known limitations" section** — top 3 dbounce-relevant §B
  entries (B6 / B7 / B14) linked to the canonical doc.
- **Startup banner** — `dbounce run` emits the §B6 + §B7 lines after
  the standard banner. §B7 is suppressed when `--redact-numerics` is
  set (post-v1.0; field reserved in bannerOpts).
- **`dbounce doctor caveats`** — new subcommand under a new `doctor`
  command group. Same shape across the Bounce suite per
  `[[cross-product-agent-parity]]`.
- **MCP tool descriptions** — `dbounce_active_mode` description now
  embeds §B6 + §B7 references + links. `dbounce_decide` description
  embeds the §B7 numeric-literal note (any tool that dry-runs SQL
  should carry the redaction caveat per the task #304 spec).

### GRANT/REVOKE/DCL classifier (#302, 2026-05-22; HIGH)

- **Bug:** `GRANT ALL PRIVILEGES ON DATABASE x TO PUBLIC` and the
  equivalent `ALTER DEFAULT PRIVILEGES ... GRANT ... TO PUBLIC` slipped
  through the `safe-default` profile. The parser classified DCL
  (privilege-management) statements as `StatementType=UNKNOWN`,
  `IsDML=false`, `IsDDL=false`, so the `sql_read_only` allow_baseline
  abstained (not a read), `deny_ast_mutating_nodes` abstained (no
  mutating flag), and the call fell through to default-allow. UAT
  Variant A + Variant C both confirmed the H3 hostile attempt succeeded
  pre-fix; KNOWN-CAVEATS §A5 in `iam-roles/docs/`. HIGH severity —
  privilege escalation to every database role is the kind of statement
  safe-default exists to refuse.
- **Root cause:** `internal/parser/postgres.go` didn't dispatch on
  `pg_query.Node_GrantStmt`, `Node_GrantRoleStmt`, or
  `Node_AlterDefaultPrivilegesStmt`. Three of the most common attacker-
  shaped statements rendered as `UNKNOWN` and the profile evaluator had
  no signal to gate on.
- **Fix:**
  - New parser statement-type constants: `StmtGrant` (`GRANT`),
    `StmtRevoke` (`REVOKE`), `StmtAlterPrivileges` (`ALTER_PRIVILEGES`).
    `GrantStmt` + `GrantRoleStmt` map to `StmtGrant` / `StmtRevoke`
    based on the `IsGrant` bool; `AlterDefaultPrivilegesStmt` always
    maps to `StmtAlterPrivileges` (the future-objects shape is what
    matters for the safe-default gate regardless of inner direction).
  - New `ParsedStatement.IsDCL` predicate so downstream rules can match
    on the DCL family without keyword-sniffing the raw SQL.
  - New `ParsedStatement.DCLTargetsPublic` predicate — set by the walker
    when any grantee resolves to PG's `PUBLIC` pseudo-role (either via
    `RoleSpecType_ROLESPEC_PUBLIC` or a defensive case-insensitive match
    on the rolename). REVOKE direction NEVER sets this predicate per the
    task spec — revoking FROM PUBLIC is cleanup and a safe-default that
    blocks cleanup is a worse failure than allowing the original grant.
  - New `Profile.DenyDCLTargetsPublic` field. Fires at **Order 2.5** in
    the profile composition (after deny_keywords / deny_actions, BEFORE
    `allow_baseline`) so a permissive sql_read_only baseline can't
    accidentally let a PUBLIC-targeting grant through. ExemptActions +
    ExemptResources are NOT consulted for this floor — a PUBLIC-targeting
    GRANT must be written as an explicit allow_rule, not implicitly
    carved out via a per-table exemption.
  - `safe-default` profile in `internal/profile/defaults.yaml` now sets
    `deny_dcl_targets_public: true` so the hard floor is on by default.
  - Wired the new predicates through `proxy.decide`'s
    `profile.ParsedStatement` construction.
- **Regression coverage:**
  - **Parser** (`internal/parser/postgres_test.go`):
    - `TestParse_GrantAllPrivilegesToPublic`
    - `TestParse_GrantSelectOnTableToSpecificUser`
    - `TestParse_GrantCaseInsensitivePublic`
    - `TestParse_RevokeFromPublic`
    - `TestParse_RevokeFromSpecificUser`
    - `TestParse_AlterDefaultPrivilegesGrantToPublic`
    - `TestParse_AlterDefaultPrivilegesGrantToSpecificUser`
    - `TestParse_GrantRoleToUser`
    - `TestParse_GrantMultipleGranteesIncludesPublic`
  - **Profile** (`internal/profile/profile_test.go`):
    - `TestEvaluate_SafeDefault_DeniesGrantAllToPublic`
    - `TestEvaluate_SafeDefault_DeniesAlterDefaultPrivilegesGrantToPublic`
    - `TestEvaluate_SafeDefault_AllowsGrantToSpecificUser`
    - `TestEvaluate_SafeDefault_AllowsRevokeFromPublic`
    - `TestEvaluate_DCLFloor_NotConsultedWhenDisabled`
    - `TestEvaluate_DCLFloor_FiresBeforeAllowBaseline`
- **End-to-end verification:** dbounce was launched against the dogfood
  Postgres with `--profile safe-default --mode transparent
  --default-policy allow`. psycopg2 replayed the four task-spec
  scenarios + a baseline SELECT; all five returned the expected
  verdict:
  - `GRANT ALL PRIVILEGES ON DATABASE postgres TO PUBLIC` → DENIED
    (`profile "safe-default": DCL targets PUBLIC ...`)
  - `GRANT SELECT ON TABLE pg_stat_activity TO postgres` → ALLOWED
    (non-PUBLIC; profile abstains; default-policy allows)
  - `REVOKE ALL PRIVILEGES ON DATABASE postgres FROM PUBLIC` → ALLOWED
    (cleanup direction; predicate never set)
  - `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO PUBLIC`
    → DENIED (the future-objects variant of the same hostile shape)
  - `SELECT 1` → ALLOWED (pure read via sql_read_only baseline; no
    regression on the existing safe-default behavior)
- Closes KNOWN-CAVEATS §A5. Per `[[creates-never-mutates]]`: the fix
  ADDS new classifier shapes + a new policy field; it never silently
  widens an existing rule.

### #306 + #307 — canonicalize `go install` as the install path; no checked-in `bin/` (2026-05-22)

Closes KNOWN-CAVEATS §A8. The repository never tracked `bin/dbounce`
(it was gitignored via the existing `bin/` pattern in `.gitignore`),
but the README still led with `go build ./cmd/dbounce` followed by
`./dbounce run`, which papered over the canonical install story and
left the door open for someone to commit a stale binary in the future.

- **README "Install" section** — adds a dedicated "Install" section
  ahead of "Quickstart" with `go install
  github.com/trsreagan3/dbounce/cmd/dbounce@latest` as the canonical
  first-time-install path. Every user who follows the README gets a
  fresh build straight from source; no pre-built binary can lag the
  codebase. Local-dev iteration via `make build` /
  `go build -o bin/dbounce ./cmd/dbounce` is documented in a separate
  subsection with an explicit reminder that `bin/` is gitignored.
- **Makefile `install` target** — wraps `go install ./cmd/dbounce` so
  local-dev iteration can match the canonical install path without
  re-typing the module URL.
- **Makefile `build` target** — now drops the binary into `./bin/`
  (gitignored) instead of the working directory, so source-tree
  iteration produces a predictable artifact location that won't
  collide with git tracking.
- Per `[[creates-never-mutates]]` this slice is hygiene-only — no
  surrounding code touched. Per `[[push-policy-public-repo]]` diff
  scanned for sensitive data before push.

### SCRAM-SHA-256 handshake hang fix (#299, 2026-05-22; CRITICAL)

- **Bug:** Connecting any modern Postgres client (psql 14+, libpq 14+,
  psycopg2, lib/pq, pgx, etc.) through dbounce against a SCRAM-SHA-256-
  authenticated upstream hung forever during initial auth. The proxy
  forwarded the SCRAM bytes upstream but the AuthenticationOk /
  ParameterStatus / BackendKeyData / ReadyForQuery responses never
  propagated back to the client. Modern PostgreSQL 14+ defaults to
  SCRAM-SHA-256, so this broke every default install.
- **Root cause:** `pumpAuthPhase` in `internal/proxy/forward.go` treated
  EVERY `AuthenticationRequest` sub-code other than 0 (Ok) as "client-
  response required" and blocked on a client read. The SCRAM-SHA-256
  flow walks `R/10` (SASL) → `R/11` (SASLContinue) → `R/12` (SASLFinal)
  → `R/0` (Ok); sub-code 12 (`AuthenticationSASLFinal`) is server-only
  and is NOT followed by a client message. The proxy deadlocked on the
  spurious client read.
- **Fix:** Introduced `authRequestExpectsClientResponse(uint32) bool` —
  an enumerated mapping from PG protocol auth sub-codes to "does the
  client respond?" The post-`R`-write branch now routes through this
  helper, so server-only sub-codes (0, 2, 6, 12) and unknown codes fall
  through to the next upstream read instead of blocking on the client.
  Wire-protocol pass-through invariants are preserved — dbounce still
  forwards SCRAM bytes verbatim and never names/inspects the SCRAM
  token or password.
- **Regression coverage:**
  - `TestForward_SCRAMSHA256HandshakeCompletes` (`internal/proxy/forwarding_test.go`)
    walks the full 4-message SCRAM server sequence via a custom in-process
    fake upstream and asserts the client session reaches `ReadyForQuery`
    in under 3s (pre-fix this hangs until `ReadTimeout` fires).
  - `TestAuthRequestExpectsClientResponse` pins the wire-protocol
    contract — each PG auth sub-code is enumerated by name with its
    expected verdict.
  - `TestIntegration_SCRAMAuthThroughProxy` (build tag `integration`)
    verifies the fix against a real PostgreSQL with SCRAM-only
    `pg_hba.conf`.
- **End-to-end verification:** psycopg2.connect() through dbounce against
  Postgres 16 with `password_encryption=scram-sha-256` succeeds in ~95ms
  (was: hung until client `connect_timeout`).
- Per `[[creates-never-mutates]]`: fix is scoped to the upstream-auth
  forwarder; no surrounding code touched.

### Per-org notification routing engine (#280, 2026-05-19; ENTERPRISE tier)

- **`dbounce run --alert-routes ROUTES.yaml`** activates the multi-
  destination routing engine. Each event is matched against the
  YAML's `routes:` list (per-route `match` block with `equals` /
  `gte` / `lte` / `gt` / `lt` / `in` / `match` (regex) / `glob`
  operators; AND-within / OR-across); matching routes dispatch the
  event to their declared `destinations:` (`webhook` per #257 preset,
  `pagerduty` via the documented Events API v2, `slack` via incoming-
  webhook). No SDK deps; raw HTTP POSTs against the documented
  vendor endpoints.
- `on_match: stop` (**default**) short-circuits subsequent routes;
  `on_match: continue` enables fan-out for catch-all archive routes.
- Secrets resolved via `${ENV_VAR}` interpolation; literal tokens in
  the YAML are refused at load time. Resolved secrets render as
  `<8-char-prefix>***` in the dry-run output + status surfaces; raw
  tokens never appear in logs, status, or error messages.
- **`dbounce config preview-routes --routes ROUTES.yaml --event sample.json`**
  dry-runs a sample event against the file and prints which routes
  matched + the masked destinations each match would dispatch to.
  Mandatory pre-deploy validation; no HTTP traffic is sent.
- Backward compat: when `--alert-routes` is unset, the existing
  `--audit-webhook-url` path is unchanged. When both are set, the
  routing engine wins + the single-webhook is ignored with a
  warning at startup.
- Additive `Exporter.Routes` field so the existing Slice 1 / #257
  / #258 wiring stays untouched; the Exporter fan-out routes events
  via the engine instead of the single-webhook when both are
  configured.
- Per `[[enterprise-self-host-only]]`: ENTERPRISE-tier feature;
  license gate currently surfaces `ErrRoutesLicenseRequired`
  (placeholder until #235 license-file plumbing lands — same shape
  as the existing webhook + alert-rules gates).
- Per `[[creates-never-mutates]]` the engine never mutates the event
  it routes. Per `[[no-hosted-saas]]` + `[[self-host-zero-billing-
  dependency]]` every destination is operator-configured.
- Per `[[cross-product-agent-parity]]` ibounce + kbouncer ship the
  same `--alert-routes` flag name + YAML schema + match operators +
  destination types.
- Documented at `docs/PER-ORG-NOTIFICATION-ROUTING.md`; the canonical
  cross-product reference lives at the iam-roles repo
  `docs/PER-ORG-NOTIFICATION-ROUTING.md`.

### AWS Security Lake audit-export adapter (#258, 2026-05-19)

- **`dbounce run --security-lake-bucket BUCKET --security-lake-region REGION
  [--security-lake-role-arn ARN] [--security-lake-rotation-seconds N]`** —
  writes OCSF v1.1.0 class 6003 events as parquet files into a
  Security-Lake-compatible S3 bucket layout
  (`region=<r>/eventday=<YYYYMMDD>/eventhour=<HH>/api_activity-
  <unix-ms>.parquet`). Per-class in-memory batching with rotation
  on the configured interval (default 300s) OR a 10 MiB size cap,
  whichever fires first; `Close()` flushes pending batches
  synchronously. Credentials via STS AssumeRole when
  `--security-lake-role-arn` is set, otherwise the default
  aws-sdk-go-v2 credential chain; refuses to start with a clear
  error if no credentials are reachable.
- Additive `Exporter.SecurityLake` field + `ExporterStatus.SecurityLake`
  so the `audit-export health` CLI surfaces the parquet writer's
  counters alongside log + webhook + heartbeat stats. The CLI's
  `buildAuditExporter` constructs the writer when the operator
  passes `--security-lake-bucket`; the Exporter fan-out treats
  the writer as another channel.
- Cross-product parity per `[[cross-product-agent-parity]]`:
  ibounce + kbounce ship the same adapter with byte-identical
  column set + partition layout. `SecurityLakeColumnNames` locks
  the schema; the cross-product test fixture asserts it.
- Per `[[no-hosted-saas]]` + `[[self-host-zero-billing-dependency]]`
  the bucket lives in the operator's AWS account; iam-jit-the-
  company never receives the data.
- Per `[[creates-never-mutates]]` every S3 operation is `PutObject`
  only; rotation timestamps guarantee unique keys per flush.
- Documented in `docs/SECURITY-LAKE-INTEGRATION.md`.

### Per-session recording CLI wiring (#290, 2026-05-19)

- **`dbounce run --record-sessions-dir PATH`** — wires the #285
  recorder library into the proxy hot path. Every audit event is
  teed into `{dir}/{agent.session_id}.ndjson` (one file per agent
  session) alongside any other configured audit transport.
  Default off; opt-in flag.
- **`dbounce session list / show / export / purge`** — read-only
  inspection of recordings. Subcommand names + flag shape match
  ibounce + kbounce + gbounce exactly per
  `[[cross-product-agent-parity]]`. `purge --dry-run` lists
  candidates without deleting; explicit `--older-than` required
  per `[[creates-never-mutates]]` (destructive only via explicit
  threshold).
- `Exporter.Recorder` field + `ExporterStatus.Recorder` so
  `audit-export health` surfaces recorder counters alongside
  log + webhook + heartbeat stats. `Exporter.Enabled()` now
  treats a configured recorder as a transport so the proxy keeps
  building events when the operator wired ONLY the recorder.
- `Shutdown` finalises every still-open recording (.partial →
  .ndjson) before the proxy exits.
- Per `[[self-host-zero-billing-dependency]]`: zero network calls;
  entirely local filesystem.
- See `docs/SESSION-REPLAY.md` in iam-roles for the cross-product
  CLI; this slice ships the dbounce side of the surface.

### Per-session recording library (#285, 2026-05-19)

- New `internal/audit/recorder.go` ships the per-session NDJSON
  recorder. Tees every audit event into
  `{dir}/{agent.session_id}.ndjson` with the same on-disk shape as
  ibounce / kbouncer / gbounce per
  `[[cross-product-agent-parity]]` so the cross-product
  `iam-jit session replay <FILE>` CLI (lives in iam-roles)
  consumes dbounce recordings unchanged.
- Files carry a `_meta` header (recording_schema_version,
  session_id, agent_name, bouncer_product, recording_started_at)
  followed by one OCSF event per line. `.partial` suffix while
  in-flight; atomic rename to `.ndjson` on clean shutdown or the
  5-minute heartbeat-idle finalisation tick. File mode 0o600.
- `ListSessions`, `ReadSession`, `EventCountByType`,
  `PurgeOlderThan`, `DetectionFindingFromSession` exposed in
  the audit package for downstream `dbounce session ...` CLI
  wiring (proxy-side wiring in the next slice).
- See `docs/SESSION-REPLAY.md` in iam-roles for the cross-product
  documentation.

### `--preset security-observe` deployment preset (#254, 2026-05-19)

- **`dbounce run --preset security-observe`** — single-flag shortcut
  for the canonical security-team observation deployment shape.
  Equivalent to the explicit flag bundle `--mode transparent
  --default-policy allow --audit-log-path ~/.dbounce/audit/dbounce.jsonl
  --heartbeat-interval 30s --audit-export-health-interval 30s`.
  Designed for the "gather data first; author profile second"
  starting position per `[[bouncer-mode-selection-for-agents]]` +
  the cross-product security-team audit-export memo.
- HARD override on `--mode` (the entire point of the preset is
  transparent); passing `--preset security-observe --mode cooperative`
  errors fast with a clear "drop the preset OR drop the explicit flag"
  message.
- SOFT overrides on `--audit-log-path` / `--heartbeat-interval` /
  `--audit-export-health-interval` / `--default-policy` (operators
  have different SIEM destinations + cadences).
- Startup banner names the preset + every derived setting with
  hard/soft annotation (suppressed when `--quiet-banner` is set,
  matching the LOW-D8-13 quiet posture).
- Same preset NAME + same override semantics ship across ibounce /
  kbounce / gbounce per `[[cross-product-agent-parity]]`. Framework
  + the post-v1.0 roadmap (`dev-loop`, `production-strict`,
  `compliance-audit`) are documented at `docs/DEPLOYMENT-PRESETS.md`
  but explicitly NOT shipped in this slice per
  `[[deliberate-feature-completion]]`.
- The cross-product `--alert-rules` setting is implicitly not in
  dbounce's preset (dbounce never registered the flag; its rule
  framework is the audit-export-health-interval poll instead).
- Per `[[security-team-positioning-safety-not-surveillance]]`:
  preset description + banner use neutral language.
- Per `[[self-host-zero-billing-dependency]]`: the preset does not
  configure `--audit-webhook-url`, so a self-hosted security-observe
  deployment phones home to nothing without an operator action.

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

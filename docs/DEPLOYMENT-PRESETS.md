# Deployment Presets

A **deployment preset** is a named bundle of `dbounce run`-command
flag values that activates a common deployment shape with one flag
instead of seven. Presets are SHORTCUTS — every preset value can be
set explicitly; the preset just makes the canonical combinations
discoverable + one-flag for the operator.

Per `[[cross-product-agent-parity]]` the same preset NAMES + same
HARD-vs-SOFT override semantics ship across **ibounce / kbounce /
dbounce / gbounce**. A product MAY skip a preset setting it doesn't
have a subsystem for; the banner annotates skipped settings.

## The mechanism

A preset is a `(name, description, values)` record where `values`
is a map keyed by run-command parameter with an explicit override
policy per entry:

- **HARD** — operator passing the flag with a DIFFERENT value
  errors. The preset's whole point depends on this setting;
  overriding it silently would yield a deployment shape that does
  not match what the operator asked for.
- **SOFT** — operator's value wins; the preset value is the default
  the operator gets when they leave the flag unset.

The preset resolution runs BEFORE downstream validation gates so
the license / SSRF / loopback-bind / mode-parse checks see the
preset-resolved values, not the raw input.

The startup banner names the active preset + lists every derived
setting (with hard/soft annotation) so the operator sees exactly
what changed. Format is identical across all four Bounce products.
The banner is suppressed when `--quiet-banner` is set (matches the
LOW-D8-13 quiet posture for the rest of the startup banner).

## Available presets (v1.0)

### `security-observe`

```sh
dbounce run --preset security-observe
```

is equivalent to the explicit bundle:

```sh
dbounce run \
  --mode transparent \
  --default-policy allow \
  --audit-log-path ~/.dbounce/audit/dbounce.jsonl \
  --heartbeat-interval 30s \
  --audit-export-health-interval 30s
```

| Setting | Why |
|---|---|
| `--mode transparent` | Observe + audit; do not enforce rules the team has not yet authored. |
| `--default-policy allow` | Transparent observation; do not surprise operators with denies. |
| `--audit-log-path <default>` | Per-product JSONL stream the security team can ship to a SIEM. |
| `--heartbeat-interval 30s` | Liveness signal so the SIEM detects when the proxy is killed/silenced. |
| `--audit-export-health-interval 30s` | Periodic `audit_export_degraded` alert when the export pipeline itself is failing. |

**Override semantics**:

- HARD: `--mode` (the entire point is transparent).
- SOFT: `--audit-log-path`, `--heartbeat-interval`,
  `--audit-export-health-interval`, `--default-policy`.

**dbounce-specific note**: the ibounce/kbounce `--alert-rules`
setting is NOT in dbounce's preset because dbounce never registered
the flag — dbounce's deterministic alert framework is the
`--audit-export-health-interval` poll (audit_export_degraded). The
preset wires that on instead. Cross-product agents that drive
`security-observe` across all four products will see the same
alerting/audit shape, just expressed via the product's native
surface.

**What the preset does NOT set** (operator wires explicitly):

- `--audit-webhook-url` + `--audit-webhook-token` — different SIEM
  endpoint per deployment; set via flag, env var, or `dbounce
  config import`.

## Roadmap (post-v1.0)

The framework supports more presets without breaking-change cycles.
Queued (NOT shipped in v1.0):

| Preset | Planned shape | Use case |
|---|---|---|
| `dev-loop` | cooperative + safe-default profile + `--prompt-on-deny` | Solo-dev iteration where the operator wants advisory denies |
| `production-strict` | transparent + strict profile + no overrides + JSONL only | Locked-down production deployments |
| `compliance-audit` | transparent + all-alerts + per-session recording | Compliance evidence-gathering shape |

Per `[[deliberate-feature-completion]]` we ship the framework with
one preset; the next presets ship when a concrete operator asks.

## Cross-product alignment

A single command runs the SAME preset across every Bounce product:

```sh
ibounce  run --preset security-observe
kbounce  run --preset security-observe
dbounce  run --preset security-observe
gbounce  run --preset security-observe
```

per `[[cross-product-agent-parity]]`: an SRE runbook that says
"spin up the Bounce suite in observation mode" maps to one flag
name regardless of which proxy is in scope.

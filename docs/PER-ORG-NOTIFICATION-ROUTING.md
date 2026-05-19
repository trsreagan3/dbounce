# dbounce per-org notification routing (#280)

**Status:** Shipped 2026-05-19. Enterprise-tier; license-gated
(placeholder error until #235 license-file plumbing lands).

For the full design rationale, YAML schema, match operators,
destination types, secret handling, dry-run usage, and constraints
see the canonical cross-product reference at:

  - **iam-roles repo:** `docs/PER-ORG-NOTIFICATION-ROUTING.md`

The cross-product specification (flag names, YAML format, match
operators, destination types) is shared across ibounce / kbouncer /
dbounce per `[[cross-product-agent-parity]]`.

## dbounce-specific notes

- The flag is `dbounce run --alert-routes ROUTES.yaml`. Identical
  shape to `ibounce run --alert-routes` and `kbounce run --alert-routes`.
- The dry-run subcommand is `dbounce config preview-routes --routes
  ROUTES.yaml --event sample.json`. No HTTP traffic is sent; secrets
  render masked.
- License gate is currently a placeholder (`audit.ErrRoutesLicenseRequired`)
  that surfaces a clear error pointing the operator at issue #235.
  Once #235 lands, the placeholder is swapped for the real verifier;
  no other code changes.
- When `--alert-routes` is set, the legacy `--audit-webhook-url`
  path is ignored (with a startup warning). The JSONL log file +
  Security Lake adapter + per-session NDJSON recorder stay
  independent.
- The routing engine reuses dbounce's existing SSRF gate
  (`upstream.GuardInternalHost`) for webhook destinations so a
  routes-defined webhook can't accidentally hit an intranet host
  unless `allow_internal: true` is set on the destination.

## Quick start

```bash
$ export SOC_SPLUNK_HEC_TOKEN=...
$ export PD_INTEGRATION_KEY=...
$ export SLACK_ONCALL_WEBHOOK=https://hooks.slack.com/services/T1/B2/secret
$ dbounce config preview-routes \
      --routes ~/.iam-jit/dbounce-routes.yaml \
      --event sample-event.json
$ dbounce run --alert-routes ~/.iam-jit/dbounce-routes.yaml
```

## Composition

- The `webhook` destination supports the per-vendor presets from
  #257 (Datadog / Splunk HEC / Sentinel) via the
  `webhook.preset` field, identical to the dbounce
  `--audit-webhook-preset` shape.
- AWS Security Lake (#258) writes parquet to S3 alongside the
  routes engine; you can also point a `webhook` destination at a
  Lambda that ingests into Security Lake for per-route Security
  Lake fan-out.
- The per-session NDJSON recorder (#285) is unaffected by the
  routing engine; it tees every event to disk regardless of
  destination routing.

## Constraints (preserved verbatim from the cross-product memo)

- Don't expose tokens in routes YAML — always use `${ENV_VAR}`.
- Don't make `on_match: continue` the default; first-match-wins is
  what most customers expect.
- Don't add Kafka / SMTP / ServiceNow destinations pre-launch.
  Webhook + PagerDuty + Slack covers the v1.0 demand surface.
- Don't make the routes engine LLM-augmented. Deterministic
  match-engine only.

# Security Policy

See [`iam-roles/docs/SECURITY-POSTURE.md`](https://github.com/trsreagan3/iam-jit/blob/main/docs/SECURITY-POSTURE.md)
for the canonical security posture documentation for the iam-jit
suite. `dbounce` is one of four Bounce-suite binaries covered there.

## Reporting Security Issues

Email security@iam-jit.com (when configured; see issue #239 in the
`trsreagan3/iam-jit` repo) or open a private security advisory on
this repo's GitHub.

Do NOT open public issues for security vulnerabilities.

## Supported Versions

Latest `main` branch + v1.0+ tagged releases. See [`CHANGELOG.md`](./CHANGELOG.md)
for the release history.

## SQL redaction posture

Per `[[dbounce-sql-redaction-gaps]]` in the iam-roles memory, the
v1.0 redactor scrubs single-quoted string literals only. Numerics,
identifiers, and comments are NOT redacted by default. For
workloads handling PHI / PCI / PII, operators MUST configure their
own redaction layer (see `docs/QUERYING-AUDIT-LOGS.md`).

## Composes with

- [`iam-roles/docs/SECURITY-POSTURE.md`](https://github.com/trsreagan3/iam-jit/blob/main/docs/SECURITY-POSTURE.md) — cross-product security posture
- [`docs/HARDENING-AGAINST-PROMPT-INJECTION.md`](./docs/HARDENING-AGAINST-PROMPT-INJECTION.md) — dbounce-specific hardening

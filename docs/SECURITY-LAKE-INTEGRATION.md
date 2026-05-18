# AWS Security Lake Integration

Cross-product runbook for the `--security-lake-*` flags shipped by
every audit-export Bounce product (ibounce, kbounce, dbounce). The
adapter writes OCSF v1.1.0 class 6003 events as parquet files into
an S3 bucket that AWS Security Lake auto-ingests via its custom-
source crawler.

Per [[no-hosted-saas]] + [[self-host-zero-billing-dependency]]: the
bucket lives in the operator's AWS account. iam-jit-the-company
NEVER receives the data; Security Lake's per-GB ingest charge lands
on the operator's AWS bill.

Per [[creates-never-mutates]]: every S3 operation is `PutObject`
only. The adapter never overwrites or deletes; rotation timestamps
ensure unique filenames per flush.

Per [[cross-product-agent-parity]]: flag names + parquet column set
+ partition layout are identical across ibounce, kbounce, dbounce.
A single Athena query (or Glue catalog scan) walks every product's
partitions without a per-product schema mapping.

Per [[scorer-is-ground-truth]] + [[security-team-positioning-safety-
not-surveillance]]: the adapter is a passive sink. Severity +
verdict come from the existing scorer; no re-evaluation. Status
detail uses neutral language — never "violation"/"unauthorized"/
"infraction" framing.

gbounce SKIPPED — its webhook export path hasn't shipped yet
(planned in G-Slice 6).

## When to use Security Lake instead of (or alongside) the webhook

The audit-export channels are independent. Pick based on the
downstream consumer's shape:

| Consumer                                    | Channel               |
|---------------------------------------------|-----------------------|
| Splunk / Datadog / Sentinel (push intake)   | `--audit-webhook-*`   |
| AWS Security Lake (centralised lake)        | `--security-lake-*`   |
| Athena / Glue / Spark / lakeFS (pull query) | `--security-lake-*`   |
| Local log file shipped by Vector / Fluent Bit | `--audit-log-path`  |
| Forensics replay across a single session    | `--record-sessions-dir` |

Multiple channels can be enabled together; each runs independently
(a Security Lake credential outage doesn't stop the JSONL log from
catching up via Vector).

## Setup

### 1. Create the S3 bucket

Security Lake recommends a dedicated bucket per data source. The
bucket policy below grants `iam-jit-*` writers `PutObject` only
(no overwrite, no read, no delete) — matches the
[[creates-never-mutates]] discipline at the IAM layer:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowBouncePutObject",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<your-account>:role/iam-jit-bounce-security-lake-writer"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::iam-jit-bounce-security-lake/*"
    }
  ]
}
```

### 2. IAM role for the writer

The bouncer's IAM identity (instance role, EKS service account, or
the operator's local profile) needs ONE permission: `s3:PutObject`
on the bucket prefix. When `--security-lake-role-arn` is set, the
bouncer assumes that role first; the role needs the same
`s3:PutObject` policy.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::iam-jit-bounce-security-lake/*"
    }
  ]
}
```

When the bouncer runs without `--security-lake-role-arn`, the
default AWS credential chain is used (env / shared-config /
instance role / EKS IRSA / ECS task role). The adapter probes
credentials at start via `sts:GetCallerIdentity` and refuses to
start with a clear error if none are reachable — the operator sees
the misconfiguration immediately, not after the first flush attempt
hours later.

### 3. Register the custom source in Security Lake

In the AWS Security Lake console (or via `aws securitylake create-
custom-log-source`), register a custom source with:

- Source name: `iam-jit-bouncer`
- OCSF event class: `API_ACTIVITY` (6003)
- S3 source location: `s3://iam-jit-bounce-security-lake/`
- IAM role: the role that grants Security Lake's Glue crawler read
  access to the bucket

Security Lake's crawler discovers the partition layout below
without any extra configuration — `region` / `eventday` /
`eventhour` are first-class Security Lake partition keys.

### 4. Start the bouncer with the adapter enabled

**ibounce** (Python):

```bash
ibounce run \
  --mode transparent \
  --security-lake-bucket iam-jit-bounce-security-lake \
  --security-lake-region us-east-1
```

**kbounce** (Go):

```bash
kbounce run \
  --mode cooperative \
  --security-lake-bucket iam-jit-bounce-security-lake \
  --security-lake-region us-east-1
```

**dbounce** (Go):

```bash
dbounce run \
  --security-lake-bucket iam-jit-bounce-security-lake \
  --security-lake-region us-east-1
```

For cross-account deployments where Security Lake lives in a
dedicated security account, add `--security-lake-role-arn` to
assume a write-only role in that account:

```bash
ibounce run \
  --security-lake-bucket iam-jit-bounce-security-lake \
  --security-lake-region us-east-1 \
  --security-lake-role-arn arn:aws:iam::<security-account>:role/SecurityLakeWriter
```

### 5. Confirm Security Lake sees the data

After the first rotation interval (default 5 minutes) the bucket
contains one or more parquet files at the canonical partition path
(see "Partition layout" below). Security Lake's Glue crawler
updates the catalog on its own cadence (typically within 15
minutes); after that the data is queryable via Athena:

```sql
SELECT
  api_operation,
  unmapped_iam_jit_verdict,
  count(*) AS n
FROM iam_jit_bouncer_custom
WHERE eventday = '20260519'
GROUP BY api_operation, unmapped_iam_jit_verdict
ORDER BY n DESC;
```

(The same query works against ibounce, kbounce, dbounce partitions
unchanged — the column set is byte-identical across all three
products. Pivot on `metadata_product_name` to distinguish.)

## Partition layout

Every parquet file lands at:

```
s3://<bucket>/region=<r>/eventday=<YYYYMMDD>/eventhour=<HH>/<class-prefix>-<unix-ms>.parquet
```

Where:

- `<r>` is the `--security-lake-region` value (becomes the `region`
  partition key).
- `<YYYYMMDD>` + `<HH>` are UTC wall-clock at flush time. Security
  Lake's catalog reads partition keys in UTC.
- `<class-prefix>` is `api_activity` for OCSF class 6003 (today's
  only emitted class). Future OCSF classes get their own per-class
  prefix; the partition keys stay the same.
- `<unix-ms>` is the unix epoch in milliseconds at flush time —
  ensures filename uniqueness across concurrent producers (mirrors
  the AWS Firehose record-id pattern).

Example:

```
s3://iam-jit-bounce-security-lake/region=us-east-1/eventday=20260519/eventhour=14/api_activity-1747667253000.parquet
```

## Parquet column schema

The same column set across all three Bounce products. JSON-encoded
columns (`resources_json`, `unmapped_iam_jit_ext_json`,
`unmapped_iam_jit_agent_json`) keep the Athena-side schema flat
while preserving the nested OCSF substructure.

The cross-product test fixture
(`test_canonical_ocsf_columns_locked_in`) asserts the column set
byte-for-byte in every product's test suite — a stray addition in
any one product fails the test until all three are updated together.

Column naming convention: dots in OCSF dot-paths become
underscores in parquet column names (matches AWS Glue's auto-crawl
convention + Athena's idiomatic flat-column shape).

| Column                          | Type    | OCSF source                            |
|---------------------------------|---------|----------------------------------------|
| `metadata_version`              | string  | `metadata.version`                     |
| `metadata_product_name`         | string  | `metadata.product.name`                |
| `metadata_product_vendor_name`  | string  | `metadata.product.vendor_name`         |
| `metadata_product_version`      | string  | `metadata.product.version`             |
| `time`                          | int64   | `time`                                 |
| `class_uid`                     | int32   | `class_uid`                            |
| `class_name`                    | string  | `class_name`                           |
| `category_uid`                  | int32   | `category_uid`                         |
| `category_name`                 | string  | `category_name`                        |
| `activity_id`                   | int32   | `activity_id`                          |
| `activity_name`                 | string  | `activity_name`                        |
| `type_uid`                      | int32   | `type_uid`                             |
| `type_name`                     | string  | `type_name`                            |
| `severity_id`                   | int32   | `severity_id`                          |
| `severity`                      | string  | `severity`                             |
| `status_id`                     | int32   | `status_id`                            |
| `status`                        | string  | `status`                               |
| `status_detail`                 | string  | `status_detail`                        |
| `actor_user_name`               | string  | `actor.user.name`                      |
| `actor_user_uid`                | string  | `actor.user.uid`                       |
| `actor_session_uid`             | string  | `actor.session.uid`                    |
| `api_operation`                 | string  | `api.operation`                        |
| `api_service_name`              | string  | `api.service.name`                     |
| `api_request_uid`               | string  | `api.request.uid`                      |
| `resources_json`                | string  | `json_encode(resources)`               |
| `src_endpoint_hostname`         | string  | `src_endpoint.hostname`                |
| `src_endpoint_ip`               | string  | `src_endpoint.ip`                      |
| `src_endpoint_port`             | int32   | `src_endpoint.port`                    |
| `dst_endpoint_hostname`         | string  | `dst_endpoint.hostname`                |
| `dst_endpoint_ip`               | string  | `dst_endpoint.ip`                      |
| `dst_endpoint_port`             | int32   | `dst_endpoint.port`                    |
| `unmapped_iam_jit_mode`         | string  | `unmapped.iam_jit.mode`                |
| `unmapped_iam_jit_profile`      | string  | `unmapped.iam_jit.profile`             |
| `unmapped_iam_jit_verdict`      | string  | `unmapped.iam_jit.verdict`             |
| `unmapped_iam_jit_decision_id`  | int64   | `unmapped.iam_jit.decision_id`         |
| `unmapped_iam_jit_enforced`     | bool    | `unmapped.iam_jit.enforced`            |
| `unmapped_iam_jit_event_type`   | string  | `unmapped.iam_jit.event_type`          |
| `unmapped_iam_jit_ext_json`     | string  | `json_encode(unmapped.iam_jit.ext)`    |
| `unmapped_iam_jit_agent_json`   | string  | `json_encode(unmapped.iam_jit.agent)`  |

Snappy compression (Security Lake default; auto-supported by Athena
+ Spark + Glue without extra codec installs).

## Rotation semantics

Each OCSF class keeps its own in-memory batch (today every event is
class 6003; future slices add more). A batch flushes when either
fires first:

1. **Time**: the oldest row in the batch is older than
   `--security-lake-rotation-seconds` (default 300 = 5 minutes).
2. **Size**: the batch's estimated in-memory bytes cross 10 MiB.
3. **Shutdown**: `stop()` flushes every pending batch synchronously
   so a clean restart never drops rows.

Crash semantics: on SIGKILL the in-memory batch is lost; the JSONL
log + webhook channels are durable fallbacks (each runs
independently). Operators who need every-event durability against
process crashes enable the JSONL log alongside Security Lake —
Vector / Fluent Bit then ships the JSONL to a separate destination.

## Cost

AWS Security Lake bills on:

1. **Ingest** — per-GB of data processed by the auto-crawler. As of
   2026 this is ~$0.75/GB for raw OCSF.
2. **Storage** — standard S3 pricing on the bucket.
3. **Query** — Athena per-TB-scanned ($5/TB as of 2026).

Sample sizing: a 10-RPS proxy emitting one OCSF event per decision
produces ~50 GB/month of raw OCSF (snappy-compressed; uncompressed
is ~150 GB). Security Lake ingest cost ~$37.50/month at that
volume; Athena queries scan only the relevant partitions when the
WHERE clause filters on `eventday` + `eventhour`.

iam-jit-the-company does NOT see any of these charges — the bucket
+ Security Lake registration + Athena queries all run in the
operator's AWS account ([[self-host-zero-billing-dependency]]).

## Troubleshooting

**Bouncer refuses to start with "no AWS credentials in the default
chain"**: the default credential chain (env vars, shared config,
instance metadata, EKS IRSA) yielded no credentials. Either set
`--security-lake-role-arn` to assume a role from existing
credentials, or wire credentials via `AWS_ACCESS_KEY_ID` /
`AWS_PROFILE` / IRSA.

**Bouncer starts but no parquet files appear in S3**: the rotation
interval defaults to 5 minutes; wait at least that long. Check the
bouncer's startup banner for the AWS account + caller ARN it
detected; verify that identity has `s3:PutObject` on the bucket
prefix.

**Security Lake catalog doesn't show the data**: the Glue crawler
runs on its own cadence (typically within 15 minutes). Confirm the
custom source registration's S3 location matches the bucket name
exactly + the OCSF event class is `API_ACTIVITY`.

**Athena queries return null on most columns**: the bouncer writes
JSON-encoded values for nested fields (`resources_json`,
`unmapped_iam_jit_ext_json`, `unmapped_iam_jit_agent_json`); use
`json_extract` to unpack them in queries.

## See also

- [`WEBHOOK-PRESETS.md`](WEBHOOK-PRESETS.md) — the alternative
  push-based audit-export path (Splunk / Datadog / Sentinel).
- [`QUERYING-AUDIT-LOGS.md`](QUERYING-AUDIT-LOGS.md) — the local
  JSONL log channel + Athena-style queries against it.
- AWS Security Lake docs:
  <https://docs.aws.amazon.com/security-lake/latest/userguide/what-is-security-lake.html>
- OCSF v1.1.0 class 6003 spec:
  <https://schema.ocsf.io/1.1.0/classes/api_activity>

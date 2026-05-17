// Package packs holds dbounce's embedded rule-pack YAMLs.
//
// D-Slice 5 ships mysql.yaml as the first pack. D-Slice 7 wires the
// profile loader that reads these into rules.RuleSets at startup; for
// D-Slice 5 the pack is embedded so it's available to the loader the
// moment that slice lands without an additional commit to add the
// file. The embed.FS handle below is the single point of access.
//
// D-Slice 6 adds snowflake.yaml + bigquery.yaml. Both ship
// calibration_status: experimental per [[scorer-is-ground-truth]] —
// Snowflake/BigQuery don't have the same eval-corpus depth as PG/MySQL
// and the underlying parser is best-effort (xwb1989 + dialect keyword
// pre-checks). See docs/SHIM-INTEGRATION.md for the JDBC-driver-shim
// integration shape that delivers these packs to running deployments.
//
// Per [[bounce-default-profile-pattern]]: packs are CONSERVATIVE +
// LEAN-PERMISSIVE defaults. Admins ALWAYS override via per-task scopes
// or by editing the active profile. Packs are starting points, not
// terminal policy.
//
// Per [[scorer-is-ground-truth]]: every rule in a pack carries its
// own calibration_status metadata so the audit reviewer knows how
// rigorously each rule was tested. MySQL ships provisional in v1.0;
// postgres ships in D-Slice 3+ with full calibration; snowflake +
// bigquery ship experimental in D-Slice 6.
package packs

import _ "embed"

// MySQL is the embedded MySQL rule pack YAML. D-Slice 7's profile
// loader unmarshals + materializes it into a rules.RuleSet.
//
//go:embed mysql.yaml
var MySQL []byte

// Snowflake is the embedded Snowflake rule pack YAML (D-Slice 6).
// Ships calibration_status: experimental — see file header for the
// honest framing rationale.
//
//go:embed snowflake.yaml
var Snowflake []byte

// BigQuery is the embedded BigQuery rule pack YAML (D-Slice 6).
// Ships calibration_status: experimental.
//
//go:embed bigquery.yaml
var BigQuery []byte

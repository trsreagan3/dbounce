// Package packs holds dbounce's embedded rule-pack YAMLs.
//
// D-Slice 5 ships mysql.yaml as the first pack. D-Slice 7 wires the
// profile loader that reads these into rules.RuleSets at startup; for
// D-Slice 5 the pack is embedded so it's available to the loader the
// moment that slice lands without an additional commit to add the
// file. The embed.FS handle below is the single point of access.
//
// Per [[bounce-default-profile-pattern]]: packs are CONSERVATIVE +
// LEAN-PERMISSIVE defaults. Admins ALWAYS override via per-task scopes
// or by editing the active profile. Packs are starting points, not
// terminal policy.
//
// Per [[scorer-is-ground-truth]]: every rule in a pack carries its
// own calibration_status metadata so the audit reviewer knows how
// rigorously each rule was tested. MySQL ships provisional in v1.0;
// postgres ships in D-Slice 3+ with full calibration.
package packs

import _ "embed"

// MySQL is the embedded MySQL rule pack YAML. D-Slice 7's profile
// loader unmarshals + materializes it into a rules.RuleSet.
//
//go:embed mysql.yaml
var MySQL []byte

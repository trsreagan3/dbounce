// Package profile — defaults.go
//
// Embedded default profiles YAML. Shipped inside the binary via
// //go:embed so a fresh install has working profiles even on an air-
// gapped machine with no network. The CLI writes this content to
// ~/.dbounce/profiles.yaml on first `run` if no file exists yet;
// existing files are NEVER overwritten so operator edits survive
// upgrades.
//
// Keep this list in sync with the iam-jit-bouncer Python defaults +
// the kbouncer Go defaults so the three products surface the same
// vocabulary to the operator.
package profile

import _ "embed"

//go:embed defaults.yaml
var defaultProfilesYAML []byte

// DefaultProfilesYAML returns the embedded default profiles YAML. The
// returned slice is a copy so callers can't mutate the embedded bytes.
func DefaultProfilesYAML() []byte {
	out := make([]byte, len(defaultProfilesYAML))
	copy(out, defaultProfilesYAML)
	return out
}

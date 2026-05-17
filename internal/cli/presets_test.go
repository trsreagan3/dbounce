package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// INFO-D8-14: newPresetsCmd MUST panic on nil ProfileWriter.
func TestPresetsCmd_NilWriter_Panics(t *testing.T) {
	assert.Panics(t, func() { _ = newPresetsCmd(nil) },
		"newPresetsCmd MUST panic on nil ProfileWriter (INFO-D8-14)")
}

func TestPresetsCmd_TreeWired(t *testing.T) {
	c := newPresetsCmd(&recordingProfileWriter{})
	assert.Equal(t, "presets", c.Name())
	subs := map[string]bool{}
	for _, s := range c.Commands() {
		subs[s.Name()] = true
	}
	for _, sub := range []string{"list", "show", "apply"} {
		assert.True(t, subs[sub], "presets must wire %s subcommand", sub)
	}
}

func TestPresetsList_ContainsStarterIDs(t *testing.T) {
	cmd := newPresetsListCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	text := out.String()
	for _, id := range []string{
		"analytics-engineer", "dba-investigation",
		"migration-runner", "incident-readonly", "schema-survey",
	} {
		assert.Contains(t, text, id, "presets list output must include starter preset id %q", id)
	}
}

func TestPresetsShow_KnownPreset(t *testing.T) {
	cmd := newPresetsShowCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"incident-readonly"})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "incident-readonly")
	assert.Contains(t, text, "allow_rules")
	assert.Contains(t, text, "deny_rules")
}

func TestPresetsShow_UnknownPreset(t *testing.T) {
	cmd := newPresetsShowCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"no-such-preset"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no preset named")
}

func TestPresetsApply_CreatesProfile_AutoName(t *testing.T) {
	rw := &recordingProfileWriter{}
	cmd := newPresetsApplyCmd(rw)
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"analytics-engineer"})
	require.NoError(t, cmd.Execute())
	require.Len(t, rw.created, 1)
	p := rw.created[0]
	assert.True(t, strings.HasPrefix(p.Name, "auto-"),
		"non-TTY + no --target should produce auto- name (got %q)", p.Name)
	assert.Contains(t, p.Name, "preset")
	assert.Contains(t, p.Name, "analytics-engineer")
	// allow_rules from the YAML should propagate
	assert.NotEmpty(t, p.Allow)
}

func TestPresetsApply_ExplicitTarget(t *testing.T) {
	rw := &recordingProfileWriter{}
	cmd := newPresetsApplyCmd(rw)
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"incident-readonly", "--target=my-readonly"})
	require.NoError(t, cmd.Execute())
	require.Len(t, rw.created, 1)
	assert.Equal(t, "my-readonly", rw.created[0].Name)
}

func TestPresetsApply_UnknownPreset(t *testing.T) {
	cmd := newPresetsApplyCmd(&recordingProfileWriter{})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"no-such-preset"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no preset named")
}

// INFO-D8-14 (AUDIT-WB-DSLICES-1-8.md): the stub-writer behavior was
// removed. newPresetsApplyCmd now panics at construction on nil
// ProfileWriter so a wiring regression is caught at build/test time
// (rather than surfacing a confusing "not configured" error to the
// operator at runtime, which was unreachable after #245 landed
// production wiring anyway).
func TestPresetsApplyCmd_NilWriter_Panics(t *testing.T) {
	assert.Panics(t, func() { _ = newPresetsApplyCmd(nil) },
		"newPresetsApplyCmd MUST panic on nil ProfileWriter (INFO-D8-14)")
}

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPresetsCmd_TreeWired(t *testing.T) {
	c := newPresetsCmd(nil)
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
	cmd := newPresetsApplyCmd(nil)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"no-such-preset"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no preset named")
}

func TestPresetsApply_StubWriterReturnsErrorFromStub(t *testing.T) {
	// The default stub writer is wired when nil is passed; it surfaces
	// a clear error rather than silently no-op'ing.
	cmd := newPresetsApplyCmd(nil)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"schema-survey"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "profile creation requires")
}

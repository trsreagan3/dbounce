package cli

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbrules "github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

// recordingProfileWriter is a ProfileWriter test double that captures
// CreateProfile calls. Lets the `--kind profile` path be exercised
// without the D-Slice 7 profile package wired in.
type recordingProfileWriter struct {
	mu       sync.Mutex
	created  []recordedProfile
	existing map[string]struct{}
	failNext error
}

type recordedProfile struct {
	Name        string
	Description string
	Allow       []dbrules.ProxyRule
	Deny        []dbrules.ProxyRule
}

func (r *recordingProfileWriter) CreateProfile(name, desc string,
	allow []dbrules.ProxyRule, deny []dbrules.ProxyRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failNext != nil {
		err := r.failNext
		r.failNext = nil
		return err
	}
	r.created = append(r.created, recordedProfile{
		Name: name, Description: desc, Allow: allow, Deny: deny,
	})
	if r.existing == nil {
		r.existing = map[string]struct{}{}
	}
	r.existing[name] = struct{}{}
	return nil
}

func (r *recordingProfileWriter) ExistingProfileNames() (map[string]struct{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]struct{}, len(r.existing))
	for k := range r.existing {
		out[k] = struct{}{}
	}
	return out, nil
}

// enqueueTestPrompt is a helper that seeds the store with a decision
// row + an associated pending_prompts row. Returns the prompt id.
func enqueueTestPrompt(t *testing.T, db string) int64 {
	t.Helper()
	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	decID, err := st.RecordDecision(store.DecisionRow{
		Dialect:         "postgres",
		Statement:       "SELECT * FROM public.audit_log",
		StatementType:   "SELECT",
		TablesTouched:   []string{"public.audit_log"},
		DecisionVerdict: "DENY",
		DecisionReason:  "out-of-scope",
		ModeAtDecision:  "transparent",
	})
	require.NoError(t, err)
	id, err := st.AddPendingPrompt(store.PendingPrompt{
		DecisionID:    decID,
		StatementType: "SELECT",
		TablesTouched: []string{"public.audit_log"},
		DenyReason:    "out-of-scope",
	})
	require.NoError(t, err)
	return id
}

// INFO-D8-14 (AUDIT-WB-DSLICES-1-8.md): ProfileWriter is non-nullable.
// The stub error message was never reachable in production after #245
// landed the profileWriterAdapter wiring; replacing it with a panic
// at construction time means a regression that drops the wiring would
// fail loudly during test/build, NOT silently surface a confusing
// "not configured" message to operators.
func TestPromptsCmd_NilWriter_Panics(t *testing.T) {
	assert.Panics(t, func() { _ = newPromptsCmd(nil) },
		"newPromptsCmd MUST panic on nil ProfileWriter (INFO-D8-14)")
}

func TestPromptsCmd_TreeWired(t *testing.T) {
	c := newPromptsCmd(&recordingProfileWriter{})
	assert.Equal(t, "prompts", c.Name())
	subs := map[string]bool{}
	for _, s := range c.Commands() {
		subs[s.Name()] = true
	}
	for _, sub := range []string{"list", "show", "answer"} {
		assert.True(t, subs[sub], "prompts must wire %s subcommand", sub)
	}
}

func TestPromptsList_EmptyAndPopulated(t *testing.T) {
	db := dbAt(t)
	cmd := newPromptsListCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "(no prompts)")

	id := enqueueTestPrompt(t, db)

	cmd2 := newPromptsListCmd()
	out2 := &bytes.Buffer{}
	cmd2.SetOut(out2)
	cmd2.SetErr(out2)
	cmd2.SetArgs([]string{"--db", db})
	require.NoError(t, cmd2.Execute())
	text := out2.String()
	assert.Contains(t, text, "SELECT")
	assert.Contains(t, text, "public.audit_log")
	_ = id
}

func TestPromptsShow_FoundAndMissing(t *testing.T) {
	db := dbAt(t)
	id := enqueueTestPrompt(t, db)

	cmd := newPromptsShowCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db, intStr(id)})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "statement_type: SELECT")
	assert.Contains(t, text, "deny_reason   : out-of-scope")

	missing := newPromptsShowCmd()
	missing.SetOut(&bytes.Buffer{})
	missing.SetErr(&bytes.Buffer{})
	missing.SetArgs([]string{"--db", db, "9999"})
	err := missing.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no prompt with id")
}

func TestPromptsAnswer_Ignore(t *testing.T) {
	db := dbAt(t)
	id := enqueueTestPrompt(t, db)

	cmd := newPromptsAnswerCmd(&recordingProfileWriter{})
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db, intStr(id), "--kind", "ignore", "--actor", "alice"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "ignored")

	// Re-answer should fail (already ignored).
	cmd2 := newPromptsAnswerCmd(&recordingProfileWriter{})
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--db", db, intStr(id), "--kind", "ignore"})
	err := cmd2.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already")
}

func TestPromptsAnswer_Always_AddsRule(t *testing.T) {
	db := dbAt(t)
	id := enqueueTestPrompt(t, db)

	cmd := newPromptsAnswerCmd(&recordingProfileWriter{})
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db, intStr(id), "--kind", "always", "--actor", "alice"})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "always")
	assert.Contains(t, text, "SELECT:public.audit_log")

	st, err := store.Open(db)
	require.NoError(t, err)
	defer st.Close()
	rules, err := st.ListRules()
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "SELECT:public.audit_log", rules[0].Rule.Pattern)
	assert.Equal(t, dbrules.EffectAllow, rules[0].Rule.Effect)
}

func TestPromptsAnswer_Profile_CallsWriter(t *testing.T) {
	db := dbAt(t)
	id := enqueueTestPrompt(t, db)
	rw := &recordingProfileWriter{}

	cmd := newPromptsAnswerCmd(rw)
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	// --target absent + non-TTY (test runner) → auto-name path.
	cmd.SetArgs([]string{"--db", db, intStr(id), "--kind", "profile", "--actor", "alice"})
	require.NoError(t, cmd.Execute())
	require.Len(t, rw.created, 1)
	p := rw.created[0]
	assert.True(t, strings.HasPrefix(p.Name, "auto-"),
		"non-TTY + no --target should produce an auto- prefixed name (got %q)", p.Name)
	assert.True(t, strings.Contains(p.Name, "prompt"),
		"auto-name should embed kind=prompt (got %q)", p.Name)
	require.Len(t, p.Allow, 1)
	assert.Equal(t, "SELECT:public.audit_log", p.Allow[0].Pattern)
}

func TestPromptsAnswer_Profile_ExplicitTarget(t *testing.T) {
	db := dbAt(t)
	id := enqueueTestPrompt(t, db)
	rw := &recordingProfileWriter{}

	cmd := newPromptsAnswerCmd(rw)
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"--db", db, intStr(id),
		"--kind", "profile", "--target=my-audit-allow", "--actor", "alice"})
	require.NoError(t, cmd.Execute())
	require.Len(t, rw.created, 1)
	assert.Equal(t, "my-audit-allow", rw.created[0].Name)
}

func TestPromptsAnswer_RejectsUnknownKind(t *testing.T) {
	db := dbAt(t)
	id := enqueueTestPrompt(t, db)
	cmd := newPromptsAnswerCmd(&recordingProfileWriter{})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", db, intStr(id), "--kind", "garbage"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--kind must be one of")
}

// INFO-D8-14: newPromptsAnswerCmd MUST panic on nil ProfileWriter.
func TestPromptsAnswerCmd_NilWriter_Panics(t *testing.T) {
	assert.Panics(t, func() { _ = newPromptsAnswerCmd(nil) },
		"newPromptsAnswerCmd MUST panic on nil ProfileWriter (INFO-D8-14)")
}

func TestPromptsAnswer_ProfileWriterErrorSurfaces(t *testing.T) {
	db := dbAt(t)
	id := enqueueTestPrompt(t, db)
	rw := &recordingProfileWriter{failNext: errors.New("simulated store failure")}
	cmd := newPromptsAnswerCmd(rw)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--db", db, intStr(id), "--kind", "profile"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated store failure")
}

func intStr(i int64) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	out := ""
	for i > 0 {
		out = string(digits[i%10]) + out
		i /= 10
	}
	return out
}

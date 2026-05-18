// Tests for the #268 `dbounce audit tail` enhancements: --follow,
// --filter, --summary, --export FORMAT --out PATH.
//
// Sentinel-literal coverage (the load-bearing test for the SQL-PII
// story per [[scorer-is-ground-truth]] + [[ibounce-honest-positioning]]):
// seed an audit row whose stored statement contains
// 'sentinel-literal-XYZ'; assert the literal is ABSENT from every
// produced export cell across csv + ocsf-bundle paths. If the redactor
// misses a literal shape (e.g. a quoted-identifier the regex sweep
// mis-classifies as a literal), the sentinel test catches it before
// the operator's PII ends up in a SIEM.

package cli

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/store"
)

const sentinelLiteral = "sentinel-literal-XYZ"

// seedRow writes one decision row with the given statement; returns the
// path to the temp DB.
func seedDBWithStatement(t *testing.T, stmt, stmtType, verdict string) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()
	_, err = st.RecordDecision(store.DecisionRow{
		At:               time.Now().UTC(),
		Dialect:          "postgres",
		Statement:        stmt,
		StatementType:    stmtType,
		TablesTouched:    []string{"public.users"},
		DecisionVerdict:  verdict,
		DecisionReason:   "test",
		ModeAtDecision:   "cooperative",
		IsDML:            true,
		ImpersonatedRole: "alice",
	})
	require.NoError(t, err)
	return dbPath
}

func TestAuditTail_FilterMutuallyExclusiveFollowSummary(t *testing.T) {
	dbPath := seedDBWithStatement(t, "SELECT 1", "SELECT", "ALLOW")
	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--follow", "--summary"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestAuditTail_ExportRequiresOut(t *testing.T) {
	dbPath := seedDBWithStatement(t, "SELECT 1", "SELECT", "ALLOW")
	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--export", "jsonl"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--out")
}

func TestAuditTail_ExportUnknownFormat(t *testing.T) {
	dbPath := seedDBWithStatement(t, "SELECT 1", "SELECT", "ALLOW")
	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SilenceUsage = true
	outFile := filepath.Join(t.TempDir(), "x.bin")
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--export", "yaml", "--out", outFile})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported --export format")
}

func TestAuditTail_FilterInvalidExpression(t *testing.T) {
	dbPath := seedDBWithStatement(t, "SELECT 1", "SELECT", "ALLOW")
	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--filter", "nope"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --filter")
}

func TestAuditTail_FilterEqualityOnActorUserName(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	for _, who := range []string{"alice", "bob", "alice"} {
		_, err := st.RecordDecision(store.DecisionRow{
			At:               time.Now().UTC(),
			Dialect:          "postgres",
			Statement:        "SELECT 1",
			StatementType:   "SELECT",
			DecisionVerdict: "ALLOW",
			ModeAtDecision:  "cooperative",
			ImpersonatedRole: who,
		})
		require.NoError(t, err)
	}
	require.NoError(t, st.Close())
	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--json",
		"--filter", "actor.user.name=alice"})
	require.NoError(t, cmd.Execute())
	// Two records expected (the two alice rows).
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		assert.Equal(t, "alice", rec["impersonated_role"])
		count++
	}
	assert.Equal(t, 2, count)
}

func TestAuditTail_FilterRegexAndNumericAndNested(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	// Two SELECTs + one DELETE — DELETE maps to OCSF activity_id=4.
	_, err = st.RecordDecision(store.DecisionRow{
		At: time.Now().UTC(), Dialect: "postgres",
		Statement: "SELECT 1", StatementType: "SELECT",
		DecisionVerdict: "ALLOW", ModeAtDecision: "cooperative",
		ImpersonatedRole: "alice-team",
	})
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		At: time.Now().UTC(), Dialect: "postgres",
		Statement: "SELECT 2", StatementType: "SELECT",
		DecisionVerdict: "ALLOW", ModeAtDecision: "cooperative",
		ImpersonatedRole: "bob-team",
	})
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		At: time.Now().UTC(), Dialect: "postgres",
		Statement: "DELETE FROM users", StatementType: "DELETE",
		DecisionVerdict: "DENY", ModeAtDecision: "transparent",
		Enforced: true, ImpersonatedRole: "carol-team",
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	// Regex on actor — match alice + carol but not bob.
	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--json",
		"--filter", "actor.user.name~^(alice|carol)"})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "alice-team")
	assert.Contains(t, text, "carol-team")
	assert.NotContains(t, text, "bob-team")

	// Numeric >= on activity_id — DELETE=4, SELECT=2; filter >=4 keeps DELETE only.
	cmd2 := newAuditCmd()
	out2 := &bytes.Buffer{}
	cmd2.SetOut(out2)
	cmd2.SetErr(out2)
	cmd2.SetArgs([]string{"tail", "--db", dbPath, "--json",
		"--filter", "activity_id>=4"})
	require.NoError(t, cmd2.Execute())
	text2 := out2.String()
	assert.Contains(t, text2, "DELETE")
	assert.NotContains(t, text2, "SELECT")

	// Numeric <= on activity_id — keep <=2 (SELECT) only.
	cmd3 := newAuditCmd()
	out3 := &bytes.Buffer{}
	cmd3.SetOut(out3)
	cmd3.SetErr(out3)
	cmd3.SetArgs([]string{"tail", "--db", dbPath, "--json",
		"--filter", "activity_id<=2"})
	require.NoError(t, cmd3.Execute())
	text3 := out3.String()
	assert.Contains(t, text3, "SELECT")
	assert.NotContains(t, text3, "DELETE")

	// Nested path: unmapped.iam_jit.verdict=DENY → DELETE row only.
	cmd4 := newAuditCmd()
	out4 := &bytes.Buffer{}
	cmd4.SetOut(out4)
	cmd4.SetErr(out4)
	cmd4.SetArgs([]string{"tail", "--db", dbPath, "--json",
		"--filter", "unmapped.iam_jit.verdict=DENY"})
	require.NoError(t, cmd4.Execute())
	text4 := out4.String()
	assert.Contains(t, text4, "DELETE")
	assert.NotContains(t, text4, "SELECT")
}

func TestAuditTail_FilterANDCombines(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		At: time.Now().UTC(), Dialect: "postgres",
		Statement: "SELECT 1", StatementType: "SELECT",
		DecisionVerdict: "ALLOW", ModeAtDecision: "cooperative",
		ImpersonatedRole: "alice",
	})
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		At: time.Now().UTC(), Dialect: "postgres",
		Statement: "DELETE FROM users", StatementType: "DELETE",
		DecisionVerdict: "ALLOW", ModeAtDecision: "cooperative",
		ImpersonatedRole: "alice",
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	// AND: actor=alice AND activity_id>=4 → DELETE only.
	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--json",
		"--filter", "actor.user.name=alice",
		"--filter", "activity_id>=4"})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "DELETE")
	assert.NotContains(t, text, `"statement_type":"SELECT"`)
}

func TestAuditTail_SummaryCounts(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	for _, row := range []struct {
		typ, who string
	}{
		{"SELECT", "alice"},
		{"SELECT", "alice"},
		{"DELETE", "bob"},
	} {
		_, err := st.RecordDecision(store.DecisionRow{
			At: time.Now().UTC(), Dialect: "postgres",
			Statement: "stmt", StatementType: row.typ,
			DecisionVerdict: "ALLOW", ModeAtDecision: "cooperative",
			ImpersonatedRole: row.who,
		})
		require.NoError(t, err)
	}
	require.NoError(t, st.Close())
	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--summary"})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "total: 3")
	assert.Contains(t, text, "by event_type")
	assert.Contains(t, text, "by severity_id")
	assert.Contains(t, text, "by actor.user.name")
	assert.Contains(t, text, "by api.operation")
	// SELECT(2) + DELETE(1)
	assert.Regexp(t, `2\s+SELECT`, text)
	assert.Regexp(t, `1\s+DELETE`, text)
	// alice(2) + bob(1)
	assert.Regexp(t, `2\s+alice`, text)
	assert.Regexp(t, `1\s+bob`, text)
}

func TestAuditTail_SummaryEmptyZeroCounts(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	require.NoError(t, st.Close())
	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--summary"})
	require.NoError(t, cmd.Execute())
	text := out.String()
	assert.Contains(t, text, "total: 0")
	// Section headers always present + each prints "(none)" placeholder.
	assert.Contains(t, text, "by event_type")
	assert.Contains(t, text, "(none)")
}

func TestAuditTail_ExportJSONLRoundTrips(t *testing.T) {
	stmt := "SELECT * FROM users WHERE name='" + sentinelLiteral + "'"
	dbPath := seedDBWithStatement(t, stmt, "SELECT", "ALLOW")
	outFile := filepath.Join(t.TempDir(), "out.jsonl")
	cmd := newAuditCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--export", "jsonl", "--out", outFile})
	require.NoError(t, cmd.Execute())
	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	// JSONL: each line parses as JSON.
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		// OCSF metadata block must be present.
		assert.Contains(t, rec, "metadata")
		assert.Contains(t, rec, "activity_id")
	}
}

// LOAD-BEARING TEST per the spec's SQL-PII story: a stored statement
// containing 'sentinel-literal-XYZ' MUST NOT appear in any CSV cell on
// the export path, because the redactor runs defensively on read.
func TestAuditTail_ExportCSV_RedactsSQLLiterals(t *testing.T) {
	stmt := "SELECT * FROM users WHERE token='" + sentinelLiteral + "'"
	dbPath := seedDBWithStatement(t, stmt, "SELECT", "ALLOW")
	outFile := filepath.Join(t.TempDir(), "out.csv")
	cmd := newAuditCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	// Include the `statement` column explicitly so we exercise the
	// redactor on the highest-risk surface.
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--export", "csv", "--out", outFile,
		"--csv-columns", "timestamp,operation,statement,verdict,actor"})
	require.NoError(t, cmd.Execute())
	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	// Sentinel MUST be absent from the whole file, full-stop.
	assert.NotContains(t, string(data), sentinelLiteral,
		"raw SQL literal must NOT appear in any CSV cell on the export path")

	// CSV parses cleanly.
	r := csv.NewReader(bytes.NewReader(data))
	records, err := r.ReadAll()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(records), 2, "header + at least one data row")
	assert.Equal(t, []string{"timestamp", "operation", "statement", "verdict", "actor"}, records[0])
	// Spot-check the data row — statement column has [REDACTED] in place
	// of the literal.
	dataRow := records[1]
	assert.Equal(t, "SELECT", dataRow[1])
	assert.Contains(t, dataRow[2], "[REDACTED]")
	assert.NotContains(t, dataRow[2], sentinelLiteral)
}

func TestAuditTail_ExportCSV_DefaultColumns(t *testing.T) {
	dbPath := seedDBWithStatement(t, "SELECT 1", "SELECT", "ALLOW")
	outFile := filepath.Join(t.TempDir(), "out.csv")
	cmd := newAuditCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--export", "csv", "--out", outFile})
	require.NoError(t, cmd.Execute())
	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	r := csv.NewReader(bytes.NewReader(data))
	records, err := r.ReadAll()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(records), 2)
	for _, want := range []string{
		"timestamp", "severity", "event_type", "actor",
		"operation", "verdict", "agent.name", "agent.session_id",
	} {
		assert.Contains(t, records[0], want, "default columns must include %q", want)
	}
}

func TestAuditTail_ExportOCSFBundle_RedactsAndValidates(t *testing.T) {
	stmt := "UPDATE users SET token='" + sentinelLiteral + "' WHERE id=42"
	dbPath := seedDBWithStatement(t, stmt, "UPDATE", "ALLOW")
	outFile := filepath.Join(t.TempDir(), "bundle.json")
	cmd := newAuditCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--export", "ocsf-bundle", "--out", outFile})
	require.NoError(t, cmd.Execute())
	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	// Sentinel literal must be absent from the entire bundle.
	assert.NotContains(t, string(data), sentinelLiteral,
		"raw SQL literal must NOT appear in OCSF bundle on the export path")

	// Bundle parses as a Detection Finding object.
	var bundle map[string]any
	require.NoError(t, json.Unmarshal(data, &bundle))
	require.Contains(t, bundle, "findings")
	require.Contains(t, bundle, "metadata")
	findings, ok := bundle["findings"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, findings)
	first, ok := findings[0].(map[string]any)
	require.True(t, ok)
	// OCSF Detection Finding shape: class_uid=2004
	assert.Equal(t, float64(2004), first["class_uid"])
	assert.Equal(t, "Detection Finding", first["class_name"])
	assert.Contains(t, first, "finding_info")
	assert.Contains(t, first, "metadata")
	assert.Contains(t, first, "observables")
}

func TestAuditTail_ExportRefusesOverwrite(t *testing.T) {
	dbPath := seedDBWithStatement(t, "SELECT 1", "SELECT", "ALLOW")
	outFile := filepath.Join(t.TempDir(), "out.jsonl")
	require.NoError(t, os.WriteFile(outFile, []byte("preexisting"), 0o600))
	cmd := newAuditCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--export", "jsonl", "--out", outFile})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to overwrite")
}

func TestAuditTail_FilterPlusExportComposes(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		At: time.Now().UTC(), Dialect: "postgres",
		Statement: "SELECT 1", StatementType: "SELECT",
		DecisionVerdict: "ALLOW", ModeAtDecision: "cooperative",
		ImpersonatedRole: "alice",
	})
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		At: time.Now().UTC(), Dialect: "postgres",
		Statement: "DELETE FROM users", StatementType: "DELETE",
		DecisionVerdict: "DENY", ModeAtDecision: "transparent", Enforced: true,
		ImpersonatedRole: "bob",
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	outFile := filepath.Join(t.TempDir(), "out.jsonl")
	cmd := newAuditCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"tail", "--db", dbPath,
		"--export", "jsonl", "--out", outFile,
		"--filter", "actor.user.name=alice"})
	require.NoError(t, cmd.Execute())
	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	require.Len(t, lines, 1, "filter must restrict export to one row")
	var rec map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &rec))
	api, _ := rec["api"].(map[string]any)
	require.NotNil(t, api)
	assert.Equal(t, "SELECT", api["operation"])
}

func TestAuditTail_FollowLoopEmitsNewRowsAndExitsOnCtx(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()

	// Pre-seed one row that should NOT be emitted (follow watermark
	// starts at MaxDecisionID).
	_, err = st.RecordDecision(store.DecisionRow{
		At: time.Now().UTC(), Dialect: "postgres",
		Statement: "SELECT pre_existing", StatementType: "SELECT",
		DecisionVerdict: "ALLOW", ModeAtDecision: "cooperative",
	})
	require.NoError(t, err)
	watermark, err := st.MaxDecisionID()
	require.NoError(t, err)

	out := &bytes.Buffer{}
	ctx, cancel := context.WithCancel(context.Background())
	// Drive the loop body directly with a deadline-bound context so the
	// test doesn't need to fire SIGINT.
	go func() {
		// Insert a fresh row after the loop starts so we exercise the
		// "new row after start" path.
		time.Sleep(40 * time.Millisecond)
		_, _ = st.RecordDecision(store.DecisionRow{
			At: time.Now().UTC(), Dialect: "postgres",
			Statement: "SELECT post_start", StatementType: "SELECT",
			DecisionVerdict: "ALLOW", ModeAtDecision: "cooperative",
		})
		// Give the loop one tick to drain.
		time.Sleep(120 * time.Millisecond)
		cancel()
	}()

	o := &auditTailOpts{}
	err = runAuditTailFollowLoop(ctx, out, st, nil, o, watermark, 30*time.Millisecond)
	require.NoError(t, err)

	text := out.String()
	assert.Contains(t, text, "SELECT post_start",
		"new row added after follow started must appear")
	assert.NotContains(t, text, "SELECT pre_existing",
		"pre-follow row must NOT be replayed under tail -f semantics")
}

func TestAuditTail_FollowLoopHonorsFilters(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()

	watermark, err := st.MaxDecisionID()
	require.NoError(t, err)

	out := &bytes.Buffer{}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		_, _ = st.RecordDecision(store.DecisionRow{
			At: time.Now().UTC(), Dialect: "postgres",
			Statement: "SELECT alice_row", StatementType: "SELECT",
			DecisionVerdict: "ALLOW", ModeAtDecision: "cooperative",
			ImpersonatedRole: "alice",
		})
		_, _ = st.RecordDecision(store.DecisionRow{
			At: time.Now().UTC(), Dialect: "postgres",
			Statement: "SELECT bob_row", StatementType: "SELECT",
			DecisionVerdict: "ALLOW", ModeAtDecision: "cooperative",
			ImpersonatedRole: "bob",
		})
		time.Sleep(120 * time.Millisecond)
		cancel()
	}()

	predicates, err := parseFilterExprs([]string{"actor.user.name=alice"})
	require.NoError(t, err)
	o := &auditTailOpts{}
	err = runAuditTailFollowLoop(ctx, out, st, predicates, o, watermark, 30*time.Millisecond)
	require.NoError(t, err)

	text := out.String()
	assert.Contains(t, text, "alice_row")
	assert.NotContains(t, text, "bob_row",
		"--filter must restrict follow output")
}

// Cobra command-tree spot-check: the new flags are wired.
func TestAuditTailCmd_HasNewFlags(t *testing.T) {
	cmd := newAuditTailCmd()
	for _, name := range []string{
		"follow", "filter", "summary", "export", "out",
		"csv-columns", "poll-interval",
	} {
		assert.NotNil(t, cmd.Flags().Lookup(name),
			"audit tail must expose --%s", name)
	}
}

func TestAuditTail_RedactorSentinelOnAllSQLFields(t *testing.T) {
	// Defensive sentinel test: the redactor runs on Statement,
	// DecisionReason, UpstreamResponseSummary, AND ParseErrors so an
	// upstream error message that echoes the literal won't slip through.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	_, err = st.RecordDecision(store.DecisionRow{
		At: time.Now().UTC(), Dialect: "postgres",
		Statement:               "SELECT '" + sentinelLiteral + "'",
		StatementType:           "SELECT",
		DecisionVerdict:         "ALLOW",
		DecisionReason:          "echo from upstream: '" + sentinelLiteral + "'",
		ModeAtDecision:          "cooperative",
		ParseErrors:             []string{"near '" + sentinelLiteral + "': parse failed"},
		UpstreamResponseSummary: "value '" + sentinelLiteral + "' rejected",
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	outCSV := filepath.Join(t.TempDir(), "out.csv")
	cmd := newAuditCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"tail", "--db", dbPath, "--export", "csv", "--out", outCSV,
		"--csv-columns", "timestamp,operation,statement"})
	require.NoError(t, cmd.Execute())
	csvData, err := os.ReadFile(outCSV)
	require.NoError(t, err)
	assert.NotContains(t, string(csvData), sentinelLiteral)

	outBundle := filepath.Join(t.TempDir(), "bundle.json")
	cmd2 := newAuditCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"tail", "--db", dbPath, "--export", "ocsf-bundle", "--out", outBundle})
	require.NoError(t, cmd2.Execute())
	bundleData, err := os.ReadFile(outBundle)
	require.NoError(t, err)
	assert.NotContains(t, string(bundleData), sentinelLiteral)
}

// errFollowCloseTest ensures the context-cancellation path terminates
// runAuditTailFollowLoop cleanly even with no rows ever inserted —
// otherwise an operator's Ctrl-C on a quiet DB would hang.
func TestAuditTail_FollowLoopExitsCleanlyOnQuietDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := store.Open(dbPath)
	require.NoError(t, err)
	defer st.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	err = runAuditTailFollowLoop(ctx, &bytes.Buffer{}, st, nil, &auditTailOpts{}, 0, 20*time.Millisecond)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected clean exit, got %v", err)
	}
}

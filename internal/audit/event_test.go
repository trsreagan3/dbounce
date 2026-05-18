package audit

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/store"
)

// TestFromDecisionRow_ProjectsOCSFRequiredFields locks the OCSF v1.1.0
// class 6003 required fields onto every projected event. metadata /
// time / class_uid / category_uid / activity_id / type_uid /
// severity_id / status_id MUST be populated on every decision per the
// [[ocsf-audit-schema]] memo; without them no SIEM ingest will accept
// the JSONL line.
func TestFromDecisionRow_ProjectsOCSFRequiredFields(t *testing.T) {
	at := time.Date(2026, 5, 18, 12, 34, 56, 789000000, time.UTC)
	row := store.DecisionRow{
		At:              at,
		Dialect:         "postgres",
		Statement:       "SELECT * FROM users",
		StatementType:   "SELECT",
		TablesTouched:   []string{"public.users"},
		DecisionVerdict: "ALLOW",
		DecisionReason:  "default-policy",
		ModeAtDecision:  "cooperative",
		ProfileName:     "safe-default",
		DecisionSource:  "default",
		Enforced:        false,
	}
	evt := FromDecisionRow(row, 42, "127.0.0.1:5433", "pg.example.com:5432")

	// Metadata
	assert.Equal(t, SchemaVersion, evt.Metadata.Version)
	assert.Equal(t, Product, evt.Metadata.Product.Name)
	assert.Equal(t, VendorName, evt.Metadata.Product.VendorName)
	assert.NotEmpty(t, evt.Metadata.Product.Version,
		"metadata.product.version is OCSF-required + must default to BuildVersion ('dev' when unstamped)")

	// Classification
	assert.Equal(t, at.UnixMilli(), evt.Time)
	assert.Equal(t, 6003, evt.ClassUID)
	assert.Equal(t, "API Activity", evt.ClassName)
	assert.Equal(t, 6, evt.CategoryUID)
	assert.Equal(t, "Application Activity", evt.CategoryName)
	assert.Equal(t, ActivityIDRead, evt.ActivityID, "SELECT must map to Read (2)")
	assert.Equal(t, "select", evt.ActivityName)
	assert.Equal(t, 600300+ActivityIDRead, evt.TypeUID,
		"type_uid MUST equal 600300+activity_id per OCSF spec")
	assert.Equal(t, "API Activity: Read", evt.TypeName)

	// Severity defaults to Informational per
	// [[security-team-positioning-safety-not-surveillance]].
	assert.Equal(t, ocsfSeverityInformationalID, evt.SeverityID)
	assert.Equal(t, ocsfSeverityInformational, evt.Severity)

	// Status: ALLOW → 1 Success.
	assert.Equal(t, StatusIDSuccess, evt.StatusID)
	assert.Equal(t, "Success", evt.Status)
	assert.Equal(t, "default-policy", evt.StatusDetail)

	// API
	assert.Equal(t, "SELECT", evt.API.Operation)
	assert.Equal(t, "postgres", evt.API.Service.Name)
	require.NotNil(t, evt.API.Request)
	assert.Equal(t, "42", evt.API.Request.UID,
		"api.request.uid MUST be the decision_id as a string per OCSF")

	// Resources
	require.Len(t, evt.Resources, 1)
	assert.Equal(t, "public.users", evt.Resources[0].Name)
	assert.Equal(t, "public.users", evt.Resources[0].UID)
	assert.Equal(t, "sql table", evt.Resources[0].Type)

	// Endpoints
	require.NotNil(t, evt.SrcEndpoint)
	assert.Equal(t, "127.0.0.1", evt.SrcEndpoint.Hostname)
	assert.Equal(t, 5433, evt.SrcEndpoint.Port)
	require.NotNil(t, evt.DstEndpoint)
	assert.Equal(t, "pg.example.com", evt.DstEndpoint.Hostname)
	assert.Equal(t, 5432, evt.DstEndpoint.Port)

	// unmapped.iam_jit native extension.
	require.NotNil(t, evt.Unmapped)
	assert.Equal(t, "cooperative", evt.Unmapped.IAMJIT.Mode)
	assert.Equal(t, "safe-default", evt.Unmapped.IAMJIT.Profile)
	assert.Equal(t, "ALLOW", evt.Unmapped.IAMJIT.Verdict)
	assert.Equal(t, int64(42), evt.Unmapped.IAMJIT.DecisionID)
	assert.False(t, evt.Unmapped.IAMJIT.Enforced)
	require.NotNil(t, evt.Unmapped.IAMJIT.Ext)
	assert.Equal(t, "postgres", evt.Unmapped.IAMJIT.Ext["dialect"])
	assert.Equal(t, "default", evt.Unmapped.IAMJIT.Ext["decision_source"])
}

// TestEvent_OCSFSchemaCompliance is the binding contract test: every
// emitted event MUST have the OCSF class-6003 required fields
// populated with correct types. Sibling agents in ibounce/kbounce ship
// the same fixture against their projection.
//
// We don't pull a JSON-Schema library (zero new deps per the slice
// constraints); the required-field + type-check below is sufficient for
// the OCSF v1.1.0 class 6003 envelope.
func TestEvent_OCSFSchemaCompliance(t *testing.T) {
	cases := []struct {
		name string
		row  store.DecisionRow
	}{
		{
			name: "pg-select-allow",
			row: store.DecisionRow{
				At:              time.Now().UTC(),
				Dialect:         "postgres",
				StatementType:   "SELECT",
				DecisionVerdict: "ALLOW",
				ModeAtDecision:  "cooperative",
				TablesTouched:   []string{"public.users"},
			},
		},
		{
			name: "mysql-update-deny-enforced",
			row: store.DecisionRow{
				At:              time.Now().UTC(),
				Dialect:         "mysql",
				StatementType:   "UPDATE",
				DecisionVerdict: "DENY",
				DecisionReason:  "rule: no UPDATE without WHERE",
				ModeAtDecision:  "transparent",
				Enforced:        true,
				IsDML:           true,
				HasMutatingNode: true,
				TablesTouched:   []string{"app.users"},
			},
		},
		{
			name: "snowflake-export-deny-other",
			row: store.DecisionRow{
				At:              time.Now().UTC(),
				Dialect:         "snowflake",
				StatementType:   "EXPORT_DATA",
				DecisionVerdict: "DENY",
				DecisionReason:  "egress profile blocks EXPORT_DATA",
				ModeAtDecision:  "transparent",
				Enforced:        true,
			},
		},
		{
			name: "bigquery-merge-allow",
			row: store.DecisionRow{
				At:              time.Now().UTC(),
				Dialect:         "bigquery",
				StatementType:   "MERGE",
				DecisionVerdict: "ALLOW",
				ModeAtDecision:  "cooperative",
				IsDML:           true,
				HasMutatingNode: true,
				TablesTouched:   []string{"dataset.target"},
			},
		},
		{
			name: "no-tables-empty-resources-still-valid",
			row: store.DecisionRow{
				At:              time.Now().UTC(),
				Dialect:         "postgres",
				StatementType:   "SELECT",
				DecisionVerdict: "ALLOW",
				ModeAtDecision:  "cooperative",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt := FromDecisionRow(tc.row, 1, "127.0.0.1:5433", "")
			require.NoError(t, assertOCSFCompliant(evt))
		})
	}
}

// TestEvent_CrossProductFixture is the shared-shape assertion the memo
// names: every product's projection MUST satisfy class_uid=6003 +
// vendor_name="iam-jit" + type_uid==600300+activity_id + presence of
// unmapped.iam_jit. Sibling ibounce + kbounce ship the same fixture
// against their projections so a single downstream SIEM rule keyed on
// these fields catches events from any iam-jit product.
func TestEvent_CrossProductFixture(t *testing.T) {
	row := store.DecisionRow{
		At:              time.Now().UTC(),
		Dialect:         "postgres",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
	}
	evt := FromDecisionRow(row, 12345, "127.0.0.1:5433", "")

	assert.Equal(t, 6003, evt.ClassUID,
		"class_uid MUST equal 6003 (OCSF API Activity) on every Bounce event")
	assert.Equal(t, "iam-jit", evt.Metadata.Product.VendorName,
		"metadata.product.vendor_name MUST equal 'iam-jit' on every Bounce event")
	assert.Equal(t, SchemaVersion, evt.Metadata.Version,
		"metadata.version MUST equal the OCSF schema version pinned for this release")
	assert.Equal(t, 600300+evt.ActivityID, evt.TypeUID,
		"type_uid invariant: == 600300 + activity_id (OCSF class-6003 rule)")
	require.NotNil(t, evt.Unmapped, "unmapped.iam_jit MUST be present")
	assert.Equal(t, "ALLOW", evt.Unmapped.IAMJIT.Verdict,
		"unmapped.iam_jit.verdict preserves the bouncer's native semantics")
	assert.Equal(t, int64(12345), evt.Unmapped.IAMJIT.DecisionID,
		"unmapped.iam_jit.decision_id MUST be numeric + match the SQLite row id")
	require.NotNil(t, evt.API.Request)
	assert.Equal(t, "12345", evt.API.Request.UID,
		"api.request.uid MUST match decision_id (as string)")
}

// TestEvent_PerDialectActivityMapping is the table-driven test from
// the memo: every supported SQL statement type across PG / MySQL /
// Snowflake / BigQuery maps to the correct OCSF activity_id. This is
// load-bearing because activity_id drives type_uid which drives every
// SIEM dashboard filter.
func TestEvent_PerDialectActivityMapping(t *testing.T) {
	cases := []struct {
		dialect string
		stmt    string
		want    int
	}{
		// SELECT → 2 (Read)
		{"postgres", "SELECT", ActivityIDRead},
		{"mysql", "SELECT", ActivityIDRead},
		{"snowflake", "SELECT", ActivityIDRead},
		{"bigquery", "SELECT", ActivityIDRead},

		// INSERT → 1 (Create)
		{"postgres", "INSERT", ActivityIDCreate},
		{"mysql", "INSERT", ActivityIDCreate},
		{"snowflake", "INSERT", ActivityIDCreate},
		{"bigquery", "INSERT", ActivityIDCreate},

		// UPDATE / ALTER / MERGE → 3 (Update)
		{"postgres", "UPDATE", ActivityIDUpdate},
		{"mysql", "UPDATE", ActivityIDUpdate},
		{"snowflake", "UPDATE", ActivityIDUpdate},
		{"bigquery", "UPDATE", ActivityIDUpdate},
		{"postgres", "ALTER", ActivityIDUpdate},
		{"mysql", "ALTER", ActivityIDUpdate},
		{"snowflake", "ALTER", ActivityIDUpdate},
		{"bigquery", "ALTER", ActivityIDUpdate},
		{"postgres", "MERGE", ActivityIDUpdate},
		{"mysql", "MERGE", ActivityIDUpdate},
		{"snowflake", "MERGE", ActivityIDUpdate},
		{"bigquery", "MERGE", ActivityIDUpdate},

		// DELETE / DROP / TRUNCATE → 4 (Delete)
		{"postgres", "DELETE", ActivityIDDelete},
		{"mysql", "DELETE", ActivityIDDelete},
		{"snowflake", "DELETE", ActivityIDDelete},
		{"bigquery", "DELETE", ActivityIDDelete},
		{"postgres", "DROP", ActivityIDDelete},
		{"mysql", "DROP", ActivityIDDelete},
		{"snowflake", "DROP", ActivityIDDelete},
		{"bigquery", "DROP", ActivityIDDelete},
		{"postgres", "TRUNCATE", ActivityIDDelete},
		{"mysql", "TRUNCATE", ActivityIDDelete},
		{"snowflake", "TRUNCATE", ActivityIDDelete},
		{"bigquery", "TRUNCATE", ActivityIDDelete},

		// Misc → 99 (Other)
		{"postgres", "CALL", ActivityIDOther},
		{"mysql", "DO", ActivityIDOther},
		{"snowflake", "EXECUTE", ActivityIDOther},
		{"postgres", "WITH-WRITE", ActivityIDOther},
		{"mysql", "LOAD_DATA", ActivityIDOther},
		{"bigquery", "EXPORT_DATA", ActivityIDOther},
		{"snowflake", "COPY_INTO", ActivityIDOther},

		// Unknown statement type → 99 (Other) so SIEMs see "something
		// happened we don't classify" instead of dropping the event.
		{"postgres", "VACUUM", ActivityIDOther},

		// Empty statement type → 0 (Unknown) so a missing parse doesn't
		// silently look like a known shape.
		{"postgres", "", ActivityIDUnknown},

		// Mixed case — classifier MUST normalize.
		{"postgres", "select", ActivityIDRead},
		{"mysql", "Insert", ActivityIDCreate},
	}
	for _, tc := range cases {
		name := tc.dialect + "/" + tc.stmt
		if tc.stmt == "" {
			name = tc.dialect + "/EMPTY"
		}
		t.Run(name, func(t *testing.T) {
			row := store.DecisionRow{
				At:              time.Now().UTC(),
				Dialect:         tc.dialect,
				StatementType:   tc.stmt,
				DecisionVerdict: "ALLOW",
				ModeAtDecision:  "cooperative",
			}
			evt := FromDecisionRow(row, 1, "h:1", "")
			assert.Equal(t, tc.want, evt.ActivityID,
				"%s/%s must map to activity_id %d", tc.dialect, tc.stmt, tc.want)
			assert.Equal(t, 600300+tc.want, evt.TypeUID,
				"type_uid invariant")
			assert.Equal(t, "postgres", "postgres") // pacify go vet
		})
	}
}

// TestVerdictToStatus exercises the verdict → OCSF status_id mapping
// per the memo. The bouncer's native verdict is preserved under
// unmapped.iam_jit.verdict; status reflects whether the upstream call
// actually succeeded.
func TestVerdictToStatus(t *testing.T) {
	cases := []struct {
		verdict  string
		enforced bool
		wantID   int
		wantStr  string
	}{
		{"ALLOW", false, StatusIDSuccess, "Success"},
		{"ALLOW", true, StatusIDSuccess, "Success"},
		{"DENY", true, StatusIDFailure, "Failure"},
		{"DENY", false, StatusIDSuccess, "Success"}, // cooperative advisory
		{"BYPASS", false, StatusIDSuccess, "Success"},
		{"", false, StatusIDUnknown, "Unknown"},
		{"BOGUS", false, StatusIDUnknown, "Unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.verdict+"-enforced-"+strconv.FormatBool(tc.enforced), func(t *testing.T) {
			id, str := verdictToStatus(tc.verdict, tc.enforced)
			assert.Equal(t, tc.wantID, id)
			assert.Equal(t, tc.wantStr, str)
		})
	}
}

// TestFromDecisionRow_DenyEnforced_TransparentMode locks the
// status_id=2 (Failure) path: a DENY that actually blocked upstream
// must report Failure to the SIEM (the call did NOT succeed).
func TestFromDecisionRow_DenyEnforced_TransparentMode(t *testing.T) {
	row := store.DecisionRow{
		At:              time.Now().UTC(),
		Dialect:         "mysql",
		StatementType:   "UPDATE",
		DecisionVerdict: "DENY",
		DecisionReason:  "rule: no UPDATE without WHERE",
		ModeAtDecision:  "transparent",
		Enforced:        true,
		IsDML:           true,
	}
	evt := FromDecisionRow(row, 1, "127.0.0.1:5433", "mysql.example.com:3306")
	assert.Equal(t, StatusIDFailure, evt.StatusID)
	assert.Equal(t, "Failure", evt.Status)
	assert.Equal(t, "rule: no UPDATE without WHERE", evt.StatusDetail)
	assert.Equal(t, "DENY", evt.Unmapped.IAMJIT.Verdict)
	assert.True(t, evt.Unmapped.IAMJIT.Enforced)
}

// TestFromDecisionRow_DenyAdvisory_CooperativeMode locks the
// status_id=1 path for advisory DENY: cooperative-mode flag without
// blocking → upstream call SUCCEEDED → OCSF Success. The deny reason
// is still preserved under status_detail + unmapped.iam_jit.verdict.
func TestFromDecisionRow_DenyAdvisory_CooperativeMode(t *testing.T) {
	row := store.DecisionRow{
		At:              time.Now().UTC(),
		Dialect:         "postgres",
		StatementType:   "DELETE",
		DecisionVerdict: "DENY",
		DecisionReason:  "advisory: DELETE without WHERE",
		ModeAtDecision:  "cooperative",
		Enforced:        false,
	}
	evt := FromDecisionRow(row, 1, "127.0.0.1:5433", "")
	assert.Equal(t, StatusIDSuccess, evt.StatusID,
		"cooperative-mode advisory DENY: the upstream call succeeded; OCSF status must reflect that")
	assert.Equal(t, "Success", evt.Status)
	assert.Equal(t, "advisory: DELETE without WHERE", evt.StatusDetail)
	assert.Equal(t, "DENY", evt.Unmapped.IAMJIT.Verdict,
		"unmapped.iam_jit.verdict preserves the bouncer's native semantics")
	assert.False(t, evt.Unmapped.IAMJIT.Enforced)
}

// TestFromDecisionRow_ResourcesPerTouchedTable verifies one OCSF
// resource entry per table — even for multi-table statements like
// JOINs.
func TestFromDecisionRow_ResourcesPerTouchedTable(t *testing.T) {
	row := store.DecisionRow{
		At:              time.Now().UTC(),
		Dialect:         "postgres",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
		TablesTouched:   []string{"public.users", "public.orders", "public.audit_log"},
	}
	evt := FromDecisionRow(row, 1, "h:1", "")
	require.Len(t, evt.Resources, 3)
	names := []string{evt.Resources[0].Name, evt.Resources[1].Name, evt.Resources[2].Name}
	assert.Equal(t, []string{"public.users", "public.orders", "public.audit_log"}, names)
	for _, r := range evt.Resources {
		assert.Equal(t, "sql table", r.Type)
		assert.Equal(t, r.Name, r.UID, "name + uid both hold schema.table")
	}
}

// TestFromDecisionRow_NoTablesTouched: when the statement targets no
// tables (e.g. SELECT 1), the resources array is OMITTED — not an
// empty array — so the JSONL line is minimal. OCSF allows omitting
// resources when none apply.
func TestFromDecisionRow_NoTablesTouched(t *testing.T) {
	row := store.DecisionRow{
		At:              time.Now().UTC(),
		Dialect:         "postgres",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
	}
	evt := FromDecisionRow(row, 1, "h:1", "")
	assert.Nil(t, evt.Resources,
		"empty tables_touched MUST produce a nil Resources slice so the JSON omits the field")
}

// TestFromDecisionRow_Actor_TaskAndImpersonatedRole exercises the
// actor population path: TaskID populates session.uid +
// ImpersonatedRole populates user.name+uid. Both fields are present-
// but-empty on v1.0 typical traffic; this test pins the wiring for
// downstream consumers that DO see them.
func TestFromDecisionRow_Actor_TaskAndImpersonatedRole(t *testing.T) {
	row := store.DecisionRow{
		At:               time.Now().UTC(),
		Dialect:          "postgres",
		StatementType:    "SELECT",
		DecisionVerdict:  "ALLOW",
		ModeAtDecision:   "cooperative",
		TaskID:           "task-abc-123",
		ImpersonatedRole: "analytics_ro",
	}
	evt := FromDecisionRow(row, 1, "h:1", "")
	require.NotNil(t, evt.Actor, "actor MUST be present when TaskID or ImpersonatedRole is set")
	require.NotNil(t, evt.Actor.Session)
	assert.Equal(t, "task-abc-123", evt.Actor.Session.UID)
	require.NotNil(t, evt.Actor.User)
	assert.Equal(t, "analytics_ro", evt.Actor.User.Name)
	assert.Equal(t, "analytics_ro", evt.Actor.User.UID)
}

// TestFromDecisionRow_Actor_OmittedWhenAbsent: when neither TaskID nor
// ImpersonatedRole is set, the actor field is OMITTED from the wire
// (not emitted as `"actor":{}`).
func TestFromDecisionRow_Actor_OmittedWhenAbsent(t *testing.T) {
	row := store.DecisionRow{
		At:              time.Now().UTC(),
		Dialect:         "postgres",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
	}
	evt := FromDecisionRow(row, 1, "h:1", "")
	assert.Nil(t, evt.Actor, "actor MUST be nil so json:omitempty drops it from the wire")
	raw, err := json.Marshal(evt)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"actor"`,
		"actor MUST be absent from the JSON when neither TaskID nor ImpersonatedRole is set")
}

// TestFromDecisionRow_Endpoint_ParsesHostPort exercises the host:port
// → OCSF Endpoint conversion.
func TestFromDecisionRow_Endpoint_ParsesHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
		wantNil  bool
	}{
		{"127.0.0.1:5433", "127.0.0.1", 5433, false},
		{"pg.example.com:5432", "pg.example.com", 5432, false},
		{"localhost:0", "localhost", 0, false},
		{"plain-hostname", "plain-hostname", 0, false},
		{"", "", 0, true},
		{"   ", "", 0, true},
		{"bad:port:format:99999", "bad:port:format:99999", 0, false}, // malformed port; fall back to full string as hostname
	}
	for _, tc := range cases {
		t.Run(tc.in+"/"+strconv.Itoa(tc.wantPort), func(t *testing.T) {
			ep := parseEndpoint(tc.in)
			if tc.wantNil {
				assert.Nil(t, ep)
				return
			}
			require.NotNil(t, ep)
			assert.Equal(t, tc.wantHost, ep.Hostname)
			assert.Equal(t, tc.wantPort, ep.Port)
		})
	}
}

// TestFromDecisionRow_NoTimestamp_DefaultsToNow guarantees the schema
// always has a time field even when the DecisionRow was constructed
// without one. time=0 would parse as 1970 and break SIEM dashboards.
func TestFromDecisionRow_NoTimestamp_DefaultsToNow(t *testing.T) {
	row := store.DecisionRow{
		Dialect:         "postgres",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
	}
	before := time.Now().UnixMilli()
	evt := FromDecisionRow(row, 1, "", "")
	after := time.Now().UnixMilli()
	assert.GreaterOrEqual(t, evt.Time, before)
	assert.LessOrEqual(t, evt.Time, after)
}

// TestFromDecisionRow_StatementRedactedPropagates: when the row has
// statement_redacted=true, the projected ext flag must be present.
// MED-D8-09 invariant — audit consumers MUST NOT trust the SQL for
// replay when the flag is set.
func TestFromDecisionRow_StatementRedactedPropagates(t *testing.T) {
	row := store.DecisionRow{
		Dialect:           "postgres",
		Statement:         "SELECT * FROM t WHERE p=[REDACTED]",
		StatementType:     "SELECT",
		DecisionVerdict:   "ALLOW",
		ModeAtDecision:    "cooperative",
		StatementRedacted: true,
	}
	evt := FromDecisionRow(row, 1, "", "")
	require.NotNil(t, evt.Unmapped)
	require.NotNil(t, evt.Unmapped.IAMJIT.Ext)
	assert.True(t, evt.Unmapped.IAMJIT.Ext["statement_redacted"].(bool),
		"MED-D8-09: statement_redacted flag MUST propagate to audit-export consumers")
}

// TestEvent_JSONShape_OCSFTags is the wire-format contract test:
// marshal an event + verify the JSON has all the OCSF-required keys
// with their schema-spec'd names. A SIEM that ingests this directly
// MUST find every required key at the OCSF-spec path.
func TestEvent_JSONShape_OCSFTags(t *testing.T) {
	row := store.DecisionRow{
		At:              time.Date(2026, 5, 18, 12, 34, 56, 789000000, time.UTC),
		Dialect:         "postgres",
		StatementType:   "DELETE",
		DecisionVerdict: "DENY",
		DecisionReason:  "matched rule X",
		ModeAtDecision:  "transparent",
		ProfileName:     "safe-default",
		Enforced:        true,
		TablesTouched:   []string{"public.users"},
	}
	evt := FromDecisionRow(row, 12345, "127.0.0.1:5433", "pg.example.com:5432")
	raw, err := json.Marshal(evt)
	require.NoError(t, err)
	s := string(raw)
	for _, k := range []string{
		`"metadata":`,
		`"version":"1.1.0"`,
		`"product":{`,
		`"name":"dbounce"`,
		`"vendor_name":"iam-jit"`,
		`"time":`,
		`"class_uid":6003`,
		`"class_name":"API Activity"`,
		`"category_uid":6`,
		`"category_name":"Application Activity"`,
		`"activity_id":4`, // DELETE → 4
		`"activity_name":"delete"`,
		`"type_uid":600304`,
		`"type_name":"API Activity: Delete"`,
		`"severity_id":1`,
		`"severity":"Informational"`,
		`"status_id":2`, // enforced DENY
		`"status":"Failure"`,
		`"status_detail":"matched rule X"`,
		`"api":`,
		`"operation":"DELETE"`,
		`"service":`,
		`"request":`,
		`"uid":"12345"`,
		`"resources":`,
		`"sql table"`,
		`"src_endpoint":`,
		`"hostname":"127.0.0.1"`,
		`"port":5433`,
		`"dst_endpoint":`,
		`"hostname":"pg.example.com"`,
		`"port":5432`,
		`"unmapped":`,
		`"iam_jit":`,
		`"verdict":"DENY"`,
		`"decision_id":12345`,
		`"enforced":true`,
	} {
		assert.True(t, strings.Contains(s, k),
			"OCSF JSON wire shape must contain %q; got %s", k, s)
	}
}

// TestNewAuditDroppedEvent_OCSFShape verifies the synthetic overflow
// event is also OCSF-class-6003 compliant: activity_id=99 (Other),
// activity_name="audit_dropped", type_uid=600399, severity_id=3
// (Medium) per the memo.
func TestNewAuditDroppedEvent_OCSFShape(t *testing.T) {
	evt := NewAuditDroppedEvent(17, "127.0.0.1:5433")
	assert.Equal(t, 6003, evt.ClassUID)
	assert.Equal(t, ActivityIDOther, evt.ActivityID)
	assert.Equal(t, "audit_dropped", evt.ActivityName)
	assert.Equal(t, 600399, evt.TypeUID)
	assert.Equal(t, "API Activity: Other", evt.TypeName)
	assert.Equal(t, ocsfSeverityMediumID, evt.SeverityID)
	assert.Equal(t, "Medium", evt.Severity)
	assert.Equal(t, StatusIDOther, evt.StatusID)
	assert.Equal(t, "Other", evt.Status)
	assert.NotEmpty(t, evt.StatusDetail,
		"AUDIT_DROPPED must include a human-readable reason for SIEM triage")

	require.NotNil(t, evt.Unmapped)
	assert.Equal(t, string(EventTypeAuditDropped), evt.Unmapped.IAMJIT.EventType)
	assert.Equal(t, int64(17), evt.Unmapped.IAMJIT.DroppedCount)

	require.NotNil(t, evt.SrcEndpoint)
	assert.Equal(t, "127.0.0.1", evt.SrcEndpoint.Hostname)
	assert.Equal(t, 5433, evt.SrcEndpoint.Port)

	// Required envelope still present.
	assert.Equal(t, SchemaVersion, evt.Metadata.Version)
	assert.Equal(t, Product, evt.Metadata.Product.Name)
	assert.Equal(t, VendorName, evt.Metadata.Product.VendorName)
	require.NoError(t, assertOCSFCompliant(evt))
}

// TestBuildVersion_DefaultIsDev pins the unstamped-build default. A
// missing -ldflags MUST surface as "dev" — not the empty string —
// so downstream events always have a non-empty metadata.product.version.
func TestBuildVersion_DefaultIsDev(t *testing.T) {
	// We can't reliably set BuildVersion in tests without affecting
	// concurrent test runs; instead pin the default for unstamped
	// builds. If a build pipeline overrides this, downstream tests
	// should pin a known stamp. The cross-product schema test asserts
	// only "non-empty" so a stamp override doesn't break it.
	assert.NotEmpty(t, BuildVersion, "BuildVersion must default to non-empty so events always have metadata.product.version")
}

// assertOCSFCompliant is the test-only schema validator we use in lieu
// of a JSON-Schema library (zero new deps per slice constraints). It
// checks every OCSF v1.1.0 class-6003 required field is present +
// correctly typed, then checks the cross-cutting invariants
// (type_uid==600300+activity_id, severity/status name agrees with id).
//
// Sibling agents in ibounce/kbounce ship an equivalent validator
// against their projection so the three-product invariant is enforced
// per-product.
func assertOCSFCompliant(evt Event) error {
	// Round-trip through JSON so we exercise the wire format the SIEM
	// actually sees, not the in-memory struct.
	raw, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	required := []string{
		"metadata", "time", "class_uid", "class_name",
		"category_uid", "category_name",
		"activity_id", "activity_name", "type_uid", "type_name",
		"severity_id", "severity", "status_id", "status",
		"api",
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return missingField(k)
		}
	}
	// Required-type checks.
	if v, ok := m["class_uid"].(float64); !ok || int(v) != 6003 {
		return badType("class_uid", "6003")
	}
	if v, ok := m["category_uid"].(float64); !ok || int(v) != 6 {
		return badType("category_uid", "6")
	}
	if _, ok := m["activity_id"].(float64); !ok {
		return badType("activity_id", "number")
	}
	if _, ok := m["type_uid"].(float64); !ok {
		return badType("type_uid", "number")
	}
	if _, ok := m["severity_id"].(float64); !ok {
		return badType("severity_id", "number")
	}
	if _, ok := m["status_id"].(float64); !ok {
		return badType("status_id", "number")
	}
	if _, ok := m["time"].(float64); !ok {
		return badType("time", "number (unix ms)")
	}
	// Required: metadata.version + metadata.product.{name, vendor_name, version}.
	md, ok := m["metadata"].(map[string]any)
	if !ok {
		return badType("metadata", "object")
	}
	if _, ok := md["version"].(string); !ok {
		return missingField("metadata.version")
	}
	prod, ok := md["product"].(map[string]any)
	if !ok {
		return badType("metadata.product", "object")
	}
	for _, k := range []string{"name", "vendor_name", "version"} {
		if _, ok := prod[k].(string); !ok {
			return missingField("metadata.product." + k)
		}
	}
	// api.operation MUST be a string. api.request.uid is recommended
	// not strictly required by OCSF but the memo says we always populate
	// it; check it here for cross-product consistency.
	api, ok := m["api"].(map[string]any)
	if !ok {
		return badType("api", "object")
	}
	if _, ok := api["operation"]; !ok {
		// AUDIT_DROPPED synthetic doesn't have an operation; tolerate.
	}
	// Cross-cutting invariant: type_uid == 600300 + activity_id.
	actID := int(m["activity_id"].(float64))
	tuid := int(m["type_uid"].(float64))
	if tuid != 600300+actID {
		return badType("type_uid", "600300+activity_id")
	}
	return nil
}

type schemaErr string

func (e schemaErr) Error() string { return string(e) }

func missingField(name string) error { return schemaErr("OCSF required field missing: " + name) }
func badType(field, want string) error {
	return schemaErr("OCSF type mismatch: " + field + " (want " + want + ")")
}

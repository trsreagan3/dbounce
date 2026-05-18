package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/store"
)

// TestFromDecisionRow_ProjectsCanonicalFields locks the cross-product
// schema's required fields onto every event. ts / product / version /
// decision_id / mode / verdict / enforced MUST be present on every
// projected event so sibling kbounce/ibounce consumers can rely on
// uniform shape.
func TestFromDecisionRow_ProjectsCanonicalFields(t *testing.T) {
	at := time.Date(2026, 5, 18, 12, 34, 56, 789000000, time.UTC)
	row := store.DecisionRow{
		At:               at,
		Dialect:          "postgres",
		Statement:        "SELECT * FROM users",
		StatementType:    "SELECT",
		TablesTouched:    []string{"public.users"},
		DecisionVerdict:  "allow",
		DecisionReason:   "default-policy",
		ModeAtDecision:   "cooperative",
		ProfileName:      "safe-default",
		DecisionSource:   "default",
		IsDML:            false,
		IsDDL:            false,
		Enforced:         false,
	}
	evt := FromDecisionRow(row, 42, "127.0.0.1:5433", "pg.example.com:5432")

	assert.Equal(t, EventTypeDecision, evt.EventType)
	assert.Equal(t, "2026-05-18T12:34:56.789Z", evt.Ts)
	assert.Equal(t, Product, evt.Product)
	assert.Equal(t, SchemaVersion, evt.Version)
	assert.Equal(t, int64(42), evt.DecisionID)
	assert.Equal(t, "cooperative", evt.Mode)
	assert.Equal(t, "safe-default", evt.Profile)
	assert.Equal(t, "allow", evt.Verdict)
	assert.Equal(t, "default-policy", evt.Reason)
	assert.Equal(t, "SELECT", evt.Action)
	assert.Equal(t, "public.users", evt.Resource)
	assert.False(t, evt.Enforced)
	assert.Equal(t, "127.0.0.1:5433", evt.Host)
	assert.Equal(t, "pg.example.com:5432", evt.Upstream)
	require.NotNil(t, evt.Ext)
	assert.Equal(t, "postgres", evt.Ext["dialect"])
	assert.Equal(t, "default", evt.Ext["decision_source"])
}

// TestFromDecisionRow_DialectExtFields_Postgres exercises the postgres
// dialect's ext fields.
func TestFromDecisionRow_DialectExtFields_Postgres(t *testing.T) {
	row := store.DecisionRow{
		Dialect:          "postgres",
		Statement:        "UPDATE users SET email='x'",
		StatementType:    "UPDATE",
		TablesTouched:    []string{"public.users"},
		FunctionsCalled:  []string{"now"},
		IsDML:            true,
		HasMutatingNode:  true,
		MutatingNodeType: "UpdateStmt",
		DecisionVerdict:  "deny",
		ModeAtDecision:   "transparent",
		Enforced:         true,
	}
	evt := FromDecisionRow(row, 1, "h", "u")
	assert.Equal(t, "postgres", evt.Ext["dialect"])
	assert.True(t, evt.Ext["is_dml"].(bool))
	assert.True(t, evt.Ext["has_mutating_node"].(bool))
	assert.Equal(t, "UpdateStmt", evt.Ext["mutating_node_type"])
	require.IsType(t, []string{}, evt.Ext["functions"])
}

// TestFromDecisionRow_DialectExtFields_MySQL covers MySQL.
func TestFromDecisionRow_DialectExtFields_MySQL(t *testing.T) {
	row := store.DecisionRow{
		Dialect:         "mysql",
		StatementType:   "INSERT",
		Statement:       "INSERT INTO t VALUES (1)",
		IsDML:           true,
		HasMutatingNode: true,
		ModeAtDecision:  "cooperative",
	}
	evt := FromDecisionRow(row, 2, "h", "u")
	assert.Equal(t, "mysql", evt.Ext["dialect"])
	assert.True(t, evt.Ext["is_dml"].(bool))
}

// TestFromDecisionRow_DialectExtFields_Snowflake covers the JDBC-shim
// Snowflake dialect.
func TestFromDecisionRow_DialectExtFields_Snowflake(t *testing.T) {
	row := store.DecisionRow{
		Dialect:         "snowflake",
		StatementType:   "SELECT",
		Statement:       "SELECT 1",
		IsDML:           false,
		ModeAtDecision:  "cooperative",
	}
	evt := FromDecisionRow(row, 3, "h", "")
	assert.Equal(t, "snowflake", evt.Ext["dialect"])
}

// TestFromDecisionRow_DialectExtFields_BigQuery covers the JDBC-shim
// BigQuery dialect.
func TestFromDecisionRow_DialectExtFields_BigQuery(t *testing.T) {
	row := store.DecisionRow{
		Dialect:         "bigquery",
		StatementType:   "MERGE",
		Statement:       "MERGE INTO t USING s ON ...",
		IsDML:           true,
		HasMutatingNode: true,
		ModeAtDecision:  "cooperative",
	}
	evt := FromDecisionRow(row, 4, "h", "")
	assert.Equal(t, "bigquery", evt.Ext["dialect"])
	assert.True(t, evt.Ext["is_dml"].(bool))
	assert.True(t, evt.Ext["has_mutating_node"].(bool))
}

// TestFromDecisionRow_NoTimestamp_DefaultsToNow guarantees the schema
// always has a ts field even when the DecisionRow was constructed
// without one.
func TestFromDecisionRow_NoTimestamp_DefaultsToNow(t *testing.T) {
	row := store.DecisionRow{
		Dialect:         "postgres",
		StatementType:   "SELECT",
		DecisionVerdict: "allow",
	}
	evt := FromDecisionRow(row, 1, "", "")
	assert.NotEmpty(t, evt.Ts, "schema requires ts even on zero-At rows")
	// Parseable as RFC3339Nano.
	_, err := time.Parse(time.RFC3339Nano, evt.Ts)
	assert.NoError(t, err)
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
		ModeAtDecision:    "cooperative",
		StatementRedacted: true,
	}
	evt := FromDecisionRow(row, 1, "", "")
	assert.True(t, evt.Ext["statement_redacted"].(bool),
		"MED-D8-09: statement_redacted flag MUST propagate to audit-export consumers")
}

// TestEvent_JSONShape_MatchesSpec encodes a fully-populated event and
// checks the JSON has all the cross-product fields with the right tags.
// This is the contract test sibling agents in ibounce/kbounce must
// match.
func TestEvent_JSONShape_MatchesSpec(t *testing.T) {
	evt := Event{
		EventType:    EventTypeDecision,
		Ts:           "2026-05-18T12:34:56.789Z",
		Product:      Product,
		Version:      SchemaVersion,
		DecisionID:   12345,
		Mode:         "transparent",
		Profile:      "safe-default",
		Verdict:      "deny",
		Reason:       "matched rule X",
		Principal:    "alice@example.com",
		Action:       "DELETE",
		Resource:     "public.users",
		Enforced:     true,
		Host:         "127.0.0.1:5433",
		Upstream:     "pg.example.com:5432",
		Ext:          map[string]any{"dialect": "postgres"},
	}
	raw, err := json.Marshal(evt)
	require.NoError(t, err)
	s := string(raw)
	// Required top-level keys from the spec doc.
	for _, k := range []string{
		`"event_type":"DECISION"`,
		`"ts":"2026-05-18T12:34:56.789Z"`,
		`"product":"dbounce"`,
		`"version":"1.0.0"`,
		`"decision_id":12345`,
		`"mode":"transparent"`,
		`"profile":"safe-default"`,
		`"verdict":"deny"`,
		`"reason":"matched rule X"`,
		`"principal":"alice@example.com"`,
		`"action":"DELETE"`,
		`"resource":"public.users"`,
		`"enforced":true`,
		`"host":"127.0.0.1:5433"`,
		`"upstream":"pg.example.com:5432"`,
		`"ext":{"dialect":"postgres"}`,
	} {
		assert.True(t, strings.Contains(s, k),
			"JSONL schema must contain %q; got %s", k, s)
	}
}

// TestNewAuditDroppedEvent_CarriesCount verifies the synthetic
// overflow event has the right shape so consumers can branch on
// EventType and read the dropped_count delta.
func TestNewAuditDroppedEvent_CarriesCount(t *testing.T) {
	evt := NewAuditDroppedEvent(17, "127.0.0.1:5433")
	assert.Equal(t, EventTypeAuditDropped, evt.EventType)
	assert.Equal(t, int64(17), evt.DroppedCount)
	assert.Equal(t, Product, evt.Product)
	assert.Equal(t, SchemaVersion, evt.Version)
	assert.Equal(t, "127.0.0.1:5433", evt.Host)
	assert.NotEmpty(t, evt.Reason, "AUDIT_DROPPED must include a human-readable reason")
}

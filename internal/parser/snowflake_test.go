package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Snowflake parser tests cover the same audit-row-relevant fields the
// PG / MySQL tests do (StatementType, TablesTouched, FunctionsCalled,
// HasMutatingNode, MutatingNodeType) so the cross-product audit-log
// scraper has consistent shape across all rows.
//
// Per [[scorer-is-ground-truth]]: the Snowflake parser is best-effort
// (no canonical Go grammar; xwb1989 + keyword pre-checks). Tests focus
// on the LOAD-BEARING dialect-shape signals the rule pack needs.
//
// Coverage:
//
//   - SELECT / INSERT / UPDATE / DELETE / CREATE TABLE / DROP TABLE
//     (delegated to xwb1989 — same shape as MySQL parser)
//   - COPY INTO <table> FROM @stage (ingest)
//   - COPY INTO @stage FROM <table> (export — exfil shape)
//   - PUT / GET (local-file transfer)
//   - UNDROP (time-travel restore)
//   - USE SECONDARY ROLES (privilege escalation)
//   - SET TAG / UNSET TAG (metadata mutation)
//   - GRANT / REVOKE
//   - CREATE/ALTER/DROP WAREHOUSE (billing-affecting)
//   - Malformed / empty SQL — never panics

func sfParse(raw string) *ParsedStatement {
	return Parse(DialectSnowflake, raw)
}

func TestSnowflake_SimpleSelect(t *testing.T) {
	ps := sfParse("SELECT id FROM users")
	require.NotNil(t, ps)
	assert.Equal(t, DialectSnowflake, ps.Dialect)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Equal(t, []string{"users"}, ps.TablesTouched)
	assert.False(t, ps.HasMutatingNode)
}

func TestSnowflake_InsertUpdateDelete(t *testing.T) {
	cases := []struct {
		sql      string
		stmtType string
		mut      string
	}{
		{`INSERT INTO orders (id) VALUES (1)`, StmtInsert, "INSERT"},
		{`UPDATE orders SET status = 'paid' WHERE id = 1`, StmtUpdate, "UPDATE"},
		{`DELETE FROM orders WHERE id = 1`, StmtDelete, "DELETE"},
	}
	for _, c := range cases {
		t.Run(c.stmtType, func(t *testing.T) {
			ps := sfParse(c.sql)
			assert.Equal(t, c.stmtType, ps.StatementType)
			assert.True(t, ps.IsDML)
			assert.True(t, ps.HasMutatingNode)
			assert.Equal(t, c.mut, ps.MutatingNodeType)
			assert.Equal(t, []string{"orders"}, ps.TablesTouched)
		})
	}
}

func TestSnowflake_CreateDropTable(t *testing.T) {
	ps := sfParse(`CREATE TABLE accounts (id INT)`)
	assert.Equal(t, StmtDDL, ps.StatementType)
	assert.True(t, ps.IsDDL)

	ps2 := sfParse(`DROP TABLE accounts`)
	assert.Equal(t, StmtDDL, ps2.StatementType)
	assert.True(t, ps2.IsDDL)
}

// COPY INTO — Snowflake's bulk-load shape (ingest direction).
func TestSnowflake_CopyIntoTable_Ingest(t *testing.T) {
	ps := sfParse(`COPY INTO sales.raw_events FROM @my_stage/2026/05/`)
	assert.Equal(t, StmtCopy, ps.StatementType,
		"COPY INTO <table> classifies as StmtCopy")
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, snowflakeMutatingCopyIntoTable, ps.MutatingNodeType,
		"MutatingNodeType MUST distinguish ingest from export")
	assert.Contains(t, ps.TablesTouched, "sales.raw_events")
}

// COPY INTO @stage — the EXPORT direction (exfil shape the rule pack
// flags hardest).
func TestSnowflake_CopyIntoStage_Export(t *testing.T) {
	ps := sfParse(`COPY INTO @exfil_stage FROM sales.customer_data`)
	assert.Equal(t, StmtCopy, ps.StatementType)
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, snowflakeMutatingCopyIntoStage, ps.MutatingNodeType,
		"COPY INTO @stage MUST flag as COPY-INTO-STAGE for exfil-rule precision")
	assert.Contains(t, ps.TablesTouched, "sales.customer_data")
}

// PUT — local file → Snowflake stage. The shim should never let this
// through unmediated.
func TestSnowflake_Put(t *testing.T) {
	ps := sfParse(`PUT file:///tmp/data.csv @my_stage`)
	assert.Equal(t, StmtCopy, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, snowflakeMutatingPut, ps.MutatingNodeType)
}

// GET — Snowflake stage → local file (exfil to a developer's laptop).
func TestSnowflake_Get(t *testing.T) {
	ps := sfParse(`GET @my_stage file:///tmp/`)
	assert.Equal(t, StmtCopy, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, snowflakeMutatingGet, ps.MutatingNodeType)
}

// UNDROP — time-travel restore. Mutating.
func TestSnowflake_Undrop(t *testing.T) {
	ps := sfParse(`UNDROP TABLE sales.customer_data`)
	assert.Equal(t, StmtDDL, ps.StatementType)
	assert.True(t, ps.IsDDL)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, snowflakeMutatingUndrop, ps.MutatingNodeType)
}

// USE SECONDARY ROLES — privilege escalation shape the rule pack must
// be able to gate explicitly.
func TestSnowflake_UseSecondaryRoles(t *testing.T) {
	ps := sfParse(`USE SECONDARY ROLES ALL`)
	assert.Equal(t, StmtUse, ps.StatementType)
	assert.True(t, ps.HasMutatingNode,
		"USE SECONDARY ROLES is an escalation; MUST flag mutating for audit")
	assert.Equal(t, snowflakeMutatingUseSecondary, ps.MutatingNodeType)
}

// SET TAG — Snowflake metadata mutation.
func TestSnowflake_SetTag(t *testing.T) {
	ps := sfParse(`SET TAG cost_center = 'analytics'`)
	assert.Equal(t, StmtSet, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, snowflakeMutatingSetTag, ps.MutatingNodeType)
}

// GRANT — privilege management.
func TestSnowflake_Grant(t *testing.T) {
	ps := sfParse(`GRANT SELECT ON TABLE sales.customer_data TO ROLE analyst`)
	assert.Equal(t, StmtDDL, ps.StatementType)
	assert.True(t, ps.IsDDL)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, snowflakeMutatingGrant, ps.MutatingNodeType)
}

// REVOKE — privilege revocation.
func TestSnowflake_Revoke(t *testing.T) {
	ps := sfParse(`REVOKE SELECT ON TABLE sales.customer_data FROM ROLE analyst`)
	assert.Equal(t, StmtDDL, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, snowflakeMutatingRevoke, ps.MutatingNodeType)
}

// CREATE WAREHOUSE — billing-affecting verb. Snowflake charges by
// warehouse uptime, so a rogue CREATE WAREHOUSE has dollar blast
// radius even before any query runs.
func TestSnowflake_CreateWarehouse(t *testing.T) {
	ps := sfParse(`CREATE WAREHOUSE expensive_wh WITH WAREHOUSE_SIZE = 'XLARGE'`)
	assert.Equal(t, StmtDDL, ps.StatementType)
	assert.True(t, ps.IsDDL)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, snowflakeMutatingWarehouseMut, ps.MutatingNodeType)
}

func TestSnowflake_AlterWarehouse(t *testing.T) {
	ps := sfParse(`ALTER WAREHOUSE my_wh SET WAREHOUSE_SIZE = 'XXLARGE'`)
	assert.Equal(t, StmtDDL, ps.StatementType)
	assert.Equal(t, snowflakeMutatingWarehouseMut, ps.MutatingNodeType)
}

// Empty / garbage SQL — never panics.

func TestSnowflake_Empty(t *testing.T) {
	ps := sfParse("")
	require.NotNil(t, ps)
	assert.Equal(t, StmtUnknown, ps.StatementType)
}

func TestSnowflake_Garbage(t *testing.T) {
	ps := sfParse("zxcvbnm asdfghjkl !@#")
	assert.Equal(t, StmtUnparseable, ps.StatementType)
	assert.NotEmpty(t, ps.ParseErrors)
}

// Cross-parser: PUT survives even when xwb1989 doesn't know it (the
// keyword pre-check MUST fire BEFORE the AST parser).
func TestSnowflake_PutSurvivesEvenWhenXWBDoesNot(t *testing.T) {
	ps := sfParse(`PUT file:///x @s`)
	assert.NotEqual(t, StmtUnparseable, ps.StatementType,
		"PUT pre-check MUST run BEFORE xwb1989 (which doesn't know PUT)")
}

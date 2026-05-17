package packs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMySQL_Embedded asserts the MySQL pack is embedded + has the
// load-bearing shape D-Slice 7's loader will key off (metadata block +
// rules block). The full YAML schema check lands with the loader.
func TestMySQL_Embedded(t *testing.T) {
	require.NotEmpty(t, MySQL, "mysql.yaml MUST be embedded for D-Slice 7's loader")
	s := string(MySQL)
	assert.Contains(t, s, "dialect: mysql")
	assert.Contains(t, s, "calibration_status: provisional",
		"MySQL pack ships provisional per [[bounce-default-profile-pattern]]")
	assert.Contains(t, s, "LOAD:*",
		"MySQL pack MUST gate LOAD DATA INFILE — the canonical MySQL exfil verb")
	assert.Contains(t, s, "SET:*",
		"MySQL pack MUST gate SET GLOBAL — the canonical MySQL admin verb")
	// Sanity: no /Users/ paths or company names leaked in.
	assert.False(t, strings.Contains(strings.ToLower(s), "reagan"))
	assert.False(t, strings.Contains(strings.ToLower(s), "omise"))
}

// TestSnowflake_Embedded asserts the D-Slice 6 Snowflake pack is
// embedded + carries the load-bearing experimental calibration mark +
// the Snowflake-specific exfil + admin verb gates.
func TestSnowflake_Embedded(t *testing.T) {
	require.NotEmpty(t, Snowflake, "snowflake.yaml MUST be embedded")
	s := string(Snowflake)
	assert.Contains(t, s, "dialect: snowflake")
	assert.Contains(t, s, "calibration_status: experimental",
		"Snowflake pack MUST ship experimental per [[scorer-is-ground-truth]] — "+
			"don't pretend Snowflake has PG-level calibration")
	assert.Contains(t, s, "COPY:*",
		"Snowflake pack MUST gate COPY INTO @stage / PUT / GET — the canonical exfil shapes")
	assert.Contains(t, s, "UNDROP:*",
		"Snowflake pack MUST gate UNDROP — the time-travel restore shape")
	assert.Contains(t, s, "access_history",
		"Snowflake pack MUST protect ACCESS_HISTORY enumeration")
	assert.False(t, strings.Contains(strings.ToLower(s), "reagan"))
	assert.False(t, strings.Contains(strings.ToLower(s), "omise"))
}

// TestBigQuery_Embedded asserts the D-Slice 6 BigQuery pack is
// embedded + carries the experimental mark + the BigQuery-specific
// exfil + enumeration gates.
func TestBigQuery_Embedded(t *testing.T) {
	require.NotEmpty(t, BigQuery, "bigquery.yaml MUST be embedded")
	s := string(BigQuery)
	assert.Contains(t, s, "dialect: bigquery")
	assert.Contains(t, s, "calibration_status: experimental",
		"BigQuery pack MUST ship experimental per [[scorer-is-ground-truth]]")
	assert.Contains(t, s, "COPY:*",
		"BigQuery pack MUST gate EXPORT DATA — the canonical exfil verb")
	assert.Contains(t, s, "LOAD:*",
		"BigQuery pack MUST gate LOAD DATA — the bulk ingest verb")
	assert.Contains(t, s, "__tables__",
		"BigQuery pack MUST gate __TABLES__ enumeration when not in dev")
	assert.False(t, strings.Contains(strings.ToLower(s), "reagan"))
	assert.False(t, strings.Contains(strings.ToLower(s), "omise"))
}

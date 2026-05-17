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

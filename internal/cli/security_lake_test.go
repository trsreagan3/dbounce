package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecurityLakeBucketRequiresRegion pins the parse-time validation:
// passing --security-lake-bucket without --security-lake-region is a
// misconfiguration and must fail-fast with a clear error.
func TestSecurityLakeBucketRequiresRegion(t *testing.T) {
	_, err := buildAuditExporter(
		"", false, -1, -1, -1, "", "", 0, false, "", "", "",
		"", // alertRoutesPath
		0, 0, 0,
		"127.0.0.1:5433", "", "",
		"my-bucket", "", "", 0,
		"", "", "", "", "", 0, 0, "",
		false,
		0,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--security-lake-region")
}

// TestSecurityLakeRegionRequiresBucket pins the symmetric validation.
func TestSecurityLakeRegionRequiresBucket(t *testing.T) {
	_, err := buildAuditExporter(
		"", false, -1, -1, -1, "", "", 0, false, "", "", "",
		"", // alertRoutesPath
		0, 0, 0,
		"127.0.0.1:5433", "", "",
		"", "us-east-1", "", 0,
		"", "", "", "", "", 0, 0, "",
		false,
		0,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--security-lake-bucket")
}

// TestRunCmdRegistersSecurityLakeFlags confirms the four
// --security-lake-* flags are registered on `dbounce run`. Cross-
// product parity (ibounce + kbounce) ships the same names.
func TestRunCmdRegistersSecurityLakeFlags(t *testing.T) {
	cmd := newRunCmd()
	flags := cmd.Flags()
	for _, name := range []string{
		"security-lake-bucket",
		"security-lake-region",
		"security-lake-role-arn",
		"security-lake-rotation-seconds",
	} {
		require.NotNil(t, flags.Lookup(name),
			"--%s flag must be registered", name)
	}
}

// TestRunCmdRegistersRotationFlags pins F-311-4 closure: the
// cross-product audit-log rotation trio MUST be registered on
// `dbounce run`. Names + env-var-override-name shape match
// LOG-RETENTION.md per [[cross-product-agent-parity]].
func TestRunCmdRegistersRotationFlags(t *testing.T) {
	cmd := newRunCmd()
	flags := cmd.Flags()
	for _, name := range []string{
		"audit-log-max-size-mb",
		"audit-log-max-age-days",
		"audit-db-retention-days",
	} {
		require.NotNil(t, flags.Lookup(name),
			"--%s flag must be registered on `dbounce run` (F-311-4 regression)",
			name)
	}
}

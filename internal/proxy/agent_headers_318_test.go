// agent_headers_318_test.go — proxy-level #318 / §A16 wiring tests for
// dbounce. Asserts registerPGAgentFromBody correctly:
//
//  1. Parses the canonical `iam-jit-agent:NAME:SESSIONID` application_name
//     tag + registers under the AGENT-SUPPLIED session id (so cross-
//     bouncer correlation works).
//  2. Bumps the per-Server totalAgentHeadersRejected counter when the
//     tag is present but invalid.
//  3. Falls back to UUID v7 minting when no canonical tag is present
//     (existing behaviour, preserves SESSION_ENDED bookend).

package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/audit"
)

// buildStartupBodyWithAppName constructs the params block of a PG
// StartupMessage — the bytes registerPGAgentFromBody sees in
// production, which is everything AFTER the 8-byte length+protocol
// preamble (per Forwarder.handshakeAndAuth in forward.go).
// param=val\x00 pairs terminated by an extra \x00.
func buildStartupBodyWithAppName(appName string) []byte {
	// NOTE: registerPGAgentFromBody receives Forwarder.startupBody —
	// the params-only block (no protocol-version preamble).
	return []byte(
		"user\x00tester\x00database\x00postgres\x00application_name\x00" + appName + "\x00\x00")
}

// TestRegisterPGAgent_CanonicalTag_UsesSuppliedSessionID — happy path:
// `application_name=iam-jit-agent:NAME:SESSIONID` → the registered
// session id is the SUPPLIED one (not a fresh UUID), so cross-bouncer
// correlation by `agent.session_id` resolves across products.
func TestRegisterPGAgent_CanonicalTag_UsesSuppliedSessionID(t *testing.T) {
	srv := &Server{agentRegistry: audit.NewAgentRegistry()}
	canonicalName := "parity-test"
	canonicalSession := "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
	body := buildStartupBodyWithAppName(
		"iam-jit-agent:" + canonicalName + ":" + canonicalSession,
	)
	sid := srv.registerPGAgentFromBody(body)
	require.Equal(t, canonicalSession, sid,
		"agent-supplied session id MUST flow through unchanged")
	// Lookup confirms the registered agent carries the right name.
	a, ok := srv.agentRegistry.Lookup(sid)
	assert.True(t, ok)
	assert.Equal(t, canonicalName, a.Name)
	assert.Equal(t, audit.DetectedFromPGAppName, a.DetectedFrom)
	// Rejection counter NOT bumped on the happy path.
	assert.Equal(t, int64(0), srv.totalAgentHeadersRejected.Load())
}

// TestRegisterPGAgent_InvalidTag_BumpsCounter — application_name with
// the `iam-jit-agent:` prefix but malformed NAME/SESSIONID bumps the
// rejection counter + the malicious value is NEVER written to the
// audit event.
func TestRegisterPGAgent_InvalidTag_BumpsCounter(t *testing.T) {
	srv := &Server{agentRegistry: audit.NewAgentRegistry()}
	body := buildStartupBodyWithAppName("iam-jit-agent:bad name; rm -rf /:also-bad")
	sid := srv.registerPGAgentFromBody(body)
	// A session id is STILL minted (so SESSION_ENDED fires) but it's
	// a fresh UUID v7, NOT the malicious caller-supplied value.
	require.NotEmpty(t, sid)
	assert.True(t, audit.IsValidSessionID(sid))
	assert.NotEqual(t, "also-bad", sid)
	// The malicious name is dropped — Mint normalizes empty to "unknown".
	a, ok := srv.agentRegistry.Lookup(sid)
	require.True(t, ok)
	assert.NotContains(t, a.Name, "rm -rf")
	assert.NotContains(t, a.Name, ";")
	// Rejection counter bumped exactly once.
	assert.Equal(t, int64(1), srv.totalAgentHeadersRejected.Load())
}

// TestRegisterPGAgent_KnownClient_NoTag_FallsThroughToPGAppName —
// no canonical tag → existing known-client mapping fires + a fresh
// UUID v7 session id is minted.
func TestRegisterPGAgent_KnownClient_NoTag_FallsThroughToPGAppName(t *testing.T) {
	srv := &Server{agentRegistry: audit.NewAgentRegistry()}
	body := buildStartupBodyWithAppName("psql")
	sid := srv.registerPGAgentFromBody(body)
	require.NotEmpty(t, sid)
	assert.True(t, audit.IsValidSessionID(sid))
	a, ok := srv.agentRegistry.Lookup(sid)
	require.True(t, ok)
	assert.Equal(t, "psql", a.Name)
	assert.Equal(t, audit.DetectedFromPGAppName, a.DetectedFrom)
	assert.Equal(t, int64(0), srv.totalAgentHeadersRejected.Load(),
		"non-tagged app_name MUST NOT bump the rejection counter")
}

// TestRegisterPGAgent_NoAppName_MintsAnonymous — entirely absent
// application_name → fresh session id minted + name=unknown (so
// SESSION_ENDED can still fire). Confirms #318 didn't regress the
// pre-existing anonymous path.
func TestRegisterPGAgent_NoAppName_MintsAnonymous(t *testing.T) {
	srv := &Server{agentRegistry: audit.NewAgentRegistry()}
	// Build a startup body with NO application_name param.
	body := []byte("user\x00tester\x00database\x00postgres\x00\x00")
	sid := srv.registerPGAgentFromBody(body)
	require.NotEmpty(t, sid)
	assert.True(t, audit.IsValidSessionID(sid))
	a, ok := srv.agentRegistry.Lookup(sid)
	require.True(t, ok)
	assert.Equal(t, "unknown", a.Name)
	assert.Equal(t, audit.DetectedFromUnknown, a.DetectedFrom)
}

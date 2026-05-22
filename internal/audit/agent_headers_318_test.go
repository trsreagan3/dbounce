// agent_headers_318_test.go — #318 / §A16 cross-bouncer agent-attribution
// parity for dbounce.
//
// dbounce sees the SQL wire protocol, not HTTP, so the canonical
// agent-attribution channel is the PostgreSQL `application_name`
// startup parameter rather than HTTP headers. The convention
// `application_name=iam-jit-agent:NAME:SESSIONID` is the wire-protocol
// equivalent of the HTTP-shaped Bouncers' `X-Agent-Name` +
// `X-Agent-Session-Id` headers.
//
// These tests cover the canonical cross-product names from the §A16
// spec (`TestApplicationName_AgentParsing_HappyPath` +
// `TestApplicationName_NoAgentTag_FallbackToUA`) plus the four
// `TestAgentHeaders_*` names so cross-product test discovery (per
// [[cross-product-agent-parity]]) finds the equivalent assertions.

package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	canonicalAgentName   = "parity-test"
	canonicalSessionID   = "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
	canonicalSessionIDv4 = "01968d6a-9c12-4a4b-b6f8-3b8e4c0d1aef"
)

// TestApplicationName_AgentParsing_HappyPath — canonical cross-product
// test name from the §A16 spec. The `iam-jit-agent:NAME:SESSIONID`
// shape parses cleanly + both pieces validate.
func TestApplicationName_AgentParsing_HappyPath(t *testing.T) {
	params := map[string]string{
		"application_name": "iam-jit-agent:" + canonicalAgentName + ":" + canonicalSessionID,
	}
	name, sessionID, raw, tagInvalid := ParsePGStartupAppNameWithSession(params)
	assert.False(t, tagInvalid)
	assert.Equal(t, canonicalAgentName, name)
	assert.Equal(t, canonicalSessionID, sessionID)
	assert.Equal(t, "iam-jit-agent:"+canonicalAgentName+":"+canonicalSessionID, raw)
}

// TestApplicationName_NoAgentTag_FallbackToUA — canonical name from
// the §A16 spec. When the `iam-jit-agent:` prefix is absent, the
// existing known-client app-name table fires unchanged.
func TestApplicationName_NoAgentTag_FallbackToUA(t *testing.T) {
	// Existing known clients still map correctly — no regression from
	// the additive #318 tag handler.
	cases := []struct {
		appName, wantName string
	}{
		{"psql", "psql"},
		{"pgcli", "pgcli"},
		{"PostgreSQL JDBC Driver", "pg-jdbc"},
		{"claude-code", "claude-code"},
		{"my-custom-app", "my-custom-app"},
	}
	for _, c := range cases {
		t.Run(c.appName, func(t *testing.T) {
			name, sessionID, _, tagInvalid := ParsePGStartupAppNameWithSession(
				map[string]string{"application_name": c.appName},
			)
			assert.False(t, tagInvalid)
			assert.Equal(t, c.wantName, name)
			assert.Empty(t, sessionID, "no session id for non-tagged app names")
		})
	}
}

// TestAgentHeaders_HappyPath — canonical cross-product test name from
// the §A16 spec. Tagged application_name → both name + session_id
// populated.
func TestAgentHeaders_HappyPath(t *testing.T) {
	name, sessionID, ok := ParseAgentTagFromAppName(
		"iam-jit-agent:" + canonicalAgentName + ":" + canonicalSessionID,
	)
	assert.True(t, ok)
	assert.Equal(t, canonicalAgentName, name)
	assert.Equal(t, canonicalSessionID, sessionID)
}

// TestAgentHeaders_NoHeaders_FallbackToUserAgent — when no
// application_name is supplied, ParsePGStartupAppNameWithSession
// returns empty / not-invalid; the connection is anonymous.
func TestAgentHeaders_NoHeaders_FallbackToUserAgent(t *testing.T) {
	name, sessionID, raw, tagInvalid := ParsePGStartupAppNameWithSession(
		map[string]string{},
	)
	assert.Empty(t, name)
	assert.Empty(t, sessionID)
	assert.Empty(t, raw)
	assert.False(t, tagInvalid)
}

// TestAgentHeaders_InvalidName_Rejected — invalid NAME in the canonical
// tag → tagInvalid=true; the caller bumps the rejection counter + the
// raw value is NEVER stamped onto the audit event.
func TestAgentHeaders_InvalidName_Rejected(t *testing.T) {
	cases := []string{
		"iam-jit-agent:bad name with spaces:" + canonicalSessionID,
		"iam-jit-agent:shell$inj:" + canonicalSessionID,
		"iam-jit-agent:back`tick:" + canonicalSessionID,
		"iam-jit-agent:rm -rf /:" + canonicalSessionID,
	}
	for _, appName := range cases {
		t.Run(appName, func(t *testing.T) {
			name, sessionID, _, tagInvalid := ParsePGStartupAppNameWithSession(
				map[string]string{"application_name": appName},
			)
			assert.True(t, tagInvalid, "malicious name must flag tagInvalid")
			// The validated (returned) name + session id MUST be empty
			// when tagInvalid fires — the malicious value never lands.
			assert.Empty(t, name, "malicious name MUST NOT be returned as a validated value")
			assert.Empty(t, sessionID, "malicious name implies malicious tag — no session id either")
		})
	}
}

// TestAgentHeaders_NameOnly_PartialDetection — for dbounce's SQL wire
// protocol there's no "name only" partial shape (the canonical tag
// requires both NAME and SESSIONID); a tag with only a name is treated
// as malformed (tagInvalid). The closest analog to the HTTP partial
// path is: tag absent → fall through to the legacy known-client table
// which lands at name=psql etc. with no session id.
func TestAgentHeaders_NameOnly_PartialDetection(t *testing.T) {
	// "iam-jit-agent:claude-code" with no trailing `:SESSIONID` →
	// tagInvalid because the colon-separator is missing.
	name, sessionID, raw, tagInvalid := ParsePGStartupAppNameWithSession(
		map[string]string{"application_name": "iam-jit-agent:claude-code"},
	)
	assert.True(t, tagInvalid)
	assert.Empty(t, name)
	assert.Empty(t, sessionID)
	assert.Equal(t, "iam-jit-agent:claude-code", raw)
}

// TestApplicationName_AgentParsing_RejectsInvalidSessionID covers the
// "session id has spaces / shell chars" rejection path.
func TestApplicationName_AgentParsing_RejectsInvalidSessionID(t *testing.T) {
	name, sessionID, _, tagInvalid := ParsePGStartupAppNameWithSession(
		map[string]string{
			"application_name": "iam-jit-agent:claude-code:not a session id",
		},
	)
	assert.True(t, tagInvalid)
	assert.Empty(t, name)
	assert.Empty(t, sessionID)
}

// TestApplicationName_AgentParsing_AcceptsUUIDv4 — operators may use
// UUID v4 (the default in many SDKs) for session ids.
func TestApplicationName_AgentParsing_AcceptsUUIDv4(t *testing.T) {
	name, sessionID, _, tagInvalid := ParsePGStartupAppNameWithSession(
		map[string]string{
			"application_name": "iam-jit-agent:claude-code:" + canonicalSessionIDv4,
		},
	)
	assert.False(t, tagInvalid)
	assert.Equal(t, "claude-code", name)
	assert.Equal(t, canonicalSessionIDv4, sessionID)
}

// TestIsValidAgentName_MatchesGbounceRegex asserts dbounce's validator
// regex matches gbounce / ibounce / kbouncer byte-for-byte per
// [[cross-product-agent-parity]].
func TestIsValidAgentName_MatchesGbounceRegex(t *testing.T) {
	cases := []struct {
		name  string
		valid bool
	}{
		{"claude-code", true},
		{"cursor", true},
		{"openai-codex", true},
		{"devin", true},
		{"gpt-4.1", true},
		{"my_agent.v2", true},
		{"a", true},
		{"", false},
		{"has spaces", false},
		{"shell$injection", false},
		{"back`tick", false},
		{"semi;colon", false},
		{"path/sep", false},
		{"with\nnewline", false},
		{"quote'mark", false},
	}
	for _, c := range cases {
		got := IsValidAgentName(c.name)
		assert.Equal(t, c.valid, got, "IsValidAgentName(%q)", c.name)
	}
}

// TestAgentRegistry_MintWithSessionID_PreservesSuppliedID asserts that
// the dbounce registry registers an agent under the caller-supplied
// session id when it passes validation — the load-bearing invariant
// for cross-bouncer correlation by `agent.session_id`.
func TestAgentRegistry_MintWithSessionID_PreservesSuppliedID(t *testing.T) {
	r := NewAgentRegistry()
	out := r.MintWithSessionID(
		Agent{Name: "claude-code", DetectedFrom: DetectedFromPGAppName},
		canonicalSessionID,
	)
	assert.Equal(t, canonicalSessionID, out)
	// Lookup confirms the same session id resolves to the agent.
	a, ok := r.Lookup(canonicalSessionID)
	assert.True(t, ok)
	assert.Equal(t, "claude-code", a.Name)
	assert.Equal(t, canonicalSessionID, a.SessionID)
}

// TestAgentRegistry_MintWithSessionID_InvalidFallsBackToMint asserts
// that supplying an invalid session id falls back to Mint's UUID v7
// minting (so the SESSION_ENDED bookend still fires).
func TestAgentRegistry_MintWithSessionID_InvalidFallsBackToMint(t *testing.T) {
	r := NewAgentRegistry()
	out := r.MintWithSessionID(
		Agent{Name: "claude-code"},
		"not a session id with spaces",
	)
	// Out is some valid session id, NOT the invalid input.
	assert.NotEqual(t, "not a session id with spaces", out)
	assert.True(t, IsValidSessionID(out))
}

// Tests for [[agent-identity-in-audit]] Feature 1 + 2 — agent
// fingerprinting + persistent session ID, per-dialect detection
// (PG application_name, MySQL handshake attrs, MCP clientInfo).
//
// Sibling agents in ibounce + kbounce ship equivalent fixtures against
// their projections; the cross-product invariant is: every projection
// emits unmapped.iam_jit.agent under the same JSON path so a single
// SIEM filter spans all three.

package audit

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trsreagan3/dbounce/internal/store"
)

// TestAgent_IsEmpty_AllZeroValue confirms the no-agent path: an Agent
// with no fields populated reports IsEmpty=true so the projection
// drops the entire unmapped.iam_jit.agent block from the wire (rather
// than emitting `"agent":{}` clutter on every observation-only smoke
// event).
func TestAgent_IsEmpty_AllZeroValue(t *testing.T) {
	var a Agent
	assert.True(t, a.IsEmpty())
}

// TestAgent_Normalize_FillsUnknownsWhenPartial: when SessionID is set
// but Name is not (an MCP connection that didn't surface clientInfo),
// Normalize stamps Name="unknown" + DetectedFrom=Unknown so SIEM
// dashboards always have a stable bucket.
func TestAgent_Normalize_FillsUnknownsWhenPartial(t *testing.T) {
	a := Agent{SessionID: "sid-xyz"}
	out := a.Normalize()
	assert.Equal(t, "unknown", out.Name)
	assert.Equal(t, DetectedFromUnknown, out.DetectedFrom)
	assert.Equal(t, "sid-xyz", out.SessionID)
}

// TestNewSessionID_IsUUIDv7 verifies the minted session id is a
// real UUID v7 (time-ordered with a random tail) per
// [[agent-identity-in-audit]]: "Don't make session ID predictable (use
// UUID v7 with random component, not a counter)."
func TestNewSessionID_IsUUIDv7(t *testing.T) {
	a := NewSessionID()
	// UUID v7 string form is 36 chars (32 hex + 4 dashes).
	require.Len(t, a, 36)
	// Version nibble (the 15th character) MUST be '7'.
	assert.Equal(t, byte('7'), a[14], "session id MUST be UUID v7 (version nibble = 7)")
	// Generating another MUST yield a different id (the random tail
	// + the monotonic counter guarantee no collisions in normal use).
	b := NewSessionID()
	assert.NotEqual(t, a, b)
}

// TestAgentRegistry_MintLookupRetire covers the happy path of the
// per-process session lifecycle: mint → lookup → retire.
func TestAgentRegistry_MintLookupRetire(t *testing.T) {
	r := NewAgentRegistry()
	sid := r.Mint(Agent{Name: "claude-code", Version: "1.0.0", DetectedFrom: DetectedFromMCPClientInfo})
	require.NotEmpty(t, sid)
	assert.Equal(t, 1, r.ActiveCount())

	got, ok := r.Lookup(sid)
	require.True(t, ok)
	assert.Equal(t, "claude-code", got.Name)
	assert.Equal(t, "1.0.0", got.Version)
	assert.Equal(t, sid, got.SessionID)
	assert.Equal(t, DetectedFromMCPClientInfo, got.DetectedFrom)

	retired, ok := r.Retire(sid)
	require.True(t, ok)
	assert.Equal(t, "claude-code", retired.Name)
	assert.Equal(t, 0, r.ActiveCount())

	// Re-retire is a no-op (defensive against double-close paths).
	_, ok = r.Retire(sid)
	assert.False(t, ok)
}

// TestAgentRegistry_MintNormalizesEmptyName: Mint must stamp
// name="unknown" when the caller passes an empty name (e.g. an MCP
// initialize without clientInfo) so SIEM dashboards never see an empty
// agent name.
func TestAgentRegistry_MintNormalizesEmptyName(t *testing.T) {
	r := NewAgentRegistry()
	sid := r.Mint(Agent{})
	got, ok := r.Lookup(sid)
	require.True(t, ok)
	assert.Equal(t, "unknown", got.Name)
	assert.Equal(t, DetectedFromUnknown, got.DetectedFrom)
}

// TestAgentRegistry_RaceFree drives concurrent Mint / Lookup / Retire
// to surface any registry-level data race under `go test -race`. Per
// the cross-product invariant + the 53d97d3 port-race precedent, the
// registry MUST be race-clean.
func TestAgentRegistry_RaceFree(t *testing.T) {
	r := NewAgentRegistry()
	const goroutines = 32
	const ops = 200
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				sid := r.Mint(Agent{Name: "claude-code"})
				_, _ = r.Lookup(sid)
				_, _ = r.Retire(sid)
				_ = r.ActiveCount()
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 0, r.ActiveCount(),
		"every minted session was retired; ActiveCount must drain to 0")
}

// TestParsePGStartupParams_KeyValuePairs parses a synthetic
// StartupMessage parameter block (the bytes after the protocol version
// in a PG StartupMessage) and verifies the standard PG parameter keys
// land in the returned map.
func TestParsePGStartupParams_KeyValuePairs(t *testing.T) {
	body := []byte("user\x00alice\x00database\x00warehouse\x00application_name\x00psql\x00\x00")
	got := ParsePGStartupParams(body)
	assert.Equal(t, "alice", got["user"])
	assert.Equal(t, "warehouse", got["database"])
	assert.Equal(t, "psql", got["application_name"])
}

// TestParsePGStartupParams_Defensive: malformed (missing trailing
// null, odd number of strings, empty body) must not panic + must
// return whatever was parsed.
func TestParsePGStartupParams_Defensive(t *testing.T) {
	cases := map[string][]byte{
		"empty":           nil,
		"trailing-only":   []byte("\x00\x00"),
		"key-no-value":    []byte("user\x00\x00"),
		"missing-final":   []byte("user\x00alice"),
		"single-pair":     []byte("application_name\x00pgcli\x00\x00"),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			got := ParsePGStartupParams(body)
			// Defensive contract: no panic. Content varies per case;
			// we only assert single-pair gets its key.
			if name == "single-pair" {
				assert.Equal(t, "pgcli", got["application_name"])
			}
		})
	}
}

// TestParsePGStartupAppName_KnownClients verifies the agent-name
// mapping for the common PG clients listed in the
// [[agent-identity-in-audit]] memo: psql / pgcli / psycopg2 / pg-jdbc
// / claude-code / cursor / codex / devin. Other names pass through as-
// is so unknown clients surface their literal app_name in the audit.
func TestParsePGStartupAppName_KnownClients(t *testing.T) {
	cases := []struct {
		appName, wantName string
	}{
		{"psql", "psql"},
		{"pgcli", "pgcli"},
		{"psycopg2", "psycopg2"},
		{"psycopg3", "psycopg2"},
		{"PostgreSQL JDBC Driver", "pg-jdbc"},
		{"claude-code", "claude-code"},
		{"claude-code/1.2.3", "claude-code"},
		{"cursor", "cursor"},
		{"codex", "codex"},
		{"devin", "devin"},
		{"my-custom-app", "my-custom-app"},
		{"", ""}, // missing application_name → empty
	}
	for _, tc := range cases {
		t.Run(tc.appName, func(t *testing.T) {
			got, _ := ParsePGStartupAppName(map[string]string{"application_name": tc.appName})
			assert.Equal(t, tc.wantName, got)
		})
	}
}

// TestParseMySQLClientAttrs_Roundtrip parses a synthetic MySQL
// HandshakeResponse attrs block (length-encoded string pairs per the
// MySQL protocol) and verifies the standard Connector/J keys land in
// the returned map.
func TestParseMySQLClientAttrs_Roundtrip(t *testing.T) {
	// Build a synthetic attrs block: key/value pairs are length-encoded
	// strings (one-byte length prefix for short strings).
	build := func(pairs ...string) []byte {
		var out []byte
		for _, s := range pairs {
			out = append(out, byte(len(s)))
			out = append(out, []byte(s)...)
		}
		return out
	}
	block := build(
		"_client_name", "MySQL Connector/J",
		"_client_version", "8.4.0",
		"_program_name", "mysqlsh",
	)
	attrs := ParseMySQLClientAttrs(block)
	assert.Equal(t, "MySQL Connector/J", attrs["_client_name"])
	assert.Equal(t, "8.4.0", attrs["_client_version"])
	assert.Equal(t, "mysqlsh", attrs["_program_name"])
}

// TestParseMySQLAgentFromAttrs_KnownClients verifies the agent-name
// mapping for common MySQL clients per the memo.
func TestParseMySQLAgentFromAttrs_KnownClients(t *testing.T) {
	cases := []struct {
		attrs              map[string]string
		wantName, wantVer  string
	}{
		{map[string]string{"_client_name": "MySQL Connector/J", "_client_version": "8.4.0"}, "mysql-connector-j", "8.4.0"},
		{map[string]string{"_client_name": "libmysql 8.0.33"}, "libmysql", ""},
		{map[string]string{"_client_name": "Python-mysql-connector"}, "python-mysql", ""},
		{map[string]string{"_program_name": "mysql"}, "mysql-cli", ""},
		{map[string]string{"_program_name": "mysqlsh"}, "mysql-cli", ""},
		{map[string]string{"_program_name": "claude-code"}, "claude-code", ""},
		{map[string]string{"_client_name": "go-sql-driver/mysql"}, "go-sql-driver/mysql", ""},
		{map[string]string{}, "", ""},
	}
	for i, tc := range cases {
		gotName, gotVer := ParseMySQLAgentFromAttrs(tc.attrs)
		assert.Equal(t, tc.wantName, gotName, "case %d (%v) name", i, tc.attrs)
		assert.Equal(t, tc.wantVer, gotVer, "case %d (%v) version", i, tc.attrs)
	}
}

// TestMCPClientInfoToAgent_PreservesNameAndStampsDetectedFrom verifies
// MCP clientInfo round-trips into the Agent struct with the right
// detection source. Empty name normalizes to "unknown" per the memo.
func TestMCPClientInfoToAgent_PreservesNameAndStampsDetectedFrom(t *testing.T) {
	a := MCPClientInfoToAgent("claude-code", "1.2.3")
	assert.Equal(t, "claude-code", a.Name)
	assert.Equal(t, "1.2.3", a.Version)
	assert.Equal(t, DetectedFromMCPClientInfo, a.DetectedFrom)

	b := MCPClientInfoToAgent("", "")
	assert.Equal(t, "unknown", b.Name)
	assert.Equal(t, DetectedFromMCPClientInfo, b.DetectedFrom)
}

// TestFromDecisionRowWithAgent_PopulatesAgentBlock verifies the
// schema-compliance addition: when agent context is passed,
// unmapped.iam_jit.agent block lands in the projected event with all
// four sub-fields (name / version / session_id / detected_from).
func TestFromDecisionRowWithAgent_PopulatesAgentBlock(t *testing.T) {
	row := store.DecisionRow{
		Dialect:         "postgres",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
		TablesTouched:   []string{"public.users"},
	}
	agent := Agent{
		Name:         "psql",
		Version:      "16.0",
		SessionID:    "session-uuid-xyz",
		DetectedFrom: DetectedFromPGAppName,
	}
	evt := FromDecisionRowWithAgent(row, 1, "127.0.0.1:5433", "", agent)

	require.NotNil(t, evt.Unmapped)
	require.NotNil(t, evt.Unmapped.IAMJIT.Agent,
		"unmapped.iam_jit.agent MUST be present when agent context is passed")
	got := *evt.Unmapped.IAMJIT.Agent
	assert.Equal(t, "psql", got.Name)
	assert.Equal(t, "16.0", got.Version)
	assert.Equal(t, "session-uuid-xyz", got.SessionID)
	assert.Equal(t, DetectedFromPGAppName, got.DetectedFrom)

	// Wire-level: the JSON MUST land under unmapped.iam_jit.agent so
	// the cross-product SIEM filter works.
	raw, err := json.Marshal(evt)
	require.NoError(t, err)
	s := string(raw)
	for _, frag := range []string{
		`"agent":`,
		`"name":"psql"`,
		`"version":"16.0"`,
		`"session_id":"session-uuid-xyz"`,
		`"detected_from":"pg_application_name"`,
	} {
		assert.True(t, strings.Contains(s, frag),
			"agent JSON wire shape must contain %q; got %s", frag, s)
	}
}

// TestFromDecisionRowWithAgent_OmitsBlockWhenAgentEmpty: an empty
// Agent MUST result in the agent block being absent from the wire
// (preserves legacy event shape for observation-only smoke tests).
func TestFromDecisionRowWithAgent_OmitsBlockWhenAgentEmpty(t *testing.T) {
	row := store.DecisionRow{
		Dialect:         "postgres",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
	}
	evt := FromDecisionRowWithAgent(row, 1, "127.0.0.1:5433", "", Agent{})
	require.NotNil(t, evt.Unmapped)
	assert.Nil(t, evt.Unmapped.IAMJIT.Agent,
		"empty Agent MUST omit unmapped.iam_jit.agent from the wire")
	raw, err := json.Marshal(evt)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(raw), `"agent":`),
		"JSON MUST NOT contain an empty agent block; got %s", string(raw))
}

// TestNewSessionEndedEvent_OCSFShape pins the SESSION_ENDED synthetic
// event's class-6003 envelope per [[agent-identity-in-audit]] Feature 2.
func TestNewSessionEndedEvent_OCSFShape(t *testing.T) {
	agent := Agent{
		Name:         "claude-code",
		Version:      "1.2.3",
		SessionID:    "the-retired-session",
		DetectedFrom: DetectedFromMCPClientInfo,
	}
	evt := NewSessionEndedEvent(agent, "mcp-stdio")

	assert.Equal(t, 6003, evt.ClassUID)
	assert.Equal(t, ActivityIDOther, evt.ActivityID)
	assert.Equal(t, "session_ended", evt.ActivityName)
	assert.Equal(t, 600399, evt.TypeUID)
	assert.Equal(t, ocsfSeverityInformationalID, evt.SeverityID,
		"SESSION_ENDED is bookkeeping; Informational per the memo")
	assert.Equal(t, StatusIDOther, evt.StatusID)

	require.NotNil(t, evt.Unmapped)
	assert.Equal(t, string(EventTypeSessionEnded), evt.Unmapped.IAMJIT.EventType)
	require.NotNil(t, evt.Unmapped.IAMJIT.Agent)
	assert.Equal(t, "the-retired-session", evt.Unmapped.IAMJIT.Agent.SessionID,
		"SESSION_ENDED MUST carry the retired session_id so the SIEM can JOIN")

	require.NoError(t, assertOCSFCompliant(evt))
}

// TestEvent_OCSFSchemaCompliance_AgentBlock extends the binding
// contract test for the agent block. Every event with an agent block
// MUST still pass the OCSF v1.1.0 class-6003 compliance check.
func TestEvent_OCSFSchemaCompliance_AgentBlock(t *testing.T) {
	row := store.DecisionRow{
		Dialect:         "postgres",
		StatementType:   "SELECT",
		DecisionVerdict: "ALLOW",
		ModeAtDecision:  "cooperative",
	}
	cases := map[string]Agent{
		"pg-app-name":      {Name: "psql", SessionID: "sid-1", DetectedFrom: DetectedFromPGAppName},
		"mysql-attrs":      {Name: "mysql-connector-j", SessionID: "sid-2", DetectedFrom: DetectedFromMySQLAttrs},
		"mcp-client-info":  {Name: "claude-code", Version: "1.0", SessionID: "sid-3", DetectedFrom: DetectedFromMCPClientInfo},
		"decide-flag":      {Name: "custom-agent", SessionID: "sid-4", DetectedFrom: DetectedFromDecideFlag},
		"session-only":     {SessionID: "sid-5"}, // Name+DetectedFrom normalize to "unknown"
	}
	for name, agent := range cases {
		t.Run(name, func(t *testing.T) {
			evt := FromDecisionRowWithAgent(row, 1, "127.0.0.1:5433", "", agent)
			require.NoError(t, assertOCSFCompliant(evt))
			require.NotNil(t, evt.Unmapped.IAMJIT.Agent)
			assert.NotEmpty(t, evt.Unmapped.IAMJIT.Agent.SessionID,
				"every populated agent block has a session_id")
			assert.NotEmpty(t, evt.Unmapped.IAMJIT.Agent.Name,
				"every populated agent block has a name (Normalize fills 'unknown')")
		})
	}
}

// Posture MCP-tool tests per #383 / §A42.

package mcp

import (
	"testing"
)

// TestMCP_PostureReturnsBlock confirms the dbounce_posture tool dispatches
// successfully + returns a result with the documented top-level keys.
func TestMCP_PostureReturnsBlock(t *testing.T) {
	t.Setenv("DBOUNCE_MODE", "transparent")
	t.Setenv("DBOUNCE_PROFILE", "staging-only")
	srv := &Server{}
	resp, err := srv.toolPosture(nil)
	if err != nil {
		t.Fatalf("toolPosture: %v", err)
	}
	for _, k := range []string{
		"schema_version", "bouncer", "captured_at", "running",
		"port", "default_port", "mode", "active_profile",
	} {
		if _, ok := resp[k]; !ok {
			t.Errorf("missing key %q in posture MCP response", k)
		}
	}
	if resp["bouncer"] != "dbounce" {
		t.Errorf("bouncer=%v want dbounce", resp["bouncer"])
	}
	if resp["mode"] != "transparent" {
		t.Errorf("mode=%v want transparent", resp["mode"])
	}
}

// TestMCP_PostureToolDescriptorPresent confirms dbounce_posture is
// included in the tool descriptor list so MCP clients see it via
// tools/list.
func TestMCP_PostureToolDescriptorPresent(t *testing.T) {
	tools := ToolDescriptors()
	for _, td := range tools {
		if td["name"] == "dbounce_posture" {
			return
		}
	}
	t.Errorf("dbounce_posture missing from ToolDescriptors() output")
}

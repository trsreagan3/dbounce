// Posture tests for dbounce per #383 / §A42.

package posture

import (
	"encoding/json"
	"testing"
)

func TestPosture_ReportsActiveProfileAndMode(t *testing.T) {
	t.Setenv("DBOUNCE_PROFILE", "staging-only")
	t.Setenv("DBOUNCE_MODE", "transparent")
	b := Capture()
	if b.ActiveProfile != "staging-only" {
		t.Errorf("ActiveProfile=%q want staging-only", b.ActiveProfile)
	}
	if b.Mode != "transparent" {
		t.Errorf("Mode=%q want transparent", b.Mode)
	}
	if b.Bouncer != "dbounce" {
		t.Errorf("Bouncer=%q want dbounce", b.Bouncer)
	}
}

func TestPosture_DetectsMisconfigPGHOSTLoopbackNoListener(t *testing.T) {
	t.Setenv("PGHOST", "127.0.0.1")
	// A high port that is almost certainly not in use.
	t.Setenv("PGPORT", "59734")
	b := Capture()
	if b.Misconfig == "" {
		t.Skip("port 59734 happens to be in use; skipping")
	}
	if b.Misconfig == "" {
		t.Errorf("misconfig should be set when PGHOST=loopback + PGPORT closed")
	}
}

func TestPosture_DefaultPortsArePinned(t *testing.T) {
	if DefaultWirePort != 5433 {
		t.Errorf("DefaultWirePort=%d; if you changed dbounce --port default, update both", DefaultWirePort)
	}
	if DefaultMgmtPort != 8768 {
		t.Errorf("DefaultMgmtPort=%d; if you changed dbounce --mgmt-port default, update both", DefaultMgmtPort)
	}
}

func TestPosture_JSONOutputValidatesAgainstSchema(t *testing.T) {
	b := Capture()
	bs, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundtrip map[string]any
	if err := json.Unmarshal(bs, &roundtrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{
		"schema_version", "bouncer", "captured_at", "running",
		"port", "default_port", "mode", "active_profile",
	} {
		if _, ok := roundtrip[k]; !ok {
			t.Errorf("missing required key %q in JSON output", k)
		}
	}
	if roundtrip["schema_version"] != SchemaVersion {
		t.Errorf("schema_version=%v want %s", roundtrip["schema_version"], SchemaVersion)
	}
}

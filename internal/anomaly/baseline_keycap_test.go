// baseline_keycap_test.go is BYTE-IDENTICAL across gbounce / kbouncer /
// dbounce (it lives in the cross-repo core package). It proves the
// SECURITY cap on distinct baseline keys: an attacker minting unbounded
// distinct (agent, action, resource) keys cannot OOM the process — the
// store stays bounded and the dropped counter reports the eviction
// honestly. #718 ADOPT-4 finding HIGH-2.
package anomaly

import (
	"strconv"
	"testing"
)

func TestBaselineKeyCapBoundsAndReportsDropped(t *testing.T) {
	s := NewBaselineStore(0, 0)

	// Flood well past the cap with distinct attacker-controlled agent
	// identities (the realistic OOM vector: a forged per-request name).
	flood := maxDistinctKeys + 2_500
	for i := 0; i < flood; i++ {
		s.Observe("agent-"+strconv.Itoa(i), "GET", "api.example.com/data", 0)
	}

	st := s.Status()
	tracked := st["tracked_keys"].(int)
	if tracked > maxDistinctKeys {
		t.Fatalf("distinct keys not bounded: tracked=%d cap=%d", tracked, maxDistinctKeys)
	}

	dropped, ok := st["dropped"].(int64)
	if !ok {
		t.Fatalf("dropped not reported as int64: %T", st["dropped"])
	}
	if dropped <= 0 {
		t.Fatalf("expected dropped>0 after flooding past the cap; got %d", dropped)
	}
	// Everything over the cap must have been evicted-and-counted.
	if int64(flood)-dropped > int64(maxDistinctKeys) {
		t.Fatalf("dropped (%d) does not account for the overflow (flood=%d cap=%d)", dropped, flood, maxDistinctKeys)
	}
}

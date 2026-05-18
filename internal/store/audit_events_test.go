package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPendingAuditEventQueue_RoundTrip pins the basic enqueue + drain
// behavior the cross-process Slice 2 wiring per
// [[security-team-audit-export]] depends on. Round-trip pause-stop +
// profile-install kinds; assert ordering (id-ASC), drain idempotency
// (the same row is never returned twice), and payload preservation.
func TestPendingAuditEventQueue_RoundTrip(t *testing.T) {
	s := scratchStore(t)

	// Empty queue → empty drain.
	rows, err := s.DrainPendingAuditEvents(0)
	require.NoError(t, err)
	assert.Empty(t, rows, "empty queue must drain to zero rows")

	// Enqueue 3 rows of mixed kinds + drain.
	id1, err := s.AddPendingAuditEvent(
		PendingAuditEventAdminFallbackEnd,
		`{"pause_id":1,"end_kind":"manual"}`)
	require.NoError(t, err)
	id2, err := s.AddPendingAuditEvent(
		PendingAuditEventProfileInstalled,
		`{"source_url":"https://x"}`)
	require.NoError(t, err)
	id3, err := s.AddPendingAuditEvent(
		PendingAuditEventAdminFallbackEnd,
		`{"pause_id":2,"end_kind":"expired"}`)
	require.NoError(t, err)
	require.Less(t, id1, id2)
	require.Less(t, id2, id3)

	depth, err := s.PendingAuditEventDepth()
	require.NoError(t, err)
	assert.Equal(t, 3, depth)

	drained, err := s.DrainPendingAuditEvents(0)
	require.NoError(t, err)
	require.Len(t, drained, 3, "drain must return all rows")
	assert.Equal(t, id1, drained[0].ID, "ordering must be id-ASC")
	assert.Equal(t, id2, drained[1].ID)
	assert.Equal(t, id3, drained[2].ID)
	assert.Equal(t, PendingAuditEventAdminFallbackEnd, drained[0].Kind)
	assert.Equal(t, PendingAuditEventProfileInstalled, drained[1].Kind)
	assert.Contains(t, drained[0].PayloadJSON, "manual")

	// Second drain returns nothing — DrainPendingAuditEvents must
	// DELETE inside the transaction to prevent double-emit.
	again, err := s.DrainPendingAuditEvents(0)
	require.NoError(t, err)
	assert.Empty(t, again, "drain must be idempotent: rows are deleted in-txn")

	depth, err = s.PendingAuditEventDepth()
	require.NoError(t, err)
	assert.Equal(t, 0, depth)
}

// TestPendingAuditEventQueue_KindRequired locks the input-validation
// guard so a typo-kind never lands on the wire.
func TestPendingAuditEventQueue_KindRequired(t *testing.T) {
	s := scratchStore(t)
	_, err := s.AddPendingAuditEvent("", `{}`)
	require.Error(t, err)
}

// TestPendingAuditEventQueue_EmptyPayloadDefaults pins the
// empty-payload convention: an empty string becomes "{}" so the drain
// side's json.Unmarshal never fails.
func TestPendingAuditEventQueue_EmptyPayloadDefaults(t *testing.T) {
	s := scratchStore(t)
	_, err := s.AddPendingAuditEvent(PendingAuditEventAdminFallbackEnd, "")
	require.NoError(t, err)
	drained, err := s.DrainPendingAuditEvents(0)
	require.NoError(t, err)
	require.Len(t, drained, 1)
	assert.Equal(t, "{}", drained[0].PayloadJSON,
		"empty payload must default to '{}' so json.Unmarshal succeeds")
}

// TestStopPause_EnqueuesAdminFallbackEnd verifies the manual-end
// path enqueues the cross-process synthetic per Slice 2 wiring.
func TestStopPause_EnqueuesAdminFallbackEnd(t *testing.T) {
	s := scratchStore(t)
	id, _, err := s.StartPause("live demo", "alice", 1*time.Hour)
	require.NoError(t, err)

	// StartPause on an empty table does NOT supersede anything, so
	// the queue is empty after the open.
	drained, err := s.DrainPendingAuditEvents(0)
	require.NoError(t, err)
	assert.Empty(t, drained, "open-pause on empty table must not enqueue")

	stopped, err := s.StopPause("alice")
	require.NoError(t, err)
	assert.Equal(t, id, stopped)

	drained, err = s.DrainPendingAuditEvents(0)
	require.NoError(t, err)
	require.Len(t, drained, 1, "stop-pause must enqueue exactly one synthetic")
	assert.Equal(t, PendingAuditEventAdminFallbackEnd, drained[0].Kind)

	// Payload must carry the fields the run-process drain emits.
	var payload struct {
		PauseID   int64  `json:"pause_id"`
		StartedBy string `json:"started_by"`
		Reason    string `json:"reason"`
		EndKind   string `json:"end_kind"`
	}
	require.NoError(t, json.Unmarshal([]byte(drained[0].PayloadJSON), &payload))
	assert.Equal(t, id, payload.PauseID)
	assert.Equal(t, "alice", payload.StartedBy)
	assert.Equal(t, "live demo", payload.Reason)
	assert.Equal(t, "manual", payload.EndKind,
		"manual stop must stamp end_kind=manual")
}

// TestStartPause_SupersedeEnqueues verifies the supersede branch fires
// the synthetic for the row it just closed.
func TestStartPause_SupersedeEnqueues(t *testing.T) {
	s := scratchStore(t)
	id1, _, err := s.StartPause("first", "alice", 1*time.Hour)
	require.NoError(t, err)
	// Drain the empty queue first (no supersede yet).
	drained, _ := s.DrainPendingAuditEvents(0)
	assert.Empty(t, drained)

	id2, _, err := s.StartPause("second", "bob", 1*time.Hour)
	require.NoError(t, err)
	require.NotEqual(t, id1, id2)

	drained, err = s.DrainPendingAuditEvents(0)
	require.NoError(t, err)
	require.Len(t, drained, 1,
		"second StartPause must enqueue ADMIN_FALLBACK_END for the superseded row")
	var payload struct {
		PauseID int64  `json:"pause_id"`
		EndKind string `json:"end_kind"`
	}
	require.NoError(t, json.Unmarshal([]byte(drained[0].PayloadJSON), &payload))
	assert.Equal(t, id1, payload.PauseID,
		"the SUPERSEDED row's id is what gets enqueued (not the new active one)")
	assert.Equal(t, "superseded", payload.EndKind)
}

// TestGetActivePause_ExpiryEnqueues verifies the wall-clock-expiry
// GC path also enqueues the synthetic so an expired pause that no
// one explicitly stopped still surfaces in the audit-export stream.
func TestGetActivePause_ExpiryEnqueues(t *testing.T) {
	s := scratchStore(t)
	// 1ms TTL — guaranteed to expire by the next GetActivePause call.
	id, _, err := s.StartPause("brief", "alice", 1*time.Millisecond)
	require.NoError(t, err)
	// Drain initial queue (empty — first pause never supersedes).
	_, _ = s.DrainPendingAuditEvents(0)

	time.Sleep(10 * time.Millisecond)

	// GetActivePause GCs expired rows + enqueues the synthetic.
	active, err := s.GetActivePause()
	require.NoError(t, err)
	assert.Nil(t, active, "expired pause must be gone after GC")

	drained, err := s.DrainPendingAuditEvents(0)
	require.NoError(t, err)
	require.Len(t, drained, 1, "expiry must enqueue exactly one synthetic")
	var payload struct {
		PauseID int64  `json:"pause_id"`
		EndKind string `json:"end_kind"`
	}
	require.NoError(t, json.Unmarshal([]byte(drained[0].PayloadJSON), &payload))
	assert.Equal(t, id, payload.PauseID)
	assert.Equal(t, "expired", payload.EndKind,
		"wall-clock expiry must stamp end_kind=expired")
}

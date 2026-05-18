// Cross-process audit-event poller per
// [[security-team-audit-export]] Slice 2 wiring.
//
// `dbounce pause stop` and `dbounce profile install` run in separate
// processes from `dbounce run` — the former two have no access to
// the run-process's wired audit.Exporter / audit.RuleEngine, so they
// CANNOT emit the ADMIN_FALLBACK_END / PROFILE_INSTALLED synthetics
// directly. The CLI side instead APPENDS rows to
// store.pending_audit_events; this poller drains the queue on a 1s
// tick + emits each row through the in-process Exporter / RuleEngine.
//
// Architecture decision (Option A from the spec):
//
//   - Single emit path. The run-process owns the audit-log file + the
//     webhook URL; a second exporter in the CLI would double-write.
//   - Matches the existing cross-process pattern. The burst sweeper's
//     applyProfileOverrideOnce already does CLI-writes-SQLite,
//     run-process-polls-SQLite; per the sync-prompt poll precedent
//     in d82ded9 the 1s cadence balances "SIEM expects prompt
//     visibility" against "no busy-loop when idle."
//   - Zero new third-party deps. Pure SQL on the existing store
//     pool.
//
// Per [[scorer-is-ground-truth]]: this poller NEVER processes
// decisions. Decisions go through the proxy hot-path's
// exportDecisionRowWithAgent + s.exportDecisionRow directly. This
// poller is for cross-process LIFECYCLE synthetics only.
//
// Per [[deliberate-feature-completion]]: 1s ticker + goroutine joins
// via connWG so Shutdown's existing drain semantics naturally cover
// it. Same shape as runBurstSweeper.
package proxy

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/store"
)

// auditEventsPollInterval is the cross-process audit-event drain
// cadence. 1s matches the sync-prompt poll precedent (d82ded9) +
// keeps SIEM ingest latency well under the "fresh visibility" bar
// operators expect after running `dbounce pause stop` /
// `dbounce profile install`. Not configurable in v1.0 per the audit-
// cadence discipline ("ship sane defaults; add a knob when an
// operator reports the default is wrong").
const auditEventsPollInterval = 1 * time.Second

// auditEventsMaxBatch caps the per-tick drain to bound memory + the
// per-tick CPU cost. 256 is the same ceiling
// store.DrainPendingAuditEvents enforces — symmetrically defended on
// both ends. Typical depth is 0 or 1; the cap is a defense-in-depth
// floor against runaway growth in a degraded state where the drain
// loop is starved.
const auditEventsMaxBatch = 256

// runPendingAuditEventsPoller is the Server's long-lived goroutine
// that drains store.pending_audit_events on its tick + emits each
// row through the wired Exporter / RuleEngine.
//
// Lifecycle:
//
//   - Started by Server.Serve via go s.runPendingAuditEventsPoller(ctx).
//   - Context cancellation is the stop signal. Server.Shutdown
//     cancels the context BEFORE waiting on connWG so the poller
//     drains its final tick promptly (matches the burst-sweeper +
//     heartbeater shutdown-ordering pattern).
//   - Joins via the same connWG the per-conn handlers use so the
//     Shutdown drain semantics naturally cover us.
//   - When neither Exporter nor RuleEngine is wired (FREE-tier
//     default), the drain still RUNS (rows would otherwise pile up
//     indefinitely in SQLite) — the per-row emit calls are
//     nil-safe + just discard the event.
func (s *Server) runPendingAuditEventsPoller(ctx context.Context) {
	s.connWG.Add(1)
	defer s.connWG.Done()
	t := time.NewTicker(auditEventsPollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.drainPendingAuditEventsOnce()
		}
	}
}

// drainPendingAuditEventsOnce reads up to auditEventsMaxBatch queue
// rows + emits each through the type-appropriate sink.
//
// Race-clean: store.DrainPendingAuditEvents SELECT+DELETEs inside one
// transaction, so two concurrent drainers (this poller + a test
// helper) never double-emit a single row. The emit calls themselves
// are nil-safe + best-effort per the Slice 2 spec.
func (s *Server) drainPendingAuditEventsOnce() {
	if s.store == nil {
		return
	}
	rows, err := s.store.DrainPendingAuditEvents(auditEventsMaxBatch)
	if err != nil {
		BumpLookupErrors()
		log.Warn().Err(err).
			Msg("dbounce: drain pending audit events failed")
		return
	}
	for _, r := range rows {
		s.emitDrainedAuditEvent(r)
	}
}

// emitDrainedAuditEvent dispatches one drained row to the
// type-appropriate emit method.
//
// Per-kind payload decoding is centralized here so each emit method
// receives a typed struct rather than a map. Unknown kinds are
// logged + dropped — a future schema-additive kind that an older
// run-process binary doesn't recognize will safely no-op rather than
// crash the poller.
func (s *Server) emitDrainedAuditEvent(r store.PendingAuditEvent) {
	switch r.Kind {
	case store.PendingAuditEventAdminFallbackEnd:
		var p adminFallbackEndPayload
		if err := json.Unmarshal([]byte(r.PayloadJSON), &p); err != nil {
			BumpLookupErrors()
			log.Warn().Err(err).
				Int64("queue_row_id", r.ID).
				Msg("dbounce: parse admin_fallback_end payload failed")
			return
		}
		s.emitAdminFallbackEnd(audit.AdminFallbackInfo{
			PauseID:   p.PauseID,
			StartedBy: p.StartedBy,
			Reason:    p.Reason,
			EndKind:   p.EndKind,
		})
	case store.PendingAuditEventProfileInstalled:
		var p profileInstalledPayload
		if err := json.Unmarshal([]byte(r.PayloadJSON), &p); err != nil {
			BumpLookupErrors()
			log.Warn().Err(err).
				Int64("queue_row_id", r.ID).
				Msg("dbounce: parse profile_installed payload failed")
			return
		}
		s.emitProfileInstalled(audit.ProfileInstalledInfo{
			SourceURL:      p.SourceURL,
			ProfileNames:   p.ProfileNames,
			SHA256:         p.SHA256,
			SHA256Verified: p.SHA256Verified,
			ProfilesPath:   p.ProfilesPath,
			InstalledBy:    p.InstalledBy,
			Dialects:       p.Dialects,
		})
	case store.PendingAuditEventAdminAction:
		var p adminActionPayload
		if err := json.Unmarshal([]byte(r.PayloadJSON), &p); err != nil {
			BumpLookupErrors()
			log.Warn().Err(err).
				Int64("queue_row_id", r.ID).
				Msg("dbounce: parse admin_action payload failed")
			return
		}
		s.emitAdminAction(audit.AdminActionInfo{
			Action:       p.Action,
			Actor:        p.Actor,
			ResourceType: p.ResourceType,
			ResourceID:   p.ResourceID,
			Result:       p.Result,
			Dialects:     p.Dialects,
			Details:      p.Details,
		})
	default:
		// Unknown kind: log + drop. The row is already deleted by
		// DrainPendingAuditEvents so no replay loop.
		log.Warn().
			Str("kind", string(r.Kind)).
			Int64("queue_row_id", r.ID).
			Msg("dbounce: unknown pending audit event kind; dropping")
	}
}

// adminFallbackEndPayload is the JSON shape store.buildAdminFallbackEndPayload
// writes. Mirrored here (rather than imported from store) because
// the poller needs the typed shape + the store package can't depend
// on the audit package (audit imports store) — the JSON layer is the
// natural decoupling boundary.
type adminFallbackEndPayload struct {
	PauseID   int64  `json:"pause_id"`
	StartedBy string `json:"started_by"`
	Reason    string `json:"reason"`
	EndKind   string `json:"end_kind"`
}

// profileInstalledPayload is the JSON shape the CLI's
// `dbounce profile install` enqueues per the
// [[security-team-audit-export]] Slice 2 wiring. Mirrors
// audit.ProfileInstalledInfo so the json.Unmarshal lands cleanly +
// the emit path is one struct-copy away.
type profileInstalledPayload struct {
	SourceURL      string   `json:"source_url"`
	ProfileNames   []string `json:"profile_names"`
	SHA256         string   `json:"sha256"`
	SHA256Verified bool     `json:"sha256_verified"`
	ProfilesPath   string   `json:"profiles_path"`
	InstalledBy    string   `json:"installed_by"`
	Dialects       []string `json:"dialects"`
}

// adminActionPayload is the JSON shape every admin CLI subcommand
// enqueues per the [[basic-app-hygiene-features]] TIER 1 #4 +
// [[security-team-audit-export]] admin-action wiring. Mirrors
// audit.AdminActionInfo so the json.Unmarshal lands cleanly + the
// emit path is one struct-copy away.
//
// Sibling agents in ibounce + kbounce ship the same payload shape +
// the same field names so the run-process drain code in all three
// products reads identically.
type adminActionPayload struct {
	Action       string         `json:"action"`
	Actor        string         `json:"actor"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Result       string         `json:"result"`
	Dialects     []string       `json:"dialects"`
	Details      map[string]any `json:"details"`
}

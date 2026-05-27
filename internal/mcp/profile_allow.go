// profile_allow.go — MCP tool handlers for #387 / §A25 Phase 2.

package mcp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/trsreagan3/dbounce/internal/profileallow"
	"github.com/trsreagan3/dbounce/internal/store"
)

func (s *Server) toolProfileAllow(args map[string]any) (map[string]any, error) {
	target, _ := args["target"].(string)
	reason, _ := args["reason"].(string)
	duration, _ := args["duration"].(string)
	profileName, _ := args["profile"].(string)

	var actions []string
	switch a := args["action"].(type) {
	case []any:
		for _, v := range a {
			if str, ok := v.(string); ok {
				actions = append(actions, str)
			}
		}
	case []string:
		actions = a
	case string:
		actions = []string{a}
	}

	activeName := ""
	if s.cfg.ActiveProfile != nil {
		activeName = s.cfg.ActiveProfile.Name
	}

	res, err := profileallow.AddProfileAllowRule(profileallow.Options{
		Target:        target,
		Actions:       actions,
		Reason:        reason,
		Duration:      duration,
		ProfileName:   profileName,
		ActiveProfile: activeName,
		ProfilesPath:  s.cfg.ProfilesPath,
		Source:        profileallow.SourceMCP,
		Actor:         s.cfg.Actor,
		// #391: wire the OCSF admin-action audit event via the same
		// cross-process pending_audit_events queue the CLI path uses.
		// The HTTP /admin/profile/allow endpoint enqueues the event;
		// the MCP path was the only surface missing the emit. Best-effort:
		// a queue-write failure is silently dropped (matches the CLI
		// enqueueAdminAction posture per [[creates-never-mutates]]).
		EmitAudit: s.mcpProfileAllowAuditEmitter(),
	})
	if err != nil {
		if perr, ok := err.(*profileallow.Error); ok {
			return map[string]any{
				"ok":      false,
				"error":   perr.Message,
				"code":    perr.Code,
				"details": perr.Details,
			}, nil
		}
		return nil, fmt.Errorf("dbounce_profile_allow: %w", err)
	}
	out := map[string]any{
		"ok":               true,
		"status":           res.Status,
		"profile_name":     res.ProfileName,
		"profile_path":     res.ProfilePath,
		"actions":          res.Actions,
		"target":           res.Target,
		"reason":           res.Reason,
		"duration":         res.Duration,
		"expires_at":       res.ExpiresAt,
		"actor":            res.Actor,
		"source":           res.Source,
		"rule_count_after": res.RuleCountAfter,
	}
	if res.PendingEntry != nil {
		out["pending_entry"] = res.PendingEntry
	}
	return out, nil
}

// mcpProfileAllowAuditEmitter returns a profileallow.EmitAuditFn that
// enqueues an ADMIN_ACTION pending audit event via the dbounce
// pending_audit_events SQLite queue. Best-effort: a nil store or a
// queue-write failure is silently dropped — matches the existing
// enqueueAdminAction posture in the CLI package (see
// internal/cli/admin_action.go).
//
// Per #391 / §B v1.1: the HTTP /admin/profile/allow endpoint emits
// the OCSF admin-action event; the MCP path (dbounce_profile_allow)
// was the only surface missing the emit. This method closes that gap
// so every dbounce_profile_allow MCP call produces an audit event
// visible to the running `dbounce run` process's poller.
func (s *Server) mcpProfileAllowAuditEmitter() profileallow.EmitAuditFn {
	if s.cfg.Store == nil {
		return nil
	}
	st := s.cfg.Store
	return func(ev profileallow.AuditEvent) {
		payload := map[string]any{
			"action":        ev.Action,
			"actor":         ev.Actor,
			"resource_type": ev.EntityKind,
			"resource_id":   ev.EntityName,
			"result":        "success",
			"details":       ev.Details,
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return // best-effort; don't surface marshal failure
		}
		_, _ = st.AddPendingAuditEvent(
			store.PendingAuditEventAdminAction, string(b))
	}
}

func (s *Server) toolDeniesRecent(args map[string]any) (map[string]any, error) {
	if s.cfg.Store == nil {
		return map[string]any{
			"ok":     false,
			"error":  "store_not_configured",
			"detail": "dbounce_denies_recent requires the MCP server to be wired with the SQLite store",
		}, nil
	}
	sinceStr := "5m"
	if v, ok := args["since"].(string); ok && v != "" {
		sinceStr = v
	}
	agentSession := ""
	if v, ok := args["agent_session"].(string); ok {
		agentSession = v
	}
	limit := 50
	switch v := args["limit"].(type) {
	case float64:
		limit = int(v)
	case int:
		limit = v
	}
	lower, perr := parseMCPSince(sinceStr)
	if perr != nil {
		return map[string]any{"ok": false, "error": "invalid_since", "detail": perr.Error()}, nil
	}
	rows, err := profileallow.RecentDenies(profileallow.RecentDeniesOptions{
		Store:          s.cfg.Store,
		Since:          lower,
		AgentSessionID: agentSession,
		Limit:          limit,
	})
	if err != nil {
		return nil, err
	}
	outRows := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		outRows = append(outRows, map[string]any{
			"when":                    r.When,
			"bouncer":                 r.Bouncer,
			"agent_session_id":        r.AgentSessionID,
			"action":                  r.Action,
			"resource":                r.Resource,
			"deny_reason":             r.DenyReason,
			"deny_source":             r.DenySource,
			"rule_id_if_dynamic":      r.RuleIDIfDynamic,
			"suggested_allow_command": r.SuggestedAllowCommand,
		})
	}
	return map[string]any{
		"ok":      true,
		"bouncer": "dbounce",
		"rows":    outRows,
		"count":   len(outRows),
	}, nil
}

func parseMCPSince(spec string) (time.Time, error) {
	s := spec
	if s == "" {
		return time.Time{}, nil
	}
	if len(s) >= 10 && (s[4] == '-' || containsT(s)) {
		t, err := time.Parse(time.RFC3339, s)
		if err == nil {
			return t, nil
		}
		return time.Time{}, err
	}
	if len(s) < 2 {
		return time.Time{}, fmt.Errorf("--since %q: too short", spec)
	}
	unit := s[len(s)-1]
	qty := 0
	for i := 0; i < len(s)-1; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return time.Time{}, fmt.Errorf("--since %q: non-numeric", spec)
		}
		qty = qty*10 + int(c-'0')
	}
	var d time.Duration
	switch unit {
	case 's':
		d = time.Duration(qty) * time.Second
	case 'm':
		d = time.Duration(qty) * time.Minute
	case 'h':
		d = time.Duration(qty) * time.Hour
	case 'd':
		d = time.Duration(qty) * 24 * time.Hour
	case 'w':
		d = time.Duration(qty) * 7 * 24 * time.Hour
	default:
		return time.Time{}, fmt.Errorf("--since %q: unknown unit %q", spec, string(unit))
	}
	return time.Now().UTC().Add(-d), nil
}

func containsT(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 'T' {
			return true
		}
	}
	return false
}

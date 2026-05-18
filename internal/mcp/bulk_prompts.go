// MCP tool handlers for the bulk-prompt-answer UX per
// [[bulk-prompt-answer-ux]].
//
// Two tools surfaced:
//
//   dbounce_prompts_bulk_pending  read-only burst summary
//   dbounce_prompts_bulk_answer   mutating bulk-answer; GATED behind
//                                 the operator-set token. Default OFF.
//
// The gating story: per the memo "Don't expose the burst-answer
// affordance to the AGENT without operator opt-in." A blank token in
// the server config refuses every call to the mutating tool. An
// operator who wants to let an agent call it sets
// --bulk-answer-mcp-token=$(uuidgen) at server start + shares the
// token with the agent out-of-band. Adversarial agent + no operator
// help → no bulk-allow.

package mcp

import (
	"fmt"
	"os/user"
	"strings"
	"time"

	"github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
)

// toolPromptsBulkPending returns the burst summary. Read-only; no
// token gate.
func (s *Server) toolPromptsBulkPending(_ map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	summary, err := s.cfg.Store.ListBulkPendingPrompts()
	if err != nil {
		return nil, err
	}
	entries := make([]map[string]any, 0, len(summary.Entries))
	for _, e := range summary.Entries {
		entries = append(entries, map[string]any{
			"dialect":        e.Key.Dialect,
			"statement_type": e.Key.StatementType,
			"table":          e.Key.Table,
			"prompt_ids":     append([]int64{}, e.PromptIDs...),
			"count":          len(e.PromptIDs),
			"sample_reason":  e.SampleReason,
		})
	}
	return map[string]any{
		"total_prompts": summary.TotalPrompts,
		"dialects":      summary.Dialects,
		"entries":       entries,
		// burst_armed is the in-memory burst-detector signal. In the
		// standalone `dbounce mcp` invocation the proxy is in a
		// separate process so the MCP server has no visibility into
		// the detector — surfaced as false. When the MCP server is
		// embedded (future), this reflects the live signal. The
		// summary itself is authoritative either way (it's the SQLite
		// pending-prompt count).
		"burst_armed": false,
	}, nil
}

// toolPromptsBulkAnswer applies one decision across all currently-
// pending prompts. Token-gated.
func (s *Server) toolPromptsBulkAnswer(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	// Token gate. Default-disabled: when the operator hasn't
	// configured a token, the mutating tool refuses every call —
	// even calls that supply a non-empty token. This is the safe
	// posture per [[bulk-prompt-answer-ux]] "DEFAULT: bulk-answer
	// MCP tool is GATED behind an operator-set token (a CLI flag
	// the operator sets per-session; the agent must include it in
	// the tool call). Off by default."
	if s.cfg.BulkAnswerToken == "" {
		return map[string]any{
			"error":     "disabled",
			"reason":    "dbounce_prompts_bulk_answer is GATED behind --bulk-answer-mcp-token; the operator has not configured a token. Per [[bulk-prompt-answer-ux]] this is the default to prevent an adversarial agent from bulk-allowing itself.",
		}, nil
	}
	suppliedToken := stringArg(args, "token", "")
	if suppliedToken == "" || suppliedToken != s.cfg.BulkAnswerToken {
		return map[string]any{
			"error":  "invalid_token",
			"reason": "the `token` argument MUST match the operator-set --bulk-answer-mcp-token value",
		}, nil
	}
	decision := strings.ToLower(strings.TrimSpace(stringArg(args, "decision", "")))
	profileName := strings.TrimSpace(stringArg(args, "profile_name", ""))
	switch decision {
	case "10min", "3h", "session", "profile", "none":
		// OK
	default:
		return nil, fmt.Errorf(
			"dbounce_prompts_bulk_answer: decision must be one of 10min|3h|session|profile|none (got %q)",
			decision)
	}
	if decision == "profile" && profileName == "" {
		return nil, fmt.Errorf(
			"dbounce_prompts_bulk_answer: decision='profile' requires profile_name")
	}
	st := s.cfg.Store
	summary, err := st.ListBulkPendingPrompts()
	if err != nil {
		return nil, err
	}
	by := s.resolveActor()

	if decision == "none" {
		return map[string]any{
			"applied":          "none",
			"total_prompts":    summary.TotalPrompts,
			"rules_created":    0,
			"prompts_answered": 0,
		}, nil
	}

	totalPromptIDs := make([]int64, 0, summary.TotalPrompts)
	for _, e := range summary.Entries {
		totalPromptIDs = append(totalPromptIDs, e.PromptIDs...)
	}
	totalPromptIDs = dedupInt64MCP(totalPromptIDs)

	if decision == "profile" {
		if perr := st.SetProfileOverride(profileName, by, "mcp bulk-answer"); perr != nil {
			return nil, perr
		}
		updated, uerr := st.AnswerPendingPromptsBulk(totalPromptIDs,
			"bulk-profile-swap", profileName, by)
		if uerr != nil {
			return nil, uerr
		}
		// Wake sync waiters with PromptDecisionAllow (operator picked
		// a broader profile → the blocked calls likely proceed under
		// it; per the cross-product permissive default per
		// [[safety-mode-lean-permissive]]).
		s.wakeSyncWaiters(totalPromptIDs, store.PromptDecisionAllow)
		return map[string]any{
			"applied":           "profile",
			"profile_name":      profileName,
			"hot_swap_pending":  true,
			"total_prompts":     summary.TotalPrompts,
			"prompts_answered":  updated,
			"rules_created":     0,
			"info":              "running proxy picks up the hot-swap within ~5s via the burst sweeper",
		}, nil
	}

	// Time-bounded ALLOW path.
	ttl := mcpDecisionTTL(decision)
	expiresAt := time.Now().UTC().Add(ttl)
	createdRules := 0
	createdPatterns := make([]map[string]any, 0, len(summary.Entries))
	for _, e := range summary.Entries {
		pattern := fmt.Sprintf("%s:%s", e.Key.StatementType, e.Key.Table)
		note := fmt.Sprintf(
			"mcp bulk-answer %s (decision=%s, dialect=%s, prompts=%d, expires_at=%s)",
			by, decision, e.Key.Dialect, len(e.PromptIDs),
			expiresAt.Format("2006-01-02T15:04:05Z"))
		r := rules.ProxyRule{
			Pattern: pattern,
			Effect:  rules.EffectAllow,
			Origin:  rules.OriginUser,
			Note:    note,
		}
		ruleID, addErr := st.AddRuleWithExpiry(r, expiresAt)
		if addErr != nil {
			return nil, fmt.Errorf("add bulk-allow rule (pattern=%q): %w", pattern, addErr)
		}
		createdRules++
		createdPatterns = append(createdPatterns, map[string]any{
			"id":      int64(ruleID),
			"dialect": e.Key.Dialect,
			"pattern": pattern,
		})
	}
	answerKind := "bulk-allow-" + decision
	updated, uerr := st.AnswerPendingPromptsBulk(totalPromptIDs, answerKind, "", by)
	if uerr != nil {
		return nil, uerr
	}
	s.wakeSyncWaiters(totalPromptIDs, store.PromptDecisionAllow)
	return map[string]any{
		"applied":          decision,
		"ttl":              ttl.String(),
		"expires_at":       expiresAt.Format("2006-01-02T15:04:05Z"),
		"total_prompts":    summary.TotalPrompts,
		"prompts_answered": updated,
		"rules_created":    createdRules,
		"rules":            createdPatterns,
	}, nil
}

func (s *Server) wakeSyncWaiters(promptIDs []int64, decision store.PromptDecision) {
	if len(promptIDs) == 0 || s.cfg.Store == nil {
		return
	}
	waiters, err := s.cfg.Store.SyncWaitIDsForPromptIDs(promptIDs)
	if err != nil {
		return
	}
	for _, waitID := range waiters {
		// Best-effort: a missing waiter (timed-out / cancelled) is
		// not an error.
		_, _ = s.cfg.Store.WakeSyncPendingPrompt(waitID, decision)
	}
}

// resolveActor returns the operator id to stamp on the bulk-answer
// rows. Prefers cfg.Actor when set; falls back to $USER then
// "dbounce-mcp".
func (s *Server) resolveActor() string {
	if s.cfg.Actor != "" {
		return s.cfg.Actor
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "dbounce-mcp"
}

func mcpDecisionTTL(decision string) time.Duration {
	switch decision {
	case "10min":
		return 10 * time.Minute
	case "3h":
		return 3 * time.Hour
	case "session":
		return 60 * time.Minute
	}
	return 10 * time.Minute
}

func dedupInt64MCP(in []int64) []int64 {
	if len(in) < 2 {
		return in
	}
	seen := make(map[int64]struct{}, len(in))
	out := make([]int64, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

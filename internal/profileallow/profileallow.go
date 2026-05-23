// Package profileallow implements the per-bouncer "easy profile
// extension" surface for dbounce — the symmetric flip of dynamic-
// deny rules.
//
// #387 / §A25 Phase 2 (dbounce). Mirrors the iam-jit Python
// profile_allow module (iam-roles commit 99ca1b6) + the kbouncer
// #386 sibling so the cross-product UX stays parity-aligned per
// [[cross-product-agent-parity]].
//
// Single entry point: AddProfileAllowRule. The pending-approval
// queue path is SHARED across all bouncers
// (~/.iam-jit/bouncer/profile-allow-pending.jsonl) so an operator-
// review surface (Phase 3) sees every bouncer's pending entries.
//
// Per [[creates-never-mutates]]: additive — new code, new package,
// no refactor of the existing dbounce profile package.

package profileallow

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/trsreagan3/dbounce/internal/profile"
)

const (
	AllowAgentSelfGrantEnv  = "IAM_JIT_BOUNCER_ALLOW_AGENT_SELF_GRANT"
	PendingApprovalsPathEnv = "IAM_JIT_PROFILE_ALLOW_PENDING_PATH"
	EasyAllowOriginTag      = "[easy_allow]"

	SourceCLI        = "cli"
	SourceMCP        = "mcp"
	SourceMCPPending = "mcp_pending"
)

var agentSources = map[string]struct{}{SourceMCP: {}}

// AdminActionProfileAllowAdded + AdminActionProfileAllowRequestedByAgent
// are the cross-product wire-stable strings emitted via EmitAuditFn.
const (
	AdminActionProfileAllowAdded            = "profile.allow.added"
	AdminActionProfileAllowRequestedByAgent = "profile.allow.requested_by_agent"
)

// AuditEvent carries the data the bouncer-specific audit emitter
// needs to construct a wire event. The profileallow package never
// constructs OCSF events directly — it hands the data off via the
// EmitAuditFn callback so each bouncer can route through its own
// pending-audit-events queue / LogWriter / Emitter.
type AuditEvent struct {
	Action       string
	Actor        string
	Source       string
	EntityName   string
	EntityKind   string
	ResourceType string
	ResourceID   string
	Details      map[string]any
}

// EmitAuditFn is the bouncer-specific audit hook. nil = no-op.
type EmitAuditFn func(AuditEvent)

// Error is the structured operations-layer error.
type Error struct {
	Code    string
	Message string
	Details map[string]any
}

func (e *Error) Error() string { return e.Message }

func newErr(code, msg string) *Error                              { return &Error{Code: code, Message: msg} }
func newErrDetail(code, msg string, d map[string]any) *Error      { return &Error{Code: code, Message: msg, Details: d} }

// Options tunes a single AddProfileAllowRule invocation.
type Options struct {
	Target              string
	Actions             []string
	Reason              string
	Duration            string
	ProfileName         string
	ActiveProfile       string
	Source              string
	Actor               string
	ProfilesPath        string
	QueuePath           string
	AllowAgentSelfGrant *bool
	EmitAudit           EmitAuditFn
}

// Result summarizes the outcome.
type Result struct {
	Status         string
	ProfileName    string
	ProfilePath    string
	Actions        []string
	Target         string
	Reason         string
	Duration       string
	ExpiresAt      string
	Actor          string
	Source         string
	RuleCountAfter int
	PendingEntry   map[string]any
}

// AddProfileAllowRule appends a profile allow rule (or queues it for
// approval). The single entry point both the CLI command + the MCP
// tool dispatch into.
func AddProfileAllowRule(opts Options) (*Result, error) {
	if err := validateTargetActions(opts.Target, opts.Actions); err != nil {
		return nil, err
	}
	if strings.TrimSpace(opts.Reason) == "" {
		return nil, newErr("missing_reason",
			"--reason is required (surfaces in note + audit event)")
	}

	source := opts.Source
	if source == "" {
		source = SourceCLI
	}
	actor := strings.TrimSpace(opts.Actor)
	if actor == "" {
		actor = resolveActor()
	}
	durationStr, expiresAt := parseDurationToExpiry(opts.Duration)

	profilesPath := opts.ProfilesPath
	if profilesPath == "" {
		p, err := profile.DefaultProfilesPath()
		if err != nil {
			return nil, fmt.Errorf("dbounce: resolve profiles path: %w", err)
		}
		profilesPath = p
	}

	profiles, lerr := profile.LoadProfiles(profilesPath)
	if lerr != nil {
		return nil, fmt.Errorf("dbounce: load profiles: %w", lerr)
	}

	targetName := opts.ProfileName
	if targetName == "" {
		targetName = opts.ActiveProfile
	}
	if targetName == "" {
		targetName = profile.FullUserProfileName
	}
	targetProfile, perr := profiles.Active(targetName)
	if perr != nil {
		return nil, newErrDetail("profile_not_found",
			fmt.Sprintf("profile %q not found; available: %s",
				targetName, strings.Join(profiles.NamesSorted(), ", ")),
			map[string]any{"profile_name": targetName})
	}

	if err := refuseOrgDistributed(targetProfile); err != nil {
		return nil, err
	}

	selfGrantEnabled := agentSelfGrantEnabled(opts.AllowAgentSelfGrant)
	isAgent := isAgentSource(source)
	queued := isAgent && !selfGrantEnabled

	if queued {
		entry, qerr := enqueuePending(pendingEntryInput{
			Target:      opts.Target,
			Actions:     opts.Actions,
			Reason:      strings.TrimSpace(opts.Reason),
			Duration:    durationStr,
			ExpiresAt:   expiresAt,
			ProfileName: targetProfile.Name,
			Actor:       actor,
			Source:      source,
			Bouncer:     "dbounce",
		}, opts.QueuePath)
		if qerr != nil {
			return nil, fmt.Errorf("dbounce: enqueue pending: %w", qerr)
		}
		emit(opts.EmitAudit, AuditEvent{
			Action:     AdminActionProfileAllowRequestedByAgent,
			Actor:      actor,
			Source:     source,
			EntityKind: "profile",
			EntityName: targetProfile.Name,
			Details: map[string]any{
				"target":     opts.Target,
				"actions":    opts.Actions,
				"reason":     strings.TrimSpace(opts.Reason),
				"pending_id": entry["id"],
				"status":     "pending_approval",
			},
		})
		return &Result{
			Status:         "pending_approval",
			ProfileName:    targetProfile.Name,
			ProfilePath:    "",
			Actions:        append([]string(nil), opts.Actions...),
			Target:         opts.Target,
			Reason:         strings.TrimSpace(opts.Reason),
			Duration:       durationStr,
			ExpiresAt:      expiresAt,
			Actor:          actor,
			Source:         source,
			RuleCountAfter: len(targetProfile.AllowRules),
			PendingEntry:   entry,
		}, nil
	}

	note := buildProvenanceNote(noteInput{
		Reason:    strings.TrimSpace(opts.Reason),
		Actor:     actor,
		Source:    source,
		Duration:  durationStr,
		ExpiresAt: expiresAt,
	})
	newRules := append([]profile.ProfileAllowRule(nil), targetProfile.AllowRules...)
	for _, act := range opts.Actions {
		newRules = append(newRules, profile.ProfileAllowRule{
			Pattern:  act,
			ArnScope: opts.Target,
			Note:     note,
		})
	}
	targetProfile.AllowRules = newRules
	if err := profile.UpsertProfile(targetProfile, profilesPath); err != nil {
		return nil, fmt.Errorf("dbounce: upsert profile: %w", err)
	}

	emit(opts.EmitAudit, AuditEvent{
		Action:     AdminActionProfileAllowAdded,
		Actor:      actor,
		Source:     source,
		EntityKind: "profile",
		EntityName: targetProfile.Name,
		Details: map[string]any{
			"target":     opts.Target,
			"actions":    opts.Actions,
			"reason":     strings.TrimSpace(opts.Reason),
			"duration":   durationStr,
			"expires_at": expiresAt,
		},
	})

	return &Result{
		Status:         "applied",
		ProfileName:    targetProfile.Name,
		ProfilePath:    profilesPath,
		Actions:        append([]string(nil), opts.Actions...),
		Target:         opts.Target,
		Reason:         strings.TrimSpace(opts.Reason),
		Duration:       durationStr,
		ExpiresAt:      expiresAt,
		Actor:          actor,
		Source:         source,
		RuleCountAfter: len(newRules),
		PendingEntry:   nil,
	}, nil
}

func validateTargetActions(target string, actions []string) *Error {
	if strings.TrimSpace(target) == "" {
		return newErr("missing_target", "--target is required")
	}
	if strings.TrimSpace(target) == "*" {
		return newErr("target_too_broad",
			"--target '*' is refused; profile allows must be specific. "+
				"Use a hostname glob (e.g. *.staging.internal) or an exact "+
				"identifier. Per [[creates-never-mutates]] the easy-allow "+
				"surface is deliberately narrower than 'allow everything'.")
	}
	if len(actions) == 0 {
		return newErr("missing_action",
			"--action is required (one or more statement_type:table_glob strings)")
	}
	for _, a := range actions {
		if strings.TrimSpace(a) == "" || !strings.Contains(a, ":") {
			return newErr("bad_action",
				fmt.Sprintf("action %q must be a 'verb:resource' string "+
					"(e.g. SELECT:public.users)", a))
		}
	}
	return nil
}

func refuseOrgDistributed(p *profile.Profile) *Error {
	if p == nil {
		return newErr("profile_not_found", "no active profile")
	}
	if !p.IsLocalSource() {
		return newErrDetail("org_distributed",
			fmt.Sprintf("profile %q is org-distributed (source=%q) and "+
				"read-only at the easy-allow surface.", p.Name, p.Source),
			map[string]any{"profile_name": p.Name, "source": p.Source})
	}
	return nil
}

func agentSelfGrantEnabled(override *bool) bool {
	if override != nil {
		return *override
	}
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(AllowAgentSelfGrantEnv)))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func isAgentSource(s string) bool {
	_, ok := agentSources[s]
	return ok
}

func parseDurationToExpiry(d string) (string, string) {
	s := strings.TrimSpace(d)
	if s == "" || s == "permanent" {
		return "", ""
	}
	var dur time.Duration
	switch {
	case strings.HasSuffix(s, "d"):
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return s, ""
		}
		dur = time.Duration(n) * 24 * time.Hour
	case strings.HasSuffix(s, "w"):
		n, err := strconv.Atoi(strings.TrimSuffix(s, "w"))
		if err != nil {
			return s, ""
		}
		dur = time.Duration(n) * 7 * 24 * time.Hour
	default:
		parsed, perr := time.ParseDuration(s)
		if perr != nil {
			return s, ""
		}
		dur = parsed
	}
	exp := time.Now().UTC().Add(dur).Truncate(time.Second)
	return s, exp.Format("2006-01-02T15:04:05Z")
}

type noteInput struct {
	Reason    string
	Actor     string
	Source    string
	Duration  string
	ExpiresAt string
}

func buildProvenanceNote(in noteInput) string {
	base := fmt.Sprintf("%s %s -- by=%s via=%s",
		EasyAllowOriginTag, in.Reason, in.Actor, in.Source)
	if in.ExpiresAt != "" {
		return base + " expires=" + in.ExpiresAt
	}
	if in.Duration != "" {
		return base + " duration=" + in.Duration
	}
	return base
}

func resolveActor() string {
	for _, k := range []string{"USER", "LOGNAME"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return "local-operator"
}

// ---------------------------------------------------------------------
// Pending queue (SHARED PATH across bouncers per
// [[cross-product-agent-parity]])
// ---------------------------------------------------------------------

type pendingEntryInput struct {
	Target      string
	Actions     []string
	Reason      string
	Duration    string
	ExpiresAt   string
	ProfileName string
	Actor       string
	Source      string
	Bouncer     string
}

func ResolvePendingPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := strings.TrimSpace(os.Getenv(PendingApprovalsPathEnv)); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".iam-jit", "bouncer", "profile-allow-pending.jsonl"), nil
}

func enqueuePending(in pendingEntryInput, explicitPath string) (map[string]any, error) {
	qp, err := ResolvePendingPath(explicitPath)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(qp); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	entry := map[string]any{
		"id":           newPendingID(),
		"requested_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"target":       in.Target,
		"actions":      in.Actions,
		"reason":       in.Reason,
		"duration":     in.Duration,
		"expires_at":   in.ExpiresAt,
		"profile_name": in.ProfileName,
		"actor":        in.Actor,
		"source":       in.Source,
		"bouncer":      in.Bouncer,
		"status":       "pending",
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(qp, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return nil, err
	}
	_ = os.Chmod(qp, 0o600)
	return entry, nil
}

func ListPending(explicitPath string) ([]map[string]any, error) {
	qp, err := ResolvePendingPath(explicitPath)
	if err != nil {
		return nil, err
	}
	raw, rerr := os.ReadFile(qp)
	if rerr != nil {
		if errors.Is(rerr, os.ErrNotExist) {
			return nil, nil
		}
		return nil, rerr
	}
	out := []map[string]any{}
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		if s == "" {
			continue
		}
		var entry map[string]any
		if jerr := json.Unmarshal([]byte(s), &entry); jerr != nil {
			continue
		}
		out = append(out, entry)
	}
	return out, nil
}

const ulidAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func newPendingID() string {
	now := uint64(time.Now().UTC().UnixMilli()) & ((1 << 48) - 1)
	rnd := make([]byte, 10)
	_, _ = rand.Read(rnd)
	tsChars := make([]byte, 10)
	for i := 9; i >= 0; i-- {
		tsChars[i] = ulidAlphabet[now&0x1F]
		now >>= 5
	}
	randChars := make([]byte, 16)
	var bits uint64
	var nbits uint
	idx := 0
	for _, b := range rnd {
		bits = (bits << 8) | uint64(b)
		nbits += 8
		for nbits >= 5 {
			nbits -= 5
			randChars[idx] = ulidAlphabet[(bits>>nbits)&0x1F]
			idx++
			if idx == 16 {
				break
			}
		}
		if idx == 16 {
			break
		}
	}
	return "pa_" + string(tsChars) + string(randChars)
}

func emit(fn EmitAuditFn, ev AuditEvent) {
	if fn == nil {
		return
	}
	fn(ev)
}

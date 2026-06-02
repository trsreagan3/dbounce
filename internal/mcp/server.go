// Package mcp implements dbounce's MCP (Model Context Protocol) server.
//
// D-Slice 7 — the MCP-over-stdio shape that Claude Code, Cursor,
// Codex, and Devin all consume. An agent client connects to `dbounce
// mcp`, discovers the tools via JSON-RPC 2.0 `tools/list`, and
// invokes them with `tools/call`. Mirrors the Python iam-jit-bouncer
// MCP tool family (`bouncer_*`) and kbouncer's MCP tool family
// (`kbounce_*`) so an operator who already learned one tool surface
// understands the other.
//
// Implementation notes:
//
//   - Hand-rolled JSON-RPC 2.0 loop over stdin/stdout. No external
//     MCP library dependency.
//   - Tools are dispatched via a string → handler map.
//   - Tools that READ state read it FRESH on every call (no caching).
//
// Audit-cadence notes (per [[audit-cadence-discipline]]):
//
//   - MCP tools that MUTATE (dbounce_add_rule, dbounce_remove_rule)
//     flow through the SAME store API + same input validation as the
//     CLI. There is no MCP-specific bypass surface.
//   - dbounce_recommend_mode_for_task is DETERMINISTIC, per
//     [[bouncer-mode-selection-for-agents]]. No LLM call.
//   - Agent-impersonation surface: the MCP server runs as the
//     operator who started `dbounce mcp`. The agent that connects can
//     do EXACTLY what dbounce-the-process can do — no more.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/parser"
	"github.com/trsreagan3/dbounce/internal/posture"
	"github.com/trsreagan3/dbounce/internal/presets"
	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
	"github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/store"
	"github.com/trsreagan3/dbounce/internal/tasks"
)

// ProtocolVersion is the MCP protocol version we advertise. Tracks
// the 2024-11-05 spec; Python + kbouncer advertise the same.
const ProtocolVersion = "2024-11-05"

// ServerName / ServerVersion identify the server to MCP clients.
const (
	ServerName    = "dbounce"
	ServerVersion = "1.0.0"
)

// maxToolCallParamsBytes caps the raw JSON-RPC `params` payload for
// `tools/call`. Bounded BEFORE per-tool dispatch so a runaway / hostile
// agent can't burn parser CPU on multi-MB SQL strings (within the
// 4 MiB scanner buffer). 16 KiB is generous for any single legitimate
// SQL statement plus its tool-args envelope. MED-D8-11 closure.
const maxToolCallParamsBytes = 16 * 1024

// Config wires the MCP server to the live dbounce state on disk.
// All fields are optional — a tool that needs something it doesn't
// have surfaces a clear error to the caller.
type Config struct {
	// Store is the SQLite handle the rules / tasks / audit tools
	// consult. Nil disables those tools.
	Store *store.Store

	// ActiveProfile names the profile currently bound to the running
	// proxy. May be nil (full-user equivalent).
	ActiveProfile *profile.Profile

	// ProfilesPath is the path to the profiles.yaml currently in use.
	ProfilesPath string

	// Mode is the cooperative/transparent mode the running proxy was
	// started with. Surfaced by dbounce_active_mode.
	Mode proxy.Mode

	// DefaultPolicy mirrors the proxy's default-policy flag.
	DefaultPolicy proxy.DefaultPolicy

	// Dialect mirrors the proxy's dialect flag.
	Dialect proxy.Dialect

	// TaskOwner is the owner slot the running proxy is bound to.
	TaskOwner string

	// Actor is the string recorded in audit rows when MCP-initiated
	// mutations land. Defaults to "dbounce-mcp" when empty.
	Actor string

	// AuditExporter, when non-nil, surfaces the #252 Slice 1
	// audit-export transport status via the dbounce_audit_export_status
	// tool. Nil = the tool reports {configured: false}. The MCP server
	// reads the exporter's Stats() snapshot; the dbounce_decide MCP
	// tool's [[agent-identity-in-audit]] wiring ALSO calls Emit on it
	// to surface SESSION_ENDED on stdio close — the only write the MCP
	// server makes against the exporter. The proxy owns the per-decision
	// write path; this is the bookkeeping-event surface only.
	AuditExporter *audit.Exporter

	// AgentRegistry is the per-process registry of live agent sessions
	// per [[agent-identity-in-audit]]. May be nil when MCP is run
	// standalone (the install-* / show-config / list-tools subcommands
	// + when no audit-export is wired); when non-nil, the server mints
	// a session id at `initialize` time + retires it on Serve return,
	// emitting SESSION_ENDED via AuditExporter.
	//
	// Wiring: the proxy.Server creates ONE AgentRegistry that both the
	// SQL listener + the MCP server share, so a SIEM consumer joining
	// on session_id can correlate MCP tool calls + SQL gated decisions
	// from the same agent process. When MCP is standalone (`dbounce
	// mcp serve` not invoked from inside a proxy), pass nil; the MCP
	// server creates its own private registry so per-call session id
	// + SESSION_ENDED still work, just without cross-process
	// correlation.
	AgentRegistry *audit.AgentRegistry

	// Host is the listener-equivalent address stamped onto SESSION_ENDED
	// events emitted by the MCP server. Defaults to "mcp-stdio" when
	// empty — the MCP server doesn't bind a network listener so there
	// is no real host:port; the constant identifies the transport.
	Host string

	// BulkAnswerToken gates the dbounce_prompts_bulk_answer MCP tool
	// per [[bulk-prompt-answer-ux]] "Don't expose the burst-answer
	// affordance to the AGENT without operator opt-in." When empty
	// (default), the tool returns {error: 'disabled'}; when non-empty,
	// the caller's `token` argument MUST match exactly or the call is
	// refused. The operator sets this via `dbounce mcp serve
	// --bulk-answer-mcp-token TOKEN`. Pre-launch invariant: an
	// adversarial agent calling the MCP tool to bulk-allow itself
	// MUST be refused by default. Composes with
	// [[ibounce-honest-positioning]] (deterrent UX, not adversarial
	// boundary — but the default-disabled posture closes the
	// trivially-exploitable case).
	BulkAnswerToken string
}

// Server is the MCP-over-stdio server.
type Server struct {
	cfg Config
	mu  sync.Mutex

	// sessionID is the per-MCP-connection agent session id minted at
	// initialize time per [[agent-identity-in-audit]] Feature 2. Bound
	// to the connection's lifetime: mint on the first `initialize`
	// request, retire on Serve() return (the stdio peer closed). The
	// AgentRegistry binding stores the parsed clientInfo (name +
	// version + DetectedFromMCPClientInfo) so subsequent audit events
	// from the SAME stdio session can JOIN on the session id.
	//
	// Read by the test path only — production code threads sessionID
	// through directly. Atomic-friendly access via mu.
	sessionID string
}

// NewServer constructs an MCP server from the given config.
//
// [[agent-identity-in-audit]] wiring: when cfg.AgentRegistry is nil,
// the server creates its own private registry so per-connection session
// id minting + SESSION_ENDED still work in the standalone `dbounce mcp
// serve` invocation. When the caller passes a shared registry (e.g. a
// future deployment where MCP + proxy share a process), cross-channel
// session correlation is preserved.
func NewServer(cfg Config) *Server {
	if cfg.Actor == "" {
		cfg.Actor = "dbounce-mcp"
	}
	if cfg.AgentRegistry == nil {
		cfg.AgentRegistry = audit.NewAgentRegistry()
	}
	if cfg.Host == "" {
		cfg.Host = "mcp-stdio"
	}
	return &Server{cfg: cfg}
}

// SessionID returns the per-connection agent session id minted at MCP
// `initialize` time. Returns empty until initialize fires. Exported
// for test inspection — production callers route through the audit
// pipeline.
func (s *Server) SessionID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionID
}

// Serve runs the JSON-RPC loop. One request per line on `in`; one
// response per line on `out`. Blocks until `in` returns io.EOF.
//
// [[agent-identity-in-audit]] Feature 2: on return (the stdio peer
// closed, which means the agent exited), retire the per-connection
// session id from the AgentRegistry + emit a SESSION_ENDED synthetic
// event via the configured AuditExporter so a SIEM consumer can JOIN
// every preceding event from that session_id against this terminator.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	defer s.retireSessionAndEmit()
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req rawRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(errResponse(nil, -32700, fmt.Sprintf("parse error: %v", err)))
			continue
		}
		resp := s.dispatch(req)
		if resp == nil {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return fmt.Errorf("mcp: encode response: %w", err)
		}
	}
	return scanner.Err()
}

// retireSessionAndEmit removes this connection's session id from the
// AgentRegistry + emits a SESSION_ENDED synthetic event via the
// configured AuditExporter. Idempotent — calling twice (defer + an
// explicit teardown) does not double-emit; Retire returns ok=false on
// the second call so the emit branch short-circuits.
//
// No-op when AgentRegistry is nil OR sessionID is empty (initialize
// never fired) OR AuditExporter is nil.
func (s *Server) retireSessionAndEmit() {
	s.mu.Lock()
	sid := s.sessionID
	s.sessionID = ""
	s.mu.Unlock()
	if sid == "" || s.cfg.AgentRegistry == nil {
		return
	}
	agent, ok := s.cfg.AgentRegistry.Retire(sid)
	if !ok || s.cfg.AuditExporter == nil || !s.cfg.AuditExporter.Enabled() {
		return
	}
	host := s.cfg.Host
	if host == "" {
		host = "mcp-stdio"
	}
	evt := audit.NewSessionEndedEvent(agent, host)
	_ = s.cfg.AuditExporter.Emit(context.Background(), evt)
}

// mintSessionFromClientInfo registers the MCP client's reported
// clientInfo block in the AgentRegistry + binds the minted session id
// to this Server. Called from the `initialize` handler.
//
// Per [[agent-identity-in-audit]] Feature 1: the MCP clientInfo block
// is the HIGHEST-confidence agent signal — the MCP spec defines a
// `clientInfo: {name, version}` block that honest clients always send.
// detected_from is stamped as DetectedFromMCPClientInfo to distinguish
// from the SQL-dialect heuristics. Idempotent: re-mint on a second
// initialize (a peer that re-handshakes mid-session) is allowed +
// rotates the session id (the new id is recorded as the active one;
// the previous id is retired with a SESSION_ENDED event so SIEM
// reviewers can trace the reset).
func (s *Server) mintSessionFromClientInfo(name, version string) {
	if s.cfg.AgentRegistry == nil {
		return
	}
	agent := audit.MCPClientInfoToAgent(name, version)
	newID := s.cfg.AgentRegistry.Mint(agent)
	s.mu.Lock()
	prev := s.sessionID
	s.sessionID = newID
	s.mu.Unlock()
	// On re-init, fire the SESSION_ENDED for the previous id so the
	// SIEM sees a clean state machine.
	if prev != "" && prev != newID {
		if oldAgent, ok := s.cfg.AgentRegistry.Retire(prev); ok &&
			s.cfg.AuditExporter != nil && s.cfg.AuditExporter.Enabled() {
			host := s.cfg.Host
			if host == "" {
				host = "mcp-stdio"
			}
			evt := audit.NewSessionEndedEvent(oldAgent, host)
			_ = s.cfg.AuditExporter.Emit(context.Background(), evt)
		}
	}
}

type rawRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (s *Server) dispatch(req rawRequest) any {
	switch req.Method {
	case "initialize":
		// [[agent-identity-in-audit]] Feature 1: capture clientInfo
		// from the initialize params + mint a per-connection session id.
		// The MCP spec defines `clientInfo: {name, version}` as part of
		// the InitializeParams payload; honest clients (Claude Code,
		// Cursor, Codex, Devin) always send it. Per the memo we DON'T
		// reject when clientInfo is missing — name falls back to
		// "unknown" + the session id still mints so SESSION_ENDED
		// still emits on close.
		var p struct {
			ClientInfo struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"clientInfo"`
		}
		_ = json.Unmarshal(req.Params, &p)
		s.mintSessionFromClientInfo(p.ClientInfo.Name, p.ClientInfo.Version)
		return okResponse(req.ID, map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{
				"name":    ServerName,
				"version": ServerVersion,
			},
		})
	case "tools/list":
		return okResponse(req.ID, map[string]any{"tools": ToolDescriptors()})
	case "tools/call":
		// MED-D8-11 (AUDIT-WB-DSLICES-1-8.md) closure: bound the
		// per-call argument size. Without a cap, a runaway / malicious
		// agent can submit multi-MB SQL strings (within the 4 MiB line
		// buffer) and burn parser CPU + memory in libpg_query /
		// xwb1989 / the Snowflake-BigQuery prefix scan. 16 KiB is
		// generous for any legitimate single-statement input
		// (Postgres's max identifier is 63 bytes; a SELECT touching
		// 50 columns + 5 joins is < 2 KiB). The cap applies uniformly
		// to ALL tools — measuring at the raw Params bytes is simpler +
		// stricter than per-arg measurement after JSON parse, and it
		// short-circuits BEFORE any tool-specific work happens.
		if len(req.Params) > maxToolCallParamsBytes {
			return errResponse(req.ID, -32602,
				fmt.Sprintf(
					"tools/call params exceed maximum size of %d bytes "+
						"(MED-D8-11 from AUDIT-WB-DSLICES-1-8.md): submit "+
						"smaller chunks. Got %d bytes.",
					maxToolCallParamsBytes, len(req.Params)))
		}
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return errResponse(req.ID, -32602, fmt.Sprintf("invalid params: %v", err))
		}
		result, err := s.callTool(p.Name, p.Arguments)
		if err != nil {
			result = map[string]any{
				"error": err.Error(),
			}
		}
		text, _ := json.MarshalIndent(result, "", "  ")
		return okResponse(req.ID, map[string]any{
			"content":           []map[string]any{{"type": "text", "text": string(text)}},
			"structuredContent": result,
		})
	case "notifications/initialized", "notifications/cancelled":
		return nil
	}
	return errResponse(req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
}

func (s *Server) callTool(name string, args map[string]any) (map[string]any, error) {
	switch name {
	case "dbounce_active_mode":
		return s.toolActiveMode(args)
	case "dbounce_active_profile":
		return s.toolActiveProfile(args)
	case "dbounce_active_task":
		return s.toolActiveTask(args)
	case "dbounce_recommend_mode_for_task":
		return toolRecommendModeForTask(args)
	case "dbounce_list_rules":
		return s.toolListRules(args)
	case "dbounce_add_rule":
		return s.toolAddRule(args)
	case "dbounce_remove_rule":
		return s.toolRemoveRule(args)
	case "dbounce_decide":
		return s.toolDecide(args)
	case "dbounce_tail_decisions":
		return s.toolTailDecisions(args)
	case "dbounce_pending_sync_prompts":
		return s.toolPendingSyncPrompts(args)
	case "dbounce_audit_export_status":
		return s.toolAuditExportStatus(args)
	case "dbounce_prompts_bulk_pending":
		return s.toolPromptsBulkPending(args)
	case "dbounce_prompts_bulk_answer":
		return s.toolPromptsBulkAnswer(args)
	case "list_audit_webhook_presets":
		return s.toolListAuditWebhookPresets(args)
	case "dbounce_posture":
		return s.toolPosture(args)
	case "dbounce_profile_allow":
		return s.toolProfileAllow(args)
	case "dbounce_denies_recent":
		return s.toolDeniesRecent(args)
	case "dbounce_scope_self_for_task":
		return s.toolScopeSelfForTask(args)
	case "dbounce_end_task":
		return s.toolEndTask(args)
	case "dbounce_task_review":
		return s.toolTaskReview(args)
	case "dbounce_list_presets":
		return s.toolListPresets(args)
	case "dbounce_apply_preset":
		return s.toolApplyPreset(args)
	case "dbounce_recommend_rules":
		return s.toolRecommendRules(args)
	}
	return nil, fmt.Errorf("unknown tool: %s", name)
}

// toolPosture surfaces dbounce's local posture (running / mode /
// profile / PGHOST wiring / MISCONFIG). Read-only; takes no
// arguments. Mirrors `dbounce posture --json` CLI shape. #383 / §A42.
func (s *Server) toolPosture(_ map[string]any) (map[string]any, error) {
	block := posture.Capture()
	bs, err := json.Marshal(block)
	if err != nil {
		return nil, fmt.Errorf("posture: marshal: %w", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(bs, &out); err != nil {
		return nil, fmt.Errorf("posture: unmarshal: %w", err)
	}
	return out, nil
}

func (s *Server) requireStore() error {
	if s.cfg.Store == nil {
		return errors.New("dbounce mcp: store not configured; pass --db to `dbounce mcp`")
	}
	return nil
}

// ---------------------------------------------------------------------
// Tools that READ live config
// ---------------------------------------------------------------------

func (s *Server) toolActiveMode(_ map[string]any) (map[string]any, error) {
	return map[string]any{
		"mode":           string(s.cfg.Mode),
		"default_policy": string(s.cfg.DefaultPolicy),
		"dialect":        string(s.cfg.Dialect),
	}, nil
}

func (s *Server) toolActiveProfile(_ map[string]any) (map[string]any, error) {
	if s.cfg.ActiveProfile == nil || s.cfg.ActiveProfile.Name == "" ||
		s.cfg.ActiveProfile.Name == profile.FullUserProfileName {
		return map[string]any{
			"name":              profile.FullUserProfileName,
			"description":       "No profile active; statements parsed + audit-logged + advisory. Default.",
			"allow_baseline":    "",
			"deny_keyword_n":    0,
			"deny_action_n":     0,
			"allow_rule_n":      0,
			"deny_ast_mutating": false,
			"source":            "local",
			"profiles_path":     s.cfg.ProfilesPath,
		}, nil
	}
	p := s.cfg.ActiveProfile
	source := p.Source
	if source == "" {
		source = "local"
	}
	return map[string]any{
		"name":              p.Name,
		"description":       p.Description,
		"allow_baseline":    string(p.AllowBaseline),
		"deny_keyword_n":    len(p.DenyKeywords),
		"deny_action_n":     len(p.DenyActions),
		"allow_rule_n":      len(p.AllowRules),
		"deny_ast_mutating": p.DenyASTMutatingNodes,
		"exempt_resources":  append([]string{}, p.ExemptResources...),
		"exempt_actions":    append([]string{}, p.ExemptActions...),
		"source":            source,
		"profiles_path":     s.cfg.ProfilesPath,
	}, nil
}

func (s *Server) toolActiveTask(_ map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	t, err := s.cfg.Store.GetActiveTask(s.cfg.TaskOwner)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return map[string]any{"active": false}, nil
	}
	return map[string]any{
		"active":       true,
		"task_id":      t.TaskID,
		"description":  t.Description,
		"started_at":   t.StartedAt,
		"expires_at":   t.ExpiresAt,
		"allow_rule_n": len(t.AllowRules),
		"deny_rule_n":  len(t.DenyRules),
	}, nil
}

// ---------------------------------------------------------------------
// dbounce_recommend_mode_for_task — DETERMINISTIC decision matrix.
// Per [[bouncer-mode-selection-for-agents]] + [[safety-mode-lean-permissive]]:
// NOT an LLM call.
// ---------------------------------------------------------------------

// writeVerbs is the SQL-shaped equivalent of kbouncer's
// containsWriteVerb K8s verb list. Case-insensitive at match time.
var writeVerbs = map[string]bool{
	"insert":   true,
	"update":   true,
	"delete":   true,
	"merge":    true,
	"truncate": true,
	"drop":     true,
	"create":   true,
	"alter":    true,
	"call":     true,
	"do":       true,
	"execute":  true,
	"grant":    true,
	"revoke":   true,
	"rename":   true,
	"comment":  true,
	"copy":     true,
	"load":     true,
	"vacuum":   true,
}

// readOnlyVerbs lists keywords that confidently signal a read-only
// task.
var readOnlyVerbs = map[string]bool{
	"select":  true,
	"show":    true,
	"explain": true,
	"read":    true,
	"query":   true,
	"audit":   true,
}

func toolRecommendModeForTask(args map[string]any) (map[string]any, error) {
	description := strings.ToLower(stringArg(args, "description", ""))
	verbs := stringSliceArg(args, "verbs")
	hasWrites := containsAnyVerb(verbs, writeVerbs) ||
		descriptionMentionsAny(description, writeVerbs)
	hasReads := containsAnyVerb(verbs, readOnlyVerbs) ||
		descriptionMentionsAny(description, readOnlyVerbs)
	prodNS := boolArg(args, "targets_prod")
	wantsAudit := boolArg(args, "wants_audit_only", false)

	// Decision matrix (mirrors kbouncer's K8s-shaped matrix, adapted
	// to SQL-shaped verbs; cooperative is the lean-permissive default
	// per [[safety-mode-lean-permissive]]):
	//
	//   wants_audit_only=true                      -> cooperative
	//   targets_prod=true AND has writes           -> transparent
	//   has writes only                            -> cooperative
	//   reads-only / SELECT-only                   -> cooperative
	//   ambiguous (no verbs, no description hints) -> cooperative
	mode := proxy.ModeCooperative
	reason := "cooperative mode: lean-permissive default per safety-mode-lean-permissive"
	switch {
	case wantsAudit:
		mode = proxy.ModeCooperative
		reason = "cooperative mode: audit-only declared (wants_audit_only=true)"
	case prodNS && hasWrites:
		mode = proxy.ModeTransparent
		reason = "transparent mode: prod-targeting write task (targets_prod=true AND writes detected: DELETE/UPDATE/DROP/CALL/etc.)"
	case hasWrites:
		reason = "cooperative mode: non-prod writes; lean-permissive with audit + admin pause available"
	case hasReads:
		reason = "cooperative mode: reads-only (SELECT/EXPLAIN); no enforcement needed"
	default:
		reason = "cooperative mode: ambiguous task shape (no write/read hints); lean-permissive default"
	}
	return map[string]any{
		"mode":          string(mode),
		"reason":        reason,
		"deterministic": true,
	}, nil
}

func containsAnyVerb(verbs []string, vocab map[string]bool) bool {
	for _, v := range verbs {
		if vocab[strings.ToLower(strings.TrimSpace(v))] {
			return true
		}
	}
	return false
}

// descriptionMentionsAny returns true when the lower-cased
// description contains any vocab token bounded by non-alphanumeric
// on both sides (same word-boundary semantics as the profile
// keyword-match path per [[cross-product-word-boundary]]).
func descriptionMentionsAny(description string, vocab map[string]bool) bool {
	if description == "" {
		return false
	}
	for token := range vocab {
		if wordBoundaryMatch(description, token) {
			return true
		}
	}
	return false
}

func wordBoundaryMatch(s, token string) bool {
	if token == "" || len(s) < len(token) {
		return false
	}
	start := 0
	for {
		i := strings.Index(s[start:], token)
		if i < 0 {
			return false
		}
		i += start
		leftOK := i == 0 || !isAlnum(s[i-1])
		end := i + len(token)
		rightOK := end == len(s) || !isAlnum(s[end])
		if leftOK && rightOK {
			return true
		}
		start = i + 1
	}
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// ---------------------------------------------------------------------
// dbounce_list_rules / add_rule / remove_rule — rule CRUD
// ---------------------------------------------------------------------

func (s *Server) toolListRules(_ map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	stored, err := s.cfg.Store.ListRules()
	if err != nil {
		return nil, err
	}
	rows := make([]map[string]any, 0, len(stored))
	for _, sr := range stored {
		m := sr.Rule.ToMap()
		m["id"] = int64(sr.ID)
		rows = append(rows, m)
	}
	return map[string]any{
		"rules": rows,
		"count": len(rows),
	}, nil
}

func (s *Server) toolAddRule(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	pattern := stringArg(args, "pattern", "")
	effect := stringArg(args, "effect", "allow")
	r := rules.ProxyRule{
		Pattern:       pattern,
		Effect:        rules.Effect(effect),
		SchemaScope:   stringArg(args, "schema_scope", ""),
		TableScope:    stringArg(args, "table_scope", ""),
		FunctionScope: stringArg(args, "function_scope", ""),
		Note:          stringArg(args, "note", ""),
		Origin:        rules.OriginUser,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := s.cfg.Store.AddRule(r)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":      int64(id),
		"pattern": r.Pattern,
		"effect":  string(r.Effect),
	}, nil
}

func (s *Server) toolRemoveRule(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	id := int64(intArg(args, "id", 0))
	if id <= 0 {
		return nil, errors.New("dbounce_remove_rule: id required (positive integer)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ok, err := s.cfg.Store.RemoveRule(rules.ID(id))
	if err != nil {
		return nil, err
	}
	return map[string]any{"removed": ok, "id": id}, nil
}

// ---------------------------------------------------------------------
// dbounce_decide — dry-run a SQL statement; returns verdict without
// writing an audit row or forwarding upstream.
// ---------------------------------------------------------------------

func (s *Server) toolDecide(args map[string]any) (map[string]any, error) {
	sql := stringArg(args, "statement", "")
	if sql == "" {
		return nil, errors.New("dbounce_decide: `statement` required (a SQL string)")
	}
	dialect := stringArg(args, "dialect", string(s.cfg.Dialect))
	if dialect == "" {
		dialect = parser.DialectPostgres
	}
	ps := parser.Parse(dialect, sql)

	if s.cfg.ActiveProfile != nil && s.cfg.ActiveProfile.Name != profile.FullUserProfileName {
		profileView := &profile.ParsedStatement{
			StatementType:    ps.StatementType,
			TablesTouched:    ps.TablesTouched,
			FunctionsCalled:  ps.FunctionsCalled,
			IsDML:            ps.IsDML,
			IsDDL:            ps.IsDDL,
			HasMutatingNode:  ps.HasMutatingNode,
			IsExplain:        ps.IsExplain,
			IsExplainAnalyze: ps.IsExplainAnalyze,
		}
		pv := s.cfg.ActiveProfile.Evaluate(profileView)
		if pv.Denied {
			return map[string]any{
				"verdict":         "deny",
				"decision_source": pv.Source,
				"reason":          pv.Reason,
				"statement_type":  ps.StatementType,
			}, nil
		}
		if pv.Allowed {
			return map[string]any{
				"verdict":         "allow",
				"decision_source": pv.Source,
				"reason":          pv.Reason,
				"statement_type":  ps.StatementType,
			}, nil
		}
	}

	if s.cfg.Store == nil {
		return map[string]any{
			"verdict":         string(s.cfg.DefaultPolicy),
			"decision_source": "default",
			"reason":          "no store configured; default policy applied",
			"statement_type":  ps.StatementType,
		}, nil
	}
	ruleSet, err := s.cfg.Store.LoadRuleSet()
	if err != nil {
		return nil, err
	}
	stmtView := &rules.ParsedStatement{
		StatementType:    ps.StatementType,
		TablesTouched:    ps.TablesTouched,
		FunctionsCalled:  ps.FunctionsCalled,
		IsDML:            ps.IsDML,
		IsDDL:            ps.IsDDL,
		HasMutatingNode:  ps.HasMutatingNode,
		IsExplain:        ps.IsExplain,
		IsExplainAnalyze: ps.IsExplainAnalyze,
	}
	res := ruleSet.Evaluate(stmtView)
	if res != nil {
		verdict := "allow"
		source := "global.allow"
		if res.Effect == rules.EffectDeny {
			verdict = "deny"
			source = "global.deny"
		}
		return map[string]any{
			"verdict":         verdict,
			"decision_source": source,
			"reason":          fmt.Sprintf("matched rule pattern %q", res.Rule.Pattern),
			"statement_type":  ps.StatementType,
		}, nil
	}
	return map[string]any{
		"verdict":         string(s.cfg.DefaultPolicy),
		"decision_source": "default",
		"reason":          fmt.Sprintf("no rule matched; default policy %q applied", s.cfg.DefaultPolicy),
		"statement_type":  ps.StatementType,
	}, nil
}

// ---------------------------------------------------------------------
// dbounce_tail_decisions — recent audit rows.
// ---------------------------------------------------------------------

func (s *Server) toolTailDecisions(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	limit := intArg(args, "limit", 50)
	rows, err := s.cfg.Store.RecentDecisions(limit)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		row := map[string]any{
			"at":                 r.At.UTC().Format("2006-01-02T15:04:05Z"),
			"dialect":            r.Dialect,
			"statement":          r.Statement,
			"statement_type":     r.StatementType,
			"tables":             r.TablesTouched,
			"functions":          r.FunctionsCalled,
			"is_dml":             r.IsDML,
			"is_ddl":             r.IsDDL,
			"has_mutating_node":  r.HasMutatingNode,
			"verdict":            r.DecisionVerdict,
			"reason":             r.DecisionReason,
			"decision_source":    r.DecisionSource,
			"profile_name":       r.ProfileName,
			"enforced":           r.Enforced,
			// MED-D8-09: surface so agents know the SQL has been
			// [REDACTED] and is not replayable.
			"statement_redacted": r.StatementRedacted,
		}
		if r.TaskID != "" {
			row["task_id"] = r.TaskID
		}
		out = append(out, row)
	}
	return map[string]any{
		"decisions": out,
		"count":     len(out),
	}, nil
}

// ---------------------------------------------------------------------
// dbounce_pending_sync_prompts — #203 synchronous deny-prompt v1.1.
// Returns the LIST of prompts whose request goroutine is currently
// blocked waiting for `dbounce prompts answer`. DETERMINISTIC: a SQL
// query of pending_prompts JOINed against the in-memory wait-channel
// registry (waiters lost on restart are filtered out automatically).
// ---------------------------------------------------------------------

func (s *Server) toolPendingSyncPrompts(_ map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	prompts, err := s.cfg.Store.ListWaitingSyncPrompts()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(prompts))
	for _, p := range prompts {
		out = append(out, map[string]any{
			"id":             p.ID,
			"created_at":     p.CreatedAt,
			"decision_id":    p.DecisionID,
			"statement_type": p.StatementType,
			"tables":         p.TablesTouched,
			"functions":      p.FunctionsCalled,
			"deny_reason":    p.DenyReason,
			"sync_wait_id":   p.SyncWaitID,
		})
	}
	return map[string]any{
		"waiting": out,
		"count":   len(out),
	}, nil
}

// ---------------------------------------------------------------------
// dbounce_audit_export_status — #252 Slice 1 security-team audit-export
// transport health. Returns per-transport counters + last_error +
// configured booleans. The webhook URL is REDACTED (userinfo masked);
// the Bearer token is NEVER surfaced — tested invariant. Read-only.
// ---------------------------------------------------------------------

func (s *Server) toolAuditExportStatus(_ map[string]any) (map[string]any, error) {
	out := map[string]any{
		"configured":      false,
		"total_events":    int64(0),
		"dropped_events":  int64(0),
		"webhook_in_flight": int64(0),
		"log": map[string]any{
			"configured": false,
		},
		"webhook": map[string]any{
			"configured": false,
		},
	}
	if s.cfg.AuditExporter == nil || !s.cfg.AuditExporter.Enabled() {
		return out, nil
	}
	st := s.cfg.AuditExporter.Status()
	out["configured"] = true
	out["host"] = st.Host
	out["upstream"] = st.Upstream

	totalEvents := int64(0)
	totalDropped := int64(0)
	var lastErr string

	if st.Log != nil {
		// Per the spec docstring: never surface the token. The
		// LogStats has no token field; only Path, Written, Dropped,
		// LastError, Fsync, QueueDepth, QueueLimit.
		out["log"] = map[string]any{
			"configured":  st.Log.Configured,
			"path":        st.Log.Path,
			"written":     st.Log.Written,
			"dropped":     st.Log.Dropped,
			"fsync":       st.Log.Fsync,
			"last_error":  st.Log.LastError,
			"queue_depth": st.Log.QueueDepth,
			"queue_limit": st.Log.QueueLimit,
		}
		totalEvents += st.Log.Written
		totalDropped += st.Log.Dropped
		if st.Log.LastError != "" {
			lastErr = "log: " + st.Log.LastError
		}
	}
	if st.Webhook != nil {
		// URLRedacted is the userinfo-masked URL; the token lives in
		// the Authorization header only + is NEVER in WebhookStats.
		out["webhook"] = map[string]any{
			"configured":   st.Webhook.Configured,
			"url_redacted": st.Webhook.URLRedacted,
			"delivered":    st.Webhook.Delivered,
			"dropped":      st.Webhook.Dropped,
			"in_flight":    st.Webhook.InFlight,
			"last_error":   st.Webhook.LastError,
			"batch_size":   st.Webhook.BatchSize,
			"queue_depth":  st.Webhook.QueueDepth,
			"queue_limit":  st.Webhook.QueueLimit,
		}
		totalEvents += st.Webhook.Delivered
		totalDropped += st.Webhook.Dropped
		out["webhook_in_flight"] = st.Webhook.InFlight
		if st.Webhook.LastError != "" {
			if lastErr != "" {
				lastErr += "; "
			}
			lastErr += "webhook: " + st.Webhook.LastError
		}
	}
	// Heartbeat surface — periodic OCSF liveness events + the
	// in-process gap watchdog per
	// [[prompt-injection-disable-bouncer-threat]]. Only surfaced when
	// --heartbeat-interval was set; configured=false otherwise so a
	// downstream agent can branch on whether the operator opted in.
	if st.Heartbeat != nil {
		out["heartbeat"] = map[string]any{
			"configured":          st.Heartbeat.Configured,
			"interval":            st.Heartbeat.Interval,
			"gap_threshold":       st.Heartbeat.GapThreshold,
			"emitted":             st.Heartbeat.Emitted,
			"gap_fired":           st.Heartbeat.GapFired,
			"missed_ticks":        st.Heartbeat.MissedTicks,
			"degraded":            st.Heartbeat.Degraded,
			"last_tick_unix_nano": st.Heartbeat.LastTickUnixNano,
		}
		if st.Heartbeat.Degraded {
			if lastErr != "" {
				lastErr += "; "
			}
			lastErr += "heartbeat: gap watchdog degraded"
		}
	} else {
		out["heartbeat"] = map[string]any{
			"configured": false,
		}
	}
	// [[audit-export-failure-visibility]] derived health block:
	// per-transport health + aggregate degraded flag + reason. Read
	// by agents that want to verify the audit-export pipeline is
	// healthy BEFORE relying on its output for compliance / security-
	// team review. Mirrors the /healthz audit_export_health JSON
	// shape exactly so agents that scrape both surfaces see one
	// consistent contract.
	health := s.cfg.AuditExporter.Health()
	healthBlock := map[string]any{
		"configured":                       health.Configured,
		"degraded":                         health.Degraded,
		"reason":                           health.Reason,
		"log_configured":                   health.LogConfigured,
		"log_writes_ok":                    health.LogWritesOK,
		"log_path":                         health.LogPath,
		"log_last_error":                   health.LogLastError,
		"log_last_error_seconds_ago":       health.LogLastErrorSecondsAgo,
		"log_dropped_since_start":          health.LogDroppedSinceStart,
		"webhook_configured":               health.WebhookConfigured,
		"webhook_url_masked":               health.WebhookURLMasked,
		"webhook_last_success_seconds_ago": health.WebhookLastSuccessSecondsAgo,
		"webhook_last_attempt_seconds_ago": health.WebhookLastAttemptSecondsAgo,
		"webhook_last_status_code":         health.WebhookLastStatusCode,
		"webhook_consecutive_failures":     health.WebhookConsecutiveFailures,
		"webhook_last_error":               health.WebhookLastError,
		"webhook_dropped_since_start":      health.WebhookDroppedSinceStart,
		"webhook_queue_depth":              health.WebhookQueueDepth,
		"webhook_queue_capacity":           health.WebhookQueueCapacity,
		"auth_failed":                      health.AuthFailed,
	}
	if s.cfg.AuditExporter.HealthMonitor != nil &&
		s.cfg.AuditExporter.HealthMonitor.Debouncer() != nil {
		fired, suppressed := s.cfg.AuditExporter.HealthMonitor.Debouncer().Stats()
		healthBlock["degraded_alert_fired"] = fired
		healthBlock["degraded_alert_suppressed"] = suppressed
	}
	out["audit_export_health"] = healthBlock
	out["total_events"] = totalEvents
	out["dropped_events"] = totalDropped
	out["last_error"] = lastErr
	return out, nil
}

// toolListAuditWebhookPresets is the agent-facing surface mirroring
// `dbounce audit-webhook presets list --json`. Returns the same
// descriptor list the CLI emits so an agent can discover the webhook
// preset shapes the bouncer speaks without spawning a subprocess.
//
// Per [[cross-product-agent-parity]]: identical JSON shape across
// ibounce / kbounce / dbounce. Per [[scorer-is-ground-truth]]: the
// descriptor list is static — the tool just defers to the shared
// audit.PresetDescriptors helper.
func (s *Server) toolListAuditWebhookPresets(_ map[string]any) (map[string]any, error) {
	descriptors := audit.PresetDescriptors()
	body, err := json.Marshal(descriptors)
	if err != nil {
		return nil, fmt.Errorf("list_audit_webhook_presets: marshal: %w", err)
	}
	var presets []map[string]any
	if err := json.Unmarshal(body, &presets); err != nil {
		return nil, fmt.Errorf("list_audit_webhook_presets: unmarshal: %w", err)
	}
	return map[string]any{"presets": presets}, nil
}

// ---------------------------------------------------------------------
// arg-coercion helpers
// ---------------------------------------------------------------------

func stringArg(args map[string]any, key, def string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return def
}

func intArg(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	}
	return def
}

func boolArg(args map[string]any, key string, def ...bool) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	if len(def) > 0 {
		return def[0]
	}
	return false
}

func stringSliceArg(args map[string]any, key string) []string {
	raw, ok := args[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------------
// JSON-RPC envelope helpers
// ---------------------------------------------------------------------

func okResponse(id json.RawMessage, result any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      jsonRawOrNull(id),
		"result":  result,
	}
}

func errResponse(id json.RawMessage, code int, message string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      jsonRawOrNull(id),
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
}

func jsonRawOrNull(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

// ---------------------------------------------------------------------
// dbounce_scope_self_for_task — agent declares a SQL task scope.
//
// Mirrors kbounce_scope_self_for_task (kbouncer/internal/mcp/server.go)
// adapted to the SQL domain: verbs → SQL statement-types (SELECT,
// DELETE, DML, MUTATING, …), resources → table / schema globs,
// namespaces → schema_scope. Per [[creates-never-mutates]]: dbounce
// CREATES a new task scope; it never mutates an existing one.
// Per [[cross-product-agent-parity]]: tool name + arg shapes parallel
// the kbounce surface so a cross-product agent re-uses learned idioms.
// ---------------------------------------------------------------------

func (s *Server) toolScopeSelfForTask(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	desc := stringArg(args, "description", "")
	stmtTypes := stringSliceArg(args, "statement_types")
	tables := stringSliceArg(args, "tables")
	schemas := stringSliceArg(args, "schemas") // optional: becomes schema_scope on each rule
	denyTypes := stringSliceArg(args, "deny_statement_types")
	durationMin := intArg(args, "duration_minutes", 30)

	if len(stmtTypes) == 0 || len(tables) == 0 {
		return nil, errors.New(
			"dbounce_scope_self_for_task: at least one statement_type + one table required " +
				"(use `*` for any statement / any table within the task)")
	}

	allowRules := make([]rules.ProxyRule, 0, len(stmtTypes)*len(tables))
	for _, st := range stmtTypes {
		for _, tbl := range tables {
			r := rules.ProxyRule{
				Pattern: st + ":" + tbl,
				Effect:  rules.EffectAllow,
				Origin:  rules.OriginTask,
			}
			if len(schemas) == 1 {
				r.SchemaScope = schemas[0]
			}
			allowRules = append(allowRules, r)
		}
	}

	denyRules := make([]rules.ProxyRule, 0, len(denyTypes))
	for _, dt := range denyTypes {
		denyRules = append(denyRules, rules.ProxyRule{
			Pattern: dt + ":*",
			Effect:  rules.EffectDeny,
			Origin:  rules.OriginTask,
		})
	}

	scope, err := tasks.BuildScope(desc, allowRules, denyRules, durationMin, s.cfg.Actor, s.cfg.TaskOwner)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.cfg.Store.AddTask(scope); err != nil {
		return nil, err
	}
	return map[string]any{
		"task_id":      scope.TaskID,
		"description":  scope.Description,
		"expires_at":   scope.ExpiresAt,
		"allow_rule_n": len(scope.AllowRules),
		"deny_rule_n":  len(scope.DenyRules),
	}, nil
}

// ---------------------------------------------------------------------
// dbounce_end_task — close the currently-active task.
// Mirrors kbounce_end_task. Part of the task lifecycle exposed by
// [[cross-product-agent-parity]].
// ---------------------------------------------------------------------

func (s *Server) toolEndTask(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	reason := stringArg(args, "reason", "ended via mcp")
	t, err := s.cfg.Store.GetActiveTask(s.cfg.TaskOwner)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return map[string]any{"ended": false, "message": "no active task"}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ok, err := s.cfg.Store.EndTask(t.TaskID, s.cfg.Actor, reason, tasks.StatusCompleted)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ended": ok, "task_id": t.TaskID}, nil
}

// ---------------------------------------------------------------------
// dbounce_task_review — post-task review summary.
//
// Mirrors kbounce_task_review adapted to the SQL domain:
// denied_calls carries (at, statement_type, tables, reason) rather
// than (verb, resource, namespace). Returns the same top-level shape
// so a cross-product agent that learned the kbounce surface uses the
// same field names for the scalar counts.
// Per [[cross-product-agent-parity]].
// ---------------------------------------------------------------------

func (s *Server) toolTaskReview(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	taskID := stringArg(args, "task_id", "")
	if taskID == "" {
		return nil, errors.New("dbounce_task_review: task_id required")
	}
	rev, err := s.cfg.Store.TaskReviewSummary(taskID)
	if err != nil {
		return nil, err
	}
	if rev == nil {
		return nil, fmt.Errorf("no task with id %q", taskID)
	}
	out := map[string]any{
		"task_id":              rev.TaskID,
		"status":               rev.Status,
		"description":          rev.Description,
		"started_at":           rev.StartedAt,
		"ended_at":             rev.EndedAt,
		"decision_count":       rev.DecisionCount,
		"allow_count":          rev.AllowCount,
		"deny_count":           rev.DenyCount,
		"pause_demoted_count":  rev.PauseDemotedCount,
		"denied_calls_n":       len(rev.DeniedCalls),
		"pause_demoted_calls_n": len(rev.PauseDemotedCalls),
	}
	if rev.FirstDecisionAt != "" {
		out["first_decision_at"] = rev.FirstDecisionAt
	}
	if rev.LastDecisionAt != "" {
		out["last_decision_at"] = rev.LastDecisionAt
	}
	// Include the first 50 denied calls so the agent can immediately
	// surface "here are the statements that were blocked during this task"
	// without requiring a follow-up query. Cap at 50 for the MCP envelope
	// (the full list is in the store for CLI review).
	if len(rev.DeniedCalls) > 0 {
		cap := 50
		if len(rev.DeniedCalls) < cap {
			cap = len(rev.DeniedCalls)
		}
		calls := make([]map[string]any, 0, cap)
		for _, c := range rev.DeniedCalls[:cap] {
			calls = append(calls, map[string]any{
				"at":             c.At,
				"statement_type": c.StatementType,
				"tables":         c.Tables,
				"reason":         c.Reason,
			})
		}
		out["denied_calls"] = calls
	}
	return out, nil
}

// ---------------------------------------------------------------------
// dbounce_list_presets / dbounce_apply_preset — curated SQL rule packs.
//
// Mirrors kbounce_list_presets / kbounce_apply_preset adapted to the
// SQL domain: presets define SQL-shaped patterns (SELECT:*, DML:*,
// MUTATING:*) rather than K8s verb:resource pairs. apply_preset ADDS
// rules (never overwrites) per [[creates-never-mutates]] +
// [[cross-product-agent-parity]].
// ---------------------------------------------------------------------

func (s *Server) toolListPresets(_ map[string]any) (map[string]any, error) {
	cat := presets.List()
	out := make([]map[string]any, 0, len(cat))
	for _, p := range cat {
		allow, deny := p.ToProxyRules()
		out = append(out, map[string]any{
			"id":          p.ID,
			"title":       p.Title,
			"description": p.Description,
			"rule_count":  len(allow) + len(deny),
		})
	}
	return map[string]any{
		"presets": out,
		"count":   len(out),
	}, nil
}

func (s *Server) toolApplyPreset(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	id := stringArg(args, "name", "")
	if id == "" {
		return nil, errors.New("dbounce_apply_preset: `name` required")
	}
	p, ok := presets.Get(id)
	if !ok {
		return nil, fmt.Errorf("dbounce_apply_preset: preset %q not found; use dbounce_list_presets to see available names", id)
	}
	allow, deny := p.ToProxyRules()
	all := append(allow, deny...)
	s.mu.Lock()
	defer s.mu.Unlock()
	ruleIDs := make([]int64, 0, len(all))
	for _, r := range all {
		rid, err := s.cfg.Store.AddRule(r)
		if err != nil {
			return nil, fmt.Errorf(
				"apply preset %q: failed on rule %q after %d applied: %w",
				id, r.Pattern, len(ruleIDs), err)
		}
		ruleIDs = append(ruleIDs, int64(rid))
	}
	return map[string]any{
		"preset":   id,
		"applied":  len(ruleIDs),
		"rule_ids": ruleIDs,
	}, nil
}

// ---------------------------------------------------------------------
// dbounce_recommend_rules — synthesize draft rules from observed
// audit-log traffic.
//
// Mirrors kbounce_recommend_rules adapted to the SQL domain:
// groups by (statement_type, table) rather than (resource, verb).
// Per [[cross-product-agent-parity]] + [[scorer-is-ground-truth]]:
// deterministic algorithm; no LLM in the synthesis path. Read-only
// at the MCP surface — returns recommendations without applying them.
// Per audit-cadence (c): operators apply via `dbounce rules apply`
// CLI or dbounce_apply_preset for curated packs.
// ---------------------------------------------------------------------

// parseSinceArg accepts a relative ("1h", "24h", "7d") or absolute
// ISO-8601 timestamp. Returns zero time on empty / unparseable input.
// Mirrors kbouncer's parseSinceArg.
func parseSinceArg(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	if strings.HasSuffix(raw, "d") {
		num := strings.TrimSuffix(raw, "d")
		if d, err := time.ParseDuration(num + "h"); err == nil {
			return time.Now().UTC().Add(-d * 24)
		}
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return time.Now().UTC().Add(-d)
	}
	return time.Time{}
}

// recommendWindowSummary is the SQL-domain equivalent of
// kbouncer's recommender.WindowSummary — reported at the top of the
// recommend_rules response so the agent has context on the window.
type recommendWindowSummary struct {
	TotalCalls     int
	DistinctTypes  int
	DistinctTables int
	AllowCount     int
	DenyCount      int
	WindowStart    time.Time
	WindowEnd      time.Time
}

func (w recommendWindowSummary) toMap() map[string]any {
	out := map[string]any{
		"total_calls":     w.TotalCalls,
		"distinct_types":  w.DistinctTypes,
		"distinct_tables": w.DistinctTables,
		"allow_count":     w.AllowCount,
		"deny_count":      w.DenyCount,
	}
	if !w.WindowStart.IsZero() {
		out["window_start"] = w.WindowStart.UTC().Format(time.RFC3339)
	}
	if !w.WindowEnd.IsZero() {
		out["window_end"] = w.WindowEnd.UTC().Format(time.RFC3339)
	}
	return out
}

// sqlRecommendation is one draft rule derived from observed audit traffic.
type sqlRecommendation struct {
	Pattern      string
	Effect       rules.Effect
	SchemaScope  string
	SupportCount int
	HitRate      float64
	Note         string
	SkippedReason string
}

func (r sqlRecommendation) toMap() map[string]any {
	out := map[string]any{
		"proposed_rule": map[string]any{
			"pattern":      r.Pattern,
			"effect":       string(r.Effect),
			"schema_scope": r.SchemaScope,
			"note":         r.Note,
			"origin":       "recommendation",
		},
		"support_count": r.SupportCount,
		"hit_rate":      sqlRound4(r.HitRate),
	}
	if r.SkippedReason != "" {
		out["skipped_reason"] = r.SkippedReason
	}
	return out
}

func sqlRound4(f float64) float64 {
	if f >= 0 {
		return float64(int(f*10000+0.5)) / 10000
	}
	return float64(int(f*10000-0.5)) / 10000
}

func (s *Server) toolRecommendRules(args map[string]any) (map[string]any, error) {
	if err := s.requireStore(); err != nil {
		return nil, err
	}
	since := stringArg(args, "since", "")
	minSupport := intArg(args, "min_support", 3)
	if minSupport <= 0 {
		minSupport = 3
	}
	includeTaskScoped := boolArg(args, "include_task_scoped", false)

	decisions, err := s.cfg.Store.RecentDecisions(1000)
	if err != nil {
		return nil, err
	}

	// Apply time window filter.
	sinceT := parseSinceArg(since)
	if !sinceT.IsZero() {
		filtered := make([]store.DecisionRow, 0, len(decisions))
		for _, d := range decisions {
			if !d.At.IsZero() && d.At.Before(sinceT) {
				continue
			}
			filtered = append(filtered, d)
		}
		decisions = filtered
	}

	// Build window summary.
	summary := recommendWindowSummary{TotalCalls: len(decisions)}
	types := map[string]struct{}{}
	tables := map[string]struct{}{}
	for _, d := range decisions {
		if d.StatementType != "" {
			types[strings.ToLower(d.StatementType)] = struct{}{}
		}
		for _, tbl := range d.TablesTouched {
			if tbl != "" {
				tables[tbl] = struct{}{}
			}
		}
		switch strings.ToUpper(d.DecisionVerdict) {
		case "ALLOW":
			summary.AllowCount++
		case "DENY":
			summary.DenyCount++
		}
		if !d.At.IsZero() {
			if summary.WindowStart.IsZero() || d.At.Before(summary.WindowStart) {
				summary.WindowStart = d.At
			}
			if d.At.After(summary.WindowEnd) {
				summary.WindowEnd = d.At
			}
		}
	}
	summary.DistinctTypes = len(types)
	summary.DistinctTables = len(tables)

	// Load existing rules for dedup.
	existing, err := s.cfg.Store.ListRules()
	if err != nil {
		return nil, err
	}
	existingRules := make([]rules.ProxyRule, 0, len(existing))
	for _, sr := range existing {
		existingRules = append(existingRules, sr.Rule)
	}

	// Group ALLOW decisions by (statement_type, first table touched).
	// Cross-product CRIT-28-01: only ALLOW decisions drive recommendations;
	// DENY/prompt decisions are not endorsements.
	type groupKey struct {
		stmtType string
		table    string
	}
	type groupVal struct {
		count   int
		schemas map[string]int
	}
	groups := map[groupKey]*groupVal{}
	totalAllow := 0
	for _, d := range decisions {
		if strings.ToUpper(d.DecisionVerdict) != "ALLOW" {
			continue
		}
		if !includeTaskScoped && d.TaskID != "" {
			continue
		}
		st := strings.ToUpper(strings.TrimSpace(d.StatementType))
		if st == "" {
			continue
		}
		// Use first table or "*" for table-less statements.
		tbl := "*"
		if len(d.TablesTouched) > 0 && d.TablesTouched[0] != "" {
			tbl = d.TablesTouched[0]
		}
		k := groupKey{stmtType: st, table: tbl}
		if groups[k] == nil {
			groups[k] = &groupVal{schemas: map[string]int{}}
		}
		groups[k].count++
		totalAllow++
		// Track schema (everything before the last dot in the table name).
		if dot := strings.LastIndex(tbl, "."); dot > 0 {
			schema := tbl[:dot]
			groups[k].schemas[schema]++
		}
	}

	recs := make([]sqlRecommendation, 0, len(groups))
	for k, gv := range groups {
		if gv.count < minSupport {
			continue
		}
		// Derive the table glob: if all observations share the same schema,
		// scope to schema.*; otherwise use the literal table name.
		tableGlob := k.table
		var schemaScope string
		if dot := strings.LastIndex(k.table, "."); dot > 0 {
			schemaScope = k.table[:dot]
		}
		// If the most-frequent schema accounts for >= 50% of this group's
		// observations, emit a schema-scoped * glob instead of a literal.
		if k.table != "*" {
			if dot := strings.LastIndex(k.table, "."); dot > 0 {
				sc := k.table[:dot]
				if float64(gv.schemas[sc]) >= 0.5*float64(gv.count) {
					tableGlob = sc + ".*"
					schemaScope = sc
				}
			}
		}
		pattern := k.stmtType + ":" + tableGlob
		note := fmt.Sprintf("recommended from %d observed calls", gv.count)
		if !summary.WindowStart.IsZero() && !summary.WindowEnd.IsZero() {
			note += fmt.Sprintf(" in window %s → %s",
				summary.WindowStart.UTC().Format(time.RFC3339),
				summary.WindowEnd.UTC().Format(time.RFC3339))
		}
		rec := sqlRecommendation{
			Pattern:      pattern,
			Effect:       rules.EffectAllow,
			SchemaScope:  schemaScope,
			SupportCount: gv.count,
			HitRate:      float64(gv.count) / float64(max1(totalAllow)),
			Note:         note,
		}
		// Dedup against existing rules (audit-cadence (b): never
		// auto-restore a rule the operator previously removed).
		for _, e := range existingRules {
			if e.Pattern == rec.Pattern && e.SchemaScope == rec.SchemaScope &&
				e.Effect == rec.Effect {
				rec.SkippedReason = "rule with this pattern + schema_scope already in store"
				break
			}
		}
		recs = append(recs, rec)
	}

	// Sort by support DESC then by pattern for stable output.
	for i := 0; i < len(recs); i++ {
		for j := i + 1; j < len(recs); j++ {
			if recs[j].SupportCount > recs[i].SupportCount ||
				(recs[j].SupportCount == recs[i].SupportCount && recs[j].Pattern < recs[i].Pattern) {
				recs[i], recs[j] = recs[j], recs[i]
			}
		}
	}

	out := make([]map[string]any, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.toMap())
	}
	return map[string]any{
		"summary":         summary.toMap(),
		"recommendations": out,
		"count":           len(out),
	}, nil
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

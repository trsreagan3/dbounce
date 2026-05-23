// MCP tool descriptors. Kept in a separate file from server.go so the
// schema definitions don't crowd the dispatcher.
//
// Each tool entry mirrors the Python iam-jit-bouncer `bouncer_*` +
// kbouncer's `kbounce_*` shape:
//
//   name         the dbounce_* tool name agents will see
//   description  agent-readable summary (one paragraph max)
//   inputSchema  JSON-Schema for the arguments
//
// Schema convention follows the Python + Go sides: type/properties/
// required. We do not use $ref or composition.

package mcp

// ToolDescriptors returns the full tool list surfaced via
// `tools/list`. Returned as a slice (not a map) so the order is
// deterministic across runs.
func ToolDescriptors() []map[string]any {
	return []map[string]any{
		{
			"name": "dbounce_active_mode",
			"description": "Return dbounce's current operating mode " +
				"(cooperative | transparent) plus the default-policy " +
				"(allow | deny) and the SQL dialect (postgres | mysql | " +
				"snowflake | bigquery). Read-only: agents introspect; " +
				"they cannot flip the mode (that requires a proxy restart " +
				"per [[agent-friendly-not-bypassable]]).",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "dbounce_active_profile",
			"description": "Return which environment profile is currently " +
				"active (the value of --profile / DBOUNCE_PROFILE at " +
				"proxy-start time, or 'full-user' if none). Surfaces the " +
				"allow_baseline + deny_ast_mutating + deny_keyword/" +
				"deny_action counts + source + exempt lists so an agent " +
				"can introspect 'is a hard-floor deny layer active?' " +
				"before recommending actions. Mirrors bouncer_active_profile / " +
				"kbounce_active_profile.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "dbounce_active_task",
			"description": "Show the currently-active task scope (if any) " +
				"for dbounce's owner slot. Returns {active: false} when " +
				"no task is open. Mirrors kbounce_active_task / " +
				"bouncer_active_task.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "dbounce_recommend_mode_for_task",
			"description": "DETERMINISTIC (not LLM) recommendation: given " +
				"a task description and/or hint verbs, return 'cooperative' " +
				"or 'transparent' per the [[bouncer-mode-selection-for-" +
				"agents]] SQL-shaped decision matrix. Writes detected " +
				"(DELETE/DROP/CALL/INSERT/etc.) on prod-targeting tasks " +
				"→ transparent. SELECT-only / ambiguous → cooperative " +
				"per [[safety-mode-lean-permissive]]. The agent's own " +
				"LLM should NOT second-guess this — the answer is " +
				"deterministic by design so the decision is auditable.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"description": map[string]any{
						"type":        "string",
						"description": "Human-readable task description (free-text). Mining for write/read keywords runs deterministically.",
					},
					"verbs": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Optional SQL verbs the task will use (select, update, delete, call, ...).",
					},
					"targets_prod": map[string]any{
						"type":        "boolean",
						"description": "True if the task will touch prod-classified schemas / tables.",
					},
					"wants_audit_only": map[string]any{
						"type":        "boolean",
						"description": "True if the task is observation-only (no enforcement needed).",
					},
				},
			},
		},
		{
			"name": "dbounce_list_rules",
			"description": "List all global rules in evaluation order " +
				"(deny-beats-allow). Returns each rule's id, pattern, " +
				"effect, scopes, note, origin. Read-only.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "dbounce_add_rule",
			"description": "Add a global rule. Pattern shape: " +
				"'statement_type:table_glob' (e.g. 'SELECT:public.*', " +
				"'DELETE:public.users', 'MUTATING:*'). statement_type may " +
				"be a literal (SELECT/INSERT/UPDATE/DELETE/DDL/CALL/DO/" +
				"EXECUTE/WITH-WRITE) or a category (DML/DDL/MUTATING/" +
				"READ). Effect: 'allow' | 'deny'. Optional schema_scope / " +
				"table_scope / function_scope are AWS-IAM-style globs. " +
				"Mutating tool — recorded under origin=user.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pattern":        map[string]any{"type": "string"},
					"effect":         map[string]any{"type": "string", "enum": []string{"allow", "deny"}, "default": "allow"},
					"schema_scope":   map[string]any{"type": "string"},
					"table_scope":    map[string]any{"type": "string"},
					"function_scope": map[string]any{"type": "string"},
					"note":           map[string]any{"type": "string"},
				},
				"required": []string{"pattern"},
			},
		},
		{
			"name": "dbounce_remove_rule",
			"description": "Remove a global rule by numeric id (from " +
				"dbounce_list_rules). Mutating tool — audit-logged.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{"type": "integer"},
				},
				"required": []string{"id"},
			},
		},
		{
			"name": "dbounce_decide",
			"description": "Dry-run a SQL statement through dbounce's " +
				"rule engine; return the verdict WITHOUT writing to the " +
				"audit log or forwarding upstream. Useful for an agent to " +
				"preview 'would this query be allowed?' before issuing it. " +
				"D-Slice 6: accepts dialect = postgres | mysql | snowflake | " +
				"bigquery. snowflake + bigquery are the supported invocation " +
				"path for those dialects (no wire-protocol proxy in v1.0); " +
				"see docs/SHIM-INTEGRATION.md. Returns {verdict, " +
				"decision_source, reason, statement_type}.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"statement": map[string]any{
						"type":        "string",
						"description": "The SQL statement to dry-run (e.g. 'SELECT * FROM public.users').",
					},
					"dialect": map[string]any{
						"type":        "string",
						"enum":        []string{"postgres", "mysql", "snowflake", "bigquery"},
						"description": "Dialect to parse with. Defaults to the proxy's --dialect. " +
							"snowflake + bigquery use the JDBC-driver-shim parser " +
							"(experimental calibration per [[scorer-is-ground-truth]]).",
					},
				},
				"required": []string{"statement"},
			},
		},
		{
			"name": "dbounce_pending_sync_prompts",
			"description": "List the synchronous deny-prompts (#203 — " +
				"--sync-prompt-on-deny) whose request goroutine is currently " +
				"BLOCKED waiting for `dbounce prompts answer`. Each entry " +
				"carries id (use with prompts answer), statement_type, " +
				"tables, deny_reason, and sync_wait_id. Excludes historical " +
				"prompts that have been answered/timed-out — only LIVE " +
				"waiters appear. DETERMINISTIC: SQL query of pending_prompts " +
				"JOINed against the in-memory wait-channel registry.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "dbounce_audit_export_status",
			"description": "#252 Slice 1: return the status of the security-team " +
				"audit-export transports (JSONL log file + HTTPS webhook). " +
				"Read-only. Returns total_events (written/delivered), " +
				"dropped_events (with per-transport breakdown), webhook_in_flight, " +
				"last_error (per transport, bounded), plus configured booleans for " +
				"both transports + the webhook URL (REDACTED — userinfo masked; " +
				"the Bearer token is NEVER surfaced). Also returns the heartbeat " +
				"block when --heartbeat-interval was set: emitted count, gap_fired, " +
				"missed_ticks, and degraded flag per " +
				"[[prompt-injection-disable-bouncer-threat]]. Additionally returns " +
				"the audit_export_health derived view per " +
				"[[audit-export-failure-visibility]]: log_writes_ok, " +
				"webhook_consecutive_failures, webhook_last_success_seconds_ago, " +
				"auth_failed, plus the top-level degraded flag + reason. Use this " +
				"to verify the audit-export is healthy before relying on its " +
				"output for compliance / security-team review. Composes with " +
				"[[security-team-audit-export]] + [[ibounce-honest-positioning]] " +
				"(operator-visibility, not adversary defense).",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "dbounce_prompts_bulk_pending",
			"description": "Return the burst summary of all currently-pending " +
				"prompts grouped by (dialect, statement_type, table) — per " +
				"[[bulk-prompt-answer-ux]]. Read-only; agents call this to " +
				"surface the bulk-answer affordance to the operator when many " +
				"calls are being blocked in a short window. Returns " +
				"{total_prompts, dialects, entries, burst_armed} where each " +
				"entry is the tuple + count of pending prompts the bulk-answer " +
				"would create one rule for. Composes with " +
				"dbounce_prompts_bulk_answer (the mutating side, gated by an " +
				"operator-set MCP token).",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "dbounce_prompts_bulk_answer",
			"description": "Resolve all currently-pending prompts en masse — " +
				"per [[bulk-prompt-answer-ux]]. Mutating; GATED behind an " +
				"operator-set token (--bulk-answer-mcp-token at server " +
				"start). When the token isn't configured (default), this tool " +
				"returns {error: 'disabled'} so an adversarial agent calling " +
				"on its own can't bulk-allow itself. Decision values: " +
				"'10min' / '3h' / 'session' create time-bounded ALLOW rules " +
				"covering the burst (one rule per dialect-aware tuple); " +
				"'profile' requires `profile_name` + posts a hot-swap signal " +
				"that the running proxy picks up within ~5s; 'none' is a " +
				"no-op. The `token` arg MUST match the operator-set value " +
				"or the call is refused.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"decision": map[string]any{
						"type": "string",
						"enum": []string{"10min", "3h", "session", "profile", "none"},
						"description": "Which bulk-answer to apply across all pending prompts.",
					},
					"profile_name": map[string]any{
						"type":        "string",
						"description": "Required when decision='profile'. Name of the profile to hot-swap to.",
					},
					"token": map[string]any{
						"type":        "string",
						"description": "Operator-set MCP bulk-answer token. MUST match --bulk-answer-mcp-token.",
					},
				},
				"required": []string{"decision", "token"},
			},
		},
		{
			"name": "dbounce_tail_decisions",
			"description": "Inspect the recent decision audit log " +
				"(every statement dbounce gated). Newest first. Useful " +
				"for agents that want to confirm 'my last query was " +
				"actually allowed' or surface a recent deny to the user.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{
						"type":    "integer",
						"default": 50,
						"minimum": 1,
						"maximum": 1000,
					},
				},
			},
		},
		{
			"name": "list_audit_webhook_presets",
			"description": "#259 — return the cross-product list of audit-" +
				"webhook preset shapes the bouncer speaks, each preset's " +
				"auth header convention + body shape + which CLI flags it " +
				"requires / accepts as optional. Per [[audit-webhook-presets]] " +
				"+ [[cross-product-agent-parity]]: identical JSON shape across " +
				"ibounce / kbounce / dbounce so an agent that wants to ask " +
				"'which webhook shape should I configure for this operator's " +
				"Datadog org?' gets a structured answer regardless of which " +
				"Bounce product it's talking to. READ-ONLY; no side effects; " +
				"safe for agents to poll. Returns the SAME descriptor list " +
				"`dbounce audit-webhook presets list --json` emits.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name": "dbounce_posture",
			"description": "Return dbounce's local posture: running / port / " +
				"mgmt port / mode / active-profile / PGHOST wiring / MISCONFIG " +
				"flag. Read-only single-bouncer view; for the cross-product " +
				"view use `iam_jit_posture` from the iam-jit MCP server. Per " +
				"[[cross-product-agent-parity]] every Bounce ships this same " +
				"shape. Per [[ibounce-honest-positioning]] reports " +
				"MISCONFIGURED rather than silently claiming intercept when " +
				"env wiring + process state disagree.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
	}
}

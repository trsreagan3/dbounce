// admin_action.go — #324c dbounce dynamic-deny admin-action constants.
//
// dbounce's broader admin-action surface already lives in event.go
// (NewAdminActionEvent + AdminActionInfo carry the OCSF v1.1.0 class
// 6003 wire shape). This file pins the dynamic-deny-specific action
// names so callers can reference them by constant rather than as raw
// strings — same pattern kbouncer + ibounce + gbounce ship under per
// [[cross-product-agent-parity]].
//
// Wire shape: identical to the cross-product
// `unmapped.iam_jit.admin_action.kind` strings declared in the
// canonical design doc at `iam-roles/docs/DYNAMIC-DENY-RULES.md`. A
// single SIEM rule keyed on
// `unmapped.iam_jit.config_change.action="dynamic_deny.*"` works
// across all four Bounce products.
//
// dbounce-specific kinds (`instance_now_denied` /
// `instance_now_allowed`) are NEW with #324c because dbounce's
// connection-level gate is genuinely different from the other
// products' per-request matchers — an operator MUST be able to
// distinguish "the file reloaded with no semantic effect on THIS
// instance" from "the file reloaded AND this instance is now refusing
// new connections."

package audit

// AdminActionKind names the cross-product stable id space for admin
// actions. Values land in OCSF unmapped.iam_jit.config_change.action
// + are queryable across SIEM dashboards regardless of which Bounce
// product fired the event. dbounce historically passes raw strings
// through AdminActionInfo.Action; this typed alias keeps the dynamic-
// deny call sites discoverable + grep-friendly.
type AdminActionKind = string

const (
	// AdminActionKindDynamicDenyReloaded — #324c. The dynamic-deny
	// YAML at `~/.iam-jit/dynamic-denies.yaml` (or the path passed via
	// `--dynamic-denies-path`) was reloaded by the in-process fsnotify
	// watcher OR the POST /admin/dynamic-denies/reload mgmt endpoint.
	// The reload reason
	// (`unmapped.iam_jit.config_change.details.dynamic_deny_reload_reason`)
	// distinguishes `file_created` / `file_modified` / `file_removed` /
	// `reload_requested` so a SIEM dashboard can split filesystem-
	// triggered reloads from operator-pushed ones. Severity
	// Informational (routine audit trail).
	AdminActionKindDynamicDenyReloaded AdminActionKind = "dynamic_deny.reloaded"

	// AdminActionKindDynamicDenyParseError — #324c. A reload attempt
	// failed YAML parse / schema validation. The previous snapshot is
	// retained in memory (fail-CLOSED per
	// [[ibounce-honest-positioning]]). Surfaced so an operator who
	// installed an invalid file sees it immediately rather than
	// "silently 0 rules applied."
	AdminActionKindDynamicDenyParseError AdminActionKind = "dynamic_deny.parse_error"

	// AdminActionKindDynamicDenyInstanceNowDenied — #324c, DBOUNCE-
	// SPECIFIC. Emitted when a reload causes THIS dbounce instance to
	// become denied (a rule's target now matches the configured
	// upstream). New connections will be refused at PG StartupMessage
	// with SQLSTATE 42501 + a structured reason referencing the rule
	// id. Existing connections continue normally.
	AdminActionKindDynamicDenyInstanceNowDenied AdminActionKind = "dynamic_deny.instance_now_denied"

	// AdminActionKindDynamicDenyInstanceNowAllowed — #324c, DBOUNCE-
	// SPECIFIC. Symmetric to InstanceNowDenied: a previously matching
	// rule was removed / expired / no longer matches, and new
	// connections will be accepted again.
	AdminActionKindDynamicDenyInstanceNowAllowed AdminActionKind = "dynamic_deny.instance_now_allowed"

	// AdminActionKindDiskPressureTransition — #461 / §A63c. The
	// disk-pressure subsystem's status crossed a threshold (ok →
	// degraded, degraded → critical, critical → emergency, or any
	// reverse transition). Surfaced so a SIEM dashboard can answer
	// "when did this bouncer cross into critical / emergency /
	// recover to ok?" from the same event stream that carries proxy
	// decisions + admin actions. Wire-shape parity with Python
	// ibounce's iam_jit.bouncer.audit_export.disk_pressure
	// ADMIN_ACTION_DISK_PRESSURE_TRANSITION per
	// [[cross-product-agent-parity]].
	AdminActionKindDiskPressureTransition AdminActionKind = "disk_pressure.transition"
)

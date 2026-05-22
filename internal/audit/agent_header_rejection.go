// agent_header_rejection.go ships the §A18 / #320 structured
// rejection breadcrumb that lands at
// `unmapped.iam_jit.ext.agent_header_rejection` whenever an inbound
// agent attribution channel fails validation.
//
// For dbounce the channel is the PostgreSQL `application_name`
// startup parameter (or MySQL `_program_name`), not HTTP headers —
// the canonical shape is `iam-jit-agent:NAME:SESSIONID`. The
// validation rejections we surface here mirror the cross-product
// enum shipped by gbounce / kbouncer / ibounce per
// [[cross-product-agent-parity]] PLUS the dbounce-specific
// `application_name_unparseable` (the prefix matched but the tag
// body failed to split into the canonical NAME:SESSIONID shape).
//
// Per [[security-team-positioning-safety-not-surveillance]] the
// breadcrumb is "audit transparency" — operator visibility into a
// validation rejection — not "violation" framing. A rejected tag is
// most often a misconfigured PG driver `application_name` setting,
// not an attack. The raw rejected value is NEVER included; only its
// length, for safe forensics.

package audit

// AgentHeaderRejectionReason names the enumerated reasons an inbound
// agent attribution channel can fail validation. Bounded set so SIEM
// filters can rely on a closed vocabulary; new reasons land here
// when the validation regex evolves. Matches the gbounce + kbouncer
// + ibounce enum byte-for-byte per [[cross-product-agent-parity]].
type AgentHeaderRejectionReason string

const (
	// AgentHeaderRejectionInvalidNameCharset names the case where the
	// agent name pulled from `application_name=iam-jit-agent:NAME:...`
	// contained a character outside the canonical [A-Za-z0-9._-]
	// shape (shell-injection payloads land here).
	AgentHeaderRejectionInvalidNameCharset AgentHeaderRejectionReason = "invalid_name_charset"

	// AgentHeaderRejectionInvalidNameLength names the case where the
	// agent name's character composition is valid but it exceeded
	// the 64-char cap.
	AgentHeaderRejectionInvalidNameLength AgentHeaderRejectionReason = "invalid_name_length"

	// AgentHeaderRejectionInvalidSessionIDFormat names the case where
	// the session id pulled from `application_name=iam-jit-agent:...:SESSIONID`
	// contained a character outside the canonical [A-Za-z0-9_-]
	// shape (UUIDs don't carry dots).
	AgentHeaderRejectionInvalidSessionIDFormat AgentHeaderRejectionReason = "invalid_session_id_format"

	// AgentHeaderRejectionInvalidSessionIDLength names the case where
	// the session id's character composition is valid but it
	// exceeded the 128-char cap.
	AgentHeaderRejectionInvalidSessionIDLength AgentHeaderRejectionReason = "invalid_session_id_length"

	// AgentHeaderRejectionApplicationNameUnparseable is the dbounce-
	// specific reason: the `iam-jit-agent:` prefix matched but the
	// tag body failed to split into NAME:SESSIONID (missing colon /
	// empty name / empty session id). Defined in every product's
	// audit package so the cross-product reason enum is one closed
	// set even though gbounce + kbouncer never emit it.
	AgentHeaderRejectionApplicationNameUnparseable AgentHeaderRejectionReason = "application_name_unparseable"
)

// AgentNameField + AgentSessionIDField + AgentApplicationNameField
// name the canonical fields the rejection breadcrumb references.
// Centralized so the audit-log shape is one string across products +
// the cross-product test suite can assert exact-match equality.
const (
	AgentNameField            = "X-Agent-Name"
	AgentSessionIDField       = "X-Agent-Session-Id"
	AgentApplicationNameField = "application_name"
)

// ClassifyAgentNameRejection returns the canonical
// AgentHeaderRejectionReason for a raw agent-name value that
// already failed IsValidAgentName. Splits charset vs length.
func ClassifyAgentNameRejection(raw string) AgentHeaderRejectionReason {
	if len(raw) > 64 {
		return AgentHeaderRejectionInvalidNameLength
	}
	return AgentHeaderRejectionInvalidNameCharset
}

// ClassifyAgentSessionIDRejection returns the canonical
// AgentHeaderRejectionReason for a raw session-id value that
// already failed IsValidSessionID.
func ClassifyAgentSessionIDRejection(raw string) AgentHeaderRejectionReason {
	if len(raw) > 128 {
		return AgentHeaderRejectionInvalidSessionIDLength
	}
	return AgentHeaderRejectionInvalidSessionIDFormat
}

// BuildAgentHeaderRejectionBreadcrumb produces the per-rejection
// entry shape that lands at
// `unmapped.iam_jit.ext.agent_header_rejection`. NEVER include the
// raw value — only its length, for safe forensics. The truncated
// stderr line emitted by `recordRejectedAgentTag` (with control-char
// filtering) is the only sink that ever sees the raw value.
func BuildAgentHeaderRejectionBreadcrumb(field string, reason AgentHeaderRejectionReason, rawValueLength int) map[string]any {
	return map[string]any{
		"field":                 field,
		"reason":                string(reason),
		"value_redacted_length": rawValueLength,
	}
}

// ClassifyApplicationNameTagRejection inspects a malformed
// `iam-jit-agent:NAME:SESSIONID` tag and returns the most specific
// reason for the rejection. The caller MUST already have established
// the tag prefix matched but ParseAgentTagFromAppName returned
// ok=false. Returns the breadcrumb map ready to splice into the OCSF
// Ext map; the rejected value's length is the FULL tail length
// (everything after `iam-jit-agent:`) so an operator sees how much
// junk the agent SDK was sending.
func ClassifyApplicationNameTagRejection(rawName, rawSession, fullTail string) map[string]any {
	// Specific reasons take precedence over the generic
	// "unparseable" so an analyst can act on a concrete validation
	// failure. Order: name length → name charset → session length →
	// session charset → unparseable.
	if rawName != "" && len(rawName) > 64 {
		return BuildAgentHeaderRejectionBreadcrumb(
			AgentApplicationNameField,
			AgentHeaderRejectionInvalidNameLength,
			len(fullTail),
		)
	}
	if rawName != "" && !IsValidAgentName(rawName) {
		return BuildAgentHeaderRejectionBreadcrumb(
			AgentApplicationNameField,
			AgentHeaderRejectionInvalidNameCharset,
			len(fullTail),
		)
	}
	if rawSession != "" && len(rawSession) > 128 {
		return BuildAgentHeaderRejectionBreadcrumb(
			AgentApplicationNameField,
			AgentHeaderRejectionInvalidSessionIDLength,
			len(fullTail),
		)
	}
	if rawSession != "" && !IsValidSessionID(rawSession) {
		return BuildAgentHeaderRejectionBreadcrumb(
			AgentApplicationNameField,
			AgentHeaderRejectionInvalidSessionIDFormat,
			len(fullTail),
		)
	}
	// Fall-through: empty pieces / missing colon separator → the
	// whole tag body is unparseable.
	return BuildAgentHeaderRejectionBreadcrumb(
		AgentApplicationNameField,
		AgentHeaderRejectionApplicationNameUnparseable,
		len(fullTail),
	)
}

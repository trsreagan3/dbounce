// Startup banner for `dbounce run`. Extracted from cli.go's RunE so
// the banner is testable without binding ports.
//
// LOW-D8-13 (AUDIT-WB-DSLICES-1-8.md) closure: bannerOpts.Quiet
// controls fingerprint suppression. When true, only the listener
// address + dialect are emitted; the configuration-shape fields
// (mode, default-policy, profile, upstream, audit db path) are
// suppressed because their combination fingerprints the deployment
// when stderr is forwarded to centralized observability. The full
// configuration remains available via the management /healthz
// endpoint for operators who need introspection.

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/profile"
	"github.com/trsreagan3/dbounce/internal/proxy"
	"github.com/trsreagan3/dbounce/internal/rules"
	"github.com/trsreagan3/dbounce/internal/upstream"
)

// bannerOpts carries the inputs writeStartupBanner consumes. Built from
// the RunE locals so the helper has no implicit globals — keeps the
// test surface to "construct, write, assert on the written bytes."
type bannerOpts struct {
	Cfg                  proxy.Config
	StoredAuditDBPath    string
	UpstreamURL          string
	UpstreamCACert       string
	ResolvedUpstream     *upstream.Upstream
	ActiveProfileName    string
	ResolvedProfilesPath string
	// ProfileFromFlag is true when --profile was passed explicitly;
	// false when the operator relied on the env var fallback (or
	// neither). Drives the "no --profile set" hint.
	ProfileFromFlag bool
	// ProfileEnvSet is true when DBOUNCE_PROFILE env var is non-empty.
	// Combined with ProfileFromFlag = false, this means the operator
	// didn't pass the flag but env-var fallback fired; we suppress the
	// hint.
	ProfileEnvSet bool
	// Quiet drives the LOW-D8-13 fingerprint-suppressed mode.
	Quiet bool
	// AuditExporter, when non-nil, drives the #252 Slice 1
	// audit-export banner lines. The banner shows the FILE PATH +
	// the REDACTED webhook URL — the token is NEVER printed (the
	// WebhookPusher's RedactedURL helper guarantees the bearer
	// header never leaks via the banner path).
	AuditExporter *audit.Exporter
	// ActiveProfile, when non-nil, lets the banner inspect the
	// resolved profile's allow_rules to decide whether the UC-34
	// admin-grant warning fires. nil → warning is skipped (the
	// banner can't introspect what it doesn't have).
	ActiveProfile *profile.Profile
}

// writeStartupBanner writes the post-startup banner to w. Returns no
// error — the banner is best-effort (stderr is the destination in
// production; tests pass a bytes.Buffer).
func writeStartupBanner(w io.Writer, opts bannerOpts) {
	cfg := opts.Cfg
	wireProto := "tcp"
	if cfg.ListenerTLS != nil {
		wireProto = "tcp+tls"
		if cfg.ListenerTLS.RequireClientCert {
			wireProto += "+mtls"
		}
	}
	// [[discovery-first-default]] (2026-05-22): default_mode label
	// surfaces the operating shape (discovery|profile) on the headline
	// banner. discovery = no profile selected (full-user); profile =
	// operator explicitly picked a named profile via --profile NAME or
	// DBOUNCE_PROFILE env var. Cross-product parity with ibounce +
	// kbouncer + gbounce per [[cross-product-agent-parity]].
	defaultModeLabel := "discovery"
	if opts.ActiveProfileName != "" &&
		opts.ActiveProfileName != "full-user" &&
		opts.ActiveProfileName != "none" {
		defaultModeLabel = "profile"
	}
	if opts.Quiet {
		// LOW-D8-13 minimal banner: address + dialect + transport only.
		// Drop mode + default-policy + profile + upstream + audit-db
		// path — each of those fingerprints the deployment when shipped
		// to centralized observability.
		fmt.Fprintf(w,
			"dbounce wire listener  : %s:%d  (dialect=%s, transport=%s)\n",
			cfg.Host, cfg.Port, cfg.Dialect, wireProto)
		fmt.Fprintln(w,
			"dbounce mgmt /healthz : (full configuration available via /healthz; banner suppressed by --quiet-banner)")
		fmt.Fprintln(w, "Ctrl+C to stop.")
		return
	}
	fmt.Fprintf(w,
		"dbounce wire listener  : %s:%d  (dialect=%s, mode=%s, default-policy=%s, transport=%s, default_mode=%s)\n",
		cfg.Host, cfg.Port, cfg.Dialect, cfg.Mode, cfg.DefaultPolicy, wireProto, defaultModeLabel)
	mgmtScheme := "http"
	if cfg.MgmtTLSCertFile != "" {
		mgmtScheme = "https"
	}
	fmt.Fprintf(w,
		"dbounce mgmt /healthz : %s://%s:%d/healthz\n",
		mgmtScheme, cfg.MgmtHost, cfg.MgmtPort)
	fmt.Fprintf(w, "audit db              : %s\n", opts.StoredAuditDBPath)
	if opts.ResolvedUpstream != nil {
		fmt.Fprintf(w,
			"upstream              : %s (D-Slice 2 forwarding ACTIVE; TLS=%s)\n",
			opts.UpstreamURL, opts.ResolvedUpstream.TLSMode)
		if opts.UpstreamCACert != "" {
			fmt.Fprintf(w,
				"upstream CA bundle    : %s\n", opts.UpstreamCACert)
		}
	} else {
		fmt.Fprintln(w,
			"upstream              : <none> — observation-only mode (no forwarding)")
	}
	fmt.Fprintf(w,
		"profile               : %s (loaded from %s)\n",
		opts.ActiveProfileName, opts.ResolvedProfilesPath)
	if !opts.ProfileFromFlag && !opts.ProfileEnvSet {
		// [[discovery-first-default]] (2026-05-22): name DISCOVERY MODE
		// explicitly; closes D1/D2 NEGATIVE-VALUE + THEATER findings
		// from the role-effectiveness eval (see KNOWN-CAVEATS §A21).
		// Per [[security-team-positioning-safety-not-surveillance]]:
		// framed as audit transparency NOT "we're not enforcing
		// anything." Named profiles (safe-default + any custom) stay
		// first-class via --profile NAME opt-in.
		fmt.Fprintln(w,
			"                        no --profile / "+envProfileVar+" set.")
		fmt.Fprintln(w,
			"                        default mode: discovery — observing all statements, denying none.")
		fmt.Fprintln(w,
			"                          every statement is parsed, audit-logged, and")
		fmt.Fprintln(w,
			"                          (with --upstream) forwarded verbatim to the DB.")
		fmt.Fprintln(w,
			"                          full OCSF event stream + recommender operate as usual.")
		fmt.Fprintln(w,
			"                          To block writes (incl. the DCL-to-PUBLIC floor),")
		fmt.Fprintln(w,
			"                          pass --profile safe-default OR export "+envProfileVar+"=safe-default.")
	}
	fmt.Fprintln(w,
		"mode                  : cooperative — every statement is parsed + audit-logged.")
	fmt.Fprintln(w,
		"                        D-Slice 1 is OBSERVATION-ONLY: nothing actually executes")
	fmt.Fprintln(w,
		"                        against the upstream. To opt into the (D-Slice 2+) transparent")
	fmt.Fprintln(w,
		"                        block path once it ships, pass --mode transparent.")
	fmt.Fprintln(w,
		"read vs write         : reads (SELECT) and writes (INSERT/UPDATE/DELETE/MERGE/DDL/")
	fmt.Fprintln(w,
		"                        CALL/DO/EXECUTE/WITH-WRITE) are classified per-statement so the")
	fmt.Fprintln(w,
		"                        D-Slice 7 safe-default profile can default to reads-fine +")
	fmt.Fprintln(w,
		"                        writes-layered-checks (the readonly-admin-minus shape).")
	// #252 Slice 1: audit-export banner lines. Token NEVER appears —
	// the file path is operator-supplied (no secret) and the webhook
	// URL goes through WebhookPusher.RedactedURL which strips userinfo.
	if opts.AuditExporter != nil && opts.AuditExporter.Enabled() {
		st := opts.AuditExporter.Status()
		if st.Log != nil {
			fmt.Fprintf(w,
				"audit-export log     : %s  (fsync=%v, queue=%d)\n",
				st.Log.Path, st.Log.Fsync, st.Log.QueueLimit)
		}
		if st.Webhook != nil {
			// Per [[oss-only-launch-decision]]: v1.0 ships fully free; no
			// ENTERPRISE-tier label in operator-facing banners. The token
			// mask note remains so operators can verify their bearer
			// secret was not leaked to stdout.
			fmt.Fprintf(w,
				"audit-export webhook : %s  (batch=%d, queue=%d; token masked)\n",
				st.Webhook.URLRedacted, st.Webhook.BatchSize, st.Webhook.QueueLimit)
		}
		// #258 — Security Lake banner. AWS account + caller ARN come
		// from sts:GetCallerIdentity at the writer's Start(); printing
		// here matches the "log AWS account + role at startup banner"
		// requirement from the issue body.
		if st.SecurityLake != nil && st.SecurityLake.Configured {
			roleLabel := st.SecurityLake.RoleARN
			if roleLabel == "" {
				roleLabel = "(default-chain)"
			}
			fmt.Fprintf(w,
				"audit-export security-lake : s3://%s/  (region=%s, account=%s, "+
					"caller=%s, role=%s, rotation=%ds)\n",
				st.SecurityLake.Bucket,
				st.SecurityLake.Region,
				st.SecurityLake.AccountID,
				st.SecurityLake.CallerARN,
				roleLabel,
				st.SecurityLake.RotationSeconds)
		}
		// Heartbeat — per [[prompt-injection-disable-bouncer-threat]].
		// Surfaces the cadence the SIEM should expect; absence detection
		// works at the SIEM end. The in-process gap watchdog handles
		// the case where the bouncer was throttled/suspended.
		if st.Heartbeat != nil && st.Heartbeat.Configured {
			fmt.Fprintf(w,
				"heartbeat            : every %s  (gap-threshold %s)\n",
				st.Heartbeat.Interval, st.Heartbeat.GapThreshold)
		}
		// Audit-export health monitor — per
		// [[audit-export-failure-visibility]]. Surfaces when the operator
		// opted into the periodic audit_export_degraded alert. The
		// passive /healthz audit_export_health block is ALWAYS available
		// when an exporter is wired; the banner line names the monitor
		// only when the operator set the interval explicitly.
		if opts.AuditExporter.HealthMonitor != nil &&
			opts.AuditExporter.HealthMonitor.Configured() {
			fmt.Fprintln(w,
				"audit-export health  : monitored (periodic audit_export_degraded "+
					"alert on log/webhook failure)")
		}
	}
	// UC-34 admin-tight warning. Per MRR-1 audit (commit 7d69e68) +
	// [[safety-mode-lean-permissive]]: PostgreSQL handler + no
	// admin-grant allow_rules in the active profile (or no profile
	// loaded at all) → emit a WARNING so the operator isn't surprised
	// when their first GRANT attempt is denied.
	//
	// Quiet-banner suppresses this too — operators who opted into the
	// fingerprint-suppressed banner shape opted out of all banner
	// hints. The /healthz endpoint still surfaces the admin-tight
	// floor state via the per-decision audit row.
	if !opts.Quiet && shouldEmitAdminGrantWarning(cfg.Dialect, opts.ActiveProfile) {
		fmt.Fprintln(w,
			"WARNING: PostgreSQL handler enabled with no admin-grant rules in profile.")
		fmt.Fprintln(w,
			"  GRANT / ALTER DEFAULT PRIVILEGES statements will be DENIED by default")
		fmt.Fprintln(w,
			"  (admin-tight per [[safety-mode-lean-permissive]]; UC-34 admin-grant floor).")
		fmt.Fprintln(w,
			"  Add an explicit allow_rule for admin-grant operations if your workflow needs them:")
		fmt.Fprintln(w,
			"    dbounce rules add 'GRANT:*' --effect allow --note 'admin DCL allowed for migrations'")
		fmt.Fprintln(w,
			"  REVOKE is unaffected (cleanup direction is always allowed).")
	}
	fmt.Fprintln(w, "Ctrl+C to stop.")
}

// shouldEmitAdminGrantWarning returns true when the startup banner
// should emit the UC-34 admin-tight warning. Fires when:
//
//   - dialect is PostgreSQL (the only dialect with full DCL parsing
//     in v1.0; MySQL classifier doesn't surface DCL yet — separate
//     follow-up task), AND
//   - the active profile has no allow_rule whose statement_type half
//     matches GRANT (literal pattern OR wildcard).
//
// A nil profile suppresses the warning — the operator's setup is
// indeterminate and emitting a misleading hint is worse than no hint
// (cross-product banner discipline: only emit signal we're sure about).
//
// Per [[ibounce-honest-positioning]]: the warning is informational,
// not prescriptive. It names the floor + the override path + the
// REVOKE carve-out so the operator reads "here is what dbounce will
// do + how to override," not "you have misconfigured something."
func shouldEmitAdminGrantWarning(dialect proxy.Dialect, p *profile.Profile) bool {
	if dialect != proxy.DialectPostgres {
		return false
	}
	if p == nil {
		return false
	}
	if profileAllowsAdminGrant(p) {
		return false
	}
	return true
}

// profileAllowsAdminGrant returns true when the profile carries at
// least one allow_rule whose statement_type half matches GRANT (literal
// GRANT, wildcard *, or the DML/DDL/MUTATING categories are NOT
// matched — those don't cover DCL per the rule-engine semantics).
//
// Conservative match: we accept GRANT literals + bare wildcards + the
// generator-shape pattern "*:*". A rule whose statement_type is one of
// the rule-engine categories (DML/DDL/MUTATING/READ) doesn't cover DCL
// per the matcher in internal/rules — same semantics applied here.
func profileAllowsAdminGrant(p *profile.Profile) bool {
	if p == nil {
		return false
	}
	for _, ar := range p.AllowRules {
		stmtType, _, err := rules.ParsePattern(ar.Pattern)
		if err != nil {
			continue
		}
		if stmtType == rules.WildcardAny {
			return true
		}
		if strings.EqualFold(stmtType, "GRANT") {
			return true
		}
	}
	return false
}

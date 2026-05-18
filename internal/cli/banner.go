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

	"github.com/trsreagan3/dbounce/internal/audit"
	"github.com/trsreagan3/dbounce/internal/proxy"
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
		"dbounce wire listener  : %s:%d  (dialect=%s, mode=%s, default-policy=%s, transport=%s)\n",
		cfg.Host, cfg.Port, cfg.Dialect, cfg.Mode, cfg.DefaultPolicy, wireProto)
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
		fmt.Fprintln(w,
			"                        no --profile / "+envProfileVar+" set — running as 'full-user' "+
				"(passthrough). To block writes by default, pass --profile safe-default OR "+
				"export "+envProfileVar+"=safe-default.")
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
			fmt.Fprintf(w,
				"audit-export webhook : %s  (batch=%d, queue=%d; ENTERPRISE — token masked)\n",
				st.Webhook.URLRedacted, st.Webhook.BatchSize, st.Webhook.QueueLimit)
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
	}
	fmt.Fprintln(w, "Ctrl+C to stop.")
}

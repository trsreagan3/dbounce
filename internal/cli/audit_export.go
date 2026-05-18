// `dbounce audit-export health` subcommand per
// [[audit-export-failure-visibility]] Part 2.
//
// Explicit health check that the operator can chain in a startup
// script. Non-zero exit when the audit-export pipeline is degraded
// (log writes failing, webhook unreachable, webhook auth failed).
// Mirrors `ibounce audit-export health` + `kbounce audit-export
// health` so an operator running multiple bouncers on the same host
// gets one consistent surface.
//
// Implementation reads the live proxy's /healthz endpoint to pick up
// the audit_export_health block. Reading /healthz (rather than re-
// opening the log file / hitting the webhook ourselves) preserves
// the [[audit-export-failure-visibility]] invariant "Don't poll the
// webhook constantly for healthcheck (DoS the customer's collector).
// Use ACTUAL audit events as the heartbeat signal."

package cli

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/dbounce/internal/audit"
)

// newAuditExportCmd implements `dbounce audit-export ...`. The "health"
// subcommand is the v1.0 surface; future subcommands (replay, dry-run-
// emit) can attach here.
func newAuditExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit-export",
		Short: "Inspect the audit-export pipeline health",
		Long: `Operator-facing health check for the security-team
audit-export pipeline (JSONL log + HTTPS webhook). Per
[[audit-export-failure-visibility]]: silent audit-export failures
are a stealth bypass — security team thinks they have visibility,
they actually have nothing. This command makes the failure modes
explicit.`,
		Args: cobra.NoArgs,
	}
	cmd.RunE = parentRequiresSubcommand("audit-export", cmd)
	cmd.AddCommand(newAuditExportHealthCmd())
	return cmd
}

// newAuditExportHealthCmd implements the `health` subcommand. Reads
// /healthz from the running proxy + reports per-transport health +
// exits non-zero when degraded.
func newAuditExportHealthCmd() *cobra.Command {
	var (
		mgmtURL string
		asJSON  bool
		timeout time.Duration
		// insecureTLS lets the operator hit a proxy whose /healthz
		// is served via HTTPS with a self-signed cert (the operator
		// owns both ends; cert verification adds friction without
		// security value here). Defaults FALSE so we don't quietly
		// accept MITM on a remote /healthz scrape.
		insecureTLS bool
	)
	cmd := &cobra.Command{
		Use:   "health",
		Short: "Check audit-export pipeline health (exit 1 when degraded)",
		Long: `Reads /healthz from the running dbounce proxy + reports
per-transport audit-export health. Exits 0 when healthy, 1 when
degraded.

Failure modes per [[audit-export-failure-visibility]]:

  F1 webhook unreachable (network down, DNS fail, collector dead)
  F2 webhook auth 401/403 (token expired/revoked)
  F3 webhook persistent 5xx (collector overloaded)
  F4 JSONL log write fails (permission denied)
  F5 JSONL log write fails (disk full)
  F6 log file deleted/moved while bouncer running
  F7 queue overflow + dropped events
  F8 license expiry mid-session (not in this command — license-
     gate plumbing is #235)

The command READS /healthz (does not directly re-hit the webhook /
re-open the log) so a degraded webhook is not made worse by the
healthcheck itself.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			health, err := fetchAuditExportHealth(mgmtURL, timeout, insecureTLS)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(health); err != nil {
					return err
				}
			} else {
				renderAuditExportHealth(out, health)
			}
			if !health.Configured {
				// Not configured ≠ degraded per the memo. Exit 0 with
				// a clear "not configured" line above.
				return nil
			}
			if health.Degraded {
				// Exit 1 so a chained startup script can detect.
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&mgmtURL, "mgmt-url",
		"http://127.0.0.1:8768/healthz",
		"URL of the running proxy's /healthz endpoint. Default targets "+
			"the management listener bound by `dbounce run` (mgmt-host=127.0.0.1, "+
			"mgmt-port=8768).")
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"Emit the full health structure as JSON (mirrors the /healthz "+
			"audit_export_health block) instead of the human-readable summary.")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second,
		"HTTP timeout for the /healthz fetch.")
	cmd.Flags().BoolVar(&insecureTLS, "insecure-tls", false,
		"Skip TLS verification on the /healthz fetch. Use only when "+
			"the proxy's --management-tls-cert is self-signed AND you trust "+
			"the network path to the proxy. Defaults false.")
	return cmd
}

// healthzPayload is the subset of /healthz we need. We only care about
// the audit_export_health block + the top-level status; the other
// fields (mode, decisions_count, pause, etc.) are intentionally
// ignored so a schema-additive change to /healthz doesn't break this
// command.
type healthzPayload struct {
	Status            string              `json:"status"`
	AuditExportHealth *audit.ExportHealth `json:"audit_export_health"`
}

// fetchAuditExportHealth makes the GET request + extracts the health
// block. A 503 response is the EXPECTED response when the pipeline is
// degraded (it's how /healthz signals to external monitors); we still
// parse the body in that case. Other HTTP errors propagate.
func fetchAuditExportHealth(url string, timeout time.Duration, insecureTLS bool) (*audit.ExportHealth, error) {
	transport := &http.Transport{}
	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 — opt-in via --insecure-tls
	}
	client := &http.Client{Timeout: timeout, Transport: transport}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("dbounce audit-export health: GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("dbounce audit-export health: read /healthz body: %w", err)
	}
	// 200 OK = healthy. 503 = degraded (per the proxy's healthz handler
	// flip). Any other status is unexpected — surface as an error.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		return nil, fmt.Errorf(
			"dbounce audit-export health: /healthz returned HTTP %d (expected 200 or 503): %s",
			resp.StatusCode, truncateForError(body, 512))
	}
	var payload healthzPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("dbounce audit-export health: parse /healthz JSON: %w", err)
	}
	if payload.AuditExportHealth == nil {
		// /healthz didn't include the audit_export_health block. The
		// most likely cause is the proxy was built without the
		// [[audit-export-failure-visibility]] surface (i.e. it's a
		// pre-feature build) OR no audit-export was configured. Return
		// a zero-Configured value so the caller renders "not configured."
		return &audit.ExportHealth{Configured: false}, nil
	}
	return payload.AuditExportHealth, nil
}

// renderAuditExportHealth prints the human-readable summary. Mirrors
// the spec memo's example output (success + degraded forms).
func renderAuditExportHealth(w io.Writer, h *audit.ExportHealth) {
	if h == nil || !h.Configured {
		fmt.Fprintln(w,
			"audit-export not configured (no --audit-log-path or --audit-webhook-url set)")
		return
	}
	mark := func(ok bool) string {
		if ok {
			return "ok"
		}
		return "FAIL"
	}
	if h.LogConfigured {
		fmt.Fprintf(w, "  [%s] JSONL log %s\n",
			mark(h.LogWritesOK), h.LogPath)
		if h.LogLastError != "" {
			fmt.Fprintf(w, "        last error: %s (%ds ago)\n",
				h.LogLastError, h.LogLastErrorSecondsAgo)
		}
		fmt.Fprintf(w, "        dropped since start: %d\n", h.LogDroppedSinceStart)
	}
	if h.WebhookConfigured {
		webhookOK := h.WebhookConsecutiveFailures == 0 && !h.AuthFailed
		fmt.Fprintf(w, "  [%s] Webhook %s\n",
			mark(webhookOK), h.WebhookURLMasked)
		if h.WebhookLastStatusCode > 0 {
			fmt.Fprintf(w, "        last status: HTTP %d\n", h.WebhookLastStatusCode)
		}
		if h.WebhookLastSuccessSecondsAgo > 0 {
			fmt.Fprintf(w, "        last success: %ds ago\n", h.WebhookLastSuccessSecondsAgo)
		}
		if h.WebhookConsecutiveFailures > 0 {
			fmt.Fprintf(w, "        consecutive failures: %d\n", h.WebhookConsecutiveFailures)
		}
		if h.WebhookLastError != "" {
			fmt.Fprintf(w, "        last error: %s\n", h.WebhookLastError)
		}
		fmt.Fprintf(w, "        dropped since start: %d\n", h.WebhookDroppedSinceStart)
		fmt.Fprintf(w, "        queue depth: %d / %d\n",
			h.WebhookQueueDepth, h.WebhookQueueCapacity)
	}
	if h.Degraded {
		fmt.Fprintf(w, "DEGRADED: %s\n", h.Reason)
	} else {
		fmt.Fprintln(w, "audit-export healthy")
	}
}

// truncateForError caps a body slice at n bytes so a long error
// response doesn't flood operator terminals.
func truncateForError(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...(truncated)"
}

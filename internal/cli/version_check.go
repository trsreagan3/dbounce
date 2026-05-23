// `dbounce version-check` — opt-in informational check against the
// GitHub Releases API to tell the operator whether their installed
// binary is behind the latest tagged release.
//
// Privacy posture (load-bearing, per [[self-host-zero-billing-dependency]]
// + [[opt-in-feedback-pipeline]]):
//
//	* ONE outbound GET to https://api.github.com/repos/trsreagan3/
//	  dbounce/releases/latest. No body, no instance id, no machine
//	  fingerprint, no install-time identifier, no telemetry of any
//	  kind.
//	* The only request header that identifies dbounce is
//	  User-Agent: dbounce/<version> — required by GitHub's API to avoid
//	  403s on unauthenticated reads + intentionally identical for
//	  every install at the same version.
//	* The operator can disable the check entirely with
//	  DBOUNCE_NO_VERSION_CHECK=1; the env-var path NEVER performs the
//	  GET so the kill-switch is verifiable by reading the code.
//	* Network failure / bad JSON / non-200 response prints the error
//	  to stderr + exits 0. The command is informational, not a CI
//	  gate, so an offline operator never gets a failed-command exit.
//
// Sibling: kbouncer (Go) + ibounce (Python) ship the same
// `version-check` subcommand with the same env-var-name shape
// (KBOUNCE_NO_VERSION_CHECK / IBOUNCE_NO_VERSION_CHECK) + same
// "is up to date." / "OUT OF DATE." output strings. Cross-product
// parity per [[cross-product-agent-parity]].
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// versionCheckEnvVar is the kill-switch env var. Setting it to any
// non-empty value other than "0" / "false" causes version-check to
// skip the GET and exit 0 with a one-line disabled notice. Mirror of
// KBOUNCE_NO_VERSION_CHECK / IBOUNCE_NO_VERSION_CHECK on the sibling
// products.
const versionCheckEnvVar = "DBOUNCE_NO_VERSION_CHECK"

// versionCheckURL is the GitHub Releases API endpoint queried by
// `dbounce version-check`. Hard-coded — version-check has no reason
// to query anywhere else and we don't want an operator-supplied
// endpoint flag to become a covert telemetry surface.
const versionCheckURL = "https://api.github.com/repos/trsreagan3/dbounce/releases/latest"

// versionCheckTimeout is the HTTP-call ceiling. 5s matches the
// kbouncer + ibounce siblings + is well above github.com's p99 latency
// for the releases endpoint.
const versionCheckTimeout = 5 * time.Second

// versionCheckTransport is overridden in tests to a mock
// http.RoundTripper so the test suite never hits the real network.
// nil → http.DefaultTransport (the production path).
var versionCheckTransport http.RoundTripper

// newVersionCheckCmd implements `dbounce version-check`. See the
// package-doc comment above for the privacy posture.
func newVersionCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version-check",
		Short: "Check GitHub Releases for a newer dbounce version (opt-in, no telemetry)",
		Long: `Compare the installed dbounce binary's version against the latest
release tagged on GitHub.

Privacy: this command sends ZERO data about your install. It performs
a single outbound GET to GitHub's public releases endpoint with a
generic ` + "`User-Agent: dbounce/<version>`" + ` header. No instance
identifier, no machine fingerprint, no telemetry of any shape.

Disable entirely: ` + "`export " + versionCheckEnvVar + "=1`" + ` (the
env-var path performs no network call at all).

Output: prints "is up to date." or "OUT OF DATE." + an upgrade hint
on stdout. Exits 0 in all success paths; network / parse failure
prints the error to stderr + still exits 0 (informational, not a CI
gate — an offline operator should not get a failed-command exit).

Pre-launch: the GitHub releases endpoint may return 404 until the
first tag is cut. The 404 is surfaced honestly to stderr + the
command still exits 0; treat it as "no releases yet" rather than a
broken installation.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVersionCheck(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	return cmd
}

// runVersionCheck is the testable entry point. Returns nil in all
// branches (per "exit 0 on success regardless of update status").
func runVersionCheck(ctx context.Context, stdout, stderr io.Writer) error {
	// Env-var kill switch. Honored BEFORE any HTTP setup so the
	// disabled path is provably side-effect-free.
	if envDisabledVersionCheck() {
		fmt.Fprintln(stdout, "dbounce version check disabled by env ("+versionCheckEnvVar+").")
		return nil
	}

	client := &http.Client{
		Timeout:   versionCheckTimeout,
		Transport: versionCheckTransport, // nil → http.DefaultTransport
	}

	reqCtx, cancel := context.WithTimeout(ctx, versionCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, versionCheckURL, nil)
	if err != nil {
		// Should never happen for a hard-coded URL, but treat as
		// soft-failure for consistency with the rest of the command.
		fmt.Fprintf(stderr, "version check failed: %v\n", err)
		return nil
	}
	req.Header.Set("User-Agent", "dbounce/"+version)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "version check failed: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Pre-launch state: the repo has no tagged releases yet. Tell
		// the operator honestly rather than emit a generic "HTTP 404"
		// that reads like a misconfiguration.
		fmt.Fprintf(stderr,
			"version check: github returned HTTP 404 (no releases tagged yet at %s); "+
				"this is expected pre-launch.\n", versionCheckURL)
		return nil
	}

	if resp.StatusCode == http.StatusForbidden {
		// GitHub rate-limits unauthenticated reads at 60/hour/IP. The
		// rate-limit response is HTTP 403; surface it explicitly so the
		// operator doesn't conflate it with an auth problem.
		fmt.Fprintln(stderr,
			"version check: github returned HTTP 403 (likely rate-limited; "+
				"unauthenticated GitHub API is 60 req/hour/IP). Try again later.")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "version check failed: github returned HTTP %d\n", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		fmt.Fprintf(stderr, "version check failed: read body: %v\n", err)
		return nil
	}

	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		fmt.Fprintf(stderr, "version check failed: parse response: %v\n", err)
		return nil
	}

	latest := strings.TrimPrefix(strings.TrimSpace(payload.TagName), "v")
	if latest == "" {
		fmt.Fprintln(stderr, "version check failed: empty tag_name in response")
		return nil
	}

	current := strings.TrimPrefix(strings.TrimSpace(version), "v")
	// "dev" / unstamped builds can't be meaningfully compared. Surface
	// the latest tag so the operator still learns something useful.
	if current == "" || current == "dev" {
		fmt.Fprintf(stdout,
			"dbounce is an unstamped build (version=%q). Latest release: v%s. "+
				"Upgrade: brew upgrade dbounce  or  https://github.com/trsreagan3/dbounce/releases/latest\n",
			version, latest)
		return nil
	}

	cur, curOK := parseSemver(current)
	lat, latOK := parseSemver(latest)
	if !curOK || !latOK {
		// Parse failure on either side → surface honestly + still exit 0.
		fmt.Fprintf(stderr,
			"version check failed: could not compare versions (current=%q latest=%q)\n",
			current, latest)
		return nil
	}

	if compareSemver(cur, lat) >= 0 {
		fmt.Fprintf(stdout, "dbounce v%s is up to date.\n", current)
		return nil
	}
	fmt.Fprintf(stdout,
		"dbounce v%s is OUT OF DATE. Latest: v%s. "+
			"Upgrade: brew upgrade dbounce  or  https://github.com/trsreagan3/dbounce/releases/latest\n",
		current, latest)
	return nil
}

// envDisabledVersionCheck returns true when the operator has opted
// out via DBOUNCE_NO_VERSION_CHECK. Accepts any non-empty value
// except the literal strings "0" / "false" (case-insensitive) so a
// shell rc that exports DBOUNCE_NO_VERSION_CHECK=0 is not a footgun.
func envDisabledVersionCheck() bool {
	v := strings.TrimSpace(os.Getenv(versionCheckEnvVar))
	if v == "" {
		return false
	}
	switch strings.ToLower(v) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// parseSemver returns (major, minor, patch) for a string like
// "1.2.3". Returns ok=false on anything we can't cleanly parse —
// pre-release suffixes ("1.2.3-rc1") aren't supported yet + are
// treated as parse failures so the caller surfaces "could not
// compare" rather than guessing.
func parseSemver(s string) ([3]int, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// compareSemver returns -1 / 0 / 1 for a < b / a == b / a > b.
func compareSemver(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

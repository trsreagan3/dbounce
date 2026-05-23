// Tests for `dbounce version-check`. Mock http.RoundTripper so the
// suite never makes a real network call — version-check's CI
// invariant is "informational, not a gate", but the tests are still
// hermetic.
package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roundTripFunc adapts a function to http.RoundTripper so each test
// can inline its mock response without ceremony.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// withMockTransport sets versionCheckTransport for the duration of the
// test + restores the previous value on cleanup. Also pins `version`
// to a known value so the User-Agent + comparison logic are
// deterministic.
func withMockTransport(t *testing.T, currentVersion string, rt http.RoundTripper) {
	t.Helper()
	prevTransport := versionCheckTransport
	prevVersion := version
	versionCheckTransport = rt
	version = currentVersion
	t.Cleanup(func() {
		versionCheckTransport = prevTransport
		version = prevVersion
	})
	// Defensive: tests that exercise the env-var disabled path set the
	// env var explicitly; everything else must run with the kill-
	// switch unset so we actually exercise the network path.
	t.Setenv(versionCheckEnvVar, "")
}

// mockJSON returns a 200 OK response with the given JSON body.
func mockJSON(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestVersionCheck_UpToDate(t *testing.T) {
	withMockTransport(t, "1.2.3", roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return mockJSON(`{"tag_name": "v1.2.3"}`), nil
	}))

	var stdout, stderr bytes.Buffer
	require.NoError(t, runVersionCheck(context.Background(), &stdout, &stderr))

	out := stdout.String()
	assert.Contains(t, out, "dbounce v1.2.3")
	assert.Contains(t, out, "is up to date.")
	assert.NotContains(t, out, "OUT OF DATE")
	assert.Empty(t, stderr.String(), "no stderr on the happy path")
}

func TestVersionCheck_OutOfDate(t *testing.T) {
	withMockTransport(t, "1.0.0", roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return mockJSON(`{"tag_name": "v1.2.3"}`), nil
	}))

	var stdout, stderr bytes.Buffer
	require.NoError(t, runVersionCheck(context.Background(), &stdout, &stderr))

	out := stdout.String()
	assert.Contains(t, out, "dbounce v1.0.0 is OUT OF DATE.")
	assert.Contains(t, out, "Latest: v1.2.3")
	assert.Contains(t, out, "brew upgrade dbounce")
	assert.Contains(t, out, "https://github.com/trsreagan3/dbounce/releases/latest")
	assert.Empty(t, stderr.String())
}

func TestVersionCheck_RealEndpoint(t *testing.T) {
	// The URL must be the canonical GitHub releases endpoint for the
	// dbounce repo. Lock it down so a future refactor that introduces
	// an operator-supplied endpoint flag has to update this test +
	// re-justify the privacy posture.
	var got string
	withMockTransport(t, "1.0.0", roundTripFunc(func(r *http.Request) (*http.Response, error) {
		got = r.URL.String()
		return mockJSON(`{"tag_name": "v1.0.0"}`), nil
	}))

	var stdout, stderr bytes.Buffer
	require.NoError(t, runVersionCheck(context.Background(), &stdout, &stderr))

	assert.Equal(t, "https://api.github.com/repos/trsreagan3/dbounce/releases/latest", got)
}

func TestVersionCheck_404Handling(t *testing.T) {
	// Pre-launch state: the GitHub repo may have no releases tagged
	// yet. A 404 must be surfaced honestly (not as a generic HTTP
	// error) and the command must still exit 0.
	withMockTransport(t, "1.0.0", roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader(`{"message":"Not Found"}`)),
			Header:     make(http.Header),
		}, nil
	}))

	var stdout, stderr bytes.Buffer
	// Exit-0 invariant: runVersionCheck returns nil even on a 404.
	require.NoError(t, runVersionCheck(context.Background(), &stdout, &stderr))

	// stderr surfaces a recognizable "no releases tagged yet" message.
	assert.Contains(t, stderr.String(), "404")
	assert.Contains(t, stderr.String(), "no releases tagged yet")
	assert.Contains(t, stderr.String(), "expected pre-launch")
	// stdout stays empty — there's no version comparison to report.
	assert.Empty(t, stdout.String())
}

func TestVersionCheck_RateLimitHandling(t *testing.T) {
	// GitHub's unauthenticated rate limit is 60 req/hour/IP. The
	// rate-limit response is HTTP 403; the command must distinguish it
	// from a generic auth error so the operator knows it's transient.
	withMockTransport(t, "1.0.0", roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body: io.NopCloser(strings.NewReader(
				`{"message":"API rate limit exceeded"}`)),
			Header: make(http.Header),
		}, nil
	}))

	var stdout, stderr bytes.Buffer
	require.NoError(t, runVersionCheck(context.Background(), &stdout, &stderr))

	assert.Contains(t, stderr.String(), "403")
	assert.Contains(t, stderr.String(), "rate-limited")
	assert.Empty(t, stdout.String())
}

func TestVersionCheck_NetworkFailure(t *testing.T) {
	wantErr := errors.New("dial tcp: connection refused")
	withMockTransport(t, "1.0.0", roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, wantErr
	}))

	var stdout, stderr bytes.Buffer
	require.NoError(t, runVersionCheck(context.Background(), &stdout, &stderr))

	assert.Contains(t, stderr.String(), "version check failed:")
	assert.Contains(t, stderr.String(), "connection refused")
	assert.Empty(t, stdout.String(), "no stdout on the failure path")
}

func TestVersionCheck_EnvVarDisabled(t *testing.T) {
	// Set the kill-switch BEFORE installing a mock that would fail the
	// test if invoked — proves the disabled path makes no HTTP call.
	t.Setenv(versionCheckEnvVar, "1")
	prevTransport := versionCheckTransport
	prevVersion := version
	versionCheckTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("version-check must not perform any HTTP call when " + versionCheckEnvVar + " is set")
		return nil, nil
	})
	version = "1.0.0"
	t.Cleanup(func() {
		versionCheckTransport = prevTransport
		version = prevVersion
	})

	var stdout, stderr bytes.Buffer
	require.NoError(t, runVersionCheck(context.Background(), &stdout, &stderr))

	assert.Contains(t, stdout.String(), "disabled by env")
	assert.Contains(t, stdout.String(), versionCheckEnvVar)
	assert.Empty(t, stderr.String())
}

func TestVersionCheck_EnvVarFalseyValuesDoNotDisable(t *testing.T) {
	// DBOUNCE_NO_VERSION_CHECK=0 or =false in a shell rc must NOT
	// disable the check — otherwise we surprise operators who use
	// 0/false as "off".
	for _, falsey := range []string{"0", "false", "FALSE", "no", "off"} {
		falsey := falsey
		t.Run(falsey, func(t *testing.T) {
			called := false
			t.Setenv(versionCheckEnvVar, falsey)
			withMockTransport(t, "1.2.3", roundTripFunc(func(r *http.Request) (*http.Response, error) {
				called = true
				return mockJSON(`{"tag_name": "v1.2.3"}`), nil
			}))
			// withMockTransport unsets the env var; restore it for this case.
			t.Setenv(versionCheckEnvVar, falsey)

			var stdout, stderr bytes.Buffer
			require.NoError(t, runVersionCheck(context.Background(), &stdout, &stderr))
			assert.True(t, called, "falsey env value %q must NOT short-circuit", falsey)
			assert.Contains(t, stdout.String(), "is up to date.")
		})
	}
}

func TestVersionCheck_BadJSON(t *testing.T) {
	withMockTransport(t, "1.0.0", roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("not json at all <<<")),
			Header:     make(http.Header),
		}, nil
	}))

	var stdout, stderr bytes.Buffer
	require.NoError(t, runVersionCheck(context.Background(), &stdout, &stderr))

	assert.Contains(t, stderr.String(), "version check failed:")
	assert.Contains(t, stderr.String(), "parse response")
	assert.Empty(t, stdout.String())
}

func TestVersionCheck_UserAgent(t *testing.T) {
	var got string
	withMockTransport(t, "9.9.9", roundTripFunc(func(r *http.Request) (*http.Response, error) {
		got = r.Header.Get("User-Agent")
		return mockJSON(`{"tag_name": "v9.9.9"}`), nil
	}))

	var stdout, stderr bytes.Buffer
	require.NoError(t, runVersionCheck(context.Background(), &stdout, &stderr))

	assert.Equal(t, "dbounce/9.9.9", got,
		"User-Agent must be dbounce/<version> with NO instance id / fingerprint")
}

func TestVersionCheck_DevBuild(t *testing.T) {
	// Unstamped "dev" build can't be semver-compared. The user still
	// gets a useful "latest is X" message + the upgrade URL.
	withMockTransport(t, "dev", roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return mockJSON(`{"tag_name": "v2.0.0"}`), nil
	}))

	var stdout, stderr bytes.Buffer
	require.NoError(t, runVersionCheck(context.Background(), &stdout, &stderr))

	out := stdout.String()
	assert.Contains(t, out, "unstamped build")
	assert.Contains(t, out, "Latest release: v2.0.0")
	assert.Contains(t, out, "https://github.com/trsreagan3/dbounce/releases/latest")
}

func TestVersionCheck_CobraWiringExitsZero(t *testing.T) {
	// Smoke-test the cobra wiring: `dbounce version-check` should
	// resolve to our command + return nil from Execute even when the
	// underlying transport fails.
	withMockTransport(t, "1.0.0", roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("simulated offline")
	}))

	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"version-check"})
	require.NoError(t, root.Execute())

	assert.Contains(t, stderr.String(), "version check failed:")
}

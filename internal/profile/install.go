// Package profile — install.go
//
// `dbounce profile install --from URL` support.
//
// Mirrors kbouncer's profile/install.go 1:1. dbounce, kbouncer, and
// iam-jit-bouncer all share the enterprise-profile-distribution
// shape: IT teams publish org-curated profiles at an HTTPS URL,
// engineers install them on day 1, and the installed profiles are
// read-only at the CLI surface so engineers can't quietly edit a deny
// rule out from under their security team.
//
// Read-only invariant:
//
//   - A profile whose Source field is non-empty and not "local" is
//     refused by UpsertProfile.
//   - `profile install` itself bypasses that check via the package-
//     private writeInstalledProfiles helper.
//   - The Source field is always FORCED to the fetch URL on install,
//     regardless of what the upstream YAML claims.
//
// Security:
//
//   - HTTPS-only. http:// is refused.
//   - Optional --sha256 pin.
//   - All-or-nothing parse: any failed validation aborts the install.

package profile

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// InstallExitOK is returned on success.
	InstallExitOK = 0
	// InstallExitPayload is returned for payload / server problems.
	InstallExitPayload = 1
	// InstallExitOperator is returned for operator-fixable problems.
	InstallExitOperator = 2
)

// InstallError carries a structured exit code plus a human-readable
// message so the cmd/ package can map both onto stderr / os.Exit
// without re-parsing the message text.
type InstallError struct {
	ExitCode   int
	Message    string
	Underlying error
}

func (e *InstallError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *InstallError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Underlying
}

func installErr(code int, msg string) *InstallError {
	return &InstallError{ExitCode: code, Message: msg}
}

func installErrWrap(code int, msg string, cause error) *InstallError {
	return &InstallError{ExitCode: code, Message: msg, Underlying: cause}
}

// InstallOptions tunes a single `profile install` invocation.
type InstallOptions struct {
	From           string
	ExpectedSHA256 string
	Force          bool
	Timeout        time.Duration
	HTTPClient     *http.Client
	ProfilesPath   string
}

// InstallResult summarizes a successful install.
type InstallResult struct {
	SourceURL      string
	ProfilesPath   string
	InstalledNames []string
	SHA256         string
	SHA256Verified bool
}

// Install fetches the URL, validates the payload, and writes the
// profiles to disk.
func Install(ctx context.Context, opts InstallOptions) (*InstallResult, error) {
	if err := requireHTTPS(opts.From); err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, opts.From, nil)
	if err != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("build fetch request: %v", err), err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("fetch failed: %v", err), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, installErr(InstallExitPayload,
			fmt.Sprintf("fetch failed: HTTP %d", resp.StatusCode))
	}
	// HIGH-D8-05 (AUDIT-WB-DSLICES-1-8.md) closure: bound the response
	// body so a malicious / compromised distribution server can't push
	// an arbitrarily-large payload into memory + yaml.Unmarshal. 1 MiB
	// is generous for YAML profiles (the bundled defaults are < 16 KiB);
	// operators with a real need for larger payloads should split into
	// multiple installs (the schema supports it cleanly). Defense-in-
	// depth pairing with the existing Timeout — Timeout bounds wall-
	// clock, this bounds memory. We use io.LimitReader with a +1 buffer
	// so a payload that's EXACTLY maxProfilePayload bytes succeeds while
	// anything strictly larger trips the size check.
	limited := io.LimitReader(resp.Body, maxProfilePayload+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("fetch failed: read body: %v", err), err)
	}
	if int64(len(payload)) > maxProfilePayload {
		return nil, installErr(InstallExitPayload,
			fmt.Sprintf("fetch failed: payload exceeds maximum size of %d bytes "+
				"(HIGH-D8-05 from AUDIT-WB-DSLICES-1-8.md): a profile YAML this "+
				"large is almost certainly a misconfigured / hostile distribution "+
				"server. Split into multiple smaller profiles + install each, or "+
				"verify the URL.", maxProfilePayload))
	}
	return InstallFromBytes(payload, opts)
}

// maxProfilePayload caps `profile install --from URL` response bodies.
// 1 MiB is much larger than any legitimate profile YAML (bundled
// defaults are < 16 KiB) but small enough that an attacker can't exhaust
// memory in a single fetch. The cap is a hard size limit, not a soft
// threshold — exceeding it is treated as a payload-class error so the
// operator gets a clear "this is too large to be legitimate" message.
const maxProfilePayload = int64(1 << 20)

// InstallFromBytes is the half of Install that operates on already-
// fetched bytes.
func InstallFromBytes(payload []byte, opts InstallOptions) (*InstallResult, error) {
	if err := requireHTTPS(opts.From); err != nil {
		return nil, err
	}

	sum := sha256.Sum256(payload)
	actualHex := hex.EncodeToString(sum[:])
	verified := false
	if opts.ExpectedSHA256 != "" {
		want := normalizeSHA256(opts.ExpectedSHA256)
		if want != actualHex {
			return nil, installErr(InstallExitOperator,
				fmt.Sprintf("sha256 mismatch:\n  expected: %s\n  actual:   %s\nrefusing to install.",
					want, actualHex))
		}
		verified = true
	}

	var raw map[string]any
	if err := yaml.Unmarshal(payload, &raw); err != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("payload is not valid YAML: %v", err), err)
	}
	profilesAny, ok := raw["profiles"]
	if !ok {
		return nil, installErr(InstallExitPayload,
			"payload must contain a non-empty `profiles` object")
	}
	profilesMap, ok := profilesAny.(map[string]any)
	if !ok {
		return nil, installErr(InstallExitPayload,
			"payload must contain a non-empty `profiles` object")
	}
	if len(profilesMap) == 0 {
		return nil, installErr(InstallExitPayload,
			"payload must contain a non-empty `profiles` object")
	}

	parsed, names, err := parseInstallPayload(profilesMap, opts.From)
	if err != nil {
		return nil, err
	}

	resolvedPath := opts.ProfilesPath
	if resolvedPath == "" {
		rp, perr := DefaultProfilesPath()
		if perr != nil {
			return nil, installErrWrap(InstallExitPayload,
				fmt.Sprintf("resolve profiles path: %v", perr), perr)
		}
		resolvedPath = rp
	}
	existing, eerr := readProfilesFile(resolvedPath)
	if eerr != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("read existing profiles: %v", eerr), eerr)
	}
	var conflicts []conflictRow
	for _, name := range names {
		if prior, ok := existing[name]; ok {
			conflicts = append(conflicts, conflictRow{
				Name:        name,
				PriorSource: priorSourceLabel(prior),
			})
		}
	}
	if len(conflicts) > 0 && !opts.Force {
		var b strings.Builder
		b.WriteString("the following profiles already exist; pass --force to overwrite:\n")
		for _, c := range conflicts {
			fmt.Fprintf(&b, "  %s  (current source: %s)\n", c.Name, c.PriorSource)
		}
		return nil, installErr(InstallExitOperator, strings.TrimRight(b.String(), "\n"))
	}

	if err := writeInstalledProfiles(resolvedPath, parsed); err != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("write profiles: %v", err), err)
	}

	return &InstallResult{
		SourceURL:      opts.From,
		ProfilesPath:   resolvedPath,
		InstalledNames: names,
		SHA256:         actualHex,
		SHA256Verified: verified,
	}, nil
}

type conflictRow struct {
	Name        string
	PriorSource string
}

func priorSourceLabel(p *Profile) string {
	if p == nil || p.Source == "" {
		return "local"
	}
	return p.Source
}

func requireHTTPS(rawURL string) *InstallError {
	if rawURL == "" {
		return installErr(InstallExitOperator,
			"refusing to fetch: --from URL is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return installErrWrap(InstallExitOperator,
			fmt.Sprintf("refusing to fetch from %q: not a valid URL: %v", rawURL, err), err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return installErr(InstallExitOperator,
			fmt.Sprintf("refusing to fetch from %q: only https:// URLs are allowed "+
				"(MITM-substitutable plaintext is an attack vector against "+
				"IT-distributed profiles).", rawURL))
	}
	return nil
}

func normalizeSHA256(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, ":", "")
	s = strings.TrimSpace(s)
	return s
}

func parseInstallPayload(profilesMap map[string]any, sourceURL string) ([]*Profile, []string, *InstallError) {
	names := make([]string, 0, len(profilesMap))
	for name := range profilesMap {
		names = append(names, name)
	}
	sortStrings(names)

	parsed := make([]*Profile, 0, len(names))
	for _, name := range names {
		bodyAny := profilesMap[name]
		body, ok := bodyAny.(map[string]any)
		if !ok {
			if bodyAny == nil {
				body = map[string]any{}
			} else {
				return nil, nil, installErr(InstallExitPayload,
					fmt.Sprintf("profile %q must be a YAML object", name))
			}
		}
		body["source"] = sourceURL

		bodyYAML, err := yaml.Marshal(body)
		if err != nil {
			return nil, nil, installErrWrap(InstallExitPayload,
				fmt.Sprintf("profile %q: re-encode for validation: %v", name, err), err)
		}
		var p Profile
		if err := yaml.Unmarshal(bodyYAML, &p); err != nil {
			return nil, nil, installErrWrap(InstallExitPayload,
				fmt.Sprintf("profile %q failed to parse: %v", name, err), err)
		}
		p.Name = name
		p.Source = sourceURL
		if verr := p.validate(); verr != nil {
			return nil, nil, installErr(InstallExitPayload,
				fmt.Sprintf("profile %q failed validation: %v", name, verr))
		}
		parsed = append(parsed, &p)
	}
	return parsed, names, nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func readProfilesFile(path string) (map[string]*Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]*Profile{}, nil
		}
		return nil, err
	}
	var pf profileFile
	if err := yaml.Unmarshal(raw, &pf); err != nil {
		return nil, fmt.Errorf("parse profiles yaml at %s: %w", path, err)
	}
	out := map[string]*Profile{}
	for name, p := range pf.Profiles {
		if p == nil {
			p = &Profile{}
		}
		p.Name = name
		out[name] = p
	}
	return out, nil
}

func writeInstalledProfiles(path string, profiles []*Profile) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %q: %w", dir, err)
		}
	}

	merged := profileFile{Profiles: map[string]*Profile{}}
	if raw, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(raw, &merged); err != nil {
			return fmt.Errorf("parse existing profiles yaml: %w", err)
		}
		if merged.Profiles == nil {
			merged.Profiles = map[string]*Profile{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat existing profiles yaml: %w", err)
	}

	for _, p := range profiles {
		merged.Profiles[p.Name] = p
	}

	out, err := yaml.Marshal(&merged)
	if err != nil {
		return fmt.Errorf("encode profiles yaml: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".profiles-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// UpsertProfile persists a single profile to profiles.yaml — insert
// if absent, replace if present.
//
// Read-only invariant: refuses to overwrite a profile whose existing
// Source field is anything other than empty/"local".
func UpsertProfile(p *Profile, path string) error {
	if p == nil || p.Name == "" {
		return errors.New("dbounce: UpsertProfile: Name is required")
	}
	resolved := path
	if resolved == "" {
		rp, err := DefaultProfilesPath()
		if err != nil {
			return fmt.Errorf("dbounce: resolve profiles path: %w", err)
		}
		resolved = rp
	}
	if dir := filepath.Dir(resolved); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("dbounce: mkdir %q: %w", dir, err)
		}
	}

	merged := profileFile{Profiles: map[string]*Profile{}}
	if raw, err := os.ReadFile(resolved); err == nil {
		if err := yaml.Unmarshal(raw, &merged); err != nil {
			return fmt.Errorf("dbounce: parse existing profiles yaml: %w", err)
		}
		if merged.Profiles == nil {
			merged.Profiles = map[string]*Profile{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("dbounce: read profiles yaml: %w", err)
	}

	if prior, exists := merged.Profiles[p.Name]; exists && prior != nil {
		if !prior.IsLocalSource() {
			return fmt.Errorf(
				"profile %q is sourced from %q and is read-only. "+
					"Pick a different name for your local override.",
				p.Name, prior.Source)
		}
	}

	return upsertProfileClean(resolved, p, &merged)
}

func upsertProfileClean(path string, p *Profile, merged *profileFile) error {
	name := p.Name
	if name == "" {
		return errors.New("dbounce: UpsertProfile: Name is required")
	}
	if merged.Profiles == nil {
		merged.Profiles = map[string]*Profile{}
	}
	merged.Profiles[name] = p

	out, err := yaml.Marshal(merged)
	if err != nil {
		return fmt.Errorf("dbounce: encode profiles yaml: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".profiles-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("dbounce: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("dbounce: write temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("dbounce: chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("dbounce: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("dbounce: rename into place: %w", err)
	}
	return nil
}

// InsecureTLSClientForTests returns an *http.Client that skips TLS
// verification. Test-only helper exported for the install_test.go
// suite so httptest.NewTLSServer (which presents a self-signed cert)
// can be the fetch target. Production code must NEVER pass this to
// Install.
func InsecureTLSClientForTests() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			//nolint:gosec // intentional: test fixture for httptest.NewTLSServer
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

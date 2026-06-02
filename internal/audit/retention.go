// Compliance retention tiering — ADOPT-10 / #734 / #624. Port of the
// Python retention.py (§A67). Multi-tier retention (hot / warm / cold)
// with per-framework defaults (PCI / HIPAA / SOX / GDPR / custom),
// write-time PII redaction, and two-key purge safety. The framework
// defaults + tier-transition semantics match the Python implementation
// exactly so an operator reads the same policy whether the bouncer is
// ibounce (Python) or a Go bouncer.
//
// Tier thresholds are CUMULATIVE age (days), not phase durations:
// "after Y days in the log the event has aged into tier X". Tier
// transitions are RENAMES (atomic); purge (the only destructive op)
// requires purge_after_days to be set AND the file older than it.
package audit

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Compliance frameworks.
const (
	FrameworkPCI    = "pci"
	FrameworkHIPAA  = "hipaa"
	FrameworkSOX    = "sox"
	FrameworkGDPR   = "gdpr"
	FrameworkCustom = "custom"
)

// Tier names. Used in archive filename prefixes.
const (
	TierHot  = "hot"
	TierWarm = "warm"
	TierCold = "cold"

	warmPrefix = "warm-"
	coldPrefix = "cold-"
)

// frameworkDefault is (hot, warm, cold, purgeAfter, gdprPIIPurge).
// purgeAfter < 0 means "keep indefinitely" (Python None). Values match
// _FRAMEWORK_DEFAULTS in retention.py exactly.
type frameworkDefault struct {
	hot, warm, cold int
	purgeAfter      int // <0 = none
	gdprPIIPurge    bool
}

var frameworkDefaults = map[string]frameworkDefault{
	FrameworkPCI:    {30, 120, 365, -1, false},
	FrameworkHIPAA:  {30, 210, 2190, 2190, false},
	FrameworkSOX:    {30, 395, 2555, -1, false},
	FrameworkGDPR:   {30, 120, 365, -1, true},
	FrameworkCustom: {30, 120, 365, -1, false},
}

// KnownFrameworks lists the valid compliance frameworks (sorted).
func KnownFrameworks() []string {
	out := make([]string, 0, len(frameworkDefaults))
	for k := range frameworkDefaults {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// piiPattern is one (kind, regex) redaction pattern. Matches
// DEFAULT_PII_PATTERNS in retention.py.
type piiPattern struct {
	kind string
	re   *regexp.Regexp
}

// defaultPIIPatterns redacts CREDENTIAL-shaped patterns by default
// per [[mitm-beta-pii-pci-concern]]. Note: Go's regexp (RE2) lacks \b
// word boundaries, so the AWS-key / secret / JWT patterns below
// approximate the Python \b anchors with explicit (^|[^...]) guards
// where it matters; the placeholder + kind labels are identical.
var defaultPIIPatterns = []piiPattern{
	{"aws_access_key_id", regexp.MustCompile(`(AKIA|ASIA)[0-9A-Z]{16}`)},
	{"bearer_token", regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._\-]+`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`)},
	{"email", regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)},
}

func redactionPlaceholder(kind string) string {
	return "[REDACTED:" + kind + "]"
}

// RetentionPolicy is a declarative retention policy. Fields map 1:1 to
// the .iam-jit.yaml retention: block.
type RetentionPolicy struct {
	Compliance     string
	HotDays        int
	WarmDays       int
	ColdDays       int
	PurgeAfterDays int // <0 = keep indefinitely
	GDPRPIIPurge   bool
	patterns       []piiPattern
}

// PolicyForFramework builds a RetentionPolicy from a framework name +
// optional overrides (nil = use the framework default). Returns an
// error on unknown framework or an invalid threshold ordering. Matches
// policy_for_framework().
func PolicyForFramework(framework string, hotDays, warmDays, coldDays, purgeAfterDays *int, gdprPIIPurge *bool) (RetentionPolicy, error) {
	f := strings.ToLower(strings.TrimSpace(framework))
	def, ok := frameworkDefaults[f]
	if !ok {
		return RetentionPolicy{}, fmt.Errorf("unknown compliance framework %q; expected one of %v", framework, KnownFrameworks())
	}
	h := def.hot
	if hotDays != nil {
		h = *hotDays
	}
	w := def.warm
	if warmDays != nil {
		w = *warmDays
	}
	c := def.cold
	if coldDays != nil {
		c = *coldDays
	}
	p := def.purgeAfter
	if purgeAfterDays != nil {
		p = *purgeAfterDays
	}
	g := def.gdprPIIPurge
	if gdprPIIPurge != nil {
		g = *gdprPIIPurge
	}
	if h <= 0 {
		return RetentionPolicy{}, fmt.Errorf("hot_days must be > 0")
	}
	if w < h {
		return RetentionPolicy{}, fmt.Errorf("warm_days (%d) must be >= hot_days (%d); use warm_days == hot_days to skip the warm tier", w, h)
	}
	if c < w {
		return RetentionPolicy{}, fmt.Errorf("cold_days (%d) must be >= warm_days (%d); use cold_days == warm_days to skip the cold tier", c, w)
	}
	if p >= 0 && p < c {
		return RetentionPolicy{}, fmt.Errorf("purge_after_days (%d) must be >= cold_days (%d) so data within the declared cold-tier retention window is never purged", p, c)
	}
	return RetentionPolicy{
		Compliance:     f,
		HotDays:        h,
		WarmDays:       w,
		ColdDays:       c,
		PurgeAfterDays: p,
		GDPRPIIPurge:   g,
		patterns:       defaultPIIPatterns,
	}, nil
}

// DefaultPolicy is the conservative default (PCI shape) when the
// operator hasn't picked a framework.
func DefaultPolicy() RetentionPolicy {
	p, _ := PolicyForFramework(FrameworkPCI, nil, nil, nil, nil, nil)
	return p
}

// RedactEventPII walks event recursively replacing values matching the
// policy's patterns with placeholders. No-op when GDPRPIIPurge is
// false. Mutates + returns event. Matches redact_event_pii().
func RedactEventPII(event map[string]any, policy RetentionPolicy) map[string]any {
	if !policy.GDPRPIIPurge {
		return event
	}
	redactInPlace(event, policy.patterns)
	return event
}

func redactString(s string, patterns []piiPattern) string {
	for _, p := range patterns {
		s = p.re.ReplaceAllString(s, redactionPlaceholder(p.kind))
	}
	return s
}

func redactInPlace(obj any, patterns []piiPattern) {
	switch v := obj.(type) {
	case map[string]any:
		for k, val := range v {
			if s, ok := val.(string); ok {
				v[k] = redactString(s, patterns)
			} else {
				redactInPlace(val, patterns)
			}
		}
	case []any:
		for i, val := range v {
			if s, ok := val.(string); ok {
				v[i] = redactString(s, patterns)
			} else {
				redactInPlace(val, patterns)
			}
		}
	}
}

// TierTransition records one file's tier transition.
type TierTransition struct {
	Path     string  `json:"path"`
	FromTier string  `json:"from_tier"`
	ToTier   string  `json:"to_tier"`
	AgeDays  float64 `json:"age_days"`
}

// RetentionApplyResult aggregates one ApplyRetention run.
type RetentionApplyResult struct {
	Transitions  []TierTransition `json:"transitions"`
	Purged       []string         `json:"purged"`
	ColdEligible []string         `json:"cold_eligible"`
}

func tierOf(name string) string {
	if strings.HasPrefix(name, coldPrefix) {
		return TierCold
	}
	if strings.HasPrefix(name, warmPrefix) {
		return TierWarm
	}
	return TierHot
}

func ageDays(path string, now time.Time) float64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	d := now.Sub(fi.ModTime()).Seconds() / 86400.0
	// Round to 6 dp to avoid float drift at exact boundaries (matches
	// Python _age_days).
	return math.Round(d*1e6) / 1e6
}

// targetTier computes the final target tier for a file of the given
// age under policy. Single-pass multi-hop (matches Python _target_tier
// / the #503 fix).
func targetTier(age float64, policy RetentionPolicy) string {
	if age > float64(policy.WarmDays) && policy.ColdDays > policy.WarmDays {
		return TierCold
	}
	if age > float64(policy.HotDays) && policy.WarmDays > policy.HotDays {
		return TierWarm
	}
	return TierHot
}

func isRotatedArchive(name string) bool {
	if !strings.HasSuffix(name, ".jsonl.gz") {
		return false
	}
	return strings.HasPrefix(name, "audit-") ||
		strings.HasPrefix(name, warmPrefix) ||
		strings.HasPrefix(name, coldPrefix)
}

// ApplyRetention walks logDir transitioning rotated archives between
// tiers per policy + collecting purge candidates. The active log is
// never touched. Transitions are renames; purge is the only
// destructive op (two-key safety). Cold-eligible files are RETURNED,
// not deleted — the S3 sink owns upload. Matches apply_retention().
func ApplyRetention(logDir string, policy RetentionPolicy, now time.Time) (RetentionApplyResult, error) {
	res := RetentionApplyResult{}
	info, err := os.Stat(logDir)
	if err != nil || !info.IsDir() {
		return res, nil
	}
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return res, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		if !isRotatedArchive(name) {
			continue
		}
		path := filepath.Join(logDir, name)
		current := tierOf(name)
		age := ageDays(path, now)

		// Purge check (highest priority + only destructive action).
		if policy.PurgeAfterDays >= 0 && age >= float64(policy.PurgeAfterDays) {
			if err := os.Remove(path); err == nil {
				res.Purged = append(res.Purged, path)
			}
			continue
		}

		target := targetTier(age, policy)
		if current == target {
			if current == TierCold {
				res.ColdEligible = append(res.ColdEligible, path)
			}
			continue
		}

		switch {
		case current == TierHot && target == TierWarm:
			stem := strings.TrimPrefix(name, "audit-")
			dst := filepath.Join(logDir, warmPrefix+stem)
			if err := transition(path, dst, policy); err == nil {
				res.Transitions = append(res.Transitions, TierTransition{Path: dst, FromTier: TierHot, ToTier: TierWarm, AgeDays: roundAge(age)})
			}
		case current == TierHot && target == TierCold:
			stem := strings.TrimPrefix(name, "audit-")
			dst := filepath.Join(logDir, coldPrefix+stem)
			if err := transition(path, dst, policy); err == nil {
				res.Transitions = append(res.Transitions, TierTransition{Path: dst, FromTier: TierHot, ToTier: TierCold, AgeDays: roundAge(age)})
				res.ColdEligible = append(res.ColdEligible, dst)
			}
		case current == TierWarm && target == TierCold:
			stem := strings.TrimPrefix(name, warmPrefix)
			dst := filepath.Join(logDir, coldPrefix+stem)
			if err := atomicRename(path, dst); err == nil {
				res.Transitions = append(res.Transitions, TierTransition{Path: dst, FromTier: TierWarm, ToTier: TierCold, AgeDays: roundAge(age)})
				res.ColdEligible = append(res.ColdEligible, dst)
			}
		}
	}
	return res, nil
}

func roundAge(a float64) float64 { return math.Round(a*100) / 100 }

func atomicRename(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.Rename(src, dst)
}

// transition renames src→dst, scrubbing PII first when the policy's
// GDPRPIIPurge is set (matches the hot→warm/cold scrub path).
func transition(src, dst string, policy RetentionPolicy) error {
	if policy.GDPRPIIPurge {
		return scrubArchivePII(src, dst, policy)
	}
	return atomicRename(src, dst)
}

// scrubArchivePII decompresses src, scrubs PII per policy, recompresses
// to dst, removes src. Streaming line-by-line. Matches
// _scrub_archive_pii().
func scrubArchivePII(src, dst string, policy RetentionPolicy) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	gzr, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gzr.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	gzw := gzip.NewWriter(out)

	sc := bufio.NewScanner(gzr)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			_, _ = gzw.Write(append(append([]byte(nil), line...), '\n'))
			continue
		}
		tree, derr := decodeJSONNumber(append([]byte(nil), line...))
		if derr != nil {
			_, _ = gzw.Write(append(append([]byte(nil), line...), '\n'))
			continue
		}
		if obj, ok := tree.(map[string]any); ok {
			RedactEventPII(obj, policy)
		}
		b, merr := json.Marshal(tree)
		if merr != nil {
			_, _ = gzw.Write(append(append([]byte(nil), line...), '\n'))
			continue
		}
		_, _ = gzw.Write(append(b, '\n'))
	}
	if err := gzw.Close(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(src)
}

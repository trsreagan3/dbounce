// baseline.go ports anomaly_detection/baseline.py: the per-agent
// behavioral baseline (rolling 14d window + exponential decay).
//
// Storage: in-memory, thread-safe. The Python reference persists to a
// sibling SQLite DB; the Go port keeps the learned baseline in process
// memory (a learned baseline is disposable state the operator can lose
// at any time without correctness impact, and an in-memory store keeps
// the core BYTE-IDENTICAL across the three repos with zero non-stdlib
// dependency per [[config-export-wire-divergence]]). The math (rolling
// window + decay_rate^age weighting + Poisson-ish variance proxy +
// hour-of-day mean/stddev) matches baseline.py exactly.
//
// PRIVACY (matches baseline.py): we NEVER store individual data
// values — only structural patterns (action shape, canonical resource
// pattern, hour-of-day bucket, counts). canonicalResourcePattern is
// lossy on purpose. Per [[independence-as-security-property]] the
// baseline stays local; nothing is sent anywhere.
package anomaly

import (
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// DimensionStats is the per-dimension summary the detector consumes
// for z-score scoring. Ports baseline.py DimensionStats.
type DimensionStats struct {
	Dimension string
	Count     float64
	Mean      float64
	Stddev    float64
}

// ZScore returns |observed - mean| / max(stddev, epsilon). Ports
// DimensionStats.z_score.
func (d DimensionStats) ZScore(observed float64) float64 {
	sd := d.Stddev
	if sd < 1e-9 {
		sd = 1e-9
	}
	return math.Abs(observed-d.Mean) / sd
}

// BaselineSummary is the snapshot the detector scores against. Ports
// baseline.py BaselineSummary.
type BaselineSummary struct {
	AgentIdentity            string
	Action                   string
	ResourcePattern          string
	TotalObservationsRolling int
	TotalObservationsDecayed float64
	Dimensions               map[string]DimensionStats
}

const prodHint = "prod"

var (
	prodHints    = []string{"prod", "production", "live"}
	stagingHints = []string{"staging", "stage", "qa", "test"}
)

// canonicalResourcePattern returns a STRUCTURAL pattern for resource —
// never the raw value. Ports baseline.py canonical_resource_pattern
// verbatim so the privacy invariant + bucketing match the Python
// reference across all protocols (AWS ARN / k8s / SQL):
//
//   - arn:aws:<svc>:...        -> arn:aws:<svc>::<env>
//   - <ns>/<name> (k8s)        -> k8s:<env>
//   - <schema>.<table> (sql)   -> sql:<env>
//   - "*"                       -> "*"
//   - "" / absent               -> "-"
//   - anything else             -> opaque:<env>
//
// where <env> is prod / staging / other based on substring hints.
func canonicalResourcePattern(resource string) string {
	s := strings.TrimSpace(resource)
	if s == "" {
		return "-"
	}
	if s == "*" {
		return "*"
	}
	lower := strings.ToLower(s)
	env := "other"
	for _, h := range prodHints {
		if strings.Contains(lower, h) {
			env = prodHint
			break
		}
	}
	if env == "other" {
		for _, h := range stagingHints {
			if strings.Contains(lower, h) {
				env = "staging"
				break
			}
		}
	}
	if strings.HasPrefix(s, "arn:") {
		parts := strings.SplitN(s, ":", 6)
		svc := "unknown"
		if len(parts) > 2 {
			svc = parts[2]
		}
		return "arn:aws:" + svc + "::" + env
	}
	if strings.Contains(s, "/") && !strings.HasPrefix(s, "/") {
		return "k8s:" + env
	}
	if strings.Contains(s, ".") && !strings.Contains(s, " ") {
		return "sql:" + env
	}
	return "opaque:" + env
}

// observation is one recorded event (privacy-safe shape only).
type observation struct {
	observedAt int64 // unix seconds
	hourOfDay  int
}

// aggKey identifies a (agent, action, resource_pattern) baseline.
type aggKey struct {
	agent    string
	action   string
	resource string
}

// BaselineStore holds per-(agent, action, resource_pattern) rolling
// observations + a decayed aggregate. Thread-safe. Ports baseline.py
// BaselineStore (the on-disk worker/queue is collapsed into a simple
// guarded map since storage is in-memory).
type BaselineStore struct {
	mu             sync.Mutex
	windowSeconds  int64
	decayRate      float64
	decayPeriodSec int64
	clock          func() time.Time

	rolling map[aggKey][]observation
	dropped int64
}

// Default tuning mirrors baseline.py defaults.
const (
	defaultWindowSeconds   = 14 * 24 * 3600 // 14 days
	defaultDecayPeriodSecs = 24 * 3600      // one decay step per day
)

// NewBaselineStore builds an in-memory store. windowSeconds<=0 uses the
// 14d default; decayRate<=0 or >1 uses 0.96.
func NewBaselineStore(windowSeconds int, decayRate float64) *BaselineStore {
	ws := int64(windowSeconds)
	if ws <= 0 {
		ws = defaultWindowSeconds
	}
	dr := decayRate
	if !(dr > 0 && dr <= 1.0) {
		dr = defaultDecayRate
	}
	return &BaselineStore{
		windowSeconds:  ws,
		decayRate:      dr,
		decayPeriodSec: defaultDecayPeriodSecs,
		clock:          time.Now,
		rolling:        map[aggKey][]observation{},
	}
}

// withClock injects a fake clock for deterministic tests.
func (s *BaselineStore) withClock(fn func() time.Time) *BaselineStore {
	s.mu.Lock()
	s.clock = fn
	s.mu.Unlock()
	return s
}

// nowUnix returns the store clock's current unix seconds.
func (s *BaselineStore) nowUnix() int64 { return s.clock().UTC().Unix() }

// Observe records one observation. resource is canonicalised before
// storage; the raw value never lands. Ports BaselineStore.observe.
// observedAtUnix<=0 uses the store clock (so callers normally omit it).
func (s *BaselineStore) Observe(agentIdentity, action, resource string, observedAtUnix int64) {
	if action == "" {
		return
	}
	ai := strings.TrimSpace(agentIdentity)
	if ai == "" {
		ai = "anonymous"
	}
	ts := observedAtUnix
	if ts <= 0 {
		ts = s.nowUnix()
	}
	pat := canonicalResourcePattern(resource)
	hr := time.Unix(ts, 0).UTC().Hour()

	s.mu.Lock()
	defer s.mu.Unlock()
	key := aggKey{agent: ai, action: action, resource: pat}
	obs := s.rolling[key]
	obs = append(obs, observation{observedAt: ts, hourOfDay: hr})
	// Prune rows past the window so memory stays bounded.
	cutoff := s.nowUnixLocked() - s.windowSeconds
	pruned := obs[:0]
	for _, o := range obs {
		if o.observedAt >= cutoff {
			pruned = append(pruned, o)
		}
	}
	s.rolling[key] = pruned
}

// nowUnixLocked is nowUnix for callers already holding s.mu.
func (s *BaselineStore) nowUnixLocked() int64 { return s.clock().UTC().Unix() }

// SummaryFor computes the per-dimension summary the detector consumes.
// Ports BaselineStore.summary_for: a rolling-window exact view +
// decay-weighted aggregates (suffixed "_decayed"). nowUnix<=0 uses the
// store clock.
func (s *BaselineStore) SummaryFor(agentIdentity, action, resource string, nowUnix int64) BaselineSummary {
	pat := canonicalResourcePattern(resource)
	ai := strings.TrimSpace(agentIdentity)
	if ai == "" {
		ai = "anonymous"
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if nowUnix <= 0 {
		nowUnix = s.nowUnixLocked()
	}
	key := aggKey{agent: ai, action: action, resource: pat}
	all := s.rolling[key]

	dims := map[string]DimensionStats{}
	cutoff := nowUnix - s.windowSeconds

	// Rolling exact view.
	var hours []float64
	rollingCount := 0
	for _, o := range all {
		if o.observedAt < cutoff {
			continue
		}
		rollingCount++
		hours = append(hours, float64(o.hourOfDay))
	}
	windowHours := float64(s.windowSeconds) / 3600.0
	if windowHours < 1.0 {
		windowHours = 1.0
	}
	if rollingCount > 0 {
		freqMean := float64(rollingCount) / windowHours
		dims["action_frequency"] = DimensionStats{
			Dimension: "action_frequency",
			Count:     float64(rollingCount),
			Mean:      freqMean,
			Stddev:    math.Sqrt(maxF(freqMean, 1e-9)), // Poisson-ish: var ~= mean
		}
		hrMean, hrSd := meanStddev(hours)
		dims["hour_of_day"] = DimensionStats{
			Dimension: "hour_of_day",
			Count:     float64(len(hours)),
			Mean:      hrMean,
			Stddev:    hrSd,
		}
	}

	// Decay-weighted aggregates.
	var freqW, hourN, hourS, hourSS float64
	for _, o := range all {
		if o.observedAt < cutoff {
			continue
		}
		agePeriods := float64(nowUnix-o.observedAt) / float64(s.decayPeriodSec)
		if agePeriods < 0 {
			agePeriods = 0
		}
		w := math.Pow(s.decayRate, agePeriods)
		freqW += w
		hourN += w
		hourS += w * float64(o.hourOfDay)
		hourSS += w * float64(o.hourOfDay) * float64(o.hourOfDay)
	}
	decayedTotal := 0.0
	if freqW > 0 {
		decayedTotal = freqW
		mean := freqW / windowHours
		dims["action_frequency_decayed"] = DimensionStats{
			Dimension: "action_frequency_decayed",
			Count:     freqW,
			Mean:      mean,
			Stddev:    math.Sqrt(maxF(mean, 1e-9)),
		}
	}
	if hourN > 0 {
		mean := hourS / hourN
		variance := maxF(0.0, (hourSS/hourN)-mean*mean)
		dims["hour_of_day_decayed"] = DimensionStats{
			Dimension: "hour_of_day_decayed",
			Count:     hourN,
			Mean:      mean,
			Stddev:    math.Sqrt(variance),
		}
	}

	return BaselineSummary{
		AgentIdentity:            ai,
		Action:                   action,
		ResourcePattern:          pat,
		TotalObservationsRolling: rollingCount,
		TotalObservationsDecayed: decayedTotal,
		Dimensions:               dims,
	}
}

// KnownAgents returns the distinct agent identities tracked so far,
// sorted. Diagnostics helper (ports BaselineStore.known_agents).
func (s *BaselineStore) KnownAgents() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := map[string]struct{}{}
	for k := range s.rolling {
		set[k.agent] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// Status returns a diagnostics snapshot suitable for /healthz + the
// query surface. Ports BaselineStore.status.
func (s *BaselineStore) Status() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, obs := range s.rolling {
		total += len(obs)
	}
	return map[string]any{
		"tracked_keys":         len(s.rolling),
		"total_observations":   total,
		"known_agent_count":    s.knownAgentCountLocked(),
		"dropped":              s.dropped,
		"window_seconds":       s.windowSeconds,
		"decay_rate":           s.decayRate,
		"decay_period_seconds": s.decayPeriodSec,
		"in_memory":            true,
	}
}

func (s *BaselineStore) knownAgentCountLocked() int {
	set := map[string]struct{}{}
	for k := range s.rolling {
		set[k.agent] = struct{}{}
	}
	return len(set)
}

// --- numeric helpers ---

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// meanStddev returns the population mean + stddev of xs. Mirrors the
// statistics.mean / statistics.pstdev path in baseline.py (a single
// sample reports stddev 0).
func meanStddev(xs []float64) (float64, float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	if len(xs) == 1 {
		return xs[0], 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))
	var ss float64
	for _, x := range xs {
		d := x - mean
		ss += d * d
	}
	return mean, math.Sqrt(ss / float64(len(xs)))
}

//go:build loadtest

// Concurrency-load probe for task #296 / §A22. Gated by `loadtest`
// build tag; not picked up by normal `go test ./...`.
package store

import (
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestConcurrencyLoad(t *testing.T) {
	for _, w := range []int{1, 5, 10, 20, 30} {
		w := w
		t.Run(fmt.Sprintf("w=%d", w), func(t *testing.T) {
			tmp := t.TempDir()
			s, err := Open(filepath.Join(tmp, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			callsPer := 600
			var (
				wg   sync.WaitGroup
				mu   sync.Mutex
				lats []time.Duration
				errs []string
			)
			t0 := time.Now()
			for i := 0; i < w; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					for j := 0; j < callsPer; j++ {
						st := time.Now()
						_, err := s.RecordDecision(DecisionRow{
							Dialect:         "postgres",
							Statement:       "SELECT 1",
							StatementType:   "SELECT",
							DecisionVerdict: "allow",
							DecisionReason:  "rule",
							ModeAtDecision:  "transparent",
							DecisionSource:  "rule",
							AgentSessionID:  fmt.Sprintf("s-%03d", idx),
						})
						dt := time.Since(st)
						mu.Lock()
						if err != nil {
							errs = append(errs, err.Error())
						} else {
							lats = append(lats, dt)
						}
						mu.Unlock()
					}
				}(i)
			}
			wg.Wait()
			wall := time.Since(t0)

			sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
			p := func(p float64) time.Duration {
				if len(lats) == 0 {
					return 0
				}
				idx := int(p * float64(len(lats)))
				if idx >= len(lats) {
					idx = len(lats) - 1
				}
				return lats[idx]
			}
			ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }
			if len(lats) == 0 {
				t.Logf("writers=%3d committed=     0 errs=%3d wall=%4.2fs (all writes failed)", w, len(errs), wall.Seconds())
				if len(errs) > 0 {
					t.Logf("first err: %s", errs[0])
				}
				return
			}
			t.Logf(
				"writers=%3d committed=%6d errs=%3d wall=%4.2fs rps=%7.0f p50=%6.2fms p95=%6.2fms p99=%6.2fms max=%6.2fms",
				w, len(lats), len(errs), wall.Seconds(),
				float64(len(lats))/wall.Seconds(),
				ms(lats[len(lats)/2]), ms(p(0.95)), ms(p(0.99)),
				ms(lats[len(lats)-1]),
			)
			if len(errs) > 0 {
				t.Logf("first err: %s", errs[0])
			}
		})
	}
}

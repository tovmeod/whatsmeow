// Copyright (c) 2026 Kavtov Platform (Phase 17.5.1)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package walltime

import (
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

// TestWallTimeHistogram_ObserveAndCount asserts that every Observe call
// increments Count() by exactly one.
func TestWallTimeHistogram_ObserveAndCount(t *testing.T) {
	h := newWallTimeHistogram()
	const n = 1000
	for i := 0; i < n; i++ {
		h.Observe(time.Duration(i) * time.Microsecond)
	}
	if got := h.Count(); got != n {
		t.Fatalf("Count() = %d, want %d", got, n)
	}
}

// TestWallTimeHistogram_QuantileEmpty asserts Quantile returns 0 on an empty
// histogram (the operator-facing dashboard sees 0s for "no samples yet"
// rather than crashing the metrics log line on driver startup).
func TestWallTimeHistogram_QuantileEmpty(t *testing.T) {
	h := newWallTimeHistogram()
	for _, q := range []float64{0.5, 0.95, 0.99} {
		if got := h.Quantile(q); got != 0 {
			t.Fatalf("Quantile(%v) on empty histogram = %v, want 0", q, got)
		}
	}
}

// TestWallTimeHistogram_QuantileApproximate observes a uniform-ish
// distribution across 14 known buckets and asserts Quantile(0.5) lands in
// the median bucket within +/- 1 bucket. The histogram is approximate by
// design (bucket-upper-bound used as the quantile estimate), so the test
// tolerates one bucket of slop.
func TestWallTimeHistogram_QuantileApproximate(t *testing.T) {
	h := newWallTimeHistogram()
	// Place 100 samples in each of the first 10 named buckets by observing
	// a duration just below each bucket upper-bound.
	const perBucket = 100
	for i := 0; i < 10; i++ {
		ub := bucketUpperBounds[i]
		for j := 0; j < perBucket; j++ {
			// Observe at half the bucket upper-bound so the sample
			// lands inside bucket i (or possibly bucket i-1 — the
			// quantile estimator tolerates +/-1 bucket of slop).
			h.Observe(ub / 2)
		}
	}
	// Total = 10 * 100 = 1000 samples; median = bucket 4 or 5 (0-indexed)
	// — the bucket whose half-upper-bound falls at the cumulative-count
	// midpoint. Exact landing depends on bucket spacing; we accept any of
	// buckets 3..6 as the median (one-bucket slop on either side of the
	// idealised median bucket 4).
	got := h.Quantile(0.5)
	allowed := map[time.Duration]bool{
		bucketUpperBounds[3]: true,
		bucketUpperBounds[4]: true,
		bucketUpperBounds[5]: true,
		bucketUpperBounds[6]: true,
	}
	if !allowed[got] {
		t.Fatalf("Quantile(0.5) = %v, want one of %v %v %v %v",
			got, bucketUpperBounds[3], bucketUpperBounds[4],
			bucketUpperBounds[5], bucketUpperBounds[6])
	}
}

// TestWallTimeHistogram_Concurrent_50Goroutines verifies that concurrent
// Observe calls from 50 goroutines all land cleanly under -race; final
// Count() equals 50 * 1000 = 50_000 with no race report.
func TestWallTimeHistogram_Concurrent_50Goroutines(t *testing.T) {
	h := newWallTimeHistogram()
	const (
		goroutines      = 50
		obsPerGoroutine = 1000
	)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			// Each goroutine gets its own PRNG so we don't add lock
			// contention from a shared rand.Source.
			r := rand.New(rand.NewPCG(uint64(seed), uint64(seed)*7+1))
			for j := 0; j < obsPerGoroutine; j++ {
				// Random durations across the full 100us..30s range.
				d := time.Duration(r.Int64N(int64(30 * time.Second)))
				h.Observe(d)
			}
		}(g)
	}
	wg.Wait()
	if got, want := h.Count(), uint64(goroutines*obsPerGoroutine); got != want {
		t.Fatalf("Count() after concurrent Observes = %d, want %d", got, want)
	}
}

// TestWallTimeHistogram_Overflow observes a duration larger than the
// highest named bucket (60s vs the 30s upper-bound) and asserts it lands
// in the overflow bucket; Quantile(0.99) on a histogram containing only
// the overflow sample returns the overflow sentinel.
func TestWallTimeHistogram_Overflow(t *testing.T) {
	h := newWallTimeHistogram()
	h.Observe(60 * time.Second)
	if got := h.Count(); got != 1 {
		t.Fatalf("Count() = %d, want 1", got)
	}
	got := h.Quantile(0.99)
	// The overflow bucket reports overflowSentinel (>30s). Just assert it
	// is strictly larger than the highest named bucket upper-bound.
	highest := bucketUpperBounds[len(bucketUpperBounds)-1]
	if got <= highest {
		t.Fatalf("Quantile(0.99) for overflow sample = %v, want > %v (highest named bucket)", got, highest)
	}
}

// TestWallTimeHistogram_NegativeDuration observes a negative duration
// (clock skew) and asserts it goes to bucket 0 without crashing or
// incrementing a wrong bucket.
func TestWallTimeHistogram_NegativeDuration(t *testing.T) {
	h := newWallTimeHistogram()
	h.Observe(-1 * time.Millisecond)
	if got := h.Count(); got != 1 {
		t.Fatalf("Count() after negative Observe = %d, want 1", got)
	}
	// Bucket 0 holds the negative sample; Quantile(0.5) on a single
	// sample returns bucket 0's upper-bound (the smallest named bucket).
	if got := h.Quantile(0.5); got != bucketUpperBounds[0] {
		t.Fatalf("Quantile(0.5) after single negative Observe = %v, want %v", got, bucketUpperBounds[0])
	}
}

// TestPackageDecryptHistogram_Initialised guards the package-level
// DecryptHistogram against accidental nil-init regression. Decoupled from
// the wallTimeHistogram tests above so that a refactor of the histogram
// type cannot silently break the message.go observer site.
func TestPackageDecryptHistogram_Initialised(t *testing.T) {
	if DecryptHistogram == nil {
		t.Fatal("DecryptHistogram package var is nil")
	}
	// Smoke-check that Observe/Count/Quantile work via the package var.
	before := DecryptHistogram.Count()
	DecryptHistogram.Observe(5 * time.Millisecond)
	after := DecryptHistogram.Count()
	if after != before+1 {
		t.Fatalf("DecryptHistogram.Count delta = %d, want 1", after-before)
	}
}

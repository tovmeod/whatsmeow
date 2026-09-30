// Copyright (c) 2026 Kavtov Platform (Phase 17.5.1)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package walltime provides a Go-native fixed-bucket histogram used to
// surface per-message decrypt wall-time quantiles (p50/p95/p99) alongside
// the existing cache-metrics log line emitted by
// store/sqlstore.cache_wiring.go (emitMetricsLoop) every 5 minutes.
//
// Design notes (Phase 17.5.1-04):
//   - Atomic, lock-free Observe: each bucket is a uint64 incremented via
//     atomic.AddUint64. No mutex; concurrent Observe from every whatsmeow
//     decrypt goroutine is safe and contention-free.
//   - No external dependency: only sync/atomic + time from stdlib. Verified
//     by go.mod diff post-plan — no new require lines added.
//   - Fixed 14 exponentially-spaced buckets + 1 overflow bucket. Bucket
//     upper-bounds cover 100us..30s, which spans realistic in-process
//     decrypt + small DB-write latencies plus a long-tail headroom for the
//     occasional slow query. Samples >30s go to the overflow bucket and
//     report overflowSentinel from Quantile.
//   - Quantile estimate is approximate: bucket upper-bound is returned
//     when the cumulative count crosses q*total. Suitable for
//     operator-facing dashboards, NOT for SLA gating. Operator sees the
//     worst-case-in-bucket, which is the conservative reading.
//   - The package-level DecryptHistogram var is the single
//     process-shared observer; whatsmeow/message.go writes into it from
//     decryptMessages via a deferred Observe(time.Since(start)).
//     Placement in a leaf util package keeps the cross-package import
//     edge minimal: whatsmeow/message.go -> util/walltime (leaf), and
//     store/sqlstore/cache_wiring.go -> util/walltime (leaf). Neither
//     edge introduces a fork-divergence point that upstream merges
//     would fight.
package walltime

import (
	"sync/atomic"
	"time"
)

// bucketUpperBounds defines the inclusive upper-bound of each named
// bucket. A duration d lands in the lowest-indexed bucket i for which
// d <= bucketUpperBounds[i]; durations larger than the last entry fall
// into the overflow bucket at index len(bucketUpperBounds).
//
// The 14 named buckets span 100us..30s with rough 2x-2.5x spacing,
// chosen to give useful resolution across the realistic decrypt latency
// distribution (sub-ms for cache-hit paths, multi-ms for libsignal
// decrypt + DB write, tens-to-hundreds of ms for cold-cache or slow-query
// paths, seconds for pathological cases).
var bucketUpperBounds = []time.Duration{
	100 * time.Microsecond,
	200 * time.Microsecond,
	500 * time.Microsecond,
	1 * time.Millisecond,
	2 * time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	20 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
}

// overflowSentinel is the value Quantile returns when the quantile lands
// in the overflow bucket (samples >30s). Using time.Hour as a sentinel
// makes operator-facing log lines clearly indicate "we saw something
// slower than every named bucket" without inventing a magic number that
// downstream parsers might interpret as a real measurement.
const overflowSentinel = time.Hour

// wallTimeHistogram is a fixed-bucket histogram with atomic per-bucket
// counters. Lowercase by intent: callers construct via
// newWallTimeHistogram and hold a pointer (the package-level
// DecryptHistogram var holds the canonical instance).
type wallTimeHistogram struct {
	// buckets[i] for i in [0, len(bucketUpperBounds)) counts samples
	// d <= bucketUpperBounds[i] (and > bucketUpperBounds[i-1] for i>0,
	// or any d <= bucketUpperBounds[0] including negatives for i=0).
	// buckets[len(bucketUpperBounds)] is the overflow bucket: samples
	// d > bucketUpperBounds[last].
	buckets [15]uint64 // 14 named buckets + 1 overflow
}

// newWallTimeHistogram returns a zero-value-initialised histogram ready
// for concurrent Observe calls. Allocation-only; no side effects.
func newWallTimeHistogram() *wallTimeHistogram {
	return &wallTimeHistogram{}
}

// Observe records a single duration sample into the appropriate bucket.
// Safe for concurrent use from arbitrary goroutines (each bucket is a
// uint64 incremented via atomic.AddUint64). Negative durations (clock
// skew) land in bucket 0. Durations larger than the highest named bucket
// land in the overflow bucket.
//
// Cost: a linear scan across 14 buckets + one atomic.AddUint64. Total
// per-call overhead is well under 200ns on modern hardware, negligible
// vs the multi-ms typical decryptMessages cost. Linear scan over 14
// entries is simpler and as-fast-as sort.Search at this size due to
// branch prediction.
func (h *wallTimeHistogram) Observe(d time.Duration) {
	for i, ub := range bucketUpperBounds {
		if d <= ub {
			atomic.AddUint64(&h.buckets[i], 1)
			return
		}
	}
	atomic.AddUint64(&h.buckets[len(bucketUpperBounds)], 1)
}

// Count returns the total number of observed samples across all buckets
// (including the overflow bucket). Safe for concurrent use; reads each
// bucket via atomic.LoadUint64 to avoid torn reads on 32-bit platforms.
func (h *wallTimeHistogram) Count() uint64 {
	var sum uint64
	for i := range h.buckets {
		sum += atomic.LoadUint64(&h.buckets[i])
	}
	return sum
}

// Quantile returns an approximate q-th quantile of the observed
// distribution. Walks buckets low-to-high, accumulating counts, and
// returns the upper-bound of the first bucket whose cumulative count
// crosses q*total. Returns 0 if no samples have been observed (operator
// dashboard shows 0s rather than crashing the metrics log line at
// startup). Returns overflowSentinel (time.Hour) when the quantile lands
// in the overflow bucket.
//
// Approximate by design: the bucket-upper-bound is a conservative
// estimate (operator sees the worst-case-in-bucket). Acceptable for
// operator-facing dashboards; NOT acceptable for SLA gating where exact
// percentiles matter.
func (h *wallTimeHistogram) Quantile(q float64) time.Duration {
	total := h.Count()
	if total == 0 {
		return 0
	}
	// Use ceiling division semantics so e.g. Quantile(0.5) on 100
	// samples wants the bucket containing the 50th sample (cumulative
	// >= 50). For q=0.99 on 100 samples we want the 99th sample's
	// bucket (cumulative >= 99). Plain rounding here is fine for the
	// histogram's intended operator-facing precision.
	target := uint64(float64(total)*q + 0.5)
	if target == 0 {
		target = 1
	}
	var cumulative uint64
	for i := range h.buckets {
		cumulative += atomic.LoadUint64(&h.buckets[i])
		if cumulative >= target {
			if i == len(bucketUpperBounds) {
				return overflowSentinel
			}
			return bucketUpperBounds[i]
		}
	}
	// Unreachable: the loop above always returns once cumulative
	// reaches total (which is non-zero and equals the sum of all
	// buckets). Defensive fallback returns overflowSentinel.
	return overflowSentinel
}

// DecryptHistogram is the process-shared histogram into which
// whatsmeow/message.go writes per-decryptMessages wall-time samples via a
// deferred Observe(time.Since(start)) call. The metrics-emitting goroutine
// in store/sqlstore.cache_wiring.go reads it via Quantile / Count and
// formats the result into the existing cache-metrics log line so the
// operator gets cache hit-rate + decrypt latency from a single
// journalctl grep on the same 5-minute cadence.
var DecryptHistogram = newWallTimeHistogram()

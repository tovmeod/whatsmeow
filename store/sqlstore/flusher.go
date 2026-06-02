// Copyright (c) 2026 Kavtov Platform (Phase 17.7)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// flusher.go implements SenderKeyFlusher — the async write-back flusher for
// the sender_keys cache (Phase 17.7-03). It maintains a dirty-set of pending
// sender-key blobs and drains them in batches via PutManySenderKeys.
//
// Design reference: .planning/phases/17.7-*/17.7-WRITEBACK-CACHE-DESIGN.md
//   §5  flush triggers
//   §6  flusher, backpressure & failure
//   §8  telemetry
package sqlstore

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// flushSenderKeyBatch is the interface the flusher needs from the store layer.
// *SQLStore satisfies this via PutManySenderKeys (plan 02).
type flushSenderKeyBatch interface {
	PutManySenderKeys(ctx context.Context, keys []SenderKeyRow) error
}

// dirtyEntry tracks one pending sender-key write in the dirty-set.
type dirtyEntry struct {
	group, user string
	session     []byte  // latest blob — monotonic forward ratchet makes "last wins" safe
	highIter    uint32  // highest iteration seen for this entry
	lastFlushed uint32  // iteration at last successful DB write
}

// SenderKeyFlusher batches dirty sender-key entries and drains them
// asynchronously via PutManySenderKeys. One instance per Container.
//
// Flush triggers (design §5):
//  1. N-boundary crossing: floor(iter/N) > floor(lastFlushed/N)
//  2. LRU eviction: eviction callback re-enqueues the dirty value
//  3. Synchronous drain on shutdown (Drain / Stop)
//
// Backpressure (design §6):
//   - dirty-set > backpressureCap → inline synchronous write on enqueue
//   - dirty-set > dropCap AND DB failing → drop coldest + slog.Error
type SenderKeyFlusher struct {
	store flushSenderKeyBatch
	log   waLog.Logger

	// env-tunable caps
	cap             int    // max dirty-set entries (KAVTOV_FLUSH_SENDERKEY_CAP)
	boundaryN       uint32 // iteration boundary N (KAVTOV_FLUSH_SENDERKEY_N)
	backpressureCap int    // dirty-set size above which inline sync write fires
	dropCap         int    // dirty-set size above which drop+log fires on DB failure

	mu    sync.Mutex
	dirty map[string]*dirtyEntry // key = "<group>|<user>"

	// flush signal: a non-blocking send wakes the flusher goroutine early.
	flushCh chan struct{}

	stopCh chan struct{}
	wg     sync.WaitGroup

	// telemetry counters
	skippedCount   atomic.Uint64
	processedCount atomic.Uint64
}

// envIntOrDefault reads an integer from an env var with a compiled default.
func envIntOrDefault(key string, fallback int) int {
	s := os.Getenv(key)
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// NewSenderKeyFlusher constructs a SenderKeyFlusher. cap is the dirty-set cap
// (env-tunable; pass 0 to use the env var / compiled default).
func NewSenderKeyFlusher(store flushSenderKeyBatch, log waLog.Logger, cap int) *SenderKeyFlusher {
	if cap <= 0 {
		cap = envIntOrDefault("KAVTOV_FLUSH_SENDERKEY_CAP", 256_000)
	}
	n := uint32(envIntOrDefault("KAVTOV_FLUSH_SENDERKEY_N", 500))
	if n == 0 {
		n = 500
	}
	return &SenderKeyFlusher{
		store:           store,
		log:             log,
		cap:             cap,
		boundaryN:       n,
		backpressureCap: cap / 5,
		dropCap:         cap * 2 / 5,
		dirty:           make(map[string]*dirtyEntry, 1024),
		flushCh:         make(chan struct{}, 1),
		stopCh:          make(chan struct{}),
	}
}

// DirtyCount returns the current dirty-set size. Used by plan 07 regression tests.
func (f *SenderKeyFlusher) DirtyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dirty)
}

// crossesBoundary returns true when iter crosses an N-boundary relative to
// lastFlushed. Design §5: floor(iter/N) > floor(lastFlushed/N).
func (f *SenderKeyFlusher) crossesBoundary(iter, lastFlushed uint32) bool {
	return iter/f.boundaryN > lastFlushed/f.boundaryN
}

// Enqueue is a stub — implementation in Task 2.
func (f *SenderKeyFlusher) Enqueue(group, user string, session []byte, iter uint32, wasFailed bool) {
}

// Drain is a stub — implementation in Task 2.
func (f *SenderKeyFlusher) Drain() {
}

// Start is a stub — implementation in Task 2.
func (f *SenderKeyFlusher) Start() {
}

// Stop is a stub — implementation in Task 2.
func (f *SenderKeyFlusher) Stop() {
}

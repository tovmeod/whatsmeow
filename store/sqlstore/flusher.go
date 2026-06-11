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
//
//	§5  flush triggers
//	§6  flusher, backpressure & failure
//	§8  telemetry
package sqlstore

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// flushSenderKeyBatch is the interface the flusher needs from the store layer.
// *SQLStore satisfies this via PutManySenderKeys (plan 02).
type flushSenderKeyBatch interface {
	PutManySenderKeys(ctx context.Context, keys []SenderKeyRow) error
}

// dirtyEntry tracks one pending sender-key write in the dirty-set.
//
// Phase 17.11-05: cols *senderKeyColumns → blob []byte (PackFlat output).
// The flat blob is produced once at PutSenderKeyStructure call time; the flusher
// holds the only reference to each dirtyEntry's blob. keyID and iter are still
// passed explicitly (derived from the structure before packing).
type dirtyEntry struct {
	group, user string
	blob        []byte // PackFlat-encoded sender_key — monotonic forward ratchet makes "last wins" safe
	highIter    uint32 // highest iteration seen for this entry
	lastFlushed uint32 // iteration at last successful DB write
	keyID       uint32 // keyID (generation) of the most-recent state; new keyID resets dedup
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

	// telemetry counters (atomic)
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

// Enqueue records a dirty entry. It implements the SKDM dedup rule and the
// three flush trigger points:
//  1. If iter <= highIter AND keyID == cached keyID AND NOT wasFailed → skip.
//  2. A new keyID (generation rotation) always processes regardless of iter.
//  3. wasFailed=true always processes (failed-tuple recovery bypass).
//  4. If N-boundary crossed, signal the async flusher.
//  5. If dirty-set > backpressureCap, perform an inline synchronous write.
//
// Phase 17.11-05: accepts []byte (PackFlat blob) instead of *senderKeyColumns.
// keyID and iter are still passed explicitly by the producer (PutSenderKeyStructure).
func (f *SenderKeyFlusher) Enqueue(group, user string, blob []byte, keyID, iter uint32, wasFailed bool) {
	k := group + "|" + user

	f.mu.Lock()

	entry, exists := f.dirty[k]
	sameGeneration := exists && entry.keyID == keyID
	if sameGeneration && iter <= entry.highIter && !wasFailed {
		// SKDM dedup: same or lower iteration within the same generation,
		// not a failed-tuple recovery → skip.
		n := f.skippedCount.Add(1)
		if n%1000 == 0 {
			processed := f.processedCount.Load()
			skipped := n
			highIter := entry.highIter
			f.mu.Unlock()
			// Embed counters in the message string for grep on JSON slog output.
			// Plan 17.7-01 reads the slice with grep SKDM_DEDUP + processed=\d+ skipped=\d+.
			slog.Info(fmt.Sprintf("SKDM_DEDUP processed=%d skipped=%d group=%s keyID=%d iter=%d cached=%d",
				processed, skipped, group, keyID, iter, highIter))
			return
		}
		f.mu.Unlock()
		return
	}

	// Log every lower-iter arrival within the same generation (not sampled —
	// signals reordering or wrong iteration assumption).
	if sameGeneration && iter < entry.highIter {
		highIter := entry.highIter
		f.mu.Unlock()
		slog.Info(fmt.Sprintf("SKDM_DEDUP lower_iter group=%s keyID=%d iter=%d cached=%d", group, keyID, iter, highIter))
		// Re-acquire lock to continue processing (wasFailed bypass path requires it).
		f.mu.Lock()
	}

	f.processedCount.Add(1)

	var lastFlushed uint32
	if exists {
		lastFlushed = entry.lastFlushed
		entry.blob = blob // blob replaces previous; monotonic ratchet makes last-wins safe
		entry.highIter = iter
		entry.keyID = keyID
	} else {
		entry = &dirtyEntry{
			group:    group,
			user:     user,
			blob:     blob,
			highIter: iter,
			keyID:    keyID,
		}
		f.dirty[k] = entry
	}

	crossesBoundary := f.crossesBoundary(iter, lastFlushed)
	dirtyLen := len(f.dirty)
	needsInlineWrite := dirtyLen > f.backpressureCap

	f.mu.Unlock()

	// Signal flusher goroutine if N-boundary was crossed (non-blocking send).
	if crossesBoundary {
		select {
		case f.flushCh <- struct{}{}:
		default:
		}
	}

	// Inline synchronous write on backpressure (valve fires when dirty-set > backpressureCap).
	// This runs outside the lock — PutManySenderKeys must not be called under mu.
	if needsInlineWrite {
		f.flushOneSynchronous(group, user, blob, iter)
	}
}

// flushOneSynchronous performs a single-row synchronous write (inline backpressure path).
// Removes the entry from the dirty-set on success. On failure, retains dirty state.
// Must NOT be called while f.mu is held.
func (f *SenderKeyFlusher) flushOneSynchronous(group, user string, blob []byte, iter uint32) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := f.store.PutManySenderKeys(ctx, []SenderKeyRow{{Group: group, User: user, Blob: blob}})
	if err != nil {
		slog.Error(fmt.Sprintf("SenderKeyFlusher inline flush failed group=%s user=%s iter=%d: %v", group, user, iter, err))

		// Catastrophe path: if dirty-set is still huge and DB is failing, drop coldest.
		f.mu.Lock()
		if len(f.dirty) > f.dropCap {
			f.dropColdestLocked()
		}
		f.mu.Unlock()
		return
	}

	// On success, clear the entry from dirty-set.
	k := group + "|" + user
	f.mu.Lock()
	if e, ok := f.dirty[k]; ok && e.highIter == iter {
		e.lastFlushed = iter
		delete(f.dirty, k)
	}
	f.mu.Unlock()
}

// dropColdestLocked removes one entry from the dirty-set (the first one
// encountered in map iteration — Go map iteration is pseudo-random, approximating
// cold-entry removal). Must be called with f.mu held.
func (f *SenderKeyFlusher) dropColdestLocked() {
	for k, e := range f.dirty {
		slog.Error(fmt.Sprintf("SenderKeyFlusher DROP dirty entry (catastrophe) group=%s user=%s highIter=%d",
			e.group, e.user, e.highIter))
		delete(f.dirty, k)
		return
	}
}

// Drain flushes the entire dirty-set synchronously. Blocks until all dirty
// entries have been written to the DB (retrying on transient failure) or the
// dirty-set is empty. Called during Container.Close via Stop().
func (f *SenderKeyFlusher) Drain() {
	for {
		f.mu.Lock()
		if len(f.dirty) == 0 {
			f.mu.Unlock()
			return
		}
		// Snapshot under lock; release before calling DB.
		rows := make([]SenderKeyRow, 0, len(f.dirty))
		snaps := make(map[string]senderKeyFlushSnap, len(f.dirty))
		for k, e := range f.dirty {
			rows = append(rows, SenderKeyRow{Group: e.group, User: e.user, Blob: e.blob})
			snaps[k] = senderKeyFlushSnap{keyID: e.keyID, iter: e.highIter}
		}
		f.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := f.store.PutManySenderKeys(ctx, rows)
		cancel()

		if err != nil {
			f.log.Errorf("SenderKeyFlusher Drain batch failed (%d rows): %v — retrying", len(rows), err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// CR-02 staleness guard (35.2-09 follow-up) — see runFlush.
		f.mu.Lock()
		clearFlushedSenderKeysLocked(f.dirty, snaps)
		drained := len(rows)
		f.mu.Unlock()

		f.log.Infof("flush: drained %d on shutdown", drained)
	}
}

// runFlush drains the dirty-set once. Called from the async goroutine on
// ticker tick or flushCh signal. A failed batch retains dirty state (retried
// next cycle). Unlike Drain(), it does not retry.
func (f *SenderKeyFlusher) runFlush() {
	f.mu.Lock()
	if len(f.dirty) == 0 {
		f.mu.Unlock()
		return
	}
	rows := make([]SenderKeyRow, 0, len(f.dirty))
	snaps := make(map[string]senderKeyFlushSnap, len(f.dirty))
	for k, e := range f.dirty {
		rows = append(rows, SenderKeyRow{Group: e.group, User: e.user, Blob: e.blob})
		snaps[k] = senderKeyFlushSnap{keyID: e.keyID, iter: e.highIter}
	}
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := f.store.PutManySenderKeys(ctx, rows)
	cancel()

	if err != nil {
		f.log.Errorf("SenderKeyFlusher batch flush failed (%d rows): %v", len(rows), err)
		return
	}

	// CR-02 staleness guard (35.2-09 follow-up): only clear an entry if no
	// newer Enqueue arrived during the in-flight DB write — same lost-update
	// flaw the session flusher had in its batch clears, and the inline path
	// here already guards against (highIter == iter check in
	// flushOneSynchronous). Clearing unconditionally dropped a newer blob
	// from the durable path: the DB holds the snapshot generation and the
	// newer ratchet state existed nowhere durable.
	f.mu.Lock()
	clearFlushedSenderKeysLocked(f.dirty, snaps)
	f.mu.Unlock()
}

// senderKeyFlushSnap records the (keyID, highIter) generation of a dirty
// entry at batch-snapshot time, for the CR-02 staleness guard.
type senderKeyFlushSnap struct {
	keyID uint32
	iter  uint32
}

// clearFlushedSenderKeysLocked applies the CR-02 staleness guard to the batch
// clear: an entry is deleted only if it is still at the snapshotted
// (keyID, highIter) generation. If a newer iteration of the SAME generation
// arrived during the in-flight write, the entry stays dirty (newer blob) and
// lastFlushed records the drained iteration so N-boundary math stays correct.
// If the keyID changed (generation rotation mid-write), the entry stays dirty
// and lastFlushed is left untouched — iteration numbering restarted, so the
// drained iteration is meaningless for the new generation.
// Must be called with f.mu held.
func clearFlushedSenderKeysLocked(dirty map[string]*dirtyEntry, snaps map[string]senderKeyFlushSnap) {
	for k, snap := range snaps {
		if e, ok := dirty[k]; ok {
			if e.keyID != snap.keyID {
				continue
			}
			e.lastFlushed = snap.iter
			if e.highIter == snap.iter {
				delete(dirty, k)
			}
		}
	}
}

// Start launches the async flusher goroutine. Must be called once per
// Container after NewSenderKeyFlusher.
func (f *SenderKeyFlusher) Start() {
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-f.stopCh:
				return
			case <-ticker.C:
				f.runFlush()
			case <-f.flushCh:
				f.runFlush()
			}
		}
	}()
}

// Stop signals the async goroutine to exit, waits for it, then calls Drain()
// synchronously to flush any remaining dirty entries before the DB closes.
func (f *SenderKeyFlusher) Stop() {
	close(f.stopCh)
	f.wg.Wait()
	f.Drain()
}

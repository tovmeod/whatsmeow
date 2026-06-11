// Copyright (c) 2026 Kavtov Platform (Phase 35.2-09)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// session_flusher.go implements SessionFlusher — the per-JID async write-back
// flusher for the whatsmeow_sessions table (D-15 Lever 2, Phase 35.2-09).
// It is a near-clone of SenderKeyFlusher (flusher.go), adapted for sessions.
//
// Design reference:
//
//	.planning/phases/17.7-*/17.7-WRITEBACK-CACHE-DESIGN.md §5 §6 §8
//	.planning/phases/35.2-.../35.2-D15-LEVERS.md (Lever 2 measured load)
//
// # Why write-back is safe for sessions (at these parameters)
//
// Measured prod load: ~2,450 session upserts/min; 72.5% of those upsert the
// same (jid, address) within a short window (coalescable). Sessions are
// the #1 DB write source at 32.5% of total pg exec time.
//
// Chosen defaults: N=1 (KAVTOV_FLUSH_SESSION_N), T=5000ms
// (KAVTOV_FLUSH_SESSION_T_MS), cap=100_000 (KAVTOV_FLUSH_SESSION_CAP).
//
// N=1 means each distinct address is flush-signalled on its FIRST Enqueue,
// so the async goroutine drains the dirty-set approximately every 1s (the
// ticker cadence). Same-address repeats arriving inside the in-flight drain
// window coalesce to last-wins: the CR-02 staleness guard keeps an entry
// dirty when a newer Enqueue landed during the batch's DB write (clearing
// unconditionally would drop the newer blob from the durable path), so the
// newer generation flushes on the next cycle. The 5s ticker is a hard bound
// on staleness for addresses that never received a second signal. The crash
// window is therefore bounded: at most ~5s of ratchet advances in the
// dirty-set survive a crash. See 35.2-09-CRASH-LOSS.md for the full analysis.
//
// DM Double-Ratchet has no replayable genesis: a crash during the flush
// window loses those ratchet advances permanently. This is acceptable for
// the prod write-reduction benefit, but the operator must decide whether
// to deploy. See 35.2-09-CRASH-LOSS.md and the SUMMARY deploy-decision
// section.
package sqlstore

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// flushSessionBatch is the interface the flusher needs from the store layer.
// *SQLStore satisfies this via PutManySessions.
type flushSessionBatch interface {
	PutManySessions(ctx context.Context, sessions map[string][]byte) error
}

// sessionDirtyEntry tracks one pending session write in the dirty-set.
type sessionDirtyEntry struct {
	blob      []byte // latest flat session blob (last-wins for same address)
	advCount  uint32 // number of Enqueues for this address (N-boundary counter)
	lastDrain uint32 // advCount at last successful DB write
}

// SessionFlusher batches dirty session entries and drains them asynchronously
// via PutManySessions. One instance per (Container, JID).
//
// Flush triggers:
//  1. N-boundary crossing: advCount crosses a multiple of N (default N=1,
//     so every new entry signals a flush immediately)
//  2. T-timer: the flush interval ticker fires (default T=5s)
//  3. Synchronous drain on shutdown (Drain / Stop)
//
// Backpressure: when dirty-set > backpressureCap, Enqueue performs a
// synchronous inline write for that address before returning.
type SessionFlusher struct {
	log waLog.Logger

	db              flushSessionBatch
	cap             int    // max dirty-set entries (KAVTOV_FLUSH_SESSION_CAP)
	boundaryN       uint32 // advance-count boundary (KAVTOV_FLUSH_SESSION_N)
	backpressureCap int    // inline sync write above this size
	dropCap         int    // drop coldest above this size when DB is failing

	mu    sync.Mutex
	dirty map[string]*sessionDirtyEntry // key = address (no jid prefix; flusher is per-JID)

	// flushMu serializes every snapshot→DB-write→clear flush cycle (runFlush,
	// each Drain iteration, flushOneSynchronous) against deletes (CR-01).
	// DeleteSession / DeleteAllSessions / MigratePNToLID run their inner DB
	// mutation inside WithFlushBlocked so an in-flight flush snapshot cannot
	// re-upsert a row after the delete lands. Lock order: flushMu strictly
	// before mu — never acquire flushMu while holding mu.
	flushMu sync.Mutex

	flushCh chan struct{}
	stopCh  chan struct{}
	wg      sync.WaitGroup

	flushInterval time.Duration // injectable for tests; default 5s
}

// envIntOrDefaultSession reads an integer from an env var with a compiled
// default. Separate helper so we do not shadow flusher.go's envIntOrDefault
// in the same package (they differ only in name).
func envIntOrDefaultSession(key string, fallback int) int {
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

// NewSessionFlusher constructs a SessionFlusher with prod defaults. cap=0 uses
// the env var / compiled default. log is used for error / info logging.
func NewSessionFlusher(db flushSessionBatch, log waLog.Logger, cap int) *SessionFlusher {
	if cap <= 0 {
		cap = envIntOrDefaultSession("KAVTOV_FLUSH_SESSION_CAP", 100_000)
	}
	n := uint32(envIntOrDefaultSession("KAVTOV_FLUSH_SESSION_N", 1))
	if n == 0 {
		n = 1
	}
	tms := envIntOrDefaultSession("KAVTOV_FLUSH_SESSION_T_MS", 5000)
	return &SessionFlusher{
		log:             log,
		db:              db,
		cap:             cap,
		boundaryN:       n,
		backpressureCap: cap / 5,
		dropCap:         cap * 2 / 5,
		dirty:           make(map[string]*sessionDirtyEntry, 1024),
		flushCh:         make(chan struct{}, 1),
		stopCh:          make(chan struct{}),
		flushInterval:   time.Duration(tms) * time.Millisecond,
	}
}

// newSessionFlusherForTest constructs a SessionFlusher with a custom flush
// interval for unit tests. Tests pass a short interval (e.g. 50ms) to avoid
// sleeping the full 5s default.
func newSessionFlusherForTest(db flushSessionBatch, cap int, flushInterval time.Duration) *SessionFlusher {
	f := NewSessionFlusher(db, waLog.Noop, cap)
	f.flushInterval = flushInterval
	return f
}

// DirtyCount returns the current dirty-set size.
func (f *SessionFlusher) DirtyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dirty)
}

// crossesBoundary returns true when the advance count crosses an N-boundary
// relative to lastDrain. Design §5: floor(adv/N) > floor(lastDrain/N).
func (f *SessionFlusher) crossesBoundary(adv, lastDrain uint32) bool {
	return adv/f.boundaryN > lastDrain/f.boundaryN
}

// Enqueue records a dirty session entry. Last-wins for same address.
// Signals the async flusher goroutine when the N-boundary is crossed.
// Performs an inline synchronous write when dirty-set > backpressureCap.
func (f *SessionFlusher) Enqueue(address string, blob []byte) {
	f.EnqueueAndMirror(address, blob, nil)
}

// EnqueueAndMirror is Enqueue with an optional mirror callback executed under
// f.mu, immediately after the dirty entry is updated (WR-03 coherence
// invariant): every LRU.Add that mirrors a write for an address MUST happen
// inside this callback, so the dirty-set (the durable winner) and the LRU
// (what readers serve first) always agree on the winning blob for an address.
// Two unsynchronized operations — Enqueue then cache.Add — allowed the
// interleaving Enqueue(A,v1); Enqueue(A,v2); cache.Add(A,v2); cache.Add(A,v1):
// the DB persists v2 while readers serve v1 from the LRU indefinitely.
//
// mirror must be fast and must not call back into the flusher (it runs under
// f.mu). Calling LRU methods inside it is safe: the established lock order is
// f.mu → LRU internal lock → secondary-index lock, and no LRU eviction
// callback or index method calls into the flusher.
func (f *SessionFlusher) EnqueueAndMirror(address string, blob []byte, mirror func()) {
	f.mu.Lock()

	entry, exists := f.dirty[address]
	var adv uint32
	var lastDrain uint32
	if exists {
		entry.blob = copyBytes(blob) // last-wins, store our own copy
		entry.advCount++
		adv = entry.advCount
		lastDrain = entry.lastDrain
	} else {
		entry = &sessionDirtyEntry{
			blob:     copyBytes(blob),
			advCount: 1,
		}
		f.dirty[address] = entry
		adv = 1
		lastDrain = 0
	}

	// CR-03: snapshot the advance count for this blob while still holding
	// f.mu, so the inline path below can verify the entry is unchanged
	// before writing and before clearing (mirrors the SenderKeyFlusher
	// template's highIter guard at flusher.go flushOneSynchronous).
	advSnap := adv

	// WR-03: mirror the blob into the LRU under the same lock that decided
	// the dirty-set winner, so LRU and dirty-set cannot disagree.
	if mirror != nil {
		mirror()
	}

	crosses := f.crossesBoundary(adv, lastDrain)
	dirtyLen := len(f.dirty)
	needsInline := dirtyLen > f.backpressureCap

	f.mu.Unlock()

	// Signal the async flusher on N-boundary crossing.
	if crosses {
		select {
		case f.flushCh <- struct{}{}:
		default:
		}
	}

	// Inline synchronous write on backpressure.
	if needsInline {
		f.flushOneSynchronous(address, blob, advSnap)
	}
}

// Peek returns the dirty blob for address if it is in the dirty-set (not yet
// flushed). Returns (copy, true) on hit; (nil, false) on miss.
// The returned slice is a heap-private copy — callers may mutate it.
func (f *SessionFlusher) Peek(address string) ([]byte, bool) {
	f.mu.Lock()
	entry, ok := f.dirty[address]
	if !ok {
		f.mu.Unlock()
		return nil, false
	}
	out := copyBytes(entry.blob)
	f.mu.Unlock()
	return out, true
}

// PeekAndMirror is Peek with an optional mirror callback executed under f.mu
// with a copy of the dirty blob (WR-03): the read-path LRU repopulate after a
// Peek hit must also happen under the flusher lock — repopulating outside it
// could install an older blob over a concurrent EnqueueAndMirror's newer one,
// reopening the LRU-vs-dirty-set disagreement on the read path. Same mirror
// constraints as EnqueueAndMirror.
func (f *SessionFlusher) PeekAndMirror(address string, mirror func(blob []byte)) ([]byte, bool) {
	f.mu.Lock()
	entry, ok := f.dirty[address]
	if !ok {
		f.mu.Unlock()
		return nil, false
	}
	out := copyBytes(entry.blob)
	if mirror != nil {
		mirror(out)
	}
	f.mu.Unlock()
	return out, true
}

// Remove drops the dirty entry for address, preventing a stale buffered blob
// from persisting after a DeleteSession. No-op if address is not dirty.
// Only takes f.mu — safe to call from inside WithFlushBlocked.
func (f *SessionFlusher) Remove(address string) {
	f.mu.Lock()
	delete(f.dirty, address)
	f.mu.Unlock()
}

// RemovePrefix drops every dirty entry whose address starts with prefix.
// Used by DeleteAllSessions (inside WithFlushBlocked) so buffered blobs
// cannot resurrect bulk-deleted sessions. Only takes f.mu — safe to call
// from inside WithFlushBlocked.
func (f *SessionFlusher) RemovePrefix(prefix string) {
	f.mu.Lock()
	for addr := range f.dirty {
		if strings.HasPrefix(addr, prefix) {
			delete(f.dirty, addr)
		}
	}
	f.mu.Unlock()
}

// flushPrefixBlocked synchronously writes every dirty entry whose address
// starts with prefix to the DB, then removes ALL prefix-matching entries from
// the dirty-set. Caller MUST hold flushMu (i.e. call this from inside
// WithFlushBlocked). Used by MigratePNToLID (CR-04) so that (a) the
// migration's SELECT copies the freshest ratchet state — not a stale DB blob
// — to the LID key, and (b) no buffered PN-addressed blob can flush back as
// a zombie pn row after the migration deletes the pn rows (post-migration
// reads are LID-addressed and would never consult it; the once-per-process
// migration gate means a re-migration would not heal it).
//
// The clear is deliberately unconditional for prefix-matching entries
// (including ones enqueued during the DB write above): retaining a
// newer-generation pn entry (the CR-02 pattern) would be wrong here because
// it would later flush back as a zombie pn row. A writer mutating a PN
// address concurrently with its own migration races the migration itself,
// independent of the flusher — that residual is not fixable at this layer.
func (f *SessionFlusher) flushPrefixBlocked(ctx context.Context, prefix string) error {
	f.mu.Lock()
	batch := make(map[string][]byte)
	for addr, e := range f.dirty {
		if strings.HasPrefix(addr, prefix) {
			batch[addr] = copyBytes(e.blob)
		}
	}
	f.mu.Unlock()
	if len(batch) > 0 {
		if err := f.db.PutManySessions(ctx, batch); err != nil {
			return err
		}
	}
	f.RemovePrefix(prefix)
	return nil
}

// WithFlushBlocked runs fn while no flush cycle (async batch, shutdown-drain
// iteration, or inline backpressure write) is in flight. Callers performing
// DB deletes (DeleteSession / DeleteAllSessions / MigratePNToLID) MUST run
// the inner DB mutation AND the matching dirty-set removal inside fn —
// otherwise a flush snapshot taken before the delete can re-upsert the
// deleted row after the delete completes (CR-01 delete-resurrection race).
//
// fn must not call WithFlushBlocked, Drain, Stop, or Enqueue (whose inline
// backpressure path re-takes flushMu); Remove and RemovePrefix are safe
// (they only take f.mu).
func (f *SessionFlusher) WithFlushBlocked(fn func() error) error {
	f.flushMu.Lock()
	defer f.flushMu.Unlock()
	return fn()
}

// flushOneSynchronous performs a single-address synchronous write on the
// backpressure path. advSnap is the entry's advCount captured under f.mu by
// the Enqueue that produced blob. Clears the dirty entry on success only if
// the entry is still at advSnap (CR-03 staleness guard, mirroring the
// SenderKeyFlusher template's highIter check): an inline flush of an older
// blob must neither overwrite a newer concurrent inline write in the DB nor
// clear a dirty entry that already holds a newer blob.
// Must NOT be called while f.mu is held.
func (f *SessionFlusher) flushOneSynchronous(address string, blob []byte, advSnap uint32) {
	// CR-01/CR-03: serialize against deletes and other flush cycles. If a
	// delete completed while we waited for flushMu, the entry is gone — skip
	// the write so the deleted row is not resurrected. If a newer Enqueue
	// superseded this blob, skip too — the newer Enqueue's own inline write
	// (or the next batch) persists the newer blob, and writing the older
	// blob here could land AFTER the newer one (unordered DB writes).
	f.flushMu.Lock()
	defer f.flushMu.Unlock()
	f.mu.Lock()
	e, stillDirty := f.dirty[address]
	current := stillDirty && e.advCount == advSnap
	f.mu.Unlock()
	if !current {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := f.db.PutManySessions(ctx, map[string][]byte{address: blob})
	if err != nil {
		slog.Error(fmt.Sprintf("SessionFlusher inline flush failed addr=%s: %v", address, err))
		f.mu.Lock()
		if len(f.dirty) > f.dropCap {
			f.dropColdestLocked()
		}
		f.mu.Unlock()
		return
	}
	f.mu.Lock()
	if e, ok := f.dirty[address]; ok && e.advCount == advSnap {
		e.lastDrain = advSnap
		delete(f.dirty, address)
	}
	f.mu.Unlock()
}

// dropColdestLocked removes one entry from the dirty-set (pseudo-random map
// iteration). Must be called with f.mu held.
func (f *SessionFlusher) dropColdestLocked() {
	for addr, e := range f.dirty {
		slog.Error(fmt.Sprintf("SessionFlusher DROP dirty entry (catastrophe) addr=%s advCount=%d", addr, e.advCount))
		delete(f.dirty, addr)
		return
	}
}

// Drain flushes the entire dirty-set synchronously, retrying on transient
// failure. Blocks until the dirty-set is empty. Called during Stop().
func (f *SessionFlusher) Drain() {
	for {
		// CR-01: hold flushMu across this iteration's snapshot→DB-write→clear
		// so a concurrent delete cannot complete inside the window and then
		// have its row re-upserted by this batch.
		f.flushMu.Lock()
		f.mu.Lock()
		if len(f.dirty) == 0 {
			f.mu.Unlock()
			f.flushMu.Unlock()
			return
		}
		// Snapshot under lock; release before calling DB.
		batch := make(map[string][]byte, len(f.dirty))
		advAt := make(map[string]uint32, len(f.dirty))
		for addr, e := range f.dirty {
			batch[addr] = copyBytes(e.blob)
			advAt[addr] = e.advCount
		}
		f.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := f.db.PutManySessions(ctx, batch)
		cancel()

		if err != nil {
			f.flushMu.Unlock()
			f.log.Errorf("SessionFlusher Drain batch failed (%d rows): %v — retrying", len(batch), err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// CR-02 staleness guard — see runFlush for the rationale.
		f.mu.Lock()
		for addr, snapAdv := range advAt {
			if e, ok := f.dirty[addr]; ok {
				e.lastDrain = snapAdv
				if e.advCount == snapAdv {
					delete(f.dirty, addr)
				}
			}
		}
		drained := len(batch)
		f.mu.Unlock()
		f.flushMu.Unlock()

		f.log.Infof("SessionFlusher: drained %d on shutdown", drained)
		// WR-01: loop back to the empty-check instead of returning — entries
		// enqueued during this batch's DB write (handlers are not guaranteed
		// quiescent at shutdown) and CR-02-retained newer generations must
		// also reach the DB before the process exits. Mirrors flusher.go's
		// Drain loop.
	}
}

// runFlush drains the dirty-set once. Called from the async goroutine.
// A failed batch retains dirty state (retried next cycle). Does NOT retry.
func (f *SessionFlusher) runFlush() {
	// CR-01: hold flushMu across snapshot→DB-write→clear so a concurrent
	// delete (running inside WithFlushBlocked) cannot complete inside the
	// window and then have its row re-upserted by this batch.
	f.flushMu.Lock()
	defer f.flushMu.Unlock()
	f.mu.Lock()
	if len(f.dirty) == 0 {
		f.mu.Unlock()
		return
	}
	batch := make(map[string][]byte, len(f.dirty))
	advAt := make(map[string]uint32, len(f.dirty))
	for addr, e := range f.dirty {
		batch[addr] = copyBytes(e.blob)
		advAt[addr] = e.advCount
	}
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := f.db.PutManySessions(ctx, batch)
	cancel()

	if err != nil {
		f.log.Errorf("SessionFlusher batch flush failed (%d rows): %v", len(batch), err)
		return
	}

	// CR-02 staleness guard: only clear an entry if no newer Enqueue arrived
	// during the in-flight DB write. Deleting unconditionally would drop the
	// newer blob from the durable path forever (DB holds the snapshot
	// generation; the only copy of the newer blob would be the evictable LRU
	// mirror) — a no-crash lost update outside the documented N/T staleness
	// bound. Mirrors the SenderKeyFlusher inline-path highIter guard.
	f.mu.Lock()
	for addr, snapAdv := range advAt {
		if e, ok := f.dirty[addr]; ok {
			e.lastDrain = snapAdv
			if e.advCount == snapAdv {
				delete(f.dirty, addr)
			}
			// else: a newer blob arrived mid-write — the entry stays dirty
			// (with the newer blob) and flushes on the next cycle.
		}
	}
	f.mu.Unlock()
}

// Start launches the async flusher goroutine. Must be called once after
// NewSessionFlusher and before any Enqueue calls in production.
func (f *SessionFlusher) Start() {
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		ticker := time.NewTicker(f.flushInterval)
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
func (f *SessionFlusher) Stop() {
	close(f.stopCh)
	f.wg.Wait()
	f.Drain()
}

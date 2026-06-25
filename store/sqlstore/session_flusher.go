// Copyright (c) 2026 Kavtov Platform (Phase 35.2-09; Phase 47.3-06 D2 redesign)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// session_flusher.go implements SessionFlusher — the per-JID async write-back
// flusher for the whatsmeow_sessions table (D-15 Lever 2, Phase 35.2-09).
//
// # Phase 47.3-06 D2 single-writer actor redesign (correctness/elegance, NOT perf)
//
// D2 is a CORRECTNESS and ELEGANCE redesign, NOT a performance win. The button-
// latency improvement came entirely from D1 (the no-op-skip in
// cached_session_store.go MigratePNToLID, fork commit 6447447 / driver
// 2026.06.81). D2 makes NO latency claim: real deletes and migrations still
// block until their serialized work completes, exactly as the V1 flush-mutex did.
//
// What D2 removes is the lock-across-I/O smell. V1 held a flush mutex from the
// dirty-set snapshot all the way through PutManySessions (a Postgres round-trip)
// and only released it after the CR-02 clear pass, so every delete/migrate
// (which ran inside the V1 flush-blocked section) waited for the entire DB
// write. D2 replaces that flush mutex with a single writer goroutine that owns
// ALL DB mutation, serialized by channel FIFO — total order without holding any
// lock across I/O.
//
// Design reference (AUTHORITATIVE):
//
//	.planning/phases/47.3-.../47.3-D2-DESIGN.md §4 (struct) §5 (writer loop)
//	  §6 (read path) §7 (invariant map incl. INV-8) §8 (CR-01) §9 (backpressure)
//	.planning/SESSION-PERSISTENCE-CONTRACT.md §2 (the 8 invariants) §9
//
// # The single-writer invariant (TOTAL — design §9)
//
// EVERY DB mutation — periodic flush, N-boundary flush, single delete, prefix
// delete, PN->LID migrate, AND backpressure relief — executes ONLY inside the
// writer goroutine's runFlush / processWork. There is NO code path that calls
// db.PutManySessions / db.DeleteSession / db.DeleteAllSessions /
// db.MigratePNToLID on any goroutine other than the writer. This totality is
// what makes the channel-FIFO CR-01 proof valid (design §8): a delete work item
// sent after a flush was already snapshotted is dequeued AFTER the flush
// completes, so the delete's DB DELETE lands after the flush's DB UPSERT — the
// row ends up deleted, never resurrected.
//
// # Concurrent reads via rwmu (design §6, D-11)
//
// The dirty-set is guarded by rwmu sync.RWMutex. The writer holds rwmu.Lock()
// only for brief in-memory passes (snapshot, clear, delete). Readers (Peek,
// PeekAndMirror, HasDirtyPrefix) and producers (EnqueueAndMirror) hold rwmu for
// brief in-memory operations only. No lock is held across DB I/O. A reader that
// LRU-misses reaches a dirty-but-unflushed blob via rwmu.RLock() with NO channel
// round-trip to the writer (which may be mid-DB-write) — this is the D-11
// solution to the 17.13 -> WhatsApp-479 read-gap.
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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// sessionWriterStore is the interface the single writer goroutine needs from
// the store layer. *SQLStore satisfies all four methods (Phase 47.3-06: the V1
// flushSessionBatch interface declared only PutManySessions, which is
// insufficient now that the writer goroutine performs deletes and migrates
// itself so they serialize FIFO with flushes — see design §5).
//
// DeleteAllSessions takes the bare phone/PN signal (NOT a "<phone>:" prefix):
// its query (deleteAllSessionsQuery in store.go, collation-fixed in D1) appends
// ':%' itself via `their_id LIKE $2 || ':%' ESCAPE '\'`.
type sessionWriterStore interface {
	PutManySessions(ctx context.Context, sessions map[string][]byte) error
	DeleteSession(ctx context.Context, address string) error
	DeleteAllSessions(ctx context.Context, phone string) error
	MigratePNToLID(ctx context.Context, pn, lid types.JID) error
}

// workKind identifies the type of write work the single writer goroutine must
// perform. All DB mutation flows through one of these (design §9: total
// single-writer invariant).
type workKind int

const (
	workFlushSync       workKind = iota // backpressure relief: flush the dirty-set + signal done (producer blocks)
	workDeleteSingle                    // delete one address from DB + dirty-set
	workDeletePrefix                    // delete all addresses for a phone from DB + dirty-set
	workMigratePNPrefix                 // flush-then-migrate a PN prefix (CR-04 ordering)
)

// writeWork is a unit of work sent to the writer goroutine via workCh. Callers
// that need synchronous completion (DeleteSession, DeleteAllSessions,
// MigratePNToLID, and the backpressure-relief workFlushSync) supply a non-nil
// done channel (buffered 1) and block on it.
type writeWork struct {
	kind    workKind
	ctx     context.Context //nolint:containedctx // carries the caller's deadline to the writer's DB call (design §12.6)
	address string          // workDeleteSingle
	prefix  string          // workDeletePrefix (bare phone), workMigratePNPrefix (address prefix "<phone>:")
	phone   string          // workDeletePrefix / workMigratePNPrefix: bare phone for the DB helper (no ':%' suffix)
	pn      types.JID       // workMigratePNPrefix: inner.MigratePNToLID arg
	lid     types.JID       // workMigratePNPrefix: inner.MigratePNToLID arg
	done    chan error      // caller blocks on receive (buffered 1)
}

// sessionDirtyEntry tracks one pending session write in the dirty-set.
type sessionDirtyEntry struct {
	blob      []byte // latest flat session blob (last-wins for same address)
	advCount  uint32 // number of Enqueues for this address (N-boundary counter)
	lastDrain uint32 // advCount at last successful DB write
}

// SessionFlusher is the single-writer actor (Phase 47.3-06 D2) that batches
// dirty session entries and drains them asynchronously. One instance per
// (Container, JID). All dirty-set mutations and ALL DB writes are owned by the
// single writer goroutine (design §9); concurrent reads use rwmu.RLock().
//
// Flush triggers:
//  1. N-boundary crossing: advCount crosses a multiple of N (default N=1,
//     so every new entry signals a flush immediately)
//  2. T-timer: the flush interval ticker fires (default T=5s)
//  3. Synchronous drain on shutdown (Drain / Stop)
//
// Backpressure: when dirty-set > backpressureCap, EnqueueAndMirror sends a
// synchronous workFlushSync work item to the writer and blocks on its done
// channel — the blocking IS the backpressure (design §9). No DB write ever
// happens off the writer goroutine.
type SessionFlusher struct {
	log waLog.Logger

	// db is the widened writer interface: the writer goroutine performs flush
	// (PutManySessions), delete (DeleteSession / DeleteAllSessions), and migrate
	// (MigratePNToLID) itself, so they serialize FIFO with each other.
	db sessionWriterStore

	cap             int    // max dirty-set entries (KAVTOV_FLUSH_SESSION_CAP)
	boundaryN       uint32 // advance-count boundary (KAVTOV_FLUSH_SESSION_N)
	backpressureCap int    // synchronous relief above this size
	dropCap         int    // drop coldest above this size when DB is failing

	// rwmu guards the dirty map. The writer holds rwmu.Lock() only for brief
	// in-memory passes (snapshot, clear, delete); EnqueueAndMirror holds
	// rwmu.Lock() briefly for the dirty entry + LRU mirror; readers (Peek,
	// PeekAndMirror, HasDirtyPrefix) hold rwmu.RLock(). NO lock is held across
	// DB I/O (design §3 §6). Replaces the V1 f.mu + flush-mutex pair.
	rwmu  sync.RWMutex
	dirty map[string]*sessionDirtyEntry // key = address (no jid prefix; flusher is per-JID)

	// workCh carries explicit write work (deletes, migrates, backpressure-relief
	// flushes) to the single writer. Buffered to absorb bursts; when full, the
	// producer blocks on the send (bounded by the caller's context) — that
	// blocking is correct backpressure (design §9), not a lock-free escape hatch.
	workCh chan writeWork

	// flushCh is the N-boundary flush signal (size 1, non-blocking send). Kept
	// separate from workCh so coalescing flush signals never starve work items.
	flushCh chan struct{}

	stopCh   chan struct{}
	stopOnce sync.Once // makes Stop idempotent (double-Stop must not double-close stopCh)
	wg       sync.WaitGroup

	flushInterval time.Duration // injectable for tests; default 5s

	// withFlushBlockedCalls is retained from V1 as a test probe. In D2 nothing
	// increments it (WithFlushBlocked is removed; the no-op-skip path in
	// MigratePNToLID never dispatches a work item), so it stays at 0 — exactly
	// what TestCachedSession_MigrateNoOp_SkipsFlushBlock_FirstSend asserts (the
	// no-op path must not take any flush coordination).
	withFlushBlockedCalls atomic.Uint64
}

// workChBuffer is the workCh buffer size (design §11/§12.1 discretion item).
const workChBuffer = 256

// NewSessionFlusher constructs a SessionFlusher with prod defaults. cap=0 uses
// the env var / compiled default. log is used for error / info logging.
// IN-06: uses the single package-level envIntOrDefault helper (flusher.go).
func NewSessionFlusher(db sessionWriterStore, log waLog.Logger, cap int) *SessionFlusher {
	if cap <= 0 {
		cap = envIntOrDefault("KAVTOV_FLUSH_SESSION_CAP", 100_000)
	}
	n := uint32(envIntOrDefault("KAVTOV_FLUSH_SESSION_N", 1))
	if n == 0 {
		n = 1
	}
	tms := envIntOrDefault("KAVTOV_FLUSH_SESSION_T_MS", 5000)
	return &SessionFlusher{
		log:             log,
		db:              db,
		cap:             cap,
		boundaryN:       n,
		backpressureCap: cap / 5,
		dropCap:         cap * 2 / 5,
		dirty:           make(map[string]*sessionDirtyEntry, 1024),
		workCh:          make(chan writeWork, workChBuffer),
		flushCh:         make(chan struct{}, 1),
		stopCh:          make(chan struct{}),
		flushInterval:   time.Duration(tms) * time.Millisecond,
	}
}

// newSessionFlusherForTest constructs a SessionFlusher with a custom flush
// interval for unit tests. Tests pass a short interval (e.g. 50ms) to avoid
// sleeping the full 5s default.
func newSessionFlusherForTest(db sessionWriterStore, cap int, flushInterval time.Duration) *SessionFlusher {
	f := NewSessionFlusher(db, waLog.Noop, cap)
	f.flushInterval = flushInterval
	return f
}

// DirtyCount returns the current dirty-set size.
func (f *SessionFlusher) DirtyCount() int {
	f.rwmu.RLock()
	defer f.rwmu.RUnlock()
	return len(f.dirty)
}

// flushSyncForTest dispatches a synchronous flush through the running writer
// goroutine and blocks until it completes. Test-only: it lets a test that has
// Start()ed the flusher force a full drain via the actor (instead of calling
// runFlush/Drain directly, which would race the writer). Returns an error if
// the writer does not complete within 5s.
func (f *SessionFlusher) flushSyncForTest() error {
	done := make(chan error, 1)
	select {
	case f.workCh <- writeWork{kind: workFlushSync, done: done}:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("flushSyncForTest: workCh send timed out")
	}
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		return fmt.Errorf("flushSyncForTest: writer did not complete within 5s")
	}
}

// crossesBoundary returns true when the advance count crosses an N-boundary
// relative to lastDrain. Design §5: floor(adv/N) > floor(lastDrain/N).
func (f *SessionFlusher) crossesBoundary(adv, lastDrain uint32) bool {
	return adv/f.boundaryN > lastDrain/f.boundaryN
}

// Enqueue records a dirty session entry. Last-wins for same address.
// Signals the async flusher goroutine when the N-boundary is crossed.
// Sends a synchronous backpressure-relief flush when dirty-set > backpressureCap.
func (f *SessionFlusher) Enqueue(address string, blob []byte) {
	f.EnqueueAndMirror(address, blob, nil)
}

// EnqueueAndMirror is Enqueue with an optional mirror callback executed under
// rwmu.Lock(), immediately after the dirty entry is updated (WR-03 coherence
// invariant): every LRU.Add that mirrors a write for an address MUST happen
// inside this callback, so the dirty-set (the durable winner) and the LRU
// (what readers serve first) always agree on the winning blob for an address.
// Two unsynchronized operations — Enqueue then cache.Add — allowed the
// interleaving Enqueue(A,v1); Enqueue(A,v2); cache.Add(A,v2); cache.Add(A,v1):
// the DB persists v2 while readers serve v1 from the LRU indefinitely.
//
// mirror must be fast and must not call back into the flusher (it runs under
// rwmu.Lock()). Calling LRU methods inside it is safe: the established lock
// order is rwmu -> LRU internal lock -> secondary-index lock, and no LRU
// eviction callback or index method calls into the flusher.
//
// Backpressure (design §9): rwmu is RELEASED before any channel send/block, so
// the producer never holds rwmu while the writer needs it to snapshot/clear
// (no deadlock). On dirty-set > backpressureCap, a synchronous workFlushSync
// work item is sent to the writer and this call blocks on its done channel —
// the blocking IS the backpressure. NO DB write happens on this goroutine.
func (f *SessionFlusher) EnqueueAndMirror(address string, blob []byte, mirror func()) {
	f.rwmu.Lock()

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

	// WR-03: mirror the blob into the LRU under the same lock that decided
	// the dirty-set winner, so LRU and dirty-set cannot disagree.
	if mirror != nil {
		mirror()
	}

	crosses := f.crossesBoundary(adv, lastDrain)
	needsRelief := len(f.dirty) > f.backpressureCap

	f.rwmu.Unlock() // RELEASE rwmu BEFORE any channel send/block (design §9 — no deadlock).

	// Signal the async flusher on N-boundary crossing (non-blocking).
	if crosses {
		select {
		case f.flushCh <- struct{}{}:
		default:
		}
	}

	// Backpressure relief: a SYNCHRONOUS flush work item, FIFO-ordered with
	// pending deletes/migrates by the single writer. Blocking on done IS the
	// backpressure — it slows this producer until the writer relieves the
	// dirty-set. rwmu is NOT held here, so no deadlock with the writer's
	// snapshot/clear. NO DB write happens on this goroutine (design §9).
	if needsRelief {
		done := make(chan error, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		select {
		case f.workCh <- writeWork{kind: workFlushSync, ctx: ctx, done: done}:
			// workCh full -> the send above blocks (bounded by ctx) = backpressure.
			select {
			case <-done:
			case <-ctx.Done():
				f.log.Errorf("SessionFlusher backpressure relief timed out addr=%s", address)
			}
		case <-ctx.Done():
			f.log.Errorf("SessionFlusher backpressure enqueue timed out addr=%s", address)
		}
	}
}

// Peek returns the dirty blob for address if it is in the dirty-set (not yet
// flushed). Returns (copy, true) on hit; (nil, false) on miss. Concurrent with
// other readers via rwmu.RLock() — no channel round-trip to the writer (D-11).
// The returned slice is a heap-private copy — callers may mutate it.
func (f *SessionFlusher) Peek(address string) ([]byte, bool) {
	f.rwmu.RLock()
	entry, ok := f.dirty[address]
	if !ok {
		f.rwmu.RUnlock()
		return nil, false
	}
	out := copyBytes(entry.blob)
	f.rwmu.RUnlock()
	return out, true
}

// PeekAndMirror is Peek with an optional mirror callback executed under
// rwmu.RLock() with a copy of the dirty blob (WR-03): the read-path LRU
// repopulate after a Peek hit must also happen under the flusher lock —
// repopulating outside it could install an older blob over a concurrent
// EnqueueAndMirror's newer one, reopening the LRU-vs-dirty-set disagreement on
// the read path. Concurrent with other readers; no channel round-trip to the
// writer (D-11). Same mirror constraints as EnqueueAndMirror.
func (f *SessionFlusher) PeekAndMirror(address string, mirror func(blob []byte)) ([]byte, bool) {
	f.rwmu.RLock()
	entry, ok := f.dirty[address]
	if !ok {
		f.rwmu.RUnlock()
		return nil, false
	}
	out := copyBytes(entry.blob)
	if mirror != nil {
		mirror(out)
	}
	f.rwmu.RUnlock()
	return out, true
}

// Remove drops the dirty entry for address, preventing a stale buffered blob
// from persisting. No-op if address is not dirty. Brief rwmu.Lock() only.
// NOTE (D2): Remove no longer participates in delete ordering — DeleteSession
// dispatches a workDeleteSingle work item so the dirty-set removal and the DB
// delete serialize FIFO inside the writer. Remove is retained for direct
// callers / tests that drop a dirty entry without a DB delete.
func (f *SessionFlusher) Remove(address string) {
	f.rwmu.Lock()
	delete(f.dirty, address)
	f.rwmu.Unlock()
}

// RemovePrefix drops every dirty entry whose address starts with prefix.
// Brief rwmu.Lock() only. Retained for direct callers / tests.
func (f *SessionFlusher) RemovePrefix(prefix string) {
	f.rwmu.Lock()
	for addr := range f.dirty {
		if strings.HasPrefix(addr, prefix) {
			delete(f.dirty, addr)
		}
	}
	f.rwmu.Unlock()
}

// HasDirtyPrefix reports whether any address in the dirty-set starts with prefix.
// Concurrent-read via rwmu.RLock() (D2: updated from V1's f.mu, design §6).
// A false result has a brief false-negative window (D-05): a PN row could be
// Enqueued after HasDirtyPrefix returns false; callers accept this (benign for
// the no-op-skip path which neither deletes nor changes reads).
func (f *SessionFlusher) HasDirtyPrefix(prefix string) bool {
	f.rwmu.RLock()
	defer f.rwmu.RUnlock()
	for addr := range f.dirty {
		if strings.HasPrefix(addr, prefix) {
			return true
		}
	}
	return false
}

// DeleteSession dispatches a workDeleteSingle work item to the writer goroutine
// and blocks on the done channel. The writer removes the address from the
// dirty-set and performs the inner DB delete, both serialized FIFO with any
// in-flight flush (CR-01 via the single-writer invariant, design §8). Callers
// (cached_session_store.go DeleteSession) must do the LRU cache.Remove AFTER
// this returns (landmine #4): the done channel confirms the writer has
// completed both the DB delete and the dirty-set removal, so no read can find
// the dirty entry after the LRU is cleared.
func (f *SessionFlusher) DeleteSession(ctx context.Context, address string) error {
	done := make(chan error, 1)
	select {
	case f.workCh <- writeWork{kind: workDeleteSingle, ctx: ctx, address: address, done: done}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DeleteAllSessions dispatches a workDeletePrefix work item and blocks on done.
// The writer sweeps prefix-matching dirty entries and runs the inner
// DeleteAllSessions (deleteAllSessionsQuery — collation-fixed in D1), serialized
// FIFO with flushes (CR-01). phone is the bare phone/PN signal the DB helper
// expects (it appends ':%' itself); the dirty-set sweep matches "<phone>:" so
// the in-memory and DB removals cover the same address set (design §5 note).
func (f *SessionFlusher) DeleteAllSessions(ctx context.Context, phone string) error {
	done := make(chan error, 1)
	work := writeWork{
		kind:   workDeletePrefix,
		ctx:    ctx,
		prefix: phone + ":",
		phone:  phone,
		done:   done,
	}
	select {
	case f.workCh <- work:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// MigratePNToLID dispatches a workMigratePNPrefix work item and blocks on done.
// The writer flushes PN-prefix dirty entries first (CR-04: the migration's
// SELECT must copy the freshest ratchet state to the LID key), removes them
// from the dirty-set, then runs the inner MigratePNToLID — all serialized FIFO
// with flushes inside the single writer. pnSignal is the bare PN signal user;
// pnPrefix is "<pnSignal>:" for the dirty-set sweep.
func (f *SessionFlusher) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	done := make(chan error, 1)
	work := writeWork{
		kind:   workMigratePNPrefix,
		ctx:    ctx,
		prefix: pn.SignalAddressUser() + ":",
		pn:     pn,
		lid:    lid,
		done:   done,
	}
	select {
	case f.workCh <- work:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WithFlushBlockedCalls returns the V1 test-probe counter. In D2 nothing
// increments it (WithFlushBlocked is removed; the no-op-skip path dispatches no
// work item), so it stays at 0 — which is what
// TestCachedSession_MigrateNoOp_SkipsFlushBlock_FirstSend asserts (the no-op
// migrate path takes no flush coordination).
func (f *SessionFlusher) WithFlushBlockedCalls() uint64 {
	return f.withFlushBlockedCalls.Load()
}

// dropColdestLocked removes one entry from the dirty-set (pseudo-random map
// iteration). Must be called with rwmu.Lock() held.
func (f *SessionFlusher) dropColdestLocked() {
	for addr, e := range f.dirty {
		f.log.Errorf("SessionFlusher DROP dirty entry (catastrophe) addr=%s advCount=%d", addr, e.advCount)
		delete(f.dirty, addr)
		return
	}
}

// runFlush drains the dirty-set once. Called from the writer goroutine ONLY.
// No lock is held across the DB write (design §5). A failed batch retains dirty
// state (retried next cycle / drop coldest above dropCap). Does NOT retry.
func (f *SessionFlusher) runFlush() {
	// Step 1: snapshot under a brief write lock.
	f.rwmu.Lock()
	if len(f.dirty) == 0 {
		f.rwmu.Unlock()
		return
	}
	batch := make(map[string][]byte, len(f.dirty))
	advAt := make(map[string]uint32, len(f.dirty))
	for addr, e := range f.dirty {
		batch[addr] = copyBytes(e.blob)
		advAt[addr] = e.advCount
	}
	f.rwmu.Unlock() // RELEASED before the DB write — no lock across I/O.

	// Step 2: DB write — NO lock held.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := f.db.PutManySessions(ctx, batch)
	cancel()

	if err != nil {
		f.log.Errorf("SessionFlusher batch flush failed (%d rows): %v", len(batch), err)
		// Bound memory under DB-write failure (INV-8): drop coldest above dropCap.
		f.rwmu.Lock()
		for len(f.dirty) > f.dropCap {
			f.dropColdestLocked()
		}
		f.rwmu.Unlock()
		return
	}

	// Step 3: CR-02 staleness guard under a brief write lock. Only clear an
	// entry if no newer Enqueue arrived during the in-flight DB write — deleting
	// unconditionally would drop the newer blob from the durable path forever
	// (DB holds the snapshot generation; the only copy of the newer blob would
	// be the evictable LRU mirror). The writer holds NO lock during step 2, so a
	// concurrent EnqueueAndMirror can increment advCount; the e.advCount ==
	// snapAdv check fires and the entry stays dirty.
	f.rwmu.Lock()
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
	f.rwmu.Unlock()
}

// processWork handles one explicit work item. Called from the writer goroutine
// ONLY, so all DB mutation here is serialized FIFO with runFlush and every
// other work item (design §9 — total single-writer invariant). No lock is held
// across any DB I/O call.
func (f *SessionFlusher) processWork(work writeWork) {
	switch work.kind {
	case workFlushSync:
		// Backpressure relief: a full dirty-set flush, FIFO-ordered with deletes
		// and migrates. The producer (EnqueueAndMirror) blocks on done.
		f.runFlush()
		if work.done != nil {
			work.done <- nil
		}

	case workDeleteSingle:
		// Step 1: remove from dirty-set under a brief write lock.
		f.rwmu.Lock()
		delete(f.dirty, work.address)
		f.rwmu.Unlock()
		// Step 2: DB delete — NO lock held. Runs AFTER any in-flight flush's
		// UPSERT (FIFO), so the row ends up deleted, never resurrected (CR-01).
		ctx, cancel := f.workCtx(work.ctx)
		err := f.db.DeleteSession(ctx, work.address)
		cancel()
		if work.done != nil {
			work.done <- err
		}

	case workDeletePrefix:
		// Step 1: sweep prefix-matching dirty entries under a brief write lock.
		f.rwmu.Lock()
		for addr := range f.dirty {
			if strings.HasPrefix(addr, work.prefix) {
				delete(f.dirty, addr)
			}
		}
		f.rwmu.Unlock()
		// Step 2: DB delete — NO lock held. work.phone is the bare phone the
		// helper expects (it appends ':%' itself via deleteAllSessionsQuery).
		ctx, cancel := f.workCtx(work.ctx)
		err := f.db.DeleteAllSessions(ctx, work.phone)
		cancel()
		if work.done != nil {
			work.done <- err
		}

	case workMigratePNPrefix:
		f.processMigratePNPrefix(work)

	default:
		f.log.Errorf("SessionFlusher: unknown work kind %d", work.kind)
		if work.done != nil {
			work.done <- fmt.Errorf("unknown work kind %d", work.kind)
		}
	}
}

// processMigratePNPrefix flushes PN-prefix dirty entries, removes them, then
// runs the inner migration (CR-04). Writer goroutine only; no lock across I/O.
func (f *SessionFlusher) processMigratePNPrefix(work writeWork) {
	ctx, cancel := f.workCtx(work.ctx)
	defer cancel()

	// Step 1: snapshot PN-prefix dirty entries under a brief write lock.
	f.rwmu.Lock()
	pnBatch := make(map[string][]byte)
	for addr, e := range f.dirty {
		if strings.HasPrefix(addr, work.prefix) {
			pnBatch[addr] = copyBytes(e.blob)
		}
	}
	f.rwmu.Unlock()

	// Step 2: flush PN-prefix entries to the DB FIRST — NO lock held — so the
	// migration's SELECT copies the freshest ratchet state to the LID key.
	if len(pnBatch) > 0 {
		if err := f.db.PutManySessions(ctx, pnBatch); err != nil {
			work.done <- fmt.Errorf("pre-migrate flush: %w", err)
			return
		}
	}

	// Step 3: remove PN-prefix entries from the dirty-set so a later flush
	// cannot re-insert a zombie pn row after the migration deletes the pn rows.
	// Unconditional removal (NOT the CR-02 generation guard): a retained newer
	// pn entry would flush back as a zombie. A writer mutating a pn address
	// concurrently with its own migration races the migration itself.
	f.rwmu.Lock()
	for addr := range f.dirty {
		if strings.HasPrefix(addr, work.prefix) {
			delete(f.dirty, addr)
		}
	}
	f.rwmu.Unlock()

	// Step 4: inner migration — NO lock held.
	work.done <- f.db.MigratePNToLID(ctx, work.pn, work.lid)
}

// workCtx derives a 30s-bounded context for a writer DB call from the caller's
// context (or a fresh background context if the caller supplied none). The
// returned cancel MUST be called by the writer after the DB call. Bounding even
// a caller-supplied context guarantees the writer goroutine cannot block
// indefinitely on a single DB statement.
func (f *SessionFlusher) workCtx(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, 30*time.Second)
}

// Drain flushes the entire dirty-set synchronously, retrying on transient
// failure. Drains pending work items FIRST so no delete/migrate is lost, then
// blocks until the dirty-set is empty. Called during Stop() (after the writer
// goroutine has exited, so there is no concurrent writer — Drain runs the
// flush passes directly).
func (f *SessionFlusher) Drain() {
	// Drain any pending work items the writer goroutine did not process before
	// stopCh fired (design §12.5). The writer is gone by the time Stop() calls
	// Drain, so process them here in FIFO order.
	for {
		select {
		case work := <-f.workCh:
			f.processWork(work)
		default:
			goto flushLoop
		}
	}

flushLoop:
	for {
		f.rwmu.Lock()
		if len(f.dirty) == 0 {
			f.rwmu.Unlock()
			return
		}
		// Snapshot under lock; release before calling DB.
		batch := make(map[string][]byte, len(f.dirty))
		advAt := make(map[string]uint32, len(f.dirty))
		for addr, e := range f.dirty {
			batch[addr] = copyBytes(e.blob)
			advAt[addr] = e.advCount
		}
		f.rwmu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := f.db.PutManySessions(ctx, batch)
		cancel()

		if err != nil {
			f.log.Errorf("SessionFlusher Drain batch failed (%d rows): %v — retrying", len(batch), err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// CR-02 staleness guard — see runFlush for the rationale.
		f.rwmu.Lock()
		for addr, snapAdv := range advAt {
			if e, ok := f.dirty[addr]; ok {
				e.lastDrain = snapAdv
				if e.advCount == snapAdv {
					delete(f.dirty, addr)
				}
			}
		}
		drained := len(batch)
		f.rwmu.Unlock()

		f.log.Infof("SessionFlusher: drained %d on shutdown", drained)
		// WR-01: loop back to the empty-check instead of returning — entries
		// enqueued during this batch's DB write (handlers are not guaranteed
		// quiescent at shutdown) and CR-02-retained newer generations must
		// also reach the DB before the process exits.
	}
}

// Start launches the single writer goroutine (the actor). Must be called once
// after NewSessionFlusher and before any Enqueue calls in production. The
// writer owns ALL DB mutation: it drains the ticker, the N-boundary flush
// signal, and the work channel (deletes, migrates, backpressure relief), so
// every DB write is serialized by this one goroutine (design §5 §9).
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
			case work := <-f.workCh:
				f.processWork(work)
			}
		}
	}()
}

// Stop signals the writer goroutine to exit, waits for it, then calls Drain()
// synchronously to flush any remaining dirty entries (and process any pending
// work items) before the DB closes. Idempotent: a second Stop is a no-op (it
// must not double-close stopCh — tests may call Stop explicitly AND via
// t.Cleanup).
func (f *SessionFlusher) Stop() {
	f.stopOnce.Do(func() {
		close(f.stopCh)
		f.wg.Wait()
		f.Drain()
	})
}

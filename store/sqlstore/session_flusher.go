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
	// IsPNMigrated reports whether the once-per-process PN→LID gate has already
	// fired for pnSignal WITHOUT mutating it. The writer re-checks it inside
	// processMigratePNPrefix before destructively removing PN dirty rows: if a
	// concurrent Branch-2 path fired the gate after this work item was dispatched,
	// inner.MigratePNToLID would no-op, so the writer must NOT drop the PN dirty
	// rows (they are the only fresh copy not yet migrated). Phase 47.3 F4 fix.
	IsPNMigrated(pnSignal string) bool
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

	// abortCh is closed once the writer has permanently stopped consuming workCh
	// AND Stop()'s Drain has finished its final workCh drain. A producer that is
	// blocked on a workCh send or on <-done selects on abortCh so a work item
	// dispatched during/after shutdown returns a definitive error instead of
	// hanging forever (Phase 47.3 F1 — no orphaned, never-drained work item).
	abortCh chan struct{}

	stopCh   chan struct{}
	stopOnce sync.Once // makes Stop idempotent (double-Stop must not double-close stopCh)
	wg       sync.WaitGroup

	flushInterval time.Duration // injectable for tests; default 5s

	// drainDeadline bounds Drain's PutManySessions retry loop on shutdown (F2).
	// Default drainTotalDeadline (30s); injectable shorter for tests.
	drainDeadline time.Duration

	// migrateDispatches counts how many workMigratePNPrefix work items have been
	// dispatched to the writer (Phase 47.3 F12 — replaces the permanently-zero
	// withFlushBlockedCalls probe). The no-op MigratePNToLID path (Branch-2 /
	// Branch-3) dispatches ZERO; the full ordered path (Branch-1) dispatches
	// exactly one. TestCachedSession_MigrateNoOp_SkipsFlushBlock_FirstSend asserts
	// a delta of 0 across the no-op call — a REAL probe (a D-02 regression that
	// wrongly dispatched a work item would now be caught, where the old vacuous
	// zero counter could not).
	migrateDispatches atomic.Uint64
}

// workChBuffer is the workCh buffer size (design §11/§12.1 discretion item).
const workChBuffer = 256

// drainTotalDeadline bounds Drain()'s PutManySessions retry loop on shutdown so
// a DB-down-at-shutdown cannot wedge Stop()/Container.Close() until systemd
// SIGKILL (Phase 47.3 F2). On exhaustion Drain logs and returns so shutdown
// completes (the unflushed dirty-set is the bounded crash-loss INV-7 already
// accepts).
const drainTotalDeadline = 30 * time.Second

// errFlusherStopped is returned to a producer whose synchronous work item could
// not be dispatched to (or completed by) the writer because the flusher is
// shutting down. A definitive error — never a hang (Phase 47.3 F1).
var errFlusherStopped = fmt.Errorf("session flusher stopped")

// dispatchSync sends a synchronous work item to the writer and blocks on its
// done channel. Every send/receive selects on abortCh so a work item dispatched
// during or after shutdown returns errFlusherStopped (or the caller's ctx error)
// instead of hanging forever on an orphaned workCh (Phase 47.3 F1). The done
// channel is buffered (1) by the caller, so a writer that completes the item
// after the caller already returned on abortCh/ctx never blocks.
func (f *SessionFlusher) dispatchSync(work writeWork) error {
	if work.done == nil {
		// Programmer error: synchronous dispatch requires a done channel.
		return fmt.Errorf("dispatchSync called with nil done channel")
	}
	select {
	case f.workCh <- work:
	case <-f.abortCh:
		return errFlusherStopped
	case <-work.ctx.Done():
		return work.ctx.Err()
	}
	select {
	case err := <-work.done:
		return err
	case <-f.abortCh:
		// The writer is gone, but the item may already be buffered in workCh.
		// Stop()'s Drain processes the buffered workCh before closing abortCh,
		// so a still-buffered item completes and lands on done first (selected
		// above). Reaching here means the item will not be processed — return a
		// definitive error rather than hang.
		select {
		case err := <-work.done:
			return err
		default:
			return errFlusherStopped
		}
	case <-work.ctx.Done():
		return work.ctx.Err()
	}
}

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
		abortCh:         make(chan struct{}),
		stopCh:          make(chan struct{}),
		flushInterval:   time.Duration(tms) * time.Millisecond,
		drainDeadline:   drainTotalDeadline,
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return f.dispatchSync(writeWork{kind: workFlushSync, ctx: ctx, done: make(chan error, 1)})
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
	//
	// Phase 47.3 F6/F9: the relief work item runs reliefFlush in the writer,
	// which guarantees the dirty-set ends at or below backpressureCap even under
	// DB-write failure (it drops coldest down to backpressureCap, not merely
	// dropCap). The writer signals the relief error on done; we log and return —
	// we do NOT loop re-dispatching a full-batch flush against a failing DB
	// (that was the throughput-collapse amplification). A single relief per
	// over-cap Enqueue is sufficient because reliefFlush already brings the
	// dirty-set below the threshold.
	if needsRelief {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := f.dispatchSync(writeWork{kind: workFlushSync, ctx: ctx, done: make(chan error, 1)}); err != nil {
			// Relief failed (DB down or shutting down). reliefFlush has already
			// bounded the dirty-set via the drop path; do NOT re-dispatch.
			f.log.Errorf("SessionFlusher backpressure relief failed addr=%s: %v", address, err)
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
	if ctx == nil {
		ctx = context.Background()
	}
	return f.dispatchSync(writeWork{
		kind:    workDeleteSingle,
		ctx:     ctx,
		address: address,
		done:    make(chan error, 1),
	})
}

// DeleteAllSessions dispatches a workDeletePrefix work item and blocks on done.
// The writer sweeps prefix-matching dirty entries and runs the inner
// DeleteAllSessions (deleteAllSessionsQuery — collation-fixed in D1), serialized
// FIFO with flushes (CR-01). phone is the bare phone/PN signal the DB helper
// expects (it appends ':%' itself); the dirty-set sweep matches "<phone>:" so
// the in-memory and DB removals cover the same address set (design §5 note).
func (f *SessionFlusher) DeleteAllSessions(ctx context.Context, phone string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return f.dispatchSync(writeWork{
		kind:   workDeletePrefix,
		ctx:    ctx,
		prefix: phone + ":",
		phone:  phone,
		done:   make(chan error, 1),
	})
}

// MigratePNToLID dispatches a workMigratePNPrefix work item and blocks on done.
// The writer flushes PN-prefix dirty entries first (CR-04: the migration's
// SELECT must copy the freshest ratchet state to the LID key), removes them
// from the dirty-set, then runs the inner MigratePNToLID — all serialized FIFO
// with flushes inside the single writer. pnSignal is the bare PN signal user;
// pnPrefix is "<pnSignal>:" for the dirty-set sweep.
func (f *SessionFlusher) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// F12 probe: count the migrate work-item dispatch. Only Branch-1 (the full
	// ordered path) calls this method; the no-op/nil-flusher branches call
	// inner.MigratePNToLID directly, so this counter stays at 0 for them.
	f.migrateDispatches.Add(1)
	return f.dispatchSync(writeWork{
		kind:   workMigratePNPrefix,
		ctx:    ctx,
		prefix: pn.SignalAddressUser() + ":",
		pn:     pn,
		lid:    lid,
		done:   make(chan error, 1),
	})
}

// MigrateDispatches returns the number of workMigratePNPrefix work items
// dispatched to the writer (Phase 47.3 F12 — a REAL probe replacing the
// permanently-zero V1 withFlushBlockedCalls counter). The no-op MigratePNToLID
// path dispatches ZERO; the full ordered path dispatches exactly one. A test can
// assert the delta across a call to verify the no-op-skip took no flush
// coordination (delta 0) and the full path did (delta 1).
func (f *SessionFlusher) MigrateDispatches() uint64 {
	return f.migrateDispatches.Load()
}

// clearStaleLocked applies the CR-02 staleness guard for a completed batch:
// for each address that was in the snapshot, record the drained generation and
// delete the dirty entry ONLY if no newer Enqueue arrived during the in-flight
// DB write (e.advCount == snapAdv). If a newer blob arrived mid-write the entry
// stays dirty (the newer generation flushes next cycle) — clearing it
// unconditionally would drop the newer blob from the durable path forever.
// Must be called with rwmu.Lock() held. Phase 47.3 F14: this clear pass was
// copy-pasted in runFlush, reliefFlush, and Drain; extracting it ensures a
// future guard fix applies to every flush path, not silently to one copy.
func (f *SessionFlusher) clearStaleLocked(advAt map[string]uint32) {
	for addr, snapAdv := range advAt {
		if e, ok := f.dirty[addr]; ok {
			e.lastDrain = snapAdv
			if e.advCount == snapAdv {
				delete(f.dirty, addr)
			}
		}
	}
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

	// Step 3: CR-02 staleness guard under a brief write lock (F14 helper). Only
	// clear an entry if no newer Enqueue arrived during the in-flight DB write.
	// The writer holds NO lock during step 2, so a concurrent EnqueueAndMirror
	// can increment advCount; clearStaleLocked keeps such entries dirty.
	f.rwmu.Lock()
	f.clearStaleLocked(advAt)
	f.rwmu.Unlock()
}

// processWork handles one explicit work item. Called from the writer goroutine
// ONLY, so all DB mutation here is serialized FIFO with runFlush and every
// other work item (design §9 — total single-writer invariant). No lock is held
// across any DB I/O call.
func (f *SessionFlusher) processWork(work writeWork) {
	switch work.kind {
	case workFlushSync:
		// Backpressure relief: bound the dirty-set to <= backpressureCap even
		// under DB-write failure (Phase 47.3 F6/F9). The producer
		// (EnqueueAndMirror) blocks on done and gets the relief error.
		err := f.reliefFlush()
		if work.done != nil {
			work.done <- err
		}

	case workDeleteSingle:
		// Phase 47.3 F3: DB delete FIRST; remove the dirty entry ONLY on success.
		// On DB error keep the dirty entry and return the error — no torn state
		// (V1 ordering: the dirty entry was the only fresh copy; dropping it
		// before a failed DB delete would lose the ratchet blob AND leave the DB
		// row, with the caller believing the session deleted).
		//
		// CR-01 ordering is preserved: this runs AFTER any in-flight flush's
		// UPSERT (single-writer FIFO), so the DELETE lands after the UPSERT and
		// the row ends up deleted, never resurrected.
		ctx, cancel := f.workCtx(work.ctx)
		err := f.db.DeleteSession(ctx, work.address)
		cancel()
		if err == nil {
			f.rwmu.Lock()
			delete(f.dirty, work.address)
			f.rwmu.Unlock()
		}
		if work.done != nil {
			work.done <- err
		}

	case workDeletePrefix:
		// Phase 47.3 F3: DB prefix-delete FIRST; sweep the dirty-set ONLY on
		// success. work.phone is the bare phone the helper expects (it appends
		// ':%' itself via deleteAllSessionsQuery).
		ctx, cancel := f.workCtx(work.ctx)
		err := f.db.DeleteAllSessions(ctx, work.phone)
		cancel()
		if err == nil {
			f.rwmu.Lock()
			for addr := range f.dirty {
				if strings.HasPrefix(addr, work.prefix) {
					delete(f.dirty, addr)
				}
			}
			f.rwmu.Unlock()
		}
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

// reliefFlush is the backpressure-relief flush (Phase 47.3 F6/F9). Unlike
// runFlush (the periodic/N-boundary flush, which on DB failure drops only to
// dropCap), reliefFlush GUARANTEES the dirty-set ends at or below
// backpressureCap on return — that is what makes the relief actually relieve.
// On a successful DB write it clears the snapshot generation (CR-02 guard) and
// returns nil. On DB-write failure it drops coldest entries down to
// backpressureCap (bounding memory AND guaranteeing the producer's needsRelief
// condition is false next time) and returns the DB error so the producer can
// log it — without the producer re-dispatching a full-batch flush against the
// failing DB (the throughput-collapse amplification the review flagged).
// Writer goroutine only; no lock held across the DB write.
func (f *SessionFlusher) reliefFlush() error {
	// Step 1: snapshot under a brief write lock.
	f.rwmu.Lock()
	if len(f.dirty) == 0 {
		f.rwmu.Unlock()
		return nil
	}
	batch := make(map[string][]byte, len(f.dirty))
	advAt := make(map[string]uint32, len(f.dirty))
	for addr, e := range f.dirty {
		batch[addr] = copyBytes(e.blob)
		advAt[addr] = e.advCount
	}
	f.rwmu.Unlock()

	// Step 2: DB write — NO lock held.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := f.db.PutManySessions(ctx, batch)
	cancel()

	if err != nil {
		f.log.Errorf("SessionFlusher relief flush failed (%d rows): %v", len(batch), err)
		// Drop coldest down to backpressureCap so the relief actually relieves
		// (NOT merely to dropCap, which stays above backpressureCap and re-arms
		// the producer's needsRelief on the very next Enqueue — F6/F9).
		f.rwmu.Lock()
		for len(f.dirty) > f.backpressureCap {
			f.dropColdestLocked()
		}
		f.rwmu.Unlock()
		return err
	}

	// Step 3: CR-02 staleness guard (same rationale as runFlush).
	f.rwmu.Lock()
	f.clearStaleLocked(advAt)
	f.rwmu.Unlock()
	return nil
}

// processMigratePNPrefix flushes PN-prefix dirty entries, runs the inner
// migration, then removes the PN dirty entries ONLY IF the migration actually
// consumed them (CR-04 + Phase 47.3 F4). Writer goroutine only; no lock across
// I/O.
func (f *SessionFlusher) processMigratePNPrefix(work writeWork) {
	ctx, cancel := f.workCtx(work.ctx)
	defer cancel()

	// Step 1: single-pass collection of PN-prefix dirty keys + their blobs under
	// a brief write lock (F13: was a double map scan — collect once here, reuse
	// pnKeys for the conditional remove in step 4).
	f.rwmu.Lock()
	pnBatch := make(map[string][]byte)
	pnKeys := make([]string, 0)
	for addr, e := range f.dirty {
		if strings.HasPrefix(addr, work.prefix) {
			pnBatch[addr] = copyBytes(e.blob)
			pnKeys = append(pnKeys, addr)
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

	// Step 3: F4 gate re-validation. If a concurrent Branch-2 path fired the
	// once-per-process gate after this work item was dispatched, the inner
	// MigratePNToLID below will NO-OP (migrate nothing) — and removing the PN
	// dirty rows would orphan them (never migrated, never re-migratable this
	// process). Re-check the gate INSIDE the writer (serialized with all other
	// mutations): only run the destructive remove if the gate has NOT already
	// fired, i.e. THIS migration is the one that will consume the rows.
	consumed := !f.db.IsPNMigrated(work.pn.SignalAddressUser())

	// Step 4: inner migration — NO lock held.
	migErr := f.db.MigratePNToLID(ctx, work.pn, work.lid)
	if migErr != nil {
		// Migration failed: keep the dirty rows for a retry (they were flushed to
		// the DB in step 2, but retaining the dirty copy lets a retry re-flush the
		// freshest generation). Do NOT remove. Return the error.
		work.done <- migErr
		return
	}

	// Step 5: remove PN-prefix entries from the dirty-set ONLY if this migration
	// actually consumed them (gate was not already fired). Conditional remove
	// (NOT the CR-02 generation guard): a consumed prefix must be swept so a
	// later flush cannot re-insert a zombie pn row after the migration deleted
	// the pn rows. If the migration no-op'd (consumed == false), the PN dirty
	// rows are retained for a real migration (F4 — no strand).
	if consumed {
		f.rwmu.Lock()
		for _, addr := range pnKeys {
			delete(f.dirty, addr)
		}
		f.rwmu.Unlock()
	}

	work.done <- nil
}

// workCtx returns a FRESH 30s-bounded background context for a writer DB
// mutation, DETACHED from the caller's cancellable request context (Phase 47.3
// F5). A delete/migrate is a durability action: once it is dispatched to the
// writer and the caller has (logically) committed to it, cancelling the
// caller's request ctx must NOT drop the DB mutation. The pre-fix code derived
// the writer's ctx from the caller's ctx, so a caller ctx that cancelled while
// the item sat in workCh failed the mutation with context.Canceled and the
// already-returned caller never retried — a silently-dropped security delete.
// The unused parent arg is retained for call-site symmetry / future deadline
// propagation; the 30s bound also guarantees the writer cannot block
// indefinitely on a single DB statement.
func (f *SessionFlusher) workCtx(_ context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// Drain processes pending work items, then flushes the entire dirty-set
// synchronously, retrying PutManySessions on transient failure UP TO a total
// deadline (Phase 47.3 F2). Called during Stop() AFTER the writer goroutine has
// exited (no concurrent writer — Drain runs the passes directly).
//
// F1: it drains pending work items in a loop until workCh is empty — and each
// such item is processed to completion (its done channel is signalled) so a
// dispatched delete/migrate that was still buffered when the writer exited is
// NEVER silently lost. After this Drain returns, Stop closes abortCh so any
// producer that races a send into the now-orphaned workCh returns
// errFlusherStopped instead of hanging.
//
// F2: the dirty-set flush retry is bounded by drainTotalDeadline — on a
// DB-down-at-shutdown it logs the un-drained count and returns so
// Stop()/Container.Close() completes instead of wedging until SIGKILL.
func (f *SessionFlusher) Drain() {
	// Drain ALL pending work items the writer did not process before stopCh
	// fired (design §12.5, F1). Loop until workCh is empty — processWork
	// signals each item's done channel, so no buffered delete/migrate is lost.
	for {
		select {
		case work := <-f.workCh:
			f.processWork(work)
		default:
			goto flushLoop
		}
	}

flushLoop:
	deadline := time.Now().Add(f.drainDeadline)
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
			if time.Now().After(deadline) {
				// F2: bound the retry. Give up so shutdown completes; the
				// un-drained dirty-set is the bounded crash-loss INV-7 accepts.
				f.rwmu.Lock()
				lost := len(f.dirty)
				f.rwmu.Unlock()
				f.log.Errorf("SessionFlusher Drain abandoned after %s: DB still failing, %d dirty entries unflushed at shutdown: %v", f.drainDeadline, lost, err)
				return
			}
			f.log.Errorf("SessionFlusher Drain batch failed (%d rows): %v — retrying", len(batch), err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// CR-02 staleness guard (F14 helper) — see runFlush for the rationale.
		f.rwmu.Lock()
		f.clearStaleLocked(advAt)
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
// work items) before the DB closes. After Drain, abortCh is closed so any
// producer that races a synchronous work-item dispatch into the now-orphaned
// workCh returns errFlusherStopped instead of hanging forever (Phase 47.3 F1).
// Idempotent: a second Stop is a no-op (it must not double-close stopCh — tests
// may call Stop explicitly AND via t.Cleanup).
func (f *SessionFlusher) Stop() {
	f.stopOnce.Do(func() {
		close(f.stopCh)
		f.wg.Wait()
		f.Drain()
		// Close abortCh AFTER Drain has emptied workCh: a producer blocked in
		// dispatchSync now observes abortCh and returns a definitive error
		// rather than waiting on a done channel no writer will ever signal.
		close(f.abortCh)
	})
}

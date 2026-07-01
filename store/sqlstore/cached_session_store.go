// Copyright (c) 2026 Kavtov Platform (Phase 17.5 / Phase 35.2-09)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"context"
	"fmt"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// CachedSessionStore wraps an inner store.SessionStore with a process-shared
// *lru.Cache[string, []byte] and an optional per-JID SessionFlusher for
// bounded-staleness write-back (Phase 35.2-09 D-15 Lever 2).
//
// # Write semantics (when flusher is set — Phase 35.2-09)
//
// PutSession and PutManySessions now defer writes to the per-JID
// SessionFlusher instead of writing through to the inner store immediately.
// The flusher batches writes and drains them asynchronously with bounded
// staleness (N=1 advance per address OR T=5s, whichever first). The row is
// durable within (N, T) or on graceful closeSignalCaches Drain — NOT
// necessarily by the time PutSession returns. The prior strict-write-through
// guarantee ("durable by the time PutSession returns") no longer holds when
// the flusher is set. See 35.2-09-CRASH-LOSS.md for the crash-loss analysis.
//
// # Read coherence under deferral (the 17.13 guard)
//
// GetSession, GetManySessions, and HasSession consult the flusher's dirty-set
// (via flusher.Peek) AFTER an LRU miss and BEFORE falling through to the
// inner DB read. This ensures that a just-written but not-yet-flushed session
// is always readable, even if it was evicted from the LRU by capacity
// pressure. ContainsSession at send.go:1398 / sendfb.go:618 / retry.go:228
// calls HasSession OUTSIDE any WithCachedSessions scope — missing the dirty-
// set here caused ErrNoSession / WhatsApp 479 (the 17.13 read-gap class).
//
// # Delete coherence (17.5 data-loss path T-35.2-09-04 re-audit + CR-01)
//
// Phase 47.3-06 D2: DeleteSession and DeleteAllSessions dispatch the inner DB
// delete AND the matching dirty-entry removal as a work item to the single
// writer goroutine (via flusher.DeleteSession / DeleteAllSessions), which
// serializes them by channel FIFO against every flush cycle (periodic batch,
// N-boundary flush, shutdown drain, backpressure-relief flush). Deletes are NOT
// deferred — the caller blocks on the work item's done channel. This prevents
// both the Phase-17.5 timer-vs-Delete race (a deferred delete racing a
// buffered re-add) and the CR-01 snapshot race (a flush batch snapshotted
// BEFORE the delete re-upserting the row AFTER the delete completes).
//
// # Phase-17.5 data-loss paths re-audit (W2)
//
// The six BLOCKER-class paths from the 17.5 review are addressed as follows:
//
//  1. Timer-vs-Delete race: deletes dispatch a delete work item to the single
//     writer (CR-01 FIFO ordering), so no buffered write — including an
//     already-snapshotted in-flight batch — can persist after a delete
//     completes.
//  2. "Clear state before inner write" inversion: the flusher snapshots-then-writes
//     and only clears the dirty entry on a confirmed drain — never clears state
//     before the DB write lands.
//  3. Ack-before-flush: acked by Drain-on-Stop (closeSignalCaches calls
//     flusher.Stop which calls Drain synchronously before DB closes).
//  4. Read-drop on LRU eviction: the Peek path covers LRU-evicted dirty entries
//     on EVERY reader (Get/GetMany/HasSession).
//  5. Double-write / write-through alongside flusher: inner.Put* is reachable
//     ONLY on the nil-flusher fallback branch (no double-write).
//  6. Cross-wrapper LRU pollution on DeleteAllSessions: unchanged — the O(K)
//     secondary-index scope still restricts evictions to (jid, phone).
//
// # Write-through fallback (nil flusher)
//
// When no flusher is set (flusher == nil), PutSession / PutManySessions
// fall through to the original strict write-through path (inner.Put* first,
// then cache.Add). This preserves backward compatibility for test contexts
// and any code path that constructs a CachedSessionStore without wiring a
// flusher.
//
// # Copy discipline (Phase 17.5 FIX CR-06 — unchanged)
//
//   - PutSession stores a copy of the caller's slice in the cache and flusher.
//   - GetSession returns a copy of the cached / dirty slice.
//   - GetManySessions returns a map whose values are copies.
//   - Nil values are NEVER cached (Pitfall 5).
//
// # Bulk-mutation key scoping (Phase 24: O(K) secondary-index lookup — unchanged)
//
//   - DeleteAllSessions(phone): O(K) secondary-index SnapshotKeys lookup.
//   - MigratePNToLID(pn, lid): inner first, then O(K) eviction of PN-keyed entries.
//
// # Single-writer assumption (unchanged)
//
// Every mutation to whatsmeow_sessions for this device's JID MUST go through
// this wrapper. Out-of-band mutations cannot be observed by the cache.
type CachedSessionStore struct {
	inner   store.SessionStore
	jid     string
	cache   *lru.Cache[string, []byte]
	flusher *SessionFlusher // nil = write-through fallback (Phase 35.2-09)

	hits, misses, evictions uint64

	// explicitRemoves points at the Container-level SessionExplicitRemoves
	// counter (signalCaches.SessionExplicitRemoves). Incremented at call
	// sites of Remove() before delegating to the LRU (Phase 17.5.2).
	explicitRemoves *uint64

	// secondaryIndex is the process-shared (jid,phone)→cacheKeys index
	// shared across all device wrappers. Used by DeleteAllSessions and
	// MigratePNToLID for O(K) bulk removal. Maintained in lockstep with
	// every c.cache.Add call. Phase 24.
	secondaryIndex *sessionSecondaryIndex
}

var _ store.SessionStore = (*CachedSessionStore)(nil)

// NewCachedSessionStore constructs a wrapper over inner with the given JID
// scope and shared LRU. explicitRemoves is a pointer to the Container-level
// SessionExplicitRemoves counter (Phase 17.5.2). secondaryIndex is the
// process-shared (jid,phone)→cacheKeys secondary index (Phase 24).
func NewCachedSessionStore(inner store.SessionStore, jid string, cache *lru.Cache[string, []byte], explicitRemoves *uint64, secondaryIndex *sessionSecondaryIndex) *CachedSessionStore {
	return &CachedSessionStore{
		inner:           inner,
		jid:             jid,
		cache:           cache,
		explicitRemoves: explicitRemoves,
		secondaryIndex:  secondaryIndex,
	}
}

// SetFlusher attaches the write-back flusher. Called by cache_wiring.go after
// wireSignalCaches constructs the per-JID SessionFlusher. Must be called
// before any PutSession calls in production; nil is safe (write-through
// fallback preserved for backward compat).
func (c *CachedSessionStore) SetFlusher(f *SessionFlusher) {
	c.flusher = f
}

func (c *CachedSessionStore) key(address string) string {
	return c.jid + "|" + address
}


// Stats returns the current values of the per-wrapper atomic counters.
// Phase 17.5 FIX dropped the coalesced / flushed counters along with the
// write-back machinery — only hits / misses / evictions remain.
func (c *CachedSessionStore) Stats() (hits, misses, evictions uint64) {
	return atomic.LoadUint64(&c.hits),
		atomic.LoadUint64(&c.misses),
		atomic.LoadUint64(&c.evictions)
}

// ---------------------------------------------------------------------------
// store.SessionStore — read methods
// ---------------------------------------------------------------------------

func (c *CachedSessionStore) GetSession(ctx context.Context, address string) ([]byte, error) {
	k := c.key(address)
	if v, ok := c.cache.Get(k); ok {
		atomic.AddUint64(&c.hits, 1)
		// Copy out so caller mutation cannot corrupt the cached slice
		// (Phase 17.5 FIX CR-06).
		return copyBytes(v), nil
	}
	atomic.AddUint64(&c.misses, 1)
	// Phase 35.2-09: consult the flusher dirty-set before the inner read.
	// A dirty-but-unflushed entry (including one evicted from the LRU by
	// capacity pressure) must be readable here — failing to do so reproduces
	// the 17.13 read-gap class (ContainsSession false -> ErrNoSession -> 479).
	if c.flusher != nil {
		// WR-03: repopulate the LRU under the flusher mutex (PeekAndMirror)
		// so this cannot install an older blob over a concurrent writer's
		// newer EnqueueAndMirror mirror.
		if blob, ok := c.flusher.PeekAndMirror(address, func(b []byte) {
			c.cache.Add(k, copyBytes(b))
			c.secondaryIndex.Insert(c.jid, addressUser(address), k)
		}); ok {
			return blob, nil // blob is already a copy from PeekAndMirror
		}
	}
	v, err := c.inner.GetSession(ctx, address)
	if err != nil {
		return nil, err
	}
	if v == nil {
		// Pitfall 5: never cache nil. A subsequent PutSession would not
		// invalidate a nil entry and subsequent Gets would erroneously
		// return nil.
		return nil, nil
	}
	// inner.GetSession returns a fresh heap slice; cache a copy so future
	// callers receive their own copies even if a prior caller's slice got
	// rewritten in place (defence in depth — the inner store already heap-
	// allocates, but the wrapper should not depend on that).
	stored := copyBytes(v)
	c.cache.Add(k, stored)
	// Phase 24 orphan-free invariant: every c.cache.Add must be paired with
	// a secondaryIndex.Insert so SnapshotKeys can reach read-populated
	// entries during DeleteAllSessions / MigratePNToLID eviction.
	c.secondaryIndex.Insert(c.jid, addressUser(address), k)
	return copyBytes(stored), nil
}

func (c *CachedSessionStore) HasSession(ctx context.Context, address string) (bool, error) {
	if _, ok := c.cache.Get(c.key(address)); ok {
		atomic.AddUint64(&c.hits, 1)
		return true, nil
	}
	atomic.AddUint64(&c.misses, 1)
	// Phase 35.2-09: consult the flusher dirty-set BEFORE the inner read.
	// ContainsSession calls this at send.go:1398 / sendfb.go:618 /
	// retry.go:228 OUTSIDE any WithCachedSessions scope. If the session for
	// this address was written via PutSession but not yet flushed AND was
	// evicted from the LRU, a false result here causes ErrNoSession ->
	// WhatsApp 479 (the 17.13 read-gap class). flusher.Peek covers this gap.
	if c.flusher != nil {
		if _, ok := c.flusher.Peek(address); ok {
			return true, nil
		}
	}
	// Intentionally do NOT cache the boolean result. The cache only stores
	// session payloads, populated by PutSession / GetSession. Caching a
	// "true" sentinel would have no payload to serve from and caching a
	// "false" sentinel would risk masking a later PutSession.
	return c.inner.HasSession(ctx, address)
}

func (c *CachedSessionStore) GetManySessions(ctx context.Context, addresses []string) (map[string][]byte, error) {
	result := make(map[string][]byte, len(addresses))
	misses := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		if v, ok := c.cache.Get(c.key(addr)); ok {
			atomic.AddUint64(&c.hits, 1)
			result[addr] = copyBytes(v)
		} else {
			atomic.AddUint64(&c.misses, 1)
			misses = append(misses, addr)
		}
	}
	if len(misses) == 0 {
		return result, nil
	}
	// Phase 35.2-09: on LRU miss, consult the flusher dirty-set before the
	// inner read. Same read-coherence requirement as GetSession / HasSession:
	// WithCachedSessions prefetch (GetManySessions) must see dirty-but-unflushed
	// AND LRU-evicted sessions so sends don't hit ErrNoSession.
	var innerMisses []string
	if c.flusher != nil {
		for _, addr := range misses {
			k := c.key(addr)
			// WR-03: repopulate under the flusher mutex — see GetSession.
			if blob, ok := c.flusher.PeekAndMirror(addr, func(b []byte) {
				c.cache.Add(k, copyBytes(b))
				c.secondaryIndex.Insert(c.jid, addressUser(addr), k)
			}); ok {
				result[addr] = blob // blob is already a copy from PeekAndMirror
			} else {
				innerMisses = append(innerMisses, addr)
			}
		}
	} else {
		innerMisses = misses
	}
	if len(innerMisses) == 0 {
		return result, nil
	}
	fetched, err := c.inner.GetManySessions(ctx, innerMisses)
	if err != nil {
		return nil, err
	}
	for addr, v := range fetched {
		if v == nil {
			// Pitfall 5: skip caching of nil; still surface to caller so
			// they observe the same map shape they'd get from inner.
			result[addr] = nil
			continue
		}
		stored := copyBytes(v)
		c.cache.Add(c.key(addr), stored)
		// Phase 24 orphan-free invariant: every c.cache.Add must be paired
		// with a secondaryIndex.Insert so SnapshotKeys can reach read-
		// populated entries during bulk-remove paths.
		c.secondaryIndex.Insert(c.jid, addressUser(addr), c.key(addr))
		result[addr] = copyBytes(stored)
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// store.SessionStore — write methods
// ---------------------------------------------------------------------------

// PutSession enqueues the session into the per-JID flusher (write-back) when
// the flusher is set, mirroring the blob into the LRU for read hits. When no
// flusher is set, falls back to strict write-through (inner first, then cache).
//
// Phase 35.2-09: on the flusher-set path, inner.PutSession is NOT called here
// (zero double-write, W3). The flusher drains to DB asynchronously. Caller
// may reuse the session buffer after this call returns; both the cache and the
// flusher store their own copies.
func (c *CachedSessionStore) PutSession(ctx context.Context, address string, session []byte) error {
	if c.flusher != nil {
		// Write-back path: enqueue into flusher, mirror into LRU for read hits.
		// No inner.PutSession call (zero double-write — inner.Put* is only on
		// the nil-flusher fallback branch below).
		// WR-03: the LRU mirror runs under the flusher mutex (EnqueueAndMirror)
		// so concurrent same-address writers (receive-path StoreSession vs
		// send-path PutCachedSessions) cannot leave the LRU and the dirty-set
		// disagreeing on the winning blob — readers check the LRU first and
		// would otherwise serve a stale blob indefinitely while a different
		// one gets persisted.
		k := c.key(address)
		c.flusher.EnqueueAndMirror(address, session, func() {
			c.cache.Add(k, copyBytes(session))
			c.secondaryIndex.Insert(c.jid, addressUser(address), k)
		})
		return nil
	}
	// Nil-flusher fallback: strict write-through (original behavior).
	if err := c.inner.PutSession(ctx, address, session); err != nil {
		return err
	}
	c.cache.Add(c.key(address), copyBytes(session))
	// Phase 24 orphan-free invariant: maintain secondaryIndex in lockstep
	// with every cache.Add (D-05). addressUser extracts the libsignal user
	// portion ("<user>" from "<user>:<device>") as the index "phone".
	c.secondaryIndex.Insert(c.jid, addressUser(address), c.key(address))
	return nil
}

// PutManySessions enqueues every session into the per-JID flusher (write-back)
// when the flusher is set, mirroring each blob into the LRU. When no flusher
// is set, falls back to strict write-through.
//
// Phase 35.2-09: on the flusher-set path, inner.PutManySessions is NOT called
// here (zero double-write, W3). This covers write path #2 (PutCachedSessions
// at end-of-batch send flush via store/sessioncache.go).
func (c *CachedSessionStore) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
	if c.flusher != nil {
		// Write-back path: enqueue each address into the flusher, mirror into
		// LRU. WR-03: mirror under the flusher mutex — see PutSession above.
		for addr, v := range sessions {
			k := c.key(addr)
			c.flusher.EnqueueAndMirror(addr, v, func() {
				c.cache.Add(k, copyBytes(v))
				c.secondaryIndex.Insert(c.jid, addressUser(addr), k)
			})
		}
		return nil
	}
	// Nil-flusher fallback: strict write-through (original behavior).
	if err := c.inner.PutManySessions(ctx, sessions); err != nil {
		return err
	}
	for addr, v := range sessions {
		c.cache.Add(c.key(addr), copyBytes(v))
		// Phase 24 orphan-free invariant: every c.cache.Add paired with
		// secondaryIndex.Insert on the same success branch (D-05).
		c.secondaryIndex.Insert(c.jid, addressUser(addr), c.key(addr))
	}
	return nil
}

// DeleteSession removes the session for this address from the inner DB and the
// flusher dirty-set, then removes the cache entry. A buffered blob cannot
// resurrect a deleted session (Phase 35.2-09 T-35.2-09-04, re-audit of the 17.5
// timer-vs-Delete race; deletes stay synchronous).
func (c *CachedSessionStore) DeleteSession(ctx context.Context, address string) error {
	// Phase 47.3-06 D2 CR-01: the inner DB delete AND the dirty-entry removal
	// run inside the single writer goroutine via a workDeleteSingle work item.
	// The writer processes flush, delete, and migrate work in channel-FIFO
	// order, so a delete sent while a flush is in flight is dequeued AFTER the
	// flush completes — the delete's DB DELETE lands after the flush's DB UPSERT
	// and the row ends up deleted, never resurrected (design §8). This replaces
	// the V1 flush-mutex lock-across-I/O delete-blocking section. Deletes are a
	// security/correctness action (identity change, corrupt session);
	// resurrection is a crypto-store integrity violation.
	//
	// flusher.DeleteSession blocks on the work item's done channel — so by the
	// time it returns the writer has completed BOTH the DB delete and the
	// dirty-set removal. The LRU cache.Remove below therefore runs AFTER the
	// dirty entry is gone (RESEARCH landmine #4): no concurrent read can fall
	// through to a still-dirty entry once the LRU is cleared.
	if c.flusher != nil {
		if err := c.flusher.DeleteSession(ctx, address); err != nil {
			return err
		}
	} else if err := c.inner.DeleteSession(ctx, address); err != nil {
		return err
	}
	// kavtov-fork: Phase 17.5.2 - pre-increment explicit-remove counter (see Plan 17.5.2-03)
	atomic.AddUint64(c.explicitRemoves, 1)
	c.cache.Remove(c.key(address))
	// Phase 24: No explicit secondaryIndex.Remove call here. Index cleanup
	// happens via the eviction callback (cache_wiring.go) which fires for
	// every cache.Remove including explicit ones — no separate index.Remove
	// needed here.
	return nil
}

// DeleteAllSessions writes through to inner and (on success) removes from
// the cache only those entries whose address starts with `phone + ":"`,
// mirroring the SQL `their_id >= phone||':' AND their_id < phone||';'`
// predicate (deleteAllSessionsQuery in store.go). Entries for other phones
// (and for other devices' wrappers sharing this LRU) are left intact.
//
// Phase 17.5 FIX CR-03 regression: the previous implementation dropped
// every dirty entry in the per-wrapper buffer AND purged every key in the
// shared LRU via a Container-level cross-cache fan-out — a single phone
// delete would silently roll back unrelated conversations on the same
// device and every conversation on every other device too.
//
// Phase 24: the former O(N) cache.Keys() prefix-walk is replaced by a
// single O(K) lookup against the secondary index (where K is the number
// of matching entries for this (jid, phone) pair, typically 1–10).
// Cross-wrapper isolation (Phase 17.5.3) is preserved by construction:
// the index is (jid, phone)-scoped, so SnapshotKeys never returns keys
// belonging to other wrappers.
func (c *CachedSessionStore) DeleteAllSessions(ctx context.Context, phone string) error {
	// Phase 47.3-06 D2 CR-01: the inner DB prefix-delete + dirty-set prefix
	// sweep run inside the single writer goroutine via a workDeletePrefix work
	// item, FIFO-ordered with flushes — so an in-flight flush snapshot cannot
	// re-upsert deleted rows after the delete completes (same resurrection race
	// as DeleteSession above). The flusher dirty-set key is the raw address (no
	// jid prefix) and the flusher is per-JID, so the phone+":" prefix sweep has
	// no cross-JID contamination risk. flusher.DeleteAllSessions blocks on the
	// work item's done channel, so the LRU sweep below runs after the dirty
	// entries are gone (landmine #4).
	if c.flusher != nil {
		if err := c.flusher.DeleteAllSessions(ctx, phone); err != nil {
			return err
		}
	} else if err := c.inner.DeleteAllSessions(ctx, phone); err != nil {
		return err
	}
	// Phase 24: single O(K) lookup instead of O(N) cache.Keys() scan.
	// SnapshotKeys acquires a read lock, copies the bucket, and releases
	// before returning — callers iterate the snapshot without holding any
	// index lock (lock-ordering discipline prevents deadlock with the
	// EvictCleanup callback).
	victims := c.secondaryIndex.SnapshotKeys(c.jid, phone)
	for _, k := range victims {
		// kavtov-fork: Phase 17.5.2 - pre-increment per iteration (Phase 24: one per snapshot entry)
		atomic.AddUint64(c.explicitRemoves, 1)
		c.cache.Remove(k)
		// Each cache.Remove fires the eviction callback (cache_wiring.go)
		// which calls EvictCleanup on the index — no separate index.Remove.
	}
	// Defensive sweep: DropKey is idempotent and guards against the race
	// where capacity eviction removed some keys between SnapshotKeys and
	// the explicit Remove loop, leaving a stale empty bucket in the index.
	c.secondaryIndex.DropKey(c.jid, phone)
	return nil
}

// MigratePNToLID first flushes PN-prefixed dirty flusher entries to the DB
// (Phase 35.2-09 CR-04 — this WRITES pending state, unlike the Phase 17.5
// regression where pending writes were DROPPED and caches purged before
// calling inner, leaving the migrated row stale), then writes through to
// inner, both inside the flusher's flush-blocked section.
// On success, EVICTS any cache entries under this wrapper's JID prefix
// whose libsignal address-user equals pn.SignalAddressUser(). Subsequent
// reads against the new LID address will cache-miss, fetch the migrated
// value from inner, and populate the cache under the LID key naturally.
//
// Key-format note (Phase 17.5 FIX2 BL-01): cache keys are
// `<jid>|<SignalAddressUser>:<device>`, NOT the full JID-string form.
// The libsignal layer composes addresses via
// `JID.SignalAddress() = NewSignalAddress(jid.SignalAddressUser(), device)`
// (whatsmeow-fork/types/jid.go:107-109), and SignalAddress.String() returns
// `<name>:<deviceID>`. The inner SQL layer agrees: store.go:272 passes
// `pn.SignalAddressUser()` to the SQL predicate `their_id >= $2 || ':'`.
// The previous implementation matched on the full JID-string form (e.g.
// `"12345@s.whatsapp.net"`), which never shared a prefix with any
// production cache key (`"12345:0"`) — so the cache-rewrite loop was a
// no-op in production. The fix evicts using `pn.SignalAddressUser() + ":"`
// to mirror the SQL semantics exactly.
//
// Evict-not-rewrite rationale: the old "rewrite into the new LID key"
// behaviour had to define precedence vs a pre-existing LID entry under
// the same key (caused by a prior failed migration attempt or out-of-band
// activity). Plain eviction is unambiguously correct: the inner SQL row
// holds the post-migration value, and the next read picks it up. The
// throughput cost is one extra inner.GetSession per migrated address on
// the first post-migration decrypt — an O(K) secondary-index lookup per
// invocation (Phase 24), replacing the former O(N) cache.Keys() full-LRU
// scan that measured 13.43% of driver CPU in the 2026-05-28 60s pprof.
// The claim in the prior docstring that this cost was "negligible at the
// steady-state PN→LID migration rate" was contradicted by that profile;
// the O(K) implementation makes it genuinely negligible.
func (c *CachedSessionStore) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	// ride-button-slow-send fix (D1): MigratePNToLID is called per recipient device
	// on EVERY send, but the inner DB migration is gated once-per-process
	// (migratedPNSessionsCache). The V1 flush-blocked wait below was thus paid on
	// every repeat call for a NO-OP migration, serializing the send behind the
	// session flusher's Postgres write (~1s/device, confirmed by block profile +
	// SLOW_SEND setup_migrate_ms). Once migrated there are no deletes to order
	// against the flusher, so skip any flush coordination. The cache sweep below
	// still runs unconditionally (cheap, idempotent), so cache-coherence behavior
	// is unchanged.
	alreadyMigrated := false
	if gater, ok := c.inner.(pnMigrationGater); ok {
		alreadyMigrated = gater.IsPNMigrated(pn.SignalAddressUser())
	}
	if !alreadyMigrated {
		// D-01/D-02 (Phase 47.3): three-branch gate for the first-send no-op-skip.
		//
		// Flush coordination (a migrate work item dispatched to the single writer)
		// is only needed when there is actual PN migration work to order against
		// the flusher. Skip it when BOTH checks are negative — "no-op path" (cheap:
		// one dirty-set scan + one index-narrowed LIKE query on the first send per
		// recipient, then IsPNMigrated takes over).
		//
		//   Branch 1 (full ordered path): hasDirty || hasDB is true — there are PN
		//     sessions in the dirty-set or the DB. Dispatch a workMigratePNPrefix
		//     work item to the single writer (D2 CR-04: flush dirty prefix first,
		//     then migrate, FIFO-ordered inside the writer).
		//
		//   Branch 2 (no-op path): both checks are false — nothing to migrate.
		//     Call inner.MigratePNToLID UNCONDITIONALLY (D-01: sets the
		//     migratedPNSessionsCache gate so every subsequent send for this pn
		//     short-circuits at IsPNMigrated before reaching this block).
		//     Skip the work-item dispatch — safe-by-construction for CR-01 (nothing
		//     to delete means no delete-resurrection risk).
		//
		//   Branch 3 (nil-flusher fallback): no SessionFlusher wired — the inner
		//     store is used directly with no write-back buffering; call inner directly
		//     with no flush coordination.
		//
		// D-05: check-to-send race accepted as benign. A PN row could be Enqueued
		// between HasDirtyPrefix returning false and inner.MigratePNToLID running,
		// but the no-op path neither deletes nor changes reads, so CR-01 and
		// read-gap/479 cannot be violated. D2's single-writer eliminates this class.
		pnPrefix := pn.SignalAddressUser() + ":"

		hasDirty := c.flusher != nil && c.flusher.HasDirtyPrefix(pnPrefix)

		// F10 (Phase 55): skip ExistsPNSession when hasDirty is true. If the
		// dirty-set already has PN entries for this recipient, Branch 1 is taken
		// regardless of the DB state — making the round-trip redundant. In a
		// fan-out of N recipients that all have dirty sessions, this reduces N DB
		// queries to 0. ExistsPNSession is still called when hasDirty=false (to
		// distinguish Branch 1 from Branch 2), and only when a flusher is wired
		// (Branch 3 ignores hasDB entirely).
		// Uses the pnExistenceChecker interface instead of a *SQLStore type
		// assertion so test doubles can track call counts.
		var hasDB bool
		if !hasDirty && c.flusher != nil {
			if checker, ok := c.inner.(pnExistenceChecker); ok {
				var err error
				hasDB, err = checker.ExistsPNSession(ctx, pnPrefix)
				if err != nil {
					return fmt.Errorf("MigratePNToLID existence check: %w", err)
				}
			}
		}

		if c.flusher != nil && (hasDirty || hasDB) {
			// Branch 1: full ordered path — flush dirty PN entries before migration.
			// Phase 47.3-06 D2 CR-04: dispatch a workMigratePNPrefix work item to
			// the single writer goroutine, which (inside the writer, FIFO-ordered
			// with flushes and deletes) (a) flushes PN-prefixed dirty entries to the
			// DB and removes them BEFORE the inner migration so the migration's
			// SELECT copies the freshest ratchet state to the LID key (a
			// dirty-but-unflushed PN session would otherwise miss the migration —
			// stale LID row), and (b) ensures neither an in-flight flush snapshot
			// nor a later drain can re-insert a zombie pn row after the migration
			// deletes the pn rows. On pre-migrate-flush failure the migration is
			// aborted (fail closed); the inner once-per-process gate is not
			// consumed, so a retry can still heal. flusher.MigratePNToLID blocks on
			// the work item's done channel. (The pnPrefix computed above is also the
			// flusher's work-item prefix — derived identically from
			// pn.SignalAddressUser()+":".)
			if err := c.flusher.MigratePNToLID(ctx, pn, lid); err != nil {
				return err
			}
		} else if c.flusher != nil {
			// Branch 2: no-op path — both hasDirty and hasDB are false.
			// Call inner directly (sets once-per-process gate); skip the work-item dispatch.
			if err := c.inner.MigratePNToLID(ctx, pn, lid); err != nil {
				return err
			}
		} else {
			// Branch 3: nil-flusher fallback — inner is used write-through; no
			// flush coordination needed.
			if err := c.inner.MigratePNToLID(ctx, pn, lid); err != nil {
				return err
			}
		}
	}
	// Phase 24: single O(K) lookup instead of the former O(N) two-pass
	// cache.Keys() walk (13.43% driver CPU per 2026-05-28 60s pprof).
	// SnapshotKeys acquires a read lock, copies the bucket, and releases
	// before returning — callers iterate without holding any index lock
	// (lock-ordering discipline prevents deadlock with EvictCleanup).
	victims := c.secondaryIndex.SnapshotKeys(c.jid, pn.SignalAddressUser())
	for _, k := range victims {
		// kavtov-fork: Phase 17.5.2 - pre-increment per iteration in MigratePNToLID
		atomic.AddUint64(c.explicitRemoves, 1)
		c.cache.Remove(k)
		// Each cache.Remove fires the eviction callback (cache_wiring.go)
		// which calls EvictCleanup on the index — no separate index.Remove.
	}
	// Defensive sweep: idempotent guard against the race where capacity
	// eviction removed some keys between SnapshotKeys and the Remove loop.
	c.secondaryIndex.DropKey(c.jid, pn.SignalAddressUser())
	return nil
}

// ---------------------------------------------------------------------------
// Narrow interfaces used by MigratePNToLID
// ---------------------------------------------------------------------------

// pnMigrationGater is satisfied by *SQLStore (and test doubles). Reports
// whether the once-per-process PN→LID gate has already fired for a given
// pnSignal WITHOUT mutating it. Checked at the top of MigratePNToLID to
// short-circuit the expensive flush/migrate path on subsequent sends to the
// same recipient.
type pnMigrationGater interface {
	IsPNMigrated(pnSignal string) bool
}

// pnExistenceChecker is satisfied by *SQLStore (and test doubles). Checks
// whether any session row exists for a PN-form prefix. Used by
// MigratePNToLID to distinguish Branch 1 (sessions exist → flush-then-
// migrate) from Branch 2 (no sessions → no-op call to set the gate).
// Only called when hasDirty is false (F10 Phase 55: when the dirty-set
// already has PN entries, Branch 1 is taken regardless of the DB state,
// making ExistsPNSession redundant).
type pnExistenceChecker interface {
	ExistsPNSession(ctx context.Context, pnPrefix string) (bool, error)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// copyBytes returns a heap-private duplicate of b, or nil if b is nil. Used
// to break the alias between caller-stack / inner-store slices and the
// cache's internal storage (Phase 17.5 FIX CR-06). Shared with the sender-
// key wrapper in the same package.
func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Copyright (c) 2026 Kavtov Platform (Phase 17.5)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"context"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// CachedSessionStore wraps an inner store.SessionStore with a process-shared
// *lru.Cache[string, []byte]. It is a strict write-through cache: every
// mutating method calls the inner store FIRST and only updates the cache on
// success. There is no write-back buffer, no deferred-write timer, no
// coalesce window, and no flush gate — those constructs (introduced by
// Plans 17.5-02 and 17.5-04) were rewritten out by the Phase 17.5 FIX
// cycle after review found six BLOCKER-class data-loss paths rooted in the
// timer-vs-Delete race and the "clear state before inner write" inversion.
//
// Correctness guarantees:
//
//   - PutSession returns only after inner.PutSession returns nil. By the
//     time PutSession returns, the row is durable in the inner store; there
//     is no "pending dirty state" the wrapper has to flush before acking.
//     This trivially satisfies the D-CACHE-03 "ack-after-flush" invariant
//     that the prior write-back design tried to enforce via a separate gate.
//
//   - DeleteSession / DeleteAllSessions / MigratePNToLID call inner first,
//     then update the cache to mirror the inner state. A failed inner call
//     leaves the cache untouched, so the cache and inner can never diverge
//     after a failed mutation.
//
//   - GetSession / GetManySessions / HasSession return cached values when
//     the cache is warm; a miss fans through to inner and (on success)
//     populates the cache with a heap-private copy.
//
// Copy discipline (Phase 17.5 FIX CR-06):
//
//   - PutSession stores a copy of the caller's slice in the cache. The
//     caller is free to reuse / mutate its buffer after PutSession returns.
//   - GetSession returns a copy of the cached slice. The caller is free to
//     mutate the returned slice without corrupting the cache.
//   - GetManySessions returns a map whose values are copies of the cached
//     slices (mirroring the per-key Get behaviour).
//   - Nil values are NEVER cached (Pitfall 5). An inner store that returns
//     (nil, nil) for an absent address must hit inner on every Get; caching
//     nil would silently mask a later PutSession for the same address.
//
// Bulk-mutation key scoping (Phase 24: O(K) secondary-index lookup):
//
//   - DeleteAllSessions(phone): looks up matching entries in the secondary
//     index for (jid, phone) and removes them via O(K) SnapshotKeys lookup
//     (matching the SQL `their_id >= phone||':' AND their_id < phone||';'`
//     predicate from deleteAllSessionsQuery in store.go). Other wrappers'
//     entries in the shared LRU are left untouched — the index is (jid,
//     phone)-scoped so cross-wrapper isolation is preserved by construction.
//
//   - MigratePNToLID(pn, lid): inner.MigratePNToLID FIRST; on success,
//     looks up matching entries via O(K) SnapshotKeys on (jid,
//     pn.SignalAddressUser()) and EVICTS them. The inner SQL row has already
//     been migrated to the LID address; reads under the new LID address will
//     cache-miss, fetch from inner, and repopulate the cache with the LID key
//     on first access. Cache keys store the libsignal-format address
//     (`<SignalAddressUser>:<device>`, e.g. `"12345:0"`), NOT the full JID
//     form (`"12345@s.whatsapp.net"`).
//
// Single-writer assumption: every mutation to whatsmeow_sessions for this
// device's JID MUST go through this wrapper. Out-of-band mutations to the
// underlying SQL table cannot be observed by the cache and will produce
// stale reads until the cache entry naturally evicts.
// (WR-04 closure: re-audited 17.5.1-02, no code change needed.)
type CachedSessionStore struct {
	inner store.SessionStore
	jid   string
	cache *lru.Cache[string, []byte]

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

func (c *CachedSessionStore) key(address string) string {
	return c.jid + "|" + address
}

// jidPrefix returns the per-wrapper key prefix used to scope cache walks to
// this device's entries.
func (c *CachedSessionStore) jidPrefix() string {
	return c.jid + "|"
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
	fetched, err := c.inner.GetManySessions(ctx, misses)
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
// store.SessionStore — write methods (strict write-through)
// ---------------------------------------------------------------------------

// PutSession writes synchronously through to the inner store, then mirrors
// the value into the cache on success. Caller may reuse the session buffer
// after this call returns; the cache stores its own copy.
func (c *CachedSessionStore) PutSession(ctx context.Context, address string, session []byte) error {
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

// PutManySessions writes through to inner.PutManySessions and then populates
// the cache with copies of every value on success.
func (c *CachedSessionStore) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
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

// DeleteSession writes through to inner and (on success) removes the cache
// entry for this address.
func (c *CachedSessionStore) DeleteSession(ctx context.Context, address string) error {
	if err := c.inner.DeleteSession(ctx, address); err != nil {
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
	if err := c.inner.DeleteAllSessions(ctx, phone); err != nil {
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

// MigratePNToLID writes through to inner FIRST (Phase 17.5 FIX CR-04
// regression: the prior implementation dropped pending writes and purged
// caches BEFORE calling inner, leaving the migrated row at a stale value).
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
	if err := c.inner.MigratePNToLID(ctx, pn, lid); err != nil {
		return err
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

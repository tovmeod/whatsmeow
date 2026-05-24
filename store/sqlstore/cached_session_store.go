// Copyright (c) 2026 Kavtov Platform (Phase 17.5)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"context"
	"strings"
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
// Bulk-mutation key scoping:
//
//   - DeleteAllSessions(phone): walks cache.Keys() and removes only entries
//     whose key starts with `jid + "|" + phone + ":"` (matching the SQL
//     `their_id >= phone||':' AND their_id < phone||';'` predicate from
//     deleteAllSessionsQuery in store.go). Other wrappers' entries in the
//     same shared LRU are left untouched because cache keys are JID-scoped.
//
//   - MigratePNToLID(pn, lid): inner.MigratePNToLID FIRST; on success, walks
//     cache.Keys() and EVICTS any entry whose libsignal address-user equals
//     `pn.SignalAddressUser()`. The inner SQL row has already been migrated
//     to the LID address; reads under the new LID address will cache-miss,
//     fetch from inner, and repopulate the cache with the LID key on first
//     access. This avoids the complexity of in-place key rewrites (and the
//     ambiguous precedence vs pre-existing LID entries that those would
//     introduce) and reaches the same eventual-consistency point on the
//     next read. Cache keys store the libsignal-format address
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
}

var _ store.SessionStore = (*CachedSessionStore)(nil)

// NewCachedSessionStore constructs a wrapper over inner with the given JID
// scope and shared LRU. explicitRemoves is a pointer to the Container-level
// SessionExplicitRemoves counter (Phase 17.5.2).
func NewCachedSessionStore(inner store.SessionStore, jid string, cache *lru.Cache[string, []byte], explicitRemoves *uint64) *CachedSessionStore {
	return &CachedSessionStore{
		inner:           inner,
		jid:             jid,
		cache:           cache,
		explicitRemoves: explicitRemoves,
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
func (c *CachedSessionStore) DeleteAllSessions(ctx context.Context, phone string) error {
	if err := c.inner.DeleteAllSessions(ctx, phone); err != nil {
		return err
	}
	jidPfx := c.jidPrefix()
	addrPfx := phone + ":"
	for _, k := range c.cache.Keys() {
		if !strings.HasPrefix(k, jidPfx) {
			continue
		}
		// k has shape "<jid>|<address>"; the address part starts at
		// len(jidPfx). Match the SQL predicate exactly: address starts
		// with phone + ":".
		if strings.HasPrefix(k[len(jidPfx):], addrPfx) {
			// kavtov-fork: Phase 17.5.2 - pre-increment per iteration (loop calls Remove N times)
			atomic.AddUint64(c.explicitRemoves, 1)
			c.cache.Remove(k)
		}
	}
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
// the first post-migration decrypt — negligible at the steady-state PN
// -> LID migration rate.
func (c *CachedSessionStore) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	if err := c.inner.MigratePNToLID(ctx, pn, lid); err != nil {
		return err
	}
	jidPfx := c.jidPrefix()
	pnPfx := pn.SignalAddressUser() + ":"

	// Two-pass walk so cache mutation during iteration is well-defined.
	// Pass 1: collect victim keys under this wrapper's JID prefix whose
	// libsignal-address user matches pn.SignalAddressUser().
	var victims []string
	for _, k := range c.cache.Keys() {
		if !strings.HasPrefix(k, jidPfx) {
			continue
		}
		// k has shape "<jid>|<address>" where <address> is
		// "<SignalAddressUser>:<device>". Match the SQL predicate exactly:
		// address starts with pn.SignalAddressUser() + ":".
		if strings.HasPrefix(k[len(jidPfx):], pnPfx) {
			victims = append(victims, k)
		}
	}
	// Pass 2: evict. Reads against the new LID address will cache-miss
	// and repopulate from inner on first access.
	for _, k := range victims {
		// kavtov-fork: Phase 17.5.2 - pre-increment per iteration in MigratePNToLID
		atomic.AddUint64(c.explicitRemoves, 1)
		c.cache.Remove(k)
	}
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

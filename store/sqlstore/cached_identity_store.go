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
)

// CachedIdentityStore wraps an inner store.IdentityStore with a process-shared
// *lru.Cache[string, *[32]byte]. The cache value uses *[32]byte so a nil
// pointer encodes "known absent" (TOFU pass-through, mirroring
// SQLStore.IsTrustedIdentity ErrNoRows handling at store.go:97-109) while a
// non-nil pointer holds the cached identity bytes.
//
// PutIdentity applies a value-equal write-skip: when the incoming key bytes
// equal the cached bytes, the wrapper returns nil WITHOUT delegating to inner
// and increments dedupedWrites. This closes RESEARCH Pitfall 3 — libsignal
// defensively calls SaveIdentity after every IsTrustedIdentity, producing the
// 37.4M:37.4M SELECT:UPSERT 1:1 ratio observed in pg_stat_statements; with
// the dedup, ~99% of those UPSERTs are eliminated in steady state.
//
// IsTrustedIdentity populates the cache on miss via a runtime type-assertion
// against `interface{ getIdentityBytes(context.Context, string) (*[32]byte, error) }`.
// The concrete *SQLStore satisfies this assertion (see the private
// getIdentityBytes method on SQLStore in this package). The
// fakeIdentityStore test-helper also satisfies it. If a future test
// injects a non-conforming fake, the wrapper falls back to
// inner.IsTrustedIdentity without caching — defensive, no log spam.
//
// Single-goroutine-per-account assumption (WR-05 closure):
// The kavtov-driver-go deployment runs one whatsmeow.Client per phone,
// and all signal-store operations for that phone execute on that
// Client's read-loop goroutine. Different phones map to different
// *store.Device and thus different CachedIdentityStore instances; the
// shared process-LRU is keyed by `jid + "|" + address`, so per-device
// key spaces never overlap. For any single cache key, at most one
// goroutine ever calls IsTrustedIdentity / PutIdentity / DeleteIdentity.
// This closes the WR-05 populate-on-miss race (two concurrent
// IsTrustedIdentity calls for the same address both reaching c.cache.Add
// before either's PutIdentity) — that interleaving cannot occur under
// the single-writer invariant.
type CachedIdentityStore struct {
	inner store.IdentityStore
	jid   string
	cache *lru.Cache[string, *[32]byte]

	hits, misses, dedupedWrites uint64

	// explicitRemoves points at the Container-level IdentityExplicitRemoves
	// counter (signalCaches.IdentityExplicitRemoves). Incremented at call
	// sites of Remove() and Purge() before delegating to the LRU (Phase 17.5.2).
	explicitRemoves *uint64
}

var _ store.IdentityStore = (*CachedIdentityStore)(nil)

// identityReader is the unexported populate-on-miss seam. The concrete
// *SQLStore (in this package) and the in-package fakeIdentityStore both
// satisfy it. The cache uses a runtime type-assertion against this
// interface so the IdentityStore interface itself stays unchanged.
type identityReader interface {
	getIdentityBytes(ctx context.Context, address string) (*[32]byte, error)
}

// NewCachedIdentityStore constructs a wrapper over inner. jid is the
// device JID (used as cache-key prefix). cache is a shared LRU
// constructed by the Container. explicitRemoves is a pointer to the
// Container-level IdentityExplicitRemoves counter (Phase 17.5.2).
func NewCachedIdentityStore(inner store.IdentityStore, jid string, cache *lru.Cache[string, *[32]byte], explicitRemoves *uint64) *CachedIdentityStore {
	return &CachedIdentityStore{
		inner:           inner,
		jid:             jid,
		cache:           cache,
		explicitRemoves: explicitRemoves,
	}
}

func (c *CachedIdentityStore) key(address string) string {
	return c.jid + "|" + address
}

// Stats returns (hits, misses, dedupedWrites) for test observability and
// for the Container's emitMetricsLoop to surface deduped UPSERT counts —
// the headline closure of the libsignal "SaveIdentity after every
// IsTrustedIdentity" 1:1 SELECT:UPSERT pattern (~99% of those UPSERTs
// eliminated in steady state by the value-equal write-skip in
// PutIdentity below).
func (c *CachedIdentityStore) Stats() (hits, misses, dedupedWrites uint64) {
	return atomic.LoadUint64(&c.hits),
		atomic.LoadUint64(&c.misses),
		atomic.LoadUint64(&c.dedupedWrites)
}

// ---------------------------------------------------------------------------
// store.IdentityStore — read
// ---------------------------------------------------------------------------

func (c *CachedIdentityStore) IsTrustedIdentity(ctx context.Context, address string, key [32]byte) (bool, error) {
	k := c.key(address)
	if v, ok := c.cache.Get(k); ok {
		atomic.AddUint64(&c.hits, 1)
		if v == nil {
			// Cached absent sentinel — mirrors SQLStore.IsTrustedIdentity
			// ErrNoRows handling: trust on first sight.
			return true, nil
		}
		return *v == key, nil
	}
	atomic.AddUint64(&c.misses, 1)

	// Populate-on-miss via the private identityReader seam. If inner does not
	// implement it (only possible if a future test injects a non-conforming
	// fake), fall back to inner.IsTrustedIdentity without caching the miss.
	reader, ok := c.inner.(identityReader)
	if !ok {
		return c.inner.IsTrustedIdentity(ctx, address, key)
	}
	bytes, err := reader.getIdentityBytes(ctx, address)
	if err != nil {
		return false, err
	}
	// bytes == nil represents "known absent"; cache it so subsequent calls
	// for the same address are also served from cache.
	c.cache.Add(k, bytes)
	if bytes == nil {
		return true, nil
	}
	return *bytes == key, nil
}

// ---------------------------------------------------------------------------
// store.IdentityStore — write
// ---------------------------------------------------------------------------

// PutIdentity applies the value-equal write-skip. The cache holds a copy of
// the most recently observed key; if the incoming key matches byte-for-byte,
// the inner UPSERT is skipped (dedupedWrites += 1). Otherwise the inner
// store is updated and the cache reflects the new value.
//
// Aliasing: the cache stores a heap copy of key (keyCopy local + &keyCopy)
// so caller-stack mutation after the call cannot corrupt cache entries.
func (c *CachedIdentityStore) PutIdentity(ctx context.Context, address string, key [32]byte) error {
	k := c.key(address)
	if cached, ok := c.cache.Get(k); ok && cached != nil && *cached == key {
		atomic.AddUint64(&c.dedupedWrites, 1)
		return nil
	}
	if err := c.inner.PutIdentity(ctx, address, key); err != nil {
		return err
	}
	keyCopy := key
	c.cache.Add(k, &keyCopy)
	return nil
}

func (c *CachedIdentityStore) DeleteIdentity(ctx context.Context, address string) error {
	if err := c.inner.DeleteIdentity(ctx, address); err != nil {
		return err
	}
	// kavtov-fork: Phase 17.5.2 - pre-increment explicit-remove counter (see Plan 17.5.2-03)
	atomic.AddUint64(c.explicitRemoves, 1)
	c.cache.Remove(c.key(address))
	return nil
}

func (c *CachedIdentityStore) DeleteAllIdentities(ctx context.Context, phone string) error {
	if err := c.inner.DeleteAllIdentities(ctx, phone); err != nil {
		return err
	}
	// kavtov-fork: Phase 17.5.3 - prefix-scan removes only this wrapper's
	// entries for the target remote phone. Previously this called the
	// LRU's bulk Purge which wiped the entire process-shared cache across
	// all device wrappers, causing ~26 explicit_removes/sec churn and
	// undoing the Phase 17.5 cache benefit for unrelated devices. See
	// 17.5.3-RCA-IDENTITIES-CACHE.md for evidence (identities.len swinging
	// 30..1617, capacity_evictions=0). The new scope matches the SQL
	// predicate `our_jid=$1 AND their_id LIKE $phone||':' ...` exactly:
	// libsignal addresses are `<phone>:<device>`, cache keys are
	// `<c.jid>|<address>`, so the composite prefix is `<c.jid>|<phone>:`.
	prefix := c.jid + "|" + phone + ":"
	for _, k := range c.cache.Keys() {
		if strings.HasPrefix(k, prefix) {
			// kavtov-fork: Phase 17.5.3 - pre-increment per iteration (matches
			// cached_session_store.go DeleteAllSessions sibling pattern)
			atomic.AddUint64(c.explicitRemoves, 1)
			c.cache.Remove(k)
		}
	}
	return nil
}

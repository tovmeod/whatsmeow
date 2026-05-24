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
)

// CachedSenderKeyStore wraps an inner store.SenderKeyStore with a
// process-shared *lru.Cache[string, []byte]. Cache key is the three-element
// composite jid + "|" + group + "|" + user (RESEARCH Finding 7) — group and
// user form the natural identity for a sender-key record (whatsmeow_sender_keys
// is keyed (our_jid, chat_id, sender_id) in PG).
//
// Like CachedSessionStore (post-Phase-17.5-FIX), this wrapper is a strict
// write-through cache: every PutSenderKey calls inner FIRST and only
// updates the cache on success. There is no value-equal write-skip — sender
// keys mutate naturally as the group ratchet advances, so equal-value
// writes would be rare and the comparison overhead on every PutSenderKey
// is not worth it.
//
// Copy discipline (Phase 17.5 FIX CR-06): GetSenderKey returns a copy of
// the cached slice; PutSenderKey stores a copy of the caller's slice.
// Neither side aliases the other's buffer.
type CachedSenderKeyStore struct {
	inner store.SenderKeyStore
	jid   string
	cache *lru.Cache[string, []byte]

	hits, misses uint64
}

var _ store.SenderKeyStore = (*CachedSenderKeyStore)(nil)

// NewCachedSenderKeyStore constructs a wrapper over inner. jid is the device
// JID (used as cache-key prefix). cache is a shared LRU constructed by the
// Container.
func NewCachedSenderKeyStore(inner store.SenderKeyStore, jid string, cache *lru.Cache[string, []byte]) *CachedSenderKeyStore {
	return &CachedSenderKeyStore{
		inner: inner,
		jid:   jid,
		cache: cache,
	}
}

func (c *CachedSenderKeyStore) key(group, user string) string {
	return c.jid + "|" + group + "|" + user
}

// Stats returns (hits, misses) for test observability and for the
// Container's emitMetricsLoop.
func (c *CachedSenderKeyStore) Stats() (hits, misses uint64) {
	return atomic.LoadUint64(&c.hits),
		atomic.LoadUint64(&c.misses)
}

// Purge clears the entire cache. The SenderKeyStore interface has no
// DeleteAll* method; Purge is exposed here for tests that want to reset
// state without recreating the wrapper.
func (c *CachedSenderKeyStore) Purge() {
	c.cache.Purge()
}

// ---------------------------------------------------------------------------
// store.SenderKeyStore
// ---------------------------------------------------------------------------

func (c *CachedSenderKeyStore) GetSenderKey(ctx context.Context, group, user string) ([]byte, error) {
	k := c.key(group, user)
	if v, ok := c.cache.Get(k); ok {
		atomic.AddUint64(&c.hits, 1)
		// Return a copy so the caller cannot mutate the cached slice
		// (Phase 17.5 FIX CR-06: prior code returned the internal slice).
		return copyBytes(v), nil
	}
	atomic.AddUint64(&c.misses, 1)
	v, err := c.inner.GetSenderKey(ctx, group, user)
	if err == nil && v != nil {
		// Do NOT cache nil (Pitfall 5 from sessions wrapper) — a future
		// PutSenderKey would not invalidate a nil entry and subsequent
		// Gets would erroneously return nil. inner.GetSenderKey already
		// returns a fresh heap slice, so the cached value is unaliased
		// from the caller's perspective; the returned slice IS the same
		// slice we cache, but copying once more here would only matter if
		// the caller mutates it before the next Get — copy for safety.
		stored := copyBytes(v)
		c.cache.Add(k, stored)
		return copyBytes(stored), err
	}
	return v, err
}

func (c *CachedSenderKeyStore) PutSenderKey(ctx context.Context, group, user string, session []byte) error {
	// Write-through: inner first; only update cache on success.
	if err := c.inner.PutSenderKey(ctx, group, user, session); err != nil {
		return err
	}
	// Copy before stash so caller's buffer reuse cannot corrupt the cache
	// (Phase 17.5 FIX CR-06: prior code aliased the caller's slice).
	c.cache.Add(c.key(group, user), copyBytes(session))
	return nil
}

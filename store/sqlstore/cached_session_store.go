// Copyright (c) 2026 Kavtov Platform (Phase 17.5)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// Burst-coalesce thresholds (D-CACHE-04). N=3 writes for the same key within
// M=50ms triggers deferred flush for the Nth and subsequent within-window
// writes. Values are research-inferred; tune post-deploy with the metrics
// surfaced by Stats().
const (
	coalesceMinBurst = 3
	coalesceWindow   = 50 * time.Millisecond
)

// dirtyEntry tracks a key's coalesce state. A non-nil pendingValue means
// "the latest write for this key has NOT been flushed to the inner store".
// burstFirstAt is the timestamp of the first write of the current burst
// window. burstCount counts writes seen within that window.
type dirtyEntry struct {
	mu            sync.Mutex
	burstFirstAt  time.Time
	burstCount    int
	pendingValue  []byte
	pendingActive bool
	timer         *time.Timer
}

// CachedSessionStore wraps an inner store.SessionStore with a process-shared
// *lru.Cache and a per-key write-coalesce buffer. It serves cache hits in
// memory, fans miss reads through to the inner store, and (after the burst
// threshold trips) defers writes for up to coalesceWindow before flushing
// the FINAL value through to inner.
//
// FlushIfDirty drains a single key's pending write synchronously; the SEND
// path uses it as the "ack-after-flush" gate (D-CACHE-03).
//
// The *Container backref is present from Plan-02-day-1 so Plan 04 EDIT 7's
// two-line flip (c.cache.Purge() -> c.container.PurgeAllSignalCaches()) is
// the only future mutation of this file.
type CachedSessionStore struct {
	inner     store.SessionStore
	jid       string
	cache     *lru.Cache[string, []byte]
	container *Container

	dirtyLock sync.Mutex
	dirty     map[string]*dirtyEntry

	hits, misses, evictions, coalescedWrites, flushedWrites uint64
}

var _ store.SessionStore = (*CachedSessionStore)(nil)

// NewCachedSessionStore constructs a wrapper over inner. The 4-arg signature
// (inner, jid, cache, container) is locked from Plan-02-day-1 so Plan 04's
// EDIT 5 wire-up requires no constructor change. container must be non-nil
// (Plan 04 EDIT 7 dereferences it).
func NewCachedSessionStore(inner store.SessionStore, jid string, cache *lru.Cache[string, []byte], container *Container) *CachedSessionStore {
	return &CachedSessionStore{
		inner:     inner,
		jid:       jid,
		cache:     cache,
		container: container,
		dirty:     make(map[string]*dirtyEntry),
	}
}

func (c *CachedSessionStore) key(address string) string {
	return c.jid + "|" + address
}

// Stats returns the current values of the per-wrapper atomic counters in a
// fixed (hits, misses, evictions, coalesced, flushed) order. Used by Plan
// 04's emitMetricsLoop and by unit tests.
func (c *CachedSessionStore) Stats() (hits, misses, evictions, coalesced, flushed uint64) {
	return atomic.LoadUint64(&c.hits),
		atomic.LoadUint64(&c.misses),
		atomic.LoadUint64(&c.evictions),
		atomic.LoadUint64(&c.coalescedWrites),
		atomic.LoadUint64(&c.flushedWrites)
}

// ---------------------------------------------------------------------------
// store.SessionStore — read methods
// ---------------------------------------------------------------------------

func (c *CachedSessionStore) GetSession(ctx context.Context, address string) ([]byte, error) {
	k := c.key(address)
	if v, ok := c.cache.Get(k); ok {
		atomic.AddUint64(&c.hits, 1)
		return v, nil
	}
	atomic.AddUint64(&c.misses, 1)
	v, err := c.inner.GetSession(ctx, address)
	if err == nil && v != nil {
		c.cache.Add(k, v)
	}
	return v, err
}

func (c *CachedSessionStore) HasSession(ctx context.Context, address string) (bool, error) {
	if _, ok := c.cache.Get(c.key(address)); ok {
		atomic.AddUint64(&c.hits, 1)
		return true, nil
	}
	atomic.AddUint64(&c.misses, 1)
	return c.inner.HasSession(ctx, address)
}

func (c *CachedSessionStore) GetManySessions(ctx context.Context, addresses []string) (map[string][]byte, error) {
	result := make(map[string][]byte, len(addresses))
	misses := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		if v, ok := c.cache.Get(c.key(addr)); ok {
			atomic.AddUint64(&c.hits, 1)
			result[addr] = v
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
		result[addr] = v
		if v != nil {
			c.cache.Add(c.key(addr), v)
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// store.SessionStore — write methods (with burst-coalesce)
// ---------------------------------------------------------------------------

// PutSession applies the LOCKED coalesce model: the first (N-1) writes per
// key within coalesceWindow go straight through to inner ("write-through"
// regime). Once the Nth-in-window write arrives, that write — and every
// subsequent write within the same window — is deferred. A time.AfterFunc
// timer drains the deferred write coalesceWindow after the first dirty
// write to bound crash exposure to <=coalesceWindow regardless of FlushIfDirty.
func (c *CachedSessionStore) PutSession(ctx context.Context, address string, session []byte) error {
	k := c.key(address)
	entry := c.getOrCreateDirty(k)
	entry.mu.Lock()
	now := time.Now()
	if entry.burstCount == 0 || now.Sub(entry.burstFirstAt) > coalesceWindow {
		// New window starts; the old window (if any) is already flushed.
		entry.burstFirstAt = now
		entry.burstCount = 0
	}
	entry.burstCount++

	if entry.burstCount < coalesceMinBurst {
		// Write-through regime.
		entry.mu.Unlock()
		if err := c.inner.PutSession(ctx, address, session); err != nil {
			return err
		}
		c.cache.Add(k, copyBytes(session))
		return nil
	}

	// Defer: stash the latest value in cache + dirty buffer, arm the drain
	// timer if not already running.
	stored := copyBytes(session)
	entry.pendingValue = stored
	if !entry.pendingActive {
		entry.pendingActive = true
		atomic.AddUint64(&c.coalescedWrites, 1)
		drainAt := entry.burstFirstAt.Add(coalesceWindow)
		delay := time.Until(drainAt)
		if delay <= 0 {
			delay = time.Microsecond
		}
		entry.timer = time.AfterFunc(delay, func() {
			// Use background context for the autonomous timer drain; the
			// originating request's ctx may already be cancelled.
			_ = c.flushDirty(context.Background(), address, k)
		})
	}
	c.cache.Add(k, stored)
	entry.mu.Unlock()
	return nil
}

func (c *CachedSessionStore) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
	if err := c.inner.PutManySessions(ctx, sessions); err != nil {
		return err
	}
	for addr, v := range sessions {
		c.cache.Add(c.key(addr), copyBytes(v))
	}
	return nil
}

func (c *CachedSessionStore) DeleteSession(ctx context.Context, address string) error {
	if err := c.inner.DeleteSession(ctx, address); err != nil {
		return err
	}
	c.cache.Remove(c.key(address))
	c.dropDirty(c.key(address))
	return nil
}

func (c *CachedSessionStore) DeleteAllSessions(ctx context.Context, phone string) error {
	if err := c.inner.DeleteAllSessions(ctx, phone); err != nil {
		return err
	}
	// TODO(plan-04): switch to c.container.PurgeAllSignalCaches()
	c.cache.Purge()
	c.dropAllDirty()
	return nil
}

func (c *CachedSessionStore) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	// TODO(plan-04): switch to c.container.PurgeAllSignalCaches()
	c.cache.Purge()
	c.dropAllDirty()
	return c.inner.MigratePNToLID(ctx, pn, lid)
}

// ---------------------------------------------------------------------------
// FlushIfDirty — D-CACHE-03 "ack-after-flush" gate. Called from message.go
// via anonymous-interface type-assert (Plan 04 EDIT 6); the SessionStore
// interface is NOT widened.
// ---------------------------------------------------------------------------

func (c *CachedSessionStore) FlushIfDirty(ctx context.Context, address string) error {
	return c.flushDirty(ctx, address, c.key(address))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (c *CachedSessionStore) getOrCreateDirty(k string) *dirtyEntry {
	c.dirtyLock.Lock()
	defer c.dirtyLock.Unlock()
	entry, ok := c.dirty[k]
	if !ok {
		entry = &dirtyEntry{}
		c.dirty[k] = entry
	}
	return entry
}

func (c *CachedSessionStore) lookupDirty(k string) *dirtyEntry {
	c.dirtyLock.Lock()
	defer c.dirtyLock.Unlock()
	return c.dirty[k]
}

func (c *CachedSessionStore) dropDirty(k string) {
	c.dirtyLock.Lock()
	entry := c.dirty[k]
	delete(c.dirty, k)
	c.dirtyLock.Unlock()
	if entry != nil {
		entry.mu.Lock()
		if entry.timer != nil {
			entry.timer.Stop()
			entry.timer = nil
		}
		entry.pendingActive = false
		entry.pendingValue = nil
		entry.mu.Unlock()
	}
}

func (c *CachedSessionStore) dropAllDirty() {
	c.dirtyLock.Lock()
	entries := make([]*dirtyEntry, 0, len(c.dirty))
	for _, e := range c.dirty {
		entries = append(entries, e)
	}
	c.dirty = make(map[string]*dirtyEntry)
	c.dirtyLock.Unlock()
	for _, e := range entries {
		e.mu.Lock()
		if e.timer != nil {
			e.timer.Stop()
			e.timer = nil
		}
		e.pendingActive = false
		e.pendingValue = nil
		e.mu.Unlock()
	}
}

// flushDirty drains any deferred write for the key. address is the raw
// address (what inner.PutSession expects); k is the cache composite key.
func (c *CachedSessionStore) flushDirty(ctx context.Context, address, k string) error {
	entry := c.lookupDirty(k)
	if entry == nil {
		return nil
	}
	entry.mu.Lock()
	if !entry.pendingActive {
		entry.mu.Unlock()
		return nil
	}
	value := entry.pendingValue
	entry.pendingValue = nil
	entry.pendingActive = false
	if entry.timer != nil {
		entry.timer.Stop()
		entry.timer = nil
	}
	// Reset burst counter so the next write starts a fresh window. Without
	// this, a Flush followed by a single write inside the original window
	// would still trip the coalesce regime even though the buffer is empty.
	entry.burstCount = 0
	entry.mu.Unlock()
	if err := c.inner.PutSession(ctx, address, value); err != nil {
		return err
	}
	atomic.AddUint64(&c.flushedWrites, 1)
	return nil
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Copyright (c) 2026 Kavtov Platform (Phase 17.5 / Phase 17.7)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"context"
	"encoding/json"
	"strings"
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
// Phase 17.7-03: Write-back mode. PutSenderKey no longer calls the inner store
// synchronously. Instead it marks the entry dirty in the SenderKeyFlusher and
// updates the read cache. The flusher drains to DB asynchronously via
// PutManySenderKeys. SKDM dedup is implicit: an arriving SKDM iteration that
// does not advance the cached highIter is skipped (no dirty entry created or
// updated).
//
// Copy discipline (Phase 17.5 FIX CR-06): GetSenderKey returns a copy of
// the cached slice; PutSenderKey stores a copy of the caller's slice.
// Neither side aliases the other's buffer.
type CachedSenderKeyStore struct {
	inner store.SenderKeyStore
	jid   string
	cache *lru.Cache[string, []byte]
	// kavtov-fork: Phase 27 — device-set index, keyed jid|group|userBare → the
	// device-qualified sender_id list for that sender. Lets GetSenderKeyDevices
	// be served from cache (the device-tolerant lookup's enumerate). Invalidated
	// by PutSenderKey only when a genuinely new device appears (see PutSenderKey).
	deviceCache *lru.Cache[string, []string]

	// Phase 17.7-03: write-back flusher. May be nil before Start() wiring
	// (will fall back to write-through when nil, preserving backward compat).
	flusher *SenderKeyFlusher

	// Phase 17.8: optional callback to invalidate the decoded struct cache on
	// wasFailed=true recovery writes (Pitfall 4 / T-17.8-05 mitigation). Nil
	// when no struct cache is wired (test scenarios, pre-attachCachedStores).
	parsedInvalidate func(key string)

	hits, misses uint64
}

var _ store.SenderKeyStore = (*CachedSenderKeyStore)(nil)

// NewCachedSenderKeyStore constructs a wrapper over inner. jid is the device
// JID (used as cache-key prefix). cache is a shared LRU constructed by the
// Container.
func NewCachedSenderKeyStore(inner store.SenderKeyStore, jid string, cache *lru.Cache[string, []byte], deviceCache *lru.Cache[string, []string]) *CachedSenderKeyStore {
	return &CachedSenderKeyStore{
		inner:       inner,
		jid:         jid,
		cache:       cache,
		deviceCache: deviceCache,
	}
}

// SetFlusher attaches the write-back flusher. Called by cache_wiring.go after
// wireSignalCaches constructs the flusher. Must be called before any
// PutSenderKey calls in production.
func (c *CachedSenderKeyStore) SetFlusher(f *SenderKeyFlusher) {
	c.flusher = f
}

// SetParsedInvalidate attaches the Phase 17.8 struct-cache invalidation callback.
// Called by attachCachedStores after the parsed LRU is wired to the device.
// The callback fires when wasFailed=true (failed-tuple recovery) to ensure
// the next LoadSenderKey re-parses the recovered []byte (Pitfall 4 guard).
func (c *CachedSenderKeyStore) SetParsedInvalidate(fn func(key string)) {
	c.parsedInvalidate = fn
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

// senderKeyBlob is a minimal struct for extracting the SKDM iteration from a
// serialized sender-key session blob. Only the path we need is unmarshalled;
// if parsing fails, iteration is treated as 0 (forces flush at next N-boundary
// — safe, no data is lost).
//
// The JSON uses the exported Go field names verbatim (no json: tags on the
// libsignal structs), so this struct also uses no json: tags — Go's default
// field-name matching produces "SenderKeyStates", "SenderChainKey",
// "Iteration". Verified against a real-blob round-trip in
// extractIteration_RealBlob_test (flusher_test.go).
type senderKeyBlob struct {
	SenderKeyStates []struct {
		KeyID          uint32
		SenderChainKey struct {
			Iteration uint32
		}
	}
}

// extractSenderKeyMeta reads the current KeyID and SenderChainKey.Iteration
// from a sender-key session blob. Returns (0, 0) on any parse failure.
// SenderKeyStates[0] is the most-recent state (libsignal prepends on
// AddSenderKeyState).
func extractSenderKeyMeta(session []byte) (keyID, iteration uint32) {
	if len(session) == 0 {
		return 0, 0
	}
	var blob senderKeyBlob
	if err := json.Unmarshal(session, &blob); err != nil {
		return 0, 0
	}
	if len(blob.SenderKeyStates) == 0 {
		return 0, 0
	}
	s := blob.SenderKeyStates[0]
	return s.KeyID, s.SenderChainKey.Iteration
}

// extractIteration is a convenience wrapper used by cache_wiring.go eviction
// callback where only the iteration is needed.
func extractIteration(session []byte) uint32 {
	_, iter := extractSenderKeyMeta(session)
	return iter
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
	return c.putSenderKeyInternal(ctx, group, user, session, false)
}

// PutSenderKeyWithMeta is the internal version that accepts a wasFailed flag.
// Used by the SKDM handler when the tuple is in failedSenderKeyTuples. The
// wasFailed=true path bypasses dedup so a failed-tuple recovery always
// re-processes. The public PutSenderKey interface remains backward-compatible.
func (c *CachedSenderKeyStore) PutSenderKeyWithMeta(ctx context.Context, group, user string, session []byte, wasFailed bool) error {
	return c.putSenderKeyInternal(ctx, group, user, session, wasFailed)
}

// putSenderKeyInternal is the shared implementation for PutSenderKey /
// PutSenderKeyWithMeta.
//
// Phase 17.7-03: write-back mode. When a flusher is attached:
//  - Updates the read cache immediately (LRU warm for subsequent decrypts).
//  - Enqueues the dirty entry to the flusher (dedup + batched DB write).
//  - Does NOT call inner.PutSenderKey synchronously.
//
// When no flusher is attached (nil): falls back to the prior write-through
// behavior (calls inner synchronously). This covers test scenarios and the
// pre-wiring window during startup.
func (c *CachedSenderKeyStore) putSenderKeyInternal(ctx context.Context, group, user string, session []byte, wasFailed bool) error {
	if c.flusher == nil {
		// Write-through fallback (no flusher wired yet).
		if err := c.inner.PutSenderKey(ctx, group, user, session); err != nil {
			return err
		}
		c.cache.Add(c.key(group, user), copyBytes(session))
		c.updateDeviceCache(group, user)
		return nil
	}

	// Write-back: update read cache and enqueue to flusher.
	// Extract keyID and iteration for SKDM dedup. Both zero on parse failure →
	// iteration-0 triggers flush at first N-boundary pass (safe fallback).
	keyID, iter := extractSenderKeyMeta(session)

	// Update the read cache immediately so subsequent GetSenderKey calls are warm.
	c.cache.Add(c.key(group, user), copyBytes(session))

	// Enqueue dirty entry (SKDM dedup logic lives in flusher.Enqueue).
	c.flusher.Enqueue(group, user, session, keyID, iter, wasFailed)

	// Phase 17.8: on a failed-tuple recovery write, invalidate the decoded
	// struct cache so the next LoadSenderKey re-parses the recovered []byte
	// instead of serving the pre-recovery struct (Pitfall 4 / T-17.8-05).
	// Normal (wasFailed=false) stores do NOT invalidate here — the struct cache
	// is already replaced by signal.go's StoreSenderKey via StoreStruct (Pitfall 2).
	if wasFailed && c.parsedInvalidate != nil {
		c.parsedInvalidate(c.key(group, user))
	}

	// Update device-set index (Phase 27 logic unchanged).
	c.updateDeviceCache(group, user)

	return nil
}

// updateDeviceCache keeps the device-set index fresh. PutSenderKey fires
// on every ratchet write-back, so invalidate ONLY when this device is not
// already in the cached set (a genuinely new device, e.g. a fresh SKDM).
// Invalidating on every write-back would defeat the device-set cache.
func (c *CachedSenderKeyStore) updateDeviceCache(group, user string) {
	dk := c.key(group, senderKeyUserBare(user))
	if set, ok := c.deviceCache.Get(dk); ok && !containsString(set, user) {
		c.deviceCache.Remove(dk)
	}
}

// GetSenderKeyDevices answers the device-tolerant lookup's enumerate from the
// dedicated device-set LRU (keyed jid|group|userBare), falling to the inner
// store once on a cold key. kavtov-fork Phase 27: this replaces the old DB
// passthrough so the hot path issues 0 DB queries. The staleness risk the old
// passthrough cited is handled by PutSenderKey, which invalidates this key when
// a genuinely new device appears.
func (c *CachedSenderKeyStore) GetSenderKeyDevices(ctx context.Context, group, userBare string) ([]string, error) {
	dk := c.key(group, userBare)
	if v, ok := c.deviceCache.Get(dk); ok {
		atomic.AddUint64(&c.hits, 1)
		return append([]string(nil), v...), nil // copy-out (CR-06)
	}
	atomic.AddUint64(&c.misses, 1)
	devices, err := c.inner.GetSenderKeyDevices(ctx, group, userBare)
	if err != nil {
		return nil, err // never cache on error
	}
	// An empty set is safe to cache: PutSenderKey invalidates this key when a
	// new device's SKDM arrives, so a cached empty cannot go permanently stale.
	c.deviceCache.Add(dk, append([]string(nil), devices...))
	return devices, nil
}

// senderKeyUserBare strips the device qualifier from a device-qualified
// sender_id ("<user>:<dev>" → "<user>"). Used to key the device-set cache.
func senderKeyUserBare(user string) string {
	if i := strings.LastIndex(user, ":"); i >= 0 {
		return user[:i]
	}
	return user
}

func containsString(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

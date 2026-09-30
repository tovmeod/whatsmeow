// Copyright (c) 2026 Kavtov Platform (Phase 17.5 / Phase 17.7)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"golang.org/x/sync/singleflight"

	"go.mau.fi/whatsmeow/store"
)

// senderKeyFlatReader is the local interface that *SQLStore satisfies to
// provide the flat read path (GetSenderKeyFlat). Using a local interface avoids
// exposing GetSenderKeyFlat as part of the upstream store.SenderKeyStore while
// enabling the cache layer to type-assert and call it without importing sqlstore
// internals from package store.
type senderKeyFlatReader interface {
	GetSenderKeyFlat(ctx context.Context, group, user string) ([]byte, error)
}

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
	deviceCache *SenderKeyDeviceCache

	// Phase 29 D-01: pointer to the process-global singleflight.Group for
	// findSenderKeyDonor coalescing. Shared by all CachedSenderKeyStore instances
	// (passed from signalCaches.DonorSF). May be nil in unit-test contexts that
	// construct the store without a Container — the nil path calls findSenderKeyDonor
	// directly (no coalescing but correct behaviour).
	sf *singleflight.Group

	// Phase 17.7-03: write-back flusher. May be nil before Start() wiring
	// (will fall back to write-through when nil, preserving backward compat).
	flusher *SenderKeyFlusher

	// pinnedMu guards the pinned overlay. Lock order: pinnedMu may be taken while
	// NOT holding the LRU's internal lock and NOT holding flusher.mu. The flusher's
	// onDrained callback acquires pinnedMu outside flusher.mu — never call flusher
	// methods while holding pinnedMu (would invert the order).
	pinnedMu sync.Mutex
	// pinned holds device sids for writes that have not yet drained to DB.
	// Key: same dk as deviceCache (c.key(group, senderKeyUserBare(user))).
	// Value: set of device-qualified sender_id strings (e.g. "9725..._1:0").
	// On write: the device sid is added. On drain callback: sid removed; inner
	// map deleted when empty. GetSenderKeyDevices returns pinned UNION DB-result.
	pinned map[deviceQueryKey]map[string]struct{}

	// pinnedBlobs holds the flat blob for writes that have not yet drained to DB
	// AND whose c.cache entry may have been evicted (risk c: eviction-before-drain).
	// Phase 38.4-02: extends the 260617-0k0 coherence mechanism to the KEY blob
	// so GetSenderKeyStructure can still serve the structure after LRU eviction.
	// Key: c.key(group, user) — same key as c.cache (device-qualified, not bare).
	// Value: copyBytes of the PackFlat blob at write time.
	// Guarded by pinnedMu (same lock as pinned — single lock, no new contention).
	// Unpinned inside the EXISTING SetFlusher onDrained closure (no second hook).
	pinnedBlobs map[string][]byte

	hits, misses uint64
}

var _ store.SenderKeyStore = (*CachedSenderKeyStore)(nil)

// Compile-time assertion: CachedSenderKeyStore satisfies the fork-local
// SenderKeyColumnarStore interface. If CachedSenderKeyStore.PutSenderKeyStructure
// is removed or its signature drifts, this line becomes a BUILD ERROR, preventing
// StoreSenderKey's type-assertion from silently falling back to keyRecord.Serialize()
// (which would silently re-introduce JSON on every per-message write — invisible
// to the no-JSON grep-gate since the JSON is inside libsignal). T-17.9-11 guard.
var _ store.SenderKeyColumnarStore = (*CachedSenderKeyStore)(nil)

// NewCachedSenderKeyStore constructs a wrapper over inner. jid is the device
// JID (used as cache-key prefix). cache is a shared LRU constructed by the
// Container. sf is a pointer to the process-global singleflight.Group for
// findSenderKeyDonor coalescing (passed from signalCaches.DonorSF); nil is
// accepted for test contexts that do not wire a Container.
func NewCachedSenderKeyStore(inner store.SenderKeyStore, jid string, cache *lru.Cache[string, []byte], deviceCache *SenderKeyDeviceCache, sf *singleflight.Group) *CachedSenderKeyStore {
	return &CachedSenderKeyStore{
		inner:       inner,
		jid:         jid,
		cache:       cache,
		deviceCache: deviceCache,
		sf:          sf,
		pinned:      make(map[deviceQueryKey]map[string]struct{}),
		pinnedBlobs: make(map[string][]byte),
	}
}

// SetFlusher attaches the write-back flusher. Called by cache_wiring.go after
// wireSignalCaches constructs the flusher. Must be called before any
// PutSenderKey calls in production.
//
// Wires the onDrained unpin callback so that after a successful DB commit the
// device sid is removed from the pinned overlay. Lock order: pinnedMu is taken
// inside the callback AFTER flusher.mu is released (Task 1 ensures the hook
// fires outside flusher.mu). The callback does NOT call any flusher method.
func (c *CachedSenderKeyStore) SetFlusher(f *SenderKeyFlusher) {
	c.flusher = f
	if f == nil {
		return
	}
	f.SetOnDrained(func(group, user string) {
		dk := c.deviceKey(group, user)
		bk := c.key(group, user)
		c.pinnedMu.Lock()
		if ps := c.pinned[dk]; ps != nil {
			delete(ps, user)
			if len(ps) == 0 {
				delete(c.pinned, dk)
			}
		}
		// Phase 38.4-02: also unpin the blob overlay. The DB commit is now
		// authoritative for this key; the pinnedBlob safety net is no longer needed.
		delete(c.pinnedBlobs, bk)
		c.pinnedMu.Unlock()
	})
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

// extractStructMeta reads the current KeyID and SenderChainKey.Iteration
// from a *SenderKeyStructure. Returns (0, 0) on nil or 0-state input.
// SenderKeyStates[0] is the most-recent state (libsignal prepends on AddSenderKeyState).
func extractStructMeta(s *groupRecord.SenderKeyStructure) (keyID, iteration uint32) {
	if s == nil || len(s.SenderKeyStates) == 0 || s.SenderKeyStates[0] == nil {
		return 0, 0
	}
	st := s.SenderKeyStates[0]
	if st.SenderChainKey == nil {
		return st.KeyID, 0
	}
	return st.KeyID, st.SenderChainKey.Iteration
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

// GetSenderKeyStructure implements store.SenderKeyColumnarStore. It reads the
// flat sender_key bytea and decodes it with store.UnpackFlat. Post-upgrade-19
// all rows carry a PackFlat blob; absent rows return (nil, nil) so LoadSenderKey
// builds an empty record.
//
// Phase 38.4-02: cache-aware read. Checks the write-through flat c.cache BEFORE
// the inner DB read (Pitfall 1 fix). A just-written key whose flusher entry has
// not yet drained to DB is served from the cache, mirroring GetSenderKey.
// On a c.cache miss, also checks pinnedBlobs (risk c: eviction-before-drain
// coherence). On miss, the DB blob is added to c.cache before returning.
// UnpackFlat error on a cached blob falls through to the DB (corrupt cache entry
// is not fatal — T-384-05 mitigated).
//
// The returned *SenderKeyStructure is READ-ONLY. The caller calls
// NewSenderKeyFromStruct to obtain a live *SenderKey record.
func (c *CachedSenderKeyStore) GetSenderKeyStructure(ctx context.Context, group, user string) (*groupRecord.SenderKeyStructure, error) {
	k := c.key(group, user)

	// Cache-aware read: check the write-through flat c.cache first.
	if v, ok := c.cache.Get(k); ok {
		atomic.AddUint64(&c.hits, 1)
		if s, err := store.UnpackFlat(v); err == nil {
			return s, nil
		}
		// UnpackFlat error on a cached blob: treat as miss, fall through to DB.
		// (T-384-05: a corrupt cache entry must not return a bad structure.)
	}

	// Cache miss: also check the pinnedBlobs overlay (risk c: eviction-before-drain).
	// A just-written-but-undrained blob whose c.cache entry was evicted is still
	// pinned here until onDrained fires (same pinnedMu as the device-set overlay).
	c.pinnedMu.Lock()
	pinned := c.pinnedBlobs[k]
	c.pinnedMu.Unlock()
	if pinned != nil {
		if s, err := store.UnpackFlat(pinned); err == nil {
			return s, nil
		}
		// Corrupt pinned blob: fall through to DB.
	}

	atomic.AddUint64(&c.misses, 1)

	r, ok := c.inner.(senderKeyFlatReader)
	if !ok {
		// inner does not implement the flat reader (test stub / pre-wiring).
		// Fall back to the legacy []byte path.
		blob, err := c.inner.GetSenderKey(ctx, group, user)
		if err != nil || blob == nil {
			return nil, err
		}
		// Cache the DB result for subsequent reads.
		c.cache.Add(k, copyBytes(blob))
		return store.UnpackFlat(blob)
	}

	blob, err := r.GetSenderKeyFlat(ctx, group, user)
	if err != nil {
		return nil, err
	}
	if blob == nil {
		// Absent row: no error, caller builds an empty record.
		return nil, nil
	}
	// Cache the DB result (mirror GetSenderKey L254-255: Add before decode, never cache nil).
	c.cache.Add(k, copyBytes(blob))
	return store.UnpackFlat(blob)
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
// PutSenderKeyWithMeta (the legacy []byte interface path).
//
// Phase 17.9: the legacy []byte path ALWAYS writes synchronously to inner
// (fmt_ver=1; no decompose, no flusher enqueue). The flusher is exclusively
// owned by the columnar path (PutSenderKeyStructure). This preserves the
// clean ownership split:
//   - Legacy []byte in → legacy putSenderKeyQuery (fmt_ver=1 row) out.
//   - Columnar *SenderKeyStructure in → fmt_ver=2 + all columns out (via flusher).
//
// The []byte LRU cache (c.cache) is updated immediately for read-path warmth.
// The wasFailed path still invalidates the parsed struct cache on recovery
// writes that arrive as legacy blobs (Pitfall 4 / T-17.8-05).
//
// T-17.9-08 note: T-17.9-08 targets the PRODUCTION columnar path (which routes
// through PutSenderKeyStructure → flusher). The legacy synchronous write here
// is only reached by non-columnar callers (test stores, SKDM handler fallbacks).
func (c *CachedSenderKeyStore) putSenderKeyInternal(ctx context.Context, group, user string, session []byte, wasFailed bool) error {
	// Legacy path: always synchronous write to inner (fmt_ver=1; no decompose).
	if err := c.inner.PutSenderKey(ctx, group, user, session); err != nil {
		return err
	}

	// Update the read cache immediately so subsequent GetSenderKey calls are warm.
	c.cache.Add(c.key(group, user), copyBytes(session))

	// Update device-set index (Phase 27 logic unchanged).
	c.updateDeviceCache(group, user)

	return nil
}

// PutSenderKeyStructure implements store.SenderKeyColumnarStore. This is the
// production flat write path (post-upgrade-19).
//
// It encodes the libsignal *SenderKeyStructure into a PackFlat bytea (no JSON,
// no columnar columns), derives keyID/iter from the structure, and enqueues
// to the write-back flusher. If the flusher is nil (pre-wiring / test scenarios),
// it falls through to a synchronous PutManySenderKeys write instead.
//
// T-17.9-10 guard: PackFlat does not call Serialize() or any JSON path.
// T-17.9-16 REPLACE-on-write coherence: parsedReplace fires with the in-hand
// structure so LoadSenderKey returns the fresh key before the flusher drains.
func (c *CachedSenderKeyStore) PutSenderKeyStructure(ctx context.Context, group, user string, s *groupRecord.SenderKeyStructure) error {
	// Encode to flat binary. PackFlat makes its own copies of all byte fields,
	// so the blob is disjoint from the libsignal structure's backing arrays.
	blob, ok := store.PackFlat(s)
	if !ok {
		// 0-state or invalid structure — fall back to legacy PutSenderKey (safety net).
		sk, _ := groupRecord.NewSenderKeyFromStruct(s,
			store.SignalProtobufSerializer.SenderKeyRecord,
			store.SignalProtobufSerializer.SenderKeyState)
		var legacyBlob []byte
		if sk != nil {
			legacyBlob = sk.Serialize() // ALLOW-JSON-DRAIN-BLOB
		}
		return c.inner.PutSenderKey(ctx, group, user, legacyBlob)
	}

	// Derive keyID/iter from the structure (0-state → (0,0)).
	keyID, iter := extractStructMeta(s)

	if c.flusher != nil {
		// Cipher write-back: enqueue flat blob to flusher (dedup + batched async drain).
		c.flusher.Enqueue(group, user, blob, keyID, iter, false)

		// Write-through []byte cache so GetSenderKey returns the fresh blob before
		// the flusher drains (D-03: blob is PackFlat output = byte-identical to DB
		// sender_key column value; safe to cache directly).
		blobCopy := copyBytes(blob)
		c.cache.Add(c.key(group, user), blobCopy)

		// Phase 38.4-02: also pin in pinnedBlobs so GetSenderKeyStructure can
		// serve the structure after LRU eviction (risk c: eviction-before-drain).
		c.pinnedMu.Lock()
		c.pinnedBlobs[c.key(group, user)] = copyBytes(blob)
		c.pinnedMu.Unlock()

		// Update device-set index (Phase 27 logic unchanged).
		c.updateDeviceCache(group, user)
		return nil
	}

	// Write-through fallback (flusher not yet wired: pre-wiring window or tests).
	// Write a flat row synchronously via PutManySenderKeys.
	if putMany, ok := c.inner.(interface {
		PutManySenderKeys(ctx context.Context, keys []SenderKeyRow) error
	}); ok {
		if err := putMany.PutManySenderKeys(ctx, []SenderKeyRow{{Group: group, User: user, Blob: blob}}); err != nil {
			return err
		}
	} else {
		// Ultimate fallback: inner does not support PutManySenderKeys (test stub).
		// This path should not occur in production (inner is always *SQLStore there).
		if err := c.inner.PutSenderKey(ctx, group, user, blob); err != nil {
			return err
		}
	}

	// Write-through []byte cache (D-03) on the synchronous fallback path.
	c.cache.Add(c.key(group, user), copyBytes(blob))

	// Phase 38.4-02: pin the blob on the synchronous fallback path too (no flusher,
	// but the pin is harmless — onDrained will never fire so it stays until Purge/restart,
	// which is the correct semantics for a synchronous write: DB is authoritative immediately).
	c.pinnedMu.Lock()
	c.pinnedBlobs[c.key(group, user)] = copyBytes(blob)
	c.pinnedMu.Unlock()

	c.updateDeviceCache(group, user)
	return nil
}

// PutSenderKeyStructureRecovery is the recovery-class variant of PutSenderKeyStructure.
// It carries donorKeyID (the KeyID from the cross-account donor) so the parsed-cache
// iteration gate can apply the stricter recovery rule: reject unless the donor strictly
// advances the cached position for that KeyID (cached.Iteration >= donor.Iteration =>
// reject). Preserved foreign-KeyID states in a merged install are not penalised
// (equal-iteration matches on non-donor KeyIDs are accepted — D-12 interaction rule).
//
// Ordering: for the recovery class, the gate verdict is evaluated BEFORE
// flusher.Enqueue — a rejected stale install does not enter the flusher dirty-set
// and therefore cannot persist its stale blob to DB via last-wins drain.
//
// Returns (installed, err) — CR-03: installed=false means the iteration gate
// rejected a stale install (nothing was written anywhere); the caller
// (TryInlineRecovery) must then report ok=false so no phantom
// SENDER_KEY_RECOVERED is logged. A StoreUncacheable verdict (structure valid
// but not flat-cacheable, e.g. a merge with > flatMaxStates states) skips the
// cache but STILL persists — mirroring the cipher path, which ignores the
// verdict — and counts as installed=true.
//
// Callers: TryInlineRecovery (recovery_sender_key.go install site).
func (c *CachedSenderKeyStore) PutSenderKeyStructureRecovery(ctx context.Context, group, user string, s *groupRecord.SenderKeyStructure, donorKeyID uint32) (bool, error) {
	blob, ok := store.PackFlat(s)
	if !ok {
		// 0-state or invalid structure — fall back to legacy PutSenderKey (safety net).
		sk, _ := groupRecord.NewSenderKeyFromStruct(s,
			store.SignalProtobufSerializer.SenderKeyRecord,
			store.SignalProtobufSerializer.SenderKeyState)
		var legacyBlob []byte
		if sk != nil {
			legacyBlob = sk.Serialize() // ALLOW-JSON-DRAIN-BLOB
		}
		return true, c.inner.PutSenderKey(ctx, group, user, legacyBlob)
	}

	// Derive the flusher Enqueue meta from the DONOR state, not blindly from
	// state[0] (CR-04 belt-and-braces). After the donor-prepend fix in
	// TryInlineRecovery's merge, state[0] IS the donor so the two coincide —
	// but deriving from the donor KeyID explicitly guarantees the recovery
	// enqueue can never carry a foreign generation's (keyID, iter), which would
	// let the flusher's same-generation dedup silently skip the recovery blob
	// (donor never reaching DB; re-lost on LRU eviction or restart).
	keyID, iter := extractStructMeta(s)
	for _, st := range s.SenderKeyStates {
		if st != nil && st.KeyID == donorKeyID && st.SenderChainKey != nil {
			keyID, iter = st.KeyID, st.SenderChainKey.Iteration
			break
		}
	}

	// Flat-path backward-only / strictly-advancing iteration gate (Risk-b).
	//
	// This gate is ported from parsedcache.go StoreStruct (deleted in Phase 38.4-03).
	// It checks the cache-aware GetSenderKeyStructure (Plan 02) and rejects a stale
	// or backward-moving install:
	//   - Donor KeyID: must strictly advance (cached.Iteration >= donor.Iteration → reject).
	//   - Non-donor KeyIDs: reject only on backward move (cached.Iteration > incoming).
	//   - Equal iteration on non-donor KeyIDs: preserved foreign state → accept (D-12).
	// No cached entry (absent or cache-miss) → write proceeds unconditionally.
	//
	// ORDERING: checked BEFORE flusher.Enqueue. A rejected stale install must not enter
	// the dirty-set or the cache (prevents last-wins DB drain of a stale blob — T-384-06).
	//
	// This is defense-in-depth for direct callers of PutSenderKeyStructureRecovery.
	// The first-line guard in recovery_sender_key.go (downgrade guard) still runs
	// BEFORE this site via TryInlineRecovery.
	existing, gErr := c.GetSenderKeyStructure(ctx, group, user)
	if gErr != nil {
		return false, gErr
	}
	if existing != nil {
		for _, inSt := range s.SenderKeyStates {
			if inSt == nil || inSt.SenderChainKey == nil {
				continue
			}
			// Find the matching cached state for this KeyID.
			var cachedIter uint32
			var found bool
			for _, exSt := range existing.SenderKeyStates {
				if exSt != nil && exSt.SenderChainKey != nil && exSt.KeyID == inSt.KeyID {
					cachedIter = exSt.SenderChainKey.Iteration
					found = true
					break
				}
			}
			if !found {
				continue // no cached counterpart — new state, accept
			}
			if inSt.KeyID == donorKeyID {
				// Donor KeyID: must strictly advance.
				if cachedIter >= inSt.SenderChainKey.Iteration {
					return false, nil // stale donor — reject
				}
			} else {
				// Non-donor (preserved foreign) KeyID: reject only on backward move.
				if cachedIter > inSt.SenderChainKey.Iteration {
					return false, nil // backward move — reject
				}
				// Equal iteration: preserved foreign state — accept (D-12 interaction rule).
			}
		}
	}

	// Persist: enqueue to the write-back flusher when wired, else write through.
	if c.flusher != nil {
		c.flusher.Enqueue(group, user, blob, keyID, iter, false)

		// Write-through []byte cache so GetSenderKey returns the fresh blob before
		// the flusher drains (D-03). Covers both StoreAccepted and StoreUncacheable —
		// both paths reach this block (StoreRejectedStale returned early above).
		c.cache.Add(c.key(group, user), copyBytes(blob))

		// Phase 38.4-02: pin the blob for eviction-before-drain coherence on recovery path.
		c.pinnedMu.Lock()
		c.pinnedBlobs[c.key(group, user)] = copyBytes(blob)
		c.pinnedMu.Unlock()

		c.updateDeviceCache(group, user)
		return true, nil
	}

	if putMany, ok := c.inner.(interface {
		PutManySenderKeys(ctx context.Context, keys []SenderKeyRow) error
	}); ok {
		if err := putMany.PutManySenderKeys(ctx, []SenderKeyRow{{Group: group, User: user, Blob: blob}}); err != nil {
			return false, err
		}
	} else {
		if err := c.inner.PutSenderKey(ctx, group, user, blob); err != nil {
			return false, err
		}
	}

	// Write-through []byte cache (D-03) on the synchronous fallback path.
	c.cache.Add(c.key(group, user), copyBytes(blob))

	// Phase 38.4-02: pin the blob on recovery synchronous fallback path.
	c.pinnedMu.Lock()
	c.pinnedBlobs[c.key(group, user)] = copyBytes(blob)
	c.pinnedMu.Unlock()

	c.updateDeviceCache(group, user)
	return true, nil
}

// deviceKey keeps account/group/sender boundaries separate and does not collapse
// agent or address namespaces. Device suffixes do not narrow enumeration.
func (c *CachedSenderKeyStore) deviceKey(group, user string) deviceQueryKey {
	var universe any = c.inner
	if sql, ok := c.inner.(*SQLStore); ok {
		universe = sql.Container
	}
	return deviceQueryKey{universe: universe, account: c.jid, group: group, sender: senderKeyUserBare(user)}
}

func (c *CachedSenderKeyStore) pinnedDevices(dk deviceQueryKey) []string {
	c.pinnedMu.Lock()
	defer c.pinnedMu.Unlock()
	var result []string
	for sid := range c.pinned[dk] {
		result = append(result, sid)
	}
	return result
}

// updateDeviceCache fences readers and replaces an existing empty entry before
// an asynchronous SQL drain. Copy ownership is preserved for every merge.
func (c *CachedSenderKeyStore) updateDeviceCache(group, user string) {
	dk := c.deviceKey(group, user)
	c.pinnedMu.Lock()
	if c.pinned[dk] == nil {
		c.pinned[dk] = make(map[string]struct{})
	}
	c.pinned[dk][user] = struct{}{}
	c.pinnedMu.Unlock()
	owner := c.deviceCache
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if f := owner.flights[dk]; f != nil {
		f.invalid = true
	}
	owner.invalidations.Add(1)
	if entry, ok := owner.Get(dk); ok {
		owner.Add(dk, deviceCacheEntry{devices: mergeDeviceSets(entry.devices, []string{user})})
	}
}

func validDeviceResult(devices []string, sender string) bool {
	if devices == nil {
		return false
	}
	for _, sid := range devices {
		i := strings.LastIndex(sid, ":")
		if i < 1 || i == len(sid)-1 || senderKeyUserBare(sid) != sender {
			return false
		}
		for _, ch := range sid[i+1:] {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

// cachedDevicesLocked checks and removes expiry under the same lock used for
// writes: it can never delete a newer positive during an expiry race.
func (c *CachedSenderKeyStore) cachedDevicesLocked(dk deviceQueryKey) ([]string, bool) {
	owner := c.deviceCache
	entry, ok := owner.Get(dk)
	if !ok {
		return nil, false
	}
	if len(entry.devices) == 0 && !owner.now().Before(entry.expiresAt) {
		owner.Remove(dk)
		owner.expiries.Add(1)
		return nil, false
	}
	if len(entry.devices) == 0 {
		owner.negativeHits.Add(1)
	} else {
		owner.positiveHits.Add(1)
	}
	atomic.AddUint64(&c.hits, 1)
	return mergeDeviceSets(entry.devices, c.pinnedDevices(dk)), true
}

// GetSenderKeyDevices coalesces cold enumeration without a worker goroutine.
// Followers own their cancellation; a canceled leader allows a live follower
// to retry. Overflow never publishes, and tokens remain until every participant
// has consumed the first completed result (including its fixed TTL).
func (c *CachedSenderKeyStore) GetSenderKeyDevices(ctx context.Context, group, userBare string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dk := c.deviceKey(group, userBare)
	owner := c.deviceCache
	owner.mu.Lock()
	if devices, hit := c.cachedDevicesLocked(dk); hit {
		owner.mu.Unlock()
		return devices, nil
	}
	if pins := c.pinnedDevices(dk); len(pins) > 0 {
		owner.positiveHits.Add(1)
		owner.mu.Unlock()
		return pins, nil
	}
	atomic.AddUint64(&c.misses, 1)
	flight := owner.flights[dk]
	if flight != nil && !(flight.completed && !flight.expiresAt.IsZero() && !owner.now().Before(flight.expiresAt)) {
		flight.participants++
		owner.mu.Unlock()
		select {
		case <-ctx.Done():
			c.releaseDeviceFlight(dk, flight)
			return nil, ctx.Err()
		case <-flight.done:
			owner.mu.Lock()
			devices, err := mergeDeviceSets(flight.devices, c.pinnedDevices(dk)), flight.err
			if entry, ok := owner.Peek(dk); ok && len(entry.devices) > 0 {
				devices = mergeDeviceSets(entry.devices, devices)
			}
			owner.mu.Unlock()
			c.releaseDeviceFlight(dk, flight)
			if err != nil && ctx.Err() == nil && (err == context.Canceled || err == context.DeadlineExceeded) {
				owner.queries.Add(1)
				devices, err = c.inner.GetSenderKeyDevices(ctx, group, dk.sender)
				return mergeDeviceSets(devices, c.pinnedDevices(dk)), err
			}
			return devices, err
		}
	}
	if flight != nil || len(owner.flights) >= owner.capacity {
		owner.overflows.Add(1)
		owner.queries.Add(1)
		owner.mu.Unlock()
		devices, err := c.inner.GetSenderKeyDevices(ctx, group, dk.sender)
		return mergeDeviceSets(devices, c.pinnedDevices(dk)), err
	}
	flight = &deviceQueryFlight{done: make(chan struct{}), participants: 1}
	owner.flights[dk] = flight
	owner.queries.Add(1)
	owner.mu.Unlock()
	devices, err := c.inner.GetSenderKeyDevices(ctx, group, dk.sender)
	completedAt := owner.now()
	if err == nil {
		err = ctx.Err()
	}
	owner.mu.Lock()
	// Completion is serialized with accepted writes. Re-read pins here rather
	// than using a pre-query snapshot that can miss a just-accepted key.
	pins := c.pinnedDevices(dk)
	if err == nil && !flight.invalid && validDeviceResult(devices, dk.sender) {
		entry := deviceCacheEntry{devices: mergeDeviceSets(devices, pins)}
		if len(entry.devices) == 0 {
			entry.expiresAt = completedAt.Add(senderKeyDeviceNegativeTTL)
			flight.expiresAt = entry.expiresAt
		}
		owner.Add(dk, entry)
	}
	devices = mergeDeviceSets(devices, pins)
	if entry, ok := owner.Peek(dk); ok && len(entry.devices) > 0 {
		devices = mergeDeviceSets(entry.devices, devices)
	}
	flight.devices, flight.err = devices, err
	flight.completed = true
	close(flight.done)
	owner.mu.Unlock()
	c.releaseDeviceFlight(dk, flight)
	return mergeDeviceSets(devices, nil), err
}

func (c *CachedSenderKeyStore) releaseDeviceFlight(dk deviceQueryKey, flight *deviceQueryFlight) {
	owner := c.deviceCache
	owner.mu.Lock()
	defer owner.mu.Unlock()
	flight.participants--
	if flight.participants == 0 && owner.flights[dk] == flight {
		delete(owner.flights, dk)
	}
}

// mergeDeviceSets returns the union of base and extra, deduplicated.
// Allocates a new slice; caller owns the result.
func mergeDeviceSets(base, extra []string) []string {
	if len(extra) == 0 {
		return append([]string(nil), base...)
	}
	out := make([]string, len(base), len(base)+len(extra))
	copy(out, base)
	for _, sid := range extra {
		if !containsString(out, sid) {
			out = append(out, sid)
		}
	}
	return out
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

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
	deviceCache *lru.Cache[string, []string]

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
	pinned map[string]map[string]struct{}

	// pinnedBlobs holds the flat blob for writes that have not yet drained to DB
	// AND whose c.cache entry may have been evicted (risk c: eviction-before-drain).
	// Phase 38.4-02: extends the 260617-0k0 coherence mechanism to the KEY blob
	// so GetSenderKeyStructure can still serve the structure after LRU eviction.
	// Key: c.key(group, user) — same key as c.cache (device-qualified, not bare).
	// Value: copyBytes of the PackFlat blob at write time.
	// Guarded by pinnedMu (same lock as pinned — single lock, no new contention).
	// Unpinned inside the EXISTING SetFlusher onDrained closure (no second hook).
	pinnedBlobs map[string][]byte

	// Phase 17.8: optional callback to invalidate the decoded struct cache on
	// wasFailed=true recovery writes (Pitfall 4 / T-17.8-05 mitigation). Nil
	// when no struct cache is wired (test scenarios, pre-attachCachedStores).
	parsedInvalidate func(key string)

	// Phase 17.9 (Task 3): REPLACE callback — set by SetParsedReplace, wired in
	// cache_wiring.go. Fires at the PutSenderKeyStructure chokepoint to synchronously
	// replace the cached *SenderKeyStructure with the in-hand structure BEFORE the
	// async flusher drains the DB columns. REPLACE (not invalidate) is required
	// because GetSenderKeyStructure reads DB columns that may not yet be drained;
	// invalidate-then-Load would read pre-drain (nil) columns = silent decrypt failure
	// on immediate read-after-write and recovery paths (T-17.9-16).
	//
	// Phase 35.2-04 (D-11 iteration gate): the signature is extended with
	// donorKeyID *uint32 (nil = cipher write, non-nil = recovery install of that KeyID)
	// and returns store.StoreVerdict (CR-03 tri-state): StoreAccepted,
	// StoreRejectedStale (stale install — recovery callers skip flusher AND DB),
	// or StoreUncacheable (flat-cache refusal — recovery callers skip the cache
	// but still persist). The caller MUST evaluate the verdict for the recovery
	// class before flusher.Enqueue (verdict-before-Enqueue ordering requirement).
	parsedReplace func(key string, s *groupRecord.SenderKeyStructure, donorKeyID *uint32) store.StoreVerdict

	// Phase 35.2 (CR-01): READ callback into the parsed struct cache — set by
	// SetParsedLoad, wired in cache_wiring.go alongside SetParsedReplace.
	// TryInlineRecovery uses it to union the cache-resident structure (which
	// under write-back can be AHEAD of the DB by up to a flush interval) with
	// the DB guard read before building the D-12 donor merge. Without it the
	// merge is built from a stale DB snapshot and can silently drop a
	// cache-only fresh generation from both the cache and the DB. Nil when no
	// struct cache is wired (test scenarios, pre-attachCachedStores) — the
	// merge then uses the DB read alone.
	parsedLoad func(key string) (*groupRecord.SenderKeyStructure, bool)

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
func NewCachedSenderKeyStore(inner store.SenderKeyStore, jid string, cache *lru.Cache[string, []byte], deviceCache *lru.Cache[string, []string], sf *singleflight.Group) *CachedSenderKeyStore {
	return &CachedSenderKeyStore{
		inner:       inner,
		jid:         jid,
		cache:       cache,
		deviceCache: deviceCache,
		sf:          sf,
		pinned:      make(map[string]map[string]struct{}),
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
		dk := c.key(group, senderKeyUserBare(user))
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

// SetParsedInvalidate attaches the Phase 17.8 struct-cache invalidation callback.
// Called by attachCachedStores after the parsed LRU is wired to the device.
// The callback fires when wasFailed=true (failed-tuple recovery) to ensure
// the next LoadSenderKey re-parses the recovered []byte (Pitfall 4 guard).
func (c *CachedSenderKeyStore) SetParsedInvalidate(fn func(key string)) {
	c.parsedInvalidate = fn
}

// SetParsedReplace attaches the Phase 17.9 struct-cache REPLACE callback.
// Called by attachCachedStores alongside SetParsedInvalidate. The callback
// fires at the PutSenderKeyStructure chokepoint (both normal ratchet-advance
// and direct recovery writes) to synchronously replace the cached
// *SenderKeyStructure before the async flusher drains the DB columns.
// MUST be a REPLACE (not invalidate) — see parsedReplace field comment.
//
// Phase 35.2-04 (D-11): the callback signature now carries donorKeyID *uint32
// (nil = cipher/ratchet write; non-nil = recovery install) and returns the
// store.StoreVerdict tri-state (CR-03). The caller evaluates the verdict
// before flusher.Enqueue for the recovery class.
func (c *CachedSenderKeyStore) SetParsedReplace(fn func(key string, s *groupRecord.SenderKeyStructure, donorKeyID *uint32) store.StoreVerdict) {
	c.parsedReplace = fn
}

// SetParsedLoad attaches the Phase 35.2 (CR-01) struct-cache READ callback.
// Called by attachCachedStores alongside SetParsedReplace. TryInlineRecovery
// uses it to build the D-12 merge base from the union of the cache-resident
// structure and the DB read (the cache can be ahead of the DB by up to a
// flush interval under write-back).
func (c *CachedSenderKeyStore) SetParsedLoad(fn func(key string) (*groupRecord.SenderKeyStructure, bool)) {
	c.parsedLoad = fn
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

	// Phase 17.8: on a failed-tuple recovery write, invalidate the decoded
	// struct cache so the next LoadSenderKey re-parses the recovered []byte
	// instead of serving the pre-recovery struct (Pitfall 4 / T-17.8-05).
	if wasFailed && c.parsedInvalidate != nil {
		c.parsedInvalidate(c.key(group, user))
	}

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

		// REPLACE-on-write coherence (T-17.9-16): replace the parsed cache entry
		// with the in-hand structure so LoadSenderKey returns the fresh key before
		// the async flusher drains the DB row.
		// donorKeyID=nil => cipher write (backward-only gate, equal-iter accepted).
		if c.parsedReplace != nil {
			c.parsedReplace(c.key(group, user), s, nil)
		}

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

	// Write-through path: also replace the parsed cache for coherence.
	// donorKeyID=nil => cipher write (backward-only gate, equal-iter accepted).
	if c.parsedReplace != nil {
		c.parsedReplace(c.key(group, user), s, nil)
	}

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

	// ORDERING: evaluate the parsed-cache gate BEFORE flusher.Enqueue for recovery.
	// A rejected stale install must not enter the dirty-set (prevents last-wins drain
	// of a stale blob to DB even when the cache correctly holds the advanced state).
	// When parsedReplace is nil (test context / pre-wiring) the gate is not active
	// and the write proceeds unconditionally.
	cacheKey := c.key(group, user)
	if c.parsedReplace != nil {
		switch c.parsedReplace(cacheKey, s, &donorKeyID) {
		case store.StoreRejectedStale:
			// Gate rejected: stale install — skip both flusher and DB write, and
			// report installed=false so TryInlineRecovery returns ok=false (CR-03:
			// no phantom SENDER_KEY_RECOVERED for an install that never happened).
			return false, nil
		case store.StoreUncacheable:
			// Structure valid but not flat-cacheable (e.g. a D-12 merge exceeding
			// flatMaxStates states). Skip the cache but STILL persist (CR-03) —
			// exactly what the cipher path does by ignoring the verdict.
			// Invalidate the stale cached entry so reads fall through to the DB
			// row (which will carry the donor) instead of serving a pre-recovery
			// entry that is missing the donor generation indefinitely.
			if c.parsedInvalidate != nil {
				c.parsedInvalidate(cacheKey)
			}
		case store.StoreAccepted:
			// Cache replaced — fall through to persistence.
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

// updateDeviceCache adds device sid to both the deviceCache LRU and the pinned
// overlay on every sender-key write. For the LRU: if an entry is already cached,
// append the sid if not present (add-on-write, O(1)). If no LRU entry exists,
// do NOT create one — GetSenderKeyDevices will cold-load from DB on first call
// and the pinned overlay covers the pre-drain window.
// Per D-01: add-on-write replaces the old invalidate-on-new-device behavior.
func (c *CachedSenderKeyStore) updateDeviceCache(group, user string) {
	dk := c.key(group, senderKeyUserBare(user))

	// Always add to pinned under pinnedMu (D-04: eviction-safe anchor).
	c.pinnedMu.Lock()
	if c.pinned[dk] == nil {
		c.pinned[dk] = make(map[string]struct{})
	}
	c.pinned[dk][user] = struct{}{}
	c.pinnedMu.Unlock()

	// Update the LRU cache if an entry already exists — add the device sid.
	// If the entry was evicted or never loaded, leave it absent; the pinned
	// overlay ensures GetSenderKeyDevices still returns this device.
	if existing, ok := c.deviceCache.Get(dk); ok {
		if !containsString(existing, user) {
			c.deviceCache.Add(dk, append(existing, user))
		}
	}
}

// GetSenderKeyDevices answers the device-tolerant lookup's enumerate from the
// dedicated device-set LRU (keyed jid|group|userBare), falling to the inner
// store once on a cold key. Returns pinned UNION DB result so a just-written
// device is visible immediately, even before the async flusher drains to DB.
func (c *CachedSenderKeyStore) GetSenderKeyDevices(ctx context.Context, group, userBare string) ([]string, error) {
	dk := c.key(group, userBare)

	// Snapshot pinned set first, outside LRU lock.
	c.pinnedMu.Lock()
	var pinnedSids []string
	if ps := c.pinned[dk]; len(ps) > 0 {
		pinnedSids = make([]string, 0, len(ps))
		for sid := range ps {
			pinnedSids = append(pinnedSids, sid)
		}
	}
	c.pinnedMu.Unlock()

	// Try LRU cache.
	if v, ok := c.deviceCache.Get(dk); ok {
		atomic.AddUint64(&c.hits, 1)
		return mergeDeviceSets(v, pinnedSids), nil
	}

	atomic.AddUint64(&c.misses, 1)
	devices, err := c.inner.GetSenderKeyDevices(ctx, group, userBare)
	if err != nil {
		return nil, err
	}
	// D-02: do NOT cache empty sets. An empty result means the sender has
	// no DB row yet (or the key truly doesn't exist). A flusher drain will
	// commit the row and fire onDrained; subsequent GetSenderKeyDevices calls
	// must re-query so they see it. Caching empty would freeze the absence.
	if len(devices) > 0 {
		c.deviceCache.Add(dk, append([]string(nil), devices...))
	}
	return mergeDeviceSets(devices, pinnedSids), nil
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

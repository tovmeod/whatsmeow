// Copyright (c) 2026 Kavtov Platform (Phase 17.5 / Phase 17.7)
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

	groupRecord "go.mau.fi/libsignal/groups/state/record"

	"go.mau.fi/whatsmeow/store"
)

// senderKeyDecomposedReader is the local interface that *SQLStore satisfies to
// provide the fmt_ver-branching columnar read path (getSenderKeyDecomposed).
// Using a local interface avoids exposing getSenderKeyDecomposed as a public
// method while enabling the cache layer to type-assert and call it without
// importing sqlstore internals from package store. The getSenderKeyDecomposed
// method is unexported; only sqlstore-internal callers use this interface.
type senderKeyDecomposedReader interface {
	getSenderKeyDecomposed(ctx context.Context, group, user string) (cols *senderKeyColumns, legacyBlob []byte, err error)
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

	// Phase 17.7-03: write-back flusher. May be nil before Start() wiring
	// (will fall back to write-through when nil, preserving backward compat).
	flusher *SenderKeyFlusher

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
	parsedReplace func(key string, s *groupRecord.SenderKeyStructure)

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

// SetParsedReplace attaches the Phase 17.9 struct-cache REPLACE callback.
// Called by attachCachedStores alongside SetParsedInvalidate. The callback
// fires at the PutSenderKeyStructure chokepoint (both normal ratchet-advance
// and direct recovery writes) to synchronously replace the cached
// *SenderKeyStructure before the async flusher drains the DB columns.
// MUST be a REPLACE (not invalidate) — see parsedReplace field comment.
func (c *CachedSenderKeyStore) SetParsedReplace(fn func(key string, s *groupRecord.SenderKeyStructure)) {
	c.parsedReplace = fn
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

// deepCopyCols returns a new *senderKeyColumns with all byte-slice payloads
// copied (the spine int64/int32 slices are already fresh from decompose;
// only the [][]byte fields alias the libsignal structure's backing arrays).
// Called before Enqueue to ensure the async flusher holds its own copies.
func deepCopyCols(c *senderKeyColumns) *senderKeyColumns {
	if c == nil {
		return nil
	}
	cp := &senderKeyColumns{
		fmtVer:              c.fmtVer,
		stKeyID:             c.stKeyID,             // int64 — value types; fresh from decompose
		stChainKeyIteration: c.stChainKeyIteration, // int64 — value types; fresh from decompose
	}
	cp.stChainKey = deepCopyByteSlices(c.stChainKey)
	cp.stSigningKeyPublic = deepCopyByteSlices(c.stSigningKeyPublic)
	cp.stSigningKeyPrivate = deepCopyByteSlices(c.stSigningKeyPrivate) // nil elements preserved
	cp.smkStateIdx = c.smkStateIdx                                     // int32 — value types; fresh from decompose
	cp.smkIteration = c.smkIteration                                   // int64 — value types; fresh from decompose
	cp.smkIV = deepCopyByteSlices(c.smkIV)
	cp.smkCipherKey = deepCopyByteSlices(c.smkCipherKey)
	cp.smkSeed = deepCopyByteSlices(c.smkSeed)
	return cp
}

// deepCopyByteSlices copies the outer slice and copies the bytes of each
// non-nil inner slice. nil elements are preserved as nil (needed for
// stSigningKeyPrivate where nil = received key / no private key present).
func deepCopyByteSlices(ss [][]byte) [][]byte {
	if ss == nil {
		return nil
	}
	out := make([][]byte, len(ss))
	for i, b := range ss {
		out[i] = copyBytes(b) // copyBytes returns nil when b is nil
	}
	return out
}

// extractSenderKeyMeta reads the current KeyID and SenderChainKey.Iteration
// from a *senderKeyColumns DTO (the decomposed columnar form). Returns (0, 0)
// on 0-state / nil input — the len==0 guard matches the old JSON parse path's
// "empty SenderKeyStates" behavior (plan 02 note: JSON parse path removed).
//
// SenderKeyStates[0] is the most-recent state (libsignal prepends on
// AddSenderKeyState), corresponding to stKeyID[0] / stChainKeyIteration[0].
func extractSenderKeyMeta(cols *senderKeyColumns) (keyID, iteration uint32) {
	if cols == nil || len(cols.stKeyID) == 0 {
		return 0, 0
	}
	return uint32(cols.stKeyID[0]), uint32(cols.stChainKeyIteration[0])
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
// sender-key in its decomposed columnar form, branching strictly on fmt_ver
// (T-17.9-12 discriminator guard):
//
//	fmt_ver=2  → recompose from columns (NEVER reads sender_key blob)
//	fmt_ver=1/NULL → Deserialize the legacy sender_key blob
//	absent row → returns (nil, nil) so LoadSenderKey builds an empty record
//
// The returned *SenderKeyStructure is READ-ONLY. The caller calls
// NewSenderKeyFromStruct to obtain a live *SenderKey record.
func (c *CachedSenderKeyStore) GetSenderKeyStructure(ctx context.Context, group, user string) (*groupRecord.SenderKeyStructure, error) {
	r, ok := c.inner.(senderKeyDecomposedReader)
	if !ok {
		// inner does not implement the columnar reader (test stub / pre-wiring).
		// Fall back to the legacy []byte path.
		blob, err := c.inner.GetSenderKey(ctx, group, user)
		if err != nil || blob == nil {
			return nil, err
		}
		return store.SignalProtobufSerializer.SenderKeyRecord.Deserialize(blob) // ALLOW-JSON-LEGACY-READ
	}

	cols, legacyBlob, err := r.getSenderKeyDecomposed(ctx, group, user)
	if err != nil {
		return nil, err
	}

	if cols != nil {
		// fmt_ver=2: recompose from columns. The sender_key blob is NOT read
		// (it was not selected in the fmt_ver=2 branch of getSenderKeyDecomposed).
		return recompose(cols), nil
	}

	if legacyBlob == nil {
		// Absent row: no error, caller builds an empty record.
		return nil, nil
	}

	// fmt_ver=1/NULL: Deserialize the legacy blob.
	return store.SignalProtobufSerializer.SenderKeyRecord.Deserialize(legacyBlob) // ALLOW-JSON-LEGACY-READ
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
// production columnar write path for fmt_ver=2 rows.
//
// It decomposes the libsignal *SenderKeyStructure into typed columns (no JSON),
// derives keyID/iter from the DTO (len==0 guard: 0-state → (0,0)), and enqueues
// to the write-back flusher. If the flusher is nil (pre-wiring / test scenarios),
// it falls through to a synchronous PutManySenderKeys write instead (write-through
// fallback that preserves the fmt_ver=2 column path).
//
// PARSED-CACHE-REPLACE-PLAN04: plan 04 Task 3 will wire a SetParsedReplace
// callback here to atomically replace the parsed struct cache entry with the
// in-hand structure at the point below where decompose + Enqueue complete. This
// must be a REPLACE (not invalidate) because GetSenderKeyStructure reads DB
// columns that the async flusher has not yet drained. The replace is a cache
// write (not a DB write) — not a divergent write.
func (c *CachedSenderKeyStore) PutSenderKeyStructure(ctx context.Context, group, user string, s *groupRecord.SenderKeyStructure) error {
	cols := decompose(s)

	// Deep-copy byte payloads before handing the DTO to the async flusher.
	// decompose() allocates fresh spine arrays (stKeyID, stChainKeyIteration)
	// but the byte-slice payloads (stChainKey[i], stSigningKeyPublic[i], etc.)
	// are slice-header aliases into the libsignal SenderKeyState's backing arrays.
	// If the Signal ratchet mutates those backing arrays in place before the async
	// drain fires, the flusher's DTO would hold post-advance bytes with pre-advance
	// keyID/iter scalars — a divergence that T-17.9-07 exists to prevent. Copying
	// here is cheap (≤5 states, small []byte, noscan — no GC concern).
	colsCopy := deepCopyCols(cols)

	// Derive keyID/iter from the DTO. Guard the 0-state shape so len==0 → (0,0)
	// (mirroring the old extractSenderKeyMeta len==0 → (0,0) behavior; avoids panic).
	keyID, iter := extractSenderKeyMeta(colsCopy)

	if c.flusher != nil {
		// Write-back: enqueue DTO to flusher (dedup + batched async drain).
		// DO NOT call c.cache.Add with a serialized blob — that would call
		// NewSenderKeyFromStruct(...).Serialize() = libsignal-internal JSON on
		// every message, invisible to the no-JSON grep-gate (T-17.9-10 guard).
		c.flusher.Enqueue(group, user, colsCopy, keyID, iter, false)

		// Phase 17.9 Task 3: REPLACE-on-write coherence.
		// GetSenderKeyStructure reads DB columns that the async flusher has NOT yet
		// drained. An invalidate-then-Load would therefore miss the cache, read
		// pre-drain (nil) columns, and silently return the wrong / empty key —
		// the silent-decrypt-failure class this phase forbids (T-17.9-16).
		// REPLACE with recompose(colsCopy): colsCopy is already deep-copied (disjoint
		// from libsignal backing arrays); recompose produces the byte-identical
		// structure GetSenderKeyStructure would later read from columns — NOT the
		// raw s pointer which may alias libsignal backing arrays.
		if c.parsedReplace != nil {
			c.parsedReplace(c.key(group, user), recompose(colsCopy))
		}

		// Update device-set index (Phase 27 logic unchanged).
		c.updateDeviceCache(group, user)
		return nil
	}

	// Write-through fallback (flusher not yet wired: pre-wiring window or tests).
	// Write a columnar row synchronously via PutManySenderKeys.
	if putMany, ok := c.inner.(interface {
		PutManySenderKeys(ctx context.Context, keys []SenderKeyRow) error
	}); ok {
		if err := putMany.PutManySenderKeys(ctx, []SenderKeyRow{{Group: group, User: user, Cols: colsCopy}}); err != nil {
			return err
		}
	} else {
		// Ultimate fallback: inner does not support PutManySenderKeys (test stub).
		// Build the blob from the structure and write via the legacy path.
		// This path should not occur in production (inner is always *SQLStore there).
		structure := recompose(colsCopy)
		sk, _ := groupRecord.NewSenderKeyFromStruct(structure,
			store.SignalProtobufSerializer.SenderKeyRecord,
			store.SignalProtobufSerializer.SenderKeyState)
		var blob []byte
		if sk != nil {
			blob = sk.Serialize() // ALLOW-JSON-DRAIN-BLOB
		}
		if err := c.inner.PutSenderKey(ctx, group, user, blob); err != nil {
			return err
		}
	}

	// Write-through path: also replace the parsed cache for coherence.
	if c.parsedReplace != nil {
		c.parsedReplace(c.key(group, user), recompose(colsCopy))
	}

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

// Copyright (c) 2026 Kavtov Platform (Phase 17.5.1)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// cache_wiring.go isolates all signal-store cache declarations and wiring
// code from container.go to minimize upstream-merge conflict surface against
// tulir/whatsmeow. container.go retains only a single "caches signalCaches"
// bridge field; everything else cache-related (LRU types, eviction counters,
// cap constants, the construction helper, the device hookup helper, the
// metrics-loop ctx + cancel + goroutine spawn, and the emitMetricsLoop
// method body) lives here. Phase 17.5.1-03.

package sqlstore

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"golang.org/x/sync/singleflight"

	"go.mau.fi/whatsmeow/store"
	waLog "go.mau.fi/whatsmeow/util/log"
	"go.mau.fi/whatsmeow/util/walltime"
)

// envCapOrDefault reads an integer LRU capacity from the named env var. A blank,
// non-integer, or non-positive value falls back to the compiled default. Lets
// the operator reduce (or raise) caps without a fork rebuild — clamps malicious
// values to the safe default by construction.
func envCapOrDefault(key string, fallback int) int {
	s := os.Getenv(key)
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// Shared LRU capacities for the signal-store caches. Resolved once at package
// init from env vars (KAVTOV_CACHE_*_CAP) with the compiled defaults below.
// The original const names are kept as vars so wireSignalCaches /
// formatCacheMetrics references stay identical.
//
// 2026-06-10 GC-storm incident: caee645 raised SKParsed cap from 500k to 1.5M.
// At 1.5M entries the warmed heap reached 2.85 GB against GOMEMLIMIT=3200 MiB
// (only 11% headroom), driving 40 GC cycles/min consuming ~4.5 of 8 cores
// (84% CPU in mark-scan). Root cause: GC headroom is set by the cap defaults
// in this file (cache_wiring.go), NOT by GOMEMLIMIT. Mitigated 2026-06-10 via
// host-only drop-in (KAVTOV_CACHE_SENDERKEY_DECODED_CAP=500000). This phase
// lands the validated 500k default and removes the drop-in.
//
// Per-entry heap bytes measured by TestCacheMemoryBudget (Phase 35.1-01) using
// ReadMemStats-delta at N=10,000 entries. Values are ground-truth from the test,
// not pprof estimates. Blob sizes from ~1-2% TABLESAMPLE on prod (avg / p95 / max):
//
//	sender_key: avg=720 B, p95=1301 B, max=282966 B (rare fat tail)
//	session:    avg=2620 B, p95=5185 B, max=653645 B (rare fat tail)
//
//	Cache            | Measured B/entry | Cap     | Budget MB
//	-----------------|------------------|---------|----------
//	SKParsed         |   903 B          | 500,000 |   430 MB
//	SenderKey bytes  |   992 B          | 500,000 |   473 MB
//	Session bytes    |  2874 B          | 100,000 |   274 MB
//	Identity         |   179 B          | 150,000 |    26 MB
//	SKDevices        |   215 B          | 300,000 |    62 MB
//	MsgSecret        |   294 B          | 300,000 |    84 MB
//	Total caches                                  | 1,349 MB
//	Base RSS (non-cache)                          |   228 MB
//	Grand total                                   | 1,577 MB
//	GOMEMLIMIT                                    | 3,200 MB
//	GC headroom                                   |  50.7%  (>= 30% threshold)
//
//	30% GC headroom constraint: available for caches <= GOMEMLIMIT*0.70 - baseRSS
//	= 3200*0.70 - 228 = 2012 MB. Total caches 1349 MB << 2012 MB. Validated by
//	TestCacheMemoryBudget in cache_sizing_test.go.
//	Override env vars to reduce caps without a fork rebuild.
var (
	signalSessionCacheCap   = envCapOrDefault("KAVTOV_CACHE_SESSION_CAP", 100_000)
	signalIdentityCacheCap  = envCapOrDefault("KAVTOV_CACHE_IDENTITY_CAP", 150_000)
	signalSenderKeyCacheCap = envCapOrDefault("KAVTOV_CACHE_SENDERKEY_CAP", 500_000)
	// kavtov-fork: Phase 27 — device-set index (one small []string per
	// jid|group|userBare).
	signalSenderKeyDevicesCacheCap = envCapOrDefault("KAVTOV_CACHE_SKDEVICES_CAP", 300_000)
	// perf 260601-uuy: message-secret pair cache (secret + realSender).
	signalMsgSecretCacheCap = envCapOrDefault("KAVTOV_CACHE_MSGSECRET_CAP", 300_000)
	// Phase 17.8: decoded struct-LRU for flat sender-key values.
	//
	// 2026-06-10 GC-storm: caee645 raised this from 500k to 1.5M; the resulting
	// warmed heap (2.85 GB) left only 11% GC headroom against GOMEMLIMIT=3200 MiB
	// and drove 40 GC cycles/min. Fixed by TestCacheMemoryBudget (Phase 35.1-01):
	// measured 903 B/entry; 500k * 903 B = 430 MB, preserving >= 30% headroom.
	// Host-only drop-in (KAVTOV_CACHE_SENDERKEY_DECODED_CAP=500000) removed in
	// Phase 35.1-02 after this default is deployed. This is the AUTHORITATIVE prod
	// cap (wireSignalCaches builds the prod LRU from it); env-overridable.
	signalSKParsedCacheCap = envCapOrDefault("KAVTOV_CACHE_SENDERKEY_DECODED_CAP", 500_000)
)

// ---------------------------------------------------------------------------
// Phase 24: secondary indexes for Sessions and Identities caches (D-02)
// ---------------------------------------------------------------------------

// indexKey is the composite outer map key for the secondary indexes.
// jid identifies the per-device JID wrapper; phone is the SignalAddressUser
// portion of the libsignal address (the "<user>" part of "<user>:<device>").
type indexKey struct{ jid, phone string }

// sessionSecondaryIndex is a process-shared secondary index for the Session
// cache. It maps (jid, phone) → set of cacheKeys, allowing O(1) bulk-removal
// of all cache entries belonging to a given (jid, phone) pair without walking
// the LRU's Keys() slice. Concurrency-safe via sync.RWMutex (mirrors
// lidmap.go:33 pattern). Phase 24 D-02.
type sessionSecondaryIndex struct {
	mu sync.RWMutex
	m  map[indexKey]map[string]struct{}
}

func newSessionSecondaryIndex() *sessionSecondaryIndex {
	return &sessionSecondaryIndex{m: make(map[indexKey]map[string]struct{})}
}

// Insert adds cacheKey to the (jid, phone) bucket in the index.
func (idx *sessionSecondaryIndex) Insert(jid, phone, cacheKey string) {
	k := indexKey{jid, phone}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if idx.m[k] == nil {
		idx.m[k] = make(map[string]struct{})
	}
	idx.m[k][cacheKey] = struct{}{}
}

// Remove deletes cacheKey from the (jid, phone) bucket. If the bucket becomes
// empty the outer indexKey entry is also deleted to avoid leaking empty maps.
func (idx *sessionSecondaryIndex) Remove(jid, phone, cacheKey string) {
	k := indexKey{jid, phone}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	bucket := idx.m[k]
	if bucket == nil {
		return
	}
	delete(bucket, cacheKey)
	if len(bucket) == 0 {
		delete(idx.m, k)
	}
}

// SnapshotKeys acquires a read lock, copies the (jid, phone) bucket into a
// new []string, releases the lock, and returns the snapshot. The caller must
// iterate the snapshot and call cache.Remove(k) WITHOUT holding any index
// lock — this snapshot-then-release discipline is the lock-ordering rule that
// prevents deadlock against the EvictCleanup callback (Phase 24 D-01).
func (idx *sessionSecondaryIndex) SnapshotKeys(jid, phone string) []string {
	k := indexKey{jid, phone}
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	bucket := idx.m[k]
	if len(bucket) == 0 {
		return nil
	}
	out := make([]string, 0, len(bucket))
	for ck := range bucket {
		out = append(out, ck)
	}
	return out
}

// DropKey deletes the entire (jid, phone) outer entry. Called by bulk-remove
// paths AFTER all cache.Remove calls have completed (the eviction callback
// will already have cleaned each per-cacheKey entry; this is a defensive
// sweep that is a no-op if the index is already clean).
func (idx *sessionSecondaryIndex) DropKey(jid, phone string) {
	k := indexKey{jid, phone}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	delete(idx.m, k)
}

// EvictCleanup removes cacheKey from the (jid, phone) bucket. Called by the
// lru.NewWithEvict callback; the (jid, phone) pair is parsed from cacheKey by
// the caller using parseCacheKey.
func (idx *sessionSecondaryIndex) EvictCleanup(cacheKey, jid, phone string) {
	k := indexKey{jid, phone}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	bucket := idx.m[k]
	if bucket == nil {
		return
	}
	delete(bucket, cacheKey)
	if len(bucket) == 0 {
		delete(idx.m, k)
	}
}

// TEST-ONLY: totalKeyCount sums the sizes of all inner sets in the session
// secondary index. Used by TestSecondaryIndex_BoundedAfter1000CapacityEvictions
// to assert that the index size does not exceed the LRU cap after evictions.
// Do not call in production code — acquires RLock, iterates all buckets.
func (idx *sessionSecondaryIndex) totalKeyCount() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	total := 0
	for _, bucket := range idx.m {
		total += len(bucket)
	}
	return total
}

// identitySecondaryIndex is the same structure as sessionSecondaryIndex for
// the Identity cache. Kept as a distinct type (not generic-deduped) so that
// Wave 2 constructor wiring can reference each index type unambiguously.
// Phase 24 D-02.
type identitySecondaryIndex struct {
	mu sync.RWMutex
	m  map[indexKey]map[string]struct{}
}

func newIdentitySecondaryIndex() *identitySecondaryIndex {
	return &identitySecondaryIndex{m: make(map[indexKey]map[string]struct{})}
}

// Insert adds cacheKey to the (jid, phone) bucket.
func (idx *identitySecondaryIndex) Insert(jid, phone, cacheKey string) {
	k := indexKey{jid, phone}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if idx.m[k] == nil {
		idx.m[k] = make(map[string]struct{})
	}
	idx.m[k][cacheKey] = struct{}{}
}

// Remove deletes cacheKey from the (jid, phone) bucket; drops the outer entry
// when the bucket becomes empty.
func (idx *identitySecondaryIndex) Remove(jid, phone, cacheKey string) {
	k := indexKey{jid, phone}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	bucket := idx.m[k]
	if bucket == nil {
		return
	}
	delete(bucket, cacheKey)
	if len(bucket) == 0 {
		delete(idx.m, k)
	}
}

// SnapshotKeys returns a copy of the (jid, phone) bucket under a read lock.
// See sessionSecondaryIndex.SnapshotKeys for the lock-ordering rationale.
func (idx *identitySecondaryIndex) SnapshotKeys(jid, phone string) []string {
	k := indexKey{jid, phone}
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	bucket := idx.m[k]
	if len(bucket) == 0 {
		return nil
	}
	out := make([]string, 0, len(bucket))
	for ck := range bucket {
		out = append(out, ck)
	}
	return out
}

// DropKey deletes the entire (jid, phone) outer entry.
func (idx *identitySecondaryIndex) DropKey(jid, phone string) {
	k := indexKey{jid, phone}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	delete(idx.m, k)
}

// EvictCleanup removes cacheKey from the (jid, phone) bucket. Called by the
// lru.NewWithEvict callback.
func (idx *identitySecondaryIndex) EvictCleanup(cacheKey, jid, phone string) {
	k := indexKey{jid, phone}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	bucket := idx.m[k]
	if bucket == nil {
		return
	}
	delete(bucket, cacheKey)
	if len(bucket) == 0 {
		delete(idx.m, k)
	}
}

// TEST-ONLY: totalKeyCount sums the sizes of all inner sets in the identity
// secondary index. Used by TestSecondaryIndex_BoundedAfter1000CapacityEvictions
// to assert that the index size does not exceed the LRU cap after evictions.
// Do not call in production code — acquires RLock, iterates all buckets.
func (idx *identitySecondaryIndex) totalKeyCount() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	total := 0
	for _, bucket := range idx.m {
		total += len(bucket)
	}
	return total
}

// ---------------------------------------------------------------------------
// Phase 24: address-parsing helpers
// ---------------------------------------------------------------------------

// parseCacheKey splits a cache key of the form "<jid>|<address>" into its
// jid and address parts, then derives phone from the address by splitting
// on the first ":" (libsignal address form "<user>:<device>"). Returns
// ok=false if the key shape doesn't match. Used by the lru.NewWithEvict
// callbacks to compute the indexKey from just the LRU-supplied cacheKey.
func parseCacheKey(cacheKey string) (jid, phone string, ok bool) {
	jid, address, found := strings.Cut(cacheKey, "|")
	if !found {
		return "", "", false
	}
	phone = addressUser(address)
	if phone == "" {
		return "", "", false
	}
	return jid, phone, true
}

// addressUser returns the user portion of a libsignal address string of the
// form "<user>:<device>". If the string contains no ":" the whole string is
// returned as the user (defensive; should not occur in practice). Used by
// Wave 2 PutSession/PutIdentity callsites to compute the index "phone" from
// a raw libsignal address string.
func addressUser(address string) string {
	user, _, _ := strings.Cut(address, ":")
	return user
}

// signalCaches owns every cache-related piece of Container state. Container
// embeds this struct (by value) as the single "caches signalCaches" bridge
// field; container.go references nothing from this file beyond that field
// and the three wireSignalCaches / attachCachedStores / closeSignalCaches
// helper calls. Keeping all cache state inside this one struct means future
// upstream merges into container.go only ever conflict on those 4-5 surface
// lines, not on every cache-related field declaration.
type signalCaches struct {
	// Phase 17.5: shared LRU caches. One LRU per cache type, shared across
	// every device. Per-wrapper JID scoping (jid + "|" prefix on every key)
	// keeps device A's entries from colliding with device B's.
	Session   *lru.Cache[string, []byte]
	Identity  *lru.Cache[string, *[32]byte]
	SenderKey *lru.Cache[string, []byte]
	// Phase 29 D-01: process-global singleflight.Group for findSenderKeyDonor.
	// Coalesces concurrent cross-account donor queries for the same
	// (group, senderBare, keyID) so N accounts missing the same key run exactly
	// one donor DB scan. Zero value is ready — no New() call needed.
	// Passed by pointer to each CachedSenderKeyStore so all accounts share one Group.
	DonorSF singleflight.Group
	// kavtov-fork: Phase 27 — device-set index for the device-tolerant group
	// sender-key lookup. Keyed jid|group|userBare → the device-qualified
	// sender_id list. Lets GetSenderKeyDevices be answered from cache (0 DB
	// queries warm) instead of the DB passthrough; invalidated by PutSenderKey
	// when a sender's device set may have changed (a new SKDM).
	SenderKeyDevices *lru.Cache[string, []string]
	// Phase 17.8: decoded struct-LRU caches. LoadSenderKey / LoadSession hits
	// call NewSenderKeyFromStruct / NewSessionFromStructure instead of JSON
	// Deserialize + graph-rebuild. Keyed with the same jid-prefix as the []byte
	// LRU (device scoping on the shared process-level LRU). Eviction is a silent
	// no-op — next Load re-populates from the []byte LRU.
	//
	// Phase 17.9 GC redesign: SKParsed now stores the flat value-struct
	// (store.flatSenderKey, via the store.SKParsedLRU alias) rather than
	// *SenderKeyStructure, to remove the per-entry GC pointer-scan cost. The
	// value type is unexported in package store; sqlstore only constructs and
	// forwards the LRU (never Get/Add), so the exported alias suffices.
	SKParsed *store.SKParsedLRU

	// perf 260601-uuy: message-secret pair cache. Keyed
	// jid|chat.ToNonAD()|sender.ToNonAD()|message_id → (secret, realSender).
	// Avoids a PG read + JSON-less Scan on the 22 GB whatsmeow_message_secrets
	// table for repeat decrypts of the same message tuple.
	MsgSecret *lru.Cache[string, msgSecretEntry]

	// kavtov-fork: Phase 17.5.2 - split eviction counter into capacity-overflow
	// ("Capacity*", incremented by lru.NewWithEvict callback) vs explicit
	// Remove/Purge ("Explicit*", incremented at call sites in cached_*_store.go
	// before delegating to the LRU). Splits the 17.5.1 conflated counter so
	// operator can tell TOFU/identity-change churn (high explicit_removes on
	// identities) from actual cap pressure (high capacity_evictions on any cache).
	SessionCapacityEvictions, IdentityCapacityEvictions, SenderKeyCapacityEvictions uint64
	SessionExplicitRemoves, IdentityExplicitRemoves, SenderKeyExplicitRemoves       uint64

	// perf 260601-uuy: message-secret cache counters. ExplicitRemoves is
	// unused (MsgSecretStore has no Delete method) but kept for counter
	// uniformity with the other caches and the formatCacheMetrics block.
	MsgSecretCapacityEvictions uint64
	MsgSecretExplicitRemoves   uint64

	// Phase 24 D-02: process-shared secondary indexes for Sessions and
	// Identities. Pointer-typed fields; initialized by wireSignalCaches BEFORE
	// the LRUs are constructed so that the NewWithEvict callbacks can close
	// over the already-populated pointer values.
	SessionIndex  *sessionSecondaryIndex
	IdentityIndex *identitySecondaryIndex

	// Phase 17.7-03: per-device write-back flushers for sender_keys. One flusher
	// per device is created in attachCachedStores and keyed by JID string here.
	// The LRU eviction callback looks up the flusher by JID (parsed from the
	// cache key) to re-enqueue dirty entries before LRU drops them.
	// Stopped (with synchronous drain) by closeSignalCaches.
	// senderKeyFlushersMu guards concurrent reads/writes.
	senderKeyFlushersMu sync.RWMutex
	senderKeyFlusherMap map[string]*SenderKeyFlusher // key: JID string

	// Phase 17.5.1 WR-01: cancellable ctx for emitMetricsLoop. Cancelled
	// by Container.Close() (via closeSignalCaches) so the metrics
	// goroutine cleanly exits and does not race with logger teardown
	// during process shutdown.
	metricsCtx    context.Context
	metricsCancel context.CancelFunc
}

// wireSignalCaches constructs the three shared LRUs on c.caches and starts
// the metrics-loop goroutine. Called once from NewWithWrappedDB AFTER the
// Container has been heap-allocated.
//
// Closure-capture invariant (RESEARCH §1): the eviction callbacks close
// over &c.caches.<Counter> — the HEAP address of the counter field on the
// already-allocated Container. Constructing the LRUs before c exists, or
// inside a literal initializer like Container{caches: signalCaches{Session:
// lru.NewWithEvict(...)}}, would close over a stale local-variable copy of
// the counter address and silently lose every eviction. The two-step
// heap-then-wire pattern is mandatory and must not be collapsed.
//
// Panics on lru.NewWithEvict failure (preserves the original behaviour from
// the pre-extract NewWithWrappedDB: an LRU construction failure indicates a
// non-positive cap, which is a programmer error caught at startup).
func wireSignalCaches(c *Container, log waLog.Logger) {
	var err error

	// Phase 24 D-02: initialize secondary indexes BEFORE constructing the
	// LRUs. The NewWithEvict callbacks close over c (same as the existing
	// counter captures); the indexes are pointer-typed fields on c.caches so
	// the deref inside the callback hits the heap-allocated value, never a
	// stale local copy. This ordering satisfies the closure-capture invariant
	// documented above (§77-87).
	c.caches.SessionIndex = newSessionSecondaryIndex()
	c.caches.IdentityIndex = newIdentitySecondaryIndex()
	// Phase 17.7-03: initialize the JID→flusher map before constructing the
	// SenderKey LRU so the eviction callback can safely read from it.
	c.caches.senderKeyFlusherMap = make(map[string]*SenderKeyFlusher)

	c.caches.Session, err = lru.NewWithEvict[string, []byte](signalSessionCacheCap, func(key string, _ []byte) {
		atomic.AddUint64(&c.caches.SessionCapacityEvictions, 1)
		if jid, phone, ok := parseCacheKey(key); ok {
			c.caches.SessionIndex.EvictCleanup(key, jid, phone)
		}
	})
	if err != nil {
		log.Errorf("Failed to construct SessionCache (cap=%d): %v", signalSessionCacheCap, err)
		panic(err)
	}
	c.caches.Identity, err = lru.NewWithEvict[string, *[32]byte](signalIdentityCacheCap, func(key string, _ *[32]byte) {
		atomic.AddUint64(&c.caches.IdentityCapacityEvictions, 1)
		if jid, phone, ok := parseCacheKey(key); ok {
			c.caches.IdentityIndex.EvictCleanup(key, jid, phone)
		}
	})
	if err != nil {
		log.Errorf("Failed to construct IdentityCache (cap=%d): %v", signalIdentityCacheCap, err)
		panic(err)
	}
	// Phase 17.7-03: SenderKey LRU eviction callback.
	//
	// Phase 17.9 update: The []byte SenderKey LRU now holds ONLY legacy fmt_ver=1
	// blobs (populated by PutSenderKey's synchronous write-through path) and
	// cache-miss populated blobs from DB reads. The columnar flusher (fmt_ver=2)
	// owns its dirty entries exclusively in the flusher's dirty-set — NOT in this
	// []byte LRU. Therefore, eviction of a []byte entry does NOT imply there is a
	// matching dirty entry in the flusher; attempting to re-enqueue would create a
	// spurious flusher entry from a stale []byte blob (and calling
	// extractSenderKeyMeta+Enqueue is no longer valid since Enqueue takes
	// *senderKeyColumns, not []byte).
	//
	// The eviction callback is now ONLY an eviction counter. The flusher's own
	// dirty-set is not affected by this LRU's eviction — the columnar path never
	// writes to this []byte LRU (no c.cache.Add on the columnar path; T-17.9-10).
	//
	// Lock ordering note retained for audit: the LRU callback is called while the
	// LRU's internal lock is held; the callback must NOT call PutSenderKey or any
	// method that re-acquires the LRU lock.
	c.caches.SenderKey, err = lru.NewWithEvict[string, []byte](signalSenderKeyCacheCap, func(_ string, _ []byte) {
		atomic.AddUint64(&c.caches.SenderKeyCapacityEvictions, 1)
	})
	if err != nil {
		log.Errorf("Failed to construct SenderKeyCache (cap=%d): %v", signalSenderKeyCacheCap, err)
		panic(err)
	}

	// Phase 17.7-03: per-device SenderKeyFlushers are constructed in
	// attachCachedStores (one per SQLStore, so each flusher has the correct JID)
	// and tracked in c.caches.senderKeyFlushers.
	// kavtov-fork: Phase 27 — device-set index cache (see signalCaches.SenderKeyDevices).
	c.caches.SenderKeyDevices, err = lru.New[string, []string](signalSenderKeyDevicesCacheCap)
	if err != nil {
		log.Errorf("Failed to construct SenderKeyDevicesCache (cap=%d): %v", signalSenderKeyDevicesCacheCap, err)
		panic(err)
	}
	// perf 260601-uuy: message-secret pair cache. Same closure-capture
	// invariant as the counters above — the eviction callback closes over
	// &c.caches.MsgSecretCapacityEvictions (the heap field on the already-
	// allocated Container).
	c.caches.MsgSecret, err = lru.NewWithEvict[string, msgSecretEntry](signalMsgSecretCacheCap, func(string, msgSecretEntry) {
		atomic.AddUint64(&c.caches.MsgSecretCapacityEvictions, 1)
	})
	if err != nil {
		log.Errorf("Failed to construct MsgSecretCache (cap=%d): %v", signalMsgSecretCacheCap, err)
		panic(err)
	}

	// Phase 17.8: decoded struct-LRU caches. lru.New (no eviction callback) —
	// struct LRU eviction is a silent no-op; no flusher interaction needed.
	c.caches.SKParsed, err = store.NewSKParsedLRU(signalSKParsedCacheCap)
	if err != nil {
		log.Errorf("Failed to construct SKParsedCache (cap=%d): %v", signalSKParsedCacheCap, err)
		panic(err)
	}
	// Phase 17.5.1 WR-01: cancelled by Container.Close (via
	// closeSignalCaches) so emitMetricsLoop exits before logger/db
	// teardown.
	c.caches.metricsCtx, c.caches.metricsCancel = context.WithCancel(context.Background())
	go c.emitMetricsLoop(c.caches.metricsCtx)
}

// attachCachedStores overwrites the three signal stores (Sessions,
// Identities, SenderKeys) on device with Cached*Store wrappers around
// innerStore, sharing the per-Container LRUs. The other 8 stores set by
// device.SetAllStores remain pointed at the bare *SQLStore. Replaces the
// three NewCached*Store assignments formerly inlined in
// container.go.initializeDevice.
//
// Phase 24 Wave 1 note: constructors for Session and Identity are called here
// with a 5th argument (the secondary-index pointer). The constructors
// themselves are extended in Phase 24 Wave 2 (plans 24-02 and 24-03) to
// accept the new parameter. The build is intentionally broken between the end
// of Wave 1 and the end of Wave 2 — do not partial-deploy or commit during
// this window.
func attachCachedStores(c *Container, device *store.Device, innerStore *SQLStore) {
	jid := device.ID.String()
	device.Sessions = NewCachedSessionStore(innerStore, jid, c.caches.Session, &c.caches.SessionExplicitRemoves, c.caches.SessionIndex)
	device.Identities = NewCachedIdentityStore(innerStore, jid, c.caches.Identity, &c.caches.IdentityExplicitRemoves, c.caches.IdentityIndex)

	// Phase 17.7-03: per-device write-back flusher, registered with the Container
	// so closeSignalCaches can Stop() it before the DB closes.
	//
	// LEAK FIX (2026-06-03): attachCachedStores is re-invoked on EVERY
	// Device.Save() (PutDevice -> initializeDevice), not just at first init.
	// Creating + Start()ing a fresh flusher each time and overwriting the map
	// entry orphaned the previous flusher's goroutine — which keeps ticking
	// (1s NewTicker -> runFlush) forever instead of exiting. In prod this leaked
	// ~6963 ticking goroutines, pushing heap past GOMEMLIMIT and spiking CPU.
	// The flusher is a per-(Container,JID) singleton: reuse the existing one on
	// re-wiring (same JID, same shared db; its dirty-set persists). Only the
	// first attach for a JID constructs + Start()s it. Check+create under the
	// mutex so concurrent saves for the same JID can't both create one.
	senderKeyStore := NewCachedSenderKeyStore(innerStore, jid, c.caches.SenderKey, c.caches.SenderKeyDevices, &c.caches.DonorSF)
	c.caches.senderKeyFlushersMu.Lock()
	flusher, exists := c.caches.senderKeyFlusherMap[jid]
	if !exists {
		flusher = NewSenderKeyFlusher(innerStore, c.log, 0)
		c.caches.senderKeyFlusherMap[jid] = flusher
		flusher.Start()
	}
	c.caches.senderKeyFlushersMu.Unlock()
	senderKeyStore.SetFlusher(flusher)
	device.SenderKeys = senderKeyStore
	// Phase 17.12: wire inline synchronous recovery. No goroutine, no map, no mutex —
	// CachedSenderKeyStore satisfies SenderKeyInlineRecoverer directly.
	device.InlineRecoverer = senderKeyStore

	// Phase 17.8: wire decoded struct-LRU caches to the device. Both parsed
	// caches use the same shared LRU (constructed in wireSignalCaches) but are
	// accessed via thin wrappers that enforce the Store-time mutex discipline.
	device.ParsedSKCache = store.NewParsedSKCache(c.caches.SKParsed)

	// Inject the wasFailed invalidation callback into the senderKeyStore so
	// that PutSenderKeyWithMeta(wasFailed=true) recovery paths invalidate the
	// struct cache (Pitfall 4 guard, T-17.8-05 mitigation).
	senderKeyStore.SetParsedInvalidate(func(key string) {
		device.ParsedSKCache.Invalidate(key)
	})

	// Phase 17.9 Task 3: REPLACE-on-write coherence for the columnar read path.
	// GetSenderKeyStructure reads DB columns that the async flusher has NOT yet
	// drained after a PutSenderKeyStructure write. REPLACE with the in-hand
	// structure at the write chokepoint so an immediate LoadSenderKey (including
	// the recovery path's direct PutSenderKeyStructure) returns the freshly-written
	// key without waiting for the async drain. MUST be a REPLACE, not invalidate
	// (T-17.9-16; see CachedSenderKeyStore.parsedReplace field comment).
	senderKeyStore.SetParsedReplace(func(key string, s *groupRecord.SenderKeyStructure) {
		device.ParsedSKCache.StoreStruct(key, s)
	})

	// perf 260601-uuy: message-secret pair cache.
	device.MsgSecrets = NewCachedMessageSecretStore(innerStore, jid, c.caches.MsgSecret, &c.caches.MsgSecretExplicitRemoves)
}

// closeSignalCaches cancels the metrics-loop ctx so emitMetricsLoop exits
// before db/logger teardown, and stops all per-device SenderKeyFlushers so
// their dirty-sets are synchronously drained before the DB connection closes.
// Nil-guarded so Close stays safe on a partially-constructed Container (test
// struct literals that never went through wireSignalCaches).
func closeSignalCaches(c *Container) {
	if c.caches.metricsCancel != nil {
		c.caches.metricsCancel()
	}
	// Phase 17.7-03: stop all per-device flushers. Each Stop() closes the
	// async goroutine and then calls Drain() synchronously, ensuring all
	// dirty entries are written before the DB connection closes.
	c.caches.senderKeyFlushersMu.Lock()
	flusherMap := c.caches.senderKeyFlusherMap
	c.caches.senderKeyFlushersMu.Unlock()
	for _, f := range flusherMap {
		f.Stop()
	}
}

// cleanCounters computes the three log-time values from a pair of raw atomic
// counter reads. Because explicit Remove/Purge calls fire the LRU eviction
// callback (which increments CapacityEvictions), the raw CapacityEvictions
// counter is inflated by ExplicitRemoves. cap_clean subtracts out the
// explicit-remove contribution; a max(0, ...) guard handles the unlikely
// atomic load-ordering edge case where ExplicitRemoves momentarily overtakes
// CapacityEvictions.
//
// Returns: (evictions, capClean, expClean) where evictions = capClean + expClean.
func cleanCounters(cap, exp uint64) (evictions, capClean, expClean uint64) {
	expClean = exp
	if cap > exp {
		capClean = cap - exp
	}
	evictions = capClean + expClean
	return
}

// emitMetricsLoop periodically logs Container-level cache state. Runs as a
// long-lived goroutine spawned by wireSignalCaches; cadence is 5 minutes.
// Phase 17.5 FIX: the per-wrapper registry and its hit/miss/coalesced/
// flushed/deduped aggregation were removed along with the write-back
// machinery; the loop now reports only what the Container itself owns
// (per-cache Len + eviction counters). Per-wrapper Stats() remains
// callable from tests but is no longer aggregated here.
//
// kavtov-fork: Phase 17.5.2 - extended log line splits `evictions=N` into
// `capacity_evictions=A explicit_removes=B`. Old `evictions=` field is
// retained as a sum (A+B) for one cycle of operator-tooling grace; a
// follow-up phase drops the sum once tooling is updated.
func (c *Container) emitMetricsLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		// Phase 17.5.1-04: decrypt_wall p50/p95/p99/count appended so operators
		// can correlate cache hit-rate trends with end-to-end decrypt latency
		// from a single journalctl log line. Quantile estimates are approximate
		// (bucket-upper-bound resolution); zero-sample histogram formats as 0s.
		c.log.Infof("%s", formatCacheMetrics(c))
	}
}

// formatCacheMetrics formats the cache-metrics log line as a string. Extracted
// so tests can assert on the formatted output without log-capture plumbing.
func formatCacheMetrics(c *Container) string {
	sessEvic, sessCap, sessExp := cleanCounters(
		atomic.LoadUint64(&c.caches.SessionCapacityEvictions),
		atomic.LoadUint64(&c.caches.SessionExplicitRemoves),
	)
	idntEvic, idntCap, idntExp := cleanCounters(
		atomic.LoadUint64(&c.caches.IdentityCapacityEvictions),
		atomic.LoadUint64(&c.caches.IdentityExplicitRemoves),
	)
	sndkEvic, sndkCap, sndkExp := cleanCounters(
		atomic.LoadUint64(&c.caches.SenderKeyCapacityEvictions),
		atomic.LoadUint64(&c.caches.SenderKeyExplicitRemoves),
	)
	// perf 260601-uuy: message_secrets block. Nil-guarded so a test Container
	// built without MsgSecret (or any partially-constructed Container) formats
	// a "not_wired" sentinel instead of panicking on a nil Len() call.
	msgSecBlock := "message_secrets={not_wired}"
	if c.caches.MsgSecret != nil {
		msgSecEvic, msgSecCap, msgSecExp := cleanCounters(
			atomic.LoadUint64(&c.caches.MsgSecretCapacityEvictions),
			atomic.LoadUint64(&c.caches.MsgSecretExplicitRemoves),
		)
		msgSecBlock = fmt.Sprintf(
			"message_secrets={len=%d, cap=%d, evictions=%d, capacity_evictions=%d, explicit_removes=%d}",
			c.caches.MsgSecret.Len(), signalMsgSecretCacheCap, msgSecEvic, msgSecCap, msgSecExp,
		)
	}
	return fmt.Sprintf(
		"Cache metrics: sessions={len=%d, cap=%d, evictions=%d, capacity_evictions=%d, explicit_removes=%d} identities={len=%d, cap=%d, evictions=%d, capacity_evictions=%d, explicit_removes=%d} sender_keys={len=%d, cap=%d, evictions=%d, capacity_evictions=%d, explicit_removes=%d} %s decrypt_wall={p50=%s, p95=%s, p99=%s, count=%d}",
		c.caches.Session.Len(), signalSessionCacheCap, sessEvic, sessCap, sessExp,
		c.caches.Identity.Len(), signalIdentityCacheCap, idntEvic, idntCap, idntExp,
		c.caches.SenderKey.Len(), signalSenderKeyCacheCap, sndkEvic, sndkCap, sndkExp,
		msgSecBlock,
		walltime.DecryptHistogram.Quantile(0.5),
		walltime.DecryptHistogram.Quantile(0.95),
		walltime.DecryptHistogram.Quantile(0.99),
		walltime.DecryptHistogram.Count(),
	)
}

// CacheLens returns live entry counts for all six signal caches.
// A -1 value means the cache is not wired (nil pointer) — distinguishable from
// an empty (0-entry) warm cache. Used by manager.go DebugStats to expose cache
// sizes without requiring a pprof.
//
// Nil-guard discipline follows the existing msgSecBlock pattern in
// formatCacheMetrics (lines 696-706 above): each field checked independently
// so a partially-constructed Container never panics.
func (c *Container) CacheLens() map[string]int {
	lens := map[string]int{
		"sk_bytes":   -1,
		"session":    -1,
		"identity":   -1,
		"sk_devices": -1,
		"msg_secret": -1,
		"sk_parsed":  -1,
	}
	if c.caches.SenderKey != nil {
		lens["sk_bytes"] = c.caches.SenderKey.Len()
	}
	if c.caches.Session != nil {
		lens["session"] = c.caches.Session.Len()
	}
	if c.caches.Identity != nil {
		lens["identity"] = c.caches.Identity.Len()
	}
	if c.caches.SenderKeyDevices != nil {
		lens["sk_devices"] = c.caches.SenderKeyDevices.Len()
	}
	if c.caches.MsgSecret != nil {
		lens["msg_secret"] = c.caches.MsgSecret.Len()
	}
	if c.caches.SKParsed != nil {
		lens["sk_parsed"] = c.caches.SKParsed.Len()
	}
	return lens
}

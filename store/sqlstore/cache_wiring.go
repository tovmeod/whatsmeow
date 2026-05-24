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
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/store"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// Shared LRU capacities for the three signal-store caches. 100k entries each
// puts the total memory budget at ~300 MB under mean value sizes — still
// under the workspace's 500 MB cache budget; re-validate post-deploy per
// ROADMAP Phase 17.5.1 caution #1. Tune here if the cardinality profile
// drifts.
const (
	signalSessionCacheCap   = 100_000
	signalIdentityCacheCap  = 100_000
	signalSenderKeyCacheCap = 100_000
)

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

	// Phase 17.5: cross-cache eviction counters incremented by the
	// lru.NewWithEvict callbacks in wireSignalCaches. Surfaced via
	// emitMetricsLoop.
	SessionEvictions, IdentityEvictions, SenderKeyEvictions uint64

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
	c.caches.Session, err = lru.NewWithEvict[string, []byte](signalSessionCacheCap, func(string, []byte) { atomic.AddUint64(&c.caches.SessionEvictions, 1) })
	if err != nil {
		log.Errorf("Failed to construct SessionCache (cap=%d): %v", signalSessionCacheCap, err)
		panic(err)
	}
	c.caches.Identity, err = lru.NewWithEvict[string, *[32]byte](signalIdentityCacheCap, func(string, *[32]byte) { atomic.AddUint64(&c.caches.IdentityEvictions, 1) })
	if err != nil {
		log.Errorf("Failed to construct IdentityCache (cap=%d): %v", signalIdentityCacheCap, err)
		panic(err)
	}
	c.caches.SenderKey, err = lru.NewWithEvict[string, []byte](signalSenderKeyCacheCap, func(string, []byte) { atomic.AddUint64(&c.caches.SenderKeyEvictions, 1) })
	if err != nil {
		log.Errorf("Failed to construct SenderKeyCache (cap=%d): %v", signalSenderKeyCacheCap, err)
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
func attachCachedStores(c *Container, device *store.Device, innerStore *SQLStore) {
	jid := device.ID.String()
	device.Sessions = NewCachedSessionStore(innerStore, jid, c.caches.Session)
	device.Identities = NewCachedIdentityStore(innerStore, jid, c.caches.Identity)
	device.SenderKeys = NewCachedSenderKeyStore(innerStore, jid, c.caches.SenderKey)
}

// closeSignalCaches cancels the metrics-loop ctx so emitMetricsLoop exits
// before db/logger teardown. Nil-guarded so Close stays safe on a
// partially-constructed Container (test struct literals that never went
// through wireSignalCaches).
func closeSignalCaches(c *Container) {
	if c.caches.metricsCancel != nil {
		c.caches.metricsCancel()
	}
}

// emitMetricsLoop periodically logs Container-level cache state. Runs as a
// long-lived goroutine spawned by wireSignalCaches; cadence is 5 minutes.
// Phase 17.5 FIX: the per-wrapper registry and its hit/miss/coalesced/
// flushed/deduped aggregation were removed along with the write-back
// machinery; the loop now reports only what the Container itself owns
// (per-cache Len + eviction counters). Per-wrapper Stats() remains
// callable from tests but is no longer aggregated here.
func (c *Container) emitMetricsLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		c.log.Infof(
			"Cache metrics: sessions={len=%d, cap=%d, evictions=%d} identities={len=%d, cap=%d, evictions=%d} sender_keys={len=%d, cap=%d, evictions=%d}",
			c.caches.Session.Len(), signalSessionCacheCap, atomic.LoadUint64(&c.caches.SessionEvictions),
			c.caches.Identity.Len(), signalIdentityCacheCap, atomic.LoadUint64(&c.caches.IdentityEvictions),
			c.caches.SenderKey.Len(), signalSenderKeyCacheCap, atomic.LoadUint64(&c.caches.SenderKeyEvictions),
		)
	}
}

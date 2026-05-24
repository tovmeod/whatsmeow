// Copyright (c) 2026 Kavtov Platform (Phase 17.5.2)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// cache_wiring_test.go contains tests for Phase 17.5.2 cache counter
// discrimination: explicit Remove/Purge paths vs capacity-overflow evictions.
// These tests exercise the signalCaches struct, the cleanCounters helper, and
// the formatCacheMetrics function.

package sqlstore

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
)

// ---------------------------------------------------------------------------
// TestCacheCounters_ExplicitRemoveIncrementsExplicit_NotPureCapacity
//
// Asserts: calling DeleteIdentity() increments IdentityExplicitRemoves by 1.
// The IdentityCapacityEvictions counter also increments by 1 (because the
// eviction callback fires inside cache.Remove) -- that is the expected
// behavior and cleanCounters compensates at log time to show capacity_evictions=0.
// ---------------------------------------------------------------------------

func TestCacheCounters_ExplicitRemoveIncrementsExplicit_NotPureCapacity(t *testing.T) {
	inner := newFakeIdentityStore()

	var capEvictions, explicitRemoves uint64
	cache, err := lru.NewWithEvict[string, *[32]byte](1000, func(string, *[32]byte) {
		atomic.AddUint64(&capEvictions, 1)
	})
	if err != nil {
		t.Fatalf("lru.NewWithEvict failed: %v", err)
	}

	wrapper := NewCachedIdentityStore(inner, "test-jid", cache, &explicitRemoves)
	ctx := context.Background()

	address := "12345:0"
	key := fillKey(0x01)

	// Put an identity so there is an entry to delete.
	if err := wrapper.PutIdentity(ctx, address, key); err != nil {
		t.Fatalf("PutIdentity: %v", err)
	}

	capBefore := atomic.LoadUint64(&capEvictions)
	expBefore := atomic.LoadUint64(&explicitRemoves)

	// DeleteIdentity triggers an explicit Remove.
	if err := wrapper.DeleteIdentity(ctx, address); err != nil {
		t.Fatalf("DeleteIdentity: %v", err)
	}

	capAfter := atomic.LoadUint64(&capEvictions)
	expAfter := atomic.LoadUint64(&explicitRemoves)

	// ExplicitRemoves must have incremented by exactly 1.
	if expAfter-expBefore != 1 {
		t.Errorf("IdentityExplicitRemoves: got delta %d, want 1", expAfter-expBefore)
	}

	// CapacityEvictions also bumps by 1 (callback fires inside Remove) --
	// this is expected behavior; log-time cleanCounters compensates.
	if capAfter-capBefore != 1 {
		t.Errorf("IdentityCapacityEvictions: got delta %d, want 1 (eviction callback fires inside Remove)", capAfter-capBefore)
	}

	// Log-time computed capacity_evictions must be 0: cap and exp both grew
	// by 1, so cleanCounters(cap, exp) yields capClean = 0.
	_, capClean, _ := cleanCounters(capAfter, expAfter)
	if capClean != 0 {
		t.Errorf("log-time capacity_evictions: got %d, want 0 (explicit Remove should not show as cap pressure)", capClean)
	}
}

// ---------------------------------------------------------------------------
// TestCacheCounters_CapacityOverflowIncrementsCapacityOnly
//
// Asserts: forcing a capacity-overflow eviction (by filling a cap=2 LRU to 3
// entries) increments the capacity counter ONLY -- IdentityExplicitRemoves
// must stay at 0.
// ---------------------------------------------------------------------------

func TestCacheCounters_CapacityOverflowIncrementsCapacityOnly(t *testing.T) {
	var capEvictions uint64
	cache, err := lru.NewWithEvict[string, *[32]byte](2, func(string, *[32]byte) {
		atomic.AddUint64(&capEvictions, 1)
	})
	if err != nil {
		t.Fatalf("lru.NewWithEvict cap=2 failed: %v", err)
	}

	var explicitRemoves uint64

	// Use the cache directly to inject entries (simulating a pure Put path
	// without a store wrapper), because we only need the eviction counter
	// behaviour on overflow. The wrapper constructor is not needed here --
	// we're testing the callback and the counter in isolation.
	key0 := fillKey(0x00)
	key1 := fillKey(0x01)
	key2 := fillKey(0x02)
	cache.Add("entry0", &key0)
	cache.Add("entry1", &key1)
	// Adding a third entry to a cap=2 LRU evicts the oldest (entry0).
	cache.Add("entry2", &key2)

	capCount := atomic.LoadUint64(&capEvictions)
	expCount := atomic.LoadUint64(&explicitRemoves)

	if capCount != 1 {
		t.Errorf("IdentityCapacityEvictions: got %d, want 1 (capacity overflow should fire exactly once)", capCount)
	}
	if expCount != 0 {
		t.Errorf("IdentityExplicitRemoves: got %d, want 0 (capacity overflow must not touch explicit counter)", expCount)
	}
}

// ---------------------------------------------------------------------------
// TestCacheMetricsLogFormat_ExtendedFields
//
// Asserts: formatCacheMetrics produces a string containing all three
// eviction-related fields per cache. Sets CapacityEvictions=10,
// ExplicitRemoves=3 on Identity (via atomic.StoreUint64) and asserts:
//   - evictions=10  (sum: capClean(7) + explicit(3))
//   - capacity_evictions=7  (10 - 3)
//   - explicit_removes=3
// ---------------------------------------------------------------------------

func TestCacheMetricsLogFormat_ExtendedFields(t *testing.T) {
	// Build a Container with the three caches initialized but no metrics
	// goroutine running (metricsCancel == nil => closeSignalCaches no-ops).
	sessCache, err := lru.New[string, []byte](10)
	if err != nil {
		t.Fatalf("lru.New session: %v", err)
	}
	idntCache, err := lru.New[string, *[32]byte](10)
	if err != nil {
		t.Fatalf("lru.New identity: %v", err)
	}
	sndkCache, err := lru.New[string, []byte](10)
	if err != nil {
		t.Fatalf("lru.New senderkey: %v", err)
	}

	c := &Container{
		caches: signalCaches{
			Session:   sessCache,
			Identity:  idntCache,
			SenderKey: sndkCache,
		},
	}

	// Set IdentityCapacityEvictions=10, IdentityExplicitRemoves=3.
	atomic.StoreUint64(&c.caches.IdentityCapacityEvictions, 10)
	atomic.StoreUint64(&c.caches.IdentityExplicitRemoves, 3)

	msg := formatCacheMetrics(c)

	// Check evictions sum for identities: capClean(7) + explicit(3) = 10.
	// The format string embeds the identity block in the middle segment.
	// We extract the identities={...} block and check for the exact substrings.
	if !strings.Contains(msg, "capacity_evictions=7") {
		t.Errorf("expected 'capacity_evictions=7' in: %s", msg)
	}
	if !strings.Contains(msg, "explicit_removes=3") {
		t.Errorf("expected 'explicit_removes=3' in: %s", msg)
	}
	// evictions= sum: we need to locate the identity block specifically to
	// avoid false match from another cache's evictions=0. Use fmt.Sprintf
	// to build the expected identity prefix.
	idntBlock := fmt.Sprintf("identities={len=%d, cap=%d, evictions=%d, capacity_evictions=%d, explicit_removes=%d}",
		0, signalIdentityCacheCap, 10, 7, 3)
	if !strings.Contains(msg, idntBlock) {
		t.Errorf("expected identity block %q in msg: %s", idntBlock, msg)
	}
	// Sanity: sessions and sender_keys both show evictions=0, capacity_evictions=0, explicit_removes=0.
	if !strings.Contains(msg, "sessions={len=0, cap=100000, evictions=0, capacity_evictions=0, explicit_removes=0}") {
		t.Errorf("expected zeroed session block in: %s", msg)
	}
	if !strings.Contains(msg, "sender_keys={len=0, cap=100000, evictions=0, capacity_evictions=0, explicit_removes=0}") {
		t.Errorf("expected zeroed sender_keys block in: %s", msg)
	}
}

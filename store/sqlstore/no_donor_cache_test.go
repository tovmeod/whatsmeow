// Copyright (c) 2026 Kavtov Platform (Phase 38.6-01)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// no_donor_cache_test.go — unit tests for the Phase 38.6-01 negative-donor cache
// in TryInlineRecovery (recovery_sender_key.go).
//
// Three cases:
//  (a) cache-hit-skips-scan: two sequential TryInlineRecovery calls for the same
//      (group, senderBare, keyID) with a no-donor stub → findSenderKeyDonor is
//      invoked ONCE; the second call is served from the cache.
//  (b) TTL-expiry-re-scans: after the cache entry is back-dated past
//      noDonorCacheTTL, the next call re-scans (findSenderKeyDonor called again).
//  (c) found-donor-not-cached: when the stub returns a donor, the cache is NOT
//      populated; subsequent calls keep scanning.
//
// All tests are hermetic: noDonorCache is reset between tests via deleteFromNoDonorCache.
// No DB required (uses stubRecoveryInner from recovery_sender_key_internal_test.go,
// same package).

package sqlstore

import (
	"context"
	"testing"
	"time"
)

// resetNoDonorCacheForTest replaces the package cache to prevent cross-test bleed.
func resetNoDonorCacheForTest() {
	resetNoDonorCacheWithCapacityForTest(noDonorCacheCapacity)
}

func resetNoDonorCacheWithCapacityForTest(capacity int) {
	noDonorCacheMu.Lock()
	defer noDonorCacheMu.Unlock()
	noDonorCache = mustNewNoDonorCache(capacity)
	donorWaves = make(map[donorQueryKey]*donorWave)
	donorFlights = make(map[donorWorkKey]*donorFlight)
	donorWorkCapacity = noDonorCacheCapacity
	donorClock = time.Now
	noDonorCacheSkips.Store(0)
	noDonorCacheEvictions.Store(0)
	noDonorCacheQueries.Store(0)
	noDonorCacheExpired.Store(0)
	noDonorCacheInvalidations.Store(0)
	noDonorCacheOverflow.Store(0)
	donorSFTotal.Store(0)
	donorSFShared.Store(0)
}

// backdateNoDonorCache overwrites the stored time for key with a time that is
// stale by more than noDonorCacheTTL. Used to simulate TTL expiry without
// sleeping.
func backdateNoDonorCache(key donorQueryKey) {
	noDonorCacheMu.Lock()
	defer noDonorCacheMu.Unlock()
	noDonorCache.Add(key, noDonorCacheEntry{
		expiresAt: time.Now().Add(-(noDonorCacheTTL + time.Second)),
	})
}

// TestNoDonorCacheHitSkipsScan verifies case (a): two sequential
// TryInlineRecovery calls for the same key with a no-donor stub result in
// findSenderKeyDonor being called exactly once (the second call hits the cache).
func TestNoDonorCacheHitSkipsScan(t *testing.T) {
	resetNoDonorCacheForTest()

	const (
		group      = "cachetest_group@g.us"
		senderBare = "55512340001_1"
		targetID   = senderBare + ":0"
		keyID      = uint32(101)
	)

	// Stub returns nil donor (no-donor scenario).
	stub := &stubRecoveryInner{donor: nil}
	cs := newStubCachedStore(t, stub, nil)

	ctx := context.Background()

	// First call: cache miss → scan runs → entry stored.
	_, ok1, err1 := cs.TryInlineRecovery(ctx, group, targetID, senderBare, keyID, 50)
	if err1 != nil {
		t.Fatalf("call 1: TryInlineRecovery: %v", err1)
	}
	if ok1 {
		t.Error("call 1: want ok=false (no donor), got true")
	}
	if got := stub.findCalls.Load(); got != 1 {
		t.Errorf("call 1: findSenderKeyDonor called %d times, want 1", got)
	}

	// Second call: cache hit → scan skipped.
	_, ok2, err2 := cs.TryInlineRecovery(ctx, group, targetID, senderBare, keyID, 50)
	if err2 != nil {
		t.Fatalf("call 2: TryInlineRecovery: %v", err2)
	}
	if ok2 {
		t.Error("call 2: want ok=false (served from cache), got true")
	}
	if got := stub.findCalls.Load(); got != 1 {
		t.Errorf("call 2: findSenderKeyDonor called %d times total, want still 1 (second call must use cache)", got)
	}
}

// TestNoDonorCacheTTLExpiryRescans verifies case (b): after the cache entry is
// artificially aged past noDonorCacheTTL, the next TryInlineRecovery call
// re-runs the donor scan.
func TestNoDonorCacheTTLExpiryRescans(t *testing.T) {
	resetNoDonorCacheForTest()

	const (
		group      = "ttltest_group@g.us"
		senderBare = "55512340002_1"
		targetID   = senderBare + ":0"
		keyID      = uint32(102)
	)

	stub := &stubRecoveryInner{donor: nil}
	cs := newStubCachedStore(t, stub, nil)

	ctx := context.Background()

	// First call: populates the cache.
	_, _, _ = cs.TryInlineRecovery(ctx, group, targetID, senderBare, keyID, 50)
	if got := stub.findCalls.Load(); got != 1 {
		t.Fatalf("setup: findSenderKeyDonor called %d times, want 1", got)
	}

	// Backdate the cache entry so it appears expired.
	sfKey := cs.donorKey(group, senderBare, keyID)
	backdateNoDonorCache(sfKey)

	// Second call: expired entry → re-scan.
	_, ok, err := cs.TryInlineRecovery(ctx, group, targetID, senderBare, keyID, 50)
	if err != nil {
		t.Fatalf("call after expiry: TryInlineRecovery: %v", err)
	}
	if ok {
		t.Error("call after expiry: want ok=false (no donor), got true")
	}
	if got := stub.findCalls.Load(); got != 2 {
		t.Errorf("call after expiry: findSenderKeyDonor called %d times total, want 2 (re-scan after TTL)", got)
	}
}

// TestNoDonorCacheFoundDonorNotCached verifies case (c): when the stub returns
// a found donor, the negative cache is NOT populated. Subsequent calls keep
// scanning (no false-negative suppression of a working recovery).
func TestNoDonorCacheFoundDonorNotCached(t *testing.T) {
	resetNoDonorCacheForTest()

	const (
		group      = "postest_group@g.us"
		senderBare = "55512340003_1"
		targetID   = senderBare + ":0"
		keyID      = uint32(103)
	)

	// Stub returns a valid donor.
	stub := &stubRecoveryInner{donor: stubDonor(keyID, 10)}
	cs := newStubCachedStore(t, stub, nil)

	ctx := context.Background()

	// First call: donor found → ok=true, cache NOT populated.
	_, ok1, err1 := cs.TryInlineRecovery(ctx, group, targetID, senderBare, keyID, 50)
	if err1 != nil {
		t.Fatalf("call 1: TryInlineRecovery: %v", err1)
	}
	if !ok1 {
		t.Error("call 1: want ok=true (donor found), got false")
	}

	// Verify no entry was stored in the negative cache for this key.
	sfKey := cs.donorKey(group, senderBare, keyID)
	if getNoDonorCacheEntry(sfKey, 50, time.Now()) {
		t.Error("found-donor path must NOT populate noDonorCache, but an entry was stored")
	}

	// Second call: the negative cache must NOT suppress the scan (since a donor
	// was found in call 1). The scan runs again → findSenderKeyDonor called at
	// least twice in total. ok may be false on call 2 if the iteration guard
	// fires (the stored state from call 1 is now cache-resident and the donor
	// iter is not strictly greater), but the important invariant is that the
	// SCAN itself is not skipped.
	_, _, err2 := cs.TryInlineRecovery(ctx, group, targetID, senderBare, keyID, 50)
	if err2 != nil {
		t.Fatalf("call 2: TryInlineRecovery: %v", err2)
	}
	if got := stub.findCalls.Load(); got < 2 {
		t.Errorf("want >= 2 findSenderKeyDonor calls (positive result must not populate negative cache), got %d", got)
	}
}

func TestNoDonorCacheFixedTTLAcrossIterations(t *testing.T) {
	resetNoDonorCacheForTest()
	t.Cleanup(resetNoDonorCacheForTest)
	now := time.Now()
	donorClock = func() time.Time { return now }

	const (
		group      = "iteration-bound@g.us"
		senderBare = "55512340004_1"
		targetID   = senderBare + ":0"
		keyID      = uint32(104)
	)
	stub := &stubRecoveryInner{
		donorForTarget: func(targetIter uint32) *donorSenderKeyState {
			if targetIter >= 10 {
				return stubDonor(keyID, 10)
			}
			return nil
		},
	}
	cs := newStubCachedStore(t, stub, nil)

	_, lowerOK, lowerErr := cs.TryInlineRecovery(context.Background(), group, targetID, senderBare, keyID, 5)
	if lowerErr != nil {
		t.Fatalf("target-5 call: %v", lowerErr)
	}
	if lowerOK {
		t.Error("target-5 call: want ok=false after a no-donor scan")
	}
	_, coveredOK, coveredErr := cs.TryInlineRecovery(context.Background(), group, targetID, senderBare, keyID, 4)
	if coveredErr != nil {
		t.Fatalf("target-4 call: %v", coveredErr)
	}
	if coveredOK {
		t.Error("target-4 call: want ok=false from the target-5 negative coverage")
	}
	if got := stub.findCalls.Load(); got != 1 {
		t.Fatalf("findSenderKeyDonor calls after covered target = %d, want 1", got)
	}

	_, higherOK, higherErr := cs.TryInlineRecovery(context.Background(), group, targetID, senderBare, keyID, 10)
	if higherErr != nil {
		t.Fatalf("target-10 call: %v", higherErr)
	}
	if higherOK {
		t.Error("target-10 call: want ok=false during the fixed target-5 absence window")
	}
	if got := stub.findCalls.Load(); got != 1 {
		t.Errorf("findSenderKeyDonor calls = %d, want 1 across advancing iterations", got)
	}
	first := now
	now = first.Add(noDonorCacheTTL - time.Nanosecond)
	_, _, _ = cs.TryInlineRecovery(context.Background(), group, targetID, senderBare, keyID, 6)
	if stub.findCalls.Load() != 1 {
		t.Fatal("scan before deadline")
	}
	now = first.Add(noDonorCacheTTL)
	_, recovered, err := cs.TryInlineRecovery(context.Background(), group, targetID, senderBare, keyID, 10)
	if err != nil || !recovered || stub.findCalls.Load() != 2 {
		t.Fatalf("equality must rescan and recover: recovered=%v calls=%d err=%v", recovered, stub.findCalls.Load(), err)
	}
}

func TestNoDonorCacheStoreAndTupleIdentity(t *testing.T) {
	resetNoDonorCacheForTest()
	t.Cleanup(resetNoDonorCacheForTest)
	stub := &stubRecoveryInner{}
	c := newStubCachedStore(t, stub, nil)
	otherRecipient := newStubCachedStore(t, stub, nil)
	otherRecipient.jid = "other-recipient"
	ctx := context.Background()
	_, _, _ = c.TryInlineRecovery(ctx, "g|x", "s_1:0", "s_1", 1, 5)
	_, _, _ = otherRecipient.TryInlineRecovery(ctx, "g|x", "s_1:9", "s_1:9", 1, 10)
	if stub.findCalls.Load() != 1 {
		t.Fatal("same universe recipients/device variants must share absence")
	}
	for _, tuple := range []struct {
		group, sender string
		key           uint32
	}{
		{"g", "x|s_1", 1}, {"g|x", "s_2", 1}, {"g|x", "s", 1}, {"g|x", "s_1", 2},
	} {
		_, _, _ = c.TryInlineRecovery(ctx, tuple.group, tuple.sender+":0", tuple.sender, tuple.key, 10)
	}
	if stub.findCalls.Load() != 5 {
		t.Fatalf("distinct tuple scans=%d want 5", stub.findCalls.Load())
	}
	other := &stubRecoveryInner{}
	secondStore := newStubCachedStore(t, other, nil)
	_, _, _ = secondStore.TryInlineRecovery(ctx, "g|x", "s_1:0", "s_1", 1, 5)
	if other.findCalls.Load() != 1 {
		t.Fatal("second store borrowed absence")
	}
	// SQLStore donor SQL has no recipient filter: only the Container is the universe.
	a, b := &Container{}, &Container{}
	c.inner = &SQLStore{Container: a}
	otherRecipient.inner = &SQLStore{Container: a}
	secondStore.inner = &SQLStore{Container: b}
	if c.donorKey("g", "s_1", 1) != otherRecipient.donorKey("g", "s_1", 1) {
		t.Fatal("Container recipients not shared")
	}
	if c.donorKey("g", "s_1", 1) == secondStore.donorKey("g", "s_1", 1) {
		t.Fatal("distinct Containers shared")
	}
}

func TestNoDonorCacheEvictionRescans(t *testing.T) {
	resetNoDonorCacheWithCapacityForTest(2)
	t.Cleanup(resetNoDonorCacheForTest)

	stub := &stubRecoveryInner{}
	cs := newStubCachedStore(t, stub, nil)
	const (
		senderBare = "55512340005_1"
		targetID   = senderBare + ":0"
		keyID      = uint32(105)
	)

	for _, group := range []string{"evict-a@g.us", "evict-b@g.us", "evict-c@g.us"} {
		_, ok, err := cs.TryInlineRecovery(context.Background(), group, targetID, senderBare, keyID, 10)
		if err != nil {
			t.Fatalf("insert %s: %v", group, err)
		}
		if ok {
			t.Errorf("insert %s: want ok=false for no donor", group)
		}
	}
	if got := noDonorCacheEvictions.Load(); got == 0 {
		t.Error("want a bounded-cache eviction after inserting three entries into capacity two")
	}

	_, ok, err := cs.TryInlineRecovery(context.Background(), "evict-a@g.us", targetID, senderBare, keyID, 10)
	if err != nil {
		t.Fatalf("evicted re-scan: %v", err)
	}
	if ok {
		t.Error("evicted re-scan: want ok=false for no donor")
	}
	if got := stub.findCalls.Load(); got != 4 {
		t.Errorf("findSenderKeyDonor calls = %d, want 4 because the evicted key re-scans", got)
	}
}

func TestNoDonorCacheCapacityAndTelemetry(t *testing.T) {
	resetNoDonorCacheForTest()
	t.Cleanup(resetNoDonorCacheForTest)
	stub := &stubRecoveryInner{}
	c := newStubCachedStore(t, stub, nil)
	now := time.Now()
	donorClock = func() time.Time { return now }
	for i := uint32(0); i <= noDonorCacheCapacity; i++ {
		_, _, _ = c.TryInlineRecovery(context.Background(), "capacity", "s:0", "s", i, 5)
	}
	if noDonorCache.Len() != noDonorCacheCapacity || noDonorCacheEvictions.Load() != 1 {
		t.Fatal("negative LRU exceeded its unchanged cap")
	}
	key := uint32(noDonorCacheCapacity)
	_, _, _ = c.TryInlineRecovery(context.Background(), "capacity", "s:0", "s", key, 10)
	if noDonorCacheSkips.Load() != 1 || noDonorCacheQueries.Load() != noDonorCacheCapacity+1 {
		t.Fatal("hit/query totals incorrect")
	}
	now = now.Add(noDonorCacheTTL)
	_, _, _ = c.TryInlineRecovery(context.Background(), "capacity", "s:0", "s", key, 20)
	if noDonorCacheExpired.Load() != 1 || noDonorCacheQueries.Load() != noDonorCacheCapacity+2 {
		t.Fatal("expiry/query totals incorrect")
	}
	notifyDonorKeys(stub, "capacity", "s", []uint32{key})
	if noDonorCacheInvalidations.Load() != 1 {
		t.Fatal("invalidation total incorrect")
	}
	assertDonorIdle(t)
}

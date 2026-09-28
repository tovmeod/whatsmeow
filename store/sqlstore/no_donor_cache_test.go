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
	noDonorCacheSkips.Store(0)
	noDonorCacheEvictions.Store(0)
}

// backdateNoDonorCache overwrites the stored time for key with a time that is
// stale by more than noDonorCacheTTL. Used to simulate TTL expiry without
// sleeping.
func backdateNoDonorCache(key string) {
	noDonorCacheMu.Lock()
	defer noDonorCacheMu.Unlock()
	noDonorCache.Add(key, noDonorCacheEntry{
		expiresAt:             time.Now().Add(-(noDonorCacheTTL + time.Second)),
		maxNegativeTargetIter: ^uint32(0),
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
	sfKey := group + "|" + senderBare + "|" + "102"
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
	sfKey := group + "|" + senderBare + "|" + "103"
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

func TestNoDonorCacheIterationBound(t *testing.T) {
	resetNoDonorCacheForTest()
	t.Cleanup(resetNoDonorCacheForTest)

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
	if !higherOK {
		t.Error("target-10 call: want ok=true; target-5 negative must not suppress its eligible donor")
	}
	if got := stub.findCalls.Load(); got != 2 {
		t.Errorf("findSenderKeyDonor calls = %d, want 2 because target-10 is outside target-5 coverage", got)
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

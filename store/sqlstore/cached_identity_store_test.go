// Copyright (c) 2026 Kavtov Platform (Phase 17.5)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Compile-time conformance is asserted inside cached_identity_store.go via
//   var _ store.IdentityStore = (*CachedIdentityStore)(nil)
// A separate test below references the wrapper type to keep the assertion
// reachable from the test binary.

// ---------------------------------------------------------------------------
// Test helper: newTestCachedIdentityStore wires a fakeIdentityStore and an
// LRU cache of *[32]byte sized to capSize. The wrapper uses "test-jid"
// (no trailing pipe) as the JID — matching production usage at
// container.go:363 where the JID comes from `device.ID.String()` without
// a trailing pipe. The wrapper composes the full cache key internally as
// `jid + "|" + address`, producing single-pipe keys
// (`"test-jid|<address>"`).
//
// Address fixtures passed to the wrapper's methods use the bare libsignal
// format (e.g. `"addr-A"`, or in the production analog
// `"<SignalAddressUser>:<device>"`). Tests MUST NOT pre-compose addresses
// with the JID or with a trailing pipe — that would produce double-pipe
// or other malformed cache keys that disagree with the production code
// path. (Phase 17.5 FIX2 IN-01.)
// ---------------------------------------------------------------------------

func newTestCachedIdentityStore(t *testing.T, capSize int) (*CachedIdentityStore, *fakeIdentityStore) {
	t.Helper()
	inner := newFakeIdentityStore()
	cache, err := lru.New[string, *[32]byte](capSize)
	if err != nil {
		t.Fatalf("lru.New[string, *[32]byte] failed: %v", err)
	}
	// "test-jid" with no trailing pipe — wrapper's key() prepends the
	// separator. Matches production format used by Container.initializeDevice.
	// explicitRemoves: a local dummy counter — these tests exercise caching
	// logic, not Container-level counter discrimination (Phase 17.5.2).
	var dummyExplicitRemoves uint64
	wrapper := NewCachedIdentityStore(inner, "test-jid", cache, &dummyExplicitRemoves, newIdentitySecondaryIndex())
	return wrapper, inner
}

// fillKey produces a deterministic [32]byte keyed by a single seed byte so
// tests can construct distinct identity keys without random.
func fillKey(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

// ---------------------------------------------------------------------------
// Compile-time conformance assertion reach test.
// ---------------------------------------------------------------------------

func TestCachedIdentityStore_InterfaceConformance(t *testing.T) {
	// Touching the type keeps the package-level
	//   var _ store.IdentityStore = (*CachedIdentityStore)(nil)
	// assertion reachable; if the wrapper drifts from the interface this test
	// (and the whole package) fails to compile.
	var c *CachedIdentityStore
	if c != nil {
		t.Fatal("nil pointer should stay nil")
	}
}

// ---------------------------------------------------------------------------
// IsTrustedIdentity miss: populates the cache via inner.getIdentityBytes;
// second call for the same address must NOT increment inner.isTrustedCalls.
// ---------------------------------------------------------------------------

func TestCachedIdentityStore_IsTrustedIdentity_MissPopulatesCache(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedIdentityStore(t, 16)
	k := fillKey(0xAB)
	if err := inner.PutIdentity(ctx, "addr-A", k); err != nil {
		t.Fatalf("seed inner.PutIdentity: %v", err)
	}
	// Reset counters consumed by seeding; we measure post-seed calls only.
	inner.putCalls.Store(0)
	inner.isTrustedCalls.Store(0)
	inner.getIdentityBytesCalls.Store(0)

	ok, err := c.IsTrustedIdentity(ctx, "addr-A", k)
	if err != nil {
		t.Fatalf("first IsTrustedIdentity: %v", err)
	}
	if !ok {
		t.Fatalf("first IsTrustedIdentity = false, want true")
	}
	// Populate path must call inner.getIdentityBytes once, NOT inner.IsTrustedIdentity.
	if got := inner.getIdentityBytesCalls.Load(); got != 1 {
		t.Errorf("inner.getIdentityBytesCalls = %d, want 1", got)
	}
	if got := inner.isTrustedCalls.Load(); got != 0 {
		t.Errorf("inner.isTrustedCalls = %d, want 0 (wrapper uses getIdentityBytes for populate-on-miss)", got)
	}

	// Second call must be served from the cache — no new inner calls.
	ok, err = c.IsTrustedIdentity(ctx, "addr-A", k)
	if err != nil {
		t.Fatalf("second IsTrustedIdentity: %v", err)
	}
	if !ok {
		t.Fatalf("second IsTrustedIdentity = false, want true")
	}
	if got := inner.getIdentityBytesCalls.Load(); got != 1 {
		t.Errorf("after cache hit: inner.getIdentityBytesCalls = %d, want 1 (no new call)", got)
	}
	if got := inner.isTrustedCalls.Load(); got != 0 {
		t.Errorf("after cache hit: inner.isTrustedCalls = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// IsTrustedIdentity for an absent row: returns (true, nil) per TOFU AND
// caches a nil sentinel so a second call also serves from cache.
// ---------------------------------------------------------------------------

func TestCachedIdentityStore_IsTrustedIdentity_AbsentRowReturnsTrueAndCachesNil(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedIdentityStore(t, 16)
	k := fillKey(0x11)

	ok, err := c.IsTrustedIdentity(ctx, "ghost-addr", k)
	if err != nil {
		t.Fatalf("first IsTrustedIdentity: %v", err)
	}
	if !ok {
		t.Fatalf("first IsTrustedIdentity = false, want true (TOFU pass-through)")
	}
	if got := inner.getIdentityBytesCalls.Load(); got != 1 {
		t.Errorf("inner.getIdentityBytesCalls = %d, want 1", got)
	}

	// Second call with a different key must STILL be served from cache as
	// "known absent" — the wrapper returns (true, nil) per TOFU and does
	// not re-query inner.
	k2 := fillKey(0x22)
	ok, err = c.IsTrustedIdentity(ctx, "ghost-addr", k2)
	if err != nil {
		t.Fatalf("second IsTrustedIdentity: %v", err)
	}
	if !ok {
		t.Fatalf("second IsTrustedIdentity = false, want true (cached absent sentinel)")
	}
	if got := inner.getIdentityBytesCalls.Load(); got != 1 {
		t.Errorf("after cached absent: inner.getIdentityBytesCalls = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// PutIdentity value-equal write-skip: PutIdentity(K) then PutIdentity(K) →
// inner.putCalls == 1, dedupedWrites == 1. Closes RESEARCH Pitfall 3
// (~99% identity_keys UPSERTs eliminated).
// ---------------------------------------------------------------------------

func TestCachedIdentityStore_PutIdentity_ValueEqualWriteSkipped(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedIdentityStore(t, 16)
	k := fillKey(0x42)

	if err := c.PutIdentity(ctx, "addr-B", k); err != nil {
		t.Fatalf("first PutIdentity: %v", err)
	}
	if err := c.PutIdentity(ctx, "addr-B", k); err != nil {
		t.Fatalf("second PutIdentity: %v", err)
	}
	if got := inner.putCalls.Load(); got != 1 {
		t.Errorf("inner.putCalls = %d, want 1 (second PutIdentity with same K must be skipped)", got)
	}
	_, _, dedupedWrites := c.Stats()
	if dedupedWrites != 1 {
		t.Errorf("Stats dedupedWrites = %d, want 1", dedupedWrites)
	}
}

// ---------------------------------------------------------------------------
// PutIdentity value-changed write-through: PutIdentity(K1), PutIdentity(K2)
// (different K) → inner.putCalls == 2, cache reflects K2.
// ---------------------------------------------------------------------------

func TestCachedIdentityStore_PutIdentity_ValueChangedWritesThrough(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedIdentityStore(t, 16)
	k1 := fillKey(0xAA)
	k2 := fillKey(0xBB)

	if err := c.PutIdentity(ctx, "addr-C", k1); err != nil {
		t.Fatalf("PutIdentity k1: %v", err)
	}
	if err := c.PutIdentity(ctx, "addr-C", k2); err != nil {
		t.Fatalf("PutIdentity k2: %v", err)
	}
	if got := inner.putCalls.Load(); got != 2 {
		t.Errorf("inner.putCalls = %d, want 2 (changed value must write through)", got)
	}
	_, _, dedupedWrites := c.Stats()
	if dedupedWrites != 0 {
		t.Errorf("Stats dedupedWrites = %d, want 0 (no duplicate writes)", dedupedWrites)
	}
	// IsTrustedIdentity(k2) must be true (cache reflects k2) and must NOT
	// trigger an inner read.
	ok, err := c.IsTrustedIdentity(ctx, "addr-C", k2)
	if err != nil {
		t.Fatalf("IsTrustedIdentity after Put: %v", err)
	}
	if !ok {
		t.Fatalf("IsTrustedIdentity(k2) = false, want true (cache should hold k2)")
	}
	if got := inner.getIdentityBytesCalls.Load(); got != 0 {
		t.Errorf("inner.getIdentityBytesCalls = %d, want 0 (Put seeds cache)", got)
	}
	if got := inner.isTrustedCalls.Load(); got != 0 {
		t.Errorf("inner.isTrustedCalls = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// DeleteIdentity: removes cache entry; next IsTrustedIdentity must call inner.
// ---------------------------------------------------------------------------

func TestCachedIdentityStore_DeleteIdentity_RemovesFromCache(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedIdentityStore(t, 16)
	k := fillKey(0x55)
	if err := c.PutIdentity(ctx, "addr-D", k); err != nil {
		t.Fatalf("PutIdentity: %v", err)
	}
	if err := c.DeleteIdentity(ctx, "addr-D"); err != nil {
		t.Fatalf("DeleteIdentity: %v", err)
	}
	if got := inner.deleteCalls.Load(); got != 1 {
		t.Errorf("inner.deleteCalls = %d, want 1", got)
	}
	// Inner store now empty for addr-D; next IsTrustedIdentity must fall through
	// (getIdentityBytes increments because populate-on-miss is the read path).
	inner.getIdentityBytesCalls.Store(0)
	if _, err := c.IsTrustedIdentity(ctx, "addr-D", k); err != nil {
		t.Fatalf("IsTrustedIdentity after Delete: %v", err)
	}
	if got := inner.getIdentityBytesCalls.Load(); got != 1 {
		t.Errorf("inner.getIdentityBytesCalls = %d, want 1 (cache must be cleared after Delete)", got)
	}
}

// ---------------------------------------------------------------------------
// DeleteAllIdentities: under Phase 17.5.3 prefix-scan semantics, the inner
// SQL DELETE always runs (delegates to inner.DeleteAllIdentities), but the
// cache is only touched for keys matching `<c.jid>|<phone>:`. If no cache
// key matches the target phone, the cache is left intact — which is the
// correct mirror of the SQL predicate (rows matching the LIKE clause are
// already absent from the inner store, nothing to invalidate in cache).
// The pre-17.5.3 implementation wiped every other phone's entries on every
// <identity/> notification — see 17.5.3-RCA-IDENTITIES-CACHE.md.
// ---------------------------------------------------------------------------

func TestCachedIdentityStore_DeleteAllIdentities_DelegatesToInner_NoMatchingPrefix_LeavesCache(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedIdentityStore(t, 16)
	for i, addr := range []string{"addr-1", "addr-2", "addr-3"} {
		if err := c.PutIdentity(ctx, addr, fillKey(byte(i+1))); err != nil {
			t.Fatalf("PutIdentity %s: %v", addr, err)
		}
	}
	if got := c.cache.Len(); got != 3 {
		t.Fatalf("pre-DeleteAll cache Len = %d, want 3", got)
	}
	// "phone-X" does not match any of the seeded addresses (none of
	// "addr-1/2/3" begins with "phone-X:"), so the prefix-scan must leave
	// the cache untouched even though the inner delegate is still invoked.
	if err := c.DeleteAllIdentities(ctx, "phone-X"); err != nil {
		t.Fatalf("DeleteAllIdentities: %v", err)
	}
	if got := inner.deleteAllCalls.Load(); got != 1 {
		t.Errorf("inner.deleteAllCalls = %d, want 1", got)
	}
	if got := c.cache.Len(); got != 3 {
		t.Errorf("post-DeleteAll cache Len = %d, want 3 (no matching prefix means no cache removal)", got)
	}
}

// ---------------------------------------------------------------------------
// Phase 17.5.3 RCA: DeleteAllIdentities(phoneA) must NOT drop cache entries
// for phoneB on the same wrapper. The previous implementation purged every
// entry in the shared LRU on every <identity/> notification, undoing the
// Phase 17.5 cache benefit for all unrelated remote phones.
// ---------------------------------------------------------------------------

func TestCachedIdentityStore_DeleteAllIdentities_RemovesOnlyMatchingPhonePrefix(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedIdentityStore(t, 32)

	// Address format mirrors libsignal: "<phone>:<device>". The wrapper's
	// prefix-scan matches `<c.jid>|<phone>:` exactly — same shape used in
	// production for identity_keys rows.
	addrsA := []string{"111:0", "111:1"}
	addrsB := []string{"222:0", "222:1"}
	for i, addr := range addrsA {
		if err := c.PutIdentity(ctx, addr, fillKey(byte(0xA0+i))); err != nil {
			t.Fatalf("seed PutIdentity A %s: %v", addr, err)
		}
	}
	for i, addr := range addrsB {
		if err := c.PutIdentity(ctx, addr, fillKey(byte(0xB0+i))); err != nil {
			t.Fatalf("seed PutIdentity B %s: %v", addr, err)
		}
	}
	if got := c.cache.Len(); got != 4 {
		t.Fatalf("pre-DeleteAll cache Len = %d, want 4", got)
	}

	if err := c.DeleteAllIdentities(ctx, "111"); err != nil {
		t.Fatalf("DeleteAllIdentities: %v", err)
	}
	if got := inner.deleteAllCalls.Load(); got != 1 {
		t.Errorf("inner.deleteAllCalls = %d, want 1", got)
	}

	// PhoneA entries must be removed; phoneB entries must survive.
	for _, addr := range addrsA {
		if _, ok := c.cache.Get("test-jid|" + addr); ok {
			t.Errorf("cache still holds %q after DeleteAllIdentities(111)", addr)
		}
	}
	for _, addr := range addrsB {
		if _, ok := c.cache.Get("test-jid|" + addr); !ok {
			t.Errorf("cache lost unrelated entry %q after DeleteAllIdentities(111)", addr)
		}
	}
}

// ---------------------------------------------------------------------------
// Phase 17.5.3 RCA (cross-jid scope): DeleteAllIdentities on a
// CachedIdentityStore bound to jid-A must NOT touch entries under jid-B in
// the same process-shared LRU. The previous implementation called the
// LRU's bulk Purge which wiped both; the prefix-scan limits removals to
// keys starting with `<c.jid>|<phone>:`.
//
// This test builds the wrapper inline (skipping newTestCachedIdentityStore)
// so it can hold a reference to the shared LRU and inject a sibling-device
// entry under a different jid prefix — same pattern as
// TestCachedSessionStore_DeleteAllSessions_DoesNotTouchOtherJIDs.
// ---------------------------------------------------------------------------

func TestCachedIdentityStore_DeleteAllIdentities_OtherJIDEntriesSurvive(t *testing.T) {
	ctx := context.Background()
	cache, err := lru.New[string, *[32]byte](32)
	if err != nil {
		t.Fatalf("lru.New[string, *[32]byte] failed: %v", err)
	}
	inner := newFakeIdentityStore()
	var dummyA uint64
	cA := NewCachedIdentityStore(inner, "jid-A", cache, &dummyA, newIdentitySecondaryIndex())

	// Seed cA's wrapper under jid-A for phone 111.
	if err := cA.PutIdentity(ctx, "111:0", fillKey(0x01)); err != nil {
		t.Fatalf("seed cA.PutIdentity: %v", err)
	}
	// Inject a sibling-device entry directly into the shared LRU under
	// jid-B. Simulates a second CachedIdentityStore wrapper that shares
	// the process-LRU.
	keyB := fillKey(0x99)
	cache.Add("jid-B|111:0", &keyB)

	if got := cache.Len(); got != 2 {
		t.Fatalf("pre-DeleteAll cache Len = %d, want 2", got)
	}

	if err := cA.DeleteAllIdentities(ctx, "111"); err != nil {
		t.Fatalf("DeleteAllIdentities: %v", err)
	}

	if _, ok := cache.Get("jid-A|111:0"); ok {
		t.Errorf("cache still holds jid-A|111:0 after DeleteAllIdentities (own scope must be removed)")
	}
	if _, ok := cache.Get("jid-B|111:0"); !ok {
		t.Errorf("DeleteAllIdentities removed an entry under a different JID prefix — must be JID-scoped")
	}
	if dummyA != 1 {
		t.Errorf("dummyA (explicitRemoves for jid-A) = %d, want 1 (one matching key removed)", dummyA)
	}
}

// ---------------------------------------------------------------------------
// Race test: N=50 goroutines, mixed Put/IsTrustedIdentity/Delete on
// overlapping addresses. Must run clean under `go test -race` and must
// not deadlock.
// ---------------------------------------------------------------------------

func TestCachedIdentityStore_Race_50Goroutines(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCachedIdentityStore(t, 64)

	const G = 50
	const N = 100
	var wg sync.WaitGroup
	wg.Add(G)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	for g := 0; g < G; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < N; i++ {
				addr := fmt.Sprintf("addr-%d", (g+i)%10) // overlapping keyspace
				k := fillKey(byte((g + i) % 256))
				switch i % 3 {
				case 0:
					_, _ = c.IsTrustedIdentity(ctx, addr, k)
				case 1:
					_ = c.PutIdentity(ctx, addr, k)
				case 2:
					_ = c.DeleteIdentity(ctx, addr)
				}
			}
		}()
	}
	select {
	case <-done:
		// ok
	case <-time.After(10 * time.Second):
		t.Fatal("race test deadlocked (10s)")
	}
}

// ---------------------------------------------------------------------------
// R3: explicit_removes counter delta equals number of cache entries removed
// by DeleteAllIdentities.
// ---------------------------------------------------------------------------

func TestCachedIdentityStore_DeleteAllIdentities_ExplicitRemovesDelta_EqualsRemoved(t *testing.T) {
	ctx := context.Background()
	idx := newIdentitySecondaryIndex()
	var explicitRemovesA uint64
	cacheWithEvict, err := lru.NewWithEvict[string, *[32]byte](1000, func(key string, _ *[32]byte) {
		if jid, phone, ok := parseCacheKey(key); ok {
			idx.EvictCleanup(key, jid, phone)
		}
	})
	if err != nil {
		t.Fatalf("lru.NewWithEvict failed: %v", err)
	}
	innerA := newFakeIdentityStore()
	cA := NewCachedIdentityStore(innerA, "jid-A", cacheWithEvict, &explicitRemovesA, idx)

	// Build a second wrapper sharing the same cache + index (different jid).
	var explicitRemovesB uint64
	innerB := newFakeIdentityStore()
	cB := NewCachedIdentityStore(innerB, "jid-B", cacheWithEvict, &explicitRemovesB, idx)

	// Populate 4 entries under "111" on cA.
	for d := 0; d < 4; d++ {
		addr := fmt.Sprintf("111:%d", d)
		if err := cA.PutIdentity(ctx, addr, fillKey(byte(0xA0+d))); err != nil {
			t.Fatalf("cA.PutIdentity 111:%d: %v", d, err)
		}
	}
	// Populate 2 entries under "222" on cA (same jid, different phone).
	for d := 0; d < 2; d++ {
		addr := fmt.Sprintf("222:%d", d)
		if err := cA.PutIdentity(ctx, addr, fillKey(byte(0xB0+d))); err != nil {
			t.Fatalf("cA.PutIdentity 222:%d: %v", d, err)
		}
	}
	// Populate 3 entries under "111" on cB (different jid, must survive).
	for d := 0; d < 3; d++ {
		addr := fmt.Sprintf("111:%d", d)
		if err := cB.PutIdentity(ctx, addr, fillKey(byte(0xC0+d))); err != nil {
			t.Fatalf("cB.PutIdentity 111:%d: %v", d, err)
		}
	}

	before := atomic.LoadUint64(&explicitRemovesA)

	if err := cA.DeleteAllIdentities(ctx, "111"); err != nil {
		t.Fatalf("DeleteAllIdentities: %v", err)
	}

	after := atomic.LoadUint64(&explicitRemovesA)
	if delta := after - before; delta != 4 {
		t.Errorf("explicitRemovesA delta = %d, want 4 (one per removed cache entry)", delta)
	}

	// inner.deleteAllCalls must be 1.
	if got := innerA.deleteAllCalls.Load(); got != 1 {
		t.Errorf("innerA.deleteAllCalls = %d, want 1", got)
	}

	// "222" entries under jid-A must survive.
	for d := 0; d < 2; d++ {
		ck := fmt.Sprintf("jid-A|222:%d", d)
		if _, ok := cacheWithEvict.Get(ck); !ok {
			t.Errorf("cache lost jid-A|222:%d after DeleteAllIdentities(111)", d)
		}
	}
	// "jid-B|111" entries (cB) must survive.
	for d := 0; d < 3; d++ {
		ck := fmt.Sprintf("jid-B|111:%d", d)
		if _, ok := cacheWithEvict.Get(ck); !ok {
			t.Errorf("cache lost cross-wrapper entry jid-B|111:%d (cross-wrapper isolation violated)", d)
		}
	}
	// explicitRemovesB must be untouched.
	if explicitRemovesB != 0 {
		t.Errorf("explicitRemovesB = %d, want 0 (jid-B entries not removed)", explicitRemovesB)
	}
}

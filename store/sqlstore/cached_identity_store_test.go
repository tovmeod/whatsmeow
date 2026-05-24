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
	wrapper := NewCachedIdentityStore(inner, "test-jid", cache)
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
// DeleteAllIdentities: bulk purge — cache Len() drops to 0.
// ---------------------------------------------------------------------------

func TestCachedIdentityStore_DeleteAllIdentities_PurgesCache(t *testing.T) {
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
	if err := c.DeleteAllIdentities(ctx, "phone-X"); err != nil {
		t.Fatalf("DeleteAllIdentities: %v", err)
	}
	if got := inner.deleteAllCalls.Load(); got != 1 {
		t.Errorf("inner.deleteAllCalls = %d, want 1", got)
	}
	if got := c.cache.Len(); got != 0 {
		t.Errorf("post-DeleteAll cache Len = %d, want 0 (Purge expected)", got)
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

// Copyright (c) 2026 Kavtov Platform (Phase 17.5)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/types"
)

// Compile-time conformance is asserted inside cached_session_store.go via
//   var _ store.SessionStore = (*CachedSessionStore)(nil)
// A separate test below references the wrapper type to keep the assertion
// reachable from the test binary.

// ---------------------------------------------------------------------------
// Test helper: newTestCachedSessionStore wires a fakeSessionStore, three
// fresh LRU caches (sessions/identities/sender_keys), and a stub *Container
// literal carrying all three caches. The 4-arg NewCachedSessionStore
// constructor takes (inner, jid, sessionCache, container).
// ---------------------------------------------------------------------------

func newTestCachedSessionStore(t *testing.T, capSize int) (*CachedSessionStore, *fakeSessionStore, *Container) {
	t.Helper()
	inner := newFakeSessionStore()
	sessionCache, err := lru.New[string, []byte](capSize)
	if err != nil {
		t.Fatalf("lru.New[string, []byte] failed: %v", err)
	}
	identityCache, err := lru.New[string, *[32]byte](capSize)
	if err != nil {
		t.Fatalf("lru.New[string, *[32]byte] failed: %v", err)
	}
	senderKeyCache, err := lru.New[string, []byte](capSize)
	if err != nil {
		t.Fatalf("lru.New[string, []byte] (sender) failed: %v", err)
	}
	container := &Container{
		SessionCache:   sessionCache,
		IdentityCache:  identityCache,
		SenderKeyCache: senderKeyCache,
	}
	wrapper := NewCachedSessionStore(inner, "test-jid|", sessionCache, container)
	return wrapper, inner, container
}

// ---------------------------------------------------------------------------
// Compile-time conformance assertion reach test.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_InterfaceConformance(t *testing.T) {
	// Touching the type keeps the package-level
	//   var _ store.SessionStore = (*CachedSessionStore)(nil)
	// assertion reachable; if the wrapper drifts from the interface this test
	// (and the whole package) fails to compile.
	var c *CachedSessionStore
	if c != nil {
		t.Fatal("nil pointer should stay nil")
	}
}

// ---------------------------------------------------------------------------
// GetSession: miss → inner; second call → cache hit.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_GetSession_MissCallsInnerAndCaches(t *testing.T) {
	ctx := context.Background()
	c, inner, _ := newTestCachedSessionStore(t, 16)
	if err := inner.PutSession(ctx, "addr-A", []byte("session-A")); err != nil {
		t.Fatalf("seed inner.PutSession: %v", err)
	}
	// reset put count consumed by seeding; we only care about get counts here
	inner.putCalls.Store(0)

	v1, err := c.GetSession(ctx, "addr-A")
	if err != nil {
		t.Fatalf("first GetSession: %v", err)
	}
	if !bytes.Equal(v1, []byte("session-A")) {
		t.Fatalf("first GetSession got %q, want %q", v1, "session-A")
	}
	v2, err := c.GetSession(ctx, "addr-A")
	if err != nil {
		t.Fatalf("second GetSession: %v", err)
	}
	if !bytes.Equal(v2, []byte("session-A")) {
		t.Fatalf("second GetSession got %q, want %q", v2, "session-A")
	}
	if got := inner.getCalls.Load(); got != 1 {
		t.Errorf("inner.getCalls = %d, want 1 (second call must hit cache)", got)
	}
}

// ---------------------------------------------------------------------------
// GetSession: inner returns (nil, nil) for missing key — must NOT cache nil.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_GetSession_NilFromInnerNotCached(t *testing.T) {
	ctx := context.Background()
	c, inner, _ := newTestCachedSessionStore(t, 16)

	v1, err := c.GetSession(ctx, "missing-addr")
	if err != nil {
		t.Fatalf("first GetSession: %v", err)
	}
	if v1 != nil {
		t.Fatalf("first GetSession got %q, want nil", v1)
	}
	v2, err := c.GetSession(ctx, "missing-addr")
	if err != nil {
		t.Fatalf("second GetSession: %v", err)
	}
	if v2 != nil {
		t.Fatalf("second GetSession got %q, want nil", v2)
	}
	if got := inner.getCalls.Load(); got != 2 {
		t.Errorf("inner.getCalls = %d, want 2 (nil result must not be cached)", got)
	}
}

// ---------------------------------------------------------------------------
// PutSession: writes through to inner AND populates cache.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_PutSession_WritesThroughAndCaches(t *testing.T) {
	ctx := context.Background()
	c, inner, _ := newTestCachedSessionStore(t, 16)

	if err := c.PutSession(ctx, "addr-B", []byte("session-B")); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	if got := inner.putCalls.Load(); got != 1 {
		t.Errorf("inner.putCalls = %d, want 1 (write-through)", got)
	}
	v, err := c.GetSession(ctx, "addr-B")
	if err != nil {
		t.Fatalf("GetSession after Put: %v", err)
	}
	if !bytes.Equal(v, []byte("session-B")) {
		t.Fatalf("GetSession after Put got %q, want %q", v, "session-B")
	}
	if got := inner.getCalls.Load(); got != 0 {
		t.Errorf("inner.getCalls = %d, want 0 (Put should seed cache so Get hits)", got)
	}
}

// ---------------------------------------------------------------------------
// DeleteSession: removes cache entry; next Get hits inner.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_DeleteSession_RemovesFromCache(t *testing.T) {
	ctx := context.Background()
	c, inner, _ := newTestCachedSessionStore(t, 16)
	if err := c.PutSession(ctx, "addr-C", []byte("session-C")); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	if err := c.DeleteSession(ctx, "addr-C"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if got := inner.deleteCalls.Load(); got != 1 {
		t.Errorf("inner.deleteCalls = %d, want 1", got)
	}
	// Inner store now empty for addr-C; next Get must fall through.
	if _, err := c.GetSession(ctx, "addr-C"); err != nil {
		t.Fatalf("GetSession after Delete: %v", err)
	}
	if got := inner.getCalls.Load(); got != 1 {
		t.Errorf("inner.getCalls = %d, want 1 (cache must be cleared after Delete)", got)
	}
}

// ---------------------------------------------------------------------------
// DeleteAllSessions: bulk purge — cache Len() must drop to 0.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_DeleteAllSessions_PurgesCache(t *testing.T) {
	ctx := context.Background()
	c, inner, container := newTestCachedSessionStore(t, 16)
	// Seed three sessions through the wrapper so the cache is populated.
	for _, addr := range []string{"addr-1", "addr-2", "addr-3"} {
		if err := c.PutSession(ctx, addr, []byte("v-"+addr)); err != nil {
			t.Fatalf("PutSession %s: %v", addr, err)
		}
	}
	if got := container.SessionCache.Len(); got != 3 {
		t.Fatalf("pre-DeleteAll cache Len = %d, want 3", got)
	}
	if err := c.DeleteAllSessions(ctx, "phone-X"); err != nil {
		t.Fatalf("DeleteAllSessions: %v", err)
	}
	if got := inner.deleteAllCalls.Load(); got != 1 {
		t.Errorf("inner.deleteAllCalls = %d, want 1", got)
	}
	if got := container.SessionCache.Len(); got != 0 {
		t.Errorf("post-DeleteAll cache Len = %d, want 0 (Purge expected)", got)
	}
}

// ---------------------------------------------------------------------------
// MigratePNToLID: bulk purge — cache Len() must drop to 0.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_MigratePNToLID_PurgesCache(t *testing.T) {
	ctx := context.Background()
	c, inner, container := newTestCachedSessionStore(t, 16)
	for _, addr := range []string{"addr-1", "addr-2"} {
		if err := c.PutSession(ctx, addr, []byte("v-"+addr)); err != nil {
			t.Fatalf("PutSession %s: %v", addr, err)
		}
	}
	if got := container.SessionCache.Len(); got != 2 {
		t.Fatalf("pre-Migrate cache Len = %d, want 2", got)
	}
	pn := types.JID{User: "12345", Server: types.DefaultUserServer}
	lid := types.JID{User: "67890", Server: types.HiddenUserServer}
	if err := c.MigratePNToLID(ctx, pn, lid); err != nil {
		t.Fatalf("MigratePNToLID: %v", err)
	}
	if got := inner.migrateCalls.Load(); got != 1 {
		t.Errorf("inner.migrateCalls = %d, want 1", got)
	}
	if got := container.SessionCache.Len(); got != 0 {
		t.Errorf("post-Migrate cache Len = %d, want 0 (Purge expected)", got)
	}
}

// ---------------------------------------------------------------------------
// GetManySessions: partial hit — only the misses go to inner.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_GetManySessions_PartialHit(t *testing.T) {
	ctx := context.Background()
	c, inner, _ := newTestCachedSessionStore(t, 32)

	hitAddrs := []string{"hit-1", "hit-2", "hit-3", "hit-4", "hit-5"}
	missAddrs := []string{"miss-1", "miss-2", "miss-3"}

	// Seed the inner store for both sets, but only warm the cache for hits.
	for _, addr := range hitAddrs {
		if err := inner.PutSession(ctx, addr, []byte("v-"+addr)); err != nil {
			t.Fatalf("seed PutSession %s: %v", addr, err)
		}
	}
	for _, addr := range missAddrs {
		if err := inner.PutSession(ctx, addr, []byte("v-"+addr)); err != nil {
			t.Fatalf("seed PutSession %s: %v", addr, err)
		}
	}
	// Warm cache for hits by calling GetSession (which goes through inner once each).
	for _, addr := range hitAddrs {
		if _, err := c.GetSession(ctx, addr); err != nil {
			t.Fatalf("warm GetSession %s: %v", addr, err)
		}
	}
	inner.getCalls.Store(0)
	inner.getManyCalls.Store(0)

	all := append(append([]string{}, hitAddrs...), missAddrs...)
	result, err := c.GetManySessions(ctx, all)
	if err != nil {
		t.Fatalf("GetManySessions: %v", err)
	}
	if got := len(result); got != len(all) {
		t.Errorf("len(result) = %d, want %d", got, len(all))
	}
	for _, addr := range all {
		v, ok := result[addr]
		if !ok {
			t.Errorf("result missing %s", addr)
			continue
		}
		if !bytes.Equal(v, []byte("v-"+addr)) {
			t.Errorf("result[%s] = %q, want %q", addr, v, "v-"+addr)
		}
	}
	// The misses set should be fetched in exactly one inner.GetManySessions call.
	if got := inner.getManyCalls.Load(); got != 1 {
		t.Errorf("inner.getManyCalls = %d, want 1", got)
	}
	if got := inner.getCalls.Load(); got != 0 {
		t.Errorf("inner.getCalls = %d, want 0 (hits served from cache)", got)
	}
	// Verify that the misses-only batch was passed (not all 8 addresses).
	gotMissBatch := inner.lastGetManyBatch()
	if got := len(gotMissBatch); got != len(missAddrs) {
		t.Errorf("inner.GetManySessions called with %d addresses, want %d (misses only)", got, len(missAddrs))
	}
}

// ---------------------------------------------------------------------------
// Eviction at cap: cap=4, 5 distinct keys → Len()==4, first-inserted evicted.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_EvictionAtCap(t *testing.T) {
	ctx := context.Background()
	c, inner, container := newTestCachedSessionStore(t, 4)
	for i := 0; i < 5; i++ {
		addr := fmt.Sprintf("addr-%d", i)
		if err := c.PutSession(ctx, addr, []byte(fmt.Sprintf("v-%d", i))); err != nil {
			t.Fatalf("PutSession %s: %v", addr, err)
		}
	}
	if got := container.SessionCache.Len(); got != 4 {
		t.Errorf("cache Len after 5 Puts = %d, want 4 (cap)", got)
	}
	// addr-0 should be evicted; next GetSession for addr-0 must hit inner.
	inner.getCalls.Store(0)
	if _, err := c.GetSession(ctx, "addr-0"); err != nil {
		t.Fatalf("GetSession addr-0: %v", err)
	}
	if got := inner.getCalls.Load(); got != 1 {
		t.Errorf("inner.getCalls for evicted addr-0 = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Hit/Miss counters via Stats() accessor.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_HitCounter_Increments(t *testing.T) {
	ctx := context.Background()
	c, _, _ := newTestCachedSessionStore(t, 16)
	if err := c.PutSession(ctx, "addr-S", []byte("v")); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	// Two hits.
	for i := 0; i < 2; i++ {
		if _, err := c.GetSession(ctx, "addr-S"); err != nil {
			t.Fatalf("GetSession hit %d: %v", i, err)
		}
	}
	// Three misses.
	for i := 0; i < 3; i++ {
		if _, err := c.GetSession(ctx, fmt.Sprintf("nope-%d", i)); err != nil {
			t.Fatalf("GetSession miss %d: %v", i, err)
		}
	}
	hits, misses, _, _, _ := c.Stats()
	if hits != 2 {
		t.Errorf("Stats hits = %d, want 2", hits)
	}
	if misses != 3 {
		t.Errorf("Stats misses = %d, want 3", misses)
	}
}

// ---------------------------------------------------------------------------
// FlushIfDirty: no-op when nothing is pending.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_FlushIfDirty_NoOpWhenClean(t *testing.T) {
	ctx := context.Background()
	c, inner, _ := newTestCachedSessionStore(t, 16)
	if err := c.FlushIfDirty(ctx, "addr-clean"); err != nil {
		t.Fatalf("FlushIfDirty: %v", err)
	}
	if got := inner.putCalls.Load(); got != 0 {
		t.Errorf("inner.putCalls = %d, want 0 (no pending write)", got)
	}
}

// ---------------------------------------------------------------------------
// FlushIfDirty: emits the final pending value after a burst triggered coalesce.
//
// Coalesce model (LOCKED; see SUMMARY deviations):
//   write-through holds until the Nth-in-window write is detected; then the
//   Nth (and subsequent within-window) writes are deferred until either the
//   coalesceWindow timer fires OR FlushIfDirty is called.
//
// For N=3, M=50ms: 3 puts within window → inner=2 (first two wrote through),
// the 3rd is deferred. After FlushIfDirty → inner=3 with the FINAL value.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_FlushIfDirty_FlushesDirtyKey(t *testing.T) {
	ctx := context.Background()
	c, inner, _ := newTestCachedSessionStore(t, 16)
	addr := "addr-burst"
	for i := 0; i < 3; i++ {
		v := []byte(fmt.Sprintf("v-%d", i))
		if err := c.PutSession(ctx, addr, v); err != nil {
			t.Fatalf("PutSession #%d: %v", i, err)
		}
	}
	// First two writes hit inner; the third is deferred (within burst window).
	if got := inner.putCalls.Load(); got != 2 {
		t.Errorf("inner.putCalls after burst = %d, want 2 (3rd write deferred)", got)
	}
	// Cache reflects the LATEST value even while the inner store is still at v-1.
	v, err := c.GetSession(ctx, addr)
	if err != nil {
		t.Fatalf("GetSession during burst: %v", err)
	}
	if !bytes.Equal(v, []byte("v-2")) {
		t.Errorf("cache value during burst = %q, want %q", v, "v-2")
	}
	// Flush must drain the deferred write to inner.
	if err := c.FlushIfDirty(ctx, addr); err != nil {
		t.Fatalf("FlushIfDirty: %v", err)
	}
	if got := inner.putCalls.Load(); got != 3 {
		t.Errorf("inner.putCalls after Flush = %d, want 3", got)
	}
	// And inner now has the FINAL value.
	innerVal, err := inner.GetSession(ctx, addr)
	if err != nil {
		t.Fatalf("inner.GetSession: %v", err)
	}
	if !bytes.Equal(innerVal, []byte("v-2")) {
		t.Errorf("inner final value = %q, want %q", innerVal, "v-2")
	}
}

// ---------------------------------------------------------------------------
// Burst-coalesce below threshold: 2 puts in window → write-through (both go).
// ---------------------------------------------------------------------------

func TestCachedSessionStore_BurstCoalesce_BelowThresholdWritesThrough(t *testing.T) {
	ctx := context.Background()
	c, inner, _ := newTestCachedSessionStore(t, 16)
	addr := "addr-low"
	for i := 0; i < 2; i++ {
		v := []byte(fmt.Sprintf("v-%d", i))
		if err := c.PutSession(ctx, addr, v); err != nil {
			t.Fatalf("PutSession #%d: %v", i, err)
		}
	}
	if got := inner.putCalls.Load(); got != 2 {
		t.Errorf("inner.putCalls = %d, want 2 (below burst threshold)", got)
	}
}

// ---------------------------------------------------------------------------
// Burst-coalesce outside window: 3 puts spaced 70ms apart → write-through.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_BurstCoalesce_OutsideWindowWritesThrough(t *testing.T) {
	ctx := context.Background()
	c, inner, _ := newTestCachedSessionStore(t, 16)
	addr := "addr-spaced"
	for i := 0; i < 3; i++ {
		v := []byte(fmt.Sprintf("v-%d", i))
		if err := c.PutSession(ctx, addr, v); err != nil {
			t.Fatalf("PutSession #%d: %v", i, err)
		}
		if i < 2 {
			// Spacing larger than coalesceWindow (50ms) so each write is
			// the first-in-window and never trips the burst counter.
			time.Sleep(70 * time.Millisecond)
		}
	}
	if got := inner.putCalls.Load(); got != 3 {
		t.Errorf("inner.putCalls = %d, want 3 (writes outside burst window)", got)
	}
}

// ---------------------------------------------------------------------------
// Race test: N=50 goroutines, mixed Get/Put/Delete on overlapping keys.
// Must run clean under `go test -race` and must not deadlock.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_Race_50Goroutines(t *testing.T) {
	ctx := context.Background()
	c, _, _ := newTestCachedSessionStore(t, 64)

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
				switch i % 4 {
				case 0:
					_, _ = c.GetSession(ctx, addr)
				case 1:
					_ = c.PutSession(ctx, addr, []byte(fmt.Sprintf("v-%d-%d", g, i)))
				case 2:
					_ = c.DeleteSession(ctx, addr)
				case 3:
					_ = c.FlushIfDirty(ctx, addr)
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

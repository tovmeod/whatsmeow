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
)

// Compile-time conformance is asserted inside cached_sender_key_store.go via
//   var _ store.SenderKeyStore = (*CachedSenderKeyStore)(nil)
// A separate test below references the wrapper type to keep the assertion
// reachable from the test binary.

// ---------------------------------------------------------------------------
// Test helper: newTestCachedSenderKeyStore wires a fakeSenderKeyStore and
// an LRU cache of []byte sized to capSize. The wrapper uses "test-jid"
// (no trailing pipe) as the JID — matching production usage at
// container.go:363 where the JID comes from `device.ID.String()` without
// a trailing pipe. The wrapper composes the full cache key internally as
// `jid + "|" + group + "|" + user` (three-element per RESEARCH Finding 7),
// producing single-pipe keys (`"test-jid|<group>|<user>"`).
//
// Group and user fixtures passed to the wrapper's methods are bare strings.
// Tests MUST NOT pre-compose group/user with the JID or with a trailing
// pipe — that would produce double-pipe or other malformed cache keys
// that disagree with the production code path. (Phase 17.5 FIX2 IN-01.)
// ---------------------------------------------------------------------------

func newTestCachedSenderKeyStore(t *testing.T, capSize int) (*CachedSenderKeyStore, *fakeSenderKeyStore) {
	t.Helper()
	inner := newFakeSenderKeyStore()
	cache, err := lru.New[string, []byte](capSize)
	if err != nil {
		t.Fatalf("lru.New[string, []byte] failed: %v", err)
	}
	deviceCache, err := lru.New[string, []string](capSize)
	if err != nil {
		t.Fatalf("lru.New[string, []string] failed: %v", err)
	}
	// "test-jid" with no trailing pipe — wrapper's key() prepends the
	// separator. Matches production format used by Container.initializeDevice.
	wrapper := NewCachedSenderKeyStore(inner, "test-jid", cache, deviceCache, nil)
	return wrapper, inner
}

// ---------------------------------------------------------------------------
// Compile-time conformance assertion reach test.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_InterfaceConformance(t *testing.T) {
	// Touching the type keeps the package-level
	//   var _ store.SenderKeyStore = (*CachedSenderKeyStore)(nil)
	// assertion reachable; if the wrapper drifts from the interface this test
	// (and the whole package) fails to compile.
	var c *CachedSenderKeyStore
	if c != nil {
		t.Fatal("nil pointer should stay nil")
	}
}

// ---------------------------------------------------------------------------
// GetSenderKey: miss → inner; second call → cache hit.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_GetSenderKey_MissCallsInnerAndCaches(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedSenderKeyStore(t, 16)
	if err := inner.PutSenderKey(ctx, "group-A", "user-1", []byte("sk-A1")); err != nil {
		t.Fatalf("seed inner.PutSenderKey: %v", err)
	}
	inner.putCalls.Store(0)

	v1, err := c.GetSenderKey(ctx, "group-A", "user-1")
	if err != nil {
		t.Fatalf("first GetSenderKey: %v", err)
	}
	if !bytes.Equal(v1, []byte("sk-A1")) {
		t.Fatalf("first GetSenderKey got %q, want %q", v1, "sk-A1")
	}
	v2, err := c.GetSenderKey(ctx, "group-A", "user-1")
	if err != nil {
		t.Fatalf("second GetSenderKey: %v", err)
	}
	if !bytes.Equal(v2, []byte("sk-A1")) {
		t.Fatalf("second GetSenderKey got %q, want %q", v2, "sk-A1")
	}
	if got := inner.getCalls.Load(); got != 1 {
		t.Errorf("inner.getCalls = %d, want 1 (second call must hit cache)", got)
	}
}

// ---------------------------------------------------------------------------
// GetSenderKey: inner returns (nil, nil) for missing key — must NOT cache nil.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_GetSenderKey_NilFromInnerNotCached(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedSenderKeyStore(t, 16)

	v1, err := c.GetSenderKey(ctx, "ghost-group", "ghost-user")
	if err != nil {
		t.Fatalf("first GetSenderKey: %v", err)
	}
	if v1 != nil {
		t.Fatalf("first GetSenderKey got %q, want nil", v1)
	}
	v2, err := c.GetSenderKey(ctx, "ghost-group", "ghost-user")
	if err != nil {
		t.Fatalf("second GetSenderKey: %v", err)
	}
	if v2 != nil {
		t.Fatalf("second GetSenderKey got %q, want nil", v2)
	}
	if got := inner.getCalls.Load(); got != 2 {
		t.Errorf("inner.getCalls = %d, want 2 (nil result must not be cached)", got)
	}
}

// ---------------------------------------------------------------------------
// PutSenderKey: writes through AND populates cache so next Get hits cache.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_PutSenderKey_WritesThroughAndCaches(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedSenderKeyStore(t, 16)

	if err := c.PutSenderKey(ctx, "group-B", "user-2", []byte("sk-B2")); err != nil {
		t.Fatalf("PutSenderKey: %v", err)
	}
	if got := inner.putCalls.Load(); got != 1 {
		t.Errorf("inner.putCalls = %d, want 1 (write-through)", got)
	}
	v, err := c.GetSenderKey(ctx, "group-B", "user-2")
	if err != nil {
		t.Fatalf("GetSenderKey after Put: %v", err)
	}
	if !bytes.Equal(v, []byte("sk-B2")) {
		t.Fatalf("GetSenderKey after Put got %q, want %q", v, "sk-B2")
	}
	if got := inner.getCalls.Load(); got != 0 {
		t.Errorf("inner.getCalls = %d, want 0 (Put should seed cache so Get hits)", got)
	}
}

// ---------------------------------------------------------------------------
// Three-element composite key isolates entries: (g1,u1), (g1,u2), (g2,u1)
// must occupy 3 distinct cache slots.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_DifferentGroupOrUserAreSeparateEntries(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCachedSenderKeyStore(t, 16)

	if err := c.PutSenderKey(ctx, "g1", "u1", []byte("v-g1u1")); err != nil {
		t.Fatalf("Put g1/u1: %v", err)
	}
	if err := c.PutSenderKey(ctx, "g1", "u2", []byte("v-g1u2")); err != nil {
		t.Fatalf("Put g1/u2: %v", err)
	}
	if err := c.PutSenderKey(ctx, "g2", "u1", []byte("v-g2u1")); err != nil {
		t.Fatalf("Put g2/u1: %v", err)
	}
	if got := c.cache.Len(); got != 3 {
		t.Fatalf("cache Len = %d, want 3 (three-element key isolates entries)", got)
	}
	// Each entry retains its value (composite key avoids collisions).
	for _, tc := range []struct {
		group, user, want string
	}{
		{"g1", "u1", "v-g1u1"},
		{"g1", "u2", "v-g1u2"},
		{"g2", "u1", "v-g2u1"},
	} {
		got, err := c.GetSenderKey(ctx, tc.group, tc.user)
		if err != nil {
			t.Fatalf("GetSenderKey %s/%s: %v", tc.group, tc.user, err)
		}
		if !bytes.Equal(got, []byte(tc.want)) {
			t.Errorf("GetSenderKey %s/%s = %q, want %q", tc.group, tc.user, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Eviction at cap: cap=4, 5 distinct keys → Len()==4, first-inserted evicted.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_EvictionAtCap(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedSenderKeyStore(t, 4)
	for i := 0; i < 5; i++ {
		group := fmt.Sprintf("g-%d", i)
		if err := c.PutSenderKey(ctx, group, "u", []byte(fmt.Sprintf("v-%d", i))); err != nil {
			t.Fatalf("PutSenderKey %s: %v", group, err)
		}
	}
	if got := c.cache.Len(); got != 4 {
		t.Errorf("cache Len after 5 Puts = %d, want 4 (cap)", got)
	}
	// g-0 should be evicted; next Get for (g-0, u) must hit inner.
	inner.getCalls.Store(0)
	if _, err := c.GetSenderKey(ctx, "g-0", "u"); err != nil {
		t.Fatalf("GetSenderKey g-0/u: %v", err)
	}
	if got := inner.getCalls.Load(); got != 1 {
		t.Errorf("inner.getCalls for evicted g-0 = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// GetSenderKeyDevices (kavtov-fork Phase 27): cache-served device-set index.
// Cold call reaches inner once and caches; warm call is served from the
// device-set cache (inner not called again). A ratchet write-back (Put of an
// already-known device) must NOT invalidate; a genuinely new device's SKDM
// MUST be returned without re-querying inner (add-on-write: appended to LRU +
// pinned overlay, D-01 decision).
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_GetSenderKeyDevices_CacheServedAndInvalidatedOnNewDevice(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedSenderKeyStore(t, 16)

	if err := inner.PutSenderKey(ctx, "group-X", "99user_1:0", []byte("sk-0")); err != nil {
		t.Fatalf("seed inner key :0: %v", err)
	}
	if err := inner.PutSenderKey(ctx, "group-X", "99user_1:5", []byte("sk-5")); err != nil {
		t.Fatalf("seed inner key :5: %v", err)
	}
	inner.devicesCalls.Store(0)

	// (1) Cold call → inner once, result has both devices, cached.
	devices, err := c.GetSenderKeyDevices(ctx, "group-X", "99user_1")
	if err != nil {
		t.Fatalf("GetSenderKeyDevices (cold): %v", err)
	}
	if got := inner.devicesCalls.Load(); got != 1 {
		t.Errorf("inner.devicesCalls after cold = %d, want 1", got)
	}
	if len(devices) != 2 {
		t.Errorf("cold returned %d devices, want 2; got %v", len(devices), devices)
	}

	// (2) Warm call → served from cache; inner NOT called again.
	if _, err := c.GetSenderKeyDevices(ctx, "group-X", "99user_1"); err != nil {
		t.Fatalf("GetSenderKeyDevices (warm): %v", err)
	}
	if got := inner.devicesCalls.Load(); got != 1 {
		t.Errorf("inner.devicesCalls after warm = %d, want 1 (served from cache)", got)
	}

	// (3) Ratchet write-back (Put of an already-known device) must NOT invalidate.
	if err := c.PutSenderKey(ctx, "group-X", "99user_1:0", []byte("sk-0b")); err != nil {
		t.Fatalf("Put existing device: %v", err)
	}
	if _, err := c.GetSenderKeyDevices(ctx, "group-X", "99user_1"); err != nil {
		t.Fatalf("GetSenderKeyDevices after write-back: %v", err)
	}
	if got := inner.devicesCalls.Load(); got != 1 {
		t.Errorf("inner.devicesCalls after write-back = %d, want 1 (write-back must not invalidate)", got)
	}

	// (4) New device's SKDM → add-on-write (D-01): device is appended directly
	// to the LRU entry + pinned overlay; inner is NOT re-queried.
	// GetSenderKeyDevices must return all 3 devices without an extra inner call.
	if err := c.PutSenderKey(ctx, "group-X", "99user_1:7", []byte("sk-7")); err != nil {
		t.Fatalf("Put new device: %v", err)
	}
	devices3, err := c.GetSenderKeyDevices(ctx, "group-X", "99user_1")
	if err != nil {
		t.Fatalf("GetSenderKeyDevices after new-device Put: %v", err)
	}
	// Under add-on-write the new device is appended to the LRU (no invalidate),
	// so inner is not re-queried — devicesCalls stays at 1.
	if got := inner.devicesCalls.Load(); got != 1 {
		t.Errorf("inner.devicesCalls after new-device Put = %d, want 1 (add-on-write, no re-query)", got)
	}
	if len(devices3) != 3 {
		t.Errorf("after new device returned %d devices, want 3; got %v", len(devices3), devices3)
	}
}

// ---------------------------------------------------------------------------
// Race test: N=50 goroutines, mixed Get/Put on overlapping keys.
// Must run clean under `go test -race` and must not deadlock.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_Race_50Goroutines(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCachedSenderKeyStore(t, 64)

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
				group := fmt.Sprintf("group-%d", (g+i)%10)
				user := fmt.Sprintf("user-%d", (g+i)%7)
				switch i % 2 {
				case 0:
					_, _ = c.GetSenderKey(ctx, group, user)
				case 1:
					_ = c.PutSenderKey(ctx, group, user, []byte(fmt.Sprintf("v-%d-%d", g, i)))
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

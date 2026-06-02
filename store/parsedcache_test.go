// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// parsedcache_test.go — Phase 17.8 plan 01.
//
// Unit tests for parsedSKCache and parsedSessionCache (parsedcache.go).
//
// Coverage:
//   SC-1: hit path returns cached pointer without deserialization.
//   SC-6: Invalidate removes the entry; subsequent LoadStruct returns a miss.
//   Store-time mutex: concurrent StoreStruct calls produce no data race.
//   Read-only discipline: re-storing a retrieved pointer is a no-op (the
//     discipline is that callers never mutate it; -race enforces this at
//     runtime).
//
// All tests run under -race; no external DB or SQL involved.
package store

import (
	"sync"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	librecord "go.mau.fi/libsignal/state/record"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newSKCache(t *testing.T, cap int) *parsedSKCache {
	t.Helper()
	c, err := lru.New[string, *groupRecord.SenderKeyStructure](cap)
	if err != nil {
		t.Fatalf("lru.New SenderKey: %v", err)
	}
	return NewParsedSKCache(c)
}

func newSessCache(t *testing.T, cap int) *parsedSessionCache {
	t.Helper()
	c, err := lru.New[string, *librecord.SessionStructure](cap)
	if err != nil {
		t.Fatalf("lru.New Session: %v", err)
	}
	return NewParsedSessionCache(c)
}

// ---------------------------------------------------------------------------
// TestDecodedSKCacheHit
//
// SC-1: after StoreStruct(key, s), LoadStruct(key) returns the SAME pointer
// (not a copy) with ok=true. Signal.go will call NewSenderKeyFromStruct on
// this pointer without any deserialization — documented here.
// ---------------------------------------------------------------------------

func TestDecodedSKCacheHit(t *testing.T) {
	cache := newSKCache(t, 128)
	key := "group1|user1"
	s := &groupRecord.SenderKeyStructure{}

	cache.StoreStruct(key, s)
	got, ok := cache.LoadStruct(key)
	if !ok {
		t.Fatal("LoadStruct after StoreStruct: want ok=true, got false")
	}
	if got != s {
		t.Fatalf("LoadStruct returned different pointer: got %p, want %p", got, s)
	}
}

// ---------------------------------------------------------------------------
// TestDecodedSKCacheMiss
//
// On a fresh cache, LoadStruct returns (nil, false).
// ---------------------------------------------------------------------------

func TestDecodedSKCacheMiss(t *testing.T) {
	cache := newSKCache(t, 128)
	got, ok := cache.LoadStruct("group-miss|user-miss")
	if ok {
		t.Fatal("LoadStruct on empty cache: want ok=false, got true")
	}
	if got != nil {
		t.Fatalf("LoadStruct on empty cache: want nil, got %p", got)
	}
}

// ---------------------------------------------------------------------------
// TestDecodedSKCacheStoreMutex
//
// 20 goroutines each call StoreStruct with a distinct pointer.
// After all goroutines finish, LoadStruct must return a non-nil result.
// The -race detector validates that no goroutine races on lru internals.
// ---------------------------------------------------------------------------

func TestDecodedSKCacheStoreMutex(t *testing.T) {
	cache := newSKCache(t, 128)
	key := "group-mutex|user-mutex"
	const N = 20

	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := &groupRecord.SenderKeyStructure{}
			cache.StoreStruct(key, s)
		}()
	}
	wg.Wait()

	got, ok := cache.LoadStruct(key)
	if !ok {
		t.Fatal("LoadStruct after concurrent StoreStruct: want ok=true, got false")
	}
	if got == nil {
		t.Fatal("LoadStruct after concurrent StoreStruct: want non-nil, got nil")
	}
}

// ---------------------------------------------------------------------------
// TestDecodedSKCacheInvalidate
//
// SC-6: StoreStruct followed by Invalidate causes the next LoadStruct to miss.
// ---------------------------------------------------------------------------

func TestDecodedSKCacheInvalidate(t *testing.T) {
	cache := newSKCache(t, 128)
	key := "group-inv|user-inv"
	s := &groupRecord.SenderKeyStructure{}

	cache.StoreStruct(key, s)
	cache.Invalidate(key)

	_, ok := cache.LoadStruct(key)
	if ok {
		t.Fatal("LoadStruct after Invalidate: want ok=false, got true")
	}
}

// ---------------------------------------------------------------------------
// TestDecodedSessionCacheHit
//
// Mirror of TestDecodedSKCacheHit for parsedSessionCache.
// ---------------------------------------------------------------------------

func TestDecodedSessionCacheHit(t *testing.T) {
	cache := newSessCache(t, 128)
	key := "addr1"
	s := &librecord.SessionStructure{}

	cache.StoreStruct(key, s)
	got, ok := cache.LoadStruct(key)
	if !ok {
		t.Fatal("LoadStruct after StoreStruct: want ok=true, got false")
	}
	if got != s {
		t.Fatalf("LoadStruct returned different pointer: got %p, want %p", got, s)
	}
}

// ---------------------------------------------------------------------------
// TestDecodedSessionCacheMiss
//
// Mirror of TestDecodedSKCacheMiss for parsedSessionCache.
// ---------------------------------------------------------------------------

func TestDecodedSessionCacheMiss(t *testing.T) {
	cache := newSessCache(t, 128)
	got, ok := cache.LoadStruct("addr-miss")
	if ok {
		t.Fatal("LoadStruct on empty session cache: want ok=false, got true")
	}
	if got != nil {
		t.Fatalf("LoadStruct on empty session cache: want nil, got %p", got)
	}
}

// ---------------------------------------------------------------------------
// TestDecodedSessionCacheInvalidate
//
// SC-6 (session): StoreStruct then Invalidate causes next LoadStruct to miss.
// ---------------------------------------------------------------------------

func TestDecodedSessionCacheInvalidate(t *testing.T) {
	cache := newSessCache(t, 128)
	key := "addr-inv"
	s := &librecord.SessionStructure{}

	cache.StoreStruct(key, s)
	cache.Invalidate(key)

	_, ok := cache.LoadStruct(key)
	if ok {
		t.Fatal("LoadStruct after Invalidate: want ok=false, got true")
	}
}

// ---------------------------------------------------------------------------
// TestParsedCacheReadOnlyInvariant
//
// Documents the read-only discipline: StoreStruct(key, s); retrieve via
// LoadStruct; then call StoreStruct(key, retrieved) — treating the retrieved
// pointer as if to "update" the cache. This is the exact anti-pattern callers
// must avoid (they should call record.Structure() for a fresh pointer on the
// Store path). The test verifies no panic occurs and the cache remains
// readable. The -race detector enforces the mutation invariant at runtime: if
// any caller modifies the cached struct while another goroutine reads it, race
// detector flags it.
// ---------------------------------------------------------------------------

func TestParsedCacheReadOnlyInvariant(t *testing.T) {
	cache := newSKCache(t, 128)
	key := "group-ro|user-ro"
	s := &groupRecord.SenderKeyStructure{}

	cache.StoreStruct(key, s)

	retrieved, ok := cache.LoadStruct(key)
	if !ok {
		t.Fatal("LoadStruct: want ok=true")
	}

	// Re-storing the retrieved pointer is a no-op in terms of correctness
	// (same pointer, same slot). Callers should NOT do this on the real Store
	// path (they must use record.Structure() for a fresh pointer), but it must
	// not corrupt or panic the cache.
	cache.StoreStruct(key, retrieved)

	got, ok := cache.LoadStruct(key)
	if !ok {
		t.Fatal("LoadStruct after re-store: want ok=true")
	}
	if got != retrieved {
		t.Fatalf("LoadStruct after re-store: got %p, want %p", got, retrieved)
	}
}

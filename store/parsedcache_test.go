// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// parsedcache_test.go — Phase 17.8 plan 01, updated Phase 17.13.
//
// Unit tests for parsedSKCache (parsedcache.go).
// Phase 17.13: parsedSessionCache removed (D-04a); session cache tests removed.
//
// Coverage:
//
//	SC-1: hit path returns cached pointer without deserialization.
//	SC-6: Invalidate removes the entry; subsequent LoadStruct returns a miss.
//	Store-time mutex: concurrent StoreStruct calls produce no data race.
//	Read-only discipline: re-storing a retrieved pointer is a no-op (the
//	  discipline is that callers never mutate it; -race enforces this at
//	  runtime).
//
// All tests run under -race; no external DB or SQL involved.
package store

import (
	"bytes"
	"reflect"
	"sync"
	"testing"

	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newSKCache(t *testing.T, cap int) *parsedSKCache {
	t.Helper()
	c, err := NewSKParsedLRU(cap)
	if err != nil {
		t.Fatalf("NewSKParsedLRU: %v", err)
	}
	return NewParsedSKCache(c)
}

// validSKStructure builds a minimal but length-valid *SenderKeyStructure that
// passes flatFromStructure's refuse-to-cache guard (chainKey=32, signingPub=33,
// signingPriv=32). Phase 17.9: the cache now stores a flat value-struct, so the
// old &SenderKeyStructure{} (0 states) is rejected by the guard and would never
// cache; tests must use a real structure.
func validSKStructure(seed int) *groupRecord.SenderKeyStructure {
	mk := func(n, b int) []byte {
		out := make([]byte, n)
		for i := range out {
			out[i] = byte(b + i)
		}
		return out
	}
	return &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{{
			KeyID: uint32(1000 + seed),
			SenderChainKey: &ratchet.SenderChainKeyStructure{
				Iteration: uint32(seed),
				ChainKey:  mk(flatChainKeyLen, 0x10+seed),
			},
			SigningKeyPublic:  mk(flatSigningPubLen, 0x20+seed),
			SigningKeyPrivate: mk(flatSigningPrivLen, 0x30+seed),
		}},
	}
}

// ---------------------------------------------------------------------------
// TestDecodedSKCacheHit
//
// SC-1: after StoreStruct(key, s), LoadStruct(key) returns a structure that is
// VALUE-EQUAL to s with ok=true. Phase 17.9: the cache stores a flat value
// struct and rebuilds a FRESH pointer on Load (no longer the same pointer), so
// the assertion is reflect.DeepEqual, not pointer identity. Signal.go calls
// NewSenderKeyFromStruct on this rebuilt structure.
// ---------------------------------------------------------------------------

func TestDecodedSKCacheHit(t *testing.T) {
	cache := newSKCache(t, 128)
	key := "group1|user1"
	s := validSKStructure(1)

	cache.StoreStruct(key, s, nil)
	got, ok := cache.LoadStruct(key)
	if !ok {
		t.Fatal("LoadStruct after StoreStruct: want ok=true, got false")
	}
	if !reflect.DeepEqual(got, s) {
		t.Fatalf("LoadStruct returned non-equal structure:\n got %+v\nwant %+v", got, s)
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
			s := validSKStructure(2)
			cache.StoreStruct(key, s, nil)
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
	s := validSKStructure(3)

	cache.StoreStruct(key, s, nil)
	cache.Invalidate(key)

	_, ok := cache.LoadStruct(key)
	if ok {
		t.Fatal("LoadStruct after Invalidate: want ok=false, got true")
	}
}

// ---------------------------------------------------------------------------
// TestParsedSKCacheRebuildIndependence
//
// Phase 17.9: the cache stores a flat value-struct and rebuilds a FRESH,
// independent *SenderKeyStructure on every LoadStruct. This test replaces the
// old pointer-identity read-only-invariant test (whose premise — caching a
// shared pointer — no longer holds). It asserts:
//  1. Two LoadStruct calls return value-equal but DISTINCT pointers (rebuild).
//  2. Re-storing a retrieved structure round-trips to a value-equal result.
//  3. Mutating a retrieved structure's bytes does NOT corrupt the cache (the
//     flat value-copy isolation that makes the old read-only discipline moot).
// ---------------------------------------------------------------------------

func TestParsedSKCacheRebuildIndependence(t *testing.T) {
	cache := newSKCache(t, 128)
	key := "group-ro|user-ro"
	s := validSKStructure(4)

	cache.StoreStruct(key, s, nil)

	a, ok := cache.LoadStruct(key)
	if !ok {
		t.Fatal("LoadStruct: want ok=true")
	}
	b, ok := cache.LoadStruct(key)
	if !ok {
		t.Fatal("second LoadStruct: want ok=true")
	}
	if a == b {
		t.Fatal("LoadStruct returned the same pointer twice; expected a fresh rebuild each call")
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("two rebuilds differ:\n a=%+v\n b=%+v", a, b)
	}

	// Mutate a's chain key in place; the cache (flat value copy) must be
	// unaffected — a subsequent Load returns the original bytes.
	origChainKey := append([]byte(nil), a.SenderKeyStates[0].SenderChainKey.ChainKey...)
	a.SenderKeyStates[0].SenderChainKey.ChainKey[0] ^= 0xFF
	c, ok := cache.LoadStruct(key)
	if !ok {
		t.Fatal("LoadStruct after mutation: want ok=true")
	}
	if !bytes.Equal(c.SenderKeyStates[0].SenderChainKey.ChainKey, origChainKey) {
		t.Fatal("mutating a retrieved structure corrupted the cached entry")
	}

	// Re-storing a retrieved structure round-trips to a value-equal result.
	cache.StoreStruct(key, c, nil)
	d, ok := cache.LoadStruct(key)
	if !ok {
		t.Fatal("LoadStruct after re-store: want ok=true")
	}
	if !reflect.DeepEqual(d, c) {
		t.Fatalf("re-store round-trip differs:\n c=%+v\n d=%+v", c, d)
	}
}

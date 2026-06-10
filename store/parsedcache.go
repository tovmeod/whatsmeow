// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Phase 17.8: decode-once read-cache for Signal sender-key and session stores.
//
// # Read-only invariant
//
// The *SenderKeyStructure / *SessionStructure pointer stored in these LRUs
// MUST NOT be modified by any caller after it is passed to StoreStruct. The
// Store path (signal.go StoreSenderKey / StoreSession) must call
// record.Structure() to produce a FRESH *Structure pointer from the
// post-ratchet record, and pass that fresh pointer to StoreStruct. Never
// modify the cached pointer in place — a concurrent LoadStruct may be reading
// it at the same moment.
//
// # libsignal version-check annotation
//
// Verified against libsignal v0.2.1: NewKeysFromStruct aliases the []byte
// fields from *KeysStructure into *message.Keys without copying. Concurrent
// NewSessionFromStructure calls from the same cached *SessionStructure produce
// *Session objects that share those backing byte slices. libsignal v0.2.1 does
// not mutate these bytes after construction, so the aliasing is safe. If
// libsignal is upgraded, re-audit: grep for mutation of cipherKey/macKey/iv
// in the new version's keys/message package.

package store

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
)

// parsedCacheEnvCapOrDefault reads an integer env var and returns its value,
// or fallback if the var is absent, non-integer, or non-positive.
// This is an inline duplicate of envCapOrDefault from package sqlstore.
// Both packages are in the same binary with no collision — different package
// namespaces — but the distinct name avoids confusion when grepping.
func parsedCacheEnvCapOrDefault(key string, fallback int) int {
	s := os.Getenv(key)
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// Package-level LRU capacity default for the decoded SKParsed cache.
//
// 2026-06-10 GC-storm: caee645 raised this from 500k to 1.5M. At 1.5M entries
// the warmed heap reached 2.85 GB against GOMEMLIMIT=3200 MiB (11% headroom),
// driving 40 GC cycles/min consuming ~4.5 of 8 cores (84% CPU in mark-scan).
// Root cause: GC headroom is controlled by cap defaults (this var +
// sqlstore.signalSKParsedCacheCap in cache_wiring.go), NOT by GOMEMLIMIT.
// Validated by TestCacheMemoryBudget (Phase 35.1-01): measured 903 B/entry;
// 500k cap = 430 MB, giving 50.7% GC headroom (>= 30% threshold). The host-only
// drop-in (KAVTOV_CACHE_SENDERKEY_DECODED_CAP=500000) was removed in Phase
// 35.1-02 because the durable fix is this default, not a host-only override.
// The AUTHORITATIVE prod cap is sqlstore's signalSKParsedCacheCap (cache_wiring.go);
// this package-level var is the store-package default for tests/standalone
// wiring. MUST match cache_wiring.go's signalSKParsedCacheCap default. Env-overridable.
var signalSKParsedCacheCap = parsedCacheEnvCapOrDefault("KAVTOV_CACHE_SENDERKEY_DECODED_CAP", 500_000)

// Process-global parsed-cache hit/miss counters. The parsed cache is a shared
// process-level LRU wrapped per-device, so global atomics (not per-wrapper
// fields) give the true aggregate effectiveness. A "miss" is a cache lookup
// that forced the columnar DB read + recompose; the hit ratio tells whether the
// decode-once cache is actually earning its keep on the live access pattern.
var (
	skParsedHits, skParsedMisses uint64
)

// SenderKeyParsedCacheStats returns the process-global hits and misses of the
// parsed sender-key cache (LoadStruct). Exposed for DebugStats / observability.
func SenderKeyParsedCacheStats() (hits, misses uint64) {
	return atomic.LoadUint64(&skParsedHits), atomic.LoadUint64(&skParsedMisses)
}

// parsedSKCache is a process-level LRU of decoded *SenderKeyStructure values.
// It sits in front of the []byte LRU (CachedSenderKeyStore) so that cache
// hits bypass JSON deserialization and the libsignal graph-rebuild entirely.
// Callers call NewSenderKeyFromStruct on the returned pointer to obtain a
// fresh, independent *SenderKey record for each decrypt.
//
// mu guards only the lru.Add / lru.Remove calls in StoreStruct and Invalidate.
// It is NOT held during NewSenderKeyFromStruct / NewSessionFromStructure calls
// or any other libsignal operation. LoadStruct holds no lock at all because
// lru.Cache is goroutine-safe.
type parsedSKCache struct {
	lru *SKParsedLRU
	mu  sync.Mutex
}

// SKParsedLRU is the concrete LRU type backing the parsed sender-key cache.
// Phase 17.9 GC redesign: the value type is flatSenderKey (a near-pointer-free
// value struct), NOT *groupRecord.SenderKeyStructure. flatSenderKey is
// deliberately unexported (package-private crypto detail), so this exported
// type alias + NewSKParsedLRU constructor are what package sqlstore uses to
// construct and forward the LRU — sqlstore only constructs and hands off the
// LRU, it never calls Get/Add on it (those happen here via flatFromStructure /
// flatToStructure), so naming the unexported value type cross-package via the
// alias is sound.
type SKParsedLRU = lru.Cache[string, flatSenderKey]

// NewSKParsedLRU constructs the parsed sender-key LRU. Used by cache_wiring.go
// (package sqlstore) so it never has to name the unexported flatSenderKey type.
func NewSKParsedLRU(capacity int) (*SKParsedLRU, error) {
	return lru.New[string, flatSenderKey](capacity)
}

// NewParsedSKCache wraps a pre-constructed LRU. The LRU is constructed by
// cache_wiring.go (plan 02) and injected here; parsedcache.go never owns LRU
// construction.
func NewParsedSKCache(cache *SKParsedLRU) *parsedSKCache {
	return &parsedSKCache{lru: cache}
}

// LoadStruct rebuilds and returns the *SenderKeyStructure for key, or
// (nil, false) on a miss. The cache stores a flatSenderKey BY VALUE; lru.Get
// copies it out (no aliasing of the cached entry), and flatToStructure rebuilds
// a fresh, independent *SenderKeyStructure. A malformed skipped tail makes
// flatToStructure return nil, which is mapped to a clean miss (never a panic,
// never a nil structure handed to NewSenderKeyFromStruct). No lock is held;
// lru.Cache.Get is goroutine-safe.
func (c *parsedSKCache) LoadStruct(key string) (*groupRecord.SenderKeyStructure, bool) {
	f, ok := c.lru.Get(key)
	if !ok {
		atomic.AddUint64(&skParsedMisses, 1)
		return nil, false
	}
	s := flatToStructure(f)
	if s == nil {
		// Malformed tail treated as a miss (re-read from DB). Count as a miss
		// so the rate reflects DB round-trips actually incurred.
		atomic.AddUint64(&skParsedMisses, 1)
		return nil, false
	}
	atomic.AddUint64(&skParsedHits, 1)
	return s, true
}

// StoreStruct replaces the cached structure for key. The structure is converted
// to its flat form first; if the length-validation guard refuses it
// (flatFromStructure ok=false — wrong field length, 0 states, or > flatMaxStates),
// the entry is left UNCACHED and the caller falls through to the uncached read
// path (correct, just not cached). Holds c.mu only for the lru.Add call (not
// across the conversion or any libsignal call). The passed-in pointer s must
// have been produced by record.Structure() on the post-ratchet record.
func (c *parsedSKCache) StoreStruct(key string, s *groupRecord.SenderKeyStructure) {
	f, ok := flatFromStructure(s)
	if !ok {
		return // refuse-to-cache: leave uncached, read path stays correct
	}
	c.mu.Lock()
	c.lru.Add(key, f)
	c.mu.Unlock()
}

// Invalidate removes the entry for key. D-04 hook — Phase 17.10 will call
// this when a recovery path writes a fresh sender key out-of-band. Phase 17.8
// does NOT wire any trigger to this method; restart-after-recovery is the
// interim coherence rule and is not regressed.
func (c *parsedSKCache) Invalidate(key string) {
	c.mu.Lock()
	c.lru.Remove(key)
	c.mu.Unlock()
}

// AddFlatToLRU converts s to its flat form and adds it to lru.
// Returns false if flatFromStructure refuses the structure (wrong field
// lengths, 0 states, or > flatMaxStates). Used by cache_sizing_test.go
// (package sqlstore) to fill SKParsedLRU entries without naming the
// unexported flatSenderKey type across the package boundary.
func AddFlatToLRU(lru *SKParsedLRU, key string, s *groupRecord.SenderKeyStructure) bool {
	f, ok := flatFromStructure(s)
	if !ok {
		return false
	}
	lru.Add(key, f)
	return true
}


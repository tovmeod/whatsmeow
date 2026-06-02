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

	lru "github.com/hashicorp/golang-lru/v2"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	librecord "go.mau.fi/libsignal/state/record"
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

// Package-level LRU capacity defaults for the decoded-struct caches.
// Sized to match the []byte LRU caps (KAVTOV_CACHE_SENDERKEY_CAP /
// KAVTOV_CACHE_SESSION_CAP) so that struct-cache evictions and []byte-cache
// evictions occur at the same working-set boundary.
var signalSKParsedCacheCap = parsedCacheEnvCapOrDefault("KAVTOV_CACHE_SENDERKEY_DECODED_CAP", 1_500_000)
var signalSessParsedCacheCap = parsedCacheEnvCapOrDefault("KAVTOV_CACHE_SESSION_DECODED_CAP", 250_000)

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
	lru *lru.Cache[string, *groupRecord.SenderKeyStructure]
	mu  sync.Mutex
}

// NewParsedSKCache wraps a pre-constructed LRU. The LRU is constructed by
// cache_wiring.go (plan 02) and injected here; parsedcache.go never owns LRU
// construction.
func NewParsedSKCache(cache *lru.Cache[string, *groupRecord.SenderKeyStructure]) *parsedSKCache {
	return &parsedSKCache{lru: cache}
}

// LoadStruct returns the cached *SenderKeyStructure for key, or (nil, false)
// on a miss. No lock is held; lru.Cache.Get is goroutine-safe. The returned
// pointer is READ-ONLY — callers must not modify the struct.
func (c *parsedSKCache) LoadStruct(key string) (*groupRecord.SenderKeyStructure, bool) {
	return c.lru.Get(key)
}

// StoreStruct replaces the cached structure for key. Holds c.mu only for the
// lru.Add call (not across any libsignal call). The passed-in pointer s must
// have been produced by record.Structure() on the post-ratchet record — never
// pass a pointer retrieved from a prior LoadStruct.
func (c *parsedSKCache) StoreStruct(key string, s *groupRecord.SenderKeyStructure) {
	c.mu.Lock()
	c.lru.Add(key, s)
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

// parsedSessionCache is the session-record counterpart of parsedSKCache.
// It caches decoded *SessionStructure values so that LoadSession hits avoid
// JSON deserialization and the libsignal graph-rebuild (~375 ns / 20 allocs
// at 0 skipped keys vs ~5,114 ns / 47 allocs for a full parse — D-03).
type parsedSessionCache struct {
	lru *lru.Cache[string, *librecord.SessionStructure]
	mu  sync.Mutex
}

// NewParsedSessionCache wraps a pre-constructed LRU (constructed by
// cache_wiring.go in plan 02 and injected here).
func NewParsedSessionCache(cache *lru.Cache[string, *librecord.SessionStructure]) *parsedSessionCache {
	return &parsedSessionCache{lru: cache}
}

// LoadStruct returns the cached *SessionStructure for key, or (nil, false) on
// a miss. No lock is held; lru.Cache.Get is goroutine-safe. The returned
// pointer is READ-ONLY — callers must not modify the struct.
func (c *parsedSessionCache) LoadStruct(key string) (*librecord.SessionStructure, bool) {
	return c.lru.Get(key)
}

// StoreStruct replaces the cached structure for key. Holds c.mu only for the
// lru.Add call. The passed-in pointer s must have been produced by
// record.Structure() on the post-ratchet record.
func (c *parsedSessionCache) StoreStruct(key string, s *librecord.SessionStructure) {
	c.mu.Lock()
	c.lru.Add(key, s)
	c.mu.Unlock()
}

// Invalidate removes the entry for key. D-04 hook — also called on StoreSession
// rollback (when inner.PutSession fails) to prevent a phantom-write in the
// struct cache that was never persisted to DB.
func (c *parsedSessionCache) Invalidate(key string) {
	c.mu.Lock()
	c.lru.Remove(key)
	c.mu.Unlock()
}

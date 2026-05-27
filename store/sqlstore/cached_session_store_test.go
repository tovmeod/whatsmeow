// Copyright (c) 2026 Kavtov Platform (Phase 17.5)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// Compile-time conformance is asserted inside cached_session_store.go via
//   var _ store.SessionStore = (*CachedSessionStore)(nil)
// A separate test below references the wrapper type to keep the assertion
// reachable from the test binary.

// ---------------------------------------------------------------------------
// Test helper: newTestCachedSessionStore wires a fakeSessionStore, a fresh
// session-only LRU cache, and the 4-arg NewCachedSessionStore constructor
// (inner, jid, cache, explicitRemoves). The Container literal is not needed
// since Phase 17.5 FIX dropped the container reverse-pointer and the
// cross-cache purge helper. Test caches use plain lru.New (no eviction
// callback) — Container-level eviction counters are not exercised by these
// tests (Phase 17.5.2 counter discrimination tests live in cache_wiring_test.go).
// ---------------------------------------------------------------------------

func newTestCachedSessionStore(t *testing.T, capSize int) (*CachedSessionStore, *fakeSessionStore, *lru.Cache[string, []byte]) {
	t.Helper()
	inner := newFakeSessionStore()
	sessionCache, err := lru.New[string, []byte](capSize)
	if err != nil {
		t.Fatalf("lru.New[string, []byte] failed: %v", err)
	}
	// explicitRemoves: a local dummy counter — these tests exercise caching
	// logic, not Container-level counter discrimination (Phase 17.5.2).
	var dummyExplicitRemoves uint64
	wrapper := NewCachedSessionStore(inner, "test-jid", sessionCache, &dummyExplicitRemoves, newSessionSecondaryIndex())
	return wrapper, inner, sessionCache
}

// ---------------------------------------------------------------------------
// Compile-time conformance assertion reach test.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_InterfaceConformance(t *testing.T) {
	// Touching the type keeps the package-level
	//   var _ store.SessionStore = (*CachedSessionStore)(nil)
	// assertion reachable; if the wrapper drifts from the interface this
	// test (and the whole package) fails to compile.
	var c *CachedSessionStore
	if c != nil {
		t.Fatal("nil pointer should stay nil")
	}
	// Also touch the interface symbol so the import is not pruned.
	var _ store.SessionStore = (*CachedSessionStore)(nil)
}

// ---------------------------------------------------------------------------
// GetSession: miss → inner; second call → cache hit.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_GetSession_CacheMiss_FillsCache(t *testing.T) {
	ctx := context.Background()
	c, inner, _ := newTestCachedSessionStore(t, 16)
	if err := inner.PutSession(ctx, "addr-A", []byte("session-A")); err != nil {
		t.Fatalf("seed inner.PutSession: %v", err)
	}
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
// GetSession: inner returns (nil, nil) for missing key — must NOT cache nil
// (Pitfall 5 regression).
// ---------------------------------------------------------------------------

func TestCachedSessionStore_GetSession_NilFromInner_NotCached(t *testing.T) {
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
// CR-06 read-path regression: GetSession must return a copy. Mutating the
// returned slice must not affect a subsequent Get.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_GetSession_CacheHit_ReturnsCopy_NotInternalSlice(t *testing.T) {
	ctx := context.Background()
	c, _, _ := newTestCachedSessionStore(t, 16)
	original := []byte("session-original")
	if err := c.PutSession(ctx, "addr-copy", original); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	// First Get: cache hit; mutate the returned slice.
	got1, err := c.GetSession(ctx, "addr-copy")
	if err != nil {
		t.Fatalf("first GetSession: %v", err)
	}
	if !bytes.Equal(got1, original) {
		t.Fatalf("first GetSession got %q, want %q", got1, original)
	}
	for i := range got1 {
		got1[i] = 0xFF
	}
	// Second Get: cache must still return the unmutated original.
	got2, err := c.GetSession(ctx, "addr-copy")
	if err != nil {
		t.Fatalf("second GetSession: %v", err)
	}
	if !bytes.Equal(got2, original) {
		t.Fatalf("second GetSession got %q (cache was corrupted), want %q", got2, original)
	}
}

// ---------------------------------------------------------------------------
// CR-06 write-path regression: PutSession must NOT alias the caller's
// buffer. Caller reuse / mutation after PutSession must not corrupt the
// cache.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_PutSession_CallerBufferReuse_DoesNotCorruptCache(t *testing.T) {
	ctx := context.Background()
	c, _, _ := newTestCachedSessionStore(t, 16)
	buf := []byte("session-write-A")
	if err := c.PutSession(ctx, "addr-buf", buf); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	// Mutate caller's buffer after Put returned. The cache must hold its
	// own copy and remain unaffected.
	for i := range buf {
		buf[i] = 0xAA
	}
	got, err := c.GetSession(ctx, "addr-buf")
	if err != nil {
		t.Fatalf("GetSession after caller mutation: %v", err)
	}
	if !bytes.Equal(got, []byte("session-write-A")) {
		t.Fatalf("GetSession got %q (cache aliased caller buffer), want %q", got, "session-write-A")
	}
}

// ---------------------------------------------------------------------------
// PutSession: write-through. Inner is called BEFORE the cache is updated.
// On success, cache reflects the new value.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_PutSession_WriteThrough_InnerFirst_ThenCache(t *testing.T) {
	ctx := context.Background()
	c, inner, _ := newTestCachedSessionStore(t, 16)

	if err := c.PutSession(ctx, "addr-B", []byte("session-B")); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	if got := inner.putCalls.Load(); got != 1 {
		t.Errorf("inner.putCalls = %d, want 1 (write-through)", got)
	}
	// Cache must now serve the value without touching inner.
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
// PutSession: inner error → cache MUST NOT be updated.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_PutSession_InnerError_NoCacheUpdate(t *testing.T) {
	ctx := context.Background()
	c, inner, cache := newTestCachedSessionStore(t, 16)

	// Seed a pre-existing cache entry so we can prove the failed Put did
	// not overwrite it.
	if err := c.PutSession(ctx, "addr-err", []byte("original")); err != nil {
		t.Fatalf("seed PutSession: %v", err)
	}
	inner.putErr = errors.New("simulated inner failure")

	err := c.PutSession(ctx, "addr-err", []byte("would-corrupt"))
	if err == nil {
		t.Fatal("PutSession expected inner error, got nil")
	}
	// Cache entry must still be the original value, not the would-be new
	// value (no cache update on inner failure).
	if v, ok := cache.Get("test-jid|addr-err"); !ok {
		t.Fatalf("cache entry missing after failed Put — expected the seed value to remain")
	} else if !bytes.Equal(v, []byte("original")) {
		t.Errorf("cache value = %q after failed Put, want %q (no cache update on inner error)", v, "original")
	}
}

// ---------------------------------------------------------------------------
// PutManySessions: write-through to inner; populate cache from input.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_PutManySessions_WriteThrough(t *testing.T) {
	ctx := context.Background()
	c, inner, _ := newTestCachedSessionStore(t, 16)

	in := map[string][]byte{
		"addr-m-1": []byte("v-m-1"),
		"addr-m-2": []byte("v-m-2"),
	}
	if err := c.PutManySessions(ctx, in); err != nil {
		t.Fatalf("PutManySessions: %v", err)
	}
	if got := inner.putManyCalls.Load(); got != 1 {
		t.Errorf("inner.putManyCalls = %d, want 1", got)
	}
	// Both keys must serve from cache (no inner.GetSession calls).
	for addr, want := range in {
		v, err := c.GetSession(ctx, addr)
		if err != nil {
			t.Fatalf("GetSession %s: %v", addr, err)
		}
		if !bytes.Equal(v, want) {
			t.Errorf("GetSession %s = %q, want %q", addr, v, want)
		}
	}
	if got := inner.getCalls.Load(); got != 0 {
		t.Errorf("inner.getCalls = %d, want 0 (PutMany should seed cache)", got)
	}
}

// ---------------------------------------------------------------------------
// PutManySessions: inner error → cache MUST NOT be updated.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_PutManySessions_InnerError_NoCacheUpdate(t *testing.T) {
	ctx := context.Background()
	c, inner, cache := newTestCachedSessionStore(t, 16)

	if err := c.PutSession(ctx, "addr-pm-pre", []byte("preexisting")); err != nil {
		t.Fatalf("seed PutSession: %v", err)
	}
	inner.putManyErr = errors.New("simulated inner failure")

	err := c.PutManySessions(ctx, map[string][]byte{
		"addr-pm-pre": []byte("would-corrupt"),
		"addr-pm-new": []byte("would-add"),
	})
	if err == nil {
		t.Fatal("PutManySessions expected inner error, got nil")
	}
	// addr-pm-pre must still be original; addr-pm-new must not exist.
	if v, ok := cache.Get("test-jid|addr-pm-pre"); !ok {
		t.Fatalf("preexisting cache entry missing after failed PutMany")
	} else if !bytes.Equal(v, []byte("preexisting")) {
		t.Errorf("preexisting cache value = %q, want %q", v, "preexisting")
	}
	if _, ok := cache.Get("test-jid|addr-pm-new"); ok {
		t.Errorf("addr-pm-new must not be cached after failed PutMany")
	}
}

// ---------------------------------------------------------------------------
// DeleteSession: write-through; cache entry removed.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_DeleteSession_WriteThrough(t *testing.T) {
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
// CR-03 regression: DeleteAllSessions(phoneA) must NOT drop cache entries
// for phoneB. The prior implementation purged every entry in the shared
// LRU; the write-through implementation must walk keys and remove only
// those that match the phone+":" prefix.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_DeleteAllSessions_OnlyRemovesPhoneScoped(t *testing.T) {
	ctx := context.Background()
	c, inner, cache := newTestCachedSessionStore(t, 32)

	// Seed entries for phoneA and phoneB through the wrapper (so the
	// cache is populated under the JID-scoped composite key). Address
	// format mirrors libsignal: "<phone>:<device>".
	addrsA := []string{"111:0", "111:1"}
	addrsB := []string{"222:0", "222:1"}
	for _, addr := range addrsA {
		if err := c.PutSession(ctx, addr, []byte("a-"+addr)); err != nil {
			t.Fatalf("seed PutSession A %s: %v", addr, err)
		}
	}
	for _, addr := range addrsB {
		if err := c.PutSession(ctx, addr, []byte("b-"+addr)); err != nil {
			t.Fatalf("seed PutSession B %s: %v", addr, err)
		}
	}
	if got := cache.Len(); got != 4 {
		t.Fatalf("pre-DeleteAll cache Len = %d, want 4", got)
	}

	if err := c.DeleteAllSessions(ctx, "111"); err != nil {
		t.Fatalf("DeleteAllSessions: %v", err)
	}
	if got := inner.deleteAllCalls.Load(); got != 1 {
		t.Errorf("inner.deleteAllCalls = %d, want 1", got)
	}

	// PhoneA entries must be gone; phoneB entries must remain in cache.
	for _, addr := range addrsA {
		if _, ok := cache.Get("test-jid|" + addr); ok {
			t.Errorf("cache still holds %q after DeleteAllSessions(111)", addr)
		}
	}
	for _, addr := range addrsB {
		if _, ok := cache.Get("test-jid|" + addr); !ok {
			t.Errorf("cache lost unrelated entry %q after DeleteAllSessions(111)", addr)
		}
	}
}

// ---------------------------------------------------------------------------
// DeleteAllSessions: also must not touch entries from OTHER JID prefixes
// in the shared LRU.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_DeleteAllSessions_DoesNotTouchOtherJIDs(t *testing.T) {
	ctx := context.Background()
	c, _, cache := newTestCachedSessionStore(t, 32)
	if err := c.PutSession(ctx, "111:0", []byte("a")); err != nil {
		t.Fatalf("seed PutSession: %v", err)
	}
	// Inject an entry under a different JID prefix directly into the
	// shared LRU. Simulates a sibling device wrapper sharing the LRU.
	cache.Add("other-jid|111:0", []byte("sibling"))

	if err := c.DeleteAllSessions(ctx, "111"); err != nil {
		t.Fatalf("DeleteAllSessions: %v", err)
	}
	if _, ok := cache.Get("other-jid|111:0"); !ok {
		t.Errorf("DeleteAllSessions removed an entry under a different JID prefix — must be JID-scoped")
	}
}

// ---------------------------------------------------------------------------
// CR-04 regression: MigratePNToLID must write through to inner FIRST. On
// inner failure the cache must be untouched.
//
// Phase 17.5 FIX2 BL-01: fixture now uses the production address shape —
// `pn.SignalAddressUser() + ":<device>"` (libsignal address format), NOT
// `pn.String() + ":<device>"` (full JID form). The prior fixture happened
// to agree with the wrong-format-on-both-sides bug in the wrapper; this
// rewrite catches a regression to that bug.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_MigratePNToLID_InnerError_NoCacheUpdate(t *testing.T) {
	ctx := context.Background()
	c, inner, cache := newTestCachedSessionStore(t, 16)

	pn := types.JID{User: "12345", Server: types.DefaultUserServer}
	lid := types.JID{User: "67890", Server: types.HiddenUserServer}

	// Production address shape: libsignal `<SignalAddressUser>:<device>`,
	// built from JID.SignalAddressUser() to be independent of the format
	// details (handles ActualAgent suffixing automatically).
	addr := pn.SignalAddressUser() + ":0"
	if err := c.PutSession(ctx, addr, []byte("preserve-me")); err != nil {
		t.Fatalf("seed PutSession: %v", err)
	}
	inner.migrateErr = errors.New("simulated inner failure")

	err := c.MigratePNToLID(ctx, pn, lid)
	if err == nil {
		t.Fatal("MigratePNToLID expected inner error, got nil")
	}
	// Cache entry must still exist under the OLD key. The new key must
	// not exist.
	if v, ok := cache.Get("test-jid|" + addr); !ok {
		t.Fatalf("original cache entry missing after failed Migrate")
	} else if !bytes.Equal(v, []byte("preserve-me")) {
		t.Errorf("original cache value = %q, want %q", v, "preserve-me")
	}
	newAddr := lid.SignalAddressUser() + ":0"
	if _, ok := cache.Get("test-jid|" + newAddr); ok {
		t.Errorf("MigratePNToLID created a new cache key despite inner failure")
	}
}

// ---------------------------------------------------------------------------
// MigratePNToLID happy path (Phase 17.5 FIX2 BL-01 regression): inner
// succeeds; PN-keyed entries are EVICTED. A subsequent GetSession against
// the new LID address triggers a cache miss, fetches from inner (which
// holds the migrated row), and populates the cache under the LID key.
//
// Production address shape: cache keys are
// `<jid>|<SignalAddressUser>:<device>`, NOT `<jid>|<JID.String()>:<device>`.
// This test uses JID.SignalAddressUser() throughout so it is independent
// of the format details and catches the BL-01 regression (where the prior
// implementation matched on pn.String() and never evicted anything in
// production).
// ---------------------------------------------------------------------------

func TestCachedSessionStore_MigratePNToLID_EvictsPNKeys_LIDReadRepopulates(t *testing.T) {
	ctx := context.Background()
	c, inner, cache := newTestCachedSessionStore(t, 32)

	pn := types.JID{User: "12345", Server: types.DefaultUserServer}
	lid := types.JID{User: "67890", Server: types.HiddenUserServer}
	pnUser := pn.SignalAddressUser()
	lidUser := lid.SignalAddressUser()

	// Seed two PN-keyed entries through the wrapper using the production
	// libsignal address format.
	addrPN0 := pnUser + ":0"
	addrPN1 := pnUser + ":1"
	if err := c.PutSession(ctx, addrPN0, []byte("migrated-0")); err != nil {
		t.Fatalf("seed PutSession PN0: %v", err)
	}
	if err := c.PutSession(ctx, addrPN1, []byte("migrated-1")); err != nil {
		t.Fatalf("seed PutSession PN1: %v", err)
	}
	// The fake inner now also holds the PN rows; the fake's
	// MigratePNToLID (which mirrors the SQL semantics) will rewrite those
	// rows under the LID address when c.MigratePNToLID below delegates
	// to inner.

	// Seed an unrelated entry under the same wrapper that must NOT be
	// touched (different user). 999 does not match pnUser="12345".
	cache.Add("test-jid|999:0", []byte("untouched"))

	if err := c.MigratePNToLID(ctx, pn, lid); err != nil {
		t.Fatalf("MigratePNToLID: %v", err)
	}
	if got := inner.migrateCalls.Load(); got != 1 {
		t.Errorf("inner.migrateCalls = %d, want 1", got)
	}

	// PN keys must be evicted from the cache.
	if _, ok := cache.Get("test-jid|" + addrPN0); ok {
		t.Errorf("PN key %q still present in cache after Migrate (eviction failed)", addrPN0)
	}
	if _, ok := cache.Get("test-jid|" + addrPN1); ok {
		t.Errorf("PN key %q still present in cache after Migrate (eviction failed)", addrPN1)
	}
	// LID keys must NOT exist in the cache yet — eviction-not-rewrite means
	// the cache is empty for the LID address until a read repopulates it.
	addrLID0 := lidUser + ":0"
	if _, ok := cache.Get("test-jid|" + addrLID0); ok {
		t.Errorf("LID key %q present in cache immediately after Migrate; expected eviction-only, no pre-populate", addrLID0)
	}

	// Subsequent GetSession against the LID address must cache-miss,
	// fetch from inner (which holds the migrated row), and populate the
	// cache under the LID key. The fake's MigratePNToLID performed the
	// inner-side rewrite so inner.GetSession("67890:0") returns
	// "migrated-0".
	inner.getCalls.Store(0)
	got, err := c.GetSession(ctx, addrLID0)
	if err != nil {
		t.Fatalf("GetSession LID after Migrate: %v", err)
	}
	if !bytes.Equal(got, []byte("migrated-0")) {
		t.Errorf("GetSession LID = %q, want %q (inner should hold migrated row)", got, "migrated-0")
	}
	if n := inner.getCalls.Load(); n != 1 {
		t.Errorf("inner.getCalls after first LID read = %d, want 1 (cache should have missed)", n)
	}
	// Second GetSession for the same LID address must hit cache.
	if _, err := c.GetSession(ctx, addrLID0); err != nil {
		t.Fatalf("GetSession LID second: %v", err)
	}
	if n := inner.getCalls.Load(); n != 1 {
		t.Errorf("inner.getCalls after second LID read = %d, want 1 (second read should hit cache)", n)
	}

	// Unrelated entry must be untouched throughout.
	if v, ok := cache.Get("test-jid|999:0"); !ok {
		t.Errorf("unrelated entry was removed by Migrate")
	} else if !bytes.Equal(v, []byte("untouched")) {
		t.Errorf("unrelated entry corrupted: got %q, want %q", v, "untouched")
	}
}

// ---------------------------------------------------------------------------
// Mixed-account isolation (Phase 17.5 FIX2 BL-01): a single wrapper holds
// cache entries for two distinct PN users. MigratePNToLID(pnA -> lidA)
// must evict ONLY pnA's entries; pnB's entries (different SignalAddressUser)
// must remain untouched. Catches the case where the eviction predicate is
// too loose (e.g. forgets the trailing ':' separator and matches any
// address starting with the same digit string).
// ---------------------------------------------------------------------------

func TestCachedSessionStore_MigratePNToLID_MixedAccount_OnlyEvictsTargetUser(t *testing.T) {
	ctx := context.Background()
	c, _, cache := newTestCachedSessionStore(t, 32)

	pnA := types.JID{User: "12345", Server: types.DefaultUserServer}
	lidA := types.JID{User: "67890", Server: types.HiddenUserServer}
	pnB := types.JID{User: "99999", Server: types.DefaultUserServer}

	// Seed cache entries for both pnA and pnB on this wrapper.
	pnAUser := pnA.SignalAddressUser()
	pnBUser := pnB.SignalAddressUser()
	addrsA := []string{pnAUser + ":0", pnAUser + ":1"}
	addrsB := []string{pnBUser + ":0", pnBUser + ":1"}
	for _, addr := range addrsA {
		if err := c.PutSession(ctx, addr, []byte("a-"+addr)); err != nil {
			t.Fatalf("seed PutSession A %s: %v", addr, err)
		}
	}
	for _, addr := range addrsB {
		if err := c.PutSession(ctx, addr, []byte("b-"+addr)); err != nil {
			t.Fatalf("seed PutSession B %s: %v", addr, err)
		}
	}
	if got := cache.Len(); got != 4 {
		t.Fatalf("pre-Migrate cache Len = %d, want 4", got)
	}

	if err := c.MigratePNToLID(ctx, pnA, lidA); err != nil {
		t.Fatalf("MigratePNToLID: %v", err)
	}

	// pnA entries must be evicted.
	for _, addr := range addrsA {
		if _, ok := cache.Get("test-jid|" + addr); ok {
			t.Errorf("pnA entry %q still cached after MigratePNToLID(pnA -> lidA)", addr)
		}
	}
	// pnB entries must remain untouched.
	for _, addr := range addrsB {
		v, ok := cache.Get("test-jid|" + addr)
		if !ok {
			t.Errorf("pnB entry %q removed by MigratePNToLID(pnA -> lidA) — eviction should be user-scoped", addr)
			continue
		}
		if !bytes.Equal(v, []byte("b-"+addr)) {
			t.Errorf("pnB entry %q value = %q, want %q (corrupted)", addr, v, "b-"+addr)
		}
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
	if got := inner.getManyCalls.Load(); got != 1 {
		t.Errorf("inner.getManyCalls = %d, want 1", got)
	}
	if got := inner.getCalls.Load(); got != 0 {
		t.Errorf("inner.getCalls = %d, want 0 (hits served from cache)", got)
	}
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
	c, inner, cache := newTestCachedSessionStore(t, 4)
	for i := 0; i < 5; i++ {
		addr := fmt.Sprintf("addr-%d", i)
		if err := c.PutSession(ctx, addr, []byte(fmt.Sprintf("v-%d", i))); err != nil {
			t.Fatalf("PutSession %s: %v", addr, err)
		}
	}
	if got := cache.Len(); got != 4 {
		t.Errorf("cache Len after 5 Puts = %d, want 4 (cap)", got)
	}
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
	for i := 0; i < 2; i++ {
		if _, err := c.GetSession(ctx, "addr-S"); err != nil {
			t.Fatalf("GetSession hit %d: %v", i, err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := c.GetSession(ctx, fmt.Sprintf("nope-%d", i)); err != nil {
			t.Fatalf("GetSession miss %d: %v", i, err)
		}
	}
	hits, misses, _ := c.Stats()
	if hits != 2 {
		t.Errorf("Stats hits = %d, want 2", hits)
	}
	if misses != 3 {
		t.Errorf("Stats misses = %d, want 3", misses)
	}
}

// ---------------------------------------------------------------------------
// Race test: N goroutines, mixed Get/Put/Delete on overlapping keys.
// Must run clean under `go test -race` and must not deadlock. The write-
// through wrapper has no shared mutable state of its own beyond atomic
// counters and the thread-safe lru.Cache, so the only thing being asserted
// here is that the wrapper itself doesn't introduce a race.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_Race_GetPutDelete(t *testing.T) {
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
				addr := fmt.Sprintf("addr-%d", (g+i)%10)
				switch i % 3 {
				case 0:
					_, _ = c.GetSession(ctx, addr)
				case 1:
					_ = c.PutSession(ctx, addr, []byte(fmt.Sprintf("v-%d-%d", g, i)))
				case 2:
					_ = c.DeleteSession(ctx, addr)
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
// newTestCachedSessionStoreWithEvict builds a test wrapper whose LRU is wired
// with NewWithEvict + EvictCleanup, mirroring wireSignalCaches. Required by
// tests that exercise the secondary-index consistency under capacity eviction
// (counter-accuracy, orphan-detection, benchmark).
// ---------------------------------------------------------------------------

func newTestCachedSessionStoreWithEvict(t *testing.T, capSize int, explicitRemoves *uint64) (*CachedSessionStore, *fakeSessionStore, *lru.Cache[string, []byte], *sessionSecondaryIndex) {
	t.Helper()
	inner := newFakeSessionStore()
	idx := newSessionSecondaryIndex()
	sessionCache, err := lru.NewWithEvict[string, []byte](capSize, func(key string, _ []byte) {
		if jid, phone, ok := parseCacheKey(key); ok {
			idx.EvictCleanup(key, jid, phone)
		}
	})
	if err != nil {
		t.Fatalf("lru.NewWithEvict[string, []byte] failed: %v", err)
	}
	wrapper := NewCachedSessionStore(inner, "test-jid", sessionCache, explicitRemoves, idx)
	return wrapper, inner, sessionCache, idx
}

// ---------------------------------------------------------------------------
// R2: explicit_removes counter delta equals number of cache entries removed
// by DeleteAllSessions.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_DeleteAllSessions_ExplicitRemovesDelta_EqualsRemoved(t *testing.T) {
	ctx := context.Background()
	var explicitRemoves uint64
	wrapper, inner, cache, idx := newTestCachedSessionStoreWithEvict(t, 1000, &explicitRemoves)

	// Build a second wrapper on the same cache + index (different jid) to
	// prove cross-wrapper isolation: the second wrapper's entries must survive.
	var dummyB uint64
	inner2 := newFakeSessionStore()
	wrapper2 := NewCachedSessionStore(inner2, "other-jid", cache, &dummyB, idx)

	// Populate 5 entries under "11111" on wrapper (test-jid).
	for d := 0; d < 5; d++ {
		addr := fmt.Sprintf("11111:%d", d)
		if err := wrapper.PutSession(ctx, addr, []byte(fmt.Sprintf("v11111-%d", d))); err != nil {
			t.Fatalf("PutSession 11111:%d: %v", d, err)
		}
	}
	// Populate 3 entries under "22222" on wrapper (same jid, different phone).
	for d := 0; d < 3; d++ {
		addr := fmt.Sprintf("22222:%d", d)
		if err := wrapper.PutSession(ctx, addr, []byte(fmt.Sprintf("v22222-%d", d))); err != nil {
			t.Fatalf("PutSession 22222:%d: %v", d, err)
		}
	}
	// Populate 2 entries under "11111" on wrapper2 (other-jid).
	for d := 0; d < 2; d++ {
		addr := fmt.Sprintf("11111:%d", d)
		if err := wrapper2.PutSession(ctx, addr, []byte(fmt.Sprintf("vB-%d", d))); err != nil {
			t.Fatalf("wrapper2.PutSession 11111:%d: %v", d, err)
		}
	}

	before := atomic.LoadUint64(&explicitRemoves)

	if err := wrapper.DeleteAllSessions(ctx, "11111"); err != nil {
		t.Fatalf("DeleteAllSessions: %v", err)
	}

	after := atomic.LoadUint64(&explicitRemoves)
	if delta := after - before; delta != 5 {
		t.Errorf("explicitRemoves delta = %d, want 5 (one per removed cache entry)", delta)
	}

	// inner.deleteAllCalls must be 1.
	if got := inner.deleteAllCalls.Load(); got != 1 {
		t.Errorf("inner.deleteAllCalls = %d, want 1", got)
	}

	// "22222" entries under test-jid must survive.
	for d := 0; d < 3; d++ {
		ck := fmt.Sprintf("test-jid|22222:%d", d)
		if _, ok := cache.Get(ck); !ok {
			t.Errorf("cache lost test-jid|22222:%d after DeleteAllSessions(11111)", d)
		}
	}
	// "other-jid|11111" entries (wrapper2) must survive.
	for d := 0; d < 2; d++ {
		ck := fmt.Sprintf("other-jid|11111:%d", d)
		if _, ok := cache.Get(ck); !ok {
			t.Errorf("cache lost other-jid|11111:%d (cross-wrapper isolation violated)", d)
		}
	}
}

// ---------------------------------------------------------------------------
// R2 (MigratePNToLID path): explicit_removes delta equals number removed.
// ---------------------------------------------------------------------------

func TestCachedSessionStore_MigratePNToLID_ExplicitRemovesDelta_EqualsRemoved(t *testing.T) {
	ctx := context.Background()
	var explicitRemoves uint64
	wrapper, _, cache, idx := newTestCachedSessionStoreWithEvict(t, 1000, &explicitRemoves)

	pn := types.JID{User: "12345", Server: types.DefaultUserServer}
	lid := types.JID{User: "67890", Server: types.HiddenUserServer}
	pnUser := pn.SignalAddressUser()

	// Build a second wrapper on same cache+index (different jid) to prove
	// cross-wrapper isolation.
	var dummyB uint64
	inner2 := newFakeSessionStore()
	wrapper2 := NewCachedSessionStore(inner2, "other-jid", cache, &dummyB, idx)

	// Seed 2 PN-keyed entries for wrapper (test-jid).
	for d := 0; d < 2; d++ {
		addr := fmt.Sprintf("%s:%d", pnUser, d)
		if err := wrapper.PutSession(ctx, addr, []byte(fmt.Sprintf("migrated-%d", d))); err != nil {
			t.Fatalf("PutSession pn:%d: %v", d, err)
		}
	}
	// Seed 1 entry for a different user on wrapper (must survive).
	otherAddr := "99999:0"
	if err := wrapper.PutSession(ctx, otherAddr, []byte("other")); err != nil {
		t.Fatalf("PutSession other: %v", err)
	}
	// Seed 1 entry under other-jid for same pn (must survive cross-wrapper).
	if err := wrapper2.PutSession(ctx, pnUser+":0", []byte("sibling")); err != nil {
		t.Fatalf("wrapper2.PutSession: %v", err)
	}

	before := atomic.LoadUint64(&explicitRemoves)

	if err := wrapper.MigratePNToLID(ctx, pn, lid); err != nil {
		t.Fatalf("MigratePNToLID: %v", err)
	}

	after := atomic.LoadUint64(&explicitRemoves)
	if delta := after - before; delta != 2 {
		t.Errorf("explicitRemoves delta = %d, want 2 (one per PN-keyed entry removed)", delta)
	}

	// PN-keyed entries must be gone from cache.
	for d := 0; d < 2; d++ {
		ck := fmt.Sprintf("test-jid|%s:%d", pnUser, d)
		if _, ok := cache.Get(ck); ok {
			t.Errorf("PN cache entry %s still present after MigratePNToLID", ck)
		}
	}
	// Other-user entry under test-jid must survive.
	if _, ok := cache.Get("test-jid|" + otherAddr); !ok {
		t.Errorf("unrelated entry test-jid|%s was removed by MigratePNToLID", otherAddr)
	}
	// Sibling entry under other-jid must survive.
	siblingCK := fmt.Sprintf("other-jid|%s:0", pnUser)
	if _, ok := cache.Get(siblingCK); !ok {
		t.Errorf("cross-wrapper entry %s was removed by MigratePNToLID (cross-wrapper isolation violated)", siblingCK)
	}
}

// ---------------------------------------------------------------------------
// B1 regression gate: GetSession read-populate is tracked in the secondary
// index and therefore reachable by DeleteAllSessions via SnapshotKeys.
// ---------------------------------------------------------------------------

func TestSessionStore_ReadPopulate_NoOrphan_After_DeleteAllSessions(t *testing.T) {
	ctx := context.Background()
	var explicitRemoves uint64
	wrapper, inner, _, _ := newTestCachedSessionStoreWithEvict(t, 1000, &explicitRemoves)

	// Seed the inner fake so GetSession returns a non-nil payload.
	if err := inner.PutSession(ctx, "33333:0", []byte("session-33333")); err != nil {
		t.Fatalf("seed inner.PutSession: %v", err)
	}
	inner.getCalls.Store(0)
	inner.putCalls.Store(0)

	// Step 1: cold cache read — exercises the §157 read-populate path in
	// GetSession, which calls c.cache.Add AND secondaryIndex.Insert.
	got, err := wrapper.GetSession(ctx, "33333:0")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !bytes.Equal(got, []byte("session-33333")) {
		t.Fatalf("GetSession returned %q, want %q", got, "session-33333")
	}

	// Step 2: cache must now hold 1 entry.
	if n := wrapper.cache.Len(); n != 1 {
		t.Fatalf("cache Len after read-populate = %d, want 1", n)
	}

	// Step 3: bulk remove — must reach the read-populated entry via
	// SnapshotKeys("33333") and remove it from the cache.
	beforeRemoves := atomic.LoadUint64(&explicitRemoves)
	if err := wrapper.DeleteAllSessions(ctx, "33333"); err != nil {
		t.Fatalf("DeleteAllSessions: %v", err)
	}

	// Step 4: orphan-free assertion — cache must be empty.
	// Without the B1 fix (read-path secondaryIndex.Insert), the read-populated
	// entry would survive: cache.Len() would be 1 (orphan). With the fix: 0.
	if n := wrapper.cache.Len(); n != 0 {
		t.Errorf("cache Len after DeleteAllSessions = %d, want 0 (B1 orphan detected: read-populate not in index)", n)
	}

	// Step 5: counter delta must be exactly 1.
	afterRemoves := atomic.LoadUint64(&explicitRemoves)
	if delta := afterRemoves - beforeRemoves; delta != 1 {
		t.Errorf("explicitRemoves delta = %d, want 1 (one read-populated entry removed)", delta)
	}
}

// ---------------------------------------------------------------------------
// B1 regression gate (GetManySessions path): read-path populates via
// GetManySessions are tracked in the secondary index and reachable by
// DeleteAllSessions.
// ---------------------------------------------------------------------------

func TestSessionStore_GetMany_Populate_NoOrphan(t *testing.T) {
	ctx := context.Background()
	var explicitRemoves uint64
	wrapper, inner, _, _ := newTestCachedSessionStoreWithEvict(t, 1000, &explicitRemoves)

	// Seed the inner fake with 3 entries for "44444".
	for d := 0; d < 3; d++ {
		addr := fmt.Sprintf("44444:%d", d)
		if err := inner.PutSession(ctx, addr, []byte(fmt.Sprintf("session-44444-%d", d))); err != nil {
			t.Fatalf("seed inner.PutSession %s: %v", addr, err)
		}
	}
	inner.getCalls.Store(0)
	inner.putCalls.Store(0)
	inner.getManyCalls.Store(0)

	// Step 1: GetManySessions — exercises §201 read-populate loop, which calls
	// c.cache.Add AND secondaryIndex.Insert for each fetched entry.
	addrs := []string{"44444:0", "44444:1", "44444:2"}
	result, err := wrapper.GetManySessions(ctx, addrs)
	if err != nil {
		t.Fatalf("GetManySessions: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("GetManySessions returned %d entries, want 3", len(result))
	}

	// Step 2: all 3 must be in the cache.
	if n := wrapper.cache.Len(); n != 3 {
		t.Fatalf("cache Len after GetManySessions populate = %d, want 3", n)
	}

	// Step 3: bulk remove via DeleteAllSessions.
	beforeRemoves := atomic.LoadUint64(&explicitRemoves)
	if err := wrapper.DeleteAllSessions(ctx, "44444"); err != nil {
		t.Fatalf("DeleteAllSessions: %v", err)
	}

	// Step 4: orphan-free — all 3 read-populated entries must be gone.
	if n := wrapper.cache.Len(); n != 0 {
		t.Errorf("cache Len after DeleteAllSessions = %d, want 0 (B1 orphan: GetManySessions populate not in index)", n)
	}

	// Step 5: counter delta must be exactly 3.
	afterRemoves := atomic.LoadUint64(&explicitRemoves)
	if delta := afterRemoves - beforeRemoves; delta != 3 {
		t.Errorf("explicitRemoves delta = %d, want 3 (one per read-populated entry removed)", delta)
	}
}

// ---------------------------------------------------------------------------
// SPEC AC: micro-benchmark — 100k entries spanning 100 phones; DeleteAllSessions
// on one phone completes <1ms (target ~100µs); build-fail gate at >10ms.
// ---------------------------------------------------------------------------

func BenchmarkDeleteAllSessions_LargeShared(b *testing.B) {
	ctx := context.Background()
	var explicitRemoves uint64
	idx := newSessionSecondaryIndex()
	cache, err := lru.NewWithEvict[string, []byte](100_000, func(key string, _ []byte) {
		if jid, phone, ok := parseCacheKey(key); ok {
			idx.EvictCleanup(key, jid, phone)
		}
	})
	if err != nil {
		b.Fatalf("lru.NewWithEvict failed: %v", err)
	}
	inner := newFakeSessionStore()
	wrapper := NewCachedSessionStore(inner, "bench-jid", cache, &explicitRemoves, idx)

	// Pre-populate 100k entries: 100 phones × 1000 devices each.
	payload := []byte("benchmark-session-payload")
	for phoneIdx := 0; phoneIdx < 100; phoneIdx++ {
		for deviceIdx := 0; deviceIdx < 1000; deviceIdx++ {
			addr := fmt.Sprintf("%d:%d", phoneIdx, deviceIdx)
			if err := wrapper.PutSession(ctx, addr, payload); err != nil {
				b.Fatalf("pre-populate PutSession %s: %v", addr, err)
			}
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		phone := fmt.Sprintf("%d", i%100)

		// Exclude repopulate time from the measurement.
		b.StopTimer()
		for d := 0; d < 1000; d++ {
			addr := fmt.Sprintf("%s:%d", phone, d)
			if err := wrapper.PutSession(ctx, addr, payload); err != nil {
				b.Fatalf("repopulate PutSession: %v", err)
			}
		}
		b.StartTimer()

		wrapper.DeleteAllSessions(ctx, phone) //nolint:errcheck
	}
	b.StopTimer()

	// SPEC AC build-fail gate: >10ms per op is a regression.
	if b.N > 0 {
		nsPerOp := b.Elapsed().Nanoseconds() / int64(b.N)
		if nsPerOp > 10_000_000 {
			b.Fatalf("DeleteAllSessions regressed: %d ns/op (>10ms threshold)", nsPerOp)
		}
	}
}

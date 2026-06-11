// Copyright (c) 2026 Kavtov Platform (Phase 35.2-09)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// cached_session_flusher_test.go covers the CachedSessionStore write-back
// wiring behaviors required by Phase 35.2-09:
//
//   - Zero double-write (W3): PutSession / PutManySessions enqueue into the
//     flusher with ZERO inner.Put* calls on the flusher-set path.
//
//   - Read coherence on ALL readers (the 17.13 guard): GetSession,
//     GetManySessions, AND HasSession return the buffered result for a dirty
//     address whose inner DB row does not exist AND which is evicted from the
//     LRU (the exact class that caused 17.13 read-gap / WhatsApp 479 errors).
//
//   - Delete coherence: DeleteSession drops the dirty entry so a buffered blob
//     cannot resurrect a deleted session.
//
//   - Drain on close: all dirty entries reach the inner store after Drain.
package sqlstore

import (
	"bytes"
	"context"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/types"
)

// ---------------------------------------------------------------------------
// Test helper: newTestCachedSessionStoreWithFlusher wires a CachedSessionStore
// backed by a fakeSessionStore, a fresh LRU, a sessionSecondaryIndex, and a
// SessionFlusher backed by a counting fake inner store (countingFlushStore).
// ---------------------------------------------------------------------------

// countingFlushStore counts PutManySessions calls and delegates to the same
// fakeSessionStore so Get-after-drain reads back the written data.
type countingFlushStore struct {
	backing  *fakeSessionStore
	callCount int
}

func (c *countingFlushStore) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
	c.callCount++
	return c.backing.PutManySessions(ctx, sessions)
}

func newTestCachedSessionStoreWithFlusher(t *testing.T, capSize int) (
	*CachedSessionStore,
	*fakeSessionStore,
	*countingFlushStore,
	*SessionFlusher,
	*lru.Cache[string, []byte],
) {
	t.Helper()
	inner := newFakeSessionStore()
	flushBacking := &countingFlushStore{backing: inner}
	wrapper, flusher, sessionCache := newTestCachedSessionStoreWiring(t, capSize, flushBacking, inner)
	return wrapper, inner, flushBacking, flusher, sessionCache
}

// newTestCachedSessionStoreWiring is the lower-level wiring helper: it accepts
// an arbitrary flushSessionBatch (e.g. blockingFlushSessionStore for the CR-01
// interleaving tests) and the inner fakeSessionStore the wrapper delegates to.
func newTestCachedSessionStoreWiring(t *testing.T, capSize int, flushBacking flushSessionBatch, inner *fakeSessionStore) (
	*CachedSessionStore,
	*SessionFlusher,
	*lru.Cache[string, []byte],
) {
	t.Helper()
	idx := newSessionSecondaryIndex()
	sessionCache, err := lru.NewWithEvict[string, []byte](capSize, func(key string, _ []byte) {
		if jid, phone, ok := parseCacheKey(key); ok {
			idx.EvictCleanup(key, jid, phone)
		}
	})
	if err != nil {
		t.Fatalf("lru.NewWithEvict failed: %v", err)
	}

	var dummyExplicitRemoves uint64
	wrapper := NewCachedSessionStore(inner, "test-jid", sessionCache, &dummyExplicitRemoves, idx)

	// Do NOT Start() the flusher here — the goroutine racing with assertions
	// would make dirty-count checks racy. Tests use Drain() for synchronous
	// draining; TestCachedSession_DrainFlushesAll calls Stop() explicitly.
	flusher := newSessionFlusherForTest(flushBacking, 1000, 5000*time.Second /* ticker irrelevant without Start */)
	t.Cleanup(flusher.Drain) // Drain is safe to call when not started

	wrapper.SetFlusher(flusher)
	return wrapper, flusher, sessionCache
}

// ---------------------------------------------------------------------------
// TestCachedSession_ZeroDoubleWrite_PutSession
// After calling PutSession with a flusher set, inner.PutSession must NOT be
// called (zero double-write; W3). The blob is reachable via the flusher dirty-
// set and/or the LRU.
// ---------------------------------------------------------------------------

func TestCachedSession_ZeroDoubleWrite_PutSession(t *testing.T) {
	ctx := context.Background()
	c, inner, _, flusher, _ := newTestCachedSessionStoreWithFlusher(t, 100)

	blob := []byte("write-back-session")
	if err := c.PutSession(ctx, "addr-wb:0", blob); err != nil {
		t.Fatalf("PutSession: %v", err)
	}

	// inner.PutSession must NOT have been called (zero double-write).
	if got := inner.putCalls.Load(); got != 0 {
		t.Errorf("inner.putCalls = %d, want 0 (zero double-write on flusher-set path)", got)
	}
	// The blob must be in the flusher dirty-set.
	if n := flusher.DirtyCount(); n != 1 {
		t.Errorf("flusher.DirtyCount = %d, want 1", n)
	}
	_, ok := flusher.Peek("addr-wb:0")
	if !ok {
		t.Error("flusher.Peek returned not-found for recently-enqueued address")
	}
}

// ---------------------------------------------------------------------------
// TestCachedSession_ZeroDoubleWrite_PutManySessions
// After calling PutManySessions with a flusher set, inner.PutManySessions
// must NOT be called.
// ---------------------------------------------------------------------------

func TestCachedSession_ZeroDoubleWrite_PutManySessions(t *testing.T) {
	ctx := context.Background()
	c, inner, _, flusher, _ := newTestCachedSessionStoreWithFlusher(t, 100)

	sessions := map[string][]byte{
		"m-addr1:0": []byte("s1"),
		"m-addr2:0": []byte("s2"),
	}
	if err := c.PutManySessions(ctx, sessions); err != nil {
		t.Fatalf("PutManySessions: %v", err)
	}

	// inner.PutManySessions must NOT have been called.
	if got := inner.putManyCalls.Load(); got != 0 {
		t.Errorf("inner.putManyCalls = %d, want 0 (zero double-write on flusher-set path)", got)
	}
	// Both addresses in the flusher dirty-set.
	if n := flusher.DirtyCount(); n != 2 {
		t.Errorf("flusher.DirtyCount = %d, want 2", n)
	}
}

// ---------------------------------------------------------------------------
// TestCachedSession_ReadCoherence_GetSession_LRUEvicted
// The 17.13 read-gap guard (BLOCKER): GetSession returns the buffered blob
// for a dirty address that is NOT in the LRU (evicted from the tiny cap=2
// LRU by later PutSession calls). The inner store does NOT hold the row yet
// (not yet flushed).
// ---------------------------------------------------------------------------

func TestCachedSession_ReadCoherence_GetSession_LRUEvicted(t *testing.T) {
	ctx := context.Background()
	// tiny cap=2 so that the third Put evicts the first.
	c, inner, _, flusher, _ := newTestCachedSessionStoreWithFlusher(t, 2)
	_ = flusher

	blobTarget := []byte("target-session")
	if err := c.PutSession(ctx, "evict-me:0", blobTarget); err != nil {
		t.Fatalf("PutSession evict-me: %v", err)
	}
	// Evict "evict-me:0" from the LRU by putting two more entries.
	if err := c.PutSession(ctx, "other1:0", []byte("o1")); err != nil {
		t.Fatalf("PutSession other1: %v", err)
	}
	if err := c.PutSession(ctx, "other2:0", []byte("o2")); err != nil {
		t.Fatalf("PutSession other2: %v", err)
	}

	// The inner store must NOT have "evict-me:0" (not yet flushed).
	if got := inner.putCalls.Load(); got != 0 {
		// On the flusher path, inner is never called directly.
		t.Logf("inner.putCalls = %d (should be 0 on flusher path)", got)
	}
	innerHas, err := inner.HasSession(ctx, "evict-me:0")
	if err != nil {
		t.Fatalf("inner.HasSession: %v", err)
	}
	if innerHas {
		t.Fatal("inner store already holds evict-me:0 — expected it to be unflushed (test setup error)")
	}

	// GetSession must return the buffered blob via flusher.Peek (read-coherence).
	got, err := c.GetSession(ctx, "evict-me:0")
	if err != nil {
		t.Fatalf("GetSession for LRU-evicted dirty address: %v", err)
	}
	if !bytes.Equal(got, blobTarget) {
		t.Errorf("GetSession = %q, want %q (read-coherence: flusher dirty-set consulted after LRU miss)", got, blobTarget)
	}
}

// ---------------------------------------------------------------------------
// TestCachedSession_ReadCoherence_HasSession_LRUEvicted
// The critical BLOCKER: HasSession returns true for a dirty address NOT in
// the LRU (evicted by cap overflow) AND not yet flushed to the inner store.
// ContainsSession calls this at send.go:1398 / sendfb.go:618 / retry.go:228
// OUTSIDE WithCachedSessions scope — missing this causes ErrNoSession /
// WhatsApp 479 (the 17.13 read-gap class).
// ---------------------------------------------------------------------------

func TestCachedSession_ReadCoherence_HasSession_LRUEvicted(t *testing.T) {
	ctx := context.Background()
	// tiny cap=2 so that the third Put evicts the first.
	c, inner, _, _, _ := newTestCachedSessionStoreWithFlusher(t, 2)

	if err := c.PutSession(ctx, "has-evict:0", []byte("check-me")); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	// Evict "has-evict:0" from the LRU.
	if err := c.PutSession(ctx, "other3:0", []byte("o3")); err != nil {
		t.Fatalf("PutSession other3: %v", err)
	}
	if err := c.PutSession(ctx, "other4:0", []byte("o4")); err != nil {
		t.Fatalf("PutSession other4: %v", err)
	}

	// Confirm inner does NOT hold "has-evict:0".
	innerHas, _ := inner.HasSession(ctx, "has-evict:0")
	if innerHas {
		t.Fatal("inner store holds has-evict:0 — test setup error; expected unflushed")
	}

	// HasSession must return true via flusher.Peek (read-coherence for ContainsSession callers).
	has, err := c.HasSession(ctx, "has-evict:0")
	if err != nil {
		t.Fatalf("HasSession: %v", err)
	}
	if !has {
		t.Error("HasSession = false for dirty LRU-evicted address — read-coherence BROKEN (17.13 read-gap class)")
	}
}

// ---------------------------------------------------------------------------
// TestCachedSession_ReadCoherence_GetManySessions_LRUEvicted
// GetManySessions returns buffered blobs for dirty LRU-evicted addresses.
// ---------------------------------------------------------------------------

func TestCachedSession_ReadCoherence_GetManySessions_LRUEvicted(t *testing.T) {
	ctx := context.Background()
	c, inner, _, flusher, _ := newTestCachedSessionStoreWithFlusher(t, 2)
	_ = flusher

	if err := c.PutSession(ctx, "many-evict:0", []byte("many-v")); err != nil {
		t.Fatalf("PutSession many-evict: %v", err)
	}
	// Evict from LRU.
	if err := c.PutSession(ctx, "many-other1:0", []byte("o")); err != nil {
		t.Fatalf("PutSession many-other1: %v", err)
	}
	if err := c.PutSession(ctx, "many-other2:0", []byte("o")); err != nil {
		t.Fatalf("PutSession many-other2: %v", err)
	}

	// Confirm inner does not hold it.
	innerHas, _ := inner.HasSession(ctx, "many-evict:0")
	if innerHas {
		t.Fatal("inner store holds many-evict:0 — expected unflushed")
	}

	result, err := c.GetManySessions(ctx, []string{"many-evict:0"})
	if err != nil {
		t.Fatalf("GetManySessions: %v", err)
	}
	v, ok := result["many-evict:0"]
	if !ok {
		t.Fatal("GetManySessions: many-evict:0 missing from result (read-coherence BROKEN)")
	}
	if !bytes.Equal(v, []byte("many-v")) {
		t.Errorf("GetManySessions[many-evict:0] = %q, want %q", v, "many-v")
	}
}

// ---------------------------------------------------------------------------
// TestCachedSession_DeleteCoherence
// DeleteSession drops the dirty entry from the flusher. A subsequent
// HasSession / GetSession returns false/nil — the buffered blob cannot
// resurrect a deleted session.
// ---------------------------------------------------------------------------

func TestCachedSession_DeleteCoherence(t *testing.T) {
	ctx := context.Background()
	c, _, _, flusher, _ := newTestCachedSessionStoreWithFlusher(t, 100)

	if err := c.PutSession(ctx, "del-addr:0", []byte("delete-me")); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	if n := flusher.DirtyCount(); n != 1 {
		t.Fatalf("flusher.DirtyCount after Put = %d, want 1", n)
	}

	if err := c.DeleteSession(ctx, "del-addr:0"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	// Dirty entry must be gone.
	if n := flusher.DirtyCount(); n != 0 {
		t.Errorf("flusher.DirtyCount after DeleteSession = %d, want 0", n)
	}
	_, ok := flusher.Peek("del-addr:0")
	if ok {
		t.Error("flusher.Peek returned found after DeleteSession (dirty entry not removed)")
	}

	// GetSession must return nil (no resurrection via the flusher).
	has, err := c.HasSession(ctx, "del-addr:0")
	if err != nil {
		t.Fatalf("HasSession after Delete: %v", err)
	}
	if has {
		t.Error("HasSession returned true after DeleteSession (session resurrected from flusher dirty-set)")
	}
}

// ---------------------------------------------------------------------------
// TestCachedSession_DrainFlushesAll
// After calling flusher.Drain (simulating closeSignalCaches), all dirty
// entries reach the inner store (the countingFlushStore's backing fakeSessionStore).
// ---------------------------------------------------------------------------

func TestCachedSession_DrainFlushesAll(t *testing.T) {
	ctx := context.Background()
	c, inner, flushBacking, flusher, _ := newTestCachedSessionStoreWithFlusher(t, 100)
	_ = flushBacking

	addrs := []string{"drain1:0", "drain2:0", "drain3:0"}
	for i, addr := range addrs {
		if err := c.PutSession(ctx, addr, []byte("v"+string(rune('0'+i)))); err != nil {
			t.Fatalf("PutSession %s: %v", addr, err)
		}
	}
	if n := flusher.DirtyCount(); n != len(addrs) {
		t.Fatalf("flusher.DirtyCount before drain = %d, want %d", n, len(addrs))
	}

	flusher.Stop() // Stop calls Drain synchronously.

	if n := flusher.DirtyCount(); n != 0 {
		t.Fatalf("flusher.DirtyCount after Stop = %d, want 0", n)
	}
	for i, addr := range addrs {
		got, err := inner.GetSession(ctx, addr)
		if err != nil {
			t.Fatalf("inner.GetSession %s: %v", addr, err)
		}
		want := []byte("v" + string(rune('0'+i)))
		if !bytes.Equal(got, want) {
			t.Errorf("inner[%s] = %q, want %q", addr, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// TestCachedSession_CR01_DeleteSessionNotResurrectedByInflightFlush
// CR-01 regression: a DeleteSession completing while a flush batch is in
// flight (snapshotted but not yet written) must NOT have its row re-upserted
// by that batch. The blockingFlushSessionStore holds the flush open between
// snapshot and DB-write apply; the delete is issued inside that window.
// ---------------------------------------------------------------------------

func TestCachedSession_CR01_DeleteSessionNotResurrectedByInflightFlush(t *testing.T) {
	ctx := context.Background()
	inner := newFakeSessionStore()
	blocking := newBlockingFlushSessionStore(inner)
	c, flusher, _ := newTestCachedSessionStoreWiring(t, 100, blocking, inner)

	if err := c.PutSession(ctx, "cr01-addr:0", []byte("doomed")); err != nil {
		t.Fatalf("PutSession: %v", err)
	}

	flushDone := make(chan struct{})
	go func() {
		flusher.runFlush()
		close(flushDone)
	}()
	<-blocking.writeStarted // flush has snapshotted the dirty-set and is mid-DB-write

	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- c.DeleteSession(ctx, "cr01-addr:0")
	}()

	// With the CR-01 fix the delete is serialized behind the in-flight flush
	// (blocks on flushMu); without it the delete completes inside the open
	// window and the released batch resurrects the row. The select only
	// sequences the release — the final-state assertions below are the actual
	// check, deterministic on both the fixed and the broken interleaving.
	select {
	case err := <-deleteDone:
		// Pre-fix interleaving: delete won the race while the flush was paused.
		if err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		close(blocking.writeRelease)
		<-flushDone
	case <-time.After(200 * time.Millisecond):
		// Fixed behavior: delete is blocked behind the in-flight flush cycle.
		close(blocking.writeRelease)
		<-flushDone
		if err := <-deleteDone; err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
	}

	if has, err := inner.HasSession(ctx, "cr01-addr:0"); err != nil {
		t.Fatalf("inner.HasSession: %v", err)
	} else if has {
		t.Fatal("deleted session resurrected in inner store by in-flight flush batch (CR-01)")
	}
	if _, ok := flusher.Peek("cr01-addr:0"); ok {
		t.Fatal("dirty entry survived DeleteSession (CR-01)")
	}
	flusher.Drain()
	if has, _ := inner.HasSession(ctx, "cr01-addr:0"); has {
		t.Fatal("deleted session resurrected by post-delete Drain (CR-01)")
	}
}

// ---------------------------------------------------------------------------
// TestCachedSession_CR01_DeleteAllSessionsNotResurrectedByInflightFlush
// Same race as above for the DeleteAllSessions sweep path (identity change →
// DeleteAllSessions is live in prod at notification.go:59).
// ---------------------------------------------------------------------------

func TestCachedSession_CR01_DeleteAllSessionsNotResurrectedByInflightFlush(t *testing.T) {
	ctx := context.Background()
	inner := newFakeSessionStore()
	blocking := newBlockingFlushSessionStore(inner)
	c, flusher, _ := newTestCachedSessionStoreWiring(t, 100, blocking, inner)

	if err := c.PutSession(ctx, "cr01b:0", []byte("doomed-all")); err != nil {
		t.Fatalf("PutSession: %v", err)
	}

	flushDone := make(chan struct{})
	go func() {
		flusher.runFlush()
		close(flushDone)
	}()
	<-blocking.writeStarted

	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- c.DeleteAllSessions(ctx, "cr01b")
	}()

	select {
	case err := <-deleteDone:
		if err != nil {
			t.Fatalf("DeleteAllSessions: %v", err)
		}
		close(blocking.writeRelease)
		<-flushDone
	case <-time.After(200 * time.Millisecond):
		close(blocking.writeRelease)
		<-flushDone
		if err := <-deleteDone; err != nil {
			t.Fatalf("DeleteAllSessions: %v", err)
		}
	}

	if has, _ := inner.HasSession(ctx, "cr01b:0"); has {
		t.Fatal("bulk-deleted session resurrected in inner store by in-flight flush batch (CR-01)")
	}
	if _, ok := flusher.Peek("cr01b:0"); ok {
		t.Fatal("dirty entry survived DeleteAllSessions sweep (CR-01)")
	}
	flusher.Drain()
	if has, _ := inner.HasSession(ctx, "cr01b:0"); has {
		t.Fatal("bulk-deleted session resurrected by post-delete Drain (CR-01)")
	}
}

// ---------------------------------------------------------------------------
// TestCachedSession_CR04_MigratePNToLIDSweepsDirtySet
// CR-04 regression: a PN-addressed session that is dirty (buffered, not yet
// flushed) at MigratePNToLID time must (a) be flushed to the DB before the
// inner migration so the freshest ratchet state migrates to the LID key, and
// (b) be removed from the dirty-set so it cannot later flush back as a
// zombie pn row that post-migration LID-addressed reads never consult.
// ---------------------------------------------------------------------------

func TestCachedSession_CR04_MigratePNToLIDSweepsDirtySet(t *testing.T) {
	ctx := context.Background()
	c, inner, _, flusher, _ := newTestCachedSessionStoreWithFlusher(t, 100)

	pn := types.JID{User: "12345", Server: types.DefaultUserServer}
	lid := types.JID{User: "777", Server: types.HiddenUserServer}
	pnAddr := pn.SignalAddressUser() + ":0"
	lidAddr := lid.SignalAddressUser() + ":0"

	fresh := []byte("freshest-ratchet")
	if err := c.PutSession(ctx, pnAddr, fresh); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	// Setup invariant: the blob is dirty (buffered), NOT yet in the inner store.
	if has, _ := inner.HasSession(ctx, pnAddr); has {
		t.Fatal("setup: pn session already flushed to inner — test needs it dirty")
	}

	if err := c.MigratePNToLID(ctx, pn, lid); err != nil {
		t.Fatalf("MigratePNToLID: %v", err)
	}

	// (a) The freshest (dirty) blob must have been migrated to the LID key.
	got, err := inner.GetSession(ctx, lidAddr)
	if err != nil {
		t.Fatalf("inner.GetSession(%s): %v", lidAddr, err)
	}
	if !bytes.Equal(got, fresh) {
		t.Fatalf("migrated LID session = %q, want %q — dirty PN state missed the migration (stale LID row, CR-04)", got, fresh)
	}
	// (b) No PN-addressed dirty entry may survive the migration.
	if _, ok := flusher.Peek(pnAddr); ok {
		t.Fatal("PN dirty entry survived MigratePNToLID — would flush back as a zombie pn row (CR-04)")
	}
	// (c) A post-migration drain must not resurrect the pn row.
	flusher.Drain()
	if has, _ := inner.HasSession(ctx, pnAddr); has {
		t.Fatal("zombie pn row written to inner store after migration (CR-04)")
	}
}

// ---------------------------------------------------------------------------
// TestCachedSession_NilFlusherFallthrough
// When no flusher is set (nil), PutSession falls through to inner.PutSession
// (backward compat / write-through fallback).
// ---------------------------------------------------------------------------

func TestCachedSession_NilFlusherFallthrough(t *testing.T) {
	ctx := context.Background()
	// Use the existing strict write-through constructor (no SetFlusher call).
	c, inner, _ := newTestCachedSessionStore(t, 16)

	if err := c.PutSession(ctx, "nil-fl:0", []byte("via-inner")); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	// With no flusher, inner.PutSession must be called.
	if got := inner.putCalls.Load(); got != 1 {
		t.Errorf("inner.putCalls = %d, want 1 (nil-flusher fallback must call inner)", got)
	}
}

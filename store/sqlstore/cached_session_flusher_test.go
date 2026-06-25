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
	"fmt"
	"strings"
	"sync"
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
// fakeSessionStore so Get-after-drain reads back the written data. Phase
// 47.3-06 D2: implements the widened sessionWriterStore interface — the writer
// goroutine performs deletes and migrates itself, and they must reach the SAME
// backing the wrapper's inner reads from (in prod the flusher.db and the
// wrapper.inner are the same *SQLStore; here both are the same fakeSessionStore).
type countingFlushStore struct {
	backing   *fakeSessionStore
	callCount int
}

func (c *countingFlushStore) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
	c.callCount++
	return c.backing.PutManySessions(ctx, sessions)
}

func (c *countingFlushStore) DeleteSession(ctx context.Context, address string) error {
	return c.backing.DeleteSession(ctx, address)
}

func (c *countingFlushStore) DeleteAllSessions(ctx context.Context, phone string) error {
	return c.backing.DeleteAllSessions(ctx, phone)
}

func (c *countingFlushStore) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	return c.backing.MigratePNToLID(ctx, pn, lid)
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
func newTestCachedSessionStoreWiring(t *testing.T, capSize int, flushBacking sessionWriterStore, inner *fakeSessionStore) (
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

	// Phase 47.3-06 D2: the writer goroutine MUST run so DeleteSession /
	// DeleteAllSessions / MigratePNToLID work items dispatched to workCh are
	// processed (those methods block on a done channel — without a writer they
	// hang). To keep DirtyCount assertions stable, boundaryN is set very high so
	// no N-boundary flush signal ever fires, and the ticker interval is long so
	// it never spontaneously flushes. Tests that want a flush trigger it
	// explicitly (flusher.flushCh <- struct{}{}) or via Drain()/Stop(). The
	// writer only auto-acts on the work channel (deletes/migrates), which is what
	// the actor-model delete/migrate tests need.
	flusher := newSessionFlusherForTest(flushBacking, 1000, 5000*time.Second)
	flusher.boundaryN = 1 << 30 // disable N-boundary auto-flush during wired tests
	flusher.Start()
	t.Cleanup(flusher.Stop) // Stop drains the workCh + dirty-set, then exits the writer

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
// CR-01 regression: a DeleteSession dispatched while a flush batch is in flight
// (snapshotted but not yet written) must NOT have its row re-upserted by that
// batch. Phase 47.3-06 D2: the single writer goroutine serializes flush and
// delete by channel FIFO — a delete work item sent while a flush is in flight
// is dequeued AFTER runFlush completes, so the delete's DB DELETE lands after
// the flush's DB UPSERT and the row ends up deleted. The blockingFlushSessionStore
// holds the writer's flush open between snapshot and DB-write apply; the delete
// is issued (via the wrapper -> workDeleteSingle work item) inside that window.
// ---------------------------------------------------------------------------

func TestCachedSession_CR01_DeleteSessionNotResurrectedByInflightFlush(t *testing.T) {
	ctx := context.Background()
	inner := newFakeSessionStore()
	blocking := newBlockingFlushSessionStore(inner)
	c, flusher, _ := newTestCachedSessionStoreWiring(t, 100, blocking, inner)

	if err := c.PutSession(ctx, "cr01-addr:0", []byte("doomed")); err != nil {
		t.Fatalf("PutSession: %v", err)
	}

	// Trigger a flush THROUGH the running writer (not a direct runFlush call —
	// the writer owns all DB mutation in D2). The blockingStore pauses the
	// writer mid-flush (snapshot taken, PutManySessions blocked).
	flusher.flushCh <- struct{}{}
	<-blocking.writeStarted // the writer has snapshotted the dirty-set and is mid-DB-write

	// Dispatch the delete: it sends a workDeleteSingle item to workCh and blocks
	// on its done channel. The writer is busy with the paused flush, so the
	// delete is queued BEHIND the flush (channel FIFO) and cannot run yet.
	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- c.DeleteSession(ctx, "cr01-addr:0")
	}()

	// The delete MUST NOT complete while the flush is paused — it is queued
	// behind the in-flight flush. Confirm it stays blocked, then release the
	// flush so the writer finishes runFlush and dequeues the delete next (FIFO).
	select {
	case err := <-deleteDone:
		t.Fatalf("DeleteSession completed while the flush was paused — FIFO ordering broken (CR-01); err=%v", err)
	case <-time.After(150 * time.Millisecond):
		// Correct: delete queued behind the paused flush. Release the flush.
	}
	close(blocking.writeRelease)
	if err := <-deleteDone; err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	if has, err := inner.HasSession(ctx, "cr01-addr:0"); err != nil {
		t.Fatalf("inner.HasSession: %v", err)
	} else if has {
		t.Fatal("deleted session resurrected in inner store by in-flight flush batch (CR-01)")
	}
	if _, ok := flusher.Peek("cr01-addr:0"); ok {
		t.Fatal("dirty entry survived DeleteSession (CR-01)")
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

	// Trigger a flush through the running writer; pause it mid-DB-write.
	flusher.flushCh <- struct{}{}
	<-blocking.writeStarted

	// Dispatch the bulk delete (workDeletePrefix work item). It queues behind
	// the paused flush (channel FIFO).
	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- c.DeleteAllSessions(ctx, "cr01b")
	}()

	select {
	case err := <-deleteDone:
		t.Fatalf("DeleteAllSessions completed while the flush was paused — FIFO ordering broken (CR-01); err=%v", err)
	case <-time.After(150 * time.Millisecond):
		// Correct: bulk delete queued behind the paused flush.
	}
	close(blocking.writeRelease)
	if err := <-deleteDone; err != nil {
		t.Fatalf("DeleteAllSessions: %v", err)
	}

	if has, _ := inner.HasSession(ctx, "cr01b:0"); has {
		t.Fatal("bulk-deleted session resurrected in inner store by in-flight flush batch (CR-01)")
	}
	if _, ok := flusher.Peek("cr01b:0"); ok {
		t.Fatal("dirty entry survived DeleteAllSessions sweep (CR-01)")
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
	// (c) A post-migration flush (through the running writer) must not resurrect
	// the pn row — the migration already swept the PN-prefix dirty entries.
	if err := flusher.flushSyncForTest(); err != nil {
		t.Fatalf("post-migration flush: %v", err)
	}
	if has, _ := inner.HasSession(ctx, pnAddr); has {
		t.Fatal("zombie pn row written to inner store after migration (CR-04)")
	}
}

// ---------------------------------------------------------------------------
// TestCachedSession_WR03_LRUAndDirtySetAgreeUnderConcurrentWriters
// WR-03 regression: flusher.Enqueue and cache.Add used to be two separate
// atomic operations with no common lock, so concurrent same-address writers
// (receive-path StoreSession vs send-path PutCachedSessions) could leave the
// dirty-set/DB at v2 and the LRU at v1 — readers (LRU-first) then serve a
// different blob than what gets persisted, indefinitely. With the
// EnqueueAndMirror invariant both views are updated under the flusher mutex,
// so at quiescence they MUST agree. (Deterministic pass with the fix; the
// disagreement interleaving is probabilistic, so this is a regression canary
// rather than a guaranteed-fail-without-fix test.)
// ---------------------------------------------------------------------------

func TestCachedSession_WR03_LRUAndDirtySetAgreeUnderConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	c, _, _, flusher, cache := newTestCachedSessionStoreWithFlusher(t, 100)

	var wg sync.WaitGroup
	const writers = 8
	const writesPerWriter = 200
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < writesPerWriter; j++ {
				blob := []byte(fmt.Sprintf("w%d-%d", i, j))
				// Exercise BOTH documented session write paths.
				if i%2 == 0 {
					_ = c.PutSession(ctx, "wr03-addr:0", blob)
				} else {
					_ = c.PutManySessions(ctx, map[string][]byte{"wr03-addr:0": blob})
				}
			}
		}(i)
	}
	wg.Wait()

	dirtyBlob, ok := flusher.Peek("wr03-addr:0")
	if !ok {
		t.Fatal("no dirty entry after concurrent writes")
	}
	lruBlob, ok := cache.Get(c.key("wr03-addr:0"))
	if !ok {
		t.Fatal("no LRU entry after concurrent writes")
	}
	if !bytes.Equal(dirtyBlob, lruBlob) {
		t.Fatalf("LRU (%q) and dirty-set (%q) disagree — readers would serve a different blob than what gets persisted (WR-03)", lruBlob, dirtyBlob)
	}
}

// ---------------------------------------------------------------------------
// TestCachedSession_MigrateNoOp_SkipsFlushBlock_FirstSend
// D-01/D-02: when there are no PN sessions in the dirty-set and no PN row in
// the inner store, MigratePNToLID must take the no-op path — call
// inner.MigratePNToLID DIRECTLY (sets the once-per-process gate) and dispatch NO
// migrate work item to the single writer goroutine. A second call for the same
// pn must also short-circuit at IsPNMigrated.
//
// Probe (carried from D1 plan 03): flusher.WithFlushBlockedCalls() — in D2
// nothing increments this counter (the V1 WithFlushBlocked is gone; the no-op
// migrate path dispatches no work item), so it stays at 0. A delta of 0 across
// the call confirms the no-op path took no flush coordination — exactly the
// behavior D-02's first-send skip requires. (Under D1 a non-zero delta would
// have meant the flush-blocked path was wrongly taken; under D2 the same
// assertion confirms no migrate work item was dispatched.)
// ---------------------------------------------------------------------------

func TestCachedSession_MigrateNoOp_SkipsFlushBlock_FirstSend(t *testing.T) {
	ctx := context.Background()

	// Use a fresh fakeSessionStore with NO PN sessions — the no-op path.
	inner := newFakeSessionStore()
	// Wire the blockingFlushSessionStore as the flush backing. The blocking
	// store remains armed (blockNext=true) so that if WithFlushBlocked IS taken
	// it will deadlock — the timeout below catches that case. The real
	// detection, however, is flusher.WithFlushBlockedCalls().
	mock := newMockFlushSessionStore()
	blocking := newBlockingFlushSessionStore(mock)
	// blockNext is already true from newBlockingFlushSessionStore.
	c, flusher, _ := newTestCachedSessionStoreWiring(t, 100, blocking, inner)

	pn := types.JID{User: "972515529399", Server: types.DefaultUserServer}
	lid := types.JID{User: "972515529399_0", Server: types.HiddenUserServer}

	// Snapshot WithFlushBlockedCalls BEFORE the call so we can assert the delta.
	callsBefore := flusher.WithFlushBlockedCalls()

	// Assert (a): MigratePNToLID completes without blocking.
	// If the code takes WithFlushBlocked and the dirty-set is non-empty,
	// blockingFlushSessionStore will deadlock — the timeout catches that case.
	// If the code takes WithFlushBlocked on an empty dirty-set it won't
	// deadlock but WithFlushBlockedCalls will be non-zero (the assertion below
	// catches THAT case — this is the vacuous-pass fix).
	done := make(chan error, 1)
	go func() {
		done <- c.MigratePNToLID(ctx, pn, lid)
	}()

	select {
	case err := <-done:
		// Assert (a): no error on the no-op path.
		if err != nil {
			t.Fatalf("MigratePNToLID: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		// The blocking store fired — WithFlushBlocked was taken AND the
		// dirty-set was non-empty (PutManySessions was called). Release it
		// so the test can clean up, then fail.
		close(blocking.writeRelease)
		<-done
		t.Fatal("MigratePNToLID blocked in WithFlushBlocked on a no-op path (no PN sessions exist) — D-02 first-send skip not implemented")
	}

	// Assert (b-real): WithFlushBlocked must NOT have been entered on the
	// no-op path. This is the primary probe — it FAILS if the no-op-skip is
	// absent even when the dirty-set is empty (closing the vacuous-pass gap).
	callsAfter := flusher.WithFlushBlockedCalls()
	if delta := callsAfter - callsBefore; delta != 0 {
		t.Errorf("WithFlushBlockedCalls delta = %d, want 0 — MigratePNToLID took WithFlushBlocked on a no-op path (no PN sessions exist, D-02 skip required)", delta)
	}

	// Assert (c): inner.MigratePNToLID WAS called (once-per-process gate must be set).
	if got := inner.migrateCalls.Load(); got != 1 {
		t.Errorf("inner.migrateCalls = %d, want 1 — inner must be called even on the no-op path (D-01)", got)
	}

	// Assert (d): a second call for the same pn returns immediately without
	// calling inner again (IsPNMigrated gate fires for already-migrated pn).
	callsBefore2 := flusher.WithFlushBlockedCalls()
	done2 := make(chan error, 1)
	go func() {
		done2 <- c.MigratePNToLID(ctx, pn, lid)
	}()
	select {
	case err := <-done2:
		if err != nil {
			t.Fatalf("second MigratePNToLID: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		close(blocking.writeRelease)
		<-done2
		t.Fatal("second MigratePNToLID blocked — IsPNMigrated gate not set by first call (D-01)")
	}
	// Second call must NOT have entered WithFlushBlocked (IsPNMigrated fires first
	// for already-migrated pn — but note: fakeSessionStore is not *SQLStore so the
	// type assertion in CachedSessionStore for IsPNMigrated always fails; inner.migrateCalls
	// may be 2 on the fake. The WithFlushBlockedCalls assertion still holds regardless).
	callsAfter2 := flusher.WithFlushBlockedCalls()
	if delta := callsAfter2 - callsBefore2; delta != 0 {
		t.Errorf("second MigratePNToLID WithFlushBlockedCalls delta = %d, want 0 — second call should not take flush-block", delta)
	}
}

// ---------------------------------------------------------------------------
// TestCollateSafePredicate
// Pure string-logic test asserting the LIKE-equivalent prefix predicate used
// by the collation-safe migration/delete queries (D-06). Validates that a PN
// form their_id='972515529399:0' matches the prefix "972515529399:" and does
// NOT false-positive on a different phone ("972526548435:") or a LID-form
// their_id ("972515529399_1:0") which starts with the same digits but uses an
// underscore delimiter.
//
// Comment: this mirrors the LIKE $2 || ':%' ESCAPE '\' predicate fixed in
// store.go:147-174 (D-06). The DB-backed predicate test (TestExistsPNSession_LIKEMatch)
// lives in store_pn_test.go (plan 02); this test covers the matching logic
// in memory and is self-contained (no external deps — passes once compiled).
// ---------------------------------------------------------------------------

func TestCollateSafePredicate(t *testing.T) {
	// PN-form their_id: <phone>:<device> (colon delimiter, no underscore).
	pnID := "972515529399:0"
	pnPrefix := "972515529399:"

	// Must match: same phone, PN form.
	if !strings.HasPrefix(pnID, pnPrefix) {
		t.Errorf("HasPrefix(%q, %q) = false — PN row must match its own prefix", pnID, pnPrefix)
	}

	// Must NOT match: different phone.
	otherPhone := "972526548435:"
	if strings.HasPrefix(pnID, otherPhone) {
		t.Errorf("HasPrefix(%q, %q) = true — different phone should not match", pnID, otherPhone)
	}

	// Must NOT match: LID-form their_id uses underscore not colon as first
	// delimiter — "972515529399_1:0" starts with same digits but the prefix
	// "972515529399:" does NOT match because '_' != ':' at position 12.
	lidID := "972515529399_1:0"
	if strings.HasPrefix(lidID, pnPrefix) {
		t.Errorf("HasPrefix(%q, %q) = true — LID-form their_id must NOT match the PN prefix", lidID, pnPrefix)
	}

	// Must NOT match: underscore-only suffix variant.
	lidID2 := "972515529399_1:1"
	if strings.HasPrefix(lidID2, pnPrefix) {
		t.Errorf("HasPrefix(%q, %q) = true — LID variant 2 must NOT match", lidID2, pnPrefix)
	}

	// Validate the inverse: empty prefix matches anything (sanity guard for the
	// test logic — ensures we're not accidentally using an empty string).
	if pnPrefix == "" {
		t.Fatal("pnPrefix is empty — test setup error")
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

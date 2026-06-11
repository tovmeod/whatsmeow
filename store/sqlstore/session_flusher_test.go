// Copyright (c) 2026 Kavtov Platform (Phase 35.2-09)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// session_flusher_test.go covers the SessionFlusher unit behavior:
//   - Same-address coalescing (two Enqueues collapse to one DB write, last-wins blob)
//   - Coalescing-realization ratio under repeat workload (W4)
//   - Bounded-staleness T-trigger: timer fires without additional Enqueue
//   - Bounded-staleness N-trigger: N=1 default signals flush on first Enqueue for an address
//   - Peek read-coherence: buffered-but-unflushed address returns the blob
//   - Stop() drains all dirty entries before returning
//   - Remove() drops a dirty entry so a stale blob cannot resurrect a deleted session
//
// Pattern: in-memory fake store, no real DB. All tests run under -race.
package sqlstore

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// mockFlushSessionStore is a thread-safe fake that implements flushSessionBatch.
// Records calls and stored sessions so tests can assert on them.
// ---------------------------------------------------------------------------

type mockFlushSessionStore struct {
	mu        sync.Mutex
	sessions  map[string][]byte
	callCount atomic.Int64
	failOnce  bool
	failErr   error
}

func newMockFlushSessionStore() *mockFlushSessionStore {
	return &mockFlushSessionStore{
		sessions: make(map[string][]byte),
	}
}

func (m *mockFlushSessionStore) PutManySessions(_ context.Context, sessions map[string][]byte) error {
	m.callCount.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failOnce && m.failErr != nil {
		err := m.failErr
		m.failOnce = false
		return err
	}
	for addr, blob := range sessions {
		stored := make([]byte, len(blob))
		copy(stored, blob)
		m.sessions[addr] = stored
	}
	return nil
}

func (m *mockFlushSessionStore) sessionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

func (m *mockFlushSessionStore) getSession(addr string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.sessions[addr]
	if !ok {
		return nil, false
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, true
}

// ---------------------------------------------------------------------------
// blockingFlushSessionStore wraps any flushSessionBatch and blocks the FIRST
// PutManySessions call between "write started" and "write released". This is
// the deterministic interleaving hook the CR-01/CR-02/CR-03/WR-01 regression
// tests use to hold a flush cycle open between its dirty-set snapshot and the
// DB-write apply, without sleeps.
// ---------------------------------------------------------------------------

type blockingFlushSessionStore struct {
	inner        flushSessionBatch
	blockNext    atomic.Bool
	writeStarted chan struct{}
	writeRelease chan struct{}
}

func newBlockingFlushSessionStore(inner flushSessionBatch) *blockingFlushSessionStore {
	b := &blockingFlushSessionStore{
		inner:        inner,
		writeStarted: make(chan struct{}),
		writeRelease: make(chan struct{}),
	}
	b.blockNext.Store(true)
	return b
}

func (b *blockingFlushSessionStore) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
	if b.blockNext.CompareAndSwap(true, false) {
		close(b.writeStarted)
		<-b.writeRelease
	}
	return b.inner.PutManySessions(ctx, sessions)
}

// ---------------------------------------------------------------------------
// newTestSessionFlusher builds a SessionFlusher with a small cap for test
// isolation and a short injectable flush interval.
// ---------------------------------------------------------------------------

func newTestSessionFlusher(t *testing.T, cap int) (*SessionFlusher, *mockFlushSessionStore) {
	t.Helper()
	store := newMockFlushSessionStore()
	f := newSessionFlusherForTest(store, cap, 50*time.Millisecond)
	return f, store
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_SameAddressCoalescing
// Two Enqueue calls for the SAME address within a window collapse to ONE DB
// write (last-wins blob). Assert DirtyCount and write-call-count prove coalescing.
// ---------------------------------------------------------------------------

func TestSessionFlusher_SameAddressCoalescing(t *testing.T) {
	f, store := newTestSessionFlusher(t, 1000)

	blob1 := []byte("session-v1")
	blob2 := []byte("session-v2")

	// Enqueue same address twice.
	f.Enqueue("addr:0", blob1)
	f.Enqueue("addr:0", blob2)

	// dirty-set should have exactly one entry (coalesced).
	if n := f.DirtyCount(); n != 1 {
		t.Fatalf("DirtyCount = %d, want 1 (coalesced)", n)
	}

	f.Drain()

	// Only one DB write call (one batch) but containing one address.
	if calls := store.callCount.Load(); calls != 1 {
		t.Errorf("PutManySessions call count = %d, want 1", calls)
	}
	// The stored value is the LAST blob (last-wins).
	v, ok := store.getSession("addr:0")
	if !ok {
		t.Fatal("addr:0 not found in store after Drain")
	}
	if string(v) != "session-v2" {
		t.Errorf("stored blob = %q, want %q (last-wins)", v, "session-v2")
	}
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_CoalescingRealizationRatio (W4)
// Under a representative same-address-repeat workload, assert the
// enqueue-count:actual-DB-write-count ratio reflects meaningful collapse.
// 10 enqueues for the same address → at most 1 DB write call (after Drain).
// ---------------------------------------------------------------------------

func TestSessionFlusher_CoalescingRealizationRatio(t *testing.T) {
	f, store := newTestSessionFlusher(t, 1000)

	const enqueueCount = 10
	for i := 0; i < enqueueCount; i++ {
		f.Enqueue("addr:0", []byte("session-repeat"))
	}

	// After all enqueues, the dirty-set should collapse to 1 entry.
	if n := f.DirtyCount(); n != 1 {
		t.Errorf("DirtyCount = %d after %d enqueues for same address, want 1", n, enqueueCount)
	}

	f.Drain()

	dbWrites := store.callCount.Load()
	ratio := float64(enqueueCount) / float64(dbWrites)
	t.Logf("W4 coalesce ratio: enqueue=%d db_writes=%d ratio=%.1f:1", enqueueCount, dbWrites, ratio)

	// The ratio should be at least 5:1 (conservative; same-address repeats
	// all coalesced → only 1 batch write, ratio = 10:1 or better).
	if ratio < 5.0 {
		t.Errorf("W4 coalescing ratio %.1f:1 is below expected minimum 5:1 (enqueue=%d db_writes=%d)",
			ratio, enqueueCount, dbWrites)
	}
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_MultiAddressCoalescing
// Many distinct addresses in one batch drain = one PutManySessions call
// (batch drain collapses all distinct addresses into one transaction).
// ---------------------------------------------------------------------------

func TestSessionFlusher_MultiAddressCoalescing(t *testing.T) {
	f, store := newTestSessionFlusher(t, 1000)

	const addrCount = 50
	for i := 0; i < addrCount; i++ {
		f.Enqueue(addressForIdx(i), []byte("session"))
	}
	if n := f.DirtyCount(); n != addrCount {
		t.Fatalf("DirtyCount = %d, want %d", n, addrCount)
	}

	f.Drain()

	// All addresses written in one PutManySessions call (batch drain).
	if calls := store.callCount.Load(); calls != 1 {
		t.Errorf("PutManySessions calls = %d, want 1 (batch drain)", calls)
	}
	if n := store.sessionCount(); n != addrCount {
		t.Errorf("store session count = %d, want %d", n, addrCount)
	}
}

func addressForIdx(i int) string {
	return fmt.Sprintf("user%d:0", i)
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_TriggerT
// After T elapses without further Enqueue, the dirty-set drains.
// Uses a short injectable flush interval so the test doesn't take 5s.
// ---------------------------------------------------------------------------

func TestSessionFlusher_TriggerT(t *testing.T) {
	f, store := newMockFlushSessionStoreAndStartedFlusher(t, 1000, 20*time.Millisecond)
	defer f.Stop()

	f.Enqueue("addr-T:0", []byte("session-T"))

	// Wait for T-trigger to fire (up to 500ms).
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if n := f.DirtyCount(); n == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if n := f.DirtyCount(); n != 0 {
		t.Fatalf("DirtyCount = %d after T-trigger interval, want 0", n)
	}
	if _, ok := store.getSession("addr-T:0"); !ok {
		t.Fatal("addr-T:0 not written to store after T-trigger")
	}
}

// newMockFlushSessionStoreAndStartedFlusher constructs and starts a flusher for
// T-trigger tests.
func newMockFlushSessionStoreAndStartedFlusher(t *testing.T, cap int, interval time.Duration) (*SessionFlusher, *mockFlushSessionStore) {
	t.Helper()
	store := newMockFlushSessionStore()
	f := newSessionFlusherForTest(store, cap, interval)
	f.Start()
	return f, store
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_TriggerN
// With N=1 (default), the first Enqueue for an address signals a flush via
// flushCh. Assert via a channel read, not a sleep race.
// ---------------------------------------------------------------------------

func TestSessionFlusher_TriggerN(t *testing.T) {
	f, _ := newTestSessionFlusher(t, 1000)
	// N=1: every new address triggers a flush signal immediately.

	f.Enqueue("addr-N:0", []byte("session-N"))

	// flushCh should receive a signal (non-blocking with short timeout).
	select {
	case <-f.flushCh:
		// correct — N=1 default triggers on first enqueue for this address
	case <-time.After(100 * time.Millisecond):
		t.Fatal("flushCh: no signal within 100ms for N=1 (first Enqueue must signal flush)")
	}
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_TriggerN_NotRepeated
// After an N-trigger signal is sent, a second Enqueue for the SAME address
// does NOT necessarily re-signal (the address is already in the dirty-set;
// the N-trigger is per new-address-entry-count).
// ---------------------------------------------------------------------------

func TestSessionFlusher_TriggerN_CountEntry(t *testing.T) {
	f, _ := newTestSessionFlusher(t, 1000)

	// Drain flushCh before test.
	select {
	case <-f.flushCh:
	default:
	}

	// First Enqueue for "addr-a:0" — must signal (new entry, N=1).
	f.Enqueue("addr-a:0", []byte("s1"))
	select {
	case <-f.flushCh:
		// correct
	case <-time.After(100 * time.Millisecond):
		t.Fatal("flushCh: no signal on first Enqueue for new address (N=1)")
	}

	// Second Enqueue for same address — no new entry created; signal is implementation-defined.
	// This test just ensures DirtyCount stays at 1 (coalescing).
	f.Enqueue("addr-a:0", []byte("s2"))
	if n := f.DirtyCount(); n != 1 {
		t.Errorf("DirtyCount = %d after second enqueue same address, want 1 (coalesced)", n)
	}
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_PeekReturnsBuffered
// Peek returns the dirty blob for a buffered-but-unflushed address.
// A miss on an address not in the dirty-set returns not-found cleanly.
// ---------------------------------------------------------------------------

func TestSessionFlusher_PeekReturnsBuffered(t *testing.T) {
	f, _ := newTestSessionFlusher(t, 1000)

	blob := []byte("buffered-session")
	f.Enqueue("peek-addr:0", blob)

	got, ok := f.Peek("peek-addr:0")
	if !ok {
		t.Fatal("Peek returned not-found for a dirty address")
	}
	if string(got) != string(blob) {
		t.Errorf("Peek blob = %q, want %q", got, blob)
	}

	// Miss path: address not in dirty-set.
	_, ok = f.Peek("unknown:0")
	if ok {
		t.Fatal("Peek returned found for an unknown address (should be not-found)")
	}
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_PeekReturnsCopy
// Peek returns a copy — mutating the returned slice must not corrupt the
// buffered blob (important for the read-coherence path).
// ---------------------------------------------------------------------------

func TestSessionFlusher_PeekReturnsCopy(t *testing.T) {
	f, _ := newTestSessionFlusher(t, 1000)

	blob := []byte("peek-original")
	f.Enqueue("copy-addr:0", blob)

	got, ok := f.Peek("copy-addr:0")
	if !ok {
		t.Fatal("Peek not found")
	}
	// Corrupt the returned slice.
	for i := range got {
		got[i] = 0xFF
	}
	// A second Peek must still return the original value.
	got2, ok := f.Peek("copy-addr:0")
	if !ok {
		t.Fatal("Peek (second) not found")
	}
	if string(got2) != "peek-original" {
		t.Errorf("Peek (second) = %q; dirty-set was corrupted by caller mutation of first Peek result", got2)
	}
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_StopDrainsAll
// Stop() flushes every dirty entry to the fake store before returning.
// Worst-case loss should only be the in-flight enqueue, not the whole buffer.
// ---------------------------------------------------------------------------

func TestSessionFlusher_StopDrainsAll(t *testing.T) {
	store := newMockFlushSessionStore()
	f := newSessionFlusherForTest(store, 1000, 5*time.Second) // long T so ticker doesn't fire spontaneously
	f.Start()

	const n = 10
	for i := 0; i < n; i++ {
		f.Enqueue("drain-addr"+string(rune('a'+i))+":0", []byte("v"))
	}
	// With N=1 default and Start() running, some entries may have already
	// drained. We only assert that after Stop(), ALL entries are written.

	// Stop must drain synchronously before returning.
	done := make(chan struct{})
	go func() {
		f.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not complete within 5 seconds")
	}

	if dc := f.DirtyCount(); dc != 0 {
		t.Fatalf("DirtyCount after Stop = %d, want 0", dc)
	}
	if n2 := store.sessionCount(); n2 != n {
		t.Fatalf("store session count after Stop = %d, want %d", n2, n)
	}
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_RemoveDropsDirtyEntry
// Remove(address) drops a dirty entry so a stale buffered blob cannot
// resurrect a deleted session.
// ---------------------------------------------------------------------------

func TestSessionFlusher_RemoveDropsDirtyEntry(t *testing.T) {
	f, _ := newTestSessionFlusher(t, 1000)

	f.Enqueue("rem-addr:0", []byte("will-be-removed"))
	if n := f.DirtyCount(); n != 1 {
		t.Fatalf("DirtyCount after Enqueue = %d, want 1", n)
	}

	f.Remove("rem-addr:0")

	if n := f.DirtyCount(); n != 0 {
		t.Fatalf("DirtyCount after Remove = %d, want 0", n)
	}
	_, ok := f.Peek("rem-addr:0")
	if ok {
		t.Fatal("Peek returned found after Remove — dirty entry was not dropped")
	}
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_DrainRetries
// Drain retries on a transient failure (failOnce) and eventually writes all
// entries. The dirty-set is empty after Drain.
// ---------------------------------------------------------------------------

func TestSessionFlusher_DrainRetries(t *testing.T) {
	store := newMockFlushSessionStore()
	store.failOnce = true
	store.failErr = context.DeadlineExceeded
	f := newSessionFlusherForTest(store, 1000, 5*time.Second)

	f.Enqueue("retry-addr:0", []byte("session-retry"))

	done := make(chan struct{})
	go func() {
		f.Drain()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Drain with retries did not complete within 5 seconds")
	}

	if n := f.DirtyCount(); n != 0 {
		t.Fatalf("DirtyCount after Drain = %d, want 0", n)
	}
	if _, ok := store.getSession("retry-addr:0"); !ok {
		t.Fatal("retry-addr:0 not written to store after Drain retries")
	}
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_Race_ConcurrentEnqueueDrain
// Concurrent Enqueue + Drain calls must not race (detected by -race).
// ---------------------------------------------------------------------------

func TestSessionFlusher_Race_ConcurrentEnqueueDrain(t *testing.T) {
	store := newMockFlushSessionStore()
	f := newSessionFlusherForTest(store, 1000, 50*time.Millisecond)
	f.Start()
	defer f.Stop()

	var wg sync.WaitGroup
	const goroutines = 20
	const opsPerGoroutine = 50

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				addr := "user" + string(rune('a'+i%26)) + ":0"
				f.Enqueue(addr, []byte("session"))
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_CR02_EnqueueDuringInflightBatchRetained
// CR-02 regression: an Enqueue landing between a batch's dirty-set snapshot
// and its post-write clear must NOT be deleted by that clear — otherwise the
// newer blob is dropped from the durable path forever (the DB holds the
// snapshot generation; the only remaining copy would be the evictable LRU
// mirror). The blocking store holds the batch open deterministically.
// ---------------------------------------------------------------------------

func TestSessionFlusher_CR02_EnqueueDuringInflightBatchRetained(t *testing.T) {
	mock := newMockFlushSessionStore()
	b := newBlockingFlushSessionStore(mock)
	f := newSessionFlusherForTest(b, 1000, 5000*time.Second)

	f.Enqueue("cr02-addr:0", []byte("v1"))

	flushDone := make(chan struct{})
	go func() {
		f.runFlush()
		close(flushDone)
	}()
	<-b.writeStarted
	// Lands between the snapshot (which captured v1) and the post-write clear.
	f.Enqueue("cr02-addr:0", []byte("v2"))
	close(b.writeRelease)
	<-flushDone

	got, ok := f.Peek("cr02-addr:0")
	if !ok {
		t.Fatal("dirty entry deleted by batch clear despite a newer Enqueue during the in-flight write — v2 dropped from the durable path (CR-02 lost update)")
	}
	if string(got) != "v2" {
		t.Fatalf("retained dirty blob = %q, want v2", got)
	}

	// The retained generation must reach the DB on the next drain.
	f.Drain()
	if v, _ := mock.getSession("cr02-addr:0"); string(v) != "v2" {
		t.Fatalf("store = %q after Drain, want v2 (newer generation never persisted)", v)
	}
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_DirtyCount
// DirtyCount reflects the current dirty-set size correctly.
// ---------------------------------------------------------------------------

func TestSessionFlusher_DirtyCount(t *testing.T) {
	f, _ := newTestSessionFlusher(t, 1000)

	if n := f.DirtyCount(); n != 0 {
		t.Fatalf("initial DirtyCount = %d, want 0", n)
	}
	f.Enqueue("user1:0", []byte("s1"))
	f.Enqueue("user2:0", []byte("s2"))
	if n := f.DirtyCount(); n != 2 {
		t.Fatalf("after 2 distinct Enqueues: DirtyCount = %d, want 2", n)
	}
}

// Ensure atomic.Int64 is accessible from tests (compile-time check).
var _ = (*atomic.Int64)(nil)

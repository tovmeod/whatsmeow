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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/types"
)

// ---------------------------------------------------------------------------
// mockFlushSessionStore is a thread-safe fake that implements the widened
// sessionWriterStore interface (Phase 47.3-06 D2): the single writer goroutine
// performs deletes and migrates itself, so the test double exposes
// PutManySessions, DeleteSession, DeleteAllSessions, and MigratePNToLID over an
// in-memory map. Records calls and stored sessions so tests can assert on them.
// ---------------------------------------------------------------------------

type mockFlushSessionStore struct {
	mu           sync.Mutex
	sessions     map[string][]byte
	callCount    atomic.Int64
	deleteCalls  atomic.Int64
	migrateCalls atomic.Int64
	failOnce     bool
	failErr      error
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

// DeleteSession / DeleteAllSessions / MigratePNToLID implement the widened
// sessionWriterStore interface (D2). They mirror the SQLStore semantics on the
// in-memory map (DeleteAllSessions matches the "<phone>:" prefix; MigratePNToLID
// rekeys the PN-prefix entries to the LID user).
func (m *mockFlushSessionStore) DeleteSession(_ context.Context, address string) error {
	m.deleteCalls.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, address)
	return nil
}

func (m *mockFlushSessionStore) DeleteAllSessions(_ context.Context, phone string) error {
	m.deleteCalls.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	pfx := phone + ":"
	for addr := range m.sessions {
		if strings.HasPrefix(addr, pfx) {
			delete(m.sessions, addr)
		}
	}
	return nil
}

func (m *mockFlushSessionStore) MigratePNToLID(_ context.Context, pn, lid types.JID) error {
	m.migrateCalls.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	pnPfx := pn.SignalAddressUser() + ":"
	lidUser := lid.SignalAddressUser()
	var victims []string
	for addr := range m.sessions {
		if strings.HasPrefix(addr, pnPfx) {
			victims = append(victims, addr)
		}
	}
	for _, addr := range victims {
		newAddr := lidUser + addr[len(pn.SignalAddressUser()):]
		m.sessions[newAddr] = m.sessions[addr]
		delete(m.sessions, addr)
	}
	return nil
}

// IsPNMigrated: the mock has no once-per-process gate, so every migration is a
// real one (never an already-migrated no-op). Phase 47.3 F4 interface widening.
func (m *mockFlushSessionStore) IsPNMigrated(string) bool { return false }

// ---------------------------------------------------------------------------
// blockingFlushSessionStore wraps any sessionWriterStore and blocks the FIRST
// PutManySessions call between "write started" and "write released". This is
// the deterministic interleaving hook the CR-01/CR-02/CR-03/WR-01 regression
// tests use to hold a flush cycle open between its dirty-set snapshot and the
// DB-write apply, without sleeps. The delete/migrate methods delegate straight
// to inner (only PutManySessions is gated) so the D2 single-writer delete
// ordering tests can hold a flush open and then dispatch a delete.
// ---------------------------------------------------------------------------

type blockingFlushSessionStore struct {
	inner        sessionWriterStore
	blockNext    atomic.Bool
	writeStarted chan struct{}
	writeRelease chan struct{}
}

func newBlockingFlushSessionStore(inner sessionWriterStore) *blockingFlushSessionStore {
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

func (b *blockingFlushSessionStore) DeleteSession(ctx context.Context, address string) error {
	return b.inner.DeleteSession(ctx, address)
}

func (b *blockingFlushSessionStore) DeleteAllSessions(ctx context.Context, phone string) error {
	return b.inner.DeleteAllSessions(ctx, phone)
}

func (b *blockingFlushSessionStore) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	return b.inner.MigratePNToLID(ctx, pn, lid)
}

func (b *blockingFlushSessionStore) IsPNMigrated(pn string) bool {
	return b.inner.IsPNMigrated(pn)
}

// ---------------------------------------------------------------------------
// gidRecordingStore wraps a sessionWriterStore and records the goroutine id of
// every PutManySessions call. Used by TestSingleWriter_BackpressureNoInlineWrite
// to assert ALL DB writes happen on the single writer goroutine (design §9 —
// no inline DB write off the writer).
// ---------------------------------------------------------------------------

type gidRecordingStore struct {
	inner sessionWriterStore
	mu    sync.Mutex
	gids  map[uint64]int // goroutine id -> call count
}

func (g *gidRecordingStore) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
	gid := goroutineID()
	g.mu.Lock()
	if g.gids == nil {
		g.gids = make(map[uint64]int)
	}
	g.gids[gid]++
	g.mu.Unlock()
	return g.inner.PutManySessions(ctx, sessions)
}

func (g *gidRecordingStore) DeleteSession(ctx context.Context, address string) error {
	return g.inner.DeleteSession(ctx, address)
}

func (g *gidRecordingStore) DeleteAllSessions(ctx context.Context, phone string) error {
	return g.inner.DeleteAllSessions(ctx, phone)
}

func (g *gidRecordingStore) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	return g.inner.MigratePNToLID(ctx, pn, lid)
}

func (g *gidRecordingStore) IsPNMigrated(pn string) bool {
	return g.inner.IsPNMigrated(pn)
}

// callerGIDs returns the distinct goroutine ids observed across all
// PutManySessions calls.
func (g *gidRecordingStore) callerGIDs() []uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]uint64, 0, len(g.gids))
	for gid := range g.gids {
		out = append(out, gid)
	}
	return out
}

// goroutineID returns the current goroutine's id by parsing the runtime stack
// header. Test-only diagnostic (the standard library deliberately hides this).
func goroutineID() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	// "goroutine <id> [...".
	fields := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))
	if len(fields) == 0 {
		return 0
	}
	id, _ := strconv.ParseUint(fields[0], 10, 64)
	return id
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
// TestHasDirtyPrefix_LockDiscipline
// HasDirtyPrefix reports whether any dirty-set entry starts with a given
// prefix — single-thread correctness + concurrent enqueue safety under -race.
// D2: takes only rwmu.RLock() (no flush mutex), mirrors Remove's lock discipline.
// ---------------------------------------------------------------------------

func TestHasDirtyPrefix_LockDiscipline(t *testing.T) {
	f, _ := newTestSessionFlusher(t, 1000)

	// Not present yet.
	if got := f.HasDirtyPrefix("972515529399:"); got {
		t.Fatal("HasDirtyPrefix returned true before any Enqueue")
	}

	// Enqueue a PN-addressed entry and assert the prefix matches.
	f.Enqueue("972515529399:0", []byte("signal-session"))
	if got := f.HasDirtyPrefix("972515529399:"); !got {
		t.Fatal("HasDirtyPrefix returned false after Enqueue of 972515529399:0 — expected true")
	}
	// A different prefix must not match.
	if got := f.HasDirtyPrefix("972526548435:"); got {
		t.Fatal("HasDirtyPrefix returned true for a prefix that was never enqueued")
	}

	// Remove the entry and assert the prefix is gone.
	f.Remove("972515529399:0")
	if got := f.HasDirtyPrefix("972515529399:"); got {
		t.Fatal("HasDirtyPrefix returned true after Remove — dirty entry not dropped")
	}
}

func TestHasDirtyPrefix_LockDiscipline_Concurrent(t *testing.T) {
	f, _ := newTestSessionFlusher(t, 1000)

	const goroutines = 10
	var wg sync.WaitGroup

	// 10 writers enqueue concurrent:0 .. concurrent:9.
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			addr := fmt.Sprintf("concurrent:%d", i)
			f.Enqueue(addr, []byte("session"))
		}()
	}

	// 10 readers call HasDirtyPrefix concurrently; at least one must return true
	// by the time all goroutines finish (we capture results after joining).
	results := make([]bool, goroutines)
	var rwg sync.WaitGroup
	rwg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer rwg.Done()
			results[i] = f.HasDirtyPrefix("concurrent:")
		}()
	}

	wg.Wait()
	rwg.Wait()

	// After all writers finished, the prefix MUST now be true.
	if got := f.HasDirtyPrefix("concurrent:"); !got {
		t.Fatal("HasDirtyPrefix returned false after all goroutines completed — expected at least one entry")
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
// TestSessionFlusher_CR03_BackpressureReliefLastWins (Phase 47.3-06 D2)
// CR-03 in D2: backpressure relief is a workFlushSync work item processed by
// the single writer goroutine, FIFO-ordered with every other DB write — there
// is NO inline write on the producer goroutine that could clobber a newer one
// (design §9). This is structurally stronger than the V1 advSnap staleness
// guard: a single writer cannot reorder its own writes. This test drives the
// backpressure relief path through the writer (cap=5 -> backpressureCap=1) and
// asserts the durable end-state is the last-written blob (last-wins, no clobber).
// ---------------------------------------------------------------------------

func TestSessionFlusher_CR03_BackpressureReliefLastWins(t *testing.T) {
	mock := newMockFlushSessionStore()
	// cap=5 -> backpressureCap=1: a second distinct dirty address triggers the
	// synchronous workFlushSync relief through the writer.
	f := newSessionFlusherForTest(mock, 5, 5000*time.Second)
	f.Start()
	defer f.Stop()

	f.Enqueue("filler:0", []byte("filler")) // dirty=1, at/below backpressureCap

	// This second distinct address pushes dirty>backpressureCap. EnqueueAndMirror
	// sends a workFlushSync to the writer and blocks on done — the relief flush
	// runs inside the single writer (no inline producer-goroutine DB write).
	f.Enqueue("cr03-addr:0", []byte("v1"))
	// A newer write for the same address: last-wins.
	f.Enqueue("cr03-addr:0", []byte("v2"))

	// Force a final synchronous flush through the writer and assert the durable
	// end-state is v2 (newer generation never lost; no older write clobbered it).
	if err := f.flushSyncForTest(); err != nil {
		t.Fatalf("flushSyncForTest: %v", err)
	}
	if v, ok := mock.getSession("cr03-addr:0"); !ok || string(v) != "v2" {
		t.Fatalf("store = %q (found=%v) after backpressure relief, want v2 (last-wins; no clobber, CR-03/D2)", v, ok)
	}
}

// ---------------------------------------------------------------------------
// TestSessionFlusher_WR01_DrainLoopsUntilEmpty
// WR-01 regression: Drain's docstring promises "blocks until the dirty-set is
// empty", but the success path returned after the FIRST batch. Entries
// enqueued during the final batch's DB write (and CR-02-retained newer
// generations) were never drained — silent shutdown data loss.
// ---------------------------------------------------------------------------

func TestSessionFlusher_WR01_DrainLoopsUntilEmpty(t *testing.T) {
	mock := newMockFlushSessionStore()
	b := newBlockingFlushSessionStore(mock)
	f := newSessionFlusherForTest(b, 1000, 5000*time.Second)

	f.Enqueue("wr01-a:0", []byte("a-v1"))

	drainDone := make(chan struct{})
	go func() {
		f.Drain()
		close(drainDone)
	}()
	<-b.writeStarted
	// Arrive during the final batch's in-flight DB write: a brand-new
	// address AND a newer generation of the in-flight address.
	f.Enqueue("wr01-b:0", []byte("b-v1"))
	f.Enqueue("wr01-a:0", []byte("a-v2"))
	close(b.writeRelease)

	select {
	case <-drainDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Drain did not complete within 5 seconds")
	}

	if n := f.DirtyCount(); n != 0 {
		t.Fatalf("DirtyCount after Drain = %d, want 0 — Drain returned before the dirty-set was empty (WR-01)", n)
	}
	if v, ok := mock.getSession("wr01-b:0"); !ok || string(v) != "b-v1" {
		t.Fatalf("wr01-b:0 = %q (found=%v) — entry enqueued during the final batch was never drained (WR-01)", v, ok)
	}
	if v, _ := mock.getSession("wr01-a:0"); string(v) != "a-v2" {
		t.Fatalf("wr01-a:0 = %q, want a-v2 — CR-02-retained newer generation must drain on shutdown (WR-01)", v)
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

// ===========================================================================
// D2 single-writer invariant tests (Phase 47.3-06). RED stubs in Task 1;
// bodies filled in Task 3 once the single-writer redesign lands.
//
// D2 is a correctness/elegance redesign (NOT a perf win — D-09): the writer
// goroutine owns ALL DB mutation (flush + delete + migrate + backpressure
// relief), serialized by channel FIFO, with no lock held across DB I/O. These
// three tests attack the hardest invariants the channel-FIFO + rwmu design
// must preserve: CR-01 delete ordering, D-11 evicted-dirty read, and INV-8
// backpressure with no off-writer DB write.
// ===========================================================================

// ---------------------------------------------------------------------------
// TestSingleWriter_DeleteOrdering (CR-01 via D2 channel-FIFO)
// A delete work item processed after a flush batch must NOT be resurrected by
// the flush's in-flight PutManySessions UPSERT. The blockingFlushSessionStore
// holds the writer's PutManySessions open between snapshot and DB apply; a
// delete work item is sent to workCh during that window. With the single
// writer, the delete is dequeued only AFTER runFlush completes (channel FIFO),
// so the net DB effect is UPSERT then DELETE -> row deleted. Replaces flushMu
// mutual exclusion with single-goroutine FIFO serialization.
// ---------------------------------------------------------------------------

func TestSingleWriter_DeleteOrdering(t *testing.T) {
	mock := newMockFlushSessionStore()
	b := newBlockingFlushSessionStore(mock)
	// boundaryN high so the Enqueue below does not spontaneously flush; the test
	// drives the flush explicitly via flushCh through the running writer.
	f := newSessionFlusherForTest(b, 1000, 5000*time.Second)
	f.boundaryN = 1 << 30
	f.Start()
	defer f.Stop()

	ctx := context.Background()
	f.Enqueue("target:0", []byte("doomed"))

	// Trigger a flush through the writer; the blockingStore pauses it mid-write
	// (snapshot of {target:0} taken, PutManySessions blocked).
	f.flushCh <- struct{}{}
	<-b.writeStarted

	// Dispatch a delete for the same address. It sends a workDeleteSingle item to
	// workCh and blocks on done. The writer is busy with the paused flush, so the
	// delete is queued BEHIND the flush (channel FIFO).
	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- f.DeleteSession(ctx, "target:0")
	}()

	// The delete MUST NOT complete while the flush is paused (FIFO: it is queued
	// behind the in-flight flush).
	select {
	case err := <-deleteDone:
		t.Fatalf("DeleteSession completed while the flush was paused — channel-FIFO ordering broken (CR-01); err=%v", err)
	case <-time.After(150 * time.Millisecond):
		// Correct: delete queued behind the paused flush.
	}

	// Release the flush. The writer finishes runFlush (UPSERT target:0), then
	// dequeues the delete (DELETE target:0). Net DB effect: UPSERT then DELETE.
	close(b.writeRelease)
	if err := <-deleteDone; err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	// CR-01: target:0 must NOT be present in the DB — the delete won over the
	// in-flight flush's upsert because the writer processed them in FIFO order.
	if _, ok := mock.getSession("target:0"); ok {
		t.Fatal("target:0 resurrected in the store by the in-flight flush upsert — CR-01 violated (the delete must win, processed FIFO after the flush)")
	}
	// The dirty entry must also be gone.
	if _, ok := f.Peek("target:0"); ok {
		t.Fatal("dirty entry survived DeleteSession (CR-01)")
	}
}

// ---------------------------------------------------------------------------
// TestSingleWriter_EvictedDirtyRead (WR-03 / D-11)
// A PeekAndMirror after LRU eviction must reach the dirty-but-unflushed blob
// via rwmu.RLock() WITHOUT a channel round-trip to the writer goroutine (a
// round-trip would block on the writer mid-DB-write — the 17.13 -> 479 read
// gap). The read must complete even while the writer holds rwmu.Lock() for a
// brief snapshot, with no deadlock.
// ---------------------------------------------------------------------------

func TestSingleWriter_EvictedDirtyRead(t *testing.T) {
	mock := newMockFlushSessionStore()
	b := newBlockingFlushSessionStore(mock)
	f := newSessionFlusherForTest(b, 1000, 5000*time.Second)
	f.boundaryN = 1 << 30
	f.Start()
	// released guards the single close(b.writeRelease): the test body closes it
	// on the happy path; the defer closes it if an assertion failed early (so a
	// paused writer cannot hang Stop()'s Drain).
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(b.writeRelease) }) }
	defer func() {
		release()
		f.Stop()
	}()

	blob := []byte("evicted-but-dirty")
	f.Enqueue("evict:0", blob)

	// Part 1: a plain read reaches the dirty blob synchronously (no channel
	// round-trip — PeekAndMirror only takes rwmu.RLock()). The mirror callback
	// stands in for the LRU repopulate (WR-03).
	var mirrored []byte
	got, ok := f.PeekAndMirror("evict:0", func(bl []byte) { mirrored = append([]byte(nil), bl...) })
	if !ok {
		t.Fatal("PeekAndMirror returned not-found for a dirty (LRU-evicted) address — read-gap (D-11)")
	}
	if string(got) != string(blob) {
		t.Fatalf("PeekAndMirror blob = %q, want %q", got, blob)
	}
	if string(mirrored) != string(blob) {
		t.Fatalf("mirror callback blob = %q, want %q (WR-03 coherence)", mirrored, blob)
	}

	// Part 2: while the writer is mid-flush (it released rwmu.Lock() after the
	// snapshot and is now blocked in PutManySessions — entry still dirty until
	// the clear pass), PeekAndMirror must still complete via rwmu.RLock() with no
	// deadlock and no channel round-trip. Use a 500ms guard.
	f.flushCh <- struct{}{}
	<-b.writeStarted // writer snapshotted (rwmu.Lock released) and is paused in the DB write

	readDone := make(chan []byte, 1)
	go func() {
		out, found := f.PeekAndMirror("evict:0", nil)
		if !found {
			readDone <- nil
			return
		}
		readDone <- out
	}()
	select {
	case out := <-readDone:
		if string(out) != string(blob) {
			t.Fatalf("mid-flush PeekAndMirror = %q, want %q (entry still dirty until the clear pass)", out, blob)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("PeekAndMirror deadlocked while the writer was mid-flush — rwmu.RLock() must not block on DB I/O (D-11)")
	}

	// Release the writer; after the clear pass the entry is in the DB.
	release()
}

// ---------------------------------------------------------------------------
// TestSingleWriter_BackpressureNoInlineWrite (INV-8 / design §7 §9)
// Backpressure relief must NOT perform any DB write on the producer goroutine.
// On dirty-set > backpressureCap, EnqueueAndMirror sends a synchronous
// workFlushSync item to workCh and blocks on its done channel (that blocking
// IS the backpressure); the relief flush runs inside the single writer,
// FIFO-ordered with deletes/migrates. This test asserts (a) the only
// PutManySessions calls happen on the writer goroutine, and (b) a full workCh
// blocks the producer (the send itself is the backpressure, not a lock-free
// inline DB write).
// ---------------------------------------------------------------------------

func TestSingleWriter_BackpressureNoInlineWrite(t *testing.T) {
	// gidRecordingStore records the goroutine id of every PutManySessions call so
	// the test can assert ALL DB writes happen on ONE goroutine (the writer) and
	// never on a producer goroutine (no inline off-writer DB write — design §9).
	rec := &gidRecordingStore{inner: newMockFlushSessionStore()}
	// cap=5 -> backpressureCap=1: a second distinct dirty address triggers relief.
	f := newSessionFlusherForTest(rec, 5, 5000*time.Second)
	f.boundaryN = 1 << 30
	f.Start()
	defer f.Stop()

	// Drive many backpressure-triggering writes from several producer goroutines.
	producerGIDs := &sync.Map{}
	var wg sync.WaitGroup
	const producers = 6
	const writesPer = 40
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			producerGIDs.Store(goroutineID(), true)
			for j := 0; j < writesPer; j++ {
				// Distinct addresses keep the dirty-set above backpressureCap so
				// EnqueueAndMirror takes the relief path (workFlushSync via the writer).
				f.Enqueue(fmt.Sprintf("bp-%d-%d:0", i, j), []byte("v"))
			}
		}(i)
	}
	wg.Wait()

	// Final synchronous flush through the writer to settle.
	if err := f.flushSyncForTest(); err != nil {
		t.Fatalf("flushSyncForTest: %v", err)
	}

	// (a) Every PutManySessions call must have happened on a SINGLE goroutine
	// (the writer), and NEVER on any producer goroutine. This proves the
	// backpressure relief did NOT perform an inline DB write off the writer.
	writerGIDs := rec.callerGIDs()
	if len(writerGIDs) != 1 {
		t.Fatalf("PutManySessions ran on %d distinct goroutines %v, want exactly 1 (the single writer); a >1 count means a DB write happened off the writer goroutine (INV-8 / design §9)", len(writerGIDs), writerGIDs)
	}
	for _, gid := range writerGIDs {
		if _, isProducer := producerGIDs.Load(gid); isProducer {
			t.Fatalf("PutManySessions ran on producer goroutine %d — inline off-writer DB write (CR-01 hole the amendment closed, design §9)", gid)
		}
	}

	// (b) A full workCh blocks the producer (the send is the backpressure, not a
	// lock-free escape hatch). Build a flusher whose writer is paused, fill workCh
	// to capacity, and assert the next send blocks rather than returning.
	assertFullWorkChBlocksProducer(t)
}

// assertFullWorkChBlocksProducer verifies that when workCh is full the producer
// blocks on the send (design §9: a full workCh blocks the producer; the send IS
// the backpressure). It pauses the writer mid-flush, fills the buffered workCh,
// then confirms one more send blocks until the writer drains.
func assertFullWorkChBlocksProducer(t *testing.T) {
	t.Helper()
	mock := newMockFlushSessionStore()
	b := newBlockingFlushSessionStore(mock)
	f := newSessionFlusherForTest(b, 1000, 5000*time.Second)
	f.boundaryN = 1 << 30
	f.Start()
	defer f.Stop()

	// Pause the writer mid-flush so it cannot drain workCh.
	f.Enqueue("seed:0", []byte("v"))
	f.flushCh <- struct{}{}
	<-b.writeStarted // writer is now blocked in PutManySessions; it will not read workCh

	// Fill workCh to capacity with fire-and-forget delete work items (done=nil).
	for i := 0; i < workChBuffer; i++ {
		f.workCh <- writeWork{kind: workDeleteSingle, address: fmt.Sprintf("x%d:0", i)}
	}

	// The next send must BLOCK (workCh is full and the writer is paused).
	sendReturned := make(chan struct{})
	go func() {
		f.workCh <- writeWork{kind: workDeleteSingle, address: "overflow:0"}
		close(sendReturned)
	}()
	select {
	case <-sendReturned:
		t.Fatal("send on a full workCh returned immediately — backpressure is not bounded by the channel send (design §9)")
	case <-time.After(150 * time.Millisecond):
		// Correct: the producer is blocked on the full-channel send.
	}

	// Release the writer; it drains workCh and the blocked send eventually lands.
	close(b.writeRelease)
	select {
	case <-sendReturned:
		// Correct: once the writer drains, the blocked send completes.
	case <-time.After(2 * time.Second):
		t.Fatal("blocked send never completed after the writer drained workCh")
	}
}

// ===========================================================================
// FAILURE-PATH tests (Phase 47.3 code-review fix-forward). The D2 happy-path
// suite above never reached the error/shutdown/cancel branches that the xhigh
// review flagged (F1-F6). These five tests are deterministic (no scheduling
// reliance) and were RED against the pre-fix code:
//   1. Shutdown-with-pending-delete (F1): a delete dispatched as the writer
//      stops completes or returns a definitive error — never hangs, never lost.
//   2. DB-delete-failure (F3): a failing inner delete RETAINS the dirty entry
//      and returns the error (no torn state, no lost ratchet blob).
//   3. Cancelled caller-ctx (F5): a delete with an already-cancelled caller ctx
//      STILL lands the durable DB delete (writer runs a detached ctx).
//   4. Backpressure-under-DB-failure (F6/F9): relief does NOT report relieved
//      while still over backpressureCap; the dirty-set is brought below cap by
//      the drop path; no unbounded re-dispatch.
//   5. Gate-race (F4): a migration that no-ops at the gate does NOT strand PN
//      dirty rows — they are re-validated, not destructively removed.
// ===========================================================================

// failableSessionStore is a deterministic failure-injection mock implementing
// sessionWriterStore. Each operation kind can be made to fail (returning a
// fixed error WITHOUT mutating the backing map) by toggling the *Fail flags.
// Toggles are guarded by mu so a test goroutine can flip them safely while the
// writer goroutine is running.
type failableSessionStore struct {
	mu           sync.Mutex
	sessions     map[string][]byte
	putFail      bool
	deleteFail   bool
	migrateFail  bool
	migrateNoop  bool // succeed but migrate nothing (stand-in for the once-per-process gate already fired)
	failErr      error
	putCalls     atomic.Int64
	deleteCalls  atomic.Int64
	migrateCalls atomic.Int64
}

func newFailableSessionStore() *failableSessionStore {
	return &failableSessionStore{
		sessions: make(map[string][]byte),
		failErr:  fmt.Errorf("injected DB failure"),
	}
}

func (s *failableSessionStore) setPutFail(v bool)     { s.mu.Lock(); s.putFail = v; s.mu.Unlock() }
func (s *failableSessionStore) setDeleteFail(v bool)  { s.mu.Lock(); s.deleteFail = v; s.mu.Unlock() }
func (s *failableSessionStore) setMigrateFail(v bool) { s.mu.Lock(); s.migrateFail = v; s.mu.Unlock() }
func (s *failableSessionStore) setMigrateNoop(v bool) { s.mu.Lock(); s.migrateNoop = v; s.mu.Unlock() }

func (s *failableSessionStore) PutManySessions(_ context.Context, sessions map[string][]byte) error {
	s.putCalls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putFail {
		return s.failErr
	}
	for addr, blob := range sessions {
		stored := make([]byte, len(blob))
		copy(stored, blob)
		s.sessions[addr] = stored
	}
	return nil
}

func (s *failableSessionStore) DeleteSession(ctx context.Context, address string) error {
	s.deleteCalls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteFail {
		return s.failErr
	}
	// F5: a delete dispatched with an already-cancelled CALLER ctx must still
	// land. The writer runs on a detached ctx — assert the ctx the writer
	// passed is NOT already cancelled.
	if ctx != nil && ctx.Err() != nil {
		return fmt.Errorf("writer ran delete on a cancelled ctx: %w", ctx.Err())
	}
	delete(s.sessions, address)
	return nil
}

func (s *failableSessionStore) DeleteAllSessions(_ context.Context, phone string) error {
	s.deleteCalls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteFail {
		return s.failErr
	}
	pfx := phone + ":"
	for addr := range s.sessions {
		if strings.HasPrefix(addr, pfx) {
			delete(s.sessions, addr)
		}
	}
	return nil
}

func (s *failableSessionStore) MigratePNToLID(_ context.Context, pn, lid types.JID) error {
	s.migrateCalls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.migrateFail {
		return s.failErr
	}
	if s.migrateNoop {
		// Stand-in for the once-per-process gate already firing in a concurrent
		// Branch-2 path: the inner migration returns nil but migrates NOTHING.
		return nil
	}
	pnPfx := pn.SignalAddressUser() + ":"
	lidUser := lid.SignalAddressUser()
	var victims []string
	for addr := range s.sessions {
		if strings.HasPrefix(addr, pnPfx) {
			victims = append(victims, addr)
		}
	}
	for _, addr := range victims {
		newAddr := lidUser + addr[len(pn.SignalAddressUser()):]
		s.sessions[newAddr] = s.sessions[addr]
		delete(s.sessions, addr)
	}
	return nil
}

// IsPNMigrated models the once-per-process gate for the F4 gate-race test: when
// migrateNoop is set, the gate has "already fired" in a concurrent Branch-2
// path, so the writer's re-validation (consumed = !IsPNMigrated) sees the
// migration did NOT consume the PN rows and must retain them.
func (s *failableSessionStore) IsPNMigrated(string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.migrateNoop
}

func (s *failableSessionStore) has(addr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[addr]
	return ok
}

// ---------------------------------------------------------------------------
// TestFailurePath_ShutdownWithPendingDelete (F1)
// A DeleteSession dispatched while the writer is stopping must complete or
// return a definitive error — it must NEVER hang on <-done and NEVER be
// silently lost. The pre-fix Drain() did ONE non-blocking workCh pass, so a
// delete sent after that pass (but before/while Stop ran) was never processed
// and the caller (Background ctx) blocked forever on <-done.
// ---------------------------------------------------------------------------

func TestFailurePath_ShutdownWithPendingDelete(t *testing.T) {
	store := newFailableSessionStore()
	store.sessions["shut:0"] = []byte("doomed")
	f := newSessionFlusherForTest(store, 1000, 5000*time.Second)
	f.boundaryN = 1 << 30
	f.Start()

	// Stop the writer FIRST: close stopCh, wait for the writer to exit, run
	// Drain (which does its workCh-drain pass and the dirty-set flush). After
	// Stop returns, NOTHING is reading workCh anymore.
	f.Stop()

	// Now dispatch a delete with a Background ctx (no deadline). The send lands
	// in the buffered workCh, then DeleteSession blocks on <-done. With the
	// pre-fix code there is no longer any consumer for workCh, so <-done hangs
	// FOREVER — a dispatched delete silently vanishes and the caller wedges.
	// The fix must guarantee a dispatched op ALWAYS completes or returns a
	// definitive error (producer sends select on a stop/abort channel; or Stop
	// is sequenced so no producer can send into an orphaned workCh).
	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- f.DeleteSession(context.Background(), "shut:0")
	}()

	select {
	case err := <-deleteDone:
		// Acceptable: completed (err==nil, row deleted) OR a definitive error.
		if err == nil && store.has("shut:0") {
			t.Fatal("shut:0 still present after a no-error shutdown delete — delete silently lost (F1)")
		}
		if err != nil {
			t.Logf("post-Stop delete returned a definitive error (acceptable, not a hang): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DeleteSession dispatched after Stop() hung on <-done — orphaned work-item, caller wedged forever (F1)")
	}
}

// ---------------------------------------------------------------------------
// TestFailurePath_DeleteDBFailureRetainsDirty (F3)
// When the inner DB delete fails, the writer must RETAIN the dirty entry and
// RETURN the error. The pre-fix code removed the dirty entry BEFORE the DB
// delete, unconditionally — so a DB failure left torn state (dirty gone, DB row
// still present, caller believes deleted). V1 removed dirty ONLY on success.
// ---------------------------------------------------------------------------

func TestFailurePath_DeleteDBFailureRetainsDirty(t *testing.T) {
	store := newFailableSessionStore()
	store.sessions["delfail:0"] = []byte("present-in-db")
	f := newSessionFlusherForTest(store, 1000, 5000*time.Second)
	f.boundaryN = 1 << 30
	f.Start()
	defer f.Stop()

	// Seed a dirty entry for the same address.
	f.Enqueue("delfail:0", []byte("dirty-blob"))
	if _, ok := f.Peek("delfail:0"); !ok {
		t.Fatal("setup: dirty entry missing")
	}

	// Make the inner delete fail.
	store.setDeleteFail(true)

	err := f.DeleteSession(context.Background(), "delfail:0")
	if err == nil {
		t.Fatal("DeleteSession returned nil despite an injected DB delete failure — error swallowed (F3)")
	}

	// The dirty entry must be RETAINED (not removed before a failed DB delete).
	if _, ok := f.Peek("delfail:0"); !ok {
		t.Fatal("dirty entry was removed despite the DB delete failing — torn state, lost ratchet blob (F3)")
	}
	// The DB row must still be present (the delete did not land).
	if !store.has("delfail:0") {
		t.Fatal("DB row gone despite injected failure — test mock inconsistency")
	}

	// Recovery: a retry after the DB heals must succeed and clear both.
	store.setDeleteFail(false)
	if err := f.DeleteSession(context.Background(), "delfail:0"); err != nil {
		t.Fatalf("retry DeleteSession after DB heal: %v", err)
	}
	if _, ok := f.Peek("delfail:0"); ok {
		t.Fatal("dirty entry survived a successful retry delete (F3)")
	}
	if store.has("delfail:0") {
		t.Fatal("DB row survived a successful retry delete (F3)")
	}
}

// ---------------------------------------------------------------------------
// TestFailurePath_CancelledCallerCtxStillDeletes (F5)
// A DeleteSession whose CALLER ctx is already cancelled when the writer dequeues
// it must STILL land the durable DB delete — the writer runs the mutation on a
// fresh background-derived ctx, detached from the caller's cancellable ctx. The
// pre-fix writer derived its DB ctx from work.ctx, so a cancelled caller ctx
// dropped the security delete with context.Canceled.
// ---------------------------------------------------------------------------

func TestFailurePath_CancelledCallerCtxStillDeletes(t *testing.T) {
	store := newFailableSessionStore()
	store.sessions["cancel:0"] = []byte("must-be-deleted")
	b := newBlockingFlushSessionStore(store)
	f := newSessionFlusherForTest(b, 1000, 5000*time.Second)
	f.boundaryN = 1 << 30
	f.Start()
	defer f.Stop()

	// Pause the writer mid-flush so the delete sits in workCh while we cancel.
	f.Enqueue("filler:0", []byte("v"))
	f.flushCh <- struct{}{}
	<-b.writeStarted

	// Dispatch the delete with a cancellable ctx, then cancel it while the item
	// is queued behind the paused flush.
	ctx, cancel := context.WithCancel(context.Background())
	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- f.DeleteSession(ctx, "cancel:0")
	}()
	time.Sleep(50 * time.Millisecond) // ensure the send landed in the buffer
	cancel()                          // caller ctx now cancelled while item is queued

	// Release the flush; the writer dequeues the delete next (FIFO) and must run
	// the DB delete on a DETACHED ctx — the failableSessionStore.DeleteSession
	// asserts the ctx it received is not already cancelled.
	close(b.writeRelease)

	// The caller may observe ctx.Err() (it returned on ctx.Done) OR nil — either
	// is acceptable for the CALLER. The DURABLE requirement is the DB delete
	// landed regardless. Wait for the delete to be processed by the writer.
	select {
	case <-deleteDone:
	case <-time.After(2 * time.Second):
		t.Fatal("delete caller did not return within 2s (F5)")
	}
	// Poll for the durable effect (the writer may complete slightly after the
	// caller returns on ctx.Done).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !store.has("cancel:0") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if store.has("cancel:0") {
		t.Fatal("cancel:0 still in DB — the cancelled caller ctx dropped the durable delete (F5)")
	}
	if store.deleteCalls.Load() == 0 {
		t.Fatal("inner DeleteSession was never called — writer skipped the DB mutation on a cancelled ctx (F5)")
	}
}

// ---------------------------------------------------------------------------
// TestFailurePath_BackpressureUnderDBFailure (F6/F9)
// Under sustained DB-write failure, backpressure relief must NOT report
// "relieved" while the dirty-set is still over backpressureCap, and must bound
// the dirty-set below backpressureCap via the drop path (no unbounded
// re-dispatch / amplification against a failing DB). The pre-fix relief flush
// dropped only to dropCap (40%, still above the 20% backpressureCap) yet
// signalled done<-nil, so every later Enqueue re-dispatched a full-batch flush.
// ---------------------------------------------------------------------------

func TestFailurePath_BackpressureUnderDBFailure(t *testing.T) {
	store := newFailableSessionStore()
	// cap=10 -> backpressureCap=2, dropCap=4. The relief drop path must bring the
	// dirty-set to <= backpressureCap (2) under DB failure, not merely <= dropCap.
	f := newSessionFlusherForTest(store, 10, 5000*time.Second)
	f.boundaryN = 1 << 30
	f.Start()
	defer f.Stop()

	store.setPutFail(true) // every flush fails

	// Drive enough distinct writes to repeatedly cross backpressureCap. Each
	// over-cap Enqueue dispatches a workFlushSync; the relief flush fails (DB
	// down) and must drop the dirty-set below backpressureCap rather than
	// signalling relieved while still over cap.
	for i := 0; i < 60; i++ {
		f.Enqueue(fmt.Sprintf("bpf-%d:0", i), []byte("v"))
	}

	// After the failing-DB backpressure storm, the dirty-set must be bounded at
	// or below backpressureCap (relief actually relieved). The pre-fix code
	// latched at dropCap (4) > backpressureCap (2).
	if dc := f.DirtyCount(); dc > f.backpressureCap {
		t.Fatalf("dirty-set = %d after backpressure relief under DB failure, want <= backpressureCap (%d) — relief signalled relieved while still over cap (F6/F9)", dc, f.backpressureCap)
	}

	// The DB stayed down the whole time, so nothing should have persisted.
	if store.putCalls.Load() == 0 {
		t.Fatal("no relief flush was ever attempted — backpressure path not exercised (test setup)")
	}

	// Heal the DB so the deferred Stop()'s Drain does not have to burn the full
	// F2 deadline retrying a down DB (keeps the test fast; the F2 bound itself is
	// covered by TestFailurePath_ShutdownWithPendingDelete's Drain path and the
	// drainTotalDeadline logic).
	store.setPutFail(false)
}

// ---------------------------------------------------------------------------
// TestFailurePath_MigrateGateRaceDoesNotStrandPN (F4)
// processMigratePNPrefix must NOT destructively remove PN dirty rows when the
// inner migration does not actually consume them (e.g. the once-per-process
// gate already fired in a concurrent Branch-2 path → inner.MigratePNToLID
// no-ops). The pre-fix code flushed + unconditionally removed PN dirty rows
// before calling inner; if inner no-op'd, those rows were orphaned (never
// migrated, never re-migrated). The fix re-validates: on a no-op migration the
// PN dirty rows are NOT lost (they remain available for a real migration).
// ---------------------------------------------------------------------------

func TestFailurePath_MigrateGateRaceDoesNotStrandPN(t *testing.T) {
	store := newFailableSessionStore()
	f := newSessionFlusherForTest(store, 1000, 5000*time.Second)
	f.boundaryN = 1 << 30
	f.Start()
	defer f.Stop()

	pn := types.JID{User: "12345", Server: types.DefaultUserServer}
	lid := types.JID{User: "777", Server: types.HiddenUserServer}
	pnAddr := pn.SignalAddressUser() + ":0"
	lidAddr := lid.SignalAddressUser() + ":0"

	// Seed a dirty PN entry. It is NOT yet in the DB.
	f.Enqueue(pnAddr, []byte("ratchet"))

	// Gate-race stand-in: the inner migration succeeds (nil) but migrates
	// NOTHING — exactly what happens when a concurrent Branch-2 path already
	// fired the once-per-process gate (s.migratedPNSessionsCache.Add returns
	// false → MigratePNToLID returns nil early without touching the rows). The
	// pre-fix processMigratePNPrefix flushed + UNCONDITIONALLY removed the PN
	// dirty rows BEFORE this no-op inner call, so the PN state is orphaned:
	// removed from the dirty-set, and (because the once-per-process gate stays
	// set this process) never migrated to LID and never re-migrated.
	store.setMigrateNoop(true)

	if err := f.MigratePNToLID(context.Background(), pn, lid); err != nil {
		t.Fatalf("MigratePNToLID (no-op gate-race): %v", err)
	}

	// FIX PRINCIPLE (F4): PN dirty state must NOT be destructively removed unless
	// the migration actually consumed it. The inner migration migrated nothing
	// (no-op), so the PN dirty entry must be RETAINED — its ratchet blob is the
	// only fresh copy not yet migrated to LID. The pre-fix code removed it
	// unconditionally, stranding it.
	if _, ok := f.Peek(pnAddr); !ok {
		t.Fatal("PN dirty entry was destructively removed after a no-op migration that consumed nothing — stranded PN state, never migrated, never re-migratable this process (F4)")
	}
	// The blob must be intact (unchanged generation).
	if got, _ := f.Peek(pnAddr); string(got) != "ratchet" {
		t.Fatalf("retained PN dirty blob = %q, want \"ratchet\" (F4)", got)
	}

	// Recovery: when a REAL migration runs (gate clears), the retained PN dirty
	// state migrates correctly to LID.
	store.setMigrateNoop(false)
	if err := f.MigratePNToLID(context.Background(), pn, lid); err != nil {
		t.Fatalf("retry MigratePNToLID after gate clears: %v", err)
	}
	if !store.has(lidAddr) {
		t.Fatal("LID row missing after a real retry migration — retained PN dirty state did not migrate (F4)")
	}
	if _, ok := f.Peek(pnAddr); ok {
		t.Fatal("PN dirty entry survived a real migration that consumed it (F4)")
	}
}

// ---------------------------------------------------------------------------
// TestFailurePath_DrainBoundedUnderDBDown (F2)
// Drain's PutManySessions retry loop must be bounded by a total deadline so a
// DB-down-at-shutdown does NOT wedge Stop()/Container.Close() until SIGKILL.
// The pre-fix Drain retried forever (100ms sleep, no cap). This test injects a
// short drain deadline and a permanently-failing DB, then asserts Stop()
// returns within the deadline + a margin instead of hanging.
// ---------------------------------------------------------------------------

func TestFailurePath_DrainBoundedUnderDBDown(t *testing.T) {
	store := newFailableSessionStore()
	f := newSessionFlusherForTest(store, 1000, 5000*time.Second)
	f.boundaryN = 1 << 30
	f.drainDeadline = 300 * time.Millisecond // short bound for the test
	f.Start()

	f.Enqueue("drainbound:0", []byte("never-persists"))
	store.setPutFail(true) // DB permanently down

	stopDone := make(chan struct{})
	go func() {
		f.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		// Correct: Drain abandoned the retry after the deadline; Stop completed.
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not complete — Drain retried a down DB forever (F2)")
	}

	// The dirty entry was never persisted (DB down) — bounded crash-loss INV-7
	// accepts this. The point is that shutdown COMPLETED rather than wedging.
	if store.has("drainbound:0") {
		t.Fatal("entry persisted despite a down DB — test mock inconsistency")
	}
}

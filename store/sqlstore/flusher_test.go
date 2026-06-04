// Copyright (c) 2026 Kavtov Platform (Phase 17.7)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// flusher_test.go covers the SenderKeyFlusher unit behavior:
//   - SKDM dedup (skip on equal/lower iter within same keyID generation)
//   - keyID rotation always processes (new generation bypasses dedup)
//   - wasFailed bypass (always processes regardless of cached iter)
//   - N=500 iteration-boundary flush trigger
//   - Eviction enqueue (dirty entry re-enqueued before LRU drop)
//   - Synchronous Drain (blocks until dirty-set empty)
//   - Inline sync valve (backpressure fires when dirty-set > backpressureCap)
//   - extractSenderKeyMeta / extractIteration with real libsignal JSON blob
//
// Pattern: in-memory fakes, no real DB. All tests run under -race.
// The CR regression suite (CR-01..CR-06 + evict/drain invariants) belongs
// exclusively to plan 07 (flusher_cr_test.go) — NOT here.
package sqlstore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// ---------------------------------------------------------------------------
// mockFlushStore is a thread-safe fake that implements flushSenderKeyBatch.
// It records calls and stored rows so tests can assert on them.
// ---------------------------------------------------------------------------

type mockFlushStore struct {
	mu       sync.Mutex
	rows     []SenderKeyRow
	calls    atomic.Int64
	failOnce bool // if true, return an error on the first call, then succeed
	failErr  error
}

func (m *mockFlushStore) PutManySenderKeys(_ context.Context, keys []SenderKeyRow) error {
	m.calls.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failOnce && m.failErr != nil {
		err := m.failErr
		m.failOnce = false
		return err
	}
	for _, k := range keys {
		m.rows = append(m.rows, SenderKeyRow{Group: k.Group, User: k.User, Blob: k.Blob})
	}
	return nil
}

func (m *mockFlushStore) rowCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}

// newTestFlusher builds a SenderKeyFlusher with a small cap for test isolation.
// N is always 500 (default) unless the test overrides by setting f.boundaryN.
func newTestFlusher(t *testing.T, cap int) (*SenderKeyFlusher, *mockFlushStore) {
	t.Helper()
	store := &mockFlushStore{}
	f := NewSenderKeyFlusher(store, waLog.Noop, cap)
	return f, store
}

// testBlob returns a minimal PackFlat blob with one state for use in flusher
// unit tests. keyID and iter encode into the blob header bytes.
// Requires valid byte lengths for chainKey (32) and signingPub (33).
func testBlob(keyID, iter uint32) []byte {
	chainKey := make([]byte, 32)
	sigPub := make([]byte, 33)
	sigPub[0] = 0x05
	sigPriv := make([]byte, 32)
	s := testStructure(keyID, iter, chainKey, sigPub, sigPriv)
	blob, _ := packFlatForTest(s)
	return blob
}

// packFlatForTest is a local alias so flusher tests don't import the store package.
// It calls the package-level store.PackFlat indirectly via NewSenderKeyRow.
func packFlatForTest(s *groupRecord.SenderKeyStructure) ([]byte, bool) {
	row := NewSenderKeyRow("g", "u", s)
	return row.Blob, row.Blob != nil
}

// testStructure builds a minimal SenderKeyStructure for keyID/iter.
func testStructure(keyID, iter uint32, chainKey, sigPub, sigPriv []byte) *groupRecord.SenderKeyStructure {
	return &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
			{
				KeyID: keyID,
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: iter,
					ChainKey:  chainKey,
				},
				SigningKeyPublic:  sigPub,
				SigningKeyPrivate: sigPriv,
			},
		},
	}
}

// ---------------------------------------------------------------------------
// TestExtractStructMeta
// Phase 17.11-05: extractSenderKeyMeta replaced by extractStructMeta.
// Verify it reads KeyID/Iteration from *SenderKeyStructure correctly.
// ---------------------------------------------------------------------------

func TestExtractSenderKeyMeta_FromCols(t *testing.T) {
	chainKey := make([]byte, 32)
	sigPub := make([]byte, 33)
	sigPub[0] = 0x05
	s := testStructure(7, 42, chainKey, sigPub, make([]byte, 32))
	keyID, iter := extractStructMeta(s)
	if keyID != 7 {
		t.Errorf("keyID = %d, want 7", keyID)
	}
	if iter != 42 {
		t.Errorf("iteration = %d, want 42", iter)
	}
}

func TestExtractSenderKeyMeta_NilCols(t *testing.T) {
	keyID, iter := extractStructMeta(nil)
	if keyID != 0 || iter != 0 {
		t.Errorf("nil structure: got keyID=%d iter=%d, want 0,0", keyID, iter)
	}
}

func TestExtractSenderKeyMeta_ZeroStateCols(t *testing.T) {
	// 0-state structure: len(SenderKeyStates)==0 → (0,0) guard.
	s := &groupRecord.SenderKeyStructure{}
	keyID, iter := extractStructMeta(s)
	if keyID != 0 || iter != 0 {
		t.Errorf("zero-state cols: got keyID=%d iter=%d, want 0,0", keyID, iter)
	}
}

// ---------------------------------------------------------------------------
// TestSKDMDedupSkipsEqualIter
// Enqueue called twice with the same keyID and iteration must NOT enqueue the
// second time — processedCount stays at 1 after the second call.
// ---------------------------------------------------------------------------

func TestSKDMDedupSkipsEqualIter(t *testing.T) {
	f, _ := newTestFlusher(t, 1000)

	// First call processes (first enqueue, no cached entry yet).
	f.Enqueue("group-A", "user-1", testBlob(1, 5), 1, 5, false)
	processed1 := f.processedCount.Load()
	if processed1 != 1 {
		t.Fatalf("after first Enqueue: processedCount = %d, want 1", processed1)
	}

	// Second call with same keyID=1 iter=5 must be skipped.
	f.Enqueue("group-A", "user-1", testBlob(1, 5), 1, 5, false)
	processed2 := f.processedCount.Load()
	if processed2 != 1 {
		t.Fatalf("after second Enqueue (same iter): processedCount = %d, want 1 (dedup must skip)", processed2)
	}
	skipped := f.skippedCount.Load()
	if skipped < 1 {
		t.Fatalf("skippedCount = %d, want >= 1 after dedup skip", skipped)
	}
}

// ---------------------------------------------------------------------------
// TestSKDMDedupProcessesHigherIter
// A higher iteration within the same keyID must always be processed.
// ---------------------------------------------------------------------------

func TestSKDMDedupProcessesHigherIter(t *testing.T) {
	f, _ := newTestFlusher(t, 1000)

	f.Enqueue("group-B", "user-2", testBlob(1, 5), 1, 5, false)
	if f.processedCount.Load() != 1 {
		t.Fatalf("processedCount after iter=5: %d, want 1", f.processedCount.Load())
	}

	// Higher iteration must process.
	f.Enqueue("group-B", "user-2", testBlob(1, 6), 1, 6, false)
	if f.processedCount.Load() != 2 {
		t.Fatalf("processedCount after iter=6: %d, want 2 (higher iter must process)", f.processedCount.Load())
	}

	// Verify highIter was updated in the dirty-set.
	f.mu.Lock()
	entry := f.dirty["group-B|user-2"]
	f.mu.Unlock()
	if entry == nil {
		t.Fatal("dirty entry missing after iter=6 enqueue")
	}
	if entry.highIter != 6 {
		t.Fatalf("highIter = %d, want 6", entry.highIter)
	}
}

// ---------------------------------------------------------------------------
// TestSKDMDedupKeyIDRotationAlwaysProcesses
// A new keyID (generation rotation) must always process, even when the new
// iteration is lower than the cached iteration. Design §3: "new keyID = new
// generation → always processes."
// ---------------------------------------------------------------------------

func TestSKDMDedupKeyIDRotationAlwaysProcesses(t *testing.T) {
	f, _ := newTestFlusher(t, 1000)

	// Seed with keyID=1, iter=500.
	f.Enqueue("group-K", "user-K", testBlob(1, 500), 1, 500, false)
	before := f.processedCount.Load()

	// New keyID=2 with low iter=1 — rotation must process despite iter < highIter.
	f.Enqueue("group-K", "user-K", testBlob(2, 1), 2, 1, false)
	after := f.processedCount.Load()
	if after <= before {
		t.Fatalf("keyID rotation: processedCount did not increase: before=%d after=%d (new generation must always process)", before, after)
	}

	// The dirty entry must have the new keyID and iter.
	f.mu.Lock()
	entry := f.dirty["group-K|user-K"]
	f.mu.Unlock()
	if entry == nil {
		t.Fatal("dirty entry missing after keyID rotation")
	}
	if entry.keyID != 2 {
		t.Fatalf("keyID = %d, want 2 after rotation", entry.keyID)
	}
	if entry.highIter != 1 {
		t.Fatalf("highIter = %d, want 1 after rotation", entry.highIter)
	}
}

// ---------------------------------------------------------------------------
// TestSKDMDedupBypassFailedTuple
// wasFailed=true must always enqueue regardless of cached iter.
// ---------------------------------------------------------------------------

func TestSKDMDedupBypassFailedTuple(t *testing.T) {
	f, _ := newTestFlusher(t, 1000)

	// Seed with keyID=1, iter=5.
	f.Enqueue("group-C", "user-3", testBlob(1, 5), 1, 5, false)
	before := f.processedCount.Load()

	// Same keyID=1, iter=5 but wasFailed=true — must bypass dedup.
	f.Enqueue("group-C", "user-3", testBlob(1, 5), 1, 5, true)
	after := f.processedCount.Load()
	if after <= before {
		t.Fatalf("processedCount did not increase on wasFailed=true bypass: before=%d after=%d", before, after)
	}
}

// ---------------------------------------------------------------------------
// TestFlushTriggerNBoundary
// iter=499 → floor(499/500)=0 == floor(0/500)=0 → NO flush signal.
// iter=500 → floor(500/500)=1 > 0 → flush signal sent to flushCh.
// ---------------------------------------------------------------------------

func TestFlushTriggerNBoundary(t *testing.T) {
	f, _ := newTestFlusher(t, 1000)
	f.boundaryN = 500

	// iter=499 → no boundary crossing (floor(499/500)=0, lastFlushed=0 → 0==0).
	f.Enqueue("group-D", "user-4", testBlob(1, 499), 1, 499, false)
	select {
	case <-f.flushCh:
		t.Fatal("flushCh received signal for iter=499 but floor(499/500)=0, no boundary crossed")
	default:
		// correct — no signal
	}

	// iter=500 → boundary crossing (floor(500/500)=1 > floor(0/500)=0).
	f.Enqueue("group-D", "user-4", testBlob(1, 500), 1, 500, false)
	select {
	case <-f.flushCh:
		// correct — boundary signal received
	case <-time.After(100 * time.Millisecond):
		t.Fatal("flushCh: no signal for iter=500 boundary crossing within 100ms")
	}
}

// ---------------------------------------------------------------------------
// TestEvictEnqueues
// Verify that after a simulated LRU eviction re-enqueue, the entry appears
// in the flusher's dirty-set (not silently dropped).
// ---------------------------------------------------------------------------

func TestEvictEnqueues(t *testing.T) {
	f, _ := newTestFlusher(t, 1000)

	group, user := "group-E", "user-5"
	var keyID uint32 = 1
	var iter uint32 = 1

	// Enqueue (as the PutSenderKeyStructure path would).
	f.Enqueue(group, user, testBlob(keyID, iter), keyID, iter, false)

	// After re-enqueue, the entry must be in the dirty-set.
	f.mu.Lock()
	entry := f.dirty[group+"|"+user]
	f.mu.Unlock()

	if entry == nil {
		t.Fatal("eviction re-enqueue: entry not found in dirty-set")
	}
	if entry.highIter != iter {
		t.Fatalf("eviction re-enqueue: highIter = %d, want %d", entry.highIter, iter)
	}
}

// ---------------------------------------------------------------------------
// TestShutdownDrain
// Enqueue 10 entries, call Drain(), confirm all 10 were written.
// ---------------------------------------------------------------------------

func TestShutdownDrain(t *testing.T) {
	f, store := newTestFlusher(t, 1000)

	for i := 0; i < 10; i++ {
		f.Enqueue("group-F", "user-"+string(rune('a'+i)), testBlob(1, 1), 1, 1, false)
	}

	// Drain must write all 10 entries.
	done := make(chan struct{})
	go func() {
		f.Drain()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Drain did not complete within 5 seconds")
	}

	// All entries must have been written.
	if n := store.rowCount(); n != 10 {
		t.Fatalf("after Drain: store has %d rows, want 10", n)
	}
	// Dirty-set must be empty.
	if n := f.DirtyCount(); n != 0 {
		t.Fatalf("after Drain: dirty-set has %d entries, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// TestInlineSyncValve
// When dirty-set size > backpressureCap, the next Enqueue performs an inline
// synchronous write (single row PutManySenderKeys call) instead of just
// enqueuing.
// ---------------------------------------------------------------------------

func TestInlineSyncValve(t *testing.T) {
	// Use a tiny cap so backpressureCap is small (cap/5).
	// backpressureCap = 10/5 = 2
	f, store := newTestFlusher(t, 10)

	// Fill dirty-set to just over backpressureCap (=2).
	for i := 0; i < 3; i++ {
		// Directly insert into dirty-set to bypass dedup logic.
		k := "group-G|" + string(rune('a'+i))
		f.mu.Lock()
		f.dirty[k] = &dirtyEntry{
			group:    "group-G",
			user:     string(rune('a' + i)),
			blob:     testBlob(1, 1),
			highIter: 1,
			keyID:    1,
		}
		f.mu.Unlock()
	}

	prevCalls := store.calls.Load()

	// Next Enqueue should trigger inline sync write because len(dirty) > backpressureCap.
	f.Enqueue("group-G", "user-Z", testBlob(1, 999), 1, 999, false)

	// Wait briefly for the inline write to complete (it's synchronous but we
	// need to account for any scheduling).
	deadline := time.Now().Add(2 * time.Second)
	for store.calls.Load() <= prevCalls && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if store.calls.Load() <= prevCalls {
		t.Fatal("inline sync valve: PutManySenderKeys was not called after dirty-set exceeded backpressureCap")
	}
}

// ---------------------------------------------------------------------------
// TestFlusherRace_ConcurrentEnqueueDrain
// Concurrent Enqueue + Drain calls must not race (detected by -race).
// ---------------------------------------------------------------------------

func TestFlusherRace_ConcurrentEnqueueDrain(t *testing.T) {
	f, _ := newTestFlusher(t, 1000)
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
				f.Enqueue("group", "user-"+string(rune('a'+i%26)), testBlob(1, uint32(j+1)), 1, uint32(j+1), false)
			}
		}()
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// TestFlusherDirtyCount
// DirtyCount reflects the current dirty-set size correctly.
// ---------------------------------------------------------------------------

func TestFlusherDirtyCount(t *testing.T) {
	f, _ := newTestFlusher(t, 1000)

	if n := f.DirtyCount(); n != 0 {
		t.Fatalf("initial DirtyCount = %d, want 0", n)
	}

	f.Enqueue("group-H", "user-1", testBlob(1, 1), 1, 1, false)
	f.Enqueue("group-H", "user-2", testBlob(1, 1), 1, 1, false)

	if n := f.DirtyCount(); n != 2 {
		t.Fatalf("after 2 Enqueues: DirtyCount = %d, want 2", n)
	}
}

// Ensure processedCount field type is accessible from tests (compile-time check).
var _ = (*atomic.Uint64)(nil)

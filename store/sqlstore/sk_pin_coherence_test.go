// Copyright (c) 2026 Kavtov Platform (Phase 260617-0k0)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// sk_pin_coherence_test.go covers the five incoherence scenarios fixed in
// Phase 260617-0k0:
//   - WriteBeforeDrain: just-written device visible before any flusher drain
//   - EvictThenEnum: device still visible after LRU eviction while write is pending
//   - DrainUnpins: onDrained fires after Drain, unpin removes pinned entry
//   - ConcurrentWrites: concurrent writes for different devices both survive in pinned
//   - EmptyNotCached: empty device-set from inner is NOT cached
package sqlstore

import (
	"context"
	"sync"
	"testing"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// TestSKPinWriteBeforeDrain verifies that after a write (flusher wired but NOT
// drained), GetSenderKeyDevices returns the written device immediately via the
// pinned overlay — without any inner call for that device.
func TestSKPinWriteBeforeDrain(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCachedSenderKeyStore(t, 16)

	// Wire a flusher but do NOT Start it — dirty-set stays in-process, mock
	// drain count stays at 0.
	ms := &mockFlushStore{}
	flusher := NewSenderKeyFlusher(ms, waLog.Noop, 0)
	c.SetFlusher(flusher)

	// updateDeviceCache is the shared internal write path exercised by all Put
	// variants. Call it directly — no blob or DB write needed for this test.
	c.updateDeviceCache("group-A", "user_1:0")

	// GetSenderKeyDevices must return the device from the pinned overlay alone
	// (flusher not drained, inner has no key yet, deviceCache empty).
	devices, err := c.GetSenderKeyDevices(ctx, "group-A", "user_1")
	if err != nil {
		t.Fatalf("GetSenderKeyDevices: %v", err)
	}

	found := false
	for _, d := range devices {
		if d == "user_1:0" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetSenderKeyDevices = %v, want to contain \"user_1:0\"", devices)
	}

	// Confirm flusher has NOT been drained (mock call count 0).
	if got := ms.calls.Load(); got != 0 {
		t.Errorf("mockFlushStore.calls = %d, want 0 (flusher not drained)", got)
	}
}

// TestSKPinEvictThenEnum verifies that evicting the deviceCache LRU entry while
// a write is pending still allows GetSenderKeyDevices to return the device via
// the pinned overlay.
func TestSKPinEvictThenEnum(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCachedSenderKeyStore(t, 16)

	ms := &mockFlushStore{}
	flusher := NewSenderKeyFlusher(ms, waLog.Noop, 0)
	c.SetFlusher(flusher)

	// Add the device via updateDeviceCache (same path as any Put variant).
	c.updateDeviceCache("group-A", "user_1:0")

	// Simulate LRU eviction by explicitly removing the deviceCache entry.
	dk := c.key("group-A", senderKeyUserBare("user_1:0"))
	c.deviceCache.Remove(dk)

	// After eviction the LRU is empty, but the pinned overlay still holds the entry.
	devices, err := c.GetSenderKeyDevices(ctx, "group-A", "user_1")
	if err != nil {
		t.Fatalf("GetSenderKeyDevices after eviction: %v", err)
	}

	found := false
	for _, d := range devices {
		if d == "user_1:0" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetSenderKeyDevices after eviction = %v, want to contain \"user_1:0\" (pin holds)", devices)
	}
}

// TestSKPinDrainUnpins verifies that after Drain commits, onDrained fires and
// removes the pin. GetSenderKeyDevices then reads from the DB path (not pinned).
func TestSKPinDrainUnpins(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedSenderKeyStore(t, 16)

	ms := &mockFlushStore{}
	flusher := NewSenderKeyFlusher(ms, waLog.Noop, 0)
	c.SetFlusher(flusher)

	// Enqueue so the dirty-set is non-empty when Drain runs; updateDeviceCache
	// adds to pinned. Both are required: updateDeviceCache alone leaves the
	// dirty-set empty so Drain returns immediately without firing onDrained.
	blob := testBlob(1, 1)
	c.flusher.Enqueue("group-B", "user_2:0", blob, 1, 1, false)
	c.updateDeviceCache("group-B", "user_2:0")

	// Seed the inner fakeSenderKeyStore so the post-drain DB read returns the device.
	if err := inner.PutSenderKey(ctx, "group-B", "user_2:0", []byte("sk")); err != nil {
		t.Fatalf("seed inner: %v", err)
	}

	// Drain commits via mockFlushStore and fires onDrained for the deleted key.
	c.flusher.Drain()

	// After drain, the pin must be gone.
	dk := c.key("group-B", senderKeyUserBare("user_2:0"))
	c.pinnedMu.Lock()
	_, stillPinned := c.pinned[dk]
	c.pinnedMu.Unlock()
	if stillPinned {
		t.Error("c.pinned still has entry for group-B/user_2 after Drain (unpin failed)")
	}

	// GetSenderKeyDevices must still return the device (now from the DB path).
	devices, err := c.GetSenderKeyDevices(ctx, "group-B", "user_2")
	if err != nil {
		t.Fatalf("GetSenderKeyDevices post-drain: %v", err)
	}
	found := false
	for _, d := range devices {
		if d == "user_2:0" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetSenderKeyDevices post-drain = %v, want to contain \"user_2:0\"", devices)
	}
}

// TestSKPinConcurrentWrites verifies that concurrent writes for two different
// device sids under the same sender both survive in pinned[key]. The -race flag
// validates the concurrency safety.
func TestSKPinConcurrentWrites(t *testing.T) {
	c, _ := newTestCachedSenderKeyStore(t, 16)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			// Half write :0, half write :5 — both for the same bare user.
			if i%2 == 0 {
				c.updateDeviceCache("group-C", "user_3:0")
			} else {
				c.updateDeviceCache("group-C", "user_3:5")
			}
		}()
	}
	wg.Wait()

	dk := c.key("group-C", senderKeyUserBare("user_3:0"))
	c.pinnedMu.Lock()
	ps := c.pinned[dk]
	_, has0 := ps["user_3:0"]
	_, has5 := ps["user_3:5"]
	c.pinnedMu.Unlock()

	if !has0 {
		t.Error("pinned[group-C|user_3] missing user_3:0 after concurrent writes")
	}
	if !has5 {
		t.Error("pinned[group-C|user_3] missing user_3:5 after concurrent writes")
	}
}

// TestSKPinEmptyNotCached verifies that when inner returns 0 devices, the
// result is NOT cached in the deviceCache LRU, forcing a re-query on the next call.
func TestSKPinEmptyNotCached(t *testing.T) {
	ctx := context.Background()
	// Fresh store with no inner data; no flusher wired.
	c, inner := newTestCachedSenderKeyStore(t, 16)

	// Call twice — inner has no rows so it returns empty each time.
	if _, err := c.GetSenderKeyDevices(ctx, "group-D", "user_4"); err != nil {
		t.Fatalf("GetSenderKeyDevices (1st): %v", err)
	}
	if _, err := c.GetSenderKeyDevices(ctx, "group-D", "user_4"); err != nil {
		t.Fatalf("GetSenderKeyDevices (2nd): %v", err)
	}

	// Both calls must have reached inner (empty not cached → 2 inner queries).
	if got := inner.devicesCalls.Load(); got != 2 {
		t.Errorf("inner.devicesCalls = %d, want 2 (empty result must not be cached)", got)
	}

	// deviceCache must be empty (no cached entry for an empty result).
	if got := c.deviceCache.Len(); got != 0 {
		t.Errorf("deviceCache.Len() = %d, want 0 (empty result not cached)", got)
	}
}

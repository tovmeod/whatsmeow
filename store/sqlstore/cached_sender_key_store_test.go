// Copyright (c) 2026 Kavtov Platform (Phase 17.5)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

func TestSenderKeyReinitialization(t *testing.T) {
	container := &Container{log: waLog.Noop}
	wireSignalCaches(container, waLog.Noop)
	t.Cleanup(func() { closeSignalCaches(container) })
	jid := types.NewJID("account", types.DefaultUserServer)
	device := &store.Device{ID: &jid}
	attachCachedStores(container, device, NewSQLStore(container, jid))
	old := device.SenderKeys.(*CachedSenderKeyStore)
	dk := old.deviceKey("g", "sender:1")
	old.deviceCache.Add(dk, deviceCacheEntry{})
	old.pinned[dk] = map[string]struct{}{"sender:1": {}}
	old.pinnedBlobs[old.key("g", "sender:1")] = []byte("pending")
	flusher := old.flusher
	attachCachedStores(container, device, NewSQLStore(container, jid))
	fresh := device.SenderKeys.(*CachedSenderKeyStore)
	if _, err := old.GetSenderKeyDevices(context.Background(), "g", "sender"); err == nil {
		t.Fatal("retired sender-key wrapper remains usable after reinitialization")
	}
	if fresh.flusher != flusher || !containsString(fresh.pinnedDevices(dk), "sender:1") {
		t.Fatal("reattachment lost the singleton flusher or pending overlay")
	}
	flusher.notifyDrained(SenderKeyRow{Group: "g", User: "sender:1", Blob: []byte("pending")})
	if len(fresh.pinnedDevices(dk)) != 0 || len(old.pinned) != 0 || len(old.pinnedBlobs) != 0 {
		t.Fatal("drain callback or retired overlay cleanup failed")
	}
}

// Pause after a successful inline SQL flush has removed the dirty row, while
// its writer still owns writeMu and must acquire snapshotMu to unpin.
func TestSenderKeyInlineFlushRetirement(t *testing.T) {
	for _, action := range []string{"attach", "delete", "close"} {
		t.Run(action, func(t *testing.T) {
			old, inner := newTestCachedSenderKeyStore(t, 16)
			f := NewSenderKeyFlusher(&mockFlushStore{}, waLog.Noop, 100)
			old.SetFlusher(f)
			structure, _ := store.UnpackFlat(testBlob(7, 2))
			if err := old.PutSenderKeyStructure(context.Background(), "g", "sender:2", structure); err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			f.SetOnDrained(func(_, user string) {
				if user == "sender:1" {
					close(entered)
					<-release
				}
			})
			f.backpressureCap = 0
			writeDone := make(chan error, 1)
			go func() { writeDone <- old.PutSenderKeyStructure(context.Background(), "g", "sender:1", structure) }()
			<-entered
			fresh := NewCachedSenderKeyStore(inner, old.jid, old.cache, old.deviceCache)
			container := &Container{log: waLog.Noop}
			container.caches.senderKeyFlusherMap = map[string]*SenderKeyFlusher{old.jid: f}
			retireDone := make(chan struct{})
			go func() {
				defer close(retireDone)
				switch action {
				case "attach":
					fresh.SetFlusher(f)
				case "delete":
					stopAccountSignalCaches(container, old.jid)
				case "close":
					closeSignalCaches(container)
				}
			}()
			awaitSenderKeyRetirementWait(t)
			close(release)
			select {
			case err := <-writeDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("inline writer deadlocked with owner retirement")
			}
			select {
			case <-retireDone:
			case <-time.After(time.Second):
				t.Fatal("owner retirement did not finish")
			}
			if !old.retired.Load() {
				t.Fatal("old owner remains writable")
			}
			if action == "attach" {
				pins := fresh.pinnedDevices(fresh.deviceKey("g", "sender"))
				if len(pins) != 1 || pins[0] != "sender:2" {
					t.Fatalf("replacement lost pending pin or retained drained pin: %v", pins)
				}
				fresh.cache.Purge()
				if got, err := fresh.GetSenderKeyStructure(context.Background(), "g", "sender:2"); err != nil || got == nil {
					t.Fatalf("replacement lost pending blob: %v, %v", got, err)
				}
				f.Stop()
			}
		})
	}
}

func awaitSenderKeyRetirementWait(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		buf := make([]byte, 128<<10)
		n := runtime.Stack(buf, true)
		stack := string(buf[:n])
		if strings.Contains(stack, "(*CachedSenderKeyStore).retire(") || strings.Contains(stack, "(*SenderKeyFlusher).lockOwner(") {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("lifecycle did not reach its owner-write barrier")
}

func TestSenderKeyConcurrentOwnerReplacement(t *testing.T) {
	old, inner := newTestCachedSenderKeyStore(t, 16)
	f := NewSenderKeyFlusher(&mockFlushStore{}, waLog.Noop, 100)
	old.SetFlusher(f)
	structure, _ := store.UnpackFlat(testBlob(7, 2))
	if err := old.PutSenderKeyStructure(context.Background(), "g", "sender:1", structure); err != nil {
		t.Fatal(err)
	}
	first := NewCachedSenderKeyStore(inner, old.jid, old.cache, old.deviceCache)
	second := NewCachedSenderKeyStore(inner, old.jid, old.cache, old.deviceCache)
	old.writeMu.Lock()
	done := make(chan struct{}, 2)
	for _, next := range []*CachedSenderKeyStore{first, second} {
		go func() { next.SetFlusher(f); done <- struct{}{} }()
	}
	// Both attachments have selected the old owner and are waiting for its
	// writer. The loser must recheck instead of transferring the old empty map.
	deadline := time.Now().Add(time.Second)
	for {
		buf := make([]byte, 128<<10)
		n := runtime.Stack(buf, true)
		if strings.Count(string(buf[:n]), "(*SenderKeyFlusher).lockOwner(") >= 2 {
			break
		}
		if time.Now().After(deadline) {
			old.writeMu.Unlock()
			t.Fatal("attachments did not reach the write barrier")
		}
		runtime.Gosched()
	}
	old.writeMu.Unlock()
	for range 2 {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("concurrent attachment deadlocked")
		}
	}
	f.snapshotMu.RLock()
	owner := f.owner
	f.snapshotMu.RUnlock()
	if owner.retired.Load() || !containsString(owner.pinnedDevices(owner.deviceKey("g", "sender")), "sender:1") {
		t.Fatal("concurrent replacement lost the live owner or pending overlay")
	}
	if !old.retired.Load() || first.retired.Load() == second.retired.Load() {
		t.Fatal("replacement did not retire exactly the displaced owners")
	}
	f.Stop()
}

func TestSenderKeyTeardownDonorFlights(t *testing.T) {
	stub := &stubRecoveryInner{entered: make(chan struct{}, 1), release: make(chan struct{})}
	blobs, _ := lru.New[string, []byte](4)
	devices, _ := NewSenderKeyDeviceCache(4)
	c := NewCachedSenderKeyStore(stub, "account", blobs, devices)
	key := c.donorKey("g", "sender", 7)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = c.lookupDonor(context.Background(), stub, key, 1) }()
	<-stub.entered
	other := donorQueryKey{universe: &Container{}, group: "other", sender: "sender", keyID: 7}
	noDonorCacheMu.Lock()
	noDonorCache.Add(other, noDonorCacheEntry{expiresAt: time.Now().Add(time.Hour)})
	noDonorCacheMu.Unlock()
	clearDonorUniverse(stub)
	noDonorCacheMu.Lock()
	_, retained := donorWaves[key]
	_, active := donorFlights[donorWorkKey{key, 1}]
	_, otherPresent := noDonorCache.Peek(other)
	noDonorCacheMu.Unlock()
	close(stub.release)
	<-done
	if retained || active {
		t.Fatal("teardown retained old-domain coordination")
	}
	if !otherPresent || getNoDonorCacheEntry(key, 1, time.Now()) {
		t.Fatal("teardown affected another universe or allowed stale absence")
	}
	clearDonorUniverse(other.universe)
}

func TestSenderKeyTeardownDeleteDevice(t *testing.T) {
	sq := commitTestStore(t, func([]driver.NamedValue) error { return nil })
	c := sq.Container
	wireSignalCaches(c, waLog.Noop)
	t.Cleanup(func() { closeSignalCaches(c) })
	jidA := types.NewJID("removed", types.DefaultUserServer)
	jidB := types.NewJID("preserved", types.DefaultUserServer)
	a, b := &store.Device{ID: &jidA}, &store.Device{ID: &jidB}
	attachCachedStores(c, a, NewSQLStore(c, jidA))
	attachCachedStores(c, b, NewSQLStore(c, jidB))
	old := a.SenderKeys.(*CachedSenderKeyStore)
	other := b.SenderKeys.(*CachedSenderKeyStore)
	keyA, keyB := old.deviceKey("g", "sender"), other.deviceKey("g", "sender")
	c.caches.SenderKeyDevices.Add(keyA, deviceCacheEntry{})
	c.caches.SenderKeyDevices.Add(keyB, deviceCacheEntry{})
	old.pinned[keyA] = map[string]struct{}{"sender:1": {}}
	if err := c.DeleteDevice(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if c.caches.SenderKeyDevices.Contains(keyA) || !c.caches.SenderKeyDevices.Contains(keyB) || len(old.pinned) != 0 {
		t.Fatal("account cleanup retained removed state or damaged another account")
	}
	if len(c.caches.senderKeyFlusherMap) != 1 || len(c.caches.sessionFlusherMap) != 1 || old.retired.Load() == false {
		t.Fatal("removed account's owner/flushers survived teardown")
	}
}

func TestSenderKeyReinitializationFencesDeviceFlight(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	c, inner := newDevicePolicyStore(t, 4, func(context.Context, string, string) ([]string, error) {
		close(entered)
		<-release
		return []string{}, nil
	})
	done := make(chan struct{})
	go func() { defer close(done); _, _ = c.GetSenderKeyDevices(context.Background(), "g", "sender") }()
	<-entered
	fresh := NewCachedSenderKeyStore(inner, c.jid, c.cache, c.deviceCache)
	c.retire(fresh)
	if len(c.deviceCache.flights) != 0 {
		t.Fatal("retirement retained old device flights")
	}
	close(release)
	<-done
	if c.deviceCache.Len() != 0 {
		t.Fatal("old empty query published into replacement owner")
	}
}

// Compile-time conformance is asserted inside cached_sender_key_store.go via
//   var _ store.SenderKeyStore = (*CachedSenderKeyStore)(nil)
// A separate test below references the wrapper type to keep the assertion
// reachable from the test binary.

// ---------------------------------------------------------------------------
// Test helper: newTestCachedSenderKeyStore wires a fakeSenderKeyStore and
// an LRU cache of []byte sized to capSize. The wrapper uses "test-jid"
// (no trailing pipe) as the JID — matching production usage at
// container.go:363 where the JID comes from `device.ID.String()` without
// a trailing pipe. The wrapper composes the full cache key internally as
// `jid + "|" + group + "|" + user` (three-element per RESEARCH Finding 7),
// producing single-pipe keys (`"test-jid|<group>|<user>"`).
//
// Group and user fixtures passed to the wrapper's methods are bare strings.
// Tests MUST NOT pre-compose group/user with the JID or with a trailing
// pipe — that would produce double-pipe or other malformed cache keys
// that disagree with the production code path. (Phase 17.5 FIX2 IN-01.)
// ---------------------------------------------------------------------------

func newTestCachedSenderKeyStore(t *testing.T, capSize int) (*CachedSenderKeyStore, *fakeSenderKeyStore) {
	t.Helper()
	inner := newFakeSenderKeyStore()
	cache, err := lru.New[string, []byte](capSize)
	if err != nil {
		t.Fatalf("lru.New[string, []byte] failed: %v", err)
	}
	deviceCache, err := NewSenderKeyDeviceCache(capSize)
	if err != nil {
		t.Fatalf("NewSenderKeyDeviceCache failed: %v", err)
	}
	// "test-jid" with no trailing pipe — wrapper's key() prepends the
	// separator. Matches production format used by Container.initializeDevice.
	wrapper := NewCachedSenderKeyStore(inner, "test-jid", cache, deviceCache)
	return wrapper, inner
}

// ---------------------------------------------------------------------------
// Compile-time conformance assertion reach test.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_InterfaceConformance(t *testing.T) {
	// Touching the type keeps the package-level
	//   var _ store.SenderKeyStore = (*CachedSenderKeyStore)(nil)
	// assertion reachable; if the wrapper drifts from the interface this test
	// (and the whole package) fails to compile.
	var c *CachedSenderKeyStore
	if c != nil {
		t.Fatal("nil pointer should stay nil")
	}
}

func TestSenderKeyDeviceNegativeTTLStartsAtCompletion(t *testing.T) {
	startedAt := time.Unix(2_000, 0)
	now := startedAt
	calls := 0
	c, _ := newDevicePolicyStore(t, 16, func(context.Context, string, string) ([]string, error) {
		calls++
		if calls == 1 {
			// The first query consumes one minute before authoritative absence.
			now = startedAt.Add(time.Minute)
		}
		return []string{}, nil
	})
	c.deviceCache.now = func() time.Time { return now }
	read := func() {
		t.Helper()
		devices, err := c.GetSenderKeyDevices(context.Background(), "empty", "user_1")
		if err != nil || len(devices) != 0 {
			t.Fatalf("authoritative empty = %v, %v", devices, err)
		}
	}
	read()
	now = startedAt.Add(5 * time.Minute)
	read()
	if calls != 1 {
		t.Fatalf("deadline anchored at query start: calls = %d, want 1", calls)
	}
	now = startedAt.Add(6*time.Minute - time.Nanosecond)
	read()
	if calls != 1 {
		t.Fatalf("pre-completion-deadline calls = %d, want 1", calls)
	}
	now = now.Add(time.Nanosecond)
	read()
	if calls != 2 {
		t.Fatalf("completion deadline equality calls = %d, want 2", calls)
	}
}

func TestSenderKeyDeviceNegativeFixedTTL(t *testing.T) {
	c, inner := newTestCachedSenderKeyStore(t, 16)
	now := time.Unix(1_000, 0)
	c.deviceCache.now = func() time.Time { return now }
	for range 3 {
		if _, err := c.GetSenderKeyDevices(context.Background(), "empty", "user_1"); err != nil {
			t.Fatal(err)
		}
	}
	if got := inner.devicesCalls.Load(); got != 1 {
		t.Fatalf("repeated authoritative empty queries = %d, want 1", got)
	}
	now = now.Add(5*time.Minute - time.Nanosecond)
	_, _ = c.GetSenderKeyDevices(context.Background(), "empty", "user_1:99")
	if inner.devicesCalls.Load() != 1 {
		t.Fatal("pre-expiry device suffix lookup missed")
	}
	now = now.Add(time.Nanosecond)
	_, _ = c.GetSenderKeyDevices(context.Background(), "empty", "user_1")
	if inner.devicesCalls.Load() != 2 {
		t.Fatal("equality must expire")
	}
	if err := c.PutSenderKey(context.Background(), "empty", "user_1:7", []byte("key")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	got, err := c.GetSenderKeyDevices(context.Background(), "empty", "user_1")
	if err != nil || !containsString(got, "user_1:7") || inner.devicesCalls.Load() != 2 {
		t.Fatalf("positive expired: %v %v", got, err)
	}
}

type devicePolicyInner struct {
	*fakeSenderKeyStore
	read  func(context.Context, string, string) ([]string, error)
	calls atomic.Int64
}

func (s *devicePolicyInner) GetSenderKeyDevices(ctx context.Context, group, sender string) ([]string, error) {
	s.calls.Add(1)
	return s.read(ctx, group, sender)
}

func newDevicePolicyStore(t *testing.T, cap int, read func(context.Context, string, string) ([]string, error)) (*CachedSenderKeyStore, *devicePolicyInner) {
	t.Helper()
	inner := &devicePolicyInner{fakeSenderKeyStore: newFakeSenderKeyStore(), read: read}
	blobs, _ := lru.New[string, []byte](cap)
	devices, err := NewSenderKeyDeviceCache(cap)
	if err != nil {
		t.Fatal(err)
	}
	return NewCachedSenderKeyStore(inner, "account", blobs, devices), inner
}

func TestSenderKeyDeviceNegativeIdentity(t *testing.T) {
	c, inner := newDevicePolicyStore(t, 32, func(context.Context, string, string) ([]string, error) { return []string{}, nil })
	for _, pair := range [][2]string{{"a|b", "c"}, {"a", "b|c"}, {"g", "42_1"}, {"g", "42_2"}, {"g", "42@s.whatsapp.net"}, {"g", "42@lid"}} {
		for range 2 {
			_, _ = c.GetSenderKeyDevices(context.Background(), pair[0], pair[1])
		}
	}
	if inner.calls.Load() != 6 {
		t.Fatalf("identity collision: %d queries", inner.calls.Load())
	}
	c2 := NewCachedSenderKeyStore(inner, "other-account", c.cache, c.deviceCache)
	_, _ = c2.GetSenderKeyDevices(context.Background(), "a", "b|c")
	other := &devicePolicyInner{fakeSenderKeyStore: newFakeSenderKeyStore(), read: inner.read}
	c3 := NewCachedSenderKeyStore(other, c.jid, c.cache, c.deviceCache)
	_, _ = c3.GetSenderKeyDevices(context.Background(), "a", "b|c")
	if inner.calls.Load() != 7 || other.calls.Load() != 1 {
		t.Fatal("account/store absence leaked")
	}
}

func TestSenderKeyDeviceNegativeNonAuthoritative(t *testing.T) {
	for _, tc := range []struct {
		name    string
		devices []string
		err     error
	}{
		{"nil", nil, nil}, {"malformed", []string{"user_1:"}, nil}, {"wrong-sender", []string{"other:0"}, nil}, {"error", nil, errors.New("query failed")}, {"cancel", []string{}, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, inner := newDevicePolicyStore(t, 4, func(context.Context, string, string) ([]string, error) { return tc.devices, tc.err })
			for range 2 {
				_, _ = c.GetSenderKeyDevices(context.Background(), "g", "user_1")
			}
			if inner.calls.Load() != 2 || c.deviceCache.Len() != 0 {
				t.Fatal("non-authoritative result cached")
			}
		})
	}
}

func awaitDeviceParticipants(t *testing.T, c *CachedSenderKeyStore, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.deviceCache.mu.Lock()
		n := 0
		for _, f := range c.deviceCache.flights {
			n += f.participants
		}
		c.deviceCache.mu.Unlock()
		if n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("participants=%d want=%d", n, want)
		}
		runtime.Gosched()
	}
}

func TestSenderKeyDeviceNegativeCoalescing(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	c, inner := newDevicePolicyStore(t, 4, func(ctx context.Context, _, _ string) ([]string, error) {
		close(entered)
		select {
		case <-release:
			return []string{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	var wg sync.WaitGroup
	results := make(chan error, 50)
	launch := func(ctx context.Context) {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := c.GetSenderKeyDevices(ctx, "g", "user_1"); results <- err }()
	}
	launch(context.Background())
	<-entered
	cancelCtx, cancel := context.WithCancel(context.Background())
	launch(cancelCtx)
	for range 48 {
		launch(context.Background())
	}
	awaitDeviceParticipants(t, c, 50)
	cancel()
	if err := <-results; !errors.Is(err, context.Canceled) {
		t.Fatalf("follower cancel: %v", err)
	}
	close(release)
	wg.Wait()
	for range 49 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if inner.calls.Load() != 1 || len(c.deviceCache.flights) != 0 {
		t.Fatal("coalescing or cleanup failed")
	}
}

func TestSenderKeyDeviceNegativeWriteFence(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var reads atomic.Int64
	c, inner := newDevicePolicyStore(t, 4, func(context.Context, string, string) ([]string, error) {
		if reads.Add(1) == 1 {
			close(entered)
			<-release
			return []string{}, nil
		}
		return []string{"user_1:0"}, nil
	})
	result := make(chan []string, 1)
	go func() { got, _ := c.GetSenderKeyDevices(context.Background(), "g", "user_1"); result <- got }()
	<-entered
	if err := c.PutSenderKey(context.Background(), "g", "user_1:7", []byte("usable")); err != nil {
		t.Fatal(err)
	}
	got, err := c.GetSenderKeyDevices(context.Background(), "g", "user_1")
	if err != nil || !containsString(got, "user_1:7") || !containsString(got, "user_1:0") {
		t.Fatalf("pin hidden while query blocked: %v %v", got, err)
	}
	close(release)
	if got := <-result; !containsString(got, "user_1:7") {
		t.Fatalf("late completion hid pin: %v", got)
	}
	if entry, ok := c.deviceCache.Peek(c.deviceKey("g", "user_1")); ok && len(entry.devices) == 0 {
		t.Fatal("late absence published")
	}
	for range 2 {
		got, err := c.GetSenderKeyDevices(context.Background(), "g", "user_1")
		if err != nil || len(got) != 2 {
			t.Fatalf("incomplete entry hid a device after stale scan: %v, %v", got, err)
		}
	}
	if inner.calls.Load() != 3 {
		t.Fatalf("expected old scan, bounded bypass, then one complete scan: %d", inner.calls.Load())
	}
}

func TestSenderKeyDeviceCacheCapacity(t *testing.T) {
	c, inner := newDevicePolicyStore(t, 2, func(_ context.Context, group, sender string) ([]string, error) {
		if group == "positive" {
			return []string{sender + ":0"}, nil
		}
		return []string{}, nil
	})
	ctx := context.Background()
	_, _ = c.GetSenderKeyDevices(ctx, "negative", "user_1")
	_, _ = c.GetSenderKeyDevices(ctx, "positive", "user_1")
	_, _ = c.GetSenderKeyDevices(ctx, "churn", "user_1")
	if c.deviceCache.Len() != 2 {
		t.Fatal("positive and empty must compete at cap")
	}
	_, _ = c.GetSenderKeyDevices(ctx, "negative", "user_1")
	if inner.calls.Load() != 4 {
		t.Fatal("evicted absence must query")
	}
	for i := range 1000 {
		_, _ = c.GetSenderKeyDevices(ctx, fmt.Sprintf("churn-%d", i), "user_1")
		if c.deviceCache.Len() > 2 || len(c.deviceCache.flights) != 0 {
			t.Fatal("state exceeded cap or retained completed flight")
		}
	}
	t.Run("overflow", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		c, inner := newDevicePolicyStore(t, 1, func(_ context.Context, group, _ string) ([]string, error) {
			if group == "blocked" {
				close(entered)
				<-release
			}
			return []string{}, nil
		})
		done := make(chan struct{})
		go func() { _, _ = c.GetSenderKeyDevices(ctx, "blocked", "user_1"); close(done) }()
		<-entered
		for range 2 {
			_, _ = c.GetSenderKeyDevices(ctx, "overflow", "user_1")
		}
		c.deviceCache.mu.Lock()
		if len(c.deviceCache.flights) != 1 || c.deviceCache.Len() != 0 {
			t.Fatal("overflow allocated or cached absence")
		}
		c.deviceCache.mu.Unlock()
		close(release)
		<-done
		if inner.calls.Load() != 3 || len(c.deviceCache.flights) != 0 {
			t.Fatal("overflow query or cleanup failed")
		}
	})
}

// ---------------------------------------------------------------------------
// GetSenderKey: miss → inner; second call → cache hit.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_GetSenderKey_MissCallsInnerAndCaches(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedSenderKeyStore(t, 16)
	if err := inner.PutSenderKey(ctx, "group-A", "user-1", []byte("sk-A1")); err != nil {
		t.Fatalf("seed inner.PutSenderKey: %v", err)
	}
	inner.putCalls.Store(0)

	v1, err := c.GetSenderKey(ctx, "group-A", "user-1")
	if err != nil {
		t.Fatalf("first GetSenderKey: %v", err)
	}
	if !bytes.Equal(v1, []byte("sk-A1")) {
		t.Fatalf("first GetSenderKey got %q, want %q", v1, "sk-A1")
	}
	v2, err := c.GetSenderKey(ctx, "group-A", "user-1")
	if err != nil {
		t.Fatalf("second GetSenderKey: %v", err)
	}
	if !bytes.Equal(v2, []byte("sk-A1")) {
		t.Fatalf("second GetSenderKey got %q, want %q", v2, "sk-A1")
	}
	if got := inner.getCalls.Load(); got != 1 {
		t.Errorf("inner.getCalls = %d, want 1 (second call must hit cache)", got)
	}
}

// ---------------------------------------------------------------------------
// GetSenderKey: inner returns (nil, nil) for missing key — must NOT cache nil.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_GetSenderKey_NilFromInnerNotCached(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedSenderKeyStore(t, 16)

	v1, err := c.GetSenderKey(ctx, "ghost-group", "ghost-user")
	if err != nil {
		t.Fatalf("first GetSenderKey: %v", err)
	}
	if v1 != nil {
		t.Fatalf("first GetSenderKey got %q, want nil", v1)
	}
	v2, err := c.GetSenderKey(ctx, "ghost-group", "ghost-user")
	if err != nil {
		t.Fatalf("second GetSenderKey: %v", err)
	}
	if v2 != nil {
		t.Fatalf("second GetSenderKey got %q, want nil", v2)
	}
	if got := inner.getCalls.Load(); got != 2 {
		t.Errorf("inner.getCalls = %d, want 2 (nil result must not be cached)", got)
	}
}

// ---------------------------------------------------------------------------
// PutSenderKey: writes through AND populates cache so next Get hits cache.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_PutSenderKey_WritesThroughAndCaches(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedSenderKeyStore(t, 16)

	if err := c.PutSenderKey(ctx, "group-B", "user-2", []byte("sk-B2")); err != nil {
		t.Fatalf("PutSenderKey: %v", err)
	}
	if got := inner.putCalls.Load(); got != 1 {
		t.Errorf("inner.putCalls = %d, want 1 (write-through)", got)
	}
	v, err := c.GetSenderKey(ctx, "group-B", "user-2")
	if err != nil {
		t.Fatalf("GetSenderKey after Put: %v", err)
	}
	if !bytes.Equal(v, []byte("sk-B2")) {
		t.Fatalf("GetSenderKey after Put got %q, want %q", v, "sk-B2")
	}
	if got := inner.getCalls.Load(); got != 0 {
		t.Errorf("inner.getCalls = %d, want 0 (Put should seed cache so Get hits)", got)
	}
}

// ---------------------------------------------------------------------------
// Three-element composite key isolates entries: (g1,u1), (g1,u2), (g2,u1)
// must occupy 3 distinct cache slots.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_DifferentGroupOrUserAreSeparateEntries(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCachedSenderKeyStore(t, 16)

	if err := c.PutSenderKey(ctx, "g1", "u1", []byte("v-g1u1")); err != nil {
		t.Fatalf("Put g1/u1: %v", err)
	}
	if err := c.PutSenderKey(ctx, "g1", "u2", []byte("v-g1u2")); err != nil {
		t.Fatalf("Put g1/u2: %v", err)
	}
	if err := c.PutSenderKey(ctx, "g2", "u1", []byte("v-g2u1")); err != nil {
		t.Fatalf("Put g2/u1: %v", err)
	}
	if got := c.cache.Len(); got != 3 {
		t.Fatalf("cache Len = %d, want 3 (three-element key isolates entries)", got)
	}
	// Each entry retains its value (composite key avoids collisions).
	for _, tc := range []struct {
		group, user, want string
	}{
		{"g1", "u1", "v-g1u1"},
		{"g1", "u2", "v-g1u2"},
		{"g2", "u1", "v-g2u1"},
	} {
		got, err := c.GetSenderKey(ctx, tc.group, tc.user)
		if err != nil {
			t.Fatalf("GetSenderKey %s/%s: %v", tc.group, tc.user, err)
		}
		if !bytes.Equal(got, []byte(tc.want)) {
			t.Errorf("GetSenderKey %s/%s = %q, want %q", tc.group, tc.user, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Eviction at cap: cap=4, 5 distinct keys → Len()==4, first-inserted evicted.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_EvictionAtCap(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedSenderKeyStore(t, 4)
	for i := 0; i < 5; i++ {
		group := fmt.Sprintf("g-%d", i)
		if err := c.PutSenderKey(ctx, group, "u", []byte(fmt.Sprintf("v-%d", i))); err != nil {
			t.Fatalf("PutSenderKey %s: %v", group, err)
		}
	}
	if got := c.cache.Len(); got != 4 {
		t.Errorf("cache Len after 5 Puts = %d, want 4 (cap)", got)
	}
	// g-0 should be evicted; next Get for (g-0, u) must hit inner.
	inner.getCalls.Store(0)
	if _, err := c.GetSenderKey(ctx, "g-0", "u"); err != nil {
		t.Fatalf("GetSenderKey g-0/u: %v", err)
	}
	if got := inner.getCalls.Load(); got != 1 {
		t.Errorf("inner.getCalls for evicted g-0 = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// GetSenderKeyDevices (kavtov-fork Phase 27): cache-served device-set index.
// Cold call reaches inner once and caches; warm call is served from the
// device-set cache (inner not called again). A ratchet write-back (Put of an
// already-known device) must NOT invalidate; a genuinely new device's SKDM
// MUST be returned without re-querying inner (add-on-write: appended to LRU +
// pinned overlay, D-01 decision).
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_GetSenderKeyDevices_CacheServedAndInvalidatedOnNewDevice(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedSenderKeyStore(t, 16)

	if err := inner.PutSenderKey(ctx, "group-X", "99user_1:0", []byte("sk-0")); err != nil {
		t.Fatalf("seed inner key :0: %v", err)
	}
	if err := inner.PutSenderKey(ctx, "group-X", "99user_1:5", []byte("sk-5")); err != nil {
		t.Fatalf("seed inner key :5: %v", err)
	}
	inner.devicesCalls.Store(0)

	// (1) Cold call → inner once, result has both devices, cached.
	devices, err := c.GetSenderKeyDevices(ctx, "group-X", "99user_1")
	if err != nil {
		t.Fatalf("GetSenderKeyDevices (cold): %v", err)
	}
	if got := inner.devicesCalls.Load(); got != 1 {
		t.Errorf("inner.devicesCalls after cold = %d, want 1", got)
	}
	if len(devices) != 2 {
		t.Errorf("cold returned %d devices, want 2; got %v", len(devices), devices)
	}

	// (2) Warm call → served from cache; inner NOT called again.
	if _, err := c.GetSenderKeyDevices(ctx, "group-X", "99user_1"); err != nil {
		t.Fatalf("GetSenderKeyDevices (warm): %v", err)
	}
	if got := inner.devicesCalls.Load(); got != 1 {
		t.Errorf("inner.devicesCalls after warm = %d, want 1 (served from cache)", got)
	}

	// (3) Ratchet write-back (Put of an already-known device) must NOT invalidate.
	if err := c.PutSenderKey(ctx, "group-X", "99user_1:0", []byte("sk-0b")); err != nil {
		t.Fatalf("Put existing device: %v", err)
	}
	if _, err := c.GetSenderKeyDevices(ctx, "group-X", "99user_1"); err != nil {
		t.Fatalf("GetSenderKeyDevices after write-back: %v", err)
	}
	if got := inner.devicesCalls.Load(); got != 1 {
		t.Errorf("inner.devicesCalls after write-back = %d, want 1 (write-back must not invalidate)", got)
	}

	// (4) New device's SKDM → add-on-write (D-01): device is appended directly
	// to the LRU entry + pinned overlay; inner is NOT re-queried.
	// GetSenderKeyDevices must return all 3 devices without an extra inner call.
	if err := c.PutSenderKey(ctx, "group-X", "99user_1:7", []byte("sk-7")); err != nil {
		t.Fatalf("Put new device: %v", err)
	}
	devices3, err := c.GetSenderKeyDevices(ctx, "group-X", "99user_1")
	if err != nil {
		t.Fatalf("GetSenderKeyDevices after new-device Put: %v", err)
	}
	// Under add-on-write the new device is appended to the LRU (no invalidate),
	// so inner is not re-queried — devicesCalls stays at 1.
	if got := inner.devicesCalls.Load(); got != 1 {
		t.Errorf("inner.devicesCalls after new-device Put = %d, want 1 (add-on-write, no re-query)", got)
	}
	if len(devices3) != 3 {
		t.Errorf("after new device returned %d devices, want 3; got %v", len(devices3), devices3)
	}
}

// ---------------------------------------------------------------------------
// Race test: N=50 goroutines, mixed Get/Put on overlapping keys.
// Must run clean under `go test -race` and must not deadlock.
// ---------------------------------------------------------------------------

func TestCachedSenderKeyStore_Race_50Goroutines(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCachedSenderKeyStore(t, 64)

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
				group := fmt.Sprintf("group-%d", (g+i)%10)
				user := fmt.Sprintf("user-%d", (g+i)%7)
				switch i % 2 {
				case 0:
					_, _ = c.GetSenderKey(ctx, group, user)
				case 1:
					_ = c.PutSenderKey(ctx, group, user, []byte(fmt.Sprintf("v-%d-%d", g, i)))
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

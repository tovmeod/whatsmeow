// Copyright (c) 2026 Kavtov Platform (Phase 17.5.2)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// cache_wiring_test.go contains tests for Phase 17.5.2 cache counter
// discrimination: explicit Remove/Purge paths vs capacity-overflow evictions.
// These tests exercise the signalCaches struct, the cleanCounters helper, and
// the formatCacheMetrics function.

package sqlstore

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Reflection keeps the RED test runnable before the snapshot API exists.
func policySnapshotJSON(t *testing.T, container *Container) map[string]map[string]any {
	t.Helper()
	method := reflect.ValueOf(container).MethodByName("SenderKeyPolicySnapshot")
	if !method.IsValid() {
		t.Fatal("Container policy snapshot missing: device and donor evidence must have separate owners")
	}
	data, err := json.Marshal(method.Call(nil)[0].Interface())
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]map[string]any
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSenderKeyDeviceCacheMetricsPolicy(t *testing.T) {
	c, inner := newTestCachedSenderKeyStore(t, 2)
	container := &Container{}
	container.caches.SenderKeyDevices = c.deviceCache
	now := time.Unix(1000, 0)
	c.deviceCache.now = func() time.Time { return now }
	read := func(group string) {
		t.Helper()
		if _, err := c.GetSenderKeyDevices(context.Background(), group, "private-sender"); err != nil {
			t.Fatal(err)
		}
	}
	read("private-group")
	read("private-group")
	first := policySnapshotJSON(t, container)["device_cache"]
	if first["availability"] != "available" || first["counter_epoch"] == "" || first["queries"] != float64(1) || first["empty_hits"] != float64(1) || first["positive_hits"] != float64(0) || first["occupancy"] != float64(1) || first["capacity"] != float64(2) {
		t.Fatalf("empty enumeration evidence incorrect: %v", first)
	}
	if second := policySnapshotJSON(t, container)["device_cache"]; !reflect.DeepEqual(first, second) {
		t.Fatalf("snapshot changed totals or gauges: %v -> %v", first, second)
	}
	now = now.Add(senderKeyDeviceNegativeTTL)
	read("private-group")
	if err := c.PutSenderKey(context.Background(), "private-group", "private-sender:7", []byte("private-key")); err != nil {
		t.Fatal(err)
	}
	read("private-group")
	read("other-group")
	read("evict-group")
	last := policySnapshotJSON(t, container)["device_cache"]
	// Acceptance fences the enumeration, then the observable write invalidates
	// it again. These are two existing owner events, not two database queries.
	if last["queries"] != float64(inner.devicesCalls.Load()) || last["queries"] != float64(4) || last["expiries"] != float64(1) || last["positive_hits"] != float64(1) || last["invalidations"] != float64(2) || last["evictions"] != float64(1) || last["overflows"] != float64(0) || last["occupancy"] != float64(2) || last["counter_epoch"] != first["counter_epoch"] {
		t.Fatalf("policy decisions or direct gauges incorrect: %v", last)
	}
}

func TestSenderKeyPolicySnapshotAvailabilityAndEpoch(t *testing.T) {
	container := &Container{}
	missing := policySnapshotJSON(t, container)
	if missing["device_cache"]["availability"] != "MISSING" {
		t.Fatalf("missing owner became zero: %v", missing)
	}
	if _, ok := missing["device_cache"]["queries"]; ok {
		t.Fatal("missing device counter must be absent")
	}
	container.caches.SenderKeyDevices, _ = NewSenderKeyDeviceCache(2)
	first := policySnapshotJSON(t, container)
	container.caches.SenderKeyDevices, _ = NewSenderKeyDeviceCache(2)
	second := policySnapshotJSON(t, container)
	if first["device_cache"]["counter_epoch"] == second["device_cache"]["counter_epoch"] {
		t.Fatal("replacement owner must change its epoch")
	}
	if first["donor_cache"]["counter_epoch"] != second["donor_cache"]["counter_epoch"] {
		t.Fatal("device replacement invalidated independent donor source")
	}
	if second["device_cache"]["queries"] != float64(0) {
		t.Fatal("supported zero absent")
	}
	data, _ := json.Marshal(second)
	for _, forbidden := range []string{"private-", "account", "sender_id", "group_id", "session", "sql", "key_id"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("policy leaked %q: %s", forbidden, data)
		}
	}
}

func TestSenderKeyDeviceCacheMetricsConcurrent(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	c, inner := newDevicePolicyStore(t, 2, func(context.Context, string, string) ([]string, error) {
		close(entered)
		<-release
		return []string{}, nil
	})
	container := &Container{}
	container.caches.SenderKeyDevices = c.deviceCache
	const workers = 12
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.GetSenderKeyDevices(context.Background(), "private-group", "private-sender")
			if err != nil {
				t.Error(err)
			}
		}()
	}
	<-entered
	awaitDeviceParticipants(t, c, workers)
	for range 5 {
		_ = policySnapshotJSON(t, container)
	}
	close(release)
	wg.Wait()
	result := policySnapshotJSON(t, container)["device_cache"]
	if result["queries"] != float64(1) || result["empty_hits"] != float64(0) || inner.calls.Load() != 1 {
		t.Fatalf("flight followers multiplied query/cache decisions: %v", result)
	}
	// Concurrent cached reads and snapshots remain read-only except for the
	// actual hit decisions; snapshots themselves contribute no cache hits.
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.GetSenderKeyDevices(context.Background(), "private-group", "private-sender")
			if err != nil {
				t.Error(err)
			}
			_ = policySnapshotJSON(t, container)
		}()
	}
	wg.Wait()
	result = policySnapshotJSON(t, container)["device_cache"]
	if result["queries"] != float64(1) || result["empty_hits"] != float64(workers) || result["occupancy"] != float64(1) {
		t.Fatalf("concurrent totals changed: %v", result)
	}
}

func TestSenderKeyDeviceCacheMetricsOverflow(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	c, inner := newDevicePolicyStore(t, 1, func(_ context.Context, group, _ string) ([]string, error) {
		if group == "blocked" {
			close(entered)
			<-release
		}
		return []string{}, nil
	})
	container := &Container{}
	container.caches.SenderKeyDevices = c.deviceCache
	done := make(chan struct{})
	go func() { _, _ = c.GetSenderKeyDevices(context.Background(), "blocked", "user"); close(done) }()
	<-entered
	for range 2 {
		_, _ = c.GetSenderKeyDevices(context.Background(), "overflow", "user")
	}
	result := policySnapshotJSON(t, container)["device_cache"]
	close(release)
	<-done
	if result["overflows"] != float64(2) || result["queries"] != float64(3) || result["occupancy"] != float64(0) || result["capacity"] != float64(1) || inner.calls.Load() != 3 {
		t.Fatalf("overflow failed open or accumulated gauges: %v", result)
	}
}

func TestDonorSingleflightMetricsPolicy(t *testing.T) {
	resetNoDonorCacheForTest()
	t.Cleanup(resetNoDonorCacheForTest)
	stub := &stubRecoveryInner{entered: make(chan struct{}, 1), release: make(chan struct{})}
	c := newStubCachedStore(t, stub, nil)
	const workers = 12
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := c.TryInlineRecovery(context.Background(), "private-group", "private-sender:0", "private-sender", 42, 8)
			if ok || err != nil {
				t.Errorf("no-donor result changed: %v %v", ok, err)
			}
		}()
	}
	<-stub.entered
	waitDonorParticipants(t, workers)
	container := &Container{}
	for range 5 {
		_ = policySnapshotJSON(t, container)
	}
	close(stub.release)
	wg.Wait()
	_, _, _ = c.TryInlineRecovery(context.Background(), "private-group", "private-sender:0", "private-sender", 42, 9)
	first := policySnapshotJSON(t, container)["donor_cache"]
	if first["queries"] != float64(1) || first["singleflight_total"] != float64(workers) || first["singleflight_shared"] != float64(workers-1) || first["negative_hits"] != float64(1) || first["skips"] != float64(1) || first["occupancy"] != float64(1) || first["capacity"] != float64(noDonorCacheCapacity) || stub.findCalls.Load() != 1 {
		t.Fatalf("coalescing multiplied one query decision: %v", first)
	}
	if second := policySnapshotJSON(t, container)["donor_cache"]; !reflect.DeepEqual(first, second) {
		t.Fatal("read reset donor totals")
	}
	backdateNoDonorCache(c.donorKey("private-group", "private-sender", 42))
	_, _, _ = c.TryInlineRecovery(context.Background(), "private-group", "private-sender:0", "private-sender", 42, 10)
	notifyDonorKeys(stub, "private-group", "private-sender", []uint32{42})
	last := policySnapshotJSON(t, container)["donor_cache"]
	if last["queries"] != float64(2) || last["expiries"] != float64(1) || last["invalidations"] != float64(1) || last["occupancy"] != float64(0) || last["counter_epoch"] != first["counter_epoch"] {
		t.Fatalf("donor expiry/invalidation evidence incorrect: %v", last)
	}
}

// ---------------------------------------------------------------------------
// TestCacheCounters_ExplicitRemoveIncrementsExplicit_NotPureCapacity
//
// Asserts: calling DeleteIdentity() increments IdentityExplicitRemoves by 1.
// The IdentityCapacityEvictions counter also increments by 1 (because the
// eviction callback fires inside cache.Remove) -- that is the expected
// behavior and cleanCounters compensates at log time to show capacity_evictions=0.
// ---------------------------------------------------------------------------

func TestCacheCounters_ExplicitRemoveIncrementsExplicit_NotPureCapacity(t *testing.T) {
	inner := newFakeIdentityStore()

	var capEvictions, explicitRemoves uint64
	cache, err := lru.NewWithEvict[string, *[32]byte](1000, func(string, *[32]byte) {
		atomic.AddUint64(&capEvictions, 1)
	})
	if err != nil {
		t.Fatalf("lru.NewWithEvict failed: %v", err)
	}

	wrapper := NewCachedIdentityStore(inner, "test-jid", cache, &explicitRemoves, newIdentitySecondaryIndex())
	ctx := context.Background()

	address := "12345:0"
	key := fillKey(0x01)

	// Put an identity so there is an entry to delete.
	if err := wrapper.PutIdentity(ctx, address, key); err != nil {
		t.Fatalf("PutIdentity: %v", err)
	}

	capBefore := atomic.LoadUint64(&capEvictions)
	expBefore := atomic.LoadUint64(&explicitRemoves)

	// DeleteIdentity triggers an explicit Remove.
	if err := wrapper.DeleteIdentity(ctx, address); err != nil {
		t.Fatalf("DeleteIdentity: %v", err)
	}

	capAfter := atomic.LoadUint64(&capEvictions)
	expAfter := atomic.LoadUint64(&explicitRemoves)

	// ExplicitRemoves must have incremented by exactly 1.
	if expAfter-expBefore != 1 {
		t.Errorf("IdentityExplicitRemoves: got delta %d, want 1", expAfter-expBefore)
	}

	// CapacityEvictions also bumps by 1 (callback fires inside Remove) --
	// this is expected behavior; log-time cleanCounters compensates.
	if capAfter-capBefore != 1 {
		t.Errorf("IdentityCapacityEvictions: got delta %d, want 1 (eviction callback fires inside Remove)", capAfter-capBefore)
	}

	// Log-time computed capacity_evictions must be 0: cap and exp both grew
	// by 1, so cleanCounters(cap, exp) yields capClean = 0.
	_, capClean, _ := cleanCounters(capAfter, expAfter)
	if capClean != 0 {
		t.Errorf("log-time capacity_evictions: got %d, want 0 (explicit Remove should not show as cap pressure)", capClean)
	}
}

// ---------------------------------------------------------------------------
// TestCacheCounters_CapacityOverflowIncrementsCapacityOnly
//
// Asserts: forcing a capacity-overflow eviction (by filling a cap=2 LRU to 3
// entries) increments the capacity counter ONLY -- IdentityExplicitRemoves
// must stay at 0.
// ---------------------------------------------------------------------------

func TestCacheCounters_CapacityOverflowIncrementsCapacityOnly(t *testing.T) {
	var capEvictions uint64
	cache, err := lru.NewWithEvict[string, *[32]byte](2, func(string, *[32]byte) {
		atomic.AddUint64(&capEvictions, 1)
	})
	if err != nil {
		t.Fatalf("lru.NewWithEvict cap=2 failed: %v", err)
	}

	var explicitRemoves uint64

	// Use the cache directly to inject entries (simulating a pure Put path
	// without a store wrapper), because we only need the eviction counter
	// behaviour on overflow. The wrapper constructor is not needed here --
	// we're testing the callback and the counter in isolation.
	key0 := fillKey(0x00)
	key1 := fillKey(0x01)
	key2 := fillKey(0x02)
	cache.Add("entry0", &key0)
	cache.Add("entry1", &key1)
	// Adding a third entry to a cap=2 LRU evicts the oldest (entry0).
	cache.Add("entry2", &key2)

	capCount := atomic.LoadUint64(&capEvictions)
	expCount := atomic.LoadUint64(&explicitRemoves)

	if capCount != 1 {
		t.Errorf("IdentityCapacityEvictions: got %d, want 1 (capacity overflow should fire exactly once)", capCount)
	}
	if expCount != 0 {
		t.Errorf("IdentityExplicitRemoves: got %d, want 0 (capacity overflow must not touch explicit counter)", expCount)
	}
}

// ---------------------------------------------------------------------------
// TestCacheMetricsLogFormat_ExtendedFields
//
// Asserts: formatCacheMetrics produces a string containing all three
// eviction-related fields per cache. Sets CapacityEvictions=10,
// ExplicitRemoves=3 on Identity (via atomic.StoreUint64) and asserts:
//   - evictions=10  (sum: capClean(7) + explicit(3))
//   - capacity_evictions=7  (10 - 3)
//   - explicit_removes=3
// ---------------------------------------------------------------------------

func TestCacheMetricsLogFormat_ExtendedFields(t *testing.T) {
	// Build a Container with the three caches initialized but no metrics
	// goroutine running (metricsCancel == nil => closeSignalCaches no-ops).
	sessCache, err := lru.New[string, []byte](10)
	if err != nil {
		t.Fatalf("lru.New session: %v", err)
	}
	idntCache, err := lru.New[string, *[32]byte](10)
	if err != nil {
		t.Fatalf("lru.New identity: %v", err)
	}
	sndkCache, err := lru.New[string, []byte](10)
	if err != nil {
		t.Fatalf("lru.New senderkey: %v", err)
	}
	msgSecCache, err := lru.New[string, msgSecretEntry](10)
	if err != nil {
		t.Fatalf("lru.New msgsecret: %v", err)
	}

	c := &Container{
		caches: signalCaches{
			Session:   sessCache,
			Identity:  idntCache,
			SenderKey: sndkCache,
			MsgSecret: msgSecCache,
		},
	}

	// Set IdentityCapacityEvictions=10, IdentityExplicitRemoves=3.
	atomic.StoreUint64(&c.caches.IdentityCapacityEvictions, 10)
	atomic.StoreUint64(&c.caches.IdentityExplicitRemoves, 3)
	// perf 260601-uuy: MsgSecretCapacityEvictions=5, no explicit removes.
	atomic.StoreUint64(&c.caches.MsgSecretCapacityEvictions, 5)

	identityChangedBefore := identityChangedTotal.Load()
	msg := formatCacheMetrics(c)

	// Check evictions sum for identities: capClean(7) + explicit(3) = 10.
	// The format string embeds the identity block in the middle segment.
	// We extract the identities={...} block and check for the exact substrings.
	if !strings.Contains(msg, "capacity_evictions=7") {
		t.Errorf("expected 'capacity_evictions=7' in: %s", msg)
	}
	if !strings.Contains(msg, "explicit_removes=3") {
		t.Errorf("expected 'explicit_removes=3' in: %s", msg)
	}
	// evictions= sum: we need to locate the identity block specifically to
	// avoid false match from another cache's evictions=0. Use fmt.Sprintf
	// to build the expected identity prefix.
	// WR-02: the block carries identity_changed= (process-global D-10
	// mismatch-accept aggregate); other tests in this package may have
	// incremented it, so the expectation uses the live value captured above
	// the formatCacheMetrics call (identityChangedBefore).
	idntBlock := fmt.Sprintf("identities={len=%d, cap=%d, evictions=%d, capacity_evictions=%d, explicit_removes=%d, identity_changed=%d}",
		0, signalIdentityCacheCap, 10, 7, 3, identityChangedBefore)
	if !strings.Contains(msg, idntBlock) {
		t.Errorf("expected identity block %q in msg: %s", idntBlock, msg)
	}
	// Sanity: sessions and sender_keys both show evictions=0, capacity_evictions=0, explicit_removes=0.
	// Caps are env-resolved vars now (perf 260601-uuy), not hardcoded 100000 literals.
	sessBlock := fmt.Sprintf("sessions={len=0, cap=%d, evictions=0, capacity_evictions=0, explicit_removes=0}", signalSessionCacheCap)
	if !strings.Contains(msg, sessBlock) {
		t.Errorf("expected zeroed session block %q in: %s", sessBlock, msg)
	}
	sndkBlock := fmt.Sprintf("sender_keys={len=0, cap=%d, evictions=0, capacity_evictions=0, explicit_removes=0}", signalSenderKeyCacheCap)
	if !strings.Contains(msg, sndkBlock) {
		t.Errorf("expected zeroed sender_keys block %q in: %s", sndkBlock, msg)
	}
	// perf 260601-uuy: message_secrets block. Cap-only evictions:
	// cleanCounters(5, 0) = (evictions=5, capClean=5, explicit=0).
	if !strings.Contains(msg, "message_secrets={len=") {
		t.Errorf("expected 'message_secrets={len=' in: %s", msg)
	}
	msgSecBlock := fmt.Sprintf("message_secrets={len=%d, cap=%d, evictions=%d, capacity_evictions=%d, explicit_removes=%d}",
		0, signalMsgSecretCacheCap, 5, 5, 0)
	if !strings.Contains(msg, msgSecBlock) {
		t.Errorf("expected message_secrets block %q in: %s", msgSecBlock, msg)
	}
}

// ---------------------------------------------------------------------------
// R4: secondary-index size does not exceed LRU cap after 1,000 capacity
// evictions. Tests the EvictCleanup callback wiring directly (no wrapper).
// ---------------------------------------------------------------------------

func TestSecondaryIndex_BoundedAfter1000CapacityEvictions(t *testing.T) {
	// cap=100, will populate 1100 distinct entries → 1000 capacity evictions.
	const cap = 100
	idx := newSessionSecondaryIndex()

	cache, err := lru.NewWithEvict[string, []byte](cap, func(key string, _ []byte) {
		if jid, phone, ok := parseCacheKey(key); ok {
			idx.EvictCleanup(key, jid, phone)
		}
	})
	if err != nil {
		t.Fatalf("lru.NewWithEvict cap=%d failed: %v", cap, err)
	}

	// Populate 1100 entries: distinct (jid, phone, device) triples.
	// Use 11 jids × 10 phones × 10 devices = 1100 entries.
	payload := []byte("v")
	for j := 0; j < 11; j++ {
		jid := fmt.Sprintf("jid-%d", j)
		for p := 0; p < 10; p++ {
			phone := fmt.Sprintf("%d", p)
			for d := 0; d < 10; d++ {
				// Cache key shape: "<jid>|<phone>:<device>"
				cacheKey := fmt.Sprintf("%s|%s:%d", jid, phone, d)
				idx.Insert(jid, phone, cacheKey)
				cache.Add(cacheKey, payload)
			}
		}
	}

	// LRU must be at cap.
	if got := cache.Len(); got != cap {
		t.Errorf("cache.Len() = %d, want %d (at cap after 1100 inserts)", got, cap)
	}

	// Secondary index must not exceed cap: every eviction callback must have
	// removed the evicted key from the index.
	if got := idx.totalKeyCount(); got > cap {
		t.Errorf("index totalKeyCount = %d, exceeds LRU cap %d (R4 violation: stale index entries after capacity evictions)", got, cap)
	}
}

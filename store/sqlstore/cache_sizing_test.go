// Copyright (c) 2026 Kavtov Platform (Phase 35.1 plan 01)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/types"
)

// TestCacheMemoryBudget measures ground-truth per-entry object count and heap
// bytes for all five signal caches, then asserts the total warmed budget at
// proposed caps stays under GOMEMLIMIT with >= 30% headroom.
//
// Phase 38.4 update: SKParsed cache removed (parsed-struct cache deleted);
// fill sizes updated to pprof-measured per-entry values (2026-06-17 pprof):
//   - SenderKey []byte: ~3686 bytes/entry (1537 MB / 432k entries)
//   - Session   []byte: ~3380 bytes/entry (270 MB / 81k entries)
//
// Caps. NOTE: the deployed wiring cap (cache_wiring.go) is 500,000 — the 400k
// reduction below is a VALIDATED PROPOSAL (D-4) pending explicit approval, not
// the live default. This test asserts the *proposed* 400k cap meets the 30%
// headroom target; it does not gate the deployed 500k config.
//
//	SenderKey[] = 400,000 entries  (proposed; down from the deployed 500k — recovers headroom once approved)
//	Session[]   = 100,000 entries
//	Identity    = 150,000 entries
//	SKDevices   = 300,000 entries
//	MsgSecret   = 300,000 entries
//
// Budget assertion: headroom = 1 - (totalBudgetMB + baseRSSMB) / goMemLimitMB >= 0.30
// Expected post-change arithmetic (CONTEXT D-4):
//
//	flat 400k×3.6KB=1440 + session 100k×3.3KB=330 + identity 26 + SKDevices 62 + MsgSecret 84 = ~1942 MB
//	headroom = 1 - (1942+228)/3200 = 0.322 (32.2% >= 30% OK)
func TestCacheMemoryBudget(t *testing.T) {
	const N = 10_000

	// Per-entry fill sizes calibrated to reproduce the pprof-measured per-entry heap
	// cost when the LRU measureHeapDelta function runs.
	//
	// pprof heap profile (2026-06-17 13:09, driver 2026.06.57):
	//   - PutSenderKeyStructure: 1537 MB across ~432k cached entries → ~3558 B/entry (raw pprof)
	//   - Session cache: 270 MB across ~81k cached entries → ~3501 B/entry (raw pprof)
	//
	// The measureHeapDelta function adds LRU node overhead (~582 B/entry for sender-key,
	// ~296 B/entry for session) on top of the payload fill bytes. To reproduce the pprof
	// per-entry total, the fill size = pprof_measured - overhead:
	//   - sender-key: 3558 - 582 ≈ 2976 B fill → measures ~3558 B total (matches pprof)
	//   - session:    3501 - 296 ≈ 3205 B fill → measures ~3501 B total (matches pprof)
	//
	// These are used only by this test for budget accounting. The deployed wiring
	// cap in cache_wiring.go is 500_000; the 400_000 below is the proposed cap
	// this test validates against the 30% headroom target (pending approval).
	const (
		// skBytesPerEntry is the fill size producing pprof-equivalent measured overhead.
		skBytesPerEntry = 2_976
		// sessionBytesPerEntry is the fill size producing pprof-equivalent measured overhead.
		sessionBytesPerEntry = 3_205
	)

	// Proposed cap constants — hard-coded in cache_wiring.go.
	const (
		capSKBytes   = 400_000 // PROPOSED cap (D-4, pending approval); deployed wiring is 500k
		capSession   = 100_000
		capIdentity  = 100_000 // quick 260619-10v: lowered 150k -> 100k (GC entry-count cut)
		capSKDevices = 300_000
		capMsgSecret = 30_000 // quick 260619-10v: lowered 300k -> 30k (mostly-dead-weight cache)
		baseRSSMB    = 228.0  // base RSS (non-cache) from incident pprof + pgtype strings
		goMemLimitMB = 3200.0
	)

	var (
		perBytesSKBytes   float64
		perBytesSession   float64
		perBytesIdentity  float64
		perBytesSKDevices float64
		perBytesMsgSecret float64
	)

	// Helper: measure HeapInuse delta for N cache fills.
	// Returns (perObjects, perBytes) per entry.
	measureHeapDelta := func(fill func(i int)) (float64, float64) {
		runtime.GC()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := 0; i < N; i++ {
			fill(i)
		}
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&after)
		deltaObjects := int64(after.HeapObjects) - int64(before.HeapObjects)
		deltaInuse := int64(after.HeapInuse) - int64(before.HeapInuse)
		perObj := float64(deltaObjects) / float64(N)
		perBytes := float64(deltaInuse) / float64(N)
		return perObj, perBytes
	}

	// ---- 1. SenderKey []byte ---------------------------------------------------
	skBytesLRU, err := lru.New[string, []byte](N + 100)
	if err != nil {
		t.Fatalf("lru.New skBytes: %v", err)
	}
	perObjSKBytes, perBytesSKBytes := measureHeapDelta(func(i int) {
		key := fmt.Sprintf("sk%d|grp%d|usr:0", i, i)
		skBytesLRU.Add(key, make([]byte, skBytesPerEntry))
	})
	t.Logf("SenderKeyBytes: per-entry %.2f objects, %.0f bytes (cap=%d → %.0f MB)",
		perObjSKBytes, perBytesSKBytes, capSKBytes,
		float64(capSKBytes)*perBytesSKBytes/(1024*1024))
	runtime.KeepAlive(skBytesLRU)

	// ---- 3. Session []byte -----------------------------------------------------
	sessLRU, err := lru.New[string, []byte](N + 100)
	if err != nil {
		t.Fatalf("lru.New session: %v", err)
	}
	perObjSession, perBytesSession := measureHeapDelta(func(i int) {
		sessLRU.Add(fmt.Sprintf("sess%d", i), make([]byte, sessionBytesPerEntry))
	})
	t.Logf("Session      : per-entry %.2f objects, %.0f bytes (cap=%d → %.0f MB)",
		perObjSession, perBytesSession, capSession,
		float64(capSession)*perBytesSession/(1024*1024))
	runtime.KeepAlive(sessLRU)

	// ---- 4. Identity *[32]byte -------------------------------------------------
	idLRU, err := lru.New[string, *[32]byte](N + 100)
	if err != nil {
		t.Fatalf("lru.New identity: %v", err)
	}
	perObjIdentity, perBytesIdentity := measureHeapDelta(func(i int) {
		v := [32]byte{}
		idLRU.Add(fmt.Sprintf("id%d", i), &v)
	})
	t.Logf("Identity     : per-entry %.2f objects, %.0f bytes (cap=%d → %.0f MB)",
		perObjIdentity, perBytesIdentity, capIdentity,
		float64(capIdentity)*perBytesIdentity/(1024*1024))
	runtime.KeepAlive(idLRU)

	// ---- 5. Actual shared typed positive/empty device owner -------------------
	skDevLRU, err := NewSenderKeyDeviceCache(N + 100)
	if err != nil {
		t.Fatalf("lru.New skDevices: %v", err)
	}
	perObjSKDevices, perBytesSKDevices := measureHeapDelta(func(i int) {
		skDevLRU.Add(deviceQueryKey{universe: skDevLRU, account: fmt.Sprintf("skd%d", i), group: fmt.Sprintf("grp%d", i), sender: fmt.Sprintf("user%d_1", i)}, deviceCacheEntry{devices: []string{"dev1:0", "dev2:0"}})
	})
	t.Logf("SKDevices positive-only observed N=%d heap_objects=%.0f heap_bytes=%.0f; linear extrapolation to %d=%.0f bytes (not a full-cap observation)",
		N, perObjSKDevices*N, perBytesSKDevices*N, capSKDevices, float64(capSKDevices)*perBytesSKDevices)
	runtime.KeepAlive(skDevLRU)
	coord, err := NewSenderKeyDeviceCache(N)
	if err != nil {
		t.Fatal(err)
	}
	coordObj, coordBytes := measureHeapDelta(func(i int) {
		coord.flights[deviceQueryKey{universe: coord, account: fmt.Sprintf("account%d", i), group: "group", sender: "sender"}] = &deviceQueryFlight{done: make(chan struct{}), participants: 1}
	})
	t.Logf("SKDevices active coordination observed N=%d heap_objects=%.0f heap_bytes=%.0f; linear extrapolation to 300000=%.0f bytes (not a full-cap observation)", N, coordObj*N, coordBytes*N, coordBytes*300000)
	if len(coord.flights) != N {
		t.Fatal("coordination fixture did not reach measured capacity")
	}
	clear(coord.flights)
	runtime.GC()
	runtime.KeepAlive(coord)
	for _, mode := range []string{"empty-only", "mixed"} {
		owner, err := NewSenderKeyDeviceCache(N)
		if err != nil {
			t.Fatal(err)
		}
		expiry := time.Now().Add(5 * time.Minute)
		obj, bytes := measureHeapDelta(func(i int) {
			entry := deviceCacheEntry{expiresAt: expiry}
			if mode == "mixed" && i%2 == 0 {
				entry = deviceCacheEntry{devices: []string{"dev1:0", "dev2:0"}}
			}
			owner.Add(deviceQueryKey{universe: owner, account: fmt.Sprintf("account%d", i), group: fmt.Sprintf("group%d", i), sender: fmt.Sprintf("user%d_1", i)}, entry)
		})
		t.Logf("SKDevices %s observed N=%d heap_objects=%.0f heap_bytes=%.0f; linear extrapolation to 300000=%.0f bytes (not a full-cap observation)", mode, N, obj*N, bytes*N, bytes*300000)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for i := range N * 3 {
			key := deviceQueryKey{universe: owner, account: fmt.Sprintf("churn%d", i), sender: "sender"}
			owner.Add(key, deviceCacheEntry{expiresAt: expiry})
			owner.mu.Lock()
			owner.flights[key] = &deviceQueryFlight{done: make(chan struct{}), participants: 1}
			delete(owner.flights, key)
			owner.mu.Unlock()
		}
		owner.Purge()
		runtime.GC()
		runtime.ReadMemStats(&after)
		t.Logf("SKDevices %s post-churn-GC observed retained_heap_bytes_delta=%d retained_objects_delta=%d resident_entries=%d active_flights=%d", mode, int64(after.HeapAlloc)-int64(before.HeapAlloc), int64(after.HeapObjects)-int64(before.HeapObjects), owner.Len(), len(owner.flights))
		if owner.Len() != 0 || len(owner.flights) != 0 {
			t.Fatal("device state not reclaimed")
		}
		if after.HeapObjects >= before.HeapObjects {
			t.Fatal("churn entries/flight objects remained reachable after purge/GC")
		}
		runtime.KeepAlive(owner)
	}

	// ---- 6. MsgSecret msgSecretEntry -------------------------------------------
	msLRU, err := lru.New[string, msgSecretEntry](N + 100)
	if err != nil {
		t.Fatalf("lru.New msgSecret: %v", err)
	}
	perObjMsgSecret, perBytesMsgSecret := measureHeapDelta(func(i int) {
		entry := msgSecretEntry{
			Secret: make([]byte, 32),
			RealSender: types.JID{
				User:   fmt.Sprintf("972500%06d", i),
				Server: "s.whatsapp.net",
			},
		}
		msLRU.Add(fmt.Sprintf("ms%d|chat%d|snd:0|id%d", i, i, i), entry)
	})
	t.Logf("MsgSecret    : per-entry %.2f objects, %.0f bytes (cap=%d → %.0f MB)",
		perObjMsgSecret, perBytesMsgSecret, capMsgSecret,
		float64(capMsgSecret)*perBytesMsgSecret/(1024*1024))
	runtime.KeepAlive(msLRU)

	// ---- Budget assertion ------------------------------------------------------
	// SKParsed term removed (Phase 38.4: parsed-struct cache deleted).
	// Expected: flat 400k×3.6KB=1440 + session 100k×3.3KB=330 + identity 17 +
	//           SKDevices 62 + MsgSecret 8 = ~1857 MB (≥30% headroom). quick
	//           260619-10v cut identity 150k->100k and MsgSecret 300k->30k.
	totalBudgetMB :=
		float64(capSKBytes)*perBytesSKBytes/(1024*1024) +
			float64(capSession)*perBytesSession/(1024*1024) +
			float64(capIdentity)*perBytesIdentity/(1024*1024) +
			float64(capSKDevices)*perBytesSKDevices/(1024*1024) +
			float64(capMsgSecret)*perBytesMsgSecret/(1024*1024)

	headroom := 1.0 - (totalBudgetMB+baseRSSMB)/goMemLimitMB

	t.Logf("Budget summary: caches=%.0f MB, base=%.0f MB, total=%.0f MB, limit=%.0f MB, headroom=%.1f%%",
		totalBudgetMB, baseRSSMB, totalBudgetMB+baseRSSMB, goMemLimitMB, headroom*100)

	if headroom < 0.30 {
		t.Errorf("GC headroom %.1f%% < 30%% (total=%.0f MB, limit=%.0f MB) — proposed caps exceed budget",
			headroom*100, totalBudgetMB+baseRSSMB, goMemLimitMB)
	}

	// Keep all caches alive so GC does not collect them before the final
	// ReadMemStats observations above complete.
	runtime.KeepAlive(skBytesLRU)
	runtime.KeepAlive(sessLRU)
	runtime.KeepAlive(idLRU)
	runtime.KeepAlive(skDevLRU)
	runtime.KeepAlive(msLRU)
}

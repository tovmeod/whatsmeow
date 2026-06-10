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

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// TestCacheMemoryBudget measures ground-truth per-entry object count and heap
// bytes for all six signal caches, then asserts the total warmed budget at
// proposed caps stays under GOMEMLIMIT with >= 30% headroom.
//
// Proposed caps (to be hard-coded in Wave 2):
//
//	SKParsed    = 500,000 entries
//	SenderKey[] = 500,000 entries
//	Session[]   = 100,000 entries
//	Identity    = 150,000 entries
//	SKDevices   = 300,000 entries
//	MsgSecret   = 300,000 entries
//
// Budget assertion: headroom = 1 - (totalBudgetMB + baseRSSMB) / goMemLimitMB >= 0.30
func TestCacheMemoryBudget(t *testing.T) {
	const N = 10_000

	// Proposed cap constants — Wave 2 will hard-code these into cache_wiring.go.
	const (
		capSKParsed  = 500_000
		capSKBytes   = 500_000
		capSession   = 100_000
		capIdentity  = 150_000
		capSKDevices = 300_000
		capMsgSecret = 300_000
		baseRSSMB    = 228.0 // base RSS (non-cache) from incident pprof + pgtype strings
		goMemLimitMB = 3200.0
	)

	var (
		perBytesSKParsed  float64
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

	// ---- 1. SKParsed -----------------------------------------------------------
	skParsedLRU, err := store.NewSKParsedLRU(N + 100)
	if err != nil {
		t.Fatalf("NewSKParsedLRU: %v", err)
	}
	// Pre-compute one representative structure (reuse across all N fills to
	// keep allocation pressure on the LRU bookkeeping, not on fixture construction).
	skStructure := recompose(makeSKColumns(1, 0))
	if skStructure == nil {
		t.Fatal("recompose returned nil")
	}
	perObjSKParsed, perBytesSKParsed := measureHeapDelta(func(i int) {
		key := fmt.Sprintf("jid%d|grp%d|usr:0", i, i)
		store.AddFlatToLRU(skParsedLRU, key, skStructure)
	})
	t.Logf("SKParsed     : per-entry %.2f objects, %.0f bytes (cap=%d → %.0f MB)",
		perObjSKParsed, perBytesSKParsed, capSKParsed,
		float64(capSKParsed)*perBytesSKParsed/(1024*1024))
	runtime.KeepAlive(skParsedLRU)

	// ---- 2. SenderKey []byte ---------------------------------------------------
	skBytesLRU, err := lru.New[string, []byte](N + 100)
	if err != nil {
		t.Fatalf("lru.New skBytes: %v", err)
	}
	perObjSKBytes, perBytesSKBytes := measureHeapDelta(func(i int) {
		key := fmt.Sprintf("sk%d|grp%d|usr:0", i, i)
		skBytesLRU.Add(key, make([]byte, 720))
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
		sessLRU.Add(fmt.Sprintf("sess%d", i), make([]byte, 2620))
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

	// ---- 5. SenderKeyDevices []string ------------------------------------------
	skDevLRU, err := lru.New[string, []string](N + 100)
	if err != nil {
		t.Fatalf("lru.New skDevices: %v", err)
	}
	perObjSKDevices, perBytesSKDevices := measureHeapDelta(func(i int) {
		skDevLRU.Add(fmt.Sprintf("skd%d|grp%d", i, i), []string{"dev1:0", "dev2:0"})
	})
	t.Logf("SKDevices    : per-entry %.2f objects, %.0f bytes (cap=%d → %.0f MB)",
		perObjSKDevices, perBytesSKDevices, capSKDevices,
		float64(capSKDevices)*perBytesSKDevices/(1024*1024))
	runtime.KeepAlive(skDevLRU)

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
	totalBudgetMB :=
		float64(capSKParsed)*perBytesSKParsed/(1024*1024) +
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
	runtime.KeepAlive(skParsedLRU)
	runtime.KeepAlive(skBytesLRU)
	runtime.KeepAlive(sessLRU)
	runtime.KeepAlive(idLRU)
	runtime.KeepAlive(skDevLRU)
	runtime.KeepAlive(msLRU)
}

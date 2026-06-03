// Copyright (c) 2026 Kavtov Platform (Phase 17.9 plan 06)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// senderkey_bench_test.go — honest full-path columnar-vs-JSON benchmark.
//
// Audit finding (17.9-AUDIT-REPORT.md §7): the prior benchmark built the BYTEA[]
// DTO in-memory BEFORE b.ResetTimer(), timing only recompose. The array text-parse
// cost was entirely excluded while the JSON arm was fully timed. That made the
// "columns cheaper than JSON" claim rest on nothing.
//
// This benchmark fixes that: the COLUMNAR read arm starts the clock BEFORE any
// serialisation/deserialisation — Value() encodes the DTO to PG array text, Scan()
// decodes it back, then recompose() rebuilds the structure. The JSON arm deserialises
// the legacy blob. Both arms start from the same in-memory *senderKeyColumns fixture
// and end at an equivalent *SenderKeyStructure. Both arms stop at *SenderKeyStructure
// (no NewSenderKeyFromStruct on either side — matching the actual hot path).
//
// Arms:
//   A. BenchmarkSenderKeyRead_JSON_*         — JSON Deserialize (baseline)
//   B. BenchmarkSenderKeyRead_Columnar_*     — Value+Scan ALL columns + recompose (full path)
//   C. BenchmarkSenderKeyArrayParse_*        — Value+Scan only (isolated array-parse cost)
//   D. BenchmarkSenderKeyWrite_Decompose_*   — decompose(structure) (columnar write cost)
//   E. BenchmarkSenderKeyWrite_Serialize_*   — Serialize(structure) (JSON write cost baseline)
//   F. TestSenderKeyGCPreCheck               — local GC pre-check: fill ParsedSKCache-equivalent
//                                              LRU with N structures, measure HeapObjects per entry
//
// Fixtures: the 0-key case (common path) and the 32-key case (sender-key max per DESIGN).
// The JSON arm reuses buildSenderKeyBlob / pbSerializer from decode_once_bench_test.go
// (same package = no redefinition needed).
//
// Correctness guard: each benchmark includes a one-time reflect.DeepEqual assert
// (outside the timing loop) proving both arms yield the identical *SenderKeyStructure.
//
// Array text format note: byteaArray.Value() generates the canonical PG BYTEA[] text
// literal that a real DB would return on SELECT. Format parity is covered by
// bytea_array_test.go round-trip tests (parse ∘ encode = id). The bench measures
// the real codec cost; a live DB would add network/PG executor overhead on top.

package sqlstore

import (
	"reflect"
	"runtime"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
)

// ---------------------------------------------------------------------------
// Fixtures — built once at package init, shared across all benchmarks.
// ---------------------------------------------------------------------------

// makeSKColumns builds a *senderKeyColumns with nStates states and nSMK skipped
// message keys per state. Every []byte field is filled with realistic-length
// values so Value()/Scan() exercise real hex encoding at the actual wire size.
//
//   - stChainKey: 32 bytes
//   - stSigningKeyPublic: 33 bytes (Curve25519 compressed, 0x05 prefix)
//   - stSigningKeyPrivate: 32 bytes (nil for even-indexed states to exercise NULL round-trip)
//   - smk IV: 16 bytes, smk CipherKey/Seed: 32 bytes each
func makeSKColumns(nStates, nSMK int) *senderKeyColumns {
	key32 := func(seed byte) []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = seed + byte(i)
		}
		return b
	}
	pub33 := func(seed byte) []byte {
		b := make([]byte, 33)
		b[0] = 0x05
		for i := 1; i < 33; i++ {
			b[i] = seed + byte(i)
		}
		return b
	}
	iv16 := func(seed byte) []byte {
		b := make([]byte, 16)
		for i := range b {
			b[i] = seed + byte(i)
		}
		return b
	}

	cols := &senderKeyColumns{
		fmtVer:              2,
		stKeyID:             make([]int64, nStates),
		stChainKeyIteration: make([]int64, nStates),
		stChainKey:          make([][]byte, nStates),
		stSigningKeyPublic:  make([][]byte, nStates),
		stSigningKeyPrivate: make([][]byte, nStates),
	}
	for i := 0; i < nStates; i++ {
		cols.stKeyID[i] = int64(i + 1)
		cols.stChainKeyIteration[i] = int64(i * 100)
		cols.stChainKey[i] = key32(byte(i + 10))
		cols.stSigningKeyPublic[i] = pub33(byte(i + 20))
		// Odd states get a private key; even states are nil (received-key case — NULL element).
		if i%2 == 1 {
			cols.stSigningKeyPrivate[i] = key32(byte(i + 30))
		} else {
			cols.stSigningKeyPrivate[i] = nil
		}

		for j := 0; j < nSMK; j++ {
			seed := byte(i*nSMK + j)
			cols.smkStateIdx = append(cols.smkStateIdx, int32(i))
			cols.smkIteration = append(cols.smkIteration, int64(j))
			cols.smkIV = append(cols.smkIV, iv16(seed))
			cols.smkCipherKey = append(cols.smkCipherKey, key32(seed+1))
			cols.smkSeed = append(cols.smkSeed, key32(seed+2))
		}
	}
	return cols
}

// skCols0 and skCols32 are the two fixtures: 0-key common case, max-skipped case.
// 1 state each — the dominant prod shape (single active SenderKeyState).
var skCols0 = makeSKColumns(1, 0)
var skCols32 = makeSKColumns(1, 32)

// jsonBlob0 / jsonBlob32 are the corresponding legacy JSON blobs.
// Derived from the *SenderKeyStructure produced by recompose so both arms start from
// the same record (guaranteed by the reflect.DeepEqual guard in each benchmark).
var jsonBlob0 = func() []byte {
	s := recompose(skCols0)
	blob := pbSerializer.SenderKeyRecord.Serialize(s)
	if len(blob) == 0 {
		panic("senderkey_bench_test: jsonBlob0 setup failed")
	}
	return blob
}()

var jsonBlob32 = func() []byte {
	s := recompose(skCols32)
	blob := pbSerializer.SenderKeyRecord.Serialize(s)
	if len(blob) == 0 {
		panic("senderkey_bench_test: jsonBlob32 setup failed")
	}
	return blob
}()

// ---------------------------------------------------------------------------
// colsRoundTrip encodes and decodes ALL column arrays for a *senderKeyColumns,
// returning a fresh *senderKeyColumns indistinguishable from what the DB would
// send back. This is the FULL array-parse path that was missing from the prior
// benchmark.
//
// Column order mirrors recoveryScanQuery and getSenderKeyDecomposed:
//   st_key_id, st_chain_key_iteration, st_chain_key,
//   st_signing_key_public, st_signing_key_private,
//   smk_state_idx, smk_iteration, smk_iv, smk_cipher_key, smk_seed
// ---------------------------------------------------------------------------
func colsRoundTrip(in *senderKeyColumns) (*senderKeyColumns, error) {
	// --- encode (driver.Valuer: Go → PG text) ---
	keyIDVal, err := int64Array(in.stKeyID).Value()
	if err != nil {
		return nil, err
	}
	iterVal, err := int64Array(in.stChainKeyIteration).Value()
	if err != nil {
		return nil, err
	}
	chainKeyVal, err := byteaArray(in.stChainKey).Value()
	if err != nil {
		return nil, err
	}
	sigPubVal, err := byteaArray(in.stSigningKeyPublic).Value()
	if err != nil {
		return nil, err
	}
	sigPrivVal, err := byteaArray(in.stSigningKeyPrivate).Value()
	if err != nil {
		return nil, err
	}
	smkStateIdxVal, err := int32Array(in.smkStateIdx).Value()
	if err != nil {
		return nil, err
	}
	smkIterVal, err := int64Array(in.smkIteration).Value()
	if err != nil {
		return nil, err
	}
	smkIVVal, err := byteaArray(in.smkIV).Value()
	if err != nil {
		return nil, err
	}
	smkCipherKeyVal, err := byteaArray(in.smkCipherKey).Value()
	if err != nil {
		return nil, err
	}
	smkSeedVal, err := byteaArray(in.smkSeed).Value()
	if err != nil {
		return nil, err
	}

	// --- decode (sql.Scanner: PG text → Go) ---
	out := &senderKeyColumns{fmtVer: 2}
	if err := (*int64Array)(&out.stKeyID).Scan(keyIDVal); err != nil {
		return nil, err
	}
	if err := (*int64Array)(&out.stChainKeyIteration).Scan(iterVal); err != nil {
		return nil, err
	}
	if err := (*byteaArray)(&out.stChainKey).Scan(chainKeyVal); err != nil {
		return nil, err
	}
	if err := (*byteaArray)(&out.stSigningKeyPublic).Scan(sigPubVal); err != nil {
		return nil, err
	}
	if err := (*byteaArray)(&out.stSigningKeyPrivate).Scan(sigPrivVal); err != nil {
		return nil, err
	}
	if err := (*int32Array)(&out.smkStateIdx).Scan(smkStateIdxVal); err != nil {
		return nil, err
	}
	if err := (*int64Array)(&out.smkIteration).Scan(smkIterVal); err != nil {
		return nil, err
	}
	if err := (*byteaArray)(&out.smkIV).Scan(smkIVVal); err != nil {
		return nil, err
	}
	if err := (*byteaArray)(&out.smkCipherKey).Scan(smkCipherKeyVal); err != nil {
		return nil, err
	}
	if err := (*byteaArray)(&out.smkSeed).Scan(smkSeedVal); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Arm A — JSON read baseline (Deserialize the legacy blob → *SenderKeyStructure)
// ---------------------------------------------------------------------------

// BenchmarkSenderKeyRead_JSON_0Keys is the JSON baseline for the 0-key common case.
func BenchmarkSenderKeyRead_JSON_0Keys(b *testing.B) {
	// One-time correctness guard: both arms yield equivalent structures.
	jsonStruct, err := pbSerializer.SenderKeyRecord.Deserialize(jsonBlob0)
	if err != nil {
		b.Fatalf("setup: JSON Deserialize failed: %v", err)
	}
	colsStruct := recompose(skCols0)
	if !reflect.DeepEqual(jsonStruct, colsStruct) {
		b.Fatal("setup: JSON and columnar arms yield different structures for 0-key fixture")
	}

	blob := jsonBlob0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pbSerializer.SenderKeyRecord.Deserialize(blob)
		if err != nil {
			b.Fatalf("JSON Deserialize failed: %v", err)
		}
	}
}

// BenchmarkSenderKeyRead_JSON_MaxSkipped is the JSON baseline for 32 skipped keys.
func BenchmarkSenderKeyRead_JSON_MaxSkipped(b *testing.B) {
	jsonStruct, err := pbSerializer.SenderKeyRecord.Deserialize(jsonBlob32)
	if err != nil {
		b.Fatalf("setup: JSON Deserialize failed: %v", err)
	}
	colsStruct := recompose(skCols32)
	if !reflect.DeepEqual(jsonStruct, colsStruct) {
		b.Fatal("setup: JSON and columnar arms yield different structures for 32-key fixture")
	}

	blob := jsonBlob32
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pbSerializer.SenderKeyRecord.Deserialize(blob)
		if err != nil {
			b.Fatalf("JSON Deserialize failed: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Arm B — Columnar read: Value+Scan ALL columns + recompose (the full honest path)
// ---------------------------------------------------------------------------

// BenchmarkSenderKeyRead_Columnar_0Keys times the full columnar read for the
// 0-key common case: encode to PG array text (Value), decode back (Scan), recompose.
// The array encode+decode is INSIDE the timed loop — fixing the audit finding.
func BenchmarkSenderKeyRead_Columnar_0Keys(b *testing.B) {
	// One-time correctness guard: the round-trip yields the same structure as JSON.
	rtCols, err := colsRoundTrip(skCols0)
	if err != nil {
		b.Fatalf("setup: colsRoundTrip failed: %v", err)
	}
	rtStruct := recompose(rtCols)
	jsonStruct, err := pbSerializer.SenderKeyRecord.Deserialize(jsonBlob0)
	if err != nil {
		b.Fatalf("setup: JSON Deserialize failed: %v", err)
	}
	if !reflect.DeepEqual(rtStruct, jsonStruct) {
		b.Fatal("setup: columnar round-trip yields different structure from JSON arm")
	}

	cols := skCols0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Value() — encode to PG array text (Go → wire text format)
		// Scan() — decode PG array text back (wire text → Go)
		// recompose() — reconstruct the *SenderKeyStructure
		out, err := colsRoundTrip(cols)
		if err != nil {
			b.Fatalf("colsRoundTrip failed: %v", err)
		}
		_ = recompose(out)
	}
}

// BenchmarkSenderKeyRead_Columnar_MaxSkipped times the full columnar read for 32 skipped keys.
func BenchmarkSenderKeyRead_Columnar_MaxSkipped(b *testing.B) {
	rtCols, err := colsRoundTrip(skCols32)
	if err != nil {
		b.Fatalf("setup: colsRoundTrip failed: %v", err)
	}
	rtStruct := recompose(rtCols)
	jsonStruct, err := pbSerializer.SenderKeyRecord.Deserialize(jsonBlob32)
	if err != nil {
		b.Fatalf("setup: JSON Deserialize failed: %v", err)
	}
	if !reflect.DeepEqual(rtStruct, jsonStruct) {
		b.Fatal("setup: columnar round-trip yields different structure from JSON arm for 32-key fixture")
	}

	cols := skCols32
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := colsRoundTrip(cols)
		if err != nil {
			b.Fatalf("colsRoundTrip failed: %v", err)
		}
		_ = recompose(out)
	}
}

// ---------------------------------------------------------------------------
// Arm C — Isolated array-parse cost: Value+Scan only (no recompose)
//
// Isolates the BYTEA[] text encode+decode cost so it can be read separately
// from recompose. This answers "how much of Arm B is array I/O vs recompose?"
// ---------------------------------------------------------------------------

// BenchmarkSenderKeyArrayParse_0Keys times Value+Scan of all columns, no recompose.
func BenchmarkSenderKeyArrayParse_0Keys(b *testing.B) {
	cols := skCols0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := colsRoundTrip(cols)
		if err != nil {
			b.Fatalf("colsRoundTrip failed: %v", err)
		}
	}
}

// BenchmarkSenderKeyArrayParse_MaxSkipped times Value+Scan only for 32 skipped keys.
func BenchmarkSenderKeyArrayParse_MaxSkipped(b *testing.B) {
	cols := skCols32
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := colsRoundTrip(cols)
		if err != nil {
			b.Fatalf("colsRoundTrip failed: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Arm D — Write: columnar decompose cost (per-message write path)
//
// Times decompose(*SenderKeyStructure) → *senderKeyColumns.
// This is the per-message columnar write overhead (no DB I/O).
// ---------------------------------------------------------------------------

// BenchmarkSenderKeyWrite_Decompose_0Keys times decompose for 0 skipped keys.
func BenchmarkSenderKeyWrite_Decompose_0Keys(b *testing.B) {
	s := recompose(skCols0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = decompose(s)
	}
}

// BenchmarkSenderKeyWrite_Decompose_MaxSkipped times decompose for 32 skipped keys.
func BenchmarkSenderKeyWrite_Decompose_MaxSkipped(b *testing.B) {
	s := recompose(skCols32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = decompose(s)
	}
}

// ---------------------------------------------------------------------------
// Arm E — Write: JSON Serialize cost (legacy write-path baseline)
//
// Times pbSerializer.SenderKeyRecord.Serialize(*SenderKeyStructure) → []byte.
// This is the per-message JSON write overhead, comparable to Arm D.
// ---------------------------------------------------------------------------

// BenchmarkSenderKeyWrite_Serialize_0Keys times JSON Serialize for 0 skipped keys.
func BenchmarkSenderKeyWrite_Serialize_0Keys(b *testing.B) {
	s := recompose(skCols0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blob := pbSerializer.SenderKeyRecord.Serialize(s)
		if len(blob) == 0 {
			b.Fatal("Serialize returned empty")
		}
	}
}

// BenchmarkSenderKeyWrite_Serialize_MaxSkipped times JSON Serialize for 32 skipped keys.
func BenchmarkSenderKeyWrite_Serialize_MaxSkipped(b *testing.B) {
	s := recompose(skCols32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blob := pbSerializer.SenderKeyRecord.Serialize(s)
		if len(blob) == 0 {
			b.Fatal("Serialize returned empty")
		}
	}
}

// ---------------------------------------------------------------------------
// Arm F — Local GC pre-check (TestSenderKeyGCPreCheck)
//
// Fills an LRU cache (same type as device.ParsedSKCache) with N distinct
// *SenderKeyStructure values and measures HeapObjects + HeapInuse per entry
// at several fill levels. Reports whether the curve is flat (plateau) or rising.
//
// This is the LOCAL sanity check for the GC gate. The prod soak (gcBgMarkWorker
// sampling across a warmup window) is Task 3, human-gated. This test catches
// obvious regressions before prod.
//
// Sender-keys are ≤32 keys, 97% zero — NOT the 17.8 GC hazard (that was the
// up-to-2000-key session graph). The expectation is a plateau.
// ---------------------------------------------------------------------------

// TestSenderKeyGCPreCheck is NOT a benchmark; it's a test that fills the LRU
// and reports GC object counts. Run with -v to see the output.
func TestSenderKeyGCPreCheck(t *testing.T) {
	// Fill sizes to probe. After filling, GC × 2 and sample.
	fillLevels := []int{0, 100, 1000, 5000, 10000}

	cache, err := lru.New[string, *groupRecord.SenderKeyStructure](20000)
	if err != nil {
		t.Fatalf("lru.New: %v", err)
	}

	// Baseline: empty cache.
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	baseHeapObjects := ms.HeapObjects
	baseHeapInuse := ms.HeapInuse

	t.Logf("GC pre-check: baseline (empty cache): HeapObjects=%d HeapInuse=%d B",
		baseHeapObjects, baseHeapInuse)

	prevHeapObjects := baseHeapObjects
	prevN := 0

	for _, n := range fillLevels {
		if n == 0 {
			continue
		}
		// Add entries up to n (0-key structures — the dominant case).
		for i := prevN; i < n; i++ {
			key := make([]byte, 0, 32)
			// distinct key per entry to avoid LRU collisions
			key = append(key, byte(i), byte(i>>8), byte(i>>16))
			cacheKey := "jid|group|user:" + string(key)
			// 0-key structure (cheapest, most realistic)
			cols := makeSKColumns(1, 0)
			s := recompose(cols)
			cache.Add(cacheKey, s)
		}
		prevN = n

		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&ms)

		deltaObjects := int64(ms.HeapObjects) - int64(baseHeapObjects)
		perEntry := float64(deltaObjects) / float64(n)
		deltaFromPrev := int64(ms.HeapObjects) - int64(prevHeapObjects)

		t.Logf("GC pre-check: n=%5d entries | HeapObjects=%d (+%d from base, +%d from prev) | HeapInuse=%d B | per-entry=%.2f objects | trend=%s",
			n,
			ms.HeapObjects,
			deltaObjects,
			deltaFromPrev,
			ms.HeapInuse,
			perEntry,
			gcTrend(deltaFromPrev, n-prevN+n), // crude: positive = rising, ~0 = plateau
		)
		prevHeapObjects = ms.HeapObjects
	}

	// 32-key structures (max skipped keys) — probe at 1000 entries.
	cache32, err := lru.New[string, *groupRecord.SenderKeyStructure](2000)
	if err != nil {
		t.Fatalf("lru.New 32-key: %v", err)
	}
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	base32 := ms.HeapObjects

	for i := 0; i < 1000; i++ {
		cacheKey := "jid|group|user32:" + string([]byte{byte(i), byte(i >> 8)})
		cols := makeSKColumns(1, 32)
		s := recompose(cols)
		cache32.Add(cacheKey, s)
	}
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	delta32 := int64(ms.HeapObjects) - int64(base32)
	perEntry32 := float64(delta32) / float64(1000)
	t.Logf("GC pre-check: 32-key case: n=1000 | HeapObjects=%d (+%d from local base) | per-entry=%.2f objects",
		ms.HeapObjects, delta32, perEntry32)

	// Keep caches alive so GC doesn't collect them before ReadMemStats.
	runtime.KeepAlive(cache)
	runtime.KeepAlive(cache32)
}

// gcTrend returns a human label for the delta-from-prev vs fill-delta ratio.
// Crude heuristic: if delta-from-prev per new entry is < 3 objects, call it plateau.
func gcTrend(deltaFromPrev int64, newEntries int) string {
	if newEntries <= 0 {
		return "n/a"
	}
	perNew := float64(deltaFromPrev) / float64(newEntries)
	switch {
	case perNew < 0:
		return "dropping"
	case perNew < 3.0:
		return "plateau"
	case perNew < 10.0:
		return "rising-slow"
	default:
		return "rising-fast"
	}
}

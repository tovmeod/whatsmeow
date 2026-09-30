// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// sweep_test.go — Phase 17.13 Plan 06: TestSweeperGuard (REQ-SWEEPER-01)
//
// Validates the sweeper's WHERE get_byte(session,0)=123 guard logic in isolation,
// using an in-memory session map. No DB connection required.
//
// The guard is the correctness-critical piece of T-17.13-16: if the live driver
// has already converted a row to flat (byte[0]=0x01), the sweeper's UPDATE must
// find 0 rows (predicate false) and skip — never overwrite a ratchet-advanced
// flat row with an older flat encoding.
//
// Test plan (mirrors plan 17.13-06 Task 1 <behavior>):
//  1. Insert a flat-encoded session row (byte[0]=0x01) into the map.
//  2. SELECT predicate get_byte(session,0)=123 must return 0 rows for the flat row.
//  3. Insert a JSON-encoded session row (byte[0]=0x7B=123).
//  4. SELECT predicate must return 1 row (the JSON row).
//  5. Simulate guarded UPDATE for the JSON row: predicate=true, row is updated.
//  6. Simulate guarded UPDATE for the flat row: predicate=false, row is NOT updated.
//
// This test runs in package store alongside flat_session_test.go so it can reuse
// the unexported helper makeSessionStructure (defined there).

package store

import (
	"bytes"
	"testing"

	"go.mau.fi/libsignal/state/record"
)

// jsonDiscriminator is the byte that every JSON-encoded session starts with
// ('{' = 0x7B = 123). This is the value the sweeper's SQL predicate targets:
// WHERE get_byte(session, 0) = 123.
const jsonDiscriminator = byte(0x7B) // '{'

// byteZeroMatchesJSON models the SQL predicate: get_byte(session, 0) = 123.
// Returns true only when the blob starts with the JSON discriminator byte.
func byteZeroMatchesJSON(blob []byte) bool {
	return len(blob) > 0 && blob[0] == jsonDiscriminator
}

// simulateGuardedUpdate models the sweeper's guarded UPDATE:
//
//	UPDATE whatsmeow_sessions SET session=$flat
//	WHERE our_jid=$jid AND their_id=$id AND get_byte(session, 0) = 123
//
// Returns the number of rows affected (0 or 1), and applies the update to
// the provided sessions map when the guard predicate passes.
func simulateGuardedUpdate(sessions map[string][]byte, key string, newBlob []byte) (rowsAffected int) {
	current, ok := sessions[key]
	if !ok {
		return 0
	}
	if !byteZeroMatchesJSON(current) {
		// Guard triggered: row is already flat (or something else); skip.
		return 0
	}
	sessions[key] = newBlob
	return 1
}

// simulateBatchedGuardedUpdate models the sweeper's single multi-row UPDATE:
//
//	UPDATE whatsmeow_sessions AS w SET session = v.flat
//	FROM (VALUES ...) AS v(our_jid, their_id, flat)
//	WHERE w.our_jid=v.our_jid AND w.their_id=v.their_id AND get_byte(w.session,0)=123
//
// Every candidate row is independently guarded by the same get_byte predicate, so
// the batched form has identical safety to the per-row form: rows already flat are
// excluded from the join and left untouched. Returns the total rows actually updated.
func simulateBatchedGuardedUpdate(sessions map[string][]byte, updates map[string][]byte) (rowsAffected int) {
	for key, newBlob := range updates {
		current, ok := sessions[key]
		if !ok {
			continue // row no longer exists — not in the join result
		}
		if !byteZeroMatchesJSON(current) {
			continue // guard: already flat, excluded by WHERE get_byte=123
		}
		sessions[key] = newBlob
		rowsAffected++
	}
	return rowsAffected
}

// makeJSONBlob builds a JSON-encoded session blob from a SessionStructure
// using the standard SignalProtobufSerializer's session Serialize method.
// Stage 3: the StoreSession JSON fallback is removed; this helper is retained
// for TestSweeperGuard which validates the guard against legacy JSON blobs.
// SignalProtobufSerializer.Session is a JSONSessionSerializer; Serialize
// JSON-encodes the structure directly without requiring valid EC key bytes.
func makeJSONBlob(s *record.SessionStructure) []byte {
	return SignalProtobufSerializer.Session.Serialize(s)
}

// TestSweeperGuard validates the discriminator predicate logic that underpins
// the sweeper's safety: flat rows (byte[0]=0x01) are never matched or overwritten
// by a guarded UPDATE; JSON rows (byte[0]=0x7B) are matched and updated correctly.
func TestSweeperGuard(t *testing.T) {
	// Build a real flat-encoded session blob using PackFlatSession.
	// makeSessionStructure is defined in flat_session_test.go (same package).
	flatStruct := makeSessionStructure(0, 0, 0, false, false)
	flatBlob, ok := PackFlatSession(flatStruct)
	if !ok {
		t.Fatal("PackFlatSession refused a valid session structure — codec broken")
	}

	// Build a real JSON-encoded session blob via the JSONSessionSerializer.
	jsonBlob := makeJSONBlob(flatStruct)

	// Sanity-check the discriminator bytes before the guard tests.
	if len(flatBlob) == 0 {
		t.Fatal("PackFlatSession returned empty blob")
	}
	if flatBlob[0] != flatSessionMagic {
		t.Fatalf("flat blob byte[0] = 0x%02X, want flatSessionMagic 0x%02X", flatBlob[0], flatSessionMagic)
	}
	if flatBlob[0] == jsonDiscriminator {
		t.Fatalf("flat blob byte[0] = 0x7B — codec violates D-02 invariant (NEVER emit 0x7B at byte[0])")
	}

	if len(jsonBlob) == 0 {
		t.Fatal("Serialize returned empty JSON blob")
	}
	if jsonBlob[0] != jsonDiscriminator {
		t.Fatalf("JSON blob byte[0] = 0x%02X, want 0x%02X ('{')", jsonBlob[0], jsonDiscriminator)
	}

	// Step 1: flat row must NOT be matched by the predicate.
	if byteZeroMatchesJSON(flatBlob) {
		t.Errorf("predicate returned true for flat blob (byte[0]=0x%02X) — guard broken", flatBlob[0])
	}

	// Step 2: JSON row must be matched by the predicate.
	if !byteZeroMatchesJSON(jsonBlob) {
		t.Errorf("predicate returned false for JSON blob (byte[0]=0x%02X) — guard broken", jsonBlob[0])
	}

	// Set up an in-memory session map modelling the whatsmeow_sessions table.
	const flatKey = "flat-jid|flat-id"
	const jsonKey = "json-jid|json-id"
	sessions := map[string][]byte{
		flatKey: flatBlob,
		jsonKey: jsonBlob,
	}
	originalFlatBlob := append([]byte(nil), flatBlob...) // snapshot for change-detection

	// Step 3: SELECT simulation — collect rows where predicate is true.
	var selectedKeys []string
	for k, v := range sessions {
		if byteZeroMatchesJSON(v) {
			selectedKeys = append(selectedKeys, k)
		}
	}
	if len(selectedKeys) != 1 || selectedKeys[0] != jsonKey {
		t.Errorf("SELECT returned %v, want exactly [%q]", selectedKeys, jsonKey)
	}

	// Step 4: guarded UPDATE on the JSON row — must succeed (rowsAffected=1).
	newFlat, ok2 := PackFlatSession(flatStruct)
	if !ok2 {
		t.Fatal("PackFlatSession refused for update blob")
	}
	affected := simulateGuardedUpdate(sessions, jsonKey, newFlat)
	if affected != 1 {
		t.Errorf("guarded UPDATE for JSON row: rowsAffected=%d, want 1", affected)
	}
	// The JSON row must now hold the flat blob (byte[0]=0x01).
	if sessions[jsonKey][0] != flatSessionMagic {
		t.Errorf("after guarded UPDATE, sessions[jsonKey][0]=0x%02X, want 0x%02X (flat magic)",
			sessions[jsonKey][0], flatSessionMagic)
	}

	// Step 5: guarded UPDATE on the flat row — must be a NO-OP (rowsAffected=0).
	// Use a distinctly different blob (different bytes) to make any accidental
	// overwrite detectable.
	differentBlob := make([]byte, len(originalFlatBlob))
	copy(differentBlob, originalFlatBlob)
	differentBlob[len(differentBlob)-1] ^= 0xFF // flip last byte

	affected = simulateGuardedUpdate(sessions, flatKey, differentBlob)
	if affected != 0 {
		t.Errorf("guarded UPDATE for flat row: rowsAffected=%d, want 0 (guard must prevent overwrite)", affected)
	}
	// The flat row must be unchanged.
	if !bytes.Equal(sessions[flatKey], originalFlatBlob) {
		t.Error("flat row was modified despite guard — predicate-based protection failed")
	}

	// Step 6: BATCHED guarded UPDATE — the sweeper applies one multi-row UPDATE per
	// batch (UPDATE ... FROM (VALUES ...) WHERE get_byte=123). A batch mixing an
	// already-flat row and a JSON row must convert ONLY the JSON row and leave the
	// flat row byte-identical; rowsAffected must be exactly 1.
	jsonToFlat, okB := PackFlatSession(flatStruct)
	if !okB {
		t.Fatal("PackFlatSession refused for batched-update blob")
	}
	batchSessions := map[string][]byte{
		flatKey: append([]byte(nil), originalFlatBlob...),
		jsonKey: makeJSONBlob(flatStruct),
	}
	batchUpdates := map[string][]byte{
		flatKey: differentBlob, // would corrupt the flat row if the guard failed
		jsonKey: jsonToFlat,    // legitimate JSON→flat conversion
	}
	batchAffected := simulateBatchedGuardedUpdate(batchSessions, batchUpdates)
	if batchAffected != 1 {
		t.Errorf("batched guarded UPDATE: rowsAffected=%d, want 1 (only the JSON row converts)", batchAffected)
	}
	if !bytes.Equal(batchSessions[flatKey], originalFlatBlob) {
		t.Error("batched UPDATE modified the already-flat row despite the per-row guard")
	}
	if batchSessions[jsonKey][0] != flatSessionMagic {
		t.Errorf("batched UPDATE: JSON row not converted (byte[0]=0x%02X, want flat magic 0x%02X)",
			batchSessions[jsonKey][0], flatSessionMagic)
	}

	// D-02 invariant check: PackFlatSession MUST NOT emit 0x7B at byte[0] for any
	// valid input. This is load-bearing for the guard: the sweeper's UPDATE predicate
	// relies on the flat codec never producing a blob that the predicate treats as JSON.
	anotherStruct := makeSessionStructure(1, 2, 5, true, false)
	anotherFlat, ok3 := PackFlatSession(anotherStruct)
	if !ok3 {
		t.Fatal("PackFlatSession refused a non-trivial valid structure")
	}
	if len(anotherFlat) > 0 && anotherFlat[0] == jsonDiscriminator {
		t.Errorf("D-02 violation: PackFlatSession emitted 0x7B at byte[0] — sweeper guard would break")
	}
}

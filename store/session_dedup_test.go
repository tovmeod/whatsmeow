// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"testing"

	"go.mau.fi/libsignal/state/record"
)

// distinctStateHashes returns the set of state fingerprints across current +
// previous states — used to prove dedup loses nothing unique.
func distinctStateHashes(t *testing.T, s *record.SessionStructure) map[string]struct{} {
	t.Helper()
	set := map[string]struct{}{}
	all := append([]*record.StateStructure{s.SessionState}, s.PreviousStates...)
	for _, st := range all {
		h, ok := stateHash(st)
		if !ok {
			t.Fatalf("stateHash failed")
		}
		set[h] = struct{}{}
	}
	return set
}

func TestDedupSessionStates(t *testing.T) {
	// makeStateStructure with identical args produces byte-identical states.
	cur := makeStateStructure(0x01, false, 2, 10, true, 2, false)
	a := makeStateStructure(0x10, false, 1, 5, false, 0, false)
	b := makeStateStructure(0x20, true, 2, 8, false, 0, false)
	aDup := makeStateStructure(0x10, false, 1, 5, false, 0, false)   // identical to a
	curDup := makeStateStructure(0x01, false, 2, 10, true, 2, false) // identical to current

	s := &record.SessionStructure{
		SessionState:   cur,
		PreviousStates: []*record.StateStructure{a, b, aDup, curDup},
	}
	wantDistinct := distinctStateHashes(t, s) // {cur, a, b}

	deduped, dropped, ok := DedupSessionStates(s)
	if !ok {
		t.Fatal("DedupSessionStates returned ok=false")
	}
	if dropped != 2 {
		t.Fatalf("dropped=%d, want 2 (aDup + curDup)", dropped)
	}
	if len(deduped.PreviousStates) != 2 {
		t.Fatalf("kept %d previous states, want 2 (a, b)", len(deduped.PreviousStates))
	}
	// current state untouched (same pointer)
	if deduped.SessionState != cur {
		t.Fatal("current SessionState was replaced")
	}
	// order preserved: a then b
	if ha, _ := stateHash(deduped.PreviousStates[0]); ha != mustHash(t, a) {
		t.Error("first retained state is not a (order not preserved)")
	}
	if hb, _ := stateHash(deduped.PreviousStates[1]); hb != mustHash(t, b) {
		t.Error("second retained state is not b (order not preserved)")
	}
	// LOSSLESS: deduped distinct set == original distinct set
	gotDistinct := distinctStateHashes(t, deduped)
	if len(gotDistinct) != len(wantDistinct) {
		t.Fatalf("deduped distinct states=%d, want %d", len(gotDistinct), len(wantDistinct))
	}
	for h := range wantDistinct {
		if _, present := gotDistinct[h]; !present {
			t.Fatal("a distinct state was lost by dedup (NOT lossless)")
		}
	}
	// deduped session must still pack/unpack cleanly
	blob, packOK := PackFlatSession(deduped)
	if !packOK {
		t.Fatal("deduped session failed to PackFlatSession")
	}
	if _, err := UnpackFlatSession(blob); err != nil {
		t.Fatalf("deduped session failed to UnpackFlatSession: %v", err)
	}
}

func TestDedupSessionStatesNoDuplicates(t *testing.T) {
	s := &record.SessionStructure{
		SessionState: makeStateStructure(0x01, false, 2, 10, false, 0, false),
		PreviousStates: []*record.StateStructure{
			makeStateStructure(0x10, false, 1, 5, false, 0, false),
			makeStateStructure(0x20, true, 2, 8, false, 0, false),
		},
	}
	_, dropped, ok := DedupSessionStates(s)
	if !ok {
		t.Fatal("ok=false")
	}
	if dropped != 0 {
		t.Fatalf("dropped=%d, want 0 (all unique)", dropped)
	}
}

func TestDedupSessionStatesEmptyPrev(t *testing.T) {
	s := &record.SessionStructure{
		SessionState:   makeStateStructure(0x01, false, 1, 0, false, 0, false),
		PreviousStates: nil,
	}
	_, dropped, ok := DedupSessionStates(s)
	if !ok || dropped != 0 {
		t.Fatalf("ok=%v dropped=%d, want ok=true dropped=0", ok, dropped)
	}
}

func mustHash(t *testing.T, st *record.StateStructure) string {
	t.Helper()
	h, ok := stateHash(st)
	if !ok {
		t.Fatal("mustHash: stateHash failed")
	}
	return h
}

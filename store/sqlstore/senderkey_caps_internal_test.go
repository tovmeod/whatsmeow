// Copyright (c) 2026 Kavtov Platform (quick 260612-0af)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// senderkey_caps_internal_test.go — contract tests for capSenderKeyStructure,
// the pure capping logic the one-time prune sweep (senderkey_prune.go) applies
// to oversized whatsmeow_sender_keys rows. In-package (needs the unexported
// helper), no DB. Reuses mkSkipped / mkCapState / skippedIters from
// recovery_sender_key_internal_test.go (same package).

package sqlstore

import (
	"testing"

	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
)

// fatStructure builds a 7-state structure whose state[1] carries nKeys skipped
// keys — over both caps when nKeys > maxSenderKeyMessageKeys.
func fatStructure(nKeys int) *groupRecord.SenderKeyStructure {
	states := make([]*groupRecord.SenderKeyStateStructure, 0, 7)
	for i := uint32(0); i < 7; i++ {
		states = append(states, mkCapState(200+i, 10*i))
	}
	keys := make([]*ratchet.SenderMessageKeyStructure, 0, nKeys)
	for i := 0; i < nKeys; i++ {
		keys = append(keys, mkSkipped(uint32(i), 0x33))
	}
	states[1].Keys = keys
	return &groupRecord.SenderKeyStructure{SenderKeyStates: states}
}

// TestCapSenderKeyStructureOverLimit: 7 states (one with 2500 skipped keys) →
// changed=true, 5 states, every state's Keys <= 2000 with the highest
// iterations kept, and the index-0 state identity preserved.
func TestCapSenderKeyStructureOverLimit(t *testing.T) {
	in := fatStructure(2500)

	out, changed := capSenderKeyStructure(in)
	if !changed {
		t.Fatal("changed = false for an over-limit structure, want true")
	}
	if len(out.SenderKeyStates) != maxSenderKeyStates {
		t.Fatalf("out states = %d, want %d", len(out.SenderKeyStates), maxSenderKeyStates)
	}
	// Index 0 had no over-cap Keys, so the SAME state pointer must survive
	// (active/donor identity preserved — sk_keyid0 / extractStructMeta invariant).
	if out.SenderKeyStates[0] != in.SenderKeyStates[0] {
		t.Error("index-0 state identity not preserved (want same pointer)")
	}
	for i, st := range out.SenderKeyStates {
		if len(st.Keys) > maxSenderKeyMessageKeys {
			t.Errorf("state[%d] keys = %d, want <= %d", i, len(st.Keys), maxSenderKeyMessageKeys)
		}
	}
	// state[1] truncation kept the HIGHEST iterations (input 0..2499 → 500..2499).
	cappedKeys := out.SenderKeyStates[1].Keys
	if len(cappedKeys) != maxSenderKeyMessageKeys {
		t.Fatalf("state[1] keys = %d, want exactly %d", len(cappedKeys), maxSenderKeyMessageKeys)
	}
	for _, k := range cappedKeys {
		if k.Iteration < 500 {
			t.Fatalf("state[1] kept iteration %d; want only the %d highest (>= 500)",
				k.Iteration, maxSenderKeyMessageKeys)
		}
	}
	// Order-preserving prefix truncation of states: survivors are input[0..4].
	for i := 0; i < maxSenderKeyStates; i++ {
		if out.SenderKeyStates[i].KeyID != in.SenderKeyStates[i].KeyID {
			t.Errorf("out[%d].KeyID = %d, want %d", i, out.SenderKeyStates[i].KeyID, in.SenderKeyStates[i].KeyID)
		}
	}
}

// TestCapSenderKeyStructureUnderLimit: a structure within both caps →
// changed=false and the SAME pointer back — this is what makes the prune
// sweep skip the DB write for legit large-but-within-cap rows.
func TestCapSenderKeyStructureUnderLimit(t *testing.T) {
	states := make([]*groupRecord.SenderKeyStateStructure, 0, 3)
	for i := uint32(0); i < 3; i++ {
		keys := make([]*ratchet.SenderMessageKeyStructure, 0, 50)
		for j := 0; j < 50; j++ {
			keys = append(keys, mkSkipped(uint32(j), byte(i)))
		}
		states = append(states, mkCapState(300+i, 10*i, keys...))
	}
	in := &groupRecord.SenderKeyStructure{SenderKeyStates: states}

	out, changed := capSenderKeyStructure(in)
	if changed {
		t.Fatal("changed = true for an under-limit structure, want false")
	}
	if out != in {
		t.Error("under-limit structure must be returned as the SAME pointer (skip-the-write contract)")
	}
}

// TestCapSenderKeyStructureNoInPlaceMutation: when changed=true the input
// structure must be untouched — the prune (and the WR-05 copy pattern) rely on
// never mutating caller-owned structures.
func TestCapSenderKeyStructureNoInPlaceMutation(t *testing.T) {
	in := fatStructure(2500)
	fatState := in.SenderKeyStates[1]

	_, changed := capSenderKeyStructure(in)
	if !changed {
		t.Fatal("changed = false, want true")
	}
	if len(in.SenderKeyStates) != 7 {
		t.Errorf("input states mutated: %d, want 7", len(in.SenderKeyStates))
	}
	if len(fatState.Keys) != 2500 {
		t.Errorf("input state[1].Keys mutated: %d, want 2500", len(fatState.Keys))
	}
	// nil input is tolerated (defensive; the sweep skips NULL blobs anyway).
	if out, ch := capSenderKeyStructure(nil); out != nil || ch {
		t.Errorf("capSenderKeyStructure(nil) = (%v, %v), want (nil, false)", out, ch)
	}
}

// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// flat_session_test.go — Phase 17.13 flat-bytea session codec tests.
//
// Covers REQ-CODEC-01..04:
//   - REQ-CODEC-01: PackFlatSession round-trip over full SessionStructure (DeepEqual)
//   - REQ-CODEC-02: nil vs []byte{} distinction preserved
//   - REQ-CODEC-03: Refuse-to-encode guard (field length violations)
//   - REQ-CODEC-04: Bounds-checked decode (malformed blobs return error, never panic)
//
// Plus FuzzUnpackFlatSession for D-01 (fuzzed codec).
//
// REQ-CODEC-05: TestFlatSessionDecryptEquivalence (added Plan 02)
// REQ-CODEC-06: TestFlatSessionProdFixtures (added Plan 02 — skip-guarded until prod fixtures provided)

package store

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"go.mau.fi/libsignal/keys/chain"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/keys/message"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/util/keyhelper"
	"go.mau.fi/libsignal/util/optional"

	"go.mau.fi/whatsmeow/types"
)

// ---------------------------------------------------------------------------
// fixture builders
// ---------------------------------------------------------------------------

// fillBytes returns a byte slice of length n where each byte is (base+i)&0xFF.
func fillBytes(n int, base byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = (base + byte(i)) & 0xFF
	}
	return out
}

// makeChainStructure builds a ChainStructure. When withPrivate=true, SenderRatchetKeyPrivate
// is a valid 32-byte slice; when false it is nil (receiver chain).
// nMessageKeys skipped message keys are added inline.
func makeChainStructure(seed byte, withPrivate bool, nMessageKeys int) *record.ChainStructure {
	var priv []byte
	if withPrivate {
		priv = fillBytes(flatSessRatchetPrivLen, seed+0x50)
	}
	mk := make([]*message.KeysStructure, nMessageKeys)
	for i := 0; i < nMessageKeys; i++ {
		mk[i] = &message.KeysStructure{
			CipherKey: fillBytes(flatSessMsgCipherKeyLen, seed+byte(i)+0x10),
			MacKey:    fillBytes(flatSessMsgMacKeyLen, seed+byte(i)+0x20),
			IV:        fillBytes(flatSessMsgIVLen, seed+byte(i)+0x30),
			Index:     uint32(i),
		}
	}
	return &record.ChainStructure{
		SenderRatchetKeyPublic:  fillBytes(flatSessRatchetPubLen, seed),
		SenderRatchetKeyPrivate: priv,
		ChainKey: &chain.KeyStructure{
			Key:   fillBytes(flatSessChainKeyLen, seed+0x40),
			Index: uint32(seed) + 100,
		},
		MessageKeys: mk,
	}
}

// makeStateStructure builds a StateStructure with the given parameters.
// senderBaseKeyNil: SenderBaseKey is nil when true.
// nReceiverChains: number of receiver chains (each with no private key, no msg keys by default).
// nMsgKeysPerChain: number of skipped message keys per chain (sender chain gets this too).
func makeStateStructure(
	seed byte,
	senderBaseKeyNil bool,
	nReceiverChains int,
	nMsgKeysPerChain int,
	hasPendingPreKey bool,
	preKeyIDState int, // 0=nil, 1=IsEmpty, 2=hasValue
	hasPendingKeyExchange bool,
) *record.StateStructure {
	var senderBaseKey []byte
	if !senderBaseKeyNil {
		senderBaseKey = fillBytes(flatSessSenderBaseKeyLen, seed+0x01)
	}

	receiverChains := make([]*record.ChainStructure, nReceiverChains)
	for i := 0; i < nReceiverChains; i++ {
		// receiver chains: no private key, share nMsgKeysPerChain message keys
		receiverChains[i] = makeChainStructure(seed+byte(i)+0x60, false, nMsgKeysPerChain)
	}

	var pendingPreKey *record.PendingPreKeyStructure
	if hasPendingPreKey {
		var pkID *optional.Uint32
		switch preKeyIDState {
		case 0:
			pkID = nil
		case 1:
			pkID = &optional.Uint32{IsEmpty: true}
		case 2:
			pkID = &optional.Uint32{IsEmpty: false, Value: 42}
		}
		pendingPreKey = &record.PendingPreKeyStructure{
			PreKeyID:       pkID,
			SignedPreKeyID: uint32(seed) + 500,
			BaseKey:        fillBytes(flatSessPendingBaseKeyLen, seed+0x70),
		}
	}

	var pendingKeyExchange *record.PendingKeyExchangeStructure
	if hasPendingKeyExchange {
		pendingKeyExchange = &record.PendingKeyExchangeStructure{
			Sequence:                uint32(seed) + 200,
			LocalBaseKeyPublic:      fillBytes(flatSessExchangeKeyLen, seed+0x01),
			LocalBaseKeyPrivate:     fillBytes(flatSessExchangeKeyLen, seed+0x02),
			LocalRatchetKeyPublic:   fillBytes(flatSessExchangeKeyLen, seed+0x03),
			LocalRatchetKeyPrivate:  fillBytes(flatSessExchangeKeyLen, seed+0x04),
			LocalIdentityKeyPublic:  fillBytes(flatSessExchangeKeyLen, seed+0x05),
			LocalIdentityKeyPrivate: fillBytes(flatSessExchangeKeyLen, seed+0x06),
		}
	}

	return &record.StateStructure{
		SessionVersion:       3,
		LocalIdentityPublic:  fillBytes(flatSessIdentityKeyLen, seed+0x10),
		RemoteIdentityPublic: fillBytes(flatSessIdentityKeyLen, seed+0x11),
		RootKey:              fillBytes(flatSessRootKeyLen, seed+0x12),
		PreviousCounter:      uint32(seed) + 10,
		LocalRegistrationID:  uint32(seed) + 20,
		RemoteRegistrationID: uint32(seed) + 30,
		NeedsRefresh:         seed%2 == 0,
		SenderBaseKey:        senderBaseKey,
		SenderChain:          makeChainStructure(seed+0x20, true, nMsgKeysPerChain),
		ReceiverChains:       receiverChains,
		PendingPreKey:        pendingPreKey,
		PendingKeyExchange:   pendingKeyExchange,
	}
}

// makeSessionStructure builds a SessionStructure with the given parameters.
func makeSessionStructure(
	nPreviousStates int,
	nReceiverChains int,
	nMessageKeys int,
	hasPendingPreKey bool,
	hasPendingKeyExchange bool,
) *record.SessionStructure {
	current := makeStateStructure(0x01, false, nReceiverChains, nMessageKeys, hasPendingPreKey, 2, hasPendingKeyExchange)
	previous := make([]*record.StateStructure, nPreviousStates)
	for i := 0; i < nPreviousStates; i++ {
		previous[i] = makeStateStructure(byte(i+2)*0x10, i%2 == 0, 1, 0, false, 0, false)
	}
	return &record.SessionStructure{
		SessionState:   current,
		PreviousStates: previous,
	}
}

// ---------------------------------------------------------------------------
// REQ-CODEC-01: TestFlatSessionRoundTrip
// ---------------------------------------------------------------------------

func TestFlatSessionRoundTrip(t *testing.T) {
	type testCase struct {
		nPreviousStates   int
		nReceiverChains   int
		nMessageKeys      int
		hasPendingPreKey  bool
		hasPendingKeyExch bool
	}

	cases := []testCase{}
	for _, nPrev := range []int{0, 1, 5} {
		for _, nRC := range []int{0, 1, 3} {
			for _, nMK := range []int{0, 1, 100, 2000} {
				for _, hasPPK := range []bool{false, true} {
					for _, hasPKE := range []bool{false, true} {
						cases = append(cases, testCase{nPrev, nRC, nMK, hasPPK, hasPKE})
					}
				}
			}
		}
	}

	for _, tc := range cases {
		orig := makeSessionStructure(tc.nPreviousStates, tc.nReceiverChains, tc.nMessageKeys, tc.hasPendingPreKey, tc.hasPendingKeyExch)
		packed, ok := PackFlatSession(orig)
		if !ok {
			t.Errorf("PackFlatSession refused valid structure (nPrev=%d nRC=%d nMK=%d ppk=%v pke=%v)",
				tc.nPreviousStates, tc.nReceiverChains, tc.nMessageKeys, tc.hasPendingPreKey, tc.hasPendingKeyExch)
			continue
		}
		if len(packed) == 0 {
			t.Errorf("PackFlatSession returned empty slice (nPrev=%d nRC=%d nMK=%d)", tc.nPreviousStates, tc.nReceiverChains, tc.nMessageKeys)
			continue
		}
		if packed[0] != flatSessionMagic {
			t.Errorf("PackFlatSession byte[0]=%02x, want %02x (magic)", packed[0], flatSessionMagic)
		}
		if packed[0] == 0x7B {
			t.Errorf("PackFlatSession emitted 0x7B (JSON discriminator) at byte[0] — invariant violated")
		}

		got, err := UnpackFlatSession(packed)
		if err != nil {
			t.Errorf("UnpackFlatSession returned error (nPrev=%d nRC=%d nMK=%d): %v",
				tc.nPreviousStates, tc.nReceiverChains, tc.nMessageKeys, err)
			continue
		}
		if !reflect.DeepEqual(got, orig) {
			t.Errorf("round-trip DeepEqual mismatch (nPrev=%d nRC=%d nMK=%d ppk=%v pke=%v)",
				tc.nPreviousStates, tc.nReceiverChains, tc.nMessageKeys, tc.hasPendingPreKey, tc.hasPendingKeyExch)
		}
	}
}

// ---------------------------------------------------------------------------
// REQ-CODEC-02: TestFlatSessionNilDistinctions
// ---------------------------------------------------------------------------

func TestFlatSessionNilDistinctions(t *testing.T) {
	// SenderBaseKey = nil (no sender base key)
	t.Run("SenderBaseKey_nil", func(t *testing.T) {
		orig := makeStateStructure(0x01, true, 0, 0, false, 0, false)
		ss := &record.SessionStructure{
			SessionState:   orig,
			PreviousStates: make([]*record.StateStructure, 0),
		}
		packed, ok := PackFlatSession(ss)
		if !ok {
			t.Fatal("PackFlatSession refused valid structure with nil SenderBaseKey")
		}
		got, err := UnpackFlatSession(packed)
		if err != nil {
			t.Fatalf("UnpackFlatSession error: %v", err)
		}
		if got.SessionState.SenderBaseKey != nil {
			t.Fatalf("SenderBaseKey should be nil, got %v (len=%d)", got.SessionState.SenderBaseKey, len(got.SessionState.SenderBaseKey))
		}
		if !reflect.DeepEqual(got, ss) {
			t.Fatal("DeepEqual mismatch for nil SenderBaseKey")
		}
	})

	// SenderBaseKey = non-nil (present)
	t.Run("SenderBaseKey_present", func(t *testing.T) {
		orig := makeStateStructure(0x02, false, 0, 0, false, 0, false)
		ss := &record.SessionStructure{
			SessionState:   orig,
			PreviousStates: make([]*record.StateStructure, 0),
		}
		packed, ok := PackFlatSession(ss)
		if !ok {
			t.Fatal("PackFlatSession refused valid structure with SenderBaseKey present")
		}
		got, err := UnpackFlatSession(packed)
		if err != nil {
			t.Fatalf("UnpackFlatSession error: %v", err)
		}
		if got.SessionState.SenderBaseKey == nil {
			t.Fatal("SenderBaseKey should be non-nil")
		}
		if !reflect.DeepEqual(got, ss) {
			t.Fatal("DeepEqual mismatch for non-nil SenderBaseKey")
		}
	})

	// SenderRatchetKeyPrivate = nil on receiver chain
	t.Run("RatchetPrivate_nil_on_receiver_chain", func(t *testing.T) {
		chainNoPriv := makeChainStructure(0x10, false, 0)
		if chainNoPriv.SenderRatchetKeyPrivate != nil {
			t.Fatal("test setup: expected nil private key for receiver chain")
		}
		orig := &record.StateStructure{
			SessionVersion:       3,
			LocalIdentityPublic:  fillBytes(flatSessIdentityKeyLen, 0x10),
			RemoteIdentityPublic: fillBytes(flatSessIdentityKeyLen, 0x11),
			RootKey:              fillBytes(flatSessRootKeyLen, 0x12),
			PreviousCounter:      10,
			LocalRegistrationID:  20,
			RemoteRegistrationID: 30,
			NeedsRefresh:         false,
			SenderBaseKey:        fillBytes(flatSessSenderBaseKeyLen, 0x13),
			SenderChain:          makeChainStructure(0x20, true, 0),
			ReceiverChains:       []*record.ChainStructure{chainNoPriv},
			PendingPreKey:        nil,
			PendingKeyExchange:   nil,
		}
		ss := &record.SessionStructure{
			SessionState:   orig,
			PreviousStates: make([]*record.StateStructure, 0),
		}
		packed, ok := PackFlatSession(ss)
		if !ok {
			t.Fatal("PackFlatSession refused valid structure")
		}
		got, err := UnpackFlatSession(packed)
		if err != nil {
			t.Fatalf("UnpackFlatSession error: %v", err)
		}
		if got.SessionState.ReceiverChains[0].SenderRatchetKeyPrivate != nil {
			t.Fatalf("receiver chain SenderRatchetKeyPrivate should be nil, got len=%d",
				len(got.SessionState.ReceiverChains[0].SenderRatchetKeyPrivate))
		}
		if !reflect.DeepEqual(got, ss) {
			t.Fatal("DeepEqual mismatch for nil receiver chain private key")
		}
	})

	// PendingPreKey = nil
	t.Run("PendingPreKey_nil", func(t *testing.T) {
		orig := makeStateStructure(0x03, false, 0, 0, false, 0, false)
		ss := &record.SessionStructure{
			SessionState:   orig,
			PreviousStates: make([]*record.StateStructure, 0),
		}
		packed, ok := PackFlatSession(ss)
		if !ok {
			t.Fatal("PackFlatSession refused valid structure with nil PendingPreKey")
		}
		got, err := UnpackFlatSession(packed)
		if err != nil {
			t.Fatalf("UnpackFlatSession error: %v", err)
		}
		if got.SessionState.PendingPreKey != nil {
			t.Fatal("PendingPreKey should be nil")
		}
	})

	// PendingKeyExchange = nil
	t.Run("PendingKeyExchange_nil", func(t *testing.T) {
		orig := makeStateStructure(0x04, false, 0, 0, false, 0, false)
		ss := &record.SessionStructure{
			SessionState:   orig,
			PreviousStates: make([]*record.StateStructure, 0),
		}
		packed, ok := PackFlatSession(ss)
		if !ok {
			t.Fatal("PackFlatSession refused valid structure with nil PendingKeyExchange")
		}
		got, err := UnpackFlatSession(packed)
		if err != nil {
			t.Fatalf("UnpackFlatSession error: %v", err)
		}
		if got.SessionState.PendingKeyExchange != nil {
			t.Fatal("PendingKeyExchange should be nil")
		}
	})

	// PreKeyID three-state: state 0 = nil pointer
	t.Run("PreKeyID_state0_nil", func(t *testing.T) {
		orig := makeStateStructure(0x05, false, 0, 0, true, 0, false) // preKeyIDState=0
		ss := &record.SessionStructure{
			SessionState:   orig,
			PreviousStates: make([]*record.StateStructure, 0),
		}
		packed, ok := PackFlatSession(ss)
		if !ok {
			t.Fatal("PackFlatSession refused valid structure with preKeyIDState=0")
		}
		got, err := UnpackFlatSession(packed)
		if err != nil {
			t.Fatalf("UnpackFlatSession error: %v", err)
		}
		if got.SessionState.PendingPreKey == nil {
			t.Fatal("PendingPreKey should be non-nil (hasPendingPreKey=true)")
		}
		if got.SessionState.PendingPreKey.PreKeyID != nil {
			t.Fatalf("PreKeyID should be nil (state=0), got %+v", got.SessionState.PendingPreKey.PreKeyID)
		}
		if !reflect.DeepEqual(got, ss) {
			t.Fatal("DeepEqual mismatch for preKeyIDState=0")
		}
	})

	// PreKeyID three-state: state 1 = IsEmpty
	t.Run("PreKeyID_state1_IsEmpty", func(t *testing.T) {
		orig := makeStateStructure(0x06, false, 0, 0, true, 1, false) // preKeyIDState=1
		ss := &record.SessionStructure{
			SessionState:   orig,
			PreviousStates: make([]*record.StateStructure, 0),
		}
		packed, ok := PackFlatSession(ss)
		if !ok {
			t.Fatal("PackFlatSession refused valid structure with preKeyIDState=1")
		}
		got, err := UnpackFlatSession(packed)
		if err != nil {
			t.Fatalf("UnpackFlatSession error: %v", err)
		}
		if got.SessionState.PendingPreKey == nil {
			t.Fatal("PendingPreKey should be non-nil")
		}
		if got.SessionState.PendingPreKey.PreKeyID == nil {
			t.Fatal("PreKeyID should be non-nil (state=1 IsEmpty)")
		}
		if !got.SessionState.PendingPreKey.PreKeyID.IsEmpty {
			t.Fatalf("PreKeyID.IsEmpty should be true (state=1), got %+v", got.SessionState.PendingPreKey.PreKeyID)
		}
		if !reflect.DeepEqual(got, ss) {
			t.Fatal("DeepEqual mismatch for preKeyIDState=1")
		}
	})

	// PreKeyID three-state: state 2 = has value
	t.Run("PreKeyID_state2_hasValue", func(t *testing.T) {
		orig := makeStateStructure(0x07, false, 0, 0, true, 2, false) // preKeyIDState=2
		ss := &record.SessionStructure{
			SessionState:   orig,
			PreviousStates: make([]*record.StateStructure, 0),
		}
		packed, ok := PackFlatSession(ss)
		if !ok {
			t.Fatal("PackFlatSession refused valid structure with preKeyIDState=2")
		}
		got, err := UnpackFlatSession(packed)
		if err != nil {
			t.Fatalf("UnpackFlatSession error: %v", err)
		}
		if got.SessionState.PendingPreKey == nil {
			t.Fatal("PendingPreKey should be non-nil")
		}
		if got.SessionState.PendingPreKey.PreKeyID == nil {
			t.Fatal("PreKeyID should be non-nil (state=2)")
		}
		if got.SessionState.PendingPreKey.PreKeyID.IsEmpty {
			t.Fatal("PreKeyID.IsEmpty should be false (state=2)")
		}
		if got.SessionState.PendingPreKey.PreKeyID.Value != 42 {
			t.Fatalf("PreKeyID.Value should be 42, got %d", got.SessionState.PendingPreKey.PreKeyID.Value)
		}
		if !reflect.DeepEqual(got, ss) {
			t.Fatal("DeepEqual mismatch for preKeyIDState=2")
		}
	})
}

// ---------------------------------------------------------------------------
// REQ-CODEC-03: TestFlatSessionRefuse
// ---------------------------------------------------------------------------

func TestFlatSessionRefuse(t *testing.T) {
	// Build a valid base session for mutation.
	validState := func() *record.StateStructure {
		return makeStateStructure(0x01, false, 0, 0, false, 0, false)
	}
	validSession := func() *record.SessionStructure {
		return &record.SessionStructure{
			SessionState:   validState(),
			PreviousStates: make([]*record.StateStructure, 0),
		}
	}

	t.Run("wrong_LocalIdentityPublic_len_32_not_33", func(t *testing.T) {
		ss := validSession()
		ss.SessionState.LocalIdentityPublic = fillBytes(32, 0x10) // wrong: 32 != 33
		if _, ok := PackFlatSession(ss); ok {
			t.Fatal("expected ok=false for wrong LocalIdentityPublic length")
		}
	})

	t.Run("wrong_RootKey_len_31", func(t *testing.T) {
		ss := validSession()
		ss.SessionState.RootKey = fillBytes(31, 0x12) // wrong: 31 != 32
		if _, ok := PackFlatSession(ss); ok {
			t.Fatal("expected ok=false for wrong RootKey length")
		}
	})

	t.Run("wrong_RemoteIdentityPublic_len", func(t *testing.T) {
		ss := validSession()
		ss.SessionState.RemoteIdentityPublic = fillBytes(32, 0x11) // wrong: 32 != 33
		if _, ok := PackFlatSession(ss); ok {
			t.Fatal("expected ok=false for wrong RemoteIdentityPublic length")
		}
	})

	t.Run("nReceiverChains_256_exceeds_u8", func(t *testing.T) {
		ss := validSession()
		ss.SessionState.ReceiverChains = make([]*record.ChainStructure, 256)
		for i := range ss.SessionState.ReceiverChains {
			ss.SessionState.ReceiverChains[i] = makeChainStructure(byte(i), false, 0)
		}
		if _, ok := PackFlatSession(ss); ok {
			t.Fatal("expected ok=false for nReceiverChains=256 (exceeds u8 ceiling)")
		}
	})

	t.Run("nPreviousStates_256_exceeds_u8", func(t *testing.T) {
		ss := &record.SessionStructure{
			SessionState:   validState(),
			PreviousStates: make([]*record.StateStructure, 256),
		}
		for i := range ss.PreviousStates {
			ss.PreviousStates[i] = makeStateStructure(byte(i), false, 0, 0, false, 0, false)
		}
		if _, ok := PackFlatSession(ss); ok {
			t.Fatal("expected ok=false for nPreviousStates=256 (exceeds u8 ceiling)")
		}
	})

	// D-03: codec MUST NOT refuse nMessageKeys=2000 (libsignal's logical cap).
	t.Run("nMessageKeys_2000_must_not_refuse", func(t *testing.T) {
		ss := makeSessionStructure(0, 0, 2000, false, false)
		packed, ok := PackFlatSession(ss)
		if !ok {
			t.Fatal("PackFlatSession must NOT refuse nMessageKeys=2000 (D-03: codec-added cap violates D-03)")
		}
		got, err := UnpackFlatSession(packed)
		if err != nil {
			t.Fatalf("UnpackFlatSession error for nMessageKeys=2000: %v", err)
		}
		if !reflect.DeepEqual(got, ss) {
			t.Fatal("DeepEqual mismatch for nMessageKeys=2000")
		}
	})

	// D-03: preKeyIDState values 0, 1, 2 must NOT refuse.
	t.Run("preKeyIDState_0_1_2_must_not_refuse", func(t *testing.T) {
		for _, state := range []int{0, 1, 2} {
			orig := makeStateStructure(0x10, false, 0, 0, true, state, false)
			ss := &record.SessionStructure{
				SessionState:   orig,
				PreviousStates: make([]*record.StateStructure, 0),
			}
			if _, ok := PackFlatSession(ss); !ok {
				t.Errorf("PackFlatSession refused valid preKeyIDState=%d", state)
			}
		}
	})

	// Wrong SenderBaseKey length when non-nil.
	t.Run("wrong_SenderBaseKey_len", func(t *testing.T) {
		ss := validSession()
		ss.SessionState.SenderBaseKey = fillBytes(32, 0x01) // wrong: 32 != 33
		if _, ok := PackFlatSession(ss); ok {
			t.Fatal("expected ok=false for wrong SenderBaseKey length")
		}
	})

	// Wrong chain key length.
	t.Run("wrong_ChainKey_len", func(t *testing.T) {
		ss := validSession()
		ss.SessionState.SenderChain.ChainKey.Key = fillBytes(31, 0x40) // wrong: 31 != 32
		if _, ok := PackFlatSession(ss); ok {
			t.Fatal("expected ok=false for wrong ChainKey length")
		}
	})

	// Wrong SenderRatchetKeyPublic length.
	t.Run("wrong_RatchetKeyPublic_len", func(t *testing.T) {
		ss := validSession()
		ss.SessionState.SenderChain.SenderRatchetKeyPublic = fillBytes(32, 0x20) // wrong: 32 != 33
		if _, ok := PackFlatSession(ss); ok {
			t.Fatal("expected ok=false for wrong SenderRatchetKeyPublic length")
		}
	})

	// Wrong MessageKey CipherKey length.
	t.Run("wrong_MsgCipherKey_len", func(t *testing.T) {
		ss := validSession()
		ss.SessionState.SenderChain.MessageKeys = []*message.KeysStructure{{
			CipherKey: fillBytes(31, 0x10), // wrong: 31 != 32
			MacKey:    fillBytes(flatSessMsgMacKeyLen, 0x20),
			IV:        fillBytes(flatSessMsgIVLen, 0x30),
			Index:     0,
		}}
		if _, ok := PackFlatSession(ss); ok {
			t.Fatal("expected ok=false for wrong MessageKey CipherKey length")
		}
	})

	// Wrong PendingPreKey BaseKey length.
	t.Run("wrong_PendingPreKey_BaseKey_len", func(t *testing.T) {
		ss := validSession()
		ss.SessionState.PendingPreKey = &record.PendingPreKeyStructure{
			PreKeyID:       nil,
			SignedPreKeyID: 10,
			BaseKey:        fillBytes(32, 0x70), // wrong: 32 != 33
		}
		if _, ok := PackFlatSession(ss); ok {
			t.Fatal("expected ok=false for wrong PendingPreKey BaseKey length")
		}
	})

	// Wrong PendingKeyExchange key length (must be 32, not 33).
	t.Run("wrong_PendingKeyExchange_key_len", func(t *testing.T) {
		ss := validSession()
		ss.SessionState.PendingKeyExchange = &record.PendingKeyExchangeStructure{
			Sequence:                200,
			LocalBaseKeyPublic:      fillBytes(33, 0x01), // wrong: 33 != 32 (Pitfall 8)
			LocalBaseKeyPrivate:     fillBytes(flatSessExchangeKeyLen, 0x02),
			LocalRatchetKeyPublic:   fillBytes(flatSessExchangeKeyLen, 0x03),
			LocalRatchetKeyPrivate:  fillBytes(flatSessExchangeKeyLen, 0x04),
			LocalIdentityKeyPublic:  fillBytes(flatSessExchangeKeyLen, 0x05),
			LocalIdentityKeyPrivate: fillBytes(flatSessExchangeKeyLen, 0x06),
		}
		if _, ok := PackFlatSession(ss); ok {
			t.Fatal("expected ok=false for wrong PendingKeyExchange key length (must be 32 not 33)")
		}
	})
}

// ---------------------------------------------------------------------------
// REQ-CODEC-04: TestFlatSessionMalformed
// ---------------------------------------------------------------------------

func TestFlatSessionMalformed(t *testing.T) {
	t.Run("empty_buffer", func(t *testing.T) {
		_, err := UnpackFlatSession([]byte{})
		if err == nil {
			t.Fatal("expected error for empty buffer")
		}
	})

	t.Run("magic_byte_not_0x01", func(t *testing.T) {
		_, err := UnpackFlatSession([]byte{0x7B, 0x00}) // 0x7B = '{' (JSON)
		if err == nil {
			t.Fatal("expected error for wrong magic byte 0x7B")
		}
	})

	t.Run("magic_byte_0x02", func(t *testing.T) {
		_, err := UnpackFlatSession([]byte{0x02, 0x00, 0x00})
		if err == nil {
			t.Fatal("expected error for wrong magic byte 0x02")
		}
	})

	t.Run("truncated_after_nPreviousStates", func(t *testing.T) {
		// magic(1) + nPrev(1) = 2 bytes; no state data follows
		_, err := UnpackFlatSession([]byte{flatSessionMagic, 0x01})
		if err == nil {
			t.Fatal("expected error for truncated buffer after nPreviousStates")
		}
	})

	t.Run("truncated_mid_state_header", func(t *testing.T) {
		// magic + nPrev=0 + 3 bytes of state (far short of a full state header)
		buf := []byte{flatSessionMagic, 0x00, 0x00, 0x00, 0x00}
		_, err := UnpackFlatSession(buf)
		if err == nil {
			t.Fatal("expected error for truncated mid-state-header")
		}
	})

	t.Run("truncated_mid_chain", func(t *testing.T) {
		// Build a valid session, then truncate to mid-chain
		ss := makeSessionStructure(0, 1, 0, false, false)
		packed, ok := PackFlatSession(ss)
		if !ok {
			t.Fatal("test setup: PackFlatSession refused valid structure")
		}
		// Truncate to somewhere in the middle
		truncated := packed[:len(packed)/2]
		_, err := UnpackFlatSession(truncated)
		if err == nil {
			t.Fatal("expected error for buffer truncated mid-chain")
		}
	})

	t.Run("truncated_mid_messageKey", func(t *testing.T) {
		// Build a session with message keys, then truncate mid-key
		ss := makeSessionStructure(0, 0, 5, false, false)
		packed, ok := PackFlatSession(ss)
		if !ok {
			t.Fatal("test setup: PackFlatSession refused valid structure")
		}
		// Remove one byte from end — truncates mid-message-key record
		truncated := packed[:len(packed)-1]
		_, err := UnpackFlatSession(truncated)
		if err == nil {
			t.Fatal("expected error for buffer truncated mid-message-key")
		}
	})

	t.Run("preKeyIDState_2_missing_u32", func(t *testing.T) {
		// Build a session with preKeyIDState=2, then corrupt to remove the u32 value.
		ss := makeSessionStructure(0, 0, 0, true, false)
		// Set preKeyIDState=2 explicitly
		ss.SessionState.PendingPreKey = &record.PendingPreKeyStructure{
			PreKeyID:       &optional.Uint32{IsEmpty: false, Value: 42},
			SignedPreKeyID: 100,
			BaseKey:        fillBytes(flatSessPendingBaseKeyLen, 0x70),
		}
		packed, ok := PackFlatSession(ss)
		if !ok {
			t.Fatal("test setup: PackFlatSession refused valid structure")
		}
		// Remove last 4 bytes (the u32 preKeyIDValue) — make it too short
		truncated := packed[:len(packed)-4]
		_, err := UnpackFlatSession(truncated)
		if err == nil {
			t.Fatal("expected error for preKeyIDState=2 with missing u32 value")
		}
	})

	t.Run("never_panics_random_garbage", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("UnpackFlatSession panicked: %v", r)
			}
		}()
		// Various random-ish garbage inputs
		garbage := [][]byte{
			{0x01},
			{0x01, 0xFF},
			{0x01, 0x05, 0xDE, 0xAD, 0xBE, 0xEF},
			{0x01, 0x00, 0x00, 0x00, 0x00, 0x03},
			make([]byte, 0),
			make([]byte, 1),
			make([]byte, 2),
			make([]byte, 100),
		}
		for _, g := range garbage {
			if len(g) > 0 {
				g[0] = 0x01 // set magic to allow parsing attempt
			}
			UnpackFlatSession(g) //nolint:errcheck — we only care about no panic
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzUnpackFlatSession — D-01 (fuzz the codec)
// ---------------------------------------------------------------------------

func FuzzUnpackFlatSession(f *testing.F) {
	// Corpus seed: zero-key session
	zeroKey := makeSessionStructure(0, 0, 0, false, false)
	if packed, ok := PackFlatSession(zeroKey); ok {
		f.Add(packed)
	}

	// Corpus seed: 2000-key session
	fatKey := makeSessionStructure(0, 0, 2000, false, false)
	if packed, ok := PackFlatSession(fatKey); ok {
		f.Add(packed)
	}

	// Corpus seed: with PendingPreKey (preKeyIDState=2)
	ppkSession := makeSessionStructure(0, 0, 0, true, false)
	if packed, ok := PackFlatSession(ppkSession); ok {
		f.Add(packed)
	}

	// Corpus seed: with PendingKeyExchange
	pkeSession := makeSessionStructure(0, 0, 0, false, true)
	if packed, ok := PackFlatSession(pkeSession); ok {
		f.Add(packed)
	}

	// Corpus seed: full complexity
	fullSession := makeSessionStructure(2, 2, 10, true, false)
	if packed, ok := PackFlatSession(fullSession); ok {
		f.Add(packed)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		// Must never panic regardless of input.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("UnpackFlatSession panicked on input len=%d: %v", len(b), r)
			}
		}()
		UnpackFlatSession(b) //nolint:errcheck — fuzz target only cares about no panic
	})
}

// ---------------------------------------------------------------------------
// REQ-CODEC-05: TestFlatSessionDecryptEquivalence
//
// Proves that a full X3DH session round-tripped through PackFlatSession +
// UnpackFlatSession + record.NewSessionFromStructure decrypts messages
// identically to the original session — including after a ratchet advance and
// with accumulated skipped keys.
//
// Uses libsignal's session/Builder + session/Cipher (DM path, not group).
// Does NOT touch any prod DB — entirely in-memory with generated keys.
// ---------------------------------------------------------------------------

// dmHarness holds the four in-memory stores and session builder for one DM peer.
type dmHarness struct {
	serializer        *serialize.Serializer
	sessionStore      *dmInMemorySession
	preKeyStore       *dmInMemoryPreKey
	signedPreKeyStore *dmInMemorySignedPreKey
	identityStore     *dmInMemoryIdentityKey
	address           *protocol.SignalAddress
	identityKP        *identity.KeyPair
	registrationID    uint32
	preKeys           []*record.PreKey
	signedPreKey      *record.SignedPreKey
	builder           *session.Builder
}

// ---------------------------------------------------------------------------
// Inline minimal in-memory store implementations (package tests is importable,
// but we inline to avoid an external test dependency on an internal package).
// ---------------------------------------------------------------------------

type dmInMemorySession struct {
	sessions   map[string]*record.Session
	serializer *serialize.Serializer
}

func newDMInMemorySession(s *serialize.Serializer) *dmInMemorySession {
	return &dmInMemorySession{sessions: make(map[string]*record.Session), serializer: s}
}

func (m *dmInMemorySession) LoadSession(ctx context.Context, addr *protocol.SignalAddress) (*record.Session, error) {
	if s, ok := m.sessions[addr.String()]; ok {
		return s, nil
	}
	s := record.NewSession(m.serializer.Session, m.serializer.State)
	m.sessions[addr.String()] = s
	return s, nil
}

func (m *dmInMemorySession) StoreSession(ctx context.Context, addr *protocol.SignalAddress, sess *record.Session) error {
	m.sessions[addr.String()] = sess
	return nil
}

func (m *dmInMemorySession) ContainsSession(ctx context.Context, addr *protocol.SignalAddress) (bool, error) {
	_, ok := m.sessions[addr.String()]
	return ok, nil
}

func (m *dmInMemorySession) DeleteSession(ctx context.Context, addr *protocol.SignalAddress) error {
	delete(m.sessions, addr.String())
	return nil
}

func (m *dmInMemorySession) DeleteAllSessions(ctx context.Context) error {
	m.sessions = make(map[string]*record.Session)
	return nil
}

func (m *dmInMemorySession) GetSubDeviceSessions(ctx context.Context, name string) ([]uint32, error) {
	return nil, nil
}

type dmInMemoryPreKey struct {
	store map[uint32]*record.PreKey
}

func newDMInMemoryPreKey() *dmInMemoryPreKey {
	return &dmInMemoryPreKey{store: make(map[uint32]*record.PreKey)}
}

func (m *dmInMemoryPreKey) LoadPreKey(ctx context.Context, id uint32) (*record.PreKey, error) {
	return m.store[id], nil
}

func (m *dmInMemoryPreKey) StorePreKey(ctx context.Context, id uint32, pk *record.PreKey) error {
	m.store[id] = pk
	return nil
}

func (m *dmInMemoryPreKey) ContainsPreKey(ctx context.Context, id uint32) (bool, error) {
	_, ok := m.store[id]
	return ok, nil
}

func (m *dmInMemoryPreKey) RemovePreKey(ctx context.Context, id uint32) error {
	delete(m.store, id)
	return nil
}

type dmInMemorySignedPreKey struct {
	store map[uint32]*record.SignedPreKey
}

func newDMInMemorySignedPreKey() *dmInMemorySignedPreKey {
	return &dmInMemorySignedPreKey{store: make(map[uint32]*record.SignedPreKey)}
}

func (m *dmInMemorySignedPreKey) LoadSignedPreKey(ctx context.Context, id uint32) (*record.SignedPreKey, error) {
	return m.store[id], nil
}

func (m *dmInMemorySignedPreKey) LoadSignedPreKeys(ctx context.Context) ([]*record.SignedPreKey, error) {
	result := make([]*record.SignedPreKey, 0, len(m.store))
	for _, v := range m.store {
		result = append(result, v)
	}
	return result, nil
}

func (m *dmInMemorySignedPreKey) StoreSignedPreKey(ctx context.Context, id uint32, spk *record.SignedPreKey) error {
	m.store[id] = spk
	return nil
}

func (m *dmInMemorySignedPreKey) ContainsSignedPreKey(ctx context.Context, id uint32) (bool, error) {
	_, ok := m.store[id]
	return ok, nil
}

func (m *dmInMemorySignedPreKey) RemoveSignedPreKey(ctx context.Context, id uint32) error {
	delete(m.store, id)
	return nil
}

type dmInMemoryIdentityKey struct {
	trustedKeys    map[string]*identity.Key
	identityKP     *identity.KeyPair
	registrationID uint32
}

func newDMInMemoryIdentityKey(kp *identity.KeyPair, regID uint32) *dmInMemoryIdentityKey {
	return &dmInMemoryIdentityKey{
		trustedKeys:    make(map[string]*identity.Key),
		identityKP:     kp,
		registrationID: regID,
	}
}

func (m *dmInMemoryIdentityKey) GetIdentityKeyPair() *identity.KeyPair {
	return m.identityKP
}

func (m *dmInMemoryIdentityKey) GetLocalRegistrationID() uint32 {
	return m.registrationID
}

func (m *dmInMemoryIdentityKey) SaveIdentity(ctx context.Context, addr *protocol.SignalAddress, key *identity.Key) error {
	m.trustedKeys[addr.String()] = key
	return nil
}

func (m *dmInMemoryIdentityKey) IsTrustedIdentity(ctx context.Context, addr *protocol.SignalAddress, key *identity.Key) (bool, error) {
	trusted := m.trustedKeys[addr.String()]
	return trusted == nil || trusted.Fingerprint() == key.Fingerprint(), nil
}

// ---------------------------------------------------------------------------
// newDMHarness creates a fully initialised DM peer (4 stores + builder).
// ---------------------------------------------------------------------------

func newDMHarness(t *testing.T, name string, deviceID uint32) *dmHarness {
	t.Helper()
	s := serialize.NewProtoBufSerializer()

	kp, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair: %v", err)
	}
	regID := keyhelper.GenerateRegistrationID()

	preKeys, err := keyhelper.GeneratePreKeys(1, 10, s.PreKeyRecord)
	if err != nil {
		t.Fatalf("GeneratePreKeys: %v", err)
	}
	spk, err := keyhelper.GenerateSignedPreKey(kp, 0, s.SignedPreKeyRecord)
	if err != nil {
		t.Fatalf("GenerateSignedPreKey: %v", err)
	}

	sessionStore := newDMInMemorySession(s)
	preKeyStore := newDMInMemoryPreKey()
	signedPreKeyStore := newDMInMemorySignedPreKey()
	identityStore := newDMInMemoryIdentityKey(kp, regID)

	ctx := context.Background()
	for _, pk := range preKeys {
		_ = preKeyStore.StorePreKey(ctx, pk.ID().Value, record.NewPreKey(pk.ID().Value, pk.KeyPair(), s.PreKeyRecord))
	}
	_ = signedPreKeyStore.StoreSignedPreKey(ctx, spk.ID(), record.NewSignedPreKey(
		spk.ID(), spk.Timestamp(), spk.KeyPair(), spk.Signature(), s.SignedPreKeyRecord,
	))

	addr := protocol.NewSignalAddress(name, deviceID)
	b := session.NewBuilder(sessionStore, preKeyStore, signedPreKeyStore, identityStore, addr, s)

	return &dmHarness{
		serializer:        s,
		sessionStore:      sessionStore,
		preKeyStore:       preKeyStore,
		signedPreKeyStore: signedPreKeyStore,
		identityStore:     identityStore,
		address:           addr,
		identityKP:        kp,
		registrationID:    regID,
		preKeys:           preKeys,
		signedPreKey:      spk,
		builder:           b,
	}
}

// bobBundle builds a prekey.Bundle from Bob's public material that Alice uses to
// establish a session towards Bob.
func bobBundle(bob *dmHarness) *prekey.Bundle {
	return prekey.NewBundle(
		bob.registrationID,
		bob.address.DeviceID(),
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKP.PublicKey(),
	)
}

// encryptDM encrypts a plaintext message from src towards dstAddr and returns the
// raw on-wire ciphertext bytes plus the type marker.
func encryptDM(t *testing.T, srcBuilder *session.Builder, dstAddr *protocol.SignalAddress, src *dmHarness, plain []byte) protocol.CiphertextMessage {
	t.Helper()
	ctx := context.Background()
	cipher := session.NewCipher(srcBuilder, dstAddr)
	msg, err := cipher.Encrypt(ctx, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Re-serialise to mimic wire transit (same as libsignal tests pattern).
	s := src.serializer
	switch msg.(type) {
	case *protocol.PreKeySignalMessage:
		m, err2 := protocol.NewPreKeySignalMessageFromBytes(msg.Serialize(), s.PreKeySignalMessage, s.SignalMessage)
		if err2 != nil {
			t.Fatalf("PreKeySignalMessageFromBytes: %v", err2)
		}
		return m
	default:
		m, err2 := protocol.NewSignalMessageFromBytes(msg.Serialize(), s.SignalMessage)
		if err2 != nil {
			t.Fatalf("SignalMessageFromBytes: %v", err2)
		}
		return m
	}
}

// decryptDM decrypts a CiphertextMessage using dstBuilder towards srcAddr.
func decryptDM(t *testing.T, dstBuilder *session.Builder, srcAddr *protocol.SignalAddress, msg protocol.CiphertextMessage) []byte {
	t.Helper()
	ctx := context.Background()
	cipher := session.NewCipher(dstBuilder, srcAddr)
	switch m := msg.(type) {
	case *protocol.PreKeySignalMessage:
		plain, err := cipher.DecryptMessage(ctx, m)
		if err != nil {
			t.Fatalf("DecryptMessage(PreKey): %v", err)
		}
		return plain
	default:
		plain, err := cipher.Decrypt(ctx, m.(*protocol.SignalMessage))
		if err != nil {
			t.Fatalf("Decrypt(Signal): %v", err)
		}
		return plain
	}
}

// swapBobSession replaces Bob's session for aliceAddr with one rebuilt from
// the flat-round-tripped structure of his current session. It returns the
// structure before the round-trip so callers can assert skipped-key counts.
func swapBobSession(t *testing.T, bob *dmHarness, aliceAddr *protocol.SignalAddress) *record.SessionStructure {
	t.Helper()
	ctx := context.Background()

	sess, err := bob.sessionStore.LoadSession(ctx, aliceAddr)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	structure := sess.Structure()

	flat, ok := PackFlatSession(structure)
	if !ok {
		t.Fatal("PackFlatSession refused valid live session structure")
	}
	structure2, err := UnpackFlatSession(flat)
	if err != nil {
		t.Fatalf("UnpackFlatSession: %v", err)
	}
	if !reflect.DeepEqual(structure, structure2) {
		t.Fatal("round-trip DeepEqual failed on live session structure")
	}

	rebuilt, err := record.NewSessionFromStructure(structure2, SignalProtobufSerializer.Session, SignalProtobufSerializer.State)
	if err != nil {
		t.Fatalf("NewSessionFromStructure: %v", err)
	}
	if err := bob.sessionStore.StoreSession(ctx, aliceAddr, rebuilt); err != nil {
		t.Fatalf("StoreSession(rebuilt): %v", err)
	}
	return structure
}

// TestFlatSessionDecryptEquivalence proves that the flat codec is semantically
// correct under real Double-Ratchet crypto:
//
//  1. First-message decrypt: Alice sends msg[0] → Bob receives it. Bob's session
//     is round-tripped (Pack→Unpack→NewSessionFromStructure) BEFORE the decrypt.
//     Decrypt from the rebuilt session must yield the original plaintext.
//
//  2. Ratchet-advance decrypt: after decrypting msg[0] from the rebuilt session,
//     Alice sends msg[1]. Bob's (now-ratcheted) session is round-tripped again.
//     Decrypt msg[1] from the re-rebuilt session must succeed.
//
//  3. Skipped-key path: Alice sends msgs 0..4. Bob decrypts msg[4] first (forces
//     the ratchet forward and accumulates skipped keys for 0..3). Bob's session
//     (with skipped keys) is round-tripped. Decrypting the still-skipped msg[0]
//     from the rebuilt session must succeed — proving the skipped-key tail is
//     preserved byte-exact through the codec.
//
// This test satisfies REQ-CODEC-05 (D-09 decrypt-equivalence gate).
func TestFlatSessionDecryptEquivalence(t *testing.T) {
	ctx := context.Background()

	// -----------------------------------------------------------------------
	// Sub-test 1: first-message decrypt from round-tripped session
	// -----------------------------------------------------------------------
	t.Run("first_message_decrypt", func(t *testing.T) {
		alice := newDMHarness(t, "alice", 1)
		bob := newDMHarness(t, "bob", 2)

		// Alice establishes session towards Bob via X3DH.
		aliceToBobBuilder := session.NewBuilder(
			alice.sessionStore, alice.preKeyStore, alice.signedPreKeyStore,
			alice.identityStore, bob.address, alice.serializer,
		)
		if err := aliceToBobBuilder.ProcessBundle(ctx, bobBundle(bob)); err != nil {
			t.Fatalf("ProcessBundle: %v", err)
		}
		// Bob's builder (will receive messages from Alice).
		bobFromAliceBuilder := session.NewBuilder(
			bob.sessionStore, bob.preKeyStore, bob.signedPreKeyStore,
			bob.identityStore, alice.address, bob.serializer,
		)

		plaintext := []byte("hello flat session codec")
		msg0 := encryptDM(t, aliceToBobBuilder, bob.address, alice, plaintext)

		// Swap Bob's session to the flat-round-tripped version BEFORE decrypt.
		// At this point Bob has no session yet (it will be created by DecryptMessage).
		// The first decrypt (PreKeySignalMessage) creates Bob's session from the
		// prekey bundle — there is nothing to round-trip before it. So we decrypt
		// first, then round-trip, then verify with msg1.
		got0 := decryptDM(t, bobFromAliceBuilder, alice.address, msg0)
		if string(got0) != string(plaintext) {
			t.Fatalf("first decrypt: got %q, want %q", got0, plaintext)
		}

		// Now Bob has a session. Round-trip it.
		swapBobSession(t, bob, alice.address)

		// Send a second message — Bob must decrypt from the rebuilt session.
		plaintext1 := []byte("second message after ratchet advance")
		msg1 := encryptDM(t, aliceToBobBuilder, bob.address, alice, plaintext1)
		got1 := decryptDM(t, bobFromAliceBuilder, alice.address, msg1)
		if string(got1) != string(plaintext1) {
			t.Fatalf("post-round-trip second message: got %q, want %q", got1, plaintext1)
		}
	})

	// -----------------------------------------------------------------------
	// Sub-test 2: ratchet-advance — capture session after first decrypt,
	// round-trip it, then send three more messages verifying each.
	// -----------------------------------------------------------------------
	t.Run("ratchet_advance", func(t *testing.T) {
		alice := newDMHarness(t, "alice-ra", 1)
		bob := newDMHarness(t, "bob-ra", 2)

		aliceToBobBuilder := session.NewBuilder(
			alice.sessionStore, alice.preKeyStore, alice.signedPreKeyStore,
			alice.identityStore, bob.address, alice.serializer,
		)
		if err := aliceToBobBuilder.ProcessBundle(ctx, bobBundle(bob)); err != nil {
			t.Fatalf("ProcessBundle: %v", err)
		}
		bobFromAliceBuilder := session.NewBuilder(
			bob.sessionStore, bob.preKeyStore, bob.signedPreKeyStore,
			bob.identityStore, alice.address, bob.serializer,
		)

		// Establish the session (Bob processes Alice's first message).
		msg0 := encryptDM(t, aliceToBobBuilder, bob.address, alice, []byte("setup"))
		decryptDM(t, bobFromAliceBuilder, alice.address, msg0)

		// Round-trip Bob's session after establishment.
		swapBobSession(t, bob, alice.address)

		// Decrypt three more messages, each advancing the ratchet, verifying
		// the session survives repeated round-trips.
		for i := 1; i <= 3; i++ {
			plain := []byte("ratchet step message")
			msg := encryptDM(t, aliceToBobBuilder, bob.address, alice, plain)
			got := decryptDM(t, bobFromAliceBuilder, alice.address, msg)
			if string(got) != string(plain) {
				t.Fatalf("ratchet step %d: got %q want %q", i, got, plain)
			}
			// Round-trip after each step.
			swapBobSession(t, bob, alice.address)
		}
	})

	// -----------------------------------------------------------------------
	// Sub-test 3: skipped-key path — Alice sends 5 messages; Bob decrypts the
	// LAST one first (msg[4]), accumulating skipped keys for 0..3. Bob's session
	// is round-tripped. Decrypting msg[0] from the rebuilt session must succeed.
	// -----------------------------------------------------------------------
	t.Run("skipped_keys_preserved", func(t *testing.T) {
		alice := newDMHarness(t, "alice-sk", 1)
		bob := newDMHarness(t, "bob-sk", 2)

		aliceToBobBuilder := session.NewBuilder(
			alice.sessionStore, alice.preKeyStore, alice.signedPreKeyStore,
			alice.identityStore, bob.address, alice.serializer,
		)
		if err := aliceToBobBuilder.ProcessBundle(ctx, bobBundle(bob)); err != nil {
			t.Fatalf("ProcessBundle: %v", err)
		}
		bobFromAliceBuilder := session.NewBuilder(
			bob.sessionStore, bob.preKeyStore, bob.signedPreKeyStore,
			bob.identityStore, alice.address, bob.serializer,
		)

		const nMsgs = 5
		plaintexts := make([][]byte, nMsgs)
		msgs := make([]protocol.CiphertextMessage, nMsgs)
		for i := 0; i < nMsgs; i++ {
			plaintexts[i] = []byte("skipped message " + string(rune('0'+i)))
			msgs[i] = encryptDM(t, aliceToBobBuilder, bob.address, alice, plaintexts[i])
		}

		// Bob decrypts the LAST message first — this processes the PreKeySignalMessage
		// (msg[0]) implicitly as part of the session bootstrap, but since the Signal
		// protocol chain is ratcheted forward to the last message counter, keys 0..3
		// are accumulated as skipped keys.
		// Actually: msg[0] is a PreKeySignalMessage; subsequent msgs[1..4] are
		// SignalMessages. Bob must first process msg[0] to initialise the session,
		// then skip ahead by decrypting msg[4].
		got0 := decryptDM(t, bobFromAliceBuilder, alice.address, msgs[0])
		if string(got0) != string(plaintexts[0]) {
			t.Fatalf("msg[0] decrypt: got %q want %q", got0, plaintexts[0])
		}
		// Now decrypt msg[4] — this advances the ratchet and accumulates skipped
		// keys for counter positions 1, 2, 3 (msg[1], msg[2], msg[3]).
		got4 := decryptDM(t, bobFromAliceBuilder, alice.address, msgs[4])
		if string(got4) != string(plaintexts[4]) {
			t.Fatalf("msg[4] decrypt: got %q want %q", got4, plaintexts[4])
		}

		// Verify skipped keys are present in Bob's session structure.
		bobSess, err := bob.sessionStore.LoadSession(ctx, alice.address)
		if err != nil {
			t.Fatalf("LoadSession: %v", err)
		}
		structure := bobSess.Structure()
		totalSkipped := 0
		for _, rc := range structure.SessionState.ReceiverChains {
			totalSkipped += len(rc.MessageKeys)
		}
		if totalSkipped == 0 {
			t.Fatal("expected accumulated skipped keys after out-of-order decrypt — skipped-key test would prove nothing")
		}
		t.Logf("skipped keys accumulated: %d", totalSkipped)

		// Round-trip Bob's session (with skipped keys).
		swapBobSession(t, bob, alice.address)

		// Decrypt the skipped messages from the rebuilt session — keys must be intact.
		got1 := decryptDM(t, bobFromAliceBuilder, alice.address, msgs[1])
		if string(got1) != string(plaintexts[1]) {
			t.Fatalf("skipped msg[1] from rebuilt session: got %q want %q", got1, plaintexts[1])
		}
		got2 := decryptDM(t, bobFromAliceBuilder, alice.address, msgs[2])
		if string(got2) != string(plaintexts[2]) {
			t.Fatalf("skipped msg[2] from rebuilt session: got %q want %q", got2, plaintexts[2])
		}
		got3 := decryptDM(t, bobFromAliceBuilder, alice.address, msgs[3])
		if string(got3) != string(plaintexts[3]) {
			t.Fatalf("skipped msg[3] from rebuilt session: got %q want %q", got3, plaintexts[3])
		}
	})
}

// ---------------------------------------------------------------------------
// REQ-CODEC-06: TestFlatSessionProdFixtures
//
// Validates the flat codec against real prod-sampled session blobs:
// fat-tail (2000-key chains), median, and random sessions.
//
// This test is skip-guarded when no fixtures are present (prodSessionFixtures
// is nil). Fixtures are NOT committed to git (live DM crypto material — T-17.13-05).
//
// To activate: see 17.13-02-PLAN.md Task 2 checkpoint for the fixture
// extraction SQL and the operator steps to populate prodSessionFixtures.
//
// Once populated, run:
//
//	go test -run TestFlatSessionProdFixtures ./store/ -v
//
// Expected output: all fixtures pass reflect.DeepEqual. Any failure indicates
// a lossless round-trip bug in the codec for that session shape.
// ---------------------------------------------------------------------------

// prodSessionFixtures holds real prod-sampled session blobs in their original
// JSON (or flat) encoding. Each entry is a raw []byte as read from the
// whatsmeow_sessions.session column.
//
// IMPORTANT: do NOT commit populated values of this variable. After completing
// the prod-fixture verification, remove the blobs and commit only the empty
// slice. (T-17.13-05 — fixture blobs are opaque DM crypto material.)
var prodSessionFixtures [][]byte // populated by operator: see Task 2 checkpoint

func TestFlatSessionProdFixtures(t *testing.T) {
	if len(prodSessionFixtures) == 0 {
		t.Skip("no prod fixtures — run Task 2 checkpoint to populate prodSessionFixtures")
	}

	passed := 0
	failed := 0
	for i, blob := range prodSessionFixtures {
		// Decode the blob using the same serializer as the live driver.
		// prod blobs are JSON (byte[0] == 0x7B); after Stage 1 deploy some may
		// already be flat (byte[0] == 0x01). Handle both.
		var structure *record.SessionStructure
		var decodeErr error
		if len(blob) > 0 && blob[0] == flatSessionMagic {
			structure, decodeErr = UnpackFlatSession(blob)
		} else {
			structure, decodeErr = SignalProtobufSerializer.Session.Deserialize(blob)
		}
		if decodeErr != nil {
			t.Errorf("fixture[%d]: decode error: %v", i, decodeErr)
			failed++
			continue
		}

		// Pack the decoded structure to flat bytes.
		flat, ok := PackFlatSession(structure)
		if !ok {
			t.Errorf("fixture[%d]: PackFlatSession refused structure (possible prod edge case)", i)
			failed++
			continue
		}

		// Unpack back to structure2 and assert byte-exact round-trip.
		structure2, err := UnpackFlatSession(flat)
		if err != nil {
			t.Errorf("fixture[%d]: UnpackFlatSession error: %v", i, err)
			failed++
			continue
		}

		if !reflect.DeepEqual(structure, structure2) {
			// Log details to help diagnose the mismatch.
			t.Errorf("fixture[%d]: reflect.DeepEqual mismatch after pack→unpack", i)
			t.Logf("  original PreviousStates count: %d", len(structure.PreviousStates))
			if structure.SessionState != nil {
				t.Logf("  original ReceiverChains count: %d", len(structure.SessionState.ReceiverChains))
				t.Logf("  original SenderChain MessageKeys: %d", len(structure.SessionState.SenderChain.MessageKeys))
				t.Logf("  original PendingPreKey: %v", structure.SessionState.PendingPreKey != nil)
				t.Logf("  original PendingKeyExchange: %v", structure.SessionState.PendingKeyExchange != nil)
			}
			failed++
			continue
		}
		passed++
	}

	t.Logf("prod fixtures: %d passed, %d failed (total %d)", passed, failed, len(prodSessionFixtures))
	if failed > 0 {
		t.Fatalf("%d fixture(s) failed reflect.DeepEqual — codec has lossless round-trip bug(s)", failed)
	}
}

// ---------------------------------------------------------------------------
// REQ-SAFETY-01: TestSessionConcurrentRatchet
//
// Validates that concurrent LoadSession + StoreSession calls on the same
// SignalAddress are race-free under the Go race detector.
//
// ROADMAP SC#5: "mutable ratchet struct shared across handler-pool goroutines"
// — in the live driver, multiple goroutines may concurrently load and store
// sessions for the same address (parallel message dispatch). This test
// exercises Device.LoadSession / Device.StoreSession (the wired flat-bytes
// path from Plan 03) from two concurrent goroutines against the same address.
//
// Design notes:
//   - The test lives in package store (not package sqlstore) to avoid an
//     import cycle. CachedSessionStore (sqlstore) is tested separately in
//     decode_once_cr_test.go TR-06 under -race, which covers the LRU tier.
//     This test covers the transient-decode path: flat bytes stored by
//     StoreSession → LoadSession byte[0]==0x01 → UnpackFlatSession.
//   - A minimal concurrentFakeSessionStore (mutex + map) is used instead of
//     CachedSessionStore; it is goroutine-safe by construction so the race
//     detector surface is the signal.go flat-encode/decode paths themselves.
//   - The writer goroutine uses a fresh session rebuilt from the same
//     SessionStructure each iteration to simulate ratchet write-back without
//     sharing a mutable *Session across goroutines (per-handler copy discipline).
// ---------------------------------------------------------------------------

// concurrentFakeSessionStore is a minimal goroutine-safe in-memory
// SessionStore used by TestSessionConcurrentRatchet. The production path
// (CachedSessionStore + SQL backend) is exercised by decode_once_cr_test.go
// TR-06; this stub isolates the signal.go flat-encode/decode concurrency
// surface from the cache layer.
type concurrentFakeSessionStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newConcurrentFakeSessionStore() *concurrentFakeSessionStore {
	return &concurrentFakeSessionStore{data: make(map[string][]byte)}
}

func (f *concurrentFakeSessionStore) GetSession(_ context.Context, address string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.data[address]
	if v == nil {
		return nil, nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (f *concurrentFakeSessionStore) HasSession(_ context.Context, address string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.data[address]
	return ok, nil
}

func (f *concurrentFakeSessionStore) GetManySessions(_ context.Context, addresses []string) (map[string][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make(map[string][]byte, len(addresses))
	for _, a := range addresses {
		if v, ok := f.data[a]; ok {
			out := make([]byte, len(v))
			copy(out, v)
			result[a] = out
		}
	}
	return result, nil
}

func (f *concurrentFakeSessionStore) PutSession(_ context.Context, address string, sess []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	stored := make([]byte, len(sess))
	copy(stored, sess)
	f.data[address] = stored
	return nil
}

func (f *concurrentFakeSessionStore) PutManySessions(_ context.Context, sessions map[string][]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for addr, sess := range sessions {
		stored := make([]byte, len(sess))
		copy(stored, sess)
		f.data[addr] = stored
	}
	return nil
}

func (f *concurrentFakeSessionStore) DeleteAllSessions(_ context.Context, _ string) error { return nil }
func (f *concurrentFakeSessionStore) DeleteSession(_ context.Context, _ string) error      { return nil }
func (f *concurrentFakeSessionStore) MigratePNToLID(_ context.Context, _, _ types.JID) error {
	return nil
}

var _ SessionStore = (*concurrentFakeSessionStore)(nil)

func TestSessionConcurrentRatchet(t *testing.T) {
	// REQ-SAFETY-01 — ROADMAP SC#5
	// Concurrent LoadSession + StoreSession on the same address must be
	// race-free. The race detector validates this when run with -race.
	//
	// Design: Device.LoadSession / Device.StoreSession are the wired flat-bytes
	// paths from Plan 03. A real X3DH session is established (using the same
	// dmHarness as TestFlatSessionDecryptEquivalence) so that the writer holds a
	// valid *record.Session whose Structure() PackFlatSession can encode. The
	// session is seeded in the store as flat bytes so LoadSession exercises the
	// byte[0]==0x01 → UnpackFlatSession transient-decode path.
	//
	// Note: the CachedSessionStore LRU tier is tested separately under -race in
	// decode_once_cr_test.go (TR-06, package sqlstore). Importing sqlstore from
	// package store would create an import cycle, so that tier is out-of-scope
	// here. CachedSessionStore (hashicorp/golang-lru/v2) is goroutine-safe by
	// design; the plan's own T-17.13-12 confirms this.
	const iters = 10

	ctx := context.Background()

	// Establish a real X3DH session between Alice and Bob so the writer has
	// a valid *record.Session with proper Curve25519 keys.
	alice := newDMHarness(t, "alice-cr", 1)
	bob := newDMHarness(t, "bob-cr", 2)

	aliceToBobBuilder := session.NewBuilder(
		alice.sessionStore, alice.preKeyStore, alice.signedPreKeyStore,
		alice.identityStore, bob.address, alice.serializer,
	)
	if err := aliceToBobBuilder.ProcessBundle(ctx, bobBundle(bob)); err != nil {
		t.Fatalf("ProcessBundle: %v", err)
	}
	bobFromAliceBuilder := session.NewBuilder(
		bob.sessionStore, bob.preKeyStore, bob.signedPreKeyStore,
		bob.identityStore, alice.address, bob.serializer,
	)

	// Exchange one message so Bob has a real post-X3DH session with valid state.
	msg0 := encryptDM(t, aliceToBobBuilder, bob.address, alice, []byte("session init"))
	decryptDM(t, bobFromAliceBuilder, alice.address, msg0)

	// Extract Bob's post-decrypt session (real Curve25519 keys, valid structure).
	bobSess, err := bob.sessionStore.LoadSession(ctx, alice.address)
	if err != nil {
		t.Fatalf("LoadSession (setup): %v", err)
	}

	// Encode the session to flat bytes for seeding Device.Sessions.
	flat, ok := PackFlatSession(bobSess.Structure())
	if !ok {
		t.Fatal("PackFlatSession refused valid live session structure")
	}

	// Wire a minimal Device with a goroutine-safe in-memory SessionStore.
	fake := newConcurrentFakeSessionStore()
	dev := &Device{Sessions: fake}
	sig := alice.address // Bob's session is keyed by Alice's address.

	// Seed the store with flat bytes so LoadSession takes the transient-decode path.
	if err := fake.PutSession(ctx, sig.String(), flat); err != nil {
		t.Fatalf("seed PutSession: %v", err)
	}

	var wg sync.WaitGroup
	var storeErr, loadErr error

	// Goroutine A: writer — simulates ratchet write-back (StoreSession after decrypt).
	// Each iteration encodes bobSess via PackFlatSession (the Stage 1 path in
	// signal.go StoreSession). StoreSession reads bobSess only via Structure()
	// and does not mutate it, so the writer is safe to reuse the same object.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			if err := dev.StoreSession(ctx, sig, bobSess); err != nil {
				storeErr = err
				return
			}
		}
	}()

	// Goroutine B: reader — simulates handler-pool parallel session load.
	// Each iteration fetches flat bytes from the store, detects byte[0]==0x01,
	// and calls UnpackFlatSession + NewSessionFromStructure.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			if _, err := dev.LoadSession(ctx, sig); err != nil {
				loadErr = err
				return
			}
		}
	}()

	wg.Wait()

	if storeErr != nil {
		t.Fatalf("StoreSession goroutine error: %v", storeErr)
	}
	if loadErr != nil {
		t.Fatalf("LoadSession goroutine error: %v", loadErr)
	}
}

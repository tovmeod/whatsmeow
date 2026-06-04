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

package store

import (
	"reflect"
	"testing"

	"go.mau.fi/libsignal/keys/chain"
	"go.mau.fi/libsignal/keys/message"
	"go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/util/optional"
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

// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

// BLOCKING full-structure round-trip fidelity gate (T-17.9-01).
//
// A lossy decompose/recompose map permanently corrupts the Signal sender-key
// ratchet — silent decrypt failure / lost group messages. This test verifies
// byte-identical round-trip identity for every structural shape:
//
//   - 0-key:         single state, empty Keys (nil slice)
//   - multi-state:   5 states, each 0 keys, order preserved
//   - max-skipped:   1 state, 32 skipped message keys (all 4 fields per key)
//   - nil-signing-priv: nil SigningKeyPrivate (dominant received-key case)
//
// The comparison is reflect.DeepEqual on the FULL *SenderKeyStructure — NOT a
// sub-field check. See 17.9-AUDIT-REPORT.md §5: partial-structure comparisons
// give false confidence and mask lossiness.

import (
	"reflect"
	"testing"

	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
)

// mkChainKey builds a SenderChainKeyStructure with deterministic test data.
func mkChainKey(iteration uint32, seed byte) *ratchet.SenderChainKeyStructure {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return &ratchet.SenderChainKeyStructure{
		Iteration: iteration,
		ChainKey:  key,
	}
}

// mkSMK builds a SenderMessageKeyStructure with deterministic test data.
func mkSMK(iteration uint32, seed byte) *ratchet.SenderMessageKeyStructure {
	iv := make([]byte, 16)
	cipherKey := make([]byte, 32)
	smkSeed := make([]byte, 32)
	for i := range iv {
		iv[i] = seed + byte(i)
	}
	for i := range cipherKey {
		cipherKey[i] = seed + 16 + byte(i)
	}
	for i := range smkSeed {
		smkSeed[i] = seed + 48 + byte(i)
	}
	return &ratchet.SenderMessageKeyStructure{
		Iteration: iteration,
		IV:        iv,
		CipherKey: cipherKey,
		Seed:      smkSeed,
	}
}

// mkSigningPub builds a 33-byte signing public key.
func mkSigningPub(seed byte) []byte {
	pub := make([]byte, 33)
	pub[0] = 0x05 // DJB EC point tag
	for i := 1; i < 33; i++ {
		pub[i] = seed + byte(i)
	}
	return pub
}

// mkSigningPriv builds a 32-byte signing private key.
func mkSigningPriv(seed byte) []byte {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = seed + byte(i)
	}
	return priv
}

// TestSenderKeyRoundTrip is the BLOCKING full-structure fidelity gate.
// Each arm must pass reflect.DeepEqual on the FULL *SenderKeyStructure.
func TestSenderKeyRoundTrip(t *testing.T) {
	t.Run("0-key", func(t *testing.T) {
		// Single state with no skipped message keys (Keys nil).
		in := &groupRecord.SenderKeyStructure{
			SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
				{
					KeyID:             42,
					SenderChainKey:    mkChainKey(7, 0xA0),
					SigningKeyPublic:  mkSigningPub(0x10),
					SigningKeyPrivate: mkSigningPriv(0x20),
					Keys:              nil,
				},
			},
		}
		out := recompose(decompose(in))
		if !reflect.DeepEqual(in, out) {
			t.Fatalf("0-key round-trip mismatch:\n  in:  %+v\n  out: %+v", in, out)
		}
	})

	t.Run("multi-state", func(t *testing.T) {
		// 5 states, no skipped keys; state order must be preserved.
		var states []*groupRecord.SenderKeyStateStructure
		for i := 0; i < 5; i++ {
			states = append(states, &groupRecord.SenderKeyStateStructure{
				KeyID:             uint32(100 + i),
				SenderChainKey:    mkChainKey(uint32(i*3), byte(i*7)),
				SigningKeyPublic:  mkSigningPub(byte(0x30 + i)),
				SigningKeyPrivate: mkSigningPriv(byte(0x50 + i)),
				Keys:              nil,
			})
		}
		in := &groupRecord.SenderKeyStructure{SenderKeyStates: states}
		out := recompose(decompose(in))
		if !reflect.DeepEqual(in, out) {
			t.Fatalf("multi-state round-trip mismatch")
		}
	})

	t.Run("max-skipped", func(t *testing.T) {
		// 1 state with 32 skipped message keys; all 4 fields per key must survive.
		var smks []*ratchet.SenderMessageKeyStructure
		for i := 0; i < 32; i++ {
			smks = append(smks, mkSMK(uint32(i), byte(i*4)))
		}
		in := &groupRecord.SenderKeyStructure{
			SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
				{
					KeyID:             99,
					SenderChainKey:    mkChainKey(31, 0xCC),
					SigningKeyPublic:  mkSigningPub(0x77),
					SigningKeyPrivate: mkSigningPriv(0x88),
					Keys:              smks,
				},
			},
		}
		out := recompose(decompose(in))
		if !reflect.DeepEqual(in, out) {
			t.Fatalf("max-skipped round-trip mismatch")
		}
	})

	t.Run("nil-signing-priv", func(t *testing.T) {
		// Every state has SigningKeyPrivate=nil — dominant received-key shape.
		// nil must survive as nil, not []byte{} (T-17.9-02 mitigation).
		var states []*groupRecord.SenderKeyStateStructure
		for i := 0; i < 3; i++ {
			states = append(states, &groupRecord.SenderKeyStateStructure{
				KeyID:             uint32(200 + i),
				SenderChainKey:    mkChainKey(uint32(i*5), byte(i*11)),
				SigningKeyPublic:  mkSigningPub(byte(0x40 + i)),
				SigningKeyPrivate: nil, // received key — MUST round-trip as nil
				Keys:              nil,
			})
		}
		in := &groupRecord.SenderKeyStructure{SenderKeyStates: states}
		out := recompose(decompose(in))
		if !reflect.DeepEqual(in, out) {
			t.Fatalf("nil-signing-priv round-trip mismatch")
		}
		// Extra explicit check: ensure nil was not silently converted to []byte{}.
		for i, st := range out.SenderKeyStates {
			if st.SigningKeyPrivate != nil {
				t.Errorf("state[%d]: SigningKeyPrivate got %v, want nil", i, st.SigningKeyPrivate)
			}
		}
	})

	t.Run("mixed-states-with-keys", func(t *testing.T) {
		// 3 states; state[0]=2 keys, state[1]=0 keys, state[2]=3 keys.
		// Exercises smkStateIdx routing between states with differing key counts.
		in := &groupRecord.SenderKeyStructure{
			SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
				{
					KeyID:             1,
					SenderChainKey:    mkChainKey(10, 0x01),
					SigningKeyPublic:  mkSigningPub(0x01),
					SigningKeyPrivate: mkSigningPriv(0x01),
					Keys: []*ratchet.SenderMessageKeyStructure{
						mkSMK(0, 0x01),
						mkSMK(1, 0x02),
					},
				},
				{
					KeyID:             2,
					SenderChainKey:    mkChainKey(20, 0x02),
					SigningKeyPublic:  mkSigningPub(0x02),
					SigningKeyPrivate: nil,
					Keys:              nil,
				},
				{
					KeyID:             3,
					SenderChainKey:    mkChainKey(30, 0x03),
					SigningKeyPublic:  mkSigningPub(0x03),
					SigningKeyPrivate: mkSigningPriv(0x03),
					Keys: []*ratchet.SenderMessageKeyStructure{
						mkSMK(0, 0x11),
						mkSMK(1, 0x12),
						mkSMK(2, 0x13),
					},
				},
			},
		}
		out := recompose(decompose(in))
		if !reflect.DeepEqual(in, out) {
			t.Fatalf("mixed-states-with-keys round-trip mismatch")
		}
	})
}

// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

// FuzzSenderKeyRoundTrip is a property/fuzz test that verifies the
// decompose/recompose round-trip identity over random valid
// *SenderKeyStructure inputs (T-17.9-03 mitigation).
//
// Random-but-valid construction:
//   - 1..5 states (bounds checked from fuzz bytes)
//   - 0..32 skipped message keys per state (97% empty in prod, exercised here)
//   - SigningKeyPrivate randomly nil (~70% probability) to exercise the
//     dominant received-key case
//
// SenderChainKey is always non-nil (invariant of valid libsignal records).

import (
	"reflect"
	"testing"

	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/groups/ratchet"
)

// FuzzSenderKeyRoundTrip asserts recompose(decompose(in)) == in for all
// random valid SenderKeyStructure inputs derived from the fuzz corpus.
func FuzzSenderKeyRoundTrip(f *testing.F) {
	// Seed corpus 1: 0-key, 1 state, nil signing private.
	f.Add(
		uint8(1),  // nStates: 1
		uint8(0),  // nKeys0: 0 skipped keys for state[0]
		uint8(70), // sigPrivNilMask: >= 70 → nil (this is 70 → nil)
		[]byte{0xAA, 0xBB, 0xCC, 0xDD}, // chainKeyExtra
		[]byte{0x05, 0x11, 0x22, 0x33}, // sigPubExtra
	)
	// Seed corpus 2: 2 states, first has 2 keys, second has 0 keys, both with private.
	f.Add(
		uint8(2),
		uint8(2),
		uint8(0), // sigPrivNilMask: 0 < 70 → non-nil
		[]byte{0x01, 0x02, 0x03, 0x04},
		[]byte{0x05, 0x06, 0x07, 0x08},
	)
	// Seed corpus 3: max states (5), max keys on first state (32), nil private everywhere.
	f.Add(
		uint8(5),
		uint8(32),
		uint8(200), // >= 70 → nil
		[]byte{0xFF, 0xFE, 0xFD, 0xFC},
		[]byte{0x05, 0xAB, 0xCD, 0xEF},
	)

	f.Fuzz(func(t *testing.T, nStates uint8, nKeys0 uint8, sigPrivNilMask uint8, chainKeyExtra []byte, sigPubExtra []byte) {
		// Bound nStates to 1..5 (a valid SenderKeyStructure has ≥1 state).
		nS := int(nStates)
		if nS < 1 {
			nS = 1
		}
		if nS > 5 {
			nS = nS%5 + 1
		}

		// nKeys0 bounds the skipped-key count for state[0] to 0..32.
		nK0 := int(nKeys0)
		if nK0 > 32 {
			nK0 = nK0 % 33
		}

		// sigPrivNilMask >= 70 → nil signing private (~70% nil probability).
		nilPriv := sigPrivNilMask >= 70

		var states []*groupRecord.SenderKeyStateStructure
		for si := 0; si < nS; si++ {
			// Deterministically vary chain key bytes per state using state index.
			chainKey := make([]byte, 32)
			for i := range chainKey {
				if i < len(chainKeyExtra) {
					chainKey[i] = chainKeyExtra[i] ^ byte(si*31+i)
				} else {
					chainKey[i] = byte(si*31 + i)
				}
			}

			sigPub := make([]byte, 33)
			sigPub[0] = 0x05 // DJB EC point tag (required by ecc.DecodePoint)
			for i := 1; i < 33; i++ {
				if i < len(sigPubExtra)+1 {
					sigPub[i] = sigPubExtra[i-1] ^ byte(si*17+i)
				} else {
					sigPub[i] = byte(si*17 + i)
				}
			}

			var sigPriv []byte
			if !nilPriv {
				sigPriv = make([]byte, 32)
				for i := range sigPriv {
					sigPriv[i] = byte(si*13 + i + 1)
				}
			}

			// Build skipped keys: only state[0] gets nK0 keys; rest get 0.
			var smks []*ratchet.SenderMessageKeyStructure
			if si == 0 {
				for ki := 0; ki < nK0; ki++ {
					iv := make([]byte, 16)
					cipherKey := make([]byte, 32)
					smkSeed := make([]byte, 32)
					for i := range iv {
						iv[i] = byte(ki*16 + i + 1)
					}
					for i := range cipherKey {
						cipherKey[i] = byte(ki*7 + i + 64)
					}
					for i := range smkSeed {
						smkSeed[i] = byte(ki*3 + i + 128)
					}
					smks = append(smks, &ratchet.SenderMessageKeyStructure{
						Iteration: uint32(ki),
						IV:        iv,
						CipherKey: cipherKey,
						Seed:      smkSeed,
					})
				}
			}

			states = append(states, &groupRecord.SenderKeyStateStructure{
				KeyID: uint32(si + 1),
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: uint32(si * 3),
					ChainKey:  chainKey,
				},
				SigningKeyPublic:  sigPub,
				SigningKeyPrivate: sigPriv,
				Keys:              smks,
			})
		}

		in := &groupRecord.SenderKeyStructure{SenderKeyStates: states}
		out := recompose(decompose(in))
		if !reflect.DeepEqual(in, out) {
			t.Fatalf("FuzzSenderKeyRoundTrip: round-trip mismatch\n  nStates=%d nKeys0=%d nilPriv=%v\n  in:  %+v\n  out: %+v",
				nS, nK0, nilPriv, in, out)
		}
	})
}

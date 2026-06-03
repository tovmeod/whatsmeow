// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package sqlstore — senderkey_columns.go
//
// Pure in-memory columnar contract for sender-keys: a typed senderKeyColumns
// DTO plus decompose(*SenderKeyStructure) and recompose(*senderKeyColumns)
// with NO JSON. This is the load-bearing correctness boundary: a lossy map
// permanently corrupts the Signal sender-key ratchet (silent decrypt failure /
// lost group messages).
//
// DB column name ↔ Go field name map (attribute-faithful, per DESIGN-DECISIONS):
//
//	fmt_ver                  → fmtVer
//	st_key_id                → stKeyID
//	st_chain_key_iteration   → stChainKeyIteration
//	st_chain_key             → stChainKey        (SenderChainKey.ChainKey — NOT Seed)
//	st_signing_key_public    → stSigningKeyPublic
//	st_signing_key_private   → stSigningKeyPrivate (nullable elements; nil on received keys)
//	smk_state_idx            → smkStateIdx
//	smk_iteration            → smkIteration
//	smk_iv                   → smkIV
//	smk_cipher_key           → smkCipherKey
//	smk_seed                 → smkSeed           (SenderMessageKey.Seed — distinct from ChainKey)

package sqlstore

import (
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/groups/ratchet"
)

// senderKeyColumns is a position-aligned columnar representation of a
// SenderKeyStructure — up to 5 SenderKeyStateStructure entries.
//
// Per-state fields (one element per state, in state-array order):
//   - stKeyID: state.KeyID cast to int64
//   - stChainKeyIteration: state.SenderChainKey.Iteration cast to int64
//   - stChainKey: state.SenderChainKey.ChainKey (the 32-byte chain key; NOT Seed)
//   - stSigningKeyPublic: state.SigningKeyPublic
//   - stSigningKeyPrivate: state.SigningKeyPrivate (nil element preserved as nil for received keys)
//
// Skipped message keys (parallel flat arrays, one entry per SenderMessageKey
// across all states; smkStateIdx identifies the owning state index):
//   - smkStateIdx: owning state index (int32)
//   - smkIteration: SenderMessageKeyStructure.Iteration
//   - smkIV: SenderMessageKeyStructure.IV
//   - smkCipherKey: SenderMessageKeyStructure.CipherKey
//   - smkSeed: SenderMessageKeyStructure.Seed
//
// fmtVer = 2 for all column-form records.
type senderKeyColumns struct {
	fmtVer int16

	// Per-state position-aligned slices (len = number of states).
	stKeyID              []int64
	stChainKeyIteration  []int64
	stChainKey           [][]byte // SenderChainKey.ChainKey
	stSigningKeyPublic   [][]byte
	stSigningKeyPrivate  [][]byte // nullable element: nil on received keys

	// Skipped message keys — parallel flat arrays (len = total skipped keys).
	smkStateIdx  []int32
	smkIteration []int64
	smkIV        [][]byte
	smkCipherKey [][]byte
	smkSeed      [][]byte
}

// decompose maps a *groupRecord.SenderKeyStructure to its typed columnar form.
// State order is preserved (states[0] stays states[0]). nil SigningKeyPrivate is
// passed through unchanged — it is NOT converted to []byte{}.
//
// Precondition: each state's SenderChainKey is non-nil (invariant of valid
// libsignal records; we do not defensively guard against nil).
func decompose(s *groupRecord.SenderKeyStructure) *senderKeyColumns {
	n := len(s.SenderKeyStates)
	c := &senderKeyColumns{
		fmtVer:              2,
		stKeyID:             make([]int64, n),
		stChainKeyIteration: make([]int64, n),
		stChainKey:          make([][]byte, n),
		stSigningKeyPublic:  make([][]byte, n),
		stSigningKeyPrivate: make([][]byte, n),
	}

	for i, st := range s.SenderKeyStates {
		c.stKeyID[i] = int64(st.KeyID)
		c.stChainKeyIteration[i] = int64(st.SenderChainKey.Iteration)
		c.stChainKey[i] = st.SenderChainKey.ChainKey // ChainKey field — NOT Seed
		c.stSigningKeyPublic[i] = st.SigningKeyPublic
		c.stSigningKeyPrivate[i] = st.SigningKeyPrivate // nil preserved as nil

		for _, smk := range st.Keys {
			c.smkStateIdx = append(c.smkStateIdx, int32(i))
			c.smkIteration = append(c.smkIteration, int64(smk.Iteration))
			c.smkIV = append(c.smkIV, smk.IV)
			c.smkCipherKey = append(c.smkCipherKey, smk.CipherKey)
			c.smkSeed = append(c.smkSeed, smk.Seed)
		}
	}

	return c
}

// recompose reconstructs a *groupRecord.SenderKeyStructure from its columnar
// form. State order is preserved. nil SigningKeyPrivate elements remain nil.
// Skipped message keys are routed back to their owning state via smkStateIdx.
//
// The resulting *SenderKeyStructure is structurally identical to the one that
// was decomposed — verify with reflect.DeepEqual (the BLOCKING gate).
func recompose(c *senderKeyColumns) *groupRecord.SenderKeyStructure {
	n := len(c.stKeyID)
	states := make([]*groupRecord.SenderKeyStateStructure, n)
	for i := range states {
		states[i] = &groupRecord.SenderKeyStateStructure{
			KeyID: uint32(c.stKeyID[i]),
			SenderChainKey: &ratchet.SenderChainKeyStructure{
				Iteration: uint32(c.stChainKeyIteration[i]),
				ChainKey:  c.stChainKey[i],
			},
			SigningKeyPublic:  c.stSigningKeyPublic[i],
			SigningKeyPrivate: c.stSigningKeyPrivate[i], // nil preserved
			// Keys populated below
		}
	}

	// Route skipped message keys back to their owning state.
	for j, stIdx := range c.smkStateIdx {
		smk := &ratchet.SenderMessageKeyStructure{
			Iteration: uint32(c.smkIteration[j]),
			IV:        c.smkIV[j],
			CipherKey: c.smkCipherKey[j],
			Seed:      c.smkSeed[j],
		}
		states[stIdx].Keys = append(states[stIdx].Keys, smk)
	}

	return &groupRecord.SenderKeyStructure{
		SenderKeyStates: states,
	}
}

// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// recovery_sender_key.go — cross-account sender-key recovery (Phase 17.9 plan 05)
//
// When an account is missing a sender-key state, find a usable donor across ALL
// accounts: match by key_id (the real crypto identifier), device-tolerant on the
// sender's device suffix, picking the closest chain_key_iteration <= target.
//
// Correctness invariants:
//   - Anchor on key_id (not device suffix): same key_id ⇒ same key, decryptable
//     regardless of the ':0' vs ':5' suffix inconsistency left by LID migration.
//   - Forward-only: a donor with chain_iter > target is useless (the chain ratchets
//     forward; you cannot go back). Reject such donors.
//   - Recipient-independent: signing keys + sender chain key/iter are not tied to
//     the recipient. Write the recovered state under the recovering account's own
//     (our_jid, chat_id, target_sender_id) via PutSenderKeyStructure (flusher +
//     parsed-cache coherent, no raw INSERT, no NULL-blob).
//   - Both fmt_ver=1 (legacy blob) and fmt_ver=2 (column) donors are consulted.
//     At deploy, most rows are fmt_ver=1 (no backfill yet), so column-only scan
//     would miss nearly all donors. Recovery parses fmt_ver=1 blobs here — this
//     is allowed (recovery is off the per-message hot path; explicitly outside the
//     no-JSON grep-gate of plan 04 which covers senderkey_columns.go, store.go,
//     cached_sender_key_store.go, signal.go — NOT this file).
//
// No recovery index is added (DESIGN-DECISIONS line 56: measure-first).

package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/groups/ratchet"

	"go.mau.fi/whatsmeow/store"
)

// senderKeyRecoveryReader is the local interface that *SQLStore satisfies to
// expose the cross-account donor scan. Using a local interface avoids exposing
// findSenderKeyDonor as a public method while letting CachedSenderKeyStore
// access it via type-assertion.
type senderKeyRecoveryReader interface {
	findSenderKeyDonor(ctx context.Context, group, senderBare string, targetKeyID uint32, targetIter uint32) (*donorSenderKeyState, error)
}

// donorSenderKeyState is the recipient-independent crypto state extracted from a
// cross-account donor row. Signing keys and SenderChainKey are from a single
// SenderKeyStateStructure whose KeyID == targetKeyID and
// SenderChainKey.Iteration is the closest value <= targetIter across all donors.
type donorSenderKeyState struct {
	// KeyID of the matching SenderKeyState (== targetKeyID).
	KeyID uint32
	// SenderChainKey at the chosen iteration.
	Iteration uint32
	ChainKey  []byte // 32-byte chain key (SenderChainKey.ChainKey — NOT Seed)
	// Signing key pair (recipient-independent).
	SigningKeyPublic  []byte
	SigningKeyPrivate []byte // nil on received (non-own) keys — preserved
	// Skipped message keys for this state, if any (forwarded for completeness).
	SkippedKeys []*ratchet.SenderMessageKeyStructure
}

// recoveryScanQuery fetches all (chat_id, bare-user LIKE) rows across ALL accounts
// (no our_jid filter — the whole point of recovery is to find another account's row).
//
// Returns fmt_ver + all columnar fields + the legacy sender_key blob.
// The fmt_ver=2 rows carry the key_id and chain_key_iteration arrays that allow
// SQL-side pre-filtering (commented in code below — we still fetch both format rows
// and do final selection in Go so the logic stays simple and correct for both).
//
// Device-tolerant: LIKE userBare||':%' ESCAPE '\' matches any device suffix.
const recoveryScanQuery = `
	SELECT
		fmt_ver,
		st_key_id, st_chain_key_iteration, st_chain_key,
		st_signing_key_public, st_signing_key_private,
		smk_state_idx, smk_iteration, smk_iv, smk_cipher_key, smk_seed,
		sender_key
	FROM whatsmeow_sender_keys
	WHERE chat_id=$1 AND sender_id LIKE $2 || ':%' ESCAPE '\'
`

// findSenderKeyDonor scans all rows for (group, senderBare LIKE) across every
// account (no our_jid filter) and returns the best donor state: the one with
// KeyID == targetKeyID and the maximum chain_key_iteration <= targetIter.
//
// Returns (nil, nil) when no qualifying donor exists (the caller decides whether
// to fall back to other recovery mechanisms or fail gracefully).
//
// Handles fmt_ver=2 (column) and fmt_ver=1/NULL (legacy blob) donors.
// Blob Deserialize is allowed here — recovery is off the per-message hot path.
func (s *SQLStore) findSenderKeyDonor(ctx context.Context, group, senderBare string, targetKeyID uint32, targetIter uint32) (*donorSenderKeyState, error) {
	escapedBare := senderKeyLikeEscaper.Replace(senderBare)
	rows, err := s.db.Query(ctx, recoveryScanQuery, group, escapedBare)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var best *donorSenderKeyState // best donor seen so far (max iter <= targetIter)

	for rows.Next() {
		var (
			fmtVer           *int16
			stKeyID          int64Array
			stChainKeyIter   int64Array
			stChainKey       byteaArray
			stSigningKeyPub  byteaArray
			stSigningKeyPriv byteaArray
			smkStateIdx      int32Array
			smkIteration     int64Array
			smkIV            byteaArray
			smkCipherKey     byteaArray
			smkSeed          byteaArray
			blob             []byte
		)
		if err := rows.Scan(
			&fmtVer,
			&stKeyID, &stChainKeyIter, &stChainKey,
			&stSigningKeyPub, &stSigningKeyPriv,
			&smkStateIdx, &smkIteration, &smkIV, &smkCipherKey, &smkSeed,
			&blob,
		); err != nil {
			return nil, err
		}

		var structure *groupRecord.SenderKeyStructure
		if fmtVer != nil && *fmtVer == 2 {
			// fmt_ver=2: recompose from columns.
			cols := &senderKeyColumns{
				fmtVer:              2,
				stKeyID:             []int64(stKeyID),
				stChainKeyIteration: []int64(stChainKeyIter),
				stChainKey:          [][]byte(stChainKey),
				stSigningKeyPublic:  [][]byte(stSigningKeyPub),
				stSigningKeyPrivate: [][]byte(stSigningKeyPriv),
				smkStateIdx:         []int32(smkStateIdx),
				smkIteration:        []int64(smkIteration),
				smkIV:               [][]byte(smkIV),
				smkCipherKey:        [][]byte(smkCipherKey),
				smkSeed:             [][]byte(smkSeed),
			}
			structure = recompose(cols)
		} else {
			// fmt_ver=1 or NULL: Deserialize the legacy blob.
			// Allowed here — recovery is off the hot path (outside the grep-gate).
			if blob == nil {
				continue // absent / NULL blob on a legacy row — skip
			}
			var dErr error
			structure, dErr = store.SignalProtobufSerializer.SenderKeyRecord.Deserialize(blob)
			if dErr != nil {
				// Corrupt blob in a donor row — skip this row, try others.
				continue
			}
		}

		if structure == nil {
			continue
		}

		// Scan each state in this donor structure for a matching key_id
		// with chain_iter <= targetIter, keeping the maximum such iteration.
		for _, st := range structure.SenderKeyStates {
			if st == nil || st.SenderChainKey == nil {
				continue
			}
			if st.KeyID != targetKeyID {
				continue // wrong key generation
			}
			donorIter := st.SenderChainKey.Iteration
			if donorIter > targetIter {
				continue // forward-only: donor is past the target, useless
			}
			if best != nil && donorIter <= best.Iteration {
				continue // not better than current best
			}
			// This state is a candidate — collect skipped keys for this state.
			var skipped []*ratchet.SenderMessageKeyStructure
			for _, smk := range st.Keys {
				if smk != nil {
					skipped = append(skipped, &ratchet.SenderMessageKeyStructure{
						Iteration: smk.Iteration,
						IV:        smk.IV,
						CipherKey: smk.CipherKey,
						Seed:      smk.Seed,
					})
				}
			}
			best = &donorSenderKeyState{
				KeyID:            st.KeyID,
				Iteration:        donorIter,
				ChainKey:         st.SenderChainKey.ChainKey,
				SigningKeyPublic:  st.SigningKeyPublic,
				SigningKeyPrivate: st.SigningKeyPrivate,
				SkippedKeys:      skipped,
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return best, nil
}

// RecoverSenderKey is the cross-account recovery entry-point for
// CachedSenderKeyStore. It finds a donor via findSenderKeyDonor (across all
// accounts, key_id-anchored, device-tolerant, forward-only closest iter) and,
// if found, persists the recipient-independent state onto the recovering account's
// own (our_jid, group, targetSenderID) via PutSenderKeyStructure.
//
// Parameters:
//   - group: the chat/group JID string (chat_id)
//   - targetSenderID: the device-qualified sender_id under which to store the
//     recovered state in the recovering account (e.g. "12345_1:0") — NOT the
//     donor's sender_id
//   - senderBare: the device-stripped sender user (LIKE prefix for donor scan)
//   - targetKeyID: the key_id the message names
//   - targetIter: the chain_key_iteration the recovering account needs
//
// Returns (true, nil) on success, (false, nil) when no qualifying donor exists,
// or (false, err) on a DB or write error.
//
// The write goes through PutSenderKeyStructure which is the flusher + parsed-cache
// coherence chokepoint (plan 04 Task 3). No raw INSERT, no NULL-blob.
func (c *CachedSenderKeyStore) RecoverSenderKey(ctx context.Context, group, targetSenderID, senderBare string, targetKeyID, targetIter uint32) (bool, error) {
	r, ok := c.inner.(senderKeyRecoveryReader)
	if !ok {
		// inner does not implement the recovery reader (test stub / pre-wiring).
		return false, nil
	}

	donor, err := r.findSenderKeyDonor(ctx, group, senderBare, targetKeyID, targetIter)
	if err != nil {
		return false, err
	}
	if donor == nil {
		return false, nil // no qualifying donor
	}

	// Build a *SenderKeyStructure from the recipient-independent donor state.
	// Use only the single matching state — the recovering account gets a fresh
	// single-state record (the minimal needed state; libsignal AddSenderKeyState
	// prepends new states to the front, so having one state here is correct).
	skippedKeys := make([]*ratchet.SenderMessageKeyStructure, len(donor.SkippedKeys))
	for i, smk := range donor.SkippedKeys {
		skippedKeys[i] = &ratchet.SenderMessageKeyStructure{
			Iteration: smk.Iteration,
			IV:        smk.IV,
			CipherKey: smk.CipherKey,
			Seed:      smk.Seed,
		}
	}
	structure := &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
			{
				KeyID: donor.KeyID,
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: donor.Iteration,
					ChainKey:  donor.ChainKey, // ChainKey field — NOT Seed
				},
				SigningKeyPublic:  donor.SigningKeyPublic,
				SigningKeyPrivate: donor.SigningKeyPrivate, // nil preserved (received key)
				Keys:              skippedKeys,
			},
		},
	}

	// Persist through the columnar write-back entrypoint (flusher + parsed-cache
	// coherence chokepoint). The recovered row is stored under the recovering
	// account's own our_jid (inner is bound to the recovering JID) + targetSenderID.
	// Result: fmt_ver=2 row with all columns + recomposed legacy blob (no NULL-blob).
	if err := c.PutSenderKeyStructure(ctx, group, targetSenderID, structure); err != nil {
		return false, err
	}
	return true, nil
}

// Compile-time assertion: *SQLStore satisfies the upstream store.SenderKeyStore
// interface (GetSenderKey, PutSenderKey, GetSenderKeyDevices). The columnar
// additions live behind fork-local interfaces (senderKeyColumnarStore,
// senderKeyRecoveryReader) that the upstream interface does not declare, so a
// future upstream-whatsmeow merge of the base interface still compiles.
//
// This assertion is complementary to the var _ store.AllSessionSpecificStores =
// (*SQLStore)(nil) line in store.go — that one covers the full bundle; this
// one is a focused, named assertion for sender-key interface stability.
var _ store.SenderKeyStore = (*SQLStore)(nil)

// Compile-time assertion: *SQLStore satisfies the fork-local recovery reader
// interface. If findSenderKeyDonor is removed or its signature drifts, this
// line becomes a BUILD ERROR, preventing RecoverSenderKey from silently
// falling back to (false, nil) via the type-assertion above.
var _ senderKeyRecoveryReader = (*SQLStore)(nil)

// fmtVerDiscriminator guards the critical invariant: recovery MUST consult
// both fmt_ver=1 (legacy blob) and fmt_ver=2 (column) donors.
// This comment is intentionally placed here (not as a runtime check) to
// document that the recoveryScanQuery returns ALL rows regardless of fmt_ver,
// and the Go loop above dispatches on fmtVer — no format is skipped.
// T-17.9-20 mitigation: recovery works before any backfill (fmt_ver=1 dominant).
var _ = errors.New // force errors import used in error return paths

// Sentinel to satisfy the sql.ErrNoRows import: the query loop does not
// call Scan on absent rows, but the errors package is imported for the
// compile-time assertion above.
var _ = sql.ErrNoRows

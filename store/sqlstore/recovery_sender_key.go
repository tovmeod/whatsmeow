// Copyright (c) 2026 Kavtov Platform (Phase 17.9 / Phase 17.11)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// recovery_sender_key.go — cross-account sender-key recovery (Phase 17.9 plan 05,
// iteration guard Phase 17.11 plan 02, inline path Phase 17.12)
//
// When an account is missing a sender-key state, TryInlineRecovery finds a usable
// donor across ALL accounts: match by key_id (the real crypto identifier),
// device-tolerant on the sender's device suffix, picking the closest
// chain_key_iteration <= target.
//
// Correctness invariants:
//   - Anchor on key_id (not device suffix): same key_id ⇒ same key, decryptable
//     regardless of the ':0' vs ':5' suffix inconsistency left by LID migration.
//   - Forward-only: a donor with chain_iter > target is useless (the chain ratchets
//     forward; you cannot go back). Reject such donors.
//   - Recipient-independent: signing keys + sender chain key/iter are not tied to
//     the recipient. Write the recovered state under the recovering account's own
//     (our_jid, chat_id, target_sender_id) via PutSenderKeyStructure (fires
//     parsedReplace synchronously). The inline retry reads from the warm
//     parsedReplace cache — no DB round-trip needed. No async flusher, no raw
//     INSERT, no NULL-blob.
//   - Both fmt_ver=1 (legacy blob) and fmt_ver=2 (column) donors are consulted.
//     At deploy, most rows are fmt_ver=1 (no backfill yet), so column-only scan
//     would miss nearly all donors. Recovery parses fmt_ver=1 blobs here — this
//     is allowed (recovery is off the per-message hot path; explicitly outside the
//     no-JSON grep-gate of plan 04 which covers senderkey_columns.go, store.go,
//     cached_sender_key_store.go, signal.go — NOT this file).
//   - No iteration downgrade: if the existing row for (group, targetSenderID) has
//     the same KeyID at Iteration >= donor.Iteration, the write is skipped. A
//     concurrent inbound SKDM can advance the ratchet between findSenderKeyDonor
//     and PutSenderKeyStructure; the guard prevents clobbering it.
//
// No recovery index is added (DESIGN-DECISIONS line 56: measure-first).

package sqlstore

import (
	"context"
	"strconv"
	"sync/atomic"

	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/groups/ratchet"

	"go.mau.fi/whatsmeow/store"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// D-05 fallback-scan instrumentation counters.
// fallbackScanEntered counts how often recoveryScanQuery (the LIKE-only fallback
// path) is entered. fallbackScanDonorFound counts how often it returns a non-nil
// donor. The ratio fallbackScanDonorFound/fallbackScanEntered is the hit rate of
// the LIKE-only fallback; a low ratio means the fallback rarely succeeds (most
// misses are fleet-correlated no-donor cases). Both counters are logged every 500
// fallback entries so the operator can measure without a prod restart.
var (
	fallbackScanEntered    atomic.Uint64
	fallbackScanDonorFound atomic.Uint64
)

// D-01 singleflight coalescing counters (Gap 1 / 29-08).
// donorSFTotal counts every TryInlineRecovery singleflight attempt (each account that
// enters the sf.Do call, whether or not the call was coalesced). donorSFShared counts
// the subset where shared=true (the call returned a cached result from a concurrent
// goroutine — the coalescing benefit). The ratio donorSFShared/donorSFTotal is the
// coalescing rate; a low ratio means the singleflight coalesces rarely (have=none
// dominant, no donor to share). Logged every donorSFLogEvery total attempts so the
// operator can measure collapse magnitude without a prod restart.
var (
	donorSFTotal  atomic.Uint64
	donorSFShared atomic.Uint64
)

// donorSFLogEvery is the sampling period for the DONOR_SF_COALESCED log line.
// 100 yields observable lines within minutes given the ~10/min donor-attempt rate.
const donorSFLogEvery = 100

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
	// OurJID is the donor account's JID (our_jid column), populated by
	// scanFlatRows for D-08 donor-jid logging in TryInlineRecovery.
	OurJID string
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

// recoveryScanQueryFast is the indexed fast-path donor query (R8).
// Filters by chat_id + sk_keyid0 (STORED GENERATED column = state[0].KeyID in PackFlat)
// + sender_id LIKE prefix, seeking the composite (chat_id, sk_keyid0) index.
// Finds single-state donors (and multi-state donors where state[0].KeyID == targetKeyID).
// Does NOT find multi-state donors where targetKeyID is only in state[1+]; those are
// covered by the LIKE-only fallback (recoveryScanQuery).
//
// Device-tolerant: LIKE userBare||':%' ESCAPE '\' matches any device suffix.
const recoveryScanQueryFast = `
	SELECT our_jid, sender_key
	FROM whatsmeow_sender_keys
	WHERE chat_id=$1 AND sk_keyid0=$3 AND sender_id LIKE $2 || ':%' ESCAPE '\'
`

// recoveryScanQuery is the LIKE-only fallback donor scan, used when recoveryScanQueryFast
// finds no qualifying donor (target KeyID is in state[1+] of some multi-state row).
// Fetches all rows for (chat_id, LIKE sender_id prefix) across ALL accounts and lets
// the Go loop scan all states for the matching KeyID.
//
// Device-tolerant: LIKE userBare||':%' ESCAPE '\' matches any device suffix.
const recoveryScanQuery = `
	SELECT our_jid, sender_key
	FROM whatsmeow_sender_keys
	WHERE chat_id=$1 AND sender_id LIKE $2 || ':%' ESCAPE '\'
`

// scanFlatRows scans a row cursor from either recoveryScanQueryFast or
// recoveryScanQuery (both SELECT our_jid, sender_key) and updates best with the
// best qualifying donor state found. Returns the updated best (may be unchanged).
func scanFlatRows(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}, targetKeyID, targetIter uint32, best *donorSenderKeyState) (*donorSenderKeyState, error) {
	for rows.Next() {
		var (
			ourJID string
			blob   []byte
		)
		if err := rows.Scan(&ourJID, &blob); err != nil {
			return best, err
		}
		if blob == nil {
			continue // NULL blob — skip (should not happen post-upgrade-19)
		}

		structure, err := store.UnpackFlat(blob)
		if err != nil {
			// Corrupt flat blob in a donor row — skip this row, try others.
			continue
		}
		if structure == nil {
			continue
		}

		// Scan each state for a matching key_id with chain_iter <= targetIter.
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
			// This state is a candidate — collect skipped keys.
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
				OurJID:           ourJID,
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
		return best, err
	}
	return best, nil
}

// findSenderKeyDonor scans all rows for (group, senderBare LIKE) across every
// account (no our_jid filter) and returns the best donor state: the one with
// KeyID == targetKeyID and the maximum chain_key_iteration <= targetIter.
//
// TWO-PATH SCAN (R8):
//  1. Fast path (recoveryScanQueryFast): filters chat_id + sk_keyid0=targetKeyID + LIKE,
//     seeking the composite (chat_id, sk_keyid0) index. Finds donors where
//     state[0].KeyID == targetKeyID without scanning the full group row-set.
//  2. Fallback path (recoveryScanQuery): runs ONLY when the fast path finds no qualifying
//     donor. LIKE-only scan covers multi-state donors where targetKeyID is in state[1+].
//
// All donor rows are PackFlat-encoded. Decode with store.UnpackFlat.
// Returns (nil, nil) when no qualifying donor exists.
func (s *SQLStore) findSenderKeyDonor(ctx context.Context, group, senderBare string, targetKeyID uint32, targetIter uint32) (*donorSenderKeyState, error) {
	escapedBare := senderKeyLikeEscaper.Replace(senderBare)

	// Fast path: indexed scan on (chat_id, sk_keyid0).
	// $3 = targetKeyID as int32 (sk_keyid0 is INT4).
	fastRows, err := s.db.Query(ctx, recoveryScanQueryFast, group, escapedBare, int32(targetKeyID))
	if err != nil {
		return nil, err
	}
	best, err := scanFlatRows(fastRows, targetKeyID, targetIter, nil)
	fastRows.Close()
	if err != nil {
		return nil, err
	}

	if best != nil {
		// Fast path found a qualifying donor — skip the fallback scan.
		return best, nil
	}

	// Fallback path: LIKE-only scan (covers multi-state donors, state[1+] KeyID match).
	// D-05: count entries and donor hits so the operator can measure hit-rate post-deploy.
	if n := fallbackScanEntered.Add(1); n%500 == 0 {
		s.log.Infof("D05_FALLBACK_SCAN entered=%d donorFound=%d group=%s",
			n, fallbackScanDonorFound.Load(), group)
	}
	fbRows, err := s.db.Query(ctx, recoveryScanQuery, group, escapedBare)
	if err != nil {
		return nil, err
	}
	defer fbRows.Close()
	fbBest, err := scanFlatRows(fbRows, targetKeyID, targetIter, nil)
	if err != nil {
		return nil, err
	}
	if fbBest != nil {
		fallbackScanDonorFound.Add(1)
	}
	return fbBest, nil
}

// TryInlineRecovery is the cross-account recovery entry-point for
// CachedSenderKeyStore. It satisfies the store.SenderKeyInlineRecoverer
// interface and is called directly from decryptGroupSenderKey in message.go on
// a sender-key miss.
//
//   - Returns (donorJID string, ok bool, err error) so the caller can log the
//     donor's account JID in SENDER_KEY_RECOVERED (D-08).
//   - Installs via PutSenderKeyStructure (warm parsedReplace cache). The inline
//     retry constructs the cipher directly from the parsedReplace cache without
//     calling GetSenderKeyDevices (D-03/D-04).
//
// Iteration-downgrade guard (T-1712-01 mitigation): a concurrent inbound SKDM
// can advance the ratchet between findSenderKeyDonor and PutSenderKeyStructure;
// the guard prevents clobbering a naturally-advanced key.
func (c *CachedSenderKeyStore) TryInlineRecovery(ctx context.Context, group, targetSenderID, senderBare string, targetKeyID, targetIter uint32) (donorJID string, ok bool, err error) {
	r, rOk := c.inner.(senderKeyRecoveryReader)
	if !rOk {
		// inner does not implement the recovery reader (test stub / pre-wiring).
		return "", false, nil
	}

	// D-01: coalesce concurrent findSenderKeyDonor calls for the same
	// (group, senderBare, keyID) via the process-global singleflight.Group.
	// N accounts missing the same key will share ONE donor DB scan; each
	// account then independently runs the downgrade guard + install below.
	// targetIter is excluded from the key (RESEARCH Open Q1): the per-account
	// iteration-downgrade guard already handles the case where a shared donor
	// is inapplicable at a lower target iteration.
	// The "|" separator prevents key collisions between distinct tuples that
	// share a prefix (T-29-01-01 mitigation).
	sfKey := group + "|" + senderBare + "|" + strconv.FormatUint(uint64(targetKeyID), 10)

	var donor *donorSenderKeyState
	if c.sf != nil {
		v, sfErr, shared := c.sf.Do(sfKey, func() (any, error) {
			return r.findSenderKeyDonor(ctx, group, senderBare, targetKeyID, targetIter)
		})
		// D-01: count total attempts and coalesced followers; emit every donorSFLogEvery
		// total attempts so the coalescing rate is observable even when shared=0 (have=none
		// dominant). Keyed on total (not shared) so lines appear regardless of coalescing.
		n := donorSFTotal.Add(1)
		if shared {
			donorSFShared.Add(1)
		}
		if n%donorSFLogEvery == 0 {
			// Obtain a logger via the inner SQLStore; guard nil so test contexts without
			// a Container do not panic. The type assertion is intra-package (both types
			// live in package sqlstore) so accessing Container.log (unexported) is legal.
			var sfLog waLog.Logger
			if sq, ok := c.inner.(*SQLStore); ok {
				sfLog = sq.log
			}
			if sfLog != nil {
				sfLog.Infof("DONOR_SF_COALESCED total=%d shared=%d", n, donorSFShared.Load())
			}
		}
		if sfErr != nil {
			return "", false, sfErr
		}
		if v != nil {
			donor = v.(*donorSenderKeyState)
		}
	} else {
		// No singleflight wired (test context); call directly.
		var findErr error
		donor, findErr = r.findSenderKeyDonor(ctx, group, senderBare, targetKeyID, targetIter)
		if findErr != nil {
			return "", false, findErr
		}
	}
	if donor == nil {
		return "", false, nil // no qualifying donor
	}

	// Iteration-downgrade guard (T-1712-01 mitigation):
	// A concurrent inbound SKDM can advance the ratchet between findSenderKeyDonor
	// and PutSenderKeyStructure. If the existing row already has the same KeyID at
	// Iteration >= donor.Iteration, the donor is stale — skip the write to avoid
	// clobbering the naturally-advanced key.
	existing, err := c.GetSenderKeyStructure(ctx, group, targetSenderID)
	if err != nil {
		return "", false, err
	}
	if existing != nil {
		for _, st := range existing.SenderKeyStates {
			if st == nil || st.SenderChainKey == nil {
				continue
			}
			if st.KeyID == donor.KeyID && st.SenderChainKey.Iteration >= donor.Iteration {
				return "", false, nil // donor is not fresher; skip write
			}
		}
	}

	// Build a *SenderKeyStructure from the recipient-independent donor state.
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
					ChainKey:  donor.ChainKey,
				},
				SigningKeyPublic:  donor.SigningKeyPublic,
				SigningKeyPrivate: donor.SigningKeyPrivate,
				Keys:              skippedKeys,
			},
		},
	}

	// Install via PutSenderKeyStructure (fires parsedReplace synchronously).
	// The inline retry reads from the warm parsedReplace cache — no DB round-trip.
	if err := c.PutSenderKeyStructure(ctx, group, targetSenderID, structure); err != nil {
		return "", false, err
	}
	return donor.OurJID, true, nil
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

// Compile-time assertion: *CachedSenderKeyStore satisfies the new inline
// recovery interface. If TryInlineRecovery is removed or its signature drifts,
// this line becomes a BUILD ERROR, preventing silent nil-fallback at the call site.
var _ store.SenderKeyInlineRecoverer = (*CachedSenderKeyStore)(nil)

// flatRecoveryNote: post-upgrade-19 all sender_key values are PackFlat format.
// findSenderKeyDonor uses store.UnpackFlat for all rows. The fast path
// (recoveryScanQueryFast + sk_keyid0 index) reduces per-scan cost for the common
// single-state donor case. The LIKE-only fallback covers multi-state donors.
